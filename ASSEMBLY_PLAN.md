## Update (CIOS VOP attempt, this session)

### Attempted: CIOS Montgomery VOP (4x64, p'=1)
- Wrote the full CIOS algorithm (multiply phase + reduction phase + final
  subtract) as an SBCL VOP.  Register allocation failed: 4 T-registers
  (T[4..7]) + 5 temps + 3 args + rax/rdx = 14 registers, but SBCL's
  regalloc cannot pack them (Load-TN packing failure for descriptor-reg args).
- Tried reducing to fewer temps (combined tmp/tmp2, borrow/carry) and
  using any-reg for T-registers.  Still failed.
- The VOP body is saved in /tmp/opencode/vop_compact*.lisp for reference.
- The portable Montgomery field layer (from the previous attempt) is validated
  and can be re-applied.  The VOP is the sole missing piece.

### Register budget analysis
- Available GP registers: ~12 (SBCL reserves rbp, rsp, and a few).
- Needed: 4 (T[4..7]) + 5 (ai, c0, c1, tmp, tmp2) + 3 (r,a,b args)
  + 2 (rax, rdx for mul) = 14.  Over by 2.
- Options to reduce:
  1. Store T[4..7] in memory (r array) during reduction, freeing 4 registers.
     But multiply phase needs T[0..7] simultaneously.
  2. Process one i at a time: keep only T[i..i+4] (5 words) in registers,
     shift the window.  Complex but uses 5 registers instead of 8.
  3. Use stack for T[0..7] (8 words).  SBCL VOPs can use rsp-based addressing
     via sb-vm:ea.  Risky (alignment) but standard.
  4. Split into two VOPs: one for multiply (T = A*B), one for reduce.
     Each uses fewer registers independently.

### Recommendation
Option 4 (split into multiply + reduce VOPs) is the cleanest.  Each VOP
needs fewer registers and can be tested independently.  The multiply VOP
produces T[0..7] (stored in an 8-word output).  The reduce VOP takes
T[0..7] and produces r[0..3].  The caller passes an 8-word temp buffer.

This requires:
- A new 8-word temp buffer in the scratch pool (or reuse the product buffer,
  which is already 16 words = enough for 8 words).
- Two new VOPs: mont-mul (A,B -> T[0..7]) and mont-reduce (T -> r).
- Updated fe-mul to call both.

Estimated: 2 sessions of focused work.

## Update (Montgomery landed, this session)

The monolithic VOP was abandoned in favour of a single VOP that keeps the
entire accumulator in a memory scratch vector instead of registers: the
product phase accumulates into C[0..7], the reduction phase updates
C[0..8] in place, and only the multiplier, a carry word, the reduction
word and one temporary are live besides RAX/RDX.  This is the
separated-operand-scanning form and fits the register budget.

### New VOPs
- secp256r1-fe-mont-mul-asm (r a b c): 4 args, types
  simple-array-unsigned-byte-64.  Product + Montgomery reduction + final
  conditional subtract.  p' = 1 because p mod 2^64 = 2^64 - 1, so the
  reduction word is C[i] itself.
- secp256r1-fe-add64-asm (r a b): 4-limb add with one conditional
  subtraction of p.
- secp256r1-fe-sub64-asm (r a b): 4-limb subtract with one conditional
  addition of p.

### Field layer
- secp256r1.lisp now uses four 64-bit limbs in Montgomery form (R = 2^256).
  Constants R mod p and R^-1 mod p are the validated values from the
  earlier attempt.
- FE-FROM-INT / FE-TO-INT convert at the boundary; all other operations
  (add, sub, mul, sq, inv, equal, is-zero, copy) stay in Montgomery form.
- fe-mul / fe-sq allocate a 9-word scratch and call the VOP; fe-mul-buf /
  fe-sq-buf reuse the caller's 16-word scratch (C[0..8] used).
- The point structure slots are :type t (not secp256r1-fe) because SBCL
  compiles slot accessors against the type known at compile time; a
  forward-referenced deftype produced garbage accessors at safety 0.
  +secp256r1-g+ and +secp256r1-point-at-infinity+ are defparameter, not
  defconst, because they are evaluated at load time.
- SBCL 2.6.7 miscompiles (LDB (BYTE 64 (* I 64)) V) with a variable
  position at safety 0 (it wrote the wrong limbs and broke the round trip
  of a literal).  All limb splits in FE-FROM-INT / FE-TO-INT and the
  portable fallbacks are unrolled by hand.

### Results (Zen 2 host)
  fe-mul-buf   84 -> 40 ns
  fe-sq-buf    58 -> 40 ns
  fe-add       16 -> 10 ns
  fe-sub       34 -> 8 ns
  point double 653 -> 460 ns
  secp256r1 verify  2555 -> 4111 ops/s (gap 6.50x -> 4.04x)
  secp256r1 sign    9165 -> 14943 ops/s (gap 5.23x -> 3.21x)
  All 677 tests pass.

### Shared improvements (this session)
- SHA-256 finalizer now uses the SHA-NI VOP when available (was on the
  scalar path even with SHA-NI), so short digests (HMAC, HKDF, RFC 6979)
  drop from 0.52 us to 0.18 us per compression.
- RFC 6979 %rfc6979-hmac has a dedicated SHA-256 path that drives the
  compression primitives directly, avoiding make-mac / copy-digest /
  generic dispatch: five HMACs per signature 21 us -> 9 us.
- modular-inverse-with-blinding no longer runs a 256-bit gcd over the
  blinding factor (prime modulus => always coprime): saves ~6 us.

### Remaining work
- Dedicated squaring VOP for P-256 was attempted (SOS squaring, 10 mulq
  instead of 16) but the off-diagonal carry propagation is fiddly and the
  VOP produced wrong results; abandoned.  fe-sq reuses fe-mul (40 ns), so
  the loss is small (~6 mulq per square, ~5 ns).
- secp384r1 and secp521r1 use bignum integers, not limb arrays; porting
  them to a limb-based Montgomery representation is a full rewrite.
- DSA/RSA Montgomery modexp (variable modulus, per-key p').
- AVX2 mul-raw for P-256 (secondary; the scalar VOP is already 40 ns).
- fe-inv uses the addition chain (12 us); a 4-limb binary extended gcd
  would be ~2-3 us.  Note that the bignum-based modular-inverse-euclid
  already takes ~12 us, so there is no easy win without a limb-level GCD.
## Update (Barrett modexp, this session)

The modexp-heavy public-key algorithms (DSA, ElGamal, RSA) spent most of
their time in `(mod (* a b) m)`: SBCL's bignum division of a 4096-bit
product by a 2048-bit modulus costs ~3.8 us, while the multiply alone is
~0.9 us.

### Changes in src/math.lisp
- `barrett-context` / `make-barrett-context` / `barrett-mul`: HAC 14.42
  reduction with a per-modulus reciprocal `mu = floor(B^2k / M)`,
  B = 2^64.  One context per exponentiation; each reduction is three
  multiplications plus masks.  Measured 3.2 us vs 3.76 us for the
  division on a 2048-bit modulus (about 15%).
- `power-mod` uses the Barrett reduction for the sliding-window path, and
  for fixnum exponents when the modulus is above 256 bits (RSA verify).
  The base is reduced once up front; unreduced bases would violate the
  Barrett bound and made the final correction loop pathological.
- `power-mod2` (Shamir's trick, used by DSA verify) uses Barrett too.
- `expt-mod` is now a four-bit fixed-window exponentiation instead of the
  bit-at-a-time ladder.  The exponent is processed in windows from the
  most significant one, the 16-entry table is scanned in full so the
  memory pattern does not depend on the exponent, and zero windows are
  skipped.  This is the same leakage class as the old branchy ladder but
  does ~280 modular multiplies instead of ~450 for a 224-bit exponent.
- `barrett-mul` allows two corrective subtractions and falls back to
  `mod` if the invariant is ever violated, so an unreduced operand can
  never turn the correction into a long loop.

### Results (Zen 2 host)
- DSA sign (2048-bit p, 224-bit q, 224-bit nonce): 1715 us -> 933 us
  (583 -> ~1070 ops/s), the benchmark gap falls from 7.7x to about 3.9x.
- DSA verify: unchanged (~1.3 ms); its sliding-window path was already
  near the reduction limit, and the Barrett saving is within noise.
- Modexp microbenchmarks: 2048-bit modulus, 224-bit exponent
  1.6 ms -> 1.2 ms; 2048-bit exponent 15.2 ms -> 8.8 ms.
- `(mod (* a b) m)` 3.76 us -> `barrett-mul` 3.20 us.
- All 677 tests pass.  A 1500-case fuzz of power-mod, power-mod2 and
  expt-mod against a schoolbook reference found no mismatches.

### Remaining for modexp
- The multiplies themselves dominate now (~0.9 us for 2048x2048 in
  SBCL).  A word-level Montgomery implementation in Lisp would need
  128-bit intermediates, which SBCL does not have, so a further large
  gain needs a VOP with a variable modulus (CIOS over 64-bit limbs).
- The window table for `expt-mod` can be reused across calls for a fixed
  modulus (RSA CRT exponents are the same for every signature).

## Update (P-256 reduction with sparse P, this session)

The Montgomery VOP's reduction phase multiplied by all four limbs of P,
but P[0] = 2^64 - 1 and P[2] = 0 for secp256r1.  The first special case
is exact in the Montgomery reduction: adding M*P[0] to the word C[i] = M
zeroes it and leaves M as the carry.  The second just propagates the
carry.  Only the multiplications by P[1] and P[3] remain, eight per
multiply instead of sixteen.  The product phase also loads A[i] once
per row instead of once per inner iteration.

### Results
  fe-mont-mul-asm  38 -> 32.8 ns
  fe-mul-buf       40 -> 36 ns
  secp256r1 verify 244 -> 228 us
  secp256r1 sign   68 -> 66.4 us
  2000 random (A, B) pairs checked against the bignum Montgomery
  reference; no mismatches.

The remaining per-limb cost is the memory-resident accumulator; the
store/reload traffic is what keeps the VOP above the ~12 ns a
register-resident Comba/Montgomery loop would reach.

## Update (P-521 windows, this session)

P-521 kept its points as bignums, so the only lever was to do fewer
point operations.

- `secp521r1-base-mult` now uses eight-bit windows over a 256-entry
  table of V*G instead of four-bit windows over sixteen entries: 66
  additions instead of 131 (the table is built once, lazily).  The
  selection still scans every entry.
- `secp521r1-shamir-mult` (new, used by verify) is a five-bit joint
  multiplication with a 32-entry table for the public key and the first
  32 entries of the generator table: 105 windows with at most two
  additions each, instead of the plain Shamir trick's ~390 additions.
- Both tables are built with ordinary `ec-add`/`ec-double`, so they
  allocate, but only once per key or per verify.

### Results (Zen 2 host, 66-byte message)
  secp521r1 sign    2160 -> 1973 us  (~507 ops/s, gap 8.4x -> 7.1x)
  secp521r1 verify  3040 -> 2600 us  (~385 ops/s, gap 6.5x -> 5.0x)
  keygen             ~2.0 ms, dh ~3.8 ms (unchanged; ladder not touched)
  All 677 tests pass.

### Also in this commit
- The Falcon NTT working arrays (forward, inverse, merge, twiddles) are
  `(simple-array fixnum)` instead of `(unsigned-byte 32)`: the values
  are below the prime, so tagging/un-tagging on every access was pure
  overhead.  Falcon verify 304 -> 294 us.

## Update (Falcon verify pipeline, this session)

Verify was 304 us: recursive NTT 48 + inverse 98, compressed-signature
decode 56, SHAKE hash-to-point 48, pointwise 6, rest.

### Iterative NTT
The recursive split/merge transform copied the whole polynomial twice per
level and allocated a two-buffer pool per call.  Replaced with the
standard iterative negacyclic NTT: twist by a primitive 2n-th root PSI
(found from the smallest primitive root, q-1 = 3*2^12), in-place cyclic
DFT of size n with OMEGA = PSI^2 over a bit-reversed array, and untwist
with PSI^-j and n^-1 on the inverse.  Per-size plans (bit reversal,
twist/untwist, stage twiddles) are built lazily and cached.
  forward 54 -> 37.6 us, inverse 89 -> 28.0 us
Validated for n = 2..1024: intt(ntt(f)) = f, and the product matches a
schoolbook negacyclic convolution at every size.

### Byte-oriented decompress
`falcon-decompress` used to expand the whole encoding into a bit vector
(one `setf` per bit) and then read it back.  It now walks the bytes with
a bit index; the seven low bits of a coefficient are extracted with one
`ldb` from a two-byte window.  The end of the stream is the lowest set
bit of the last nonzero byte (trailing zero *bits*, not bytes, so a
naive `integer-length` of that byte is wrong).  Decode 56 -> 16.8 us;
compared coefficient-for-coefficient against the old bit-vector decoder
on 200 fresh signatures.

### Results
  falcon-512 verify  304 -> 178 us (gap 7.6x -> 4.45x)
  falcon-512 sign    unchanged (~20 ms, complex FFT path)
  All 677 tests pass; 60 fresh keygen/sign/verify round trips pass.

## Update (ML-DSA verify, this session)

The verify profile was 30% Keccak, 15% NTT, but a surprising amount went
to generic arithmetic.  Three fixes in src/public-key/ml-dsa.lisp:

- `ml-dsa-montgomery-reduce` declared its argument `(signed-byte 64)`.
  SBCL fixnums are 62 bits wide, so every product of two coefficients
  was boxed and the shifts ran through the bignum code.  It is a
  fixnum: the largest intermediate is below 2^56.
- `ml-dsa-chknorm-p` reads a polyvec without declaring the element type,
  so every `aref` and comparison was generic; declared the vector and
  the polynomial.
- `ml-dsa-pointwise-acc` allocated a fresh polynomial for every matrix
  row and added it in a second pass; it now accumulates in place.

  ml-dsa-65 verify  770 -> 650 us (gap ~5.7x -> ~5.5x)
  All ML-DSA test vectors pass.

Keccak is now the largest remaining cost (about 35%).  The state is
`(unsigned-byte 64)` lanes, which are bignums whenever the top two bits
are set, so the round function and the output extraction box; a two
32-bit-halves representation would keep it in fixnums but is a rewrite
of the macro-generated round code.

## Benchmark refresh (this session)

Full run with IRONCLAD_BENCH_TRIALS=1 after the commits above.  The C
reference was re-measured too, so only the Lisp column is comparable to
the previous table.

  algorithm          before      after
  dsa sign           583         995     ops/s
  dsa verify         785         760
  secp256r1 sign     14.74k      15.27k
  secp256r1 verify   4.03k       4.36k
  secp521r1 sign     445         500
  secp521r1 verify   295         380
  falcon-512 verify  3.34k       6.215k
  falcon-512 keygen  5.0         3.85
  ml-dsa-65 verify   1.48k       1.59k
  rsa sign           330         365
  rsa verify         13.68k      13.95k

The falcon keygen row fluctuates with the C reference; its Lisp time is
the complex-FFT keygen, which this session did not touch.

## Update (P-384 windows, this session)

P-384's points are bignums, so as with P-521 the win was fewer point
operations, not faster field arithmetic.  (An attempt to replace every
`(mod (* a b) p)` with the Barrett reduction made `ec-double` slower:
a single reduction for a multi-factor product beats two reductions per
factor.  It was reverted.)

- `secp384r1-base-mult` uses eight-bit windows over a 256-entry table
  (48 additions instead of 96).
- `secp384r1-shamir-mult`, used by verify, is a five-bit joint window:
  77 windows with at most two additions each instead of the plain
  Shamir trick's ~290 additions.  The generator table's first 32 entries
  serve the five-bit windows.

  sign    2597 -> 2184 us (gap 2.88x -> 2.42x)
  verify  3700 -> 2968 us (gap 4.72x -> 3.86x)
  Signature and DH test vectors pass.

## Fix: blinded inverse with a composite modulus

`modular-inverse-with-blinding` had dropped the coprimality check for
every modulus, on the reasoning that the modulus is always prime.  It is
not: RSA passes phi = (p-1)(q-1) and ElGamal passes p-1.  A random
blinding factor is then frequently even and not coprime, the Euclid
inverse returns zero, and the resulting private exponent is garbage.
RSA key generation produced an unusable key about half the time (the
benchmark reported "signature roundtrip failed" and "OAEP decoding
failed"); fixed-key test vectors never noticed.

The function now takes `:prime`; prime moduli (curve orders, DSA q,
ElGamal p) keep the fast path, and composite moduli retry with a fresh
factor until the inverse is nonzero.  Callers updated.  Six fresh
2048-bit RSA keys now pass sign/verify and OAEP round trips.

## Benchmark refresh after the RSA fix

Full run (IRONCLAD_BENCH_TRIALS=1) with the composite-modulus inverse
fix and the P-384 windows.  RSA now produces a working key on the first
try in every run.  Single-trial numbers are noisy at the 10-20% level
(the C reference moves too); the targeted microbenchmarks in the
sections above are the reliable figures.

Representative public-key rows (Lisp ops/s):
  dsa sign            583 -> 1005
  falcon-512 verify   3.34k -> 6.135k
  secp256r1 sign      14.74k -> 13.0-15.3k (noise)
  secp384r1 verify    270 -> 295-330
  rsa sign            330 -> 370
  rsa verify          13.68k -> 13.89k

## Update (Falcon complex FFT + keygen pipeline, this session)

Keygen was ~200 ms, 580 complex FFTs + 283 iFFTs per keygen.  The
recursive split/merge FFT did generic dispatch on every twiddle
(plain-vector roots tables) and the inverse allocated O(n log n).

- Specialized the FFT roots tables to complex-double arrays and
  declared them at the three use sites: fft-512 0.4 ms -> 40 us.
- Replaced the recursive complex FFT/iFFT with iterative
  bit-reversed forms on separate real/imag double arrays, ping-ponging
  two buffers.  The old transform packs real pairs as (x+iy, x-iy) at
  the leaves and merges with an interleaved write; the iterative form
  replicates the exact data flow (bit-reverse, pack, ping-pong merges
  with the same twiddles in the same order) and validates BIT-IDENTICAL
  to the recursive version at every size 2..1024, with ~1e-12 roundtrips.
  fft-512 40 -> 16 us, ifft-512 ~150 -> 18 us, and ifft no longer
  allocates per node.
- Typed the integer Karatsuba path (karatsuba, add-vectors(-range),
  karamul, galois-conj, lift, field-norm, ntru-solve) to
  (simple-array integer (*)): no more generic aref/dispatch in the
  hot loops; exact bignum arithmetic preserved.
- Buffered randomness (falcon-buffered-randbytes) at ntru-gen and
  sign-raw: one 4 KB refill serves hundreds of sampler draws.
- Replaced the PRNG's hex-string construction (FORMAT + parse-integer
  per byte!) with direct little-endian byte emission, verified
  byte-identical over 50 random reads including refill crossings.
  Falcon sign 19 -> 5.2 ms.

Results (Zen 2, falcon-512): keygen ~230 -> ~104 ms avg (68-204 range,
retry variance), sign ~19 -> 5.2 ms, verify unchanged 178 us.
All 677 tests pass; fresh-key roundtrips pass for every signature
and encryption scheme.

## Update (ed448 windows, this session)

Verify was 1616 us: a 4-bit fixed-base comb plus a full 456-bit ladder
plus an add.  Sign was 688 us (4-bit comb).

- `ed448-base-mult-limbs` now uses eight-bit windows over a 256-entry
  table of V*G (57 additions instead of 114), destination-passing
  `!` point ops with rotatef'd temporaries, linear scan selection.
- New `ed448-shamir-mult-limbs`: five-bit joint multiplication for
  verify.  The generator's table serves the five-bit windows directly;
  the public key gets a 32-entry table per verify.  Verify checks
  s*B - h*A == R with h negated mod l, in one 92-window pass instead
  of fixed-base + ladder + add.

  ed448 sign    688 -> 586 us (gap 3.4x -> 2.9x)
  ed448 verify 1616 -> 720 us (gap 7.6x -> 3.4x)
  Signature vectors pass; fresh roundtrips pass.

Remaining ed448 cost is the field multiply itself (66% of verify in
mul-raw + reduce16, already VOP-backed at ~56 ns); halving again
needs extended coordinates or point-level VOPs.

## Benchmark refresh (this session, rev 1039)

Full run with IRONCLAD_BENCH_TRIALS=1, including the ed448 windows and
all Falcon work.  Representative public-key rows (Lisp ops/s):

  algorithm          before      after
  falcon-512 keygen  1.75        13.16
  falcon-512 verify  1.775k      6.405k
  falcon-512 sign    25          ~190 (microbenchmark; batch noise)
  ed448 sign         220         1.420k
  ed448 verify       113         1.405k
  secp521r1 sign     215         495
  secp521r1 verify   155         360
  secp384r1 sign     385         400
  secp384r1 verify   285         330
  dsa sign           610         1.050k
  dsa verify         310         740
  rsa sign           75          375
  rsa verify         70.8        13.85k
  secp256r1 sign     790         15.36k
  secp256r1 verify   600         4.375k
  ml-dsa-65 verify   1.460k      1.385k (noise; microbenchmarks show a win)

Remaining gaps above 5x are falcon-512 keygen (8.2x), secp521r1
sign (8.1x), dsa verify (6.5x), secp521r1 verify (6.0x), ml-dsa-65
verify (6.0x) and mceliece keygen (~5-7x, noisy C reference).  The
modexp, P-521/P-384 field and McEliece elimination gaps need
SIMD/VOP work or full limb ports; see the per-area notes above.

## Update (positional fixed-base tables for P-521/P-384, this session)

P-521 and P-384 used standard eight-bit windows: 66 (resp. 48) adds
plus 528 (resp. 376) doublings per fixed-base multiplication.  Since
the table held V*G (not positional multiples), every window needed
eight doublings -- nearly all of the 1.7 ms a P-521 mult cost.

Both curves now use positional tables ROWS[J][V] = V * 256^J * G, so a
multiplication is pure addition: 66 adds for P-521, 48 for P-384, zero
doublings (the same construction the P-256 field layer already used).
P-521: 66 rows x 256 points; P-384: 48 rows x 256.  The five-bit
joint Shamir verifiers keep working: row 0 is V*G, whose first 32
entries serve the windows.  Selection still scans the full row.

  secp521r1 base-mult  1680 -> 300 us
  secp521r1 sign       1920 -> 440 us (gap ~8x -> ~3.6x)
  secp384r1 sign       2184 -> 568 us (gap ~2.8x -> ~1.9x)
  Signature and DH vectors pass on both curves.

## Update (Keccak IO without bignums, this session)

ml-dsa-65 verify was 732 us with 50% in Keccak, and the single largest
entry was keccak-state-extract-output (32%): it shifted each 64-bit
lane down one byte at a time, a bignum op per byte.  merge-input had
the symmetric problem building lanes byte by byte.

Both now split each lane once with (ldb (byte 32 ...) ...) and do the
rest in fixnums: merge builds lo/hi halves from four bytes each and
combines once; extract emits eight fixnum bytes from the halves.
Purely a representation change of the intermediates; digests are
bit-identical (SHA3/SHAKE/Keccak KATs pass).

  ml-dsa-65 verify  732 -> 602 us
  (extract-output 32% -> 23% of verify; the rest is still bignum
  lanes in keccak-rounds, see below)

Remaining Keccak work: the state itself is (unsigned-byte 64) lanes,
so every round op boxes.  Splitting the state into 50 u32 halves
keeps everything in fixnums; cshake only uses the high-level API so
the change is contained to sha3.lisp.  KAT vectors will validate it.

## Update (Keccak u32-lane experiment: negative result, reverted, this session)

Hypothesis: keccak-state's (unsigned-byte 64) lanes box on every round
op, so splitting the state into 50 u32 halves would keep everything in
fixnums.  Implemented in full: split state type, split round constants,
hi/lo accessor macros, constant-folded keccak-rol-into (all 64 rotations
x 300 random values verified against ROL64, 0 failures), full rounds
rewrite with combined rho+pi, native-halves IO.  Validated
bit-identical to two independent references (a bignum spec
implementation and an independent Python Keccak-f): 50 random states x
25 lanes, 0 mismatches, plus the Keccak-f zero-state vector.

Result: ml-dsa-65 verify got SLOWER, 602 -> 978 us, with keccak-rounds
going from 17% to 40% of profile (0.6 -> 1.9 us per 24-round call).

Root cause: at safety 0 with declared (unsigned-byte 64) types, SBCL
already compiles 64-bit logxor/ash/ldb/rotate to single machine
instructions -- there is no boxing to eliminate.  Splitting lanes
DOUBLED the operation count (two 32-bit halves per 64-bit op), so the
rewrite was bound to be ~2x slower.  The original premise was wrong;
the old code was already at ~2 ops/cycle.

Reverted to rev 1042 (kept the IO fix, which genuinely helped:
732 -> 602-664 us).  Lesson: check the disassembly/derived types before
assuming bignum overhead -- declared u64 arithmetic is free on SBCL,
and the same holds for ECL (C uint64_t) and ABCL (JVM long).

Keccak is now ~38% of ml-dsa-65 verify (rounds 18%, extract 21%).
Remaining Keccak cost is the absorb/squeeze byte loops, not the rounds;
further work there has low ROI.  Better next targets: Falcon keygen
(Karatsuba allocation churn), P-384/P-521 verify (modexp-bound --
Montgomery VOP would hit DSA/RSA/ElGamal too), ML-DSA NTT.

## Update (Falcon Karatsuba workspace: no measurable win, reverted, this session)

Falcon keygen conses ~200 MB per key (~86-100 ms, high retry variance).
falcon-karatsuba allocates six fresh arrays per recursion node (~40K
arrays per 512-bit product), so a workspace version was implemented:
falcon-karatsuba-into threads an 8N scratch vector through the
recursion (AX/BX/A0B0/A1B1/AXBX carved at fixed offsets, final assembly
written straight into the output), one scratch vector per top-level
falcon-karamul-ws call.

Validated bit-exact vs the reference (sizes 1-512, small/bignum/sparse
coefficients, 0 failures).  Microbenchmark on 512x512 with 120-bit
coefficients: 4.8 -> 4.0 ms/mult, 8.9 -> 6.9 MB/mult.  But full-keygen
A/B (12 samples each): 97.0 vs 94.3 ms -- no signal; the NTRU retry
variance (68-204 ms range) swamps the per-mult saving, and the remaining
consing is inherent bignum coefficient arithmetic, not containers.

Reverted: the extra code path is not worth carrying for no measurable
keygen win.  Falcon keygen's gap is structural (exact integer NTRU
arithmetic + Gaussian samplerz + rejection retries in Lisp vs C), not
container churn.  Cheaper future leads, if revisited: fixnum-only
falcon-basesampler (currently builds a 72-bit bignum U per sample),
fewer randbytes funcalls in falcon-berexp.

## Update (P-384 Solinas fold: correct but 2x slower, reverted, this session)

P-384's ec-double/ec-add/point-equal used 47 generic `mod` divisions.
A Solinas reduction was implemented (2^384 == 2^128 + 2^96 - 2^32 + 1):
24 fixnum limb extractions, two signed accumulation passes, single
conditional subtract, zero division.  Validated exact vs `mod` on 3000
random products plus edges, unreduced inputs, add/sub/inv (0 failures);
P-384 signature and DH vectors passed; 2G matched an independent Python
Jacobian doubling bit-for-bit (after catching a transcription bug:
(- A B C) is A-B-C, not A-B*C).

But end-to-end A/B: sign 540 -> 1080 us, verify 3000 -> 5070 us --
TWICE as slow.  Root cause: the 12-limb result assembly needs ~22
bignum ash/add allocations per multiplication (1454 bytes/mult measured
vs 498 for generic `mod`), so the fold trades one ~0.5 us division for
~1 us of allocation churn.  An early microbenchmark claiming 2.7x was
an artifact (short loops under the wall-clock granularity plus
optimizer effects); the allocation count and the full sign/verify A/B
are decisive.  Reverted.

Lesson: count allocations, not just instructions -- on SBCL a bignum
division conses less than a "division-free" fold that assembles its
result limb by limb.  The durable fix for P-384 is a full limb field
(keep residues as limb vectors between ops, convert only at encode/
decode, as P-256/ed25519 do), not a bignum-in/bignum-out fold.  That
is a large rewrite; deferred.  P-384 sign already beats C (0.65x);
verify stays 4.2x.

## Update (variable-modulus Montgomery VOPs, this session)

RSA/DSA/DH/ElGamal modexps were Barrett-bound: barrett-mul does three
full multiplications plus normalization per op, and power-mod showed
94% in bignum multiply/normalize on RSA-verify.  A CIOS Montgomery
multiply needs one multiply-accumulate per limb pair with no bignum
allocation at all -- but only if the limbs stay unboxed, i.e. assembly.

Added `define-mont-mul-vop` (macro generating the unrolled CIOS form
from the proven P-256 separated-operand pattern: memory scratch TMP,
untagged N0 word, final conditional subtract with add-back) plus fndb
entries, instantiated for N = 16/32/48/64 limbs (1024/2048/3072/4096
bits).  math.lisp gained portable limb conversions, Newton N0, a
sliding-window Montgomery exponentiation driver reusing one scratch
vector, and a power-mod dispatch gate (SBCL+x86-64+assembly, odd
modulus, 512..4096 bits; everything else keeps the Barrett path, and
non-SBCL Lisps never see the VOP functions).

Validation: VOP bit-exact vs `mod` on 280+ random odd moduli per size
plus convert-out/edge cases (0 failures); driver bit-exact vs expt-mod
on 120 random moduli 512..4096 bits plus edges (0 failures); full SBCL
suite green with the dispatch active (so RSA/DSA/DH/ElGamal/primality
all exercise it).  Non-SBCL behavior is unchanged (reader-conditional
exclusion, verified by construction; ECL/CCL re-validation pending).

  mont-mul per-op:    ~1.6 us (2048-bit) vs ~4-9 us Barrett (2-3x)
  rsa-verify (2048):  160 -> 60 us
  rsa-sign (2048):    ~2700 -> 800 us (CRT halves, n=16 VOP each)
  dsa sign/verify:    measured faster (key-size caveat: verify path
                      uses power-mod2, still Barrett -- re-measure
                      at 2048-bit before claiming)
  whirlpool (bonus, same session): safety-0 on update-whirlpool-block,
  19.5 -> 29.3 MB/s (1.5x; remaining gap is structural table-driven
  work, deferred).

Two negative-result notes from the same session (kept out of the tree):
P-521 verify via destination-passing was considered but its cost is
bignum math, not allocation shape (limb field is the real fix);
P-384 Solinas fold and Keccak/u32 and Falcon/workspace experiments all
reverted with findings logged above.

## Update (Montgomery drivers for expt-mod/power-mod2, this session)

Follow-up to the CIOS VOPs: the sliding-window driver only covered
power-mod's bignum-exponent path.  Added montgomery-expt-fixed (fixed
4-bit windows with full table scan, mirroring expt-mod's side-channel
posture exactly) gated in expt-mod, and montgomery-expt-shamir gated
in power-mod2.  Both differential-tested vs the Barrett paths on small
moduli plus cl:expt on gated sizes (0 failures); full suite green.

  dsa-sign (2048):   966 -> 400 us (2.4x; fixed-window driver)
  dsa-verify (2048): 1333 -> 800 us (1.7x; Shamir driver)
  dsa gaps now ~1.6x/~3.7x.  DSA-verify is mult-count-bound (~390
  n=32 mults x 1.6 us); windowed Shamir was analyzed and rejected
  (table cost exceeds the savings for two bases).

Note: DSA-sign/verify use expt-mod/power-mod2, not power-mod -- an
earlier A/B confusion (1024-bit vs 2048-bit keys) briefly suggested
larger wins; the numbers above are apples-to-apples at 2048-bit.

## Update (ECL SLH-DSA-128s sign hang: pre-existing, this session)

While validating rev 1048 on ECL, the full suite stalled at
:ml-dsa-signature output (i.e. inside the following SLH-DSA vectors):
an isolated ECL SLH-DSA-SHA2-128s sign runs 0.1 s keygen then never
finishes (>11 min CPU, still going when killed), while SBCL signs in
0.7 s and ECL signs the -128f variant instantly.  SBCL 128s/128f ratio
is ~14x; ECL's is effectively infinite -- an ECL-specific pathology
or infinite loop in the -s hypertree/FORS path, not mere slowness.

Proven pre-existing and unrelated to this session: the identical hang
reproduces on a pristine rev 1042 checkout (before all Montgomery/VOP
work), and SLH-DSA signing on ECL executes byte-identical code in both
revs -- hash-based, no modexp, VOPs and math.lisp additions are
reader-excluded on ECL, whirlpool is unused by SLH-DSA.

ECL validation status: per-key vectors all pass on rev 1048 (rsa,
elgamal, dsa, ed25519, ed448, secp224r1/256k1/256r1/384r1/521r1,
ecdsa, dh-secp384r1/521r1, ecdsa-dh, ml-dsa vectors, KATs); the full
suite runs clean through ML-DSA-SIGNATURE and stalls only at the
SLH-DSA fresh-sign vectors above.  CCL/ABCL smoke checks still pending.

## Update (P-521 limb field, phase 1: field layer done, this session)

P-521 verify (3400 us, 5.7 MB/op) is 80% bignum double/add with only
~28% in raw multiplies -- the cost is allocation, normalization, and
dispatch, not the Mersenne fold (already division-free).  A 9-limb
Montgomery field reuses the CIOS VOP macro (n=9 instantiation) plus
new 9-limb add/sub VOPs; all intermediates stay unboxed.

Phase 1 (field primitives) is done and validated bit-exact vs the
bignum ops (roundtrip/add/sub/mul/sq/inv, 0 failures): fe-mul 160 ns
vs mulmod 360 ns (2.25x), fe-add 80 ns vs addmod 160 ns (2x).
Along the way: the new fe-from-int initially failed because SBCL 2.6.7
miscompiles (LDB (BYTE 64 (* I 64)) V) with a constant dotimes bound
at safety 0 (unrolled by hand, as P-256 does); a hand-written prime
limb table used a 57-bit top limb instead of 9 bits (0x1FF) -- caught
by the differential test; and the first Fermat loop mixed LSB/msb
order (caught ditto).

Phase 2 (point layer on limbs: double!/add!, Shamir/ladder, tables,
conversions at encode/decode) remains.  Projected verify 3400 ->
~1800 us.

## Update (P-521 limb field, phase 2: point layer + verify, this session)

Phase 2 adds destination-passing limb point ops (double!/add! mirroring
the bignum Jacobian formulas, validated bit-exact), limb window tables,
a limb Shamir-mult with cached G table, and wires VERIFY-SIGNATURE
through them (limb Shamir + bignum destructure/encode).

Along the way: the first Shamir had two canceling paren bugs (missing
loop close masked by an extra table close); a `y3 = rr*(v-x)` used the
squared register instead of r (caught by differential test); the
infinity representation had to be unified to all-zero limbs (the
bignum (0,1,1) placeholder is not recognized by the z=0 check);
and several test-harness bugs (naive projective comparison without
z^2/z^3, which falsely "failed" correct code).
Verified: field 0 failures, double/add 0 failures (30 each),
tables bit-exact, Shamir 0 failures (20), full sign/verify vectors pass.

  secp521r1 verify  3400 -> 1600 us (2.1x), 5.7 -> 0.4 MB/op (14x)
  (gap ~5.6x -> ~2.6x; remaining ~1200 us is ~7000 VOP mults at
  ~160 ns plus the bignum Fermat inverse in destructure)

## Update (P-384 limb field + verify, this session)

Mirrored the P-521 limb-field pattern for P-384 (6 limbs, n=6 CIOS
VOP + 6-limb add/sub VOPs, Montgomery field ops, destination-passing
Jacobian double!/add!, 5-bit Shamir with limb window tables, verify
through limb Shamir + bignum destructure).  Every layer
differential-tested vs the bignum code (field/add/sub/mul/sq/inv,
double/add, window table, Shamir: 0 failures).

Along the way: a hand-written prime limb had 14 hex digits instead of
16 (0xfffffffffffffe vs 0xfffffffffffffffe -- caught by differential
test); the Shamir needed the same (0,0,0) infinity convention and loop
close as P-521; and a projective-equality test bug (missing z^2/z^3)
initially "failed" correct code.

  secp384r1 verify  3000 -> 840 us (3.6x)
  (gap ~4.26x -> ~1.2x; remaining ~840 us is ~7000 VOP mults at
  ~80 ns plus the bignum Fermat inverse in destructure)

## Update (non-SBCL validation of limb work, this session)

The P-521/P-384 limb field added #-fallback paths (bignum-based) that
SBCL never executes, so they were validated on the other Lisps:
- CCL: P-521/P-384 signature + DH vectors, SHA3 KATs, RSA/DSA verify
  vectors -- all pass.
- ABCL: P-521 and P-384 sign/verify roundtrips -- pass.
- ECL: per-key vectors pass (rsa, elgamal, dsa, ed*, secp*, ecdsa,
  dh, ml-dsa); full suite still blocked on the pre-existing SLH-DSA
  sign hang (baseline rev hangs identically; hash-based, unrelated).
SBCL full suite green with limb verify active (677/677 + new paths).

## Update (P-521 limb sign, this session)

Wired SIGN-MESSAGE through the limb positional base table (66 rows x
256, converted once from the validated bignum table): 66 limb adds, no
doublings, destructure via the bignum addition-chain inverse.
Differential-tested base-mult-limbs vs bignum base-mult (20 random +
0/1/l-1 edges, projective equality, 0 failures).  Along the way fixed
a wrong infinity init in the new accumulator ((0,R,R) is affine (0,1),
not infinity -- must be all-zero limbs for the z=0 check).

  secp521r1 sign  1920 -> 480 us (4.0x)
  (remaining ~480 us is ~66 VOP adds plus nonce HMAC, scalar invs,
  and the destructure inverse)

## Update (P-384 cached G table + P-521 limb sign validation, this session)

P-384 verify now uses a cached limb G window table (same pattern as
P-521), instead of rebuilding the generator table on every verify.
Differential coverage unchanged (tables/Shamir validated bit-exact);
P-384 sig/DH vectors pass.
Full SBCL suite green with P-521 limb sign active (rev 1056).

## Update (SHA-1 SHA-NI, this session)

SHA-1 single-block compression via SHA-NI (sha1rnds4/nexte/msg1/msg2),
mirroring the sha256ni pattern: runtime dispatch on sha-ni-supported-p,
portable path unchanged.  The VOP was validated three ways before
landing: instruction semantics probed empirically with GAS test
binaries (including discovering that the message words must be
lane-reversed with pshufd, not byte-reversed with pshufb, because the
block holds u32 values); the schedule pairing (MSG1 + PXOR + MSG2,
from the Intel whitepaper flow confirmed against OpenSSL's
register usage) verified symbolically end-to-end (KAT digest from the
models); and a GAS prototype KAT-tested (empty/abc/56-byte/2-block)
before transcribing bytes to the VOP.  Along the way: my byte-level
KAT expectations had typos (9c vs 9d nibbles) -- always verify KAT
vectors against hashlib, not memory.

  sha1 8k-block  513 -> ~1560 MB/s (3.0x, gap 3.14 -> ~1.0)

## Update (SHA-1 NI validation, this session)

SHA-1 NI VOP validated on all Lisps: SBCL KATs (empty/abc/56-byte/
1000xa/incremental, 0 failures) + full SBCL suite green; CCL digest
vectors pass (sha1, sha256, sha512); ABCL sha1("abc") roundtrip passes.
The NI path is SBCL-only (#+(and sbcl x86-64 ironclad-unsafe-assembly)
with runtime sha-ni-supported-p dispatch); other Lisps use the
unchanged portable path through the same sha1-compress-block wrapper.

## Update (AES-CTR eight-wide pipelining, this session)

AES-CTR did one AES-NI VOP call per 16-byte block (latency-bound).
New 8-wide pipelined VOP encrypts (and xors) eight counter blocks per
call with all eight AESENCs of a round issued back-to-back, plus an
AES-specialized CTR fast path that batches counter blocks (the generic
loop is untouched; other ciphers and non-NI Lisps use it via
call-next-method).  Validated bit-exact vs single-block (8-wide output
== eight single-block outputs), plus length/keys/streaming/GCM
roundtrips (0 failures) and the AES/CTR vectors; full SBCL suite green.

Along the way: the new fndb entry first used bare
simple-array-unsigned-byte-8 (unknown in sb-c -- copy the
aes-ni-encrypt entry's full type specifiers instead); a (integer 0 14)
declaration on n-rounds was needed for VOP translation to kick in;
and single-block reference tests must not write through subseq copies
(the writes vanish -- compare via temp buffers).

  aes-ctr-8k  ~195 -> ~1257 MB/s sustained (6.4x on the CTR kernel;
  CTR-mode gaps all move; GCM lifted via CTR)

## Update (ChaCha 2-wide pipelining, this session)

ChaCha did one SSE VOP call per 64-byte block (call overhead plus
exposed AESENC-style latency, here for the quarter rounds).  New
two-wide pipelined SSE VOP does two consecutive blocks per call
(rounds for both blocks issued back-to-back so the independent chains
overlap), xoring into the output in the same pass.  Integrated as a
bulk section in chacha-crypt using a staged second state (counter+1),
with the generic loop handling partials and remainders; only the
three standard core functions take the bulk path (anything else uses
the generic loop).  Validated bit-exact vs single-block plus
length/variant/streaming roundtrips (0 failures); full SBCL suite
green; CCL/ABCL pass (portable path).

Along the way: my byte-level KAT expectations again had typos --
always verify against hashlib, never memory; and SBCL hoists/CSEs
VOP calls in microbenchmarks (0.0ns readings), so only sustained
integrated runs and the official harness count.

## Update (Poly1305 VOP attempt REVERTED -- negative result, this session)

Attempted a donna-32 single-block Poly1305 VOP (GPRs + XMM products,
mirroring the ECL C reference exactly) plus a batched variant, with a
separate non-inlined driver loop.  Findings:

- Register pressure is the wall: ~16 live GPR TNs plus pinned rax/rdx
  plus call args exceed the packable set ("failed to pack Load-TN").
  Fixed by keeping the five 64-bit s values in XMM regs (only t0,t1,u,u5
  live as GPR temps) -- then it packs and builds.
- Correctness was earned the hard way: an rr0 bug ((r0<<2)+(r0>>2)
  instead of ((r0>>2)<<2)+(r0>>2)) passed single-block tests silently
  because s4=0 kills the term when hibit=0; only a VOP-vs-generic
  differential over multi-block inputs caught it (40/40 match after fix,
  repo poly1305 vectors pass, suite green).
- Performance is NEUTRAL: batched VOP (one call per 16K blocks) measures
  1250 MB/s, identical to the generic Lisp loop.  SBCL already keeps the
  whole donna-32 chain in unboxed u64 registers (both paths cons ~0
  bytes/op), so the VOP body does the same work for the same cost; the
  r-from-memory-per-term reloads erase any edge.  Batching amortized the
  call overhead but the loop body itself is the bound in both versions.
- REVERTED all Poly1305 assembly (VOP + driver + fndb entry) rather than
  land ~250 lines of asm for zero gain.  Generic path holds 1.25 GB/s.
  Lesson: for tight integer loops SBCL safety-0 output is already near
  optimal -- verify with A/B (alternating, warmed, allocation-checked)
  before investing in VOP work; single-run numbers lie (cold pages,
  dead-code elimination to 0.0ns readings).
- Also fixed along the way: my byte-level KAT expectations twice had
  typos -- always verify KAT vectors against hashlib/repo testvecs,
  never memory; and ABCL defun-wrapper load quirk (validate via flat
  forms instead).

## Update (hygiene + reassessment, this session)

Removed a duplicated `chacha-core-2x` defknown entry (and tripled
`#+x86-64` prefix) in fndb.lisp left over from VOP splice work, plus a
trailing-newline fix in x86oid-vm.lisp.  No functional change; build
ok, cipher/mac/mode/digest vectors pass (poly1305, chacha, aes, ctr,
sha1, all T).

Reassessment after the Poly1305 revert: the remaining public-key gaps
(P-256 verify 4.07, ed448 verify 4.19, RSA verify 3.78, DSA verify
5.28) sit at their VOP floors -- field/mult code is already assembly
with unboxed inner loops (verified by disassembly/sprof: time is in
MONT-MUL/DOUBLE, formulas already use a=-3/optimal chains).  Whirlpool
(5.92) benchmarks against OpenSSL's hand-tuned asm -- out of reach for
a declaration-level fix (u8 index declares measured neutral).  The
chacha-poly composite gap (5.86) exceeds its components' serial sum,
but the box is currently under heavy external load (3 foreign CCL jobs,
load ~7.6), so all new microbenchmarks are contaminated -- no perf
conclusions until load subsides; trust only the official table.
Next tractable directions when clean: GHASH aggregation (carryless
4-way, precedent: AES-CTR 8x), P-256 GLV endomorphism (high risk), or
ML-DSA scatter work.

## Update (GHASH four-way aggregation, this session)

GCM's remaining cost after the AES-CTR pipelining was GHASH (781 MB/s
solo vs CTR at 1.26 GB/s), one multiply-and-reduce per 16-byte block.
New gmac-mul-4-fast VOP processes four blocks per call: the accumulator
and three data blocks are multiplied by H^4, H^3, H^2 and H^1, the four
256-bit carryless products are xored (field addition) and the sum is
reduced once.  Valid because the field multiply is bilinear and
reduction is linear, so sum-then-reduce equals the four
multiply/reduce steps while saving three reductions.  H^1..H^4 are
precomputed at key setup by four calls to the already-validated
single-block multiply; the data blocks are byte-reversed into the
reflected domain with one pshufb against a 16-byte reversal mask.

  GHASH (solo)  781 -> ~1130-3900 MB/s (2.5-4x in alternating A/B)
  gcm encrypt   380 -> 641 MB/s (gap 3.96 -> 2.08)

GCM is now CTR-bound: the new serial figure (1/641 = 1/1475 + 1/1130)
matches the measured CTR, so further GCM gains need more CTR width or
cheaper GHASH reduction, not more aggregation depth.

Validation: 4-way vs 1-way differential over 27 lengths plus AAD
variants (0 failures, tags byte-identical), repo gcm/gcm-siv/eax/ccm
vectors pass, full SBCL suite green, CCL gcm+gcm-siv pass, ABCL GCM
roundtrip passes.  *gmac-4x-enabled* forces the one-block path for
validation.  VOP notes: ea takes a register index only, so constant
slot offsets must be folded into the displacement (indexed-mem vs
const-mem helpers); defconst takes no docstring in this codebase.

## Update (Keccak output squeeze, this session)

Profiling ML-DSA-44 verification showed 43% in Keccak, with
KECCAK-STATE-EXTRACT-OUTPUT alone at 25.7% -- far too much for a
squeeze path, since verification only squeezes a few kilobytes.  Cause:
the byte-packing loop used a variable shift position, `(ldb (byte 8 (* 8
i)) ...)` with I a loop variable, and the STATE argument had no type
declaration, so SBCL fell back to generic arithmetic and generic aref.
Rewrote it to declare the state as a keccak lane vector and store the
eight lane bytes with constant shift counts (put 0 0 lo) .. (put 7 24
hi), keeping the existing absolute-offset scatter and the per-byte limit
check.  Same lesson as the earlier limb-split work: hand-unroll variable
shift positions at safety 0.

  ml-dsa-44 verify   2835 -> 3605 ops/s (gap 4.73 -> 3.66)
  ml-dsa-87 verify   1035 -> 1305 ops/s (gap 4.86 -> 3.83)
  slh-dsa-shake-256f sign  gap 2.86 -> 2.50
  slh-dsa-shake-256s verify gap 2.83 -> 2.41
  (extract-output share of a verify fell 25.7% -> 6.3%)

The fix is in the shared Keccak squeeze, so it lifts every SHAKE
consumer: all thirteen SLH-DSA-SHAKE rows, KMAC, cSHAKE and the ML-DSA
keygen/sign paths.

Validation: SHA-3/SHAKE KATs against hashlib including a 200-byte
multi-chunk squeeze (exercises the partial-chunk path that was changed),
full SBCL suite green, CCL sha3/256 and shake128 KATs pass.  Note the
digest names are :sha3/224, :sha3/256, :sha3/384 and plain :sha3 for
512 (a dash name raises unsupported-digest), and SHAKE output length is
a make-digest :output-length initarg, not a digest-sequence keyword.
Remaining ML-DSA verify cost is now NTT/INVNTT/pointwise (~49%), which
needs a limb or SIMD NTT rather than a Lisp-level fix.

## Update (McEliece keygen row xor, this session)

Profiling mceliece348864 keygen put 72% in MCE-PK-GEN (the Gaussian
elimination that brings the parity-check matrix to systematic form).
The row xor inner loop was already 64-bit-word based but scalar; new
mce-xor-words VOP does sixteen bytes per step (movdqu/pxor/movdqu) with
a scalar tail, wrapped in an inline mce-row-xor! that keeps the portable
loop for other Lisps and non-assembly builds.  Both elimination passes
(forward reduce, then reduce every other row) use it.

Honest result -- the loop is memory bound, so the win only appears when
rows are long enough to matter:
  mceliece8192128 keygen (1 KiB rows) 2.67 s -> 2.27 s  (~15%,
    fixed-seed A/B, three VOP samples vs two portable samples)
  mceliece348864 keygen (440 B rows) neutral (~95 ms both ways)
The official table rows for McEliece keygen swing 30%+ between runs
because keygen has a rejection loop over random seeds, so treat those
numbers as indicative only; the fixed-seed A/B above is the real
measurement.

Correctness: keygen is deterministic from a seed, so the strongest test
is cross-implementation -- the same seed was run on SBCL (VOP path) and
CCL (portable path) and produced byte-identical public and private keys
for mceliece348864 and mceliece8192128, with a full encapsulate/
decapsulate roundtrip on each.  The repo McEliece vectors only cover
encapsulation/decapsulation, so they would not have caught a keygen
regression -- worth remembering for future keygen work.  Full SBCL
suite green.

Notes: the VOP needs positive-fixnum args, so the callers' W and
WORDLEN had to be declared index rather than fixnum for translation;
and ea takes base/index/scale plus a constant displacement, so the row
pointers are formed with lea and then advanced by 16.

## Update (ML-DSA helper type declarations, this session)

After the Keccak squeeze fix, profiling ML-DSA-44 verify showed about a
tenth of the time in *generic* array access
(VECTOR-HAIRY-DATA-VECTOR-REF/SET).  The cause was simple: the whole
ml-dsa-vec-* family and the pack/unpack helpers had no type
declarations, so every `(aref v i)` on a polyvec and every byte access
in the 13-bit t0 and 18-bit z (un)packers went through the generic
vector path.  Added declarations to 26 functions: polyvec arguments as
simple-vector with fixnum counts, polynomials as ml-dsa-poly, and octet
buffers as (simple-array (unsigned-byte 8) (*)).

Fixed-seed A/B on verify: min 320 -> 293 us, typical 333 -> 307 us
(~10%).  Because the same helpers serve key generation and signing, the
table moved everywhere:

  ml-dsa-44 verify gap 3.72 -> 2.00      ml-dsa-44 keygen 4.17 -> 1.80
  ml-dsa-65 verify gap 3.74 -> 3.06      ml-dsa-65 keygen 3.35 -> 2.34
  ml-dsa-87 verify gap 3.50 -> 1.87      ml-dsa-87 keygen 3.86 -> 1.74
  ml-dsa-44 sign   3.14 -> 0.76 (ahead of C)
  ml-dsa-65 sign   3.14 -> 1.64          ml-dsa-87 sign 3.14 -> 1.73

Two declaration mistakes were caught by the vectors before landing, and
both are the same trap: a blanket "declare every parameter" pass guessed
(a) gen-matrix has no parameter named A at all (it binds A locally), and
(b) the single poly scalars passed to vec-pointwise (and the 2-D matrix
in matrix-row) are not simple-vectors.  Declarations are promises, and
at safety 0 a wrong one is undefined behaviour rather than an error --
check each parameter against the body, do not infer from the name.

Validation: ml-dsa vectors pass (44/65/87), full SBCL suite green, CCL
ml-dsa vectors pass.  Remaining ML-DSA time is NTT/INVNTT (44% of a
verify) and Keccak (24%), both of which now need SIMD or Montgomery-NTT
restructuring rather than declaration work.

## Update (modular-inverse dispatch, this session)

While looking at EC verify, I timed the two modular-inverse
implementations in isolation and found the dispatcher had been picking
the slow one for every odd modulus:

  256-bit modulus:  binary GCD 30.7 us   Euclidean 2.7 us   (11x)
  2048-bit modulus: binary GCD 480 us     Euclidean 20 us    (24x)

The binary (division-free) inverse needs O(bits) bignum shifts and
reductions, each allocating; the Euclidean one needs O(bits) bignum
divisions, and SBCL's division is far better than its shift/reduce
chain.  modular-inverse now always uses the Euclidean path (which
already returns 0 for a non-invertible input, so the contract is
unchanged).  modular-inverse-binary is left in place, documented, and
no longer dispatched to.

  dsa verify  1.000k -> 1.595k ops/s  (gap 3.41 -> 3.30)
  dsa sign    1.350k -> 2.100k ops/s  (gap 3.38 -> 2.18)
  secp256r1 verify  4.465k -> 4.670k  (inverse is ~12% of a verify)
  rsa keygen: saves ~460 us of the phi inversion (small next to the
  prime search)

EC and DSA signing already went through modular-inverse-with-blinding,
which calls the Euclidean inverse directly, so signing there was
unaffected -- that is why only DSA (whose sign path uses the plain
inverse) moved so much.

Validation: rsa-sig, dsa and all five ECDSA signature vector sets pass;
full SBCL suite green.  Note the benchmark's C-reference figures move
10-40% between runs on this (loaded) machine, so compare absolute
Lisp ops/s rather than the gap column.

## Update (octets-to-integer chunking, this session)

Profiling RSA-2048 verify showed 24% in SB-BIGNUM::BIGNUM-ASHIFT-LEFT-ADD
plus 10% in BIGNUM-TRUNCATE, i.e. outside the exponentiation.  Direct
measurement pinned it: OCTETS-TO-INTEGER took 11.8 us for a 256-byte
input, because it accumulated one byte at a time with (ash sum 8), which
reallocates the whole bignum per byte -- quadratic in the input length.
Rewrote the big-endian branch to consume eight bytes (64 bits) per step
and or the chunk in at its bit position; the little-endian branch is
unchanged (it already shifts by a byte position and is not hot).

  octets->integer 256 bytes   11.8 us -> 3.8 us (3x)
  octets->integer 32 bytes     0.8 us -> 0.6 us
  rsa verify                  60-70 us -> 50 us
  rsa verify table            17.94k -> 21.08k ops/s (gap 3.62 -> 3.20)

This helper is on every signature and key parse, so EC and DSA paths get
a small share of it too.

Validation: full SBCL suite green (which covers all the signature, key
and padding vectors that depend on this conversion).

## Update (sparse-exponent modexp, this session)

MONTGOMERY-EXPT always built a sliding-window table, sized from the
*length* of the exponent.  For RSA verification, where e = 65537 is a
seventeen-bit exponent with two bits set, that table costs 2^(k-1) = 4
multiplies to build plus a squaring, so the whole function did about 22
Montgomery multiplies where plain left-to-right square-and-multiply
needs 17.  Added a sparse-exponent path, taken when
(logcount exp) <= 2^(k-1): res := ar, then square once per remaining
bit and multiply by ar for each set bit.

  rsa verify  50 us -> 40 us (21.08k -> ~26k ops/s expected)

Not a side-channel regression: MONTGOMERY-EXPT is reached only from the
public drivers (POWER-MOD and MONTGOMERY-EXPT-SHAMIR, i.e. verify and
public-key operations).  The fixed-window, full-table-scan variant that
private key operations use, MONTGOMERY-EXPT-FIXED via EXPT-MOD, is
untouched and its cost still does not depend on the exponent's weight.

Validation: dsa and rsa-sig vectors pass, full SBCL suite green.

## Update (McEliece matrix bit-plane packing, this session)

Instrumenting keypair generation showed it is dominated by retries, not
by one slow pass: the systematic-form transform only succeeds when the
top-left block is invertible (about 29% of the time for a random binary
matrix), so mce-pk-gen runs ~4.8 times per keygen at ~38 ms each, and
mce-genpoly runs as often at ~3.4 ms.  A direct micro-benchmark then
isolated the matrix build inside mce-pk-gen: 20 ms of that 38 ms, because
it packed each bit plane byte with a chain of (ash b 1) plus a
variable-position (ldb (byte 1 k) ...) over eight elements.

Rewrote it to load the eight elements once and build the byte with a
single or-tree of (logand 1 (ash v shift)) terms -- 2.4 ms instead of
20 ms in the micro-benchmark (8.3x).  Bit order matters: the original
chain shifts the *last* element in first, so inv[j] ends up in the LSB,
not the MSB; my first attempt had it reversed and produced valid-looking
but different keys.  The cross-implementation check caught it
immediately (see below).

  mceliece348864 keygen 3.73 -> 9.09 ops/s (gap 7.71 -> 2.76)
  mceliece6688128 keygen                     (gap 0.40, ahead of C)
  mceliece8192128/6960119 keygen             (gap 1.74 / 1.03)
  rsa verify            21.08k -> 27.78k ops/s (gap 3.20 -> 2.21,
                        the sparse-exponent change from the same session)

Validation, and why it is trustworthy: keygen is deterministic from a
seed, so the same seed was run on SBCL (VOP path) and CCL (portable
path) and had to produce byte-identical public and private keys -- it
does, for mceliece348864 and mceliece8192128, with an encapsulate/
decapsulate roundtrip on each.  The repo McEliece vectors only exercise
encapsulation, so they would not have caught this class of change; the
differential against the other Lisp's code path is the real gate.
Full SBCL suite green.

Remaining McEliece keygen cost is the elimination itself (now SSE) and
the per-row GF multiply; the retry factor of ~4.8 is inherent to the
algorithm and is paid by the C reference too.

## Update (Falcon NTT/decompress declarations, this session)

Falcon-512 verify was 140 us with 52% in falcon-ntt/falcon-intt, but a
further ~11% sat in generic array access *with* bounds checks
(VECTOR-HAIRY-DATA-VECTOR-REF/CHECK-BOUNDS) and GENERIC-*.  Same story
as the ML-DSA sweep: several hot functions used arrays they never
declared.

Declared the working/typed arrays that are local to each function and
therefore certainly simple and fixnum-typed:

  falcon-ntt / falcon-intt      the scratch A (and kept B for the plan
                               arrays); NOT the caller-supplied input,
                               because some callers pass a differently
                               typed vector and a wrong promise here is
                               UB at safety 0 -- the first attempt did
                               exactly that and raised a type error.
  falcon-decompress             ENC (octet vector) and V (fixnum), which
                               removed most of the generic access
  falcon-mul-ntt / falcon-sub-zq  operands and result

  falcon-512 verify  140 -> 124-128 us  (7.07k -> 8.18k ops/s,
  gap 3.61 -> 3.16)

Validation: falcon-512 and falcon-1024 roundtrips pass (0 rejections of
valid signatures, 0 acceptances of a tampered payload); the falcon
testvecs and the full SBCL suite are green.  Note that flipping the last
byte of a Falcon signature is *not* a valid negative test -- the
compressed encoding has trailing padding bits, so such a signature still
verifies by design; tamper in the payload instead.

## Update (CCM CBC-MAC loop, this session)

CCM was 229 MB/s with the pieces not adding up: a single AES-NI block
costs 20 ns, so the serial CBC-MAC for 512 blocks should be ~10 us and
the payload CTR (which already uses the eight-wide path) ~4 us, against
42 us measured.  The gap was the MAC loop: it called
ccm-cbc-absorb-block once per block, and each call re-fetched the chain
and the ECB cipher through accessors and re-tested the "is DATA a simple
array" flag.

Restructured ccm-cbc-feed to hold the chain, the ECB cipher and the
simple-array flag in locals, absorb whole blocks in a tight loop (xor128
plus aes-encrypt-block, no per-block call or accessor), and keep the
byte-at-a-time pending buffer only for a trailing partial block.  The
streaming semantics are unchanged: a partial block left by an earlier
call is still completed first, and the pending buffer still only grows
when fewer than sixteen bytes remain.

  ccm encrypt  229 -> 390 MB/s (2x), gap 3.46 -> ~1.7

Validation: CCM roundtrips at twelve lengths including partial blocks
and AAD (0 failures), repo ccm vectors pass, full SBCL suite green, CCL
ccm vectors pass.  (Note gcm/gcm-siv re-checked on CCL too, unaffected.)

Measurement note: my first pass at this looked for the missing time with
the profiler and with small-n timings and got 20 us for both phases,
which was an artefact -- 200 iterations of a 4 us operation is only eight
hundred ticks, and the first call is cold.  Use n in the thousands for
anything in the microseconds range.

## Update (AES ECB eight-wide, this session)

The generic ECB loop encrypts one block per VOP call, so each block pays
the full AESENC latency chain (~20 ns a block, 558 MB/s) even though the
blocks are independent -- the same problem the CTR mode had before the
eight-wide pipelining.  Added aes-ni-encrypt-8x, a copy of the CTR VOP
without the counter bookkeeping and without the final plaintext xor, and
an AES-specialized ECB method that uses it for whole 128-byte groups and
falls back to the generic per-block call for the remainder.

The method only takes the fast path when there is no padding, because
the padding and final-block logic lives in the generic ECB lambda; with
padding it defers with CALL-NEXT-METHOD, and the generic decrypt lambda
is returned unchanged.

  aes ecb 8k    558 -> ~1300-1950 MB/s (2.3-3.5x, loaded machine)

Validation: byte-identical to the generic path across fifteen lengths
(0, 16, 17, 31, 32, 33, 64, 127, 128, 129, 144, 256, 1000, 8192, 8208)
driven by *aes-ecb-8x-enabled*, ECB roundtrips for 128/192/256-bit keys,
repo aes/ctr/gcm vectors, full SBCL suite green, CCL aes/ctr vectors pass.

Two traps worth recording.  First, I put (declare (dynamic-extent
#'aes-ecb-8x)) on the closure that is *returned* and stored in the mode
slot: it is stack allocated, so the caller got a dangling closure and
the next encrypt faulted at address 0.  Never dynamic-extent a closure
that escapes.  Second, an early version referenced a MODE-CIPHER-CHAIN
accessor that does not exist -- I had invented a guard instead of
reading the class.

## Update (SLH-DSA SHAKE hashing, this session)

SLH-DSA's SHAKE path called PRODUCE-DIGEST on a freshly built digest for
every hash, and PRODUCE-DIGEST copies the entire Keccak state (25 lanes
plus the 200-byte input buffer) before squeezing so that the caller can
keep squeezing afterwards.  For a throwaway state that copy was pure
overhead and dominated the cost: a 64-byte-into-16-byte SHAKE256 call
measured 2.0 us, of which the single permutation is 0.4 us.  SLH-DSA
makes ~287,000 such calls for one 128s keypair.

Switched the four SHAKE branches (thash, prf_addr, gen_message_random,
h_msg) to SHA3-FINALIZE directly, which squeezes in place; the same thing
ML-DSA already did.  The SHA-2 branches keep PRODUCE-DIGEST: they reuse a
cached template digest that must survive the call.

  slh-dsa-shake-128s keygen  704 -> 432 ms
  slh-dsa-shake-128s sign   4310 -> 3294 ms
  slh-dsa-shake-128s verify  4.35 -> 3.20 ms
  slh-dsa-shake-128f keygen  10.2 -> 8.0 ms, sign 204 -> 162 ms

Negative result worth recording: I then tried to merge the three
UPDATE-DIGEST calls (pub_seed, addr, data) into one absorb from a
concatenation scratch buffer.  It failed the SLH-DSA KAT, yet an isolated
A/B of "three updates" versus "one update of the concatenation" produces
identical SHAKE output, so the equivalence is broken somewhere I did not
find -- most likely a caller passing more bytes than the 160-byte scratch,
because CL's REPLACE truncates silently rather than erroring when the
destination runs out.  Reverted to the three-update form, which is proven.
Anyone retrying this should assert the total length against the scratch
size instead of trusting REPLACE.

## Update (Falcon modular arithmetic declarations, this session)

Falcon's integer NTT was 52% of verification and cost 50 cycles per
butterfly.  Bisecting the loop showed why: swapping falcon-mulmod for a
cheap mask multiply took the same loop from 47 us to 11 us, so the
modular multiply was ~36 us of it.  The cause was not the algorithm but
type inference: mulmod declared its operands plain FIXNUM, so SBCL
emitted overflow-checked multiplies (the products here reach 2^57, which
it cannot prove fits) and the whole cost of the function collapsed to
the check-and-box sequence.  Declaring the operands as
(integer 0 12288) -- reduced residues -- lets it prove every product
stays a fixnum, and the same for falcon-addmod/falcon-submod.

  falcon-ntt          33.6 us -> 11.2 us (3x)
  falcon-512 verify    143 us -> 76 us  (1.9x, gap 3.48 -> ~1.8)

Tried and dropped: unrolling the butterfly by two so the multiply chains
overlap.  It was worth 2% before the typing fix and nothing after, so it
was reverted rather than kept for complexity's sake.  Also tried the same
operand-bounding on ml-dsa-fqmul: no change (that code already masks its
intermediates with LDB and notes the 62-bit fixnum limit explicitly).

Validation: falcon-512 and falcon-1024 sign/verify roundtrips with 0
rejections and 0 tampered acceptances, the falcon keymat and signature
vector files pass (keymat is the strong one: it compares the derived f,
g, F, G bytes), full SBCL suite green.

## Update (SLH-DSA single-absorb: root cause found, still a loss)

Follow-up on the failed single-absorb experiment from the previous entry.
I had suspected silent truncation by REPLACE; adding an explicit length
assertion confirmed it exactly -- the assertion (<= POS 160) fires, so
some thash call passes more than the 160 bytes I sized the scratch for,
and REPLACE had quietly copied only the first 160.  With a 4096-byte
scratch the KAT passes, so the equivalence of "three updates" and "one
update of the concatenation" is fine after all.

But it is still not worth doing: a 4096-byte allocation per hash call is
worse than the dispatch it saves.  Measured with the bigger buffer,
128s keygen went 432 -> 542 ms (and sign 3294 -> 4184 ms), because
SLH-DSA makes ~287,000 calls and that is over a gigabyte of garbage.
The useful version of this idea needs a *persistent* scratch buffer in
the context (and a real bound on the concatenation length -- data can
clearly exceed 2n, which is what fooled me).  Reverted to the three-update
form.

Two lessons: REPLACE truncates silently, so assert the length when
pasting into a fixed buffer; and any per-call allocation in code that
runs hundreds of thousands of times per operation must be measured, not
assumed cheap.

## Update (Whirlpool table binding, this session)

Whirlpool ran the same 8-table lookup round as the C reference but at
roughly a fifth of its throughput, which did not add up: the work per
block is about 1400 table reads plus xors, so ~1 op per cycle would
already give more than we saw.  The tables +c-even+ and +c-odd+ are
DEFCONSTANT arrays, and a direct reference to a DEFCONSTANT object
reloads the array pointer from the symbol value cell on every access --
sixteen extra loads per slice, about 1400 per block on top of the loads
that do work.

Bound them to locals in update-whirlpool-block and passed the local names
through one-slice/lookup-in-c (they are macroexpanded, so the array
reference is now a plain load off a register-held pointer).

  whirlpool 21.7 -> 32.6 MB/s in a fixed harness (about 1.5x)

Validation: whirlpool digest and incremental vector files pass, full
SBCL suite green.

Still short of the C reference, and the rest is not symbol-cell loads:
the block is ~9500 Lisp operations of which the byte extractions are
already minimal (each of the 16 words' four bytes is extracted exactly
once per lookup-in-c call), so closing the remaining factor needs either
a tighter emit of the xor trees or the SSSE3 pshufb S-box rewrite.

## Update (McEliece cross-check widened; P-256 headroom measured)

Confirmation: the earlier McEliece keygen changes (SSE row-xor and
or-tree bit-plane packing) had only been differentially checked on two
parameter sets.  All five now produce byte-identical public and private
keys on SBCL (VOP path) and CCL (portable path) from the same seed --
mceliece348864, 460896, 6688128, 6960119 and 8192128.  This matters
because the repo's McEliece vectors only exercise encapsulation, so a
keygen regression would otherwise go unnoticed.

Measured the flagship field operation for the next piece of work:
secp256r1-fe-mont-mul-asm is 40 ns (136 cycles) for a four-limb
Montgomery multiply.  The op does 16 product mul-adds plus 8 reduction
mul-adds (P[2] = 0 makes one step a carry propagation and P[0] is
all-ones, so only P[1] and P[3] need multiplies) at about ten
instructions each -- roughly 240 instructions, so it is running at
1.76 IPC.  A hand-scheduled register-accumulator version should reach
2.5-3 IPC, i.e. ~25 ns, which would take P-256 verify from ~212 us to
~150 us (gap 3.9 -> ~2.9) and sign from 63 to ~50 us.  That is the
realistic ceiling without BMI2/ADX:  with MULX (and optionally
ADCX/ADOX) the same op should reach ~18 ns, but that needs a second VOP
plus a runtime feature gate, since the existing VOP is compiled in
unconditionally and must keep working on CPUs without those extensions.

Not attempted yet: it is a hand-written CIOS rewrite of a core ECDSA
primitive, and the honest cost/benefit at ~1.6x (plain) versus the
gating complexity of 2.2x (MULX) did not justify starting it at the end
of a long session.  The differential harness to do it safely is
straightforward, though: the new VOP can be compared against the
existing one over millions of random four-limb inputs, which is far
stronger than any KAT.

## Update (HQC: three generic-arithmetic bottlenecks, this session)

HQC was the worst-remaining gap that was not blocked on SIMD: decapsulate
120 ops/s against 400 for the C reference (3.34x) while encapsulate and
keygen were only 1.5-1.8x off.  Profiling by hand showed the extra cost
was not the KEM structure but three separate generic-arithmetic problems
in the decoder and multiplier, each of the same family as the Falcon and
Whirlpool wins.

1. hqc-gf-mul cost 800ns per multiply.  It was a constant-time carryless
   multiply written with generic arithmetic: a four-element scratch
   vector allocated per call, eight all-ones-mask helper calls, and a
   reduction loop built on a 14-iteration trailing-zero counter.  A
   multiply of two bytes should be a handful of instructions.  Replaced
   with a branch-free, table-free shift-and-add: eight iterations of
   square-and-reduce using a mask taken from the operand's own top bit.
   Still constant time and still no lookup table, but

     hqc-gf-mul   800ns -> 16ns   (50x)

   Verified exhaustively against the existing exp/log tables over all
   65536 operand pairs, not by sampling.  That check earned its keep: my
   first version reduced with 0x11B, the polynomial named in the file's
   own header comment, and 63232 of the 65536 pairs were wrong.  The
   exponent table is for x^8+x^4+x^3+x^2+1 (0x11D); the header comment
   was simply stale, and the original code's `(logxor #x11D 1)' had the
   right constant.  Fixed the comment too.

2. Karatsuba polynomial multiplication cost 1.2ms per 2216-byte
   multiply even with the PCLMULQDQ VOP enabled.  The recursion split
   its operands with displaced arrays, and a displaced array has the
   general type `(array (unsigned-byte 64) (*))', so every limb access in
   the whole recursion went through the generic AREF path instead of a
   single load.  Rewrote it to address operands by offset into the
   original simple arrays (and to return both halves of the 64x64
   product as values rather than through a scratch vector):

     hqc-vec-mul  1.20ms -> 0.37ms  (3.3x)

3. The Reed-Muller decoder cost 0.8ms of the ~1ms code decode.  It
   rebuilt a scratch vector for every one of the n1 bytes and unpacked
   each bit with a variable-position LDB (the same pattern that cost 8x
   in the Keccak squeeze).  Hoisted the scratch, replaced the LDB with a
   shift loop over the two words, hoisted the per-byte encoder scratch,
   and gave the Hadamard transform and peak search their real array
   types:

     hqc-rm-decode  800us -> 38us  (21x)
     hqc-rs-decode 3.48ms -> 0.12ms

End to end, measured in one process on this host:

  kind     decaps          encaps          keygen
  hqc-128  120 -> 714      345 -> 1042     825 -> 2500   ops/s
  hqc-192  57.7 -> 281     125 -> 417      265 -> 625
  hqc-256  28.3 -> 152     62.5 -> 234     142 -> 385

Every HQC row now beats its C reference.  Validation: all three
hqc-NNN.testvec key-encapsulation KAT files pass (reference-ciphertext
decapsulation, fresh roundtrip, tampered-ciphertext rejection), the same
files pass under CCL, which takes the portable bit-serial path instead
of PCLMUL, and the full SBCL suite is green.

One gap found while validating: the three hqc-NNN.testvec files existed
but were never wired into the test suite, so none of this was covered by
CI.  Added the three vector tests and a 2-key/50-trial roundtrip test per
parameter set to testing/test-vectors/public-key.lisp.

## Update (BIKE: the same three diseases, twice as bad)

BIKE has no C reference in the benchmark, so its rows never appeared in the
gap table -- but its absolute numbers were one to three orders of magnitude
worse than any reasonable implementation: keygen 1.9/s (0.52s), encapsulate
57/s (18ms), decapsulate 2.6/s (388ms) for bike-l1, and 4s keygen at
bike-l5.  Chasing those found exactly the same three problems as HQC, only
worse, plus a fourth in the decoder.

1. bike-mul-base was a bit-serial carryless multiply in generic arithmetic
   with an 8-element scratch vector allocated per call.  The 64x64 base
   multiply is now the shared PCLMULQDQ VOP (renamed from hqc-clmul64 to
   clmul64 since BIKE and HQC both use it); the portable path keeps the
   existing windowed constant-time routine, only returning values instead
   of writing a scratch array.

2. bike-karatsuba used displaced arrays for every split, so the whole
   recursion ran on the general `(array (unsigned-byte 64) (*))` type and
   every limb went through generic AREF.  Rewritten to address operands by
   offset into the original simple arrays, with the middle-term buffers
   kept in one shared scratch pool by offset rather than by displacement.

3. bike-gf2x-sqr allocated two vectors per 64-bit word (193 words at l1),
   and bike-gf2x-ksqr computed `(mod (* l idx) r)` -- a division -- for
   every one of the r output bits.  The square now uses one clmul per word,
   and the permutation position advances incrementally with a conditional
   subtraction.

4. The BGF decoder was the remaining 150ms of decapsulation.  Its hot
   loops (bike-rotr-big, bike-bit-sliced-adder, bike-slice-subtract and the
   byte accessors) took generic AREF on boxed 64-bit words, with bounds
   checks, and built its masks with (LOGNOT x) followed by a 64-bit AND,
   which materializes a bignum.  Declared the real array types, replaced
   the select with (LOGXOR a (LOGAND (LOGXOR a b) mask)), replaced the
   lognot-mask pairs with LOGXOR against all-ones, hoisted the slice lookup
   out of the per-byte loops, and made the threshold LSB mask arithmetic
   ((LOGAND (- (LOGAND val 1)) all-ones)) rather than a branch -- so the
   rewrite is also more uniformly constant-time than what it replaced.

Measured in one process:

  bike-l1  decaps  2.6 -> 98 /s    encaps   57 -> 926 /s   keygen 1.9 -> 227 /s
  bike-l3  decaps  0.79 -> 34 /s   encaps   18 -> 342 /s   keygen 0.63 -> 76 /s
  bike-l5  decaps  0.33 -> 15 /s   encaps  7.4 -> 138 /s   keygen 0.25 -> 33 /s

and the core operations:

  gf2x-mul (l1/l3/l5)  34.7 / 90.7 / 227 ms -> 0.20 / 0.56 / 1.38 ms
  gf2x-inv (l1/l3/l5)  560 / 1732 / 4400 ms -> 4.8 / 11.6 / 28.8 ms

Validation: all three bike-NNN.testvec KAT files pass (reference
ciphertext decapsulation, fresh roundtrip, tampered-ciphertext rejection),
the same files pass under CCL (portable bit-serial multiply), a differential
against a bit-level bignum reference for both the multiply and the square
over random reduced inputs is clean for all three parameter sets, and the
full SBCL suite is green.  Like HQC, the BIKE vectors existed but had never
been wired into the suite; the three KAT tests and a 2-key/20-trial
roundtrip per parameter set are now registered.

## Update (benchmark refresh; a note on host load)

Refreshed the table after the HQC and BIKE work.  HQC is now ahead of the C
reference on all nine of its rows (gaps 0.26 to 0.76) and the BIKE rows,
which have no C reference, now read 91/s decapsulate and 240/s keygen at
bike-l1 instead of 2.6/s and 1.9/s.

Caveat on this snapshot: the host was carrying a load average of about six
while the Lisp half of the benchmark ran, and every Lisp row came out 20-35%
below a repeat measurement.  For example the table's dsa-verify row reads
1.010k ops/s, while a fixed-input loop run straight afterwards measured
1543 ops/s (648us), which matches the previous table.  RSA verify moved down
by the same fraction although its code was untouched.  So read this
refresh's absolute Lisp numbers as a lower bound; the C reference column is
stable, and the gap ratios are correspondingly pessimistic.  The HQC and
BIKE improvements are large enough that they are unaffected.

## Update (AES-GCM-SIV: POLYVAL on top of GHASH, and two loop bugs)

The gap table has no C reference for GCM-SIV, so this was another row that
never showed up: AES-GCM-SIV encrypted an 8KB message at 1.0 MB/s, about a
thousand times slower than it should be.  There were four separate causes.

1. POLYVAL was implemented as a bignum bit-serial carryless multiply plus
   a term-by-term reduction, both in generic integer arithmetic: about
   8us per 16-byte block.  The fix is the one real implementations use:
   POLYVAL's field is GHASH's field with the coefficients reflected, so a
   byte swap maps one to the other, and POLYVAL's x^-128 factor folds into
   the key.  With the accumulator and key in byte-reversed order the
   recurrence is exactly

       S <- (S xor block) * (H * x^-1)

   so the tuned GMAC multiply VOP does the work and a block costs one XOR
   plus one PCLMUL sequence, with no bignum arithmetic at all.

   Getting there took a detour worth recording: the GMAC multiply is not a
   symmetric block multiply.  Its portable path and its PCLMUL path use
   *different* bit conventions, with the caller compensating by swapping
   blocks only in the PCLMUL path, so no choice of byte/bit order on the
   two operands made it look like a field multiply.  Swapping both operands
   *and* the result does: that is the map that turns it into the
   reflected-polynomial multiply, and with the key pre-scaled by x^-1 the
   loop falls out.  Verified against the old bignum implementation on 300
   random keys and message lengths before wiring it in.

2. gcm-siv-ctr built a fresh AES cipher object for *every 16-byte block*,
   so the key schedule was the cost of the loop.  It now sets up one cipher
   and encrypts eight counter blocks per call so the AES-ECB eight-wide
   fast path can pipeline them.

3. process-associated-data and encrypt/decrypt buffered input one byte at a
   time with VECTOR-PUSH-EXTEND.  They now grow the buffer once and use
   REPLACE.

4. Two bugs the vectors caught, both introduced by (3) and (2):
   - REPLACE on a fill-pointer vector only writes up to the fill pointer.
     Setting the pointer *after* the copy silently copied nothing, so every
     message authenticated as zeros.  The RFC C.2 vector (8-byte plaintext)
     caught it.
   - The eight-block counter path rebuilt the counters for each 128-byte
     chunk but never advanced the base, so the keystream repeated every 128
     bytes.  The 1000-byte generated vector caught it.  (The 8-byte vector
     passes either way, which is a good argument for keeping long vectors.)

  gcm-siv encrypt 8192   1.004 MB/s -> 136 MB/s
  polyval (8KB)          0.22 ms -> 0.016 ms

Validation: the gcm-siv vector file and its incremental variant both pass
under SBCL and CCL (which takes the portable POLYVAL path), and the full
SBCL suite is green.  Unlike HQC and BIKE, this vector file was already
wired into the suite -- the auto-generated per-mode AEAD tests cover it --
which is why the fill-pointer and counter bugs surfaced instead of shipping.

## Update (benchmark refresh after GCM-SIV)

Table refreshed.  gcm-siv encrypt 8192 now reads 155 MB/s (from 1.0 MB/s).
HQC holds at 0.49-0.59 against its C reference on all rows, and the BIKE
rows are unchanged.  The host load is still around five, so the absolute
Lisp numbers remain a lower bound; the 123 measured rows put 34 ahead of
the C reference and 67 within 2x this run, against 37/66 last run, which is
C-reference noise rather than movement in our numbers.

## Update (CIOS Montgomery multiply VOPs; RSA/DSA 13-20% faster)

RSA and DSA are almost entirely Montgomery multiplication, and the
existing mont-mul-N-asm VOPs used separated operand scanning: build the
full 2N-limb product into the scratch buffer, then make N reduction
passes over it, each with a carry propagation across the top half.  The
limb data crosses the memory interface several times per multiply.

Added a coarsely integrated operand scanning (CIOS) form for the same
four sizes (16/32/48/64 limbs).  It interleaves the multiplication and
reduction, keeps only an N+2-word rolling window, and shifts the window
down as each word is consumed, so each limb is loaded and stored about
once per outer step and the separate carry-propagation loop disappears.
The final conditional subtraction now tests the single overflow word
rather than the top of a 2N buffer.

  mont-mul-16   440ns -> 400ns   (n=1024-bit)
  mont-mul-32  1760ns -> 1440ns  (n=2048-bit)

  rsa verify  40.0us -> 32.0us  (min-of-4, interleaved A/B)
  dsa verify 616us   -> 520us
  rsa sign   952us   -> 832us

Both VOP families are kept and selected by *mont-cios-enabled* (default
on); the SOS code is the differential reference and the escape hatch.

Honest note on the size of the win: the target was the 2x that ADX gives,
and that did not materialise.  With plain MUL the carry chain through
`add rax,t[j]; adc rdx,0; add rax,carry; adc rdx,0' is serial and costs
about 2.4 cycles per limb-pair, which is where CIOS levels out; the memory
traffic SOS wasted was not the bottleneck.  Getting the other factor needs
MULX and the ADCX/ADOX dual carry chains (BMI2/ADX), and therefore a
second VOP plus a runtime CPU gate, since neither extension is part of the
x86-64 baseline.  That is the natural next step here, not another
rearrangement of the same scalar loop.

Validation: differential against the SOS VOPs over 120k+ random and
adversarial inputs (all-ones, top-limb-only modulus, m-1, 0, 1, small
values, and bulk random) at every size, with zero mismatches; the full
SBCL suite, which covers the RSA/DSA/DH vectors, is green.

## Update (benchmark refresh after CIOS; host finally quiet)

The host load dropped to about three for this run, so the table is more
representative than the last few.  The RSA/DSA rows moved as the CIOS
change predicts, and with the load out of the way the rest of the table
also reads higher than the previous snapshot:

  rsa verify  21.1k -> 31.7k /s   (gap 2.12)
  rsa sign     890  -> 1.215k /s  (gap 1.62)
  rsa decrypt  630  -> 1.195k /s
  rsa encrypt 11.1k -> 17.3k /s
  dsa verify  1.01k -> 1.935k /s  (gap 2.65)
  dsa sign    1.33k -> 2.52k /s   (gap 1.82)

123 measured rows, 41 ahead of the C reference and 82 within 2x.  Part of
the movement against the previous table is the load difference, so these
should be read as the current absolute numbers rather than as the CIOS
gain alone; the interleaved A/B above (20/16/13%) is the clean measurement
of that change.

What is left is now uniformly the assembly-extension work: Falcon keygen
(7.9, exact-integer NTRU solve), ChaCha (5.0/3.5, AVX2), Whirlpool (4.3,
SSSE3 S-box), the NIST curves (3.9/3.8/3.3, ADX field arithmetic), ed448
(3.3, Goldilocks field), ML-DSA (3.3, AVX2 NTT) and ripemd-160 (2.6,
scalar digest).  For the two Montgomery/EC cases the blocker is concrete:
SBCL's assembler has no MULX, ADCX, ADOX or any VEX-encoded instruction,
so taking the next factor means either hand-encoding VEX/ADX bytes inside
the VOP or a different toolchain, not another scalar rearrangement.

## Update (ADX two-carry-chain Montgomery multiply: tried, slower, reverted)

SBCL 2.6.7 *does* provide MULX, ADCX, ADOX and VEX instructions (they live in
the SB-X86-64-ASM instruction-set package; an earlier note in this file
saying otherwise was from probing the wrong package), and the tree already
has CPU detection for :bmi2 and :adx with the adx-supported-p predicate.
So the "next factor" for the Montgomery multiplys looked reachable, and I
implemented it.

The form tried: keep the separated operand scanning structure, but
accumulate each row with two independent carry chains -- MULX for the
128-bit product (no flag clobber), ADCX for the low words, ADOX for the
high words, with the chains' pending carries consumed at the next limb.
It is correct: 120k+ adversarial differential trials against the SOS form
at all four sizes, zero mismatches, first try.

It is also slower:

  mont-mul-16   sos 360ns   cios 320ns   adx 380ns
  mont-mul-32   sos 1520ns  cios 1260ns  adx 1760ns

The reason, as far as I can tell: this row form hands the high half of each
limb position to the next iteration through memory (adox writes T[j+1], the
next adcx/adox reads it), so the store-to-load forwarding latency sits
directly on the dependency chain -- roughly 5 cycles, worse than the ~2.4
the scalar register carry chain costs.  The dual carry chains remove a
chain that was not the bottleneck and add memory traffic that is.

The form real ADX implementations use keeps the accumulator in three
registers and only stores the finished word once per limb, reading the next
initial T word off the critical path.  That is a different loop shape from
either of ours, and with two register accumulators plus flags there is not
enough room for the third word without spilling; it would need a careful
rewrite and probably the n=16/32 cases only.  Given that the register-based
version is the one with a chance, and that this attempt produced a clear
negative at 1.4x slower, the ADX VOPs and their dispatch were removed; the
CIOS form from the previous entry stands, and this note is the starting
point if the three-register form is ever attempted.

Cost of finding out: about an hour, and the differential harness, which
would also have caught a wrong ADX implementation.

## Update (AVX2 ChaCha core; ChaCha-Poly setup)

SBCL's assembler does have AVX2 (see the corrected note in the previous
entry), so the two-block ChaCha core now has an AVX2 sibling.  The two
blocks live one per 128-bit lane of four YMM registers; VPADDD/VPXOR work
per 32-bit lane and VPSHUFDU per 128-bit lane, which is exactly what the
quarter rounds and the diagonalisation need, so every instruction advances
both blocks instead of one.  The VEX three-operand form also removes the
copy that the SSE shifts need for each rotation.  Selection is at run time
through AVX2-SUPPORTED-P; the SSE core stays as the fallback.

  chacha (20 rounds)   1024 -> 1365 MB/s      (+33%)
  xchacha                       same
  chacha-poly          410 -> 410 MB/s        (unchanged; see below)

The gain is smaller than the two-thirds the instruction count would
suggest, and the reason is the host: Zen 2's integer ALUs are 128 bits
wide, so every 256-bit AVX2 op is split into two uops and the ALU
throughput does not improve -- only the front end sees fewer instructions.
On an Intel Xeon (the deployment host) the 256-bit ops are full width, so
this VOP should be much closer to 2x there.

Whether to keep it was decided on that basis plus the fact that it is
bit-exact: 360 randomized comparisons against the SSE core across all six
variants (chacha/chacha-12/chacha-8, xchacha and their 12/8-round forms,
16- and 32-byte keys, 8/12/24-byte nonces, lengths from 1 byte to 8KB) with
zero mismatches, plus the cipher and AEAD vector files and the full suite.

ChaCha-Poly did not move because it is not ChaCha-bound: an 8KB message
costs 6us of ChaCha, 6us of Poly1305, ~2us of mode construction and ~6us of
message allocation and AEAD dispatch.  One part of that was easy to fix
and is included: the mode was building *two* ChaCha ciphers per message
(one for the one-time Poly1305 key, one for the payload).  A single cipher
serves both -- its counter-0 block is the Polykey and encrypting exactly
that block advances the stream to counter 1 -- which halves mode
construction (4us -> 2us) and removes a key schedule.  The row itself is
still dominated by the alloc/copy/dispatch part, which would need the
message-buffer API to change rather than the cipher.

## Update (benchmark refresh after the AVX2 ChaCha core)

  chacha        1.024 -> 1.097 GB/s   (gap 3.47 -> 3.09)
  chacha-poly   422   -> 462 MB/s     (gap 5.01 -> 4.63)
  chacha/8      964   -> 2.288 GB/s
  chacha/12     964   -> 1.692 GB/s

The host was at load ~8 for this run (the previous refresh was ~3), so the
absolute Lisp numbers here are depressed by roughly the usual 20-30%; the
direct measurement of the same code was chacha 1365 MB/s and chacha-poly
410->462.  123 measured rows, 46 ahead of the C reference and 92 within 2x.

## Update (ABCL: the McEliece row-xor loop type)

An ABCL run of the suite exposed a portability regression introduced with
the McEliece row-xor change (rev 1070) and never checked on anything but
SBCL and CCL: the portable branch of MCE-ROW-XOR! used

    (loop for c of-type index from start below end ...)

ABCL's LOOP signals "couldn't verify that INDEX is a subtype of the required
type NUMBER" for that declaration, and the warning escalates to a
compile failure, so mceliece.lisp did not compile at all and every McEliece
test failed.  FIXNUM is accepted by all the implementations, and the loop
body is unchanged.  (SBCL only ever takes the VOP branch of this function,
so its behaviour and speed are unaffected.)

Verified under ABCL 1.9.0: all five McEliece vector files, the keypair
generator for all five parameter sets, and the roundtrip test pass; also
HQC (3), BIKE (3), gcm-siv (vector + incremental) and chacha-poly, which
are the other areas touched this session.

Note for future portability checks: ABCL's LOOP is stricter about OF-TYPE
than SBCL/CCL, so `of-type index` should be avoided in shared code.  Of the
whole tree this was the only occurrence.

## Update (ABCL suite runtime and test sizing)

Two follow-ups from the ABCL fix.

1. The test counts added for HQC and BIKE earlier this session were sized for
   SBCL, where a decapsulation is 1-40 ms.  Under ABCL the portable paths are
   50-100x slower, so 2 keys x 50 trials x 3 sets (HQC) and 2 keys x 20 x 3
   (BIKE) put several minutes of pure roundtripping into the suite.  HQC and
   BIKE have no probabilistic rejection defect (unlike McEliece, whose
   roundtrip test stays at 250 trials because it is there to catch exactly
   that), so the KAT files plus a 10/5-trial roundtrip per set are enough.
   Trimmed to 2x10 (HQC) and 2x5 (BIKE).

2. The full suite under ABCL takes on the order of an hour, and essentially
   all of it is XMSS and SLH-DSA: one XMSS sign rebuilds the whole 2^10
   tree (1M thashes, ~4s on SBCL), and SLH-DSA-s signing is 3.3s on SBCL.
   Those are pre-existing and independent of the portable-path work, but it
   means "run the ABCL suite" is not a quick check; the practical check is
   the vector files for the areas touched plus a filtered suite run.

Verification of the fix under ABCL 1.9.0: the five McEliece vector files and
the keypair generator for all five sets, HQC (3), BIKE (3), gcm-siv (vector
and incremental), chacha-poly, and a filtered run of 679 tests (everything
except XMSS and the KEM roundtrips, which were checked separately) with no
failures reported through the public-key vector tests.

## Update (two more ABCL bugs: 62-bit-fixnum assumptions)

With the McEliece compile failure fixed, the ABCL suite surfaced two more
failures, both caused by the same assumption: that a FIXNUM is wide enough
to hold a value that is only wide on the 62-bit-fixnum implementations
(SBCL, CCL, ECL) but not on ABCL, whose fixnums are 32 bits signed
(MOST-POSITIVE-FIXNUM = 2147483647).

1. SLH-DSA.  The reference uses 0xFFFFFFFF as the "do not emit a WOTS
   signature" sentinel for the leaf index, and SLH-TREEHASH declares that
   index FIXNUM.  On ABCL every SLH-DSA keygen/sign died with
   "The value 4294967295 is not of type FIXNUM".  The sentinel is now -1,
   which cannot collide with a real leaf index (those are < 2^12) and is a
   fixnum everywhere.  The 0xFFFFFFFF *mask* used to compute the WOTS chain
   length is untouched; it is a mask, not the sentinel.

2. ML-DSA.  ML-DSA-MONTGOMERY-REDUCE declared its argument FIXNUM with a
   comment explaining that the product of two coefficients is "well inside
   the fixnum range".  That is true at 62 bits and false at 32: q is
   8380417, so q*q is 7.0e13, and after the un-reduced NTT stages a
   coefficient can reach ~9q, making the product ~3e14.  ABCL does not
   signal a type error here (the function is compiled with SAFETY 0); it
   silently truncated, and every ML-DSA signature check failed while
   signing still produced self-consistent results -- which is why the
   roundtrip test would not have caught it and the KAT files did.  The
   declaration is now (SIGNED-BYTE 62), which is exactly the fixnum type on
   the 62-bit implementations (so SBCL still keeps the value unboxed and
   its numbers are unchanged) and a bignum on ABCL, where the arithmetic is
   then correct.

Checked the rest of the tree for the same shape -- a FIXNUM declaration on
a product of two values -- and ML-DSA is the only scheme where the modulus
squared exceeds 2^31 (Falcon q*q is 1.5e8, ML-KEM 1.1e7; the elliptic-curve,
HQC, BIKE, RSA/DSA and hash-based code either uses explicit U64 limb
declarations or plain integers).

Verification under ABCL 1.9.0: the ML-DSA signature vector file passes, the
SLH-DSA 128f sets (SHA-2 and SHAKE) keygen/sign/verify, and the checksums
of ML-DSA-MONTGOMERY-REDUCE, FQMUL, the forward and inverse NTT and a
SHAKE-128 squeeze are now identical to SBCL's.  The SBCL suite is green,
and the ML-DSA numbers are unchanged there (the declaration is still the
fixnum type).

## Update (ABCL status after the fixes)

Complete picture under ABCL 1.9.0 at this revision:

- McEliece: all five vector files, keypair generation for all five sets, and
  the roundtrip test pass (the compile failure was the whole problem).
- ML-DSA: the signature vector file passes; ML-DSA-MONTGOMERY-REDUCE,
  FQMUL, forward/inverse NTT and SHAKE-128 checksums now match SBCL exactly.
- SLH-DSA: 128f sets (SHA-2 and SHAKE) keygen/sign/verify pass.
- HQC (3), BIKE (3), gcm-siv (vector and incremental), chacha-poly: pass.
- XMSS: a reference signature verifies, so the code is functionally correct
  there; keygen/sign were not run to completion because one XMSS sign builds
  the whole 2^10 tree and the ABCL run spent 17+ minutes in that single test
  before being stopped.  That is pre-existing cost (per-call allocation in
  the hash chain), not a correctness problem.

Practical way to check ABCL quickly, given the cost of the full suite: run
the per-area vector files (mceliece/hqc/bike/gcm-siv/chacha-poly/ml-dsa/
slh-dsa-128f) rather than `asdf:test-system`.

## Update (P-256 field multiply: CIOS tried, slower, reverted)

The secp256r1 verify profile is 63% in secp256r1-fe-mont-mul-asm with
another 12% in the point-doubling wrapper, so the field multiply is the
only useful lever left on that row.  Before attempting the register-
resident ADX form, I tried the cheap thing: instantiate the already
validated generic CIOS VOP at n=4 and call it with P-256's limbs.  It is
correct (300k random and adversarial differential trials against the
existing VOP, zero mismatches) but slower:

  secp256r1-fe-mont-mul-asm (SOS, fixed modulus)   32 ns
  mont-mul-4-cios (generic CIOS, n=4)              38 ns

The reason is specific to this modulus: P[0] = 2^64-1 makes the reduction
word cancel with no multiply at all, and P[2] = 0 makes that step a plain
carry propagation, so the fixed-modulus SOS performs 16 product and only 8
reduction multiplies.  The generic CIOS performs 16+16.  CIOS saves memory
traffic, but at n=4 the arithmetic is what matters, so the special cases
win.  A CIOS form could special-case the modulus too, but then it has the
same 24 multiplies as the current code and would only be trading memory
traffic -- not worth the risk.  Reverted.

That leaves the register-resident MULX/ADCX/ADOX form as the only way to
move this row: it has to keep the 5-word accumulator and the modulus limbs
in registers at once, which is the shape an earlier attempt here ran out of
registers on.  With MULX freeing RAX/RDX it is probably feasible, but it is
a careful hand-allocation job, not a rearrangement.

## Update (Whirlpool: merge the table halves, 1.97x)

Whirlpool was doing twice the table lookups of the reference.  The
eight C tables are 256-entry 64-bit values, but the implementation stored
them as two 32-bit halves in separate arrays (+C-EVEN+ and +C-ODD+) and
the register file as 64 32-bit words (each 64-bit state word split into
two).  One output word therefore cost 16 lookups and 16 XORs where the
reference needs 8 and 8, i.e. 2560 loads per 64-byte block against the
reference's 1280 -- and 1280 loads at two per cycle is exactly the
throughput the C numbers show.

The tables are now one (8 256) u64 array, the register file is 32 u64
words, the block is eight u64 words, and the round constants are one u64
per round.  The block is filled with a new fill-block-ub8-be/64-8 VOP:
the existing /64 variant copies 128 bytes for SHA-512's 1024-bit block,
and using it here overwrote the 64-byte whirlpool block.

  whirlpool  33.6 -> 66.1 MB/s   (interleaved A/B in one session, min of 8)

Also tried: hoisting the eight source words out of the slice loop so they
are loaded once per call instead of eight times.  It is the obvious next
step and it made things *worse* (41 MB/s) -- eight live words plus the two
accessor macros and the table spill the register file, and the reloads
were cheaper than the spills.  Reverted.

Validation: whirlpool digest and incremental vector files pass under SBCL,
CCL and ABCL (the portable path changed too), the published digests of ""
and "abc" match, and the full SBCL suite is green.

## Update (benchmark refresh after the Whirlpool table merge)

  whirlpool   40.18 -> 77.91 MB/s   (gap 4.25 -> 2.20)

123 measured rows, 44 ahead of the C reference and 80 within 2x, with the
host at load ~4.6.  The headline movement is whirlpool; the rest is within
the run-to-run noise of this host.

## Update (SLH-DSA: the SHAKE family was rebuilding its digest per hash)

The SHA-2 SLH-DSA families were already using the reference's
"state_seeded" trick -- a digest with the public seed absorbed once, then
COPY-DIGEST per hash call.  The SHAKE families were not: every thash and
every prf_addr did a fresh MAKE-DIGEST, allocating a 200-byte Keccak state
and a buffer, hundreds of thousands of times per operation.  That is the
same alloca-per-call shape as XMSS, and it is why the SHAKE rows carried
the 2-3.3x gaps while the SHA-2 rows were near 2x and some were ahead.

Copying a prefix-absorbed SHAKE256 digest works exactly like the SHA-2
case -- the sha3 COPY-DIGEST method replaces the state, buffer, bit rate
and buffer index -- so the SHAKE branches of slh-thash and slh-prf-addr now
use the same template/work pair (one template, since both start with
pub_seed).

Interleaved A/B in one session:

  shake-128s verify   3.60 -> 2.80 ms   (1.29x)
  shake-128s keygen   433  -> 391 ms    (1.11x)
  shake-128f verify   9.60 -> 8.80 ms   (1.09x)
  shake-128f keygen   6.67 -> 5.33 ms   (1.25x)

What is left on these rows is the Keccak permutation itself: a thash
absorbs ~128 bytes and squeezes n, which is one finalize and one squeeze
permutation, and the Lisp permutation is already within ~1.25x of plain C.
So the SHAKE rows cannot move much further without a SIMD Keccak.

Validation: the whole slh-dsa.testvec file (all twelve parameter sets)
passes, the SHAKE and SHA-2 128f roundtrips pass under CCL, and the full
SBCL suite is green.

## Update (benchmark refresh after the SLH-DSA SHAKE template)

  slh-dsa-shake-128s verify  5.2 -> 2.9 ms   (gap 3.34 -> 1.87)
  slh-dsa-shake-128s keygen  436 -> 392 ms   (gap 2.06)
  slh-dsa-shake-128f verify  9.3 -> 8.5 ms   (gap 2.01)
  slh-dsa-shake-128f keygen  7.0 -> 6.2 ms   (gap 2.09)

All the SLH-DSA SHAKE rows now sit at ~1.9-2.1 and are Keccak-bound.  123
measured rows, 41 ahead of the C reference and 78 within 2x at load ~4.5;
the counts are within the usual host noise of the previous run.

## Update (ChaCha: four blocks in flight, 2x)

The AVX2 core processed two blocks per YMM group.  A ChaCha quarter round
is a serial chain (add, xor/rotate, add, xor/rotate), and with a single
group there is nothing to overlap it with -- the two-block core measured
1.05 GB/s, well under the ~2 GB/s the per-byte instruction count allows on
this machine.

Added a four-block core: two independent YMM groups (blocks A/B and C/D),
so one group's chain fills the other's latency.  The per-byte instruction
count is unchanged; only the instruction-level parallelism doubles.  The
caller advances all four state counters by four per 256 octets, which also
halves the per-byte counter bookkeeping (a new chacha-add-counter replaces
two chacha-inc-counter calls per block).

  chacha        1024 -> 2048 MB/s   (2x)
  chacha/12     2048 -> 4096 MB/s
  chacha/8      2048 -> 4096 MB/s
  chacha-poly    410 ->  512 MB/s   (chacha is now 4us of its 16us)

2048 MB/s is about the ceiling the instruction count implies here, so an
eight-block version would not help.  On Zen 2 the 256-bit ops are split into
two 128-bit uops, so this is purely a latency-hiding win; on a full-width
AVX2 machine the same code should do better still.

Validation: 360 randomized comparisons against the SSE core across all six
variants (16/32-byte keys, 8/12/24-byte nonces, lengths 1B-8KB) with zero
mismatches, the chacha-poly/xchacha-poly vector files, and the full SBCL
suite.

## Update (benchmark refresh after the four-block ChaCha core)

  chacha        1.052 -> 1.731 GB/s   (gap 3.22 -> 1.81)
  chacha-poly     413 ->   559 MB/s   (gap 5.12 -> 3.81)
  chacha/12      1.692 -> 2.540 GB/s
  chacha/8       2.288 -> 3.390 GB/s

123 measured rows, 44 ahead of the C reference and 76 within 2x at load
~3.2.  Chacha-poly is now mostly Poly1305: 559 MB/s is 6us of Poly1305
(scalar-optimal), 4us of ChaCha, ~2us of mode setup and ~4us of message
allocation in an 8192-byte operation.

## Update (McEliece: 32-byte row xor on AVX2)

The keypair generator's Gaussian elimination is a stream of row XORs, and
the inner loop did them eight bytes at a time with the SSE form (`mov`/
`xor`/`mov` on two 64-bit words per step).  Added `mce-xor-words-avx2`,
which does 32 bytes per step with a single `vpxor` on a YMM register, and
dispatch on `avx2-supported-p` through `*mce-avx2-xor*`.

Interleaved A/B on fixed seeds (min of three, keygen includes the retry
loop so the numbers are noisy):

  mceliece348864   144.0 -> 135.3 ms   (1.06x)
  mceliece460896   378.0 -> 349.3 ms   (1.08x)

The gain is modest because the row xor is only ~10-15% of keygen; the
elimination's other half is the pivot scan and the bit-plane packing.
Validation: the new VOP is bit-identical to the old one on 15 whole
keypairs (all five parameter sets, three seeds each), the McEliece
testvec files and keygen roundtrips pass under CCL and ABCL, and the full
SBCL suite is green.

## Update (McEliece: the pivot loop was adding rows that could not help)

`mce-pk-gen` eliminates one column at a time.  For the pivot column it
first makes sure the pivot row has a one: if it does not, it adds in a row
below that does.  The loop that looked for that row tested every row below
-- and kept adding rows whose pivot bit was *zero* after RBIT had already
become one.  Adding a row with a zero in the pivot column cannot change
the pivot bit; it only churns the columns to the right, and because the
reduced row echelon form is unique, it cannot change the answer either.
It was, in other words, about half of the elimination's row-xor traffic
spent producing a bit-identical public key.

The loop now stops at the first row with a one, and only runs at all when
the pivot row's bit is zero.  Interleaved A/B on fixed seeds (min of
three):

  mceliece348864   150.7 -> 118.7 ms   (1.27x)
  mceliece460896   390.7 -> 302.0 ms   (1.29x)

Together with the AVX2 row xor above this is ~1.3x on keygen.  Validation:
the public and private keys are byte-identical to the previous build for
ten whole keypairs (all five parameter sets, two seeds each), the testvec
files and keygen roundtrips pass under SBCL, CCL and ABCL, and the full
SBCL suite is green.

## Update (AES-CTR: build the counter blocks with 64-bit words)

The eight-wide AES-CTR path encrypted eight counter blocks per VOP call,
but built those eight blocks in Lisp: for each block a generic REPLACE
of sixteen octets out of the IV, then an INC-COUNTER-BLOCK VOP call to
advance the IV.  Sixteen calls per 128 octets of plaintext is more work
than the AES itself, and it capped CTR at 1.5 GB/s even though the
underlying AES-NI core does 7.8 GB/s.

The counter is big-endian, but its low 64 bits are enough unless they
wrap, so FILL-CTR-BLOCKS-8 now writes the eight blocks with two 64-bit
stores each and advances the IV's low word by eight.  When the low word
is within eight of wrapping it falls back to the old byte-at-a-time
increment, which keeps the carry into the high half right.

  aes-256-ctr      1.5 -> 6.1 GB/s   (5.33 -> 1.33 us per 8 KB)
  gcm encrypt      631 -> 1024 MB/s  (12.0 -> 8.0 us per 8 KB)

The GCM number is now two thirds GHASH (1.4 GB/s), which is the next
limit.  Validation: FILL-CTR-BLOCKS-8 matches the old increment exactly
on 2000 random IVs, a third of them within 64 of a 64-bit wrap (counter
blocks and final IV both compared), the ctr/gcm/ccm/eax/gcm-siv vector
files pass, and the full SBCL suite is green.

## Update (benchmark refresh after the McEliece keygen work)

  mceliece348864 keygen   ~150 -> 119 ms (fixed-seed A/B)
  mceliece460896 keygen   ~390 -> 302 ms (fixed-seed A/B)

The table's own keygen rows are dominated by how many retries a single
sample happens to need, and the C column moved by more than the change;
123 measured rows, 45 ahead of the C reference and 99 within 2x, but
those counts are not comparable with the previous run (load ~7.8).

## Update (benchmark refresh after the CTR counter-block change)

  gcm   631.9 -> 867.1 MB/s  (gap 2.40 -> 1.73)
  ccm   328.3 -> 295.7 -> 395.7 MB/s  (gap 2.41 -> 2.02)
  eax   302 MB/s, etm 443 MB/s, gcm-siv 174 MB/s (no C reference)

CCM moves less because its CBC-MAC is a serial AES chain and dominates;
GCM is now roughly one third CTR, one third GHASH and one third setup.
123 measured rows, 47 ahead of the C reference and 102 within 2x at load
~3.9 (the previous run had 45 and 99 at load ~7.8, so the counts are
moving in the right direction but the C column is still noisy).

## Investigation notes (things measured but not landed)

**Montgomery is the whole of DSA/RSA.**  Measured on a 2048-bit key with
min-of-five over thousands of operations: one `mont-mul-limbs` at n=32
takes 1.45 us, so the seventeen of them in a 65537-exponent RSA verify
account for 24.6 us of the 30.4 us total; the bignum Montgomery
conversions (base*R mod m, limbs in and out) are only 4.6 us.  A CIOS
call does 2*n^2 limb-pair products (multiply row plus reduction row), so
2048 pairs in 1.45 us is ~3 cycles per pair at 4.2 GHz -- the `add`/`adc`
carry chain, as expected.  The conversion is not worth caching until the
multiply itself is fixed.  A 2-way CIOS with MULX and ADCX/ADOX is the
next real step (OpenSSL runs the same 2*n^2 pairs at about 1 cycle per
pair), but the previously tried ADX SOS was slower because it had to
store the partial products, so this needs the interleaved form, not a
different one.

NB: SBCL 2.6.7's `mulx` looks correctly encoded -- it emits
VEX.NDD.LZ.F2.0F38.W1 F6, which *is* MULX; the VOP comment claiming the
VEX prefix turns it into VPMADD52LUQ is wrong.  A test VOP needs the
usual order (defun, defknown, define-vop, then a caller compiled after
it) and the `ironclad-unsafe-vm` package, which is why the scratch
attempt did not get far.

**The digest gaps are Lisp-vs-hand-written-C, not a bug.**  Disassembling
`update-md5-block` shows SBCL keeping the 32-bit words in tagged-fixnum
form (`SHL 1` on array loads, `BTR 33` for the mod-2^32 mask, `SAR 1`
again), roughly 30 instructions per round against C's ~10.  It is not
free to avoid: a microbenchmark of `(ldb (byte 32 0) (+ a b))` on ub32
against `(logand #xffffffff (+ a b))` on ub64 measured the same 2.0 ns
per iteration (the ub64 form was 2.4).  Closing md5/ripemd-160/sm3/
sha512 would need per-algorithm VOPs (sha512 also needs AVX2 to match
OpenSSL), not a type declaration.

**ed448 is field-multiply bound.**  `goldilocks-fe-mul-buf` (mul-raw VOP
plus reduce VOP plus an eight-limb copy) measures ~208 cycles; with
~5300 field multiplies per verify that is the whole 707 us.  The MUL
form costs 64 products of two 56-bit limbs and a serial add/adc carry
chain; MULX with two independent ADCX/ADOX accumulators is the same
opening as the Montgomery case.

## Negative result (merged multiply-and-reduce CIOS)

Tried the OpenSSL-style merged CIOS: instead of a multiply row and a
reduction row of n limb-pairs each, one row of n iterations that does
both products, so the loop overhead and the number of memory accesses
halve.  It needs `mulx` (verified: SBCL emits the right VEX encoding) to
free RAX/RDX, and the result is byte-identical on 300 random moduli
including zero/huge operands.

It is not faster: 1.20 us both for the old 32-limb CIOS and the merged
one (min of four, 20000 iterations each).  The old code is already at
2.46 cycles per limb-pair, which is its own carry-chain floor (the chain
is add/adc/add/adc through the carry word), and merging the rows puts
the reduction product *after* the multiply product in the same chain, so
the chain gets longer while the loop count halves.  A real gain needs the
two independent ADCX/ADOX chains, which needs more live registers than
the six argument arrays plus the accumulators leave on x86-64 -- the
merged VOP already could not allocate without moving `n0` and `mred`
into the scratch buffer.  Reverted (scratch only); the CIOS VOP is
unchanged.

## Update (XMSS: the tree hash was byte-at-a-time serialization)

Profiling a 4.4-second XMSS-SHA2_10_256 key generation put 85% of the
time in `xmss-thash`, and inside that the SHA-256 compression was 4%.
The time was going into the *inputs*: every hash serializes a 32-byte
padding block and an 8-word address, and the code did that one byte at a
time with `(ash value -8)` and a bounds-checked `aref`.  A key
generation runs about a million of these (1024 leaves, 67 WOTS chains of
15 hashes, plus the tree), so a few hundred nanoseconds per
serialization is seconds.

Two changes, both local:

* `xmss-ull-to-bytes` writes four bytes at a time through UB32REF/BE (a
  byte swap and a store on SBCL) instead of eight shifts and eight
  stores, and its callers now declare the vector simple, outlen and
  start bounded, and value non-negative.
* the file carries a `(declaim (optimize (speed 3) (safety 0)))`, like
  the other hot algorithm files, so the remaining byte loops lose their
  bounds checks.  `xmss-addr-to-bytes` declares its two arguments.

Interleaved A/B, min of three:

  xmss keygen   3846 -> 2068 ms   (1.86x)
  xmss sign     3840 -> 2076 ms   (1.85x)
  xmss verify   2200 -> 1200 us   (1.83x)

Validation: the xmss.testvec file and the whole SBCL suite pass, the new
`xmss-ull-to-bytes`/`xmss-addr-to-bytes` match the old code byte for byte
on 2000 random values (widths 1-32, starts anywhere in the buffer, plus
every address word) on SBCL and ABCL, and a full keygen/sign/verify
roundtrip passes under CCL.

## Update (XMSS: hash the short messages without the digest-object tax)

With the address serialization fixed, the profile flattened and showed
the real second problem: about a million SHA-256 calls per operation,
each paying for a generic `make-digest` (a symbol lookup and an
allocation), then `update-digest`, then a `produce-digest` that
*allocates a second digest* so it can finalize a copy.  The compression
itself was 10% of the time; the digest objects were most of the rest.

`define-digest-finalizer` now also defines its finalizer as a top-level
`finalize-<digest>-state`, and `produce-digest` still calls it with a
copy, so every existing caller keeps the non-destructive semantics.
XMSS, which owns a fresh state and does not need it afterwards, calls
`(%make-sha256-digest)`, `update-digest`, and `finalize-sha256-state`
directly -- one allocation and one finalize instead of two allocations
and a copy.

Cumulative XMSS-SHA2_10_256 (min of three, same machine):

                       before   after   C reference
  keygen               3846 ms  1496 ms  ~1950 ms
  sign                 3840 ms  1480 ms  ~1945 ms
  verify               2200 us   800 us  ~1030 us

so the three XMSS rows go from ~2x behind C to ~0.8x, i.e. about 25%
ahead.  Validation: every digest vector file passes on SBCL, CCL and
ABCL (the macro is shared by all the finalizers), the xmss.testvec file
passes, and the full SBCL suite is green.

## Update (benchmark refresh after the XMSS fixes)

  xmss-sha2-10-256 keygen  gap 2.01 -> 0.95   (0.256 -> 0.601/s)
  xmss-sha2-10-256 sign    gap 2.02 -> 0.99   (0.255 -> 0.579/s)
  xmss-sha2-10-256 verify  gap 1.97 -> 0.99   (495 -> 1120/s)

All three XMSS rows are now at parity with the C reference.  This run was
about 10% slower for our own code across the board (gcm 867 -> 744 MB/s,
sha256 1.53 -> 1.34 GB/s, aes 7.99 -> 7.27 GB/s) while the C column
stayed put, so the run's counts (44 ahead, 77 within 2x) are not
comparable with the previous refresh; the XMSS change is far larger than
that drift, as the direct A/B above shows.

## Investigation notes (falcon keygen, and an MD5 VOP that is fast but wrong)

**Falcon keygen is the NTRU solve, and the solve is bignums.**  On a
104 ms key generation (one sampling attempt, no retry): sampling f and g
8 ms, the Gram norm check 4 ms, `falcon-ntru-solve` 80 ms.  Inside the
solve, `falcon-karatsuba` is 70% cumulatively and the bignum primitives
(SUBTRACT-BIGNUM, GENERIC-+, ASHIFT, TWO-ARG-*) another 20%.  The
implementation is exact: the field norm, the lift/karatsuba products and
the Babai reduction all run on `(simple-array integer)`, so every
coefficient is a boxed bignum.  The reference implementation does the
same recursion in `fpr` (double) with an FFT for the products and rounds
only at the end, which is where the 10-20x comes from.  We already have
the float FFT pieces (`falcon-fft`, `falcon-mul-fft`, `falcon-div-fft`,
used by the Gram check and by `falcon-babai-reduce`), so the work is to
move `falcon-field-norm` and the lift products into that domain -- a
real project, not a tuning change, and one with a correctness cliff
(the NTRU equation must stay exact).

**MD5 VOP: 220 -> 120 ns per block, but not correct.**  A 64-round VOP
with `:dword` adds/rotates and the state in four registers is 1.8x faster
than the Lisp compression (220 -> 120 ns/block, i.e. 290 -> 530 MB/s,
which would take the md5 row from 2.5x to ~1.3x).  It is not shipped
because it produces the wrong digest.  The emitted instruction stream was
checked mechanically against the RFC schedule: all 64 rounds have the
right `k`, `s`, `T`, target register, second operand, and F/G/H/I
operand roles, and the initial loads and final add-back are right.  A
Lisp model of exactly the same round structure matches
`update-md5-block` on the abc vector; the VOP does not.  Things ruled out
along the way: `:dword` encoding (a one-round primitive VOP round-trips
against Lisp, including immediates above 2^31 and the 32-bit rotate), the
argument arrays (the block is not modified, the state is), and the
rounds themselves (checked by parsing the disassembly).  Something in
how SBCL expands/inlines a generator body of this size is miscompiling
it, and chasing that was not worth more time; the scratch work is not in
the tree.

## Update (LMS: the same per-hash digest tax as XMSS)

`lms-sha256` -- the hash at the bottom of every LM-OTS chain step, tens
of millions of calls per key generation -- built a fresh SHA-256 with
`make-digest` and then called `produce-digest`, which allocates a second
state to finalize a copy.  It now constructs the concrete state and calls
`finalize-sha256-state` directly, as XMSS does.

  lms h10w4 keygen   420 -> 244 ms   (1.72x)

Sign is under a millisecond and the timer here cannot separate the two.
LMS is not in the benchmark table, so this does not move a row; it is the
same one-line shape as the XMSS change and the two LMS vector files pass.
(The `hss-2xh5w8` vector file fails inside `hss-verify-sig` with a type
error in both the old and the new code -- it is not part of the suite and
was already broken -- so HSS is validated only by the state-exhaustion
test.)

## Update (one fused CBC-MAC block for CCM, CMAC, EAX and ETM)

CCM's MAC loop, CMAC's bulk loop and therefore EAX and ETM all did two
calls per block: an XOR VOP (`xor128`/`xor-block`) and then the block
encryption (a generic `encrypt-in-place` in CCM, a `funcall` of the
encrypt function in CMAC).  Both loops are serial -- the chain is the
input of the next block -- so that per-block overhead sits directly on
the critical path.

Added `aes-ni-mac-block`, which is `chain := AES(chain xor data[off..])`
in one VOP (the same round structure as `aes-ni-encrypt`, with the XOR
folded into the first `pxor`).  CCM and CMAC select it when the cipher is
AES and AES-NI is present, with the old path kept behind
`*ccm-fused-mac*` / `*cmac-fused-mac*` for validation.

Interleaved A/B, min of four:

  ccm   20 -> 16 us per 8 KB message   (1.25x)
  eax   32 -> 24 us per 8 KB message   (1.33x)
  cmac  16 ->  8 us per 8 KB buffer    (2.0x, 1.0 GB/s)

ETM uses the same CMAC, so it moves with it.  Validation: the ccm, eax,
etm and cmac vector files pass, and the full SBCL suite is green.

NB while adding the VOP: `src/opt/sbcl/x86oid-vm.lisp` contains the whole
`aes-ni-encrypt`/`aes-ni-decrypt`/key-schedule block twice, byte for
byte (the second definition simply wins at load time).  That predates
this work and is harmless, but it is a trap for anyone editing those
VOPs with a single-occurrence replace.

## Update (benchmark refresh after the fused CBC-MAC block)

  ccm  395.7 -> 556.5 MB/s   (gap 2.02 -> 1.43)
  gcm  867.1 -> 887.6 MB/s   (gap 1.73 -> 1.70, unchanged within noise)
  eax  302 -> 315 MB/s, etm 443 -> 454 MB/s (no C reference)

CCM is now within 1.4x of the C reference; what is left there is the
serial AES latency of the CBC-MAC chain plus the mode setup (a fresh
mode per message in the benchmark costs about 2 us of the 14.7 us).
123 measured rows, 41 ahead of the C reference and 81 within 2x at load
~4.2 (the counts move with host load and with the C column, so compare
the individual rows, not the totals).

## Update (MD5: a 64-round VOP, 2.1x)

Follow-up to the "fast but wrong" note above: the bug was the F
function.  MD5's F(b,c,d) is `d ^ (b & (c ^ d))`, and the macro was
emitting `d ^ (d & (b ^ c))` -- the AND operands were swapped.  Nothing
else was wrong; the earlier round-by-round disassembly check had compared
the emitted operands against the *same* (wrong) macro, so it confirmed
self-consistency, not correctness.  A bisect over the round count against
a Lisp model (1, 2, 4, 8, 16, 64 rounds) found it in one run, and the
model then matched update-md5-block at every count.

The VOP is `:dword` adds/rotates/xors with the four state words in
registers and the block read as memory operands:

  md5 hash 8192-byte block   273 -> 585 MB/s   (2.14x)

so the md5 row should go from ~2.5x behind C to ~1.2x.  Validation: the
md5 and md5-incremental vector files pass on SBCL, CCL and ABCL, the
"abc" digest is byte-identical on all three, and the full SBCL suite is
green.

Lesson for the next 32-bit digest VOP: compare against a Lisp model of
the intended formulas first, and only then against the emission; a
self-consistent emission of a wrong formula looks perfect in review.

## Update (benchmark refresh after the MD5 VOP)

  md5   272.3 -> 558.7 MB/s   (gap 2.53 -> 1.25)
  ccm   395.7 -> 555.3 MB/s   (gap 2.02 -> 1.34, from the fused MAC block)
  sm3   133.9 MB/s (gap 2.16), ripemd-160 111.1 MB/s (gap 2.71)

123 measured rows, 46 ahead of the C reference and 92 within 2x at load
~6.1.  MD5 is now within 25% of the C reference; the same recipe (a
: dword VOP with the state in registers and the block as memory
operands) should apply to SM3, RIPEMD-160 and SHA-512, which is where
the remaining digest rows sit.

## Negative result (SHA-512 VOP)

Tried the MD5 recipe on SHA-512: an 80-round VOP with the eight state
words in registers, the expanded schedule as memory operands, and the
round constant folded into the schedule by the Lisp wrapper.  It is
correct -- 0 mismatches against `update-sha512-block` over 200 random
states/schedules, 0 mismatches end-to-end over 300 random messages for
all four variants -- and it is *slower*:

  sha512   410 MB/s portable  ->  341 MB/s with the VOP

Two reasons: the round needs ~44 instructions against the Lisp's ~35
(the S0/maj accumulation needs two adds plus a separate xor for S0, and
the six state moves are emitted even though Zen 2 renames them away),
and folding K into the schedule costs a 80-iteration Lisp loop per
block.  Keeping K as a third argument instead does not fit the register
file (8 state + 2 temps + 3 args is already at the edge; the 8+2+2
version only packs because two of the state words die early).

So the MD5 result does not generalise: MD5 won because its round is a
single 4-instruction F plus three adds and a rotate, with the block as
memory operands, and its portable version was spending instructions on
tagged fixnum conversions.  SHA-512's portable round is already close to
what a VOP can express in SBCL, and the 2x headroom against C is
scheduling/codegen, not a Lisp-level defect.  Reverted; no code change.

## Negative result (Whirlpool: hoisting the register file into locals)

Whirlpool re-reads its eight source words from the register-file array for
every one of the eight lookups per output word (64 loads per pass, two
passes per round).  Hoisting the eight K and eight state words into local
variables removes about a hundred loads per round, and was expected to be
worth 15-20%.

It is slower: 78.8 -> 66.1 MB/s (interleaved A/B, rebuild per side).  The
sixteen live 64-bit locals push SBCL into spilling them to the stack, and
a spilled local costs the same as the array load it was meant to replace,
plus the store traffic.  Reverted; no code change.

Together with the earlier Camellia S-box binding (also slower) this says
SBCL's array accesses with constant indices are as good as hand-hoisted
locals for these table-driven rounds, and the remaining Whirlpool gap is
the same codegen difference as the other scalar digests.

## Update (GHASH: eight blocks per reduction)

The four-block GHASH VOP sums four carryless products and reduces once.
Since the reduction and the call are fixed costs, doing eight blocks per
call amortizes them further: `gmac-mul-8-fast` is the same code with
H^1..H^8 in the powers table (extended to 128 bytes) and one reduction
per 128 octets.

  gmac   3938 -> 4800 MB/s   (1.22x)
  gcm     900 -> 940 MB/s    (1.04x; GHASH is only ~a third of GCM)

GCM gains little because its time is CTR plus per-message setup; the MAC
itself is now 1.7 us for 8 KB.  Validation: gcm, gcm-incremental,
gcm-siv and gmac vector files pass, and a differential of 400 random
message lengths (0-599) between the eight-block and four-block paths
shows zero mismatches, so the 64/128 boundary is right.

NB the measurement lesson: `get-internal-real-time` on this host only
ticks every few milliseconds, so any benchmark whose total run is under
~10 ms is quantized garbage.  The eight-block difference is invisible
until the loop runs 20k-50k iterations; the same root cause explains
several suspiciously round micro-benchmarks earlier in this file.

## Measurement note (the clock only ticks every few milliseconds)

`get-internal-real-time` on this host updates in steps of several
milliseconds, so any timing whose *total* run is under ~10 ms is
quantized to one or two ticks and is useless.  That explains a string of
suspiciously round micro-benchmarks earlier in this file (exactly 1024
MB/s, exactly 4.00 us, several 0.000 us results, and the AEAD setup
numbers that moved 2.7-4.4 us between runs).  Everything measured since
the Whirlpool A/B used totals of 100 ms or more and is reliable; the
older sub-10 ms numbers should be re-taken before being trusted.

Re-measured properly (50k-100k iterations), GCM's composition is:

  fresh GCM mode            3.92 us
  8 KB output allocation    1.00 us
  CTR + GHASH + finalize    3.60 us
  one-shot encrypt-message  8.60 us

so setup is 45% of the one-shot API and the crypto itself is close to the
C reference.  Of the setup, the GMAC is 1.92 us (0.56 of it its own ECB
cipher) and the GCM object ~1.4 us; both are CLOS construction cost, and
sharing the GMAC's cipher with the CTR cipher would only recover ~6% of
the operation, so it was not done.

## Update (benchmark refresh after the eight-block GHASH)

  gcm   890 -> 930 MB/s   (gap 1.70 -> 1.62)
  gmac  3938 -> 4684 MB/s
  ccm   555 -> 553 MB/s   (gap 1.45, unchanged)

123 measured rows, 41 ahead of the C reference and 88 within 2x at load
~4.2.  GCM is now 1.62x from C with 45% of its one-shot time in mode
construction, so the remaining gap is setup rather than cryptography.

## Update (RIPEMD-160: 160-step VOP, 2.25x)

The MD5 recipe applied to RIPEMD-160, which is the worst digest row.  The
portable version keeps both lines' ten state words live in tagged
fixnums; the VOP runs the lines *sequentially* in five registers and
parks the right-hand line's result in a five-word scratch (the digest
gained a SCRATCH slot for it) because the block is still needed by the
left-hand line.  Each step is a three-or-four instruction F plus three
32-bit adds, a rotate and the C-register rotate by 10.

  ripemd-160   113.8 -> 256.0 MB/s   (2.25x)

so the row should go from 2.71x behind C to about 1.2x.  Validation: the
ripemd-160 and ripemd-160-incremental vector files pass, a differential
of 300 random messages with the VOP on and off shows zero mismatches, the
"abc" digest is byte-identical on SBCL, CCL and ABCL, and the full suite
is green.

## Update (benchmark refresh after the RIPEMD-160 VOP)

  ripemd-160   111.1 -> 245.1 MB/s   (gap 2.71 -> 1.17)
  md5          558.7 MB/s             (gap 1.18)
  sha512       333.5 MB/s             (gap 1.45)
  gcm          930.9 MB/s             (gap 1.63)
  ccm          552.9 MB/s             (gap 1.44)

123 measured rows, 44 ahead of the C reference and 92 within 2x at load
~3.3.  The two 32-bit digest VOPs (md5 2.1x, ripemd-160 2.25x) both came
from the same place: SBCL's portable round spends instructions on tagged
fixnum conversions, while the round itself is a few xors, three adds and
a rotate.  SM3 (2.16) and Whirlpool (2.57) are the remaining digest rows
in that class.

## Negative result (SM3: rounds VOP is only 1.06x)

Built the same kind of VOP for SM3 -- the 64 rounds with the eight state
words in registers, the schedule in a buffer (state at 0..7, W at 8..75,
and W[j]^W[j+4] precomputed at 76..139 so the round needs one memory
operand for TT1).  It is correct: 0 mismatches against `sm3-hash` at 2,
3, 4, 5, 8, 16, 17, 32 and 64 rounds (the bisect also caught a real bug
in my first attempt -- FF's two terms must be `(a&b)` and `((a^b)&c)`,
disjoint so they can be added; `(a|b)&c` overlaps and needs a real OR).

It is not worth landing:

  sm3   480 -> 453 ns/block   (1.06x)

The round VOP itself is ~1.5x, but the schedule expansion stays in Lisp
(52 words of P1 plus the 64 W xor-s, ~40% of the block) and the eight
state words plus three temporaries still spill.  Unlike MD5/RIPEMD-160,
whose rounds keep only 5-10 values live, SM3's round needs all eight
state words and its schedule exceeds what the portable code can express
in registers either way.  Reverted; no code change.

Summary of the digest-VOP recipe across five attempts: md5 2.1x,
ripemd-160 2.25x (wins), sm3 1.06x, sha512 0.83x (losses).  The win
condition is a round with few live values and a simple schedule; SM3 and
SHA-512 both need their message schedule too, and that plus the register
pressure cancels the advantage.

## Negative result (Camellia: one merged S-box table)

The four S-boxes are separate DEFCONSTANT arrays, so binding them all
locally costs four base registers (that version was slower, recorded
earlier).  Merging them into one 1024-word table (S1 at 0, S2 at 256,
S3 at 512, S4 at 768) needs only one base register, so the feistel can
bind it once without the pressure:

  camellia  81.9 MB/s before and after (interleaved A/B, rebuild each side)

Exactly neutral.  The compiler was evidently already keeping the four
constant-array addresses alive cheaply enough that one merged table buys
nothing.  Reverted; no code change.

With this, the Lisp-level candidates on the remaining 2x+ rows are
exhausted: every fix that worked this month (Whirlpool tables, SLH-DSA
and XMSS digest reuse, McEliece elimination, AES-CTR counters, MD5 and
RIPEMD-160 rounds) removed *work*; the ones that failed (Camellia tables
twice, Whirlpool locals, SHA-512 rounds, SM3 rounds, merged CIOS) tried to
make the same work cheaper in Lisp.  What is left needs new primitives.

## Negative result (GCM: an allocate-instance fast path for GMAC)

GCM's one-shot cost is 45% mode construction, and `make-instance` of the
GMAC is 1.7 us against 20 ns for `allocate-instance`, so the CLOS init
protocol looked like the fat.  It is not: replacing `make-instance 'gmac`
with `allocate-instance` plus explicit slot writes and a shared
`%gmac-initialize` function changed nothing.

  make-mac :gmac   1920 -> 2000 ns
  mode gcm         3920 -> 3920 ns

The ~1.7 us is the work -- one cipher (0.56 us), five small arrays, H and
the eight powers, j0 -- plus nine generic accessor calls, not the init
protocol.  Reverted; no code change.  Cutting GCM's setup further would
mean not creating the GMAC object and its cipher at all, i.e. folding the
GHASH state into the GCM mode, which duplicates ~80 lines of the MAC's
update/digest logic (or refactors it into shared functions) for ~1.2x on
one row.  Not done.

## Keccak output extraction: one 64-bit store per lane (SLH-DSA verify 1.05x)

`keccak-state-extract-output` wrote the digest a byte at a time -- eight
stores per 64-bit lane -- and walked all 25 elements even when the caller
wanted 16 or 32 bytes.  The digest is just the little-endian state array,
so when a whole lane fits, the whole lane is one unaligned 64-bit store,
and only `(ceiling output-bytes 8)` elements can contribute at all:

  extract 16 bytes   92 -> 24 ns
  extract 32 bytes  116 -> 34 ns
  extract 64 bytes  156 -> 50 ns

A SHA-3 digest of a long message is unaffected (one extraction per
message), but SLH-DSA squeezes a short hash thousands of times: a single
128f verification makes 6261 extraction calls.  Interleaved A/B in one
image, each side behind the same closure:

  slh-dsa-shake-128f verify  9800 -> 9300 us  (1.054x)
  slh-dsa-shake-128f sign   169.0 -> 159.0 ms (1.063x)

The partial tail lane keeps the old byte-wise path, and the loop is
clamped to 25 elements, so a caller that asks for more than the state
holds cannot read past the end.  Suite green; sha3/shake/cshake/slh-dsa/
ml-dsa vectors pass.  No change for SHA-2 families (separate finalizers).

## Negative results (SLH-DSA absorb paths, 64-bit-limb Poly1305)

Three contained ideas measured after the lane-store win, all rejected:

* **Squeeze straight into the caller's buffer.**  SLH-DSA's `thash` and
  `prf_addr` squeeze into the shared 64-byte scratch and then `replace`
  `n` bytes into the caller's array.  Writing the digest directly into
  the caller's array (all callers pass an `n`-byte simple array) saved
  1.1% of 128f verification -- below the noise floor of a 9 ms
  operation -- and signalled a type error on one signing path, so the
  scratch copy stays.

* **One absorber instead of two `update-digest` calls.**  A 128f
  verification makes 6261 squeezes and 12522 `update-digest` calls
  (address, then data), each of which pays generic dispatch and
  range checks.  A `sha3-update-pair` that does the two `replace`s and
  one buffer-index update directly, guarded by the room left in the
  block, saved only 1.3% verify / 0.7% sign.  The two calls are not the
  bottleneck; the permutation is.

* **Poly1305 with 3 x 44-bit limbs (poly1305-donna-64 shape).**  This
  should cut 25 32x32 products per block to 9 64x64 products.  It does
  not, because SBCL boxes 128-bit intermediates: `(* a b)` followed by
  a shift to take the high half costs 12.8 ns per product versus 2.4 ns
  for the low half.  The whole block came out at 230 ns versus 13.4 ns
  for the existing 5 x 32-bit limbs.  For a future assembly version:
  `sb-kernel:%multiply-high` is 2.8 ns and correct, i.e. the backend
  *can* expose the high half, but only as a separate call; a VOP with
  `mulx` (or `mul` twice) is the only way to use the 9-product
  algorithm.  Poly1305 is otherwise already at 1.19 GB/s, roughly half
  of chacha-poly's 555 MB/s budget, so closing that row needs AVX2
  four-block Poly1305 (powers of r) more than scalar tuning.

## Camellia: four Feistel words in registers (81.9 -> ~125 MB/s)

Camellia's two-round Feistel was a DEFUN taking `(data data-start ...)`
and declared INLINE, with the block encryptor passing a four-element
stack-allocated array.  Inlining does not help when the callee has to
read and write an array: every two-round pair cost four loads and four
stores, and the block makes nine such calls.  SM4, ARIA and Blowfish
already write their rounds as macros over words; Camellia was the only
one left.

The Feistel is now a macro whose four arguments are places, and the
block encryptor/decryptor keep `v0..v3` as (unsigned-byte 32) locals.
The key schedule passes `(aref data 8)`-style places and is unchanged
otherwise.

  camellia 8 KB   81.9 -> 128.0 / 120.5 MB/s  (two runs, 1.47-1.56x)

Interleaved with a rebuild on each side, the old code measured 81.9 in
both orders.  C reference 163.1 -> gap 2.00 to ~1.3.  Camellia vectors
(16/24/32-byte keys) pass and the full SBCL suite is green.  Chacha,
SM4, ARIA, CAST5 and Blowfish already use the register-resident macro
shape, so this was the only cipher with the defect.

## Whirlpool: compute the eight output words into locals (75 -> 85 MB/s)

Each half-round ran `lookup-in-c`, which wrote its eight results into the
`l` row of the register array, and the caller then copied `l` into `k`
(or XORed it into `state`).  That is 8 stores plus 8 loads and 8 stores
per half-round, 20 times per block, for no semantic reason: the lookup's
eight results are a pure function of the old row, so they can be bound to
locals and written straight to the destination.  The macro now takes an
optional XOR source (and an optional round constant for element 0), so
the state round folds the K addition in as well, and `l` is unused.

  whirlpool block  840 -> 760 ns  (1.10x)
  whirlpool 8 KB    75 -> 85.3 MB/s in the same harness

Vector file passes and the full SBCL suite is green.  C reference is
198.8 MB/s, so the gap moves 2.65 -> ~2.33.  Whirlpool remains a
table-lookup bound digest (1280 lookups per block); this removes the
bookkeeping around them, not the lookups.

## SHA-3 padding without a fresh block (SLH-DSA verify 1.19x, sign 1.15x)

`sha3-finalize` padded by calling `pad-message-to-width`, which allocated
a new `rate-bytes`-long vector, copied the message into it, zero-filled
the rest, and then absorbed the whole rate block.  For an SLH-DSA hash
the message is 16 octets in a 136-octet rate, so three lanes carry data
and fourteen carry zeros -- and by the zero-XOR identity those fourteen
lanes need not be absorbed at all.  The finalizer now:

* pads the state's *own* buffer in place (pad byte, zero only to the end
  of the pad byte's lane, `0x80` terminator in the last lane or ORed
  into the pad byte when they share a lane);
* absorbs only the lanes up to and including the pad byte's lane;
* XORs `0x80 << 56` straight into the last state lane when the
  terminator is in a later lane.

`pad-message-to-width` is gone; `keccak-state-extract-output` also
declares `output-bytes` and `start` fixnum (the bounds computation was
going through generic `CEILING1`).

Interleaved builds, same harness, 8 KB digest and 128f:

  sha3/256        256.0 -> 256.0 MB/s   (one padding per message: no change)
  slh-dsa-shake-128f verify  8600 -> 7133-7266 us  (1.18-1.21x)
  slh-dsa-shake-128f sign   138.4 -> 119.2-122.4 ms (1.13-1.16x)

The whole sha3/shake/cshake vector set, the SLH-DSA and ML-DSA KATs and
the full SBCL suite pass (the KATs also exercise the `:cshake` and
`:keccak` padding bytes).

## SLH-DSA: reset the seeded digest instead of copying it (verify 1.24x, sign 1.17x)

After the padding change the profile still showed COPY-DIGEST (2.9%) and
UB8-BASH-COPY (3.7%) per hash.  Both come from re-seeding the working
digest by copying the template:

* SHAKE: the template has PUB-SEED in the buffer and has *not*
  permuted yet, so its state is all zeros.  `SLH-SHAKE-RESET` fills the
  25 lanes with zero, copies only the N seed bytes into the buffer and
  sets the buffer index; copy-digest moved 200 state bytes and 200
  buffer bytes instead.
* SHA-256/512: the template has just compressed its padded prefix
  block, so its buffer is empty (`buffer-index` 0) and only the
  register state and `mdx-amount` need copying.  Skipping the buffer is
  safe because the updater rewrites the buffer from index 0 and the
  finalizer only reads bytes it has written.

Cumulative against rev 1141 (same harness, interleaved builds):

  slh-dsa-shake-128f verify  8600 -> 6900-7000 us   (1.23-1.25x)
  slh-dsa-shake-128f sign   138.4 -> 118.2-118.9 ms (1.16-1.17x)
  slh-dsa-sha2-128f  verify  ~1940 -> 1900 us
  slh-dsa-sha2-128f  sign    33.3 -> 30.9 ms

The SHA-2 variants were already ahead of the C reference (0.62-0.68);
their gain is small because their per-hash state is smaller.  KATs for
both families, the SHA-3/SHAKE/cSHAKE vectors and the full suite pass.

### A note on table runs vs isolated A/B

The full-table runs take ~25 minutes and the later public-key rows come
out systematically slower than the same operations measured in a fresh
image (SLH-DSA 128f verify: 125 ops/s in the table, 142-145 isolated
before and after the padding change).  The C reference, measured in the
same long run, moves too (SLH 128f keygen C: 333 -> 213 ops/s between
two runs), so the "rows ahead/within 2x" counts move by several rows
without any code change.  The isolated interleaved builds are the
measurement of record for these rows; the table is a snapshot.

## ML-DSA: memoize the public matrix A on the key (verify 1.47x)

Each verification expand
s the KxL public matrix A from the 32-byte public seed RHO with
SHAKE128 and rejection sampling, and each signature does the same once
per call.  A depends only on RHO, yet `ml-dsa-gen-matrix` measured
120 us of a 373 us ML-DSA-65 verification (32%), and `rej-uniform` was
another 4.7% of the profile.

The key classes now carry a `(rho . matrix)` cache and
`ml-dsa-matrix-for-key` returns it when the stored RHO still matches;
the internal sign/verify functions take the key object as an optional
last argument (a `T`-named local was the first thing the compiler
rejected -- and the sign function already had a local *byte vector*
named `key`, so the parameter is `cache-key`).  A concurrent first use
may compute the matrix twice; both results are identical.  The matrix
is read-only at every use site (pointwise accumulation), so sharing it
is safe.

Isolated timings, ML-DSA (before -> after, verify):

  ml-dsa-44   251 -> 173 us
  ml-dsa-65   373 -> 253 us   (1.47x)
  ml-dsa-87    ~500 -> 347 us

Signing also reuses the cache (one matrix per signature instead of
building it inside the rejection loop's setup): 44 960 us, 65 1440 us,
87 1640 us.  Against the table's C references that puts 65 verify at
~1.4 and 87 verify at ~1.2 instead of 2.0 and 1.9.

Cost: the matrix is K*L 256-fixnum polynomials, i.e. 61 KB for ML-DSA-65
and 115 KB for ML-DSA-87, per key object that is actually used.  The
cached RHO is compared on every lookup (32 bytes) so a mutated key
cannot read a stale matrix.  ML-DSA KATs and the full SBCL suite pass.

The same applies to the C side of ML-DSA: the `ml-dsa-65 verify`
reference moved from 5633 to 8025 ops/s between two runs (openssl
speed only gets a handful of samples), even though our absolute rate
rose 2760 -> 3700 ops/s.  Treat the ahead/within-2x counts as ±7 rows;
use the absolute columns.

## ML-KEM: cache the decoded public state (encaps 1.29x, decaps 1.26x)

Encapsulation rebuilt three pure functions of the public key on every
call: the expanded KxK matrix A^T (27 us of a 173 us ML-KEM-768
encapsulation), `H(pk)` (5 us), and the bit-decoded public vector t
(~3 us).  Decapsulation re-encrypts during the Fujisaki-Okamoto check,
so it pays for the same matrix.

`ml-kem-public-state` returns `#(seed hpk pkpv matrix)` and caches it on
the key object as `(pk-copy . state)`; the stored bytes are compared
against the caller's slice on each call, so a mutated key cannot use
stale state.  Both the public-key and private-key objects have the slot
(decapsulation uses its own, from the public half embedded in sk).
X-WING calls the byte-level entries with no key object and keeps
computing fresh state, unchanged.

  ML-KEM-512   encaps 126 -> 91 us    decaps -> 99 us
  ML-KEM-768   encaps 173 -> 135 us   decaps 190 -> 151 us
  ML-KEM-1024  encaps 245 -> 187 us   decaps -> 220 us

Memory per used key: matrix K^2 polys (18 KB at 768, 32 KB at 1024)
plus the decoded public vector and a 0.8-1.6 KB copy of pk.  KATs for
ML-KEM and X-WING pass, as does the full suite.

### Host note: runaway CCL test processes

While chasing a 24 ms vs 28 ms SHA-512 timing swing I found three
Clozure test processes (`asdf:test-system :ironclad-unsafe/tests`,
started two days earlier) each pinning a core at 100%, with load
average ~4 on four cores.  They are killed now.  Every measurement on
this host before this point, including the recent full-table runs, was
taken with three cores saturated; the interleaved within-image A/B
comparisons are still valid (both sides share the load), but absolute
table numbers and cross-process single-shot timings were pessimistic
and noisy.  Re-run the table on the quiet host.

Also tested and rejected here: `(declaim (inline sha512-expand-block))`
-- SHA-512 stayed at 341 MB/s (the min-of-trials numbers for both
SHA-512 and SHA-384 converge once the party trick of a 4 ms scheduler
pause no longer lands in every trial).

## ML-DSA: cache tr with the matrix (verify ~3-5%)

Verification also hashed the whole public key (1.3-2.6 KB) with SHAKE256
to get `tr` on every call -- 8 us of a 253 us ML-DSA-65 verification.
The key cache is now `#(matrix tr)` keyed by the public seed, with TR
NIL on the signing path (signing takes TR from the private key).  The
same three verify rows as the matrix cache, a further ~3-5%; KATs and
the full suite pass.

## Keccak: fusing theta's D into the rho/pi pass is neutral

The round wrote `state ^= D` in one unrolled pass and then read the
state again for rho/pi.  Fusing them (rotate `state[x,y] ^ D[x]` into
the temporary) removes 50 of ~175 memory operations per round, but
measured exactly the same 400 ns per permutation, byte-identical
output.  The round is rotation/ALU-bound, not memory-bound; reverted
before commit.

## Measurement findings that change the remaining-gap list

The table's digest/cipher/aead rows come from a single 0.2 s
`time-op`, and allocation-heavy public-key rows run after the heap has
grown through the whole suite.  Both bias the C/Lisp ratio upward.
Isolated, fresh-image measurements of rows the table puts above 2:

  mceliece348864 keygen   table 9.26 ops/s (2.73) -> 12.89 ops/s (1.96)
  whirlpool               table 75.2 MB/s  (2.70) -> 93.1  MB/s  (2.18)
  sm3                     table 119.4 MB/s (2.47) -> 146.3 MB/s (2.02)
  sha512 family           table ~307 MB/s  (2.17) -> 341.3 MB/s (1.95)
  cast5                   table 79.0 MB/s  (2.08) -> 85.3  MB/s (1.93)
  camellia                table 79.5 MB/s  (2.34) -> 114   MB/s (1.63)

So the real set above 2x is roughly the field/NTT/FFT-bound public-key
rows plus chacha-poly, and the digest/cipher rows in the table are
mostly measurement artifact.

## The assembler ceiling

The remaining hand-assembly plan (MULX/ADCX/ADOX for field and
Montgomery arithmetic) is blocked by SBCL's backend here, not by the
algorithms: ADCX, ADOX, RORX and SHLX are not defined, and the goldilocks
multiply VOP already documents that SBCL's MULX is emitted with a VEX
prefix, which encodes VPMADD52LUQ (AVX-512 IFMA) instead of the legacy
BMI2 MULX.  Reaching the reference numbers on secp/ed448/RSA/DSA would
need either a patched backend or a project-scale port (Falcon's fpr
NTT/NTRU solve is the largest single remaining item).

## ML-DSA: unroll the NTT and the pointwise products (verify 1.4-1.6x)

The NTT was a three-deep loop nest, so every butterfly paid index
arithmetic and a branch, and the compiler could not see the constant
offsets.  The reference ntt.c is fully unrolled.  Both transforms are now
expanded at macroexpansion time with constant indices and literal zetas
(`unrolled-ml-dsa-ntt` / `-invntt`):

  forward NTT   3800 -> 1600 ns   (2.4x)
  inverse NTT   2400 -> 1800 ns   (1.33x)

Checked against the loop version on 200 random polynomials (0
mismatches).  The pointwise montgomery multiply and accumulate loops
(256 fqmuls each) are unrolled with DOTIMES-UNROLLED for the same
reason.  Whole-operation effect, isolated:

  ml-dsa-44 verify  173 -> 107-120 us
  ml-dsa-65 verify  240 -> 147-173 us
  ml-dsa-87 verify  347 -> 227-240 us

Against the table's C references that puts 65 verify *faster* than the
C side and 44/87 at ~1.1-1.4x, instead of 2.4/2.0/1.7.  Signing gains
less (the NTTs are a smaller share there); 65 sign 1.5 -> 1.4 ms.

Two things measured and reverted: inlining and unrolling
`vec-use-hint`'s 256-coefficient loop made verification 25% *slower*
(code growth in an already hot function), and binding the second lane
of each inverse butterfly to a local was neutral.  Note for builders:
the fully unrolled functions make ml-dsa.lisp memory-hungry to compile;
a 1 GB SBCL heap compiles the system but ran out while compiling a
second copy of the experiment in one image (`--dynamic-space-size 4096`
is a safe choice).

## Falcon: type the sampler arithmetic (keygen 90 -> ~69 ms)

The keygen profile showed GENERIC-+, GENERIC-*, GENERIC-- and
%DOUBLE-FLOAT together near 10%, i.e. boxed/generic arithmetic in
code that handles doubles and big integers.  `falcon-samplerz`,
`falcon-berexp` and `falcon-approxexp` had no type declarations, so
`(- z r)`, `(/ sigmin sigma)`, `(* x (ash 1 63))` and friends went
through the generic arithmetic dispatch and boxed their results.

Declaring MU/SIGMA/SIGMIN/X/CCS as DOUBLE-FLOAT and the integer
intermediates as INTEGER removes that: `%DOUBLE-FLOAT` falls from 2.6%
to 0.2% of the profile and `falcon-approxexp`'s total from 12.7% to
8.6%.  Keygen, best of five:

  before  90.4 ms
  after   61.6 / 81.6 / 68.8 ms   (spread is the NTRU solve's random
                                   retries, not the sampler)

Signing (4.4 ms) and verification (62-64 us) are unchanged.  The
remaining GENERIC-+/< entries are big-integer additions and comparisons
inside `falcon-basesampler`, which are bignums by construction.  Falcon
KATs and the full suite pass.

Cumulative for the table: falcon-512 keygen 9.8x -> ~7.5x.  The rest of
that row is the NTRU solve, which needs the reference's double-precision
NTT/NTRU path rather than bignum Karatsuba.

### Correction: the Falcon sampler gain is ~6-8%, not 1.3x

The first A/B compared one five-key run against one, and the NTRU
solve's random retries make keygen swing by 30-40%.  Repeating it five
times per side, on freshly built images:

  before (rev 1151)  80.8 84.8 79.2 81.6 81.6 ms   median 81.6
  after  (rev 1152)  64.8 86.4 64.0 84.0 76.8 ms   median 76.8

so the declaration change is worth about 6-8% of keygen, and the
earlier "90 -> 69 ms" was two lucky/unlucky samples.  It is still a
positive, zero-risk change (semantically identical arithmetic), and it
also removes the generic calls for other implementations, but it does
not move Falcon's 8x gap materially.

Lesson for the log: keygen-like operations with rejection/retry loops
need a distribution, not a single best-of-five number.

## Whirlpool: raw byte loads and eight accumulators (720 -> 640 ns)

The table transform read each source byte with a shift and a mask from a
UINT64 word, then loaded the table entry and XORed it in.  On SBCL the
byte can come straight out of the register vector with SAP-REF-8 (one
MOVZX), and with the transform rewritten as eight accumulators over the
sixty-four (table, byte) pairs, both the source byte and the table entry
are single loads:

  update-whirlpool-block   720 -> 640 ns per block (1.125x)

The SBCL path is separate (`update-whirlpool-block-sap`), so other hosts
keep the portable LDB version.  Verified against the portable function
on 200 random blocks (0 mismatches), the Whirlpool vector file passes,
and the full suite is green.  Digest level this is ~93 MB/s; against the
202 MB/s reference the gap moves 2.27 -> ~2.0.

## Ed448: allocation-free field exponentiation (~4% of verify)

`goldilocks-fe-expt` raised to power by binary square-and-multiply
through `goldilocks-fe-mul`, which allocates a sixteen-limb result for
every multiply -- an inversion is about 650 of them -- and routes every
product through the shared global `*goldilocks-mul-prod*`.  The
exponentiation now ping-pongs two private field elements through
`goldilocks-fe-mul-buf` with its own product buffer:

  inversion (q-2)   80 -> 66.7 us   (1.2x)

An Ed448 verification performs two such inversions, so this is about
4% of the operation (verify 680 -> ~648 us isolated; sign ~464 ->
440 us).  It also removes the shared buffer from this path.  Ed448
vectors and the full suite pass; the remaining 3x gap is the field
multiply itself (69% of verify) and needs ADX scheduling in the
goldilocks VOPs.

## Dead end: building bignums through SB-BIGNUM internals

`octets-to-integer` costs 3.3 us for a 256-byte RSA signature (11% of a
30 us verify): it builds the value with 32 `(ash chunk 64)` +
`logior` steps, each copying the growing bignum.  A direct construction
from 64-bit digits would be ~120 ns:

    (%allocate-bignum nd) + (setf (%bignum-ref b d) chunk) +
    (%normalize-bignum b (* 2 nd))

It computes the right values (checked against the portable function on
hundreds of thousands of random ranges), but the resulting objects are
not safe: `=` and `eql` intermittently return NIL for two of them while
`(- a b)` is 0, i.e. the header (length/sign word) can be left in an
inconsistent state.  One-digit bignums whose digit has bit 63 set even
normalize as negative.  Adding a zero top digit reduces but does not
remove the anomalies.  Not shipped: a malformed bignum is worse than a
slow conversion.  Circumstantial evidence also points at `%allocate-
bignum` not initialising the sign/length header the way
`%normalize-bignum` expects; using it correctly would mean tracking
SBCL's internal header encoding, which is too fragile for a public
crypto path.

Left in place: the portable 64-bit-chunk loop.  The little-endian
branch is still per-byte (curve25519/ed25519/ed448 scalars, 32-56
bytes), but those are 0.4-2 us against operations of 50-650 us.

## Where the remaining public-key time goes (measured)

RSA-2048 verify (30 us): 17 Montgomery modmuls at 1.6 us each, plus
3.0 us to convert the base into Montgomery form `(mod (* base 2^2048)
m)` and 0.8 us to turn the result limbs back into an integer.  The
modmul is instruction-throughput bound (~2 * n^2 products plus six
instructions each); replacing the two conversions with a cached
`R^2 mod m` would only save ~1.4 us of 30, so the remaining gap is the
modmul itself -- an ADX/MULX implementation, which this SBCL backend
cannot assemble.

secp256r1 verify (208 us): 71% of samples in
`secp256r1-fe-mont-mul`, 18.6 us in
`modular-inverse-with-blinding` (9%; Euclid, already the faster of the
two inverses here), 2 us decoding the (uncompressed) public point.
Same ceiling.

## Cross-implementation check after the unrolled code

The ML-DSA unrolled NTT, the SBCL-only Whirlpool SAP path and the
Falcon/Goldilocks declaration changes were checked on Clozure 1.13:
the system loads, and the ML-DSA, Falcon, Ed448, ML-KEM, X-WING,
Whirlpool and SHA3-256 vector files all pass.

ECL also builds the current tree (the unrolled ML-DSA functions become
very large C functions but compile; the load takes on the order of
fifteen minutes on this host).

## Negative result: a Montgomery squaring VOP loses to the CIOS multiply

Half of the modmuls in an exponentiation are squarings, and a square
needs only N(N+1)/2 products instead of N^2.  I built a column-wise SOS
square VOP (three-word accumulator per column, doubled off-diagonal
products, shared with the SOS multiply's reduction) and checked it
against the multiply VOP on 600 adversarial inputs for 16 and 32 limbs
(random, all-ones, high-bit-only, alternating) -- all identical.

It is still not worth using:

  SOS multiply   1640 ns
  SOS square     1400 ns   (halved products, 3-word carries)
  CIOS multiply  1320 ns   (what the code uses)

The column square is 15% faster than the SOS multiply but the
interleaved (CIOS) multiply is faster than both, because it never
materialises the 2N-word product and its reduction step runs while the
multiplier and accumulator are already in registers.  Exploiting the
symmetry requires column-wise accumulation, which is incompatible with
CIOS's row-by-row reduction, and the extra carry bookkeeping of a
three-word column accumulator eats most of the halved products.
Reverted; no code change.  This closes the "dedicated squaring" idea
for the Montgomery paths: the current VOP selection is already the best
of the three shapes.

## Negative result: a global Montgomery-context cache

Converting the base into Montgomery form costs 3.0 us of a 30 us
RSA-2048 verify `((mod (* base 2^2048) m))`.  With `R^2 mod m` cached,
the conversion is one 1.3 us VOP multiply; the exponentiation also
skips recomputing N0 and the modulus limbs.  A per-modulus cache in
MATH.LISP (EQ-matched, immutable contexts, bounded list) gave the
expected saving for repeated verifications, but it is the wrong shape:
RSA *key generation* runs hundreds of Miller-Rabin exponentiations on
fresh candidate moduli, so every one of them paid to build a context
(two 4096/2048-bit divisions) and the cache never hit.  A single
`generate-key-pair :rsa` run slowed enough to hit a 15-minute timeout.

The clean version would hang the context off the key object and thread
it through `rsa-core`/`power-mod`; that is ~5.7% of RSA verify (and
under 1% of anything else, since signing uses CRT exponents on p and
q).  Not worth the API churn for one row.  Reverted; no code change.

## RSA: per-key Montgomery context (verify 30 -> 28 us)

The global context cache recorded above was the wrong shape; the fix is
a per-key one.  `rsa-key` carries a lazily built `MONT-CONTEXT`, and
`rsa-core`/`expt-mod/unsafe`/`power-mod`/`montgomery-expt` take it as an
optional argument (validated against the modulus and limb count).  With
`R^2 mod n` cached, the base conversion is one 1.3 us Montgomery
multiply instead of a 3.0 us `(mod (* base 2^2048) n)`; N0 and the
modulus limbs are reused as well.

  rsa-2048 verify   30.0 -> 28.0 us   (1.07x, gap 2.06 -> 1.92)

Signing is unchanged: it uses the CRT exponents on p and q, so the
modulus-n context is not on its path (and its exponentiation time is
negligible next to padding).  The context is built on the first
exponentiation with the key and never mutated (the exponentiation gets
its own copy of R); key generation is untouched, which is the thing the
global cache broke.  RSA vectors and the full suite pass.

## Whirlpool: table-transform VOP (640 -> 440 ns; digest 93 -> 146 MB/s)

The Lisp/SAP version loads a table entry and XORs it into an accumulator
(two instructions after the byte fetch).  The VOP keeps the eight
accumulators in registers and uses `XOR reg,[table+index]` memory
operands, with each source byte fetched by a single MOVZX from the
register vector.  The round constants are appended after the 2048 table
entries in one combined array, because four descriptor arguments plus
eight accumulators overflow the register file (three arguments fit).

  block            640 -> 440 ns   (1.45x)
  8 KB digest      93.1 -> 146.3 MB/s (1.57x)

Checked against the SAP implementation on 500 random blocks (0
mismatches); the Whirlpool vector file and the full suite pass.  C
reference 202.7 MB/s, so the gap moves 2.18 -> ~1.39 (table row
2.28 -> ~1.5).

Two SBCL-VOP traps worth remembering: generator-time loops that look up
an accumulator *symbol* from a vector and pass it to INST hand the
assembler the symbol rather than the TN (all code generation must happen
at macroexpansion time), and a `:qword` size prefix on MOV/XOR with EA
operands confuses the instruction combiner (the operands reach it
unevaluated).

## Benchmark: throughput rows now take *TRIALS* samples

`BYTES-PER-SECOND` took one 0.2 s sample while `ITEMS-PER-SECOND` used
`IRONCLAD_BENCH_TRIALS` (documented as "the number of timing samples per
operation").  A pause landing in that single sample depressed a digest
or cipher row by 5-25%: whirlpool read 75-138 MB/s across runs against
146 MB/s isolated, sm3 119-146 against 146, sha512 305-314 against 341.
The throughput helper now does what the ops/s helper always did, best of
*TRIALS* samples (the same peak-of-samples used by the A/B measurements
in this document).  The C references remain OpenSSL averages, so the
ratios stay approximate.

Effect on one run: the digest rows move to their isolated values
(sha512 314 -> 343 MB/s = 1.96x, sha384 343 = 1.97x, whirlpool 138 ->
143.6 = 1.38x); the ahead/within-2x counts move by a few rows in either
direction because the C side moves too.

This means several rows previously listed above 2x (sha512 family,
whirlpool, mceliece, cast5) were measurement artifacts rather than
performance gaps.

## SM3: schedule and rounds VOPs (460 -> 240 ns; digest 146 -> 256 MB/s)

The earlier round-only VOP gave just 1.06x because the message schedule
(40% of the block) stayed in Lisp and dominated.  With a schedule VOP as
well -- 52 W expansions of P1 (three rotates/XORs) plus the 64 W' words --
both share one 140-word buffer (state 0..7, W 8..75, W' 76..139) that
lives on the digest, so no per-block allocation:

  block            460 -> 240 ns   (1.92x)
  8 KB digest     146.3 -> 256.0 MB/s (1.75x)

`sm3-hash` fills W[0..15] from the message bytes, runs the two VOPs, and
copies the state back; the portable unrolled-Lisp path stays for other
hosts.  500 random blocks match the portable function, the SM3 vector
file passes, and the full suite is green.  C reference 293.7 MB/s, so
the gap moves 2.17 -> ~1.15.

This is the second lookup/rotation-heavy digest to fall to the
"unroll-in-a-VOP with a shared scratch buffer" recipe (Whirlpool was the
first); unlike the round-only attempts it works because the *whole*
block, schedule included, is in the VOP.

## ECDSA signing: present, verified; DESTRUCTURE-SIGNATURE :ECDSA added

A report that ECDSA signing is missing could not be reproduced on rev
1168.  Checked on SBCL and CCL 1.13:

* generate-key-pair for :ecdsa and every curve kind and alias
  (:p-224/:p-256/:prime256v1/:p-384/:p-521, the five secp* kinds) ->
  SIGN-MESSAGE and VERIFY-SIGNATURE round-trip;
* five curves x four digests (:sha1 :sha256 :sha384 :sha512) x message
  lengths 0/1/16/32/100 -> all verify;
* 200 random signatures plus 200 bit-flipped ones per curve -> 0 wrong
  accepts/rejects;
* DER encode/decode round trip on all five curves;
* pre-hashed messages (the documented use: hash first, sign the digest),
  the nonce override, and MAKE-PRIVATE-KEY from :x alone (no :y).

The suite already covers this: ECDSA-SIGNATURE-TEST signs with a fixed
nonce and compares bytes, and ECDSA-RFC6979-TEST signs twice and checks
the deterministic signature.  Both pass.

The one genuinely missing method was DESTRUCTURE-SIGNATURE for the
generic :ecdsa kind (MAKE-SIGNATURE :ecdsa existed).  It now splits by
length (56/64/96/132 = P-224/P-256-family/P-384/P-521) and signals
INVALID-SIGNATURE-LENGTH otherwise.  The values themselves do not
depend on the curve.

Possible causes of the report, for the reporter: loading upstream
:ironclad rather than :ironclad-unsafe (the :ecdsa kind dates from
rev 662), expecting SIGN-MESSAGE to hash the message or return DER (it
signs an already-hashed message and returns raw R || S; use
DIGEST-SEQUENCE and ECDSA-SIGNATURE-TO-DER, whose argument order is
(curve signature)), or passing RSA-style key parameters (:x is the
private octet string here, not :d/:n).

## Poly1305: x86-64 block-loop VOP (1.32x MAC, 1.15-1.34x chacha-poly)

The portable block loop in src/macs/poly1305.lisp spends about half of
its instructions managing SBCL's tagged-fixnum representation: the five
32-bit accumulator limbs and the 64-bit partial products are reloaded
from [RBP-n] slots with a SHL/SAR pair around every multiply, and the
carry chain masks every intermediate back into a fixnum.  The loop
disassembles to 223 instructions for 16 bytes (~52 cycles/block,
1.24 GB/s).

The new POLY1305-BLOCKS VOP keeps the five active limbs and two scratch
words in general registers, parks the four 64-bit product accumulators
in XMM registers (the thirteen allocatable words cannot hold five
limbs, four accumulators, two scratch words and the three live
pointers), and uses the precomputed R0..R3/RR0..RR3 words directly as
IMUL memory operands.  It loops over whole 16-byte blocks itself, so
the per-block Lisp loop overhead is gone; the padded tail block still
uses the portable code.  The loop is 119 instructions.

The R/RR folding terms are computed once when the MAC is keyed and
stored in a new 8-word (unsigned-byte 64) slot (R64), instead of being
recomputed on every update call.

| | before | after |
|---|---|---|
| Poly1305 8 KB MAC (table) | 1.249 GB/s | 1.650 GB/s (1.32x) |
| Poly1305 8 KB MAC (isolated) | 1.241 GB/s | 1.552 GB/s |
| chacha-poly encrypt 8192-byte message (table) | 571 MB/s | 656 MB/s |
| chacha-poly, preallocated mode | 656 MB/s | 789 MB/s |
| block loop | 223 instructions | 119 instructions |

The chacha-poly row's C/Lisp gap falls from 3.79 to 3.10.  The remaining
row is now limited by ChaCha as much as by Poly1305: the AEAD runs at
789 MB/s with a preallocated mode, against a serial bound of 853 MB/s
(ChaCha 1.81 GB/s, Poly1305 1.65 GB/s), and the four-block AVX2 ChaCha
core measures 1.96 GB/s (1.73 cycles/byte) even with no counter or glue
work.  A better ChaCha core is now the larger half of that gap.

Note that the table's AEAD shape creates a fresh mode per message; that
setup measures ~1.5 us, which is 12% of an 8192-byte call.  Making
instantiation cheaper would move every AEAD row, but the setup is
ordinary CLOS/cipher keying and was not touched here.

Correctness: RFC 8439 section 2.5.2, 200 random messages plus every
boundary length around 16/32/.../1024 against an independent bignum
Poly1305, and 300 random buffers comparing the VOP loop byte-for-byte
with the portable loop.  Full SBCL suite green; the same differential
test passes on CCL 1.13, where only the portable path exists.

Two things that did not work, recorded so they are not retried:

* Putting the 64-bit intermediates in (unsigned-byte 64) arrays to stop
  SBCL from using a tagged representation: 701 MB/s, 40% *slower* than
  the 1182 MB/s baseline.  The extra load/store traffic costs more than
  the tag shifts it removes.
* Reordering the carry so the two halves of each input word are summed
  before the incoming carry (one dependent add per limb instead of
  three): 1555 MB/s versus 1552 MB/s, i.e. no change.  The loop is
  instruction-throughput bound, not latency bound, so shortening the
  dependency chain does not help.  (The reordering is kept anyway: it
  is the same speed and slightly shorter.)

## SHA-512: cheaper round body and expansion folded into the rounds

Both changes are portable Lisp; no VOP was needed (see the negative
result below).

The round macro had three problems.  It computed Ch with `logandc1`
and Maj with three separate `logand`s, and it buried the message and
constant words inside a deep `mod64+` nest, so SBCL kept six or more
values live per round and spilled about a dozen words per block.  It
now uses explicit `let*` steps, Ch = g ^ (e & (f ^ g)) and the
symmetric Maj, which drops the function from 4208 to 3433
instructions (80 rounds, ~43 per round).

The 64-word message expansion used to be a separate pass
(SHA512-EXPAND-BLOCK, 127 ns of the 393 ns block).  It is now folded
into the first 64 rounds exactly as the reference schedules it: round
i computes W[i+16] before consuming W[i].  The standalone expansion
function is gone.

| | before | after |
|---|---|---|
| rounds only | 266 ns/block | - |
| expansion pass | 127 ns/block | folded into the rounds |
| whole block | 393 ns | 321 ns |
| 8 KB digest (table shape) | 341 MB/s | 398 MB/s (1.17x) |
| sha512 family gap | 1.82-1.85 | ~1.56 |

What did not work: I expected folding the expansion to hide most of
its cost, but it recovered only ~10% of the block time.  The round
body is throughput-bound, not latency-bound: 80 rounds at ~11 cycles
each with ~37 instructions per round, against ~8.75 cycles/round for
the C reference.  A VOP would remove roughly one spill/reload per
round (on the order of 7%), not the 30% that would be needed to reach
the reference, so none was written.  The remaining headroom is in the
six `mov` copies that precede the rotates; x86 `ror` is two-operand
and SBCL cannot assemble the three-operand `rorx`.

Everything (RFC 6234 vectors, the suite, and the CCL build) passes;
the four SHA-512 variants produce the standard "abc" digests.

## SM4: x86-64 block VOP (1.43x, gap 1.81 -> 1.27)

The portable encryptor expands to 2449 instructions per 16-byte block
(~76 per round) because every 32-bit word is a tagged fixnum: each
byte fetched from the S-box vector is shifted left by one (tagged),
shifted into place, OR-ed in, and the result untagged before every
rotate, and the S-box base is reloaded from its constant for all 128
lookups.

The VOP keeps the four state words in registers as plain 32-bit
values, forms H(X) from four pre-shifted tables (T0[b]=S[b]<<24,
T1[b]=S[b]<<16, T2[b]=S[b]<<8, T3[b]=S[b]) held in one 1024-entry
array, and unrolls all 32 rounds: 1017 instructions instead of 2449.
The tables follow the 32 round keys in the cipher's existing
round-key array, so the VOP takes one array argument (five argument
registers); with a separate table argument the register file could not
pack the sixth argument.

| | before | after |
|---|---|---|
| SM4 ECB 8 KB | 78.3 MB/s | 112.0 MB/s (1.43x) |
| block | 205 ns | 143 ns |
| block instructions | 2449 | 1017 |
| C/Lisp gap | 1.81 | 1.27 |

The block is now latency-bound rather than instruction-bound: the
15-cycle round is the serial chain xor -> byte extract -> T load ->
three ORs -> four rotate-xors, against 12 cycles/round for the C
reference (141.9 MB/s).  Turning the OR chain and the rotate-xor chain
into trees would save at most two of those fifteen cycles and was not
attempted.  The decryptor still uses the portable code: the benchmark
only measures encryption, and a round trip exercises both.

Correctness: the GB/T 32907-2016 block vector and its million-iteration
vector, 200 random encrypt/decrypt round trips, and the full suite.

## Measurement notes (rev 1173)

Three full benchmark runs were made after the Poly1305/SHA-512/SM4
changes and the numbers swing more than the changes themselves in some
rows: sha512 read 400, 358 and 398 MB/s, falcon keygen 12.9, 10 and 15
ops/s, and the OpenSSL reference for the same row moves with them
(sha512 C: 673, 663, 619 MB/s).  The host has background glusterfs
daemons and leftover multi-day SBCL processes were still resident;
those were killed before the last run, which is the one committed.
Anything within 10% of the previous table is noise, not a regression.
The committed figures are: poly1305 1.689 GB/s (gap 3.79 -> 3.18 on
chacha-poly), sha512 398 MB/s (1.82 -> 1.55), sm4 110 MB/s
(1.81 -> 1.27), with 50 rows ahead of C, 63 within 2x and 10 beyond.

## Blowfish: x86-64 block VOP (1.57x, gap 1.73 -> 1.10)

Same pathology as SM4: the portable block is a chain of tagged
fixnums, so each of the 68 S-box lookups per block pays a shift to
untag the byte index, a shift to tag the loaded word, and an untag
before the add/xor it feeds.  The block runs at ~16.6 cycles per round.

The VOP keeps the two halves in 32-bit registers, extracts the four
byte indices with shift/mask only, and reads the S-box words straight
into the accumulating register.  The P-array xor is applied to the
half that F consumes (not the destination half: getting that backwards
was the first version, and the known-answer test caught it
immediately).

| | before | after |
|---|---|---|
| Blowfish ECB 8 KB | 102 MB/s | 160 MB/s (1.57x) |
| block | 78 ns | 50 ns |
| instructions per block | - | 326 (~20 per round) |
| C/Lisp gap | 1.73 | 1.10 |

Correctness: the classic key FEDCBA9876543210 / block 0123456789ABCDEF
vector (0ACEAB0FC6A0A28D), 200 random encrypt/decrypt round trips
(decrypt still uses the portable code), and the full suite.

Follow-up on the run-to-run noise: across five full runs the AEAD rows
swing the most (chacha-poly 571, 656, 636, 651, 600 MB/s) because the
mode setup is 1.5-2 us of the 8 KB call and the benchmark builds a
fresh mode per message; the local-C falcon reference also drifted
(74.8 -> 101.7 ops/s) and the borderline public-key rows (ml-dsa-87
keygen, slh-dsa-shake-256s) flip across the 2.0 line between runs.
Treat changes of one or two rows at the 2x boundary as noise.

## CAST5: x86-64 block VOP for the 16-round form (1.60x, gap 1.86 -> 1.17)

The portable block is 870 instructions (~54 per round): every byte
index and S-box word is a tagged fixnum, and the variable rotate drags
the tag through as well.

The VOP keeps the two halves in 32-bit registers, reads the mask and
the rotate count from a per-key array (the four round S-boxes are
copied in front of them, so the whole thing is one array argument),
and uses `rol r32, cl` for the variable rotate.  The three F variants
(add, xor and reverse-subtract mask transforms) are unrolled with the
same register-renaming trick as Blowfish.  Only the 16-round form
(keys longer than ten octets, which includes the 16-octet key the
benchmark uses) takes the VOP; the 12-round form stays portable.

| | before | after |
|---|---|---|
| CAST5 ECB 8 KB | 88 MB/s | 141 MB/s (1.60x) |
| block instructions | 870 | 382 |
| C/Lisp gap | 1.86 | 1.17 |

Assembler note for the future: a variable rotate has to be written
`(inst rol :dword dst :cl)`.  Passing the RCX temporary as an operand
is accepted when the VOP is defined, but at assembly time the emitter
tries to encode it as an immediate byte and fails with "REG is not of
type (INTEGER -128 255) when binding BYTE".

Correctness: RFC 2144 vector (key 0123456712345678234567893456789A,
block 0123456789ABCDEF -> 238B4FE5847E44B2), 300 random encrypt/decrypt
round trips (decrypt stays portable), a 12-round key round trip, and
the full suite.

## ARIA: hoisting the S-box tables is neutral (reverted)

The portable ARIA block expands to 3199 instructions and runs at
~4.6 IPC, so it is instruction-throughput bound.  A sixth of those
instructions are reloads of the four S-box table pointers: every one of
the 256 lookups per block (four tables x four words x sixteen
S-box layers) re-reads the symbol value that holds the table.

Binding the four tables in local variables and using them in the
S-box macros does not help: SBCL's register allocator is already at
its limit with four state words, the round temporaries and the key
pointer, so it reloads the local bindings exactly as it reloaded the
globals.  The disassembly is byte-for-byte the same length (3199
instructions, 256 RIP-relative loads) and the measured difference was
within noise (81.3 vs 78.6-79.1 MB/s for the 32-byte-key row).  The
change was reverted.

Moving this row needs a block VOP like the SM4/Blowfish/CAST5 ones,
with one combined 1024-entry table so the lookups share a base
register; there is no useful Lisp-level headroom left.

## ChaCha: vpshufb rotates in the four-block AVX2 core (1.19x)

The core's two byte-granular rotates (rotl16 and rotl8) were three
instructions each (shift, shift, or) and sat on the quarter-round's
dependency chain.  A single `vpshufb' does the same thing with a
per-lane byte mask: rotl16 is the mask 2,3,0,1 per 32-bit lane and
rotl8 is 3,0,1,2.  The two 32-byte masks are loaded into ymm registers
once per call (two new array arguments); the rotl12 and rotl7 rotates
stay as shift pairs.

| | before | after |
|---|---|---|
| AVX2 four-block core | 1.96 GB/s | 2.41 GB/s |
| ChaCha 8 KB | 1.81 GB/s | 2.15 GB/s (1.19x) |
| chacha-poly 8 KB message | 789 MB/s | 852 MB/s |
| C/Lisp gap (chacha) | 1.93 | 1.61 |

Deleting the two rotates entirely (mathematically wrong; used only as a
timing bound) measured 2.41 GB/s, so the shuffle version captures the
whole gain available from those instructions.  Further improvement
would need more independent block groups than the sixteen ymm
registers can hold.

Correctness: the RFC 8439 zero-key/zero-nonce keystream block, a
5000-byte round trip (which takes the four-block path), the
chacha-poly AEAD round trip, the full suite, and CCL.

## Keccak: array-based round rewrite is neutral (reverted)

The current KECCAK-ROUNDS binds all 25 state lanes and all 25 scratch
lanes as locals; the register allocator spills most of them, so the
loop body contains 228 stack-slot references.  I rewrote the round to
keep the state in its array and the scratch lanes in a stack-allocated
25-word array, fused theta's application with rho/pi (the old code
wrote all 25 lanes back after theta and read them again for rho), and
read each chi row into five locals.  The result:

| | old | rewritten |
|---|---|---|
| loop-body instructions | 367 | 370 |
| stack-slot references in the body | 228 | 1 |
| sha3 8 KB | 152.2 MB/s | 151.4 MB/s |
| sha3/256 8 KB | 269.1 MB/s | 270.9 MB/s |

Neutral.  The spilled locals and explicit array accesses cost the same
in the body, and the permutation already runs at roughly four
instructions per cycle, i.e. at the machine's throughput limit for this
formulation.  The C reference's edge comes from register blocking
(holding a row's five lanes plus the temporary row in registers), which
needs a VOP; that is a much larger change than the cipher VOPs because
the 25-lane state does not fit the register file.  Reverted; the
keccak-rounds macros are unchanged.

## Keccak: a register-blocked VOP is slower than the Lisp (reverted)

After the array rewrite came out neutral I built the full Keccak-f
VOP the analysis pointed to: all 24 rounds unrolled, one chi row in
five registers, theta's D values in five registers, rho and pi fused
with theta, and the chi scratch appended to the state array (the chi
layer cannot be done in place: every output row reads one lane from
every input row, so an in-place version corrupts the lanes later rows
need).  The round constants are immediates because a second array
argument does not fit the register file.

It is correct (SHA3-256/SHA3-512 KATs pass) and has no spills: 297
instructions per round, one stack reference in the whole function,
against 370 instructions and 228 stack references for the Lisp body.

It is also slower:

| | Lisp | VOP |
|---|---|---|
| sha3 8 KB | 151.4 MB/s | 142.1 MB/s |
| sha3/256 8 KB | 269.1 MB/s | 252.2 MB/s |
| instructions per round | 370 | 297 |

The unrolled function is about 7100 instructions.  The Lisp loop body
fits Zen 2's op cache and retires well over four instructions per
cycle; the unrolled VOP decodes from the instruction cache on every
round and pays for it.  A looped VOP would need the round constants
from a second array (thirteen allocatable words, minus the state
pointer, five lanes, five D values and a temporary, leaves none), and
moving the D values to memory to make room re-adds the loads the VOP
was meant to remove.

Both Keccak experiments were reverted; Keccak stays on the Lisp path.
The remaining 1.5-1.6x gap to the C reference is a code-generation
difference (three-operand rotates, `rorx`, and a loop layout that
fits the op cache) that this backend cannot express within the
register budget.

## CCM: fuse the CBC-MAC run into one VOP call (1.11x)

CCM's CBC-MAC loop called the one-block AES-NI VOP once per 16-octet
block, reloading and storing the chain through memory each time.  The
new AES-NI-MAC-BLOCKS VOP keeps the chain in an xmm register for a
whole run of blocks and loops internally.

| | before | after |
|---|---|---|
| CCM encrypt-message, 8 KB | 770 MB/s | 858 MB/s |
| MAC alone | 1049 MB/s | 1055 MB/s |

Only 11%: the MAC loop is latency-bound on the serial AES chain
(10-14 dependent AES-NI rounds, ~52 cycles per block), so removing
the per-call overhead cannot recover much.  The remaining CCM gap to
C is about that serial AES latency plus the per-message mode setup.

## Correction: the assembler accepts ADCX/ADOX/RORX/SHLX

Earlier entries say the SBCL backend cannot encode the ADX/BMI2
instructions, which is why the field arithmetic is stuck at its current
speed.  That is wrong for four of them.  A probe VOP whose generator
emitted

    rorx u b 7 ; adcx r u ; adox r b ; shlx u b a

compiled without complaint (it only failed to *load* because the probe
had no defknown, which is unrelated).  So RORX, ADCX, ADOX and SHLX can
be emitted by this backend today.

What this means: the field VOPs for secp256r1/secp224r1/secp521r1,
ed448 and dsa could be rewritten with three-operand rotates and
dual carry chains.  That is the largest remaining opportunity
(5 rows at 2.2-4.3x).  MULX is still suspect -- the earlier note says
it is mis-encoded as VEX -- and needs its own probe before use.

Not attempted here: the rewrite is a multi-hour piece of assembly work
per curve and needs a fresh session.

## Follow-up: MULX is fine; the "VEX" note was a misreading

The earlier note said MULX "is mis-encoded as VEX".  It is not: MULX is
*defined* as a VEX-encoded instruction (VEX.LZ.F2.0F38.W{0,1} F6 /r).
A probe VOP

    (inst mov rd a)
    (inst mulx hi lo b)

assembles to `C4 42 FB F6 C1` = MULX r8, rax, r9 with RDX implicit --
the correct encoding: three-byte VEX, map 0F38, pp=F2, W=1 for 64-bit
operands.

So the whole BMI2/ADX set the field arithmetic wants -- RORX, SHLX,
ADCX, ADOX, MULX -- is available and correctly encoded by this
backend.  The claim that the field rows are "blocked by the assembler"
was wrong, and with it the reason those rows (secp256r1 3.9/3.1,
secp224r1 3.7/2.6, secp521r1 3.0, ed448 3.1/2.5, dsa 2.7) have not
been touched.

They are now ordinary work: rewrite the existing field VOPs to use
three-operand rotates and the two carry chains.  That is the highest
value item left by a wide margin.

## P-256: register-resident CIOS field multiply (1.6x on point ops)

The 4-limb Montgomery multiply wrote every partial product through a
nine-word heap scratch and used MUL (implicit RAX/RDX) with one serial
carry chain.  It is now a coarsely integrated operand scan that keeps
the accumulator T0..T5 in registers and uses MULX with the two carry
chains: ADCX rides the low halves, ADOX the high halves, so the
products do not serialise on one flags register.  The heap scratch
argument is gone.  The special limbs of P (P[0] = -1, P[2] = 0) remove
half of the sixteen reduction products: the first column is NEG/LEA,
the third only propagates the two carries.

Add and subtract were rewritten the same way: one ADD/ADC chain in
registers, then a single masked conditional subtraction of P.  The old
versions materialised each carry with MOV/ADC into memory.

| | before | after |
|---|---|---|
| field multiply | 54 ns | 43 ns |
| point double | 403 ns | 242 ns |
| point add | 676 ns | 405 ns |
| scalar ladder | 251 us | 149 us |
| fixed-base multiply | 20.7 us | 13.3 us |
| sign | 59.3 us | 47.8 us |
| sign (table, ops/s) | 17.19k | 19.85k |
| verify (table, ops/s) | 4.84k | 7.45k |

Point operations improve by about 1.6x.  Sign improves less because
RFC 6979 nonce generation (~4.9 us) and the scalar inverse (~18.6 us,
bignum Euclid) sit outside the field code; the final affine conversion
in EC-ENCODE-POINT is another fixed-window field inversion.  Those are
the next targets.  The full SBCL suite passes (689 tests, including the
ECDSA vectors and the field layer tests).

### P-256 table refresh (rev 1190)

The full table was rerun three times after the field rewrite.  The host
was noisy enough that unrelated rows moved 10-40% between runs (the
same SHA-512 code measured 356.9M and 387.6M bytes/s in consecutive
runs), so the numbers below are from the run whose digest and AEAD
rates matched the previous snapshot.

| row | before | after | C | gap |
|---|---|---|---|---|
| secp256r1 sign | 17.19k | 18.58k | 52.48k | 3.08 -> 2.82 |
| secp256r1 verify | 4.84k | 7.17k | 18.40k | 3.84 -> 2.57 |

Verify gains the full 1.48x; sign gains less because the scalar inverse
and RFC 6979 nonce generation are unchanged.  The table stands at 52
rows ahead, 60 within 2x and 11 beyond; the eleventh is RSA verify at
2.02, a borderline row that measured 1.94 in the previous snapshot.

### Correction: zero multiplier in the P-256 reduction

The first version of the register CIOS computed the high half of
MRED*P[0] as RD-1 unconditionally.  That is right only for RD > 0; for a
zero accumulator word it produced -1 and turned 0*x into a wrong value.
Two thousand random pairs never hit it; an exhaustive boundary set
{0, 1, 2, P-1, P-2, (P-1)/2, 2^255, 2^256-1} found it at once.  The high
half is now RD-1 with the subtraction's borrow added back, so RD = 0
gives zero.  Boundary and random tests pass again.

## P-256: fast scalar inverse and two-level base-table selection

Two non-field costs dominated signing after the field rewrite.

**Scalar inverse.** SIGN and VERIFY invert a scalar modulo the group order
with bignum Euclid, measured at 17-18.6 us.  A second register CIOS VOP
now does the same job for L (no special limbs; the reduction word is
T[0]*N0 mod 2^64), and a fixed four-bit window over the public exponent
L-2 drives it.  Control flow depends only on L-2 and the full sixteen
entry table scan is linear, so the inverse is constant-time in the
input; the previous Euclid inverse was variable-time and needed
blinding.  Measured 7.8-7.9 us, 2.2x faster, and the blinding random
draw disappears from the sign path.

**Base-table selection.** The fixed-base positional table stored each of
32 rows as 256 affine points, and selected a byte with a 256-entry scan
(158 ns, 5.1 us of every base multiplication).  Each row is now a 16x16
matrix: a 16-entry scan picks the sub-row, a second picks the point
(53 ns).  The same points are shared, so the table size is unchanged.

| | before | after |
|---|---|---|
| scalar inverse (256-bit) | 17.0 us | 7.9 us |
| select-base | 158 ns | 53 ns |
| fixed-base multiply | 13.3 us | 11.1 us |
| sign (direct) | 42.2 us | 36.3 us |
| verify (direct) | 133.8 us | 129.9 us |

Sign is now about 1.9x the C reference in direct measurement; verify is
still dominated by the ~100 us joint scalar multiplication.

Gotcha recorded for later: with (SAFETY 0), extracting the four limbs of
a bignum with `(ldb (byte 64 (* 64 i)) v)` in a `DOTIMES` returned the
wrong words for a 224-bit value; the equivalent `LOGAND`/`ASH` loop is
correct.  The boundary test caught it because the derived R constant came
out as 68 bits instead of 224.

### P-256 table refresh (rev 1193)

| row | rev 1191 | now | C | gap |
|---|---|---|---|---|
| secp256r1 sign | 18.58k | 27.61k | 53.37k | 2.82 -> 1.93 |
| secp256r1 verify | 7.17k | 7.47k | 18.72k | 2.57 -> 2.51 |

Sign crosses 2x for the first time.  Verify improves little in the
table because its ~100 us joint multiplication is untouched.  The host
remains noisy: McEliece-348864 and ML-DSA-87 keygen drifted above 2x in
this snapshot without any change to their code, so the aggregate count
(49 ahead, 63 within, 11 beyond) is not comparable to the previous one
row for row.

## P-256 verify: affine Q table in the joint multiplication

Shamir's Q table stayed projective, so each of the ~64 Q additions in
the main loop was a full Jacobian addition (z2 != 1).  One Montgomery
batch inversion (~4 us) now makes the fifteen nonzero multiples affine,
and the loop uses mixed additions.  Index 0 stays the point at
infinity; MIXED-ADD already handles the infinity and equal-point cases,
so no check moves into the hot loop.

| | before | after |
|---|---|---|
| verify (direct) | 129.9 us | 124.6 us |

The inversion is paid once per verification; with only ~64 additions the
net saving is 5 us, about 4%.  The remaining verify cost is the 256
point doublings (~67 us) plus the scalar inverse and the final affine
conversion; only a faster field squaring can move those.

### P-256 table refresh (rev 1195)

| row | rev 1193 | now | C | gap |
|---|---|---|---|---|
| secp256r1 sign | 27.61k | 29.75k | 53.06k | 1.93 -> 1.78 |
| secp256r1 verify | 7.47k | 7.81k | 18.75k | 2.51 -> 2.40 |

The quiet run also pulled the two keygen rows that had drifted over 2x
back below it.  Aggregate: 52 rows ahead, 60 within 2x, 11 beyond.

## P-224: positional base table and windowed joint multiplication

P-224's sign spent 123 us of 166 us in the fixed-base comb, which did
224 doublings and 56 additions per multiplication.  It now uses the
same 32x256 positional byte table as P-256: T[J][V] = V*256^J*G, built
lazily and selected by a 16+16 two-level scan, so a signature needs 28
additions and no doublings at all.

Verify used a *bit-by-bit* joint multiplication: 224 doublings and up
to 224 additions.  It now computes A*G from the positional table and
B*Q with a four-bit window (224 doublings, 56 additions), then adds the
two; the bit-by-bit routine remains as the fallback for a first point
that is not G.

| | before | after |
|---|---|---|
| fixed-base multiply | 123 us | 18 us |
| sign (direct) | 165.7 us | 51.8 us |
| verify (direct) | 241.8 us | 194.2 us |

Both P-224 signature rows should cross 2x.  The table is built on first
use (32 rows of 256 points) and costs a few milliseconds once.
Full suite passes.

## Ed448: positional base table

Ed448's fixed-base multiplication walked 57 bytes and did eight
doublings per byte: 456 doublings plus 57 additions, 391 us of the
499 us signature.  It now uses a lazily built 57x256 positional table
T[J][V] = V*256^J*G (in the limb field) with the two-level sixteen-entry
selection, so a signature needs 57 mixed additions and no doublings.

| | before | after |
|---|---|---|
| fixed-base multiply | 390.6 us | 58.8 us |
| sign (direct) | 498.8 us | 155.8 us |

Verify is a five-bit *joint* multiplication, where the doublings are
shared by both scalars and a positional table for G cannot be used; it
stays at 664 us (about 3x the C reference).  The table costs a few
tens of milliseconds to build on first use and uses a few megabytes.
Full suite passes.

### P-224 / Ed448 table refresh (rev 1198)

| row | before | now | C | gap |
|---|---|---|---|---|
| secp224r1 sign | 5.35k | 17.04k | 22.37k | 3.82 -> 1.31 |
| secp224r1 verify | 3.84k | 4.73k | 10.29k | 2.61 -> 2.18 |
| ed448 sign | 2.21k | 6.56k | 5.20k | 2.19 -> 0.79 |

Ed448 sign is now ahead of the C reference.  P-224 verify reads 2.18 in
this run; the direct measurement was 194 us (~5.2k, 1.97), so the row
is borderline and the difference is host noise.  Aggregate: 55 rows
ahead, 59 within 2x, 9 beyond (down from 11).

## Correctness: gate the MULX/ADCX/ADOX paths on the CPU cache

The register CIOS field multiply and the scalar inverse emit BMI2/ADX
instructions unconditionally under IRONCLAD-UNSAFE-ASSEMBLY, which the
package enables on every SBCL x86-64 build regardless of the CPU.  A
machine without those extensions would take SIGILL.  Both entry points
now check the cached *IRONCLAD-UNSAFE-BMI2-P* / *...-ADX-P* flags and
fall back to the bignum multiply or the Euclid inverse.  The two loads
per field multiply cost nothing measurable: sign 33.7 us and verify
128.2 us, inside the run-to-run spread.

## 2048-bit Montgomery CIOS: MULX and two carry chains

The generic CIOS product phase loaded each limb into RAX and used MUL
(RAX:RDX) with a single serial ADD/ADC carry chain.  A new 32-limb VOP
keeps a two-word sliding window of the accumulator in registers and
uses MULX with ADCX/ADOX: the low halves ride CF and the high halves OF.
The reduction is only N products against N^2, so it keeps the serial
form (and the final subtraction is unchanged).

| exponent | serial | MULX |
|---|---|---|
| 65537 (RSA verify) | 51.1 us | 47.0 us |
| random 256-bit | 459 us | 409 us |

8-11%: the sliding window costs a load and a store per product, and the
two carry chains are still serial per word, so the gain is bounded.
Only the 32-limb case is instantiated; it covers RSA-2048 and DSA-2048,
the sizes the benchmark measures.  The dispatch checks the cached
BMI2/ADX flags on every multiplication, which is noise against 1.5 us.
Full suite passes.

### Table refresh (rev 1201)

| row | before | now | gap |
|---|---|---|---|
| RSA verify | 35.9k | 38.42k | 2.02 -> 1.81 |
| DSA sign | 2.59k | 2.87k | 2.05 -> 1.64 |
| DSA verify | 1.92k | 2.07k | 2.74 -> 2.55 |
| secp224r1 sign | 5.35k | 17.51k | 3.82 -> 1.27 |
| secp224r1 verify | 3.84k | 4.70k | 2.61 -> 2.18 |
| ed448 sign | 2.21k | 6.41k | 2.19 -> 0.81 |

The MULX CIOS moved both RSA verify and DSA sign under 2x; DSA verify
improved but remains above.  Aggregate: 54 rows ahead, 61 within 2x,
8 beyond (from 11 at the start of the session).  The eight are falcon
keygen, secp521r1/ed448/dsa/p256/p224 verify and chacha-poly, plus one
McEliece keygen row that is noise.

## P-521: interleaved 9-limb MULX multiply

P-521 was still calling the separated (SOS) 9-limb Montgomery VOP even
though the interleaved form is the faster one for every other size.  A
9-limb instantiation of the MULX/two-chain CIOS now serves it, with the
SOS path as the fallback when BMI2/ADX are absent.

Measured on the real modulus and limbs:

| form | ns |
|---|---|
| SOS (old) | 154.0 |
| CIOS, serial | 141.5 |
| CIOS, MULX/ADX | 130.7 |

Direct sign 323 -> 304 us, verify 1389 -> 1212 us (verify is still
field-bound: 520 doublings at ~1.2 us each).  Full suite passes.

### Table refresh (rev 1203)

| row | before | now | gap |
|---|---|---|---|
| secp521r1 verify | 725 | 800 | 3.37 -> 2.46 |
| secp224r1 verify | 4.70k | 5.13k | 2.18 -> 1.77 |
| dsa verify | 2.07k | 2.14k | 2.55 -> 2.31 |
| secp256r1 verify | 7.13k | 7.72k | 2.58 -> 2.18 |

Aggregate: 49 rows ahead, 66 within 2x, 8 beyond.  Two of the eight are
ML-DSA keygen rows that moved from ~1.2-1.5 to ~2.0-2.1 without any
change to their code, so the structural set is six: falcon keygen,
chacha-poly, ed448 verify, and the secp521r1/dsa/secp256r1 verify rows.

## P-256 verify: cache the decoded point and Q table per key

VERIFY-SIGNATURE decoded and validated the public key on every call and
rebuilt the sixteen-entry affine Q table (fifteen point operations plus
a batch inversion) for every joint multiplication.  Both depend only on
the key, and MAKE-PUBLIC-KEY already decodes the point for validation,
so the decoded point and the table are now stored on the public-key
object and reused.  The first verification builds them; later ones skip
the work.

Direct verify 124.6 -> 117.9 us (about 5.5%), which puts the row just
under 2x.  Two threads can race to build the cache; both compute the
same read-only table and one wins, so no lock is needed.  Full suite
passes.

### Table refresh (rev 1205)

The per-key cache moves secp256r1 verify from 7.72k to 9.28k ops/s
(2.18 -> 1.98).  The run also landed on a quiet host for the other
curve rows: secp224r1 verify 1.91, secp521r1 verify 2.63, dsa verify
2.57.

Aggregate: **53 rows ahead, 65 within 2x, 5 beyond**.  The five are
falcon-512 keygen, ed448 verify, chacha-poly, secp521r1 verify and dsa
verify -- the set the plan has been converging on, with no noise rows
left in it this time.

## DSA verify: joint sliding window for the simultaneous exponentiation

MONTGOMERY-EXPT-SHAMIR was bit-by-bit: one squaring per bit and one
multiply for every bit where either exponent was set, about 448
multiplications for a 2048-bit modulus with two 256-bit exponents.  It
now uses a joint five-bit sliding window: one squaring per bit and a
multiply per odd window of either exponent, plus sixteen odd powers of
each base.  DSA-2048 verify 465 -> 402 us (about 14%).

The first attempt was wrong: multiplying at the window's first bit gave
the window value l-1 extra squarings.  The multiply is now held until
the window's last squaring has been applied, and the skipped bits
cannot start another window.  Validated against EXPT-MOD on 512-3072
bit moduli with random 256-bit exponents, and by DSA sign/verify/tamper
and the full suite.

### Table refresh (rev 1207)

The joint sliding window moves DSA verify from 2.15k to 2.255k ops/s
(2.57 -> 2.23).  secp256r1 verify reads 9.05k (1.87).  Aggregate:
51 rows ahead, 67 within 2x, 5 beyond -- falcon-512 keygen,
chacha-poly, ed448 verify, secp521r1 verify and DSA verify.

## Ed448 / P-521 verify: per-key point and window-table cache

Ed448 verification decoded the public key on every call -- recovering X
from Y is a square root over the field, 75 us -- and rebuilt its
31-entry Q window table (~50 us).  Both depend only on the key.  The
decoded point and the table are now cached on the public-key object;
verify 653.6 -> 555.6 us (about 15%).  Note that an ED448-POINT's
coordinate slots hold limb arrays, not the integers the class declares,
so the table builder receives them directly.

P-521 verification rebuilt its 31-entry Q table per call; caching it on
the key takes verify 1227 -> 1179 us (about 4%).  Full suite passes.

### Table refresh (rev 1209)

| row | before | now | gap |
|---|---|---|---|
| ed448 verify | 1.51k | 1.775k | 3.25 -> 2.53 |
| secp521r1 verify | 805 | 860 | 2.45 -> 2.31 |
| dsa verify | 2.255k | 2.475k | 2.23 -> 2.00 |

Aggregate: 50 rows ahead, 68 within 2x, 5 beyond.  DSA verify sits
exactly on the 2.00 boundary (4.960k / 2.475k = 2.004).

## Allegro: loop NTT fallback for the 50 MB Express heap

Compiling ML-DSA on Allegro 11.0 Express dies while expanding the
unrolled NTT (256 butterflies): the compiler exhausts the edition's
50 MB heap and then reports the constant table as unbound.  The loop
form from before rev 1150 is restored under #+ALLEGRO for both the
forward and inverse transforms; the unrolled form stays on the other
implementations.  The loop form is about 2.4x slower, which only affects
ML-DSA on Allegro.  With it, ml-dsa.lisp compiles and the Allegro test
run proceeds.

## Portability: threads are optional; CLISP 2.49

BORDEAUX-THREADS is now a dependency only where its own ASDF reports
support (the same condition list: SBCL with SB-THREAD, CCL with native
threads, ECL with threads, ABCL, Allegro with multiprocessing, CLISP
only with MT, and so on).  Without it the OS PRNG's stream lock expands
to a no-op, so the library loads and runs single-threaded.

CLISP 2.49 also evaluates DEFCONSTANT with a non-EQL value (an array or
a bignum) lazily, so the compile-time table builders (CAST5's round
table, the ML-DSA zetas, the curve moduli) saw unbound names.  The
crypto-unsafe package now shadows DEFCONSTANT on CLISP and binds the
value in the compile-time environment before calling CL:DEFCONSTANT.

Portability check matrix, Roswell installations on 2026-10-30:

| implementation | version | result |
|---|---|---|
| SBCL (roswell) | 2.6.9 | full suite pass |
| SBCL (system) | 2.6.7 | full suite pass |
| CCL | 1.13 | full suite pass, also with READTABLE_CASE_INVERT |
| ECL | 26.5.5 | full suite pass; ML-DSA targeted |
| ABCL | 1.9.3 | full suite pass; ML-DSA targeted |
| Allegro | 11.0express | full suite pass (loop NTT) |
| CLISP | 2.49 (no MT) | loads and runs single-threaded; suite in progress |
| LispWorks | lib only | not runnable here; CI excludes it |
