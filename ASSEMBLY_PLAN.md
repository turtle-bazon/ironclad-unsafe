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
