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
