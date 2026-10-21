# Plan: Assembly/AVX2 Big-Integer & Public-Key Performance Work

## Goal
Close the remaining public-key performance gaps in `benchmark/all-algorithms.md`
(falcon 36×, mceliece 32×, ed448 32×, secp256r1 27×, ed25519 20×, hqc 21×)
by rewriting field arithmetic with limb-based representations and assembly VOPs.

## Current State
- Digests and SHA-NI are at/near C parity.
- secp256r1 already uses 32-bit limb field elements + assembly VOPs for
  `fe-mul-raw`, `fe-sqr-raw`, `fe-reduce` (see `src/opt/sbcl/x86oid-vm.lisp`).
- ed25519, secp224/384/521, ed448, falcon, mceliece, hqc use pure-Lisp
  bignum `mod (* a b) p` in their point/field operations.
- Falcon's bottleneck is the recursive complex-double FFT.

## Phases (in priority order)

### Phase 1 — ed25519 (highest value, simplest field)
- **Representation**: points currently store bignum integers; convert to
  `ed25519-fe` (8 × u32 limbs, radix 2^32) using the existing
  `ed25519-fe-*` functions (already defined, currently unused by point ops).
- **Work**:
  1. Change `ed25519-point` slots (x,y,z,w) to `ed25519-fe` arrays.
  2. Rewrite `ed25519-double!`, `ed25519-add!`, `ec-double`, `ec-add`,
     `ec-scalar-mult`, `ed25519-base-mult`, `ed25519-scalar-mult-general`,
     `ed25519-public-key`, `ed25519-sign`, `ed25519-verify`,
     `ec-encode/decode-point` to use `ed25519-fe-*` in-place ops.
  3. Add assembly VOPs for `ed25519-fe-mul` and `ed25519-fe-sq`
     (radix-2^25.5, 5-limb, matching ref10/SUPERCOP).
- **Validation**: existing `:ed25519` test vectors + randomised roundtrip.
- **Expected gain**: ~5-10× (remove bignum mod from hot loop).

### Phase 2 — secp256r1 (already partially optimized)
- **Work**:
  1. Profile to find remaining bottleneck (likely `ec-add`/`ec-double` consing
     from `make-secp256r1-point` + scratch pool).
  2. Make scalar mult fully destination-passing (no per-iteration allocation).
  3. Add VOPs for `secp256r1-fe-add`, `fe-sub`, `fe-neg` (currently Lisp).
  4. Use endomorphism? (secp256r1 has no efficient GLV; skip.)
- **Expected gain**: ~2-3×.

### Phase 3 — secp224r1, secp384r1, secp521r1, secp256k1
- Clone the secp256r1 approach: limb representation + assembly VOPs per curve.
- secp256k1: add GLV endomorphism (λ) for 2× speedup on scalar mult.

### Phase 4 — ed448
- Similar to ed25519 but with p = 2^448 - 2^224 - 1 (Goldilocks).
- Use radix-2^56 limbs (8 limbs) with the efficient reduction.
- Done: the reduction of an integer modulo the prime without a
  division (rev 900); the field in limbs of 56 bits, in Lisp, as the
  reference (rev 901); the product of two field elements in assembly
  (rev 903); the reduction of a product in assembly (rev 904); the
  scalar multiplication of Ed448 and Curve448 in the limb field
  (rev 908); the reduction of a sum or a difference in assembly, for
  which the field element was given eight limbs of scratch (rev 909);
  and the exponentiation and the inversion in the limb field (rev
  910).  The product of two field elements takes 129 nanoseconds,
  against 440 for the product of two bignums and the division that
  follows it, and the sum takes 58 nanoseconds.  Ed448 verifies 2.7
  times faster, signs 2.8 times faster and generates its keys 2.8
  times faster; Curve448 is 3.2 times faster.  The gap of the
  verification of Ed448 is 11.4 times the C reference, against 29.5
  before, and the gap of the signature is 4.8 times, against 12.6.
- The rest of the field layer is done, and so is the move of the
  point arithmetic to limbs.  What is left is the same for the other
  curves, which have primes of another shape: secp224r1, whose prime
  is 2^224 - 2^96 + 1, and secp521r1, whose prime is 2^521 - 1.
  `MULX` is not usable, see the notes below, so the product is made
  with `MUL`.

#### The field of secp224r1

The prime of P-224 is B^7 - B^3 + 1 with B = 2^32, so it wants
seven limbs of 32 bits, and B^7 is congruent to B^3 - 1: the high
half of a product, H, is folded back in by adding it, shifted up by
three limbs, and by subtracting it.  The product of two elements is
fourteen limbs, and the Comba is the one of Ed25519 with seven limbs
instead of eight.

The fold is where the care is needed, and where a first attempt
failed: the subtraction and the addition meet at the fourth limb,
and the sum there can be negative, so the carry out of that limb
can be -1.  The way out is the one the P-256 code takes, two
arrays and signed carries.

With B = 2^32 and p = B^7 - B^3 + 1, the value of the product N
is L + H*B^7, where L is the low seven limbs and H the high seven,
and B^7 is congruent to B^3 - 1, so

    N = L + H*B^3 - H   (mod p).

So the value is the sum of three parts, and they are put in two
arrays, so that no part is read after it has been written:

* the first array holds L, unchanged;
* the second holds H*B^3 - H: the limbs of H are added at the
  fourth limb and up, in the order of the limbs, so that a limb of H
  is read before the word it is added to is written, and H is then
  given back from the first seven words.

The two arrays are then added, word by word, and the excess is what
is left above B^7: the high words of the second array, plus the
carry of the addition, plus the borrow of the subtraction, which is
a whole B^7 and so is congruent to B^3 - 1.  The excess is folded in
the same way, the words at the fourth limb and up get it and the
first seven words give it back, and the excess of that fold is
folded in again: the excess can be 1, and folding it in can give an
excess of 1 again, so the fold is a loop and not a fixed number of
rounds.  The last step is the conditional subtraction of the prime.

Every carry and every borrow along the way is signed, and the
carries are propagated with an arithmetic shift, so that a sum which
is negative simply carries -1 into the next word.

The same shape of the reduction is in the field of P-256, in
`src/public-key/secp256r1.lisp`, and its assembly version is the
VOP `secp256r1-reduce-fast-asm`, which sums the shifted pieces of
the product into 64-bit accumulators and propagates the carries
once, at the end.  That is the shape to copy.

The reduction has been written in Lisp and now runs.  The value
before the fold is now correct: it is congruent to the product, which
is the check that matters.  Getting there took four fixes, and they
are the whole of the difficulty of this reduction:

* the borrow of a subtraction is a whole B^7, and it counts as minus
  one in the excess, so it has to be *added* to the next word, not
  subtracted from it;
* a carry and a borrow are signed, and the high part of a negative
  number is its floor and not its truncation, so the shift has to
  floor: `ash` and not `truncate`;
* the excess is the whole high part of the value: the words seven to
  nine, the carry of the addition of L, which counts as plus one, and
  the borrow of the subtraction of H, which counts as minus one;
* the fold must add the excess at the fourth limb and up and take it
  back at the bottom in two separate passes.  Adding and subtracting
  in one sum hides the borrow of the second, because the two cancel in
  the sum and only the carry of the sum survives.

What is left is the last of these: the value after the fold is still
off by B^4, which is the fourth limb of the excess, so the part of
the excess that is given back at the bottom is one limb out of place.

The field of P-224 was measured with bignums: the product of two
elements is 42 nanoseconds and the division that follows it 187, so
the division is four fifths of the cost of a multiplication, and
replacing it with a fold in bignums is no use: the fold was
measured at 266 nanoseconds, because every step of it allocates.