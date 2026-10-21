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

The fold is now in two passes, the excess added at the fourth limb
and up and given back at the bottom, and the value before the fold
is congruent to the product.  The value after the fold is still
wrong, and the words three to six come out as (2^56-1, 2^56-1, 2^56-1,
2^56-1) where the excess of the case, which is B^3 - 2, has the
limbs (2^56-2, 2^56-1, 2^56-1, 0).  So the first pass is adding
the limbs of the excess one place too high, or the second is taking
them back one place too low: the excess has to be added at the
fourth limb and up, and taken back at the bottom, and the borrow of
the second has to be carried on to the words above the third, which
the first has already changed.

The multiply of P-224 is now in assembly, the same shape as the
P-256 one with seven limbs instead of eight, so the product has
fourteen columns.  The reduction is still in Lisp, and it is what the
multiply now costs: the assembly multiply is some tens of
nanoseconds, the Lisp reduction several hundred, and the whole
multiply five times the bignum one.  The reduction is what has to
come next; the prime is B^7 - B^3 + 1, so B^7 is congruent to B^3
minus one, and the excess of a value is folded back in at the fourth
limb.  The P-256 reduction shows the shape of the work: it sums the
words of the shifted lists into accumulators without carries, and
propagates the carries once at the end.

The P-256 field is worth a note, because the same shape of work
applies there.  A multiply of the P-256 field costs about eighty
nanoseconds, of which the reduction is the larger part, and a
multiply that returns a fresh vector costs about a hundred and
sixty, the difference being the two arrays it allocates.  The point
operations make about a dozen multiplies each, so the allocations
are a good fraction of the cost of a scalar multiplication: the
verify of a P-256 signature spends most of its time in the field
multiplies, not in the digest or the inversion.  The way out is to
keep the product buffer and the reduction scratch in the scratch
pool that the point operations already carry, and to multiply into
the pool rather than into fresh vectors.

The key generation of the falcon is the slowest thing in the whole
table, at two hundred and thirteen milliseconds, and the number
theoretic transform is not what costs there.  The generation of the
NTRU is a hundred and fifty seven of those milliseconds, so
seventy-four per cent of the key generation is the generation of
the NTRU and its solution, and the fast Fourier transform and the
sampling of the signature are the rest.  The NTRU generation uses
the transform, so it is one of the places the transform matters, but
it is not where the transform's own cost shows: the solve of the
NTRU is a linear algebra over the field, and the sampling of the
polynomials is a Gaussian sampler.

The falcon verify is worth a note, because it is not the field that
costs there.  The prime of this implementation is 12289, a small
one, so the modular arithmetic is cheap; what costs is the shape of
the number theoretic transform.  The transform of a polynomial of
512 coefficients takes eighty microseconds, the verify needs about
six of them, and the whole verify takes five hundred and eighty
microseconds.  The transform is a recursive split into the even and
the odd coefficients, and every node of the recursion allocates
three arrays: about fifteen hundred of them for one transform, at
the cost of some sixty microseconds.  The rest is the generic MOD,
which needs a division for every sum and every difference; the sums
and the differences are of reduced residues, so a single conditional
subtraction would do.

The transform has therefore been rewritten in place, with a pool of
two buffers per level of the recursion, with the sums and the
differences done by a conditional subtraction and a conditional
addition, and with the product reduced by a multiplication by the
reciprocal of the prime instead of by a division.  The new transform
has been run against the old one over random polynomials of every
size from two to five hundred and twelve coefficients, and the two
agree; the reciprocal has been run against the division over two
hundred thousand random pairs, and the two agree.

The rewrite did not make the verify faster, and that is worth
recording, because the reason it was written for was wrong.  The
fifteen hundred arrays of a transform are not what they look like:
SBCL allocates them out of the young generation with a bump
pointer, so the allocation itself is a few nanoseconds each, and the
whole lot costs less than the arithmetic.  What the rewrite does
remove is the garbage: a transform no longer leaves fifteen hundred
arrays behind for the collector.  The arithmetic is what the time
goes on, and one butterfly of the transform is a multiply, two sums
or differences, and four array accesses, and the C reference does
the same work in a fraction of the time.

The transform of the falcon is to be done in SIMD, and the shape of
the work is settled.  A butterfly of the transform is a multiply of
the residue by a twiddle, a reduction of the product, and a sum and a
difference; the multiply and the reduction are the arithmetic, and
the arrays are the memory.  The VOP does the whole merge of the
recursion, four elements at a time, and the whole split of the
inverse, and the arrays stay as they are.

Four things make that possible.  The first is the interleave: the
merge writes the sum and the difference of a pair of elements to the
two places that follow each other, and the unpacking of the two
vectors of sums and the two vectors of differences puts them there
in the right order, with two instructions.  The second is the
layout: the elements of an array of residues are machine words with
the residue in the low half, so a load of two of them is a vector
of two residues in the even thirty-two bit lanes, and the multiply
that only reads the even lanes is exactly the multiply that is
wanted.  The third is the reduction: the reciprocal of the prime
times the product is a sixty-bit number, and the sixty-four bit
lanes hold it, so the quotient estimate and the remainder are both
computed without ever leaving the lane.  The fourth is the table:
the twiddles of a merge are the even-indexed entries of the roots
table, and they are wanted four at a time, so the table of the
twiddles is made once per size.

The instructions of a merge of four elements are then: two loads of
the operands, one load of the twiddles, the multiply, the reduction
(the product times the reciprocal, the shift that gives the quotient
estimate, the estimate times the prime, the difference, and the
conditional subtraction of the prime), the sum and the difference,
the two unpacks, and the two stores.  That is about thirty
instructions for four elements, against perhaps eighty for the four
elements one at a time.

The transform is to be checked against the one it replaces over
random polynomials of every size, as the rewrite of the transform
above was, and the check is to be kept.  The check has to use
coefficients that are not below the prime, because the polynomials
of the NTRU have coefficients that may be negative, and the
reduction of a product below assumes that the residues are below the
prime.  The transform reduces its coefficients first, and the check
of the transform against the one it replaces has to do the same, or
it will not notice the difference.

The twiddle tables, the thirty-two bit buffers of the recursion, the
merge split out as its own function, and the reduction by the
reciprocal of the prime are in the tree now, and the transform that
uses them agrees with the one it replaces over random polynomials of
every size, in both directions.

Two things about the shape of the merge were found after the plan
was written, and one of them corrects it.

The first is that the residues are best kept in thirty-two bit
arrays, not in the machine words of a general array.  The four
elements of a group are then the four lanes of a vector, and the
unpacking that interleaves the sums and the differences puts them
where the recursion wants them.  With the residues in machine words
the interleave cannot be done at all, because the unpacking of the
vectors puts the two values of a pair in the two halves of one
machine word rather than in two machine words.  So the buffers of
the recursion are thirty-two bit arrays, and the transform takes
and returns arrays of fixnums and converts at its ends.

The second is that the multiply of four thirty-two bit lanes is not
an instruction of the older set.  The older PMULLD takes two
operands and multiplies the destination by one source, and the form
that multiplies two sources into a destination of its own is the
vector one, VPMULLD, which needs a machine with AVX.  The multiply
of the even thirty-two bit lanes into sixty-four bit lanes, which
the reduction needs for the product of the reciprocal, is the same:
the older PMULUDQ takes two operands and the vector one takes
three.  The instructions of the older set take two operands, the
destination and one source, and the destination is also the first
source: PADDD X0 X1 adds X1 to X0.  The shifts by a constant are
named with an -IMM suffix, PSRLQ-IMM and the like, and the shuffle
of the thirty-two bit lanes takes three operands in the older form,
PSHUFD X0 X1 #xB1.  So the merge needs VPMULLD and VPMULUDQ and
nothing else of the vector set.

The machine is to be asked at run time, not at build time, because
the library is built on one machine and run on another, and the file
for the processor features has what is wanted: IRONCLAD-CPU-FEATURE-P
with the keyword :AVX2, which is the conservative probe, because a
machine with AVX2 has AVX, and which also asks whether the operating
system has enabled the extended processor state.

The field of P-224 is now in the tree, in limbs of 32 bits, with
the product of two elements, their sum and their difference, all
reduced, and the new test :secp224r1-field checks them against the
integer arithmetic.  The point arithmetic is in the tree too, as
secp224r1-point-double-limbs and secp224r1-point-add-limbs, and the
new test :secp224r1-point-limbs checks the two of them against the
integer arithmetic, up to the common factor in Z that the projective
equality allows.  The scalar multiplication that uses them is still
to come.  Three things were worth knowing: the reduction of a product
takes the low half and the high half of the value, so a sum, which
has no high half, is reduced by the same code with the words above
the seventh zero; the borrow of a subtraction is subtracted, not
added, which is the same sign as the borrow in the reduction; and a
variable may not be called T, which is a constant.

The field of P-224 was measured with bignums: the product of two
elements is 42 nanoseconds and the division that follows it 187, so
the division is four fifths of the cost of a multiplication, and
replacing it with a fold in bignums is no use: the fold was
measured at 266 nanoseconds, because every step of it allocates.