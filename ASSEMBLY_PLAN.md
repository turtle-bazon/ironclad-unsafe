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
theoretic transform is not what costs there.  What the measurements
say, for a key of five hundred and twelve coefficients, is this: the
solution of the NTRU equation is a hundred and thirty-three
milliseconds of it, the reduction of the sample by Babai is four
milliseconds and a half, the sampling of the polynomials is seven
milliseconds, and the Gram-Schmidt norm is seven and a half.  So
the solution of the NTRU equation is two thirds of the key
generation, and it is built out of the fast Fourier transform and the
Karatsuba product: a transform of five hundred and twelve
coefficients takes four hundred microseconds, a product of two of
them takes six hundred, and the reduction calls the transform four
times and the product twice for each of its seven rounds.

Both of those are slower than they should be for what they do, and
the reason is the same in each: they are made of many small arrays.
The transform of five hundred and twelve coefficients makes three
thousand of them, and the Karatsuba product of the same size makes
about eight thousand, and a fifth of a transform and a third of a
product is the time spent making them.  A transform with a pool of
buffers per level of its recursion, and a product that writes into
a destination rather than returning a fresh array, would both be
several times quicker, and neither of them changes what the
transform or the product computes.

The two of them are the same shape as the number theoretic transform
of the falcon, which is split into the even and the odd
coefficients, transformed, and merged, and which is the same work
over a different field.  So the same treatment serves both, and the
plan for the transform of the number theoretic transform applies to
the fast Fourier transform: a pool of buffers per level of the
recursion, the results written into the buffers of the level above
rather than into fresh arrays, and the two split and merge steps
inlined so that the buffers can be shared.  The one thing to be
careful about is that the merge writes the sum of a pair and the
difference of a pair to the two places that follow each other, so
the results of the two halves cannot share the buffer of the halves
themselves.  The generation of the
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

What the assembler of SBCL does with the instructions of the merge
has been found out by trying them, one at a time, and it is worth
writing down.  The address of an element is given as a displacement,
a base, an index and a scale, and the index has to be a register or
nothing; a literal there is an error.  The vector multiply of four
thirty-two bit lanes gives the exact products, and the vector
multiply of the even thirty-two bit lanes into sixty-four bit ones
gives the sixty-four bit products, and it is the wider form of that
one, so the lanes above the first two are rubbish and are not to be
read.  The shift of the sixty-four bit lanes by a constant takes the
count in bits, and the counts above thirty-two do not work: the
count of forty gives nothing at all, and the count of thirty-two
works.  The reduction wants a shift of thirty-two, and the reciprocal
of the prime for it is 349525, which is also what the Lisp
reduction has to use, so that the two agree.

The vector merge itself is written and does not work yet, and what
is known about it is worth writing down.  A VOP that only loads four
words from one array and stores them to another, with an index, is
right: the form of the address with an index and a scale, the loop
with a countdown and a conditional jump, and the arguments as
descriptors all work.  The merge adds to that the vector multiply of
four thirty-two bit lanes, the vector multiply of the even lanes
into sixty-four bit ones, the shift of the sixty-four bit lanes by a
constant, and the unpacking of the sums and the differences, and
that VOP assembles and then faults with a bad address, so one of
those four is not doing what it should.  The instructions of the
assembler are all there: the vector forms of the multiply and of the
shift are known to it, and the shift by a constant is the same
instruction with an immediate, which the assembler's names do not
show.  One thing the constants need is that they fit a signed
thirty-two bit immediate, so the reciprocal of the prime has to be
the one of 2^43 rather than the one of 2^44, which is a little
smaller and works the same.

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
The complex transform of the falcon was pooled, in the same way as
the number theoretic one: the two halves of the coefficients and the
two results of their transforms come from a pool of buffers, one set
per level of the recursion, and a transform writes into an array
that the caller gives it.  The transform of five hundred and twelve
coefficients went from four hundred and fourteen microseconds to a
hundred and sixty-eight, the norm of the Gram-Schmidt from seven
thousand three hundred and thirty-six microseconds to four thousand
three hundred and sixty-eight, and the signature from twenty-five
and a tenth of a millisecond to eighteen and seven tenths.  The
keygen, which uses the norm a few dozen times, went from two hundred
and seven milliseconds to a hundred and seventy-seven, though that
number moves with the random draw of the key.

The pooling of the complex transform was not straightforward, and
what it taught is worth writing down.  The first attempt compared
the pooled transform with the old one over vectors of zeroes, which
proved nothing at all, since the transform of zeroes is zeroes; the
comparison has to be over random coefficients.  The second attempt
declared the coefficients to be a simple vector, which is a lie when
they are a vector of doubles, and with the safety checks off the
compiler then reads the eight bytes of the double as if they were a
pointer, so that the transform of the vector (one, two) returned the
pair of denormals (2.3d-313, 2.3d-313) and the division of the Gram-
Schmidt divided by zero.  A declaration of type must name the real
type of the array: a vector of doubles is FALCON-DVEC, a vector of
complexes is FALCON-CVEC, and SIMPLE-VECTOR is only for the vectors
of pointers, which are the tables of roots and the pool itself.  The
coefficients of the transform do not always come from a vector of
doubles, because the map of the vector in the norm of the Gram-
Schmidt gives a general vector of boxed doubles, so the transform
copies them into a vector of doubles first, which costs one pass and
buys a typed recursion.  The third attempt had a parallel LET
where a sequential one was wanted, so that the count of the pairs of
the merge referred to a variable that was not bound yet, and the
fourth had a print statement as the last form of a function, so that
the function returned nil where it should have returned its buffers.

The complex transform is not the transform that the falcon spends
most of its time in: the number theoretic one takes fifty
microseconds for five hundred and twelve coefficients and the
Karatsuba product takes six hundred, and both are in the keygen, in
the solution of the NTRU equation, which is a hundred and thirty
three milliseconds of the two hundred of the keygen.

The reduction of the field of P-224 was in the way of the multiply:
the reduction of a product took eight hundred nanoseconds of the nine
hundred and sixty of the multiply, and it was written with the safety
checks on, which made every access of the array a checked one.  With
the checks off, and with the excess kept as four limbs of thirty-two
bits in the high words of the array instead of as a big number, the
multiply went down to two hundred and forty nanoseconds.  The excess
is the part of the value which is above B^7; it is congruent to
itself times B^3, less itself, and it is folded in until there is
none, and it is one at most after the first fold, so the loop that
folds it in runs at most twice.

Two things about the writing of the check of the reduction are worth
remembering.  A value of fourteen limbs is reduced against the prime
with the integer arithmetic, and the check of that is easy to get
wrong: the limbs are little endian, so the value is made with DPB and
not with a shift of the accumulator, which shifts the low limbs out
of their places and gives a number that is wrong and looks plausible.
And the value of the prime in the file is right while the value of
the limbs of the prime in the same file was, for a while, read as
something else; the two have to be compared, and they are equal.

The field of P-521 was bignums, and the prime is a Mersenne prime,
2^521 - 1, so the reduction of a value is a fold: the low five
hundred and twenty-one bits of the value, plus the high ones, since
2^521 is congruent to one.  The sum of the two is below 2^522, so one
more fold finishes it, and the division that the generic arithmetic
does is not needed.  The fold is done by a function that takes a
value of any size and folds it until it is small, so that it can be
used on the sums and the differences of the point arithmetic as well
as on the products, and the inverse, which was an exponentiation with
the generic modular arithmetic, is now an exponentiation with the
fast multiplication.  The signature of P-521 went from four and six
tenths of a millisecond to two and a half.

The fold has a trap in it: the second step must take away the prime,
2^521 - 1, and not 2^521, because 2^521 is congruent to one and not
to zero.  Taking away 2^521 leaves a value that is one too large,
and the check of the reduction against the generic one finds it at
once.

The Karatsuba product of the falcon keeps its coefficients in vectors
of general integers, and a general vector of integers boxes every
element, so every product of the recursion makes a box for every
coefficient it writes.  With vectors of sixty-four bit integers
instead, the product of five hundred and twelve coefficients went
from five hundred and seventy microseconds to two hundred and
seventy, and the norm of the field from three hundred and sixty-eight
to a hundred and eighty.

The change was reverted, because the key generation hung with it.
The product itself is right: it was checked against a plain
convolution over the sizes four, eight, sixteen, sixty-four and five
hundred and twelve, and the norm of the field and the reduction of
Babai both work.  So the fault is in one of the callers, and the
next attempt should look at the vectors that the solution of the
NTRU equation hands to the products, which are the lift of the norm
and the Galois conjugate of the polynomial: the lift and the
conjugate now make vectors of sixty-four bit integers, and their
values are the ones of the equation, which are of the order of the
square of the prime, and that is well inside the range, but the
values of the coefficients of the equation are not checked
anywhere.

The field of P-224 is in limbs, with the product in the assembly, and
the point arithmetic in limbs as well, but the signature of P-224
still works on bignums, and the limb point arithmetic is eleven times
slower than the bignum one: twenty-two microseconds for a doubling
against two.  The reason is not the arithmetic but the allocation:
every field operation makes a fresh array for the product, a fresh
array for the scratch of the reduction and a fresh array for the
result, and a doubling makes thirteen of them.

So the limbs of P-224 want the treatment that the limbs of P-256
have: a pool of field elements, a product buffer and the scratch of
the reduction in the last two slots of the pool, and point
operations that write into destinations they are given and take
their temporaries from the pool.  The rewriting was begun and
reverted, and the traps it has are worth writing down.  A variable
may not be called T, which is a constant, and TW is the name to use.
A function whose last form is a branch with several forms in it must
have them wrapped in a PROGN, or the branch is read as a COND with
too many elements.  A reduction that takes the scratch of its own as
an argument has every caller changed at once, or the scratch is
unbound and the reduction writes to a null address: the corruption
warning of SBCL says the memory fault is at 0x22, which is a small
address, and a small address is a null pointer with an offset in it.
That was one cause of the corruption, and the other was not found
before the work was reverted, so the next attempt should look for it
in the assembly, which writes into the array of the product and
which the other curves say assumes the usual layout of a simple
vector.

The rewriting of the point arithmetic of P-224 in limbs was begun a
second time and reverted again, and the traps of the first attempt
are worth writing down.  A SETF with several pairs has no order that
the language gives, so the swap of two triples of coordinates, which
is what the ladder does at every step, has to be written out with
three assignments and a temporary; with the arrays of the field, a
wrong swap gives a point that is not on the curve, and the key
generation fails with an invalid point rather than with a wrong
signature.  The reduction that takes the scratch of its own as an
argument needs the parameter added to the parameter list as well:
without it the scratch is an undefined special variable, and the
corruption warning of SBCL gives the memory fault at 0x22, a small
address, which is a null pointer with an offset in it.

The pooling of the point arithmetic does make the limbs faster than
they were: the doubling of a point went from twenty-two microseconds
to six, and the addition from ten to eight, and the reason is that
the field operations allocate nothing any more.  It is still slower
than the bignum arithmetic of the same curve, whose doubling takes
two microseconds, because the product of two limbs of the field of
P-224 takes two hundred nanoseconds and the bignum product takes a
hundred and eighty: the field of P-224 is too small for the limbs to
win, and the assembly of the reduction is what will make them win.

The signature of P-224 now works on the limbs: the field of the
curve is in limbs with the product in the assembly, the point
arithmetic takes its temporaries from a pool of field elements and
writes into destinations it is given, and the comb for the generator
and the ladder are in limbs as well.  The comb and the ladder were
checked against the bignum ones, over the affines of the points they
give, for a dozen scalars each, and they agree.

Three traps were in the way, and they are worth writing down.  A
reduction that takes the scratch of its own as an argument has to
clear the words that it does not write: the first three words of the
scratch are read and never written, which is harmless when the
scratch is fresh and zeroes and fatal when it is reused.  The sum of
two points has a factor of two in it, in the difference of the two
ordinates that is squared, and the version of the sum in limbs that
was in the tree had it and the version that replaced it had not, so
the two did not agree; the test of the point arithmetic in limbs
compares with the bignum arithmetic and did not see it, because the
test only sees the version that is in the tree.  And the swap of two
triples of coordinates has to be a macro: a function that sets its
parameters sets its own parameters and leaves the caller's variables
alone, so the accumulator of the comb never moved and the comb
returned the point at infinity.

The limbs of P-224 are thirty-two bits, and that is the whole
story: the comb in limbs takes a millisecond and a tenth, and the
comb in bignums takes a hundred and twenty microseconds, and the
ladder in limbs takes a millisecond and two hundred and the ladder
in bignums two hundred and forty.  The reason is that a bignum of
two hundred and twenty-four bits is four words of sixty-four bits
inside, so the product of two of them is sixteen multiplications of
sixty-four bits, while the product of two limbs of thirty-two bits
is forty-nine of them, and the reduction of the product of P-224 is
in Lisp.

So the field of P-224 in thirty-two bit limbs cannot win, and the
signature of P-224 goes back to the bignums until the field is in
limbs of fifty-six bits, which is four limbs and which is what the
reference does.  The point arithmetic in limbs, with the pool of
field elements and the destinations, is in the tree and is checked
against the bignum arithmetic, and it is what the field of
fifty-six bits will use.

The same is to be said of the field of P-521, which is nine words of
sixty-four bits in the bignums, and which the limbs of sixty-four
bits will halve the time of, and of the field of P-384, which is
six words of sixty-four bits, and which the limbs of sixty-four bits
will make four times faster.

The point arithmetic of P-521 makes its products without reducing
them, and the products of three values, which the sum of two points
needs for the ordinates, are of a thousand five hundred and sixty
bits; they are reduced once, at the end, and the reduction of a
number of that size is a fold of several rounds.  Reducing every
product as it is made keeps the values inside the field, and the
sum and the difference of two reduced values need one subtraction
and one addition at most, which the fold does not.

The measurements of the field of P-521, on an idle machine, are these:
the fast multiply is two hundred nanoseconds and the generic one six
hundred, the doubling of a point is two microseconds and the sum of
two points six, and the inverse of a number, which is the Fermat
exponentiation, is two hundred and forty microseconds; the signature
is two and a half milliseconds and the verification six and a half,
the verification being a joint multiplication of two scalars.

The field of P-521 is nine words of sixty-four bits in the bignums,
and the limbs of sixty-four bits with the product and the reduction
in the assembly are what will halve the time of the multiply of
that field.

The point arithmetic of P-521 now reduces every product as it is
made, which is what the reference does: its field element is nine
words of sixty-four bits and its product is reduced at once, and its
sum and its difference are one subtraction and one addition.  The
helpers are SECP521R1-ADDMOD, SECP521R1-SUBMOD and SECP521R1-DBLMOD;
they need reduced values, and they give reduced values, which the
Mersenne fold of the sum of two reduced values gives with one
subtraction at most.

The check of the change is against the integer arithmetic: the
projective coordinates of the doubling and of the sum of two points
are the same as the ones the reference arithmetic gives, for points
on the curve and for points with a third coordinate that is not one.

On a machine with a load of two, the measurements are these.  The
signature of P-521 is two thousand one hundred and thirty microseconds
and the verification three thousand and seventy, where the old
arithmetic gives two thousand five hundred and thirty and three
thousand four hundred and seventy; the multiplication of the
generator is one thousand eight hundred and sixty-seven microseconds
and the inverse of a number two hundred, where the old gives two
thousand one hundred and thirty-three and two hundred and twenty.
The difference is the width of the products: the old arithmetic
multiplies three values, of a thousand five hundred and sixty bits,
and reduces the product at the end, and the new one multiplies two
values and reduces each product at once.

The doubling of a point is the largest part of the signature, and it
is nine multiplications of the field, so the field is what the
assembly must make faster.  The nine words of sixty-four bits of the
field of P-521 are in the bignums, and the product of two of them is
in the bignum code of SBCL, which allocates; the assembly of the
Comba product and of the Mersenne fold will keep the field in an
array of nine words and will not allocate.

What is left of the field of P-521, when it is in limbs, is the
alignment.  The prime of P-521 is 2^521 - 1, and the fold of a product
adds the high half of it to the low half, shifted up by 521 bits, and
521 is a prime number, so no size of limb divides it: the shift is
always between the limbs.  The sizes that keep the product of the
field small enough for the columns of the Comba to fit in a word are
nine limbs of fifty-eight bits, which leave fifty-seven bits of shift
inside a limb, and ten limbs of fifty-six bits, which leave
seventeen.  The first has eighty-one products and the second a
hundred, and the first is the one to take.

The additions and the subtractions of the field are in Lisp in the
curves whose field is in limbs, and they cost as much as the
multiplications: the point arithmetic of P-256 does ten of each for a
doubling, and the addition of two eight-limb field elements in Lisp
costs the better part of three hundred nanoseconds, while the product
of two of them, which is in the assembly, costs about thirty.  The
sum and the difference are therefore what is left to move into the
assembly, and they are what the curves whose field is in limbs are
waiting for.

The conditional subtraction of the prime, which every sum and every
difference needs, wants eight words of scratch, which the field
element of the goldilocks has, since it is sixteen words long, and
which the field element of P-256 does not have, since it is eight
words long.  The field element of P-256 has to grow to sixteen words
for that, and the change is small, because the functions of the field
touch only the low eight words: the type, the zero, the copy and the
two new ones.

The sum is computed in the low eight words, with the carry out of the
addition, and the difference between that sum and the prime is
computed in the eight words of scratch, with the borrow out of the
subtraction.  A borrow means that the sum is below the prime, and
the sum is the answer; without a borrow the scratch is the answer,
and it is copied over the sum.  The difference of two field elements
is computed the same way, and the prime is added to it when the
borrow says that it is negative.

The table of the benchmark, after the change of the point arithmetic
of P-521, has the signature of P-521 at four hundred and forty-five
operations a second, where it was at two hundred and fifteen, and the
gap between it and the reference at eight and a tenth, where it was at
nineteen and a tenth.  The verification of P-521 is at three hundred
and ten operations a second, where it was at a hundred and fifty-five,
and the gap at six and a quarter, where it was at fourteen and a
third.

The sums and the differences of the field of P-256 are in the
assembly now, which is what the curves whose field is in limbs were
waiting for: the product of two field elements was already there, in
the assembly, and the sum and the difference were in Lisp, and they
cost as much as the product.  The verification of P-256 is six hundred
and forty microseconds, where it was eight hundred and forty, and the
signature is a hundred and sixty, where it was a hundred and sixty.

Three things about the writing of the two are worth remembering.  The
limbs of the field are words of thirty-two bits, and the move that
reads them has to be the thirty-two bit one, for the sixty-four bit
one reads the neighbour with the limb and the value that comes out
is a number that is wrong and looks plausible.  The instruction set
has no subtract with borrow, so the borrow of a subtraction is taken
from the sign of the difference and the carry of an addition from its
high bits, and no flag of an arithmetic instruction is read but the
one that the test sets.  And the immediate of thirty-two ones is
assembled as a word of sixty-four ones, for the assembler gives it
the sign of the word, so the limbs of the prime that are all ones
are made by shifting a word of ones.

The field of P-224 is four limbs of fifty-six bits in the reference,
and its reduction is the one of a Solinas prime: the high half of
the product is added to the low half, shifted up by ninety-six bits,
less itself, and the multiples of the prime that are added first make
every difference positive, so that no borrow is ever needed.  The
reference adds a multiple of the prime of a hundred and twenty-seven
bits, for the coefficients of the product are not reduced, and the
same thing in sixty-four bits has to add a smaller multiple, for the
coefficients are reduced first.

The reduction of the reference was checked in a program of its own,
in which the coefficients of the product are the columns of the
product, which are not reduced, and the value that comes out of it
is the product modulo the prime, for three hundred pairs of random
values and for the corners.

The field of P-224, in limbs, is the next thing, and it is the
largest gap of the table.  The reference has it in four limbs of
fifty-six bits, and the product of two field elements is seven
coefficients of a hundred and twenty-eight bits, which are the
columns of the product and are not reduced.  The reduction of those
coefficients is the one of a Solinas prime, and it is what the
reference does, and it was checked in a program of its own.

In sixty-four bits, the coefficients have to be reduced before the
reduction, for the multiples of the prime that the reference adds
first are of a hundred and twenty-seven bits and cannot be held in a
word.  The reduction of a prime of the shape 2^n - 2^m + 1 is then
this: the part of the value that is above 2^n is congruent to itself
shifted up by m bits, less itself, and the part of the value that is
above 2^n again is folded in the same way, and the value is below the
prime after two folds.  The shifts by m bits are between the limbs
when m is a multiple of the size of a limb, and the prime of P-224
has m of ninety-six bits, so the limbs are of thirty-two bits and
there are seven of them, and the shift is three limbs.

The Comba of seven limbs of thirty-two bits has forty-nine products
and the bignums of the field have four words, so the product of the
bignums is sixteen wide products and the product of the limbs is
forty-nine narrow ones, and the limb field can only win when the
reduction and the sums and the differences are in the assembly, which
is what the P-256 has now.

The sums and the differences of the field of P-224 are in the
assembly now, and they are the same code as the ones of P-256 with
seven limbs instead of eight, for the limbs of the prime of P-224 are
a one, two zeros and four limbs of ones, where the limbs of the
prime of P-256 are three limbs of ones, three zeros, a one and a
limb of ones.  The sum of two field elements takes less than five
nanoseconds, where the sum of two numbers with the general division
takes about a hundred.

The product of two field elements is still a tie with the product of
two numbers, at two hundred nanoseconds for both, for the Comba of
the limbs is in the assembly and the reduction of the product is
still in Lisp.  The signature of P-224 is still made with the
numbers, for the limb field cannot be faster than they are until
the reduction is in the assembly too, and that is the last piece of
the field of P-224 in limbs.

The reduction of the field of P-224 was written in the assembly as
well, and it is not exact yet, so it is not in the tree.  The
algorithm is the one of the Lisp reduction, which is checked against
the integer arithmetic: the limbs of the high half of the product go
up by three limbs, the high half is given back from the bottom, the
low half is added, and the excess, which is what is left above the
seventh limb, is folded in until there is none, for the excess can be
one and folding it in can give an excess of one again.

Two conventions of borrows are in it, and they are not the same.  In
the subtraction of the high half the borrow is a count, zero or one,
and it is subtracted.  In the fold it is signed, minus one or zero,
and it is added, for the value of the difference is the difference
less one.  The excess that the fold leaves is the carry of the
addition and the borrow of the subtraction, and it is two too large
in the assembly, which is worth a tenth of the value of the excess:
the result is too large by 2^97 less two.  The borrow of the
subtraction of the prime is signed in the Lisp reduction, but the
prime is below the value there, so that borrow never happens and the
convention does not matter.

The borrow of a subtraction in the assembly has to be counted, and
the count is made by shifting the difference up by a limb and taking
the low bit of it, for the shift of a word of ones gives minus one
and the low bit of that is one.  A move into memory with an
immediate has no size that the assembler can tell, so the words that
are cleared are cleared with a register.

The way to find the two that are too many is to compare the scratch
of the assembly with the scratch of the Lisp reduction, for the two
are the same eleven words and the phases are the same.  The scratch
of the Lisp reduction is not reachable while the assembly is there,
for the reader throws the Lisp away, so the two have to be compared
by making the Lisp the one that is read, or by writing the eleven
words of the scratch of the assembly out and computing the same
words with the Lisp in a program of its own.  The eleven words are
the three that the first phase does not write, the seven that the
second phase writes, and the one that the first phase writes at the
end, so the phases are four words, and the first phase to differ is
the one that is wrong.

The excess of the fold is a count of limbs and not a number, and the
two borrows of the fold are of different kinds: the borrow of the
subtraction of the excess is signed and is added, and the borrow of
the subtraction of the high half is a count and is subtracted.  The
excess that the fold leaves is the carry of the addition of the
excess and the borrow of the subtraction of it, and the count of the
two is what the next fold works with.

The scratch of the assembly and the scratch of the Lisp reduction
were compared, word by word, on the same product, and the four words
of the excess agree and the seven words of the value do not: the
assembly is two too small in the first word and two too large in the
fourth.  So the excess, which is what the fold works with, is right,
and the fold itself is wrong: the first pass of the fold, which
adds the excess at the fourth limb and up, and the second, which
gives it back at the bottom, do not between them give what the Lisp
gives.

The two are to be compared the same way again, with the first and
the second pass of the fold separated: the first pass writes the
words three to six and the second writes the words zero to six, so
the words zero to two are the same after both and the words three
to six are not, and the two that differ are the words that the
first pass writes and the second one reads.

The comparison is made by calling the assembly directly, for the
Lisp reduction is the one that is read when the assembly is not
wired in, and the scratch of each is the eleven words that the
reduction leaves.

The comparison of the two scratches says more than it first seemed.
The four words of the excess that the fold leaves are the same in
the two, and the seven words of the value differ by two in the first
word and two in the fourth, and that is exactly what a value of the
excess that is two too large gives, for the fold adds the excess at
the fourth limb and gives it back at the bottom, and the difference
between the two is the excess times B^3 less the excess.

So the excess that the fold works with, which is the excess as it
is made by the fourth phase and not the excess that the fold
leaves, is two too large in its first word, and the three words
above it are right.  The first word of that excess is the fourth
word of the shift of the high half, which is the eleventh word of
the product, plus the borrow of the subtraction of the high half and
the carry of the addition of the low half.  The borrow is a count
and the carry is a count, and the two of them are two too large
between them, so one of the two counts is one too large, or both of
them are.

The counts of the two phases are made the same way in the two:
a sum carries one when it reaches a limb, and a difference borrows
one when it goes below zero.  In the assembly the count of a
difference is made by shifting it up a limb, which gives minus one,
and taking the low bit of that, which gives one; in the Lisp it is
the test for a negative value.  The borrow of the fold is signed
and is added, and there the shift up a limb is used as it is.

The borrow of the subtraction of the high half is signed and is
subtracted, and the excess takes it as it is: the excess is the word
of the shift of the high half, less one when the subtraction
borrowed, plus the carry of the addition of the low half.  The
assembly counted the borrow, which made the excess two too large,
and the count is the reason the two scratches differed by two in
the first word and by two in the fourth.

With the borrow signed, as the Lisp reduction has it, the first four
phases of the two agree, and the difference is in the fold: the
words one, two, three and six of the value are two too large.  The
fold adds the excess at the fourth limb and up and gives it back at
the bottom, and the words that the two passes write are the words
zero to six, so the difference of two in the words one, two, three
and six says that the first pass and the second pass do not
between them take out what the excess is.

The two passes are to be compared one at a time: the first pass
alone, with the second pass left out, and then the second pass
alone, with the first left out.  The scratch of the assembly is the
eleven words that the reduction leaves, and the Lisp reduction is
the one that is read when the assembly is not wired in, so the two
are compared by calling each of them on the same product and
looking at the eleven words.

The fold adds the excess at the fourth limb and up and takes it
back at the bottom, so the net of the two passes on the words one
and two is nothing, and the net on the word six is the fourth word
of the excess, which is zero.  The two scratches differ by two in
the words one, two, three and six, and the words one and two are
left by the fold as they were, so the difference is not in the fold
but in the phases before it, and the excess, which is the four
words above the value, is the same in the two.

So the two phases that make the value are to be compared the same
way as the fold: the excess was compared by a probe in the Lisp
reduction and by stopping the assembly, and the phases are to be
compared by a probe after the subtraction of the high half and
after the addition of the low half, with the assembly stopped at
the same two places.

The two words that carry the difference, the first and the second,
are the words where the subtraction of the high half and the
addition of the low half carry their borrows and their carries, so
the difference is a borrow or a carry that is one too large or one
too small in one of the two phases, and the words three and six
carry it further.

The probes of the two phases that make the value say that the
difference is there and not in the fold: after the addition of the
low half the words one, two and three of the value are two too large
in the assembly, and the words zero, four, five and six and the
whole of the excess are the same in the two.

The excess is made of the word of the shift of the high half, less
one when the subtraction of the high half borrowed, and the carry of
the addition of the low half.  The excess is the same in the two,
so the borrow of the subtraction and the carry of the addition are
the same in the two, and the words that differ are the ones that
the addition carries into and out of: the words one, two and three
are two too large and the word zero is not, and a word that is two
too large in the middle of a chain of carries makes the words above
it two too large as well, which they are not.

So the addition of the low half is not the whole of it either, and
the word that is two too large is one that the addition writes, and
the subtraction of the high half writes before it.  The two phases
are to be probed one at a time: the subtraction of the high half
alone, with a probe after it, against the assembly stopped at the
same place, and then the addition of the low half alone.

The words of the value that the addition writes are the words zero
to six, and the excess that it takes is the word seven and the three
above it, so the word six and the three words above it are worth
looking at first: the excess is the same in the two, but the words
below it are not.

The subtraction of the high half is where the two differ, and not
the addition of the low half: after the subtraction the words one,
two and three of the value are two too large in the assembly, and
the word zero, the words four, five and six and the whole of the
excess are the same in the two.  The excess is the same, so the
borrow of the subtraction and the carry of the addition are the
same.

The subtraction of the high half is a chain of borrows: the first
three words of the scratch are cleared and the limbs of the high
half come out of the fourth word and up, so the first three words
are zero less a limb of the high half less the borrow, and the
fourth word is a limb of the shift less a limb of the high half
less the borrow.  The words one and two are two too large and the
word three is two too large, and the word four and the two above it
are the same, so the chain is right again at the fourth word.

The borrow of the subtraction is signed and is subtracted, so that a
word that borrows makes the word above it one larger, and the word
that borrows has the borrow of the word below it added to it, which
is what the two together do.  A word two too large with the word
above it right again is not a chain of borrows, and the three words
that are two too large are the three that the borrow of the word
below reaches, so the borrow is two too small in the word below the
first of them and right in the fourth word.

The subtraction is therefore to be compared a word at a time, with
the borrow of each word written out, which the probe can do: the
probe of the phase two should also give the borrow, and the
assembly should write its borrow out as well, and the two borrows
are to be compared word by word.

The field of P-224 was written again after the reference, in four
limbs of fifty-six bits, and the reduction of it is the one of the
reference: the product of two field elements is seven wide
coefficients of a hundred and twenty-eight bits, which are the
columns of the product and are not reduced, and the reduction of
those coefficients is the one of a Solinas prime, in which the
multiples of the prime that are added first make every difference
positive, so that no borrow is ever needed.  The value that comes
out is below twice the prime, and the contract at the end takes it
below the prime.

It agrees with the integer arithmetic, for two hundred pairs of
random values.  The old reduction of the field, which is in Lisp
and which is checked against the integer arithmetic as well, is
kept for the while: the field in limbs of thirty-two bits that the
point arithmetic of the tree uses is not the field in limbs of
fifty-six bits that the reference uses, and the point arithmetic
has to be moved to the new field before the two can be told apart.

What the reference has that the old reduction does not is that the
subtractions are of numbers that are known to be positive, so that
the reduction can be written without a borrow and can be written in
the assembly without a borrow either, which is what the assembly of
the reference does.

The sums and the differences of the field of P-224 are written after
the reference as well: they are made in the wide form and reduced,
like the product is, and the contract brings them below the prime.
They agree with the integer arithmetic, for two hundred pairs of
random values.

What the field of the reference gives that the field of the tree
does not have is that every subtraction in it is of numbers that are
known to be positive, for the multiples of the prime are added
first.  That is what the reduction in the assembly needs and what
the reduction that was in the tree did not have, and it is the
reason that the reduction in the assembly could be written at all.

The field of the reference is in four limbs of fifty-six bits and
the point arithmetic of the tree is in seven limbs of thirty-two
bits, so the point arithmetic is to be moved to the new field
before the two can be compared, and the comparison is the next
thing to do.

The field of P-224 is now the field of the reference all the way
through: four limbs of fifty-six bits for the element, seven wide
coefficients for the product, the reduction of a Solinas prime, the
contract, and the sums and the differences made in the wide form and
reduced.  The point arithmetic of the tree, the comb and the ladder,
run on that field and agree with the big numbers, for the corners
and for twenty random triples.

The signature is not moved onto that field yet, for the product and
the reduction of it are in Lisp, where the coefficients are big
numbers, and the comb of the limbs takes three thousand two hundred
microseconds where the comb of the big numbers takes a hundred and
twenty.  The assembly of the product and of the reduction is what
makes the field win, and it is the next thing: sixteen products of
fifty-six by fifty-six bits for the product, and the reduction of
the reference, which needs no borrow and so can be written in the
assembly as it is.

The assembly of the field of P-224 follows the structure of the
reference, and the words are these.

The element is four words of sixty-four bits, each holding a limb of
fifty-six bits, and the value is below the prime, so the top word
holds only eight bits.  The product is seven wide coefficients of a
hundred and twenty-eight bits, and each of them is two words.

The product is made in columns, as the reference makes it: the
coefficient of a column is the sum of the products of the limbs whose
indices add up to the column, and the columns are seven, for four
limbs on each side.  The product of two limbs of fifty-six bits is a
hundred and twelve bits, and it is made of a low half of fifty-six
bits and a high half of fifty-six bits, and the low halves of a
column are summed in one word and the high halves in another.  The
sum of the low halves of a column is under 2^58 and the sum of the
high halves is under 2^50, so both fit in a word, and the coefficient
is the low sum plus the high sum shifted up by fifty-six bits, which
is the hundred and twenty-eight bits of the reference's coefficient.
The carry of a column is the high sum shifted up by fifty-six bits
plus the part of the low sum above fifty-six bits, and it is the
carry of the next column.

The reduction is the one of the reference, and it needs no borrow,
for the multiples of the prime are added first: the wide
coefficients are the seven limbs of fifty-six bits, each in two words,
and the constants of the reference, which are of a hundred and
twenty-seven bits, are added to the three lowest of them.

The prime of P-224 is 2^224 - 2^96 + 1, and its limbs of fifty-six
bits are one, 2^56 - 2^40, 2^56 - 1 and 2^8, and the multiples of
it that the reference adds are of a hundred and twenty-seven bits,
which in the limbs of fifty-six bits are the word of ones shifted up
by seventy-one bits, less the words of the limbs.

The contract at the end is a comparison and a subtraction, and the
comparison is of the value with the prime, and the value is below
twice the prime, so one subtraction is enough.

The assembly of the field of P-224, in the words it is to have.

The element is four words of sixty-four bits, each holding a limb of
fifty-six bits.  The product is eight words, each holding a limb of
fifty-six bits, and the limbs are the columns of the product with the
carries carried into the next column, so that every limb of the
product is below 2^56.  The columns are seven, and the carry of a
column is the high half of the column, shifted up by fifty-six bits,
plus the part of the low half that is above fifty-six bits, and the
low halves of a column are summed in one word and the high halves in
another, as the goldilocks does: the low halves of a column of four
products sum to under 2^58 and the high halves to under 2^50, so both
fit in a word, and the limb of the product is the low half of the low
sum with the rest of the column carried on.  The product of two
elements is therefore eight words, and it is the product of the
reference with the carries carried, which is the same number.

The reduction of that product is the one of the reference, and it is
written on the eight limbs of fifty-six bits.  The value is the low
four limbs plus the high four limbs times B^7, and B^7 is congruent
to B^3 less one, so the value is congruent to the low four limbs
plus the high four limbs times B^3, less the high four limbs.  The
multiples of the prime that are added first make every difference
positive: the prime is B^7 - B^3 + 1, and a multiple of it large
enough is B^7, whose limbs of fifty-six bits are one, zero, zero and
one, and the multiple that the reference uses is that one with the
words of ones in it, so that the difference of the high four limbs
from the low four limbs is made without a borrow.

The four limbs of the multiple of the prime that the reference adds
are the ones of the wide form: the first is 2^64 + 8, the second is
2^64 - 2^48 - 8, the third is 2^64 - 8 and the fourth is 2^64 - 8,
and each of them is added to the limb of the same place, and the
differences are then without a borrow, and the reduction is the
shifting of the high limbs and the carrying that the reference does.

The sums and the differences are made in the same eight words, the
sum of two elements is the eight limbs with the carries of the sum,
and the difference of two elements is the eight limbs with the
multiple of the prime added first, and both are reduced the same way.

The Comba of the assembly of the field of P-224 is the Comba of the
goldilocks, which is for the same limbs of fifty-six bits and is
written the same way: the low halves of a column are summed in one
word and the high halves in another, the limb of the product is the
low fifty-six bits of the low sum, which is made by shifting the sum
up by eight bits and back down by eight, and the carry into the next
column is the high sum shifted up by eight bits with the part of the
low sum above fifty-six bits added to it, which is the low sum
shifted right by fifty-six bits.

The comment of that Comba says that it stores a word of thirty-two
bits, and that is stale: the words it stores are fifty-six bits
wide, and the shifts of eight and fifty-six are the ones of a limb
of fifty-six bits.  The product of the goldilocks is of eight limbs
and has fifteen columns and a carry, and the product of the field of
P-224 is of four limbs and has seven columns and a carry.

The Comba of the field of P-224 is written, in the assembly, as the
Comba of the goldilocks with four limbs and eight columns, and it did
not compile, so it is not in the tree.  It is this, with the name of
the routine changed to SECP224R1-FE-MUL-LIMBS-ASM, for the one that is
there is the one of the thirty-two bit limbs:

#+x86-64
(define-vop (secp224r1-fe-mul-raw-asm)
  ;; C := A * B, as eight limbs of fifty-six bits, with the carries
  ;; carried, after the goldilocks.
  ;;
  ;; A and B are four limbs of fifty-six bits in words of sixty-four
  ;; bits, and C is eight words of sixty-four bits, each holding a limb
  ;; of fifty-six bits.
  ;;
  ;; The low halves of a column are summed in one word and the high
  ;; halves in another: the low halves of a column of four products
  ;; sum to under 2^58 and the high halves to under 2^50, so both fit
  ;; in a word.  The limb of the product is the low fifty-six bits of
  ;; the low sum, and the carry into the next column is the high sum
  ;; shifted up by fifty-six bits with the part of the low sum above
  ;; fifty-six bits added to it.
  (:translate ironclad::secp224r1-fe-mul-limbs-asm)
  (:policy :fast-safe)
  (:args (c :scs (descriptor-reg))
         (a :scs (descriptor-reg))
         (b :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-64
              simple-array-unsigned-byte-64
              simple-array-unsigned-byte-64)
  (:temporary (:sc unsigned-reg) lo hi carry tmp)
  (:temporary (:sc unsigned-reg :offset rax-offset) rax-tmp)
  (:temporary (:sc unsigned-reg :offset rdx-offset) rdx-tmp)
  (:generator 1000
    (let ((data-offset (- (* n-word-bytes vector-data-offset)
                           other-pointer-lowtag)))
      (flet ((a64 (i) (ea (+ data-offset (* 8 i)) a))
             (b64 (i) (ea (+ data-offset (* 8 i)) b))
             (c64 (k) (ea (+ data-offset (* 8 k)) c)))
        (inst mov carry 0)
        (dotimes (k 8)
          (inst mov lo carry)
          (inst mov hi 0)
          (dolist (i (loop for x from (max 0 (- k 3)) to (min 3 k)
                           collect x))
            (let ((j (- k i)))
              (inst mov rax-tmp (a64 i))
              (inst mov tmp (b64 j))
              (inst mul tmp)
              (inst add lo rax-tmp)
              (inst adc hi rdx-tmp)))
          ;; The limb is the low fifty-six bits of the low sum, and the
          ;; carry is the rest of the column.
          (inst mov tmp lo)
          (inst shl tmp 8)
          (inst shr tmp 8)
          (inst mov (c64 k) tmp)
          (inst mov carry hi)
          (inst shl carry 48)
          (inst mov tmp lo)
          (inst shr tmp 56)
          (inst or carry tmp))))))


The name of the routine has to be one of its own, for the one that
translates the same symbol is the Comba of the thirty-two bit limbs,
and the definition of the function has to be made before the file of
the routines is read.
