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

### Phase 5 — Falcon (FFT/NTT)
- Replace recursive complex-double FFT with iterative, cache-friendly version.
- Add AVX2 VOPs for the butterfly operations.
- Validate against `falcon-*-keymat` test vectors (bit-exact).

### Phase 6 — HQC / McEliece
- These are code-based (no big-int field); bottlenecks are polynomial
  multiplication over GF(2). Add carry-less multiply (PCLMULQDQ) VOPs.

## Infrastructure needed
- New VOP definitions in `src/opt/sbcl/x86oid-vm.lisp`.
- New `defknown` entries in `src/opt/sbcl/fndb.lisp`.
- Assembly detection already in place (`ironclad-assembly` feature).
- Each phase needs its own test-validated PR.

## Risk / validation
- Every change must keep all 671 tests passing.
- Add randomised roundtrip tests (like McEliece's `kem-roundtrip-test`)
  for any modified algorithm.
- Benchmark before/after on `all-algorithms.md`.

## Recommended first step
Start with **Phase 1 (ed25519)**: it has the cleanest existing limb
infrastructure (`ed25519-fe-*`) and the point ops are the clear bottleneck
(2MB consing per sign). Converting point slots from integers to `ed25519-fe`
arrays and routing through the existing fe ops is the highest-ROI single change.
EOF
echo "written"
## Notes on BMI2, ADX and AVX2 (measured, 2026-10-21)

The CPU feature detection is in place (`bmi2-supported-p`,
`adx-supported-p`, `avx2-supported-p`, `avx512-supported-p` in
`src/opt/sbcl/cpu-features.lisp`).  The findings below are what the
measurements showed, and they decide where the new instruction sets can
actually pay off.

An earlier revision of this file claimed that the assembler of the
SBCL in use did not know `MULX`, `ADCX` and `ADOX`, and that they
would have to be emitted as raw bytes.  That was wrong: the check
that produced it, `ironclad-instruction-known-p`, looked the
instruction up in the `SB-ASSEM` package, but SBCL creates the
structure for an x86-64 instruction in `SB-X86-64-ASM`, so the check
always answered NIL.  With the check fixed, both SBCL 2.6.7 and
2.6.9 turn out to know `MULX`, `ADCX`, `ADOX` and the whole AVX2 and
AVX-512 instruction set.

### Where they do *not* help

* **BMI2 `MULX` in the 32-bit limb Comba** (`secp256r1-mul-raw-asm`,
  `ed25519-mul-raw-asm`): little gain.  `MULX` avoids the fixed
  RAX/RDX operands of `MUL`, but the out-of-order engine already
  renames those registers away, so the product latency and
  throughput are the same.  It does free the registers, which
  matters when the accumulator needs more of them.
* **ADX `ADCX`/`ADOX` in a 32-bit limb Comba**: the accumulator of a
  Comba column is 128 bits wide, and the products of two 32-bit limbs
  are 64 bits, so the two halves of a product are *not* independent
  halves of the accumulator.  The carry of the low half has to reach
  the high half, which is exactly the dependency that `ADCX`/`ADOX`
  cannot express.  `ADCX`/`ADOX` only pay off when the two halves of
  the product are the two halves of the accumulator, that is, when the
  limbs are wide enough that a product is 128 bits.
* **AVX2 `VPMULUDQ` in a 32-bit limb Comba**: the columns of a Comba
  have between one and eight products, and only two of the sixteen
  columns have eight, so four-way multiplication cannot be applied
  uniformly.  The row-wise variant that would suit `VPMULUDQ` sums four
  64-bit products, which overflows a 64-bit lane; splitting the
  products into halves needs a horizontal sum that costs more than the
  four multiplies it saves.

### Where they do help

* **A 56-bit limb field, as in ed448 and curve448** (q = 2^448 - 2^224
  - 1, eight limbs): a product of two limbs is 112 bits, so the low
  64 bits and the high 48 bits of the product are the two halves of a
  128-bit accumulator, and `ADCX`/`ADOX` give two independent carry
  chains.  `MULX` produces the product without fixing RAX and RDX.
  The reduction is cheap as well: 2^448 = 2^224 + 1 (mod q) and 224
  bits are exactly four limbs, so the high half of a product is folded
  back by adding it and by adding it shifted up by four limbs.
  This is the design to use for ed448 and curve448.  Both
  instructions are now known to the assembler, so the kernel can be
  written with them directly.
* **A 4-lane AVX2 field**: `VPMULUDQ` fits a field of 32-bit limbs, but
  only in a layout where four independent products are needed at once
  and the results are used separately.  The symmetric primitives
  (ChaCha20, Poly1305) are the better AVX2 target: four blocks of
  ChaCha20 in the four lanes of a YMM register is the classic SIMD
  formulation and would remove most of the 5.7x gap of the `chacha`
  cipher.

### Constraints to keep in mind

* The assembler of SBCL 2.6.7 and 2.6.9 knows `MULX`, `ADCX`, `ADOX`
  and the whole AVX2 and AVX-512 instruction set, so they can be
  emitted directly; no raw byte encoding is needed.
  `ironclad-instruction-known-p` checks for an instruction, and
  looks it up in the `SB-X86-64-ASM` package, where SBCL creates
  the structure for an instruction when it defines it.
* A VOP must not use an instruction that the CPU of the machine it
  runs on does not have.  The features of the machine are detected
  once, when the system is loaded, and cached; the assembly code
  that uses them is only reached when the corresponding feature was
  found.
* The features of the development machine (AMD Zen 2) and of the
  target machine (Intel Xeon, Skylake) differ, so a path that is
  only exercised on one of them is not enough:

  | feature  | AMD Zen 2    | Intel Skylake |
  |----------|--------------|---------------|
  | AES-NI   | yes          | yes           |
  | PCLMULQDQ| yes          | yes           |
  | SHA-NI   | yes          | **no**        |
  | BMI1/2   | yes          | yes           |
  | ADX      | yes          | yes           |
  | AVX2     | yes          | yes           |
  | AVX-512  | **no**       | yes           |

  The target has no SHA-NI: the SHA-256 code must keep working
  without it.  An AVX-512 path can only be tested on the target.
* A VOP's `:translate` has to name a *different* symbol than the
  VOP itself (`secp256r1-reduce-fast-asm` translates
  `ironclad::secp256r1-fe-reduce-fast-asm`), and the `defknown` for
  the translated symbol has to exist in `src/opt/sbcl/fndb.lisp`.
  The argument types of the `defknown` have to be real types;
  `unsigned-num` is only understood by the VOP itself.
* A `defknown` whose arguments are vectors must not be given a
  vector that SBCL's escape analysis can stack allocate.  A stack
  vector has a different layout from a heap vector, and a VOP that
  addresses its array argument with the heap layout then reads and
  writes outside the array.  Passing the array through a function
  that is not inlined makes the array escape into a real call, and
  it is then always heap allocated.
