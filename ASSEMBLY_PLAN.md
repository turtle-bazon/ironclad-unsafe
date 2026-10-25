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
- Dedicated squaring VOP for P-256 (SOS squaring, ~10 mulq instead of 16);
  estimated ~7% on verify.  Not yet done.
- secp384r1 and secp521r1 use bignum integers, not limb arrays; porting
  them to a limb-based Montgomery representation is a full rewrite.
- DSA/RSA Montgomery modexp (variable modulus, per-key p').
- AVX2 mul-raw for P-256 (secondary; the scalar VOP is already 40 ns).
- fe-inv uses the addition chain (12 us); a 4-limb binary extended gcd
  would be ~2-3 us.