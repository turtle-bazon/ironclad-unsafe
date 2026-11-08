;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;;
;;;; ed25519-comb.lisp -- fixed-base scalar multiplication and field
;;;; inversion in x86-64 assembly, using radix-2^51 field arithmetic.
;;;;
;;;; The generator point is fixed, so we precompute (in Lisp) the digit
;;;; table T[j][v] = v * 256^j * G and hand it to a single VOP.  The VOP
;;;; sums the 32 selected table points with the unified twisted-Edwards
;;;; addition formula, doing every field operation on 5 x 51-bit limbs.
;;;;
;;;; The comb VOP takes exactly two arguments -- the flat radix-2^51 digit
;;;; table and a scratch vector -- because every other value (the scalar
;;;; digits, the constant 2*d, and the result) lives inside the scratch
;;;; vector.  That keeps register pressure low enough for the register
;;;; allocator while still pinning the handful of registers the code
;;;; actually wants.
;;;;
;;;; The inversion VOP reuses the same field routines for the standard
;;;; 2^255-21 addition chain (254 squarings and 11 multiplications), which
;;;; is the other half of the cost of signing.
;;;;
;;;; Scratch layout, in bytes from the scratch base:
;;;;
;;;;     0   scalar digits, one 64-bit word each (32 words)
;;;;     256 2*d, five radix-2^51 limbs
;;;;     296 result X,Y,Z,T, four coordinates of five limbs
;;;;     456 .. field-element working area
;;;;
;;;; Every field-element offset below is a byte offset from the scratch
;;;; base, so the emitted code can use constant displacements.

#+(and x86-64 ironclad-unsafe-assembly)
(in-package :ironclad-unsafe-vm)

#+(and x86-64 ironclad-unsafe-assembly)
(progn
  (defconstant +c-scalar+  0)    ; 32 x 8 bytes
  (defconstant +c-twod+    256)  ; five limbs
  (defconstant +c-result+  296)  ; X, Y, Z, T (four x five limbs)
  (defconstant +c-x2+      456)
  (defconstant +c-y2+      496)
  (defconstant +c-z2+      536)
  (defconstant +c-t2+      576)
  (defconstant +c-ymx1+    616)
  (defconstant +c-ypx1+    656)
  (defconstant +c-ymx2+    696)
  (defconstant +c-ypx2+    736)
  (defconstant +c-a+       776)
  (defconstant +c-b+       816)
  (defconstant +c-c+       856)
  (defconstant +c-d+       896)
  (defconstant +c-e+       936)
  (defconstant +c-f+       976)
  (defconstant +c-g+       1016)
  (defconstant +c-h+       1056)
  (defconstant +c-mulacc+  1096) ; nine 128-bit columns
  (defconstant +c-hacc+    1240) ; five 128-bit accumulators
  (defconstant +c-c19+     1320) ; the constant 19
  (defconstant +c-acc0+    1328) ; X, Y, Z, T (four x five limbs)
  (defconstant +c-acc1+    1488)
  (defconstant +c-scratch-bytes+ 1648))

#+(and x86-64 ironclad-unsafe-assembly)
(defmacro ed25519-with-fe-ops ((p-scr tmp1 tmp2 rax-tmp rdx-tmp
                                mulacc hacc c19) &body body)
  "Expand to LABELS defining FE-ADD, FE-SUB and FE-MUL on the scratch
vector addressed by P-SCR, then evaluate BODY.  Every field element is
five 64-bit limbs at a byte offset from P-SCR.  C19 is kept for the
callers' scratch layouts but is no longer read by FE-MUL."
  (declare (ignorable c19))
  `(labels
       ((fe-add (dst a b)
          ;; dst = a + b, limbwise (lazy reduction).
          (dotimes (i 5)
            (inst mov ,tmp1 (ea (+ a (* 8 i)) ,p-scr))
            (inst add ,tmp1 (ea (+ b (* 8 i)) ,p-scr))
            (inst mov (ea (+ dst (* 8 i)) ,p-scr) ,tmp1)))
        (fe-sub (dst a b)
          ;; dst = a - b + 4*q, limbwise; 4*q keeps every limb positive
          ;; given |a|,|b| < 2^54.
          (inst mov ,tmp1 1)
          (inst shl ,tmp1 53)
          (inst sub ,tmp1 76)          ; 4*q0 = 2^53 - 76
          (dotimes (i 5)
            (inst mov ,tmp2 (ea (+ a (* 8 i)) ,p-scr))
            (inst add ,tmp2 ,tmp1)
            (inst sub ,tmp2 (ea (+ b (* 8 i)) ,p-scr))
            (inst mov (ea (+ dst (* 8 i)) ,p-scr) ,tmp2)
            (when (zerop i)
              (inst add ,tmp1 72))))   ; 4*qi = 2^53 - 4
        (fe-mul (dst a b)
          ;; dst = a * b mod q, radix 2^51, fully unrolled.
          ;;
          ;; Column form with the 2^255 == 19 fold applied to the
          ;; operand: with B19[j] = 19*b[j] (j = 1..4),
          ;;   h[k] = sum_{i<=k} a[i]*b[k-i] + sum_{i>k} a[i]*B19[k-i+5]
          ;; and each column is summed in a register pair.  The old form
          ;; accumulated 25 products into nine 128-bit columns in memory
          ;; (a read-modify-write add/adc pair per product) and folded the
          ;; top four columns in a second pass.  Bounds: inputs < 2^54 and
          ;; B19 < 2^58.3, so a column of five products is < 2^115.
          ;; DST may alias A or B: every input is read before DST is
          ;; written.  MULACC now only holds B19.
          (flet ((column (k terms)
                   ;; HACC[k] := sum of (X * Y) over TERMS, each X and Y
                   ;; a byte offset from P-SCR.
                   (loop for (x y) in terms
                         for first = t then nil
                         do (inst mov ,rax-tmp (ea x ,p-scr))
                            (inst mul :qword (ea y ,p-scr))
                            (if first
                                (progn
                                  (inst mov ,tmp1 ,rax-tmp)
                                  (inst mov ,tmp2 ,rdx-tmp))
                                (progn
                                  (inst add ,tmp1 ,rax-tmp)
                                  (inst adc ,tmp2 ,rdx-tmp))))
                   (inst mov (ea (+ ,hacc (* 16 k)) ,p-scr) ,tmp1)
                   (inst mov (ea (+ ,hacc (* 16 k) 8) ,p-scr) ,tmp2)))
            (if (eql a b)
                ;; Square: 15 products.  MULACC holds 2a0 2a1 2a2 2a3
                ;; 19a3 19a4; bounds as above (2a < 2^55, 19a < 2^58.3).
                (flet ((av (i) (+ a (* 8 i)))
                       (d (i) (+ ,mulacc (* 8 i)))
                       (n19 (i) (+ ,mulacc 32 (* 8 (- i 3)))))
                  (dotimes (i 4)
                    (inst mov ,tmp1 (ea (av i) ,p-scr))
                    (inst add ,tmp1 ,tmp1)
                    (inst mov (ea (d i) ,p-scr) ,tmp1))
                  (inst imul ,tmp1 (ea (av 3) ,p-scr) 19)
                  (inst mov (ea (n19 3) ,p-scr) ,tmp1)
                  (inst imul ,tmp1 (ea (av 4) ,p-scr) 19)
                  (inst mov (ea (n19 4) ,p-scr) ,tmp1)
                  (column 0 (list (list (av 0) (av 0)) (list (d 1) (n19 4))
                                  (list (d 2) (n19 3))))
                  (column 1 (list (list (d 0) (av 1)) (list (d 2) (n19 4))
                                  (list (av 3) (n19 3))))
                  (column 2 (list (list (d 0) (av 2)) (list (av 1) (av 1))
                                  (list (d 3) (n19 4))))
                  (column 3 (list (list (d 0) (av 3)) (list (d 1) (av 2))
                                  (list (av 4) (n19 4))))
                  (column 4 (list (list (d 0) (av 4)) (list (d 1) (av 3))
                                  (list (av 2) (av 2)))))
                (progn
                  (dotimes (j 4)
                    (inst imul ,tmp1 (ea (+ b (* 8 (1+ j))) ,p-scr) 19)
                    (inst mov (ea (+ ,mulacc (* 8 j)) ,p-scr) ,tmp1))
                  (dotimes (k 5)
                    (column k (loop for i below 5
                                    collect (list (+ a (* 8 i))
                                                  (if (<= i k)
                                                      (+ b (* 8 (- k i)))
                                                      (+ ,mulacc (* 8 (+ (- k i) 4)))))))))))
          ;; carry chain
          (inst xor ,tmp1 ,tmp1)
          (dotimes (k 5)
            (let ((h (+ ,hacc (* 16 k))))
              (inst mov ,rax-tmp (ea h ,p-scr))
              (inst mov ,rdx-tmp (ea (+ h 8) ,p-scr))
              (inst add ,rax-tmp ,tmp1)
              (inst adc ,rdx-tmp 0)
              (inst mov ,tmp2 ,rax-tmp)
              (inst shl ,tmp2 13)
              (inst shr ,tmp2 13)
              (inst mov (ea (+ dst (* 8 k)) ,p-scr) ,tmp2)
              (inst shrd ,rax-tmp ,rdx-tmp 51)
              (inst mov ,tmp1 ,rax-tmp)))
          ;; 5. fold the final carry back into limb 0
          (inst imul ,rax-tmp ,tmp1 19)
          (inst add ,rax-tmp (ea dst ,p-scr))
          (inst mov ,tmp2 ,rax-tmp)
          (inst shr ,tmp2 51)
          (inst shl ,rax-tmp 13)
          (inst shr ,rax-tmp 13)
          (inst mov (ea dst ,p-scr) ,rax-tmp)
          (inst add (ea (+ dst 8) ,p-scr) ,tmp2)))
     ,@body))

#+(and x86-64 ironclad-unsafe-assembly)
(define-vop (ed25519-comb-asm)
  (:translate ironclad-unsafe::ed25519-comb-asm)
  (:policy :fast-safe)
  (:args (table :scs (descriptor-reg))
         (scratch :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-64
              simple-array-unsigned-byte-64)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdi-offset) p-scr)
  (:temporary (:sc unsigned-reg :offset sb-vm::rsi-offset) p-table)
  (:temporary (:sc unsigned-reg :offset sb-vm::r8-offset) jj)
  (:temporary (:sc unsigned-reg :offset sb-vm::r10-offset) tmp1)
  (:temporary (:sc unsigned-reg :offset sb-vm::r11-offset) tmp2)
  (:temporary (:sc unsigned-reg :offset sb-vm::rax-offset) rax-tmp)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdx-offset) rdx-tmp)
  (:generator 1000
    (let ((data-offset (- (* n-word-bytes vector-data-offset)
                           other-pointer-lowtag))
          (loop-label (gen-label))
          (skip-label (gen-label)))
      (ed25519-with-fe-ops (p-scr tmp1 tmp2 rax-tmp rdx-tmp
                                  +c-mulacc+ +c-hacc+ +c-c19+)
        ;; ---- prologue ----
        (inst lea p-scr (ea data-offset scratch))
        (inst lea p-table (ea data-offset table))
        (inst mov :qword (ea +c-c19+ p-scr) 19)
        ;; acc0 = identity (0, 1, 1, 0)
        (inst xor rax-tmp rax-tmp)
        (dotimes (k 20)
          (inst mov :qword (ea (+ +c-acc0+ (* 8 k)) p-scr) rax-tmp))
        (inst mov rax-tmp 1)
        (inst mov :qword (ea (+ +c-acc0+ 40) p-scr) rax-tmp)
        (inst mov :qword (ea (+ +c-acc0+ 80) p-scr) rax-tmp)
        ;; ---- main loop over the 32 base-256 digits ----
        (inst xor jj jj)
        (emit-label loop-label)
        (inst movzx '(:byte :dword) tmp1 (ea 0 p-scr jj 8))
        (inst test tmp1 tmp1)
        (inst jmp :z skip-label)
        ;; locate T[jj][digit]
        (inst mov tmp2 jj)
        (inst shl tmp2 8)
        (inst add tmp2 tmp1)
        (inst imul tmp2 tmp2 160)
        (inst lea tmp2 (ea 0 p-table tmp2))
        ;; copy the chosen point into scratch
        (dotimes (k 20)
          (inst mov rax-tmp (ea (* 8 k) tmp2))
          (inst mov :qword (ea (+ +c-x2+ (* 8 k)) p-scr) rax-tmp))
        ;; unified addition (a = -1) with k = 2d:
        ;;   A = (Y1-X1)(Y2-X2)   B = (Y1+X1)(Y2+X2)
        ;;   C = 2d*T1*T2         D = 2*Z1*Z2
        ;;   E = B-A  F = D-C  G = D+C  H = B+A
        ;;   X3 = E*F  Y3 = G*H  Z3 = F*G  T3 = E*H
        (fe-sub +c-ymx1+ (+ +c-acc0+ 40) (+ +c-acc0+ 0))
        (fe-add +c-ypx1+ (+ +c-acc0+ 40) (+ +c-acc0+ 0))
        (fe-sub +c-ymx2+ (+ +c-x2+ 40) (+ +c-x2+ 0))
        (fe-add +c-ypx2+ (+ +c-x2+ 40) (+ +c-x2+ 0))
        (fe-mul +c-a+ +c-ymx1+ +c-ymx2+)
        (fe-mul +c-b+ +c-ypx1+ +c-ypx2+)
        (fe-mul +c-c+ (+ +c-acc0+ 120) (+ +c-x2+ 120)) ; T1*T2
        (fe-mul +c-c+ +c-c+ +c-twod+)
        (fe-mul +c-d+ (+ +c-acc0+ 80) (+ +c-x2+ 80))   ; Z1*Z2
        (fe-add +c-d+ +c-d+ +c-d+)
        (fe-sub +c-e+ +c-b+ +c-a+)
        (fe-sub +c-f+ +c-d+ +c-c+)
        (fe-add +c-g+ +c-d+ +c-c+)
        (fe-add +c-h+ +c-b+ +c-a+)
        (fe-mul (+ +c-acc1+ 0) +c-e+ +c-f+)
        (fe-mul (+ +c-acc1+ 40) +c-g+ +c-h+)
        (fe-mul (+ +c-acc1+ 80) +c-f+ +c-g+)
        (fe-mul (+ +c-acc1+ 120) +c-e+ +c-h+)
        ;; acc0 <- acc1
        (dotimes (k 20)
          (inst mov rax-tmp (ea (+ +c-acc1+ (* 8 k)) p-scr))
          (inst mov :qword (ea (+ +c-acc0+ (* 8 k)) p-scr) rax-tmp))
        (emit-label skip-label)
        (inst inc jj)
        (inst cmp jj 32)
        (inst jmp :nz loop-label)
        ;; ---- epilogue: copy acc0 to the result slot ----
        (dotimes (k 20)
          (inst mov rax-tmp (ea (+ +c-acc0+ (* 8 k)) p-scr))
          (inst mov :qword (ea (+ +c-result+ (* 8 k)) p-scr) rax-tmp))))))

#+(and x86-64 ironclad-unsafe-assembly)
(define-vop (ed25519-inv-asm)
  (:translate ironclad-unsafe::ed25519-inv-asm)
  (:policy :fast-safe)
  (:args (scratch :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-64)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdi-offset) p-scr)
  (:temporary (:sc unsigned-reg :offset sb-vm::r8-offset) jj)
  (:temporary (:sc unsigned-reg :offset sb-vm::r10-offset) tmp1)
  (:temporary (:sc unsigned-reg :offset sb-vm::r11-offset) tmp2)
  (:temporary (:sc unsigned-reg :offset sb-vm::rax-offset) rax-tmp)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdx-offset) rdx-tmp)
  (:generator 300
    (let ((data-offset (- (* n-word-bytes vector-data-offset)
                           other-pointer-lowtag)))
      (ed25519-with-fe-ops (p-scr tmp1 tmp2 rax-tmp rdx-tmp
                                  +c-mulacc+ +c-hacc+ +c-c19+)
        (labels ((sq (r a) (fe-mul r a a))
                 (sq-n (r a n)
                   ;; R := A^(2^N), N > 0, with the repeated squarings
                   ;; emitted as a counted loop to keep the code small.
                   (fe-mul r a a)
                   (when (> n 1)
                     (let ((top (gen-label)))
                       (inst mov jj (1- n))
                       (emit-label top)
                       (fe-mul r r r)
                       (inst dec jj)
                       (inst jmp :nz top)))))
          (let ((z +c-x2+) (out +c-result+)
                (t0 +c-y2+) (t1 +c-z2+) (t2 +c-t2+) (t3 +c-ymx1+))
            (inst lea p-scr (ea data-offset scratch))
            (inst mov :qword (ea +c-c19+ p-scr) 19)
            (sq t0 z)                 ; z^2
            (sq-n t1 t0 2)            ; z^8
            (fe-mul t1 z t1)          ; z^9
            (fe-mul t0 t0 t1)         ; z^11
            (sq t2 t0)                ; z^22
            (fe-mul t1 t1 t2)         ; z^(2^5-1)
            (sq-n t2 t1 5)
            (fe-mul t1 t2 t1)         ; z^(2^10-1)
            (sq-n t2 t1 10)
            (fe-mul t2 t2 t1)         ; z^(2^20-1)
            (sq-n t3 t2 20)
            (fe-mul t2 t3 t2)         ; z^(2^40-1)
            (sq-n t2 t2 10)
            (fe-mul t1 t2 t1)         ; z^(2^50-1)
            (sq-n t2 t1 50)
            (fe-mul t2 t2 t1)         ; z^(2^100-1)
            (sq-n t3 t2 100)
            (fe-mul t2 t3 t2)         ; z^(2^200-1)
            (sq-n t2 t2 50)
            (fe-mul t1 t2 t1)         ; z^(2^250-1)
            (sq-n t1 t1 5)
            (fe-mul out t1 t0)))))))  ; z^(2^255-21)

;;; Variable-base double-and-add for arbitrary points, used by verify.
;;;
;;; Scratch layout, in bytes:
;;;
;;;     0     one 64-bit word per scalar bit, most significant first
;;;     2048  P (X,Y,Z,T)
;;;     2208  accumulator (X,Y,Z,T)
;;;     2368  zero, 2*d, and the field-element temporaries
;;;     2808  multiply working area

#+(and x86-64 ironclad-unsafe-assembly)
(progn
  (defconstant +g-scalar+  0)     ; 256 words
  (defconstant +g-p+       2048)
  (defconstant +g-acc+     2208)
  (defconstant +g-zero+    2368)
  (defconstant +g-twod+    2408)
  (defconstant +g-tmp1+    2448)
  (defconstant +g-a+       2488)
  (defconstant +g-b+       2528)
  (defconstant +g-c+       2568)
  (defconstant +g-d+       2608)
  (defconstant +g-e+       2648)
  (defconstant +g-f+       2688)
  (defconstant +g-g+       2728)
  (defconstant +g-h+       2768)
  (defconstant +g-mulacc+  2808)  ; nine 128-bit columns
  (defconstant +g-hacc+    2952)  ; five 128-bit accumulators
  (defconstant +g-c19+     3032)  ; the constant 19
  (defconstant +g-scratch-bytes+ 3040))

#+(and x86-64 ironclad-unsafe-assembly)
(define-vop (ed25519-gen-mult-asm)
  (:translate ironclad-unsafe::ed25519-gen-mult-asm)
  (:policy :fast-safe)
  (:args (point :scs (descriptor-reg))
         (scratch :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-64
              simple-array-unsigned-byte-64)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdi-offset) p-scr)
  (:temporary (:sc unsigned-reg :offset sb-vm::rsi-offset) p-point)
  (:temporary (:sc unsigned-reg :offset sb-vm::r8-offset) jj)
  (:temporary (:sc unsigned-reg :offset sb-vm::r10-offset) tmp1)
  (:temporary (:sc unsigned-reg :offset sb-vm::r11-offset) tmp2)
  (:temporary (:sc unsigned-reg :offset sb-vm::rax-offset) rax-tmp)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdx-offset) rdx-tmp)
  (:generator 1500
    (let ((data-offset (- (* n-word-bytes vector-data-offset)
                           other-pointer-lowtag))
          (main-top (gen-label))
          (skip-label (gen-label)))
      (ed25519-with-fe-ops (p-scr tmp1 tmp2 rax-tmp rdx-tmp
                                  +g-mulacc+ +g-hacc+ +g-c19+)
        (labels ((point-double (dst src)
                   ;; dbl-2008-hwcd with a = -1.
                   (let ((x src) (y (+ src 40)) (z (+ src 80)))
                     (fe-mul +g-a+ x x)                 ; A = X^2
                     (fe-mul +g-b+ y y)                 ; B = Y^2
                     (fe-mul +g-c+ z z)                 ; C = Z^2
                     (fe-add +g-c+ +g-c+ +g-c+)         ; C = 2Z^2
                     (fe-sub +g-d+ +g-zero+ +g-a+)      ; D = -A
                     (fe-add +g-tmp1+ x y)              ; X+Y
                     (fe-mul +g-e+ +g-tmp1+ +g-tmp1+)   ; (X+Y)^2
                     (fe-sub +g-e+ +g-e+ +g-a+)
                     (fe-sub +g-e+ +g-e+ +g-b+)
                     (fe-add +g-g+ +g-d+ +g-b+)         ; G = D+B
                     (fe-sub +g-f+ +g-g+ +g-c+)         ; F = G-C
                     (fe-sub +g-h+ +g-d+ +g-b+)         ; H = D-B
                     (fe-mul (+ dst 0) +g-e+ +g-f+)
                     (fe-mul (+ dst 40) +g-g+ +g-h+)
                     (fe-mul (+ dst 80) +g-f+ +g-g+)
                     (fe-mul (+ dst 120) +g-e+ +g-h+)))
                 (point-add (dst p q)
                   ;; add-2008-hwcd-3 with k = 2d.
                   (fe-sub +g-a+ (+ p 40) (+ p 0))     ; Y1-X1
                   (fe-add +g-b+ (+ p 40) (+ p 0))     ; Y1+X1
                   (fe-sub +g-tmp1+ (+ q 40) (+ q 0))  ; Y2-X2
                   (fe-add +g-c+ (+ q 40) (+ q 0))     ; Y2+X2
                   (fe-mul +g-a+ +g-a+ +g-tmp1+)       ; A
                   (fe-mul +g-b+ +g-b+ +g-c+)          ; B
                   (fe-mul +g-c+ (+ p 120) (+ q 120))  ; T1*T2
                   (fe-mul +g-c+ +g-c+ +g-twod+)       ; C = 2d*T1*T2
                   (fe-mul +g-d+ (+ p 80) (+ q 80))    ; Z1*Z2
                   (fe-add +g-d+ +g-d+ +g-d+)          ; D = 2Z1Z2
                   (fe-sub +g-e+ +g-b+ +g-a+)          ; E = B-A
                   (fe-sub +g-f+ +g-d+ +g-c+)          ; F = D-C
                   (fe-add +g-g+ +g-d+ +g-c+)          ; G = D+C
                   (fe-add +g-h+ +g-b+ +g-a+)          ; H = B+A
                   (fe-mul (+ dst 0) +g-e+ +g-f+)
                   (fe-mul (+ dst 40) +g-g+ +g-h+)
                   (fe-mul (+ dst 80) +g-f+ +g-g+)
                   (fe-mul (+ dst 120) +g-e+ +g-h+)))
          (inst lea p-scr (ea data-offset scratch))
          (inst lea p-point (ea data-offset point))
          ;; P := the input point (already radix-2^51)
          (dotimes (k 20)
            (inst mov rax-tmp (ea (* 8 k) p-point))
            (inst mov :qword (ea (+ +g-p+ (* 8 k)) p-scr) rax-tmp))
          (inst xor rax-tmp rax-tmp)
          (dotimes (k 5)
            (inst mov :qword (ea (+ +g-zero+ (* 8 k)) p-scr) rax-tmp))
          (inst mov :qword (ea +g-c19+ p-scr) 19)
          ;; acc := identity (0, 1, 1, 0)
          (dotimes (k 20)
            (inst mov :qword (ea (+ +g-acc+ (* 8 k)) p-scr) rax-tmp))
          (inst mov rax-tmp 1)
          (inst mov :qword (ea (+ +g-acc+ 40) p-scr) rax-tmp)
          (inst mov :qword (ea (+ +g-acc+ 80) p-scr) rax-tmp)
          ;; left-to-right double-and-add over 256 bits
          (inst xor jj jj)
          (emit-label main-top)
          (point-double +g-acc+ +g-acc+)
          (inst movzx '(:byte :dword) tmp1 (ea +g-scalar+ p-scr jj 8))
          (inst test tmp1 tmp1)
          (inst jmp :z skip-label)
          (point-add +g-acc+ +g-acc+ +g-p+)
          (emit-label skip-label)
          (inst inc jj)
          (inst cmp jj 256)
          (inst jmp :nz main-top))))))

;;; z^(2^252-3), the exponent needed to decompress an ed25519 point.
;;; Same scratch layout and field routines as the inversion above.

#+(and x86-64 ironclad-unsafe-assembly)
(define-vop (ed25519-pow22523-asm)
  (:translate ironclad-unsafe::ed25519-pow22523-asm)
  (:policy :fast-safe)
  (:args (scratch :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-64)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdi-offset) p-scr)
  (:temporary (:sc unsigned-reg :offset sb-vm::r8-offset) jj)
  (:temporary (:sc unsigned-reg :offset sb-vm::r10-offset) tmp1)
  (:temporary (:sc unsigned-reg :offset sb-vm::r11-offset) tmp2)
  (:temporary (:sc unsigned-reg :offset sb-vm::rax-offset) rax-tmp)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdx-offset) rdx-tmp)
  (:generator 300
    (let ((data-offset (- (* n-word-bytes vector-data-offset)
                           other-pointer-lowtag)))
      (ed25519-with-fe-ops (p-scr tmp1 tmp2 rax-tmp rdx-tmp
                                  +c-mulacc+ +c-hacc+ +c-c19+)
        (labels ((sq (r a) (fe-mul r a a))
                 (sq-n (r a n)
                   (fe-mul r a a)
                   (when (> n 1)
                     (let ((top (gen-label)))
                       (inst mov jj (1- n))
                       (emit-label top)
                       (fe-mul r r r)
                       (inst dec jj)
                       (inst jmp :nz top)))))
          (let ((z +c-x2+) (out +c-result+)
                (t0 +c-y2+) (t1 +c-z2+) (t2 +c-t2+) (t3 +c-ymx1+))
            (inst lea p-scr (ea data-offset scratch))
            (inst mov :qword (ea +c-c19+ p-scr) 19)
            (sq t0 z)
            (sq t1 t0)
            (sq t1 t1)
            (fe-mul t1 z t1)
            (fe-mul t0 t0 t1)
            (sq t0 t0)
            (fe-mul t0 t1 t0)        ; z^(2^5-1)
            (sq-n t1 t0 5)
            (fe-mul t0 t1 t0)        ; z^(2^10-1)
            (sq-n t1 t0 10)
            (fe-mul t1 t1 t0)        ; z^(2^20-1)
            (sq-n t2 t1 20)
            (fe-mul t1 t2 t1)        ; z^(2^40-1)
            (sq-n t1 t1 10)
            (fe-mul t0 t1 t0)        ; z^(2^50-1)
            (sq-n t1 t0 50)
            (fe-mul t1 t1 t0)        ; z^(2^100-1)
            (sq-n t2 t1 100)
            (fe-mul t1 t2 t1)        ; z^(2^200-1)
            (sq-n t1 t1 50)
            (fe-mul t0 t1 t0)        ; z^(2^250-1)
            (sq t0 t0)
            (sq t0 t0)
            (fe-mul out t0 z)))))))  ; z^(2^252-3)

;;; X25519 Montgomery ladder (RFC 7748, section 5) in one VOP.
;;;
;;; The Lisp ladder allocated eighteen field elements per step and ran
;;; every multiply through the 8 x 32-bit limb layer, so X25519 was an
;;; order of magnitude behind OpenSSL even though the same field drives
;;; the fast ed25519 code.  This VOP runs the whole 255-step ladder on
;;; radix-2^51 limbs with the field routines above, and swaps the two
;;; working points with an xor mask instead of a branch, so the
;;; instruction and memory trace do not depend on the scalar bits.
;;;
;;; Scratch layout, in bytes:
;;;
;;;     0     one 64-bit word per scalar bit, bit 254 first (255 words)
;;;     2048  x1 (the input u-coordinate)
;;;     2088  x2, 2128 z2   (contiguous, swapped together)
;;;     2168  x3, 2208 z3   (contiguous, swapped together)
;;;     2248  a24 = 121665
;;;     2288  field temporaries A AA B BB E C D DA CB T
;;;     2688  multiply working area, the constant 19, the swap state

#+(and x86-64 ironclad-unsafe-assembly)
(progn
  (defconstant +x-x1+     2048)
  (defconstant +x-x2+     2088)
  (defconstant +x-z2+     2128)
  (defconstant +x-x3+     2168)
  (defconstant +x-z3+     2208)
  (defconstant +x-a24+    2248)
  (defconstant +x-a+      2288)
  (defconstant +x-aa+     2328)
  (defconstant +x-b+      2368)
  (defconstant +x-bb+     2408)
  (defconstant +x-e+      2448)
  (defconstant +x-c+      2488)
  (defconstant +x-d+      2528)
  (defconstant +x-da+     2568)
  (defconstant +x-cb+     2608)
  (defconstant +x-t+      2648)
  (defconstant +x-mulacc+ 2688)   ; nine 128-bit columns
  (defconstant +x-hacc+   2832)   ; five 128-bit accumulators
  (defconstant +x-c19+    2912)
  (defconstant +x-swap+   2920)
  (defconstant +x-scratch-words+ 366))

#+(and x86-64 ironclad-unsafe-assembly)
(define-vop (curve25519-ladder-asm)
  (:translate ironclad-unsafe::curve25519-ladder-asm)
  (:policy :fast-safe)
  (:args (scratch :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-64)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdi-offset) p-scr)
  (:temporary (:sc unsigned-reg :offset sb-vm::rsi-offset) mask)
  (:temporary (:sc unsigned-reg :offset sb-vm::r8-offset) jj)
  (:temporary (:sc unsigned-reg :offset sb-vm::r9-offset) tmp3)
  (:temporary (:sc unsigned-reg :offset sb-vm::r10-offset) tmp1)
  (:temporary (:sc unsigned-reg :offset sb-vm::r11-offset) tmp2)
  (:temporary (:sc unsigned-reg :offset sb-vm::rax-offset) rax-tmp)
  (:temporary (:sc unsigned-reg :offset sb-vm::rdx-offset) rdx-tmp)
  (:generator 2000
    (let ((data-offset (- (* n-word-bytes vector-data-offset)
                           other-pointer-lowtag))
          (top (gen-label)))
      (ed25519-with-fe-ops (p-scr tmp1 tmp2 rax-tmp rdx-tmp
                                  +x-mulacc+ +x-hacc+ +x-c19+)
        (labels ((cswap ()
                   ;; (x2,z2) <-> (x3,z3) when MASK is all ones.
                   (dotimes (k 10)
                     (inst mov tmp1 (ea (+ +x-x2+ (* 8 k)) p-scr))
                     (inst mov tmp2 (ea (+ +x-x3+ (* 8 k)) p-scr))
                     (inst mov tmp3 tmp1)
                     (inst xor tmp3 tmp2)
                     (inst and tmp3 mask)
                     (inst xor tmp1 tmp3)
                     (inst xor tmp2 tmp3)
                     (inst mov (ea (+ +x-x2+ (* 8 k)) p-scr) tmp1)
                     (inst mov (ea (+ +x-x3+ (* 8 k)) p-scr) tmp2))))
          (inst lea p-scr (ea data-offset scratch))
          (inst mov :qword (ea +x-c19+ p-scr) 19)
          (inst mov :qword (ea +x-swap+ p-scr) 0)
          (inst xor jj jj)
          (emit-label top)
          ;; swap ^= bit; cswap; swap = bit
          (inst mov mask (ea 0 p-scr jj 8))
          (inst mov tmp3 mask)
          (inst xor mask (ea +x-swap+ p-scr))
          (inst mov (ea +x-swap+ p-scr) tmp3)
          (inst neg mask)
          (cswap)
          ;; One ladder step.
          (fe-add +x-a+ +x-x2+ +x-z2+)        ; A  = x2 + z2
          (fe-mul +x-aa+ +x-a+ +x-a+)         ; AA = A^2
          (fe-sub +x-b+ +x-x2+ +x-z2+)        ; B  = x2 - z2
          (fe-mul +x-bb+ +x-b+ +x-b+)         ; BB = B^2
          (fe-sub +x-e+ +x-aa+ +x-bb+)        ; E  = AA - BB
          (fe-add +x-c+ +x-x3+ +x-z3+)        ; C  = x3 + z3
          (fe-sub +x-d+ +x-x3+ +x-z3+)        ; D  = x3 - z3
          (fe-mul +x-da+ +x-d+ +x-a+)         ; DA = D * A
          (fe-mul +x-cb+ +x-c+ +x-b+)         ; CB = C * B
          (fe-add +x-t+ +x-da+ +x-cb+)
          (fe-mul +x-x3+ +x-t+ +x-t+)         ; x3 = (DA + CB)^2
          (fe-sub +x-t+ +x-da+ +x-cb+)
          (fe-mul +x-t+ +x-t+ +x-t+)
          (fe-mul +x-z3+ +x-x1+ +x-t+)        ; z3 = x1 * (DA - CB)^2
          (fe-mul +x-x2+ +x-aa+ +x-bb+)       ; x2 = AA * BB
          (fe-mul +x-t+ +x-a24+ +x-e+)
          (fe-add +x-t+ +x-aa+ +x-t+)
          (fe-mul +x-z2+ +x-e+ +x-t+)         ; z2 = E * (AA + a24 * E)
          (inst inc jj)
          (inst cmp jj 255)
          (inst jmp :nz top)
          ;; Final conditional swap.
          (inst mov mask (ea +x-swap+ p-scr))
          (inst neg mask)
          (cswap))))))
