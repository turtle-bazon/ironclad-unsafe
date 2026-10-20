;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; secp256r1.lisp -- secp256r1 (a.k.a. NIST P-256) elliptic curve


(in-package :crypto)


;;; class definitions

(defclass secp256r1-public-key ()
  ((y :initarg :y :reader secp256r1-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass secp256r1-private-key ()
  ((x :initarg :x :reader secp256r1-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader secp256r1-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  ;; Internally, a point (x, y) is represented using the Jacobian projective
  ;; coordinates (X, Y, Z), with x = X / Z^2 and y = Y / Z^3.  Coordinates
  ;; are P-256 field elements (8x32-bit limbs); see the fe- layer above.
  (defstruct (secp256r1-point
              (:constructor make-secp256r1-point
                  (&key (x (secp256r1-fe-zero))
                        (y (secp256r1-fe-zero))
                        (z (secp256r1-fe-zero))))
              (:predicate nil))
    (x (secp256r1-fe-zero) :type secp256r1-fe :read-only t)
    (y (secp256r1-fe-zero) :type secp256r1-fe :read-only t)
    (z (secp256r1-fe-zero) :type secp256r1-fe :read-only t)))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun secp256r1-point-from-ints (x y z)
    (make-secp256r1-point :x (secp256r1-fe-from-int x)
                          :y (secp256r1-fe-from-int y)
                          :z (secp256r1-fe-from-int z))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defmethod make-load-form ((p secp256r1-point) &optional env)
    (declare (ignore env))
    `(make-secp256r1-point :x ,(secp256r1-point-x p)
                           :y ,(secp256r1-point-y p)
                           :z ,(secp256r1-point-z p))))

(declaim (inline secp256r1-point-x secp256r1-point-y secp256r1-point-z))


;;; constant and function definitions

(defconstant +secp256r1-bits+ 256)
(defconstant +secp256r1-p+ 115792089210356248762697446949407573530086143415290314195533631308867097853951)
(defconstant +secp256r1-b+ 41058363725152142129326129780047268409114441015993725554835256314039467401291)
(defconstant +secp256r1-l+ 115792089210356248762697446949407573529996955224135760342422259061068512044369)
(defconstant +secp256r1-i+ 28948022302589062190674361737351893382521535853822578548883407827216774463488)

;;; The prime's limbs, little endian.  Keeping them in a vector avoids
;;; extracting them from the bignum constant on every add and subtract.
(defconstant +secp256r1-p-limbs+ (make-array 8 :element-type '(unsigned-byte 32)
                                                    :initial-contents
                                                    '(4294967295 4294967295
                                                      4294967295 0 0 0 1
                                                      4294967295)))

;;; P-256 field arithmetic on 32-bit limbs.
;;;
;;; A field element is (SIMPLE-ARRAY (UNSIGNED-BYTE 32) (8)), little
;;; endian.  All intermediate values fit in 34 bits, so every operation
;;; stays in fixnums on all 64-bit Lisps with no bignum consing.  School
;;; book multiply accumulates with split 32-bit products; reduction is
;;; the Solinas form of the P-256 prime.  An SBCL x86-64 VOP can later
;;; replace SECP256R1-FE-MUL behind the same interface.

(deftype secp256r1-fe () '(simple-array (unsigned-byte 32) (8)))

(declaim (inline secp256r1-fe-zero secp256r1-fe-copy
                 secp256r1-fe-from-int secp256r1-fe-to-int
                 secp256r1-fe-add secp256r1-fe-sub
                 secp256r1-fe-equal secp256r1-fe-is-zero
                 secp256r1-fe-sqr-raw secp256r1-fe-sq secp256r1-fesq))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun secp256r1-fe-zero ()
    (make-array 8 :element-type '(unsigned-byte 32) :initial-element 0)))

(defun secp256r1-fe-copy (a)
  (declare (type secp256r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (secp256r1-fe-zero)))
    (dotimes (i 8 r)
      (setf (aref r i) (aref a i)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun secp256r1-fe-from-int (n)
    (declare (type integer n)
             (optimize (speed 3) (safety 0) (space 0) (debug 0)))
    (let ((r (secp256r1-fe-zero)))
      (dotimes (i 8 r)
        (setf (aref r i) (ldb (byte 32 (* i 32)) n))))))

(defun secp256r1-fe-to-int (a)
  (declare (type secp256r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((n 0))
    (declare (type integer n))
    (dotimes (i 8 n)
      (setf n (dpb (aref a i) (byte 32 (* i 32)) n)))))

(defun secp256r1-fe-add (r a b)
  "R := (A + B) mod P, all reduced residues."
  (declare (type secp256r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((carry 0))
    (declare (type (unsigned-byte 32) carry))
    (dotimes (i 8)
      (let ((s (+ (aref a i) (aref b i) carry)))
        (setf (aref r i) (ldb (byte 32 0) s)
              carry (ash s -32))))
    ;; Subtract P when R >= P.  CARRY = 1 implies R >= 2^256 > P.
    (when (or (plusp carry)
              (loop for i from 7 downto 0
                    for limb = (aref r i)
                    for plimb = (aref +secp256r1-p-limbs+ i)
                    when (/= limb plimb) return (> limb plimb)
                    finally (return t)))
      (let ((borrow 0))
        (declare (type (unsigned-byte 32) borrow))
        (dotimes (i 8)
          (let ((d (- (aref r i)
                      (aref +secp256r1-p-limbs+ i)
                      borrow)))
            (setf (aref r i) (ldb (byte 32 0) d)
                  borrow (logand (ash d -32) 1)))))))
  r)

(defun secp256r1-fe-sub (r a b)
  "R := (A - B) mod P, all reduced residues."
  (declare (type secp256r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((borrow 0))
    (declare (type (unsigned-byte 32) borrow))
    (dotimes (i 8)
      (let ((d (- (aref a i) (aref b i) borrow)))
        (setf (aref r i) (ldb (byte 32 0) d)
              borrow (logand (ash d -32) 1))))
    (when (plusp borrow)
      (let ((carry 0))
        (declare (type (unsigned-byte 32) carry))
        (dotimes (i 8)
          (let ((s (+ (aref r i)
                      (aref +secp256r1-p-limbs+ i)
                      carry)))
            (setf (aref r i) (ldb (byte 32 0) s)
                  carry (ash s -32)))))))
  r)

(defun secp256r1-fe-mul-raw (r a b)
  "R := A * B as 16 limbs, no reduction.  R holds (UNSIGNED-BYTE 64)."
  (declare (type secp256r1-fe a b)
           (type (simple-array (unsigned-byte 64) (16)) r)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-assembly)
  (secp256r1-fe-mul-raw-asm r a b)
  #-(and sbcl x86-64 ironclad-assembly)
  (progn
    (dotimes (k 16)
      (setf (aref r k) 0))
    (dotimes (i 8)
      (let ((carry 0))
        (declare (type (unsigned-byte 32) carry))
        (dotimes (j 8)
          ;; S = R[I+J] + A[I]*B[J] + CARRY stays below 2^34: the stored
          ;; word and the carry are each under 2^33 by construction.
          (let* ((prod (* (aref a i) (aref b j)))
                 (plo (ldb (byte 32 0) prod))
                 (phi (ash prod -32))
                 (s (+ (aref r (+ i j)) plo carry)))
            (setf (aref r (+ i j)) (ldb (byte 32 0) s)
                  carry (+ (ash s -32) phi))))
        (setf (aref r (+ i 8)) carry))))
  r)

(defun secp256r1-fe-normalize16 (c)
  "Propagate carries so C holds 16 canonical 32-bit words."
  (declare (type (simple-array (unsigned-byte 64) (16)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (k 15)
    (let ((carry (ash (aref c k) -32)))
      (setf (aref c k) (ldb (byte 32 0) (aref c k))
            (aref c (1+ k)) (+ (aref c (1+ k)) carry))))
  (setf (aref c 15) (ldb (byte 32 0) (aref c 15)))
  c)

(declaim (inline secp256r1--adc secp256r1--sbb secp256r1--fe-ge-p))

(defun secp256r1--adc (a b c)
  "Add three small words; return (VALUES word carry).
All arguments are at most 32-bit field limbs plus a small carry, so
the sum stays under 2^34 and every operation remains in fixnums."
  (declare (type (unsigned-byte 34) a b c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((s (+ a b c)))
    (values (ldb (byte 32 0) s) (ash s -32))))

(defun secp256r1--sbb (a b borrow)
  "Subtract with borrow; return (VALUES word borrow-out).
A and B are 32-bit field limbs, BORROW is 0 or 1, so the difference
stays within fixnum range."
  (declare (type (unsigned-byte 32) a b)
           (type (unsigned-byte 32) borrow)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((d (- a b borrow)))
    (values (ldb (byte 32 0) d) (if (minusp d) 1 0))))

(defun secp256r1--fe-ge-p (a)
  (declare (type secp256r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (loop for i from 7 downto 0
        for limb = (aref a i)
        for plimb = (aref +secp256r1-p-limbs+ i)
        when (/= limb plimb) return (> limb plimb)
        finally (return t)))

(defun secp256r1-fe-mul (r a b)
  "R := (A * B) mod P for reduced residues in limb form."
  (declare (type secp256r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((c (make-array 16 :element-type '(unsigned-byte 64)
                       :initial-element 0)))
    ;; NB: the product must stay in the heap; the assembly VOP assumes
    ;; the usual heap layout of a simple vector.
    (secp256r1-fe-mul-raw c a b)
    #+(and sbcl x86-64 ironclad-assembly)
    (let ((q (secp256r1-fe-zero)))
      (secp256r1-fe-reduce-asm r q c))
    #-(and sbcl x86-64 ironclad-assembly)
    (progn
      (secp256r1-fe-normalize16 c)
      (secp256r1-fe-solinas r c)))
  r)

(defun secp256r1-fe-solinas (r c)
  "R := C mod P via the P-256 Solinas reduction.
C holds 16 possibly non-canonical (UNSIGNED-BYTE 64) limbs; callers
normalize first unless the words are already canonical."
  (declare (type secp256r1-fe r)
           (type (simple-array (unsigned-byte 64) (16)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((p (secp256r1-fe-zero))
        (n (secp256r1-fe-zero))
        (hp 0)
        (hn 0))
    (declare (type (unsigned-byte 64) hp hn)
             (dynamic-extent p n))
    ;; P := S1 + 2*S2 + 2*S3 + S4 + S5, N := S6 + S7 + S8 + S9.
    ;; Each SI is under 2^256, so P < 7*2^256 and N < 4*2^256.
    ;; Words below are (C15 .. C0), high word to low word.
    (macrolet ((sw (i) `(aref c ,i)))
      ;; S1 = (C7 .. C0).
      (dotimes (i 8)
        (setf (aref p i) (sw i)))
      ;; 2*S2, S2 = (C15 C14 C13 C12 C11 0 0 0), low word first.
      (let ((carry 0))
        (dotimes (i 8)
          (let ((w (if (>= i 3) (sw (+ i 8)) 0)))
            (multiple-value-bind (lo c1) (secp256r1--adc w w (aref p i))
              (multiple-value-bind (sum c2) (secp256r1--adc lo 0 carry)
                (setf (aref p i) sum
                      carry (+ c1 c2))))))
        (setf hp (+ hp carry)))
      ;; 2*S3, S3 = (0 C15 C14 C13 C12 0 0 0), low word first.
      (let ((carry 0))
        (dotimes (i 8)
          (let ((w (if (and (>= i 3) (<= i 6)) (sw (+ i 9)) 0)))
            (multiple-value-bind (lo c1) (secp256r1--adc w w (aref p i))
              (multiple-value-bind (sum c2) (secp256r1--adc lo 0 carry)
                (setf (aref p i) sum
                      carry (+ c1 c2))))))
        (setf hp (+ hp carry)))
      ;; S4 = (C15 C14 0 0 0 C10 C9 C8), low word first.
      (let ((carry 0))
        (dotimes (i 8)
          (let ((w (cond ((>= i 6) (sw (+ i 8)))
                         ((<= i 2) (sw (+ i 8)))
                         (t 0))))
            (multiple-value-bind (sum c1)
                (secp256r1--adc w (aref p i) carry)
              (setf (aref p i) sum
                    carry c1))))
        (setf hp (+ hp carry)))
      ;; S5 = (C8 C13 C15 C14 C13 C11 C10 C9), low word first.
      (let ((carry 0)
            (s5 #(9 10 11 13 14 15 13 8)))
        (dotimes (i 8)
          (multiple-value-bind (sum c1)
              (secp256r1--adc (sw (aref s5 i)) (aref p i) carry)
            (setf (aref p i) sum
                  carry c1)))
        (setf hp (+ hp carry)))
      ;; N = S6 + S7 + S8 + S9, low word first.
      ;; S6 = (C10 C8 0 0 0 C13 C12 C11).
      (let ((s6 #(11 12 13 0 0 0 8 10)))
        (dotimes (i 8)
          (setf (aref n i) (if (zerop (aref s6 i)) 0 (sw (aref s6 i))))))
      ;; S7 = (C11 C9 0 0 C15 C14 C13 C12).
      (let ((s7 #(12 13 14 15 0 0 9 11))
            (carry 0))
        (dotimes (i 8)
          (multiple-value-bind (sum c1)
              (secp256r1--adc (aref n i) (if (zerop (aref s7 i)) 0 (sw (aref s7 i))) carry)
            (setf (aref n i) sum
                  carry c1)))
        (setf hn (+ hn carry)))
      ;; S8 = (C12 0 C10 C9 C8 C15 C14 C13).
      (let ((s8 #(13 14 15 8 9 10 0 12))
            (carry 0))
        (dotimes (i 8)
          (multiple-value-bind (sum c1)
              (secp256r1--adc (aref n i) (if (zerop (aref s8 i)) 0 (sw (aref s8 i))) carry)
            (setf (aref n i) sum
                  carry c1)))
        (setf hn (+ hn carry)))
      ;; S9 = (C13 0 C11 C10 C9 0 C15 C14).
      (let ((s9 #(14 15 0 9 10 11 0 13))
            (carry 0))
        (dotimes (i 8)
          (multiple-value-bind (sum c1)
              (secp256r1--adc (aref n i) (if (zerop (aref s9 i)) 0 (sw (aref s9 i))) carry)
            (setf (aref n i) sum
                  carry c1)))
        (setf hn (+ hn carry)))
      ;; T := P + 8*P256 - N into R.  P + 8p >= 8p > 4*2^256 > N,
      ;; so no borrow runs out of the top word.
      (let ((carry 0)
            (borrow 0))
        (dotimes (i 8)
          (let ((pw (* 8 (aref +secp256r1-p-limbs+ i))))
            (multiple-value-bind (summed c1)
                (secp256r1--adc (aref p i) pw carry)
              (multiple-value-bind (word b1)
                  (secp256r1--sbb summed (aref n i) borrow)
                (setf (aref r i) word
                      carry c1
                      borrow b1)))))
        ;; H counts 2^256 units: P's overflow plus the carry out of the
        ;; P + 8p addition (which already contains FLOOR(8*P/2^256)),
        ;; minus the borrow run out of the low-word subtraction and
        ;; minus N's overflow.  H is non-negative because the folded
        ;; value T = P8 + 8p - N8 alone already exceeds 2^256.
        (let ((h (+ hp carry)))
          (declare (type (unsigned-byte 64) h))
          (setf h (- h borrow hn))
          ;; Fold H: H * 2^256 = H * (2^224 - 2^192 - 2^96 + 1).
          (let ((carry 0))
            (dotimes (i 8)
              (let ((s (+ (aref r i) carry
                          (if (zerop i) h 0)
                          (if (= i 7) h 0)
                          (if (= i 3) (- h) 0)
                          (if (= i 6) (- h) 0))))
                (let ((q (floor s #.(ash 1 32))))
                  (setf (aref r i) (- s (* q #.(ash 1 32)))
                        carry q)))))
          ;; The folded value is under 2*P: one conditional subtract.
          (when (secp256r1--fe-ge-p r)
            (let ((borrow 0))
              (dotimes (i 8)
                (multiple-value-bind (word b1)
                    (secp256r1--sbb (aref r i)
                                    (aref +secp256r1-p-limbs+ i)
                                    borrow)
                  (setf (aref r i) word
                        borrow b1)))))))))
    r)

(defun secp256r1-fe-equal (a b)
  "T when limb vectors A and B hold the same value."
  (declare (type secp256r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 8 t)
    (unless (= (aref a i) (aref b i))
      (return nil))))

(defun secp256r1-fe-is-zero (a)
  "T when the field element A is zero."
  (declare (type secp256r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 8 t)
    (unless (zerop (aref a i))
      (return nil))))

(declaim (inline secp256r1-femul secp256r1-feadd secp256r1-fesub
                 secp256r1-femul! secp256r1-feadd! secp256r1-fesub!
                 secp256r1-fesq!))

(defun secp256r1-femul (a b)
  "Product of field elements A and B as a fresh vector."
  (declare (type secp256r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (secp256r1-fe-zero)))
    (secp256r1-fe-mul r a b)
    r))

(defun secp256r1-feadd (a b)
  "Sum of field elements A and B as a fresh vector."
  (declare (type secp256r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (secp256r1-fe-zero)))
    (secp256r1-fe-add r a b)
    r))

(defun secp256r1-fesub (a b)
  "Difference of field elements A and B as a fresh vector."
  (declare (type secp256r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (secp256r1-fe-zero)))
    (secp256r1-fe-sub r a b)
    r))

(defun secp256r1-femul! (r a b)
  "Product of field elements A and B into destination R (no consing)."
  (declare (type secp256r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp256r1-fe-mul r a b)
  r)

(defun secp256r1-feadd! (r a b)
  "Sum of field elements A and B into destination R (no consing)."
  (declare (type secp256r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp256r1-fe-add r a b)
  r)

(defun secp256r1-fesub! (r a b)
  "Difference of field elements A and B into destination R (no consing)."
  (declare (type secp256r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp256r1-fe-sub r a b)
  r)

(defun secp256r1-fesq! (r a)
  "Square of field element A into destination R (no consing)."
  (declare (type secp256r1-fe r a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp256r1-fe-sq r a)
  r)

(defun secp256r1-fe-sqr-raw (r a)
  "R := A * A as 16 limbs, no reduction."
  (declare (type secp256r1-fe a)
           (type (simple-array (unsigned-byte 64) (16)) r)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-assembly)
  (secp256r1-fe-sqr-raw-asm r a)
  #-(and sbcl x86-64 ironclad-assembly)
  (progn
    (dotimes (k 16)
      (setf (aref r k) 0))
    (secp256r1-fe-mul-raw r a a))
  r)

(defun secp256r1-fe-sq (r a)
  "R := A^2 mod P."
  (declare (type secp256r1-fe r a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((c (make-array 16 :element-type '(unsigned-byte 64)
                       :initial-element 0)))
    ;; NB: the product must stay in the heap; see SECP256R1-FE-MUL.
    (secp256r1-fe-sqr-raw c a)
    #+(and sbcl x86-64 ironclad-assembly)
    (let ((q (secp256r1-fe-zero)))
      (secp256r1-fe-reduce-asm r q c))
    #-(and sbcl x86-64 ironclad-assembly)
    (progn
      (secp256r1-fe-normalize16 c)
      (secp256r1-fe-solinas r c)))
  r)

(defun secp256r1-fesq (a)
  "Square of field element A as a fresh vector."
  (declare (type secp256r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (secp256r1-fe-zero)))
    (secp256r1-fe-sq r a)
    r))

(defconst +secp256r1-g+
  (secp256r1-point-from-ints
   48439561293906451759052585252797914202762949526041747995844080717082404635286
   36134250956749795798585127919587881956611106672985015071877198253568414405109
   1))
(defconst +secp256r1-point-at-infinity+
  (secp256r1-point-from-ints 1 1 0))


(defconstant +secp256r1-p-minus-2+ (- +secp256r1-p+ 2))

(declaim (inline secp256r1-fe-inv))
(defun secp256r1-fe-inv (a)
  "Field element inverse via Fermat's little theorem: A^(P-2) mod P.
Uses square-and-multiply over the field element representation,
avoiding bignum arithmetic entirely.  Not constant-time; callers that
need side-channel resistance should blind the input first (see
MODULAR-INVERSE-WITH-BLINDING)."
  (declare (type secp256r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((result (secp256r1-fe-from-int 1))
        (base a))
    (declare (type secp256r1-fe result base))
    (loop for i from (1- (integer-length +secp256r1-p-minus-2+)) downto 0
          do (secp256r1-fe-sq result result)
             (when (logbitp i +secp256r1-p-minus-2+)
               (secp256r1-fe-mul result result base)))
    result))

(defmethod ec-scalar-inv ((kind (eql :secp256r1)) n)
  ;; Fermat inversion over field elements is faster than bignum binary
  ;; GCD now that field multiply is native-compiled.  Callers only invert
  ;; nonzero field elements (z = 0 is rejected earlier).
  (declare (type integer n))
  (if (zerop n)
      0
      (secp256r1-fe-to-int (secp256r1-fe-inv (secp256r1-fe-from-int n)))))

(defmethod ec-point-equal ((p secp256r1-point) (q secp256r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (secp256r1-point-x p))
        (y1 (secp256r1-point-y p))
        (z1 (secp256r1-point-z p))
        (x2 (secp256r1-point-x q))
        (y2 (secp256r1-point-y q))
        (z2 (secp256r1-point-z q)))
    (declare (type secp256r1-fe x1 y1 z1 x2 y2 z2))
    (let ((z1z1 (secp256r1-fesq z1))
          (z2z2 (secp256r1-fesq z2)))
      (and (secp256r1-fe-is-zero
            (secp256r1-fesub (secp256r1-femul x1 z2z2)
                             (secp256r1-femul x2 z1z1)))
           (secp256r1-fe-is-zero
            (secp256r1-fesub (secp256r1-femul (secp256r1-femul y1 z2) z2z2)
                             (secp256r1-femul (secp256r1-femul y2 z1) z1z1)))))))

(defmethod ec-double ((p secp256r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((dst (make-secp256r1-point))
        (s (secp256r1-make-scratch)))
    (secp256r1-double! dst p s)
    dst))

(defmethod ec-add ((p secp256r1-point) (q secp256r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((dst (make-secp256r1-point))
        (s (secp256r1-make-scratch)))
    (secp256r1-add! dst p q s)
    dst))

;;; Fixed-base comb for the generator point.
;;;
;;; SIGN-MESSAGE and key generation always multiply G by a secret scalar.
;;; A 4-bit window needs 64 additions and 256 doublings instead of the
;;; ladder's 256 of each.  The window value is secret, so table lookup
;;; scans all 16 entries instead of indexing directly; the iteration
;;; count is fixed either way.
;;;
;;; The table is built lazily on first use: building it at file load
;;; time would call EC-ADD while this file is still being compiled,
;;; when its methods are not available yet.

(defvar *secp256r1-base-table* nil
  "Positional table T[J][V] = V * 256^J * G, built on first use.")

(declaim (ftype (function () simple-vector) secp256r1-build-base-table))


(defun secp256r1-mixed-add! (dst p q s)
  "DST := P + Q where Q (y coordinate finite, z == 1) is affine,
reusing scratch pool S. DST must differ from P."
  (declare (type secp256r1-point dst p q)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (secp256r1-point-x p))
        (y1 (secp256r1-point-y p))
        (z1 (secp256r1-point-z p))
        (x2 (secp256r1-point-x q))
        (y2 (secp256r1-point-y q))
        (z1z1 (svref s 0))
        (u1 (svref s 1))
        (u2 (svref s 2))
        (t1 (svref s 3))
        (s1 (svref s 4))
        (tt2 (svref s 5))
        (s2 (svref s 6))
        (hh (svref s 7))
        (t3 (svref s 8))
        (t4 (svref s 9))
        (ii (svref s 10))
        (jj (svref s 11))
        (t5 (svref s 12))
        (rr (svref s 13))
        (vv (svref s 14))
        (t6 (svref s 15))
        (t7 (svref s 16))
        (t8 (svref s 17))
        (x3 (svref s 18))
        (t9 (svref s 19))
        (t10 (svref s 20))
        (t11 (svref s 21))
        (t12 (svref s 22))
        (y3 (svref s 23))
        (t14 (svref s 24))
        (z3 (svref s 25)))
    (declare (type secp256r1-fe x1 y1 z1 x2 y2 z1z1 u1 u2 t1 s1 tt2 s2 hh
                               t3 t4 ii jj t5 rr vv t6 t7 t8 x3 t9 t10 t11
                               t12 y3 t14 z3))
    (cond ((secp256r1-fe-is-zero z1)
           (secp256r1-point-copy! dst q))
          ((secp256r1-fe-is-zero (secp256r1-point-z q))
           (secp256r1-point-copy! dst p))
          (t
           ;; Q is affine; z2 = 1.
           (secp256r1-fe-mul z1z1 z1 z1)
           (secp256r1-fe-copy! u1 x1)
           (secp256r1-fe-mul u2 x2 z1z1)
           (secp256r1-fe-copy! s1 y1)
           (secp256r1-fe-mul tt2 y2 z1)
           (secp256r1-fe-mul s2 tt2 z1z1)
           (if (secp256r1-fe-equal u1 u2)
               (if (secp256r1-fe-equal s1 s2)
                   (secp256r1-double! dst p s)
                   (secp256r1-point-set-inf! dst))
               (progn
                 (secp256r1-fe-sub hh u2 u1)
                 (secp256r1-fe-mul t3 hh hh)
                 (secp256r1-fe-add t4 t3 t3)
                 (secp256r1-fe-add ii t4 t4)
                 (secp256r1-fe-mul jj hh ii)
                 (secp256r1-fe-sub t5 s2 s1)
                 (secp256r1-fe-add rr t5 t5)
                 (secp256r1-fe-mul vv u1 ii)
                 (secp256r1-fe-mul t6 rr rr)
                 (secp256r1-fe-sub t7 t6 jj)
                 (secp256r1-fe-add t8 vv vv)
                 (secp256r1-fe-sub x3 t7 t8)
                 (secp256r1-fe-sub t9 vv x3)
                 (secp256r1-fe-mul t10 rr t9)
                 (secp256r1-fe-mul t11 s1 jj)
                 (secp256r1-fe-add t12 t11 t11)
                 (secp256r1-fe-sub y3 t10 t12)
                 ;; z3 = 2*Z1*H
                 (secp256r1-fe-add t14 z1 z1)
                 (secp256r1-fe-mul z3 t14 hh)
                 (secp256r1-fe-copy! (secp256r1-point-x dst) x3)
                 (secp256r1-fe-copy! (secp256r1-point-y dst) y3)
                 (secp256r1-fe-copy! (secp256r1-point-z dst) z3)
                 dst))))))


(defun secp256r1-ensure-base-table ()
  (or *secp256r1-base-table*
      (setf *secp256r1-base-table* (secp256r1-build-base-table))))

(defmethod ec-scalar-mult ((p secp256r1-point) e)
  ;; Secret scalars use the fixed-schedule ladder, except for the fixed
  ;; base point G (signing nonces, key generation), which uses the
  ;; constant-iteration comb above.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (if (and (eq p +secp256r1-g+) (not (minusp e)))
      (secp256r1-base-mult e)
      (secp256r1-ladder-mult p e)))

(defun secp256r1-ladder-mult (point e)
  "Fixed-schedule Montgomery ladder using destination-passing ops."
  (declare (type secp256r1-point point)
           (type integer e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (when (minusp e)
    (error "negative scalars are not supported by secp256r1-ladder-mult"))
  (if (zerop e)
      +secp256r1-point-at-infinity+
      (let ((r0 (secp256r1-point-from-ints 1 1 0))
            (r1 (secp256r1-point-from-ints 1 1 0))
            (tmp (secp256r1-point-from-ints 1 1 0))
            (tmp2 (secp256r1-point-from-ints 1 1 0))
            (s (secp256r1-make-scratch)))
        (declare (type secp256r1-point r0 r1 tmp tmp2)
                 (type simple-vector s))
        ;; R1 is a copy: the loop writes its result back into R1, and
        ;; POINT may be the shared generator constant.
        (secp256r1-point-copy! r1 point)
        (loop for i from (1- +secp256r1-bits+) downto 0 do
          (if (logbitp i e)
              (progn
                (secp256r1-add! tmp r0 r1 s)
                (secp256r1-double! tmp2 r1 s)
                (secp256r1-point-copy! r0 tmp)
                (secp256r1-point-copy! r1 tmp2))
              (progn
                (secp256r1-add! tmp r0 r1 s)
                (secp256r1-double! tmp2 r0 s)
                (secp256r1-point-copy! r1 tmp)
                (secp256r1-point-copy! r0 tmp2))))
        r0)))

(defmethod ec-point-on-curve-p ((p secp256r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x (secp256r1-point-x p))
        (y (secp256r1-point-y p))
        (z (secp256r1-point-z p))
        (b (secp256r1-fe-from-int +secp256r1-b+)))
    (declare (type secp256r1-fe x y z b))
    (let* ((y2 (secp256r1-fesq y))
           (x2 (secp256r1-fesq x))
           (x3 (secp256r1-femul x2 x))
           (z2 (secp256r1-fesq z))
           (z4 (secp256r1-fesq z2))
           (z6 (secp256r1-femul z4 z2))
           (xz4 (secp256r1-femul x z4))
           (xz4-3 (secp256r1-feadd xz4 (secp256r1-feadd xz4 xz4)))
           (bz6 (secp256r1-femul b z6))
           (a (secp256r1-feadd (secp256r1-fesub x3 xz4-3) bz6)))
      (declare (type secp256r1-fe y2 x3 z2 z4 z6 a))
      (secp256r1-fe-equal y2 a))))

(defmethod ec-make-point ((kind (eql :secp256r1)) &key x y)
  (unless x
    (error 'missing-point-parameter
           :kind 'secp256r1
           :parameter 'x
           :description "coordinate"))
  (unless y
    (error 'missing-point-parameter
           :kind 'secp256r1
           :parameter 'y
           :description "coordinate"))
  (let ((p (make-secp256r1-point :x (secp256r1-fe-from-int x)
                                :y (secp256r1-fe-from-int y)
                                :z (secp256r1-fe-from-int 1))))
    (if (ec-point-on-curve-p p)
        p
        (error 'invalid-curve-point :kind 'secp256r1))))

(defmethod ec-destructure-point ((p secp256r1-point))
  (let ((x (secp256r1-point-x p))
        (y (secp256r1-point-y p))
        (z (secp256r1-point-z p)))
    (declare (type secp256r1-fe x y z))
    (when (secp256r1-fe-is-zero z)
      (error 'ironclad-error
             :format-control "The point at infinity can't be encoded."))
    (let* ((invz (secp256r1-fe-from-int
                  (ec-scalar-inv :secp256r1 (secp256r1-fe-to-int z))))
           (invz2 (secp256r1-fesq invz))
           (invz3 (secp256r1-femul invz2 invz)))
      (list :x (secp256r1-fe-to-int (secp256r1-femul x invz2))
            :y (secp256r1-fe-to-int (secp256r1-femul y invz3))))))

(defmethod ec-encode-scalar ((kind (eql :secp256r1)) n)
  (integer-to-octets n :n-bits +secp256r1-bits+ :big-endian t))

(defmethod ec-decode-scalar ((kind (eql :secp256r1)) octets)
  (octets-to-integer octets :big-endian t))

(defmethod ec-encode-point ((p secp256r1-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x))
         (y (getf coordinates :y)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (vector 4)
                 (ec-encode-scalar :secp256r1 x)
                 (ec-encode-scalar :secp256r1 y))))

(defmethod ec-decode-point ((kind (eql :secp256r1)) octets)
  (case (aref octets 0)
    ((2 3)
     ;; Compressed point
     (if (= (length octets) (1+ (/ +secp256r1-bits+ 8)))
         (let* ((x-bytes (subseq octets 1 (1+ (/ +secp256r1-bits+ 8))))
                (x (ec-decode-scalar :secp256r1 x-bytes))
                (y-sign (- (aref octets 0) 2))
                (y2 (mod (+ (* x x x) (* -3 x) +secp256r1-b+) +secp256r1-p+))
                (y (expt-mod y2 +secp256r1-i+ +secp256r1-p+))
                (y (if (= (logand y 1) y-sign) y (- +secp256r1-p+ y))))
           (ec-make-point :secp256r1 :x x :y y))
         (error 'invalid-curve-point :kind 'secp256r1)))
    ((4)
     ;; Uncompressed point
     (if (= (length octets) (1+ (/ +secp256r1-bits+ 4)))
         (let* ((x-bytes (subseq octets 1 (1+ (/ +secp256r1-bits+ 8))))
                (x (ec-decode-scalar :secp256r1 x-bytes))
                (y-bytes (subseq octets (1+ (/ +secp256r1-bits+ 8))))
                (y (ec-decode-scalar :secp256r1 y-bytes)))
           (ec-make-point :secp256r1 :x x :y y))
         (error 'invalid-curve-point :kind 'secp256r1)))
    (t
     (error 'invalid-curve-point :kind 'secp256r1))))

(defun secp256r1-public-key (sk)
  (let ((a (ec-decode-scalar :secp256r1 sk)))
    (ec-encode-point (ec-scalar-mult +secp256r1-g+ a))))

(defmethod make-signature ((kind (eql :secp256r1)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'secp256r1
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'secp256r1
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :secp256r1)) signature)
  (let ((length (length signature)))
    (if (/= length (/ +secp256r1-bits+ 4))
        (error 'invalid-signature-length :kind 'secp256r1)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defmethod generate-signature-nonce ((key secp256r1-private-key) message &optional parameters)
  (or *signature-nonce-for-test*
      (rfc6979-generate-k (secp256r1-key-x key)
                          message
                          +secp256r1-l+
                          (integer-length +secp256r1-l+)
                          (ceiling (integer-length +secp256r1-l+) 8)
                          :digest (or parameters *ecdsa-rfc6979-digest*))))

;;; Note that hashing is not performed here.
(defmethod sign-message ((key secp256r1-private-key) message &key (start 0) end (digest *ecdsa-rfc6979-digest*) &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((end (min (or end (length message)) (/ +secp256r1-bits+ 8)))
         (sk (ec-decode-scalar :secp256r1 (secp256r1-key-x key)))
         (h (subseq message start end))
         (k (generate-signature-nonce key h digest))
         (invk (modular-inverse-with-blinding k +secp256r1-l+))
         (r (ec-scalar-mult +secp256r1-g+ k))
         (x (subseq (ec-encode-point r) 1 (1+ (/ +secp256r1-bits+ 8))))
         (r (ec-decode-scalar :secp256r1 x))
         (r (mod r +secp256r1-l+))
         (e (ec-decode-scalar :secp256r1 h))
         (s (mod (* invk (+ e (* sk r))) +secp256r1-l+)))
    (if (not (or (zerop r) (zerop s)))
        (make-signature :secp256r1
                        :r (ec-encode-scalar :secp256r1 r)
                        :s (ec-encode-scalar :secp256r1 s))
        (sign-message key message :start start :end end))))

(defmethod verify-signature ((key secp256r1-public-key) message signature &key (start 0) end &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length signature) (/ +secp256r1-bits+ 4))
    (error 'invalid-signature-length :kind 'secp256r1))
  (let* ((end (min (or end (length message)) (/ +secp256r1-bits+ 8)))
         (pk (ec-decode-point :secp256r1 (secp256r1-key-y key)))
         (signature-elements (destructure-signature :secp256r1 signature))
         (r (ec-decode-scalar :secp256r1 (getf signature-elements :r)))
         (s (ec-decode-scalar :secp256r1 (getf signature-elements :s))))
    ;; Degenerate (r = 0 or s = 0) signatures are invalid; answer NIL
    ;; before the W/RP computations, which assume nonzero operands.
    (unless (and (< 0 r +secp256r1-l+) (< 0 s +secp256r1-l+))
      (return-from verify-signature nil))
    (let* ((h (subseq message start end))
         (e (ec-decode-scalar :secp256r1 h))
         (w (modular-inverse-with-blinding s +secp256r1-l+))
         (u1 (mod (* e w) +secp256r1-l+))
         (u2 (mod (* r w) +secp256r1-l+))
         ;; Joint multiplication (Shamir's trick): one pass instead of two.
         (rp (secp256r1-shamir-mult +secp256r1-g+ pk u1 u2))
         (x (subseq (ec-encode-point rp) 1 (1+ (/ +secp256r1-bits+ 8))))
         (v (ec-decode-scalar :secp256r1 x))
         (v (mod v +secp256r1-l+)))
     (and (< 0 r +secp256r1-l+)
          (< 0 s +secp256r1-l+)
          ;; RP is the point at infinity only for invalid signatures;
          ;; answer NIL instead of failing inside EC-ENCODE-POINT.
          (not (ec-point-equal rp +secp256r1-point-at-infinity+))
          (= v r)))))

(defmethod make-public-key ((kind (eql :secp256r1)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'secp256r1
           :parameter 'y
           :description "public key"))
  ;; Reject malformed encodings and off-curve points now, at
  ;; construction time, rather than at first use.
  (ec-decode-point :secp256r1 y)
  (make-instance 'secp256r1-public-key :y y))

(defmethod destructure-public-key ((public-key secp256r1-public-key))
  (list :y (secp256r1-key-y public-key)))

(defmethod make-private-key ((kind (eql :secp256r1)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'secp256r1
           :parameter 'x
           :description "private key"))
  ;; The scalar must lie in [1, N-1]; 0 yields the point at infinity
  ;; and values >= N silently wrap to the wrong public key.
  (unless (< 0 (octets-to-integer x :big-endian t) +secp256r1-l+)
    (error 'invalid-private-key :kind 'secp256r1))
  (make-instance 'secp256r1-private-key :x x :y (or y (secp256r1-public-key x))))

(defmethod destructure-private-key ((private-key secp256r1-private-key))
  (list :x (secp256r1-key-x private-key)
        :y (secp256r1-key-y private-key)))

(defmethod generate-key-pair ((kind (eql :secp256r1)) &key &allow-other-keys)
  (let* ((sk (ec-encode-scalar :secp256r1 (1+ (strong-random (1- +secp256r1-l+)))))
         (pk (secp256r1-public-key sk)))
    (values (make-private-key :secp256r1 :x sk :y pk)
            (make-public-key :secp256r1 :y pk))))

(defmethod diffie-hellman ((private-key secp256r1-private-key) (public-key secp256r1-public-key))
  (let ((s (ec-decode-scalar :secp256r1 (secp256r1-key-x private-key)))
        (p (ec-decode-point :secp256r1 (secp256r1-key-y public-key))))
    (ec-encode-point (ec-scalar-mult p s))))

;;; Scratch-based P-256 point operations.
;;;
;;; The allocating EC-DOUBLE/EC-ADD methods cons ~260KB per fixed-base
;;; multiplication (a fresh vector per field op plus a fresh point per
;;; point op).  The destination-passing variants below reuse caller
;;; buffers instead: DST must be distinct from the source points, and S
;;; is a scratch pool of at least 32 field elements (see
;;; SECP256R1-MAKE-SCRATCH).  Formulas are identical to the EC-DOUBLE
;;; and EC-ADD methods; only allocation differs.

(declaim (inline secp256r1-fe-copy! secp256r1-point-copy!
                 secp256r1-point-set-inf! secp256r1-make-scratch))

(defun secp256r1-fe-copy! (dst src)
  "Copy field element SRC into DST."
  (declare (type secp256r1-fe dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 8 dst)
    (setf (aref dst i) (aref src i))))

(defun secp256r1-point-copy! (dst src)
  "Copy point SRC into DST."
  (declare (type secp256r1-point dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp256r1-fe-copy! (secp256r1-point-x dst) (secp256r1-point-x src))
  (secp256r1-fe-copy! (secp256r1-point-y dst) (secp256r1-point-y src))
  (secp256r1-fe-copy! (secp256r1-point-z dst) (secp256r1-point-z src))
  dst)

(defun secp256r1-point-set-inf! (dst)
  "Set DST to the point at infinity (1, 1, 0)."
  (declare (type secp256r1-point dst)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x (secp256r1-point-x dst))
        (y (secp256r1-point-y dst))
        (z (secp256r1-point-z dst)))
    (declare (type secp256r1-fe x y z))
    (dotimes (i 8)
      (setf (aref x i) 0
            (aref y i) 0
            (aref z i) 0))
    (setf (aref x 0) 1
          (aref y 0) 1))
  dst)

(defun secp256r1-make-scratch ()
  "A fresh scratch pool for the ! point operations."
  (let ((s (make-array 32)))
    (dotimes (i 32 s)
      (setf (svref s i) (secp256r1-fe-zero)))))

(defun secp256r1-double! (dst src s)
  "DST := 2*SRC reusing scratch pool S. DST must differ from SRC."
  (declare (type secp256r1-point dst src)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (secp256r1-point-x src))
        (y1 (secp256r1-point-y src))
        (z1 (secp256r1-point-z src))
        (xx (svref s 0))
        (yy (svref s 1))
        (yyyy (svref s 2))
        (zz (svref s 3))
        (x1+yy (svref s 4))
        (y1+z1 (svref s 5))
        (t1 (svref s 6))
        (t2 (svref s 7))
        (t3 (svref s 8))
        (ss (svref s 9))
        (t4 (svref s 10))
        (t5 (svref s 11))
        (t6 (svref s 12))
        (mm (svref s 13))
        (t7 (svref s 14))
        (t8 (svref s 15))
        (uu (svref s 16))
        (t9 (svref s 17))
        (t10 (svref s 18))
        (e2 (svref s 19))
        (e4 (svref s 20))
        (e8 (svref s 21))
        (y2 (svref s 22))
        (t11 (svref s 23))
        (t12 (svref s 24))
        (z2 (svref s 25)))
    (declare (type secp256r1-fe x1 y1 z1 xx yy yyyy zz x1+yy y1+z1
                               t1 t2 t3 ss t4 t5 t6 mm t7 t8 uu t9 t10
                               e2 e4 e8 y2 t11 t12 z2))
    (if (secp256r1-fe-is-zero z1)
        (secp256r1-point-set-inf! dst)
        (progn
          (secp256r1-fe-sq xx x1)
          (secp256r1-fe-sq yy y1)
          (secp256r1-fe-sq yyyy yy)
          (secp256r1-fe-sq zz z1)
          (secp256r1-fe-add x1+yy x1 yy)
          (secp256r1-fe-add y1+z1 y1 z1)
          (secp256r1-fe-sq t1 x1+yy)
          (secp256r1-fe-sub t2 t1 xx)
          (secp256r1-fe-sub t3 t2 yyyy)
          (secp256r1-fe-add ss t3 t3)
          (secp256r1-fe-sq t4 zz)
          (secp256r1-fe-sub t5 xx t4)
          (secp256r1-fe-add t6 t5 t5)
          (secp256r1-fe-add mm t6 t5)
          (secp256r1-fe-sq t7 mm)
          (secp256r1-fe-add t8 ss ss)
          (secp256r1-fe-sub uu t7 t8)
          (secp256r1-fe-sub t9 ss uu)
          (secp256r1-fe-mul t10 mm t9)
          (secp256r1-fe-add e2 yyyy yyyy)
          (secp256r1-fe-add e4 e2 e2)
          (secp256r1-fe-add e8 e4 e4)
          (secp256r1-fe-sub y2 t10 e8)
          (secp256r1-fe-sq t11 y1+z1)
          (secp256r1-fe-sub t12 t11 yy)
          (secp256r1-fe-sub z2 t12 zz)
          (secp256r1-fe-copy! (secp256r1-point-x dst) uu)
          (secp256r1-fe-copy! (secp256r1-point-y dst) y2)
          (secp256r1-fe-copy! (secp256r1-point-z dst) z2)
          dst))))

(defun secp256r1-add! (dst p q s)
  "DST := P + Q reusing scratch pool S. DST must differ from P and Q."
  (declare (type secp256r1-point dst p q)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (secp256r1-point-x p))
        (y1 (secp256r1-point-y p))
        (z1 (secp256r1-point-z p))
        (x2 (secp256r1-point-x q))
        (y2 (secp256r1-point-y q))
        (z2 (secp256r1-point-z q))
        (z1z1 (svref s 0))
        (z2z2 (svref s 1))
        (u1 (svref s 2))
        (u2 (svref s 3))
        (tt1 (svref s 4))
        (s1 (svref s 5))
        (tt2 (svref s 6))
        (s2 (svref s 7))
        (hh (svref s 8))
        (t3 (svref s 9))
        (t4 (svref s 10))
        (ii (svref s 11))
        (jj (svref s 12))
        (t5 (svref s 13))
        (rr (svref s 14))
        (vv (svref s 15))
        (t6 (svref s 16))
        (t7 (svref s 17))
        (t8 (svref s 18))
        (x3 (svref s 19))
        (t9 (svref s 20))
        (t10 (svref s 21))
        (t11 (svref s 22))
        (t12 (svref s 23))
        (y3 (svref s 24))
        (z1+z2 (svref s 25))
        (t13 (svref s 26))
        (t14 (svref s 27))
        (t15 (svref s 28))
        (z3 (svref s 29)))
    (declare (type secp256r1-fe x1 y1 z1 x2 y2 z2 z1z1 z2z2 u1 u2
                               tt1 s1 tt2 s2 hh t3 t4 ii jj t5 rr vv
                               t6 t7 t8 x3 t9 t10 t11 t12 y3 z1+z2
                               t13 t14 t15 z3))
    (cond ((secp256r1-fe-is-zero z1)
           (secp256r1-point-copy! dst q))
          ((secp256r1-fe-is-zero z2)
           (secp256r1-point-copy! dst p))
          (t
           (secp256r1-fe-sq z1z1 z1)
           (secp256r1-fe-sq z2z2 z2)
           (secp256r1-fe-mul u1 x1 z2z2)
           (secp256r1-fe-mul u2 x2 z1z1)
           (secp256r1-fe-mul tt1 y1 z2)
           (secp256r1-fe-mul s1 tt1 z2z2)
           (secp256r1-fe-mul tt2 y2 z1)
           (secp256r1-fe-mul s2 tt2 z1z1)
           (if (secp256r1-fe-equal u1 u2)
               (if (secp256r1-fe-equal s1 s2)
                   (secp256r1-double! dst p s)
                   (secp256r1-point-set-inf! dst))
               (progn
                 (secp256r1-fe-sub hh u2 u1)
                 (secp256r1-fe-sq t3 hh)
                 (secp256r1-fe-add t4 t3 t3)
                 (secp256r1-fe-add ii t4 t4)
                 (secp256r1-fe-mul jj hh ii)
                 (secp256r1-fe-sub t5 s2 s1)
                 (secp256r1-fe-add rr t5 t5)
                 (secp256r1-fe-mul vv u1 ii)
                 (secp256r1-fe-sq t6 rr)
                 (secp256r1-fe-sub t7 t6 jj)
                 (secp256r1-fe-add t8 vv vv)
                 (secp256r1-fe-sub x3 t7 t8)
                 (secp256r1-fe-sub t9 vv x3)
                 (secp256r1-fe-mul t10 rr t9)
                 (secp256r1-fe-mul t11 s1 jj)
                 (secp256r1-fe-add t12 t11 t11)
                 (secp256r1-fe-sub y3 t10 t12)
                 (secp256r1-fe-add z1+z2 z1 z2)
                 (secp256r1-fe-sq t13 z1+z2)
                 (secp256r1-fe-sub t14 t13 z1z1)
                 (secp256r1-fe-sub t15 t14 z2z2)
                 (secp256r1-fe-mul z3 t15 hh)
                 (secp256r1-fe-copy! (secp256r1-point-x dst) x3)
                 (secp256r1-fe-copy! (secp256r1-point-y dst) y3)
                 (secp256r1-fe-copy! (secp256r1-point-z dst) z3)
                 dst))))))

;;; Positional fixed-base table.
;;;
;;; T[J][V] = V * 256^J * G for J in [0, 32) and V in [0, 256), in affine
;;; coordinates.  A scalar multiplication is then 32 mixed additions (one
;;; per byte of K) and no doublings at all, instead of the 256 doublings
;;; and 64 additions of the 4-bit comb.  The table is built lazily on
;;; first use; Montgomery's batch-inversion trick makes affine
;;; normalization cost one inversion per row rather than one per point.

(defun secp256r1-point-from-fe (x y)
  "A fresh affine point with coordinates copied from field elements X, Y."
  (declare (type secp256r1-fe x y)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((p (make-secp256r1-point)))
    (secp256r1-fe-copy! (secp256r1-point-x p) x)
    (secp256r1-fe-copy! (secp256r1-point-y p) y)
    (setf (aref (secp256r1-point-z p) 0) 1)
    p))

(defun secp256r1-batch-affine! (points)
  "Convert the nonzero projective POINTS to affine in place, using a
single field inversion (Montgomery's batch trick).  Index 0 is left as
the point at infinity."
  (declare (type simple-vector points)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length points))
         (prods (make-array n))
         (acc (secp256r1-fe-from-int 1)))
    (declare (type fixnum n)
             (type simple-vector prods)
             (type secp256r1-fe acc))
    (setf (aref prods 0) (secp256r1-fe-from-int 1))
    (loop for i of-type fixnum from 1 below n do
      (let ((z (secp256r1-point-z (aref points i))))
        (declare (type secp256r1-fe z))
        (secp256r1-fe-mul acc acc z)
        (setf (aref prods i) (secp256r1-fe-copy acc))))
    (let ((inv (secp256r1-fe-inv acc)))
      (declare (type secp256r1-fe inv))
      (loop for i of-type fixnum downfrom (1- n) to 1 do
        (let* ((pt (aref points i))
               (z (secp256r1-point-z pt))
               (zi (secp256r1-femul inv (aref prods (1- i))))
               (zi2 (secp256r1-fesq zi))
               (zi3 (secp256r1-femul zi2 zi))
               (x (secp256r1-femul (secp256r1-point-x pt) zi2))
               (y (secp256r1-femul (secp256r1-point-y pt) zi3)))
          (declare (type secp256r1-fe z zi zi2 zi3 x y))
          (setf inv (secp256r1-femul inv z))
          (setf (aref points i) (secp256r1-point-from-fe x y)))))
    points))

(defun secp256r1-build-base-table ()
  "Build the positional table T[J][V] = V * 256^J * G."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((rows (make-array 32))
        (base (secp256r1-point-from-ints 1 1 0))
        (s (secp256r1-make-scratch)))
    (declare (type simple-vector rows)
             (type secp256r1-point base)
             (type simple-vector s))
    (secp256r1-point-copy! base +secp256r1-g+)
    (dotimes (j 32 (progn (setf *secp256r1-base-table* rows) rows))
      (declare (type fixnum j))
      (let ((row (make-array 256))
            (tmp (secp256r1-point-from-ints 1 1 0)))
        (declare (type simple-vector row)
                 (type secp256r1-point tmp))
        (setf (aref row 0) +secp256r1-point-at-infinity+
              (aref row 1) (secp256r1-point-from-ints 1 1 0))
        (secp256r1-point-copy! (aref row 1) base)
        ;; Row[V] = V * base, built from earlier entries: even V doubles
        ;; row[V/2], odd V adds base to row[V-1].
        (loop for v of-type fixnum from 2 below 256 do
          (let ((dst (secp256r1-point-from-ints 1 1 0)))
            (declare (type secp256r1-point dst))
            (if (evenp v)
                (secp256r1-double! dst (aref row (ash v -1)) s)
                (secp256r1-add! dst (aref row (1- v)) base s))
            (setf (aref row v) dst)))
        (secp256r1-batch-affine! row)
        (setf (aref rows j) row)
        ;; base := 256 * base = 256^(J+1) * G
        (loop repeat 8 do
          (secp256r1-double! tmp base s)
          (secp256r1-point-copy! base tmp))))))

(declaim (inline secp256r1-select-base))
(defun secp256r1-select-base (row v)
  "Select index V from the affine positional-table ROW.  The scan touches
every entry in order, so the memory access pattern does not depend on V."
  (declare (type simple-vector row)
           (type (unsigned-byte 8) v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((sel (aref row 0)))
    (loop for i of-type fixnum from 1 below 256
          do (when (= i v) (setf sel (aref row i))))
    sel))

(defun secp256r1-base-mult (k)
  "Fixed-base multiplication K*G using the positional byte table: 32
mixed additions and no doublings."
  (declare (type integer k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (secp256r1-ensure-base-table))
        (acc (secp256r1-point-from-ints 1 1 0))
        (tmp (secp256r1-point-from-ints 1 1 0))
        (s (secp256r1-make-scratch)))
    (declare (type simple-vector table)
             (type secp256r1-point acc tmp)
             (type simple-vector s))
    (dotimes (j 32 acc)
      (declare (type fixnum j))
      (let ((v (ldb (byte 8 (* j 8)) k)))
        (declare (type (unsigned-byte 8) v))
        (secp256r1-mixed-add! tmp acc
                              (secp256r1-select-base (aref table j) v) s)
        (secp256r1-point-copy! acc tmp)))))

(defun secp256r1-shamir-mult (p q a b)
  "Public-only joint scalar multiplication A*P + B*Q for verification.
Uses 4-bit windows and destination-passing point operations; P must be
the fixed generator, whose affine multiples come from the byte table."
  (declare (type secp256r1-point p q)
           (type integer a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (eq p +secp256r1-g+)
    (return-from secp256r1-shamir-mult (%ec-shamir-mult p q a b)))
  (let* ((nbits (max (integer-length a) (integer-length b) 1))
         (windows (ceiling nbits 4))
         (tg (aref (secp256r1-ensure-base-table) 0))
         (tq (make-array 16))
         (acc (secp256r1-point-from-ints 1 1 0))
         (tmp (secp256r1-point-from-ints 1 1 0))
         (s (secp256r1-make-scratch)))
    (declare (type fixnum nbits windows)
             (type simple-vector tg tq)
             (type secp256r1-point acc tmp)
             (type simple-vector s))
    ;; Small multiples of Q; Q is public, so they stay projective.
    (setf (aref tq 0) +secp256r1-point-at-infinity+
          (aref tq 1) q)
    (loop for v of-type fixnum from 2 below 16 do
      (let ((dst (secp256r1-point-from-ints 1 1 0)))
        (declare (type secp256r1-point dst))
        (if (evenp v)
            (secp256r1-double! dst (aref tq (ash v -1)) s)
            (secp256r1-add! dst (aref tq (1- v)) q s))
        (setf (aref tq v) dst)))
    (loop for w of-type fixnum downfrom (1- windows) to 0 do
      (unless (= w (1- windows))
        (loop repeat 4 do
          (secp256r1-double! tmp acc s)
          (secp256r1-point-copy! acc tmp)))
      (let* ((shift (* w 4))
             (ga (if (< shift nbits) (ldb (byte 4 shift) a) 0))
             (gb (if (< shift nbits) (ldb (byte 4 shift) b) 0)))
        (declare (type fixnum shift)
                 (type (unsigned-byte 4) ga gb))
        (unless (zerop ga)
          (secp256r1-mixed-add! tmp acc (aref tg ga) s)
          (secp256r1-point-copy! acc tmp))
        (unless (zerop gb)
          (secp256r1-add! tmp acc (aref tq gb) s)
          (secp256r1-point-copy! acc tmp))))
    acc))
