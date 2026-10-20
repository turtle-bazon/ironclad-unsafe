;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ed25519.lisp -- implementation of the ed25519 signature algorithm

(in-package :crypto)


;;; class definitions

(defclass ed25519-public-key ()
  ((y :initarg :y :reader ed25519-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass ed25519-private-key ()
  ((x :initarg :x :reader ed25519-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader ed25519-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass ed25519-point ()
    ;; Internally, a point (x, y) is represented in extended homogeneous
    ;; coordinates (X, Y, Z, W), with x = X / Z, y = Y / Z and x * y = W / Z.
    ;; Each coordinate is an ed25519-fe (8 x 32-bit limbs).
    ((x :initarg :x :type ed25519-fe)
     (y :initarg :y :type ed25519-fe)
     (z :initarg :z :type ed25519-fe)
     (w :initarg :w :type ed25519-fe)))
  (defmethod make-load-form ((p ed25519-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constant, variable and function definitions

(defconstant +ed25519-bits+ 256)
(defconstant +ed25519-q+ 57896044618658097711785492504343953926634992332820282019728792003956564819949)
(defconstant +ed25519-l+ 7237005577332262213973186563042994240857116359379907606001950938285454250989)
(defconstant +ed25519-d+ 37095705934669439343138083508754565189542113879843219016388785533085940283555)
(defconstant +ed25519-i+ 19681161376707505956807079304988542015446066515923890162744021073123829784752)

;; ed25519-base-point and ed25519-point-at-infinity defined after fe functions.


;;;; ed25519 field arithmetic on 32-bit limbs.
;;;
;;; A field element is (SIMPLE-ARRAY (UNSIGNED-BYTE 32) (8)), little
;;; endian.  All intermediate values stay in fixnums on 64-bit Lisps
;;; because every product is a 64-bit value and every accumulated sum
;;; stays under 2^34.  Reduction uses the Solinas form of the ed25519
;;; prime q = 2^255 - 19 (so 2^256 == 38 mod q).

(deftype ed25519-fe () '(simple-array (unsigned-byte 32) (8)))

(declaim (inline ed25519-fe-zero ed25519-fe-copy ed25519-fe-from-int ed25519-fe-to-int))

(defun ed25519-fe-zero ()
  (make-array 8 :element-type '(unsigned-byte 32) :initial-element 0))

(defun ed25519-fe-copy (a)
  (declare (type ed25519-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (ed25519-fe-zero)))
    (dotimes (i 8 r)
      (setf (aref r i) (aref a i)))))

(defun ed25519-fe-from-int (n)
  (declare (type integer n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (ed25519-fe-zero)))
    (dotimes (i 8 r)
      (setf (aref r i) (ldb (byte 32 (* i 32)) n)))))

(defun ed25519-fe-to-int (a)
  (declare (type ed25519-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((n 0))
    (declare (type integer n))
    (dotimes (i 8 n)
      (setf n (dpb (aref a i) (byte 32 (* i 32)) n)))))

(defun ed25519-fe-add (r a b)
  "R := (A + B) mod Q, all reduced residues."
  (declare (type ed25519-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((carry 0))
    (declare (type (unsigned-byte 32) carry))
    (dotimes (i 8)
      (let ((s (+ (aref a i) (aref b i) carry)))
        (setf (aref r i) (ldb (byte 32 0) s)
              carry (ash s -32))))
    (when (or (plusp carry)
              (loop for i from 7 downto 0
                    for limb = (aref r i)
                    for qlimb = (ldb (byte 32 (* i 32)) +ed25519-q+)
                    when (/= limb qlimb) return (> limb qlimb)
                    finally (return t)))
      (let ((borrow 0))
        (declare (type (unsigned-byte 32) borrow))
        (dotimes (i 8)
          (let ((d (- (aref r i)
                      (ldb (byte 32 (* i 32)) +ed25519-q+)
                      borrow)))
            (setf (aref r i) (ldb (byte 32 0) d)
                  borrow (if (minusp d) 1 0)))))))
  r)

(defun ed25519-fe-sub (r a b)
  "R := (A - B) mod Q, all reduced residues."
  (declare (type ed25519-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((borrow 0))
    (declare (type (unsigned-byte 32) borrow))
    (dotimes (i 8)
      (let ((d (- (aref a i) (aref b i) borrow)))
        (setf (aref r i) (ldb (byte 32 0) d)
              borrow (if (minusp d) 1 0))))
    (when (plusp borrow)
      (let ((carry 0))
        (declare (type (unsigned-byte 32) carry))
        (dotimes (i 8)
          (let ((s (+ (aref r i)
                      (ldb (byte 32 (* i 32)) +ed25519-q+)
                      carry)))
            (setf (aref r i) (ldb (byte 32 0) s)
                  carry (ash s -32)))))))
  r)

(declaim (inline ed25519--adc ed25519--sbb))

(defun ed25519--adc (a b c)
  "Add three small words; return (VALUES word carry).
All arguments are at most 32-bit limbs plus a small carry, so the sum
stays under 2^34 and every operation remains in fixnums."
  (declare (type (unsigned-byte 34) a b c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((s (+ a b c)))
    (values (ldb (byte 32 0) s) (ash s -32))))

(defun ed25519--sbb (a b borrow)
  "Subtract with borrow; return (VALUES word borrow-out).
A and B are 32-bit field limbs, BORROW is 0 or 1."
  (declare (type (unsigned-byte 32) a b)
           (type (unsigned-byte 32) borrow)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((d (- a b borrow)))
    (values (ldb (byte 32 0) d) (if (minusp d) 1 0))))

(defun ed25519-fe-mul-raw (r a b)
  "R := A * B as 16 limbs, no reduction.  R holds 32-bit limbs."
  (declare (type ed25519-fe a b)
           (type (simple-array (unsigned-byte 32) (16)) r)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-assembly)
  (ed25519-fe-mul-raw-asm r a b)
  #-(and sbcl x86-64 ironclad-assembly)
  (progn
    (dotimes (k 16)
      (setf (aref r k) 0))
    (dotimes (i 8)
      (let ((carry 0))
        (declare (type (unsigned-byte 32) carry))
        (dotimes (j 8)
          (let* ((prod (* (aref a i) (aref b j)))
                 (plo (ldb (byte 32 0) prod))
                 (phi (ash prod -32))
                 (s (+ (aref r (+ i j)) plo carry)))
            (setf (aref r (+ i j)) (ldb (byte 32 0) s)
                  carry (+ (ash s -32) phi))))
        (setf (aref r (+ i 8)) carry)))
    r))

(defun ed25519-fe-normalize16 (c)
  "Propagate carries so C holds 16 canonical 32-bit words."
  (declare (type (simple-array (unsigned-byte 32) (16)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (k 15)
    (let ((carry (ash (aref c k) -32)))
      (declare (type (unsigned-byte 32) carry))
      (setf (aref c k) (ldb (byte 32 0) (aref c k))
            (aref c (1+ k)) (+ (aref c (1+ k)) carry))))
  (setf (aref c 15) (ldb (byte 32 0) (aref c 15)))
  c)

(defun ed25519-fe-reduce16 (c)
  "Reduce 16-limb product C modulo Q = 2^255 - 19.
C holds 16 canonical 32-bit limbs (little endian).  Result is stored
in the low 8 limbs of C.  HIGH limbs are clobbered.

Reduction: X = LOW + HIGH * 2^256 where 2^256 == 38 (mod Q).
So X == LOW + HIGH * 38 (mod Q).  The result is under 2*Q, so one
conditional subtract of Q suffices."
  (declare (type (simple-array (unsigned-byte 32) (16)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; Add HIGH * 38 to LOW (c[0..7]), propagating carries.
  ;; HIGH = c[8..15].  HIGH * 38 < 38 * 2^256, so carry out of limb 7
  ;; is at most 37 (fits in a fixnum).
  (let ((carry 0))
    (declare (type (unsigned-byte 32) carry))
    (dotimes (i 8)
      (let* ((prod (* (aref c (+ i 8)) 38))
             (plo (ldb (byte 32 0) prod))
             (phi (ash prod -32)))
        (multiple-value-bind (lo c1) (ed25519--adc (aref c i) plo carry)
          (setf (aref c i) lo
                carry (+ c1 phi)))))
    ;; Handle any carry out of the low 8 limbs: this is X'_HIGH (<= 37).
    ;; X' == X'_LOW + X'_HIGH * 38 (mod Q), where X'_LOW = c[0..7].
    (when (plusp carry)
      (let ((prod (* carry 38))
            (i 0))
        (declare (type (unsigned-byte 32) i))
        ;; Add carry * 38 to c[0], propagating.
        (multiple-value-bind (plo phi) (values (ldb (byte 32 0) prod)
                                               (ash prod -32))
          (multiple-value-bind (lo c1) (ed25519--adc (aref c 0) plo 0)
            (setf (aref c 0) lo
                  carry (+ c1 phi)))
          (when (plusp carry)
            (loop while (plusp carry) do
              (incf i)
              (multiple-value-bind (lo c1) (ed25519--adc (aref c i) carry 0)
                (setf (aref c i) lo
                      carry c1)))))))

  ;; Conditional subtract Q until the result is canonical.  After the
  ;; folds above the value is < 2^256 = 2*Q + 38, so at most two
  ;; subtractions are needed.  Compare from the top limb down.
  (dotimes (pass 2)
    (let ((geq nil))
      (dotimes (k 8)
        (let ((i (- 7 k)))
          (let ((cl (aref c i))
                (ql (ldb (byte 32 (* i 32)) +ed25519-q+)))
            (cond ((> cl ql) (setf geq t) (return))
                  ((< cl ql) (setf geq nil) (return))))))
      (when geq
        (let ((borrow 0))
          (declare (type (unsigned-byte 32) borrow))
          (dotimes (j 8)
            (let ((d (- (aref c j)
                        (ldb (byte 32 (* j 32)) +ed25519-q+)
                        borrow)))
              (setf (aref c j) (ldb (byte 32 0) d)
                    borrow (if (minusp d) 1 0))))))))

  c))

(defun ed25519-fe-mul (r a b)
  "R := (A * B) mod Q for reduced residues in limb form."
  (declare (type ed25519-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((prod (make-array 16 :element-type '(unsigned-byte 32) :initial-element 0)))
    ;; NB: the product must stay in the heap.  The assembly multiply
    ;; assumes the usual heap layout of a simple vector; a stack
    ;; allocated (or escape-analyzed) array has a different layout and
    ;; the VOP then writes outside the array, corrupting the caller.
    (declare (type (simple-array (unsigned-byte 32) (16)) prod))
    (ed25519-fe-mul-raw prod a b)
    (ed25519-fe-normalize16 prod)
    (ed25519-fe-reduce16 prod)
    (dotimes (i 8 r)
      (setf (aref r i) (aref prod i)))))

(defun ed25519-fe-sqr-raw (r a)
  "R := A * A as 16 limbs, no reduction.  R holds 32-bit limbs."
  (declare (type ed25519-fe a)
           (type (simple-array (unsigned-byte 32) (16)) r)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-assembly)
  (ed25519-fe-sqr-raw-asm r a)
  #-(and sbcl x86-64 ironclad-assembly)
  (progn
    (dotimes (k 16)
      (setf (aref r k) 0))
    (ed25519-fe-mul-raw r a a)
    r))

(defun ed25519-fe-sq (r a)
  "R := A^2 mod Q."
  (declare (type ed25519-fe r a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((prod (make-array 16 :element-type '(unsigned-byte 32) :initial-element 0)))
    ;; NB: the product must stay in the heap.  The assembly multiply
    ;; assumes the usual heap layout of a simple vector; a stack
    ;; allocated (or escape-analyzed) array has a different layout and
    ;; the VOP then writes outside the array, corrupting the caller.
    (declare (type (simple-array (unsigned-byte 32) (16)) prod))
    (ed25519-fe-sqr-raw prod a)
    (ed25519-fe-normalize16 prod)
    (ed25519-fe-reduce16 prod)
    (dotimes (i 8 r)
      (setf (aref r i) (aref prod i)))))

(defun ed25519-fe-equal (a b)
  (declare (type ed25519-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 8 t)
    (unless (= (aref a i) (aref b i))
      (return nil))))

(defun ed25519-fe-is-zero (a)
  (declare (type ed25519-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 8 t)
    (unless (zerop (aref a i))
      (return nil))))

(defconstant +ed25519-q-minus-2+ (- +ed25519-q+ 2))

(declaim (inline ed25519-fe-sq-n))
(defun ed25519-fe-sq-n (r a n)
  "R := A^(2^N).  N must be positive."
  (declare (type ed25519-fe r a)
           (type (integer 1) n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (ed25519-fe-sq r a)
  (loop repeat (1- n) do (ed25519-fe-sq r r))
  r)

;; NB: do not inline these.  When inlined, SBCL's escape analysis can
;; stack-allocate the scratch vector that the assembly VOP works on,
;; and the VOP then writes outside it, corrupting the caller's frame.
(declaim (notinline ed25519-fe-inv))
(defun ed25519-fe-inv (z)
  "Field element inverse via the standard 2^255-21 addition chain.
Uses 254 squarings and 11 multiplications."
  (declare (type ed25519-fe z)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-assembly)
  (let ((n 0)
        (scratch (make-array 208 :element-type '(unsigned-byte 64))))
    (declare (type integer n)
             (type (simple-array (unsigned-byte 64) (*)) scratch))
    (dotimes (i 8)
      (setf n (dpb (aref z i) (byte 32 (* 32 i)) n)))
    (setf n (mod n +ed25519-q+))
    ;; Scratch element 57 is the radix-2^51 input, element 37 the result
    ;; (see the layout in src/opt/sbcl/ed25519-comb.lisp).
    (dotimes (i 5)
      (setf (aref scratch (+ 57 i)) (ldb (byte 51 (* 51 i)) n)))
    (ed25519-inv-asm scratch)
    (let ((m 0))
      (declare (type integer m))
      (dotimes (i 5)
        (setf m (+ m (ash (aref scratch (+ 37 i)) (* 51 i)))))
      (ed25519-fe-from-int (mod m +ed25519-q+))))
  #-(and sbcl x86-64 ironclad-assembly)
  (let ((t0 (ed25519-fe-zero)) (t1 (ed25519-fe-zero))
        (t2 (ed25519-fe-zero)) (t3 (ed25519-fe-zero))
        (out (ed25519-fe-zero)))
    (declare (type ed25519-fe t0 t1 t2 t3 out)
             (dynamic-extent t0 t1 t2 t3))
    (ed25519-fe-sq t0 z)                 ; z^2
    (ed25519-fe-sq-n t1 t0 2)            ; z^8
    (ed25519-fe-mul t1 z t1)             ; z^9
    (ed25519-fe-mul t0 t0 t1)            ; z^11
    (ed25519-fe-sq t2 t0)                ; z^22
    (ed25519-fe-mul t1 t1 t2)            ; z^(2^5-1)
    (ed25519-fe-sq-n t2 t1 5)            ; z^(2^10-2^5)
    (ed25519-fe-mul t1 t2 t1)            ; z^(2^10-1)
    (ed25519-fe-sq-n t2 t1 10)
    (ed25519-fe-mul t2 t2 t1)            ; z^(2^20-1)
    (ed25519-fe-sq-n t3 t2 20)
    (ed25519-fe-mul t2 t3 t2)            ; z^(2^40-1)
    (ed25519-fe-sq-n t2 t2 10)
    (ed25519-fe-mul t1 t2 t1)            ; z^(2^50-1)
    (ed25519-fe-sq-n t2 t1 50)
    (ed25519-fe-mul t2 t2 t1)            ; z^(2^100-1)
    (ed25519-fe-sq-n t3 t2 100)
    (ed25519-fe-mul t2 t3 t2)            ; z^(2^200-1)
    (ed25519-fe-sq-n t2 t2 50)
    (ed25519-fe-mul t1 t2 t1)            ; z^(2^250-1)
    (ed25519-fe-sq-n t1 t1 5)
    (ed25519-fe-mul out t1 t0)           ; z^(2^255-21)
    out))

(declaim (notinline ed25519-fe-pow22523))
(defun ed25519-fe-pow22523 (z)
  "Field element z^(2^252-3), used to recover x when decompressing a point."
  (declare (type ed25519-fe z)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-assembly)
  (let ((n 0)
        (scratch (make-array 208 :element-type '(unsigned-byte 64))))
    (declare (type integer n)
             (type (simple-array (unsigned-byte 64) (*)) scratch))
    (dotimes (i 8)
      (setf n (dpb (aref z i) (byte 32 (* 32 i)) n)))
    (setf n (mod n +ed25519-q+))
    (dotimes (i 5)
      (setf (aref scratch (+ 57 i)) (ldb (byte 51 (* 51 i)) n)))
    (ed25519-pow22523-asm scratch)
    (let ((m 0))
      (declare (type integer m))
      (dotimes (i 5)
        (setf m (+ m (ash (aref scratch (+ 37 i)) (* 51 i)))))
      (ed25519-fe-from-int (mod m +ed25519-q+))))
  #-(and sbcl x86-64 ironclad-assembly)
  (ed25519-fe-from-int
   (expt-mod (ed25519-fe-to-int z) (/ (- +ed25519-q+ 5) 8) +ed25519-q+)))

(defmethod ec-scalar-inv ((kind (eql :ed25519)) n)
  ;; Field-element Fermat inversion is faster than bignum expt-mod.
  (declare (type integer n))
  (if (zerop n)
      0
      (ed25519-fe-to-int (ed25519-fe-inv (ed25519-fe-from-int n)))))

(defvar ed25519-base-point
  (make-instance 'ed25519-point
                 :x (ed25519-fe-from-int 15112221349535400772501151409588531511454012693041857206046113283949847762202)
                 :y (ed25519-fe-from-int 46316835694926478169428394003475163141307993866256225615783033603165251855960)
                 :z (ed25519-fe-from-int 1)
                 :w (ed25519-fe-from-int 46827403850823179245072216630277197565144205554125654976674165829533817101731)))

(defvar ed25519-point-at-infinity
  (make-instance 'ed25519-point
                 :x (ed25519-fe-from-int 0)
                 :y (ed25519-fe-from-int 1)
                 :z (ed25519-fe-from-int 1)
                 :w (ed25519-fe-from-int 0)))

(defun ed25519-recover-x (y)
  "Recover the X coordinate of a point on ed25519 curve from the Y coordinate."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer y))
  (let* ((u (mod (1- (* y y)) +ed25519-q+))
         (v (mod (1+ (* +ed25519-d+ (1+ u))) +ed25519-q+))
         (v3 (mod (* v v v) +ed25519-q+))
         (uv3 (mod (* u v3) +ed25519-q+))
         (uv7 (mod (* uv3 v3 v) +ed25519-q+))
         (x (mod (* uv3 (ed25519-fe-to-int
                         (ed25519-fe-pow22523 (ed25519-fe-from-int uv7))))
                  +ed25519-q+)))
    (declare (type integer u v v3 uv3 uv7 x))
    (unless (= u (mod (* v x x) +ed25519-q+))
      (setf x (mod (* x +ed25519-i+) +ed25519-q+)))
    (unless (evenp x)
      (setf x (- +ed25519-q+ x)))
    x))

(defmethod ec-add ((p ed25519-point) (q ed25519-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((dst (make-instance 'ed25519-point :x (ed25519-fe-zero) :y (ed25519-fe-zero) :z (ed25519-fe-zero) :w (ed25519-fe-zero))))
    (ed25519-add! dst p q)
    dst))

(defmethod ec-double ((p ed25519-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((dst (make-instance 'ed25519-point :x (ed25519-fe-zero) :y (ed25519-fe-zero) :z (ed25519-fe-zero) :w (ed25519-fe-zero))))
    (ed25519-double! dst p)
    dst))

(declaim (inline ed25519-double!))
(defun ed25519-double! (dst p)
  "DST := 2*P. DST must differ from P."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type ed25519-fe x1 y1 z1))
    (let ((a (ed25519-fe-zero)) (b (ed25519-fe-zero)) (c (ed25519-fe-zero))
          (d (ed25519-fe-zero)) (i (ed25519-fe-zero)) (h (ed25519-fe-zero))
          (e (ed25519-fe-zero)) (g (ed25519-fe-zero)) (f (ed25519-fe-zero))
          (x2 (ed25519-fe-zero)) (y2 (ed25519-fe-zero)) (z2 (ed25519-fe-zero))
          (w2 (ed25519-fe-zero)))
      (declare (type ed25519-fe a b c d i h e g f x2 y2 z2 w2)
               (dynamic-extent a b c d i h e g f x2 y2 z2 w2))
      (ed25519-fe-sq a x1)
      (ed25519-fe-sq b y1)
      (ed25519-fe-sq c z1)
      (ed25519-fe-add c c c)
      (ed25519-fe-add d x1 y1)
      (ed25519-fe-sq i d)
      (ed25519-fe-add h a b)
      (ed25519-fe-sub e h i)
      (ed25519-fe-sub g a b)
      (ed25519-fe-add f c g)
      (ed25519-fe-mul x2 e f)
      (ed25519-fe-mul y2 g h)
      (ed25519-fe-mul z2 f g)
      (ed25519-fe-mul w2 e h)
      (let ((dx (slot-value dst 'x)) (dy (slot-value dst 'y))
            (dz (slot-value dst 'z)) (dw (slot-value dst 'w)))
        (dotimes (k 8)
          (setf (aref dx k) (aref x2 k)
                (aref dy k) (aref y2 k)
                (aref dz k) (aref z2 k)
                (aref dw k) (aref w2 k))))
      dst)))

(declaim (inline ed25519-add!))
(defun ed25519-add! (dst p q)
  "DST := P + Q. DST must differ from P and Q."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z) (w1 w)) p
    (declare (type ed25519-fe x1 y1 z1 w1))
    (with-slots ((x2 x) (y2 y) (z2 z) (w2 w)) q
      (declare (type ed25519-fe x2 y2 z2 w2))
      (let ((ymx1 (ed25519-fe-zero)) (ypx1 (ed25519-fe-zero))
            (ymx2 (ed25519-fe-zero)) (ypx2 (ed25519-fe-zero))
            (a (ed25519-fe-zero)) (b (ed25519-fe-zero)) (i (ed25519-fe-zero))
            (c (ed25519-fe-zero)) (d (ed25519-fe-zero)) (e (ed25519-fe-zero))
            (f (ed25519-fe-zero)) (g (ed25519-fe-zero)) (h (ed25519-fe-zero))
            (x3 (ed25519-fe-zero)) (y3 (ed25519-fe-zero)) (z3 (ed25519-fe-zero))
            (w3 (ed25519-fe-zero)) (dconst (ed25519-fe-from-int +ed25519-d+)))
        (declare (type ed25519-fe ymx1 ypx1 ymx2 ypx2 a b i c d e f g h x3 y3 z3 w3 dconst)
                 (dynamic-extent ymx1 ypx1 ymx2 ypx2 a b i c d e f g h x3 y3 z3 w3))
        (ed25519-fe-sub ymx1 y1 x1)
        (ed25519-fe-add ypx1 y1 x1)
        (ed25519-fe-sub ymx2 y2 x2)
        (ed25519-fe-add ypx2 y2 x2)
        (ed25519-fe-mul a ymx1 ymx2)
        (ed25519-fe-mul b ypx1 ypx2)
        (ed25519-fe-mul i w1 w2)
        (ed25519-fe-mul c i dconst)
        (ed25519-fe-add c c c)
        (ed25519-fe-mul d z1 z2)
        (ed25519-fe-add d d d)
        (ed25519-fe-sub e b a)
        (ed25519-fe-sub f d c)
        (ed25519-fe-add g d c)
        (ed25519-fe-add h b a)
        (ed25519-fe-mul x3 e f)
        (ed25519-fe-mul y3 g h)
        (ed25519-fe-mul z3 f g)
        (ed25519-fe-mul w3 e h)
        (let ((dx (slot-value dst 'x)) (dy (slot-value dst 'y))
              (dz (slot-value dst 'z)) (dw (slot-value dst 'w)))
          (dotimes (k 8)
            (setf (aref dx k) (aref x3 k)
                  (aref dy k) (aref y3 k)
                  (aref dz k) (aref z3 k)
                  (aref dw k) (aref w3 k))))
        dst))))

(declaim (inline ed25519-point-copy!))
(defun ed25519-point-copy! (dst src)
  "Copy point SRC into DST."
  (declare (type ed25519-point dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((dx (slot-value dst 'x)) (dy (slot-value dst 'y))
        (dz (slot-value dst 'z)) (dw (slot-value dst 'w))
        (sx (slot-value src 'x)) (sy (slot-value src 'y))
        (sz (slot-value src 'z)) (sw (slot-value src 'w)))
    (dotimes (i 8)
      (setf (aref dx i) (aref sx i)
            (aref dy i) (aref sy i)
            (aref dz i) (aref sz i)
            (aref dw i) (aref sw i))))
  dst)

;;; Scalar multiplication for arbitrary points (not the generator).
;;; Uses destination-based Montgomery ladder to avoid consing intermediate
;;; points.  This is used by ed25519-verify for the public-key multiplication.
;;; Radix-2^51 representation of the same positional table, used by the
;;; x86-64 assembly comb (see src/opt/sbcl/ed25519-comb.lisp).  Each field
;;; element is five 64-bit limbs holding a value mod 2^255-19.

(defconstant +ed25519-r51-limb-bits+ 51)

(defvar *ed25519-r51-table* nil
  "Flat T[J][V] as 5-limb radix-2^51 values: X,Y,Z,T per entry.  Built on first use.")
(defvar *ed25519-r51-twod* nil
  "The constant 2*d in radix-2^51 limb form.")

(defun ed25519-r51-constant (n)
  (declare (type integer n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (make-array 5 :element-type '(unsigned-byte 64))))
    (dotimes (i 5 r)
      (setf (aref r i) (ldb (byte +ed25519-r51-limb-bits+
                                  (* +ed25519-r51-limb-bits+ i))
                            n)))))

(defun ed25519-point-to-r51! (flat base p)
  "Store point P's X,Y,Z,T at BASE as contiguous radix-2^51 limbs."
  (declare (type (simple-array (unsigned-byte 64) (*)) flat)
           (type fixnum base)
           (type ed25519-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (flet ((store (off fe)
           (declare (type fixnum off) (type ed25519-fe fe))
           (let ((n (ed25519-fe-to-int fe)))
             (dotimes (i 5)
               (setf (aref flat (+ base off i))
                     (ldb (byte +ed25519-r51-limb-bits+
                                (* +ed25519-r51-limb-bits+ i))
                          n))))))
    (store 0 (slot-value p 'x))
    (store 5 (slot-value p 'y))
    (store 10 (slot-value p 'z))
    (store 15 (slot-value p 'w)))
  flat)

(defun ed25519-r51-twod ()
  (or *ed25519-r51-twod*
      (setf *ed25519-r51-twod*
            (ed25519-r51-constant (mod (* 2 +ed25519-d+) +ed25519-q+)))))

(defun ed25519-r51-coord (result base)
  "Integer represented by the five radix-2^51 limbs at BASE of RESULT."
  (declare (type (simple-array (unsigned-byte 64) (*)) result)
           (type fixnum base)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((n 0))
    (declare (type integer n))
    (dotimes (i 5 n)
      (setf n (+ n (ash (aref result (+ base i))
                        (* +ed25519-r51-limb-bits+ i)))))))


(defun ed25519-scalar-mult-general (p e)
  "Compute E*P for an arbitrary point P."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (when (minusp e)
    (error "negative scalars not supported by ed25519-scalar-mult-general"))
  #+(and sbcl x86-64 ironclad-assembly)
  (if (< e (ash 1 256))
      ;; Radix-2^51 double-and-add, all in one VOP.  The point and the
      ;; working area live in the single scratch vector (the layout is
      ;; documented in src/opt/sbcl/ed25519-comb.lisp).
      (let ((point (make-array 20 :element-type '(unsigned-byte 64)))
            (scratch (make-array 384 :element-type '(unsigned-byte 64))))
        ;; NB: both arrays are passed to the assembly comb VOP, which
        ;; assumes the heap layout of a simple vector, so they must not
        ;; be stack allocated.
        (declare (type (simple-array (unsigned-byte 64) (*)) point scratch))
        (ed25519-point-to-r51! point 0 p)
        ;; scratch[0..255]: scalar bits, most significant first.
        (dotimes (j 256)
          (setf (aref scratch j) (ldb (byte 1 (- 255 j)) e)))
        ;; scratch[301..305]: 2*d.
        (let ((twod (ed25519-r51-twod)))
          (declare (type (simple-array (unsigned-byte 64) (*)) twod))
          (dotimes (i 5)
            (setf (aref scratch (+ 301 i)) (aref twod i))))
        (ed25519-gen-mult-asm point scratch)
        ;; scratch[276..295]: X,Y,Z,T.
        (make-instance 'ed25519-point
                       :x (ed25519-fe-from-int (mod (ed25519-r51-coord scratch 276)
                                                    +ed25519-q+))
                       :y (ed25519-fe-from-int (mod (ed25519-r51-coord scratch 281)
                                                    +ed25519-q+))
                       :z (ed25519-fe-from-int (mod (ed25519-r51-coord scratch 286)
                                                    +ed25519-q+))
                       :w (ed25519-fe-from-int (mod (ed25519-r51-coord scratch 291)
                                                    +ed25519-q+))))
      (ed25519-scalar-mult-general-lisp p e))
  #-(and sbcl x86-64 ironclad-assembly)
  (ed25519-scalar-mult-general-lisp p e))

(defun ed25519-scalar-mult-general-lisp (p e)
  "Compute E*P for arbitrary point P using destination-based ladder.
No consing of intermediate points - uses 4 pre-allocated point objects."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (let* ((r0 (make-instance 'ed25519-point :x (ed25519-fe-zero) :y (ed25519-fe-zero) :z (ed25519-fe-zero) :w (ed25519-fe-zero)))
         (r1 (make-instance 'ed25519-point :x (ed25519-fe-zero) :y (ed25519-fe-zero) :z (ed25519-fe-zero) :w (ed25519-fe-zero)))
         (t0 (make-instance 'ed25519-point :x (ed25519-fe-zero) :y (ed25519-fe-zero) :z (ed25519-fe-zero) :w (ed25519-fe-zero)))
         (t1 (make-instance 'ed25519-point :x (ed25519-fe-zero) :y (ed25519-fe-zero) :z (ed25519-fe-zero) :w (ed25519-fe-zero))))
    ;; Initialize r0 = infinity (0,1,1,0), r1 = P
    (let ((zero (ed25519-fe-from-int 0)) (one (ed25519-fe-from-int 1)))
      (replace (slot-value r0 'x) zero)
      (replace (slot-value r0 'y) one)
      (replace (slot-value r0 'z) one)
      (replace (slot-value r0 'w) zero))
    (ed25519-point-copy! r1 p)
    ;; Process bits from MSB to LSB
    (do ((i (1- (integer-length e)) (1- i)))
        ((minusp i) r0)
      (if (logbitp i e)
          (progn
            (ed25519-add! t0 r0 r1)
            (ed25519-double! t1 r1)
            ;; Copy t0 -> r0, t1 -> r1
            (ed25519-point-copy! r0 t0)
            (ed25519-point-copy! r1 t1))
          (progn
            (ed25519-add! t0 r1 r0)
            (ed25519-double! t1 r0)
            ;; Copy t0 -> r1, t1 -> r0
            (ed25519-point-copy! r1 t0)
            (ed25519-point-copy! r0 t1))))))

;;; Fixed-base positional comb for the generator point.
;;;
;;; SIGN-MESSAGE and key generation always multiply G by a secret
;;; scalar, so the whole digit table can be precomputed.  Split a
;;; 256-bit scalar into 32 base-256 digits,
;;;
;;;     k = sum_j d_j * 256^j,
;;;
;;; and precompute, for every position j,
;;;
;;;     T[j][v] = v * 256^j * G      (0 <= v < 256).
;;;
;;; Then
;;;
;;;     k G = sum_j T[j][d_j],
;;;
;;; which costs 32 unified point additions and no doublings at all.
;;; (The old double-and-add comb needed 256 doublings plus 32 adds.)

(defconstant +ed25519-base-window-size+ 8)
(defconstant +ed25519-base-window-count+ 32)
(defconstant +ed25519-base-window-mask+ 255)

(defvar *ed25519-base-table* nil
  "Precomputed T[J][V] = V * 256^J * G.  Built on first use.")

(defun ed25519-ensure-base-table ()
  (or *ed25519-base-table*
      (setf *ed25519-base-table*
            (let ((table (make-array +ed25519-base-window-count+))
                  (base ed25519-base-point))
              (dotimes (j +ed25519-base-window-count+)
                (let ((row (make-array 256)))
                  (setf (aref row 0) ed25519-point-at-infinity
                        (aref row 1) base)
                  (loop for v from 2 below 256
                        do (setf (aref row v)
                                 (if (evenp v)
                                     (ec-double (aref row (ash v -1)))
                                     (ec-add (aref row (1- v)) base))))
                  (setf (aref table j) row))
                ;; base := 256 * base = 2^8 * base for the next position.
                (dotimes (i 8)
                  (setf base (ec-double base))))
              table))))

(defun ed25519-ensure-r51-table ()
  "Build the flat radix-2^51 positional table if needed."
  (or *ed25519-r51-table*
      (let ((table (make-array (* +ed25519-base-window-count+ 256 20)
                               :element-type '(unsigned-byte 64)))
            (base ed25519-base-point))
        (dotimes (j +ed25519-base-window-count+)
          (let ((row (make-array 256)))
            (setf (aref row 0) ed25519-point-at-infinity
                  (aref row 1) base)
            (loop for v from 2 below 256
                  do (setf (aref row v)
                           (if (evenp v)
                               (ec-double (aref row (ash v -1)))
                               (ec-add (aref row (1- v)) base))))
            (dotimes (v 256)
              (ed25519-point-to-r51! table (* (+ (* j 256) v) 20)
                                     (aref row v))))
          (dotimes (i 8)
            (setf base (ec-double base))))
        (setf *ed25519-r51-table* table))))

(defun ed25519-base-mult (k)
  "Fixed-base positional comb for G (secret scalar, fixed schedule).
32 unified additions, no doublings."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  #+(and sbcl x86-64 ironclad-assembly)
  (let ((table (ed25519-ensure-r51-table))
        (twod (ed25519-r51-twod))
        (scratch (make-array 208 :element-type '(unsigned-byte 64))))
    (declare (type (simple-array (unsigned-byte 64) (*)) table twod scratch))
    ;; scratch[0..31]: the 32 base-256 digits (one per 64-bit word).
    (dotimes (j 32)
      (setf (aref scratch j) (ldb (byte 8 (* j 8)) k)))
    ;; scratch[32..36]: the constant 2*d (byte offset 256).
    (dotimes (i 5)
      (setf (aref scratch (+ 32 i)) (aref twod i)))
    (ed25519-comb-asm table scratch)
    ;; scratch[37..56]: the result X,Y,Z,T (byte offset 296).
    (make-instance 'ed25519-point
                   :x (ed25519-fe-from-int (mod (ed25519-r51-coord scratch 37)
                                                +ed25519-q+))
                   :y (ed25519-fe-from-int (mod (ed25519-r51-coord scratch 42)
                                                +ed25519-q+))
                   :z (ed25519-fe-from-int (mod (ed25519-r51-coord scratch 47)
                                                +ed25519-q+))
                   :w (ed25519-fe-from-int (mod (ed25519-r51-coord scratch 52)
                                                +ed25519-q+))))
  #-(and sbcl x86-64 ironclad-assembly)
  (let ((table (ed25519-ensure-base-table))
        (acc (make-instance 'ed25519-point
                            :x (ed25519-fe-zero) :y (ed25519-fe-zero)
                            :z (ed25519-fe-zero) :w (ed25519-fe-zero)))
        (out (make-instance 'ed25519-point
                            :x (ed25519-fe-zero) :y (ed25519-fe-zero)
                            :z (ed25519-fe-zero) :w (ed25519-fe-zero))))
    (ed25519-point-copy! acc ed25519-point-at-infinity)
    (dotimes (j +ed25519-base-window-count+ acc)
      (let ((v (ldb (byte +ed25519-base-window-size+
                         (* j +ed25519-base-window-size+))
                    k)))
        (unless (zerop v)
          (ed25519-add! out acc (aref (aref table j) v))
          (rotatef acc out))))))

(defmethod ec-scalar-mult ((p ed25519-point) e)
  ;; Secret scalars use the fixed-schedule ladder.  The generator G uses
  ;; the faster fixed-base comb.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (if (and (eq p ed25519-base-point) (not (minusp e)))
      (ed25519-base-mult e)
      (do ((r0 ed25519-point-at-infinity)
           (r1 p)
           (i 254 (1- i)))
          ((minusp i) r0)
        (declare (type ed25519-point r0 r1)
                 (type fixnum i))
        (if (logbitp i e)
            (setf r0 (ec-add r0 r1)
                  r1 (ec-double r1))
            (setf r1 (ec-add r0 r1)
                  r0 (ec-double r0))))))

(defmethod ec-point-on-curve-p ((p ed25519-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots (x y z w) p
    (declare (type ed25519-fe x y z w))
    (let ((xx (ed25519-fe-zero)) (yy (ed25519-fe-zero)) (zz (ed25519-fe-zero))
          (ww (ed25519-fe-zero)) (a (ed25519-fe-zero)) (b (ed25519-fe-zero))
          (dconst (ed25519-fe-from-int +ed25519-d+)) (prod (ed25519-fe-zero)))
      (declare (type ed25519-fe xx yy zz ww a b dconst prod))
      (replace xx x)
      (replace yy y)
      (replace zz z)
      (replace ww w)
      (ed25519-fe-sq xx xx)
      (ed25519-fe-sq yy yy)
      (ed25519-fe-sq zz zz)
      (ed25519-fe-sq ww ww)
      (ed25519-fe-sub a yy xx)
      (ed25519-fe-mul prod dconst ww)
      (ed25519-fe-add b zz prod)
      (ed25519-fe-sub a a b)
      (ed25519-fe-is-zero a))))

(defmethod ec-point-equal ((p ed25519-point) (q ed25519-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type ed25519-fe x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type ed25519-fe x2 y2 z2))
      (let ((t1 (ed25519-fe-zero)) (t2 (ed25519-fe-zero))
            (u1 (ed25519-fe-zero)) (u2 (ed25519-fe-zero)))
        (declare (type ed25519-fe t1 t2 u1 u2))
        (ed25519-fe-mul t1 x1 z2)
        (ed25519-fe-mul t2 x2 z1)
        (ed25519-fe-sub t1 t1 t2)
        (ed25519-fe-mul u1 y1 z2)
        (ed25519-fe-mul u2 y2 z1)
        (ed25519-fe-sub u1 u1 u2)
        (and (ed25519-fe-is-zero t1)
             (ed25519-fe-is-zero u1))))))

(defmethod ec-make-point ((kind (eql :ed25519)) &key x y)
  (unless x
    (error 'missing-point-parameter
           :kind 'ed25519
           :parameter 'x
           :description "coordinate"))
  (unless y
    (error 'missing-point-parameter
           :kind 'ed25519
           :parameter 'y
           :description "coordinate"))
  (let* ((xf (ed25519-fe-from-int x))
         (yf (ed25519-fe-from-int y))
         (zf (ed25519-fe-from-int 1))
         (wf (ed25519-fe-zero)))
    (declare (type ed25519-fe xf yf zf wf))
    (ed25519-fe-mul wf xf yf)
    (let ((p (make-instance 'ed25519-point :x xf :y yf :z zf :w wf)))
      (declare (type ed25519-point p))
      (if (ec-point-on-curve-p p)
          p
          (error 'invalid-curve-point :kind 'ed25519)))))

(defmethod ec-destructure-point ((p ed25519-point))
  (with-slots (x y z) p
    (declare (type ed25519-fe x y z))
    (let* ((invz (ed25519-fe-inv z))
           (xr (ed25519-fe-zero)) (yr (ed25519-fe-zero)))
      (declare (type ed25519-fe invz xr yr))
      (ed25519-fe-mul xr x invz)
      (ed25519-fe-mul yr y invz)
      (list :x (ed25519-fe-to-int xr)
            :y (ed25519-fe-to-int yr)))))

(defmethod ec-encode-scalar ((kind (eql :ed25519)) n)
  (integer-to-octets n :n-bits +ed25519-bits+ :big-endian nil))

(defmethod ec-decode-scalar ((kind (eql :ed25519)) octets)
  (octets-to-integer octets :big-endian nil))

(defmethod ec-encode-point ((p ed25519-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x))
         (y (getf coordinates :y)))
    (declare (type integer x y))
    (setf (ldb (byte 1 (- +ed25519-bits+ 1)) y) (ldb (byte 1 0) x))
    (ec-encode-scalar :ed25519 y)))

(defmethod ec-decode-point ((kind (eql :ed25519)) octets)
  (let* ((y (ec-decode-scalar :ed25519 octets))
         (b (ldb (byte 1 (- +ed25519-bits+ 1)) y)))
    (declare (type integer y)
             (type fixnum b))
    (setf (ldb (byte 1 (- +ed25519-bits+ 1)) y) 0)
    (let ((x (ed25519-recover-x y)))
      (declare (type integer x))
      (unless (= (ldb (byte 1 0) x) b)
        (setf x (- +ed25519-q+ x)))
      (ec-make-point :ed25519 :x x :y y))))

(defun ed25519-hash (&rest messages)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((digest (make-digest :sha512)))
    (dolist (m messages)
      (update-digest digest m))
    (produce-digest digest)))

(defun ed25519-public-key (sk)
  "Compute the public key associated to the private key SK."
  (declare (type (simple-array (unsigned-byte 8) (*)) sk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((h (ed25519-hash sk)))
    (setf h (subseq h 0 (/ +ed25519-bits+ 8)))
    (setf (ldb (byte 3 0) (elt h 0)) 0)
    (setf (ldb (byte 2 6) (elt h (- (/ +ed25519-bits+ 8) 1))) 1)
    (let ((a (ec-decode-scalar :ed25519 h)))
      (ec-encode-point (ec-scalar-mult ed25519-base-point a)))))

(defmethod make-signature ((kind (eql :ed25519)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'ed25519
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'ed25519
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :ed25519)) signature)
  (let ((length (length signature)))
    (if (/= length (/ +ed25519-bits+ 4))
        (error 'invalid-signature-length :kind 'ed25519)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defun ed25519-sign (m sk pk)
  (declare (type (simple-array (unsigned-byte 8) (*)) m sk pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((h (ed25519-hash sk)))
    (setf (ldb (byte 3 0) (elt h 0)) 0)
    (setf (ldb (byte 2 6) (elt h (- (/ +ed25519-bits+ 8) 1))) 1)
    (let* ((a (ec-decode-scalar :ed25519 (subseq h 0 (/ +ed25519-bits+ 8))))
           (rh (ed25519-hash (subseq h (/ +ed25519-bits+ 8) (/ +ed25519-bits+ 4)) m))
           (ri (mod (ec-decode-scalar :ed25519 rh) +ed25519-l+))
           (r (ec-scalar-mult ed25519-base-point ri))
           (rp (ec-encode-point r))
           (k (mod (ec-decode-scalar :ed25519 (ed25519-hash rp pk m)) +ed25519-l+))
           (s (mod (+ (* k a) ri) +ed25519-l+)))
      (declare (type integer a ri k s)
               (type (simple-array (unsigned-byte 8) (*)) rh)
               (type ed25519-point r))
      (make-signature :ed25519 :r rp :s (ec-encode-scalar :ed25519 s)))))

(defun ed25519-verify (s m pk)
  (declare (type (simple-array (unsigned-byte 8) (*)) s m pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length s) (/ +ed25519-bits+ 4))
    (error 'invalid-signature-length :kind 'ed25519))
  (unless (= (length pk) (/ +ed25519-bits+ 8))
    (error 'invalid-public-key-length :kind 'ed25519))
  (let* ((signature-elements (destructure-signature :ed25519 s))
         (r (getf signature-elements :r))
         (rp (ec-decode-point :ed25519 r))
         (s (ec-decode-scalar :ed25519 (getf signature-elements :s)))
         (a (ec-decode-point :ed25519 pk))
         (h (mod (ec-decode-scalar :ed25519 (ed25519-hash r pk m)) +ed25519-l+))
         (res1 (ec-scalar-mult ed25519-base-point s))
         (res2 (ec-add rp (ed25519-scalar-mult-general a h))))
    (declare (type (simple-array (unsigned-byte 8) (*)) r)
             (type integer s h)
             (type ed25519-point rp a res1 res2))
    (and (< s +ed25519-l+)
         (ec-point-equal res1 res2))))

(defmethod make-public-key ((kind (eql :ed25519)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'ed25519
           :parameter 'y
           :description "public key"))
  (make-instance 'ed25519-public-key :y y))

(defmethod destructure-public-key ((public-key ed25519-public-key))
  (list :y (ed25519-key-y public-key)))

(defmethod make-private-key ((kind (eql :ed25519)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'ed25519
           :parameter 'x
           :description "private key"))
  (make-instance 'ed25519-private-key :x x :y (or y (ed25519-public-key x))))

(defmethod destructure-private-key ((private-key ed25519-private-key))
  (list :x (ed25519-key-x private-key)
        :y (ed25519-key-y private-key)))

(defmethod sign-message ((key ed25519-private-key) message &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (sk (ed25519-key-x key))
        (pk (ed25519-key-y key)))
    (ed25519-sign (subseq message start end) sk pk)))

(defmethod verify-signature ((key ed25519-public-key) message signature &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (pk (ed25519-key-y key)))
    (ed25519-verify signature (subseq message start end) pk)))

(defmethod generate-key-pair ((kind (eql :ed25519)) &key &allow-other-keys)
  (let* ((sk (random-data (/ +ed25519-bits+ 8)))
         (pk (ed25519-public-key sk)))
    (values (make-private-key :ed25519 :x sk :y pk)
            (make-public-key :ed25519 :y pk))))
