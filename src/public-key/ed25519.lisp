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
    ((x :initarg :x :type integer)
     (y :initarg :y :type integer)
     (z :initarg :z :type integer)
     (w :initarg :w :type integer)))
  (defmethod make-load-form ((p ed25519-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constant, variable and function definitions

(defconstant +ed25519-bits+ 256)
(defconstant +ed25519-q+ 57896044618658097711785492504343953926634992332820282019728792003956564819949)
(defconstant +ed25519-l+ 7237005577332262213973186563042994240857116359379907606001950938285454250989)
(defconstant +ed25519-d+ 37095705934669439343138083508754565189542113879843219016388785533085940283555)
(defconstant +ed25519-i+ 19681161376707505956807079304988542015446066515923890162744021073123829784752)

(defconst +ed25519-b+
  (make-instance 'ed25519-point
                 :x 15112221349535400772501151409588531511454012693041857206046113283949847762202
                 :y 46316835694926478169428394003475163141307993866256225615783033603165251855960
                 :z 1
                 :w 46827403850823179245072216630277197565144205554125654976674165829533817101731))
(defconst +ed25519-point-at-infinity+
  (make-instance 'ed25519-point :x 0 :y 1 :z 1 :w 0))


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
  r)

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

  ;; Conditional subtract Q if result >= Q.  Result is in c[0..7] and
  ;; is under 2*Q (since X' < 2^256 + 38*37 < 2^256 + 1406 < 2*Q).
  ;; Reduce c[0..7] mod Q (bignum, simple, correct).
  (let ((x 0))
    (dotimes (i 8)
      (setf x (dpb (aref c i) (byte 32 (* i 32)) x)))
    (setf x (mod x +ed25519-q+))
    (dotimes (i 8)
      (setf (aref c i) (ldb (byte 32 (* i 32)) x))))

  c))

(defun ed25519-fe-mul (r a b)
  "R := (A * B) mod Q for reduced residues in limb form."
  (declare (type ed25519-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((prod (make-array 16 :element-type '(unsigned-byte 32) :initial-element 0)))
    (declare (type (simple-array (unsigned-byte 32) (16)) prod))
    (ed25519-fe-mul-raw prod a b)
    (ed25519-fe-normalize16 prod)
    (ed25519-fe-reduce16 prod)
    (dotimes (i 8 r)
      (setf (aref r i) (aref prod i)))))

(defun ed25519-fe-sq (r a)
  "R := A^2 mod Q."
  (declare (type ed25519-fe r a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (ed25519-fe-mul r a a))

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

(declaim (inline ed25519-fe-inv))
(defun ed25519-fe-inv (a)
  "Field element inverse via Fermat's little theorem: A^(Q-2) mod Q."
  (declare (type ed25519-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((result (ed25519-fe-from-int 1))
        (base a))
    (declare (type ed25519-fe result base))
    (loop for i from (1- (integer-length +ed25519-q-minus-2+)) downto 0
          do (ed25519-fe-sq result result)
             (when (logbitp i +ed25519-q-minus-2+)
               (ed25519-fe-mul result result base)))
    result))

(defmethod ec-scalar-inv ((kind (eql :ed25519)) n)
  ;; Field-element Fermat inversion is faster than bignum expt-mod.
  (declare (type integer n))
  (if (zerop n)
      0
      (ed25519-fe-to-int (ed25519-fe-inv (ed25519-fe-from-int n)))))

(defun ed25519-recover-x (y)
  "Recover the X coordinate of a point on ed25519 curve from the Y coordinate."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer y))
  (let* ((u (mod (1- (* y y)) +ed25519-q+))
         (v (mod (1+ (* +ed25519-d+ (1+ u))) +ed25519-q+))
         (v3 (mod (* v v v) +ed25519-q+))
         (uv3 (mod (* u v3) +ed25519-q+))
         (uv7 (mod (* uv3 v3 v) +ed25519-q+))
         (x (mod (* uv3 (expt-mod uv7 (/ (- +ed25519-q+ 5) 8) +ed25519-q+)) +ed25519-q+)))
    (declare (type integer u v v3 uv3 uv7 x))
    (unless (= u (mod (* v x x) +ed25519-q+))
      (setf x (mod (* x +ed25519-i+) +ed25519-q+)))
    (unless (evenp x)
      (setf x (- +ed25519-q+ x)))
    x))

(defmethod ec-add ((p ed25519-point) (q ed25519-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((dst (make-instance 'ed25519-point :x 0 :y 0 :z 0 :w 0)))
    (ed25519-add! dst p q)
    dst))

(defmethod ec-double ((p ed25519-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((dst (make-instance 'ed25519-point :x 0 :y 0 :z 0 :w 0)))
    (ed25519-double! dst p)
    dst))

(defun ed25519-double! (dst p)
  "DST := 2*P. DST must differ from P."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (let ((xf (ed25519-fe-from-int x1)) (yf (ed25519-fe-from-int y1))
          (zf (ed25519-fe-from-int z1)))
      (declare (type ed25519-fe xf yf zf))
      (let ((a (ed25519-fe-zero)) (b (ed25519-fe-zero)) (c (ed25519-fe-zero))
            (d (ed25519-fe-zero)) (i (ed25519-fe-zero)) (h (ed25519-fe-zero))
            (e (ed25519-fe-zero)) (g (ed25519-fe-zero)) (f (ed25519-fe-zero))
            (x2 (ed25519-fe-zero)) (y2 (ed25519-fe-zero)) (z2 (ed25519-fe-zero))
            (w2 (ed25519-fe-zero)))
        (declare (type ed25519-fe a b c d i h e g f x2 y2 z2 w2))
        (ed25519-fe-sq a xf)
        (ed25519-fe-sq b yf)
        (ed25519-fe-sq c zf)
        (ed25519-fe-add c c c)
        (ed25519-fe-add d xf yf)
        (ed25519-fe-sq i d)
        (ed25519-fe-add h a b)
        (ed25519-fe-sub e h i)
        (ed25519-fe-sub g a b)
        (ed25519-fe-add f c g)
        (ed25519-fe-mul x2 e f)
        (ed25519-fe-mul y2 g h)
        (ed25519-fe-mul z2 f g)
        (ed25519-fe-mul w2 e h)
        (setf (slot-value dst 'x) (ed25519-fe-to-int x2)
              (slot-value dst 'y) (ed25519-fe-to-int y2)
              (slot-value dst 'z) (ed25519-fe-to-int z2)
              (slot-value dst 'w) (ed25519-fe-to-int w2))
        dst))))

(defun ed25519-add! (dst p q)
  "DST := P + Q. DST must differ from P and Q."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z) (w1 w)) p
    (declare (type integer x1 y1 z1 w1))
    (with-slots ((x2 x) (y2 y) (z2 z) (w2 w)) q
      (declare (type integer x2 y2 z2 w2))
      (let ((xf1 (ed25519-fe-from-int x1)) (yf1 (ed25519-fe-from-int y1))
            (zf1 (ed25519-fe-from-int z1)) (wf1 (ed25519-fe-from-int w1))
            (xf2 (ed25519-fe-from-int x2)) (yf2 (ed25519-fe-from-int y2))
            (zf2 (ed25519-fe-from-int z2)) (wf2 (ed25519-fe-from-int w2)))
        (declare (type ed25519-fe xf1 yf1 zf1 wf1 xf2 yf2 zf2 wf2))
        (let ((ymx1 (ed25519-fe-zero)) (ypx1 (ed25519-fe-zero))
              (ymx2 (ed25519-fe-zero)) (ypx2 (ed25519-fe-zero))
              (a (ed25519-fe-zero)) (b (ed25519-fe-zero)) (i (ed25519-fe-zero))
              (c (ed25519-fe-zero)) (d (ed25519-fe-zero)) (e (ed25519-fe-zero))
              (f (ed25519-fe-zero)) (g (ed25519-fe-zero)) (h (ed25519-fe-zero))
              (x3 (ed25519-fe-zero)) (y3 (ed25519-fe-zero)) (z3 (ed25519-fe-zero))
              (w3 (ed25519-fe-zero)) (dconst (ed25519-fe-from-int +ed25519-d+)))
          (declare (type ed25519-fe ymx1 ypx1 ymx2 ypx2 a b i c d e f g h x3 y3 z3 w3 dconst))
          (ed25519-fe-sub ymx1 yf1 xf1)
          (ed25519-fe-add ypx1 yf1 xf1)
          (ed25519-fe-sub ymx2 yf2 xf2)
          (ed25519-fe-add ypx2 yf2 xf2)
          (ed25519-fe-mul a ymx1 ymx2)
          (ed25519-fe-mul b ypx1 ypx2)
          (ed25519-fe-mul i wf1 wf2)
          (ed25519-fe-mul c i dconst)
          (ed25519-fe-add c c c)
          (ed25519-fe-mul d zf1 zf2)
          (ed25519-fe-add d d d)
          (ed25519-fe-sub e b a)
          (ed25519-fe-sub f d c)
          (ed25519-fe-add g d c)
          (ed25519-fe-add h b a)
          (ed25519-fe-mul x3 e f)
          (ed25519-fe-mul y3 g h)
          (ed25519-fe-mul z3 f g)
          (ed25519-fe-mul w3 e h)
          (setf (slot-value dst 'x) (ed25519-fe-to-int x3)
                (slot-value dst 'y) (ed25519-fe-to-int y3)
                (slot-value dst 'z) (ed25519-fe-to-int z3)
                (slot-value dst 'w) (ed25519-fe-to-int w3))
          dst)))))(declaim (inline ed25519-point-copy!))
(defun ed25519-point-copy! (dst src)
  "Copy point SRC into DST."
  (declare (type ed25519-point dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (slot-value dst 'x) (slot-value src 'x)
        (slot-value dst 'y) (slot-value src 'y)
        (slot-value dst 'z) (slot-value src 'z)
        (slot-value dst 'w) (slot-value src 'w))
  dst)

;;; Scalar multiplication for arbitrary points (not the generator).
;;; Uses destination-based Montgomery ladder to avoid consing intermediate
;;; points.  This is used by ed25519-verify for the public-key multiplication.
(defun ed25519-scalar-mult-general (p e)
  "Compute E*P for arbitrary point P using destination-based ladder.
No consing of intermediate points - uses 4 pre-allocated point objects."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (when (minusp e)
    (error "negative scalars not supported by ed25519-scalar-mult-general"))
  (let* ((r0 (make-instance 'ed25519-point :x 0 :y 0 :z 0 :w 0))
         (r1 (make-instance 'ed25519-point :x 0 :y 0 :z 0 :w 0))
         (t0 (make-instance 'ed25519-point :x 0 :y 0 :z 0 :w 0))
         (t1 (make-instance 'ed25519-point :x 0 :y 0 :z 0 :w 0)))
    ;; Initialize r0 = infinity (0,1,1,0), r1 = P
    (setf (slot-value r0 'x) 0 (slot-value r0 'y) 1
          (slot-value r0 'z) 1 (slot-value r0 'w) 0)
    (setf (slot-value r1 'x) (slot-value p 'x)
          (slot-value r1 'y) (slot-value p 'y)
          (slot-value r1 'z) (slot-value p 'z)
          (slot-value r1 'w) (slot-value p 'w))
    ;; Process bits from MSB to LSB
    (do ((i (1- (integer-length e)) (1- i)))
        ((minusp i) r0)
      (if (logbitp i e)
          (progn
            (ed25519-add! t0 r0 r1)
            (ed25519-double! t1 r1)
            ;; Copy t0 -> r0, t1 -> r1 (no aliasing: copy slot values)
            (setf (slot-value r0 'x) (slot-value t0 'x)
                  (slot-value r0 'y) (slot-value t0 'y)
                  (slot-value r0 'z) (slot-value t0 'z)
                  (slot-value r0 'w) (slot-value t0 'w))
            (setf (slot-value r1 'x) (slot-value t1 'x)
                  (slot-value r1 'y) (slot-value t1 'y)
                  (slot-value r1 'z) (slot-value t1 'z)
                  (slot-value r1 'w) (slot-value t1 'w)))
          (progn
            (ed25519-add! t0 r1 r0)
            (ed25519-double! t1 r0)
            ;; Copy t0 -> r1, t1 -> r0
            (setf (slot-value r1 'x) (slot-value t0 'x)
                  (slot-value r1 'y) (slot-value t0 'y)
                  (slot-value r1 'z) (slot-value t0 'z)
                  (slot-value r1 'w) (slot-value t0 'w))
            (setf (slot-value r0 'x) (slot-value t1 'x)
                  (slot-value r0 'y) (slot-value t1 'y)
                  (slot-value r0 'z) (slot-value t1 'z)
                  (slot-value r0 'w) (slot-value t1 'w)))))))

;;; Fixed-base comb for the generator point.
;;;
;;; SIGN-MESSAGE and key generation always multiply G by a secret scalar.
;;; A 4-bit window needs 64 adds and 256 doublings instead of the
;;; ladder's ~128 adds and 255 doublings.

(defvar *ed25519-base-table* nil
  "Precomputed I * G for I in [0, 16). Built on first use.")

(defun ed25519-ensure-base-table ()
  (or *ed25519-base-table*
      (setf *ed25519-base-table*
            (let ((table (make-array 16)))
              (setf (aref table 0) +ed25519-point-at-infinity+)
              (setf (aref table 1) +ed25519-b+)
              (loop for i from 2 below 16
                    do (setf (aref table i)
                             (if (evenp i)
                                 (ec-double (aref table (ash i -1)))
                                 (ec-add (aref table (1- i)) +ed25519-b+))))
              table))))

(declaim (inline ed25519-select-base))
(defun ed25519-select-base (table v)
  "Select TABLE[V].  Linear scan over the small cached table."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type (integer 0 15) v))
  (let ((sel +ed25519-point-at-infinity+))
    (dotimes (i 16 sel)
      (when (= i v)
        (setf sel (aref table i))))))

(defun ed25519-base-mult (k)
  "Fixed-base 4-bit comb for G (secret scalar, fixed schedule).
Destination-based: reuses pre-allocated point buffers instead of
consing a new point per ec-double/ec-add."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  (let ((table (ed25519-ensure-base-table))
        (acc +ed25519-point-at-infinity+)
        (tmp (make-instance 'ed25519-point :x 0 :y 0 :z 0 :w 0))
        (out (make-instance 'ed25519-point :x 0 :y 0 :z 0 :w 0))
        (sel (make-instance 'ed25519-point :x 0 :y 0 :z 0 :w 0)))
    (loop for j from 63 downto 0 do          ; 256 bits / 4 = 64 nibbles
      (dotimes (i 4)
        (ed25519-double! tmp acc)
        (ed25519-point-copy! acc tmp))
      (setf sel (ed25519-select-base table (ldb (byte 4 (* j 4)) k)))
      (unless (eq sel +ed25519-point-at-infinity+)
        (ed25519-add! out acc sel)
        (setf acc out)))
    acc))

(defmethod ec-scalar-mult ((p ed25519-point) e)
  ;; Secret scalars use the fixed-schedule ladder.  The generator G uses
  ;; the faster fixed-base comb.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (if (and (eq p +ed25519-b+) (not (minusp e)))
      (ed25519-base-mult e)
      (do ((r0 +ed25519-point-at-infinity+)
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
    (declare (type integer x y z w))
    (let ((xx (ed25519-fe-from-int x)) (yy (ed25519-fe-from-int y))
          (zz (ed25519-fe-from-int z)) (ww (ed25519-fe-from-int w))
          (a (ed25519-fe-zero)) (b (ed25519-fe-zero))
          (dconst (ed25519-fe-from-int +ed25519-d+)) (prod (ed25519-fe-zero)))
      (declare (type ed25519-fe xx yy zz ww a b dconst prod))
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
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (let ((xf1 (ed25519-fe-from-int x1)) (yf1 (ed25519-fe-from-int y1))
            (zf1 (ed25519-fe-from-int z1))
            (xf2 (ed25519-fe-from-int x2)) (yf2 (ed25519-fe-from-int y2))
            (zf2 (ed25519-fe-from-int z2))
            (t1 (ed25519-fe-zero)) (t2 (ed25519-fe-zero))
            (u1 (ed25519-fe-zero)) (u2 (ed25519-fe-zero)))
        (declare (type ed25519-fe xf1 yf1 zf1 xf2 yf2 zf2 t1 t2 u1 u2))
        (ed25519-fe-mul t1 xf1 zf2)
        (ed25519-fe-mul t2 xf2 zf1)
        (ed25519-fe-sub t1 t1 t2)
        (ed25519-fe-mul u1 yf1 zf2)
        (ed25519-fe-mul u2 yf2 zf1)
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
  (let* ((wf (ed25519-fe-zero))
         (xf (ed25519-fe-from-int x))
         (yf (ed25519-fe-from-int y))
         (zf (ed25519-fe-from-int 1)))
    (declare (type ed25519-fe wf xf yf zf))
    (ed25519-fe-mul wf xf yf)
    (let ((p (make-instance 'ed25519-point :x x :y y :z 1 :w (ed25519-fe-to-int wf))))
      (declare (type ed25519-point p))
      (if (ec-point-on-curve-p p)
          p
          (error 'invalid-curve-point :kind 'ed25519)))))

(defmethod ec-destructure-point ((p ed25519-point))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((xf (ed25519-fe-from-int x))
           (yf (ed25519-fe-from-int y))
           (zf (ed25519-fe-from-int z))
           (invz (ed25519-fe-inv zf))
           (xr (ed25519-fe-zero)) (yr (ed25519-fe-zero)))
      (declare (type ed25519-fe xf yf zf invz xr yr))
      (ed25519-fe-mul xr xf invz)
      (ed25519-fe-mul yr yf invz)
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
      (ec-encode-point (ec-scalar-mult +ed25519-b+ a)))))

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
           (r (ec-scalar-mult +ed25519-b+ ri))
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
         (res1 (ec-scalar-mult +ed25519-b+ s))
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
