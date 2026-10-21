;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; curve448.lisp -- implementation of the curve448 Diffie-Hellman function

(in-package :crypto)


;;; class definitions

(defclass curve448-public-key ()
  ((y :initarg :y :reader curve448-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass curve448-private-key ()
  ((x :initarg :x :reader curve448-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader curve448-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass curve448-point ()
    ;; Internally, we represent a point (x, y) using only the projective
    ;; coordinate (X, Z) for x, with x = X / Z.
    ((x :initarg :x :type integer)
     (z :initarg :z :type integer)))
  (defmethod make-load-form ((p curve448-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constants and function definitions

(defconstant +curve448-bits+ 448)
(defconstant +curve448-p+ 726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439)
(defconstant +curve448-a24+ 39081)

(defconst +curve448-g+
  (make-instance 'curve448-point :x 5 :z 1))


(defmethod ec-scalar-inv ((kind (eql :curve448)) n)
  (expt-mod n (- +curve448-p+ 2) +curve448-p+))

(defun curve448-double-and-add (x1 z1 x2 z2 x3)
  "Point doubling and addition on curve448 curve."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer x1 z1 x2 z2 x3))
  (let* ((t1 (goldilocks-reduce (+ x1 z1)))
         (t2 (goldilocks-reduce (- x1 z1)))
         (t3 (goldilocks-reduce (- x2 z2)))
         (t4 (goldilocks-reduce (* t1 t3)))
         (t5 (goldilocks-reduce (+ x2 z2)))
         (t6 (goldilocks-reduce (* t2 t5)))
         (t7 (goldilocks-reduce (- t4 t6)))
         (t8 (goldilocks-reduce (* t7 t7)))
         (z5 (goldilocks-reduce (* x3 t8)))
         (t9 (goldilocks-reduce (+ t4 t6)))
         (x5 (goldilocks-reduce (* t9 t9)))
         (t10 (goldilocks-reduce (* t1 t1)))
         (t11 (goldilocks-reduce (* t2 t2)))
         (x4 (goldilocks-reduce (* t10 t11)))
         (t12 (goldilocks-reduce (- t10 t11)))
         (t13 (goldilocks-reduce (* t12 +curve448-a24+)))
         (t14 (goldilocks-reduce (+ t13 t10)))
         (z4 (goldilocks-reduce (* t14 t12))))
    (declare (type integer t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 t12 t13 t14 x4 z4 x5 z5))
    (values x4 z4 x5 z5)))

;;; ------------------------------------------------------------------
;;; The scalar multiplication in the limb field
;;;;
;;; As in Ed448, the point stays as it is, as a bignum, and the scalar
;;; multiplication is done in the limb field, where the product of two
;;; field elements is four times faster than the product of two
;;; bignums and the division that follows it.

(defvar +curve448-a24-limbs+
  (goldilocks-fe-from-int +curve448-a24+)
  "The constant a24 of the Curve448 curve, in limbs.")

(defun curve448-double-and-add-limbs (x1 z1 x2 z2 x3)
  "The double and add of the Curve448 curve, in limbs.
The four coordinates are returned as multiple values."
  (declare (type goldilocks-fe x1 z1 x2 z2 x3)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((t1 (goldilocks-fe-add x1 z1))
         (t2 (goldilocks-fe-sub x1 z1))
         (t3 (goldilocks-fe-sub x2 z2))
         (t4 (goldilocks-fe-mul t1 t3))
         (t5 (goldilocks-fe-add x2 z2))
         (t6 (goldilocks-fe-mul t2 t5))
         (t7 (goldilocks-fe-sub t4 t6))
         (t8 (goldilocks-fe-mul t7 t7))
         (z5 (goldilocks-fe-mul x3 t8))
         (t9 (goldilocks-fe-add t4 t6))
         (x5 (goldilocks-fe-mul t9 t9))
         (t10 (goldilocks-fe-mul t1 t1))
         (t11 (goldilocks-fe-mul t2 t2))
         (x4 (goldilocks-fe-mul t10 t11))
         (t12 (goldilocks-fe-sub t10 t11))
         (t13 (goldilocks-fe-mul t12 +curve448-a24-limbs+))
         (t14 (goldilocks-fe-add t13 t10))
         (z4 (goldilocks-fe-mul t14 t12)))
    (values x4 z4 x5 z5)))

(defun curve448-ladder-mult-limbs (x n)
  "N times the point (X : 1), in the limb field.
X is a bignum, and the result is a point."
  (declare (type integer x n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (goldilocks-fe-from-int 1))
        (z1 (goldilocks-fe-from-int 0))
        (x2 (goldilocks-fe-from-int x))
        (z2 (goldilocks-fe-from-int 1))
        (x3 (goldilocks-fe-from-int x)))
    (loop for i from 447 downto 0 do
      (if (logbitp i n)
          (multiple-value-setq (x2 z2 x1 z1)
            (curve448-double-and-add-limbs x2 z2 x1 z1 x3))
          (multiple-value-setq (x1 z1 x2 z2)
            (curve448-double-and-add-limbs x1 z1 x2 z2 x3))))
    (make-instance 'curve448-point
                   :x (goldilocks-fe-to-int x1)
                   :z (goldilocks-fe-to-int z1))))

(defmethod ec-scalar-mult ((p curve448-point) n)
  ;; Point multiplication on curve448 curve using the Montgomery ladder,
  ;; in the limb field.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer n))
  (with-slots (x z) p
    (declare (type integer x z))
    (assert (= 1 z))
    (curve448-ladder-mult-limbs x n)))

(defmethod ec-make-point ((kind (eql :curve448)) &key x)
  (unless x
    (error 'missing-point-parameter
           :kind 'curve448
           :parameter 'x
           :description "coordinate"))
  (make-instance 'curve448-point :x x :z 1))

(defmethod ec-destructure-point ((p curve448-point))
  (with-slots (x z) p
    (declare (type integer x z))
    (let ((x (goldilocks-reduce (* x (ec-scalar-inv :curve448 z)))))
      (list :x x))))

(defmethod ec-encode-scalar ((kind (eql :curve448)) n)
  (integer-to-octets n :n-bits +curve448-bits+ :big-endian nil))

(defmethod ec-decode-scalar ((kind (eql :curve448)) octets)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x (ldb (byte +curve448-bits+ 0)
                (octets-to-integer octets :big-endian nil))))
    (setf (ldb (byte 2 0) x) 0)
    (setf (ldb (byte 1 (1- +curve448-bits+)) x) 1)
    x))

(defmethod ec-encode-point ((p curve448-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x)))
    (ec-encode-scalar :curve448 x)))

(defmethod ec-decode-point ((kind (eql :curve448)) octets)
  (let ((x (ldb (byte +curve448-bits+ 0)
                (octets-to-integer octets :big-endian nil))))
    (ec-make-point :curve448 :x x)))

(defun curve448-public-key (sk)
  "Compute the public key associated to the private key SK."
  (declare (type (simple-array (unsigned-byte 8) (*)) sk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((s (ec-decode-scalar :curve448 sk))
         (p (ec-scalar-mult +curve448-g+ s)))
    (ec-encode-point p)))

(defmethod make-public-key ((kind (eql :curve448)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'curve448
           :parameter 'y
           :description "public key"))
  (make-instance 'curve448-public-key :y y))

(defmethod destructure-public-key ((public-key curve448-public-key))
  (list :y (curve448-key-y public-key)))

(defmethod make-private-key ((kind (eql :curve448)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'curve448
           :parameter 'x
           :description "private key"))
  (make-instance 'curve448-private-key :x x :y (or y (curve448-public-key x))))

(defmethod destructure-private-key ((private-key curve448-private-key))
  (list :x (curve448-key-x private-key)
        :y (curve448-key-y private-key)))

(defmethod generate-key-pair ((kind (eql :curve448)) &key &allow-other-keys)
  (let ((sk (random-data (ceiling +curve448-bits+ 8))))
    (setf (ldb (byte 2 0) (elt sk 0)) 0)
    (setf (ldb (byte 1 7) (elt sk (- (ceiling +curve448-bits+ 8) 1))) 1)
    (let ((pk (curve448-public-key sk)))
      (values (make-private-key :curve448 :x sk :y pk)
              (make-public-key :curve448 :y pk)))))

(defmethod diffie-hellman ((private-key curve448-private-key) (public-key curve448-public-key))
  (let ((s (ec-decode-scalar :curve448 (curve448-key-x private-key)))
        (p (ec-decode-point :curve448 (curve448-key-y public-key))))
    (ec-encode-point (ec-scalar-mult p s))))
