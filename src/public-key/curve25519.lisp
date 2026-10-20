;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; curve25519.lisp -- implementation of the curve25519 Diffie-Hellman function

(in-package :crypto)


;;; class definitions

(defclass curve25519-public-key ()
  ((y :initarg :y :reader curve25519-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass curve25519-private-key ()
  ((x :initarg :x :reader curve25519-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader curve25519-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass curve25519-point ()
    ;; Internally, we represent a point (x, y) using only the projective
    ;; coordinate (X, Z) for x, with x = X / Z.
    ((x :initarg :x :type ed25519-fe)
     (z :initarg :z :type ed25519-fe)))
  (defmethod make-load-form ((p curve25519-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constants and function definitions

(defconstant +curve25519-bits+ 256)
(defconstant +curve25519-p+ 57896044618658097711785492504343953926634992332820282019728792003956564819949)
(defconstant +curve25519-a24+ 121666)

(defconst +curve25519-g+
  (make-instance 'curve25519-point
                 :x (ed25519-fe-from-int 9)
                 :z (ed25519-fe-from-int 1)))


(defmethod ec-scalar-inv ((kind (eql :curve25519)) n)
  (declare (type integer n))
  (if (zerop n)
      0
      (ed25519-fe-to-int (ed25519-fe-inv (ed25519-fe-from-int n)))))

(defun curve25519-double-and-add (x1 z1 x2 z2 x3)
  "Point doubling and addition on curve25519 curve, using the shared
2^255-19 field layer (see src/public-key/ed25519.lisp)."
  (declare (type ed25519-fe x1 z1 x2 z2 x3)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((t1 (ed25519-fe-zero)) (t2 (ed25519-fe-zero)) (t3 (ed25519-fe-zero))
        (t4 (ed25519-fe-zero)) (t5 (ed25519-fe-zero)) (t6 (ed25519-fe-zero))
        (t7 (ed25519-fe-zero)) (t8 (ed25519-fe-zero)) (t9 (ed25519-fe-zero))
        (t10 (ed25519-fe-zero)) (t11 (ed25519-fe-zero)) (t12 (ed25519-fe-zero))
        (t13 (ed25519-fe-zero)) (t14 (ed25519-fe-zero))
        (x4 (ed25519-fe-zero)) (z4 (ed25519-fe-zero))
        (x5 (ed25519-fe-zero)) (z5 (ed25519-fe-zero)))
    (declare (type ed25519-fe t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 t12 t13 t14
                               x4 z4 x5 z5))
    (ed25519-fe-add t1 x1 z1)
    (ed25519-fe-sq t2 t1)
    (ed25519-fe-sub t3 x1 z1)
    (ed25519-fe-sq t4 t3)
    (ed25519-fe-sub t5 t2 t4)
    (ed25519-fe-add t6 x2 z2)
    (ed25519-fe-sub t7 x2 z2)
    (ed25519-fe-mul t8 t1 t7)
    (ed25519-fe-mul t9 t3 t6)
    (ed25519-fe-add t10 t8 t9)
    (ed25519-fe-sub t11 t8 t9)
    (ed25519-fe-mul x4 t2 t4)
    (ed25519-fe-mul t12 t5 (ed25519-fe-from-int +curve25519-a24+))
    (ed25519-fe-add t13 t4 t12)
    (ed25519-fe-mul z4 t5 t13)
    (ed25519-fe-sq x5 t10)
    (ed25519-fe-sq t14 t11)
    (ed25519-fe-mul z5 x3 t14)
    (values x4 z4 x5 z5)))

(defmethod ec-scalar-mult ((p curve25519-point) n)
  ;; Point multiplication on curve22519 curve using the Montgomery ladder.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer n))
  (with-slots (x z) p
    (declare (type ed25519-fe x z))
    (do ((x1 (ed25519-fe-from-int 1))
         (z1 (ed25519-fe-zero))
         (x2 (ed25519-fe-copy x))
         (z2 (ed25519-fe-from-int 1))
         (i 254 (1- i)))
        ((minusp i) (make-instance 'curve25519-point :x x1 :z z1))
      (declare (type ed25519-fe x1 z1 x2 z2)
               (type fixnum i))
      (if (logbitp i n)
          (multiple-value-setq (x2 z2 x1 z1)
            (curve25519-double-and-add x2 z2 x1 z1 x))
          (multiple-value-setq (x1 z1 x2 z2)
            (curve25519-double-and-add x1 z1 x2 z2 x))))))

(defmethod ec-make-point ((kind (eql :curve25519)) &key x)
  (unless x
    (error 'missing-point-parameter
           :kind 'curve25519
           :parameter 'x
           :description "coordinate"))
  (make-instance 'curve25519-point
                 :x (ed25519-fe-from-int x)
                 :z (ed25519-fe-from-int 1)))

(defmethod ec-destructure-point ((p curve25519-point))
  (with-slots (x z) p
    (declare (type ed25519-fe x z))
    (let ((x (ed25519-fe-mul x (ed25519-fe-inv z))))
      (list :x (ed25519-fe-to-int x)))))

(defmethod ec-encode-scalar ((kind (eql :curve25519)) n)
  (integer-to-octets n :n-bits +curve25519-bits+ :big-endian nil))

(defmethod ec-decode-scalar ((kind (eql :curve25519)) octets)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x (ldb (byte (1- +curve25519-bits+) 0)
                (octets-to-integer octets :big-endian nil))))
    (setf (ldb (byte 3 0) x) 0)
    (setf (ldb (byte 1 (- +curve25519-bits+ 2)) x) 1)
    x))

(defmethod ec-encode-point ((p curve25519-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x)))
    (ec-encode-scalar :curve25519 x)))

(defmethod ec-decode-point ((kind (eql :curve25519)) octets)
  (let ((x (ldb (byte (1- +curve25519-bits+) 0)
                (octets-to-integer octets :big-endian nil))))
    (make-instance 'curve25519-point
                   :x (ed25519-fe-from-int x)
                   :z (ed25519-fe-from-int 1))))

(defun curve25519-public-key (sk)
  "Compute the public key associated to the private key SK."
  (declare (type (simple-array (unsigned-byte 8) (*)) sk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((s (ec-decode-scalar :curve25519 sk))
         (p (ec-scalar-mult +curve25519-g+ s)))
    (ec-encode-point p)))

(defmethod make-public-key ((kind (eql :curve25519)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'curve25519
           :parameter 'y
           :description "public key"))
  (make-instance 'curve25519-public-key :y y))

(defmethod destructure-public-key ((public-key curve25519-public-key))
  (list :y (curve25519-key-y public-key)))

(defmethod make-private-key ((kind (eql :curve25519)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'curve25519
           :parameter 'x
           :description "private key"))
  (make-instance 'curve25519-private-key :x x :y (or y (curve25519-public-key x))))

(defmethod destructure-private-key ((private-key curve25519-private-key))
  (list :x (curve25519-key-x private-key)
        :y (curve25519-key-y private-key)))

(defmethod generate-key-pair ((kind (eql :curve25519)) &key &allow-other-keys)
  (let ((sk (random-data (/ +curve25519-bits+ 8))))
    (setf (ldb (byte 3 0) (elt sk 0)) 0)
    (setf (ldb (byte 2 6) (elt sk (- (/ +curve25519-bits+ 8) 1))) 1)
    (let ((pk (curve25519-public-key sk)))
      (values (make-private-key :curve25519 :x sk :y pk)
              (make-public-key :curve25519 :y pk)))))

(defmethod diffie-hellman ((private-key curve25519-private-key) (public-key curve25519-public-key))
  (let ((s (ec-decode-scalar :curve25519 (curve25519-key-x private-key)))
        (p (ec-decode-point :curve25519 (curve25519-key-y public-key))))
    (ec-encode-point (ec-scalar-mult p s))))
