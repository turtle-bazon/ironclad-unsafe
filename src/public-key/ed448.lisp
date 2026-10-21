;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ed448.lisp -- implementation of the ed448 signature algorithm

(in-package :crypto)


;;; class definitions

(defclass ed448-public-key ()
  ((y :initarg :y :reader ed448-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass ed448-private-key ()
  ((x :initarg :x :reader ed448-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader ed448-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass ed448-point ()
    ;; Internally, a point (x, y) is represented using the projective
    ;; coordinates (X, Y, Z), with x = X / Z and y = Y / Z.
    ((x :initarg :x :type integer)
     (y :initarg :y :type integer)
     (z :initarg :z :type integer)))
  (defmethod make-load-form ((p ed448-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constant and function definitions

(defconstant +ed448-bits+ 456)
(defconstant +ed448-q+ 726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439)
(defconstant +ed448-l+ 181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779)
(defconstant +ed448-d+ -39081)

(defconst +ed448-b+
  (make-instance 'ed448-point
                 :x 224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710
                 :y 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660
                 :z 1))
(defconst +ed448-point-at-infinity+
  (make-instance 'ed448-point :x 0 :y 1 :z 1))

;;; ------------------------------------------------------------------
;;; The scalar multiplication in the limb field
;;;;
;;; The points stay as they are, as bignums, and the scalar
;;; multiplication is done in the limb field, where the product of two
;;; field elements is four times faster than the product of two
;;; bignums and the division that follows it.  The coordinates are
;;; converted at each end of the multiplication, which costs about a
;;; microsecond and is nothing next to the multiplication itself.

(defvar +ed448-d-limbs+
  (goldilocks-fe-from-int (+ +ed448-q+ +ed448-d+))
  "The constant d of the Ed448 curve, in limbs.")

(defun ed448-point-double-limbs (x1 y1 z1)
  "The double of the point (X1 : Y1 : Z1), in limbs.
The three coordinates are returned as multiple values."
  (declare (type goldilocks-fe x1 y1 z1)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((a (goldilocks-fe-add x1 y1))
         (b (goldilocks-fe-mul a a))
         (c (goldilocks-fe-mul x1 x1))
         (d (goldilocks-fe-mul y1 y1))
         (e (goldilocks-fe-add c d))
         (f (goldilocks-fe-mul z1 z1))
         (g (goldilocks-fe-sub e (goldilocks-fe-add f f)))
         (x2 (goldilocks-fe-mul (goldilocks-fe-sub b e) g))
         (y2 (goldilocks-fe-mul (goldilocks-fe-sub c d) e))
         (z2 (goldilocks-fe-mul e g)))
    (values x2 y2 z2)))

(defun ed448-point-add-limbs (x1 y1 z1 x2 y2 z2)
  "The sum of the points (X1 : Y1 : Z1) and (X2 : Y2 : Z2), in limbs.
The three coordinates are returned as multiple values."
  (declare (type goldilocks-fe x1 y1 z1 x2 y2 z2)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((a (goldilocks-fe-mul z1 z2))
         (b (goldilocks-fe-mul a a))
         (c (goldilocks-fe-mul x1 x2))
         (d (goldilocks-fe-mul y1 y2))
         (k (goldilocks-fe-mul c d))
         (e (goldilocks-fe-mul +ed448-d-limbs+ k))
         (f (goldilocks-fe-sub b e))
         (g (goldilocks-fe-add b e))
         (h (goldilocks-fe-mul (goldilocks-fe-add x1 y1) (goldilocks-fe-add x2 y2)))
         (i (goldilocks-fe-mul a f))
         (j (goldilocks-fe-mul a g))
         (x3 (goldilocks-fe-mul i (goldilocks-fe-sub (goldilocks-fe-sub h c) d)))
         (y3 (goldilocks-fe-mul j (goldilocks-fe-sub d c)))
         (z3 (goldilocks-fe-mul f g)))
    (values x3 y3 z3)))

(defun ed448-ladder-mult-limbs (x y z e)
  "E times the point (X : Y : Z), in the limb field.
X, Y and Z are bignums, and the result is a point."
  (declare (type integer x y z e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (when (minusp e)
    (error "negative scalars are not supported by ed448-ladder-mult-limbs"))
  (if (zerop e)
      +ed448-point-at-infinity+
      (let* ((r0x (goldilocks-fe-from-int 0))
             (r0y (goldilocks-fe-from-int 1))
             (r0z (goldilocks-fe-from-int 1))
             (r1x (goldilocks-fe-from-int x))
             (r1y (goldilocks-fe-from-int y))
             (r1z (goldilocks-fe-from-int z))
             (tx nil) (ty nil) (tz nil) (ux nil) (uy nil) (uz nil))
        (declare (ignorable tx ty tz ux uy uz))
        (loop for i from (1- +ed448-bits+) downto 0 do
          (if (logbitp i e)
              (progn
                (multiple-value-setq (tx ty tz)
                  (ed448-point-add-limbs r0x r0y r0z r1x r1y r1z))
                (multiple-value-setq (ux uy uz)
                  (ed448-point-double-limbs r1x r1y r1z))
                (setf r0x tx r0y ty r0z tz
                      r1x ux r1y uy r1z uz))
              (progn
                (multiple-value-setq (tx ty tz)
                  (ed448-point-add-limbs r0x r0y r0z r1x r1y r1z))
                (multiple-value-setq (ux uy uz)
                  (ed448-point-double-limbs r0x r0y r0z))
                (setf r1x tx r1y ty r1z tz
                      r0x ux r0y uy r0z uz))))
        (make-instance 'ed448-point
                       :x (goldilocks-fe-to-int r0x)
                       :y (goldilocks-fe-to-int r0y)
                       :z (goldilocks-fe-to-int r0z)))))

(defvar *ed448-base-table-limbs* nil
  "Precomputed I * G for I in [0, 16), in limbs.")

(defun ed448-ensure-base-table-limbs ()
  (or *ed448-base-table-limbs*
      (setf *ed448-base-table-limbs*
            (let ((table (make-array 16))
                  (x nil) (y nil) (z nil))
              (declare (ignorable x y z))
              (setf (aref table 0) (vector (goldilocks-fe-from-int 0)
                                           (goldilocks-fe-from-int 1)
                                           (goldilocks-fe-from-int 1))
                    (aref table 1) (vector (goldilocks-fe-from-int
                                            (slot-value +ed448-b+ 'x))
                                           (goldilocks-fe-from-int
                                            (slot-value +ed448-b+ 'y))
                                           (goldilocks-fe-from-int 1)))
              (loop for i from 2 below 16
                    do (progn
                         (multiple-value-setq (x y z)
                           (if (evenp i)
                               (ed448-point-double-limbs
                                (aref (aref table (ash i -1)) 0)
                                (aref (aref table (ash i -1)) 1)
                                (aref (aref table (ash i -1)) 2))
                               (ed448-point-add-limbs
                                (aref (aref table (1- i)) 0)
                                (aref (aref table (1- i)) 1)
                                (aref (aref table (1- i)) 2)
                                (aref (aref table 1) 0)
                                (aref (aref table 1) 1)
                                (aref (aref table 1) 2))))
                         (setf (aref table i) (vector x y z))))
              table))))

(defun ed448-base-mult-limbs (k)
  "The fixed-base comb for G, in the limb field."
  (declare (type integer k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (ed448-ensure-base-table-limbs))
        (ax (goldilocks-fe-from-int 0))
        (ay (goldilocks-fe-from-int 1))
        (az (goldilocks-fe-from-int 1))
        (x nil) (y nil) (z nil))
    (declare (ignorable x y z))
    (loop for j from 113 downto 0 do          ; 456 bits / 4 = 114 nibbles
      (progn
        (dotimes (i 4)
          (multiple-value-setq (x y z) (ed448-point-double-limbs ax ay az))
          (setf ax x ay y az z))
        ;; The point is selected with a linear scan, so that the time
        ;; does not depend on the secret scalar.
        (let ((v (ldb (byte 4 (* j 4)) k)))
          (dotimes (i 16)
            (when (= i v)
              (multiple-value-setq (x y z)
                (ed448-point-add-limbs ax ay az
                                       (aref (aref table i) 0)
                                       (aref (aref table i) 1)
                                       (aref (aref table i) 2)))
              (setf ax x ay y az z))))))
    (make-instance 'ed448-point
                   :x (goldilocks-fe-to-int ax)
                   :y (goldilocks-fe-to-int ay)
                   :z (goldilocks-fe-to-int az))))


(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun ed448-dom (x y)
    (declare (type (unsigned-byte 8) x)
             (type (simple-array (unsigned-byte 8) (*)) y)
             (optimize (speed 3) (safety 0) (space 0) (debug 0)))
    (when (> (length y) 255)
      (error 'ironclad-error
             :format-control "The Y array is to big."))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (map 'vector #'char-code "SigEd448")
                 (vector x)
                 (vector (length y))
                 y)))
;; Ed448 (x = 0), no context (y = #())
(defconst +ed448-dom+ (ed448-dom 0 (make-array 0 :element-type '(unsigned-byte 8))))

(defmethod ec-scalar-inv ((kind (eql :ed448)) n)
  (expt-mod n (- +ed448-q+ 2) +ed448-q+))

(defun ed448-recover-x (y)
  "Recover the X coordinate of a point on ed448 curve from the Y coordinate."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer y))
  (let* ((u (goldilocks-reduce (1- (* y y))))
         (v (goldilocks-reduce (1- (* +ed448-d+ (1+ u)))))
         (uv (goldilocks-reduce (* u v)))
         (u3v (goldilocks-reduce (* u u uv)))
         (u5v3 (goldilocks-reduce (* u3v uv uv)))
         ;; The value recovered here depends only on the public key, so
         ;; the variable-time sliding-window exponentiation is safe.
         (x (goldilocks-reduce (* u3v (expt-mod/unsafe u5v3 (/ (- +ed448-q+ 3) 4) +ed448-q+)))))
    (declare (type integer u v uv u3v u5v3 x))
    (unless (evenp x)
      (setf x (- +ed448-q+ x)))
    x))

(defmethod ec-add ((p ed448-point) (q ed448-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (let* ((a (goldilocks-reduce (* z1 z2)))
             (b (goldilocks-reduce (* a a)))
             (c (goldilocks-reduce (* x1 x2)))
             (d (goldilocks-reduce (* y1 y2)))
             (k (goldilocks-reduce (* c d)))
             (e (goldilocks-reduce (* +ed448-d+ k)))
             (f (goldilocks-reduce (- b e)))
             (g (goldilocks-reduce (+ b e)))
             (h (goldilocks-reduce (* (+ x1 y1) (+ x2 y2))))
             (i (goldilocks-reduce (* a f)))
             (j (goldilocks-reduce (* a g)))
             (x3 (goldilocks-reduce (* i (- h c d))))
             (y3 (goldilocks-reduce (* j (- d c))))
             (z3 (goldilocks-reduce (* f g))))
        (declare (type integer a b c d e f g h i j k x3 y3 z3))
        (make-instance 'ed448-point :x x3 :y y3 :z z3)))))

(defmethod ec-double ((p ed448-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (let* ((a (goldilocks-reduce (+ x1 y1)))
           (b (goldilocks-reduce (* a a)))
           (c (goldilocks-reduce (* x1 x1)))
           (d (goldilocks-reduce (* y1 y1)))
           (e (goldilocks-reduce (+ c d)))
           (f (goldilocks-reduce (* z1 z1)))
           (g (goldilocks-reduce (- e (* 2 f))))
           (x2 (goldilocks-reduce (* (- b e) g)))
           (y2 (goldilocks-reduce (* (- c d) e)))
           (z2 (goldilocks-reduce (* e g))))
      (declare (type integer a b c d e f g x2 y2 z2))
      (make-instance 'ed448-point :x x2 :y y2 :z z2))))

(defun ed448-double! (dst p)
  "DST := 2*P. No consing."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (let* ((a (goldilocks-reduce (+ x1 y1)))
           (b (goldilocks-reduce (* a a)))
           (c (goldilocks-reduce (* x1 x1)))
           (d (goldilocks-reduce (* y1 y1)))
           (e (goldilocks-reduce (+ c d)))
           (f (goldilocks-reduce (* z1 z1)))
           (g (goldilocks-reduce (- e (* 2 f))))
           (x2 (goldilocks-reduce (* (- b e) g)))
           (y2 (goldilocks-reduce (* (- c d) e)))
           (z2 (goldilocks-reduce (* e g))))
      (declare (type integer x2 y2 z2))
      (setf (slot-value dst 'x) x2
            (slot-value dst 'y) y2
            (slot-value dst 'z) z2)
      dst)))

(defun ed448-add! (dst p q)
  "DST := P + Q. No consing."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (let* ((a (goldilocks-reduce (* z1 z2)))
             (b (goldilocks-reduce (* a a)))
             (c (goldilocks-reduce (* x1 x2)))
             (d (goldilocks-reduce (* y1 y2)))
             (k (goldilocks-reduce (* c d)))
             (e (goldilocks-reduce (* +ed448-d+ k)))
             (f (goldilocks-reduce (- b e)))
             (g (goldilocks-reduce (+ b e)))
             (h (goldilocks-reduce (* (+ x1 y1) (+ x2 y2))))
             (i (goldilocks-reduce (* a f)))
             (j (goldilocks-reduce (* a g)))
             (x3 (goldilocks-reduce (* i (- h c d))))
             (y3 (goldilocks-reduce (* j (- d c))))
             (z3 (goldilocks-reduce (* f g))))
        (declare (type integer x3 y3 z3))
        (setf (slot-value dst 'x) x3
              (slot-value dst 'y) y3
              (slot-value dst 'z) z3)
        dst))))

(declaim (inline ed448-point-copy!))
(defun ed448-point-copy! (dst src)
  "Copy point SRC into DST."
  (declare (type ed448-point dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (slot-value dst 'x) (slot-value src 'x)
        (slot-value dst 'y) (slot-value src 'y)
        (slot-value dst 'z) (slot-value src 'z))
  dst)

;;; Scalar multiplication for arbitrary points (not the generator).
;;; Uses destination-based Montgomery ladder to avoid consing intermediate
;;; points.  This is used by ed448-verify for the public-key multiplication.
(defun ed448-scalar-mult-general (p e)
  "Compute E*P for arbitrary point P, in the limb field."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (ed448-ladder-mult-limbs (slot-value p 'x) (slot-value p 'y)
                           (slot-value p 'z) e))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Fixed-base comb for the generator point.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SIGN-MESSAGE and key generation always multiply G by a secret scalar.
;;; A 4-bit window needs 114 adds and 456 doublings instead of the
;;; ladder's ~228 adds and 455 doublings.

(defvar *ed448-base-table* nil
  "Precomputed I * G for I in [0, 16). Built on first use.")

(defun ed448-ensure-base-table ()
  (or *ed448-base-table*
      (setf *ed448-base-table*
            (let ((table (make-array 16)))
              (setf (aref table 0) +ed448-point-at-infinity+)
              (setf (aref table 1) +ed448-b+)
              (loop for i from 2 below 16
                    do (setf (aref table i)
                             (if (evenp i)
                                 (ec-double (aref table (ash i -1)))
                                 (ec-add (aref table (1- i)) +ed448-b+))))
              table))))

(declaim (inline ed448-select-base))
(defun ed448-select-base (table v)
  "Select TABLE[V].  Linear scan over the small cached table."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type (integer 0 15) v))
  (let ((sel +ed448-point-at-infinity+))
    (dotimes (i 16 sel)
      (when (= i v)
        (setf sel (aref table i))))))

(defun ed448-base-mult (k)
  "Fixed-base 4-bit comb for G (secret scalar, fixed schedule)."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  (ed448-base-mult-limbs k))

(defmethod ec-scalar-mult ((p ed448-point) e)
  ;; Secret scalars use the fixed-schedule ladder, except for the fixed
  ;; base point G (signing nonces, key generation), which uses the
  ;; constant-iteration comb above.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (if (and (eq p +ed448-b+) (not (minusp e)))
      (ed448-base-mult e)
      (ed448-ladder-mult p e)))

(defun ed448-ladder-mult (point e)
  "Fixed-schedule Montgomery ladder, in the limb field."
  (declare (type ed448-point point)
           (type integer e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (ed448-ladder-mult-limbs (slot-value point 'x) (slot-value point 'y)
                           (slot-value point 'z) e))

(defmethod ec-point-on-curve-p ((p ed448-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((xx (goldilocks-reduce (* x x)))
           (yy (goldilocks-reduce (* y y)))
           (zz (goldilocks-reduce (* z z)))
           (zzzz (goldilocks-reduce (* zz zz)))
           (a (goldilocks-reduce (* zz (+ yy xx))))
           (b (goldilocks-reduce (+ zzzz (* +ed448-d+ xx yy)))))
      (declare (type integer xx yy zz zzzz a b))
      (zerop (goldilocks-reduce (- a b))))))

(defmethod ec-point-equal ((p ed448-point) (q ed448-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (and (zerop (goldilocks-reduce (- (* x1 z2) (* x2 z1))))
           (zerop (goldilocks-reduce (- (* y1 z2) (* y2 z1))))))))

(defmethod ec-make-point ((kind (eql :ed448)) &key x y)
  (unless x
    (error 'missing-point-parameter
           :kind 'ed448
           :parameter 'x
           :description "coordinate"))
  (unless y
    (error 'missing-point-parameter
           :kind 'ed448
           :parameter 'y
           :description "coordinate"))
  (let ((p (make-instance 'ed448-point :x x :y y :z 1)))
    (if (ec-point-on-curve-p p)
        p
        (error 'invalid-curve-point :kind 'ed448))))

(defmethod ec-destructure-point ((p ed448-point))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((invz (ec-scalar-inv :ed448 z))
           (x (goldilocks-reduce (* x invz)))
           (y (goldilocks-reduce (* y invz))))
      (list :x x :y y))))

(defmethod ec-encode-scalar ((kind (eql :ed448)) n)
  (integer-to-octets n :n-bits +ed448-bits+ :big-endian nil))

(defmethod ec-decode-scalar ((kind (eql :ed448)) octets)
  (octets-to-integer octets :big-endian nil))

(defmethod ec-encode-point ((p ed448-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x))
         (y (getf coordinates :y)))
    (declare (type integer x y))
    (setf (ldb (byte 1 (- +ed448-bits+ 1)) y) (ldb (byte 1 0) x))
    (ec-encode-scalar :ed448 y)))

(defmethod ec-decode-point ((kind (eql :ed448)) octets)
  (let* ((y (ec-decode-scalar :ed448 octets))
         (b (ldb (byte 1 (- +ed448-bits+ 1)) y)))
    (setf (ldb (byte 1 (- +ed448-bits+ 1)) y) 0)
    (let ((x (ed448-recover-x y)))
      (declare (type integer x))
      (unless (= (ldb (byte 1 0) x) b)
        (setf x (- +ed448-q+ x)))
      (ec-make-point :ed448 :x x :y y))))

(defun ed448-hash (&rest messages)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((digest (make-digest :shake256 :output-length 114)))
    (dolist (m messages)
      (update-digest digest m))
    (produce-digest digest)))

(defun ed448-public-key (sk)
  "Compute the public key associated to the private key SK."
  (let ((h (ed448-hash sk)))
    (setf h (subseq h 0 (ceiling +ed448-bits+ 8)))
    (setf (ldb (byte 2 0) (elt h 0)) 0)
    (setf (ldb (byte 1 7) (elt h (- (ceiling +ed448-bits+ 8) 2))) 1)
    (setf (elt h (- (ceiling +ed448-bits+ 8) 1)) 0)
    (let ((a (ec-decode-scalar :ed448 h)))
      (ec-encode-point (ec-scalar-mult +ed448-b+ a)))))

(defmethod make-signature ((kind (eql :ed448)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'ed448
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'ed448
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :ed448)) signature)
  (let ((length (length signature)))
    (if (/= length (/ +ed448-bits+ 4))
        (error 'invalid-signature-length :kind 'ed448)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defun ed448-sign (m sk pk)
  (declare (type (simple-array (unsigned-byte 8) (*)) m sk pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((h (ed448-hash sk)))
    (setf (ldb (byte 2 0) (elt h 0)) 0)
    (setf (ldb (byte 1 7) (elt h (- (ceiling +ed448-bits+ 8) 2))) 1)
    (setf (elt h (- (ceiling +ed448-bits+ 8) 1)) 0)
    (let* ((a (ec-decode-scalar :ed448 (subseq h 0 (ceiling +ed448-bits+ 8))))
           (rh (ed448-hash +ed448-dom+ (subseq h (ceiling +ed448-bits+ 8) (ceiling +ed448-bits+ 4)) m))
           (ri (mod (ec-decode-scalar :ed448 rh) +ed448-l+))
           (r (ec-scalar-mult +ed448-b+ ri))
           (rp (ec-encode-point r))
           (k (mod (ec-decode-scalar :ed448 (ed448-hash +ed448-dom+ rp pk m)) +ed448-l+))
           (s (mod (+ (* k a) ri) +ed448-l+)))
      (make-signature :ed448 :r rp :s (ec-encode-scalar :ed448 s)))))

(defun ed448-verify (s m pk)
  (declare (type (simple-array (unsigned-byte 8) (*)) s m pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length s) (ceiling +ed448-bits+ 4))
    (error 'invalid-signature-length :kind 'ed448))
  (unless (= (length pk) (ceiling +ed448-bits+ 8))
    (error 'invalid-public-key-length :kind 'ed448))
  (let* ((signature-elements (destructure-signature :ed448 s))
         (r (getf signature-elements :r))
         (rp (ec-decode-point :ed448 r))
         (s (ec-decode-scalar :ed448 (getf signature-elements :s)))
         (a (ec-decode-point :ed448 pk))
         (h (mod (ec-decode-scalar :ed448 (ed448-hash +ed448-dom+ r pk m)) +ed448-l+))
         (res1 (ec-scalar-mult +ed448-b+ s))
         (res2 (ec-add rp (ed448-scalar-mult-general a h))))
    (declare (type (simple-array (unsigned-byte 8) (*)) r)
             (type integer s h)
             (type ed448-point rp a res1 res2))
    (and (< s +ed448-l+)
         (ec-point-equal res1 res2))))

(defmethod make-public-key ((kind (eql :ed448)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'ed448
           :parameter 'y
           :description "public key"))
  (make-instance 'ed448-public-key :y y))

(defmethod destructure-public-key ((public-key ed448-public-key))
  (list :y (ed448-key-y public-key)))

(defmethod make-private-key ((kind (eql :ed448)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'ed448
           :parameter 'x
           :description "private key"))
  (make-instance 'ed448-private-key :x x :y (or y (ed448-public-key x))))

(defmethod destructure-private-key ((private-key ed448-private-key))
  (list :x (ed448-key-x private-key)
        :y (ed448-key-y private-key)))

(defmethod sign-message ((key ed448-private-key) message &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (sk (ed448-key-x key))
        (pk (ed448-key-y key)))
    (ed448-sign (subseq message start end) sk pk)))

(defmethod verify-signature ((key ed448-public-key) message signature &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (pk (ed448-key-y key)))
    (ed448-verify signature (subseq message start end) pk)))

(defmethod generate-key-pair ((kind (eql :ed448)) &key &allow-other-keys)
  (let* ((sk (random-data (ceiling +ed448-bits+ 8)))
         (pk (ed448-public-key sk)))
    (values (make-private-key :ed448 :x sk :y pk)
            (make-public-key :ed448 :y pk))))
