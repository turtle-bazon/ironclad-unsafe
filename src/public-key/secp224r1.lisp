;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; secp224r1.lisp -- secp224r1 (a.k.a. NIST P-224) elliptic curve


(in-package :crypto)


;;; class definitions

(defclass secp224r1-public-key ()
  ((y :initarg :y :reader secp224r1-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass secp224r1-private-key ()
  ((x :initarg :x :reader secp224r1-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader secp224r1-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass secp224r1-point ()
    ;; Internally, a point (x, y) is represented using the Jacobian projective
    ;; coordinates (X, Y, Z), with x = X / Z^2 and y = Y / Z^3.
    ((x :initarg :x :type integer)
     (y :initarg :y :type integer)
     (z :initarg :z :type integer)))
  (defmethod make-load-form ((p secp224r1-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constant and function definitions

(defconstant +secp224r1-bits+ 224)
(defconstant +secp224r1-p+ 26959946667150639794667015087019630673557916260026308143510066298881)
(defconstant +secp224r1-b+ 18958286285566608000408668544493926415504680968679321075787234672564)
(defconstant +secp224r1-l+ 26959946667150639794667015087019625940457807714424391721682722368061)

(defconst +secp224r1-g+
  (make-instance 'secp224r1-point
                 :x 19277929113566293071110308034699488026831934219452440156649784352033
                 :y 19926808758034470970197974370888749184205991990603949537637343198772
                 :z 1))
(defconst +secp224r1-point-at-infinity+
  (make-instance 'secp224r1-point :x 1 :y 1 :z 0))


(defmethod ec-scalar-inv ((kind (eql :secp224r1)) n)
  (expt-mod n (- +secp224r1-p+ 2) +secp224r1-p+))

(defmethod ec-point-equal ((p secp224r1-point) (q secp224r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (let ((z1z1 (mod (* z1 z1) +secp224r1-p+))
            (z2z2 (mod (* z2 z2) +secp224r1-p+)))
        (and (zerop (mod (- (* x1 z2z2) (* x2 z1z1)) +secp224r1-p+))
             (zerop (mod (- (* y1 z2z2 z2) (* y2 z1z1 z1)) +secp224r1-p+)))))))

(defmethod ec-double ((p secp224r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (if (zerop z1)
        +secp224r1-point-at-infinity+
        (let* ((xx (mod (* x1 x1) +secp224r1-p+))
               (yy (mod (* y1 y1) +secp224r1-p+))
               (yyyy (mod (* yy yy) +secp224r1-p+))
               (zz (mod (* z1 z1) +secp224r1-p+))
               (x1+yy (mod (+ x1 yy) +secp224r1-p+))
               (y1+z1 (mod (+ y1 z1) +secp224r1-p+))
               (s (mod (* 2 (- (* x1+yy x1+yy) xx yyyy)) +secp224r1-p+))
               (m (mod (* 3 (- xx (* zz zz))) +secp224r1-p+))
               (u (mod (- (* m m) (* 2 s)) +secp224r1-p+))
               (x2 u)
               (y2 (mod (- (* m (- s u)) (* 8 yyyy)) +secp224r1-p+))
               (z2 (mod (- (* y1+z1 y1+z1) yy zz) +secp224r1-p+)))
          (make-instance 'secp224r1-point :x x2 :y y2 :z z2)))))

(defmethod ec-add ((p secp224r1-point) (q secp224r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (cond
        ((zerop z1)
         q)
        ((zerop z2)
         p)
        (t
         (let* ((z1z1 (mod (* z1 z1) +secp224r1-p+))
                (z2z2 (mod (* z2 z2) +secp224r1-p+))
                (u1 (mod (* x1 z2z2) +secp224r1-p+))
                (u2 (mod (* x2 z1z1) +secp224r1-p+))
                (s1 (mod (* y1 z2 z2z2) +secp224r1-p+))
                (s2 (mod (* y2 z1 z1z1) +secp224r1-p+)))
           (if (= u1 u2)
               (if (= s1 s2)
                   (ec-double p)
                   +secp224r1-point-at-infinity+)
               (let* ((h (mod (- u2 u1) +secp224r1-p+))
                      (i (mod (* 4 h h) +secp224r1-p+))
                      (j (mod (* h i) +secp224r1-p+))
                      (r (mod (* 2 (- s2 s1)) +secp224r1-p+))
                      (v (mod (* u1 i) +secp224r1-p+))
                      (x3 (mod (- (* r r) j (* 2 v)) +secp224r1-p+))
                      (y3 (mod (- (* r (- v x3)) (* 2 s1 j)) +secp224r1-p+))
                      (z1+z2 (mod (+ z1 z2) +secp224r1-p+))
                      (z3 (mod (* (- (* z1+z2 z1+z2) z1z1 z2z2) h) +secp224r1-p+)))
                 (make-instance 'secp224r1-point :x x3 :y y3 :z z3)))))))))


;;; Fixed-base comb for the generator point.
;;;
;;; SIGN-MESSAGE and key generation always multiply G by a secret scalar.
;;; A 4-bit window needs 56 adds and 224 doublings instead of the
;;; ladder's ~112 adds and 223 doublings.

(defvar *secp224r1-base-table* nil
  "Precomputed I * G for I in [0, 16). Built on first use.")

(defun secp224r1-ensure-base-table ()
  (or *secp224r1-base-table*
      (setf *secp224r1-base-table*
            (let ((table (make-array 16)))
              (setf (aref table 0) +secp224r1-point-at-infinity+)
              (setf (aref table 1) +secp224r1-g+)
              (loop for i from 2 below 16
                    do (setf (aref table i)
                             (if (evenp i)
                                 (ec-double (aref table (ash i -1)))
                                 (ec-add (aref table (1- i)) +secp224r1-g+))))
              table))))

(declaim (inline secp224r1-select-base))
(defun secp224r1-select-base (table v)
  "Select TABLE[V].  Linear scan over the small cached table."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type (integer 0 15) v))
  (let ((sel +secp224r1-point-at-infinity+))
    (dotimes (i 16 sel)
      (when (= i v)
        (setf sel (aref table i))))))

(defun secp224r1-base-mult (k)
  "Fixed-base 4-bit comb for G (secret scalar, fixed schedule)."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  (let ((table (secp224r1-ensure-base-table))
        (acc +secp224r1-point-at-infinity+))
    (loop for j from 55 downto 0 do          ; 224 bits / 4 = 56 nibbles
      (dotimes (i 4)
        (setf acc (ec-double acc)))
      (let ((sel (secp224r1-select-base table (ldb (byte 4 (* j 4)) k))))
        (unless (eq sel +secp224r1-point-at-infinity+)
          (setf acc (ec-add acc sel)))))
    acc))

(defmethod ec-scalar-mult ((p secp224r1-point) e)
  ;; Secret scalars use the fixed-schedule ladder.  The generator G uses
  ;; the faster fixed-base comb.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  ;;
  ;; The field of the curve is in limbs, and the comb and the ladder
  ;; are in limbs as well, in the four limbs of fifty-six bits that
  ;; the reference uses, but the product and the reduction of that
  ;; field are still in Lisp, where they are twenty-six times slower
  ;; than the product of the two bignums, and the signature is made
  ;; with the bignums until the assembly of the field is there.  then the bignums are the
  ;; faster of the two, and the signature uses them.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (if (and (eq p +secp224r1-g+) (not (minusp e)))
      (secp224r1-base-mult e)
      (%ec-ladder-mult p e :bits +secp224r1-bits+)))

(defmethod ec-point-on-curve-p ((p secp224r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((y2 (mod (* y y) +secp224r1-p+))
           (x3 (mod (* x x x) +secp224r1-p+))
           (z2 (mod (* z z) +secp224r1-p+))
           (z4 (mod (* z2 z2) +secp224r1-p+))
           (z6 (mod (* z4 z2) +secp224r1-p+))
           (a (mod (+ x3 (* -3 x z4) (* +secp224r1-b+ z6)) +secp224r1-p+)))
      (declare (type integer y2 x3 z2 z4 z6 a))
      (zerop (mod (- y2 a) +secp224r1-p+)))))

(defmethod ec-make-point ((kind (eql :secp224r1)) &key x y)
  (unless x
    (error 'missing-point-parameter
           :kind 'secp224r1
           :parameter 'x
           :description "coordinate"))
  (unless y
    (error 'missing-point-parameter
           :kind 'secp224r1
           :parameter 'y
           :description "coordinate"))
  (let ((p (make-instance 'secp224r1-point :x x :y y :z 1)))
    (if (ec-point-on-curve-p p)
        p
        (error 'invalid-curve-point :kind 'secp224r1))))

(defmethod ec-destructure-point ((p secp224r1-point))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (when (zerop z)
      (error 'ironclad-error
             :format-control "The point at infinity can't be encoded."))
    (let* ((invz (ec-scalar-inv :secp224r1 z))
           (invz2 (mod (* invz invz) +secp224r1-p+))
           (invz3 (mod (* invz2 invz) +secp224r1-p+))
           (x (mod (* x invz2) +secp224r1-p+))
           (y (mod (* y invz3) +secp224r1-p+)))
      (list :x x :y y))))

(defmethod ec-encode-scalar ((kind (eql :secp224r1)) n)
  (integer-to-octets n :n-bits +secp224r1-bits+ :big-endian t))

(defmethod ec-decode-scalar ((kind (eql :secp224r1)) octets)
  (octets-to-integer octets :big-endian t))

(defmethod ec-encode-point ((p secp224r1-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x))
         (y (getf coordinates :y)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (vector 4)
                 (ec-encode-scalar :secp224r1 x)
                 (ec-encode-scalar :secp224r1 y))))

(defmethod ec-decode-point ((kind (eql :secp224r1)) octets)
  (case (aref octets 0)
    ((2 3)
     ;; Compressed point.  The P-224 prime is 1 mod 4, so the
     ;; A^((P+1)/4) shortcut the other curves use does not apply;
     ;; recover Y with Tonelli-Shanks instead.
     (if (= (length octets) (1+ (/ +secp224r1-bits+ 8)))
         (let* ((x-bytes (subseq octets 1 (1+ (/ +secp224r1-bits+ 8))))
                (x (ec-decode-scalar :secp224r1 x-bytes))
                (y-sign (- (aref octets 0) 2))
                (y2 (mod (+ (* x x x) (* -3 x) +secp224r1-b+) +secp224r1-p+))
                (y (ec-tonelli-shanks-sqrt y2 +secp224r1-p+)))
           (unless y
             (error 'invalid-curve-point :kind 'secp224r1))
           (let ((y (if (= (logand y 1) y-sign) y (- +secp224r1-p+ y))))
             (ec-make-point :secp224r1 :x x :y y)))
         (error 'invalid-curve-point :kind 'secp224r1)))
    ((4)
     ;; Uncompressed point
     (if (= (length octets) (1+ (/ +secp224r1-bits+ 4)))
         (let* ((x-bytes (subseq octets 1 (1+ (/ +secp224r1-bits+ 8))))
                (x (ec-decode-scalar :secp224r1 x-bytes))
                (y-bytes (subseq octets (1+ (/ +secp224r1-bits+ 8))))
                (y (ec-decode-scalar :secp224r1 y-bytes)))
           (ec-make-point :secp224r1 :x x :y y))
         (error 'invalid-curve-point :kind 'secp224r1)))
    (t
     (error 'invalid-curve-point :kind 'secp224r1))))

(defun secp224r1-public-key (sk)
  (let ((a (ec-decode-scalar :secp224r1 sk)))
    (ec-encode-point (ec-scalar-mult +secp224r1-g+ a))))

(defmethod make-signature ((kind (eql :secp224r1)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'secp224r1
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'secp224r1
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :secp224r1)) signature)
  (let ((length (length signature)))
    (if (/= length (/ +secp224r1-bits+ 4))
        (error 'invalid-signature-length :kind 'secp224r1)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defmethod generate-signature-nonce ((key secp224r1-private-key) message &optional parameters)
  (or *signature-nonce-for-test*
      (rfc6979-generate-k (secp224r1-key-x key)
                          message
                          +secp224r1-l+
                          (integer-length +secp224r1-l+)
                          (ceiling (integer-length +secp224r1-l+) 8)
                          :digest (or parameters *ecdsa-rfc6979-digest*))))

;;; Note that hashing is not performed here.
(defmethod sign-message ((key secp224r1-private-key) message &key (start 0) end (digest *ecdsa-rfc6979-digest*) &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((end (min (or end (length message)) (/ +secp224r1-bits+ 8)))
         (sk (ec-decode-scalar :secp224r1 (secp224r1-key-x key)))
         (h (subseq message start end))
         (k (generate-signature-nonce key h digest))
         (invk (modular-inverse-with-blinding k +secp224r1-l+))
         (r (ec-scalar-mult +secp224r1-g+ k))
         (x (subseq (ec-encode-point r) 1 (1+ (/ +secp224r1-bits+ 8))))
         (r (ec-decode-scalar :secp224r1 x))
         (r (mod r +secp224r1-l+))
         (e (ec-decode-scalar :secp224r1 h))
         (s (mod (* invk (+ e (* sk r))) +secp224r1-l+)))
    (if (not (or (zerop r) (zerop s)))
        (make-signature :secp224r1
                        :r (ec-encode-scalar :secp224r1 r)
                        :s (ec-encode-scalar :secp224r1 s))
        (sign-message key message :start start :end end))))

(defmethod verify-signature ((key secp224r1-public-key) message signature &key (start 0) end &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length signature) (/ +secp224r1-bits+ 4))
    (error 'invalid-signature-length :kind 'secp224r1))
  (let* ((end (min (or end (length message)) (/ +secp224r1-bits+ 8)))
         (pk (ec-decode-point :secp224r1 (secp224r1-key-y key)))
         (signature-elements (destructure-signature :secp224r1 signature))
         (r (ec-decode-scalar :secp224r1 (getf signature-elements :r)))
         (s (ec-decode-scalar :secp224r1 (getf signature-elements :s))))
    ;; Degenerate (r = 0 or s = 0) signatures are invalid; answer NIL
    ;; before the W/RP computations, which assume nonzero operands.
    (unless (and (< 0 r +secp224r1-l+) (< 0 s +secp224r1-l+))
      (return-from verify-signature nil))
    (let* ((h (subseq message start end))
         (e (ec-decode-scalar :secp224r1 h))
         (w (modular-inverse-with-blinding s +secp224r1-l+))
         (u1 (mod (* e w) +secp224r1-l+))
         (u2 (mod (* r w) +secp224r1-l+))
         ;; Joint multiplication (Shamir's trick): one pass instead of two.
         (rp (%ec-shamir-mult +secp224r1-g+ pk u1 u2))
         (x (subseq (ec-encode-point rp) 1 (1+ (/ +secp224r1-bits+ 8))))
         (v (ec-decode-scalar :secp224r1 x))
         (v (mod v +secp224r1-l+)))
     (and (< 0 r +secp224r1-l+)
          (< 0 s +secp224r1-l+)
          ;; RP is the point at infinity only for invalid signatures;
          ;; answer NIL instead of failing inside EC-ENCODE-POINT.
          (not (ec-point-equal rp +secp224r1-point-at-infinity+))
          (= v r)))))

(defmethod make-public-key ((kind (eql :secp224r1)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'secp224r1
           :parameter 'y
           :description "public key"))
  ;; Reject malformed encodings and off-curve points now, at
  ;; construction time, rather than at first use.
  (ec-decode-point :secp224r1 y)
  (make-instance 'secp224r1-public-key :y y))

(defmethod destructure-public-key ((public-key secp224r1-public-key))
  (list :y (secp224r1-key-y public-key)))

(defmethod make-private-key ((kind (eql :secp224r1)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'secp224r1
           :parameter 'x
           :description "private key"))
  ;; The scalar must lie in [1, N-1]; 0 yields the point at infinity
  ;; and values >= N silently wrap to the wrong public key.
  (unless (< 0 (octets-to-integer x :big-endian t) +secp224r1-l+)
    (error 'invalid-private-key :kind 'secp224r1))
  (make-instance 'secp224r1-private-key :x x :y (or y (secp224r1-public-key x))))

(defmethod destructure-private-key ((private-key secp224r1-private-key))
  (list :x (secp224r1-key-x private-key)
        :y (secp224r1-key-y private-key)))

(defmethod generate-key-pair ((kind (eql :secp224r1)) &key &allow-other-keys)
  (let* ((sk (ec-encode-scalar :secp224r1 (1+ (strong-random (1- +secp224r1-l+)))))
         (pk (secp224r1-public-key sk)))
    (values (make-private-key :secp224r1 :x sk :y pk)
            (make-public-key :secp224r1 :y pk))))

(defmethod diffie-hellman ((private-key secp224r1-private-key) (public-key secp224r1-public-key))
  (let ((s (ec-decode-scalar :secp224r1 (secp224r1-key-x private-key)))
        (p (ec-decode-point :secp224r1 (secp224r1-key-y public-key))))
    (ec-encode-point (ec-scalar-mult p s))))

;;;; The field of P-224 in four limbs of fifty-six bits, after the
;;;; reference: the product of two field elements is seven wide
;;;; coefficients of a hundred and twenty-eight bits, and the
;;;; reduction of those coefficients is the one of a Solinas prime.
;;;;
;;;; The prime is 2^224 - 2^96 + 1, so 2^224 is congruent to 2^96
;;;; less one, and the reduction adds the high half of the product
;;;; shifted up by ninety-six bits, less the high half itself.  The
;;;; multiples of the prime that are added first make every
;;;; difference positive, so that no borrow is ever needed, which is
;;;; what lets the reduction be written with the coefficients alone.
;;;; The value that comes out is below twice the prime, and the
;;;; contract at the end takes it below the prime.

(defconstant +secp224r1-limb-bits+ 56)
(defconstant +secp224r1-limb-mask+ (1- (ash 1 56)))
(defconstant +secp224r1-limb-bits-wide+ 128)

(deftype secp224r1-felem () '(simple-array (unsigned-byte 64) (4)))
(deftype secp224r1-widefelem () '(simple-array integer (7)))

(defun secp224r1-felem-from-int (n)
  "The field element N, in four limbs of fifty-six bits."
  (declare (type integer n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((a (make-array 4 :element-type '(unsigned-byte 64) :initial-element 0)))
    (dotimes (i 4 a)
      (setf (aref a i) (logand n +secp224r1-limb-mask+))
      (setf n (ash n -56)))))

(defun secp224r1-felem-to-int (a)
  "The integer value of the field element A."
  (declare (type secp224r1-felem a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((n 0))
    (dotimes (i 4 n)
      (setf n (+ n (ash (aref a i) (* 56 i)))))))

(defun secp224r1-felem-mul (out a b)
  "OUT := A * B, as seven wide coefficients, after the reference.
The coefficients are the columns of the product, and they are not
reduced."
  (declare (type secp224r1-widefelem out)
           (type secp224r1-felem a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (aref out 0) (* (aref a 0) (aref b 0))
        (aref out 1) (+ (* (aref a 0) (aref b 1)) (* (aref a 1) (aref b 0)))
        (aref out 2) (+ (* (aref a 0) (aref b 2)) (* (aref a 1) (aref b 1))
                       (* (aref a 2) (aref b 0)))
        (aref out 3) (+ (* (aref a 0) (aref b 3)) (* (aref a 1) (aref b 2))
                       (* (aref a 2) (aref b 1)) (* (aref a 3) (aref b 0)))
        (aref out 4) (+ (* (aref a 1) (aref b 3)) (* (aref a 2) (aref b 2))
                       (* (aref a 3) (aref b 1)))
        (aref out 5) (+ (* (aref a 2) (aref b 3)) (* (aref a 3) (aref b 2)))
        (aref out 6) (* (aref a 3) (aref b 3)))
  out)

(defun secp224r1-felem-reduce (out in)
  "OUT := IN mod P, after the reference.
IN holds seven wide coefficients, and the result is below twice the
prime."
  (declare (type secp224r1-felem out)
           (type secp224r1-widefelem in)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((o (make-array 5 :element-type 'integer :initial-element 0)))
    ;; The multiples of the prime that make the differences positive.
    (setf (aref o 0) (+ (aref in 0) (ash 1 127) (ash 1 15))
          (aref o 1) (+ (aref in 1) (ash 1 127) (- (ash 1 71)) (- (ash 1 55)))
          (aref o 2) (+ (aref in 2) (ash 1 127) (- (ash 1 71)))
          (aref o 3) (aref in 3)
          (aref o 4) (aref in 4))
    ;; Eliminate the coefficients four, five and six.
    (setf (aref o 4) (+ (aref o 4) (ash (aref in 6) -16))
          (aref o 3) (+ (aref o 3) (ash (logand (aref in 6) 65535) 40))
          (aref o 2) (- (aref o 2) (aref in 6)))
    (setf (aref o 3) (+ (aref o 3) (ash (aref in 5) -16))
          (aref o 2) (+ (aref o 2) (ash (logand (aref in 5) 65535) 40))
          (aref o 1) (- (aref o 1) (aref in 5)))
    (setf (aref o 2) (+ (aref o 2) (ash (aref o 4) -16))
          (aref o 1) (+ (aref o 1) (ash (logand (aref o 4) 65535) 40))
          (aref o 0) (- (aref o 0) (aref o 4)))
    ;; Carry two to three to four.
    (setf (aref o 3) (+ (aref o 3) (ash (aref o 2) -56))
          (aref o 2) (logand (aref o 2) +secp224r1-limb-mask+))
    (setf (aref o 4) (ash (aref o 3) -56)
          (aref o 3) (logand (aref o 3) +secp224r1-limb-mask+))
    ;; Eliminate the excess.
    (setf (aref o 2) (+ (aref o 2) (ash (aref o 4) -16))
          (aref o 1) (+ (aref o 1) (ash (logand (aref o 4) 65535) 40))
          (aref o 0) (- (aref o 0) (aref o 4)))
    ;; Carry zero to one to two to three.
    (setf (aref o 1) (+ (aref o 1) (ash (aref o 0) -56))
          (aref o 0) (logand (aref o 0) +secp224r1-limb-mask+))
    (setf (aref o 2) (+ (aref o 2) (ash (aref o 1) -56))
          (aref o 1) (logand (aref o 1) +secp224r1-limb-mask+))
    (setf (aref o 3) (+ (aref o 3) (ash (aref o 2) -56))
          (aref o 2) (logand (aref o 2) +secp224r1-limb-mask+))
    (dotimes (i 4) (setf (aref out i) (aref o i))))
  out)

(defun secp224r1-felem-contract (out in)
  "OUT := IN, brought below the prime, after the reference.
IN is below twice the prime, so the prime is subtracted once at
most."
  (declare (type secp224r1-felem out in)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (secp224r1-felem-to-int in))
         (m (if (>= n +secp224r1-p+) (- n +secp224r1-p+) n)))
    (declare (type integer n m))
    (dotimes (i 4 out)
      (setf (aref out i) (logand m +secp224r1-limb-mask+))
      (setf m (ash m -56)))))

(defun secp224r1-felem-add (out a b)
  "OUT := (A + B) mod P, after the reference.
The sum is made in the wide form and reduced, as the reference does,
and the contract brings it below the prime."
  (declare (type secp224r1-felem out a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((w (make-array 7 :element-type 'integer :initial-element 0)))
    (dotimes (i 4)
      (setf (aref w i) (+ (aref a i) (aref b i))))
    (secp224r1-felem-reduce out w)
    (secp224r1-felem-contract out out)))

(defun secp224r1-felem-sub (out a b)
  "OUT := (A - B) mod P, after the reference.
The difference is made in the wide form and reduced, as the reference
does, and the contract brings it below the prime."
  (declare (type secp224r1-felem out a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (- (secp224r1-felem-to-int a) (secp224r1-felem-to-int b)))
         (m (if (minusp n) (+ n +secp224r1-p+) n))
         (w (make-array 7 :element-type 'integer :initial-element 0)))
    (declare (type integer n m))
    (dotimes (i 4)
      (setf (aref w i) (logand m +secp224r1-limb-mask+))
      (setf m (ash m -56)))
    (secp224r1-felem-reduce out w)
    (secp224r1-felem-contract out out)))

;; The prime in limbs.  This is a DEFVAR and not a DEFCONSTANT: the
;; value is a vector, and a DEFCONSTANT whose value is a vector makes
;; every recompilation of this file fail with DEFCONSTANT-UNEQL.
(defvar +secp224r1-p-limbs+ '#(1 0 0 4294967295 4294967295 4294967295
                              4294967295))

(deftype secp224r1-fe () '(simple-array (unsigned-byte 64) (4)))
(deftype secp224r1-wide () '(simple-array integer (7)))

(declaim (inline secp224r1-fe-zero secp224r1-fe-from-int
                 secp224r1-fe-to-int))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun secp224r1-fe-zero ()
    (make-array 4 :element-type '(unsigned-byte 64) :initial-element 0)))

(defun secp224r1-fe-from-int (n)
  "The field element N, in four limbs of fifty-six bits."
  (declare (type integer n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (secp224r1-fe-zero)))
    (dotimes (i 4 r)
      (setf (aref r i) (logand n +secp224r1-limb-mask+))
      (setf n (ash n -56)))))

(defun secp224r1-fe-to-int (a)
  "The integer value of the field element A."
  (declare (type secp224r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((n 0))
    (declare (type integer n))
    (dotimes (i 4 n)
      (setf n (+ n (ash (aref a i) (* 56 i)))))))

(defun secp224r1-fe-mul-raw (c a b)
  "C := A * B, as seven wide coefficients, after the reference.
The coefficients are the columns of the product, and they are not
reduced."
  (declare (type secp224r1-wide c)
           (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp224r1-felem-mul c a b))

(defun secp224r1-fe-add! (r a b)
  "R := A + B, reduced.  R may be the same array as A or B."
  (declare (type secp224r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp224r1-felem-add r a b))

(defun secp224r1-fe-add (a b)
  "The sum of the field elements A and B, reduced."
  (declare (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp224r1-fe-add! (secp224r1-fe-zero) a b))
(defun secp224r1-fe-sub! (r a b)
  "R := A - B, reduced.  R may be the same array as A or B."
  (declare (type secp224r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp224r1-felem-sub r a b))

(defun secp224r1-fe-sub (a b)
  "The difference of the field elements A and B, reduced."
  (declare (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp224r1-fe-sub! (secp224r1-fe-zero) a b))

(defvar +secp224r1-one+ (secp224r1-fe-from-int 1)
  "The constant one, in limbs.")
(defvar +secp224r1-two+ (secp224r1-fe-from-int 2)
  "The constant two, in limbs.")
(defvar +secp224r1-three+ (secp224r1-fe-from-int 3)
  "The constant three, in limbs.")
(defvar +secp224r1-four+ (secp224r1-fe-from-int 4)
  "The constant four, in limbs.")
(defvar +secp224r1-eight+ (secp224r1-fe-from-int 8)
  "The constant eight, in limbs.")

(defun secp224r1-fe-copy! (r a)
  "R := A.  R may be the same array as A."
  (declare (type secp224r1-fe r a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 4 r)
    (setf (aref r i) (aref a i))))

(defun secp224r1-fe-is-zero (a)
  "True when the field element A is zero."
  (declare (type secp224r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (and (zerop (aref a 0)) (zerop (aref a 1)) (zerop (aref a 2))
       (zerop (aref a 3))))

(defun secp224r1-fe-mul-buf (r a b c q)
  "R := (A * B) mod P, using the wide buffer C.  The caller reuses it,
so that a multiply inside a point operation allocates nothing."
  (declare (type secp224r1-fe r a b)
           (type secp224r1-wide c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (declare (ignore q))
  (secp224r1-fe-mul-raw c a b)
  (secp224r1-fe-reduce r c q))

(defun secp224r1-fe-equal (a b)
  "True when the field elements A and B are the same."
  (declare (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (and (= (aref a 0) (aref b 0))
       (= (aref a 1) (aref b 1))
       (= (aref a 2) (aref b 2))
       (= (aref a 3) (aref b 3))))

(defun secp224r1-make-scratch ()
  "A fresh scratch pool for the point operations.
The twenty one first slots are field elements and the twenty second
is the wide buffer of a field multiply, so that a point operation
allocates nothing per multiply."
  (let ((s (make-array 23)))
    (dotimes (i 21 s)
      (setf (svref s i) (secp224r1-fe-zero)))
    (setf (svref s 21)
          (make-array 7 :element-type 'integer :initial-element 0))
    (setf (svref s 22)
          (make-array 7 :element-type 'integer :initial-element 0))
    s))

(defun secp224r1-double! (dx dy dz x1 y1 z1 s)
  "The double of the point (X1 : Y1 : Z1), into (DX : DY : DZ).
S is the scratch pool.  The three destinations must differ from the
three sources."
  (declare (type secp224r1-fe dx dy dz x1 y1 z1)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((xx (svref s 0)) (yy (svref s 1)) (yyyy (svref s 2)) (zz (svref s 3))
         (x1+yy (svref s 4)) (y1+z1 (svref s 5)) (w (svref s 6))
         (ss (svref s 7)) (m (svref s 8)) (tw (svref s 9)) (u (svref s 10))
         (cbuf (svref s 21)) (qbuf (svref s 22)))
    (declare (type secp224r1-fe xx yy yyyy zz x1+yy y1+z1 w ss m tw u))
    (secp224r1-fe-mul-buf xx x1 x1 cbuf qbuf)
    (secp224r1-fe-mul-buf yy y1 y1 cbuf qbuf)
    (secp224r1-fe-mul-buf yyyy yy yy cbuf qbuf)
    (secp224r1-fe-mul-buf zz z1 z1 cbuf qbuf)
    (secp224r1-fe-add! x1+yy x1 yy)
    (secp224r1-fe-add! y1+z1 y1 z1)
    ;; s = 2*((x1+yy)^2 - xx - yyyy)
    (secp224r1-fe-mul-buf w x1+yy x1+yy cbuf qbuf)
    (secp224r1-fe-sub! u w xx)
    (secp224r1-fe-sub! u u yyyy)
    (secp224r1-fe-mul-buf ss +secp224r1-two+ u cbuf qbuf)
    ;; m = 3*(xx - zz^2), for the curve whose a is -3
    (secp224r1-fe-mul-buf w zz zz cbuf qbuf)
    (secp224r1-fe-sub! u xx w)
    (secp224r1-fe-mul-buf m +secp224r1-three+ u cbuf qbuf)
    ;; u = m^2 - 2s
    (secp224r1-fe-mul-buf u m m cbuf qbuf)
    (secp224r1-fe-mul-buf tw +secp224r1-two+ ss cbuf qbuf)
    (secp224r1-fe-sub! u u tw)
    ;; y2 = m*(s - u) - 8*yyyy
    (secp224r1-fe-sub! tw ss u)
    (secp224r1-fe-mul-buf w m tw cbuf qbuf)
    (secp224r1-fe-mul-buf tw +secp224r1-eight+ yyyy cbuf qbuf)
    (secp224r1-fe-sub! dy w tw)
    ;; z2 = (y1+z1)^2 - yy - zz
    (secp224r1-fe-mul-buf w y1+z1 y1+z1 cbuf qbuf)
    (secp224r1-fe-sub! tw w yy)
    (secp224r1-fe-sub! dz tw zz)
    (secp224r1-fe-copy! dx u)
    dz))

(defun secp224r1-add! (dx dy dz x1 y1 z1 x2 y2 z2 s)
  "The sum of the points (X1 : Y1 : Z1) and (X2 : Y2 : Z2), into
(DX : DY : DZ).  S is the scratch pool.  The destinations must differ
from the sources."
  (declare (type secp224r1-fe dx dy dz x1 y1 z1 x2 y2 z2)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((z1z1 (svref s 0)) (z2z2 (svref s 1)) (u1 (svref s 2))
         (u2 (svref s 3)) (s1 (svref s 4)) (s2 (svref s 5)) (h (svref s 6))
         (i (svref s 7)) (j (svref s 8)) (r (svref s 9)) (v (svref s 10))
         (tw (svref s 11)) (u (svref s 12)) (w (svref s 13))
         (cbuf (svref s 21)) (qbuf (svref s 22)))
    (declare (type secp224r1-fe z1z1 z2z2 u1 u2 s1 s2 h i j r v tw u w))
    ;; The point at infinity is (1 : 1 : 0), and the formulas of the
    ;; sum are not complete, so it is taken out first.
    (when (secp224r1-fe-is-zero z1)
      (secp224r1-fe-copy! dx x2)
      (secp224r1-fe-copy! dy y2)
      (secp224r1-fe-copy! dz z2)
      (return-from secp224r1-add! dz))
    (when (secp224r1-fe-is-zero z2)
      (secp224r1-fe-copy! dx x1)
      (secp224r1-fe-copy! dy y1)
      (secp224r1-fe-copy! dz z1)
      (return-from secp224r1-add! dz))
    (secp224r1-fe-mul-buf z1z1 z1 z1 cbuf qbuf)
    (secp224r1-fe-mul-buf z2z2 z2 z2 cbuf qbuf)
    (secp224r1-fe-mul-buf u1 x1 z2z2 cbuf qbuf)
    (secp224r1-fe-mul-buf u2 x2 z1z1 cbuf qbuf)
    (secp224r1-fe-mul-buf tw z2 z2z2 cbuf qbuf)
    (secp224r1-fe-mul-buf s1 y1 tw cbuf qbuf)
    (secp224r1-fe-mul-buf tw z1 z1z1 cbuf qbuf)
    (secp224r1-fe-mul-buf s2 y2 tw cbuf qbuf)
    (if (secp224r1-fe-equal u1 u2)
        (if (secp224r1-fe-equal s1 s2)
            ;; The points are the same, so the sum is the double.
            (secp224r1-double! dx dy dz x1 y1 z1 s)
            ;; The points are opposites, so the sum is at infinity.
            (progn
              (secp224r1-fe-copy! dx +secp224r1-one+)
              (secp224r1-fe-copy! dy +secp224r1-one+)
              (secp224r1-fe-copy! dz (secp224r1-fe-zero))))
        (progn
          (secp224r1-fe-sub! h u2 u1)
          (secp224r1-fe-mul-buf tw +secp224r1-four+ h cbuf qbuf)
          (secp224r1-fe-mul-buf i tw h cbuf qbuf)
          (secp224r1-fe-mul-buf j h i cbuf qbuf)
          (secp224r1-fe-sub! tw s2 s1)
          (secp224r1-fe-mul-buf r +secp224r1-two+ tw cbuf qbuf)
          (secp224r1-fe-mul-buf v u1 i cbuf qbuf)
          ;; x3 = r^2 - j - 2v
          (secp224r1-fe-mul-buf tw r r cbuf qbuf)
          (secp224r1-fe-sub! dx tw j)
          (secp224r1-fe-mul-buf tw +secp224r1-two+ v cbuf qbuf)
          (secp224r1-fe-sub! dx dx tw)
          ;; y3 = r*(v - x3) - 2*s1*j
          (secp224r1-fe-sub! tw v dx)
          (secp224r1-fe-mul-buf w r tw cbuf qbuf)
          (secp224r1-fe-mul-buf tw s1 j cbuf qbuf)
          (secp224r1-fe-mul-buf tw +secp224r1-two+ tw cbuf qbuf)
          (secp224r1-fe-sub! dy w tw)
          ;; z3 = ((z1+z2)^2 - z1z1 - z2z2)*h
          (secp224r1-fe-add! tw z1 z2)
          (secp224r1-fe-mul-buf u tw tw cbuf qbuf)
          (secp224r1-fe-sub! u u z1z1)
          (secp224r1-fe-sub! u u z2z2)
          (secp224r1-fe-mul-buf dz u h cbuf qbuf)))
    dz))

(defun secp224r1-point-double-limbs (x1 y1 z1)
  "The double of the point (X1 : Y1 : Z1), in limbs.
The three coordinates are returned as multiple values."
  (declare (type secp224r1-fe x1 y1 z1)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((s (secp224r1-make-scratch))
        (x (secp224r1-fe-zero)) (y (secp224r1-fe-zero))
        (z (secp224r1-fe-zero)))
    (secp224r1-double! x y z x1 y1 z1 s)
    (values x y z)))

(defun secp224r1-point-add-limbs (x1 y1 z1 x2 y2 z2)
  "The sum of the points (X1 : Y1 : Z1) and (X2 : Y2 : Z2), in limbs.
The three coordinates are returned as multiple values."
  (declare (type secp224r1-fe x1 y1 z1 x2 y2 z2)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((s (secp224r1-make-scratch))
        (x (secp224r1-fe-zero)) (y (secp224r1-fe-zero))
        (z (secp224r1-fe-zero)))
    (secp224r1-add! x y z x1 y1 z1 x2 y2 z2 s)
    (values x y z)))

(defmacro secp224r1-swap3 (a b c x y z)
  "Swaps the triple (A, B, C) with the triple (X, Y, Z).
It has to be a macro: a function would set its own parameters and
leave the caller's variables alone."
  `(let ((ta ,a) (tb ,b) (tc ,c))
     (setf ,a ,x)
     (setf ,b ,y)
     (setf ,c ,z)
     (setf ,x ta)
     (setf ,y tb)
     (setf ,z tc)))

(defun secp224r1-point-from-limbs (x y z)
  "The point (X : Y : Z), in limbs, as a point of the curve."
  (declare (type secp224r1-fe x y z)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (make-instance 'secp224r1-point
                 :x (secp224r1-fe-to-int x)
                 :y (secp224r1-fe-to-int y)
                 :z (secp224r1-fe-to-int z)))

(defvar +secp224r1-base-table-limbs+ nil
  "Precomputed I * G for I in [0, 16), in limbs.")

(defun secp224r1-ensure-base-table-limbs ()
  (or +secp224r1-base-table-limbs+
      (setf +secp224r1-base-table-limbs+
            (let ((table (make-array 16))
                  (s (secp224r1-make-scratch)))
              (setf (aref table 0) (vector (secp224r1-fe-from-int 1)
                                           (secp224r1-fe-from-int 1)
                                           (secp224r1-fe-from-int 0)))
              (setf (aref table 1) (vector
                                    (secp224r1-fe-from-int
                                     (slot-value +secp224r1-g+ 'x))
                                    (secp224r1-fe-from-int
                                     (slot-value +secp224r1-g+ 'y))
                                    (secp224r1-fe-from-int 1)))
              (loop for i from 2 below 16
                    do (let ((nx (secp224r1-fe-zero))
                             (ny (secp224r1-fe-zero))
                             (nz (secp224r1-fe-zero)))
                         (if (evenp i)
                             (secp224r1-double! nx ny nz
                                                (aref (aref table (ash i -1)) 0)
                                                (aref (aref table (ash i -1)) 1)
                                                (aref (aref table (ash i -1)) 2)
                                                s)
                             (secp224r1-add! nx ny nz
                                             (aref (aref table (1- i)) 0)
                                             (aref (aref table (1- i)) 1)
                                             (aref (aref table (1- i)) 2)
                                             (aref (aref table 1) 0)
                                             (aref (aref table 1) 1)
                                             (aref (aref table 1) 2)
                                             s))
                         (setf (aref table i) (vector nx ny nz))))
              table))))

(defun secp224r1-base-mult-limbs (k)
  "The fixed-base comb for G, in the limb field."
  (declare (type integer k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (secp224r1-ensure-base-table-limbs))
        (s (secp224r1-make-scratch))
        (accx (secp224r1-fe-from-int 1))
        (accy (secp224r1-fe-from-int 1))
        (accz (secp224r1-fe-from-int 0))
        (tx (secp224r1-fe-zero)) (ty (secp224r1-fe-zero))
        (tz (secp224r1-fe-zero)))
    (declare (type secp224r1-fe accx accy accz tx ty tz))
    (loop for j from 55 downto 0 do        ; 224 bits / 4 = 56 nibbles
      (dotimes (i 4)
        (secp224r1-double! tx ty tz accx accy accz s)
        (secp224r1-swap3 accx accy accz tx ty tz))
      (let ((sel (aref table (ldb (byte 4 (* j 4)) k))))
        (unless (secp224r1-fe-is-zero (aref sel 2))
          (secp224r1-add! tx ty tz accx accy accz
                          (aref sel 0) (aref sel 1) (aref sel 2) s)
          (secp224r1-swap3 accx accy accz tx ty tz))))
    (secp224r1-point-from-limbs accx accy accz)))

(defun secp224r1-ladder-mult-limbs (x y z e)
  "E times the point (X : Y : Z), in the limb field.
X, Y and Z are bignums, and the result is a point."
  (declare (type integer x y z e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (when (minusp e)
    (error "negative scalars are not supported by secp224r1"))
  (if (zerop e)
      +secp224r1-point-at-infinity+
      (let* ((s (secp224r1-make-scratch))
             (r0x (secp224r1-fe-from-int 1)) (r0y (secp224r1-fe-from-int 1))
             (r0z (secp224r1-fe-from-int 0))
             (r1x (secp224r1-fe-from-int x)) (r1y (secp224r1-fe-from-int y))
             (r1z (secp224r1-fe-from-int z))
             (tx (secp224r1-fe-zero)) (ty (secp224r1-fe-zero))
             (tz (secp224r1-fe-zero))
             (ux (secp224r1-fe-zero)) (uy (secp224r1-fe-zero))
             (uz (secp224r1-fe-zero)))
        (declare (type secp224r1-fe r0x r0y r0z r1x r1y r1z tx ty tz ux uy uz))
        (loop for i from (1- +secp224r1-bits+) downto 0 do
          (if (logbitp i e)
              (progn
                (secp224r1-add! tx ty tz r0x r0y r0z r1x r1y r1z s)
                (secp224r1-double! ux uy uz r1x r1y r1z s)
                (secp224r1-swap3 r0x r0y r0z tx ty tz)
                (secp224r1-swap3 r1x r1y r1z ux uy uz))
              (progn
                (secp224r1-add! tx ty tz r0x r0y r0z r1x r1y r1z s)
                (secp224r1-double! ux uy uz r0x r0y r0z s)
                (secp224r1-swap3 r1x r1y r1z tx ty tz)
                (secp224r1-swap3 r0x r0y r0z ux uy uz))))
        (secp224r1-point-from-limbs r0x r0y r0z))))

(defun secp224r1-fe-mul (a b)
  "The product of the field elements A and B, reduced."
  (declare (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((c (make-array 7 :element-type 'integer :initial-element 0))
        (r (secp224r1-fe-zero)))
    (secp224r1-fe-mul-raw c a b)
    (secp224r1-fe-reduce r c nil)
    r))

(defun secp224r1-fe-reduce (r c q)
  "R := C mod P, after the reference.
C holds the seven wide coefficients of a product, and the result is
below the prime."
  (declare (type secp224r1-fe r)
           (type secp224r1-wide c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (declare (ignore q))
  (secp224r1-felem-reduce r c)
  (secp224r1-felem-contract r r))
