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

(defmethod ec-scalar-mult ((p secp224r1-point) e)
  ;; Fixed-window multiplication; see %EC-WINDOW-MULT.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (%ec-window-mult p e))

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
