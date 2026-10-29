;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; secp224r1.lisp -- secp224r1 (a.k.a. NIST P-224) elliptic curve


(in-package :crypto-unsafe)


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


(defun secp224r1-fe-inv (a)
  "The inverse of the field element A, by the reference's addition
chain: roughly two hundred and twenty squarings and a handful of
multiplications, all in the limb field."
  (declare (type integer a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((in (secp224r1-fe-from-int a))
         (ftmp (secp224r1-fe-zero)) (ftmp2 (secp224r1-fe-zero))
         (ftmp3 (secp224r1-fe-zero)) (ftmp4 (secp224r1-fe-zero))
         (out (secp224r1-fe-zero))
         (w (make-array 14 :element-type '(unsigned-byte 64)
                            :initial-element 0)))
    (declare (type secp224r1-fe in ftmp ftmp2 ftmp3 ftmp4 out))
    (flet ((sq (src dst)
             (secp224r1-fe-mul-raw w src src)
             (secp224r1-felem-reduce dst w))
           (ml (a b dst)
             (secp224r1-fe-mul-raw w a b)
             (secp224r1-felem-reduce dst w)))
      ;; 2^1 - 1 -> 2
      (sq in ftmp)
      (ml in ftmp ftmp)
      (sq ftmp ftmp)
      (ml in ftmp ftmp)
      (sq ftmp ftmp2)
      (sq ftmp2 ftmp2)
      (sq ftmp2 ftmp2)
      (ml ftmp2 ftmp ftmp)
      (sq ftmp ftmp2)
      (dotimes (i 5) (sq ftmp2 ftmp2))
      (ml ftmp2 ftmp ftmp2)
      (sq ftmp2 ftmp3)
      (dotimes (i 11) (sq ftmp3 ftmp3))
      (ml ftmp3 ftmp2 ftmp2)
      (sq ftmp2 ftmp3)
      (dotimes (i 23) (sq ftmp3 ftmp3))
      (ml ftmp3 ftmp2 ftmp3)
      (sq ftmp3 ftmp4)
      (dotimes (i 47) (sq ftmp4 ftmp4))
      (ml ftmp3 ftmp4 ftmp3)
      (sq ftmp3 ftmp4)
      (dotimes (i 23) (sq ftmp4 ftmp4))
      (ml ftmp2 ftmp4 ftmp2)
      (dotimes (i 6) (sq ftmp2 ftmp2))
      (ml ftmp2 ftmp ftmp)
      (sq ftmp ftmp)
      (ml ftmp in ftmp)
      (dotimes (i 97) (sq ftmp ftmp))
      (ml ftmp ftmp3 out))
    (secp224r1-fe-to-int out)))

(defmethod ec-scalar-inv ((kind (eql :secp224r1)) n)
  (secp224r1-fe-inv n))


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
  ;; The field of the curve is in limbs, and the comb and the ladder
  ;; are in limbs as well, with the product and the reduction in the
  ;; assembly of the reference.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (if (and (eq p +secp224r1-g+) (not (minusp e)))
      (secp224r1-base-mult-positional e)
      (let ((px (slot-value p 'x))
            (py (slot-value p 'y))
            (pz (slot-value p 'z)))
        (declare (type integer px py pz))
        (secp224r1-ladder-mult-limbs px py pz e))))

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
      (error 'ironclad-unsafe-error
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
         (invk (modular-inverse-with-blinding k +secp224r1-l+ :prime t))
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
         (w (modular-inverse-with-blinding s +secp224r1-l+ :prime t))
         (u1 (mod (* e w) +secp224r1-l+))
         (u2 (mod (* r w) +secp224r1-l+))
         ;; Joint multiplication (Shamir's trick): one pass instead of
         ;; two, in the limb field of the reference.
         (rp (secp224r1-shamir-mult-limbs
              (slot-value +secp224r1-g+ 'x) (slot-value +secp224r1-g+ 'y)
              (slot-value +secp224r1-g+ 'z)
              (slot-value pk 'x) (slot-value pk 'y) (slot-value pk 'z)
              u1 u2))
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
(deftype secp224r1-wide () '(simple-array (unsigned-byte 64) (14)))

(declaim (inline secp224r1-wide-get secp224r1-wide-set))

(defun secp224r1-wide-get (w k)
  "The K-th wide coefficient of W, which is two words of sixty-four
bits, the low word first."
  (declare (type secp224r1-wide w)
           (type (integer 0 6) k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (+ (aref w (* 2 k)) (ash (aref w (1+ (* 2 k))) 64)))

(defun secp224r1-wide-set (w k v)
  "Set the K-th wide coefficient of W to V, in two words."
  (declare (type secp224r1-wide w)
           (type (integer 0 6) k)
           (type integer v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (aref w (* 2 k)) (logand v 18446744073709551615)
        (aref w (1+ (* 2 k))) (ash v -64))
  w)

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
  "OUT := A * B, as the seven wide coefficients of the reference: the
columns of the product, without the carries carried.  Each
coefficient is two words of sixty-four bits, the low word first."
  (declare (type secp224r1-wide out)
           (type secp224r1-felem a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp224r1-wide-set out 0 (* (aref a 0) (aref b 0)))
  (secp224r1-wide-set out 1 (+ (* (aref a 0) (aref b 1))
                               (* (aref a 1) (aref b 0))))
  (secp224r1-wide-set out 2 (+ (* (aref a 0) (aref b 2))
                               (* (aref a 1) (aref b 1))
                               (* (aref a 2) (aref b 0))))
  (secp224r1-wide-set out 3 (+ (* (aref a 0) (aref b 3))
                               (* (aref a 1) (aref b 2))
                               (* (aref a 2) (aref b 1))
                               (* (aref a 3) (aref b 0))))
  (secp224r1-wide-set out 4 (+ (* (aref a 1) (aref b 3))
                               (* (aref a 2) (aref b 2))
                               (* (aref a 3) (aref b 1))))
  (secp224r1-wide-set out 5 (+ (* (aref a 2) (aref b 3))
                               (* (aref a 3) (aref b 2))))
  (secp224r1-wide-set out 6 (* (aref a 3) (aref b 3)))
  out)

(defun secp224r1-felem-reduce (out in)
  "OUT := IN mod P, after the reference.
IN holds the seven wide coefficients of a product, two words each,
and the result is below twice the prime."
  (declare (type secp224r1-felem out)
           (type secp224r1-wide in)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn (secp224r1-fe-reduce-limbs-asm out in) out)
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  (let ((o (make-array 5 :element-type 'integer :initial-element 0)))
    ;; The multiples of the prime that make the differences positive.
    (setf (aref o 0) (+ (secp224r1-wide-get in 0) (ash 1 127) (ash 1 15))
          (aref o 1) (+ (secp224r1-wide-get in 1) (ash 1 127) (- (ash 1 71)) (- (ash 1 55)))
          (aref o 2) (+ (secp224r1-wide-get in 2) (ash 1 127) (- (ash 1 71)))
          (aref o 3) (secp224r1-wide-get in 3)
          (aref o 4) (secp224r1-wide-get in 4))
    ;; Eliminate the coefficients four, five and six.
    (setf (aref o 4) (+ (aref o 4) (ash (secp224r1-wide-get in 6) -16))
          (aref o 3) (+ (aref o 3) (ash (logand (secp224r1-wide-get in 6) 65535) 40))
          (aref o 2) (- (aref o 2) (secp224r1-wide-get in 6)))
    (setf (aref o 3) (+ (aref o 3) (ash (secp224r1-wide-get in 5) -16))
          (aref o 2) (+ (aref o 2) (ash (logand (secp224r1-wide-get in 5) 65535) 40))
          (aref o 1) (- (aref o 1) (secp224r1-wide-get in 5)))
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
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn (secp224r1-fe-contract-limbs-asm out in) out)
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  (let* ((n (secp224r1-felem-to-int in))
         (m (if (>= n +secp224r1-p+) (- n +secp224r1-p+) n)))
    (declare (type integer n m))
    (dotimes (i 4 out)
      (setf (aref out i) (logand m +secp224r1-limb-mask+))
      (setf m (ash m -56)))))

(defun secp224r1-felem-add (out a b)
  "OUT := (A + B) mod P, by adding the limbs and folding the carry.
A and B are below the prime, so their sum is below twice it; the
carry out of the top limb is a 2^224, which is 2^96 - 1 modulo the
prime, and the contract then brings the result below the prime."
  (declare (type secp224r1-felem out a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((mask +secp224r1-limb-mask+)
         (s0 (+ (aref a 0) (aref b 0)))
         (s1 (+ (aref a 1) (aref b 1)))
         (s2 (+ (aref a 2) (aref b 2)))
         (s3 (+ (aref a 3) (aref b 3))))
    (declare (type (unsigned-byte 64) mask s0 s1 s2 s3))
    ;; Carry zero to one to two to three.
    (setf s1 (+ s1 (ash s0 -56)) s0 (logand s0 mask))
    (setf s2 (+ s2 (ash s1 -56)) s1 (logand s1 mask))
    (setf s3 (+ s3 (ash s2 -56)) s2 (logand s2 mask))
    (let ((c (ash s3 -56)))
      (declare (type (unsigned-byte 64) c))
      (setf s3 (logand s3 mask))
      (when (plusp c)
        ;; 2^224 is 2^96 - 1, whose limbs are (2^56 - 1) and
        ;; (2^40 - 1); add the constant and carry it up.
        (setf s0 (+ s0 mask))
        (setf s1 (+ s1 (ash s0 -56) (1- (ash 1 40))))
        (setf s0 (logand s0 mask))
        (setf s2 (+ s2 (ash s1 -56)) s1 (logand s1 mask))
        (setf s3 (+ s3 (ash s2 -56)) s2 (logand s2 mask))))
    (setf (aref out 0) s0 (aref out 1) s1
          (aref out 2) s2 (aref out 3) s3)
    (secp224r1-felem-contract out out)))

(defun secp224r1-felem-sub (out a b)
  "OUT := (A - B) mod P, by subtracting the limbs and adding the
prime, whose limbs are 1, 2^56 - 2^40, 2^56 - 1 and 2^56 - 1.
A and B are below the prime, so their difference lies in (-P, P).
When it is negative a 2^224 is borrowed into the top limb; adding the
prime then cancels that 2^224, so the carry out is dropped instead of
being folded.  When it is not negative, a carry out is folded as
2^96 - 1.  The contract then brings the result below the prime."
  (declare (type secp224r1-felem out a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((mask +secp224r1-limb-mask+)
         (x0 (- (aref a 0) (aref b 0)))
         (x1 (- (aref a 1) (aref b 1)))
         (x2 (- (aref a 2) (aref b 2)))
         (x3 (- (aref a 3) (aref b 3)))
         (borrow 0))
    (declare (type (signed-byte 64) x0 x1 x2 x3)
             (type (unsigned-byte 1) borrow))
    ;; Borrow zero to one to two to three; the borrow out of the top
    ;; limb is a 2^224.
    (when (minusp x0) (decf x1) (incf x0 (ash 1 56)))
    (when (minusp x1) (decf x2) (incf x1 (ash 1 56)))
    (when (minusp x2) (decf x3) (incf x2 (ash 1 56)))
    (when (minusp x3) (setf borrow 1) (incf x3 (ash 1 56)))
    ;; Add the prime.
    (setf x0 (+ x0 1)
          x1 (+ x1 (- (ash 1 56) (ash 1 40)))
          x2 (+ x2 mask)
          x3 (+ x3 mask))
    ;; Carry zero to one to two to three.
    (setf x1 (+ x1 (ash x0 -56)) x0 (logand x0 mask))
    (setf x2 (+ x2 (ash x1 -56)) x1 (logand x1 mask))
    (setf x3 (+ x3 (ash x2 -56)) x2 (logand x2 mask))
    (let ((c (ash x3 -56)))
      (declare (type (unsigned-byte 64) c))
      (setf x3 (logand x3 mask))
      ;; The borrowed 2^224 and the carry out of the sum cancel; only
      ;; a carry with no borrow is a real 2^224, folded as 2^96 - 1.
      (when (and (plusp c) (zerop borrow))
        (setf x0 (+ x0 mask))
        (setf x1 (+ x1 (ash x0 -56) (1- (ash 1 40))))
        (setf x0 (logand x0 mask))
        (setf x2 (+ x2 (ash x1 -56)) x1 (logand x1 mask))
        (setf x3 (+ x3 (ash x2 -56)) x2 (logand x2 mask))))
    (setf (aref out 0) x0 (aref out 1) x1
          (aref out 2) x2 (aref out 3) x3)
    (secp224r1-felem-contract out out)))

;; The prime in limbs.  This is a DEFVAR and not a DEFCONSTANT: the
;; value is a vector, and a DEFCONSTANT whose value is a vector makes
;; every recompilation of this file fail with DEFCONSTANT-UNEQL.
(defvar +secp224r1-p-limbs+ '#(1 0 0 4294967295 4294967295 4294967295
                              4294967295))

(deftype secp224r1-fe () '(simple-array (unsigned-byte 64) (4)))

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
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn (secp224r1-fe-mul-limbs-asm c a b) c)
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn (secp224r1-felem-mul c a b) c))

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
  "True when the field element A is zero.
A reduced element is below twice the prime, so it is zero when it is
zero, the prime, or twice the prime; the reference checks the three."
  (declare (type secp224r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((a0 (aref a 0)) (a1 (aref a 1))
        (a2 (aref a 2)) (a3 (aref a 3))
        (mask +secp224r1-limb-mask+))
    (declare (type (unsigned-byte 64) a0 a1 a2 a3 mask))
    (or (and (zerop a0) (zerop a1) (zerop a2) (zerop a3))
        (and (= a0 1) (= a1 #x00ffff0000000000)
             (= a2 mask) (= a3 mask))
        (and (= a0 2) (= a1 #x00fffe0000000000)
             (= a2 mask) (= a3 #x01ffffffffffffff)))))

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
  (let ((s (make-array 24)))
    (dotimes (i 21 s)
      (setf (svref s i) (secp224r1-fe-zero)))
    (setf (svref s 21)
          (make-array 14 :element-type '(unsigned-byte 64)
                          :initial-element 0))
    (setf (svref s 22)
          (make-array 14 :element-type '(unsigned-byte 64)
                          :initial-element 0))
    (setf (svref s 23)
          (make-array 7 :element-type 'integer :initial-element 0))
    s))

;;; The wide coefficients of the reference are pairs of words, the low
;;; word first, so that every operation on them is exact modulo 2^128,
;;; which is what the reduction of the reference assumes.  The helpers
;;; below work on the two words directly, so that no bignum is made.

(defconstant +secp224r1-u64-mask+ #xffffffffffffffff)
(defconstant +secp224r1-two58p2+ #x400000000000004)
(defconstant +secp224r1-two58m42m2+ #x3fffbfffffffffc)
(defconstant +secp224r1-two58m2+ #x3fffffffffffffc)
(defconstant +secp224r1-two64p8-lo+ #x100)
(defconstant +secp224r1-two64m8+ #xffffffffffffff00)
(defconstant +secp224r1-two64m48m8+ #xfffeffffffffff00)

(declaim (inline secp224r1-wide-add! secp224r1-wide-sub!
                 secp224r1-wide-from-fe secp224r1-felem-sum!
                 secp224r1-felem-diff! secp224r1-felem-scalar!
                 secp224r1-wide-add-pair! secp224r1-wide-sub-word!
                 secp224r1-wide-diff-128-64!))

(defun secp224r1-wide-add-pair! (w k lo hi)
  "Add (HI:LO) to coefficient K of W, modulo 2^128."
  (declare (type secp224r1-wide w)
           (type (integer 0 6) k)
           (type (unsigned-byte 64) lo hi)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((i (* 2 k))
         (l (aref w i))
         (s (logand (+ l lo) +secp224r1-u64-mask+)))
    (setf (aref w i) s
          (aref w (1+ i))
          (logand (+ (aref w (1+ i)) hi (if (< s l) 1 0))
                  +secp224r1-u64-mask+))
    w))

(defun secp224r1-wide-sub-word! (w k v)
  "Subtract the word V from coefficient K of W, modulo 2^128."
  (declare (type secp224r1-wide w)
           (type (integer 0 6) k)
           (type (unsigned-byte 64) v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((i (* 2 k))
         (l (aref w i))
         (s (logand (- l v) +secp224r1-u64-mask+)))
    (setf (aref w i) s
          (aref w (1+ i))
          (logand (- (aref w (1+ i)) (if (< l v) 1 0))
                  +secp224r1-u64-mask+))
    w))

(defun secp224r1-wide-add! (out in)
  "OUT := OUT + IN, coefficient by coefficient, modulo 2^128."
  (declare (type secp224r1-wide out in)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (k 7 out)
    (let* ((i (* 2 k))
           (l (aref out i))
           (s (logand (+ l (aref in i)) +secp224r1-u64-mask+)))
      (setf (aref out i) s
            (aref out (1+ i))
            (logand (+ (aref out (1+ i)) (aref in (1+ i))
                       (if (< s l) 1 0))
                    +secp224r1-u64-mask+)))))

(defun secp224r1-wide-sub! (out in)
  "OUT := OUT - IN, coefficient by coefficient, modulo 2^128."
  (declare (type secp224r1-wide out in)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (k 7 out)
    (let* ((i (* 2 k))
           (l (aref out i))
           (v (aref in i))
           (s (logand (- l v) +secp224r1-u64-mask+)))
      (setf (aref out i) s
            (aref out (1+ i))
            (logand (- (aref out (1+ i)) (aref in (1+ i))
                       (if (< l v) 1 0))
                    +secp224r1-u64-mask+)))))

(defun secp224r1-wide-sub-pair! (w k lo hi)
  "Subtract (HI:LO) from coefficient K of W, modulo 2^128."
  (declare (type secp224r1-wide w)
           (type (integer 0 6) k)
           (type (unsigned-byte 64) lo hi)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((i (* 2 k))
         (l (aref w i))
         (s (logand (- l lo) +secp224r1-u64-mask+)))
    (setf (aref w i) s
          (aref w (1+ i))
          (logand (- (aref w (1+ i)) hi (if (< l lo) 1 0))
                  +secp224r1-u64-mask+))
    w))

(defun secp224r1-wide-diff! (out in)
  "OUT := OUT - IN, after the reference: a multiple of the prime is
added first, so that no coefficient borrows, and the coefficients of
IN stay below 2^127."
  (declare (type secp224r1-wide out in)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; two120, two120 - 2^64, and two120 - 2^104 - 2^64.
  (secp224r1-wide-add-pair! out 0 0 (ash 1 56))
  (secp224r1-wide-add-pair! out 1 0 (1- (ash 1 56)))
  (secp224r1-wide-add-pair! out 2 0 (1- (ash 1 56)))
  (secp224r1-wide-add-pair! out 3 0 (ash 1 56))
  (secp224r1-wide-add-pair! out 4 0 (- (ash 1 56) (ash 1 40) 1))
  (secp224r1-wide-add-pair! out 5 0 (1- (ash 1 56)))
  (secp224r1-wide-add-pair! out 6 0 (1- (ash 1 56)))
  (dotimes (k 7 out)
    (secp224r1-wide-sub-pair! out k (aref in (* 2 k)) (aref in (1+ (* 2 k))))))

(defun secp224r1-wide-scalar! (w k)
  "W := W * K, coefficient by coefficient, modulo 2^128."
  (declare (type secp224r1-wide w)
           (type (integer 0 65535) k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 7 w)
    (let* ((j (* 2 i))
           (p (* (aref w j) k))
           (l (logand p +secp224r1-u64-mask+)))
      (setf (aref w j) l
            (aref w (1+ j))
            (logand (+ (* (aref w (1+ j)) k) (ash p -64))
                    +secp224r1-u64-mask+)))))

(defun secp224r1-wide-from-fe (w a)
  "W := A, as seven wide coefficients; the high words are zero."
  (declare (type secp224r1-wide w)
           (type secp224r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (loop for i from 0 below 7
        do (setf (aref w (* 2 i)) (if (< i 4) (aref a i) 0)
                 (aref w (1+ (* 2 i))) 0))
  w)

(defun secp224r1-wide-diff-128-64! (w a)
  "W := W - A, after the reference: a multiple of the prime is added
first, so that the subtraction cannot borrow."
  (declare (type secp224r1-wide w)
           (type secp224r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp224r1-wide-add-pair! w 0 +secp224r1-two64p8-lo+ 1)
  (secp224r1-wide-add-pair! w 1 +secp224r1-two64m48m8+ 0)
  (secp224r1-wide-add-pair! w 2 +secp224r1-two64m8+ 0)
  (secp224r1-wide-add-pair! w 3 +secp224r1-two64m8+ 0)
  (dotimes (i 4 w)
    (secp224r1-wide-sub-word! w i (aref a i))))

(defun secp224r1-felem-sum! (out in)
  "OUT := OUT + IN, limb by limb, without reducing."
  (declare (type secp224r1-fe out in)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (aref out 0) (+ (aref out 0) (aref in 0))
        (aref out 1) (+ (aref out 1) (aref in 1))
        (aref out 2) (+ (aref out 2) (aref in 2))
        (aref out 3) (+ (aref out 3) (aref in 3)))
  out)

(defun secp224r1-felem-diff! (out in)
  "OUT := OUT - IN, after the reference: the multiple of the prime is
added first, so that every limb of the difference is positive."
  (declare (type secp224r1-fe out in)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (aref out 0) (+ (aref out 0) +secp224r1-two58p2+
                        (- (aref in 0)))
        (aref out 1) (+ (aref out 1) +secp224r1-two58m42m2+
                        (- (aref in 1)))
        (aref out 2) (+ (aref out 2) +secp224r1-two58m2+
                        (- (aref in 2)))
        (aref out 3) (+ (aref out 3) +secp224r1-two58m2+
                        (- (aref in 3))))
  out)

(defun secp224r1-felem-scalar! (out k)
  "OUT := OUT * K, limb by limb, without reducing."
  (declare (type secp224r1-fe out)
           (type (integer 0 65535) k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (aref out 0) (* (aref out 0) k)
        (aref out 1) (* (aref out 1) k)
        (aref out 2) (* (aref out 2) k)
        (aref out 3) (* (aref out 3) k))
  out)

(defun secp224r1-double! (dx dy dz x1 y1 z1 s)
  "The double of the point (X1 : Y1 : Z1), into (DX : DY : DZ), after
the reference: the sums and differences stay unreduced, and only the
products are reduced.  S is the scratch pool."
  (declare (type secp224r1-fe dx dy dz x1 y1 z1)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((delta (svref s 0)) (gamma (svref s 1)) (beta (svref s 2))
         (alpha (svref s 3)) (ftmp (svref s 4)) (ftmp2 (svref s 5))
         (w (svref s 21)) (w2 (svref s 22)))
    (declare (type secp224r1-fe delta gamma beta alpha ftmp ftmp2)
             (type secp224r1-wide w w2))
    ;; delta = z^2
    (secp224r1-fe-mul-raw w z1 z1)
    (secp224r1-felem-reduce delta w)
    ;; gamma = y^2
    (secp224r1-fe-mul-raw w y1 y1)
    (secp224r1-felem-reduce gamma w)
    ;; beta = x*gamma
    (secp224r1-fe-mul-raw w x1 gamma)
    (secp224r1-felem-reduce beta w)
    ;; alpha = 3*(x-delta)*(x+delta)
    (secp224r1-fe-copy! ftmp x1)
    (secp224r1-felem-diff! ftmp delta)
    (secp224r1-fe-copy! ftmp2 x1)
    (secp224r1-felem-sum! ftmp2 delta)
    (secp224r1-felem-scalar! ftmp2 3)
    (secp224r1-fe-mul-raw w ftmp ftmp2)
    (secp224r1-felem-reduce alpha w)
    ;; x' = alpha^2 - 8*beta
    (secp224r1-fe-mul-raw w alpha alpha)
    (secp224r1-fe-copy! ftmp beta)
    (secp224r1-felem-scalar! ftmp 8)
    (secp224r1-wide-diff-128-64! w ftmp)
    (secp224r1-felem-reduce dx w)
    ;; z' = (y+z)^2 - gamma - delta
    (secp224r1-felem-sum! delta gamma)
    (secp224r1-fe-copy! ftmp y1)
    (secp224r1-felem-sum! ftmp z1)
    (secp224r1-fe-mul-raw w ftmp ftmp)
    (secp224r1-wide-diff-128-64! w delta)
    (secp224r1-felem-reduce dz w)
    ;; y' = alpha*(4*beta - x') - 8*gamma^2
    (secp224r1-felem-scalar! beta 4)
    (secp224r1-felem-diff! beta dx)
    (secp224r1-fe-mul-raw w alpha beta)
    (secp224r1-fe-mul-raw w2 gamma gamma)
    (secp224r1-wide-scalar! w2 8)
    (secp224r1-wide-diff! w w2)
    (secp224r1-felem-reduce dy w)
    dz))

(defun secp224r1-add! (dx dy dz x1 y1 z1 x2 y2 z2 s)
  "The sum of the points (X1 : Y1 : Z1) and (X2 : Y2 : Z2), into
(DX : DY : DZ), after the reference.  S is the scratch pool."
  (declare (type secp224r1-fe dx dy dz x1 y1 z1 x2 y2 z2)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((ftmp (svref s 0)) (ftmp2 (svref s 1)) (ftmp3 (svref s 2))
         (ftmp4 (svref s 3)) (ftmp5 (svref s 4)) (xo (svref s 5))
         (yo (svref s 6)) (zo (svref s 7))
         (w (svref s 21)) (w2 (svref s 22)))
    (declare (type secp224r1-fe ftmp ftmp2 ftmp3 ftmp4 ftmp5 xo yo zo)
             (type secp224r1-wide w w2))
    ;; The formulas are not complete; the point at infinity is taken
    ;; out first.
    (when (secp224r1-fe-is-zero z1)
      (secp224r1-fe-copy! dx x2) (secp224r1-fe-copy! dy y2)
      (secp224r1-fe-copy! dz z2)
      (return-from secp224r1-add! dz))
    (when (secp224r1-fe-is-zero z2)
      (secp224r1-fe-copy! dx x1) (secp224r1-fe-copy! dy y1)
      (secp224r1-fe-copy! dz z1)
      (return-from secp224r1-add! dz))
    ;; ftmp2 = z2^2
    (secp224r1-fe-mul-raw w z2 z2)
    (secp224r1-felem-reduce ftmp2 w)
    ;; ftmp4 = z2^3
    (secp224r1-fe-mul-raw w ftmp2 z2)
    (secp224r1-felem-reduce ftmp4 w)
    ;; ftmp4 = z2^3*y1
    (secp224r1-fe-mul-raw w2 ftmp4 y1)
    (secp224r1-felem-reduce ftmp4 w2)
    ;; ftmp2 = z2^2*x1
    (secp224r1-fe-mul-raw w2 ftmp2 x1)
    (secp224r1-felem-reduce ftmp2 w2)
    ;; ftmp = z1^2
    (secp224r1-fe-mul-raw w z1 z1)
    (secp224r1-felem-reduce ftmp w)
    ;; ftmp3 = z1^3
    (secp224r1-fe-mul-raw w ftmp z1)
    (secp224r1-felem-reduce ftmp3 w)
    ;; ftmp3 = z1^3*y2 - z2^3*y1
    (secp224r1-fe-mul-raw w ftmp3 y2)
    (secp224r1-wide-diff-128-64! w ftmp4)
    (secp224r1-felem-reduce ftmp3 w)
    ;; ftmp = z1^2*x2 - z2^2*x1
    (secp224r1-fe-mul-raw w ftmp x2)
    (secp224r1-wide-diff-128-64! w ftmp2)
    (secp224r1-felem-reduce ftmp w)
    ;; The sum of two equal points is their double.
    (when (and (secp224r1-fe-is-zero ftmp)
               (secp224r1-fe-is-zero ftmp3))
      (return-from secp224r1-add! (secp224r1-double! dx dy dz x1 y1 z1 s)))
    ;; ftmp5 = z1*z2
    (secp224r1-fe-mul-raw w z1 z2)
    (secp224r1-felem-reduce ftmp5 w)
    ;; z_out = ftmp*ftmp5
    (secp224r1-fe-mul-raw w ftmp ftmp5)
    (secp224r1-felem-reduce zo w)
    ;; ftmp = ftmp^2
    (secp224r1-fe-copy! ftmp5 ftmp)
    (secp224r1-fe-mul-raw w ftmp ftmp)
    (secp224r1-felem-reduce ftmp w)
    ;; ftmp5 = ftmp*ftmp5 (the cube of h)
    (secp224r1-fe-mul-raw w ftmp ftmp5)
    (secp224r1-felem-reduce ftmp5 w)
    ;; ftmp2 = ftmp2*ftmp
    (secp224r1-fe-mul-raw w ftmp2 ftmp)
    (secp224r1-felem-reduce ftmp2 w)
    ;; w = ftmp4*ftmp5
    (secp224r1-fe-mul-raw w ftmp4 ftmp5)
    ;; w2 = ftmp3^2 - ftmp5
    (secp224r1-fe-mul-raw w2 ftmp3 ftmp3)
    (secp224r1-wide-diff-128-64! w2 ftmp5)
    ;; x_out = ftmp3^2 - ftmp5^? ... after the reference:
    (secp224r1-fe-copy! ftmp5 ftmp2)
    (secp224r1-felem-scalar! ftmp5 2)
    (secp224r1-wide-diff-128-64! w2 ftmp5)
    (secp224r1-felem-reduce xo w2)
    ;; ftmp2 = ftmp2 - x_out
    (secp224r1-felem-diff! ftmp2 xo)
    ;; w2 = ftmp3*ftmp2 - w
    (secp224r1-fe-mul-raw w2 ftmp3 ftmp2)
    (secp224r1-wide-diff! w2 w)
    (secp224r1-felem-reduce yo w2)
    (secp224r1-fe-copy! dx xo)
    (secp224r1-fe-copy! dy yo)
    (secp224r1-fe-copy! dz zo)
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
  ;; The point operations leave the coordinates reduced but not
  ;; contracted, so they are brought below the prime before they leave
  ;; the limb field.
  (let ((c (secp224r1-fe-zero)) (xi 0) (yi 0) (zi 0))
    (secp224r1-fe-copy! c x)
    (secp224r1-felem-contract c c)
    (setf xi (secp224r1-fe-to-int c))
    (secp224r1-fe-copy! c y)
    (secp224r1-felem-contract c c)
    (setf yi (secp224r1-fe-to-int c))
    (secp224r1-fe-copy! c z)
    (secp224r1-felem-contract c c)
    (setf zi (secp224r1-fe-to-int c))
    (make-instance 'secp224r1-point :x xi :y yi :z zi)))

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

(defvar *secp224r1-base-table-positional* nil
  "T[J][V] = V * 256^J * G, in limbs, as a 32-row 16x16 matrix.")

(defun secp224r1-build-base-table-positional ()
  "Build the positional table T[J][V] = V * 256^J * G."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((rows (make-array 32))
        (s (secp224r1-make-scratch))
        (bx (secp224r1-fe-from-int (slot-value +secp224r1-g+ 'x)))
        (by (secp224r1-fe-from-int (slot-value +secp224r1-g+ 'y)))
        (bz (secp224r1-fe-from-int 1)))
    (declare (type simple-vector rows)
             (type simple-vector s)
             (type secp224r1-fe bx by bz))
    (flet ((cp (a)
             (let ((c (secp224r1-fe-zero)))
               (secp224r1-fe-copy! c a)
               c)))
      (dotimes (j 32 (progn (setf *secp224r1-base-table-positional* rows) rows))
        (declare (type fixnum j))
        (let ((flat (make-array 256)))
          (declare (type simple-vector flat))
          (setf (aref flat 0)
                (vector (secp224r1-fe-from-int 1)
                        (secp224r1-fe-from-int 1)
                        (secp224r1-fe-from-int 0)))
          (setf (aref flat 1)
                (vector (cp bx) (cp by) (cp bz)))
          (loop for v of-type fixnum from 2 below 256 do
            (let ((x (secp224r1-fe-zero))
                  (y (secp224r1-fe-zero))
                  (z (secp224r1-fe-zero)))
              (if (evenp v)
                  (let ((src (aref flat (ash v -1))))
                    (secp224r1-double! x y z
                                       (aref src 0) (aref src 1) (aref src 2) s))
                  (let ((src (aref flat (1- v)))
                        (one (aref flat 1)))
                    (secp224r1-add! x y z
                                    (aref src 0) (aref src 1) (aref src 2)
                                    (aref one 0) (aref one 1) (aref one 2) s)))
              (setf (aref flat v) (vector x y z))))
          ;; Sixteen sub-rows of sixteen, for a two-level constant-time
          ;; selection.
          (let ((subs (make-array 16)))
            (dotimes (h 16)
              (let ((sub (make-array 16)))
                (dotimes (l 16)
                  (setf (aref sub l) (aref flat (+ (* 16 h) l))))
                (setf (aref subs h) sub)))
            (setf (aref rows j) subs))
          ;; base := 256 * base
          (dotimes (i 8)
            (declare (ignore i))
            (let ((x (secp224r1-fe-zero))
                  (y (secp224r1-fe-zero))
                  (z (secp224r1-fe-zero)))
              (secp224r1-double! x y z bx by bz s)
              (setf bx x by y bz z))))))))

(declaim (inline secp224r1-select-base-positional))
(defun secp224r1-select-base-positional (row v)
  "Select V from a 16x16 matrix of point triples by two linear scans."
  (declare (type simple-vector row)
           (type (unsigned-byte 8) v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((hi (ash v -4))
         (lo (logand v 15))
         (sub (aref row 0)))
    (declare (type (unsigned-byte 4) hi lo)
             (type simple-vector sub))
    (loop for i of-type fixnum from 1 below 16
          do (when (= i hi) (setf sub (aref row i))))
    (let ((sel (aref sub 0)))
      (loop for i of-type fixnum from 1 below 16
            do (when (= i lo) (setf sel (aref sub i))))
      sel)))

(defun secp224r1-base-mult-positional-limbs (k)
  "K*G using the positional byte table: twenty-eight additions, no
doublings.  Returns the three coordinates as multiple values."
  (declare (type integer k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (or *secp224r1-base-table-positional*
                   (setf *secp224r1-base-table-positional*
                         (secp224r1-build-base-table-positional))))
        (s (secp224r1-make-scratch))
        (ax (secp224r1-fe-from-int 1))
        (ay (secp224r1-fe-from-int 1))
        (az (secp224r1-fe-from-int 0))
        (tx (secp224r1-fe-zero))
        (ty (secp224r1-fe-zero))
        (tz (secp224r1-fe-zero)))
    (declare (type simple-vector table s)
             (type secp224r1-fe ax ay az tx ty tz))
    ;; K < L < 2^224, so bytes 0..27 are all that can be nonzero.
    (loop for j of-type fixnum from 27 downto 0 do
      (let ((v (ldb (byte 8 (* j 8)) k)))
        (declare (type (unsigned-byte 8) v))
        (unless (zerop v)
          (let ((sel (secp224r1-select-base-positional (aref table j) v)))
            (declare (type simple-vector sel))
            (secp224r1-add! tx ty tz ax ay az
                            (aref sel 0) (aref sel 1) (aref sel 2) s)
            (secp224r1-swap3 ax ay az tx ty tz)))))
    (values ax ay az)))

(defun secp224r1-base-mult-positional (k)
  "K*G as a point."
  (multiple-value-bind (x y z) (secp224r1-base-mult-positional-limbs k)
    (secp224r1-point-from-limbs x y z)))

(defun secp224r1-window-mult-limbs (px py pz e)
  "E times the limb point (PX : PY : PZ) with four-bit windows.
Returns the three coordinates as multiple values."
  (declare (type secp224r1-fe px py pz)
           (type integer e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (make-array 16))
        (s (secp224r1-make-scratch))
        (ax (secp224r1-fe-from-int 1))
        (ay (secp224r1-fe-from-int 1))
        (az (secp224r1-fe-from-int 0))
        (tx (secp224r1-fe-zero))
        (ty (secp224r1-fe-zero))
        (tz (secp224r1-fe-zero)))
    (declare (type simple-vector table s)
             (type secp224r1-fe ax ay az tx ty tz))
    (setf (aref table 0)
          (vector (secp224r1-fe-from-int 1)
                  (secp224r1-fe-from-int 1)
                  (secp224r1-fe-from-int 0)))
    (setf (aref table 1) (vector px py pz))
    (loop for v of-type fixnum from 2 below 16 do
      (let ((x (secp224r1-fe-zero))
            (y (secp224r1-fe-zero))
            (z (secp224r1-fe-zero)))
        (if (evenp v)
            (let ((src (aref table (ash v -1))))
              (secp224r1-double! x y z
                                 (aref src 0) (aref src 1) (aref src 2) s))
            (let ((src (aref table (1- v)))
                  (one (aref table 1)))
              (secp224r1-add! x y z
                              (aref src 0) (aref src 1) (aref src 2)
                              (aref one 0) (aref one 1) (aref one 2) s)))
        (setf (aref table v) (vector x y z))))
    (let ((nibbles (ceiling (integer-length e) 4)))
      (declare (type fixnum nibbles))
      (loop for j of-type fixnum downfrom (1- nibbles) to 0 do
        (unless (= j (1- nibbles))
          (dotimes (i 4)
            (declare (ignore i))
            (secp224r1-double! tx ty tz ax ay az s)
            (secp224r1-swap3 ax ay az tx ty tz)))
        (let ((v (ldb (byte 4 (* j 4)) e)))
          (declare (type (unsigned-byte 4) v))
          (unless (zerop v)
            (let ((sel (aref table v)))
              (declare (type simple-vector sel))
              (secp224r1-add! tx ty tz ax ay az
                              (aref sel 0) (aref sel 1) (aref sel 2) s)
              (secp224r1-swap3 ax ay az tx ty tz))))))
    (values ax ay az)))

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

(defun secp224r1-binary-joint-mult-limbs (x1 y1 z1 x2 y2 z2 a b)
  "A times (X1 : Y1 : Z1) plus B times (X2 : Y2 : Z2), bit by bit."
  (declare (type integer x1 y1 z1 x2 y2 z2 a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((s (secp224r1-make-scratch))
         (px (secp224r1-fe-from-int x1)) (py (secp224r1-fe-from-int y1))
         (pz (secp224r1-fe-from-int z1))
         (qx (secp224r1-fe-from-int x2)) (qy (secp224r1-fe-from-int y2))
         (qz (secp224r1-fe-from-int z2))
         (pqx (secp224r1-fe-zero)) (pqy (secp224r1-fe-zero))
         (pqz (secp224r1-fe-zero))
         (rx (secp224r1-fe-from-int 1)) (ry (secp224r1-fe-from-int 1))
         (rz (secp224r1-fe-from-int 0))
         (tx (secp224r1-fe-zero)) (ty (secp224r1-fe-zero))
         (tz (secp224r1-fe-zero)))
    (declare (type secp224r1-fe px py pz qx qy qz pqx pqy pqz
                   rx ry rz tx ty tz))
    (secp224r1-add! pqx pqy pqz px py pz qx qy qz s)
    (loop for i downfrom (1- (max (integer-length a)
                                  (integer-length b) 1)) to 0 do
      (secp224r1-double! tx ty tz rx ry rz s)
      (secp224r1-swap3 rx ry rz tx ty tz)
      (let ((ai (logbitp i a)) (bi (logbitp i b)))
        (cond ((and ai bi)
               (secp224r1-add! tx ty tz rx ry rz pqx pqy pqz s))
              (ai
               (secp224r1-add! tx ty tz rx ry rz px py pz s))
              (bi
               (secp224r1-add! tx ty tz rx ry rz qx qy qz s)))
        (when (or ai bi)
          (secp224r1-swap3 rx ry rz tx ty tz))))
    (secp224r1-point-from-limbs rx ry rz)))

(defun secp224r1-shamir-mult-limbs (x1 y1 z1 x2 y2 z2 a b)
  "A times G plus B times (X2 : Y2 : Z2).  When the first point is the
generator, use the positional table for A*G and a four-bit window for
B*Q, then add the two; otherwise fall back to the bit-by-bit joint
multiplication."
  (declare (type integer x1 y1 z1 x2 y2 z2 a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((gx (slot-value +secp224r1-g+ 'x))
        (gy (slot-value +secp224r1-g+ 'y))
        (gz (slot-value +secp224r1-g+ 'z)))
    (if (and (= x1 gx) (= y1 gy) (= z1 gz))
        (multiple-value-bind (px py pz) (secp224r1-base-mult-positional-limbs a)
          (multiple-value-bind (qx qy qz)
              (secp224r1-window-mult-limbs
               (secp224r1-fe-from-int x2)
               (secp224r1-fe-from-int y2)
               (secp224r1-fe-from-int z2)
               b)
            (let ((s (secp224r1-make-scratch))
                  (rx (secp224r1-fe-zero))
                  (ry (secp224r1-fe-zero))
                  (rz (secp224r1-fe-zero)))
              (declare (type simple-vector s)
                       (type secp224r1-fe rx ry rz))
              (secp224r1-add! rx ry rz px py pz qx qy qz s)
              (secp224r1-point-from-limbs rx ry rz))))
        (secp224r1-binary-joint-mult-limbs x1 y1 z1 x2 y2 z2 a b))))

(defun secp224r1-fe-mul (a b)
  "The product of the field elements A and B, reduced."
  (declare (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((c (make-array 14 :element-type '(unsigned-byte 64)
                           :initial-element 0))
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
