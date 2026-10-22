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

;; The prime in limbs.  This is a DEFVAR and not a DEFCONSTANT: the
;; value is a vector, and a DEFCONSTANT whose value is a vector makes
;; every recompilation of this file fail with DEFCONSTANT-UNEQL.
(defvar +secp224r1-p-limbs+ '#(1 0 0 4294967295 4294967295 4294967295
                              4294967295))

(deftype secp224r1-fe () '(simple-array (unsigned-byte 32) (7)))

(declaim (inline secp224r1-fe-zero secp224r1-fe-from-int
                 secp224r1-fe-to-int))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun secp224r1-fe-zero ()
    (make-array 7 :element-type '(unsigned-byte 32) :initial-element 0)))

(defun secp224r1-fe-from-int (n)
  "The field element N, reduced."
  (declare (type integer n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (secp224r1-fe-zero)))
    (dotimes (i 7 r)
      (setf (aref r i) (ldb (byte 32 (* i 32)) n)))))

(defun secp224r1-fe-to-int (a)
  "The integer value of the field element A."
  (declare (type secp224r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((n 0))
    (declare (type integer n))
    (dotimes (i 7 n)
      (setf n (dpb (aref a i) (byte 32 (* i 32)) n)))))

(defun secp224r1-fe-mul-raw (c a b)
  "C := A * B, as fourteen limbs of 32 bits, in words of 64 bits."
  (declare (type secp224r1-fe a b)
           (type (simple-array (unsigned-byte 64) (14)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-assembly)
  (secp224r1-fe-mul-raw-asm c a b)
  #-(and sbcl x86-64 ironclad-assembly)
  (progn
    (dotimes (k 14) (setf (aref c k) 0))
  (dotimes (i 7)
    (let ((carry 0))
      (declare (type integer carry))
      (dotimes (j 7)
        (let* ((prod (* (aref a i) (aref b j)))
               (plo (ldb (byte 32 0) prod))
               (phi (ash prod -32))
               (k (+ i j))
               (s (+ (aref c k) plo carry)))
          (setf (aref c k) (logand s #xffffffff)
                carry (+ (ash s -32) phi))))
      ;; The carry can be larger than a limb, so it is propagated.
      (loop for k from (+ i 7) below 14
            while (plusp carry)
            do (let ((s (+ (aref c k) carry)))
                 (setf (aref c k) (logand s #xffffffff)
                       carry (ash s -32)))))))
  c)

(defun secp224r1-fe-add (a b)
  "The sum of the field elements A and B, reduced."
  (declare (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; The reduction of a product takes the low half and the high half
  ;; of the value; a sum has no high half, so the words above the
  ;; seventh are zero, and the reduction folds the value back in.
  (let ((c (make-array 14 :element-type '(unsigned-byte 64) :initial-element 0))
        (r (secp224r1-fe-zero)))
    (dotimes (i 7)
      (setf (aref c i) (+ (aref a i) (aref b i))))
    (secp224r1-fe-reduce r c)
    r))
(defun secp224r1-fe-sub (a b)
  "The difference of the field elements A and B, reduced."
  (declare (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((c (make-array 14 :element-type '(unsigned-byte 64) :initial-element 0))
        (r (secp224r1-fe-zero))
        (borrow 0) (carry 0))
    ;; The borrow is subtracted: it is a whole B^7 when it is not
    ;; zero, and the borrow out is its magnitude.
    (dotimes (i 7)
      (let ((v (- (- (aref a i) (aref b i)) borrow)))
        (setf (aref c i) (logand v #xffffffff)
              borrow (if (minusp v) 1 0))))
    ;; The difference is negative when there was a borrow, and the
    ;; prime is added to it.
    (when (= borrow 1)
      (setf carry 0)
      (dotimes (i 7)
        (let ((v (+ (aref c i) (aref +secp224r1-p-limbs+ i) carry)))
          (setf (aref c i) (logand v #xffffffff)
                carry (ash v -32)))))
    (secp224r1-fe-reduce r c)
    r))
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

(defun secp224r1-fe-equal (a b)
  "True when the field elements A and B are the same."
  (declare (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (and (= (aref a 0) (aref b 0))
       (= (aref a 1) (aref b 1))
       (= (aref a 2) (aref b 2))
       (= (aref a 3) (aref b 3))
       (= (aref a 4) (aref b 4))
       (= (aref a 5) (aref b 5))
       (= (aref a 6) (aref b 6))))

(defun secp224r1-point-double-limbs (x1 y1 z1)
  "The double of the point (X1 : Y1 : Z1), in limbs.
The three coordinates are returned as multiple values."
  (declare (type secp224r1-fe x1 y1 z1)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((xx (secp224r1-fe-mul x1 x1))
         (yy (secp224r1-fe-mul y1 y1))
         (yyyy (secp224r1-fe-mul yy yy))
         (zz (secp224r1-fe-mul z1 z1))
         (x1+yy (secp224r1-fe-add x1 yy))
         (y1+z1 (secp224r1-fe-add y1 z1))
         ;; s = 2*((x1+yy)^2 - xx - yyyy)
         (w (secp224r1-fe-mul x1+yy x1+yy))
         (w (secp224r1-fe-sub w xx))
         (w (secp224r1-fe-sub w yyyy))
         (s (secp224r1-fe-mul +secp224r1-two+ w))
         ;; m = 3*(xx - zz^2), for the curve whose a is -3
         (w (secp224r1-fe-mul zz zz))
         (w (secp224r1-fe-sub xx w))
         (m (secp224r1-fe-mul +secp224r1-three+ w))
         ;; u = m^2 - 2s
         (u (secp224r1-fe-mul m m))
         (u (secp224r1-fe-sub u (secp224r1-fe-mul +secp224r1-two+ s)))
         ;; y2 = m*(s - u) - 8*yyyy
         (w (secp224r1-fe-sub s u))
         (w (secp224r1-fe-mul m w))
         (y2 (secp224r1-fe-sub w (secp224r1-fe-mul +secp224r1-eight+ yyyy)))
         ;; z2 = (y1+z1)^2 - yy - zz
         (w (secp224r1-fe-mul y1+z1 y1+z1))
         (w (secp224r1-fe-sub w yy))
         (z2 (secp224r1-fe-sub w zz)))
    (values u y2 z2)))

(defun secp224r1-point-add-limbs (x1 y1 z1 x2 y2 z2)
  "The sum of the points (X1 : Y1 : Z1) and (X2 : Y2 : Z2), in limbs.
The three coordinates are returned as multiple values."
  (declare (type secp224r1-fe x1 y1 z1 x2 y2 z2)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((z1z1 (secp224r1-fe-mul z1 z1))
         (z2z2 (secp224r1-fe-mul z2 z2))
         (u1 (secp224r1-fe-mul x1 z2z2))
         (u2 (secp224r1-fe-mul x2 z1z1))
         (s1 (secp224r1-fe-mul y1 (secp224r1-fe-mul z2 z2z2)))
         (s2 (secp224r1-fe-mul y2 (secp224r1-fe-mul z1 z1z1))))
    (if (secp224r1-fe-equal u1 u2)
        (if (secp224r1-fe-equal s1 s2)
            ;; The points are the same, so the sum is the double.
            (secp224r1-point-double-limbs x1 y1 z1)
            ;; The points are opposites, so the sum is at infinity.
            (values +secp224r1-one+ +secp224r1-one+ (secp224r1-fe-zero)))
        (let* ((h (secp224r1-fe-sub u2 u1))
               (i (secp224r1-fe-mul (secp224r1-fe-mul +secp224r1-four+ h) h))
               (j (secp224r1-fe-mul h i))
               (r (secp224r1-fe-mul +secp224r1-two+
                                 (secp224r1-fe-sub s2 s1)))
               (v (secp224r1-fe-mul u1 i))
               ;; x3 = r^2 - j - 2v
               (x3 (secp224r1-fe-mul r r))
               (x3 (secp224r1-fe-sub x3 j))
               (x3 (secp224r1-fe-sub x3 (secp224r1-fe-mul +secp224r1-two+ v)))
               ;; y3 = r*(v - x3) - 2*s1*j
               (w (secp224r1-fe-sub v x3))
               (w (secp224r1-fe-mul r w))
               (y3 (secp224r1-fe-sub w
                              (secp224r1-fe-mul +secp224r1-two+
                                            (secp224r1-fe-mul s1 j))))
               ;; z3 = ((z1+z2)^2 - z1z1 - z2z2)*h
               (z1+z2 (secp224r1-fe-add z1 z2))
               (w (secp224r1-fe-mul z1+z2 z1+z2))
               (w (secp224r1-fe-sub w z1z1))
               (w (secp224r1-fe-sub w z2z2))
               (z3 (secp224r1-fe-mul w h)))
          (values x3 y3 z3)))))

(defun secp224r1-fe-mul (a b)
  "The product of the field elements A and B, reduced."
  (declare (type secp224r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((c (make-array 14 :element-type '(unsigned-byte 64) :initial-element 0))
        (r (secp224r1-fe-zero)))
    (secp224r1-fe-mul-raw c a b)
    (secp224r1-fe-reduce r c)
    r))

(defun secp224r1-fe-reduce (r c)
  "R := C mod P, the Solinas form of the P-224 prime.
C holds fourteen limbs of 32 bits, in words of 64 bits, and R holds
seven limbs of 32 bits.

The prime is B^7 - B^3 + 1 with B = 2^32, so B^7 is congruent to
B^3 - 1.  The value of C is the low seven limbs, L, plus the high
seven limbs, H, times B^7, so it is congruent to L + H*B^3 - H.

The three parts go into one array of eleven words, so that no part is
read after it has been written, and every carry and every borrow is
signed, so that a sum which is negative carries -1 into the next
word.  The excess, the part of the value which is above B^7, is kept
in the four high words of the array, as four limbs, so that no big
number is made."
  (declare (type (simple-array (unsigned-byte 64) (14)) c)
           (type secp224r1-fe r)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((q (make-array 11 :element-type '(unsigned-byte 64) :initial-element 0))
        (carry 0) (borrow 0))
    ;; q := H*B^3 - H.  The limbs of H go to the fourth limb and up,
    ;; and H is then given back from the first seven words.
    (dotimes (j 7)
      (let ((v (+ (aref c (+ 7 j)) carry)))
        (setf (aref q (+ 3 j)) (logand v #xffffffff)
              carry (ash v -32))))
    (setf (aref q 10) carry)
    (dotimes (i 7)
      (let ((v (+ (- (aref q i) (aref c (+ 7 i))) borrow)))
        (setf (aref q i) (logand v #xffffffff)
              borrow (ash v -32))))
    ;; The value is L + q, with the excess being what is left above
    ;; B^7: the high words of q, the borrow of the subtraction of H,
    ;; and the carry of the addition of L.
    (setf carry 0)
    (dotimes (i 7)
      (let ((v (+ (aref c i) (aref q i) carry)))
        (setf (aref q i) (logand v #xffffffff)
              carry (ash v -32))))
    ;; The excess goes into the high words, the borrow and the carry
    ;; being added to its low word, with a carry of their own.
    (let ((v (+ (aref q 7) borrow carry)))
      (setf (aref q 7) (logand v #xffffffff)
            carry (ash v -32)))
    (dotimes (i 3)
      (let ((v (+ (aref q (+ 8 i)) carry)))
        (setf (aref q (+ 8 i)) (logand v #xffffffff)
              carry (ash v -32))))
    (setf (aref q 10) carry)
    ;; The excess is congruent to itself times B^3, less itself, and
    ;; is folded in until there is none.  The excess can be 1, and
    ;; folding it in can give an excess of 1 again, so this is a loop.
    (loop
      ;; Is the excess zero?
      (unless (or (plusp (aref q 7)) (plusp (aref q 8))
                  (plusp (aref q 9)) (plusp (aref q 10)))
        (return))
      ;; The excess is added at the fourth limb and up, with a carry.
      (setf carry 0)
      (dotimes (i 4)
        (let ((v (+ (aref q (+ 3 i)) (aref q (+ 7 i)) carry)))
          (setf (aref q (+ 3 i)) (logand v #xffffffff)
                carry (ash v -32))))
      ;; And given back at the bottom, with a borrow.  The two have to
      ;; be done separately: adding them together would hide the
      ;; borrow of the second.  The borrow has to be carried on to the
      ;; words above the fourth, which the first pass has changed.
      (setf borrow 0)
      (dotimes (i 7)
        (let ((v (+ (- (aref q i) (if (< i 4) (aref q (+ 7 i)) 0)) borrow)))
          (setf (aref q i) (logand v #xffffffff)
                borrow (ash v -32))))
      ;; The new excess is the carry of the addition and the borrow of
      ;; the subtraction; it is one at most.
      (setf (aref q 7) (logand (+ carry borrow) #xffffffff)
            (aref q 8) 0
            (aref q 9) 0
            (aref q 10) 0))
    ;; The value is below B^7 now, and the prime is B^7 - B^3 + 1, so
    ;; the value is at least the prime exactly when the addition of
    ;; B^3 - 1 reaches B^7.  The sum is not kept, only its carry.
    (let ((cc 0))
      (dotimes (i 7)
        (let ((v (+ (aref q i) (if (<= i 2) #xffffffff 0) cc)))
          (setf cc (ash v -32))))
      (when (= cc 1)
        ;; The prime is subtracted.  It is below the value, so no
        ;; borrow runs out of the top.
        (let ((bb 0))
          (dotimes (i 7)
            (let ((v (- (aref q i) (aref +secp224r1-p-limbs+ i) bb)))
              (setf (aref q i) (logand v #xffffffff)
                    bb (ash v -32)))))))
    (dotimes (i 7) (setf (aref r i) (aref q i)))
  r))
