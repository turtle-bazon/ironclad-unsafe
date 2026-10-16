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
  ;; coordinates (X, Y, Z), with x = X / Z^2 and y = Y / Z^3.
  (defstruct (secp256r1-point
              (:constructor make-secp256r1-point
                  (&key (x 1) (y 1) (z 1)))
              (:predicate nil))
    (x 1 :type integer :read-only t)
    (y 1 :type integer :read-only t)
    (z 1 :type integer :read-only t)))

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

;;; P-256 field addition/subtraction without division.
;;;
;;; Sums and differences of reduced residues only need one conditional
;;; carry/borrow fixup.  These are plain portable integer operations,
;;; so all Lisps share the same code path.

(declaim (inline secp256r1-add-mod secp256r1-sub-mod))

(defun secp256r1-add-mod (a b)
  "Compute (A + B) mod +SECP256R1-P+ for residues A and B."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer a b))
  (let ((s (+ a b)))
    (declare (type integer s))
    (if (>= s +secp256r1-p+)
        (- s +secp256r1-p+)
        s)))

(defun secp256r1-sub-mod (a b)
  "Compute (A - B) mod +SECP256R1-P+ for residues A and B."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer a b))
  (let ((d (- a b)))
    (declare (type integer d))
    (if (minusp d)
        (+ d +secp256r1-p+)
        d)))

(defconst +secp256r1-g+
  (make-secp256r1-point
                 :x 48439561293906451759052585252797914202762949526041747995844080717082404635286
                 :y 36134250956749795798585127919587881956611106672985015071877198253568414405109
                 :z 1))
(defconst +secp256r1-point-at-infinity+
  (make-secp256r1-point :x 1 :y 1 :z 0))


(defmethod ec-scalar-inv ((kind (eql :secp256r1)) n)
  ;; Binary GCD inversion is much cheaper than Fermat exponentiation here.
  ;; Callers only invert nonzero field elements (z = 0 is rejected earlier).
  (modular-inverse n +secp256r1-p+))

(defmethod ec-point-equal ((p secp256r1-point) (q secp256r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (secp256r1-point-x p))
        (y1 (secp256r1-point-y p))
        (z1 (secp256r1-point-z p))
        (x2 (secp256r1-point-x q))
        (y2 (secp256r1-point-y q))
        (z2 (secp256r1-point-z q)))
    (declare (type integer x1 y1 z1 x2 y2 z2))
    (let ((z1z1 (mod (* z1 z1) +secp256r1-p+))
          (z2z2 (mod (* z2 z2) +secp256r1-p+)))
      (and (zerop (mod (- (* x1 z2z2) (* x2 z1z1)) +secp256r1-p+))
           (zerop (mod (- (* y1 z2z2 z2) (* y2 z1z1 z1)) +secp256r1-p+))))))

(defmethod ec-double ((p secp256r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (secp256r1-point-x p))
        (y1 (secp256r1-point-y p))
        (z1 (secp256r1-point-z p)))
    (declare (type integer x1 y1 z1))
    (if (zerop z1)
        +secp256r1-point-at-infinity+
        (let* ((xx (mod (* x1 x1) +secp256r1-p+))
               (yy (mod (* y1 y1) +secp256r1-p+))
               (yyyy (mod (* yy yy) +secp256r1-p+))
               (zz (mod (* z1 z1) +secp256r1-p+))
               (x1+yy (secp256r1-add-mod x1 yy))
               (y1+z1 (secp256r1-add-mod y1 z1))
               (t1 (mod (* x1+yy x1+yy) +secp256r1-p+))
               (t2 (secp256r1-sub-mod t1 xx))
               (t3 (secp256r1-sub-mod t2 yyyy))
               (s (secp256r1-add-mod t3 t3))
               (t4 (mod (* zz zz) +secp256r1-p+))
               (t5 (secp256r1-sub-mod xx t4))
               (t6 (secp256r1-add-mod t5 t5))
               (m (secp256r1-add-mod t6 t5))
               (t7 (mod (* m m) +secp256r1-p+))
               (t8 (secp256r1-add-mod s s))
               (u (secp256r1-sub-mod t7 t8))
               (x2 u)
               (t9 (secp256r1-sub-mod s u))
               (t10 (mod (* m t9) +secp256r1-p+))
               (e2 (secp256r1-add-mod yyyy yyyy))
               (e4 (secp256r1-add-mod e2 e2))
               (e8 (secp256r1-add-mod e4 e4))
               (y2 (secp256r1-sub-mod t10 e8))
               (t11 (mod (* y1+z1 y1+z1) +secp256r1-p+))
               (t12 (secp256r1-sub-mod t11 yy))
               (z2 (secp256r1-sub-mod t12 zz)))
          (make-secp256r1-point :x x2 :y y2 :z z2)))))

(defmethod ec-add ((p secp256r1-point) (q secp256r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (secp256r1-point-x p))
        (y1 (secp256r1-point-y p))
        (z1 (secp256r1-point-z p))
        (x2 (secp256r1-point-x q))
        (y2 (secp256r1-point-y q))
        (z2 (secp256r1-point-z q)))
    (declare (type integer x1 y1 z1 x2 y2 z2))
    (cond
        ((zerop z1)
         q)
        ((zerop z2)
         p)
        (t
         (let* ((z1z1 (mod (* z1 z1) +secp256r1-p+))
                (z2z2 (mod (* z2 z2) +secp256r1-p+))
                (u1 (mod (* x1 z2z2) +secp256r1-p+))
                (u2 (mod (* x2 z1z1) +secp256r1-p+))
                (t1 (mod (* y1 z2) +secp256r1-p+))
                (s1 (mod (* t1 z2z2) +secp256r1-p+))
                (t2 (mod (* y2 z1) +secp256r1-p+))
                (s2 (mod (* t2 z1z1) +secp256r1-p+)))
           (if (= u1 u2)
               (if (= s1 s2)
                   (ec-double p)
                   +secp256r1-point-at-infinity+)
               (let* ((h (secp256r1-sub-mod u2 u1))
                      (t3 (mod (* h h) +secp256r1-p+))
                      (t4 (secp256r1-add-mod t3 t3))
                      (i (secp256r1-add-mod t4 t4))
                      (j (mod (* h i) +secp256r1-p+))
                      (t5 (secp256r1-sub-mod s2 s1))
                      (r (secp256r1-add-mod t5 t5))
                      (v (mod (* u1 i) +secp256r1-p+))
                      (t6 (mod (* r r) +secp256r1-p+))
                      (t7 (secp256r1-sub-mod t6 j))
                      (t8 (secp256r1-add-mod v v))
                      (x3 (secp256r1-sub-mod t7 t8))
                      (t9 (secp256r1-sub-mod v x3))
                      (t10 (mod (* r t9) +secp256r1-p+))
                      (t11 (mod (* s1 j) +secp256r1-p+))
                      (t12 (secp256r1-add-mod t11 t11))
                      (y3 (secp256r1-sub-mod t10 t12))
                      (z1+z2 (secp256r1-add-mod z1 z2))
                      (t13 (mod (* z1+z2 z1+z2) +secp256r1-p+))
                      (t14 (secp256r1-sub-mod t13 z1z1))
                      (t15 (secp256r1-sub-mod t14 z2z2))
                      (z3 (mod (* t15 h) +secp256r1-p+)))
                 (make-secp256r1-point :x x3 :y y3 :z z3))))))))

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
  "Precomputed I * G for I in [0, 16), built on first use.")

(defun secp256r1-ensure-base-table ()
  (or *secp256r1-base-table*
      (setf *secp256r1-base-table*
            (let ((table (make-array 16)))
              (setf (aref table 0) +secp256r1-point-at-infinity+)
              (dotimes (i 15 table)
                (setf (aref table (1+ i))
                      (ec-add (aref table i) +secp256r1-g+)))))))

(declaim (inline secp256r1-select-base))
(defun secp256r1-select-base (table v)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type (integer 0 15) v))
  (let ((sel +secp256r1-point-at-infinity+))
    (dotimes (i 16 sel)
      (when (= i v)
        (setf sel (aref table i))))))

(defun secp256r1-base-mult (k)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  (let ((table (secp256r1-ensure-base-table))
        (r +secp256r1-point-at-infinity+))
    (loop for j from 63 downto 0 do
      (dotimes (i 4)
        (setf r (ec-double r)))
      (setf r (ec-add r (secp256r1-select-base table (ldb (byte 4 (* j 4)) k)))))
    r))

(defmethod ec-scalar-mult ((p secp256r1-point) e)
  ;; Secret scalars use the fixed-schedule ladder, except for the fixed
  ;; base point G (signing nonces, key generation), which uses the
  ;; constant-iteration comb above.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (if (and (eq p +secp256r1-g+) (not (minusp e)))
      (secp256r1-base-mult e)
      (%ec-ladder-mult p e :bits +secp256r1-bits+)))

(defmethod ec-point-on-curve-p ((p secp256r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((y2 (mod (* y y) +secp256r1-p+))
           (x3 (mod (* x x x) +secp256r1-p+))
           (z2 (mod (* z z) +secp256r1-p+))
           (z4 (mod (* z2 z2) +secp256r1-p+))
           (z6 (mod (* z4 z2) +secp256r1-p+))
           (a (mod (+ x3 (* -3 x z4) (* +secp256r1-b+ z6)) +secp256r1-p+)))
      (declare (type integer y2 x3 z2 z4 z6 a))
      (zerop (mod (- y2 a) +secp256r1-p+)))))

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
  (let ((p (make-secp256r1-point :x x :y y :z 1)))
    (if (ec-point-on-curve-p p)
        p
        (error 'invalid-curve-point :kind 'secp256r1))))

(defmethod ec-destructure-point ((p secp256r1-point))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (when (zerop z)
      (error 'ironclad-error
             :format-control "The point at infinity can't be encoded."))
    (let* ((invz (ec-scalar-inv :secp256r1 z))
           (invz2 (mod (* invz invz) +secp256r1-p+))
           (invz3 (mod (* invz2 invz) +secp256r1-p+))
           (x (mod (* x invz2) +secp256r1-p+))
           (y (mod (* y invz3) +secp256r1-p+)))
      (list :x x :y y))))

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
         (rp (%ec-shamir-mult +secp256r1-g+ pk u1 u2))
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
