;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; secp384r1.lisp -- secp384r1 (a.k.a. NIST P-384) elliptic curve


(in-package :crypto-unsafe)


;;; class definitions

(defclass secp384r1-public-key ()
  ((y :initarg :y :reader secp384r1-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass secp384r1-private-key ()
  ((x :initarg :x :reader secp384r1-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader secp384r1-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass secp384r1-point ()
    ;; Internally, a point (x, y) is represented using the Jacobian projective
    ;; coordinates (X, Y, Z), with x = X / Z^2 and y = Y / Z^3.
    ((x :initarg :x :type integer)
     (y :initarg :y :type integer)
     (z :initarg :z :type integer)))
  (defmethod make-load-form ((p secp384r1-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constant and function definitions

(defconstant +secp384r1-bits+ 384)
(defconstant +secp384r1-p+ 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319)
(defconstant +secp384r1-b+ 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575)
(defconstant +secp384r1-l+ 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643)
(defconstant +secp384r1-i+ 29551504647295859409209280075107710353809804452849085000961220053184291328622652746785449566194203501396205229834239)

(defconst +secp384r1-g+
  (make-instance 'secp384r1-point
                 :x 26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087
                 :y 8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871
                 :z 1))
(defconst +secp384r1-point-at-infinity+
  (make-instance 'secp384r1-point :x 1 :y 1 :z 0))


(defmethod ec-scalar-inv ((kind (eql :secp384r1)) n)
  (expt-mod n (- +secp384r1-p+ 2) +secp384r1-p+))

(defmethod ec-point-equal ((p secp384r1-point) (q secp384r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (let ((z1z1 (mod (* z1 z1) +secp384r1-p+))
            (z2z2 (mod (* z2 z2) +secp384r1-p+)))
        (and (zerop (mod (- (* x1 z2z2) (* x2 z1z1)) +secp384r1-p+))
             (zerop (mod (- (* y1 z2z2 z2) (* y2 z1z1 z1)) +secp384r1-p+)))))))

(defmethod ec-double ((p secp384r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (if (zerop z1)
        +secp384r1-point-at-infinity+
        (let* ((xx (mod (* x1 x1) +secp384r1-p+))
               (yy (mod (* y1 y1) +secp384r1-p+))
               (yyyy (mod (* yy yy) +secp384r1-p+))
               (zz (mod (* z1 z1) +secp384r1-p+))
               (x1+yy (mod (+ x1 yy) +secp384r1-p+))
               (y1+z1 (mod (+ y1 z1) +secp384r1-p+))
               (s (mod (* 2 (- (* x1+yy x1+yy) xx yyyy)) +secp384r1-p+))
               (m (mod (* 3 (- xx (* zz zz))) +secp384r1-p+))
               (u (mod (- (* m m) (* 2 s)) +secp384r1-p+))
               (x2 u)
               (y2 (mod (- (* m (- s u)) (* 8 yyyy)) +secp384r1-p+))
               (z2 (mod (- (* y1+z1 y1+z1) yy zz) +secp384r1-p+)))
          (make-instance 'secp384r1-point :x x2 :y y2 :z z2)))))

(defmethod ec-add ((p secp384r1-point) (q secp384r1-point))
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
         (let* ((z1z1 (mod (* z1 z1) +secp384r1-p+))
                (z2z2 (mod (* z2 z2) +secp384r1-p+))
                (u1 (mod (* x1 z2z2) +secp384r1-p+))
                (u2 (mod (* x2 z1z1) +secp384r1-p+))
                (s1 (mod (* y1 z2 z2z2) +secp384r1-p+))
                (s2 (mod (* y2 z1 z1z1) +secp384r1-p+)))
           (if (= u1 u2)
               (if (= s1 s2)
                   (ec-double p)
                   +secp384r1-point-at-infinity+)
               (let* ((h (mod (- u2 u1) +secp384r1-p+))
                      (i (mod (* 4 h h) +secp384r1-p+))
                      (j (mod (* h i) +secp384r1-p+))
                      (r (mod (* 2 (- s2 s1)) +secp384r1-p+))
                      (v (mod (* u1 i) +secp384r1-p+))
                      (x3 (mod (- (* r r) j (* 2 v)) +secp384r1-p+))
                      (y3 (mod (- (* r (- v x3)) (* 2 s1 j)) +secp384r1-p+))
                      (z1+z2 (mod (+ z1 z2) +secp384r1-p+))
                      (z3 (mod (* (- (* z1+z2 z1+z2) z1z1 z2z2) h) +secp384r1-p+)))
                 (make-instance 'secp384r1-point :x x3 :y y3 :z z3)))))))))


;;; Fixed-base positional table for the generator point.
;;;
;;; SIGN-MESSAGE and key generation always multiply G by a secret scalar.
;;; Row J holds V * 256^J * G for V in [0, 256), so a multiplication is
;;; 48 additions and no doublings (instead of the ladder's ~192 adds and
;;; 383 doublings, or a standard window's 48 adds and 376 doublings).
;;; The selection scans all 256 entries of a row, so the memory pattern
;;; does not depend on the secret scalar.
;;;
;;; The table is built lazily on first use: 48 rows of 256 points.

(defvar *secp384r1-base-table* nil
  "Positional table ROWS[J][V] = V * 256^J * G. Built on first use.")

(defun secp384r1-ensure-base-table ()
  (or *secp384r1-base-table*
      (setf *secp384r1-base-table*
            (let ((rows (make-array 48))
                  (base +secp384r1-g+))
              (dotimes (j 48 rows)
                (declare (type fixnum j))
                (let ((row (make-array 256)))
                  (setf (aref row 0) +secp384r1-point-at-infinity+
                        (aref row 1) base)
                  (loop for v of-type fixnum from 2 below 256 do
                    (setf (aref row v)
                          (if (evenp v)
                              (ec-double (aref row (ash v -1)))
                              (ec-add (aref row (1- v)) base))))
                  (setf (aref rows j) row)
                  ;; base := 256 * base for the next row.
                  (dotimes (i 8)
                    (declare (ignore i))
                    (setf base (ec-double base)))))))))

(declaim (inline secp384r1-select-base))
(defun secp384r1-select-base (row v)
  "Select index V from the positional-table ROW.  Linear scan over all
256 entries, so the memory access pattern does not depend on V."
  (declare (type simple-vector row)
           (type (unsigned-byte 8) v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((sel (aref row 0)))
    (dotimes (i 256 sel)
      (when (= i v)
        (setf sel (aref row i))))))

(defun secp384r1-base-mult (k)
  "Fixed-base multiplication K*G via the positional byte table: 48
additions and no doublings."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  (let ((table (secp384r1-ensure-base-table))
        (acc +secp384r1-point-at-infinity+))
    (declare (type simple-vector table))
    (loop for j of-type fixnum from 47 downto 0 do
      (let ((v (ldb (byte 8 (* j 8)) k)))
        (declare (type (unsigned-byte 8) v))
        (unless (zerop v)
          (setf acc (ec-add acc (secp384r1-select-base (aref table j) v))))))
    acc))

(defmethod ec-scalar-mult ((p secp384r1-point) e)
  ;; Secret scalars use the fixed-schedule ladder.  The generator G uses
  ;; the faster fixed-base comb.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (if (and (eq p +secp384r1-g+) (not (minusp e)))
      (secp384r1-base-mult e)
      (%ec-ladder-mult p e :bits +secp384r1-bits+)))

(defmethod ec-point-on-curve-p ((p secp384r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((y2 (mod (* y y) +secp384r1-p+))
           (x3 (mod (* x x x) +secp384r1-p+))
           (z2 (mod (* z z) +secp384r1-p+))
           (z4 (mod (* z2 z2) +secp384r1-p+))
           (z6 (mod (* z4 z2) +secp384r1-p+))
           (a (mod (+ x3 (* -3 x z4) (* +secp384r1-b+ z6)) +secp384r1-p+)))
      (declare (type integer y2 x3 z2 z4 z6 a))
      (zerop (mod (- y2 a) +secp384r1-p+)))))

(defmethod ec-make-point ((kind (eql :secp384r1)) &key x y)
  (unless x
    (error 'missing-point-parameter
           :kind 'secp384r1
           :parameter 'x
           :description "coordinate"))
  (unless y
    (error 'missing-point-parameter
           :kind 'secp384r1
           :parameter 'y
           :description "coordinate"))
  (let ((p (make-instance 'secp384r1-point :x x :y y :z 1)))
    (if (ec-point-on-curve-p p)
        p
        (error 'invalid-curve-point :kind 'secp384r1))))

(defmethod ec-destructure-point ((p secp384r1-point))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (when (zerop z)
      (error 'ironclad-unsafe-error
             :format-control "The point at infinity can't be encoded."))
    (let* ((invz (ec-scalar-inv :secp384r1 z))
           (invz2 (mod (* invz invz) +secp384r1-p+))
           (invz3 (mod (* invz2 invz) +secp384r1-p+))
           (x (mod (* x invz2) +secp384r1-p+))
           (y (mod (* y invz3) +secp384r1-p+)))
      (list :x x :y y))))

(defmethod ec-encode-scalar ((kind (eql :secp384r1)) n)
  (integer-to-octets n :n-bits +secp384r1-bits+ :big-endian t))

(defmethod ec-decode-scalar ((kind (eql :secp384r1)) octets)
  (octets-to-integer octets :big-endian t))

(defmethod ec-encode-point ((p secp384r1-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x))
         (y (getf coordinates :y)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (vector 4)
                 (ec-encode-scalar :secp384r1 x)
                 (ec-encode-scalar :secp384r1 y))))

(defmethod ec-decode-point ((kind (eql :secp384r1)) octets)
  (case (aref octets 0)
    ((2 3)
     ;; Compressed point
     (if (= (length octets) (1+ (/ +secp384r1-bits+ 8)))
         (let* ((x-bytes (subseq octets 1 (1+ (/ +secp384r1-bits+ 8))))
                (x (ec-decode-scalar :secp384r1 x-bytes))
                (y-sign (- (aref octets 0) 2))
                (y2 (mod (+ (* x x x) (* -3 x) +secp384r1-b+) +secp384r1-p+))
                (y (expt-mod y2 +secp384r1-i+ +secp384r1-p+))
                (y (if (= (logand y 1) y-sign) y (- +secp384r1-p+ y))))
           (ec-make-point :secp384r1 :x x :y y))
         (error 'invalid-curve-point :kind 'secp384r1)))
    ((4)
     ;; Uncompressed point
     (if (= (length octets) (1+ (/ +secp384r1-bits+ 4)))
         (let* ((x-bytes (subseq octets 1 (1+ (/ +secp384r1-bits+ 8))))
                (x (ec-decode-scalar :secp384r1 x-bytes))
                (y-bytes (subseq octets (1+ (/ +secp384r1-bits+ 8))))
                (y (ec-decode-scalar :secp384r1 y-bytes)))
           (ec-make-point :secp384r1 :x x :y y))
         (error 'invalid-curve-point :kind 'secp384r1)))
    (t
     (error 'invalid-curve-point :kind 'secp384r1))))

(defun secp384r1-public-key (sk)
  (let ((a (ec-decode-scalar :secp384r1 sk)))
    (ec-encode-point (ec-scalar-mult +secp384r1-g+ a))))

(defmethod make-signature ((kind (eql :secp384r1)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'secp384r1
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'secp384r1
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :secp384r1)) signature)
  (let ((length (length signature)))
    (if (/= length (/ +secp384r1-bits+ 4))
        (error 'invalid-signature-length :kind 'secp384r1)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defmethod generate-signature-nonce ((key secp384r1-private-key) message &optional parameters)
  (or *signature-nonce-for-test*
      (rfc6979-generate-k (secp384r1-key-x key)
                          message
                          +secp384r1-l+
                          (integer-length +secp384r1-l+)
                          (ceiling (integer-length +secp384r1-l+) 8)
                          :digest (or parameters *ecdsa-rfc6979-digest*))))

;;; Note that hashing is not performed here.
(defmethod sign-message ((key secp384r1-private-key) message &key (start 0) end (digest *ecdsa-rfc6979-digest*) &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((end (min (or end (length message)) (/ +secp384r1-bits+ 8)))
         (sk (ec-decode-scalar :secp384r1 (secp384r1-key-x key)))
         (h (subseq message start end))
         (k (generate-signature-nonce key h digest))
         (invk (modular-inverse-with-blinding k +secp384r1-l+ :prime t))
         (r (ec-scalar-mult +secp384r1-g+ k))
         (x (subseq (ec-encode-point r) 1 (1+ (/ +secp384r1-bits+ 8))))
         (r (ec-decode-scalar :secp384r1 x))
         (r (mod r +secp384r1-l+))
         (e (ec-decode-scalar :secp384r1 h))
         (s (mod (* invk (+ e (* sk r))) +secp384r1-l+)))
    (if (not (or (zerop r) (zerop s)))
        (make-signature :secp384r1
                        :r (ec-encode-scalar :secp384r1 r)
                        :s (ec-encode-scalar :secp384r1 s))
        (sign-message key message :start start :end end))))

;;; Windowed joint multiplication for verification.
;;;
;;; The plain Shamir trick does one addition per set bit of either
;;; scalar (about 290 for two 384-bit scalars).  Five-bit windows need
;;; 77 windows with at most two additions each.

(defun secp384r1-make-window-table (p)
  "The table V * P for V in [0, 32), built from doubles and adds."
  (declare (type secp384r1-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (make-array 32)))
    (setf (aref table 0) +secp384r1-point-at-infinity+
          (aref table 1) p)
    (loop for v of-type fixnum from 2 below 32 do
      (setf (aref table v)
            (if (evenp v)
                (ec-double (aref table (ash v -1)))
                (ec-add (aref table (1- v)) p))))
    table))

(defun secp384r1-shamir-mult (p q a b)
  "A * P + B * Q, public only, with five-bit windows."
  (declare (type secp384r1-point p q)
           (type integer a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((w 5)
         (abit (integer-length a))
         (bbit (integer-length b))
         (bits (max abit bbit 1))
         (nwin (ceiling bits w))
         ;; Row 0 of the positional table is V*G for V in [0, 256),
         ;; so its first 32 entries serve the five-bit windows directly.
         (tp (if (eq p +secp384r1-g+)
                 (aref (secp384r1-ensure-base-table) 0)
                 (secp384r1-make-window-table p)))
         (tq (secp384r1-make-window-table q))
         (acc +secp384r1-point-at-infinity+))
    (declare (type fixnum w abit bbit bits nwin)
             (type simple-vector tp tq))
    (loop for wi of-type fixnum downfrom (1- nwin) to 0 do
      (unless (= wi (1- nwin))
        (dotimes (i w)
          (declare (ignore i))
          (setf acc (ec-double acc))))
      (let* ((shift (* wi w))
             (va (if (< shift abit) (ldb (byte w shift) a) 0))
             (vb (if (< shift bbit) (ldb (byte w shift) b) 0)))
        (declare (type fixnum shift)
                 (type (unsigned-byte 5) va vb))
        (unless (zerop va) (setf acc (ec-add acc (aref tp va))))
        (unless (zerop vb) (setf acc (ec-add acc (aref tq vb))))))
    acc))

(defmethod verify-signature ((key secp384r1-public-key) message signature &key (start 0) end &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length signature) (/ +secp384r1-bits+ 4))
    (error 'invalid-signature-length :kind 'secp384r1))
  (let* ((end (min (or end (length message)) (/ +secp384r1-bits+ 8)))
         (pk (ec-decode-point :secp384r1 (secp384r1-key-y key)))
         (signature-elements (destructure-signature :secp384r1 signature))
         (r (ec-decode-scalar :secp384r1 (getf signature-elements :r)))
         (s (ec-decode-scalar :secp384r1 (getf signature-elements :s))))
    ;; Degenerate (r = 0 or s = 0) signatures are invalid; answer NIL
    ;; before the W/RP computations, which assume nonzero operands.
    (unless (and (< 0 r +secp384r1-l+) (< 0 s +secp384r1-l+))
      (return-from verify-signature nil))
    (let* ((h (subseq message start end))
         (e (ec-decode-scalar :secp384r1 h))
         (w (modular-inverse-with-blinding s +secp384r1-l+ :prime t))
         (u1 (mod (* e w) +secp384r1-l+))
         (u2 (mod (* r w) +secp384r1-l+))
         ;; Joint multiplication: one pass instead of two.
         (rp (secp384r1-shamir-mult +secp384r1-g+ pk u1 u2))
         (x (subseq (ec-encode-point rp) 1 (1+ (/ +secp384r1-bits+ 8))))
         (v (ec-decode-scalar :secp384r1 x))
         (v (mod v +secp384r1-l+)))
     (and (< 0 r +secp384r1-l+)
          (< 0 s +secp384r1-l+)
          ;; RP is the point at infinity only for invalid signatures;
          ;; answer NIL instead of failing inside EC-ENCODE-POINT.
          (not (ec-point-equal rp +secp384r1-point-at-infinity+))
          (= v r)))))

(defmethod make-public-key ((kind (eql :secp384r1)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'secp384r1
           :parameter 'y
           :description "public key"))
  ;; Reject malformed encodings and off-curve points now, at
  ;; construction time, rather than at first use.
  (ec-decode-point :secp384r1 y)
  (make-instance 'secp384r1-public-key :y y))

(defmethod destructure-public-key ((public-key secp384r1-public-key))
  (list :y (secp384r1-key-y public-key)))

(defmethod make-private-key ((kind (eql :secp384r1)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'secp384r1
           :parameter 'x
           :description "private key"))
  ;; The scalar must lie in [1, N-1]; 0 yields the point at infinity
  ;; and values >= N silently wrap to the wrong public key.
  (unless (< 0 (octets-to-integer x :big-endian t) +secp384r1-l+)
    (error 'invalid-private-key :kind 'secp384r1))
  (make-instance 'secp384r1-private-key :x x :y (or y (secp384r1-public-key x))))

(defmethod destructure-private-key ((private-key secp384r1-private-key))
  (list :x (secp384r1-key-x private-key)
        :y (secp384r1-key-y private-key)))

(defmethod generate-key-pair ((kind (eql :secp384r1)) &key &allow-other-keys)
  (let* ((sk (ec-encode-scalar :secp384r1 (1+ (strong-random (1- +secp384r1-l+)))))
         (pk (secp384r1-public-key sk)))
    (values (make-private-key :secp384r1 :x sk :y pk)
            (make-public-key :secp384r1 :y pk))))

(defmethod diffie-hellman ((private-key secp384r1-private-key) (public-key secp384r1-public-key))
  (let ((s (ec-decode-scalar :secp384r1 (secp384r1-key-x private-key)))
        (p (ec-decode-point :secp384r1 (secp384r1-key-y public-key))))
    (ec-encode-point (ec-scalar-mult p s))))
