;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

(in-package :crypto-unsafe)


(defgeneric ec-point-on-curve-p (p)
  (:documentation "Return T if the point P is on the curve."))

(defgeneric ec-point-equal (p q)
  (:documentation "Return T if P and Q represent the same point."))

(defgeneric ec-double (p)
  (:documentation "Return the point 2P."))

(defgeneric ec-add (p q)
  (:documentation "Return the point P + Q."))

(defgeneric ec-scalar-mult (p e)
  (:documentation "Return the point e * P."))

(defgeneric ec-scalar-inv (kind n)
  (:documentation "Return the modular inverse of N."))

(defgeneric ec-make-point (kind &key &allow-other-keys)
  (:documentation "Return a point of KIND, initialized according to the
specified coordinates."))

(defgeneric ec-destructure-point (p)
  (:documentation "Return a plist containing the coordinates of the point P."))

(defgeneric ec-encode-scalar (kind n)
  (:documentation "Return an octet vector representing the integer N."))

(defgeneric ec-decode-scalar (kind octets)
  (:documentation "Return the integer represented by the OCTETS."))

(defgeneric ec-encode-point (p)
  (:documentation "Return an octet vector representing the point P."))

(defgeneric ec-decode-point (kind octets)
  (:documentation "Return the point represented by the OCTETS."))


;;; Shared fast paths for scalar multiplication.
;;;
;;; The per-curve EC-SCALAR-MULT methods historically used a Montgomery
;;; ladder (one doubling plus one addition per bit).  A fixed-window
;;; method does the same doublings but only ~15/16 as many additions,
;;; and verification (a*P + b*Q) halves its cost again with Shamir's
;;; trick.  Both are written against the EC-ADD/EC-DOUBLE generics so
;;; they work for every Jacobian point class; the methods handle the
;;; point at infinity, which the loops below rely on.
;;;
;;; SECRET/Public split:
;;;
;;; * %EC-LADDER-MULT is the path used for secret scalars.  It has a fixed
;;;   number of doublings/additions when BITS is supplied and does not use
;;;   secret-dependent table indices.
;;; * %EC-WINDOW-MULT and %EC-SHAMIR-MULT remain for public-only uses such
;;;   as verification.  Do not call them with a private key, nonce, or
;;;   ECDH secret.

(defun %ec-infinity-like (point)
  "A fresh point at infinity of the same class as POINT."
  (etypecase point
    (secp256r1-point
     +secp256r1-point-at-infinity+)
    (standard-object
     (make-instance (class-of point) :x 1 :y 1 :z 0))))

(defun %ec-ladder-mult (point e &key (bits (integer-length e)))
  "Return E * POINT using a fixed-schedule Montgomery ladder."
  (declare (type integer e)
           (type (integer 0 *) bits))
  (when (minusp e)
    (error "negative scalars are not supported by ~A" '%ec-ladder-mult))
  (if (zerop e)
      (%ec-infinity-like point)
      (let ((r0 (%ec-infinity-like point))
            (r1 point))
        (loop for i from (1- bits) downto 0
              do (if (logbitp i e)
                     (setf r0 (ec-add r0 r1)
                           r1 (ec-double r1))
                     (setf r1 (ec-add r1 r0)
                           r0 (ec-double r0))))
        r0)))

(defun %ec-window-mult (point e &key (width 4))
  "Left-to-right fixed-WIDTH scalar multiplication: E * POINT.
Public-only: the selected window index is a secret-dependent table index."
  (declare (type integer e)
           (type (integer 1 8) width))
  (let ((infinity (%ec-infinity-like point)))
    (if (zerop e)
        infinity
        (let* ((size (ash 1 width))
               (table (make-array size)))
          ;; Odd multiples from even ones: T[2i] = 2*T[i],
          ;; T[2i+1] = T[2i] + POINT.
          (setf (aref table 0) infinity
                (aref table 1) point)
          (loop for i from 2 below size
                do (setf (aref table i)
                         (if (evenp i)
                             (ec-double (aref table (ash i -1)))
                             (ec-add (aref table (1- i)) point))))
          (let ((r infinity))
            (loop for shift downfrom (* width (1- (ceiling (integer-length e) width))) to 0 by width
                  do (dotimes (i width)
                       (setf r (ec-double r)))
                     (let ((v (ldb (byte width shift) e)))
                       (unless (zerop v)
                         (setf r (ec-add r (aref table v))))))
            r)))))

(defun %ec-shamir-mult (p q a b)
  "Joint scalar multiplication A*P + B*Q using Shamir's trick.
Public-only: the branch schedule depends on the scalar bits."
  (declare (type integer a b))
  (let ((r (%ec-infinity-like p))
        (pq (ec-add p q))
        (nbits (max (integer-length a) (integer-length b) 1)))
    (loop for i downfrom (1- nbits) to 0
          do (setf r (ec-double r))
             (let ((ai (logbitp i a))
                   (bi (logbitp i b)))
               (cond ((and ai bi) (setf r (ec-add r pq)))
                     (ai (setf r (ec-add r p)))
                     (bi (setf r (ec-add r q))))))
    r))

(defun ec-tonelli-shanks-sqrt (a p)
  "Square root of A modulo the odd prime P (Tonelli-Shanks), or NIL
if A is not a quadratic residue.  The curves with P = 3 mod 4 use
A^((P+1)/4) inline instead; this general routine exists for primes
like the P-224 prime with P = 1 mod 4."
  (let ((a (mod a p)))
    (cond ((zerop a) 0)
          ((/= (expt-mod a (ash (1- p) -1) p) 1) nil)
          (t
           (let ((q (1- p)) (s 0))
             (loop while (evenp q) do (setf q (ash q -1)) (incf s))
             (let ((z 2))
               (loop while (= (expt-mod z (ash (1- p) -1) p) 1) do (incf z))
               (let ((c (expt-mod z q p))
                     (x (expt-mod a (ash (1+ q) -1) p))
                     (tval (expt-mod a q p))
                     (m s))
                 (loop while (/= tval 1)
                       do (let ((i 1))
                            (loop for tt = (expt-mod tval 2 p) then (expt-mod tt 2 p)
                                  while (/= tt 1) do (incf i))
                            (let ((b (expt-mod c (ash 1 (- m i 1)) p)))
                              (setf x (mod (* x b) p)
                                    c (mod (* b b) p)
                                    tval (mod (* tval c) p)
                                    m i))))
                 x)))))))


;;; Fixed-window scalar multiplication on a limb field.
;;;
;;; Variable-base multiplication (key agreement, ECIES) used to fall back
;;; to %EC-LADDER-MULT, which works on the bignum point classes: two
;;; generic point operations, with a fresh CLOS point and bignum MODs, per
;;; scalar bit.  The curves with a limb field (secp384r1, secp521r1) get a
;;; five-bit fixed window instead:
;;;
;;;  * the schedule depends only on the curve size (BITS doublings and
;;;    CEILING(BITS/5) additions), never on the scalar's value;
;;;  * every table entry is read by a masked scan over all 32 entries, so
;;;    the memory access pattern does not depend on the digits;
;;;  * a zero digit still performs an addition (of entry 1) and the
;;;    result is discarded with a mask.
;;;
;;; The point formulas still take their early exits while the accumulator
;;; is the point at infinity (the leading window), as the ladder did.

(defmacro define-limb-window-mult (name &key limbs bits fe-zero make-scratch
                                            make-table double add)
  "Define (NAME PX PY PZ E) => RX RY RZ, the limb point E*P.  PX, PY and
PZ are Montgomery limb arrays; E is a non-negative integer below
2^BITS."
  (let ((nwin (ceiling bits 5)))
    `(defun ,name (px py pz e)
       (declare (type (simple-array (unsigned-byte 64) (,limbs)) px py pz)
                (type (integer 0) e)
                (optimize (speed 3) (safety 0) (space 0) (debug 0)))
       (let ((table (,make-table px py pz))
             (s (,make-scratch))
             (rx (,fe-zero)) (ry (,fe-zero)) (rz (,fe-zero))
             (tx (,fe-zero)) (ty (,fe-zero)) (tz (,fe-zero))
             (ex (,fe-zero)) (ey (,fe-zero)) (ez (,fe-zero)))
         (declare (type simple-vector table s)
                  (type (simple-array (unsigned-byte 64) (,limbs))
                        rx ry rz tx ty tz ex ey ez))
         (flet ((select! (index)
                  ;; E := TABLE[INDEX], reading every entry.
                  (declare (type (unsigned-byte 5) index))
                  (dotimes (k ,limbs)
                    (setf (aref ex k) 0 (aref ey k) 0 (aref ez k) 0))
                  (dotimes (i 32)
                    (let ((m (ldb (byte 64 0) (ash (1- (logxor i index)) -63)))
                          (entry (svref table i)))
                      (declare (type (unsigned-byte 64) m)
                               (type simple-vector entry))
                      (let ((sx (svref entry 0)) (sy (svref entry 1))
                            (sz (svref entry 2)))
                        (declare (type (simple-array (unsigned-byte 64) (,limbs))
                                       sx sy sz))
                        (dotimes (k ,limbs)
                          (setf (aref ex k) (logior (aref ex k) (logand m (aref sx k)))
                                (aref ey k) (logior (aref ey k) (logand m (aref sy k)))
                                (aref ez k) (logior (aref ez k) (logand m (aref sz k)))))))))
                (take! (bit)
                  ;; R := T when BIT is 1, else unchanged.  The mask is
                  ;; built here: passed as an argument, the all-ones
                  ;; word is not a fixnum and was boxed as a bignum on
                  ;; every window.
                  (declare (type bit bit))
                  (let ((m (ldb (byte 64 0) (- bit))))
                    (declare (type (unsigned-byte 64) m))
                  (dotimes (k ,limbs)
                    (setf (aref rx k) (logxor (aref rx k)
                                              (logand m (logxor (aref rx k) (aref tx k))))
                          (aref ry k) (logxor (aref ry k)
                                              (logand m (logxor (aref ry k) (aref ty k))))
                          (aref rz k) (logxor (aref rz k)
                                              (logand m (logxor (aref rz k) (aref tz k)))))))))
           ;; R starts as the point at infinity (all-zero limbs).
           (dotimes (k ,limbs)
             (setf (aref rx k) 0 (aref ry k) 0 (aref rz k) 0))
           (loop for wi of-type fixnum downfrom ,(1- nwin) to 0 do
             (unless (= wi ,(1- nwin))
               (loop repeat 5 do
                 (,double tx ty tz rx ry rz s)
                 (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))
             (let* ((digit (ldb (byte 5 (* wi 5)) e))
                    (nonzero (ash (+ digit 31) -5)))
               (declare (type (unsigned-byte 5) digit)
                        (type bit nonzero))
               ;; Entry DIGIT, or entry 1 for a zero digit (discarded).
               (select! (logior digit (logxor 1 nonzero)))
               (,add tx ty tz rx ry rz ex ey ez s)
               (take! nonzero))))
         (values rx ry rz)))))
