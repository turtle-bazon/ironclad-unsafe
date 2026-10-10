;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

(in-package :crypto)


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

(defun %ec-infinity-like (point)
  "A fresh point at infinity of the same class as POINT."
  (make-instance (class-of point) :x 1 :y 1 :z 0))

(defun %ec-window-mult (point e &key (width 4))
  "Left-to-right fixed-WIDTH scalar multiplication: E * POINT."
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
  "Joint scalar multiplication A*P + B*Q (Shamir's trick)."
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
