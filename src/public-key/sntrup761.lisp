;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; sntrup761.lisp -- the Streamlined NTRU Prime 761 KEM
;;;;
;;;; sntrup761 is the lattice KEM OpenSSH uses in its
;;;; sntrup761x25519-sha512 key exchanges.  The construction is by
;;;; Bernstein, Chuengsatiansup, Lange and van Vredendaal; this file
;;;; follows the public-domain SUPERCOP "compact" implementation
;;;; (sntrup761.c) that OpenSSH ships.
;;;;
;;;; Parameters: p = 761, q = 4591, w = 286.
;;;; Public key 1158 octets, secret key 1763, ciphertext 1039, secret 32.
;;;;
;;;; (sntrup761-keypair) => public-key, secret-key
;;;; (sntrup761-encapsulate public-key) => ciphertext, shared-secret
;;;; (sntrup761-decapsulate ciphertext secret-key) => shared-secret
;;;;
;;;; The optional :RANDOM argument is a function of one integer that
;;;; returns that many random octets; it exists so the deterministic
;;;; reference vectors can drive key generation.

(in-package :crypto-unsafe)

(defconstant +sntrup761-p+ 761)
(defconstant +sntrup761-q+ 4591)
(defconstant +sntrup761-w+ 286)
(defconstant +sntrup761-q12+ 2295)      ; (q - 1) / 2
(defconstant +sntrup761-hash-bytes+ 32)
(defconstant +sntrup761-small-bytes+ 191)   ; (p + 3) / 4
(defconstant +sntrup761-confirm-bytes+ 32)
(defconstant +sntrup761-secret-keys-bytes+ 382) ; 2 * Small_bytes
(defconstant +sntrup761-public-key-bytes+ 1158)
(defconstant +sntrup761-secret-key-bytes+ 1763)
(defconstant +sntrup761-ciphertext-bytes+ 1039)
(defconstant +sntrup761-shared-secret-bytes+ 32)

;;; The three fixed-point multipliers Fq_freeze uses.  They are
;;; (2^n + q/2) / q for n = 16, 20 and 28, rounded down as in C.
(defconstant +sntrup761-q16+ (truncate (+ #x10000 (floor +sntrup761-q+ 2))
                                       +sntrup761-q+))
(defconstant +sntrup761-q20+ (truncate (+ #x100000 (floor +sntrup761-q+ 2))
                                       +sntrup761-q+))
(defconstant +sntrup761-q28+ (truncate (+ #x10000000 (floor +sntrup761-q+ 2))
                                       +sntrup761-q+))

(declaim (inline sntrup761-f3-freeze sntrup761-fq-freeze))

(defun sntrup761-f3-freeze (x)
  "Reduce the small integer X modulo 3 to -1, 0 or 1."
  (declare (type fixnum x))
  (- x (* 3 (ash (+ (* 10923 x) 16384) -15))))

(defun sntrup761-fq-freeze (x)
  "Reduce the integer X modulo q to the balanced range [-q/2, q/2]."
  (declare (type fixnum x))
  (let ((q +sntrup761-q+))
    (setf x (- x (* q (ash (* +sntrup761-q16+ x) -16))))
    (setf x (- x (* q (ash (* +sntrup761-q20+ x) -20))))
    (- x (* q (ash (+ (* +sntrup761-q28+ x) #x8000000) -28)))))

;;; ---- polynomial arithmetic in R3 = F3[x]/(x^p - x + 1) ----

(defun sntrup761-r3-mult (h f g)
  "H = F * G in R3, all three small vectors of length p."
  (declare (type (simple-array (signed-byte 8) (*)) h f g))
  (let ((p +sntrup761-p+)
        (fg (make-array (1- (* 2 +sntrup761-p+))
                        :element-type '(signed-byte 16) :initial-element 0)))
    (dotimes (i p)
      (let ((fi (aref f i)))
        (unless (zerop fi)
          (dotimes (j p)
            (incf (aref fg (+ i j)) (* fi (aref g j)))))))
    (loop for i from p below (1- (* 2 p))
          do (incf (aref fg (- i p)) (aref fg i)))
    (loop for i from p below (1- (* 2 p))
          do (incf (aref fg (1+ (- i p))) (aref fg i)))
    (dotimes (i p)
      (setf (aref h i) (sntrup761-f3-freeze (aref fg i))))
    h))

(defun sntrup761-r3-from-rq (out r)
  "Reduce the Fq vector R into the small vector OUT."
  (declare (type (simple-array (signed-byte 8) (*)) out)
           (type (simple-array (signed-byte 16) (*)) r))
  (dotimes (i +sntrup761-p+ out)
    (setf (aref out i) (sntrup761-f3-freeze (aref r i)))))

(defun sntrup761-r3-recip (out in)
  "The inverse of the small vector IN in R3, into OUT.

Returns (VALUES OUT INVERTIBLE-P); the caller retries key generation when
IN is not invertible, exactly as KeyGen does."
  (declare (type (simple-array (signed-byte 8) (*)) out in))
  (let* ((p +sntrup761-p+)
         (size (1+ p))
         (f (make-array size :element-type '(signed-byte 8) :initial-element 0))
         (g (make-array size :element-type '(signed-byte 8) :initial-element 0))
         (v (make-array size :element-type '(signed-byte 8) :initial-element 0))
         (r (make-array size :element-type '(signed-byte 8) :initial-element 0))
         (delta 1))
    (setf (aref r 0) 1
          (aref f 0) 1
          (aref f (1- p)) -1
          (aref f p) -1)
    (dotimes (i p)
      (setf (aref g (- p 1 i)) (aref in i)))
    (dotimes (loop-count (1- (* 2 p)))
      (declare (ignore loop-count))
      (loop for i from p downto 1
            do (setf (aref v i) (aref v (1- i))))
      (setf (aref v 0) 0)
      (let ((sign (- (* (aref g 0) (aref f 0))))
            (swap (logand (if (minusp (- delta)) -1 0)
                          (if (zerop (aref g 0)) 0 -1))))
        (setf delta (logxor delta (logand swap (logxor delta (- delta)))))
        (incf delta)
        (dotimes (i size)
          (let ((tmp (logand swap (logxor (aref f i) (aref g i)))))
            (setf (aref f i) (logxor (aref f i) tmp)
                  (aref g i) (logxor (aref g i) tmp))
            (setf tmp (logand swap (logxor (aref v i) (aref r i))))
            (setf (aref v i) (logxor (aref v i) tmp)
                  (aref r i) (logxor (aref r i) tmp))))
        (dotimes (i size)
          (setf (aref g i)
                (sntrup761-f3-freeze (+ (aref g i) (* sign (aref f i))))))
        (dotimes (i size)
          (setf (aref r i)
                (sntrup761-f3-freeze (+ (aref r i) (* sign (aref v i))))))
        (dotimes (i p)
          (setf (aref g i) (aref g (1+ i))))
        (setf (aref g p) 0)))
    (let ((sign (aref f 0)))
      (dotimes (i p)
        (setf (aref out i) (* sign (aref v (- p 1 i))))))
    (values out (zerop delta))))

;;; ---- polynomial arithmetic in Rq ----

(defun sntrup761-rq-mult-small (h f g)
  "H = F * G in Rq, where F is an Fq vector and G a small vector."
  (declare (type (simple-array (signed-byte 16) (*)) h f)
           (type (simple-array (signed-byte 8) (*)) g))
  (let ((p +sntrup761-p+)
        (fg (make-array (1- (* 2 +sntrup761-p+))
                        :element-type '(signed-byte 32) :initial-element 0)))
    (dotimes (i p)
      (let ((fi (aref f i)))
        (dotimes (j p)
          (incf (aref fg (+ i j)) (* fi (aref g j))))))
    (loop for i from p below (1- (* 2 p))
          do (incf (aref fg (- i p)) (aref fg i)))
    (loop for i from p below (1- (* 2 p))
          do (incf (aref fg (1+ (- i p))) (aref fg i)))
    (dotimes (i p)
      (setf (aref h i) (sntrup761-fq-freeze (aref fg i))))
    h))

(defun sntrup761-rq-mult3 (h f)
  "H = 3 * F in Rq."
  (declare (type (simple-array (signed-byte 16) (*)) h f))
  (dotimes (i +sntrup761-p+ h)
    (setf (aref h i) (sntrup761-fq-freeze (* 3 (aref f i))))))

(defun sntrup761-fq-recip (a)
  "A^(q-2) modulo q, the multiplicative inverse of the unit A."
  (declare (type fixnum a))
  (let ((ai a))
    (dotimes (i (1- (- +sntrup761-q+ 2)) ai)
      (declare (ignore i))
      (setf ai (sntrup761-fq-freeze (* a ai))))))

(defun sntrup761-rq-recip3 (out in)
  "The inverse of 3 * IN in Rq, into OUT, with the same retry protocol
as SNTRUP761-R3-RECIP."
  (declare (type (simple-array (signed-byte 16) (*)) out)
           (type (simple-array (signed-byte 8) (*)) in))
  (let* ((p +sntrup761-p+)
         (size (1+ p))
         (f (make-array size :element-type '(signed-byte 16) :initial-element 0))
         (g (make-array size :element-type '(signed-byte 16) :initial-element 0))
         (v (make-array size :element-type '(signed-byte 16) :initial-element 0))
         (r (make-array size :element-type '(signed-byte 16) :initial-element 0))
         (delta 1))
    (setf (aref r 0) (sntrup761-fq-recip 3)
          (aref f 0) 1
          (aref f (1- p)) -1
          (aref f p) -1)
    (dotimes (i p)
      (setf (aref g (- p 1 i)) (aref in i)))
    (dotimes (loop-count (1- (* 2 p)))
      (declare (ignore loop-count))
      (loop for i from p downto 1
            do (setf (aref v i) (aref v (1- i))))
      (setf (aref v 0) 0)
      (let ((swap (logand (if (minusp (- delta)) -1 0)
                          (if (zerop (aref g 0)) 0 -1))))
        (setf delta (logxor delta (logand swap (logxor delta (- delta)))))
        (incf delta)
        (dotimes (i size)
          (let ((tmp (logand swap (logxor (aref f i) (aref g i)))))
            (setf (aref f i) (logxor (aref f i) tmp)
                  (aref g i) (logxor (aref g i) tmp))
            (setf tmp (logand swap (logxor (aref v i) (aref r i))))
            (setf (aref v i) (logxor (aref v i) tmp)
                  (aref r i) (logxor (aref r i) tmp))))
        (let ((f0 (aref f 0))
              (g0 (aref g 0)))
          (dotimes (i size)
            (setf (aref g i)
                  (sntrup761-fq-freeze (- (* f0 (aref g i))
                                          (* g0 (aref f i))))))
          (dotimes (i size)
            (setf (aref r i)
                  (sntrup761-fq-freeze (- (* f0 (aref r i))
                                          (* g0 (aref v i)))))))
        (dotimes (i p)
          (setf (aref g i) (aref g (1+ i))))
        (setf (aref g p) 0)))
    (let ((scale (sntrup761-fq-recip (aref f 0))))
      (dotimes (i p)
        (setf (aref out i)
              (sntrup761-fq-freeze (* scale (aref v (- p 1 i)))))))
    (values out (zerop delta))))

(defun sntrup761-round (out a)
  "OUT = A - (A mod 3), the multiple of 3 nearest to A in each place."
  (declare (type (simple-array (signed-byte 16) (*)) out a))
  (dotimes (i +sntrup761-p+ out)
    (setf (aref out i) (- (aref a i) (sntrup761-f3-freeze (aref a i))))))

;;; ---- encodings ----

(defun sntrup761-encode (s pos r m len)
  "Pack LEN digits of the mixed-radix numbers R/M into S from POS on.

This is the reference Encode: adjacent digits are combined, their low
octets written, and the reduced digits packed recursively.  Returns the
position after the last octet written."
  (declare (type (simple-array (unsigned-byte 8) (*)) s)
           (type (simple-array (unsigned-byte 16) (*)) r m)
           (type fixnum pos len))
  (if (= len 1)
      (let ((rr (aref r 0))
            (mm (aref m 0)))
        (loop while (> mm 1)
              do (setf (aref s pos) (logand rr #xff))
                 (incf pos)
                 (setf rr (ash rr -8)
                       mm (ash (+ mm 255) -8)))
        pos)
      (let* ((half (ash (+ len 1) -1))
             (r2 (make-array half :element-type '(unsigned-byte 16)))
             (m2 (make-array half :element-type '(unsigned-byte 16)))
             (i 0))
        (loop while (< i (1- len))
              do (let* ((m0 (aref m i))
                        (rr (+ (aref r i) (* (aref r (1+ i)) m0)))
                        (mm (* (aref m (1+ i)) m0)))
                   (loop while (>= mm 16384)
                         do (setf (aref s pos) (logand rr #xff))
                            (incf pos)
                            (setf rr (ash rr -8)
                                  mm (ash (+ mm 255) -8)))
                   (setf (aref r2 (ash i -1)) rr
                         (aref m2 (ash i -1)) mm))
                 (incf i 2))
        (when (< i len)
          (setf (aref r2 (ash i -1)) (aref r i)
                (aref m2 (ash i -1)) (aref m i)))
        (sntrup761-encode s pos r2 m2 half))))

(defun sntrup761-decode (out opos s ipos m len)
  "Unpack LEN mixed-radix digits from S at IPOS into OUT at OPOS.

Returns the position after the octets consumed at this level."
  (declare (type (simple-array (unsigned-byte 16) (*)) out)
           (type (simple-array (unsigned-byte 8) (*)) s)
           (type (simple-array (unsigned-byte 16) (*)) m)
           (type fixnum opos ipos len))
  (if (= len 1)
      (let ((mm (aref m 0)))
        (setf (aref out opos)
              (cond ((= mm 1) 0)
                    ((<= mm 256)
                     (mod (aref s ipos) mm))
                    (t
                     (mod (+ (aref s ipos) (ash (aref s (1+ ipos)) 8)) mm))))
        ipos)
      (let* ((half (ash (+ len 1) -1))
             (pairs (ash len -1))
             (r2 (make-array half :element-type '(unsigned-byte 16)))
             (m2 (make-array half :element-type '(unsigned-byte 16)))
             (bottomr (make-array pairs :element-type '(unsigned-byte 16)))
             (bottomt (make-array pairs :element-type '(unsigned-byte 32)))
             (i 0))
        (loop while (< i (1- len))
              do (let* ((mm (* (aref m i) (aref m (1+ i))))
                        (slot (ash i -1)))
                   (cond ((> mm (* 256 16383))
                          (setf (aref bottomt slot) (* 256 256)
                                (aref bottomr slot)
                                (+ (aref s ipos) (* 256 (aref s (1+ ipos))))
                                (aref m2 slot)
                                (ash (+ (ash (+ mm 255) -8) 255) -8))
                          (incf ipos 2))
                         ((>= mm 16384)
                          (setf (aref bottomt slot) 256
                                (aref bottomr slot) (aref s ipos)
                                (aref m2 slot) (ash (+ mm 255) -8))
                          (incf ipos))
                         (t
                          (setf (aref bottomt slot) 1
                                (aref bottomr slot) 0
                                (aref m2 slot) mm))))
                 (incf i 2))
        (when (< i len)
          (setf (aref m2 (ash i -1)) (aref m i)))
        (setf ipos (sntrup761-decode r2 0 s ipos m2 half))
        (dotimes (k pairs)
          (let* ((mi (aref m (* 2 k)))
                 (mi+1 (aref m (1+ (* 2 k))))
                 (r (+ (aref bottomr k) (* (aref bottomt k) (aref r2 k))))
                 (quot (truncate r mi)))
            (setf (aref out opos) (- r (* quot mi)))
            (incf opos)
            (setf (aref out opos) (mod quot mi+1))
            (incf opos)))
        (when (< i len)
          (setf (aref out opos) (aref r2 (ash i -1)))
          (incf opos))
        ipos)))

(defun sntrup761-small-encode (s f)
  "Pack the small vector F two bits per coefficient into S."
  (declare (type (simple-array (unsigned-byte 8) (*)) s)
           (type (simple-array (signed-byte 8) (*)) f))
  (let ((pos 0))
    (dotimes (i (truncate +sntrup761-p+ 4))
      (let ((x 0))
        (dotimes (j 4)
          (incf x (ash (1+ (aref f (+ (* 4 i) j))) (* 2 j))))
        (setf (aref s pos) x))
      (incf pos))
    (setf (aref s pos) (1+ (aref f (1- +sntrup761-p+))))
    (incf pos)
    pos))

(defun sntrup761-small-decode (f s &optional (start 0))
  "Unpack the small vector F from S, starting at octet START."
  (declare (type (simple-array (signed-byte 8) (*)) f)
           (type (simple-array (unsigned-byte 8) (*)) s))
  (let ((pos 0))
    (dotimes (i (truncate +sntrup761-p+ 4))
      (let ((x (aref s (+ start pos))))
        (dotimes (j 4)
          (setf (aref f (+ (* 4 i) j))
                (1- (logand (ash x (- (* 2 j))) 3)))))
      (incf pos))
    (setf (aref f (1- +sntrup761-p+))
          (1- (logand (aref s (+ start pos)) 3)))
    f))

(defun sntrup761-rq-encode (s r)
  "Pack the balanced Fq vector R into S (1158 octets)."
  (declare (type (simple-array (unsigned-byte 8) (*)) s)
           (type (simple-array (signed-byte 16) (*)) r))
  (let ((digits (make-array +sntrup761-p+ :element-type '(unsigned-byte 16)))
        (modulus (make-array +sntrup761-p+ :element-type '(unsigned-byte 16)
                             :initial-element +sntrup761-q+)))
    (dotimes (i +sntrup761-p+)
      (setf (aref digits i) (+ (aref r i) +sntrup761-q12+)))
    (sntrup761-encode s 0 digits modulus +sntrup761-p+)))

(defun sntrup761-rq-decode (r s)
  "Unpack the balanced Fq vector R from S."
  (declare (type (simple-array (signed-byte 16) (*)) r)
           (type (simple-array (unsigned-byte 8) (*)) s))
  (let ((digits (make-array +sntrup761-p+ :element-type '(unsigned-byte 16)))
        (modulus (make-array +sntrup761-p+ :element-type '(unsigned-byte 16)
                             :initial-element +sntrup761-q+)))
    (sntrup761-decode digits 0 s 0 modulus +sntrup761-p+)
    (dotimes (i +sntrup761-p+ r)
      (setf (aref r i) (- (aref digits i) +sntrup761-q12+)))))

(defun sntrup761-rounded-encode (s r)
  "Pack the rounded vector R (multiples of 3) into the first 1007 octets of S."
  (declare (type (simple-array (unsigned-byte 8) (*)) s)
           (type (simple-array (signed-byte 16) (*)) r))
  (let ((digits (make-array +sntrup761-p+ :element-type '(unsigned-byte 16)))
        (modulus (make-array +sntrup761-p+ :element-type '(unsigned-byte 16)
                             :initial-element (truncate (+ +sntrup761-q+ 2) 3))))
    (dotimes (i +sntrup761-p+)
      (setf (aref digits i)
            (ash (* (+ (aref r i) +sntrup761-q12+) 10923) -15)))
    (sntrup761-encode s 0 digits modulus +sntrup761-p+)))

(defun sntrup761-rounded-decode (r s)
  "Unpack the rounded vector R from S."
  (declare (type (simple-array (signed-byte 16) (*)) r)
           (type (simple-array (unsigned-byte 8) (*)) s))
  (let ((digits (make-array +sntrup761-p+ :element-type '(unsigned-byte 16)))
        (modulus (make-array +sntrup761-p+ :element-type '(unsigned-byte 16)
                             :initial-element (truncate (+ +sntrup761-q+ 2) 3))))
    (sntrup761-decode digits 0 s 0 modulus +sntrup761-p+)
    (dotimes (i +sntrup761-p+ r)
      (setf (aref r i) (- (* (aref digits i) 3) +sntrup761-q12+)))))

;;; ---- randomness and hashing ----

(defun sntrup761-short-from-list (out list)
  "Turn 761 uniform 32-bit words into a weight-w small vector.

The first w words are made even and the rest odd, then both the values
and the words are sorted, so the low two bits give a small vector with
exactly w nonzero entries in a uniformly random order."
  (declare (type (simple-array (signed-byte 8) (*)) out)
           (type (simple-array (unsigned-byte 32) (*)) list))
  (let ((p +sntrup761-p+)
        (w +sntrup761-w+))
    (dotimes (i w)
      (setf (aref list i) (logand (aref list i) #xfffffffe)))
    (loop for i from w below p
          do (setf (aref list i) (logior (logand (aref list i) #xfffffffc) 1)))
    (let ((sorted (sort list #'<)))
      (dotimes (i p out)
        (setf (aref out i) (1- (logand (aref sorted i) 3)))))))

(defun sntrup761-short-random (out random)
  "Fill OUT with a fresh weight-w small vector from RANDOM."
  (declare (type (simple-array (signed-byte 8) (*)) out))
  (let* ((p +sntrup761-p+)
         (bytes (funcall random (* 4 p)))
         (words (make-array p :element-type '(unsigned-byte 32))))
    (dotimes (i p)
      (let ((pos (* 4 i)))
        (setf (aref words i)
              (logior (aref bytes pos)
                      (ash (aref bytes (+ pos 1)) 8)
                      (ash (aref bytes (+ pos 2)) 16)
                      (ash (aref bytes (+ pos 3)) 24)))))
    (sntrup761-short-from-list out words)))

(defun sntrup761-small-random (out random)
  "Fill OUT with uniform elements of {-1, 0, 1} from RANDOM."
  (declare (type (simple-array (signed-byte 8) (*)) out))
  (let* ((p +sntrup761-p+)
         (bytes (funcall random (* 4 p))))
    (dotimes (i p out)
      (let ((pos (* 4 i))
            (word 0))
        (setf word
              (logior (aref bytes pos)
                      (ash (aref bytes (+ pos 1)) 8)
                      (ash (aref bytes (+ pos 2)) 16)
                      (ash (aref bytes (+ pos 3)) 24)))
        (setf (aref out i)
              (1- (ash (* (logand word #x3fffffff) 3) -30)))))))

(defun sntrup761-hash-prefix (byte octets)
  "The first 32 octets of SHA-512(BYTE || OCTETS)."
  (declare (type (unsigned-byte 8) byte))
  (let ((input (make-array (1+ (length octets))
                           :element-type '(unsigned-byte 8))))
    (setf (aref input 0) byte)
    (replace input octets :start1 1)
    (subseq (digest-sequence :sha512 input) 0 +sntrup761-hash-bytes+)))

(defun sntrup761-hash-confirm (r-enc cache)
  "The confirmation hash of the encoded short vector and the cached hash."
  (let ((x (make-array (* 2 +sntrup761-hash-bytes+)
                       :element-type '(unsigned-byte 8))))
    (replace x (sntrup761-hash-prefix 3 r-enc))
    (replace x cache :start1 +sntrup761-hash-bytes+)
    (sntrup761-hash-prefix 2 x)))

(defun sntrup761-hash-session (domain r-enc ciphertext)
  "The shared secret hashed with DOMAIN (1 or 0) from the two halves."
  (let ((x (make-array (+ +sntrup761-hash-bytes+
                          +sntrup761-ciphertext-bytes+)
                       :element-type '(unsigned-byte 8))))
    (replace x (sntrup761-hash-prefix 3 r-enc))
    (replace x ciphertext :start1 +sntrup761-hash-bytes+)
    (sntrup761-hash-prefix domain x)))

;;; ---- key generation, encapsulation, decapsulation ----

(defun sntrup761-keygen (h f ginv random)
  "Fill H with the public key polynomial, F with f and GINV with g^-1."
  (declare (type (simple-array (signed-byte 16) (*)) h)
           (type (simple-array (signed-byte 8) (*)) f ginv))
  (let ((g (make-array +sntrup761-p+ :element-type '(signed-byte 8)))
        (finv (make-array +sntrup761-p+ :element-type '(signed-byte 16))))
    (loop
      (sntrup761-small-random g random)
      (when (nth-value 1 (sntrup761-r3-recip ginv g))
        (return)))
    (sntrup761-short-random f random)
    (sntrup761-rq-recip3 finv f)
    (sntrup761-rq-mult-small h finv g)))

(defun sntrup761-encrypt (c r h)
  "The rounded ciphertext polynomial C from the short vector R and H."
  (declare (type (simple-array (signed-byte 16) (*)) c h)
           (type (simple-array (signed-byte 8) (*)) r))
  (let ((hr (make-array +sntrup761-p+ :element-type '(signed-byte 16))))
    (sntrup761-rq-mult-small hr h r)
    (sntrup761-round c hr)))

(defun sntrup761-decrypt (r c f ginv)
  "Recover the short vector R from the ciphertext polynomial C.

A vector whose weight is wrong is replaced by an all-{1,0} vector so the
caller's re-encryption check fails instead of accepting an invalid key."
  (declare (type (simple-array (signed-byte 8) (*)) r f ginv)
           (type (simple-array (signed-byte 16) (*)) c))
  (let ((p +sntrup761-p+)
        (w +sntrup761-w+)
        (cf (make-array +sntrup761-p+ :element-type '(signed-byte 16)))
        (cf3 (make-array +sntrup761-p+ :element-type '(signed-byte 16)))
        (e (make-array +sntrup761-p+ :element-type '(signed-byte 8)))
        (ev (make-array +sntrup761-p+ :element-type '(signed-byte 8))))
    (sntrup761-rq-mult-small cf c f)
    (sntrup761-rq-mult3 cf3 cf)
    (sntrup761-r3-from-rq e cf3)
    (sntrup761-r3-mult ev e ginv)
    (let ((weight 0))
      (dotimes (i p)
        (incf weight (logand (aref ev i) 1)))
      (let ((mask (if (= weight w) 0 -1)))
        (dotimes (i w)
          (setf (aref r i)
                (logxor (logand (logxor (aref ev i) 1) (lognot mask)) 1)))
        (loop for i from w below p
              do (setf (aref r i) (logand (aref ev i) (lognot mask))))))
    r))

(defun sntrup761-hide (ciphertext r-enc r pk cache)
  "Encrypt R under PK into CIPHERTEXT and append its confirmation."
  (declare (type (simple-array (unsigned-byte 8) (*)) ciphertext r-enc pk cache)
           (type (simple-array (signed-byte 8) (*)) r))
  (sntrup761-small-encode r-enc r)
  (let ((h (make-array +sntrup761-p+ :element-type '(signed-byte 16)))
        (c (make-array +sntrup761-p+ :element-type '(signed-byte 16))))
    (sntrup761-rq-decode h pk)
    (sntrup761-encrypt c r h)
    (sntrup761-rounded-encode ciphertext c))
  (replace ciphertext (sntrup761-hash-confirm r-enc cache)
           :start1 (- +sntrup761-ciphertext-bytes+
                      +sntrup761-confirm-bytes+))
  ciphertext)

(defun sntrup761-keypair (&key (random #'random-data))
  "Generate a fresh sntrup761 keypair.

Returns (VALUES PUBLIC-KEY SECRET-KEY), 1158 and 1763 octets."
  (let* ((h (make-array +sntrup761-p+ :element-type '(signed-byte 16)))
         (f (make-array +sntrup761-p+ :element-type '(signed-byte 8)))
         (ginv (make-array +sntrup761-p+ :element-type '(signed-byte 8)))
         (pk (make-array +sntrup761-public-key-bytes+
                         :element-type '(unsigned-byte 8)))
         (sk (make-array +sntrup761-secret-key-bytes+
                         :element-type '(unsigned-byte 8)))
         (f-enc (make-array +sntrup761-small-bytes+
                            :element-type '(unsigned-byte 8)))
         (g-enc (make-array +sntrup761-small-bytes+
                            :element-type '(unsigned-byte 8))))
    (sntrup761-keygen h f ginv random)
    (sntrup761-rq-encode pk h)
    (sntrup761-small-encode f-enc f)
    (sntrup761-small-encode g-enc ginv)
    (replace sk f-enc)
    (replace sk g-enc :start1 +sntrup761-small-bytes+)
    (replace sk pk :start1 +sntrup761-secret-keys-bytes+)
    (replace sk (funcall random +sntrup761-small-bytes+)
             :start1 (+ +sntrup761-secret-keys-bytes+
                        +sntrup761-public-key-bytes+))
    (replace sk (sntrup761-hash-prefix 4 pk)
             :start1 (+ +sntrup761-secret-keys-bytes+
                        +sntrup761-public-key-bytes+
                        +sntrup761-small-bytes+))
    (values pk sk)))

(defun sntrup761-encapsulate (pk &key (random #'random-data))
  "Encapsulate a shared secret under PUBLIC-KEY.

Returns (VALUES CIPHERTEXT SHARED-SECRET), 1039 and 32 octets."
  (unless (and (typep pk '(simple-array (unsigned-byte 8) (*)))
               (= (length pk) +sntrup761-public-key-bytes+))
    (error 'missing-key-parameter
           :kind :sntrup761 :parameter 'bytes
           :description "sntrup761 public key"))
  (let ((cache (sntrup761-hash-prefix 4 pk))
        (r (make-array +sntrup761-p+ :element-type '(signed-byte 8)))
        (ciphertext (make-array +sntrup761-ciphertext-bytes+
                                :element-type '(unsigned-byte 8)))
        (r-enc (make-array +sntrup761-small-bytes+
                           :element-type '(unsigned-byte 8))))
    (sntrup761-short-random r random)
    (sntrup761-hide ciphertext r-enc r pk cache)
    (values ciphertext (sntrup761-hash-session 1 r-enc ciphertext))))

(defun sntrup761-decapsulate (ciphertext sk)
  "Decapsulate CIPHERTEXT with SECRET-KEY, returning 32 octets.

A ciphertext that does not re-encrypt to itself yields the secret picked
by the implicit-rejection hash instead of an error, as in the reference."
  (unless (and (typep ciphertext '(simple-array (unsigned-byte 8) (*)))
               (= (length ciphertext) +sntrup761-ciphertext-bytes+))
    (error 'invalid-message-length :kind :sntrup761))
  (unless (and (typep sk '(simple-array (unsigned-byte 8) (*)))
               (= (length sk) +sntrup761-secret-key-bytes+))
    (error 'missing-key-parameter
           :kind :sntrup761 :parameter 'bytes
           :description "sntrup761 secret key"))
  (let* ((pk-start +sntrup761-secret-keys-bytes+)
         (rho-start (+ pk-start +sntrup761-public-key-bytes+))
         (cache-start (+ rho-start +sntrup761-small-bytes+))
         (pk (subseq sk pk-start rho-start))
         (rho (subseq sk rho-start cache-start))
         (cache (subseq sk cache-start))
         (r (make-array +sntrup761-p+ :element-type '(signed-byte 8)))
         (f (make-array +sntrup761-p+ :element-type '(signed-byte 8)))
         (ginv (make-array +sntrup761-p+ :element-type '(signed-byte 8)))
         (c (make-array +sntrup761-p+ :element-type '(signed-byte 16)))
         (r-enc (make-array +sntrup761-small-bytes+
                            :element-type '(unsigned-byte 8)))
         (ciphertext-new (make-array +sntrup761-ciphertext-bytes+
                                     :element-type '(unsigned-byte 8))))
    (sntrup761-small-decode f sk)
    (sntrup761-small-decode ginv sk +sntrup761-small-bytes+)
    (sntrup761-rounded-decode c ciphertext)
    (sntrup761-decrypt r c f ginv)
    (sntrup761-hide ciphertext-new r-enc r pk cache)
    (let ((mask (if (equalp ciphertext ciphertext-new) 0 -1)))
      (dotimes (i +sntrup761-small-bytes+)
        (setf (aref r-enc i)
              (logxor (aref r-enc i)
                      (logand mask (logxor (aref r-enc i) (aref rho i))))))
      (sntrup761-hash-session (1+ mask) r-enc ciphertext))))

;;; ---- generic key interface ----

(defclass sntrup761-key ()
  ((bytes :initarg :bytes :reader sntrup761-key-bytes)))

(defclass sntrup761-public-key (sntrup761-key)
  ())

(defclass sntrup761-private-key (sntrup761-key)
  ())

(defun sntrup761-check-bytes (bytes length kind)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) length))
    (error 'missing-key-parameter
           :kind kind :parameter 'bytes
           :description "sntrup761 key bytes"))
  (copy-seq bytes))

(defmethod make-public-key ((kind (eql :sntrup761)) &key bytes &allow-other-keys)
  (make-instance 'sntrup761-public-key
                 :bytes (sntrup761-check-bytes
                         bytes +sntrup761-public-key-bytes+ kind)))

(defmethod make-private-key ((kind (eql :sntrup761)) &key bytes &allow-other-keys)
  (make-instance 'sntrup761-private-key
                 :bytes (sntrup761-check-bytes
                         bytes +sntrup761-secret-key-bytes+ kind)))

(defmethod destructure-public-key ((public-key sntrup761-public-key))
  (list :bytes (copy-seq (sntrup761-key-bytes public-key))))

(defmethod destructure-private-key ((private-key sntrup761-private-key))
  (list :bytes (copy-seq (sntrup761-key-bytes private-key))))

(defmethod generate-key-pair ((kind (eql :sntrup761)) &key &allow-other-keys)
  (multiple-value-bind (pk sk)
      (sntrup761-keypair)
    (values (make-private-key :sntrup761 :bytes sk)
            (make-public-key :sntrup761 :bytes pk))))

(defmethod encapsulate-key ((public-key sntrup761-public-key))
  (sntrup761-encapsulate (sntrup761-key-bytes public-key)))

(defmethod decapsulate-key ((private-key sntrup761-private-key) ciphertext)
  (sntrup761-decapsulate ciphertext (sntrup761-key-bytes private-key)))
