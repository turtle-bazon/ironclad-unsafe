;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; rsa.lisp -- implementation of the RSA public key algorithm

(in-package :crypto)

;;; class definitions

(defclass rsa-key ()
  ((n :initarg :n :reader rsa-key-modulus :type integer)))

(defclass rsa-public-key (rsa-key)
  ((e :initarg :e :reader rsa-key-exponent :type integer)))

(defclass rsa-private-key (rsa-key)
  ((d :initarg :d :reader rsa-key-exponent :type integer)
   (p :initarg :p :reader rsa-key-prime-p :type integer)
   (q :initarg :q :reader rsa-key-prime-q :type integer)
   (crt-dp :initarg :crt-dp :accessor rsa-key-crt-dp :type (or null integer))
   (crt-dq :initarg :crt-dq :accessor rsa-key-crt-dq :type (or null integer))
   (crt-qinv :initarg :crt-qinv :accessor rsa-key-crt-qinv :type (or null integer))))

;;; function definitions

(defmethod make-public-key ((kind (eql :rsa))
                            &key e n &allow-other-keys)
  (unless e
    (error 'missing-key-parameter
           :kind 'rsa
           :parameter 'e
           :description "public exponent"))
  (unless n
    (error 'missing-key-parameter
           :kind 'rsa
           :parameter 'n
           :description "modulus"))
  (make-instance 'rsa-public-key :e e :n n))

(defmethod destructure-public-key ((public-key rsa-public-key))
  (list :e (rsa-key-exponent public-key)
        :n (rsa-key-modulus public-key)))

(defmethod make-private-key ((kind (eql :rsa))
                             &key d n (p 0) (q 0) &allow-other-keys)
  (unless d
    (error 'missing-key-parameter
           :kind 'rsa
           :parameter 'd
           :description "private exponent"))
  (unless n
    (error 'missing-key-parameter
           :kind 'rsa
           :parameter 'n
           :description "modulus"))
  (let ((dp nil) (dq nil) (qinv nil))
    (when (and (plusp p) (plusp q))
      (setf dp (mod d (1- p))
            dq (mod d (1- q))
            qinv (modular-inverse q p)))
    (make-instance 'rsa-private-key
                   :d d :n n :p p :q q
                   :crt-dp dp :crt-dq dq :crt-qinv qinv)))

(defmethod destructure-private-key ((private-key rsa-private-key))
  (list :d (rsa-key-exponent private-key)
        :n (rsa-key-modulus private-key)
        :p (rsa-key-prime-p private-key)
        :q (rsa-key-prime-q private-key)))

(defun rsa-choose-public-exponent (phi)
  "Pick a small standard public exponent when possible, else a random valid one."
  (or (find-if (lambda (e)
                 (and (< e phi) (= 1 (gcd e phi))))
               '(65537 257 17 5 3))
      (loop for e = (+ 2 (strong-random (- phi 2)))
            until (= 1 (gcd e phi))
            finally (return e))))

(defmethod generate-key-pair ((kind (eql :rsa)) &key num-bits &allow-other-keys)
  (unless num-bits
    (error 'missing-key-parameter
           :kind 'rsa
           :parameter 'num-bits
           :description "modulus size"))
  (let ((l (floor num-bits 2)))
    (multiple-value-bind (p q n)
        (loop for a = (generate-prime (- num-bits l))
              for b = (generate-prime l)
              for c = (* a b)
              until (and (/= a b) (= num-bits (integer-length c)))
              finally (return (values a b c)))
      (let* ((phi (* (1- p) (1- q)))
             (e (rsa-choose-public-exponent phi))
             (d (modular-inverse-with-blinding e phi))
             (dp (mod d (1- p)))
             (dq (mod d (1- q)))
             (qinv (modular-inverse q p)))
        (values (make-instance 'rsa-private-key
                               :d d :n n :p p :q q
                               :crt-dp dp :crt-dq dq :crt-qinv qinv)
                (make-public-key :rsa :e e :n n))))))

(defun rsa-core (msg exponent modulus)
  (assert (< msg modulus))
  (expt-mod/unsafe msg exponent modulus))

(defun rsa-crt-core (m key)
  "Compute m^d mod n using CRT when the primes and CRT parameters are available."
  (let ((n (rsa-key-modulus key))
        (p (rsa-key-prime-p key))
        (q (rsa-key-prime-q key))
        (dp (rsa-key-crt-dp key))
        (dq (rsa-key-crt-dq key))
        (qinv (rsa-key-crt-qinv key)))
    (when (and (plusp p) (plusp q) dp dq qinv)
      (let ((mp (expt-mod/unsafe m dp p))
            (mq (expt-mod/unsafe m dq q)))
        (return-from rsa-crt-core
          (mod (+ mq (* q (mod (* qinv (- mp mq)) p))) n)))))
  (rsa-core m (rsa-key-exponent key) (rsa-key-modulus key)))

(defmethod make-message ((kind (eql :rsa)) &key m n-bits &allow-other-keys)
  (unless m
    (error 'missing-message-parameter
           :kind 'rsa
           :parameter 'm
           :description "ciphertext"))
  (unless n-bits
    (error 'missing-message-parameter
           :kind 'rsa
           :parameter 'n-bits
           :description "modulus size"))
  (integer-to-octets m :n-bits n-bits))

(defmethod destructure-message ((kind (eql :rsa)) message)
  (list :m (octets-to-integer message) :n-bits (* 8 (length message))))

(defmethod encrypt-message ((key rsa-public-key) msg &key (start 0) end oaep &allow-other-keys)
  (let* ((n (rsa-key-modulus key))
         (nbits (integer-length n))
         (e (rsa-key-exponent key))
         (m (if oaep
                (octets-to-integer (oaep-encode oaep (subseq msg start end) (/ nbits 8)))
                (octets-to-integer msg :start start :end end))))
    (unless (< m n)
      (error 'invalid-message-length :kind 'rsa))
    (make-message :rsa :m (rsa-core m e n) :n-bits nbits)))

(defmethod decrypt-message ((key rsa-private-key) msg &key (start 0) end n-bits oaep &allow-other-keys)
  (let* ((n (rsa-key-modulus key))
         (nbits (integer-length n))
         (end (or end (length msg))))
    (unless (= (* 8 (- end start)) nbits)
      (error 'invalid-message-length :kind 'rsa))
    (let* ((message-elements (destructure-message :rsa (subseq msg start end)))
           (c (getf message-elements :m)))
      (unless (< c n)
        (error 'invalid-message-length :kind 'rsa))
      (let ((m (rsa-crt-core c key)))
        (if oaep
            (oaep-decode oaep (integer-to-octets m :n-bits nbits))
            (integer-to-octets m :n-bits nbits))))))

(defmethod make-signature ((kind (eql :rsa)) &key s n-bits &allow-other-keys)
  (unless s
    (error 'missing-signature-parameter
           :kind 'rsa
           :parameter 's
           :description "signature"))
  (unless n-bits
    (error 'missing-signature-parameter
           :kind 'rsa
           :parameter 'n-bits
           :description "modulus size"))
  (integer-to-octets s :n-bits n-bits))

(defmethod destructure-signature ((kind (eql :rsa)) signature)
  (list :s (octets-to-integer signature) :n-bits (* 8 (length signature))))

(defmethod sign-message ((key rsa-private-key) msg &key (start 0) end pss &allow-other-keys)
  (let ((nbits (integer-length (rsa-key-modulus key)))
        (m (subseq msg start end)))
    (when pss
      (setf m (pss-encode pss m (/ nbits 8))))
    (setf m (octets-to-integer m))
    (make-signature :rsa
                    :s (rsa-crt-core m key)
                    :n-bits nbits)))

(defmethod verify-signature ((key rsa-public-key) msg signature &key (start 0) end pss &allow-other-keys)
  (let ((nbits (integer-length (rsa-key-modulus key))))
    (unless (= (* 8 (length signature)) nbits)
      (error 'invalid-signature-length :kind 'rsa))
    (let* ((signature-elements (destructure-signature :rsa signature))
           (s (getf signature-elements :s))
           (m (rsa-core s (rsa-key-exponent key) (rsa-key-modulus key))))
      (if pss
          (pss-verify pss (subseq msg start end) (integer-to-octets m :n-bits nbits))
          (= (octets-to-integer msg :start start :end end) m)))))
