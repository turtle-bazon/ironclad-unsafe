;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; public-key.lisp -- implementation of common public key components

(in-package :crypto-unsafe)


(defun list-all-key-pair-kinds ()
  (copy-list '(:curve25519 :curve448 :dsa :ecdsa :ed25519 :ed448 :elgamal
               :ml-dsa-44 :ml-dsa-65 :ml-dsa-87
               :ml-kem-512 :ml-kem-768 :ml-kem-1024
               :bike-l1 :bike-l3 :bike-l5
               :hqc-128 :hqc-192 :hqc-256
               :rsa :falcon-512 :falcon-1024 :slh-dsa-sha2-128s :slh-dsa-sha2-128f :slh-dsa-sha2-192s :slh-dsa-sha2-192f :slh-dsa-sha2-256s :slh-dsa-sha2-256f :slh-dsa-shake-128s :slh-dsa-shake-128f :slh-dsa-shake-192s :slh-dsa-shake-192f :slh-dsa-shake-256s :slh-dsa-shake-256f :mceliece348864 :mceliece460896 :mceliece6688128 :mceliece6960119 :mceliece8192128 :xmss-sha256-h10 :xmss-sha2-10-256 :secp224r1 :secp256k1 :secp256r1 :secp384r1 :secp521r1
               :p-224 :p-256 :prime256v1 :p-384 :p-521 :x-wing)))


;;; class definitions

(defclass discrete-logarithm-group ()
  ((p :initarg :p :reader group-pval)
   (q :initarg :q :reader group-qval)
   (g :initarg :g :reader group-gval)))


;;; Special variable to force the signature nonce during tests instead of
;;; generating a random one.

(defparameter *signature-nonce-for-test* nil)


;;; converting from integers to octet vectors

(defun octets-to-integer (octet-vec &key (start 0) end (big-endian t) n-bits)
  (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec)
           (optimize (speed 3) (space 0) (safety 1) (debug 0)))
  (let ((end (or end (length octet-vec))))
    (multiple-value-bind (n-bits n-bytes)
        (let ((size (- end start)))
          (if n-bits
              (values n-bits (min (ceiling n-bits 8) size))
              (values (* 8 size) size)))
      ;; Accumulate eight bytes (64 bits) at a time.  A per-byte
      ;; (ash sum 8) reallocates the whole bignum every byte, which is
      ;; quadratic and cost about 20% of an RSA-2048 verify.
      (let ((sum
              (if big-endian
                  (let ((base (- end n-bytes))
                        (acc 0))
                    (declare (type fixnum base end)
                             (type integer acc))
                    (loop for hi of-type fixnum = end then (- hi 8)
                          for shift of-type fixnum = 0 then (+ shift 64)
                          while (> hi base)
                          do (let ((lo (max base (- hi 8)))
                                   (chunk 0))
                               (declare (type fixnum lo)
                                        (type (unsigned-byte 64) chunk))
                               (loop for i of-type fixnum from lo below hi
                                     do (setf chunk (logior (ash chunk 8)
                                                            (aref octet-vec i))))
                               (setf acc (logior acc (ash chunk shift)))))
                    acc)
                  (loop for i from start below (+ start n-bytes)
                        for j from 0 by 8
                        sum (ash (aref octet-vec i) j)))))
        (ldb (byte n-bits 0) sum)))))

(defun integer-to-octets (bignum &key n-bits (big-endian t))
  (declare (optimize (speed 3) (space 0) (safety 1) (debug 0)))
  (let* ((n-bits (or n-bits (integer-length bignum)))
         (bignum (ldb (byte n-bits 0) bignum))
         (n-bytes (ceiling n-bits 8))
         (octet-vec (make-array n-bytes :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec))
    (if big-endian
        (loop for i from (1- n-bytes) downto 0
              for index from 0
              do (setf (aref octet-vec index) (ldb (byte 8 (* i 8)) bignum))
              finally (return octet-vec))
        (loop for i from 0 below n-bytes
              for byte from 0 by 8
              do (setf (aref octet-vec i) (ldb (byte 8 byte) bignum))
              finally (return octet-vec)))))

(defun maybe-integerize (thing)
  (etypecase thing
    (integer thing)
    ((simple-array (unsigned-byte 8) (*)) (octets-to-integer thing))))
