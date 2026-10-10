;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; x-wing.lisp -- X-Wing hybrid post-quantum KEM
;;;; (draft-connolly-cfrg-xwing-kem-09)
;;;;
;;;; X25519 + ML-KEM-768 combiner.  The 32-byte decapsulation key is a
;;;; seed: SHAKE256(sk, 96) yields the ML-KEM-768 keygen coins (64 bytes)
;;;; and the X25519 secret (32 bytes).  The 1216-byte encapsulation key
;;;; is the ML-KEM-768 public key (1184) followed by the X25519 public
;;;; key (32); the 1120-byte ciphertext likewise.  The 32-byte shared
;;;; secret is SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel).
;;;;
;;;; (generate-key-pair :x-wing) => private-key, public-key
;;;; (encapsulate-key public-key) => ciphertext, shared-secret
;;;; (decapsulate-key private-key ciphertext) => shared-secret

(in-package :crypto)


;;; The 6-byte ASCII label "\./^\" (5c2e2f2f5e5c).
(defconst +x-wing-label+
  (make-array 6 :element-type '(unsigned-byte 8)
                :initial-contents '(92 46 47 47 94 92)))

(defun x-wing-expand (sk)
  "Expand the 32-byte seed SK; returns (pk-M sk-M pk-X sk-X) byte vectors."
  (declare (type (simple-array (unsigned-byte 8) (32)) sk))
  (let ((expanded (ml-kem-shake256 sk 96)))
    (multiple-value-bind (pk-m sk-m)
        (ml-kem-keypair-from-coins (subseq expanded 0 64)
                                   +ml-kem-768-params+)
      (let ((sk-x (subseq expanded 64 96)))
        (values pk-m sk-m (curve25519-public-key sk-x) sk-x)))))

(defun x-wing-ecdh (sk-x peer-x)
  "Raw RFC 7748 X25519 shared secret (32 bytes)."
  (diffie-hellman (make-private-key :curve25519 :x sk-x)
                  (make-public-key :curve25519 :y peer-x)))

(defun x-wing-combiner (ss-m ss-x ct-x pk-x)
  (ml-kem-sha3-256 (concatenate '(simple-array (unsigned-byte 8) (*))
                                ss-m ss-x ct-x pk-x +x-wing-label+)))

(defun x-wing-keypair-from-seed (seed)
  "Deterministic keypair from 32-byte SEED; returns (pk-1216 sk-32)."
  (multiple-value-bind (pk-m sk-m pk-x sk-x)
      (x-wing-expand seed)
    (declare (ignore sk-m sk-x))
    (let ((pk (make-array 1216 :element-type '(unsigned-byte 8))))
      (replace pk pk-m :end2 1184)
      (replace pk pk-x :start1 1184)
      (values pk (copy-seq seed)))))

(defun x-wing-encaps-derand (pk eseed)
  "Deterministic encapsulation under 1216-byte PK with 64-byte ESEED;
returns (ct-1120 ss-32)."
  (let ((pk-m (subseq pk 0 1184))
        (pk-x (subseq pk 1184 1216))
        (ek-x (subseq eseed 32 64)))
    (let ((ct-x (curve25519-public-key ek-x))
          (ss-x (x-wing-ecdh ek-x pk-x)))
      (multiple-value-bind (ct-m ss-m)
          (ml-kem-encaps-from-message (subseq eseed 0 32) pk-m
                                      +ml-kem-768-params+)
        (let ((ct (make-array 1120 :element-type '(unsigned-byte 8))))
          (replace ct ct-m :end2 1088)
          (replace ct ct-x :start1 1088)
          (values ct (x-wing-combiner ss-m ss-x ct-x pk-x)))))))

(defun x-wing-decapsulate (ct sk)
  "Decapsulate 1120-byte CT with 32-byte seed SK; returns 32-byte secret."
  (multiple-value-bind (pk-m sk-m pk-x sk-x) (x-wing-expand sk)
    (declare (ignore pk-m))
    (let ((ct-m (subseq ct 0 1088))
          (ct-x (subseq ct 1088 1120)))
      (let ((ss-m (ml-kem-decapsulate ct-m sk-m +ml-kem-768-params+))
            (ss-x (x-wing-ecdh sk-x ct-x)))
        (x-wing-combiner ss-m ss-x ct-x pk-x)))))


;;;
;;; Public API: key classes, generation, encapsulation
;;;

(defclass x-wing-key ()
  ((bytes :initarg :bytes :reader x-wing-key-bytes)))

(defclass x-wing-public-key (x-wing-key)
  ())

(defclass x-wing-private-key (x-wing-key)
  ())

(defun x-wing-check-bytes (bytes length kind)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) length))
    (error 'missing-key-parameter
           :kind kind
           :parameter 'bytes
           :description "X-Wing key bytes"))
  (copy-seq bytes))

(defmethod make-public-key ((kind (eql :x-wing)) &key bytes &allow-other-keys)
  (make-instance 'x-wing-public-key
                 :bytes (x-wing-check-bytes bytes 1216 :x-wing)))

(defmethod make-private-key ((kind (eql :x-wing)) &key bytes &allow-other-keys)
  (make-instance 'x-wing-private-key
                 :bytes (x-wing-check-bytes bytes 32 :x-wing)))

(defmethod destructure-public-key ((public-key x-wing-public-key))
  (list :bytes (copy-seq (x-wing-key-bytes public-key))))

(defmethod destructure-private-key ((private-key x-wing-private-key))
  (list :bytes (copy-seq (x-wing-key-bytes private-key))))

(defmethod generate-key-pair ((kind (eql :x-wing)) &key &allow-other-keys)
  (multiple-value-bind (pk sk)
      (x-wing-keypair-from-seed (random-data 32))
    (values (make-private-key :x-wing :bytes sk)
            (make-public-key :x-wing :bytes pk))))

(defmethod encapsulate-key ((public-key x-wing-public-key))
  (x-wing-encaps-derand (x-wing-key-bytes public-key) (random-data 64)))

(defmethod decapsulate-key ((private-key x-wing-private-key) ciphertext)
  (unless (and (typep ciphertext '(simple-array (unsigned-byte 8) (*)))
               (= (length ciphertext) 1120))
    (error 'invalid-message-length :kind 'x-wing))
  (x-wing-decapsulate ciphertext (x-wing-key-bytes private-key)))
