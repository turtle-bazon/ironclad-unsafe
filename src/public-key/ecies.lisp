;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ecies.lisp -- Elliptic Curve Integrated Encryption Scheme
;;;;
;;;; ECIES over the SEC curves, built from existing pieces: an
;;;; ephemeral key pair, ECDH for the shared secret, HKDF-SHA256 for
;;;; key derivation (32-octet AES-256-GCM key) and AES-256-GCM for the
;;;; data.  Layout, all concatenated:
;;;;
;;;;   ephemeral public key, uncompressed (65/65/97/133 octets)
;;;;   initialization vector (12 octets)
;;;;   ciphertext (message length)
;;;;   authentication tag (16 octets)
;;;;
;;;; (encrypt-message recipient-public-key message &key info salt)
;;;; (decrypt-message recipient-private-key message &key info salt)
;;;; INFO and SALT are HKDF info/salt octet vectors (both empty by
;;;; default); sender and receiver must agree on them.

(in-package :crypto)


(defun %ecies-field-octets (curve)
  (ecase curve
    (:secp256k1 32)
    (:secp256r1 32)
    (:secp384r1 48)
    (:secp521r1 66)))

(defun %ecies-kdf (x salt info)
  "HKDF-SHA256 over the shared-secret octets X; 32-octet output."
  (let ((kdf (make-kdf :hkdf :digest :sha256
                       :additional-data (or info (make-array 0 :element-type '(unsigned-byte 8))))))
    (derive-key kdf x (or salt (make-array 0 :element-type '(unsigned-byte 8))) 0 32)))

(defun %ecies-shared-x (curve private-key public-key field-octets)
  "X coordinate of the ECDSA Diffie-Hellman secret as octets."
  (let ((secret (diffie-hellman private-key public-key)))
    ;; The shared secret is the uncompressed point encoding;
    ;; the x coordinate follows the 0x04 prefix.
    (subseq secret 1 (1+ field-octets))))

(defun %ecies-encrypt (curve recipient-public message start end info salt)
  (multiple-value-bind (ephemeral-private ephemeral-public)
      (generate-key-pair curve)
    (let* ((field-octets (%ecies-field-octets curve))
           (ephemeral-octets (getf (destructure-public-key ephemeral-public) :y))
           (x (%ecies-shared-x curve ephemeral-private recipient-public field-octets))
           (enc-key (%ecies-kdf x salt info))
           (iv (random-data 12))
           (mode (make-authenticated-encryption-mode :gcm
                                                     :cipher-name :aes
                                                     :key enc-key
                                                     :initialization-vector iv))
           (ciphertext (encrypt-message mode message :start start :end end))
           (tag (produce-tag mode)))
      (concatenate '(simple-array (unsigned-byte 8) (*))
                   ephemeral-octets iv ciphertext tag))))

(defun %ecies-decrypt (curve recipient-private message start end info salt)
  (let* ((end (or end (length message)))
         (field-octets (%ecies-field-octets curve))
         (ephemeral-length (1+ (* 2 field-octets)))
         (iv-length 12)
         (tag-length 16))
    (unless (>= (- end start) (+ ephemeral-length iv-length tag-length))
      (error 'invalid-message-length :kind 'ecies))
    (let* ((ephemeral-end (+ start ephemeral-length))
           (iv-end (+ ephemeral-end iv-length))
           (tag-start (- end tag-length))
           (ephemeral (subseq message start ephemeral-end))
           (iv (subseq message ephemeral-end iv-end))
           (ciphertext (subseq message iv-end tag-start))
           (tag (subseq message tag-start end))
           (ephemeral-public (make-public-key curve :y ephemeral))
           (x (%ecies-shared-x curve recipient-private ephemeral-public field-octets))
           (enc-key (%ecies-kdf x salt info))
           (mode (make-authenticated-encryption-mode :gcm
                                                     :cipher-name :aes
                                                     :key enc-key
                                                     :initialization-vector iv
                                                     :tag tag)))
      (decrypt-message mode ciphertext))))

(defmacro define-ecies-methods (curve public-class private-class)
  `(progn
     (defmethod encrypt-message ((key ,public-class) message &key (start 0) end info salt &allow-other-keys)
       (%ecies-encrypt ,curve key message start end info salt))
     (defmethod decrypt-message ((key ,private-class) message &key (start 0) end info salt &allow-other-keys)
       (%ecies-decrypt ,curve key message start end info salt))))

(define-ecies-methods :secp256k1 secp256k1-public-key secp256k1-private-key)
(define-ecies-methods :secp256r1 secp256r1-public-key secp256r1-private-key)
(define-ecies-methods :secp384r1 secp384r1-public-key secp384r1-private-key)
(define-ecies-methods :secp521r1 secp521r1-public-key secp521r1-private-key)
