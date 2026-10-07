;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ecdsa.lisp -- generic ECDSA interface over the SEC prime curves
;;;;
;;;; Ironclad implements ECDSA separately for each curve
;;;; (:secp256k1, :secp256r1, :secp384r1, :secp521r1).  Callers that
;;;; want "just ECDSA" -- or that use the standard NIST names :p-256,
;;;; :p-384, :p-521 / :prime256v1 -- previously got a
;;;; NO-APPLICABLE-METHOD error from GENERATE-KEY-PAIR, MAKE-PUBLIC-KEY
;;;; and MAKE-PRIVATE-KEY.  This file adds a generic :ecdsa key kind
;;;; (plus the standard aliases) that resolves to one of the concrete
;;;; curve implementations and delegates to it.
;;;;
;;;; The delegated methods return the concrete curve key objects, so
;;;; SIGN-MESSAGE, VERIFY-SIGNATURE and DIFFIE-HELLMAN need no new
;;;; methods: the existing per-curve methods apply directly.
;;;;
;;;; Examples:
;;;;   (generate-key-pair :ecdsa) ; defaults to :secp256r1 (NIST P-256)
;;;;   (generate-key-pair :ecdsa :curve :secp384r1)
;;;;   (generate-key-pair :p-256)
;;;;   (make-public-key :ecdsa :curve :secp256k1 :y octets)
;;;;   (make-private-key :ecdsa :curve :secp521r1 :x octets)

(in-package :crypto)


(defparameter *ecdsa-canonical-curves*
  '(:secp256k1 :secp256r1 :secp384r1 :secp521r1)
  "Concrete curve kinds with native ECDSA implementations.")

(defparameter *ecdsa-curve-aliases*
  '((:p-256 . :secp256r1)
    (:prime256v1 . :secp256r1)
    (:p-384 . :secp384r1)
    (:p-521 . :secp521r1))
  "Standard (NIST/OpenSSL) names mapped to Ironclad curve kinds.")

(defun resolve-ecdsa-curve (curve)
  "Resolve CURVE to a canonical ECDSA curve kind.
CURVE may be a canonical kind, a known alias, or NIL (meaning the
default curve :secp256r1).  Signals IRONCLAD-ERROR for unknown curves."
  (let ((curve (or curve :secp256r1)))
    (cond
      ((member curve *ecdsa-canonical-curves* :test #'eq)
       curve)
      ((cdr (assoc curve *ecdsa-curve-aliases* :test #'eq)))
      (t
       (error 'ironclad-error
              :format-control "Unknown ECDSA curve: ~A."
              :format-arguments (list curve))))))

(defun ecdsa-curve-for-key (key)
  "Return the canonical curve kind of the ECDSA KEY object.
KEY must be one of the concrete SEC curve key objects."
  (etypecase key
    (secp256k1-public-key :secp256k1)
    (secp256k1-private-key :secp256k1)
    (secp256r1-public-key :secp256r1)
    (secp256r1-private-key :secp256r1)
    (secp384r1-public-key :secp384r1)
    (secp384r1-private-key :secp384r1)
    (secp521r1-public-key :secp521r1)
    (secp521r1-private-key :secp521r1)))


;;; key pair generation

(defmethod generate-key-pair ((kind (eql :ecdsa)) &key (curve :secp256r1) &allow-other-keys)
  (generate-key-pair (resolve-ecdsa-curve curve)))

(defmethod generate-key-pair ((kind (eql :p-256)) &key &allow-other-keys)
  (generate-key-pair :secp256r1))

(defmethod generate-key-pair ((kind (eql :prime256v1)) &key &allow-other-keys)
  (generate-key-pair :secp256r1))

(defmethod generate-key-pair ((kind (eql :p-384)) &key &allow-other-keys)
  (generate-key-pair :secp384r1))

(defmethod generate-key-pair ((kind (eql :p-521)) &key &allow-other-keys)
  (generate-key-pair :secp521r1))


;;; key construction

(defmethod make-public-key ((kind (eql :ecdsa)) &key (curve :secp256r1) y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'ecdsa
           :parameter 'y
           :description "public key"))
  (make-public-key (resolve-ecdsa-curve curve) :y y))

(defmethod make-private-key ((kind (eql :ecdsa)) &key (curve :secp256r1) x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'ecdsa
           :parameter 'x
           :description "private key"))
  (make-private-key (resolve-ecdsa-curve curve) :x x :y y))

(macrolet ((define-alias-key-constructors (alias canonical)
             `(progn
                (defmethod make-public-key ((kind (eql ,alias)) &key y &allow-other-keys)
                  (unless y
                    (error 'missing-key-parameter
                           :kind ',alias
                           :parameter 'y
                           :description "public key"))
                  (make-public-key ,canonical :y y))
                (defmethod make-private-key ((kind (eql ,alias)) &key x y &allow-other-keys)
                  (unless x
                    (error 'missing-key-parameter
                           :kind ',alias
                           :parameter 'x
                           :description "private key"))
                  (make-private-key ,canonical :x x :y y)))))
  (define-alias-key-constructors :p-256 :secp256r1)
  (define-alias-key-constructors :prime256v1 :secp256r1)
  (define-alias-key-constructors :p-384 :secp384r1)
  (define-alias-key-constructors :p-521 :secp521r1))


;;; signatures
;;;
;;; The raw signature encoding is the concatenation R || S for every
;;; curve, so MAKE-SIGNATURE only needs CURVE for error reporting.
;;; DESTRUCTURE-SIGNATURE is intentionally not provided for :ecdsa:
;;; 32-byte halves are ambiguous between :secp256k1 and :secp256r1, so
;;; callers must destructure with the concrete curve kind.

(defmethod make-signature ((kind (eql :ecdsa)) &key (curve :secp256r1) r s &allow-other-keys)
  (make-signature (resolve-ecdsa-curve curve) :r r :s s))


;;; RFC 6979 deterministic nonces

(defun ecdsa-curve-order (curve)
  "Return the group order of the ECDSA CURVE (a canonical curve kind)."
  (ecase curve
    (:secp256k1 +secp256k1-l+)
    (:secp256r1 +secp256r1-l+)
    (:secp384r1 +secp384r1-l+)
    (:secp521r1 +secp521r1-l+)))

(defun ecdsa-field-octets (curve)
  "Number of message-hash octets consumed by SIGN-MESSAGE for CURVE."
  (ecase curve
    (:secp256k1 32)
    (:secp256r1 32)
    (:secp384r1 48)
    (:secp521r1 66)))

(defun ecdsa-key-x-octets (key)
  "Return the private-key octets of the ECDSA private KEY."
  (let ((curve (ecdsa-curve-for-key key)))
    (ecase curve
      (:secp256k1 (secp256k1-key-x key))
      (:secp256r1 (secp256r1-key-x key))
      (:secp384r1 (secp384r1-key-x key))
      (:secp521r1 (secp521r1-key-x key)))))

(defun compute-deterministic-nonce (key message &key (digest *ecdsa-rfc6979-digest*)
                                                      (start 0) end)
  "RFC 6979 deterministic signature nonce for ECDSA private KEY over
the MESSAGE octets between START and END.  MESSAGE is the message
hash (hashing is not performed here), exactly as passed to
SIGN-MESSAGE.  DIGEST selects the HMAC hash (default
*ECDSA-RFC6979-DIGEST*).  Returns an integer K with 1 <= K < N.
Redefine GENERATE-SIGNATURE-NONCE to use this (it is the default for
the SEC curves) or to restore random nonces."
  (let* ((curve (ecdsa-curve-for-key key))
         (order (ecdsa-curve-order curve))
         (qlen (integer-length order))
         (rolen (ceiling qlen 8))
         (end (min (or end (length message))
                   (+ start (ecdsa-field-octets curve))))
         (h1 (subseq message start (min end (length message)))))
    (rfc6979-generate-k (ecdsa-key-x-octets key) h1
                        order qlen rolen :digest digest)))
