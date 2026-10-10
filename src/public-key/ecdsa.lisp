;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ecdsa.lisp -- generic ECDSA interface over the SEC prime curves
;;;;
;;;; Ironclad implements ECDSA separately for each curve
;;;; (:secp224r1, :secp256k1, :secp256r1, :secp384r1, :secp521r1).  Callers that
;;;; want "just ECDSA" -- or that use the standard NIST names :p-224,
;;;; :p-256, :p-384, :p-521 / :prime256v1 -- previously got a
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
  '(:secp224r1 :secp256k1 :secp256r1 :secp384r1 :secp521r1)
  "Concrete curve kinds with native ECDSA implementations.")

(defparameter *ecdsa-curve-aliases*
  '((:p-224 . :secp224r1)
    (:p-256 . :secp256r1)
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
    (secp224r1-public-key :secp224r1)
    (secp224r1-private-key :secp224r1)
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

(defmethod generate-key-pair ((kind (eql :p-224)) &key &allow-other-keys)
  (generate-key-pair :secp224r1))

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
  (define-alias-key-constructors :p-224 :secp224r1)
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
    (:secp224r1 +secp224r1-l+)
    (:secp256k1 +secp256k1-l+)
    (:secp256r1 +secp256r1-l+)
    (:secp384r1 +secp384r1-l+)
    (:secp521r1 +secp521r1-l+)))

(defun ecdsa-field-octets (curve)
  "Number of message-hash octets consumed by SIGN-MESSAGE for CURVE."
  (ecase curve
    (:secp224r1 28)
    (:secp256k1 32)
    (:secp256r1 32)
    (:secp384r1 48)
    (:secp521r1 66)))

(defun ecdsa-key-x-octets (key)
  "Return the private-key octets of the ECDSA private KEY."
  (let ((curve (ecdsa-curve-for-key key)))
    (ecase curve
      (:secp224r1 (secp224r1-key-x key))
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


;;; SEC 1 / DER interoperability
;;;
;;; Ironclad signatures are raw R || S concatenations.  Most of the
;;; outside world (X.509, TLS, Bitcoin, ...) uses DER-encoded
;;; ASN.1 SEQUENCEs of two INTEGERs instead.  Ironclad points are
;;; uncompressed (0x04 || X || Y); the outside world often uses
;;; compressed (0x02/0x03 || X) form.  This section bridges both gaps.

(defun ecdsa-point-curve (point)
  "Return the canonical curve kind of the SEC POINT object."
  (etypecase point
    (secp224r1-point :secp224r1)
    (secp256k1-point :secp256k1)
    (secp256r1-point :secp256r1)
    (secp384r1-point :secp384r1)
    (secp521r1-point :secp521r1)))

(defun ecdsa-field-prime (curve)
  "Return the field prime of the ECDSA CURVE (a canonical curve kind)."
  (ecase curve
    (:secp224r1 +secp224r1-p+)
    (:secp256k1 +secp256k1-p+)
    (:secp256r1 +secp256r1-p+)
    (:secp384r1 +secp384r1-p+)
    (:secp521r1 +secp521r1-p+)))

(defun ec-encode-point-compressed (point)
  "SEC 1 compressed encoding (0x02/0x03 || X) of the EC POINT.
Decoding is handled by EC-DECODE-POINT, which already accepts
compressed points."
  (let* ((curve (ecdsa-point-curve point))
         (coordinates (ec-destructure-point point))
         (prefix (if (oddp (getf coordinates :y)) 3 2)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (vector prefix)
                 (integer-to-octets (getf coordinates :x)
                                    :n-bits (* 8 (ecdsa-field-octets curve))
                                    :big-endian t))))

(defun %der-encode-length (length)
  "DER length octets for LENGTH."
  (declare (type (integer 0 *) length))
  (if (< length 128)
      (vector length)
      (let ((bytes (integer-to-octets length :big-endian t)))
        (concatenate '(simple-array (unsigned-byte 8) (*))
                     (vector (logior #x80 (length bytes)))
                     bytes))))

(defun %der-encode-integer (n)
  "DER TLV for the non-negative integer N."
  (declare (type integer n))
  (unless (and (integerp n) (not (minusp n)))
    (error 'ironclad-error
           :format-control "Cannot DER-encode negative signature element ~A."
           :format-arguments (list n)))
  (let* ((magnitude (if (zerop n)
                        (vector 0)
                        (integer-to-octets n :n-bits (integer-length n)
                                             :big-endian t)))
         ;; A set high bit would flip the sign; pad with a zero octet,
         ;; counted in the length.
         (pad (if (logbitp 7 (aref magnitude 0)) 1 0)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (vector #x02)
                 (%der-encode-length (+ (length magnitude) pad))
                 (if (plusp pad) (vector 0) #())
                 magnitude)))

(defun ecdsa-der-encode (r s)
  "Encode ECDSA signature integers R and S as a DER octet vector
\(ASN.1 SEQUENCE of two INTEGERs, as used by X.509, TLS, etc.)."
  (declare (type integer r s))
  (let ((rb (%der-encode-integer r))
        (sb (%der-encode-integer s)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (vector #x30)
                 (%der-encode-length (+ (length rb) (length sb)))
                 rb sb)))

(defun ecdsa-der-decode (der &key (start 0) end)
  "Decode a DER ECDSA signature between START and END.
Returns (VALUES R S) as integers.  Malformed input -- wrong tags,
bad lengths, negative or non-minimal integers, trailing data --
signals IRONCLAD-ERROR."
  (check-type der simple-octet-vector)
  (let ((end (or end (length der))))
    (labels ((need (pos n what)
               (unless (<= (+ pos n) end)
                 (error 'ironclad-error
                        :format-control "Truncated DER signature in ~A."
                        :format-arguments (list what)))
               pos)
             (take-length (pos)
               (need pos 1 "length")
               (let ((first (aref der pos)))
                 (cond ((< first #x80)
                        (values first (1+ pos)))
                       ((= first #x80)
                        (error 'ironclad-error
                               :format-control "Indefinite DER length is not allowed in signatures."))
                       (t
                        (let ((count (logand first #x7f)))
                          (when (> count 4)
                            (error 'ironclad-error
                                   :format-control "Overlong DER length ~D." :format-arguments (list count)))
                          (need (1+ pos) count "long-form length")
                          (let ((length (octets-to-integer der :start (1+ pos)
                                                               :end (+ pos 1 count)
                                                               :big-endian t)))
                            (when (< length 128)
                              (error 'ironclad-error
                                     :format-control "Non-minimal DER length ~D." :format-arguments (list length)))
                            (values length (+ pos 1 count))))))))
             (take-integer (pos)
               (need pos 1 "integer tag")
               (unless (= (aref der pos) #x02)
                 (error 'ironclad-error
                        :format-control "Expected DER INTEGER tag, found ~2,'0X."
                        :format-arguments (list (aref der pos))))
               (multiple-value-bind (length p) (take-length (1+ pos))
                 (when (zerop length)
                   (error 'ironclad-error
                          :format-control "Empty DER INTEGER."))
                 (need p length "integer body")
                 (let ((first (aref der p)))
                   (cond ((>= first #x80)
                          (error 'ironclad-error
                                 :format-control "Negative DER signature element."))
                         ((and (> length 1)
                               (zerop first)
                               (< (aref der (1+ p)) #x80))
                          (error 'ironclad-error
                                 :format-control "Non-minimal DER INTEGER encoding."))))
                 (values (octets-to-integer der :start p :end (+ p length)
                                                :big-endian t)
                         (+ p length)))))
      (need start 1 "sequence tag")
      (unless (= (aref der start) #x30)
        (error 'ironclad-error
               :format-control "Expected DER SEQUENCE tag, found ~2,'0X."
               :format-arguments (list (aref der start))))
      (multiple-value-bind (length pos) (take-length (1+ start))
        (unless (= (+ pos length) end)
          (error 'ironclad-error
                 :format-control "DER signature length mismatch: ~D bytes of content for ~D bytes of input."
                 :format-arguments (list length (- end pos))))
        (multiple-value-bind (r p) (take-integer pos)
          (multiple-value-bind (s p2) (take-integer p)
            (unless (= p2 end)
              (error 'ironclad-error
                     :format-control "Trailing data after DER signature."))
            (values r s)))))))

(defun ecdsa-signature-to-der (curve signature)
  "Convert the raw R || S SIGNATURE on CURVE to DER encoding.
CURVE accepts canonical kinds and aliases (see RESOLVE-ECDSA-CURVE)."
  (let* ((curve (resolve-ecdsa-curve curve))
         (rolen (ecdsa-field-octets curve)))
    (unless (= (length signature) (* 2 rolen))
      (error 'invalid-signature-length :kind curve))
    (ecdsa-der-encode
     (octets-to-integer signature :start 0 :end rolen :big-endian t)
     (octets-to-integer signature :start rolen :end (* 2 rolen)
                                    :big-endian t))))

(defun ecdsa-der-to-signature (curve der)
  "Convert the DER signature DER to raw R || S form on CURVE.
Elements that do not fit the curve size signal
INVALID-SIGNATURE-LENGTH."
  (multiple-value-bind (r s) (ecdsa-der-decode der)
    (let* ((curve (resolve-ecdsa-curve curve))
           (rolen (ecdsa-field-octets curve))
           (limit (ash 1 (* 8 rolen))))
      (unless (and (< -1 r limit) (< -1 s limit))
        (error 'invalid-signature-length :kind curve))
      (make-signature curve
                      :r (integer-to-octets r :n-bits (* 8 rolen)
                                              :big-endian t)
                      :s (integer-to-octets s :n-bits (* 8 rolen)
                                              :big-endian t)))))
