;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; rfc6979.lisp -- deterministic nonce generation per RFC 6979
;;;;
;;;; DSA and ECDSA signatures need a fresh random nonce k for every
;;;; signature.  A broken or biased RNG leaks the private key (see the
;;;; well-known PlayStation 3 failure).  RFC 6979 derives k
;;;; deterministically with HMAC-DRBG from the private key and the
;;;; message hash, so signatures are reproducible and need no randomness
;;;; at signing time.  Verifiers are unaffected.
;;;;
;;;; This file provides the curve-independent core:
;;;; RFC6979-GENERATE-K.  Thin per-curve wrappers live with the curve
;;;; implementations; COMPUTE-DETERMINISTIC-NONCE (the key-object
;;;; convenience entry point named in the manual) lives in ecdsa.lisp.

(in-package :crypto)


(defparameter *ecdsa-rfc6979-digest* :sha256
  "Hash function used for the HMAC steps of RFC 6979 nonce generation.
May be any digest name accepted by MAKE-MAC.  RFC 6979 uses the same
hash that produced the message digest; binding this to e.g. :sha512
when signing SHA-512 digests is also fine.")


(defun %rfc6979-hmac (key data digest)
  "HMAC-DIGEST over DATA with KEY, as simple-octet-vectors."
  (declare (type simple-octet-vector key data))
  (let ((mac (make-mac :hmac key digest)))
    (update-mac mac data)
    (produce-mac mac)))

(defun %rfc6979-cat (&rest parts)
  "Concatenate octet vectors into a fresh simple-octet-vector."
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) parts))

(defun %rfc6979-bits2int (octets qlen)
  "RFC 6979 section 2.3.2: leftmost QLEN bits of OCTETS as an integer."
  (let* ((value (octets-to-integer octets :big-endian t))
         (blen (* 8 (length octets))))
    (if (> blen qlen)
        (ash value (- qlen blen))
        value)))

(defun rfc6979-generate-k (priv-octets h1-octets order qlen rolen
                           &key (digest *ecdsa-rfc6979-digest*))
  "RFC 6979 section 3.2: deterministic nonce for private key
PRIV-OCTETS and message hash H1-OCTETS over the group of ORDER.
QLEN is the bit length of ORDER, ROLEN = CEIL(QLEN/8).
Returns an integer K with 1 <= K < ORDER."
  (declare (type simple-octet-vector priv-octets h1-octets)
           (type integer order qlen rolen))
  (let* ((hlen (digest-length digest))
         (x (mod (octets-to-integer priv-octets :big-endian t) order))
         (x-oct (integer-to-octets x :n-bits (* 8 rolen) :big-endian t))
         ;; bits2octets(h1): bits2int, reduced mod order (2.3.4; the
         ;; value is < 2*ORDER so one conditional subtraction suffices).
         (z1 (%rfc6979-bits2int h1-octets qlen))
         (z1 (if (>= z1 order) (- z1 order) z1))
         (h-oct (integer-to-octets z1 :n-bits (* 8 rolen) :big-endian t))
         (v (make-array hlen :element-type '(unsigned-byte 8)
                             :initial-element 1))
         (k (make-array hlen :element-type '(unsigned-byte 8)
                             :initial-element 0)))
    (declare (type simple-octet-vector v k x-oct h-oct))
    (flet ((hmac (k &rest parts)
             (%rfc6979-hmac k (apply #'%rfc6979-cat parts) digest)))
      (setf k (hmac k v #(0) x-oct h-oct))
      (setf v (hmac k v))
      (setf k (hmac k v #(1) x-oct h-oct))
      (setf v (hmac k v))
      (loop
        (let ((t-oct (make-array 0 :element-type '(unsigned-byte 8))))
          (declare (type simple-octet-vector t-oct))
          (loop while (< (* 8 (length t-oct)) qlen)
                do (setf v (hmac k v)
                         t-oct (%rfc6979-cat t-oct v)))
          ;; Note: compared against ORDER, never reduced mod ORDER;
          ;; a modular reduction here would bias K (RFC 6979 3.2.h.3).
          (let ((candidate (%rfc6979-bits2int t-oct qlen)))
            (when (and (plusp candidate) (< candidate order))
              (return candidate))))
        (setf k (hmac k v #(0)))
        (setf v (hmac k v))))))
