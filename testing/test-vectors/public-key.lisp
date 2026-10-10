;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

(rtest:deftest :rsa-oaep-encryption (run-test-vector-file :rsa-enc *public-key-encryption-tests*) t)
(rtest:deftest :elgamal-encryption (run-test-vector-file :elgamal-enc *public-key-encryption-tests*) t)
(rtest:deftest :ecies-encryption (run-test-vector-file :ecies *public-key-encryption-tests*) t)
(rtest:deftest :ml-kem-encapsulation (run-test-vector-file :ml-kem *public-key-encryption-tests*) t)
(rtest:deftest :x-wing-encapsulation (run-test-vector-file :x-wing *public-key-encryption-tests*) t)
(rtest:deftest :ml-dsa-signature (run-test-vector-file :ml-dsa *public-key-signature-tests*) t)

(rtest:deftest :rsa-pss-signature (run-test-vector-file :rsa-sig *public-key-signature-tests*) t)
(rtest:deftest :elgamal-signature (run-test-vector-file :elgamal-sig *public-key-signature-tests*) t)
(rtest:deftest :dsa-signature (run-test-vector-file :dsa *public-key-signature-tests*) t)
(rtest:deftest :ed25519-signature (run-test-vector-file :ed25519 *public-key-signature-tests*) t)
(rtest:deftest :ed448-signature (run-test-vector-file :ed448 *public-key-signature-tests*) t)
(rtest:deftest :secp256k1-signature (run-test-vector-file :secp256k1-sig *public-key-signature-tests*) t)
(rtest:deftest :secp224r1-signature (run-test-vector-file :secp224r1-sig *public-key-signature-tests*) t)
(rtest:deftest :secp256r1-signature (run-test-vector-file :secp256r1-sig *public-key-signature-tests*) t)
(rtest:deftest :secp384r1-signature (run-test-vector-file :secp384r1-sig *public-key-signature-tests*) t)
(rtest:deftest :secp521r1-signature (run-test-vector-file :secp521r1-sig *public-key-signature-tests*) t)
(rtest:deftest :ecdsa-signature (run-test-vector-file :ecdsa-sig *public-key-signature-tests*) t)
(rtest:deftest :ecdsa-rfc6979 (run-test-vector-file :ecdsa-rfc6979 *public-key-signature-tests*) t)
(rtest:deftest :ecdsa-codec (run-test-vector-file :ecdsa-codec *public-key-signature-tests*) t)
(rtest:deftest :curve25519-dh (run-test-vector-file :curve25519 *public-key-diffie-hellman-tests*) t)
(rtest:deftest :curve448-dh (run-test-vector-file :curve448 *public-key-diffie-hellman-tests*) t)
(rtest:deftest :elgamal-dh (run-test-vector-file :elgamal-dh *public-key-diffie-hellman-tests*) t)
(rtest:deftest :secp256k1-dh (run-test-vector-file :secp256k1-dh *public-key-diffie-hellman-tests*) t)
(rtest:deftest :secp224r1-dh (run-test-vector-file :secp224r1-dh *public-key-diffie-hellman-tests*) t)
(rtest:deftest :secp256r1-dh (run-test-vector-file :secp256r1-dh *public-key-diffie-hellman-tests*) t)
(rtest:deftest :secp384r1-dh (run-test-vector-file :secp384r1-dh *public-key-diffie-hellman-tests*) t)
(rtest:deftest :secp521r1-dh (run-test-vector-file :secp521r1-dh *public-key-diffie-hellman-tests*) t)
(rtest:deftest :ecdsa-dh (run-test-vector-file :ecdsa-dh *public-key-diffie-hellman-tests*) t)

(rtest:deftest :ecies-tamper
  ;; Flipping any byte of ephemeral key, IV, ciphertext or tag must
  ;; fail (invalid point or bad tag), never decrypt.
  (multiple-value-bind (priv pub) (ironclad:generate-key-pair :secp256r1)
    (let* ((msg (ironclad:random-data 32))
           (ct (ironclad:encrypt-message pub msg))
           (ok t))
      (dotimes (i (length ct))
        (let ((bad (copy-seq ct)))
          (setf (aref bad i) (logxor (aref bad i) 1))
          (handler-case (progn (ironclad:decrypt-message priv bad) (setf ok nil))
            (ironclad:ironclad-error () nil))))
      ;; ... and the untouched message still verifies, as does a
      ;; decryption with mismatched info/salt.
      (and ok
           (equalp (ironclad:decrypt-message priv ct) msg)
           (handler-case (progn (ironclad:decrypt-message
                                 priv ct :info (ironclad:random-data 4)) nil)
             (ironclad:ironclad-error () t)))))
  t)

(rtest:deftest :ecies-wrong-key
  (multiple-value-bind (priv1 pub1) (ironclad:generate-key-pair :secp256r1)
    (declare (ignore priv1))
    (multiple-value-bind (priv2 pub2) (ironclad:generate-key-pair :secp256r1)
      (declare (ignore pub2))
      (let ((ct (ironclad:encrypt-message pub1 (ironclad:random-data 16))))
        (handler-case (progn (ironclad:decrypt-message priv2 ct) nil)
          (ironclad:ironclad-error () t)))))
  t)

(rtest:deftest :ecdsa-reject-degenerate-signatures
  (multiple-value-bind (priv pub) (ironclad:generate-key-pair :ecdsa)
    (let* ((msg (ironclad:random-data 32))
           (sig (ironclad:sign-message priv msg))
           (half (/ (length sig) 2))
           (sig-r0 (copy-seq sig))
           (sig-s0 (copy-seq sig)))
      (fill sig-r0 0 :end half)
      (fill sig-s0 0 :start half)
      ;; Degenerate (r = 0 / s = 0) signatures must verify as NIL,
      ;; not signal an error; the genuine signature must verify.
      (and (null (ironclad:verify-signature pub msg sig-r0))
           (null (ironclad:verify-signature pub msg sig-s0))
           (ironclad:verify-signature pub msg sig))))
  t)

(rtest:deftest :ecdsa-reject-bad-keys
  (flet ((fails-p (thunk)
           (handler-case (progn (funcall thunk) nil)
             (ironclad:ironclad-error () t))))
    (let ((zeroes (ironclad:hex-string-to-byte-array
                   (concatenate 'string "04" (make-string 64 :initial-element #\0)
                                (make-string 64 :initial-element #\0)))))
      (and
       ;; malformed and off-curve points rejected at construction
       (fails-p (lambda () (ironclad:make-public-key :secp256r1
                                                     :y (ironclad:hex-string-to-byte-array "04"))))
       (fails-p (lambda () (ironclad:make-public-key :secp256r1 :y zeroes)))
       ;; private scalar 0 and >= N rejected ...
       (fails-p (lambda () (ironclad:make-private-key :secp256r1
                                                      :x (ironclad:hex-string-to-byte-array
                                                          (make-string 64 :initial-element #\0)))))
       (fails-p (lambda () (ironclad:make-private-key :secp256r1
                                                      :x (ironclad:integer-to-octets
                                                          (ironclad:ecdsa-curve-order :secp256r1)
                                                          :n-bits 256 :big-endian t))))
       ;; ... while N-1 is accepted and usable
       (let* ((sk (ironclad:make-private-key
                   :secp256r1
                   :x (ironclad:integer-to-octets
                       (1- (ironclad:ecdsa-curve-order :secp256r1))
                       :n-bits 256 :big-endian t)))
              (pk (ironclad:make-public-key
                   :secp256r1
                   :y (getf (ironclad:destructure-private-key sk) :y)))
              (msg (ironclad:random-data 32)))
         (ironclad:verify-signature pk msg (ironclad:sign-message sk msg))))))
  t)

(rtest:deftest :ecdsa-compressed-pubkey-roundtrip
  (multiple-value-bind (priv pub) (ironclad:generate-key-pair :ecdsa :curve :secp384r1)
    (let* ((msg (ironclad:random-data 48))
           (sig (ironclad:sign-message priv msg))
           (raw (getf (ironclad:destructure-public-key pub) :y))
           (reimported (ironclad:make-public-key
                        :ecdsa :curve :secp384r1
                        :y (ironclad:ec-encode-point-compressed
                            (ironclad:ec-decode-point :secp384r1 raw)))))
      (ironclad:verify-signature reimported msg sig)))
  t)
