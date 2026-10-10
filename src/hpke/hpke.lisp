;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; hpke.lisp -- Hybrid Public Key Encryption (RFC 9180)
;;;;
;;;; DHKEM (X25519, X448, P-256, P-384, P-521) over HKDF-SHA256/384/512,
;;;; AES-128/256-GCM and ChaCha20-Poly1305 AEADs, all four modes (base,
;;;; psk, auth, auth-psk), stateful sequence-number contexts, and secret
;;;; export.  Ciphersuite and KEM identifiers:
;;;;
;;;;   KEM:  :dhkem-p256 (16) :dhkem-p384 (17) :dhkem-p521 (18)
;;;;         :dhkem-x25519 (32) :dhkem-x448 (33)
;;;;   KDF:  :hkdf-sha256 (1) :hkdf-sha384 (2) :hkdf-sha512 (3)
;;;;   AEAD: :aes-128-gcm (1) :aes-256-gcm (2) :chacha20-poly1305 (3)
;;;;         :export-only (65535)
;;;;   Mode: :base (0) :psk (1) :auth (2) :auth-psk (3)
;;;;
;;;;   (hpke-derive-keypair kem ikm) => sk, pk
;;;;   (hpke-setup-sender kem kdf aead pk-r info ...) => enc, context
;;;;   (hpke-setup-recipient kem kdf aead enc sk-r info ...) => context
;;;;   (hpke-seal sender-context aad pt) => ct
;;;;   (hpke-open recipient-context aad ct) => pt or NIL
;;;;   (hpke-export context exporter-context length) => bytes

(in-package :crypto)


(defconst +hpke-version-label+ (ascii-string-to-byte-array "HPKE-v1"))
(defconst +hpke-kem-label+ (ascii-string-to-byte-array "KEM"))
(defconst +hpke-hpke-label+ (ascii-string-to-byte-array "HPKE"))

(defun hpke-i2osp (n length)
  (integer-to-octets n :n-bits (* 8 length) :big-endian t))

(defun hpke-concat (&rest parts)
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) parts))

(defun hpke-empty-octets ()
  (make-array 0 :element-type '(unsigned-byte 8)))

(defun hpke-kem-suite-id (kem-id)
  (hpke-concat +hpke-kem-label+ (hpke-i2osp kem-id 2)))

(defun hpke-suite-id (kem-id kdf-id aead-id)
  (hpke-concat +hpke-hpke-label+
               (hpke-i2osp kem-id 2)
               (hpke-i2osp kdf-id 2)
               (hpke-i2osp aead-id 2)))


;;;
;;; Ciphersuite tables
;;;

(defun hpke-kem-info (kem)
  "Returns (kem-id curve digest nsecret nsk npk ndh order bitmask) for KEM."
  (ecase kem
    (:dhkem-p256
     (list 16 :secp256r1 :sha256 32 32 65 32 +secp256r1-l+ #xFF))
    (:dhkem-p384
     (list 17 :secp384r1 :sha384 48 48 97 48 +secp384r1-l+ #xFF))
    (:dhkem-p521
     (list 18 :secp521r1 :sha512 64 66 133 66 +secp521r1-l+ #x01))
    (:dhkem-x25519
     (list 32 :curve25519 :sha256 32 32 32 32 nil nil))
    (:dhkem-x448
     (list 33 :curve448 :sha512 64 56 56 56 nil nil))))

(defun hpke-kdf-info (kdf)
  "Returns (digest nh) for KDF."
  (ecase kdf
    (:hkdf-sha256 (values :sha256 32))
    (:hkdf-sha384 (values :sha384 48))
    (:hkdf-sha512 (values :sha512 64))))

(defun hpke-aead-info (aead)
  "Returns (nk nn mode cipher) for AEAD; mode/cipher NIL for export-only."
  (ecase aead
    (:aes-128-gcm (values 16 12 :gcm :aes))
    (:aes-256-gcm (values 32 12 :gcm :aes))
    (:chacha20-poly1305 (values 32 12 :chacha-poly nil))
    (:export-only (values 0 0 nil nil))))

(defun hpke-mode-value (mode)
  (ecase mode
    (:base 0)
    (:psk 1)
    (:auth 2)
    (:auth-psk 3)))


;;;
;;; Labeled KDF
;;;

(defun hpke-labeled-extract (digest suite-id salt label ikm)
  (hkdf-extract digest salt
                (hpke-concat +hpke-version-label+ suite-id label ikm)))

(defun hpke-labeled-expand (digest suite-id prk label info length)
  (hkdf-expand digest prk
               (hpke-concat (hpke-i2osp length 2)
                            +hpke-version-label+ suite-id label info)
               length))


;;;
;;; Diffie-Hellman layer
;;;

(defun hpke-pk-from-sk (curve sk)
  "Serialized public key for the Nsk-byte private key SK."
  (ecase curve
    ((:secp256r1 :secp384r1 :secp521r1)
     (getf (destructure-private-key (make-private-key curve :x sk)) :y))
    (:curve25519
     (curve25519-public-key sk))
    (:curve448
     (curve448-public-key sk))))

(defun hpke-dh (curve sk pk ndh)
  "Raw DH shared secret (Ndh bytes); validates peer keys and outputs."
  (ecase curve
    ((:secp256r1 :secp384r1 :secp521r1)
     ;; MAKE-PUBLIC-KEY rejects off-curve points; the shared secret
     ;; cannot be the point at infinity for valid inputs, and
     ;; EC-ENCODE-POINT signals loudly if it ever were.
     (let ((ss (diffie-hellman (make-private-key curve :x sk)
                               (make-public-key curve :y pk))))
       (subseq ss 1 (1+ ndh))))
    ((:curve25519 :curve448)
     (let ((ss (diffie-hellman (make-private-key curve :x sk)
                               (make-public-key curve :y pk))))
       (when (every #'zerop ss)
         (error 'ironclad-error
                :format-control "HPKE DH output is all zero."))
       ss))))

(defun hpke-check-bytes (bytes length what)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) length))
    (error 'ironclad-error
           :format-control "HPKE ~A has wrong length (expected ~A bytes)."
           :format-arguments (list what length)))
  bytes)

(defun hpke-derive-keypair (kem ikm)
  "Deterministically derive an (sk pk) byte-vector pair from IKM."
  (destructuring-bind (kem-id curve digest nsecret nsk npk ndh order bitmask)
      (hpke-kem-info kem)
    (declare (ignore nsecret npk ndh))
    (let ((suite-id (hpke-kem-suite-id kem-id))
          (dkp-prk (hpke-labeled-extract digest (hpke-kem-suite-id kem-id)
                                         (hpke-empty-octets) (ascii-string-to-byte-array "dkp_prk")
                                         ikm)))
      (if order
          (loop with counter-bytes = (make-array 1 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                for counter from 0 to 255
                do (setf (aref counter-bytes 0) counter)
                   (let ((cand (hpke-labeled-expand digest (hpke-kem-suite-id kem-id)
                                                    dkp-prk (ascii-string-to-byte-array "candidate")
                                                    counter-bytes nsk)))
                     (setf (aref cand 0) (logand (aref cand 0) bitmask))
                     (let ((sk (octets-to-integer cand :big-endian t)))
                       (when (and (< 0 sk) (< sk order))
                         (return (values (hpke-i2osp sk nsk)
                                         (hpke-pk-from-sk curve (hpke-i2osp sk nsk)))))))
                finally (error 'ironclad-error
                               :format-control "HPKE DeriveKeyPair failed."))
          (let ((sk (hpke-labeled-expand digest (hpke-kem-suite-id kem-id)
                                          dkp-prk (ascii-string-to-byte-array "sk")
                                          (hpke-empty-octets) nsk)))
            (values sk (hpke-pk-from-sk curve sk)))))))


;;;
;;; DHKEM
;;;

(defun hpke-kem-extract-expand (digest kem-id dh kem-context nsecret)
  (let ((eae-prk (hpke-labeled-extract digest (hpke-kem-suite-id kem-id)
                                       (hpke-empty-octets)
                                       (ascii-string-to-byte-array "eae_prk")
                                       dh)))
    (hpke-labeled-expand digest (hpke-kem-suite-id kem-id)
                         eae-prk (ascii-string-to-byte-array "shared_secret")
                         kem-context nsecret)))

(defun hpke-kem-encap (kem pk-r)
  "Returns (shared-secret enc); fresh ephemeral via DeriveKeyPair."
  (destructuring-bind (kem-id curve digest nsecret nsk npk ndh order bitmask)
      (hpke-kem-info kem)
    (declare (ignore order bitmask))
    (hpke-check-bytes pk-r npk "recipient public key")
    (multiple-value-bind (sk-e pk-e) (hpke-derive-keypair kem (random-data nsk))
      (let* ((dh (hpke-dh curve sk-e pk-r ndh))
             (kem-context (hpke-concat pk-e pk-r)))
        (values (hpke-kem-extract-expand digest kem-id dh kem-context nsecret)
                pk-e)))))

(defun hpke-kem-encap-with-ek (kem pk-r sk-e pk-e)
  "Encapsulation with an explicit ephemeral keypair (deterministic)."
  (destructuring-bind (kem-id curve digest nsecret nsk npk ndh order bitmask)
      (hpke-kem-info kem)
    (declare (ignore nsk order bitmask))
    (hpke-check-bytes pk-r npk "recipient public key")
    (hpke-check-bytes pk-e npk "ephemeral public key")
    (let* ((dh (hpke-dh curve sk-e pk-r ndh))
           (kem-context (hpke-concat pk-e pk-r)))
      (values (hpke-kem-extract-expand digest kem-id dh kem-context nsecret)
              pk-e))))

(defun hpke-kem-decap (kem enc sk-r)
  "Returns the shared secret for ENC under private key SK-R."
  (destructuring-bind (kem-id curve digest nsecret nsk npk ndh order bitmask)
      (hpke-kem-info kem)
    (declare (ignore order bitmask))
    (hpke-check-bytes enc npk "encapsulated key")
    (hpke-check-bytes sk-r nsk "recipient private key")
    (let* ((dh (hpke-dh curve sk-r enc ndh))
           (pk-r (hpke-pk-from-sk curve sk-r))
           (kem-context (hpke-concat enc pk-r)))
      (hpke-kem-extract-expand digest kem-id dh kem-context nsecret))))

(defun hpke-kem-auth-encap (kem pk-r sk-s)
  "Returns (shared-secret enc) with sender authentication."
  (destructuring-bind (kem-id curve digest nsecret nsk npk ndh order bitmask)
      (hpke-kem-info kem)
    (declare (ignore order bitmask))
    (hpke-check-bytes pk-r npk "recipient public key")
    (hpke-check-bytes sk-s nsk "sender private key")
    (multiple-value-bind (sk-e pk-e) (hpke-derive-keypair kem (random-data nsk))
      (let* ((dh (hpke-concat (hpke-dh curve sk-e pk-r ndh)
                              (hpke-dh curve sk-s pk-r ndh)))
             (pk-s (hpke-pk-from-sk curve sk-s))
             (kem-context (hpke-concat pk-e pk-r pk-s)))
        (values (hpke-kem-extract-expand digest kem-id dh kem-context nsecret)
                pk-e)))))

(defun hpke-kem-auth-encap-with-ek (kem pk-r sk-s sk-e pk-e)
  "Authenticated encapsulation with explicit ephemeral keypair."
  (destructuring-bind (kem-id curve digest nsecret nsk npk ndh order bitmask)
      (hpke-kem-info kem)
    (declare (ignore nsk order bitmask))
    (hpke-check-bytes pk-r npk "recipient public key")
    (hpke-check-bytes sk-s nsk "sender private key")
    (hpke-check-bytes pk-e npk "ephemeral public key")
    (let* ((dh (hpke-concat (hpke-dh curve sk-e pk-r ndh)
                            (hpke-dh curve sk-s pk-r ndh)))
           (pk-s (hpke-pk-from-sk curve sk-s))
           (kem-context (hpke-concat pk-e pk-r pk-s)))
      (values (hpke-kem-extract-expand digest kem-id dh kem-context nsecret)
              pk-e))))

(defun hpke-kem-auth-decap (kem enc sk-r pk-s)
  "Returns the shared secret, assured for sender key PK-S."
  (destructuring-bind (kem-id curve digest nsecret nsk npk ndh order bitmask)
      (hpke-kem-info kem)
    (declare (ignore order bitmask))
    (hpke-check-bytes enc npk "encapsulated key")
    (hpke-check-bytes sk-r nsk "recipient private key")
    (hpke-check-bytes pk-s npk "sender public key")
    (let* ((dh (hpke-concat (hpke-dh curve sk-r enc ndh)
                            (hpke-dh curve sk-r pk-s ndh)))
           (pk-r (hpke-pk-from-sk curve sk-r))
           (kem-context (hpke-concat enc pk-r pk-s)))
      (hpke-kem-extract-expand digest kem-id dh kem-context nsecret))))


;;;
;;; Key schedule and contexts
;;;

(defclass hpke-context ()
  ((suite :initarg :suite :reader hpke-context-suite)
   (key :initarg :key :reader hpke-context-key)
   (base-nonce :initarg :base-nonce :reader hpke-context-base-nonce)
   (seq :initarg :seq :accessor hpke-context-seq)
   (exporter-secret :initarg :exporter-secret :reader hpke-context-exporter-secret)))

(defclass hpke-sender-context (hpke-context)
  ((enc :initarg :enc :reader hpke-context-enc)))

(defclass hpke-recipient-context (hpke-context)
  ())

(defun hpke-verify-psk-inputs (mode psk psk-id)
  (let ((got-psk (plusp (length psk)))
        (got-psk-id (plusp (length psk-id))))
    (unless (eq got-psk got-psk-id)
      (error 'ironclad-error
             :format-control "HPKE inconsistent PSK inputs."))
    (when (and got-psk (member mode '(:base :auth)))
      (error 'ironclad-error
             :format-control "HPKE PSK input provided when not needed."))
    (unless (or got-psk (member mode '(:base :auth)))
      (error 'ironclad-error
             :format-control "HPKE missing required PSK input."))))

(defun hpke-key-schedule (kem kdf aead mode shared-secret info psk psk-id)
  "Returns (key base-nonce exporter-secret); validates PSK inputs."
  (hpke-verify-psk-inputs mode psk psk-id)
  (multiple-value-bind (digest nh) (hpke-kdf-info kdf)
    (destructuring-bind (kem-id curve kdf2 nsecret nsk npk ndh order bitmask)
        (hpke-kem-info kem)
      (declare (ignore curve kdf2 nsecret nsk npk ndh order bitmask))
      (multiple-value-bind (nk nn mode-name cipher)
          (hpke-aead-info aead)
        (declare (ignore mode-name cipher))
        (let* ((kem-id-num kem-id)
               (kdf-id-num (ecase kdf (:hkdf-sha256 1) (:hkdf-sha384 2) (:hkdf-sha512 3)))
               (aead-id-num (ecase aead (:aes-128-gcm 1) (:aes-256-gcm 2) (:chacha20-poly1305 3) (:export-only 65535)))
               (suite-id (hpke-suite-id kem-id-num kdf-id-num aead-id-num))
               (psk-id-hash (hpke-labeled-extract digest suite-id
                                                  (hpke-empty-octets)
                                                  (ascii-string-to-byte-array "psk_id_hash")
                                                  psk-id))
               (info-hash (hpke-labeled-extract digest suite-id
                                                (hpke-empty-octets)
                                                (ascii-string-to-byte-array "info_hash")
                                                info))
               (key-schedule-context (hpke-concat (vector (hpke-mode-value mode))
                                                  psk-id-hash info-hash))
               (secret (hpke-labeled-extract digest suite-id shared-secret
                                             (ascii-string-to-byte-array "secret")
                                             psk)))
          (values (hpke-labeled-expand digest suite-id secret
                                       (ascii-string-to-byte-array "key")
                                       key-schedule-context nk)
                  (hpke-labeled-expand digest suite-id secret
                                       (ascii-string-to-byte-array "base_nonce")
                                       key-schedule-context nn)
                  (hpke-labeled-expand digest suite-id secret
                                       (ascii-string-to-byte-array "exp")
                                       key-schedule-context nh)))))))

(defun hpke-compute-nonce (base-nonce seq nn)
  (let ((seq-bytes (hpke-i2osp seq nn))
        (nonce (copy-seq base-nonce)))
    (dotimes (i nn nonce)
      (setf (aref nonce i) (logxor (aref nonce i) (aref seq-bytes i))))))

(defun hpke-bump-seq (ctx nn)
  (let ((seq (hpke-context-seq ctx)))
    (when (>= seq (1- (ash 1 (* 8 nn))))
      (error 'ironclad-error
             :format-control "HPKE message limit reached."))
    (setf (hpke-context-seq ctx) (1+ seq))
    seq))

(defun hpke-aead-seal (aead key nonce aad pt)
  (multiple-value-bind (nk nn mode-name cipher)
      (hpke-aead-info aead)
    (declare (ignore nk nn))
    (unless mode-name
      (error 'ironclad-error
             :format-control "HPKE export-only suite cannot seal."))
    (let ((mode (if cipher
                    (make-authenticated-encryption-mode mode-name
                                                        :cipher-name cipher
                                                        :key (copy-seq key)
                                                        :initialization-vector (copy-seq nonce))
                    (make-authenticated-encryption-mode mode-name
                                                        :key (copy-seq key)
                                                        :initialization-vector (copy-seq nonce)))))
      (let ((body (encrypt-message mode pt :associated-data aad)))
        (hpke-concat body (produce-tag mode))))))

(defun hpke-aead-open (aead key nonce aad ct)
  (multiple-value-bind (nk nn mode-name cipher)
      (hpke-aead-info aead)
    (declare (ignore nk nn))
    (unless mode-name
      (error 'ironclad-error
             :format-control "HPKE export-only suite cannot open."))
    (when (< (length ct) 16)
      (return-from hpke-aead-open nil))
    (let ((mode (if cipher
                    (make-authenticated-encryption-mode mode-name
                                                        :cipher-name cipher
                                                        :key (copy-seq key)
                                                        :initialization-vector (copy-seq nonce)
                                                        :tag (subseq ct (- (length ct) 16)))
                    (make-authenticated-encryption-mode mode-name
                                                        :key (copy-seq key)
                                                        :initialization-vector (copy-seq nonce)
                                                        :tag (subseq ct (- (length ct) 16))))))
      (handler-case
          (decrypt-message mode (subseq ct 0 (- (length ct) 16))
                           :associated-data aad)
        (ironclad-error () nil)))))

(defun hpke-setup-sender (kem kdf aead pk-r info &key
                          (psk (hpke-empty-octets)) (psk-id (hpke-empty-octets))
                          sk-s ephemeral-keypair
                          (mode (if sk-s :auth :base)))
  "Returns (enc sender-context).  EPHEMERAL-KEYPAIR is an (skE pkE) list
overriding fresh randomness (deterministic testing)."
  (when (and sk-s (member mode '(:base :psk)))
    (error 'ironclad-error
           :format-control "HPKE sender key provided for non-auth mode."))
  (when (and (null sk-s) (member mode '(:auth :auth-psk)))
    (error 'ironclad-error
           :format-control "HPKE auth mode needs a sender key."))
  (multiple-value-bind (shared-secret enc)
      (if sk-s
          (if ephemeral-keypair
              (hpke-kem-auth-encap-with-ek kem pk-r sk-s
                                           (first ephemeral-keypair)
                                           (second ephemeral-keypair))
              (hpke-kem-auth-encap kem pk-r sk-s))
          (if ephemeral-keypair
              (hpke-kem-encap-with-ek kem pk-r
                                      (first ephemeral-keypair)
                                      (second ephemeral-keypair))
              (hpke-kem-encap kem pk-r)))
    (setf mode (cond ((plusp (length psk)) (if sk-s :auth-psk :psk))
                     (sk-s :auth)
                     (t :base)))
    (multiple-value-bind (key base-nonce exporter-secret)
        (hpke-key-schedule kem kdf aead mode shared-secret info psk psk-id)
      (values enc (make-instance 'hpke-sender-context
                                 :suite (list kem kdf aead mode)
                                 :key key :base-nonce base-nonce :seq 0
                                 :exporter-secret exporter-secret
                                 :enc enc)))))

(defun hpke-setup-recipient (kem kdf aead enc sk-r info &key
                             (psk (hpke-empty-octets)) (psk-id (hpke-empty-octets))
                             pk-s (mode (if pk-s :auth :base)))
  "Returns a recipient context."
  (when (and pk-s (member mode '(:base :psk)))
    (error 'ironclad-error
           :format-control "HPKE sender key provided for non-auth mode."))
  (when (and (null pk-s) (member mode '(:auth :auth-psk)))
    (error 'ironclad-error
           :format-control "HPKE auth mode needs a sender key."))
  (let ((shared-secret (if pk-s
                           (hpke-kem-auth-decap kem enc sk-r pk-s)
                           (hpke-kem-decap kem enc sk-r))))
    (setf mode (cond ((plusp (length psk)) (if pk-s :auth-psk :psk))
                     (pk-s :auth)
                     (t :base)))
    (multiple-value-bind (key base-nonce exporter-secret)
        (hpke-key-schedule kem kdf aead mode shared-secret info psk psk-id)
      (make-instance 'hpke-recipient-context
                     :suite (list kem kdf aead mode)
                     :key key :base-nonce base-nonce :seq 0
                     :exporter-secret exporter-secret))))

(defgeneric hpke-seal (context aad pt)
  (:documentation "Encrypt PT with AAD under a sender context; returns CT."))

(defgeneric hpke-open (context aad ct)
  (:documentation "Decrypt CT with AAD under a recipient context;
returns PT or NIL on failure."))

(defgeneric hpke-export (context exporter-context length)
  (:documentation "Export LENGTH secret bytes under EXPORTER-CONTEXT."))

(defmethod hpke-seal ((context hpke-sender-context) aad pt)
  (destructuring-bind (kem kdf aead mode) (hpke-context-suite context)
    (declare (ignore kem kdf mode))
    (when (eq aead :export-only)
      (error 'ironclad-error
             :format-control "HPKE export-only suite cannot seal."))
    (multiple-value-bind (nk nn mode-name cipher)
        (hpke-aead-info aead)
      (declare (ignore nk mode-name cipher))
      (let* ((seq (hpke-bump-seq context nn))
             (nonce (hpke-compute-nonce (hpke-context-base-nonce context) seq nn)))
        (hpke-aead-seal aead (hpke-context-key context) nonce aad pt)))))

(defmethod hpke-open ((context hpke-recipient-context) aad ct)
  (destructuring-bind (kem kdf aead mode) (hpke-context-suite context)
    (declare (ignore kem kdf mode))
    (when (eq aead :export-only)
      (error 'ironclad-error
             :format-control "HPKE export-only suite cannot open."))
    (multiple-value-bind (nk nn mode-name cipher)
        (hpke-aead-info aead)
      (declare (ignore nk mode-name cipher))
      (let* ((seq (hpke-bump-seq context nn))
             (nonce (hpke-compute-nonce (hpke-context-base-nonce context) seq nn)))
        (hpke-aead-open aead (hpke-context-key context) nonce aad ct)))))

(defmethod hpke-export ((context hpke-context) exporter-context length)
  (destructuring-bind (kem kdf aead mode) (hpke-context-suite context)
    (declare (ignore mode))
    (multiple-value-bind (digest nh) (hpke-kdf-info kdf)
      (declare (ignore nh))
      (destructuring-bind (kem-id curve kdf2 nsecret nsk npk ndh order bitmask)
          (hpke-kem-info kem)
        (declare (ignore curve kdf2 nsecret nsk npk ndh order bitmask))
        (let ((kdf-id-num (ecase kdf (:hkdf-sha256 1) (:hkdf-sha384 2) (:hkdf-sha512 3)))
              (aead-id-num (ecase aead (:aes-128-gcm 1) (:aes-256-gcm 2) (:chacha20-poly1305 3) (:export-only 65535))))
          (hpke-labeled-expand digest (hpke-suite-id kem-id kdf-id-num aead-id-num)
                               (hpke-context-exporter-secret context)
                               (ascii-string-to-byte-array "sec")
                               exporter-context length))))))

(defun hpke-seal-message (kem kdf aead mode pk-r info aad pt &key psk psk-id sk-s)
  "One-shot encryption; returns (enc ct)."
  (multiple-value-bind (enc ctx)
      (hpke-setup-sender kem kdf aead pk-r info
                         :psk (or psk (hpke-empty-octets))
                         :psk-id (or psk-id (hpke-empty-octets))
                         :sk-s sk-s :mode mode)
    (values enc (hpke-seal ctx aad pt))))

(defun hpke-open-message (kem kdf aead mode enc sk-r info aad ct &key psk psk-id pk-s)
  "One-shot decryption; returns PT or NIL."
  (let ((ctx (hpke-setup-recipient kem kdf aead enc sk-r info
                                   :psk (or psk (hpke-empty-octets))
                                   :psk-id (or psk-id (hpke-empty-octets))
                                   :pk-s pk-s :mode mode)))
    (hpke-open ctx aad ct)))
