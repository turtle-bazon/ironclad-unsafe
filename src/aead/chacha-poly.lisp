;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; chacha-poly.lisp -- ChaCha20-Poly1305 and XChaCha20-Poly1305
;;;; authenticated encryption (RFC 8439, draft-arcivanov-xchacha)
;;;;
;;;; Construction: the Poly1305 one-time key is the first 32 bytes of
;;;; the ChaCha20 keystream for block counter 0; the payload is
;;;; encrypted with counter 1 onwards; the tag is computed over
;;;; AAD || pad16 || ciphertext || pad16 || le64(AAD length) ||
;;;; le64(ciphertext length).
;;;;
;;;; (make-authenticated-encryption-mode :chacha-poly
;;;;   :key key :initialization-vector iv)       ; 32-byte key, 12-byte nonce
;;;; (make-authenticated-encryption-mode :xchacha-poly
;;;;   :key key :initialization-vector iv)       ; 32-byte key, 24-byte nonce

(in-package :crypto)


(defclass chacha-poly-base (aead-mode)
  ((data-cipher :accessor chacha-poly-cipher
                :initform nil)
   (mac :accessor chacha-poly-mac
        :initform nil)
   (associated-data-length :accessor chacha-poly-ad-length
                           :initform 0
                           :type (integer 0 *))
   (data-length :accessor chacha-poly-data-length
                :initform 0
                :type (integer 0 *))
   (associated-data-finalized-p :accessor chacha-poly-ad-finalized-p
                                :initform nil
                                :type boolean)
   (tag-finalized-p :accessor chacha-poly-tag-finalized-p
                    :initform nil
                    :type boolean)))

(defclass chacha-poly (chacha-poly-base)
  ())

(defclass xchacha-poly (chacha-poly-base)
  ())

(defgeneric chacha-poly-cipher-name (mode)
  (:documentation "Stream cipher (:CHACHA or :XCHACHA) backing the AEAD MODE."))

(defgeneric chacha-poly-iv-length (mode)
  (:documentation "Nonce length in octets required by the AEAD MODE."))

(defmethod chacha-poly-cipher-name ((mode chacha-poly))
  :chacha)

(defmethod chacha-poly-cipher-name ((mode xchacha-poly))
  :xchacha)

(defmethod chacha-poly-iv-length ((mode chacha-poly))
  12)

(defmethod chacha-poly-iv-length ((mode xchacha-poly))
  24)

(defun chacha-poly-initialize (mode key initialization-vector)
  "Build fresh cipher/MAC state for MODE.  Always constructs new
sub-objects: neither the Chacha ciphers nor Poly1305 support
REINITIALIZE-INSTANCE, and the Poly1305 key is single-use anyway."
  (declare (type simple-octet-vector key initialization-vector))
  (let ((cipher-name (chacha-poly-cipher-name mode))
        (iv-length (chacha-poly-iv-length mode)))
    (unless (= (length key) 32)
      (error 'invalid-key-length :cipher cipher-name :accepted-lengths '(32)))
    (unless (= (length initialization-vector) iv-length)
      (error 'invalid-initialization-vector :cipher cipher-name :block-length iv-length))
    ;; One-time Poly1305 key: first 32 bytes of the counter-0 block.
    (let* ((poly-cipher (make-cipher cipher-name
                                     :key key
                                     :mode :stream
                                     :initialization-vector initialization-vector))
           (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (poly-key (make-array 32 :element-type '(unsigned-byte 8))))
      (declare (dynamic-extent zeros))
      (encrypt poly-cipher zeros poly-key)
      ;; Payload encryption starts at block counter 1: burn block 0.
      (let ((data-cipher (make-cipher cipher-name
                                      :key key
                                      :mode :stream
                                      :initialization-vector initialization-vector))
            (burn (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0))
            (scratch (make-array 64 :element-type '(unsigned-byte 8))))
        (declare (dynamic-extent burn scratch))
        (encrypt data-cipher burn scratch)
        (setf (chacha-poly-cipher mode) data-cipher
              (chacha-poly-mac mode) (make-mac :poly1305 poly-key)
              (chacha-poly-ad-length mode) 0
              (chacha-poly-data-length mode) 0
              (chacha-poly-ad-finalized-p mode) nil
              (chacha-poly-tag-finalized-p mode) nil)))
    mode))

(defmethod shared-initialize :after ((mode chacha-poly-base) slot-names &rest initargs &key key initialization-vector &allow-other-keys)
  (declare (ignore slot-names initargs))
  (chacha-poly-initialize mode key initialization-vector))

(defun chacha-poly-pad-mac (mac length)
  "Feed zero padding up to a 16-octet boundary for LENGTH octets."
  (declare (type (integer 0 *) length))
  (let ((remaining (mod length 16)))
    (unless (zerop remaining)
      (let ((padding (make-array (- 16 remaining)
                                 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
        (declare (dynamic-extent padding))
        (update-mac mac padding)))))

(defun chacha-poly-finalize-aad (mode)
  (unless (chacha-poly-ad-finalized-p mode)
    (chacha-poly-pad-mac (chacha-poly-mac mode) (chacha-poly-ad-length mode))
    (setf (chacha-poly-ad-finalized-p mode) t)))

(defun chacha-poly-finalize-tag (mode)
  (unless (chacha-poly-tag-finalized-p mode)
    (chacha-poly-finalize-aad mode)
    (let ((mac (chacha-poly-mac mode))
          (lengths (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (declare (dynamic-extent lengths))
      (chacha-poly-pad-mac mac (chacha-poly-data-length mode))
      (setf (ub64ref/le lengths 0) (chacha-poly-ad-length mode)
            (ub64ref/le lengths 8) (chacha-poly-data-length mode))
      (update-mac mac lengths))
    (setf (chacha-poly-tag-finalized-p mode) t)))

(defmethod process-associated-data ((mode chacha-poly-base) data &key (start 0) end)
  (if (encryption-started-p mode)
      (error 'ironclad-error :format-control "All associated data must be processed before the encryption begins.")
      (let* ((end (or end (length data)))
             (length (- end start)))
        (incf (chacha-poly-ad-length mode) length)
        (update-mac (chacha-poly-mac mode) data :start start :end end))))

(defmethod produce-tag ((mode chacha-poly-base) &key tag (tag-start 0))
  (chacha-poly-finalize-tag mode)
  (let* ((mac-digest (produce-mac (chacha-poly-mac mode)))
         (digest-size (length mac-digest)))
    (etypecase tag
      (simple-octet-vector
       (if (<= digest-size (- (length tag) tag-start))
           (progn (replace tag mac-digest :start1 tag-start) tag)
           (error 'insufficient-buffer-space
                  :buffer tag
                  :start tag-start
                  :length digest-size)))
      (null
       mac-digest))))

(defmethod encrypt ((mode chacha-poly-base) plaintext ciphertext &key (plaintext-start 0) plaintext-end (ciphertext-start 0) handle-final-block)
  (declare (ignore handle-final-block))
  (let ((cipher (chacha-poly-cipher mode))
        (mac (chacha-poly-mac mode))
        (plaintext-end (or plaintext-end (length plaintext)))
        (consumed-bytes 0)
        (produced-bytes 0))
    (when (< plaintext-start plaintext-end)
      (unless (encryption-started-p mode)
        (chacha-poly-finalize-aad mode)
        (setf (encryption-started-p mode) t))
      (multiple-value-setq (consumed-bytes produced-bytes)
        (encrypt cipher plaintext ciphertext
                 :plaintext-start plaintext-start :plaintext-end plaintext-end
                 :ciphertext-start ciphertext-start))
      (incf (chacha-poly-data-length mode) produced-bytes)
      (update-mac mac ciphertext
                  :start ciphertext-start :end (+ ciphertext-start produced-bytes)))
    (values consumed-bytes produced-bytes)))

(defmethod decrypt ((mode chacha-poly-base) ciphertext plaintext &key (ciphertext-start 0) ciphertext-end (plaintext-start 0) handle-final-block)
  (let ((cipher (chacha-poly-cipher mode))
        (mac (chacha-poly-mac mode))
        (ciphertext-end (or ciphertext-end (length ciphertext)))
        (consumed-bytes 0)
        (produced-bytes 0))
    (when (< ciphertext-start ciphertext-end)
      (unless (encryption-started-p mode)
        (chacha-poly-finalize-aad mode)
        (setf (encryption-started-p mode) t))
      (update-mac mac ciphertext
                  :start ciphertext-start :end ciphertext-end)
      (multiple-value-setq (consumed-bytes produced-bytes)
        (decrypt cipher ciphertext plaintext
                 :ciphertext-start ciphertext-start :ciphertext-end ciphertext-end
                 :plaintext-start plaintext-start))
      (incf (chacha-poly-data-length mode) consumed-bytes))
    (when (and handle-final-block (tag mode))
      (let ((correct-tag (tag mode))
            (computed-tag (produce-tag mode)))
        (unless (constant-time-equal computed-tag correct-tag)
          (error 'bad-authentication-tag))))
    (values consumed-bytes produced-bytes)))

(defmethod encrypt-message ((mode chacha-poly-base) message &key (start 0) end associated-data (associated-data-start 0) associated-data-end &allow-other-keys)
  (let* ((length (- (or end (length message)) start))
         (encrypted-message (make-array length :element-type '(unsigned-byte 8))))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start :end associated-data-end))
    (encrypt mode message encrypted-message
             :plaintext-start start :plaintext-end end)
    encrypted-message))

(defmethod decrypt-message ((mode chacha-poly-base) message &key (start 0) end associated-data (associated-data-start 0) associated-data-end &allow-other-keys)
  (let* ((length (- (or end (length message)) start))
         (decrypted-message (make-array length :element-type '(unsigned-byte 8))))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start :end associated-data-end))
    (decrypt mode message decrypted-message
             :plaintext-start start :plaintext-end end
             :handle-final-block t)
    decrypted-message))

(defaead chacha-poly)
(defaead xchacha-poly)
