;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ccm.lisp -- Counter with CBC-MAC (RFC 3610), AES only
;;;;
;;;; Parameters: 128/192/256-bit KEY, 7..13-octet nonce
;;;; (INITIALIZATION-VECTOR), TAG-LENGTH M in (4 6 8 10 12 14 16),
;;;; MESSAGE-LENGTH = total plaintext octets.  The message length
;;;; drives block B0, so incremental ENCRYPT/DECRYPT calls require it
;;;; up front; ENCRYPT-MESSAGE and DECRYPT-MESSAGE infer it from the
;;;; message when omitted.
;;;;
;;;; (make-authenticated-encryption-mode :ccm
;;;;   &key tag key initialization-vector (tag-length 16) message-length)

(in-package :crypto)


(defclass ccm (aead-mode)
  ((ecb-cipher :accessor ccm-ecb
               :initform nil)
   (ctr-cipher :accessor ccm-ctr
               :initform nil)
   (chain :accessor ccm-chain
          :initform nil)
   (pending :accessor ccm-pending
            :initform nil)
   (associated-data :accessor ccm-ad-buffer
                    :initform nil)
   (key :accessor ccm-key
        :initform nil)
   (nonce :accessor ccm-nonce
          :initform nil)
   (tag-length :accessor ccm-tag-length
               :initform 16
               :type (integer 0 *))
   (message-length :accessor ccm-message-length
                   :initform nil)
   (associated-data-length :accessor ccm-ad-length
                           :initform 0
                           :type (integer 0 *))
   (data-length :accessor ccm-data-length
                :initform 0
                :type (integer 0 *))
   (started-p :accessor ccm-started-p
              :initform nil
              :type boolean)
   (finalized-p :accessor ccm-finalized-p
                :initform nil
                :type boolean)))

(defun ccm-check-parameters (nonce tag-length message-length)
  (let ((nonce-length (length nonce)))
    (unless (<= 7 nonce-length 13)
      (error 'ironclad-error
             :format-control "CCM nonce must be 7 to 13 octets long, not ~D."
             :format-arguments (list nonce-length))))
  (unless (member tag-length '(4 6 8 10 12 14 16))
    (error 'ironclad-error
           :format-control "CCM tag length must be one of 4, 6, 8, 10, 12, 14 or 16, not ~D."
           :format-arguments (list tag-length)))
  (when (and message-length
             (or (minusp message-length)
                 (>= message-length (expt 256 (* 8 (- 15 (length nonce)))))))
    (error 'ironclad-error
           :format-control "CCM message length ~D out of range for a ~D-octet nonce."
           :format-arguments (list message-length (length nonce))))
  (values))

(defun ccm-build-state (mode)
  "Create fresh cipher state from the stored KEY, NONCE and lengths.
B0 itself is emitted lazily by CCM-BEGIN-DATA, once the AAD is known
to be complete."
  (let* ((key (ccm-key mode))
         (nonce (ccm-nonce mode))
         (ecb (make-cipher :aes :key key :mode :ecb))
         (a1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (q (- 15 (length nonce))))
    (setf (aref a1 0) (1- q))
    (replace a1 nonce :start1 1)
    (setf (aref a1 15) 1)
    (setf (ccm-ecb mode) ecb
          (ccm-ctr mode) (make-cipher :aes :key key :mode :ctr
                                      :initialization-vector a1)
          (ccm-chain mode) (make-array 16 :element-type '(unsigned-byte 8)
                                           :initial-element 0)
          (ccm-pending mode) (make-array 0 :element-type '(unsigned-byte 8)
                                            :adjustable t :fill-pointer 0)
          (ccm-ad-buffer mode) (make-array 0 :element-type '(unsigned-byte 8)
                                               :adjustable t :fill-pointer 0)
          (ccm-ad-length mode) 0
          (ccm-data-length mode) 0
          (ccm-started-p mode) nil
          (ccm-finalized-p mode) nil))
  mode)

(defmethod shared-initialize :after ((mode ccm) slot-names &rest initargs &key key initialization-vector (tag-length 16) message-length &allow-other-keys)
  (declare (ignore slot-names initargs))
  (ccm-check-parameters initialization-vector tag-length message-length)
  (setf (ccm-key mode) (copy-seq key)
        (ccm-nonce mode) (copy-seq initialization-vector)
        (ccm-tag-length mode) tag-length
        (ccm-message-length mode) message-length)
  (ccm-build-state mode))

(defun ccm-ecb-block (mode input)
  "AES-ECB encryption of the 16-octet INPUT; fresh 16-octet output."
  (declare (type (simple-array (unsigned-byte 8) (16)) input))
  (let ((output (make-array 16 :element-type '(unsigned-byte 8))))
    (encrypt (ccm-ecb mode) input output)
    output))

(defun ccm-cbc-feed (mode data start end)
  "Absorb DATA[START,END) into the CBC-MAC chain, buffering partials."
  (declare (type (vector (unsigned-byte 8)) data))
  (let ((pending (ccm-pending mode)))
    (loop with pos = start
          do (loop while (and (< (fill-pointer pending) 16) (< pos end))
                   do (vector-push-extend (aref data pos) pending)
                      (incf pos))
             (when (< (fill-pointer pending) 16)
               (return))
             (ccm-process-pending-block mode)
          while (< pos end))
    (values)))

(defun ccm-process-pending-block (mode)
  "XOR the full 16-octet PENDING buffer into the chain and encrypt.
Caller ensures PENDING holds exactly 16 octets."
  (let ((pending (ccm-pending mode))
        (chain (ccm-chain mode)))
    (dotimes (i 16)
      (setf (aref chain i) (logxor (aref chain i) (aref pending i))))
    (replace chain (ccm-ecb-block mode chain))
    (setf (fill-pointer pending) 0))
  (values))

(defun ccm-pad-and-process-pending (mode)
  "Zero-pad a non-empty PENDING buffer to 16 octets and process it."
  (let ((pending (ccm-pending mode)))
    (unless (zerop (fill-pointer pending))
      (loop while (< (fill-pointer pending) 16)
            do (vector-push-extend 0 pending))
      (ccm-process-pending-block mode)))
  (values))

(defun ccm-encode-ad-length (length)
  "RFC 3610 reversible encoding of the AAD length."
  (declare (type (integer 0 *) length))
  (cond ((< length (- (expt 2 16) (expt 2 8)))
         (let ((encoded (make-array 2 :element-type '(unsigned-byte 8))))
           (setf (aref encoded 0) (ldb (byte 8 8) length)
                 (aref encoded 1) (ldb (byte 8 0) length))
           encoded))
        ((< length (expt 2 32))
         (concatenate '(simple-array (unsigned-byte 8) (*))
                      #(255 254)
                      (integer-to-octets length :n-bits 32 :big-endian t)))
        (t
         (concatenate '(simple-array (unsigned-byte 8) (*))
                      #(255 255)
                      (integer-to-octets length :n-bits 64 :big-endian t)))))

(defun ccm-begin-data (mode)
  "Emit B0 and the buffered AAD into the CBC-MAC chain.  Called once,
on the first data block (or at finalization for empty messages)."
  (unless (ccm-started-p mode)
    (let* ((nonce (ccm-nonce mode))
           (q (- 15 (length nonce)))
           (tag-length (ccm-tag-length mode))
           (message-length (ccm-message-length mode))
           (ad-length (ccm-ad-length mode))
           (flags (logior (if (plusp ad-length) 64 0)
                          (ash (truncate (- tag-length 2) 2) 3)
                          (1- q)))
           (b0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (unless message-length
        (error 'ironclad-error
               :format-control "CCM :MESSAGE-LENGTH is required for incremental encryption; ENCRYPT-MESSAGE and DECRYPT-MESSAGE infer it automatically."))
      (setf (aref b0 0) flags)
      (replace b0 nonce :start1 1)
      (let ((encoded-length (integer-to-octets message-length :n-bits (* 8 q) :big-endian t)))
        (replace b0 encoded-length :start1 (- 16 q)))
      (replace (ccm-chain mode) (ccm-ecb-block mode b0))
      (when (plusp ad-length)
        (let ((encoded (ccm-encode-ad-length ad-length)))
          (ccm-cbc-feed mode encoded 0 (length encoded))
          (let ((buffered (ccm-ad-buffer mode)))
            (ccm-cbc-feed mode buffered 0 (length buffered))))
        ;; The AAD field is zero-padded to 16 octets on its own;
        ;; message blocks start on a fresh boundary (RFC 3610 2.2).
        (ccm-pad-and-process-pending mode))
      (setf (ccm-started-p mode) t))
    (values)))

(defun ccm-finalize (mode)
  "Zero-pad the CBC-MAC message tail and verify the declared length."
  (unless (ccm-finalized-p mode)
    (ccm-begin-data mode)
    (ccm-pad-and-process-pending mode)
    (unless (= (ccm-data-length mode) (ccm-message-length mode))
      (error 'ironclad-error
             :format-control "CCM processed ~D octets, but :MESSAGE-LENGTH declared ~D."
             :format-arguments (list (ccm-data-length mode) (ccm-message-length mode))))
    (setf (ccm-finalized-p mode) t))
  (values))

(defun ccm-compute-tag (mode)
  "The M-octet authentication tag for the finalized state."
  (ccm-finalize mode)
  (let* ((tag-length (ccm-tag-length mode))
         (t-value (subseq (ccm-chain mode) 0 tag-length))
         (a0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (s0 (ccm-ecb-block mode
                            (progn (replace a0 (ccm-nonce mode) :start1 1)
                                   (setf (aref a0 0) (1- (- 15 (length (ccm-nonce mode)))))
                                   a0))))
    (map '(simple-array (unsigned-byte 8) (*)) #'logxor t-value (subseq s0 0 tag-length))))

(defmethod process-associated-data ((mode ccm) data &key (start 0) end)
  (if (encryption-started-p mode)
      (error 'ironclad-error :format-control "All associated data must be processed before the encryption begins.")
      (let* ((end (or end (length data)))
             (buffer (ccm-ad-buffer mode)))
        (incf (ccm-ad-length mode) (- end start))
        (loop for i from start below end
              do (vector-push-extend (aref data i) buffer))))
  (values))

(defmethod produce-tag ((mode ccm) &key tag (tag-start 0))
  (let* ((mac-digest (ccm-compute-tag mode))
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

(defmethod encrypt ((mode ccm) plaintext ciphertext &key (plaintext-start 0) plaintext-end (ciphertext-start 0) handle-final-block)
  (declare (ignore handle-final-block))
  (let ((plaintext-end (or plaintext-end (length plaintext)))
        (consumed-bytes 0)
        (produced-bytes 0))
    (when (< plaintext-start plaintext-end)
      (ccm-begin-data mode)
      (unless (encryption-started-p mode)
        (setf (encryption-started-p mode) t))
      (multiple-value-setq (consumed-bytes produced-bytes)
        (encrypt (ccm-ctr mode) plaintext ciphertext
                 :plaintext-start plaintext-start :plaintext-end plaintext-end
                 :ciphertext-start ciphertext-start))
      (incf (ccm-data-length mode) produced-bytes)
      (ccm-cbc-feed mode plaintext plaintext-start (+ plaintext-start consumed-bytes)))
    (values consumed-bytes produced-bytes)))

(defmethod decrypt ((mode ccm) ciphertext plaintext &key (ciphertext-start 0) ciphertext-end (plaintext-start 0) handle-final-block)
  (let ((ciphertext-end (or ciphertext-end (length ciphertext)))
        (consumed-bytes 0)
        (produced-bytes 0))
    (when (< ciphertext-start ciphertext-end)
      (ccm-begin-data mode)
      (unless (encryption-started-p mode)
        (setf (encryption-started-p mode) t))
      (multiple-value-setq (consumed-bytes produced-bytes)
        (decrypt (ccm-ctr mode) ciphertext plaintext
                 :ciphertext-start ciphertext-start :ciphertext-end ciphertext-end
                 :plaintext-start plaintext-start))
      (incf (ccm-data-length mode) consumed-bytes)
      (ccm-cbc-feed mode plaintext plaintext-start (+ plaintext-start produced-bytes)))
    (when (and handle-final-block (tag mode))
      (let ((correct-tag (tag mode))
            (computed-tag (produce-tag mode)))
        (unless (constant-time-equal computed-tag correct-tag)
          (error 'bad-authentication-tag))))
    (values consumed-bytes produced-bytes)))

(defun ccm-ensure-message-length (mode start end length)
  (unless (ccm-message-length mode)
    (setf (ccm-message-length mode) (- (or end length) start)))
  mode)

(defmethod encrypt-message ((mode ccm) message &key (start 0) end associated-data (associated-data-start 0) associated-data-end &allow-other-keys)
  (let* ((length (- (or end (length message)) start))
         (encrypted-message (make-array length :element-type '(unsigned-byte 8))))
    (ccm-ensure-message-length mode start end (length message))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start :end associated-data-end))
    (encrypt mode message encrypted-message
             :plaintext-start start :plaintext-end end)
    encrypted-message))

(defmethod decrypt-message ((mode ccm) message &key (start 0) end associated-data (associated-data-start 0) associated-data-end &allow-other-keys)
  (let* ((length (- (or end (length message)) start))
         (decrypted-message (make-array length :element-type '(unsigned-byte 8))))
    (ccm-ensure-message-length mode start end (length message))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start :end associated-data-end))
    (decrypt mode message decrypted-message
             :plaintext-start start :plaintext-end end
             :handle-final-block t)
    decrypted-message))

(defaead ccm)
