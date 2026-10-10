;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ascon-aead128.lisp -- Ascon-AEAD128 authenticated encryption
;;;; (NIST SP 800-232, Ascon v1.3 AEAD)
;;;;
;;;; 128-bit key, 128-bit nonce, 128-bit tag, 16-octet rate.
;;;;
;;;; (make-authenticated-encryption-mode :ascon-aead128
;;;;   :key key :initialization-vector iv)  ; 16-byte key, 16-byte nonce

(in-package :crypto)


(defclass ascon-aead128 (aead-mode)
  ((key :accessor ascon-aead128-key
        :type (simple-array (unsigned-byte 8) (16)))
   (nonce :accessor ascon-aead128-nonce
          :type (simple-array (unsigned-byte 8) (16)))
   (state :accessor ascon-aead128-state
          :type (simple-array (unsigned-byte 64) (5)))
   (pending-data :accessor ascon-aead128-pending-data
                 :type (simple-array (unsigned-byte 8) (*))
                 :initform (make-array 0 :element-type '(unsigned-byte 8)))
   (domain-separated-p :accessor ascon-aead128-domain-separated-p
                       :initform nil
                       :type boolean)))

(defun ascon-aead128-load-key (key nonce)
  "Return the 5-word state after the Ascon-AEAD128 initialization."
  (let ((s (make-array 5 :element-type '(unsigned-byte 64) :initial-element 0))
        (k0 (ascon-load-le key 0 8))
        (k1 (ascon-load-le key 8 8)))
    (setf (aref s 0) +ascon-aead-iv+)
    (setf (aref s 1) k0
          (aref s 2) k1
          (aref s 3) (ascon-load-le nonce 0 8)
          (aref s 4) (ascon-load-le nonce 8 8))
    (ascon-p12 s)
    (setf (aref s 3) (logxor (aref s 3) k0)
          (aref s 4) (logxor (aref s 4) k1))
    s))

(defun ascon-aead128-initialize (mode key initialization-vector)
  "Reset MODE state for a fresh encryption or decryption."
  (declare (type simple-octet-vector key initialization-vector))
  (unless (= (length key) 16)
    (error 'invalid-key-length :cipher :ascon-aead128 :accepted-lengths '(16)))
  (unless (= (length initialization-vector) 16)
    (error 'invalid-initialization-vector
           :cipher :ascon-aead128 :block-length 16))
  (setf (ascon-aead128-key mode) (copy-seq key)
        (ascon-aead128-nonce mode) (copy-seq initialization-vector)
        (ascon-aead128-state mode)
        (ascon-aead128-load-key (ascon-aead128-key mode) (ascon-aead128-nonce mode))
        (ascon-aead128-pending-data mode)
        (make-array 0 :element-type '(unsigned-byte 8))
        (ascon-aead128-domain-separated-p mode) nil)
  mode)

(defmethod shared-initialize :after ((mode ascon-aead128) slot-names &rest initargs
                                     &key key initialization-vector &allow-other-keys)
  (declare (ignore slot-names initargs))
  (ascon-aead128-initialize mode key initialization-vector))

(defmethod process-associated-data ((mode ascon-aead128) data &key (start 0) end)
  "Associated data is buffered; it is absorbed before any payload."
  (let ((stop (or end (length data))))
    (when (> stop start)
      (setf (ascon-aead128-pending-data mode)
            (concatenate '(simple-array (unsigned-byte 8) (*))
                         (ascon-aead128-pending-data mode)
                         (subseq data start stop)))))
  (values))

(defun ascon-aead128-absorb-block (s w0 w1 pad0 pad1)
  "XOR two padded words into the state and permute."
  (declare (type (simple-array (unsigned-byte 64) (5)) s)
           (type integer w0 w1 pad0 pad1))
  (setf (aref s 0) (ldb (byte 64 0) (logxor (aref s 0) w0 pad0)))
  (setf (aref s 1) (ldb (byte 64 0) (logxor (aref s 1) w1 pad1)))
  (ascon-p8 s)
  (values))

(defun ascon-aead128-absorb (mode data)
  "Absorb associated data (padded final block) into the state."
  (declare (type ascon-aead128 mode)
           (type (simple-array (unsigned-byte 8) (*)) data))
  (let ((s (ascon-aead128-state mode))
        (len (length data))
        (pos 0))
    (declare (type fixnum len pos))
    (loop while (>= (- len pos) 16)
          do (ascon-aead128-absorb-block s
                                      (ascon-load-le data pos 8)
                                      (ascon-load-le data (+ pos 8) 8)
                                      0 0)
             (incf pos 16))
    (let ((rest (- len pos)))
      (declare (type fixnum rest))
      (cond ((>= rest 8)
             ;; C uses ">= 8": a full word 0 plus the (possibly zero
             ;; length) tail of word 1, padded on word 1.
             (let ((tail (- rest 8)))
               (declare (type fixnum tail))
               (ascon-aead128-absorb-block s
                                        (ascon-load-le data pos 8)
                                        (ascon-load-le data (+ pos 8) tail)
                                        0 (ash 1 (* 8 tail)))))
            (t
             (ascon-aead128-absorb-block s
                                      (ascon-load-le data pos rest)
                                      0
                                      (ash 1 (* 8 rest)) 0)))))
  (values))

(defun ascon-aead128-absorb-pending (mode)
  "Absorb the buffered associated data (once) and add domain separation."
  (let ((data (ascon-aead128-pending-data mode))
        (s (ascon-aead128-state mode)))
    (unless (ascon-aead128-domain-separated-p mode)
      (when (plusp (length data))
        (ascon-aead128-absorb mode data))
      (setf (ascon-aead128-pending-data mode)
            (make-array 0 :element-type '(unsigned-byte 8)))
      (setf (aref s 4) (ldb (byte 64 0)
                            (logxor (aref s 4) (ash #x80 56))))
      (setf (ascon-aead128-domain-separated-p mode) t)))
  (values))

(defun ascon-aead128-encrypt-block (mode data start end out out-start)
  "Encrypt DATA[START, END) into OUT at OUT-START; returns octet count."
  (declare (type ascon-aead128 mode)
           (type fixnum start end out-start)
           (type (simple-array (unsigned-byte 8) (*)) data out))
  (let ((s (ascon-aead128-state mode))
        (len (- end start))
        (pos 0))
    (declare (type fixnum len pos))
    (loop while (>= (- len pos) 16)
          do (setf (aref s 0)
                   (ldb (byte 64 0)
                        (logxor (aref s 0)
                                (ascon-load-le data (+ start pos) 8))))
             (setf (aref s 1)
                   (ldb (byte 64 0)
                        (logxor (aref s 1)
                                (ascon-load-le data (+ start pos 8) 8))))
             (ascon-store-le out (+ out-start pos) (aref s 0) 8)
             (ascon-store-le out (+ out-start pos 8) (aref s 1) 8)
             (ascon-p8 s)
             (incf pos 16))
    (let ((rest (- len pos)))
      (declare (type fixnum rest))
      (cond ((>= rest 8)
             (let ((tail (- rest 8)))
               (declare (type fixnum tail))
               (setf (aref s 0)
                     (ldb (byte 64 0)
                          (logxor (aref s 0)
                                  (ascon-load-le data (+ start pos) 8))))
               (ascon-store-le out (+ out-start pos) (aref s 0) 8)
               (let ((w (ascon-load-le data (+ start pos 8) tail)))
                 (setf (aref s 1)
                       (ldb (byte 64 0)
                            (logxor (aref s 1) w)))
                 (ascon-store-le out (+ out-start pos 8) (aref s 1) tail)
                 (setf (aref s 1)
                       (ldb (byte 64 0)
                            (logxor (aref s 1)
                                    (ash 1 (* 8 tail))))))))
            (t
             (let ((w (ascon-load-le data (+ start pos) rest)))
               (setf (aref s 0)
                     (ldb (byte 64 0)
                          (logxor (aref s 0) w)))
               (ascon-store-le out (+ out-start pos) (aref s 0) rest)
               (setf (aref s 0)
                     (ldb (byte 64 0)
                          (logxor (aref s 0)
                                  (ash 1 (* 8 rest)))))))))
    len))

(defmethod encrypt ((mode ascon-aead128) plaintext ciphertext
                    &key (plaintext-start 0) plaintext-end
                         (ciphertext-start 0) handle-final-block)
  (declare (ignore handle-final-block))
  (let ((end (or plaintext-end (length plaintext))))
    (ascon-aead128-absorb-pending mode)
    (setf (encryption-started-p mode) t)
    (ascon-aead128-encrypt-block mode plaintext plaintext-start end
                              ciphertext ciphertext-start)
    (values (- end plaintext-start) (- end plaintext-start))))

(defun ascon-aead128-decrypt-block (mode data start end out out-start)
  "Decrypt DATA[START, END) into OUT at OUT-START, absorbing the raw
ciphertext into the state; returns octet count."
  (declare (type ascon-aead128 mode)
           (type fixnum start end out-start)
           (type (simple-array (unsigned-byte 8) (*)) data out))
  (let ((s (ascon-aead128-state mode))
        (len (- end start))
        (pos 0))
    (declare (type fixnum len pos))
    (loop while (>= (- len pos) 16)
          do (let ((c0 (ascon-load-le data (+ start pos) 8))
                   (c1 (ascon-load-le data (+ start pos 8) 8)))
               (ascon-store-le out (+ out-start pos) (logxor (aref s 0) c0) 8)
               (ascon-store-le out (+ out-start pos 8) (logxor (aref s 1) c1) 8)
               (setf (aref s 0) c0
                     (aref s 1) c1)
               (ascon-p8 s)
               (incf pos 16)))
    (let ((rest (- len pos)))
      (declare (type fixnum rest))
      (cond ((>= rest 8)
             (let ((tail (- rest 8)))
               (declare (type fixnum tail))
               (let* ((c0 (ascon-load-le data (+ start pos) 8))
                      (c1 (ascon-load-le data (+ start pos 8) tail)))
                 (ascon-store-le out (+ out-start pos) (logxor (aref s 0) c0) 8)
                 (ascon-store-le out (+ out-start pos)
                                 (ldb (byte (* 8 tail) 0)
                                      (logxor (aref s 1) c1))
                                 tail)
                  (setf (aref s 0) c0
                        (aref s 1)
                        (ldb (byte 64 0)
                             (logxor (logand (aref s 1) (lognot (1- (ash 1 (* 8 tail)))))
                                     (logior c1 (ash 1 (* 8 tail)))))))))
             (t
              (when (plusp rest)
                (let ((c0 (ascon-load-le data (+ start pos) rest)))
                  (ascon-store-le out (+ out-start pos)
                                  (ldb (byte (* 8 rest) 0)
                                       (logxor (aref s 0) c0))
                                  rest)
                  (setf (aref s 0)
                        (ldb (byte 64 0)
                             (logxor c0 (ash 1 (* 8 rest))))))))))
    len))

(defmethod decrypt ((mode ascon-aead128) ciphertext plaintext
                    &key (ciphertext-start 0) ciphertext-end
                         (plaintext-start 0) handle-final-block)
  (let ((end (or ciphertext-end (length ciphertext))))
    (ascon-aead128-absorb-pending mode)
    (ascon-aead128-decrypt-block mode ciphertext ciphertext-start end
                              plaintext plaintext-start)
    (when handle-final-block
      (let ((computed (ascon-aead128-compute-tag mode))
            (expected (tag mode)))
        (when expected
          (unless (constant-time-equal computed expected)
            (error 'bad-authentication-tag)))))
    (values (- end ciphertext-start) (- end ciphertext-start))))

(defun ascon-aead128-finalize (mode)
  "Absorb the key and finish the permutation (tag input)."
  (let ((s (ascon-aead128-state mode))
        (k (ascon-aead128-key mode)))
    (setf (aref s 2) (logxor (aref s 2) (ascon-load-le k 0 8))
          (aref s 3) (logxor (aref s 3) (ascon-load-le k 8 8)))
    (ascon-p12 s)
    (setf (aref s 3) (logxor (aref s 3) (ascon-load-le k 0 8))
          (aref s 4) (logxor (aref s 4) (ascon-load-le k 8 8)))
    (values)))

(defun ascon-aead128-compute-tag (mode)
  (ascon-aead128-finalize mode)
  (let ((s (ascon-aead128-state mode))
        (tag (make-array 16 :element-type '(unsigned-byte 8))))
    (ascon-store-le tag 0 (aref s 3) 8)
    (ascon-store-le tag 8 (aref s 4) 8)
    tag))

(defmethod produce-tag ((mode ascon-aead128) &key tag (tag-start 0))
  (let ((computed (ascon-aead128-compute-tag mode)))
    (etypecase tag
      (simple-octet-vector
       (if (<= 16 (- (length tag) tag-start))
           (progn (replace tag computed :start1 tag-start) tag)
           (error 'insufficient-buffer-space
                  :buffer tag :start tag-start :length 16)))
      (null computed))))

(defmethod encrypt-message ((mode ascon-aead128) message &key (start 0) end
                            associated-data (associated-data-start 0)
                            associated-data-end &allow-other-keys)
  (let ((length (- (or end (length message)) start))
        (ciphertext (make-array (- (or end (length message)) start)
                                :element-type '(unsigned-byte 8))))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start
                               :end associated-data-end))
    (encrypt mode message ciphertext
             :plaintext-start start :plaintext-end end)
    ciphertext))

(defmethod decrypt-message ((mode ascon-aead128) message &key (start 0) end
                            associated-data (associated-data-start 0)
                            associated-data-end &allow-other-keys)
  (let ((plaintext (make-array (- (or end (length message)) start)
                               :element-type '(unsigned-byte 8))))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start
                               :end associated-data-end))
    (decrypt mode message plaintext
             :ciphertext-start start :ciphertext-end end
             :handle-final-block t)
    plaintext))

(defaead ascon-aead128)
