;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ascon.lisp -- Ascon-Hash256 and Ascon-XOF128 (NIST SP 800-232)
;;;;
;;;; Sponge over the 320-bit Ascon permutation (5 x 64-bit words,
;;;; little-endian byte layout, per the standard).  Rate 8, p12 for
;;;; absorption and squeezing.
;;;;
;;;; (MAKE-DIGEST :ASCON-HASH256)               ; 32-octet output
;;;; (MAKE-DIGEST :ASCON-XOF128 &key output-length) ; default 32

(in-package :crypto)


(defconstant +ascon-mask64+ #xFFFFFFFFFFFFFFFF)

(defconstant +ascon-hash-iv+ 8800401358850)
(defconstant +ascon-xof-iv+ 8796106391555)
;;; Ascon-AEAD128 (rate 16, 6-round middle layer), used by
;;; src/aead/ascon.lisp.
(defconstant +ascon-aead-iv+ 17594342703105)

(defun ascon-ror64 (x n)
  "Right-rotate the 64-bit X by N bits."
  (declare (type (unsigned-byte 64) x)
           (type (integer 0 63) n)
           (optimize (speed 3) (safety 0) (debug 0)))
  (when (plusp n)
    (ldb (byte 64 0)
         (logior (ash x (- n))
                 (ash x (- 64 n))))))

(defun ascon-round (s c)
  (declare (type (simple-array (unsigned-byte 64) (5)) s)
           (type (unsigned-byte 8) c)
           (optimize (speed 3) (safety 0) (debug 0)))
  (let ((x0 (aref s 0)) (x1 (aref s 1)) (x2 (aref s 2))
        (x3 (aref s 3)) (x4 (aref s 4)))
    (declare (type (unsigned-byte 64) x0 x1 x2 x3 x4))
    ;; Round constant, then the linear mixing step.
    (setf x2 (ldb (byte 64 0) (logxor x2 c)))
    (setf x0 (ldb (byte 64 0) (logxor x0 x4))
          x4 (ldb (byte 64 0) (logxor x4 x3))
          x2 (ldb (byte 64 0) (logxor x2 x1)))
    ;; S-box.  Intermediates may go negative (LOGNOT of an unsigned
    ;; word), so keep them as integers and truncate each store below.
     (let ((t0 (logxor x0 (logand (lognot x1) x2)))
           (t1 (logxor x1 (logand (lognot x2) x3)))
           (t2 (logxor x2 (logand (lognot x3) x4)))
           (t3 (logxor x3 (logand (lognot x4) x0)))
           (t4 (logxor x4 (logand (lognot x0) x1)))
           (u1 0) (u0 0) (u3 0) (u2 0))
       (declare (type integer t0 t1 t2 t3 t4 u0 u1 u2 u3))
      (setf u1 (ldb (byte 64 0) (logxor t1 t0))
            u0 (ldb (byte 64 0) (logxor t0 t4))
            u3 (ldb (byte 64 0) (logxor t3 t2))
            u2 (ldb (byte 64 0) (lognot t2)))
      (setf (aref s 0) (ldb (byte 64 0)
                            (logxor u0 (ascon-ror64 u0 19) (ascon-ror64 u0 28)))
            (aref s 1) (ldb (byte 64 0)
                            (logxor u1 (ascon-ror64 u1 61) (ascon-ror64 u1 39)))
            (aref s 2) (ldb (byte 64 0)
                            (logxor u2 (ascon-ror64 u2 1) (ascon-ror64 u2 6)))
            (aref s 3) (ldb (byte 64 0)
                            (logxor u3 (ascon-ror64 u3 10) (ascon-ror64 u3 17)))
            (aref s 4) (ldb (byte 64 0)
                            (logxor t4 (ascon-ror64 t4 7) (ascon-ror64 t4 41)))))
    (values)))

(defun ascon-p12 (s)
  (declare (type (simple-array (unsigned-byte 64) (5)) s))
  (ascon-round s #xF0)
  (ascon-round s #xE1)
  (ascon-round s #xD2)
  (ascon-round s #xC3)
  (ascon-round s #xB4)
  (ascon-round s #xA5)
  (ascon-round s #x96)
  (ascon-round s #x87)
  (ascon-round s #x78)
  (ascon-round s #x69)
  (ascon-round s #x5A)
  (ascon-round s #x4B)
  (values))

(defun ascon-p8 (s)
  (declare (type (simple-array (unsigned-byte 64) (5)) s))
  (ascon-round s #xB4)
  (ascon-round s #xA5)
  (ascon-round s #x96)
  (ascon-round s #x87)
  (ascon-round s #x78)
  (ascon-round s #x69)
  (ascon-round s #x5A)
  (ascon-round s #x4B)
  (values))

(defun ascon-load-le (bytes start n)
  "Load N bytes at START little-endian into a 64-bit word."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type fixnum start n))
  (let ((w 0))
    (dotimes (i n w)
      (setf w (logior w (ash (aref bytes (+ start i)) (* 8 i)))))))

(defun ascon-store-le (bytes start word n)
  "Store the low N bytes of WORD little-endian at START."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type fixnum start n))
  (dotimes (i n)
    (setf (aref bytes (+ start i)) (ldb (byte 8 (* 8 i)) word)))
  (values))


;;;
;;; Digest structures
;;;

(defstruct (ascon-hash
            (:constructor %make-ascon-hash-state)
            (:copier nil))
  (words (make-array 5 :element-type '(unsigned-byte 64) :initial-element 0)
         :type (simple-array (unsigned-byte 64) (5)))
  (buffer (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)
          :type (simple-array (unsigned-byte 8) (8)))
  (buffer-length 0 :type (integer 0 8))
  (iv 0 :type (unsigned-byte 64))
  (output-length 32 :type (integer 0 *)))

(defun %ascon-init-state (iv)
  (let ((state (%make-ascon-hash-state)))
    (setf (aref (ascon-hash-words state) 0) iv
          (ascon-hash-iv state) iv)
    ;; The initial permutation (IV -> P12) is applied once at setup.
    (ascon-p12 (ascon-hash-words state))
    state))

(defun %make-ascon-hash256-digest (&key &allow-other-keys)
  (let ((state (%ascon-init-state +ascon-hash-iv+)))
    (setf (ascon-hash-output-length state) 32)
    state))

(defun %make-ascon-xof128-digest (&key (output-length 32))
  (unless (and (integerp output-length) (plusp output-length))
    (error 'ironclad-error
           :format-control "Ascon-XOF128 output length must be a positive integer, not ~A."
           :format-arguments (list output-length)))
  (let ((state (%ascon-init-state +ascon-xof-iv+)))
    (setf (ascon-hash-output-length state) output-length)
    state))

(defmethod reinitialize-instance ((state ascon-hash) &rest initargs)
  (declare (ignore initargs))
  (fill (ascon-hash-words state) 0)
  (setf (aref (ascon-hash-words state) 0) (ascon-hash-iv state))
  (ascon-p12 (ascon-hash-words state))
  (fill (ascon-hash-buffer state) 0)
  (setf (ascon-hash-buffer-length state) 0)
  state)

(defmethod copy-digest ((state ascon-hash) &optional copy)
  (check-type copy (or null ascon-hash))
  (let ((copy (or copy (%make-ascon-hash-state))))
    (replace (ascon-hash-words copy) (ascon-hash-words state))
    (replace (ascon-hash-buffer copy) (ascon-hash-buffer state))
    (setf (ascon-hash-buffer-length copy) (ascon-hash-buffer-length state)
          (ascon-hash-iv copy) (ascon-hash-iv state)
          (ascon-hash-output-length copy) (ascon-hash-output-length state))
    copy))

(defmethod digest-length ((state ascon-hash))
  (ascon-hash-output-length state))

(defmethod block-length ((state ascon-hash))
  8)


;;;
;;; Updating
;;;

(defun ascon-hash-update (state sequence start end)
  (declare (type ascon-hash state)
           (type fixnum start end))
  (let ((words (ascon-hash-words state))
        (buffer (ascon-hash-buffer state))
        (pos start))
    ;; Fill the pending partial block first.
    (let ((have (ascon-hash-buffer-length state)))
      (when (plusp have)
        (let ((take (min (- 8 have) (- end pos))))
          (replace buffer sequence :start1 have :end1 (+ have take)
                   :start2 pos :end2 (+ pos take))
          (incf pos take)
          (incf (ascon-hash-buffer-length state) take)
          (when (= (ascon-hash-buffer-length state) 8)
            (setf (aref words 0)
                  (ldb (byte 64 0)
                       (logxor (aref words 0)
                               (ascon-load-le buffer 0 8))))
            (ascon-p12 words)
            (setf (ascon-hash-buffer-length state) 0)))))
    ;; Absorb full blocks straight from the input.
    (loop while (>= (- end pos) 8)
          do (setf (aref words 0)
                   (ldb (byte 64 0)
                        (logxor (aref words 0)
                                (ascon-load-le sequence pos 8))))
             (ascon-p12 words)
             (incf pos 8))
    ;; Buffer the remainder.
    (let ((left (- end pos)))
      (when (plusp left)
        (replace buffer sequence :start1 0 :end1 left
                 :start2 pos :end2 end)
        (setf (ascon-hash-buffer-length state) left)))
    state))

(define-digest-updater ascon-hash
  (ascon-hash-update state sequence start end))

(defun ascon-hash-finalize (state digest digest-start)
  (declare (type ascon-hash state))
  (let ((words (ascon-hash-words state))
        (buffer (ascon-hash-buffer state))
        (have (ascon-hash-buffer-length state))
        (remaining (ascon-hash-output-length state))
        (position digest-start))
    ;; Absorb the final partial block with 0x01 padding.
    (setf (aref words 0)
          (ldb (byte 64 0)
               (logxor (aref words 0)
                       (ascon-load-le buffer 0 have)
                       (ash 1 (* 8 have)))))
    (ascon-p12 words)
    ;; Squeeze output blocks.
    (loop while (> remaining 8)
          do (ascon-store-le digest position (aref words 0) 8)
             (ascon-p12 words)
             (incf position 8)
             (decf remaining 8))
    (ascon-store-le digest position (aref words 0) remaining))
  digest)

(defmethod produce-digest ((state ascon-hash) &key digest (digest-start 0))
  (let ((digest-size (ascon-hash-output-length state))
        (state-copy (copy-digest state)))
    (etypecase digest
      (simple-octet-vector
       (if (<= digest-size (- (length digest) digest-start))
           (ascon-hash-finalize state-copy digest digest-start)
           (error 'insufficient-buffer-space
                  :buffer digest
                  :start digest-start
                  :length digest-size)))
      (null
       (ascon-hash-finalize state-copy
                            (make-array digest-size :element-type '(unsigned-byte 8))
                            0)))))

(setf (get 'ascon-hash256 '%digest-length) 32)
(setf (get 'ascon-hash256 '%make-digest) (symbol-function '%make-ascon-hash256-digest))
(setf (get 'ascon-xof128 '%digest-length) 32)
(setf (get 'ascon-xof128 '%make-digest) (symbol-function '%make-ascon-xof128-digest))
