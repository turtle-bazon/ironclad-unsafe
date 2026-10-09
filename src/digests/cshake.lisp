;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; cshake.lisp -- cSHAKE128/256 extensible-output functions (NIST SP 800-185)
;;;;
;;;; (MAKE-DIGEST :cshake128 &key output-length function-name customization)
;;;; FUNCTION-NAME and CUSTOMIZATION are strings or octet vectors
;;;; (both empty by default, in which case cSHAKE matches SHAKE).

(in-package :crypto)


(defun left-encode (x)
  "Left-encode the non-negative integer X (SP 800-185 2.3)."
  (declare (type (integer 0 *) x))
  (let ((bytes (if (zerop x)
                   (vector 0)
                   (integer-to-octets x :big-endian t))))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (vector (length bytes))
                 bytes)))

(defun right-encode (x)
  "Right-encode the non-negative integer X (SP 800-185 2.3)."
  (declare (type (integer 0 *) x))
  (let ((bytes (if (zerop x)
                   (vector 0)
                   (integer-to-octets x :big-endian t))))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 bytes
                 (vector (length bytes)))))

(defun encode-string (octets)
  "Encode the octet string OCTETS (SP 800-185 2.3); length in bits."
  (declare (type (simple-array (unsigned-byte 8) (*)) octets))
  (concatenate '(simple-array (unsigned-byte 8) (*))
               (left-encode (* 8 (length octets)))
               octets))

(defun bytepad (data rate-bytes)
  "Pad DATA out to a multiple of RATE-BYTES octets (SP 800-185 2.3)."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type (integer 1 *) rate-bytes))
  (let* ((prefixed (concatenate '(simple-array (unsigned-byte 8) (*))
                                (left-encode rate-bytes)
                                data))
         (padded-length (* rate-bytes (ceiling (length prefixed) rate-bytes)))
         (out (make-array padded-length
                          :element-type '(unsigned-byte 8)
                          :initial-element 0)))
    (replace out prefixed)
    out))

(defun coerce-octets (thing)
  (etypecase thing
    (string (coerce-octets (ascii-string-to-byte-array thing)))
    ((simple-array (unsigned-byte 8) (*))
     (copy-seq thing))
    ((vector (unsigned-byte 8))
     (coerce thing '(simple-array (unsigned-byte 8) (*))))
    ((vector *)
     (map '(simple-array (unsigned-byte 8) (*)) #'identity thing))))

(defstruct (cshake
             (:include sha3)
             (:constructor nil)
             (:copier nil))
  (function-name #() :type (simple-array (unsigned-byte 8) (*)))
  (customization #() :type (simple-array (unsigned-byte 8) (*))))

(defstruct (cshake128
             (:include cshake)
             (:constructor %make-cshake128 (bit-rate output-length function-name customization))
             (:copier nil)))

(defstruct (cshake256
             (:include cshake)
             (:constructor %make-cshake256 (bit-rate output-length function-name customization))
             (:copier nil)))

(defun %make-cshake128-digest (&key (output-length 32) (function-name "") (customization ""))
  (let* ((n (coerce-octets function-name))
         (s (coerce-octets customization))
         (state (%make-cshake128 1344 output-length n s)))
    (unless (and (zerop (length n)) (zerop (length s)))
      (let ((prefix (bytepad (concatenate '(simple-array (unsigned-byte 8) (*))
                                          (encode-string n)
                                          (encode-string s))
                             168)))
        (sha3-update state prefix 0 (length prefix))))
    state))

(defun %make-cshake256-digest (&key (output-length 32) (function-name "") (customization ""))
  (let* ((n (coerce-octets function-name))
         (s (coerce-octets customization))
         (state (%make-cshake256 1088 output-length n s)))
    (unless (and (zerop (length n)) (zerop (length s)))
      (let ((prefix (bytepad (concatenate '(simple-array (unsigned-byte 8) (*))
                                          (encode-string n)
                                          (encode-string s))
                             136)))
        (sha3-update state prefix 0 (length prefix))))
    state))

(defmethod block-length ((state cshake128))
  168)

(defmethod block-length ((state cshake256))
  136)

(defmethod digest-length ((state cshake128))
  (sha3-output-length state))

(defmethod digest-length ((state cshake256))
  (sha3-output-length state))

(defmethod reinitialize-instance ((state cshake128) &rest initargs)
  (declare (ignore initargs))
  (setf (sha3-state state) (make-keccak-state))
  (setf (sha3-buffer-index state) 0)
  (let ((n (cshake-function-name state))
        (s (cshake-customization state)))
    (unless (and (zerop (length n)) (zerop (length s)))
      (let ((prefix (bytepad (concatenate '(simple-array (unsigned-byte 8) (*))
                                          (encode-string n)
                                          (encode-string s))
                             168)))
        (sha3-update state prefix 0 (length prefix)))))
  state)

(defmethod reinitialize-instance ((state cshake256) &rest initargs)
  (declare (ignore initargs))
  (setf (sha3-state state) (make-keccak-state))
  (setf (sha3-buffer-index state) 0)
  (let ((n (cshake-function-name state))
        (s (cshake-customization state)))
    (unless (and (zerop (length n)) (zerop (length s)))
      (let ((prefix (bytepad (concatenate '(simple-array (unsigned-byte 8) (*))
                                          (encode-string n)
                                          (encode-string s))
                             136)))
        (sha3-update state prefix 0 (length prefix)))))
  state)

(defmethod copy-digest ((state cshake128) &optional copy)
  (check-type copy (or null cshake128))
  (let ((copy (or copy (%make-cshake128-digest))))
    (replace (sha3-state copy) (sha3-state state))
    (setf (sha3-bit-rate copy) (sha3-bit-rate state))
    (replace (sha3-buffer copy) (sha3-buffer state))
    (setf (sha3-buffer-index copy) (sha3-buffer-index state))
    (setf (sha3-output-length copy) (sha3-output-length state))
    (setf (cshake-function-name copy) (copy-seq (cshake-function-name state))
          (cshake-customization copy) (copy-seq (cshake-customization state)))
    copy))

(defmethod copy-digest ((state cshake256) &optional copy)
  (check-type copy (or null cshake256))
  (let ((copy (or copy (%make-cshake256-digest))))
    (replace (sha3-state copy) (sha3-state state))
    (setf (sha3-bit-rate copy) (sha3-bit-rate state))
    (replace (sha3-buffer copy) (sha3-buffer state))
    (setf (sha3-buffer-index copy) (sha3-buffer-index state))
    (setf (sha3-output-length copy) (sha3-output-length state))
    (setf (cshake-function-name copy) (copy-seq (cshake-function-name state))
          (cshake-customization copy) (copy-seq (cshake-customization state)))
    copy))

(defmethod produce-digest ((state cshake128) &key digest (digest-start 0))
  (let ((digest-size (digest-length state))
        (state-copy (copy-digest state)))
    (if digest
        (if (> digest-size (- (length digest) digest-start))
            (error 'insufficient-buffer-space
                   :buffer digest
                   :start digest-start
                   :length digest-size)
            (sha3-finalize state-copy digest digest-start))
        (sha3-finalize state-copy
                       (make-array digest-size :element-type '(unsigned-byte 8))
                       0))))

(defmethod produce-digest ((state cshake256) &key digest (digest-start 0))
  (let ((digest-size (digest-length state))
        (state-copy (copy-digest state)))
    (if digest
        (if (> digest-size (- (length digest) digest-start))
            (error 'insufficient-buffer-space
                   :buffer digest
                   :start digest-start
                   :length digest-size)
            (sha3-finalize state-copy digest digest-start))
        (sha3-finalize state-copy
                       (make-array digest-size :element-type '(unsigned-byte 8))
                       0))))

(setf (get 'cshake128 '%digest-length) 32)
(setf (get 'cshake128 '%make-digest) (symbol-function '%make-cshake128-digest))
(setf (get 'cshake256 '%digest-length) 32)
(setf (get 'cshake256 '%make-digest) (symbol-function '%make-cshake256-digest))
