;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; kmac.lisp -- KMAC128/256 message authentication (NIST SP 800-185)
;;;;
;;;; (MAKE-MAC :kmac128 key &key customization output-length)
;;;; KEY is any-length octets; CUSTOMIZATION a string or octets;
;;;; OUTPUT-LENGTH the tag size in octets (32 by default).

(in-package :crypto)


(defclass kmac (mac)
  ((digest :accessor kmac-state :initarg :digest)
   (output-length :accessor kmac-output-length :initarg :output-length)
   (customization :accessor kmac-customization :initarg :customization)
   (key :accessor kmac-key :initarg :key)))

(defclass kmac128 (kmac)
  ())

(defclass kmac256 (kmac)
  ())

(defun kmac-rate (kind)
  (ecase kind
    (:kmac128 168)
    (:kmac256 136)))

(defun kmac-cshake-name (kind)
  (ecase kind
    (:kmac128 :cshake128)
    (:kmac256 :cshake256)))

(defun make-kmac (kind key &key (customization "") (output-length 32))
  (check-type key (vector (unsigned-byte 8)))
  (unless (and (integerp output-length) (plusp output-length))
    (error 'invalid-mac-parameter
           :mac-name kind
           :message "The output length must be a positive integer."))
  (make-instance (ecase kind
                   (:kmac128 'kmac128)
                   (:kmac256 'kmac256))
                 :key (coerce-octets key)
                 :customization (coerce-octets customization)
                 :output-length output-length))

(defun make-kmac128 (key &key (customization "") (output-length 32))
  (make-kmac :kmac128 key :customization customization :output-length output-length))

(defun make-kmac256 (key &key (customization "") (output-length 32))
  (make-kmac :kmac256 key :customization customization :output-length output-length))

(defmethod copy-kmac ((mac kmac) &optional copy)
  (declare (type (or null kmac) copy))
  (let ((copy (if copy
                  copy
                  (make-instance (class-of mac)
                                 :digest (make-digest :shake256)
                                 :output-length 32
                                 :customization #()
                                 :key #()))))
    (declare (type kmac copy))
    (setf (kmac-state copy) (copy-digest (kmac-state mac)))
    (setf (kmac-output-length copy) (kmac-output-length mac))
    (setf (kmac-customization copy) (copy-seq (kmac-customization mac)))
    (setf (kmac-key copy) (copy-seq (kmac-key mac)))
    copy))

(defmethod shared-initialize :after ((mac kmac) slot-names
                                     &rest initargs
                                     &key key customization output-length &allow-other-keys)
  (declare (ignore slot-names initargs))
  ;; Build (or rebuild, on REINITIALIZE-INSTANCE) the key-fed state.
  ;; Slots keep their stored values unless overridden by INITARGS.
  (let* ((kind (etypecase mac
                 (kmac128 :kmac128)
                 (kmac256 :kmac256)))
         (rate (kmac-rate kind))
         (key (coerce-octets (or key (kmac-key mac))))
         (custom (if customization
                     (coerce-octets customization)
                     (kmac-customization mac)))
         (outlen (or output-length (kmac-output-length mac)))
         (state (make-digest (kmac-cshake-name kind)
                             :output-length outlen
                             :function-name "KMAC"
                             :customization custom))
         (prefix (bytepad (encode-string key) rate)))
    (check-type key simple-octet-vector)
    (sha3-update state prefix 0 (length prefix))
    (setf (kmac-state mac) state
          (kmac-output-length mac) outlen
          (kmac-customization mac) custom
          (kmac-key mac) key))
  mac)

(defun update-kmac (mac sequence &key (start 0) end)
  (sha3-update (kmac-state mac) sequence start (or end (length sequence)))
  mac)

(defun kmac-digest (mac)
  (let* ((output-length (kmac-output-length mac))
         (mac-copy (copy-kmac mac))
         (state (kmac-state mac-copy))
         (suffix (right-encode (* 8 output-length))))
    (sha3-update state suffix 0 (length suffix))
    (produce-digest state)))

(defmac kmac128
        make-kmac128
        update-kmac
        kmac-digest)

(defmac kmac256
        make-kmac256
        update-kmac
        kmac-digest)
