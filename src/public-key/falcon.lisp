;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; falcon.lisp -- Falcon signatures (FIPS 206, Falcon-512/1024)
;;;;
;;;; Direct translation of the falcon.py reference: NTT arithmetic mod
;;;; 12289, SHAKE256 hash-to-point, compression codec, FFT sampling.
;;;; Staged: verify first, then sign, then keygen.

(in-package :crypto)


;;;
;;; Parameters
;;;

(defconstant +falcon-q+ 12289)
(defconstant +falcon-head-len+ 1)
(defconstant +falcon-salt-len+ 40)

(defstruct falcon-params
  kind n logn sigma sigmin sig-bound sig-bytelen vk-bytes)

(defparameter +falcon-512-params+
  (make-falcon-params :kind :falcon-512 :n 512 :logn 9
                      :sigma 165.7366171829776d0
                      :sigmin 1.2778336969128337d0
                      :sig-bound 34034726 :sig-bytelen 666
                      :vk-bytes 897))

(defparameter +falcon-1024-params+
  (make-falcon-params :kind :falcon-1024 :n 1024 :logn 10
                      :sigma 168.38857144654395d0
                      :sigmin 1.298280334344292d0
                      :sig-bound 70265242 :sig-bytelen 1280
                      :vk-bytes 1793))

(defvar *falcon-params* nil)

(defun falcon-params-for-kind (kind)
  (ecase kind
    (:falcon-512 +falcon-512-params+)
    (:falcon-1024 +falcon-1024-params+)))

(declaim (inline falcon-n falcon-q))
(defun falcon-n () (falcon-params-n *falcon-params*))
(defun falcon-q () +falcon-q+)


;;;
;;; Polynomial helpers. Polys are simple-vectors of fixnums (coefficients).
;;;

(defun falcon-ntt-roots (n)
  (ecase n
    (2 +falcon-ntt-roots-2+)
    (4 +falcon-ntt-roots-4+)
    (8 +falcon-ntt-roots-8+)
    (16 +falcon-ntt-roots-16+)
    (32 +falcon-ntt-roots-32+)
    (64 +falcon-ntt-roots-64+)
    (128 +falcon-ntt-roots-128+)
    (256 +falcon-ntt-roots-256+)
    (512 +falcon-ntt-roots-512+)
    (1024 +falcon-ntt-roots-1024+)))

(defconstant +falcon-ntt-i2+ 6145)
(defconstant +falcon-ntt-sqr1+ 1479)

(defun falcon-split (f)
  "Split coefficient poly into even/odd halves."
  (let* ((n (length f))
         (h (ash n -1))
         (f0 (make-array h :element-type 'fixnum))
         (f1 (make-array h :element-type 'fixnum)))
    (dotimes (i h)
      (setf (aref f0 i) (aref f (* 2 i))
            (aref f1 i) (aref f (+ (* 2 i) 1))))
    (values f0 f1)))

(defun falcon-merge (f0 f1)
  "Interleave halves back into one coefficient poly."
  (let* ((h (length f0))
         (f (make-array (* 2 h) :element-type 'fixnum)))
    (dotimes (i h)
      (setf (aref f (* 2 i)) (aref f0 i)
            (aref f (+ (* 2 i) 1)) (aref f1 i)))
    f))

(defun falcon-split-ntt (f-ntt)
  (let* ((n (length f-ntt))
         (h (ash n -1))
         (w (falcon-ntt-roots n))
         (f0 (make-array h :element-type 'fixnum))
         (f1 (make-array h :element-type 'fixnum)))
    (dotimes (i h)
      (setf (aref f0 i) (mod (* +falcon-ntt-i2+
                                (+ (aref f-ntt (* 2 i)) (aref f-ntt (+ (* 2 i) 1))))
                             +falcon-q+)
            (aref f1 i) (mod (* +falcon-ntt-i2+
                                (- (aref f-ntt (* 2 i)) (aref f-ntt (+ (* 2 i) 1)))
                                (aref +falcon-ntt-inv-mod-q+ (aref w (* 2 i))))
                             +falcon-q+)))
    (values f0 f1)))

(defun falcon-merge-ntt (f0-ntt f1-ntt)
  (let* ((h (length f0-ntt))
         (n (* 2 h))
         (w (falcon-ntt-roots n))
         (f (make-array n :element-type 'fixnum)))
    (dotimes (i h)
      (setf (aref f (* 2 i)) (mod (+ (aref f0-ntt i)
                                     (* (aref w (* 2 i)) (aref f1-ntt i)))
                                  +falcon-q+)
            (aref f (+ (* 2 i) 1)) (mod (- (aref f0-ntt i)
                                           (* (aref w (* 2 i)) (aref f1-ntt i)))
                                        +falcon-q+)))
    f))

(defun falcon-ntt (f)
  "Forward NTT: coefficients -> NTT domain."
  (let ((n (length f)))
    (cond ((> n 2)
           (multiple-value-bind (f0 f1) (falcon-split f)
             (falcon-merge-ntt (falcon-ntt f0) (falcon-ntt f1))))
          ((= n 2)
           (let ((r (make-array 2 :element-type 'fixnum)))
             (setf (aref r 0) (mod (+ (aref f 0) (* +falcon-ntt-sqr1+ (aref f 1)))
                                   +falcon-q+)
                   (aref r 1) (mod (- (aref f 0) (* +falcon-ntt-sqr1+ (aref f 1)))
                                   +falcon-q+))
             r)))))

(defun falcon-intt (f-ntt)
  "Inverse NTT: NTT domain -> coefficients."
  (let ((n (length f-ntt)))
    (cond ((> n 2)
           (multiple-value-bind (f0 f1) (falcon-split-ntt f-ntt)
             (falcon-merge (falcon-intt f0) (falcon-intt f1))))
          ((= n 2)
           (let ((r (make-array 2 :element-type 'fixnum)))
             (setf (aref r 0) (mod (* +falcon-ntt-i2+
                                      (+ (aref f-ntt 0) (aref f-ntt 1)))
                                   +falcon-q+)
                   (aref r 1) (mod (* +falcon-ntt-i2+
                                      (aref +falcon-ntt-inv-mod-q+ +falcon-ntt-sqr1+)
                                      (- (aref f-ntt 0) (aref f-ntt 1)))
                                   +falcon-q+))
             r)))))

(defun falcon-mul-ntt (a b)
  (let* ((n (length a))
         (r (make-array n :element-type 'fixnum)))
    (dotimes (i n r)
      (setf (aref r i) (mod (* (aref a i) (aref b i)) +falcon-q+)))))

(defun falcon-mul-zq (f g)
  "Multiply polys mod (x^n+1, q) via NTT."
  (falcon-intt (falcon-mul-ntt (falcon-ntt f) (falcon-ntt g))))

(defun falcon-sub-zq (f g)
  (let* ((n (length f))
         (r (make-array n :element-type 'fixnum)))
    (dotimes (i n r)
      (setf (aref r i) (mod (- (aref f i) (aref g i)) +falcon-q+)))))


;;;
;;; Serialization: 14 bits per coefficient, little-endian bignum buffer.
;;;

(defun falcon-serialize (poly)
  "14-bit LE-group packing written as a big-endian byte string."
  (let ((buf 0))
    (dotimes (i (length poly))
      (setf buf (logior buf (ash (aref poly i) (* 14 i)))))
    (let* ((nbytes (ceiling (* (length poly) 14) 8))
           (out (make-array nbytes :element-type '(unsigned-byte 8)
                                   :initial-element 0)))
      (dotimes (i nbytes out)
        (setf (aref out (- nbytes 1 i)) (ldb (byte 8 (* 8 i)) buf))))))

(defun falcon-deserialize (bytes n)
  "Inverse of falcon-serialize: big-endian bytes, 14-bit LE groups."
  (let ((buf 0)
        (poly (make-array n :element-type 'fixnum :initial-element 0)))
    (dotimes (i (length bytes))
      (setf buf (+ (ash buf 8) (aref bytes i))))
    (dotimes (i n poly)
      (setf (aref poly i) (ldb (byte 14 (* 14 i)) buf)))))


;;;
;;; Hash-to-point: SHAKE256(salt || m), 16-bit BE rejection to mod q.
;;;

(defun falcon-hash-to-point (msg salt n)
  (let* ((k (ash 1 16))
         (kq (* (floor k +falcon-q+) +falcon-q+))
         ;; Squeeze generously; XOF prefix property keeps values identical.
         (need-bytes (* 6 n))
         (d (make-digest :shake256 :output-length need-bytes))
         (out (make-array n :element-type 'fixnum :initial-element 0)))
    (update-digest d salt)
    (update-digest d msg)
    (let ((buf (produce-digest d)))
      (loop with i = 0 and pos = 0
            while (< i n)
            do (let ((elt (+ (ash (aref buf pos) 8) (aref buf (+ pos 1)))))
                 (incf pos 2)
                 (when (< elt kq)
                   (setf (aref out i) (mod elt +falcon-q+))
                   (incf i)))
            finally (return out)))))


;;;
;;; Compression codec (decompress only for verify).
;;;

(defun falcon-decompress (enc slen n)
  "Decode ENC (<= slen bytes) into an n-coefficient poly, or NIL if invalid."
  (when (> (length enc) slen)
    (return-from falcon-decompress nil))
  ;; Build bit string MSB-first per byte.
  (let ((bits (make-array (* 8 (length enc)) :element-type 'bit)))
    (dotimes (i (length enc))
      (dotimes (b 8)
        (setf (aref bits (+ (* i 8) b)) (ldb (byte 1 (- 7 b)) (aref enc i)))))
    ;; Strip trailing zeros; empty remainder means invalid.
    (let ((len (length bits)))
      (loop while (and (plusp len) (zerop (aref bits (1- len))))
            do (decf len))
      (when (zerop len)
        (return-from falcon-decompress nil))
      (let ((v (make-array n :element-type 'fixnum :initial-element 0))
            (nv 0)
            (pos 0))
        (loop while (and (< pos len) (< nv n))
              do (let ((sign (if (= (aref bits pos) 1) -1 1)))
                   (when (> (+ pos 8) len)
                     (return-from falcon-decompress nil))
                   (let ((low 0))
                     (dotimes (b 7)
                       (setf low (+ (* low 2) (aref bits (+ pos 1 b)))))
                     (let ((i (+ pos 8)) (high 0))
                       (loop while (and (< i len) (zerop (aref bits i)))
                             do (incf i) (incf high))
                       (when (>= i len)
                         (return-from falcon-decompress nil))
                       (let ((coef (* sign (+ low (ash high 7)))))
                         (when (and (zerop coef) (minusp sign))
                           (return-from falcon-decompress nil))
                         (setf (aref v nv) coef)
                         (incf nv)
                         (setf pos (+ i 1)))))))
        (if (= nv n) v nil)))))


;;;
;;; Verify
;;;

(defun falcon-verify (msg sig pk &optional (params +falcon-512-params+))
  "Verify SIG over MSG under PK (FIPS 206 wire format); returns T/nil."
  (let ((*falcon-params* params))
    (let* ((n (falcon-n))
           (logn (falcon-params-logn params))
           (sig-bytelen (falcon-params-sig-bytelen params))
           (bound (falcon-params-sig-bound params)))
      (unless (and (= (length pk) (falcon-params-vk-bytes params))
                   (= (aref pk 0) logn))
        (return-from falcon-verify nil))
      (unless (and (= (length sig) sig-bytelen)
                   (= (aref sig 0) (+ #x30 logn)))
        (return-from falcon-verify nil))
      (let* ((h (falcon-deserialize (subseq pk 1) n))
             (salt (subseq sig +falcon-head-len+
                           (+ +falcon-head-len+ +falcon-salt-len+)))
             (enc (subseq sig (+ +falcon-head-len+ +falcon-salt-len+)))
             (s1 (falcon-decompress enc (- sig-bytelen +falcon-head-len+
                                           +falcon-salt-len+) n)))
        (when (null s1)
          (return-from falcon-verify nil))
        (let* ((c (falcon-hash-to-point msg salt n))
               (s0raw (falcon-sub-zq c (falcon-mul-zq s1 h)))
               (half (ash +falcon-q+ -1))
               (norm 0))
          (dotimes (i n)
            (let ((s0i (- (mod (+ (aref s0raw i) half) +falcon-q+) half)))
              (incf norm (* s0i s0i))))
          (dotimes (i n)
            (incf norm (* (aref s1 i) (aref s1 i))))
          (<= norm bound))))))


;;;
;;; Public API (verify first; keygen/sign follow in later steps).
;;;

(defclass falcon-512-public-key ()
  ((bytes :initarg :bytes :reader falcon-key-bytes
          :type (simple-array (unsigned-byte 8) (*))))
  (:documentation "897-byte Falcon-512 public key."))

(defclass falcon-1024-public-key ()
  ((bytes :initarg :bytes :reader falcon-key-bytes
          :type (simple-array (unsigned-byte 8) (*))))
  (:documentation "1793-byte Falcon-1024 public key."))

(defmethod make-public-key ((kind (eql :falcon-512))
                            &key bytes &allow-other-keys)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) 897))
    (error 'missing-key-parameter
           :kind :falcon-512 :parameter 'bytes
           :description "Falcon-512 public key bytes"))
  (make-instance 'falcon-512-public-key :bytes (copy-seq bytes)))

(defmethod make-public-key ((kind (eql :falcon-1024))
                            &key bytes &allow-other-keys)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) 1793))
    (error 'missing-key-parameter
           :kind :falcon-1024 :parameter 'bytes
           :description "Falcon-1024 public key bytes"))
  (make-instance 'falcon-1024-public-key :bytes (copy-seq bytes)))

(defmethod destructure-public-key ((key falcon-512-public-key))
  (list :bytes (copy-seq (falcon-key-bytes key))))

(defmethod destructure-public-key ((key falcon-1024-public-key))
  (list :bytes (copy-seq (falcon-key-bytes key))))

(defmethod verify-signature ((key falcon-512-public-key) message signature
                             &key (start 0) end &allow-other-keys)
  (falcon-verify (subseq message start (or end (length message)))
                 signature (falcon-key-bytes key)
                 +falcon-512-params+))

(defmethod verify-signature ((key falcon-1024-public-key) message signature
                             &key (start 0) end &allow-other-keys)
  (falcon-verify (subseq message start (or end (length message)))
                 signature (falcon-key-bytes key)
                 +falcon-1024-params+))
