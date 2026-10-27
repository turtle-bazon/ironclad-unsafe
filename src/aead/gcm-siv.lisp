;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; gcm-siv.lisp -- AES-GCM-SIV nonce misuse-resistant AEAD (RFC 8452)
;;;;
;;;; Single class/mode GCM-SIV: 16-octet keys use AES-128 throughout,
;;;; 32-octet keys use AES-256; the nonce is always 12 octets and the
;;;; tag 16 octets.  Being an SIV construction, encryption needs the
;;;; whole plaintext before emitting anything: ENCRYPT/DECRYPT buffer
;;;; their input and process it when called with HANDLE-FINAL-BLOCK,
;;;; which ENCRYPT-MESSAGE and DECRYPT-MESSAGE always pass.
;;;; PRODUCE-TAG before finalization signals an error.  As required by
;;;; RFC 8452 section 9, decrypt releases plaintext only together with
;;;; a successful tag check.
;;;;
;;;; (make-authenticated-encryption-mode :gcm-siv
;;;;   &key tag key initialization-vector)

(in-package :crypto-unsafe)


(defconst +polyval-red+
  (logior (ash 1 128) (ash 1 127) (ash 1 126) (ash 1 121) 1))

(defconst +polyval-xinv+
  (logior (ash 1 127) (ash 1 124) (ash 1 121) (ash 1 114) 1))

(defun polyval-clmul (a b)
  "Carryless multiplication of 128-bit field elements."
  (declare (type (unsigned-byte 128) a b)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  ;; Iterate over the sparser operand.
  (when (> (logcount a) (logcount b))
    (rotatef a b))
  (loop with result of-type (unsigned-byte 256) = 0
        with aa of-type integer = a
        while (plusp b)
        when (oddp b)
        do (setf result (logxor result aa))
        do (setf aa (ash aa 1)
                 b (ash b -1))
        finally (return result)))

(defun polyval-reduce (r)
  "Reduce R (at most 255 bits) modulo x^128+x^127+x^126+x^121+1."
  (declare (type integer r)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (loop for length of-type fixnum = (integer-length r) then (integer-length r)
        while (> length 128)
        do (setf r (logxor r (ash +polyval-red+ (- length 129)))))
  r)

(defun polyval-mul (a b)
  "GF(2^128) product (plain multiplication, no Montgomery factor)."
  (declare (type (unsigned-byte 128) a b))
  (polyval-reduce (polyval-clmul a b)))

(defun polyval-dot (a b)
  "GF(2^128) product scaled by x^-128, the POLYVAL step.
Portable form: a bignum carryless multiply and a term-by-term reduction."
  (declare (type (unsigned-byte 128) a b))
  (let ((tprod (polyval-clmul a b)))
    (logxor (ash tprod -128)
            (polyval-mul (logand tprod #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
                         +polyval-xinv+))))

(defvar *polyval-ghash-p*
  #+(and sbcl x86-64 ironclad-unsafe-assembly) (pclmulqdq-supported-p)
  #-(and sbcl x86-64 ironclad-unsafe-assembly) nil
  "True when POLYVAL can ride on the GHASH block multiply.

POLYVAL's field is GHASH's field with the coefficients reflected, so a
byte swap turns one into the other, and the x^-128 factor of POLYVAL's
dot product folds into the key.  Concretely, with the accumulator and
key in byte-reversed order, POLYVAL is exactly the GHASH recurrence

    S <- (S xor block) * (H * x^-1)

so the tuned GMAC multiply does the work and the per-block cost is one
XOR plus one carryless multiply, with no bignum arithmetic at all.  This
is the same reduction BoringSSL uses (mulX of the key).")

(defun polyval-key-block (key)
  "The GHASH-domain key block for POLYVAL key KEY: H*x^-1 mod p,
little-endian.  DOT(H, x^127) is H*x^127*x^-128 = H*x^-1."
  (declare (type (simple-array (unsigned-byte 8) (16)) key)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((h (octets-to-integer key :big-endian nil)))
    (integer-to-octets (polyval-dot h (ash 1 127))
                       :n-bits 128 :big-endian nil)))

(defun polyval-octets-ghash (key data start end)
  (declare (type (simple-array (unsigned-byte 8) (*)) key data)
           (type fixnum start end)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((acc (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (k1 (polyval-key-block key))
        (pos start))
    (declare (type (simple-array (unsigned-byte 8) (16)) acc k1)
             (type fixnum pos))
    (loop while (< pos end)
          do (xor-block 16 acc 0 data pos acc 0)
             (gmac-mul acc k1)
             (incf pos 16))
    acc))

(defun polyval-octets (key data start end)
  "POLYVAL over DATA[START..END), which must be a multiple of 16 octets.
Operates on the buffer in place: the list of per-block copies that the
block interface builds is what made the old code allocate 512 arrays for
an 8KB message."
  (declare (type (simple-array (unsigned-byte 8) (*)) key data)
           (type fixnum start end)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (if *polyval-ghash-p*
      (polyval-octets-ghash key data start end)
      (let ((h (octets-to-integer key :big-endian nil))
            (s 0)
            (pos start))
        (declare (type (unsigned-byte 128) h s)
                 (type fixnum pos))
        (loop while (< pos end)
              do (setf s (polyval-dot
                          (logxor s (logior (ub64ref/le data pos)
                                            (ash (ub64ref/le data (+ pos 8)) 64)))
                          h))
                 (incf pos 16))
        (integer-to-octets s :n-bits 128 :big-endian nil))))

(defun polyval (key blocks)
  "POLYVAL over the 16-octet BLOCKS with 16-octet KEY; 16-octet digest.
KEY and BLOCKS use the RFC 8452 little-endian bit convention, which is
the plain integer value of the little-endian octets."
  (declare (type (simple-array (unsigned-byte 8) (16)) key))
  (let ((h (octets-to-integer key :big-endian nil))
        (s 0))
    (declare (type (unsigned-byte 128) h s))
    (dolist (block blocks s)
      (setf s (polyval-dot (logxor s (octets-to-integer block :big-endian nil)) h)))
    (integer-to-octets s :n-bits 128 :big-endian nil)))


(defclass gcm-siv (aead-mode)
  ((key :accessor gcm-siv-key
        :initform nil)
   (nonce :accessor gcm-siv-nonce
          :initform nil)
   (plaintext-buffer :accessor gcm-siv-pt
                     :initform nil)
   (ciphertext-buffer :accessor gcm-siv-ct
                      :initform nil)
   (associated-data :accessor gcm-siv-ad
                    :initform nil)
   (associated-data-length :accessor gcm-siv-ad-length
                           :initform 0
                           :type (integer 0 *))
   (output-base :accessor gcm-siv-output-base
                :initform nil)
   (finalized-p :accessor gcm-siv-finalized-p
                :initform nil
                :type boolean)
   (computed-tag :accessor gcm-siv-computed-tag
                 :initform nil)))

(defun gcm-siv-buffer ()
  (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))

(defun gcm-siv-check-init (key nonce)
  (unless (member (length key) '(16 32))
    (error 'invalid-key-length :cipher 'gcm-siv :accepted-lengths '(16 32)))
  (unless (= (length nonce) 12)
    (error 'invalid-initialization-vector :cipher 'gcm-siv :block-length 12))
  (values))

(defmethod shared-initialize :after ((mode gcm-siv) slot-names &rest initargs &key key initialization-vector &allow-other-keys)
  (declare (ignore slot-names initargs))
  (gcm-siv-check-init key initialization-vector)
  (setf (gcm-siv-key mode) (copy-seq key)
        (gcm-siv-nonce mode) (copy-seq initialization-vector)
        (gcm-siv-pt mode) (gcm-siv-buffer)
        (gcm-siv-ct mode) (gcm-siv-buffer)
        (gcm-siv-ad mode) (gcm-siv-buffer)
        (gcm-siv-ad-length mode) 0
        (gcm-siv-output-base mode) nil
        (gcm-siv-finalized-p mode) nil
        (gcm-siv-computed-tag mode) nil)
  mode)

(defun gcm-siv-pad16 (buffer)
  "Fresh copy of BUFFER zero-padded up to a 16-octet boundary."
  (let* ((length (length buffer))
         (padded (+ length (mod (- 16 (mod length 16)) 16)))
         (out (make-array padded :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace out buffer)
    out))

(defun gcm-siv-derive-keys (key nonce)
  "Per-message (authentication-key, encryption-key) octet vectors."
  (declare (type simple-octet-vector key nonce))
  (let* ((aes (make-cipher :aes :key key :mode :ecb))
         (nblocks (if (= (length key) 32) 6 4))
         (material (make-array (* 8 nblocks) :element-type '(unsigned-byte 8)))
         (counter (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (out (make-array 16 :element-type '(unsigned-byte 8))))
    (replace counter nonce :start1 4)
    (dotimes (i nblocks)
      (setf (ub32ref/le counter 0) i)
      (encrypt aes counter out)
      (replace material out :start1 (* 8 i) :end1 (+ (* 8 i) 8) :end2 8))
    (values (subseq material 0 16)
            (subseq material 16))))

(defun gcm-siv-length-block (ad-length data-length)
  (let ((block (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (ub64ref/le block 0) (* 8 ad-length)
          (ub64ref/le block 8) (* 8 data-length))
    block))

(defun gcm-siv-blocks (buffer)
  "BUFFER (multiple of 16 octets) as a list of 16-octet chunks."
  (loop for start from 0 below (length buffer) by 16
        collect (subseq buffer start (+ start 16))))

(defun gcm-siv-authenticate (auth-key nonce ad data)
  "POLYVAL tag input processing through the masked encryption."
  ;; AD and DATA arrive as adjustable fill-pointer buffers, not simple
  ;; arrays.
  (declare (type (simple-array (unsigned-byte 8) (*)) auth-key nonce)
           (type (array (unsigned-byte 8) (*)) ad data)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let* ((ad-length (length ad))
         (data-length (length data))
         (pad-ad (* 16 (ceiling ad-length 16)))
         (pad-data (* 16 (ceiling data-length 16)))
         (buf (make-array (+ pad-ad pad-data 16)
                          :element-type '(unsigned-byte 8) :initial-element 0))
         (lb (gcm-siv-length-block ad-length data-length)))
    (replace buf ad)
    (replace buf data :start1 pad-ad)
    (replace buf lb :start1 (+ pad-ad pad-data))
    (let ((s (polyval-octets auth-key buf 0 (length buf))))
      (dotimes (i 12 s)
        (setf (aref s i) (logxor (aref s i) (aref nonce i))))
      (setf (aref s 15) (logand (aref s 15) #x7f))
      s)))

(defun gcm-siv-ecb (key block)
  (let ((cipher (make-cipher :aes :key key :mode :ecb))
        (out (make-array 16 :element-type '(unsigned-byte 8))))
    (encrypt cipher block out)
    out))

(defun gcm-siv-ctr (enc-key iv data)
  "AES-CTR with a little-endian 32-bit counter in the first word.
Eight counter blocks are encrypted per call so the AES-ECB fast path can
pipeline eight independent blocks; one call per block left every AESENC
latency exposed, and rebuilding the cipher per block (the original form)
made the key schedule the cost of the whole loop."
  (declare (type (simple-array (unsigned-byte 8) (*)) enc-key iv)
           (type (array (unsigned-byte 8) (*)) data)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let* ((length (length data))
         (out (make-array length :element-type '(unsigned-byte 8)))
         (aes (make-cipher :aes :key enc-key :mode :ecb))
         (inbuf (make-array 128 :element-type '(unsigned-byte 8)))
         (ks (make-array 128 :element-type '(unsigned-byte 8)))
         (base (ub32ref/le iv 0)))
    (declare (type fixnum length)
             (type (unsigned-byte 32) base))
    (loop for pos from 0 below length by 128
          do (let ((n (min 128 (- length pos))))
               (declare (type fixnum n))
               (dotimes (j 8)
                 (replace inbuf iv :start1 (* 16 j) :start2 0 :end2 16)
                 (setf (ub32ref/le inbuf (* 16 j))
                       (logand (+ base j) #xFFFFFFFF)))
               (encrypt aes inbuf ks)
               (dotimes (i n)
                 (setf (aref out (+ pos i))
                       (logxor (aref data (+ pos i)) (aref ks i))))
               (setf base (logand (+ base 8) #xFFFFFFFF))))
    out))

(defun gcm-siv-run-encrypt (mode)
  "Full two-pass encryption over the buffered plaintext.
Returns (VALUES ciphertext tag); pure computation, no state change."
  (let* ((key (gcm-siv-key mode))
         (nonce (gcm-siv-nonce mode))
         (ad (gcm-siv-ad mode))
         (pt (gcm-siv-pt mode)))
    (when (or (> (length pt) (expt 2 36)) (> (length ad) (expt 2 36)))
      (error 'ironclad-unsafe-error
             :format-control "GCM-SIV message or associated data exceeds 2^36 octets."))
    (multiple-value-bind (auth-key enc-key) (gcm-siv-derive-keys key nonce)
      (let* ((pre-tag (gcm-siv-authenticate auth-key nonce ad pt))
             (tag (gcm-siv-ecb enc-key pre-tag))
             (iv (copy-seq tag)))
        (setf (aref iv 15) (logior (aref iv 15) #x80))
        (values (gcm-siv-ctr enc-key iv pt) tag)))))

(defun gcm-siv-run-decrypt (mode)
  "Counter-mode decryption over the buffered ciphertext (unauthenticated)."
  (let* ((key (gcm-siv-key mode))
         (nonce (gcm-siv-nonce mode))
         (ct (gcm-siv-ct mode))
         (tag (or (tag mode)
                  (error 'ironclad-unsafe-error
                         :format-control "GCM-SIV decryption needs the tag up front for its counter mode."))))
    (multiple-value-bind (auth-key enc-key) (gcm-siv-derive-keys key nonce)
      (declare (ignore auth-key))
      (let ((iv (copy-seq tag)))
        (setf (aref iv 15) (logior (aref iv 15) #x80))
        (gcm-siv-ctr enc-key iv ct)))))

(defun gcm-siv-expected-tag (mode plaintext)
  "Recompute the tag over PLAINTEXT for verification."
  (let* ((key (gcm-siv-key mode))
         (nonce (gcm-siv-nonce mode))
         (ad (gcm-siv-ad mode)))
    (multiple-value-bind (auth-key enc-key) (gcm-siv-derive-keys key nonce)
      (let* ((pre-tag (gcm-siv-authenticate auth-key nonce ad plaintext)))
        (gcm-siv-ecb enc-key pre-tag)))))

(defun gcm-siv-finalize-encrypt (mode output output-start)
  (multiple-value-bind (ciphertext tag) (gcm-siv-run-encrypt mode)
    (replace output ciphertext :start1 output-start)
    (setf (gcm-siv-computed-tag mode) tag
          (gcm-siv-finalized-p mode) t))
  (values (length (gcm-siv-pt mode)) (length (gcm-siv-pt mode))))

(defun gcm-siv-finalize-decrypt (mode output output-start)
  (let ((plaintext (gcm-siv-run-decrypt mode)))
    (replace output plaintext :start1 output-start)
    (let ((expected (gcm-siv-expected-tag mode plaintext)))
      (setf (gcm-siv-computed-tag mode) expected
            (gcm-siv-finalized-p mode) t)
      (let ((correct-tag (tag mode)))
        (when (and correct-tag (not (constant-time-equal expected correct-tag)))
          (error 'bad-authentication-tag))))
    (values (length (gcm-siv-ct mode)) (length (gcm-siv-ct mode)))))

(defun gcm-siv-note-output-base (mode start)
  (unless (gcm-siv-output-base mode)
    (setf (gcm-siv-output-base mode) start))
  (gcm-siv-output-base mode))

(defun gcm-siv-append (buffer data start end)
  "Append DATA[START..END) to BUFFER, an adjustable fill-pointer vector.
Returns the buffer, which ADJUST-ARRAY may have replaced.  Copying one
byte at a time through VECTOR-PUSH-EXTEND made the mode's own buffering
the largest single cost of an 8KB message."
  (declare (type (array (unsigned-byte 8) (*)) buffer data)
           (type fixnum start end)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let* ((old (fill-pointer buffer))
         (new (+ old (- end start))))
    (declare (type fixnum old new))
    (when (> new (array-dimension buffer 0))
      (setf buffer (adjust-array buffer (max new (* 2 (array-dimension buffer 0))))))
    ;; The fill pointer must move first: sequence functions only see the
    ;; active, fill-pointer-length part of the vector, so REPLACE with the
    ;; old fill pointer copies nothing.
    (setf (fill-pointer buffer) new)
    (replace buffer data :start1 old :start2 start :end2 end)
    buffer))

(defmethod process-associated-data ((mode gcm-siv) data &key (start 0) end)
  (if (encryption-started-p mode)
      (error 'ironclad-unsafe-error :format-control "All associated data must be processed before the encryption begins.")
      (let* ((end (or end (length data)))
             (buffer (gcm-siv-ad mode)))
        (incf (gcm-siv-ad-length mode) (- end start))
        (setf (gcm-siv-ad mode) (gcm-siv-append buffer data start end))))
  (values))

(defmethod produce-tag ((mode gcm-siv) &key tag (tag-start 0))
  ;; Like GCM, intermediate tags over buffered-so-far plaintext are
  ;; allowed (this also covers empty messages, which never see a final
  ;; ENCRYPT call); decryption must still go through a final DECRYPT.
  (let ((mac-digest (if (gcm-siv-finalized-p mode)
                        (gcm-siv-computed-tag mode)
                        (if (plusp (length (gcm-siv-ct mode)))
                            (error 'ironclad-unsafe-error
                                   :format-control "GCM-SIV decryption must be finalized with HANDLE-FINAL-BLOCK before producing a tag.")
                            (nth-value 1 (gcm-siv-run-encrypt mode))))))
    (etypecase tag
      (simple-octet-vector
       (if (<= (length mac-digest) (- (length tag) tag-start))
           (progn (replace tag mac-digest :start1 tag-start) tag)
           (error 'insufficient-buffer-space
                  :buffer tag
                  :start tag-start
                  :length (length mac-digest))))
      (null
       (copy-seq mac-digest)))))

(defmethod encrypt ((mode gcm-siv) plaintext ciphertext &key (plaintext-start 0) plaintext-end (ciphertext-start 0) handle-final-block)
  (let ((plaintext-end (or plaintext-end (length plaintext))))
    (when (gcm-siv-finalized-p mode)
      (error 'ironclad-unsafe-error
             :format-control "GCM-SIV message already finalized; start a new mode for more data."))
    (unless (encryption-started-p mode)
      (setf (encryption-started-p mode) t))
    (let ((buffer (gcm-siv-pt mode))
          (base (gcm-siv-note-output-base mode ciphertext-start))
          (length (- plaintext-end plaintext-start)))
      (setf (gcm-siv-pt mode)
            (gcm-siv-append buffer plaintext plaintext-start plaintext-end))
      (if handle-final-block
          (gcm-siv-finalize-encrypt mode ciphertext base)
          (values length 0)))))

(defmethod decrypt ((mode gcm-siv) ciphertext plaintext &key (ciphertext-start 0) ciphertext-end (plaintext-start 0) handle-final-block)
  (let ((ciphertext-end (or ciphertext-end (length ciphertext))))
    (when (gcm-siv-finalized-p mode)
      (error 'ironclad-unsafe-error
             :format-control "GCM-SIV message already finalized; start a new mode for more data."))
    (unless (encryption-started-p mode)
      (setf (encryption-started-p mode) t))
    (let ((buffer (gcm-siv-ct mode))
          (length (- ciphertext-end ciphertext-start)))
      (gcm-siv-note-output-base mode plaintext-start)
      (setf (gcm-siv-ct mode)
            (gcm-siv-append buffer ciphertext ciphertext-start ciphertext-end))
      (if handle-final-block
          (gcm-siv-finalize-decrypt mode plaintext (gcm-siv-output-base mode))
          (values length 0)))))

(defmethod encrypt-message ((mode gcm-siv) message &key (start 0) end associated-data (associated-data-start 0) associated-data-end &allow-other-keys)
  (let* ((length (- (or end (length message)) start))
         (encrypted-message (make-array length :element-type '(unsigned-byte 8))))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start :end associated-data-end))
    (encrypt mode message encrypted-message
             :plaintext-start start :plaintext-end end
             :handle-final-block t)
    encrypted-message))

(defmethod decrypt-message ((mode gcm-siv) message &key (start 0) end associated-data (associated-data-start 0) associated-data-end &allow-other-keys)
  (let* ((length (- (or end (length message)) start))
         (decrypted-message (make-array length :element-type '(unsigned-byte 8))))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start :end associated-data-end))
    (decrypt mode message decrypted-message
             :plaintext-start start :plaintext-end end
             :handle-final-block t)
    decrypted-message))

(defaead gcm-siv)
