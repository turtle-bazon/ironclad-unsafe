;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;; benchmark-all.lisp -- benchmark all Ironclad algorithms.
;;;
;;; Usage (from the repository root):
;;;
;;;   sbcl --load ~/quicklisp/setup.lisp --script benchmark/benchmark-all.lisp
;;;
;;; Two details are easy to get wrong.  Quicklisp must be loaded first,
;;; because Ironclad depends on bordeaux-threads and a bare `--script` run
;;; cannot take `--eval` arguments ahead of the script.  And the script must
;;; be given with `--script`: passing the filename as a bare argument
;;; followed by `--quit` silently loads nothing at all and exits 0, which
;;; looks like a successful run.
;;;
;;; An optional trailing argument selects a subset of the benchmark groups,
;;; e.g. `digests public-key`.  Note that a subset run still writes to the
;;; same output files, so it replaces the full table with a partial one.
;;; Re-run without arguments to regenerate a complete set.
;;;
;;; IRONCLAD_BENCH_TRIALS sets the number of timing samples per operation
;;; (default 5; use 1 for a quick pass at the old runtime).
;;;
;;; Output:
;;;   benchmark/all-algorithms.sexp  raw alist results
;;;   benchmark/all-algorithms.org   detailed table
;;;
;;; C references:
;;;   * OpenSSL `speed` when available.
;;;   * Local C benchmarks under benchmark/c-bin/ when built.

(require 'asdf)
(push (truename #p"./") asdf:*central-registry*)
(asdf:load-system :ironclad)

(defpackage :bench-all
  (:use :cl))
(in-package :bench-all)

(defparameter *raw-output* #P"benchmark/all-algorithms.sexp")
(defparameter *table-output* #P"benchmark/all-algorithms.org")
(defparameter *size* 8192)
(defparameter *min-seconds* 0.20d0)
(defparameter *max-seconds* 3.0d0)
(defparameter *max-count* 1000000)
(defparameter *trials*
  (let ((setting (uiop:getenv "IRONCLAD_BENCH_TRIALS")))
    (if (and setting (plusp (length setting)))
        (or (ignore-errors (parse-integer setting)) 5)
        5))
  "Independent timing samples per operation.  Set IRONCLAD_BENCH_TRIALS=1
for a quick run at the old speed; each extra trial costs up to
*MAX-SECONDS*.")

;;; ------------------------------------------------------------------
;;; Time utilities

(defun now ()
  (/ (get-internal-real-time)
     (coerce internal-time-units-per-second 'double-float)))

(defun time-op (thunk)
  (let ((start (now))
        (count 0))
    (loop
      (funcall thunk)
      (incf count)
      (let ((elapsed (- (now) start)))
        (when (or (>= elapsed *min-seconds*)
                  (>= elapsed *max-seconds*)
                  (>= count *max-count*))
          (return (values count elapsed)))))))

(defun items-per-second (thunk)
  (let ((best 0.0d0))
    (dotimes (_ (max 1 *trials*))
      (multiple-value-bind (count elapsed) (time-op thunk)
        (when (plusp elapsed)
          (setf best (max best (/ (coerce count 'double-float) elapsed))))))
    best))

(defun bytes-per-second (thunk)
  (multiple-value-bind (count elapsed) (time-op thunk)
    (if (zerop elapsed)
        0.0d0
        (/ (* count *size*) elapsed))))

(defun random-octets (n)
  (ironclad:random-data n))

;;; ------------------------------------------------------------------
;;; Result records

(defparameter *results* '())

(defun record (category algorithm source operation unit value)
  (push (list :category category
              :algorithm algorithm
              :source source
              :operation operation
              :unit unit
              :value (coerce value 'double-float))
        *results*))

(defun record-lisp (category algorithm operation unit value)
  (record category algorithm "ironclad" operation unit value))

(defun stringify (x)
  (string-downcase (princ-to-string x)))

(defun report-benchmark-error (category algorithm condition)
  "Record a benchmark that signalled instead of producing a number.

Every benchmark wraps its body in a handler, so that one algorithm
failing cannot abort the run.  The handler must not simply return nil,
though: a silently dropped row is indistinguishable from one that was
never requested, and that is how mceliece348864 lost its encapsulate and
decapsulate rows -- its keygen row was still there, so nothing looked
wrong.

BENCHMARK-PUBLIC-KEY deliberately tries the KEM, signature, DH and
encryption operations on every kind, since key kinds do not advertise
which of the four they support.  On a KEM the signing operations simply
have no applicable method, which is expected and not a result; those are
dropped.  Anything else is a genuine failure and is reported."
  (unless (string= (symbol-name (class-name (class-of condition)))
                   "NO-APPLICABLE-METHOD-ERROR")
    (format *error-output* "~&benchmark error: ~a ~a: ~a~%"
            category algorithm condition)
    (finish-output *error-output*)
    (record-lisp category (stringify algorithm) "benchmark-error" "status" 0.0d0)))

;;; ------------------------------------------------------------------
;;; Symmetric primitives

(defun benchmark-cipher (name)
  (let* ((key-length (car (last (ironclad:key-lengths name))))
         (key (random-octets key-length))
         (block-length (ironclad:block-length name))
         (mode (if (= block-length 1) :stream :ecb))
         (cipher (ironclad:make-cipher name :key key :mode mode))
         (buffer (random-octets *size*))
         (rate (bytes-per-second
                 (lambda () (ironclad:encrypt-in-place cipher buffer)))))
    (record-lisp "cipher" (stringify name)
                 (format nil "encrypt ~D-byte buffer" *size*)
                 "bytes/s" rate)))

(defun benchmark-mode (mode)
  (let* ((cipher-name :aes)
         (key-length (car (last (ironclad:key-lengths cipher-name))))
         (key (random-octets key-length))
         (iv (random-octets (ironclad:block-length cipher-name)))
         (cipher (ironclad:make-cipher cipher-name :key key :mode mode
                                       :initialization-vector iv))
         (buffer (random-octets *size*))
         (rate (bytes-per-second
                 (lambda () (ironclad:encrypt-in-place cipher buffer)))))
    (record-lisp "cipher-mode" (stringify mode)
                 (format nil "AES encrypt ~D-byte buffer" *size*)
                 "bytes/s" rate)))

(defun benchmark-digest (name)
  (let* ((digest (ironclad:make-digest name))
         (buffer (random-octets *size*))
         (rate (bytes-per-second
                 (lambda () (ironclad:update-digest digest buffer)))))
    (record-lisp "digest" (stringify name)
                 (format nil "hash ~D-byte block" *size*)
                 "bytes/s" rate)))

(defun mac-default-key (name)
  (random-octets
   (ecase name
     (:blake2-mac 64)
     (:blake2s-mac 32)
     (:cmac 32)
     (:gmac 32)
     (:hmac 32)
     (:kmac128 32)
     (:kmac256 64)
     (:poly1305 32)
     (:siphash 16)
     (:skein-mac 64))))

(defun benchmark-mac (name)
  (let* ((key (mac-default-key name))
         (iv (random-octets 16))
         (mac (case name
                (:cmac (ironclad:make-mac name key :aes))
                (:gmac (ironclad:make-mac name key :aes iv))
                (:hmac (ironclad:make-mac name key :sha256))
                (otherwise (ironclad:make-mac name key))))
         (buffer (random-octets *size*))
         (rate (bytes-per-second
                 (lambda () (ironclad:update-mac mac buffer)))))
    (record-lisp "mac" (stringify name)
                 (format nil "MAC ~D-byte block" *size*)
                 "bytes/s" rate)))

(defun aead-initargs (name)
  (let ((key (random-octets 32))
        (iv (random-octets 12)))
    (ecase name
      (:gcm (list :cipher-name :aes :key key :initialization-vector iv))
      (:gcm-siv (list :key key :initialization-vector iv))
      (:ccm (list :key key :initialization-vector iv
                  :tag-length 16 :message-length *size*))
      (:chacha-poly (list :key key :initialization-vector iv))
      (:xchacha-poly (list :key key :initialization-vector (random-octets 24)))
      (:etm (list :cipher (ironclad:make-cipher :aes :key key :mode :ctr
                                                :initialization-vector
                                                (random-octets 16))
                  :mac (ironclad:make-mac :cmac key :aes)))
      (:eax (list :cipher-name :aes :key key :initialization-vector iv)))))

(defun benchmark-aead (name)
  (handler-case
      (let* ((args (aead-initargs name))
             (message (random-octets *size*)))
        (let ((rate (bytes-per-second
                      (lambda ()
                        (let ((mode (apply #'ironclad:make-authenticated-encryption-mode
                                           name args)))
                          (ironclad:encrypt-message mode message))))))
          (record-lisp "aead" (stringify name)
                       (format nil "encrypt ~D-byte message" *size*)
                       "bytes/s" rate)))
    (error (condition)
      (report-benchmark-error "aead" name condition))))

;;; ------------------------------------------------------------------
;;; KDFs and PRNGs

(defun kdf-arguments (kind)
  (ecase kind
    ((:argon2i :argon2d :argon2id) (list :block-count 8))
    ((:bcrypt :bcrypt-pbkdf) (list))
    ((:scrypt-kdf) (list :n 1024 :r 8 :p 1))
    ((:pbkdf1) (list :digest :sha1))
    ((:pbkdf2) (list :digest :sha256))
    ((:hkdf :hmac-kdf) (list :digest :sha256))))

(defun kdf-derive-args (kind)
  (let ((passphrase (random-octets 16))
        (salt (random-octets 16)))
    (list passphrase salt
          (case kind
            ((:bcrypt :bcrypt-pbkdf) 16)
            ((:pbkdf1 :pbkdf2) 1000)
            (otherwise 1))
          (if (eq kind :bcrypt) 24 32))))

(defun benchmark-kdf (kind)
  (handler-case
      (let* ((kdf (apply #'ironclad:make-kdf kind (kdf-arguments kind)))
             (args (kdf-derive-args kind))
             (rate (items-per-second
                     (lambda () (apply #'ironclad:derive-key kdf args)))))
        (record-lisp "kdf" (stringify kind) "derive-key" "ops/s" rate))
    (error (condition)
      (report-benchmark-error "kdf" kind condition))))

(defun benchmark-prng (name)
  (handler-case
      (let* ((prng (if (eq name :os)
                       (ironclad:make-prng name)
                       (ironclad:make-prng name :seed :urandom)))
             (buffer-size 4096)
             (rate (bytes-per-second
                     (lambda ()
                       (ironclad:random-data buffer-size prng)))))
        (record-lisp "prng" (stringify name)
                     (format nil "generate ~D bytes" buffer-size)
                     "bytes/s" rate))
    (error (condition)
      (report-benchmark-error "prng" name condition))))

;;; ------------------------------------------------------------------
;;; Public-key algorithms

(defparameter *num-bits-alist*
  '((:rsa . 2048)
    (:dsa . 2048)
    (:elgamal . 2048)))

(defparameter *alias-to-canonical*
  '((:ecdsa . :secp256r1)
    (:p-224 . :secp224r1)
    (:p-256 . :secp256r1)
    (:prime256v1 . :secp256r1)
    (:p-384 . :secp384r1)
    (:p-521 . :secp521r1)
    (:xmss-sha256-h10 . :xmss-sha2-10-256)))

(defun canonical-kind (kind)
  (or (cdr (assoc kind *alias-to-canonical*)) kind))

(defun generate-key-pair-for (kind)
  (let ((num-bits (cdr (assoc kind *num-bits-alist*))))
    (if num-bits
        (ironclad:generate-key-pair kind :num-bits num-bits)
        (ironclad:generate-key-pair kind))))

(defun benchmark-keypair-gen (kind)
  (let ((rate (items-per-second
                (lambda () (generate-key-pair-for kind)))))
    (record-lisp "public-key" (stringify kind) "keygen" "ops/s" rate)))

(defun benchmark-signature-op (kind priv pub)
  (handler-case
      (let ((message (random-octets 32)))
        (let ((signature (ironclad:sign-message priv message)))
          (unless (ironclad:verify-signature pub message signature)
            (error "signature roundtrip failed"))
          (let ((sign-rate (items-per-second
                             (lambda () (ironclad:sign-message priv message))))
                (verify-rate (items-per-second
                               (lambda ()
                                 (ironclad:verify-signature pub message signature)))))
            (record-lisp "public-key" (stringify kind) "sign" "ops/s" sign-rate)
            (record-lisp "public-key" (stringify kind) "verify" "ops/s" verify-rate))))
    (error (condition)
      (report-benchmark-error "public-key" kind condition))))

(defun benchmark-kem-op (kind priv pub)
  (handler-case
      (multiple-value-bind (ciphertext secret) (ironclad:encapsulate-key pub)
        (let ((secret2 (ironclad:decapsulate-key priv ciphertext)))
          (unless (equalp secret secret2)
            (error "KEM roundtrip failed"))
          (let ((encap-rate (items-per-second
                              (lambda ()
                                (multiple-value-bind (ct ss)
                                    (ironclad:encapsulate-key pub)
                                  (declare (ignore ct ss))))))
                (decap-rate (items-per-second
                              (lambda ()
                                (ironclad:decapsulate-key priv ciphertext)))))
            (record-lisp "public-key" (stringify kind) "encapsulate" "ops/s" encap-rate)
            (record-lisp "public-key" (stringify kind) "decapsulate" "ops/s" decap-rate))))
    (error (condition)
      (report-benchmark-error "public-key" kind condition))))

(defun benchmark-dh-op (kind priv pub)
  (handler-case
      (multiple-value-bind (priv2 pub2) (generate-key-pair-for kind)
        (let ((shared1 (ironclad:diffie-hellman priv pub2))
              (shared2 (ironclad:diffie-hellman priv2 pub)))
          (unless (equalp shared1 shared2)
            (error "Diffie-Hellman roundtrip failed"))
          (let ((rate (items-per-second
                        (lambda () (ironclad:diffie-hellman priv pub2)))))
            (record-lisp "public-key" (stringify kind) "diffie-hellman" "ops/s" rate))))
    (error (condition)
      (report-benchmark-error "public-key" kind condition))))

(defun benchmark-encryption-op (kind priv pub)
  (handler-case
      (let ((message (random-octets 16)))
        ;; RSA and ElGamal do not pad the message unless the OAEP
        ;; scheme is requested (see the README), so their roundtrip
        ;; only works with padding.  The other kinds use ECIES, which
        ;; always pads.
        (let ((oaep (and (member kind '(:rsa :elgamal)) t)))
          (let ((ciphertext (if oaep
                                (ironclad:encrypt-message pub message :oaep oaep)
                                (ironclad:encrypt-message pub message))))
            (let ((plaintext (if oaep
                                  (ironclad:decrypt-message priv ciphertext :oaep oaep)
                                  (ironclad:decrypt-message priv ciphertext))))
              (unless (equalp plaintext message)
                (error "encryption roundtrip failed"))
              (let ((encrypt-rate (items-per-second
                                    (lambda ()
                                      (if oaep
                                          (ironclad:encrypt-message pub message :oaep oaep)
                                          (ironclad:encrypt-message pub message)))))
                    (decrypt-rate (items-per-second
                                   (lambda ()
                                     (if oaep
                                         (ironclad:decrypt-message priv ciphertext :oaep oaep)
                                         (ironclad:decrypt-message priv ciphertext))))))
                (record-lisp "public-key" (stringify kind) "encrypt" "ops/s" encrypt-rate)
                (record-lisp "public-key" (stringify kind) "decrypt" "ops/s" decrypt-rate))))))
    (error (condition)
      (report-benchmark-error "public-key" kind condition))))

(defun benchmark-public-key (kind)
  (multiple-value-bind (priv pub) (generate-key-pair-for kind)
    (benchmark-keypair-gen kind)
    (benchmark-kem-op kind priv pub)
    (benchmark-signature-op kind priv pub)
    (benchmark-dh-op kind priv pub)
    (benchmark-encryption-op kind priv pub)))

;;; ------------------------------------------------------------------
;;; HPKE

(defun benchmark-hpke ()
  (dolist (kem '(:dhkem-x25519 :dhkem-x448 :dhkem-p256 :dhkem-p384 :dhkem-p521))
    (handler-case
        (multiple-value-bind (sk-r pk-r)
            (ironclad:hpke-derive-keypair kem (ironclad:random-data 32))
          (let ((ikm (ironclad:random-data 32))
                (info (ironclad:random-data 16))
                (message (random-octets 64))
                (aad (random-octets 8)))
            (let ((keypair-rate (items-per-second
                                  (lambda ()
                                    (multiple-value-bind (sk pk)
                                        (ironclad:hpke-derive-keypair kem ikm)
                                      (declare (ignore sk pk))))))
                  (sender-setup-rate (items-per-second
                                      (lambda ()
                                        (multiple-value-bind (enc sender)
                                            (ironclad:hpke-setup-sender
                                              kem :hkdf-sha256 :aes-128-gcm pk-r info)
                                          (declare (ignore enc sender))))))
                  (recipient-setup-rate (items-per-second
                                          (lambda ()
                                            (let ((enc (nth-value 0
                                                            (ironclad:hpke-setup-sender
                                                              kem :hkdf-sha256 :aes-128-gcm
                                                              pk-r info))))
                                              (nth-value 0
                                                (ironclad:hpke-setup-recipient
                                                  kem :hkdf-sha256 :aes-128-gcm enc sk-r info)))))))
              (multiple-value-bind (enc sender)
                  (ironclad:hpke-setup-sender kem :hkdf-sha256 :aes-128-gcm pk-r info)
                (let ((recipient (ironclad:hpke-setup-recipient
                                   kem :hkdf-sha256 :aes-128-gcm enc sk-r info)))
                  (let* ((ciphertext (ironclad:hpke-seal sender aad message))
                         (seal-rate (items-per-second
                                      (lambda ()
                                        (ironclad:hpke-seal sender aad message))))
                         (open-rate (items-per-second
                                      (lambda ()
                                        (ironclad:hpke-open recipient aad ciphertext)))))
                    (record-lisp "hpke" (stringify kem) "derive-keypair" "ops/s" keypair-rate)
                    (record-lisp "hpke" (stringify kem) "setup-sender" "ops/s" sender-setup-rate)
                    (record-lisp "hpke" (stringify kem) "setup-recipient" "ops/s" recipient-setup-rate)
                    (record-lisp "hpke" (stringify kem) "seal" "ops/s" seal-rate)
                    (record-lisp "hpke" (stringify kem) "open" "ops/s" open-rate)))))))
      (error (condition)
        (report-benchmark-error "hpke" kem condition)))))

;;; ------------------------------------------------------------------
;;; OpenSSL reference helpers

(defun run-program (program args)
  (uiop:run-program (cons program args)
                    :output :string
                    :error-output :string
                    :ignore-error-status t))

(defun split-lines (text)
  (with-input-from-string (stream text)
    (loop for line = (read-line stream nil)
          while line
          collect line)))

(defun split-colon (line)
  (do* ((start 0 (1+ pos))
          (pos (position #\: line :start 0)
               (position #\: line :start start))
          (parts '()))
        ((null pos) (nreverse (cons (subseq line start) parts)))
      (push (subseq line start pos) parts)))

(defun split-whitespace (line)
  (loop with len = (length line)
        with start = 0
        for i from 0 below len
        when (member (char line i) '(#\Space #\Tab #\Return #\Newline))
        collect (subseq line start i) into parts
        and do (setf start (1+ i))
        finally (return (remove-if (lambda (s) (zerop (length s)))
                                   (nconc parts (list (subseq line start len)))))))

(defun parse-number (string)
  (let ((*read-eval* nil))
    (ignore-errors
      (let ((n (read-from-string string)))
        (if (realp n) n nil)))))

(defun openssl-output-lines (algorithm &key evp)
  (let ((args (list "speed" "-elapsed" "-seconds" "2" "-mr"
                    "-provider" "legacy" "-provider" "default")))
    (when evp
      (setf args (append args (list "-evp"))))
    (setf args (append args (list algorithm)))
    (split-lines
      (run-program "openssl" args))))

(defun openssl-throughput (algorithm &optional (size *size*))
  (let ((sizes '())
        (values '()))
    (dolist (line (openssl-output-lines algorithm :evp t))
      (cond
        ((and (>= (length line) 2)
              (char= (char line 0) #\+)
              (char= (char line 1) #\H))
         (let ((fields (split-colon line)))
           (setf sizes (mapcar #'parse-number (rest fields)))))
        ((and (>= (length line) 2)
              (char= (char line 0) #\+)
              (char= (char line 1) #\F))
         (let* ((fields (split-colon line))
                (tail (rest (rest fields))))
           (setf values (mapcar #'parse-number tail))))))
    (when (and sizes values)
      (let ((index (position size sizes)))
        (when index
          (nth index values))))))

(defun openssl-sign-verify (algorithm)
  (let ((values '()))
    (dolist (line (openssl-output-lines algorithm))
      (when (and (>= (length line) 2)
                 (char= (char line 0) #\+)
                 (char= (char line 1) #\F))
        (let* ((fields (split-colon line))
               (numbers (remove nil (mapcar #'parse-number (rest fields)))))
          (when (>= (length numbers) 2)
            (setf values (list (first (last numbers 2))
                               (first (last numbers 1))))))))
    values))

(defparameter *openssl-throughput-map*
  '((:aes . "aes-256-cbc")
    (:aria . "aria-256-cbc")
    (:blowfish . "bf-cbc")
    (:camellia . "camellia-256-cbc")
    (:cast5 . "cast5-cbc")
    (:chacha . "chacha20")
    (:des . "des-cbc")
    (:3des . "des-ede3-cbc")
    (:idea . "idea-cbc")
    (:rc2 . "rc2-cbc")
    (:seed . "seed-cbc")
    (:sm4 . "sm4-cbc")
    (:chacha-poly . "chacha20-poly1305")
    (:gcm . "aes-256-gcm")
    (:ccm . "aes-256-ccm")))

(defparameter *openssl-digest-map*
  '((:md5 . "md5")
    (:sha1 . "sha1")
    (:sha224 . "sha224")
    (:sha256 . "sha256")
    (:sha384 . "sha384")
    (:sha512 . "sha512")
    (:sha512/224 . "sha512-224")
    (:sha512/256 . "sha512-256")
    (:sha3/224 . "sha3-224")
    (:sha3/256 . "sha3-256")
    (:sha3/384 . "sha3-384")
    (:sha3 . "sha3-512")
    (:ripemd-160 . "ripemd160")
    (:sm3 . "sm3")
    (:whirlpool . "whirlpool")
    (:blake2 . "blake2b512")
    (:blake2/256 . "blake2b512")
    (:blake2s . "blake2s256")))

(defparameter *openssl-public-key-map*
  '((:rsa . "rsa2048")
    (:dsa . "dsa2048")
    (:elgamal . nil)
    (:curve25519 . nil)
    (:curve448 . nil)
    (:secp224r1 . "ecdsap224")
    (:secp256k1 . nil)
    (:secp256r1 . "ecdsap256")
    (:secp384r1 . "ecdsap384")
    (:secp521r1 . "ecdsap521")
    (:ed25519 . "ed25519")
    (:ed448 . "ed448")))

(defun add-openssl-throughput-results (category lisp-kind)
  (let ((openssl-alg (cdr (assoc lisp-kind *openssl-throughput-map*))))
    (when openssl-alg
      (let ((rate (openssl-throughput openssl-alg)))
        (when rate
          (record category (stringify lisp-kind) (format nil "openssl ~a" openssl-alg)
                  (case category
                    ("digest" (format nil "hash ~D-byte block" *size*))
                    (otherwise (format nil "encrypt ~D-byte buffer" *size*)))
                  "bytes/s" rate))))))

(defun add-openssl-digest-results ()
  (dolist (pair *openssl-digest-map*)
    (let ((rate (openssl-throughput (cdr pair))))
      (when rate
        (record "digest" (stringify (car pair))
                (format nil "openssl ~a" (cdr pair))
                (format nil "hash ~D-byte block" *size*)
                "bytes/s" rate)))))

(defun add-openssl-aead-results ()
  (dolist (pair (remove-if-not (lambda (x)
                                 (member x '(:gcm :chacha-poly :ccm)))
                               (mapcar #'car *openssl-throughput-map*)))
    (let ((openssl-alg (cdr (assoc pair *openssl-throughput-map*))))
      (let ((rate (openssl-throughput openssl-alg)))
        (when rate
          (record "aead" (stringify pair)
                  (format nil "openssl ~a" openssl-alg)
                  (format nil "encrypt ~D-byte message" *size*)
                  "bytes/s" rate))))))

(defun add-openssl-public-key-results (kind)
  (let ((openssl-alg (cdr (assoc kind *openssl-public-key-map*))))
    (when openssl-alg
      (let ((sv (openssl-sign-verify openssl-alg)))
        (when sv
          (record "public-key" (stringify kind)
                  (format nil "openssl ~a" openssl-alg)
                  "sign" "ops/s" (first sv))
          (record "public-key" (stringify kind)
                  (format nil "openssl ~a" openssl-alg)
                  "verify" "ops/s" (second sv)))))))

;;; ------------------------------------------------------------------
;;; Local C reference benchmarks

(defparameter *local-c-map*
  '((:hqc-128 . "hqc-128")
    (:hqc-192 . "hqc-192")
    (:hqc-256 . "hqc-256")
    (:mceliece348864 . "mceliece348864-clean")
    (:mceliece460896 . "mceliece460896")
    (:mceliece6688128 . "mceliece6688128")
    (:mceliece6960119 . "mceliece6960119")
    (:mceliece8192128 . "mceliece8192128")
    (:falcon-512 . "falcon-512-clean")
    (:ml-dsa-44 . "mldsa-44-ref")
    (:ml-dsa-65 . "mldsa-65-ref")
    (:ml-dsa-87 . "mldsa-87-ref")
    (:slh-dsa-sha2-128s . "slh-dsa-sha2-128s")
    (:slh-dsa-sha2-128f . "slh-dsa-sha2-128f")
    (:slh-dsa-sha2-192s . "slh-dsa-sha2-192s")
    (:slh-dsa-sha2-192f . "slh-dsa-sha2-192f")
    (:slh-dsa-sha2-256s . "slh-dsa-sha2-256s")
    (:slh-dsa-sha2-256f . "slh-dsa-sha2-256f")
    (:slh-dsa-shake-128s . "slh-dsa-shake-128s")
    (:slh-dsa-shake-128f . "slh-dsa-shake-128f")
    (:slh-dsa-shake-192s . "slh-dsa-shake-192s")
    (:slh-dsa-shake-192f . "slh-dsa-shake-192f")
    (:slh-dsa-shake-256s . "slh-dsa-shake-256s")
    (:slh-dsa-shake-256f . "slh-dsa-shake-256f")
    (:xmss-sha2-10-256 . "xmss-sha2_10_256")))

(defun parse-key-value-lines (text)
  (let ((values '()))
    (dolist (line (split-lines text))
      (let ((pos (position #\= line)))
        (when pos
          (let ((key (string-upcase (subseq line 0 pos)))
                (number (parse-number (subseq line (1+ pos)))))
            (when number
              (push (cons key number) values))))))
    (nreverse values)))

(defun add-local-c-results (kind)
  (let ((name (cdr (assoc kind *local-c-map*))))
    (when name
      (let* ((binary (namestring (merge-pathnames name #P"benchmark/c-bin/")))
             (text (run-program binary '("1")))
             (values (parse-key-value-lines text)))
        (flet ((ms (key)
                 (or (cdr (assoc key values :test #'equal)) 0.0d0))
               (crate (key)
                 (let ((value (cdr (assoc key values :test #'equal))))
                   (if (and value (> value 0.0d0))
                       (/ 1000.0d0 value)
                       0.0d0))))
          (when (> (ms "KEYGEN_MS") 0.0d0)
            (record "public-key" (stringify kind)
                    (format nil "C ~a" name)
                    "keygen" "ops/s" (crate "KEYGEN_MS")))
          (when (> (ms "ENCAPS_MS") 0.0d0)
            (record "public-key" (stringify kind)
                    (format nil "C ~a" name)
                    "encapsulate" "ops/s" (crate "ENCAPS_MS")))
          (when (> (ms "DECAPS_MS") 0.0d0)
            (record "public-key" (stringify kind)
                    (format nil "C ~a" name)
                    "decapsulate" "ops/s" (crate "DECAPS_MS")))
          (when (> (ms "SIGN_MS") 0.0d0)
            (record "public-key" (stringify kind)
                    (format nil "C ~a" name)
                    "sign" "ops/s" (crate "SIGN_MS")))
          (when (> (ms "VERIFY_MS") 0.0d0)
            (record "public-key" (stringify kind)
                    (format nil "C ~a" name)
                    "verify" "ops/s" (crate "VERIFY_MS"))))))))

;;; ------------------------------------------------------------------
;;; Aliases

(defun copy-alias-results (alias canonical)
  (let ((alias-name (stringify alias))
        (canonical-name (stringify canonical)))
    (dolist (result *results*)
      (when (and (string= (getf result :category) "public-key")
                 (string= (getf result :algorithm) canonical-name)
                 (string= (getf result :source) "ironclad"))
        (record "public-key" alias-name (getf result :source)
                (getf result :operation) (getf result :unit)
                (getf result :value))))))

(defun replicate-alias-results ()
  (let ((canonical-results (copy-list *results*)))
    (dolist (pair *alias-to-canonical*)
      (let* ((alias (car pair))
             (canonical (cdr pair))
             (alias-name (stringify alias))
             (canonical-name (stringify canonical)))
        (dolist (result canonical-results)
          (when (and (string= (getf result :algorithm) canonical-name))
            (record (getf result :category) alias-name (getf result :source)
                    (getf result :operation) (getf result :unit)
                    (getf result :value))))))))

;;; ------------------------------------------------------------------
;;; Output

(defun trim-decimal (string)
  "Remove trailing zeroes after the decimal point."
  (let ((trimmed (string-right-trim "0" string)))
    (if (and (plusp (length trimmed))
             (char= (char trimmed (1- (length trimmed))) #\.))
        (subseq trimmed 0 (1- (length trimmed)))
        trimmed)))

(defun format-decimal (value &optional (decimals 8))
  (trim-decimal
   (if (= decimals 4)
       (format nil "~,4F" value)
       (format nil "~,8F" value))))

(defun format-significant (value)
  "Format VALUE with about four significant digits and no exponent."
  (let ((string (format nil "~,4g" value)))
    (if (or (search "d" string :test #'char-equal)
            (search "e" string :test #'char-equal))
        (format-decimal value 8)
        (trim-decimal string))))

(defun format-rate (value)
  "Format a plain positive rate with readable k/M/G/T suffixes."
  (if (> value 0.0d0)
      (cond
        ((>= value 1.0d12)
         (concatenate 'string (format-significant (/ value 1.0d12)) "T"))
        ((>= value 1.0d9)
         (concatenate 'string (format-significant (/ value 1.0d9)) "G"))
        ((>= value 1.0d6)
         (concatenate 'string (format-significant (/ value 1.0d6)) "M"))
        ((>= value 1.0d3)
         (concatenate 'string (format-significant (/ value 1.0d3)) "k"))
        (t (format-significant value)))
      "-"))

(defun sort-results (results)
  (sort (copy-list results)
        (lambda (a b)
          (let ((ca (getf a :category))
                (cb (getf b :category)))
            (cond
              ((string< ca cb) t)
              ((string> ca cb) nil)
              (t
               (let ((aa (getf a :algorithm))
                     (ab (getf b :algorithm)))
                 (cond
                   ((string< aa ab) t)
                   ((string> aa ab) nil)
                   (t
                    (string< (getf a :operation)
                             (getf b :operation)))))))))))

(defun write-raw ()
  (ensure-directories-exist *raw-output*)
  (with-open-file (stream *raw-output* :direction :output
                          :if-exists :supersede)
    (write (sort-results *results*) :stream stream)))

(defun result-key (result)
  (list (getf result :category)
        (getf result :algorithm)
        (getf result :operation)
        (getf result :unit)))

(defun find-lisp-result (key)
  (find-if (lambda (result)
             (and (equalp (result-key result) key)
                  (string= (getf result :source) "ironclad")))
           *results*))

(defun find-c-results (key)
  (remove-if (lambda (result)
               (string= (getf result :source) "ironclad"))
             (remove-if-not (lambda (result)
                              (equalp (result-key result) key))
                            *results*)))

(defun make-table-row (key lisp-result c-result)
  (let ((c (and c-result (getf c-result :value)))
        (lisp (getf lisp-result :value)))
    (list :category (first key)
          :algorithm (second key)
          :operation (third key)
          :unit (getf lisp-result :unit)
          :lisp (format-rate lisp)
          :c (if c-result (format-rate c) "-")
          :source (if c-result (getf c-result :source) "-")
          :ratio (if (and c (> c 0.0d0))
                     (/ c lisp)
                     nil)
          :sort-ratio (if (and c (> c 0.0d0))
                          (/ c lisp)
                          -1.0d0))))

(defun table-rows ()
  (loop for key in (remove-duplicates
                     (mapcar #'result-key (sort-results *results*))
                     :test #'equalp)
        for lisp = (find-lisp-result key)
        when lisp
        append (let ((c-results (find-c-results key)))
                 (if c-results
                     (loop for c-result in c-results
                           collect (make-table-row key lisp c-result))
                     (list (make-table-row key lisp nil))))))

(defun write-table ()
  (ensure-directories-exist *table-output*)
  (with-open-file (stream *table-output* :direction :output
                          :if-exists :supersede)
    (format stream "#+TITLE: Ironclad all-algorithm benchmark~%~%")
    (format stream "Generated: ~a~%" (get-universal-time))
    (format stream "Lisp: ~a ~a~%" (lisp-implementation-type)
            (lisp-implementation-version))
    (format stream "Platform: ~a ~a (~a)~%~%"
            (software-type) (software-version) (machine-type))
    (format stream "* Results~%~%")
    (format stream "Sorted by C/Lisp ratio, descending. Rows without a local C reference are listed last.~%~%")
    (format stream "| Category | Algorithm | Operation | Unit | Lisp | C | C source | C/Lisp |~%")
    (format stream "|---|---|---|---|---:|---:|---|---:|~%")
    (dolist (row (sort (table-rows)
                       #'>
                       :key (lambda (row) (getf row :sort-ratio))))
      (format stream "| ~a | ~a | ~a | ~a | ~a | ~a | ~a | ~a |~%"
              (getf row :category)
              (getf row :algorithm)
              (getf row :operation)
              (getf row :unit)
              (getf row :lisp)
              (getf row :c)
              (getf row :source)
              (if (getf row :ratio)
                  (format nil "~,3g" (getf row :ratio))
                  "-")))
    (terpri stream)))

;;; ------------------------------------------------------------------

(defun selected (name)
  (let ((args (uiop:command-line-arguments)))
    (or (null args)
        (member name args :test #'string=))))

(defun run-all ()
  (when (selected "ciphers")
    (dolist (name (ironclad:list-all-ciphers))
      (format t "cipher ~a~%" name)
      (finish-output)
      (benchmark-cipher name)))
  (when (selected "cipher-modes")
    (dolist (mode (ironclad:list-all-modes))
      (format t "cipher-mode ~a~%" mode)
      (finish-output)
      (benchmark-mode mode)))
  (when (selected "digests")
    (dolist (name (ironclad:list-all-digests))
      (format t "digest ~a~%" name)
      (finish-output)
      (benchmark-digest name)))
  (when (selected "macs")
    (dolist (name (ironclad:list-all-macs))
      (format t "mac ~a~%" name)
      (finish-output)
      (benchmark-mac name)))
  (when (selected "aeads")
    (dolist (name (ironclad:list-all-authenticated-encryption-modes))
      (format t "aead ~a~%" name)
      (finish-output)
      (benchmark-aead name)))
  (when (selected "kdfs")
    (dolist (kind (ironclad:list-all-kdfs))
      (format t "kdf ~a~%" kind)
      (finish-output)
      (benchmark-kdf kind)))
  (when (selected "prngs")
    (dolist (name (ironclad:list-all-prngs))
      (format t "prng ~a~%" name)
      (finish-output)
      (benchmark-prng name)))
  (when (selected "public-key")
    (let* ((all-kinds (ironclad:list-all-key-pair-kinds))
           (canonical (remove-duplicates (mapcar #'canonical-kind all-kinds))))
      (dolist (kind canonical)
        (format t "public-key ~a~%" kind)
        (finish-output)
        (handler-case (benchmark-public-key kind)
          (error (condition)
            (format t "  error: ~a~%" condition)
            (finish-output))))
      (replicate-alias-results)
      (sb-ext:gc :full t)))
  (when (selected "hpke")
    (format t "hpke~%")
    (finish-output)
    (benchmark-hpke))
  (sb-ext:gc :full t)
  (when (selected "c-references")
    (format t "C references~%")
    (finish-output)
    (add-openssl-digest-results)
    (add-openssl-aead-results)
    (dolist (name (ironclad:list-all-ciphers))
      (when (assoc name *openssl-throughput-map*)
        (let* ((openssl-alg (cdr (assoc name *openssl-throughput-map*)))
               (rate (openssl-throughput openssl-alg)))
          (when rate
            (record "cipher" (stringify name)
                    (format nil "openssl ~a" openssl-alg)
                    (format nil "encrypt ~D-byte buffer" *size*)
                    "bytes/s" rate)))))
    (dolist (pair *openssl-public-key-map*)
      (add-openssl-public-key-results (car pair))))
  (dolist (kind (remove-duplicates (mapcar #'canonical-kind
                                        (ironclad:list-all-key-pair-kinds))))
    (add-local-c-results kind))
  (write-raw)
  (write-table)
  (format t "Wrote ~a and ~a~%" (namestring *raw-output*) (namestring *table-output*)))

(run-all)
(uiop:quit)
