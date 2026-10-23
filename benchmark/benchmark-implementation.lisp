(asdf:load-system "ironclad-unsafe")

(defparameter *data-size*
  #+sbcl (expt 2 27)
  #+ccl (expt 2 23)
  #-(or sbcl ccl) (expt 2 20))
(defparameter *buffer-size* 32768)
(defparameter *iterations* 100)
(defparameter *implementation-result-file* "benchmark-tmp")
(defparameter *result* (acons "version"
                              (format nil "~a ~a"
                                      (lisp-implementation-type)
                                      (lisp-implementation-version))
                              '()))

(defmacro get-speed-data (&body body)
  (let ((start-time (gensym))
        (end-time (gensym))
        (result (gensym))
        (duration (gensym))
        (speed (gensym)))
    `(let* ((,start-time (get-internal-real-time))
            (,result ,@body)
            (,end-time (get-internal-real-time))
            (,duration (/ (- ,end-time ,start-time) internal-time-units-per-second))
            (,speed (round *data-size* ,duration)))
       (values ,speed ,result))))

(defmacro get-speed-ops (&body body)
  (let ((start-time (gensym))
        (end-time (gensym))
        (result (gensym))
        (duration (gensym))
        (speed (gensym)))
    `(let* ((,start-time (get-internal-real-time))
            (,result ,@body)
            (,end-time (get-internal-real-time))
            (,duration (/ (- ,end-time ,start-time) internal-time-units-per-second))
            (,speed (round *iterations* ,duration)))
       (values ,speed ,result))))

(defun benchmark-ciphers ()
  (let ((speeds '()))
    (dolist (cipher-name (ironclad-unsafe:list-all-ciphers))
      (flet ((stream-cipher-p (cipher-name)
               (= 1 (ironclad-unsafe:block-length cipher-name))))
        (let* ((key (ironclad-unsafe:random-data (car (last (ironclad-unsafe:key-lengths cipher-name)))))
               (cipher (ironclad-unsafe:make-cipher cipher-name
                                             :key key
                                             :mode (if (stream-cipher-p cipher-name)
                                                       :stream
                                                       :ecb)))
               (buffer (ironclad-unsafe:random-data *buffer-size*))
               (speed (get-speed-data (dotimes (i (ceiling *data-size* *buffer-size*))
                                        (ironclad-unsafe:encrypt-in-place cipher buffer)))))
          (setf speeds (acons cipher-name speed speeds)))))
    (setf *result* (acons "ciphers" speeds *result*))))

(defun benchmark-digests ()
  (let ((speeds '()))
    (dolist (digest-name (ironclad-unsafe:list-all-digests))
      (let* ((digest (ironclad-unsafe:make-digest digest-name))
             (buffer (ironclad-unsafe:random-data *buffer-size*))
             (speed (get-speed-data (dotimes (i (ceiling *data-size* *buffer-size*)
                                                (ironclad-unsafe:produce-digest digest))
                                      (ironclad-unsafe:update-digest digest buffer)))))
        (setf speeds (acons digest-name speed speeds))))
    (setf *result* (acons "digests" speeds *result*))))

(defun benchmark-macs ()
  (let ((speeds '()))
    (dolist (mac-name (ironclad-unsafe:list-all-macs))
      (let* ((key-length (ecase mac-name
                           (:blake2-mac 64)
                           (:blake2s-mac 32)
                           (:cmac 32)
                           (:gmac 32)
                           (:hmac 32)
                           (:poly1305 32)
                           (:siphash 16)
                           (:skein-mac 64)))
             (key (ironclad-unsafe:random-data key-length))
             (iv (case mac-name
                   (:gmac (ironclad-unsafe:random-data 12))))
             (extra-args (case mac-name
                           (:cmac '(:aes))
                           (:gmac (list :aes iv))
                           (:hmac '(:sha256))))
             (mac (apply #'ironclad-unsafe:make-mac mac-name key extra-args))
             (buffer (ironclad-unsafe:random-data *buffer-size*))
             (speed (get-speed-data (dotimes (i (ceiling *data-size* *buffer-size*)
                                                (ironclad-unsafe:produce-mac mac))
                                      (ironclad-unsafe:update-mac mac buffer)))))
        (setf speeds (acons mac-name speed speeds))))
    (setf *result* (acons "macs" speeds *result*))))

(defun benchmark-modes ()
  (let ((speeds '()))
    (dolist (mode-name (ironclad-unsafe:list-all-modes))
      (let* ((cipher-name :aes)
             (key (ironclad-unsafe:random-data (car (last (ironclad-unsafe:key-lengths cipher-name)))))
             (iv (ironclad-unsafe:random-data (ironclad-unsafe:block-length cipher-name)))
             (cipher (ironclad-unsafe:make-cipher cipher-name
                                           :mode mode-name
                                           :key key
                                           :initialization-vector iv))
             (buffer (ironclad-unsafe:random-data *buffer-size*))
             (speed (get-speed-data (dotimes (i (ceiling *data-size* *buffer-size*))
                                      (ironclad-unsafe:encrypt-in-place cipher buffer)))))
        (setf speeds (acons mode-name speed speeds))))
    (setf *result* (acons "modes" speeds *result*))))

(defun benchmark-diffie-hellman ()
  (let ((speeds '()))
    (dolist (dh-name '(:curve25519 :curve448 :elgamal
                       :secp256k1 :secp256r1 :secp384r1 :secp521r1))
      (multiple-value-bind (private-key public-key)
          (if (member dh-name '(:curve25519 :curve448
                                :secp256k1 :secp256r1 :secp384r1 :secp521r1))
              (ironclad-unsafe:generate-key-pair dh-name)
              (ironclad-unsafe:generate-key-pair dh-name :num-bits 2048))
        (let ((speed (get-speed-ops (loop repeat *iterations*
                                          do (ironclad-unsafe:diffie-hellman private-key public-key)))))
          (setf speeds (acons dh-name speed speeds)))))
    (setf *result* (acons "diffie-hellman" speeds *result*))))

(defun benchmark-message-encryptions ()
  (let ((speeds '())
        (message (ironclad-unsafe:random-data 20)))
    (dolist (encryption-name '(:elgamal :rsa))
      (let* ((public-key (nth-value 1 (ironclad-unsafe:generate-key-pair encryption-name :num-bits 2048)))
             (speed (get-speed-ops (loop repeat *iterations*
                                         do (ironclad-unsafe:encrypt-message public-key message)))))
        (setf speeds (acons encryption-name speed speeds))))
    (setf *result* (acons "message-encryptions" speeds *result*))))

(defun benchmark-signatures ()
  (let ((speeds '())
        (message (ironclad-unsafe:random-data 20)))
    (dolist (signature-name '(:dsa :ed25519 :ed448 :elgamal :rsa
                              :secp256k1 :secp256r1 :secp384r1 :secp521r1))
      (let* ((private-key (if (member signature-name '(:ed25519 :ed448 :secp256k1
                                                       :secp256r1 :secp384r1 :secp521r1))
                              (ironclad-unsafe:generate-key-pair signature-name)
                              (ironclad-unsafe:generate-key-pair signature-name :num-bits 2048)))
             (speed (get-speed-ops (loop repeat *iterations*
                                         do (ironclad-unsafe:sign-message private-key message)))))
        (setf speeds (acons signature-name speed speeds))))
    (setf *result* (acons "signatures" speeds *result*))))

(defun benchmark-verifications ()
  (let ((speeds '())
        (message (ironclad-unsafe:random-data 20)))
    (dolist (signature-name '(:dsa :ed25519 :ed448 :elgamal :rsa
                              :secp256k1 :secp256r1 :secp384r1 :secp521r1))
      (multiple-value-bind (private-key public-key)
          (if (member signature-name '(:ed25519 :ed448 :secp256k1
                                       :secp256r1 :secp384r1 :secp521r1))
              (ironclad-unsafe:generate-key-pair signature-name)
              (ironclad-unsafe:generate-key-pair signature-name :num-bits 2048))
        (let* ((signature (ironclad-unsafe:sign-message private-key message))
               (speed (get-speed-ops (loop repeat *iterations*
                                           do (ironclad-unsafe:verify-signature public-key message signature)))))
          (setf speeds (acons signature-name speed speeds)))))
    (setf *result* (acons "verifications" speeds *result*))))

(benchmark-ciphers)
(benchmark-digests)
(benchmark-macs)
(benchmark-modes)
(benchmark-diffie-hellman)
(benchmark-message-encryptions)
(benchmark-signatures)
(benchmark-verifications)
(with-open-file (file *implementation-result-file* :direction :output :if-exists :supersede)
  (write *result* :stream file))

(uiop:quit)
