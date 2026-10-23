;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-unsafe-tests)

(rtest:deftest verify-key.bad-cipher
  (handler-case (crypto-unsafe::verify-key :error
                                    (make-array 0
                                                :element-type '(unsigned-byte 8)))
    (crypto-unsafe:unsupported-cipher () :ok)
    (:no-error () :error))
  :ok)

(rtest:deftest verify-key.bad-key0
  (handler-case (crypto-unsafe::verify-key :aes "")
    (type-error () :ok)
    (:no-error () :error))
  :ok)

(rtest:deftest verify-key.bad-key1
  (handler-case (crypto-unsafe::verify-key :aes nil)
    (crypto-unsafe:key-not-supplied () :ok)
    (:no-error () :error))
  :ok)

(rtest:deftest unprovided-key
  (handler-case
      (crypto-unsafe:make-cipher :blowfish :mode :ecb
                          :initialization-vector (make-array 8 :element-type '(unsigned-byte 8)))
    (crypto-unsafe:key-not-supplied () :ok)
    (:no-error () :error))
  :ok)

(rtest:deftest unsupported-mode.1
  (handler-case
      (crypto-unsafe:make-cipher :blowfish :mode :stream
                          :key (make-array 8 :element-type '(unsigned-byte 8))
                          :initialization-vector (make-array 8 :element-type '(unsigned-byte 8)))
    (crypto-unsafe:unsupported-mode () :ok)
    (:no-error () :error))
  :ok)

(rtest:deftest unsupported-mode.2
  (handler-case
      (crypto-unsafe:make-cipher :salsa20 :mode :cbc
                          :key (make-array 16 :element-type '(unsigned-byte 8)))
    (crypto-unsafe:unsupported-mode () :ok)
    (:no-error () :error))
  :ok)

(rtest:deftest block-length.known-ciphers
  (dolist (name (crypto-unsafe:list-all-ciphers) :ok)
    (unless (crypto-unsafe:block-length name)
      (return :error)))
  :ok)

(rtest:deftest block-length.bad-cipher
  (crypto-unsafe:block-length :error)
  nil)

(rtest:deftest key-lengths.known-ciphers
  (dolist (name (crypto-unsafe:list-all-ciphers) :ok)
    (unless (crypto-unsafe:key-lengths name)
      (return :error)))
  :ok)

(rtest:deftest key-lengths.bad-cipher
  (crypto-unsafe:key-lengths :error)
  nil)

#.(loop for cipher in (crypto-unsafe:list-all-ciphers)
        collect `(rtest:deftest ,cipher
                   (run-test-vector-file ',cipher *cipher-tests*) t) into forms
        finally (return `(progn ,@forms)))

#.(if (boundp '*cipher-stream-tests*)
      (loop for cipher in (crypto-unsafe:list-all-ciphers)
            collect `(rtest:deftest ,(crypto-unsafe::symbolicate cipher '#:/stream)
                       (run-test-vector-file ',cipher *cipher-stream-tests*) t)
              into forms
         finally (return `(progn ,@forms)))
      nil)

(rtest:deftest ciphers.crypto-package
  (every #'(lambda (s)
             (eq (nth-value 1 (find-symbol (symbol-name s)
                                           (find-package :ironclad-unsafe)))
                 :external))
         (crypto-unsafe:list-all-ciphers))
  t)

(rtest:deftest clean-symbols.ciphers
    (loop with n-ciphers = (length (crypto-unsafe:list-all-ciphers))
     for s being each symbol of :crypto-unsafe
     when (crypto-unsafe::%find-cipher s)
     count s into computed-n-ciphers
     finally (return (= n-ciphers computed-n-ciphers)))
  t)
