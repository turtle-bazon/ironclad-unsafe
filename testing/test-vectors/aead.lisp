;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

(in-package :crypto-unsafe-tests)

#.(loop for mode in (crypto-unsafe:list-all-authenticated-encryption-modes)
        collect `(rtest:deftest ,mode
                   (run-test-vector-file ',mode *authenticated-encryption-tests*)
                   t)
          into forms
        finally (return `(progn ,@forms)))

#.(loop for mode in (crypto-unsafe:list-all-authenticated-encryption-modes)
        collect `(rtest:deftest ,(crypto-unsafe::symbolicate mode '#:/incremental)
                   (run-test-vector-file ',mode *authenticated-encryption-incremental-tests*)
                   t)
          into forms
        finally (return `(progn ,@forms)))

(rtest:deftest :chacha-poly-reject-bad-tag
  (let* ((key (ironclad-unsafe:random-data 32))
         (iv (ironclad-unsafe:random-data 12))
         (msg (ironclad-unsafe:random-data 48))
         (ad (ironclad-unsafe:random-data 16))
         (enc (ironclad-unsafe:make-authenticated-encryption-mode
               :chacha-poly :key key :initialization-vector iv))
         (ct (ironclad-unsafe:encrypt-message enc msg :associated-data ad))
         (tag (ironclad-unsafe:produce-tag enc))
         (bad-tag (copy-seq tag)))
    (setf (aref bad-tag 0) (logxor (aref bad-tag 0) 1))
    (let ((dec (ironclad-unsafe:make-authenticated-encryption-mode
                :chacha-poly :key key :initialization-vector iv :tag bad-tag)))
      (handler-case (progn (ironclad-unsafe:decrypt-message dec ct :associated-data ad)
                           nil)
        (ironclad-unsafe:bad-authentication-tag () t))))
  t)

(rtest:deftest :gcm-siv-reject-bad-tag
  (let* ((key (ironclad-unsafe:random-data 16))
         (iv (ironclad-unsafe:random-data 12))
         (msg (ironclad-unsafe:random-data 48))
         (ad (ironclad-unsafe:random-data 16))
         (enc (ironclad-unsafe:make-authenticated-encryption-mode
               :gcm-siv :key key :initialization-vector iv))
         (ct (ironclad-unsafe:encrypt-message enc msg :associated-data ad))
         (tag (ironclad-unsafe:produce-tag enc))
         (bad-tag (copy-seq tag)))
    (setf (aref bad-tag 0) (logxor (aref bad-tag 0) 1))
    (let ((dec (ironclad-unsafe:make-authenticated-encryption-mode
                :gcm-siv :key key :initialization-vector iv :tag bad-tag)))
      (handler-case (progn (ironclad-unsafe:decrypt-message dec ct :associated-data ad)
                           nil)
        (ironclad-unsafe:bad-authentication-tag () t))))
  t)
