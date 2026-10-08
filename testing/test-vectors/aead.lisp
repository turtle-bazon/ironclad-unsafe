;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

(in-package :crypto-tests)

#.(loop for mode in (crypto:list-all-authenticated-encryption-modes)
        collect `(rtest:deftest ,mode
                   (run-test-vector-file ',mode *authenticated-encryption-tests*)
                   t)
          into forms
        finally (return `(progn ,@forms)))

#.(loop for mode in (crypto:list-all-authenticated-encryption-modes)
        collect `(rtest:deftest ,(crypto::symbolicate mode '#:/incremental)
                   (run-test-vector-file ',mode *authenticated-encryption-incremental-tests*)
                   t)
          into forms
        finally (return `(progn ,@forms)))

(rtest:deftest :chacha-poly-reject-bad-tag
  (let* ((key (ironclad:random-data 32))
         (iv (ironclad:random-data 12))
         (msg (ironclad:random-data 48))
         (ad (ironclad:random-data 16))
         (enc (ironclad:make-authenticated-encryption-mode
               :chacha-poly :key key :initialization-vector iv))
         (ct (ironclad:encrypt-message enc msg :associated-data ad))
         (tag (ironclad:produce-tag enc))
         (bad-tag (copy-seq tag)))
    (setf (aref bad-tag 0) (logxor (aref bad-tag 0) 1))
    (let ((dec (ironclad:make-authenticated-encryption-mode
                :chacha-poly :key key :initialization-vector iv :tag bad-tag)))
      (handler-case (progn (ironclad:decrypt-message dec ct :associated-data ad)
                           nil)
        (ironclad:bad-authentication-tag () t))))
  t)
