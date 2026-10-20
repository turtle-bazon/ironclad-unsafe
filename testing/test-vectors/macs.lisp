;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

#.(loop for mac in (crypto:list-all-macs)
        collect `(rtest:deftest ,mac
                   (run-test-vector-file ',mac *mac-tests*) t)
          into forms
        finally (return `(progn ,@forms)))

#.(loop for mac in (crypto:list-all-macs)
        collect `(rtest:deftest ,(crypto::symbolicate mac '#:/incremental)
                   (run-test-vector-file ',mac *mac-incremental-tests*) t)
          into forms
        finally (return `(progn ,@forms)))

#.(if (boundp '*mac-stream-tests*)
      (loop for mac in (crypto:list-all-macs)
         collect `(rtest:deftest ,(crypto::symbolicate mac '#:/stream)
                      (run-test-vector-file ',mac *mac-stream-tests*) t)
           into forms
         finally (return `(progn ,@forms)))
      nil)

#.(loop for mac in (crypto:list-all-macs)
        collect `(rtest:deftest ,(crypto::symbolicate mac '#:/reinitialize-instance)
                   (run-test-vector-file ',mac *mac-reinitialize-instance-tests*) t)
          into forms
        finally (return `(progn ,@forms)))

(rtest:deftest :blake2-mac/truncated-digest
  ;; A MAC that asks for fewer bytes than the underlying digest
  ;; produces must truncate the hash, and must not write the full hash
  ;; into a short buffer: that used to corrupt the heap.
  (let ((data (make-array 100 :element-type '(unsigned-byte 8)
                         :initial-element 1))
        (empty-key (make-array 0 :element-type '(unsigned-byte 8)))
        (ok t))
    (let ((mac (crypto:make-mac :blake2-mac empty-key :digest-length 32)))
      (crypto:update-mac mac data)
      (let ((digest (crypto:produce-mac mac)))
        (unless (and (= (length digest) 32)
                     (equalp digest (crypto:digest-sequence :blake2/256 data)))
          (setf ok nil))))
    (let ((mac (crypto:make-mac :blake2s-mac empty-key :digest-length 16)))
      (crypto:update-mac mac data)
      (let ((digest (crypto:produce-mac mac)))
        (unless (and (= (length digest) 16)
                     (equalp digest (crypto:digest-sequence :blake2s/128 data)))
          (setf ok nil))))
    ok)
  t)
