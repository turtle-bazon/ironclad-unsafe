;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;; c-vs-lisp.lisp -- benchmark Ironclad against local C reference builds.

(require 'asdf)
(push (truename #p"./") asdf:*central-registry*)
(asdf:load-system :ironclad-unsafe)

(defpackage :c-vs-lisp
  (:use :cl))
(in-package :c-vs-lisp)

(defparameter *c-bin-dir* #P"benchmark/c-bin/")
(defparameter *output-file* #P"benchmark/c-vs-lisp.org")

(defparameter *benchmarks*
  (list
   ;; name, Lisp kind, type, iterations
   (list :name "hqc-128" :kind :hqc-128 :type :kem :iterations 20)
   (list :name "hqc-192" :kind :hqc-192 :type :kem :iterations 20)
   (list :name "hqc-256" :kind :hqc-256 :type :kem :iterations 20)

   (list :name "mceliece348864-clean" :kind :mceliece348864 :type :kem :iterations 20)
   (list :name "mceliece348864-avx2" :kind :mceliece348864 :type :kem :iterations 20)
   (list :name "mceliece460896" :kind :mceliece460896 :type :kem :iterations 10)
   (list :name "mceliece6688128" :kind :mceliece6688128 :type :kem :iterations 5)
   (list :name "mceliece6960119" :kind :mceliece6960119 :type :kem :iterations 5)
   (list :name "mceliece8192128" :kind :mceliece8192128 :type :kem :iterations 5)

   (list :name "falcon-512-clean" :kind :falcon-512 :type :sign :iterations 50)
   (list :name "falcon-512-avx2" :kind :falcon-512 :type :sign :iterations 50)

   (list :name "mldsa-44-ref" :kind :ml-dsa-44 :type :sign :iterations 50)
   (list :name "mldsa-65-ref" :kind :ml-dsa-65 :type :sign :iterations 50)
   (list :name "mldsa-87-ref" :kind :ml-dsa-87 :type :sign :iterations 50)
   (list :name "mldsa-44-avx2" :kind :ml-dsa-44 :type :sign :iterations 50)
   (list :name "mldsa-65-avx2" :kind :ml-dsa-65 :type :sign :iterations 50)
   (list :name "mldsa-87-avx2" :kind :ml-dsa-87 :type :sign :iterations 50)

   (list :name "slh-dsa-sha2-128s" :kind :slh-dsa-sha2-128s :type :sign :iterations 1)
   (list :name "slh-dsa-sha2-128f" :kind :slh-dsa-sha2-128f :type :sign :iterations 1)
   (list :name "slh-dsa-sha2-192s" :kind :slh-dsa-sha2-192s :type :sign :iterations 1)
   (list :name "slh-dsa-sha2-192f" :kind :slh-dsa-sha2-192f :type :sign :iterations 1)
   (list :name "slh-dsa-sha2-256s" :kind :slh-dsa-sha2-256s :type :sign :iterations 1)
   (list :name "slh-dsa-sha2-256f" :kind :slh-dsa-sha2-256f :type :sign :iterations 1)
   (list :name "slh-dsa-shake-128s" :kind :slh-dsa-shake-128s :type :sign :iterations 1)
   (list :name "slh-dsa-shake-128f" :kind :slh-dsa-shake-128f :type :sign :iterations 1)
   (list :name "slh-dsa-shake-192s" :kind :slh-dsa-shake-192s :type :sign :iterations 1)
   (list :name "slh-dsa-shake-192f" :kind :slh-dsa-shake-192f :type :sign :iterations 1)
   (list :name "slh-dsa-shake-256s" :kind :slh-dsa-shake-256s :type :sign :iterations 1)
   (list :name "slh-dsa-shake-256f" :kind :slh-dsa-shake-256f :type :sign :iterations 1)

   (list :name "xmss-sha2_10_256" :kind :xmss-sha2-10-256 :type :sign :iterations 5)))

(defun now-ms ()
  (/ (get-internal-run-time)
     (coerce internal-time-units-per-second 'double-float)
     0.001))

(defun bench-message ()
  (let ((m (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32 m)
      (setf (aref m i) (mod (* i 7 3) 256)))))

(defun lisp-benchmark-kem (kind iterations)
  (multiple-value-bind (priv pub) (ironclad-unsafe:generate-key-pair kind)
    (let ((keygen-start (now-ms)))
      (multiple-value-bind (priv2 pub2) (ironclad-unsafe:generate-key-pair kind)
        (declare (ignore priv2 pub2)))
      (let ((keygen (- (now-ms) keygen-start)))
        (multiple-value-bind (ct ss) (ironclad-unsafe:encapsulate-key pub)
          (let ((ss2 (ironclad-unsafe:decapsulate-key priv ct)))
            (unless (equalp ss ss2)
              (error "KEM roundtrip failed for ~A" kind))
            (let ((encaps-start (now-ms))
                  (decaps-start 0.0d0)
                  (encaps 0.0d0)
                  (decaps 0.0d0))
              (dotimes (i iterations)
                (setf encaps-start (now-ms))
                (multiple-value-bind (ct2 ss3) (ironclad-unsafe:encapsulate-key pub)
                  (setf ct ct2 ss ss3))
                (incf encaps (- (now-ms) encaps-start))
                (setf decaps-start (now-ms))
                (setf ss2 (ironclad-unsafe:decapsulate-key priv ct))
                (incf decaps (- (now-ms) decaps-start)))
              (list :keygen-ms keygen
                    :encaps-ms (/ encaps iterations)
                    :decaps-ms (/ decaps iterations)))))))))

(defun lisp-benchmark-sign (kind iterations)
  (let ((msg (bench-message)))
    (multiple-value-bind (priv pub) (ironclad-unsafe:generate-key-pair kind)
      (let ((keygen-start (now-ms)))
        (multiple-value-bind (priv2 pub2) (ironclad-unsafe:generate-key-pair kind)
          (declare (ignore priv2 pub2)))
        (let ((keygen (- (now-ms) keygen-start)))
          (let ((sig (ironclad-unsafe:sign-message priv msg)))
            (unless (ironclad-unsafe:verify-signature pub msg sig)
              (error "signature roundtrip failed for ~A" kind))
            (let ((sign 0.0d0)
                  (verify 0.0d0)
                  (sign-start 0.0d0)
                  (verify-start 0.0d0))
              (dotimes (i iterations)
                (setf sign-start (now-ms))
                (setf sig (ironclad-unsafe:sign-message priv msg))
                (incf sign (- (now-ms) sign-start))
                (setf verify-start (now-ms))
                (unless (ironclad-unsafe:verify-signature pub msg sig)
                  (error "signature verification failed for ~A" kind))
                (incf verify (- (now-ms) verify-start)))
              (list :keygen-ms keygen
                    :sign-ms (/ sign iterations)
                    :verify-ms (/ verify iterations)))))))))

(defvar *lisp-cache* (make-hash-table :test #'equal))

(defun lisp-benchmark (kind type iterations)
  (let ((key (list kind type iterations)))
    (or (gethash key *lisp-cache*)
        (let ((result
                (let ((ironclad-unsafe:*prng*
                        (ironclad-unsafe:make-prng :fortuna
                                            :seed (make-array 64 :element-type '(unsigned-byte 8)
                                                              :initial-element 7))))
                  (ecase type
                    (:kem (lisp-benchmark-kem kind iterations))
                    (:sign (lisp-benchmark-sign kind iterations))))))
          (setf (gethash key *lisp-cache*) result)
          result))))

(defun run-c-benchmark (name iterations)
  (let* ((path (merge-pathnames name *c-bin-dir*))
         (output
           (uiop:run-program (list (namestring path) (princ-to-string iterations))
                             :output :string
                             :error-output :string
                              :ignore-error-status t)))
    (with-input-from-string (stream output)
      (let ((result '()))
        (loop for line = (read-line stream nil)
              while line
              do (let ((pos (position #\= line)))
                   (when pos
                     (let* ((key (string-upcase (subseq line 0 pos)))
                            (value (subseq line (1+ pos)))
                            (number (ignore-errors (read-from-string value))))
                       (when (numberp number)
                         (push (cons key number) result))))))
        (nreverse result)))))

(defun result-ms (result key)
  (or (getf result (intern (substitute #\- #\_ key) :keyword))
      (cdr (assoc key result :test #'string=))
      0.0d0))

(defun detailed-rows (bench c-result lisp-result)
  (let* ((name (getf bench :name))
         (type (getf bench :type))
         (keys (ecase type
                 (:kem '("KEYGEN_MS" "ENCAPS_MS" "DECAPS_MS"))
                 (:sign '("KEYGEN_MS" "SIGN_MS" "VERIFY_MS"))))
         (labels (ecase type
                   (:kem '("keygen" "encaps" "decaps"))
                   (:sign '("keygen" "sign" "verify")))))
    (loop for key in keys
          for label in labels
          collect (list name label
                        (result-ms lisp-result key)
                        (result-ms c-result key)))))

(defun speed-ratio (lisp c)
  (if (> c 0.0d0)
      (/ lisp c)
      0.0d0))

(defun fmt-ms (x)
  (format nil "~,3f" x))

(defun fmt-ratio (x)
  (format nil "~,2f" x))

(declaim (ftype (function (list) list) summarize))

(defun write-table (rows)
  (ensure-directories-exist *output-file*)
  (with-open-file (stream *output-file* :direction :output
                          :if-exists :supersede)
    (format stream "#+TITLE: Ironclad Lisp vs C benchmark~%~%")
    (format stream "Generated: ~a~%~%" (get-universal-time))
    (format stream "Lisp: ~a ~a~%" (lisp-implementation-type) (lisp-implementation-version))
    (format stream "Platform: ~a ~a (~a)~%~%"
            (software-type) (software-version) (machine-type))
    (format stream "* Detailed results~%~%")
    (format stream "| Algorithm | Operation | Lisp ms | C ms | Lisp/C |~%")
    (format stream "|---|---|---:|---:|---:|~%")
    (dolist (row rows)
      (destructuring-bind (name label lisp c) row
        (format stream "| ~a | ~a | ~a | ~a | ~a |~%"
                name label (fmt-ms lisp) (fmt-ms c) (fmt-ratio (speed-ratio lisp c)))))
    (terpri stream)
    (format stream "* Summary~%~%")
    (format stream "| Algorithm | Lisp total ms | C total ms | Lisp/C |~%")
    (format stream "|---|---:|---:|---:|~%")
    (dolist (summary (summarize rows))
      (destructuring-bind (name lisp-total c-total) summary
        (format stream "| ~a | ~a | ~a | ~a |~%"
                name (fmt-ms lisp-total) (fmt-ms c-total)
                (fmt-ratio (speed-ratio lisp-total c-total)))))
    (terpri stream)))

(defun summarize (rows)
  (let ((table (make-hash-table :test #'equal))
        (order '()))
    (dolist (row rows)
      (destructuring-bind (name label lisp c) row
        (declare (ignore label))
        (let ((cell (gethash name table)))
          (unless cell
            (setf cell (list name 0.0d0 0.0d0)
                  (gethash name table) cell
                  order (cons name order)))
          (incf (second cell) lisp)
          (incf (third cell) c))))
    (mapcar (lambda (name) (gethash name table)) (nreverse order))))

(defun main ()
  (let* ((args (uiop:command-line-arguments))
         (benches (if args
                      (remove-if-not (lambda (b) (member (getf b :name) args :test #'string=))
                                     *benchmarks*)
                      *benchmarks*))
         (rows '()))
    (dolist (bench benches)
      (let* ((name (getf bench :name))
             (kind (getf bench :kind))
             (type (getf bench :type))
             (iterations (getf bench :iterations)))
        (format t "~&Benchmarking ~a...~%" name)
        (finish-output)
        (let ((c-result (run-c-benchmark name iterations))
              (lisp-result (lisp-benchmark kind type iterations)))
          (setf rows (append rows (detailed-rows bench c-result lisp-result))))))
    (write-table rows)
    (format t "~&Wrote ~a~%" (namestring *output-file*))
    (finish-output)))

(main)
(uiop:quit)
