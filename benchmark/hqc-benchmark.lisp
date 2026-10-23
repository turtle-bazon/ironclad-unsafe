;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; hqc-benchmark.lisp -- small HQC KEM-cycle benchmark.

(asdf:load-system "ironclad-unsafe")

(defparameter *hqc-benchmark-iterations* 3
  "Number of full KEM cycles to average for each HQC parameter set.")

(defun hqc-seconds (start end)
  (/ (- end start) (coerce internal-time-units-per-second 'double-float)))

(defun hqc-benchmark-kind (kind)
  "Return keygen, encapsulation, decapsulation, and total cycle seconds."
  (let ((keygen 0.0d0)
        (encaps 0.0d0)
        (decaps 0.0d0))
    (dotimes (i *hqc-benchmark-iterations*)
      (let ((t0 (get-internal-run-time)))
        (multiple-value-bind (private public)
            (ironclad-unsafe:generate-key-pair kind)
          (let ((t1 (get-internal-run-time)))
            (multiple-value-bind (ciphertext secret)
                (ironclad-unsafe:encapsulate-key public)
              (let ((t2 (get-internal-run-time)))
                (let ((secret2 (ironclad-unsafe:decapsulate-key private ciphertext)))
                  (unless (equalp secret secret2)
                    (error "HQC KEM roundtrip failed for ~A" kind))
                  (let ((t3 (get-internal-run-time)))
                    (incf keygen (hqc-seconds t0 t1))
                    (incf encaps (hqc-seconds t1 t2))
                    (incf decaps (hqc-seconds t2 t3))))))))))
    (let ((iterations (coerce *hqc-benchmark-iterations* 'double-float)))
      (values (/ keygen iterations)
              (/ encaps iterations)
              (/ decaps iterations)
              (/ (+ keygen encaps decaps) iterations)))))

(defun hqc-benchmark ()
  (dolist (kind '(:hqc-128 :hqc-192 :hqc-256))
    (multiple-value-bind (keygen encaps decaps total)
        (hqc-benchmark-kind kind)
      (format t "~&~A: keygen ~,3fs  encaps ~,3fs  decaps ~,3fs  total ~,3fs~%"
              kind keygen encaps decaps total)))
  (values))

(hqc-benchmark)
