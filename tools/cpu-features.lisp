;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; cpu-features.lisp -- report the CPU features Ironclad detects.
;;;;
;;;; Usage:  sbcl --script tools/cpu-features.lisp [path-to-ironclad-source]
;;;;
;;;; The default source tree is the checkout this file lives in.  The
;;;; script only loads the library and prints what was detected; it
;;;; does not run any of the assembly.

(require :asdf)

(defparameter *source*
  (or (second *posix-argv*)
      (merge-pathnames "../" (make-pathname :name nil :type nil
                                           :defaults (or *load-truename* *default-pathname*)))))

(format t "~&source tree: ~A~%" *source*)
(push (truename *source*) asdf:*central-registry*)
(asdf:load-system :ironclad)

(defun probe (name)
  (let ((sym (find-symbol name "IRONCLAD")))
    (and sym (symbol-function sym))))

(format t "~&features: ~A~%" (funcall (probe "IRONCLAD-CPU-FEATURES")))

(format t "~&aes=~A pclmulqdq=~A sha-ni=~A bmi2=~A adx=~A avx2=~A avx512=~A amd=~A~%"
        (funcall (probe "AES-NI-SUPPORTED-P"))
        (funcall (probe "PCLMULQDQ-SUPPORTED-P"))
        (funcall (probe "SHA-NI-SUPPORTED-P"))
        (funcall (probe "BMI2-SUPPORTED-P"))
        (funcall (probe "ADX-SUPPORTED-P"))
        (funcall (probe "AVX2-SUPPORTED-P"))
        (funcall (probe "AVX512-SUPPORTED-P"))
        (funcall (probe "AMD-CPU-P")))

(let ((known (probe "IRONCLAD-INSTRUCTION-KNOWN-P")))
  (format t "~&assembler: ~{~A~^ ~}~%"
          (loop for name in '("MULX" "ADCX" "ADOX" "VPADDQ" "VPMULLQ" "VPMOVZXDQ"
                              "KMOVQ" "VINSERTI128" "VPCONFLICT" "VPMADD52")
                for r = (funcall known name)
                collect (format nil "~A=~A" name (if r "yes" "no")))))
