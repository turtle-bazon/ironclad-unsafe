;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; cpu-features.lisp -- the CPU features Ironclad can use
;;;;
;;;; Detection is delegated to SB-CPU-FEATURES, which reads CPUID together
;;;; with SBCL's XGETBV-backed AVX flags (so an AVX2 CPU whose OS does not
;;;; enable the YMM state is reported correctly), works without
;;;; /proc/cpuinfo, and re-probes when a saved image starts on another
;;;; machine.
;;;;
;;;; The assembly paths ask the predicates below from their inner loops,
;;;; so each answer is cached in a special variable.  The cache is
;;;; recomputed from SB-CPU-FEATURES:*CPU-FEATURES-REFRESH-HOOKS* after
;;;; every re-probe, including the one at image startup.  Masking with
;;;; SB-CPU-FEATURES:WITH-CPU-FEATURES-DISABLED / -ONLY is honoured too:
;;;; while a mask is active the predicates bypass the cache, which is how
;;;; the tests exercise the portable fallbacks on a machine that has the
;;;; extensions.

(in-package :crypto-unsafe)

;;; ------------------------------------------------------------------
;;; The cache
;;; ------------------------------------------------------------------

(defvar *ironclad-unsafe-aes-ni-p* nil)
(defvar *ironclad-unsafe-pclmulqdq-p* nil)
(defvar *ironclad-unsafe-sha-ni-p* nil)
(defvar *ironclad-unsafe-bmi1-p* nil)
(defvar *ironclad-unsafe-bmi2-p* nil)
(defvar *ironclad-unsafe-adx-p* nil)
(defvar *ironclad-unsafe-avx2-p* nil)
(defvar *ironclad-unsafe-avx512-p* nil)
(defvar *amd-cpu-p* nil)

(defun sb-cpu-features-symbol (name)
  (find-symbol name "SB-CPU-FEATURES"))

(defun ironclad-unsafe-cpu-vendor ()
  (let ((f (sb-cpu-features-symbol "CPU-VENDOR")))
    (and f (fboundp f) (funcall f))))

(defun ironclad-unsafe-initialize-cpu-features ()
  "Recompute the cached answers from SB-CPU-FEATURES.  Runs at load time
and after every SB-CPU-FEATURES re-probe."
  (flet ((has (feature)
           (and (member feature (sb-cpu-features:detected-cpu-features)
                        :test #'eq)
                t)))
    (setf *ironclad-unsafe-aes-ni-p* (has :aes)
          *ironclad-unsafe-pclmulqdq-p* (has :pclmulqdq)
          *ironclad-unsafe-sha-ni-p* (has :sha-ni)
          *ironclad-unsafe-bmi1-p* (has :bmi1)
          *ironclad-unsafe-bmi2-p* (has :bmi2)
          *ironclad-unsafe-adx-p* (has :adx)
          *ironclad-unsafe-avx2-p* (has :avx2)
          *ironclad-unsafe-avx512-p* (has :avx512f)
          *amd-cpu-p* (and (member (ironclad-unsafe-cpu-vendor) '(:amd :hygon)) t)))
  (ironclad-unsafe-cpu-features))

(defun ironclad-unsafe-cpu-features ()
  "The effective CPU feature list (detected minus any masked features)."
  (sb-cpu-features:cpu-features))

(defun ironclad-unsafe-cpu-feature-p (feature)
  "True when FEATURE (a keyword such as :BMI2 or :AVX2) is available and
not masked."
  (declare (type keyword feature))
  (sb-cpu-features:cpu-feature-p feature))

;;; ------------------------------------------------------------------
;;; Predicates.  Cheap enough for inner loops: one special-variable read,
;;; plus one more for the mask, which is NIL outside tests.
;;; ------------------------------------------------------------------

(defun ironclad-unsafe-cpu-masked-p ()
  (let ((v (sb-cpu-features-symbol "*DISABLED-CPU-FEATURES*")))
    (and v (boundp v) (symbol-value v))))

(defmacro define-cached-cpu-predicate (name feature cache documentation)
  `(progn
     (declaim (inline ,name))
     (defun ,name ()
       ,documentation
       (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
       (if (ironclad-unsafe-cpu-masked-p)
           (sb-cpu-features:cpu-feature-p ,feature)
           ,cache))))

(define-cached-cpu-predicate aes-ni-supported-p :aes *ironclad-unsafe-aes-ni-p*
  "True when the CPU implements the AES-NI instruction set.")
(define-cached-cpu-predicate pclmulqdq-supported-p :pclmulqdq
  *ironclad-unsafe-pclmulqdq-p*
  "True when the CPU implements the PCLMULQDQ instruction.")
(define-cached-cpu-predicate sha-ni-supported-p :sha-ni *ironclad-unsafe-sha-ni-p*
  "True when the CPU implements the SHA-NI instruction set.")
(define-cached-cpu-predicate bmi1-supported-p :bmi1 *ironclad-unsafe-bmi1-p*
  "True when the CPU implements the BMI1 instruction set (ANDN, ...).")
(define-cached-cpu-predicate bmi2-supported-p :bmi2 *ironclad-unsafe-bmi2-p*
  "True when the CPU implements the BMI2 instruction set (MULX, RORX, ...).")
(define-cached-cpu-predicate adx-supported-p :adx *ironclad-unsafe-adx-p*
  "True when the CPU implements the ADX instruction set (ADCX, ADOX).")
(define-cached-cpu-predicate avx2-supported-p :avx2 *ironclad-unsafe-avx2-p*
  "True when the CPU implements AVX2 and the OS enables its state.")
(define-cached-cpu-predicate avx512-supported-p :avx512f *ironclad-unsafe-avx512-p*
  "True when the CPU implements AVX-512F and the OS enables its state.")

(defun amd-cpu-p ()
  "True when the CPU is made by AMD (or Hygon)."
  *amd-cpu-p*)

;;; ------------------------------------------------------------------
;;; Assembler support
;;; ------------------------------------------------------------------

(defun ironclad-unsafe-instruction-known-p (name)
  "True when the assembler of this SBCL knows the instruction NAME.
NAME is a string, e.g. \"MULX\" or \"VPADDQ\"."
  (declare (type string name))
  (handler-case
      ;; SBCL registers an instruction by creating its symbol in
      ;; SB-X86-64-ASM; the encoder table moved between versions, so the
      ;; symbol is the reliable thing to look for.
      (not (null (find-symbol name "SB-X86-64-ASM")))
    (error () nil)))

;;; ------------------------------------------------------------------
;;; Load-time initialization and re-probing
;;; ------------------------------------------------------------------

(let ((hooks (sb-cpu-features-symbol "*CPU-FEATURES-REFRESH-HOOKS*")))
  (when (and hooks (boundp hooks))
    (pushnew 'ironclad-unsafe-initialize-cpu-features (symbol-value hooks))))
(ironclad-unsafe-initialize-cpu-features)
