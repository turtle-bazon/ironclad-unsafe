;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; cpu-features.lisp -- detection of the CPU features Ironclad can use
;;;;
;;;; The CPU is probed exactly once, when the system is loaded, and the
;;;; result is cached in *IRONCLAD-CPU-FEATURES*.  Every consumer asks
;;;; that cache instead of running its own probe, so that:
;;;;
;;;;  * the answer is consistent for the whole life of the image;
;;;;  * the (relatively expensive) CPUID leaves and the /proc/cpuinfo
;;;;    parsing happen once rather than once per call site;
;;;;  * a build that runs on several machines does not have to be
;;;;    recompiled for each of them -- the library is "re-instructed"
;;;;    for the machine it is loaded on.
;;;;
;;;; The Linux detection reads /proc/cpuinfo, which is the reference for
;;;; "what can this kernel actually let the process do": the kernel only
;;;; advertises a flag in the "flags" line if the CPU implements it *and*
;;;; the OS has enabled the corresponding state (XCR0).  The CPUID
;;;; probes are kept as a fallback for the systems where /proc/cpuinfo is
;;;; not available, and for the checks that the kernel does not report.

(in-package :crypto)

;;; ------------------------------------------------------------------
;;; The cache
;;; ------------------------------------------------------------------

(defvar *ironclad-unsafe-cpu-features* nil
  "The list of CPU features available on this machine, as keywords.
Filled in by IRONCLAD-INITIALIZE-CPU-FEATURES when the system is loaded.")

(defvar *ironclad-unsafe-cpu-features-ready-p* nil
  "True once the CPU has been probed.")

(defun ironclad-unsafe-cpu-features ()
  "Return the list of CPU features available on this machine."
  (unless *ironclad-unsafe-cpu-features-ready-p*
    (ironclad-unsafe-initialize-cpu-features))
  *ironclad-unsafe-cpu-features*)

(defun ironclad-unsafe-cpu-feature-p (feature)
  "True when FEATURE is available on this machine.
FEATURE is a keyword, e.g. :BMI2 or :AVX2."
  (declare (type keyword feature))
  (and (member feature (ironclad-unsafe-cpu-features) :test #'eq) t))

;;; ------------------------------------------------------------------
;;; Detection
;;; ------------------------------------------------------------------

(defvar *ironclad-unsafe-aes-ni-p* nil)
(defvar *ironclad-unsafe-pclmulqdq-p* nil)
(defvar *ironclad-unsafe-sha-ni-p* nil)
(defvar *ironclad-unsafe-bmi2-p* nil)
(defvar *ironclad-unsafe-adx-p* nil)
(defvar *ironclad-unsafe-avx2-p* nil)
(defvar *ironclad-unsafe-avx512-p* nil)

(defun ironclad-unsafe-initialize-cpu-features ()
  "Probe the CPU and cache the result.  Called once, at load time."
  (let ((features (ironclad-unsafe-detect-cpu-features)))
    (setf *ironclad-unsafe-cpu-features* features
          *ironclad-unsafe-cpu-features-ready-p* t
          *ironclad-unsafe-aes-ni-p* (and (member :aes features :test #'eq) t)
          *ironclad-unsafe-pclmulqdq-p* (and (member :pclmulqdq features :test #'eq) t)
          *ironclad-unsafe-sha-ni-p* (and (member :sha-ni features :test #'eq) t)
          *ironclad-unsafe-bmi2-p* (and (member :bmi2 features :test #'eq) t)
          *ironclad-unsafe-adx-p* (and (member :adx features :test #'eq) t)
          *ironclad-unsafe-avx2-p* (and (member :avx2 features :test #'eq) t)
          *ironclad-unsafe-avx512-p* (and (member :avx512f features :test #'eq) t)))
  *ironclad-unsafe-cpu-features*)

(defun ironclad-unsafe-detect-cpu-features ()
  "Return the list of features of the CPU we are running on, as keywords."
  (let ((flags (ironclad-unsafe-linux-cpu-flags)))
    (if flags
        (ironclad-unsafe-features-from-flags flags)
        (ironclad-unsafe-features-from-cpuid))))

(defun ironclad-unsafe-features-from-flags (flags)
  "Return the features of FLAGS, a list of keywords as found in the
\"flags\" line of /proc/cpuinfo."
  (let ((features nil))
    (dolist (feature '(:aes :pclmulqdq :sha-ni :bmi1 :bmi2 :adx
                        :avx :avx2 :avx512f :avx512dq :avx512cd
                        :avx512bw :avx512vl :vaes :gfni :avx512vnni))
      (when (member feature flags :test #'eq)
        (push feature features)))
    (nreverse features)))

;;; The OS check for the YMM state, needed on the systems where the
;;; CPUID probe is the only source of information.
(defun ironclad-unsafe-avx2-os-supported-p ()
  "True when the OS enables the YMM register state."
  #+linux
  (let ((flags nil))
    (with-open-file (stream "/proc/cpuinfo" :if-does-not-exist nil)
      (when stream
        (loop for line = (read-line stream nil nil)
              while (and line (not flags))
              when (search "flags" line)
              do (setf flags line))))
    (and flags (not (null (search "avx2" flags)))))
  #+darwin
  (let ((output ""))
    (ignore-errors
      (setf output (uiop:run-program '("sysctl" "-n" "hw.optional.avx2")
                                     :ignore-error-status t :output :string)))
    (and output
         (not (string= (string-trim '(#\Space #\Newline) output) ""))))
  #-(or linux darwin)
  nil)

(defun ironclad-unsafe-features-from-cpuid ()
  "Return the features of the CPU, as reported by the CPUID probes.
This is the fallback for the systems without a usable /proc/cpuinfo.
Note that the CPUID probes do not know whether the OS enables the
extended processor state, so on those systems the AVX2 check has to be
supplemented by IRONCLAD-AVX2-OS-SUPPORTED-P."
  #+ironclad-unsafe-assembly
  (progn
    (let ((features nil))
      (dolist (probe '((:aes . aes-ni-support-p)
                        (:pclmulqdq . pclmulqdq-support-p)
                        (:sha-ni . sha-ni-support-p)
                        (:bmi2 . bmi2-support-p)
                        (:adx . adx-support-p)
                        (:avx2 . avx2-cpu-support-p)))
        (when (funcall (cdr probe))
          (push (car probe) features)))
      (when (and (member :avx2 features :test #'eq)
                 (not (ironclad-unsafe-avx2-os-supported-p)))
        (setf features (remove :avx2 features :test #'eq)))
      (nreverse features)))
  #-ironclad-unsafe-assembly
  (progn
    nil))

;;; The features listed in the "flags" (or "Features") line of
;;; /proc/cpuinfo, as a list of keywords.  NIL when the file cannot be
;;; read or does not contain such a line.
(defun ironclad-unsafe-linux-cpu-flags ()
  "Return the CPU flags reported by /proc/cpuinfo as a list of keywords,
or NIL when the file is unavailable."
  (let ((result nil))
    (with-open-file (stream "/proc/cpuinfo" :if-does-not-exist nil)
      (when stream
        (loop for line = (read-line stream nil nil)
              while (and line (not result))
              when (or (search "flags" line) (search "Features" line))
              do (setf result (ironclad-unsafe-parse-cpu-flags line)))))
    result))

(defun ironclad-unsafe-parse-cpu-flags (line)
  "Split LINE into its whitespace separated words and return them as
keywords, with underscores turned into hyphens."
  (let ((words nil)
        (length (length line))
        (i 0))
    (loop while (< i length)
          do (if (or (char= (char line i) #\Space) (char= (char line i) #\Tab))
                 (incf i)
                 (let ((start i))
                   (loop while (and (< i length)
                                    (not (or (char= (char line i) #\Space)
                                             (char= (char line i) #\Tab))))
                         do (incf i))
                   (push (intern (substitute #\- #\_ (string-upcase
                                                      (subseq line start i)))
                                  :keyword)
                         words))))
    (nreverse words)))

;;; ------------------------------------------------------------------
;;; The individual feature predicates read the cached answer, so they
;;; are cheap enough to be called from the inner loops.

(defun aes-ni-supported-p ()
  "True when the CPU implements the AES-NI instruction set."
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  *ironclad-unsafe-aes-ni-p*)

(defun pclmulqdq-supported-p ()
  "True when the CPU implements the PCLMULQDQ instruction."
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  *ironclad-unsafe-pclmulqdq-p*)

(defun sha-ni-supported-p ()
  "True when the CPU implements the SHA-NI instruction set."
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  *ironclad-unsafe-sha-ni-p*)

(defun bmi2-supported-p ()
  "True when the CPU implements the BMI2 instruction set."
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  *ironclad-unsafe-bmi2-p*)

(defun adx-supported-p ()
  "True when the CPU implements the ADX instruction set."
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  *ironclad-unsafe-adx-p*)

(defun avx2-supported-p ()
  "True when the CPU implements AVX2 and the OS enables its state."
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  *ironclad-unsafe-avx2-p*)

(defun avx512-supported-p ()
  "True when the CPU implements AVX-512F and the OS enables its state."
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  *ironclad-unsafe-avx512-p*)

;;; ------------------------------------------------------------------
;;; Vendor
;;; ------------------------------------------------------------------

(defvar *amd-cpu-p* nil)
(defvar *amd-cpu-p-known-p* nil)

(defun amd-cpu-p ()
  "True when the CPU is made by AMD."
  (if *amd-cpu-p-known-p*
      *amd-cpu-p*
      (setf *amd-cpu-p-known-p* t
            *amd-cpu-p* (with-open-file (stream "/proc/cpuinfo" :if-does-not-exist nil)
                          (when stream
                            (loop for line = (read-line stream nil nil)
                                  while line
                                  when (search "vendor_id" line)
                                  return (not (null (search "AuthenticAMD" line)))))))))

;;; ------------------------------------------------------------------
;;; Assembler support
;;; ------------------------------------------------------------------

(defun ironclad-unsafe-instruction-known-p (name)
  "True when the assembler of this SBCL knows the instruction NAME.
NAME is a string, e.g. \"MULX\" or \"VPADDQ\"."
  (declare (type string name))
  (handler-case
      ;; The instruction structures live in SB-X86-64-ASM; SBCL creates
      ;; one and registers its encoder when it defines the instruction,
      ;; so the presence of the symbol is what we are after.  (The
      ;; encoder table itself moved between SBCL versions, so it is not
      ;; a reliable place to look.)
      (not (null (find-symbol name "SB-X86-64-ASM")))
    (error () nil)))

;;; ------------------------------------------------------------------
;;; Load-time initialization
;;;
;;; The library is "re-instructed" for the machine it is loaded on: the
;;; feature cache is filled in here, and every implementation that has
;;; an assembly variant selects it from the cached answer.
;;; ------------------------------------------------------------------

(eval-when (:load-toplevel)
  (ironclad-unsafe-initialize-cpu-features))
