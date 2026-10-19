;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

(in-package :crypto)

;;; Check what features are supported by the CPU

#+(and sbcl x86-64)
(sb-ext:defglobal aes-ni-support-known-p nil)
#+(and sbcl x86-64)
(sb-ext:defglobal aes-ni-supported-p nil)
#+(and sbcl x86-64)
(declaim (inline aes-ni-supported-p))
#+(and sbcl x86-64)
(defun aes-ni-supported-p ()
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  #+ironclad-assembly (if aes-ni-support-known-p
                          aes-ni-supported-p
                          (setf aes-ni-support-known-p t
                                aes-ni-supported-p (aes-ni-support-p)))
  #-ironclad-assembly nil)

;;; CPU vendor detection (also defined in x86oid-vm.lisp for compile-time use).

#+(and sbcl x86-64)
(sb-ext:defglobal *amd-cpu-p* nil)
#+(and sbcl x86-64)
(sb-ext:defglobal *amd-cpu-p-known-p* nil)
#+(and sbcl x86-64)
(defun amd-cpu-p ()
  (if *amd-cpu-p-known-p*
      *amd-cpu-p*
      (setf *amd-cpu-p-known-p* t
            *amd-cpu-p* (with-open-file (stream "/proc/cpuinfo" :if-does-not-exist nil)
                          (when stream
                            (loop for line = (read-line stream nil nil)
                                  while line
                                  when (search "vendor_id" line)
                                  return (not (null (search "AuthenticAMD" line)))))))))

;;; SHA-NI support probe.
;;;;
;;; Deliberately NOT inlined.  Inlining this drags the CPUID VOP into every
;;; caller; when that happens inside the SHA-256 block compressor the
;;; surrounding register state is corrupted and the process takes a memory
;;; fault (observed as a fault at a fixed static-space address, reproducible
;;; with the ETM test vectors).  Keeping the probe behind a real call keeps
;;; CPUID confined to its own tiny function.

#+(and sbcl x86-64)
(sb-ext:defglobal sha-ni-support-known-p nil)
#+(and sbcl x86-64)
(sb-ext:defglobal sha-ni-supported-p nil)
#+(and sbcl x86-64)
(declaim (notinline sha-ni-supported-p))
#+(and sbcl x86-64)
(defun sha-ni-os-supported-p ()
  "Cross-platform SHA-NI detection.

Linux:   check /proc/cpuinfo for the 'sha_ni' flag (most reliable).
macOS:   sysctl hw.optional.sha256 (or hw.optional.sha).
FreeBSD: sysctl hw.instruction_sse or cpu features.
Other:   disabled (no reliable cross-platform detection available)."
  #+linux
  (with-open-file (stream "/proc/cpuinfo" :if-does-not-exist nil)
    (when stream
      (loop for line = (read-line stream nil nil)
            while line
            thereis (and (search "flags" line)
                         (search "sha_ni" line)))))
  #+darwin
  (handler-case
      (let ((output (uiop:run-program '("sysctl" "-n" "hw.optional.sha256")
                                      :ignore-error-status t :output :string)))
        (and output (string/= (string-trim '(#\Space #\Newline) output) "")
             (not (string= (string-trim '(#\Space #\Newline) output) "0"))))
    (error () nil))
  #+freebsd
  (handler-case
      (let ((output (uiop:run-program '("sysctl" "-n" "hw.instruction_sse")
                                      :ignore-error-status t :output :string)))
        (and output (search "SHA" output :test #'char-equal)))
    (error () nil))
  #-(or linux darwin freebsd)
  nil)

#+(and sbcl x86-64)
(defun sha-ni-supported-p ()
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  #+ironclad-assembly
  (if sha-ni-support-known-p
      sha-ni-supported-p
      (setf sha-ni-support-known-p t
            sha-ni-supported-p (sha-ni-os-supported-p)))
  #-ironclad-assembly nil)

#+(and sbcl x86-64)
(sb-ext:defglobal pclmulqdq-support-known-p nil)
#+(and sbcl x86-64)
(sb-ext:defglobal pclmulqdq-supported-p nil)
#+(and sbcl x86-64)
(declaim (inline pclmulqdq-supported-p))
#+(and sbcl x86-64)
(defun pclmulqdq-supported-p ()
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  #+ironclad-assembly (if pclmulqdq-support-known-p
                          pclmulqdq-supported-p
                          (setf pclmulqdq-support-known-p t
                                pclmulqdq-supported-p (pclmulqdq-support-p)))
  #-ironclad-assembly nil)
