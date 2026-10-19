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

;;; SHA-NI runtime probe: actually execute a SHA-NI instruction and catch
;;; SIGILL.  Used to detect environments where CPUID advertises SHA-NI but
;;; the instructions are not executable.
#+(and sbcl x86-64 ironclad-assembly)
(defun sha-ni-probe ()
  (catch 'sha-ni-sigill
    (sb-sys:enable-interrupt sb-unix:sigill
      (lambda (signal code frame)
        (declare (ignore signal code frame))
        (throw 'sha-ni-sigill nil)))
    (let ((compress (find-symbol "SHA256NI-COMPRESS" :crypto)))
      (when compress
        (let ((regs (make-array 8 :element-type '(unsigned-byte 32) :initial-element 0))
              (block (make-array 64 :element-type '(unsigned-byte 32) :initial-element 0)))
          (funcall compress regs block))))
    (sb-sys:enable-interrupt sb-unix:sigill :default)
    t))

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
(defun sha-ni-supported-p ()
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  ;; SHA-NI can be disabled at runtime.  In virtualised or containerised
  ;; environments the CPUID leaf that advertises SHA-NI is sometimes passed
  ;; through from a host that has it, while the SHA-NI instructions
  ;; themselves are not executable there (observed as SIGILL).  CPUID alone
  ;; cannot detect this, so we probe by actually executing a SHA-NI
  ;; instruction behind a SIGILL handler.
  (cond (#-ironclad-assembly nil
         #+ironclad-assembly
         (if sha-ni-support-known-p
             sha-ni-supported-p
             (setf sha-ni-support-known-p t
                   sha-ni-supported-p
                   (and (sha-ni-support-p)
                        (sha-ni-probe)))))))

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
