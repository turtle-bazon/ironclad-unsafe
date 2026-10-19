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
(defun sha-ni-probe-via-subprocess ()
  "Probe SHA-NI by running a tiny test program in a subprocess.
Returns T if SHA-NI works, NIL if it SIGILLs or is unavailable."
  (let ((test-file "/tmp/sha_ni_probe_test.s")
        (obj-file "/tmp/sha_ni_probe_test.o")
        (bin-file "/tmp/sha_ni_probe_test"))
    (handler-case
        (progn
          (with-open-file (s test-file :direction :output :if-exists :supersede)
            (format s ".globl _start~%_start:~%")
            (if (amd-cpu-p)
                (format s "    .byte 0x0F, 0x38, 0xCB, 0xD1~%")
                (format s "    .byte 0x66, 0x0F, 0x38, 0xCB, 0xD1, 0x00~%"))
            (write-string "    movq $60, %rax
    xorq %rdi, %rdi
    syscall
" s))
          (let ((as-result (sb-ext:run-program "as" (list test-file "-o" obj-file)
                                               :search t :wait t)))
            (unless (and as-result (zerop (sb-ext:process-exit-code as-result)))
              (return-from sha-ni-probe-via-subprocess nil)))
          (let ((ld-result (sb-ext:run-program "ld" (list obj-file "-o" bin-file)
                                               :search t :wait t)))
            (unless (and ld-result (zerop (sb-ext:process-exit-code ld-result)))
              (return-from sha-ni-probe-via-subprocess nil)))
          (let ((run-result (sb-ext:run-program bin-file nil :search nil :wait t)))
            (and run-result (zerop (sb-ext:process-exit-code run-result)))))
      (error (c)
        (declare (ignore c))
        nil))))

#+(and sbcl x86-64)
(defun sha-ni-supported-p ()
  (declare (optimize (speed 3) (space 0) (debug 0) (safety 0)))
  #+ironclad-assembly
  (if sha-ni-support-known-p
      sha-ni-supported-p
      (setf sha-ni-support-known-p t
            sha-ni-supported-p
            (and (sha-ni-support-p)
                 (sha-ni-probe-via-subprocess))))
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
