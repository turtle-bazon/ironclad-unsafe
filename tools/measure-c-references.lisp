;;;; Measure the C reference on this machine, without running the whole
;;;; Lisp benchmark.  This is the C half of benchmark/benchmark-all.lisp:
;;;; the local C binaries under benchmark/c-bin/ and the system OpenSSL.
;;;;
;;;; Usage (from the repository root):
;;;;
;;;;   sbcl --load ~/quicklisp/setup.lisp --load tools/measure-c-references.lisp

(require :asdf)
(push (truename #p"./") asdf:*central-registry*)
(asdf:load-system :ironclad-unsafe)

(defpackage :measure-c
  (:use :cl))
(in-package :measure-c)

(defun run-program (cmd args)
  "Run CMD with ARGS and return its output as a string."
  (handler-case
      (uiop:run-program (cons cmd args)
                        :output :string
                        :error-output :string
                        :ignore-error-status t)
    (error () "")))

(defun parse-number (string)
  "Parse STRING as a number, or return NIL."
  (let ((*read-eval* nil))
    (ignore-errors
      (let ((n (read-from-string string)))
        (if (realp n) n nil)))))
(defun parse-key-value-lines (text)
  "Parse the KEY=VALUE lines of TEXT into an alist of numbers."
  (let ((result nil))
    (dolist (line (uiop:split-string text :separator '(#\Newline)))
      (let ((pos (position #\= line)))
        (when pos
          (let* ((key (string-upcase (string-trim " " (subseq line 0 pos))))
                 (value (string-trim " " (subseq line (1+ pos)))))
            (multiple-value-bind (number end)
                (parse-number value)
              (declare (ignore end))
              (when number
                (push (cons key number) result)))))))
    (nreverse result)))

(defvar *c-binaries*
  '("hqc-128" "hqc-192" "hqc-256"
    "mceliece348864-clean" "mceliece348864-avx2" "mceliece460896" "mceliece6688128"
    "mceliece6960119" "mceliece8192128"
    "falcon-512-clean" "falcon-512-avx2"
    "mldsa-44-ref" "mldsa-65-ref" "mldsa-87-ref"
    "mldsa-44-avx2" "mldsa-65-avx2" "mldsa-87-avx2"
    "xmss-sha2_10_256"))

(format t "~&-- local C references --~%")
(dolist (name *c-binaries*)
  (let* ((path (merge-pathnames (format nil "benchmark/c-bin/~A" name)))
         (text (if (probe-file path) (run-program (namestring path) '("1")) "")))
    (let ((values (parse-key-value-lines text)))
      (format t "~A~%" name)
      (dolist (key '("KEYGEN_MS" "ENCAPS_MS" "DECAPS_MS" "SIGN_MS" "VERIFY_MS"))
        (let ((entry (assoc key values :test #'equal)))
          (when entry
            (format t "    ~A ~,4f ops/s~%" key (/ 1000.0d0 (cdr entry)))))))))

(format t "~&-- OpenSSL --~%")
(dolist (spec '("sha256" "sha512" "sha1" "md5" "sha3-256"
                "chacha20-poly1305" "chacha20" "aes-256-cbc" "aes-128-gcm"
                "ecdsa-with-SHA256" "ed25519" "x25519" "rsa2048"))
  (let ((text (run-program "openssl" (list "speed" "-seconds" "1" spec))))
    (format t "~A:~%" spec)
    (dolist (line (uiop:split-string text :separator '(#\Newline)))
      (when (search "k" line)
        (format t "    ~A~%" (string-trim " " line))))))
