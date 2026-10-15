;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;; run-selected-tests.lisp -- run Ironclad tests selectively with progress markers
;;;
;;; This file is normally loaded by tools/run-cross-lisp-tests.sh after
;;; :ironclad/tests has been loaded.
;;;
;;; Select tests by setting IRONCLAD_TESTS to a whitespace- or comma-separated
;;; list of test names or case-insensitive substrings:
;;;
;;;   IRONCLAD_TESTS='prng-fortuna sha512/256' \
;;;     tools/run-cross-lisp-tests.sh sbcl-bin
;;;   IRONCLAD_TESTS='mceliece' tools/run-cross-lisp-tests.sh ecl abcl-bin
;;;
;;; Substring matching makes it easy to stop later if a slow test is reached.
;;; With no selection, the complete Ironclad regression suite runs.

(require :asdf)
(push #p"./" asdf:*central-registry*)

(unless (find-package :regression-test)
  (ql:quickload :rt))

(unless (find-package :ironclad-tests)
  (asdf:load-system :ironclad/tests))

(defpackage #:ironclad-test-runner
  (:use #:cl))

(in-package #:ironclad-test-runner)

(defun selected-patterns ()
  "Return the requested test name patterns as a list of strings."
  (let ((value (uiop:getenv "IRONCLAD_TESTS")))
    (if (or (null value) (string= value ""))
        '()
        (remove-if #'uiop:emptyp
                   (uiop:split-string
                    value
                    :separator '(#\Space #\Tab #\Newline #\Return #\, #\;))))))

(defun normalize-pattern (pattern)
  (string-left-trim ":" (string-trim '(#\Space #\Tab) pattern)))

(defun all-test-names ()
  "Return Ironclad test names in definition order."
  (copy-list (rt:pending-tests)))

(defun matching-test-names (pattern)
  (let ((needle (normalize-pattern pattern)))
    (remove-if-not (lambda (name)
                     (search needle (string name) :test #'char-equal))
                   (all-test-names))))

(defun selected-test-names (patterns)
  (remove-duplicates
   (loop for pattern in patterns
         append (matching-test-names pattern))
   :from-end t))

(defun report-selected-tests (names)
  (format t "~&Selected ~A test~:P: ~{~S~^, ~}~%" (length names) names)
  (finish-output))

(defun run-test (name)
  "Run one test and report exactly where it starts and ends."
  (format t "~&=== TEST START ~S ===~%" name)
  (force-output *standard-output*)
  (finish-output *standard-output*)
  (block run-test
    (handler-bind ((error (lambda (condition)
                            (format t "~&=== TEST ERROR ~S: ~A ===~%"
                                    name condition)
                            (finish-output *standard-output*)
                            (return-from run-test :error))))
      (let ((result (rt:do-test name)))
        (cond
          ((eq result name)
           (format t "~&=== TEST PASS ~S ===~%" name)
           (finish-output *standard-output*)
           :pass)
          (t
           (format t "~&=== TEST FAIL ~S ===~%" name)
           (finish-output *standard-output*)
           :fail))))))

(defun print-test-names ()
  (dolist (name (all-test-names))
    (format t "~A~%" name))
  (finish-output))

(defun finish (status failed-tests)
  (fresh-line)
  (format t "IRONCLAD-TEST-STATUS: ~A~%" status)
  (when failed-tests
    (format t "IRONCLAD-TEST-FAILURES: ~{~S~^, ~}~%" failed-tests))
  (format t "IRONCLAD-TEST-PROCESS: DONE~%")
  (finish-output)
  (unless (eq status :pass)
    (uiop:quit 1)))

(let ((patterns (selected-patterns)))
  (cond
    ((string= (or (uiop:getenv "IRONCLAD_TEST_ACTION") "run") "list")
     (print-test-names))
    ((null patterns)
     (format t "~&Running full Ironclad test suite.~%")
     (finish-output)
     (let ((succeeded (rt:do-tests)))
       (finish (if succeeded :pass :fail)
               (unless succeeded '(:full-suite)))))
    (t
     (let ((names (selected-test-names patterns)))
       (report-selected-tests names)
       (let ((failed '()))
         (dolist (name names)
           (let ((status (run-test name)))
             (unless (eq status :pass)
               (push name failed))))
         (finish (if failed :fail :pass) (reverse failed)))))))
