;;;; Compare the C reference measurements of two benchmark runs.
;;;;
;;;; Usage: sbcl --load tools/compare-c-references.lisp <amd.sexp> <intel.sexp>

(defpackage :compare-c (:use :cl))
(in-package :compare-c)

(defun read-sexp (path)
  (with-open-file (stream path :element-type 'character)
    (let ((*readtable* (copy-readtable nil)))
      (read stream nil :eof))))

(defun key (entry)
  (list (getf entry :category) (getf entry :algorithm) (getf entry :operation)))

(defun main (&rest args)
  (let* ((amd (read-sexp (first args)))
         (intel (read-sexp (second args)))
         (amd-by-key (make-hash-table :test #'equal))
         (intel-by-key (make-hash-table :test #'equal)))
    (dolist (e amd) (setf (gethash (key e) amd-by-key) e))
    (dolist (e intel) (setf (gethash (key e) intel-by-key) e))
    (let ((rows nil))
      (maphash
       (lambda (k entry)
         (let ((old (gethash k amd-by-key)))
           (when (and old
                      (getf entry :value)
                      (getf old :value)
                      (> (getf old :value) 0))
             (push (list k
                         (getf old :value)
                         (getf entry :value)
                         (/ (getf entry :value) (getf old :value))
                         (getf entry :source))
                   rows))))
       intel-by-key)
      (format t "~&~A~%" (format nil "~50A ~14A ~14A ~8A" "OPERATION" "AMD C" "INTEL C" "RATIO"))
      (dolist (row (sort rows #'> :key (lambda (r) (nth 3 r))))
        (format t "~50A ~14,4f ~14,4f ~8,2f~%"
                (format nil "~A ~A ~A" (first (first row)) (second (first row)) (third (first row)))
                (second row) (third row) (fourth row)))
      (let ((ratios (mapcar (lambda (r) (nth 3 r)) rows)))
        (when ratios
          (format t "~&~D C measurements compared.~%" (length ratios))
          (format t "median ~,2fx   min ~,2fx   max ~,2fx~%"
                  (median ratios) (minimum ratios) (maximum ratios))
          (format t "(> 1 means the C reference is FASTER on the Intel host)~%"))))))

(defun median (numbers)
  (let* ((sorted (sort (copy-list numbers) #'<))
         (n (length sorted)))
    (if (evenp n)
        (/ (+ (nth (1- (/ n 2)) sorted) (nth (/ n 2) sorted)) 2)
        (nth (/ n 2) sorted))))
