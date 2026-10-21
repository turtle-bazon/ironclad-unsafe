;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; all-algorithms-md.lisp -- build benchmark/all-algorithms.md.
;;;;
;;;; Usage (from the repository root):
;;;;
;;;;   sbcl --load ~/quicklisp/setup.lisp --script benchmark/all-algorithms-md.lisp
;;;;
;;;; The .md file is the human readable summary of the benchmark: the
;;;; current Lisp results from benchmark/all-algorithms.org, the results
;;;; of the first full benchmark run from
;;;; benchmark/all-algorithms-initial.org, and the C reference.  The
;;;; C reference is taken from the .org file, which records it next to
;;;; every Lisp measurement.
;;;;
;;;; The values are printed with a readable suffix, so 12180 is shown as
;;;; "12.18k"; the ratios are plain numbers with two decimals.

(require 'asdf)

(defpackage :all-algorithms-md
  (:use :cl))
(in-package :all-algorithms-md)

(defparameter *current* #P"benchmark/all-algorithms.org")
(defparameter *initial* #P"benchmark/all-algorithms-initial.org")
(defparameter *output* #P"benchmark/all-algorithms.md")

(defun split (string separator)
  "Split STRING on SEPARATOR, a character."
  (let ((parts nil)
        (start 0)
        (length (length string)))
    (loop for i from 0 below length
          when (char= (char string i) separator)
            do (push (subseq string start i) parts)
             (setf start (1+ i)))
    (push (subseq string start) parts)
    (nreverse parts)))

(defun read-table (path)
  "Read the table in PATH and return it as a list of rows.
Each row is a list of the column values, as strings."
  (with-open-file (stream path :direction :input :element-type 'character)
    (let ((rows nil))
      (loop for line = (read-line stream nil nil)
            while line
            do (when (and (> (length line) 0)
                          (char= (char line 0) #\|))
                 (let ((cells (mapcar (lambda (c) (string-trim " " (or c "")))
                                       (split (string-trim "|" line) #\|))))
                   (unless (or (member (first cells) '("Category" "---") :test #'string=)
                               ;; The separator row of the table.
                               (every (lambda (c)
                                        (every (lambda (ch) (char= ch #\-)) c))
                                      cells))
                     (push cells rows)))))
      (nreverse rows))))

(defun parse-scaled (text)
  "Parse TEXT, which is a number with an optional k/M/G suffix, into a
float.  Returns NIL when TEXT is not a number."
  (let ((text (string-trim " " text)))
    (when (plusp (length text))
      (let* ((suffix (char text (1- (length text))))
             (body (if (find suffix "kMG")
                       (subseq text 0 (1- (length text)))
                       text))
             (scale (cond ((char= suffix #\k) 1e3)
                           ((char= suffix #\M) 1e6)
                           ((char= suffix #\G) 1e9)
                           (t 1)))
             (value (read-from-string body nil nil)))
        (when (numberp value)
          (* value scale))))))

(defun strip-trailing-zeros (text)
  "Remove the trailing zeros and the trailing decimal point from TEXT."
  (let ((text text)
        (dot (position #\. text)))
    (when dot
      (loop while (and (> (length text) dot)
                       (char= (char text (1- (length text))) #\0))
            do (setf text (subseq text 0 (1- (length text)))))
      (when (and (= (length text) (1+ dot))
                 (char= (char text dot) #\.))
        (setf text (subseq text 0 dot))))
    text))

(defun format-scaled (value)
  "Format VALUE with a readable suffix."
  (cond ((null value) "-")
        ((>= value 1e9) (format nil "~,3fG" (/ value 1e9)))
        ((>= value 1e6) (format nil "~,3fM" (/ value 1e6)))
        ((>= value 1e3) (format nil "~,3fk" (/ value 1e3)))
        ;; A value below a thousand is printed with at most three
        ;; decimals and without trailing zeros.
        (t (strip-trailing-zeros (format nil "~,3f" value)))))

(defun row-key (row)
  "The identity of a row: category, algorithm and operation."
  (list (nth 0 row) (nth 1 row) (nth 2 row)))

(defun build ()
  (let* ((current (read-table *current*))
         (initial (read-table *initial*))
         (initial-by-key (make-hash-table :test #'equal))
         (rows nil))
    (dolist (row initial)
      (setf (gethash (row-key row) initial-by-key) row))
    (dolist (row current)
      (let* ((key (row-key row))
             (old (gethash key initial-by-key))
             (lisp (parse-scaled (nth 4 row)))
             (c (parse-scaled (nth 5 row)))
             (old-lisp (and old (parse-scaled (nth 4 old))))
             (old-c (and old (parse-scaled (nth 5 old)))))
        (push (list :key key
                    :unit (nth 3 row)
                    :old-lisp old-lisp
                    :lisp lisp
                    :old-c old-c
                    :c c)
              rows)))
    (nreverse rows)))

(defun speed-ratio (c lisp)
  (and c lisp (plusp lisp) (/ c lisp)))

(defun emit (rows)
  (with-open-file (stream *output* :direction :output :if-exists :supersede
                          :if-does-not-exist :create :element-type 'character)
    (flet ((emit (fmt &rest args)
             (apply #'format stream fmt args)
             (terpri stream)))
      (emit "# Ironclad all-algorithm benchmark: Lisp initial/current vs C reference")
      (emit "")
      (emit "Full ungrouped results generated by `benchmark/benchmark-all.lisp`.")
      (emit "")
      (emit "`Lisp initial` comes from the first full all-algorithm snapshot in `benchmark/all-algorithms-initial.org` from hg rev `747:c8e0303d1c04`.")
      (emit "`Lisp current` comes from the latest benchmark run.")
      (emit "`C reference` is the current local C reference measurement; there are no initial/current C columns.")
      (emit "Values use readable suffixes, so `12.18k` means 12180.")
      (emit "Sorted by current C/Lisp ratio, descending. Rows without a C reference are listed last.")
      (emit "`C/Lisp` is C reference divided by Lisp speed, so higher values mean a larger Lisp slowdown.")
      (emit "")
      (emit "| Category | Algorithm | Operation | Unit | Lisp initial | Lisp current | C reference | C/Lisp initial | C/Lisp current |")
      (emit "|---|---|---|---|---:|---:|---:|---:|---:|")
      (let ((sorted (stable-sort (copy-list rows)
                              (lambda (a b)
                                (let ((ra (speed-ratio (getf a :c) (getf a :lisp)))
                                      (rb (speed-ratio (getf b :c) (getf b :lisp))))
                                  (cond ((and ra rb) (> ra rb))
                                        ((and ra (not rb)) t)
                                        ((and (not ra) rb) nil)
                                        (t nil)))))))
        (dolist (row sorted)
          (let* ((key (getf row :key))
                 (old-lisp (getf row :old-lisp))
                 (lisp (getf row :lisp))
                 (c (getf row :c))
                 (old-ratio (speed-ratio (getf row :old-c) old-lisp))
                 (new-ratio (speed-ratio c lisp))
                 (cells (list (first key) (second key) (third key)
                              (getf row :unit)
                              (format-scaled old-lisp)
                              (format-scaled lisp)
                              (format-scaled c)
                              (if old-ratio (format nil "~,2f" old-ratio) "-")
                              (if new-ratio (format nil "~,2f" new-ratio) "-"))))
            (emit "| ~{~A~^ | ~} |" cells)))))))

(let ((rows (build)))
  (emit rows)
  (format t "~&Wrote ~A~%" *output*))
