;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; check-argument-counts.lisp -- find calls that do not match the
;;;; definition of the function they call.
;;;;
;;;; SBCL warns "The function F is called with N arguments, but wants
;;;; exactly M" when a call does not match the definition, but Ironclad
;;;; muffles the style warnings while it compiles, and the field layer
;;;; is compiled with (safety 0), so such a call is not diagnosed at
;;;; run time either.  The assembly code then uses whatever happened to
;;;; be in the argument register as a pointer.
;;;;
;;;; This script reads the sources and compares every call with the
;;;; definition of the function it calls, so that such a mistake is
;;;; found before it is run.  It only looks at the functions that are
;;;; called with a fixed number of arguments and that are defined with
;;;; a fixed number of required arguments; a function that takes
;;;; keyword arguments, or that is defined by a macro, is skipped,
;;;; because the number of arguments cannot be worked out from the
;;;; source.
;;;;
;;;; The reader follows IN-PACKAGE, because the symbol that names a
;;;; function depends on the package that is current when the form is
;;;; read: a call and its definition only get the same symbol when both
;;;; are read in the same package.
;;;;
;;;; Usage (from the repository root):
;;;;
;;;;   sbcl --load ~/quicklisp/setup.lisp --script tools/check-argument-counts.lisp
;;;;
;;;; Do not add --non-interactive to that line: in this SBCL (2.6.7)
;;;; --non-interactive and --script together do not run the script at
;;;; all, and the exit code is then always 0, so a build would report
;;;; success without having checked anything.
;;;;
;;;; It reports every mismatch, and the files it could not read, and
;;;; exits with
;;;;
;;;;   0  every file was read, and every call matches its definition
;;;;   1  a call does not match its definition
;;;;   2  some file could not be read, so the check is partial
;;;;
;;;; The exit code is 2, not 0, when a file was skipped, so that a
;;;; partial check cannot be mistaken for a clean one.

(require :asdf)
(push (truename #p"./") asdf:*central-registry*)
;; Load the library, so that the packages the sources mention exist.
(asdf:load-system :ironclad-unsafe)

(defpackage :check-argument-counts
  (:use :cl))
(in-package :check-argument-counts)

;;; The definitions we know about: name -> the number of arguments.
(defvar *definitions* (make-hash-table :test #'eq))

;;; The names whose arity cannot be worked out from the source: the ones
;;; that are defined more than once, and the ones that are also used as
;;; a variable, where the name in the call is a local function or a
;;; slot accessor rather than the function that was defined.
(defvar *ambiguous* (make-hash-table :test #'eq))

(defun proper-list-p (form)
  "True when FORM is a proper list.  LISTP is not enough: it only looks
at the first two cells, so it answers T for the dotted list that a
destructuring binding uses."
  (loop for tail = form then (cdr tail)
        while (consp tail)
        finally (return (null tail))))

(defun sub-forms (form)
  "The sub forms of FORM.  A dotted list, as used by a destructuring
binding, has no sub forms."
  (if (proper-list-p form) form nil))

(defun fixed-arity-p (lambda-list)
  "True when the number of arguments that LAMBDA-LIST takes is fixed.
It is not when the list has &optional, &key or &rest: a call with
fewer arguments than the definition wants is then legal."
  (not (some (lambda (arg)
               (or (member arg '(&optional &key &rest &aux))
                   (and (consp arg)
                        (member (car arg) '(&optional &key &rest &aux)))))
             lambda-list)))

(defun required-count (lambda-list)
  "The number of required arguments in LAMBDA-LIST."
  (let ((n 0))
    (dolist (arg lambda-list n)
      (cond ((null arg) (return n))
            ((member arg '(&optional &rest &key &aux)) (return n))
            ((and (consp arg) (member (car arg) '(&optional &rest &key &aux)))
             (return n))
            (t (incf n))))))

;;; ------------------------------------------------------------------
;;; Reading the sources
;;; ------------------------------------------------------------------

(defvar *problems* nil)
(defvar *unreadable* nil)          ; a list of (path . condition)
(defvar *forms-cache* (make-hash-table :test #'equal))

(defun read-error-reason (condition)
  "A short description of CONDITION, which is why a file could not be
read.  The reader reports where it stopped in the message of the
error, so the name of the file is not repeated here."
  (typecase condition
    (simple-error
     (handler-case
         (apply #'format nil (simple-error-format-control condition)
                (simple-error-format-arguments condition))
       (error () (format nil "~A" condition))))
    (t (format nil "~A" condition))))

(defun evaluate-definition-form (form)
  "Evaluate FORM when it defines something.

A file can use a read-time evaluation that needs a constant or a
function that the same file defines: Ironclad's whirlpool does.  The
reader does not evaluate the definitions, so whether the file can be
read at all depends on whether they happen to be visible when the
read-time evaluation is reached.  Evaluating the definitions as they
are read makes the file readable, and the coverage of the check the
same from one run to the next."
  (when (and (consp form) (proper-list-p form))
    (let ((head (car form)))
      (cond
        ((and (symbolp head)
              (member (symbol-name head)
                      '("DEFCONSTANT" "DEFPARAMETER" "DEFVAR" "DEFUN" "DEFMACRO")
                      :test #'string-equal))
         (eval-quietly form))
        ((and (symbolp head) (string-equal (symbol-name head) "EVAL-WHEN"))
         ;; The clauses are (:compile-toplevel ...) (:load-toplevel ...)
         ;; and (:execute ...); the body of the last one is wanted.
         ;; The forms are evaluated one at a time: a constant that is
         ;; already defined, and whose value is not the same, would
         ;; otherwise stop the rest of the body from being evaluated.
         (let ((body (rest (car (last form)))))
           (dolist (form body)
             (eval-quietly form))))))))

(defun eval-quietly (form)
  "Evaluate FORM, ignoring a failure and the style warnings that a
redefinition gives."
  (handler-bind ((style-warning #'muffle-warning))
    (ignore-errors (eval form))))

(defun read-forms-1 (path)
  "Read the forms of PATH.  Returns NIL when the file cannot be read,
which happens for the files that need a package we do not have."
  (handler-case
      (with-open-file (stream path :direction :input :element-type 'character
                                  :external-format :utf-8)
        (let ((forms nil)
              (*package* (find-package :cl-user))
              ;; Ironclad installs a reader macro for the s-box literals
              ;; that it uses; use the same readtable, or the files that
              ;; have them cannot be read at all.
              (*readtable* (if (boundp (find-symbol "*IRONCLAD-READTABLE*" "IRONCLAD"))
                              (symbol-value (find-symbol "*IRONCLAD-READTABLE*" "IRONCLAD"))
                              (copy-readtable nil))))
          (loop for form = (read stream nil :eof)
                until (eq form :eof)
                do (when (and (consp form) (eq (car form) 'in-package)
                              (second form))
                     (let ((pkg (find-package
                                 (if (symbolp (second form))
                                     (symbol-name (second form))
                                     (second form)))))
                       (when pkg (setf *package* pkg))))
                   (evaluate-definition-form form)
                   (push form forms))
          (nreverse forms)))
    (error (c)
      ;; A style warning is not a failure: the file is still read.
      (push (cons path c) *unreadable*)
      nil)))

(defun read-forms (path)
  "The forms of PATH, read once and kept.  Returns NIL when the file
cannot be read."
  (multiple-value-bind (forms presentp) (gethash path *forms-cache*)
    (if presentp
        forms
        (setf (gethash path *forms-cache*) (read-forms-1 path)))))

(defun source-files ()
  (directory "src/**/*.lisp"))

;;; ------------------------------------------------------------------
;;; Collecting the definitions
;;; ------------------------------------------------------------------

(defparameter *definition-forms* '(defun)
  "Only DEFUN is used.  A DEFMETHOD describes one method of a generic
function, whose arity is that of the generic function, so the arity of
a method says nothing about the calls.")

(defun collect-bindings (form)
  "Note the names that are bound as variables, so that a call to a name
that is also a variable is not checked."
  (when (consp form)
    (let ((head (car form)))
      (cond
        ((member head '(let let* lambda flet labels) :test #'eq)
         ;; the binding list
         (let ((bindings (second form)))
           (when (proper-list-p bindings)
             (dolist (binding bindings)
               (when (and (consp binding) (symbolp (car binding)))
                 (setf (gethash (car binding) *ambiguous*) t))))))
        ((member head '(defvar defparameter defconstant defmacro) :test #'eq)
         (let ((name (second form)))
           (when (symbolp name) (setf (gethash name *ambiguous*) t))))
        ((eq head 'defstruct)
         ;; the slot names; the first element is the name of the
         ;; structure, the rest are the slots
         (let ((slots (cddr form)))
           (dolist (slot slots)
             (when (and (consp slot) (symbolp (car slot)))
               (setf (gethash (car slot) *ambiguous*) t)))))
        ((member head '(defknown) :test #'eq)
         ;; the name, or a list of names
         (let ((name (second form)))
           (cond ((symbolp name) (setf (gethash name *ambiguous*) t))
                 ((and (consp name) (every #'symbolp name))
                  (dolist (n name) (setf (gethash n *ambiguous*) t))))))))
      (dolist (sub (sub-forms form)) (collect-bindings sub))))

(defun collect-definitions (form)
  (when (and (consp form) (proper-list-p form)
             (member (car form) *definition-forms* :test #'eq))
    (let* ((name (second form))
           (ll (third form)))
      (when (and (symbolp name) (proper-list-p ll) (fixed-arity-p ll))
        (when (gethash name *definitions*)
          (setf (gethash name *ambiguous*) t))
        (setf (gethash name *definitions*) (required-count ll))))
    (dolist (sub (sub-forms form)) (collect-definitions sub))))

;;; ------------------------------------------------------------------
;;; Checking the calls
;;; ------------------------------------------------------------------

(defun check-call (form path)
  ;; A call is a list whose car is the function that is called.  The
  ;; sub forms are visited whatever they look like: the binding list of
  ;; a LET or a LAMBDA is a list of lists, and the calls are inside it.
  (when (and (consp form) (proper-list-p form))
    (let ((head (car form)))
      ;; A name that is defined more than once cannot be checked: the
      ;; arity that the compiler sees depends on which definition is
      ;; current.
      (when (and (gethash head *definitions*)
                 (not (gethash head *ambiguous*)))
        (let* ((required (gethash head *definitions*))
               (given (length (rest form))))
          (unless (= given required)
            (push (list :path path :name head
                        :required required :given given)
                  *problems*))))))
  ;; The body of a DEFKNOWN is a type declaration, not code.  The
  ;; symbol lives in SB-C, so it is recognized by its name.
  (when (and (consp form) (proper-list-p form)
             (not (and (symbolp (car form))
                       (string-equal (symbol-name (car form)) "DEFKNOWN"))))
    (dolist (sub (sub-forms form)) (check-call sub path))))

;;; ------------------------------------------------------------------
;;; Main
;;; ------------------------------------------------------------------

(defun main (&rest args)
  (declare (ignore args))
  (let ((files (source-files)))
    (format t "~&~D source files.~%" (length files))
    ;; First pass: the definitions.
    (dolist (path files)
      (dolist (form (read-forms path))
        (collect-definitions form)))
    ;; The names that cannot be checked.
    (dolist (path files)
      (dolist (form (read-forms path))
        (collect-bindings form)))
    (format t "~&~D definitions with a fixed arity known.~%"
            (hash-table-count *definitions*))
    ;; Second pass: the calls.
    (dolist (path files)
      (dolist (form (read-forms path))
        (check-call form path)))
    (when *unreadable*
      (format t "~&~D files could not be read and were skipped:~%"
              (length *unreadable*))
      (dolist (entry (sort (copy-list *unreadable*) #'string<
                           :key (lambda (e) (namestring (pathname (car e))))))
        (format t "  ~A~%    ~A~%" (pathname (car entry))
                (read-error-reason (cdr entry)))))
    (format t "~&-- calls that do not match the definition --~%")
    (if (null *problems*)
        (format t "none found~%")
        (dolist (problem (sort (copy-list *problems*) #'string<
                               :key (lambda (p) (format nil "~A ~A"
                                                         (pathname (getf p :path))
                                                         (getf p :name)))))
          (format t "~A: (~A ...) is called with ~A arguments, but wants ~A~%"
                  (pathname (getf problem :path)) (getf problem :name)
                  (getf problem :given) (getf problem :required))))
    (when *problems*
      (format t "~&~D mismatches found.~%" (length *problems*))
      (sb-ext:exit :code 1))
    (when *unreadable*
      ;; The check is partial: the files above were not read, so the
      ;; verdict is about the rest of the sources only.
      (format t "~&The check is partial: the files above were not read.~%")
      (sb-ext:exit :code 2))
    (format t "~&All calls match their definition.~%")))

(main)
