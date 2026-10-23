;;;; -*- mode: lisp, indent-tabs-mode: nil -*-
;;;;
;;;; text.lisp -- convenience functions for text handling

(in-package :ironclad-unsafe)

(defun execute-with-digesting-text-stream (digest format fn)
  (with-open-stream (stream (ironclad-unsafe:make-digesting-stream digest))
    (with-open-stream (text-stream (flexi-streams:make-flexi-stream
                                    stream :external-format (flexi-streams:make-external-format format)))
      (funcall fn text-stream)
      (finish-output text-stream)
      (ironclad-unsafe:produce-digest stream))))

(defmacro with-digesting-text-stream ((var digest &key (external-format :utf-8)) &body body)
  `(execute-with-digesting-text-stream ,digest ,external-format (lambda (,var) ,@body)))

