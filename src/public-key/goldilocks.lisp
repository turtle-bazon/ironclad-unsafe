;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; goldilocks.lisp -- the field of the Ed448 and Curve448 curves
;;;;
;;;; Both curves are defined over the "Goldilocks" prime
;;;;
;;;;   q = 2^448 - 2^224 - 1
;;;;
;;;; The shape of the prime makes a reduction much cheaper than the
;;;; general remainder: since 2^448 is congruent to 2^224 + 1 modulo
;;;; q, the high half of a value can simply be folded back into the
;;;; low half, with a shift and an addition.  A division, which is
;;;; several times more expensive than a multiplication, is not needed
;;;; at all.

(in-package :crypto)

(defconstant +goldilocks-q+
  726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439)

;;; The mask of the low 448 bits, and the value of 2^448.
(defconstant +goldilocks-q-mask+ (1- (ash 1 448)))
(defconstant +goldilocks-q-top+ (ash 1 448))

;;; Above this size the value needs more than one fold, and the
;;; division of the general remainder, which is written in C, is
;;; cheaper than the folds, each of which allocates.
(defconstant +goldilocks-q-fold-limit+ (ash 1 672))

(defun goldilocks-reduce (v)
  "Reduce the integer V into the range [0, +goldilocks-q+).
V may be of any size, and may be negative."
  (declare (type integer v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (if (minusp v)
      ;; The reduction of the absolute value, complemented: the
      ;; reduction of -v is q minus the reduction of v, unless the
      ;; latter is zero.
      (let ((r (goldilocks-reduce (- v))))
        (if (zerop r) 0 (- +goldilocks-q+ r)))
      (if (>= v +goldilocks-q-fold-limit+)
          ;; A large value, such as the product of two field elements.
          ;; The division is the cheaper of the two ways of reducing it.
          (mod v +goldilocks-q+)
          (let ((mask +goldilocks-q-mask+))
            ;; Fold the high half of the value back into the low half,
            ;; for as long as the value does not fit into 448 bits.
            ;; Since 2^448 = 2^224 + 1 modulo q, the high half is added
            ;; once at the bottom and once shifted up by 224 bits.
            (loop while (>= v +goldilocks-q-top+)
                  do (let ((hi (ash v -448)))
                       (setf v (+ (logand v mask) hi (ash hi 224)))))
            ;; The value now fits into 448 bits, so at most one
            ;; subtraction of the prime is needed.
            (if (>= v +goldilocks-q+)
                (- v +goldilocks-q+)
                v)))))
