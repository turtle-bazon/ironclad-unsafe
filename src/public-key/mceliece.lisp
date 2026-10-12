;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; mceliece.lisp -- Classic McEliece KEM, mceliece348864 (level 1)
;;;;
;;;; Direct translation of the PQClean clean implementation:
;;;; GF(2^12) arithmetic, Goppa support, Patterson decoding.

(in-package :crypto)


;;;
;;; Parameters (mceliece348864)
;;;

(defconstant +mce-gfbits+ 12)
(defconstant +mce-sys-n+ 3488)
(defconstant +mce-sys-t+ 64)
(defconstant +mce-cond-bytes+ 2088)
(defconstant +mce-irr-bytes+ 128)
(defconstant +mce-pk-nrows+ 768)
(defconstant +mce-pk-ncols+ 2720)
(defconstant +mce-pk-row-bytes+ 340)
(defconstant +mce-synd-bytes+ 96)
(defconstant +mce-gfmask+ #xFFF)
(defconstant +mce-pk-bytes+ 261120)
(defconstant +mce-sk-bytes+ 6492)
(defconstant +mce-ct-bytes+ 96)
(defconstant +mce-ss-bytes+ 32)


;;;
;;; GF(2^12) = GF(2)[x]/(x^12 + x^3 + 1)
;;;

(declaim (inline mce-gf-add))
(defun mce-gf-add (a b)
  (logxor a b))

(defun mce-gf-mul (a b)
  (let ((tmp 0))
    (dotimes (i +mce-gfbits+)
      (when (logbitp i b)
        (setf tmp (logxor tmp (ash a i)))))
    ;; reduce x^12 = x^3 + 1
    (let ((tt (logand tmp #x7FC000)))
      (setf tmp (logxor tmp (ash tt -9) (ash tt -12))))
    (let ((tt (logand tmp #x3000)))
      (setf tmp (logxor tmp (ash tt -9) (ash tt -12))))
    (logand tmp +mce-gfmask+)))

(defun mce-gf-sq (a)
  (let ((x a))
    (setf x (logand (logior x (ash x 8)) #x00FF00FF))
    (setf x (logand (logior x (ash x 4)) #x0F0F0F0F))
    (setf x (logand (logior x (ash x 2)) #x33333333))
    (setf x (logand (logior x (ash x 1)) #x55555555))
    (let ((tt (logand x #x7FC000)))
      (setf x (logxor x (ash tt -9) (ash tt -12))))
    (let ((tt (logand x #x3000)))
      (setf x (logxor x (ash tt -9) (ash tt -12))))
    (logand x +mce-gfmask+)))

(defun mce-gf-inv (a)
  (let* ((out (mce-gf-sq a))
         (tmp-11 (mce-gf-mul out a)))
    (setf out (mce-gf-sq (mce-gf-sq tmp-11)))
    (let ((tmp-1111 (mce-gf-mul out tmp-11)))
      (setf out (mce-gf-sq (mce-gf-sq (mce-gf-sq (mce-gf-sq tmp-1111)))))
      (setf out (mce-gf-mul out tmp-1111))
      (setf out (mce-gf-sq (mce-gf-sq out)))
      (setf out (mce-gf-mul out tmp-11))
      (setf out (mce-gf-sq out))
      (setf out (mce-gf-mul out a))
      (mce-gf-sq out))))

(declaim (inline mce-gf-frac))
(defun mce-gf-frac (den num)
  (mce-gf-mul (mce-gf-inv den) num))

(defun mce-gf-poly-mul (out in0 in1)
  "Multiply degree<SYS_T polys mod x^64 + x^3 + 1 (Goppa reduction)."
  (let ((prod (make-array (1- (* 2 +mce-sys-t+)) :initial-element 0)))
    (dotimes (i +mce-sys-t+)
      (dotimes (j +mce-sys-t+)
        (setf (aref prod (+ i j))
              (logxor (aref prod (+ i j))
                      (mce-gf-mul (aref in0 i) (aref in1 j))))))
    (loop for i from (* 2 (1- +mce-sys-t+)) downto +mce-sys-t+
          do (setf (aref prod (+ (- i +mce-sys-t+) 3))
                   (logxor (aref prod (+ (- i +mce-sys-t+) 3)) (aref prod i))
                   (aref prod (+ (- i +mce-sys-t+) 1))
                   (logxor (aref prod (+ (- i +mce-sys-t+) 1)) (aref prod i))
                   (aref prod (+ (- i +mce-sys-t+) 0))
                   (logxor (aref prod (+ (- i +mce-sys-t+) 0))
                           (mce-gf-mul (aref prod i) 2))))
    (dotimes (i +mce-sys-t+ out)
      (setf (aref out i) (aref prod i)))))
