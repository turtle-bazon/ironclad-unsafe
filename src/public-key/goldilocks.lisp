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


;;; ------------------------------------------------------------------
;;; The field in limbs
;;;;
;;; A field element is eight limbs of 56 bits, each held in a word of
;;; 64 bits.  The limbs are not always reduced: the intermediate
;;; results of a multiplication need a few more bits than 56, and are
;;; brought back into range by the reduction.

(defconstant +goldilocks-limb-bits+ 56)
(defconstant +goldilocks-limb-mask+ (1- (ash 1 56)))
(defconstant +goldilocks-limbs+ 8)

(deftype goldilocks-fe () '(simple-array (unsigned-byte 64) (8)))
(deftype goldilocks-product () '(simple-array (unsigned-byte 64) (16)))

(defun goldilocks-fe-zero ()
  "The field element zero."
  (make-array 8 :element-type '(unsigned-byte 64) :initial-element 0))

(defun goldilocks-fe-one ()
  "The field element one."
  (let ((a (make-array 8 :element-type '(unsigned-byte 64) :initial-element 0)))
    (setf (aref a 0) 1)
    a))

(defun goldilocks-fe-from-int (n)
  "The field element N, which must not be negative."
  (declare (type integer n))
  (let ((a (make-array 8 :element-type '(unsigned-byte 64) :initial-element 0)))
    (dotimes (i 8 n)
      (setf (aref a i) (logand n +goldilocks-limb-mask+))
      (setf n (ash n -56)))
    a))

(defun goldilocks-fe-to-int (a)
  "The integer value of the field element A."
  (declare (type goldilocks-fe a))
  (let ((v 0))
    (dotimes (i 8 v)
      (setf v (+ v (ash (aref a i) (* 56 i)))))))

(defun goldilocks-fe-mul-raw (r a b)
  "R := A * B, as sixteen limbs of 56 bits, without any reduction.
This is the portable version; the assembly version is faster."
  (declare (type goldilocks-fe a b)
           (type goldilocks-product r)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (k 16) (setf (aref r k) 0))
  (dotimes (i 8)
    (let ((carry 0))
      (declare (type integer carry))
      (dotimes (j 8)
        (let* ((prod (* (aref a i) (aref b j)))
               (plo (logand prod +goldilocks-limb-mask+))
               (phi (ash prod -56))
               (k (+ i j))
               (s (+ (aref r k) plo carry)))
          (setf (aref r k) (logand s +goldilocks-limb-mask+)
                carry (+ (ash s -56) phi))))
      ;; The carry can be as large as a limb, so it has to be
      ;; propagated into the higher limbs.
      (loop for k from (+ i 8) below 16
            while (plusp carry)
            do (let ((s (+ (aref r k) carry)))
                 (setf (aref r k) (logand s +goldilocks-limb-mask+)
                       carry (ash s -56))))))
  r)

(defun goldilocks-fe-reduce8 (c)
  "Reduce the eight limbs of C, which may be loose, modulo the prime.
The result is in C, and is below the prime."
  (declare (type goldilocks-fe c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; Bring the limbs back into range.  While the value is above 2^448
  ;; bits, the excess is congruent to itself plus itself shifted up by
  ;; 224 bits, since 2^448 = 2^224 + 1 modulo the prime.
  (loop
    (let ((carry 0))
      (declare (type integer carry))
      (dotimes (i 7)
        (let* ((v (+ (aref c i) carry))
               (lo (logand v +goldilocks-limb-mask+)))
          (setf (aref c i) lo
                carry (ash v -56))))
      (let* ((v (+ (aref c 7) carry))
             (lo (logand v +goldilocks-limb-mask+)))
        (setf (aref c 7) lo
              carry (ash v -56)))
      (when (zerop carry) (return))
      (setf (aref c 0) (+ (aref c 0) carry)
            (aref c 4) (+ (aref c 4) carry))))
  ;; The value is now below 2^448, so the prime is 2^448 - 2^224 - 1
  ;; and the value is at least the prime exactly when the addition of
  ;; 2^224 + 1 reaches 2^448.
  (let ((carry 0))
    (declare (type integer carry))
    ;; The addition is only used to find out whether the value reaches
    ;; 2^448, so the limbs themselves are left alone.
    (dotimes (i 8)
      (let* ((add (if (or (= i 0) (= i 4)) 1 0))
             (v (+ (aref c i) add carry)))
        (setf carry (ash v -56))))
    (when (= carry 1)
      ;; Subtract the prime, whose limbs are all 2^56 - 1 except the
      ;; fifth, which is 2^56 - 2.
      (let ((borrow 0))
        (declare (type integer borrow))
        (dotimes (i 8)
          (let* ((qi (if (= i 4) (- +goldilocks-limb-mask+ 1) +goldilocks-limb-mask+))
                 (v (- (aref c i) qi borrow)))
            (setf (aref c i) (logand v +goldilocks-limb-mask+)
                  borrow (if (minusp v) 1 0)))))))
  c)

(defun goldilocks-fe-reduce16 (c)
  "Reduce the sixteen limbs of C, a product, modulo the prime.
The result is in the low eight limbs of C; the others are clobbered."
  (declare (type goldilocks-product c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; The product is the low half plus the high half shifted up by 448
  ;; bits, and 2^448 = 2^224 + 1 modulo the prime, so the high half is
  ;; added once at the bottom and once shifted up by 224 bits.
  (dotimes (i 8)
    (setf (aref c i) (+ (aref c i) (aref c (+ i 8)))))
  (dotimes (i 4)
    (setf (aref c (+ 4 i)) (+ (aref c (+ 4 i)) (aref c (+ 8 i)))
          (aref c (+ 8 i)) (aref c (+ 12 i))))
  ;; What is left above 2^448 bits is folded back in as well.
  (dotimes (i 4)
    (setf (aref c i) (+ (aref c i) (aref c (+ 8 i)))
          (aref c (+ 4 i)) (+ (aref c (+ 4 i)) (aref c (+ 8 i)))))
  (let ((r (make-array 8 :element-type '(unsigned-byte 64) :initial-element 0)))
    (dotimes (i 8) (setf (aref r i) (aref c i)))
    (goldilocks-fe-reduce8 r)
    (dotimes (i 8) (setf (aref c i) (aref r i)))
    c))

(defun goldilocks-fe-mul (a b)
  "The product of the field elements A and B, reduced."
  (declare (type goldilocks-fe a b))
  (let ((prod (make-array 16 :element-type '(unsigned-byte 64) :initial-element 0)))
    (declare (type goldilocks-product prod))
    (goldilocks-fe-mul-raw prod a b)
    (goldilocks-fe-reduce16 prod)
    (let ((r (make-array 8 :element-type '(unsigned-byte 64) :initial-element 0)))
      (dotimes (i 8) (setf (aref r i) (aref prod i)))
      r)))

(defun goldilocks-fe-add (a b)
  "The sum of the field elements A and B, reduced."
  (declare (type goldilocks-fe a b))
  (let ((r (make-array 8 :element-type '(unsigned-byte 64) :initial-element 0)))
    (dotimes (i 8) (setf (aref r i) (+ (aref a i) (aref b i))))
    (goldilocks-fe-reduce8 r)
    r))

(defun goldilocks-fe-sub (a b)
  "The difference of the field elements A and B, reduced."
  (declare (type goldilocks-fe a b))
  (let ((r (make-array 8 :element-type '(unsigned-byte 64) :initial-element 0)))
    (let ((borrow 0))
      (dotimes (i 8)
        (let* ((v (- (aref a i) (aref b i) borrow))
               (lo (logand v +goldilocks-limb-mask+)))
          (setf (aref r i) lo
                borrow (if (minusp v) 1 0))))
    ;; A borrow means that the difference is negative.  The prime is
    ;; 2^448 less 2^224 + 1, so the prime has to be added, which is
    ;; the same as subtracting 2^224 + 1 from the 2^448 that the limbs
    ;; hold.
    (when (= borrow 1)
      (let ((borrow 0))
        (dotimes (i 8)
          (let* ((sub (if (or (= i 0) (= i 4)) 1 0))
                 (v (- (aref r i) sub borrow)))
            (setf (aref r i) (logand v +goldilocks-limb-mask+)
                  borrow (if (minusp v) 1 0)))))))
    (goldilocks-fe-reduce8 r)
    r))
