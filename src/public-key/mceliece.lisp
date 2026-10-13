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
(defconstant +mce-cond-bytes+ 5888)
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


;;;
;;; Irreducible-polynomial generation (secret-key generation).
;;;

(defun mce-genpoly (out f)
  "OUT := minimal polynomial of the extension element F.
Returns T on success, NIL when the matrix is not systematic."
  (let ((mat (make-array (list (1+ +mce-sys-t+) +mce-sys-t+)
                         :element-type 'fixnum :initial-element 0))
        (prev (make-array +mce-sys-t+ :element-type 'fixnum :initial-element 0))
        (prod (make-array +mce-sys-t+ :element-type 'fixnum :initial-element 0)))
    (setf (aref mat 0 0) 1)
    (dotimes (i +mce-sys-t+)
      (setf (aref mat 1 i) (aref f i)))
    (loop for j from 2 to +mce-sys-t+
          do (dotimes (i +mce-sys-t+)
               (setf (aref prev i) (aref mat (1- j) i)))
             (mce-gf-poly-mul prod prev f)
             (dotimes (i +mce-sys-t+)
               (setf (aref mat j i) (aref prod i))))
    (dotimes (j +mce-sys-t+)
      (loop for k from (1+ j) below +mce-sys-t+
            do (when (zerop (aref mat j j))
                 (loop for c from j to +mce-sys-t+
                       do (setf (aref mat c j)
                                (logxor (aref mat c j) (aref mat c k))))))
      (when (zerop (aref mat j j))
        (return-from mce-genpoly nil))
      (let ((inv (mce-gf-inv (aref mat j j))))
        (loop for c from j to +mce-sys-t+
              do (setf (aref mat c j) (mce-gf-mul (aref mat c j) inv)))
        (dotimes (k +mce-sys-t+)
          (unless (= k j)
            (let ((tt (aref mat j k)))
              (loop for c from j to +mce-sys-t+
                    do (setf (aref mat c k)
                             (logxor (aref mat c k)
                                     (mce-gf-mul (aref mat c j) tt)))))))))
    (dotimes (i +mce-sys-t+ out)
      (setf (aref out i) (aref mat +mce-sys-t+ i)))
    t))


;;;
;;; Bit reversal, polynomial evaluation, syndrome, Berlekamp-Massey.
;;;

(defun mce-bitrev (a)
  (let ((x a))
    (setf x (logior (ash (logand x #x00FF) 8) (ash (logand x #xFF00) -8)))
    (setf x (logior (ash (logand x #x0F0F) 4) (ash (logand x #xF0F0) -4)))
    (setf x (logior (ash (logand x #x3333) 2) (ash (logand x #xCCCC) -2)))
    (setf x (logior (ash (logand x #x5555) 1) (ash (logand x #xAAAA) -1)))
    (ash x -4)))

(defun mce-eval (f a)
  "Evaluate the degree-SYS_T Goppa polynomial F at field element A."
  (let ((r (aref f +mce-sys-t+)))
    (loop for i from (1- +mce-sys-t+) downto 0
          do (setf r (mce-gf-add (mce-gf-mul r a) (aref f i))))
    r))

(defun mce-root (out f l)
  "OUT[i] = F(L[i]) for every support element."
  (dotimes (i +mce-sys-n+ out)
    (setf (aref out i) (mce-eval f (aref l i)))))

(defun mce-synd (out f l r-bytes)
  "Syndrome of the received word R-BYTES under (F, L), length 2*SYS_T."
  (let ((bytes (coerce r-bytes '(simple-array (unsigned-byte 8) (*)))))
    (dotimes (j (* 2 +mce-sys-t+))
      (setf (aref out j) 0))
    (dotimes (i +mce-sys-n+)
      (let* ((c (ldb (byte 1 (mod i 8)) (aref bytes (truncate i 8))))
             (e (mce-eval f (aref l i)))
             (e-inv (mce-gf-inv (mce-gf-mul e e))))
        (when (plusp c)
          (dotimes (j (* 2 +mce-sys-t+))
            (setf (aref out j) (mce-gf-add (aref out j) e-inv))
            (setf e-inv (mce-gf-mul e-inv (aref l i))))))))
  (values))

(defun mce-bm (out s)
  "Berlekamp-Massey: minimal polynomial of the syndrome S."
  (let ((C (make-array (1+ +mce-sys-t+) :initial-element 0))
        (B (make-array (1+ +mce-sys-t+) :initial-element 0))
        (temp-b (make-array (1+ +mce-sys-t+) :initial-element 0))
        (lf 0)
        (be 1)
        (d 0))
    (setf (aref C 0) 1 (aref B 1) 1)
    (dotimes (N (* 2 +mce-sys-t+))
      (setf d 0)
      (dotimes (i (1+ (min N +mce-sys-t+)))
        (when (<= i N)
          (setf d (logxor d (mce-gf-mul (aref C i) (aref s (- N i)))))))
      (let* ((mne (if (zerop d) 0 1))
             (f (mce-gf-frac be d)))
        (dotimes (i (1+ +mce-sys-t+))
          (setf (aref temp-b i) (aref C i))
          (when (= mne 1)
            (setf (aref C i) (logxor (aref C i) (mce-gf-mul f (aref B i))))))
        (when (< (* 2 lf) (+ N 1))
          (dotimes (i (1+ +mce-sys-t+))
            (setf (aref B i) (aref temp-b i)))
          (setf lf (1+ (- N lf))
                be d))
        (loop for i from +mce-sys-t+ downto 1
              do (setf (aref B i) (aref B (1- i))))
        (setf (aref B 0) 0)))
    (dotimes (i (1+ +mce-sys-t+) out)
      (setf (aref out i) (aref C (- +mce-sys-t+ i))))))


;;;
;;; Little-endian field loads, support generation, bit packing.
;;;

(defun mce-load-gf (bytes off)
  "Load a 12-bit field element from BYTES at OFF (little-endian)."
  (logand (logior (aref bytes off)
                  (ash (aref bytes (1+ off)) 8))
          +mce-gfmask+))

(defun mce-store-gf (bytes off v)
  (setf (aref bytes off) (logand v #xFF)
        (aref bytes (1+ off)) (ldb (byte 8 8) v))
  (values))

(defun mce-load4 (bytes off)
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes))
  (logior (aref bytes off)
          (ash (aref bytes (+ off 1)) 8)
          (ash (aref bytes (+ off 2)) 16)
          (ash (aref bytes (+ off 3)) 24)))

(defun mce-store8 (bytes off v)
  (setf (aref bytes off) (ldb (byte 8 0) v)
        (aref bytes (+ off 1)) (ldb (byte 8 8) v)
        (aref bytes (+ off 2)) (ldb (byte 8 16) v)
        (aref bytes (+ off 3)) (ldb (byte 8 24) v)
        (aref bytes (+ off 4)) (ldb (byte 8 32) v)
        (aref bytes (+ off 5)) (ldb (byte 8 40) v)
        (aref bytes (+ off 6)) (ldb (byte 8 48) v)
        (aref bytes (+ off 7)) (ldb (byte 8 56) v))
  (values))

(defun mce-load8 (bytes off)
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes))
  (logior (aref bytes off)
          (ash (aref bytes (+ off 1)) 8)
          (ash (aref bytes (+ off 2)) 16)
          (ash (aref bytes (+ off 3)) 24)
          (ash (aref bytes (+ off 4)) 32)
          (ash (aref bytes (+ off 5)) 40)
          (ash (aref bytes (+ off 6)) 48)
          (ash (aref bytes (+ off 7)) 56)))


;;;
;;; Bit reversal, polynomial evaluation, syndrome, Berlekamp-Massey.
;;;







;;;
;;; Little-endian field loads, support generation, bit packing.
;;;




;;;
;;; Benes network: 64x64 bit transpose, one switching layer, apply.
;;;

(defparameter *mce-tmasks*
  #(#x5555555555555555 #xAAAAAAAAAAAAAAAA
    #x3333333333333333 #xCCCCCCCCCCCCCCCC
    #x0F0F0F0F0F0F0F0F #xF0F0F0F0F0F0F0F0
    #x00FF00FF00FF00FF #xFF00FF00FF00FF00
    #x0000FFFF0000FFFF #xFFFF0000FFFF0000
    #x00000000FFFFFFFF #xFFFFFFFF00000000))

(defun mce-transpose-64x64 (out src)
  "OUT := transpose(SRC) over the 64x64 bit matrix."
  (let ((res (copy-seq src)))
    (loop for d from 5 downto 0
          do (let ((s (ash 1 d))
                   (lo (aref *mce-tmasks* (* 2 d)))
                   (hi (aref *mce-tmasks* (+ 1 (* 2 d)))))
               (loop for i from 0 below 64 by (* 2 s)
                     do (loop for j from i below (+ i s)
                              do (let ((av (aref res j)) (bv (aref res (+ j s))))
                                   (setf (aref res j)
                                         (logior (logand av lo) (ash (logand bv lo) s)))
                                   (setf (aref res (+ j s))
                                         (logior (ash (logand av hi) (- s))
                                                 (logand bv hi))))))))
    (replace out res)
    (values)))

(defun mce-layer (data bits lgs)
  "Apply one Benes switching layer."
  (let ((s (ash 1 lgs))
        (k 0))
    (loop for i from 0 below 64 by (* 2 s)
          do (loop for j from i below (+ i s)
                   do (let ((d (logand (logxor (aref data j) (aref data (+ j s)))
                                      (aref bits k))))
                        (setf (aref data j) (logxor (aref data j) d)
                              (aref data (+ j s)) (logxor (aref data (+ j s)) d))
                        (incf k))))
    (values)))

(defun mce-apply-benes (r bits)
  "Apply the Benes network with condition BITS to bit vector R."
  (let ((bs (make-array 64 :element-type '(unsigned-byte 64)))
        (cond (make-array 64 :element-type '(unsigned-byte 64)
                           :initial-element 0))
        (off 0)
        (inc 256))
    (dotimes (i 64)
      (setf (aref bs i) (mce-load8 r (* i 8))))
    (mce-transpose-64x64 bs bs)
    (dotimes (low 6)
      (dotimes (i 64)
        (setf (aref cond i) (mce-load4 bits (+ off (* i 4)))))
      (mce-transpose-64x64 cond cond)
      (mce-layer bs cond low)
      (incf off inc))
    (mce-transpose-64x64 bs bs)
    (dotimes (low 6)
      (dotimes (i 32)
        (setf (aref cond i) (mce-load8 bits (+ off (* i 8)))))
      (mce-layer bs cond low)
      (incf off inc))
    (loop for low from 4 downto 0
          do (dotimes (i 32)
               (setf (aref cond i) (mce-load8 bits (+ off (* i 8)))))
             (mce-layer bs cond low)
             (incf off inc))
    (mce-transpose-64x64 bs bs)
    (loop for low from 5 downto 0
          do (dotimes (i 64)
               (setf (aref cond i) (mce-load4 bits (+ off (* i 4)))))
             (mce-transpose-64x64 cond cond)
             (mce-layer bs cond low)
             (incf off inc))
    (mce-transpose-64x64 bs bs)
    (dotimes (i 64)
      (mce-store8 r (* i 8) (aref bs i)))
    (values)))

(defun mce-support-gen (s cond-bytes)
  "Support from condition bits (Benes sieve then bit interleave)."
  (let ((l (make-array +mce-gfbits+ :element-type '(simple-array (unsigned-byte 8) (*))))
        (size (truncate (ash 1 +mce-gfbits+) 8)))
    (dotimes (i +mce-gfbits+)
      (setf (aref l i) (make-array size :element-type '(unsigned-byte 8)
                                            :initial-element 0)))
    (dotimes (i (ash 1 +mce-gfbits+))
      (let ((a (mce-bitrev i)))
        (dotimes (j +mce-gfbits+)
          (setf (aref (aref l j) (truncate i 8))
                (logior (aref (aref l j) (truncate i 8))
                        (ash (ldb (byte 1 j) a) (mod i 8)))))))
    (dotimes (j +mce-gfbits+)
      (mce-apply-benes (aref l j) cond-bytes))
    (dotimes (i +mce-sys-n+)
      (let ((v 0))
        (loop for j from (1- +mce-gfbits+) downto 0
              do (setf v (ash v 1))
                 (setf v (logior v (ldb (byte 1 (mod i 8))
                                        (aref (aref l j) (truncate i 8))))))
        (setf (aref s i) v)))))
