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


;;;
;;; Control bits (Nassimi-Sahni Benes network setup).
;;;

(declaim (inline mce-u32 mce-s32))
(defun mce-u32 (x)
  (logand x #xFFFFFFFF))

(defun mce-s32 (x)
  (if (>= x #x80000000)
      (- x #x100000000)
      x))

(defun mce-int32-min (a b)
  (if (< (mce-s32 a) (mce-s32 b)) a b))

(defun mce-int32-sort (vec)
  (sort vec #'< :key #'mce-s32))

(defun mce-cblayer (p cb ptr s n)
  "Apply one int16 Benes layer with control bits CB at byte offset PTR."
  (let ((stride (ash 1 s))
        (index 0))
    (loop for i from 0 below n by (* stride 2)
          do (dotimes (j stride)
               (let* ((a (aref p (+ i j)))
                      (b (aref p (+ i j stride)))
                      (d (logxor a b))
                      (m (ldb (byte 1 (mod index 8))
                              (aref cb (+ ptr (truncate index 8))))))
                 (unless (zerop m)
                   (setf (aref p (+ i j)) (logxor a d)
                         (aref p (+ i j stride)) (logxor b d)))
                 (incf index)))))
  (values))

(defun mce-cb-small (a b n w)
  "Refinement loop for widths <= 10."
  (dotimes (x n)
    (setf (aref b x)
          (logior (ash (logand (aref a x) #xFFFF) 10)
                  (logand (aref b x) #x3FF))))
  (loop for i from 1 below (- w 1)
        do (dotimes (x n)
             (setf (aref a x)
                   (mce-u32 (logior (ash (logand (aref b x) #xFFFFFC00) 6)
                                    x))))
           (mce-int32-sort a)
           (dotimes (x n)
             (setf (aref a x)
                   (mce-u32 (logior (ash (aref a x) 20)
                                    (aref b x)))))
           (mce-int32-sort a)
           (dotimes (x n)
             (let ((app (logand (aref a x) #xFFFFF))
                   (apc (logior (logand (aref a x) #xFFC00)
                                (logand (aref b x) #x3FF))))
               (setf (aref b x) (mce-int32-min apc app)))))
  (dotimes (x n)
    (setf (aref b x) (logand (aref b x) #x3FF)))
  (values))

(defun mce-cb-large (a b n w)
  "Refinement loop for widths > 10."
  (dotimes (x n)
    (setf (aref b x)
          (mce-u32 (logior (ash (aref a x) 16)
                           (logand (aref b x) #xFFFF)))))
  (loop for i from 1 below (- w 1)
        do (dotimes (x n)
             (setf (aref a x)
                   (logior (logand (aref b x) #xFFFF0000) x)))
           (mce-int32-sort a)
           (dotimes (x n)
             (setf (aref a x)
                   (mce-u32 (logior (ash (aref a x) 16)
                                    (logand (aref b x) #xFFFF)))))
           (when (< i (- w 2))
             (dotimes (x n)
               (setf (aref b x)
                     (logior (logand (aref a x) #xFFFF0000)
                             (mce-u32 (ash (mce-s32 (aref b x)) -16)))))
             (mce-int32-sort b)
             (dotimes (x n)
               (setf (aref b x)
                     (mce-u32 (logior (ash (aref b x) 16)
                                      (logand (aref a x) #xFFFF))))))
           (mce-int32-sort a)
           (dotimes (x n)
             (let ((cpx (logior (logand (aref b x) #xFFFF0000)
                                (logand (aref a x) #xFFFF))))
               (setf (aref b x) (mce-int32-min (aref b x) cpx)))))
  (dotimes (x n)
    (setf (aref b x) (logand (aref b x) #xFFFF)))
  (values))


(defun mce-cbrecursion (out pos step pil w n temp)
  "Nassimi-Sahni recursion; emits control bits into OUT."
  (if (= w 1)
      (let ((o (truncate pos 8)))
        (setf (aref out o)
              (logand #xFF (logxor (aref out o) (ash (aref pil 0) (mod pos 8))))))
      (let ((a (make-array n :element-type '(unsigned-byte 32)
                              :displaced-to temp :displaced-index-offset 0))
            (b (make-array n :element-type '(unsigned-byte 32)
                              :displaced-to temp :displaced-index-offset n))
            (q (make-array n :element-type 'fixnum :initial-element 0))
            (half (truncate n 2)))
        (dotimes (x n)
          (setf (aref a x)
                (logior (ash (logxor (aref pil x) 1) 16)
                        (aref pil (logxor x 1)))))
        (mce-int32-sort a)
        (dotimes (x n)
          (let* ((ax (aref a x))
                 (px (logand ax #xFFFF))
                 (cx (min px x)))
            (setf (aref b x) (logior (ash px 16) cx))))
        (dotimes (x n)
          (setf (aref a x) (mce-u32 (+ (ash (aref a x) 16) x))))
        (mce-int32-sort a)
        (dotimes (x n)
          (setf (aref a x)
                (mce-u32 (+ (ash (aref a x) 16)
                            (mce-u32 (ash (mce-s32 (aref b x)) -16))))))
        (mce-int32-sort a)
        (if (<= w 10)
            (mce-cb-small a b n w)
            (mce-cb-large a b n w))
        (dotimes (x n)
          (setf (aref a x) (mce-u32 (+ (ash (aref pil x) 16) x))))
        (mce-int32-sort a)
        (loop for j from 0 below half
              do (let* ((x (* 2 j))
                        (fj (logand (aref b x) 1))
                        (fx (+ x fj))
                        (fx1 (logxor fx 1))
                        (o (truncate pos 8)))
                   (setf (aref out o)
                         (logand #xFF
                                 (logxor (aref out o) (ash fj (mod pos 8)))))
                   (incf pos step)
                   (setf (aref b x) (mce-u32 (+ (ash (aref a x) 16) fx))
                         (aref b (1+ x))
                         (mce-u32 (+ (ash (aref a (1+ x)) 16) fx1)))))
        (mce-int32-sort b)
        (incf pos (* (- (* 2 w) 3) step half))
        (loop for k from 0 below half
              do (let* ((y (* 2 k))
                        (lk (logand (aref b y) 1))
                        (ly (+ y lk))
                        (ly1 (logxor ly 1))
                        (o (truncate pos 8)))
                   (setf (aref out o)
                         (logand #xFF
                                 (logxor (aref out o) (ash lk (mod pos 8)))))
                   (incf pos step)
                   (setf (aref a y)
                         (mce-u32 (+ (ash ly 16) (logand (aref b y) #xFFFF)))
                         (aref a (1+ y))
                         (mce-u32 (+ (ash ly1 16)
                                     (logand (aref b (1+ y)) #xFFFF))))))
        (mce-int32-sort a)
        (decf pos (* (- (* 2 w) 2) step half))
        (loop for j from 0 below half
              do (setf (aref q j)
                       (ash (logand (aref a (* 2 j)) #xFFFF) -1)
                       (aref q (+ j half))
                       (ash (logand (aref a (1+ (* 2 j))) #xFFFF) -1)))
        (mce-cbrecursion out pos (* step 2)
                         (make-array half :element-type 'fixnum
                                            :displaced-to q :displaced-index-offset 0)
                         (1- w) half temp)
        (mce-cbrecursion out (+ pos step) (* step 2)
                         (make-array half :element-type 'fixnum
                                            :displaced-to q
                                            :displaced-index-offset half)
                         (1- w) half temp)))
  (values))

(defun mce-controlbits (out pil w n)
  "Control bits for permutation PIL; verifies by application."
  (let ((temp (make-array (* 2 n) :element-type '(unsigned-byte 32)
                                     :initial-element 0))
        (ptest (make-array n :element-type 'fixnum :initial-element 0))
        (nbytes (truncate (+ (truncate (* (1- (* 2 w)) n) 2) 7) 8)))
    (loop
      (dotimes (i nbytes)
        (setf (aref out i) 0))
      (mce-cbrecursion out 0 1 pil w n temp)
      (dotimes (i n)
        (setf (aref ptest i) i))
      (let ((ptr 0))
        (dotimes (i w)
          (mce-cblayer ptest out ptr i n)
          (incf ptr (truncate n 16)))
        (loop for i from (- w 2) downto 0
              do (mce-cblayer ptest out ptr i n)
                 (incf ptr (truncate n 16))))
      (when (dotimes (i n t)
              (unless (= (aref pil i) (aref ptest i))
                (return nil)))
        (return out)))))


;;;
;;; Public-key generation.
;;;

(defun mce-perm-check (piv perm)
  "Sort PERM into PIV; NIL when two entries collide."
  (let ((idx (make-array 4096 :element-type 'fixnum)))
    (dotimes (i 4096)
      (setf (aref idx i) i))
    (setf idx (sort idx #'< :key (lambda (i) (aref perm i))))
    (loop for j from 1 below 4096
          do (when (= (aref perm (aref idx (1- j))) (aref perm (aref idx j)))
               (return-from mce-perm-check nil)))
    (dotimes (j 4096)
      (setf (aref piv j) (aref idx j)))
    t))

(defun mce-pk-gen (pk sk perm piv)
  "PK := public key for secret Goppa bytes SK and permutation PERM.
PIV is 4096-element scratch/output. Returns T on success, NIL on failure."
  (unless (mce-perm-check piv perm)
    (return-from mce-pk-gen nil))
  (let ((g (make-array 65 :element-type 'fixnum :initial-element 0))
        (l (make-array +mce-sys-n+ :element-type 'fixnum))
        (inv (make-array +mce-sys-n+ :element-type 'fixnum))
        (rows (make-array +mce-pk-nrows+)))
    (setf (aref g +mce-sys-t+) 1)
    (dotimes (i +mce-sys-t+)
      (setf (aref g i) (mce-load-gf sk (* i 2))))
    (dotimes (i +mce-sys-n+)
      (setf (aref l i) (mce-bitrev (aref piv i))))
    (dotimes (i +mce-pk-nrows+)
      (setf (aref rows i)
            (make-array 436 :element-type '(unsigned-byte 8) :initial-element 0)))
    (mce-root inv g l)
    (dotimes (i +mce-sys-n+)
      (setf (aref inv i) (mce-gf-inv (aref inv i))))
    (dotimes (i +mce-sys-t+)
      (loop for j from 0 below +mce-sys-n+ by 8
            do (let ((base (truncate j 8)))
                 (dotimes (k +mce-gfbits+)
                   (let ((b 0)
                         (rk (aref rows (+ (* i +mce-gfbits+) k))))
                     (declare (type (simple-array (unsigned-byte 8) (*)) rk))
                     (loop for q from 7 downto 0
                           do (setf b (logior (ash b 1)
                                              (ldb (byte 1 k) (aref inv (+ j q))))))
                     (setf (aref rk base) b)))))
      (dotimes (j +mce-sys-n+)
        (setf (aref inv j) (mce-gf-mul (aref inv j) (aref l j)))))
    (loop for i from 0 below (truncate +mce-pk-nrows+ 8)
          do (dotimes (j 8)
               (let ((row (+ (* i 8) j)))
                 (when (>= row +mce-pk-nrows+)
                   (return))
                 (let ((rr (aref rows row)))
                   (declare (type (simple-array (unsigned-byte 8) (*)) rr))
                   (loop for k from (1+ row) below +mce-pk-nrows+
                         do (let ((rk (aref rows k)))
                              (declare (type (simple-array (unsigned-byte 8) (*)) rk))
                              (when (= (ldb (byte 1 j)
                                            (logxor (aref rr i) (aref rk i)))
                                       1)
                                (dotimes (c 436)
                                  (setf (aref rr c)
                                        (logxor (aref rr c) (aref rk c)))))))
                   (when (zerop (ldb (byte 1 j) (aref rr i)))
                     (return-from mce-pk-gen nil))
                   (dotimes (k +mce-pk-nrows+)
                     (unless (= k row)
                       (let ((rk (aref rows k)))
                         (declare (type (simple-array (unsigned-byte 8) (*)) rk))
                         (when (= (ldb (byte 1 j) (aref rk i)) 1)
                           (dotimes (c 436)
                             (setf (aref rk c)
                                   (logxor (aref rk c) (aref rr c))))))))))))
    (dotimes (i +mce-pk-nrows+)
      (let ((rr (aref rows i)))
        (declare (type (simple-array (unsigned-byte 8) (*)) rr))
        (dotimes (j +mce-pk-row-bytes+)
          (setf (aref pk (+ (* i +mce-pk-row-bytes+) j))
                (aref rr (+ (truncate +mce-pk-nrows+ 8) j))))))
    t))


;;;
;;; KEM: keypair, encryption, decryption, encapsulation.
;;;

(defun mce-shake256 (input output-length)
  (let ((d (make-digest :shake256 :output-length output-length)))
    (update-digest d input)
    (produce-digest d)))

(defun mce-keypair-from-seed (seed32)
  "Deterministic keypair from 32-byte SEED32; returns (pk sk)."
  (let ((seed (make-array 33 :element-type '(unsigned-byte 8) :initial-element 0))
        (pk (make-array +mce-pk-bytes+ :element-type '(unsigned-byte 8)
                                          :initial-element 0))
        (sk (make-array +mce-sk-bytes+ :element-type '(unsigned-byte 8)
                                          :initial-element 0))
        (f (make-array +mce-sys-t+ :element-type 'fixnum :initial-element 0))
        (irr (make-array +mce-sys-t+ :element-type 'fixnum :initial-element 0))
        (irr-bytes (make-array +mce-irr-bytes+
                               :element-type '(unsigned-byte 8)
                               :initial-element 0))
        (perm (make-array (ash 1 +mce-gfbits+) :element-type '(unsigned-byte 32)
                                                     :initial-element 0))
        (piv (make-array (ash 1 +mce-gfbits+) :element-type 'fixnum
                                                   :initial-element 0))
        (cond-bytes (make-array +mce-cond-bytes+
                                :element-type '(unsigned-byte 8)
                                :initial-element 0)))
    (setf (aref seed 0) 64)
    (replace seed seed32 :start1 1)
    (loop
      (let ((r (mce-shake256 seed 16980)))
        (replace sk seed :start2 1 :end2 33)
        (replace seed r :start1 1 :start2 16948)
        (dotimes (i +mce-sys-t+)
          (setf (aref f i) (mce-load-gf r (+ 16820 (* i 2)))))
        (when (mce-genpoly irr f)
          (dotimes (i +mce-sys-t+)
            (mce-store-gf irr-bytes (* i 2) (aref irr i)))
          (dotimes (i (ash 1 +mce-gfbits+))
            (setf (aref perm i) (mce-load4 r (+ 436 (* i 4)))))
          (when (mce-pk-gen pk irr-bytes perm piv)
            (replace sk irr-bytes :start1 40)
            (mce-controlbits cond-bytes piv +mce-gfbits+ (ash 1 +mce-gfbits+))
            (replace sk cond-bytes :start1 168)
            (replace sk r :start1 6056 :end2 436)
            (mce-store8 sk 32 #xFFFFFFFF)
            (return (values pk sk))))))))

(defun mce-gen-e (e random-fn)
  "Random weight-SYS_T error vector into E (436 bytes)."
  (loop
    (let ((buf (funcall random-fn 256))
          (ind (make-array +mce-sys-t+ :element-type 'fixnum))
          (count 0))
      (dotimes (i (* 2 +mce-sys-t+))
        (when (< count +mce-sys-t+)
          (let ((tgt (mce-load-gf buf (* i 2))))
            (when (< tgt +mce-sys-n+)
              (setf (aref ind count) tgt)
              (incf count)))))
      (when (= count +mce-sys-t+)
        (let ((distinct t))
          (loop for i from 1 below +mce-sys-t+
                do (loop for j from 0 below i
                         do (when (= (aref ind i) (aref ind j))
                              (setf distinct nil))))
          (when distinct
            (fill e 0)
            (dotimes (j +mce-sys-t+)
              (let ((tgt (aref ind j)))
                (setf (aref e (ash tgt -3))
                      (logior (aref e (ash tgt -3))
                              (ash 1 (logand tgt 7))))))
            (return e)))))))

(defun mce-syndrome-bytes (s pk e)
  "Niederreiter syndrome S (96 bytes) of error vector E under PK."
  (dotimes (i +mce-synd-bytes+)
    (setf (aref s i) 0))
  (let ((row (make-array 436 :element-type '(unsigned-byte 8)
                                   :initial-element 0)))
    (dotimes (i +mce-pk-nrows+)
      (fill row 0)
      (replace row pk :start1 96 :start2 (* i +mce-pk-row-bytes+)
                         :end2 (+ (* i +mce-pk-row-bytes+) +mce-pk-row-bytes+))
      (let ((q (ash i -3)))
        (setf (aref row q) (logior (aref row q) (ash 1 (logand i 7)))))
      (let ((b 0))
        (dotimes (j 436)
          (setf b (logxor b (logand (aref row j) (aref e j)))))
        (setf b (logxor b (ash b -4)))
        (setf b (logxor b (ash b -2)))
        (setf b (logxor b (ash b -1)))
        (let ((q (ash i -3)))
          (setf (aref s q)
                (logior (aref s q) (ash (logand b 1) (logand i 7))))))))
  (values))

(defun mce-encrypt (ct pk e)
  "Syndrome ciphertext CT of the given error vector E under PK."
  (mce-syndrome-bytes ct pk e)
  (values))

(defun mce-decrypt (e sk c)
  "Niederreiter decrypt C under SK into E; T on success."
  (let ((r (make-array 436 :element-type '(unsigned-byte 8) :initial-element 0))
        (g (make-array 65 :element-type 'fixnum :initial-element 0))
        (l (make-array +mce-sys-n+ :element-type 'fixnum))
        (s (make-array 128 :element-type 'fixnum))
        (s-cmp (make-array 128 :element-type 'fixnum))
        (locator (make-array 65 :element-type 'fixnum))
        (images (make-array +mce-sys-n+ :element-type 'fixnum)))
    (replace r c :end2 +mce-synd-bytes+)
    (dotimes (i +mce-sys-t+)
      (setf (aref g i) (mce-load-gf sk (+ 40 (* i 2)))))
    (setf (aref g +mce-sys-t+) 1)
    (mce-support-gen l (subseq sk 168 (+ 168 +mce-cond-bytes+)))
    (mce-synd s g l r)
    (mce-bm locator s)
    (mce-root images locator l)
    (fill e 0)
    (let ((w 0))
      (dotimes (i +mce-sys-n+)
        (let ((tgt (if (zerop (aref images i)) 1 0)))
          (setf (aref e (ash i -3))
                (logior (aref e (ash i -3)) (ash tgt (logand i 7))))
          (incf w tgt)))
      (mce-synd s-cmp g l e)
      (and (= w +mce-sys-t+)
           (dotimes (i 128 t)
             (unless (= (aref s i) (aref s-cmp i))
               (return nil)))))))

(defun mce-encaps-from-error (e pk)
  "Deterministic encapsulation with error vector E; returns (ct ss)."
  (let ((ct (make-array +mce-ct-bytes+ :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
    (mce-encrypt ct pk e)
    (let ((pre (make-array 533 :element-type '(unsigned-byte 8)
                                     :initial-element 0)))
      (setf (aref pre 0) 1)
      (replace pre e :start1 1)
      (replace pre ct :start1 437)
      (values ct (mce-shake256 pre 32)))))

(defun mce-decapsulate (ct sk)
  "Decapsulation with implicit rejection; returns 32-byte secret."
  (let ((e (make-array 436 :element-type '(unsigned-byte 8) :initial-element 0))
        (pre (make-array 533 :element-type '(unsigned-byte 8) :initial-element 0)))
    (if (mce-decrypt e sk ct)
        (progn (setf (aref pre 0) 1)
               (replace pre e :start1 1))
        (progn (setf (aref pre 0) 0)
               (replace pre sk :start1 1 :start2 6056 :end2 6492)))
    (replace pre ct :start1 437)
    (mce-shake256 pre 32)))


;;;
;;; Public API: key classes, generation, encapsulation.
;;;

(defclass mceliece-key ()
  ((kind :initarg :kind :reader mceliece-key-kind)
   (bytes :initarg :bytes :reader mceliece-key-bytes)))

(defclass mceliece-public-key (mceliece-key)
  ())

(defclass mceliece-private-key (mceliece-key)
  ())

(defclass mceliece348864-public-key (mceliece-public-key)
  ())

(defclass mceliece348864-private-key (mceliece-private-key)
  ())

(defun mce-check-bytes (bytes length kind)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) length))
    (error 'missing-key-parameter
           :kind kind
           :parameter 'bytes
           :description "McEliece key bytes"))
  (copy-seq bytes))

(defmethod make-public-key ((kind (eql :mceliece348864)) &key bytes
                            &allow-other-keys)
  (make-instance 'mceliece348864-public-key :kind kind
                                            :bytes (mce-check-bytes bytes
                                                                    +mce-pk-bytes+
                                                                    kind)))

(defmethod make-private-key ((kind (eql :mceliece348864)) &key bytes
                             &allow-other-keys)
  (make-instance 'mceliece348864-private-key :kind kind
                                              :bytes (mce-check-bytes bytes
                                                                      +mce-sk-bytes+
                                                                      kind)))

(defmethod generate-key-pair ((kind (eql :mceliece348864)) &key
                              &allow-other-keys)
  (multiple-value-bind (pk sk)
      (mce-keypair-from-seed (random-data 32))
    (values (make-private-key kind :bytes sk)
            (make-public-key kind :bytes pk))))

(defmethod destructure-public-key ((public-key mceliece-public-key))
  (list :bytes (copy-seq (mceliece-key-bytes public-key))))

(defmethod destructure-private-key ((private-key mceliece-private-key))
  (list :bytes (copy-seq (mceliece-key-bytes private-key))))

(defmethod encapsulate-key ((public-key mceliece348864-public-key))
  (let ((e (make-array 436 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
    (mce-gen-e e (lambda (k) (random-data k)))
    (mce-encaps-from-error e (mceliece-key-bytes public-key))))

(defmethod decapsulate-key ((private-key mceliece348864-private-key) ciphertext)
  (unless (and (typep ciphertext '(simple-array (unsigned-byte 8) (*)))
               (= (length ciphertext) +mce-ct-bytes+))
    (error 'invalid-message-length :kind (mceliece-key-kind private-key)))
  (mce-decapsulate ciphertext (mceliece-key-bytes private-key)))
