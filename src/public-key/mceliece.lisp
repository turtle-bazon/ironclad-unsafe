;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; mceliece.lisp -- Classic McEliece KEM family
;;; (mceliece348864/460896/6688128/6960119/8192128).
;;;;
;;;; Direct translation of the PQClean clean implementations:
;;;; GF(2^m) arithmetic, Goppa support, Patterson decoding.

(in-package :crypto-unsafe)


;;;
;;; Parameters: one struct per set, selected via *MCE-PARAMS*.
;;;

(defstruct mce-params
  kind gfbits sys-n sys-t gfmask cond-bytes irr-bytes
  pk-nrows pk-row-bytes synd-bytes pk-bytes sk-bytes ct-bytes poly-red)

(defparameter +mce-348864-params+
  (make-mce-params :kind :mceliece348864 :gfbits 12 :sys-n 3488 :sys-t 64
                   :gfmask #xFFF :cond-bytes 5888 :irr-bytes 128
                   :pk-nrows 768 :pk-row-bytes 340 :synd-bytes 96
                   :pk-bytes 261120 :sk-bytes 6492 :ct-bytes 96
                   :poly-red '((3 nil) (1 nil) (0 t))))

(defparameter +mce-460896-params+
  (make-mce-params :kind :mceliece460896 :gfbits 13 :sys-n 4608 :sys-t 96
                   :gfmask #x1FFF :cond-bytes 12800 :irr-bytes 192
                   :pk-nrows 1248 :pk-row-bytes 420 :synd-bytes 156
                   :pk-bytes 524160 :sk-bytes 13608 :ct-bytes 156
                   :poly-red '((10 nil) (9 nil) (6 nil) (0 nil))))

(defparameter +mce-6688128-params+
  (make-mce-params :kind :mceliece6688128 :gfbits 13 :sys-n 6688 :sys-t 128
                   :gfmask #x1FFF :cond-bytes 12800 :irr-bytes 256
                   :pk-nrows 1664 :pk-row-bytes 628 :synd-bytes 208
                   :pk-bytes 1044992 :sk-bytes 13932 :ct-bytes 208
                   :poly-red '((7 nil) (2 nil) (1 nil) (0 nil))))

(defparameter +mce-6960119-params+
  (make-mce-params :kind :mceliece6960119 :gfbits 13 :sys-n 6960 :sys-t 119
                   :gfmask #x1FFF :cond-bytes 12800 :irr-bytes 238
                   :pk-nrows 1547 :pk-row-bytes 677 :synd-bytes 194
                   :pk-bytes 1047319 :sk-bytes 13948 :ct-bytes 194
                   :poly-red '((8 nil) (0 nil))))

(defparameter +mce-8192128-params+
  (make-mce-params :kind :mceliece8192128 :gfbits 13 :sys-n 8192 :sys-t 128
                   :gfmask #x1FFF :cond-bytes 12800 :irr-bytes 256
                   :pk-nrows 1664 :pk-row-bytes 816 :synd-bytes 208
                   :pk-bytes 1357824 :sk-bytes 14120 :ct-bytes 208
                   :poly-red '((7 nil) (2 nil) (1 nil) (0 nil))))

(defparameter *mce-params* +mce-348864-params+)

(defun mce-params-for-kind (kind)
  (case kind
    (:mceliece348864 +mce-348864-params+)
    (:mceliece460896 +mce-460896-params+)
    (:mceliece6688128 +mce-6688128-params+)
    (:mceliece6960119 +mce-6960119-params+)
    (:mceliece8192128 +mce-8192128-params+)
    (otherwise (error "unknown McEliece kind ~A" kind))))

(declaim (inline mce-gfbits mce-sys-n mce-sys-t mce-gfmask mce-cond-bytes
                 mce-irr-bytes mce-pk-nrows mce-pk-row-bytes mce-synd-bytes
                 mce-pk-bytes mce-sk-bytes mce-ct-bytes
                 mce-perm-len mce-sup-row-bytes mce-r-len))

(defun mce-gfbits () (mce-params-gfbits *mce-params*))
(defun mce-sys-n () (mce-params-sys-n *mce-params*))
(defun mce-sys-t () (mce-params-sys-t *mce-params*))
(defun mce-gfmask () (mce-params-gfmask *mce-params*))
(defun mce-cond-bytes () (mce-params-cond-bytes *mce-params*))
(defun mce-irr-bytes () (mce-params-irr-bytes *mce-params*))
(defun mce-pk-nrows () (mce-params-pk-nrows *mce-params*))
(defun mce-pk-row-bytes () (mce-params-pk-row-bytes *mce-params*))
(defun mce-synd-bytes () (mce-params-synd-bytes *mce-params*))
(defun mce-pk-bytes () (mce-params-pk-bytes *mce-params*))
(defun mce-sk-bytes () (mce-params-sk-bytes *mce-params*))
(defun mce-ct-bytes () (mce-params-ct-bytes *mce-params*))
(defun mce-perm-len () (ash 1 (mce-gfbits)))
(defun mce-sup-row-bytes () (ash (ash 1 (mce-gfbits)) -3))
(defun mce-r-len ()
  (+ (ash (mce-sys-n) -3) (* 4 (mce-perm-len)) (* 2 (mce-sys-t)) 32))


;;;
;;; GF(2^12) = GF(2)[x]/(x^12 + x^3 + 1)
;;;

(declaim (inline mce-gf-add))
(defun mce-gf-add (a b)
  (logxor a b))

(declaim (inline mce-gf-mul))
(defun mce-gf-mul (a b)
  (if (= (mce-gfbits) 12)
      (mce-gf-mul-12 a b)
      (mce-gf-mul-13 a b)))

;;; Shift-and-reduce multiply used only to build the log/antilog tables.
(defun mce-gf-mul-raw (a b bits low-poly)
  (declare (type fixnum a b bits low-poly)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r 0)
        (top (ash 1 (1- bits)))
        (mask (1- (ash 1 bits))))
    (declare (type fixnum r top mask))
    (dotimes (i bits r)
      (when (logbitp 0 b)
        (setf r (logxor r a)))
      (setf b (ash b -1))
      (let ((hi (logand a top)))
        (setf a (logand (ash a 1) mask))
        (when (plusp hi)
          (setf a (logxor a low-poly)))))))

(defun mce-build-gf-exp (bits gen low-poly)
  (declare (type fixnum bits gen low-poly)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (1- (ash 1 bits)))
         (exp (make-array (* 2 n) :element-type 'fixnum))
         (x 1))
    (declare (type fixnum n x)
             (type (simple-array fixnum (*)) exp))
    (dotimes (i n)
      (setf (aref exp i) x)
      (setf x (mce-gf-mul-raw x gen bits low-poly)))
    (loop for i from n below (* 2 n)
          do (setf (aref exp i) (aref exp (- i n))))
    exp))

(defun mce-build-gf-log (bits gen low-poly)
  (declare (type fixnum bits gen low-poly)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (1- (ash 1 bits)))
         (log (make-array (ash 1 bits) :element-type 'fixnum :initial-element 0))
         (x 1))
    (declare (type fixnum n x)
             (type (simple-array fixnum (*)) log))
    (dotimes (i n)
      (setf (aref log x) i)
      (setf x (mce-gf-mul-raw x gen bits low-poly)))
    log))

(declaim (type (simple-array fixnum (*)) *mce-exp12* *mce-log12*
                                        *mce-exp13* *mce-log13*))
(defparameter *mce-exp12* (mce-build-gf-exp 12 3 #x9))
(defparameter *mce-log12* (mce-build-gf-log 12 3 #x9))
(defparameter *mce-exp13* (mce-build-gf-exp 13 2 #x1B))
(defparameter *mce-log13* (mce-build-gf-log 13 2 #x1B))

(defparameter *mce-bit-masks*
  (let ((v (make-array 64 :element-type '(unsigned-byte 64))))
    (dotimes (i 64 v)
      (setf (aref v i) (ash 1 i)))))

(defparameter *mce-bit-values*
  (let ((v (make-array 8 :element-type 'fixnum)))
    (dotimes (i 8 v)
      (setf (aref v i) (ash 1 i)))))

(declaim (inline mce-gf-mul-12 mce-gf-mul-13))
(defun mce-gf-mul-12 (a b)
  (declare (type fixnum a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (if (or (zerop a) (zerop b))
      0
      (let ((s (+ (aref *mce-log12* a) (aref *mce-log12* b))))
        (declare (type fixnum s))
        (aref *mce-exp12* (if (>= s 4095) (- s 4095) s)))))

(defun mce-gf-sq (a)
  (declare (type (unsigned-byte 16) a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x a))
    (declare (type (unsigned-byte 32) x))
    (setf x (logand (logior x (ash x 8)) #x00FF00FF))
    (setf x (logand (logior x (ash x 4)) #x0F0F0F0F))
    (setf x (logand (logior x (ash x 2)) #x33333333))
    (setf x (logand (logior x (ash x 1)) #x55555555))
    (let ((tt (logand x #x7FC000)))
      (setf x (logxor x (ash tt -9) (ash tt -12))))
    (let ((tt (logand x #x3000)))
      (setf x (logxor x (ash tt -9) (ash tt -12))))
    (logand x #xFFF)))

(declaim (inline mce-gf-inv))
(defun mce-gf-inv (a)
  (if (= (mce-gfbits) 12)
      (mce-gf-inv-12 a)
      (mce-gf-frac-13 a 1)))

(defun mce-gf-inv-12 (a)
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
  (if (= (mce-gfbits) 12)
      (mce-gf-mul (mce-gf-inv den) num)
      (mce-gf-frac-13 den num)))

(defun mce-gf-mul-13 (a b)
  (declare (type fixnum a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (if (or (zerop a) (zerop b))
      0
      (let ((s (+ (aref *mce-log13* a) (aref *mce-log13* b))))
        (declare (type fixnum s))
        (aref *mce-exp13* (if (>= s 8191) (- s 8191) s)))))

(defun mce13-sq2 (a)
  (let ((x a)
        (tt 0))
    (setf x (logand (logior x (ash x 24)) #x000000FF000000FF))
    (setf x (logand (logior x (ash x 12)) #x000F000F000F000F))
    (setf x (logand (logior x (ash x 6)) #x0303030303030303))
    (setf x (logand (logior x (ash x 3)) #x1111111111111111))
    (dolist (m '(#x0001FF0000000000 #x000000FF80000000
                 #x000000007FC00000 #x00000000003FE000))
      (setf tt (logand x m))
      (setf x (logxor x (ash tt -9) (ash tt -10) (ash tt -12) (ash tt -13))))
    (logand x #x1FFF)))

(defun mce13-sqmul (a m)
  (let ((x 0)
        (t0 a)
        (tt 0))
    (setf x (* (ash m 6) (logand t0 (ash 1 6))))
    (setf t0 (logxor t0 (ash t0 7)))
    (setf x (logxor x (* m (logand t0 #x04001))))
    (setf x (logxor x (ash (* m (logand t0 #x08002)) 1)))
    (setf x (logxor x (ash (* m (logand t0 #x10004)) 2)))
    (setf x (logxor x (ash (* m (logand t0 #x20008)) 3)))
    (setf x (logxor x (ash (* m (logand t0 #x40010)) 4)))
    (setf x (logxor x (ash (* m (logand t0 #x80020)) 5)))
    (dolist (mm '(#x0000001FF0000000 #x000000000FF80000 #x000000000007E000))
      (setf tt (logand x mm))
      (setf x (logxor x (ash tt -9) (ash tt -10) (ash tt -12) (ash tt -13))))
    (logand x #x1FFF)))

(defun mce13-sq2mul (a m)
  (let ((x 0)
        (t0 a)
        (t1 m)
        (tt 0))
    (setf x (* (ash t1 18) (logand t0 (ash 1 6))))
    (setf t0 (logxor t0 (ash t0 21)))
    (setf x (logxor x (* t1 (logand t0 #x010000001))))
    (setf x (logxor x (ash (* t1 (logand t0 #x020000002)) 3)))
    (setf x (logxor x (ash (* t1 (logand t0 #x040000004)) 6)))
    (setf x (logxor x (ash (* t1 (logand t0 #x080000008)) 9)))
    (setf x (logxor x (ash (* t1 (logand t0 #x100000010)) 12)))
    (setf x (logxor x (ash (* t1 (logand t0 #x200000020)) 15)))
    (dolist (mm '(#x1FF0000000000000 #x000FF80000000000 #x000007FC00000000
                  #x00000003FE000000 #x0000000001FE0000 #x000000000001E000))
      (setf tt (logand x mm))
      (setf x (logxor x (ash tt -9) (ash tt -10) (ash tt -12) (ash tt -13))))
    (logand x #x1FFF)))

(defun mce-gf-frac-13 (den num)
  (let* ((tmp-11 (mce13-sqmul den den))
         (tmp-1111 (mce13-sq2mul tmp-11 tmp-11))
         (out (mce13-sq2 tmp-1111)))
    (setf out (mce13-sq2mul out tmp-1111))
    (setf out (mce13-sq2 out))
    (setf out (mce13-sq2mul out tmp-1111))
    (mce13-sqmul out num)))

(defun mce-gf-poly-mul (out in0 in1)
  "Multiply degree<SYS_T polys with the set's Goppa reduction."
  (declare (type (simple-array fixnum (*)) out in0 in1)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((tt (mce-sys-t))
        (prod (make-array (1- (* 2 (mce-sys-t))) :element-type 'fixnum
                          :initial-element 0)))
    (declare (type fixnum tt)
             (type (simple-array fixnum (*)) prod))
    (dotimes (i (mce-sys-t))
      (dotimes (j (mce-sys-t))
        (setf (aref prod (+ i j))
              (logxor (aref prod (+ i j))
                      (mce-gf-mul (aref in0 i) (aref in1 j))))))
    (loop for i from (* 2 (1- tt)) downto tt
          do (let ((p (aref prod i)))
               (dolist (r (mce-params-poly-red *mce-params*))
                 (setf (aref prod (+ (- i tt) (car r)))
                       (logxor (aref prod (+ (- i tt) (car r)))
                               (if (cadr r) (mce-gf-mul p 2) p))))))
    (dotimes (i (mce-sys-t) out)
      (setf (aref out i) (aref prod i)))))


;;;
;;; Irreducible-polynomial generation (secret-key generation).
;;;

(defun mce-genpoly (out f)
  "OUT := minimal polynomial of the extension element F.
Returns T on success, NIL when the matrix is not systematic."
  (declare (type (simple-array fixnum (*)) out f)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((mat (make-array (list (1+ (mce-sys-t)) (mce-sys-t))
                         :element-type 'fixnum :initial-element 0))
        (prev (make-array (mce-sys-t) :element-type 'fixnum :initial-element 0))
        (prod (make-array (mce-sys-t) :element-type 'fixnum :initial-element 0)))
    (declare (type (simple-array fixnum (* *)) mat)
             (type (simple-array fixnum (*)) prev prod))
    (setf (aref mat 0 0) 1)
    (dotimes (i (mce-sys-t))
      (setf (aref mat 1 i) (aref f i)))
    (loop for j from 2 to (mce-sys-t)
          do (dotimes (i (mce-sys-t))
               (setf (aref prev i) (aref mat (1- j) i)))
             (mce-gf-poly-mul prod prev f)
             (dotimes (i (mce-sys-t))
               (setf (aref mat j i) (aref prod i))))
    (dotimes (j (mce-sys-t))
      (loop for k from (1+ j) below (mce-sys-t)
            do (when (zerop (aref mat j j))
                 (loop for c from j to (mce-sys-t)
                       do (setf (aref mat c j)
                                (logxor (aref mat c j) (aref mat c k))))))
      (when (zerop (aref mat j j))
        (return-from mce-genpoly nil))
      (let ((inv (mce-gf-inv (aref mat j j))))
        (loop for c from j to (mce-sys-t)
              do (setf (aref mat c j) (mce-gf-mul (aref mat c j) inv)))
        (dotimes (k (mce-sys-t))
          (unless (= k j)
            (let ((tt (aref mat j k)))
              (loop for c from j to (mce-sys-t)
                    do (setf (aref mat c k)
                             (logxor (aref mat c k)
                                     (mce-gf-mul (aref mat c j) tt)))))))))
    (dotimes (i (mce-sys-t) out)
      (setf (aref out i) (aref mat (mce-sys-t) i)))
    t))


;;;
;;; Bit reversal, polynomial evaluation, syndrome, Berlekamp-Massey.
;;;

(defun mce-bitrev16 (x)
  "Reverse the low 16 bits of X."
  (declare (type fixnum x)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf x (logior (ash (logand x #x00FF) 8) (ash (logand x #xFF00) -8)))
  (setf x (logior (ash (logand x #x0F0F) 4) (ash (logand x #xF0F0) -4)))
  (setf x (logior (ash (logand x #x3333) 2) (ash (logand x #xCCCC) -2)))
  (setf x (logior (ash (logand x #x5555) 1) (ash (logand x #xAAAA) -1)))
  x)

(defun mce-bitrev (a)
  "Bit-reversal over GFBITS bits (via 16-bit reversal)."
  (declare (type fixnum a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (if (= (mce-gfbits) 12)
      (ash (mce-bitrev16 a) -4)
      (ash (mce-bitrev16 a) -3)))

(defun mce-eval (f a)
  "Evaluate the degree-SYS_T Goppa polynomial F at field element A."
  (declare (type (simple-array fixnum (*)) f)
           (type fixnum a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (aref f (mce-sys-t))))
    (declare (type fixnum r))
    (loop for i from (1- (mce-sys-t)) downto 0
          do (setf r (logxor (mce-gf-mul r a) (aref f i)))
          finally (return r))))

(defun mce-root (out f l)
  "OUT[i] = F(L[i]) for every support element."
  (declare (type (simple-array fixnum (*)) out f l)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i (mce-sys-n) out)
    (setf (aref out i) (mce-eval f (aref l i)))))

(defun mce-synd (out f l r-bytes)
  "Syndrome of the received word R-BYTES under (F, L), length 2*SYS_T."
  (declare (type (simple-array fixnum (*)) out f l)
           (type (simple-array (unsigned-byte 8) (*)) r-bytes)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((bytes r-bytes))
    (dotimes (j (* 2 (mce-sys-t)))
      (setf (aref out j) 0))
    (dotimes (i (mce-sys-n))
      (let* ((c (ldb (byte 1 (logand i 7)) (aref bytes (ash i -3))))
             (e (mce-eval f (aref l i)))
             (e-inv (mce-gf-inv (mce-gf-mul e e))))
        (when (plusp c)
          (dotimes (j (* 2 (mce-sys-t)))
            (setf (aref out j) (logxor (aref out j) e-inv))
            (setf e-inv (mce-gf-mul e-inv (aref l i))))))))
  (values))

(defun mce-bm (out s)
  "Berlekamp-Massey: minimal polynomial of the syndrome S."
  (let ((C (make-array (1+ (mce-sys-t)) :initial-element 0))
        (B (make-array (1+ (mce-sys-t)) :initial-element 0))
        (temp-b (make-array (1+ (mce-sys-t)) :initial-element 0))
        (lf 0)
        (be 1)
        (d 0))
    (setf (aref C 0) 1 (aref B 1) 1)
    (dotimes (N (* 2 (mce-sys-t)))
      (setf d 0)
      (dotimes (i (1+ (min N (mce-sys-t))))
        (when (<= i N)
          (setf d (logxor d (mce-gf-mul (aref C i) (aref s (- N i)))))))
      (let* ((mne (if (zerop d) 0 1))
             (f (mce-gf-frac be d)))
        (dotimes (i (1+ (mce-sys-t)))
          (setf (aref temp-b i) (aref C i))
          (when (= mne 1)
            (setf (aref C i) (logxor (aref C i) (mce-gf-mul f (aref B i))))))
        (when (and (not (zerop d)) (< (* 2 lf) (+ N 1)))
          (dotimes (i (1+ (mce-sys-t)))
            (setf (aref B i) (aref temp-b i)))
          (setf lf (1+ (- N lf))
                be d))
        (loop for i from (mce-sys-t) downto 1
              do (setf (aref B i) (aref B (1- i))))
        (setf (aref B 0) 0)))
    (dotimes (i (1+ (mce-sys-t)) out)
      (setf (aref out i) (aref C (- (mce-sys-t) i))))))


;;;
;;; Little-endian field loads, support generation, bit packing.
;;;

(defun mce-load-gf (bytes off)
  "Load a 12-bit field element from BYTES at OFF (little-endian)."
  (logand (logior (aref bytes off)
                  (ash (aref bytes (1+ off)) 8))
          (mce-gfmask)))

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

(defun mce-layer-ex (data bits lgs)
  "128-element exterior Benes layer with sequential condition bits."
  (let ((s (ash 1 lgs))
        (k 0))
    (loop for i from 0 below 128 by (* 2 s)
          do (loop for j from i below (+ i s)
                   do (let ((d (logand (logxor (aref data j) (aref data (+ j s)))
                                      (aref bits k))))
                        (setf (aref data j) (logxor (aref data j) d)
                              (aref data (+ j s)) (logxor (aref data (+ j s)) d))
                        (incf k))))
    (values)))

(defun mce-layer-in (data0 data1 bits lgs)
  "Middle Benes layer over two 64-element halves, two bits per pair."
  (let ((s (ash 1 lgs))
        (k 0))
    (loop for i from 0 below 64 by (* 2 s)
          do (loop for j from i below (+ i s)
                   do (let ((d0 (logand (logxor (aref data0 j) (aref data0 (+ j s)))
                                       (aref bits k))))
                        (setf (aref data0 j) (logxor (aref data0 j) d0)
                              (aref data0 (+ j s)) (logxor (aref data0 (+ j s)) d0))
                        (incf k)
                        (let ((d1 (logand (logxor (aref data1 j) (aref data1 (+ j s)))
                                          (aref bits k))))
                          (setf (aref data1 j) (logxor (aref data1 j) d1)
                                (aref data1 (+ j s)) (logxor (aref data1 (+ j s)) d1))
                          (incf k)))))
    (values)))

(defun mce-apply-benes-13 (r bits)
  "Apply the double-width (m=13) Benes network to 1024-bit vector R."
  (let* ((rv (make-array 128 :element-type '(unsigned-byte 64)))
         (rh (make-array 128 :element-type '(unsigned-byte 64)))
         (rv0 (make-array 64 :element-type '(unsigned-byte 64)
                                :displaced-to rv :displaced-index-offset 0))
         (rv1 (make-array 64 :element-type '(unsigned-byte 64)
                                :displaced-to rv :displaced-index-offset 64))
         (rh0 (make-array 64 :element-type '(unsigned-byte 64)
                                :displaced-to rh :displaced-index-offset 0))
         (rh1 (make-array 64 :element-type '(unsigned-byte 64)
                                :displaced-to rh :displaced-index-offset 64))
         (bv (make-array 64 :element-type '(unsigned-byte 64)))
         (bh (make-array 64 :element-type '(unsigned-byte 64)))
         (off 0))
    (dotimes (i 64)
      (setf (aref rv0 i) (mce-load8 r (* i 16))
            (aref rv1 i) (mce-load8 r (+ (* i 16) 8))))
    (mce-transpose-64x64 rh0 rv0)
    (mce-transpose-64x64 rh1 rv1)
    (dotimes (iter 7)
      (dotimes (i 64)
        (setf (aref bv i) (mce-load8 bits off))
        (incf off 8))
      (mce-transpose-64x64 bh bv)
      (mce-layer-ex rh bh iter))
    (mce-transpose-64x64 rv0 rh0)
    (mce-transpose-64x64 rv1 rh1)
    (dotimes (iter 6)
      (dotimes (i 64)
        (setf (aref bv i) (mce-load8 bits off))
        (incf off 8))
      (mce-layer-in rv0 rv1 bv iter))
    (loop for iter from 4 downto 0
          do (dotimes (i 64)
               (setf (aref bv i) (mce-load8 bits off))
               (incf off 8))
             (mce-layer-in rv0 rv1 bv iter))
    (mce-transpose-64x64 rh0 rv0)
    (mce-transpose-64x64 rh1 rv1)
    (loop for iter from 6 downto 0
          do (dotimes (i 64)
               (setf (aref bv i) (mce-load8 bits off))
               (incf off 8))
             (mce-transpose-64x64 bh bv)
             (mce-layer-ex rh bh iter))
    (mce-transpose-64x64 rv0 rh0)
    (mce-transpose-64x64 rv1 rh1)
    (dotimes (i 64)
      (mce-store8 r (* i 16) (aref rv0 i))
      (mce-store8 r (+ (* i 16) 8) (aref rv1 i)))
    (values)))

(defun mce-support-gen (s cond-bytes)
  "Support from condition bits (Benes sieve then bit interleave)."
  (let ((l (make-array (mce-gfbits) :element-type '(simple-array (unsigned-byte 8) (*))))
        (size (truncate (ash 1 (mce-gfbits)) 8)))
    (dotimes (i (mce-gfbits))
      (setf (aref l i) (make-array size :element-type '(unsigned-byte 8)
                                            :initial-element 0)))
    (dotimes (i (ash 1 (mce-gfbits)))
      (let ((a (mce-bitrev i)))
        (dotimes (j (mce-gfbits))
          (setf (aref (aref l j) (truncate i 8))
                (logior (aref (aref l j) (truncate i 8))
                        (ash (ldb (byte 1 j) a) (mod i 8)))))))
    (dotimes (j (mce-gfbits))
      (if (= (mce-gfbits) 12)
          (mce-apply-benes (aref l j) cond-bytes)
          (mce-apply-benes-13 (aref l j) cond-bytes)))
    (dotimes (i (mce-sys-n))
      (let ((v 0))
        (loop for j from (1- (mce-gfbits)) downto 0
              do (setf v (ash v 1))
                 (setf v (logior v (ldb (byte 1 (mod i 8))
                                        (aref (aref l j) (truncate i 8))))))
        (setf (aref s i) v)))))


;;;
;;; Control bits (Nassimi-Sahni Benes network setup).
;;;

(declaim (inline mce-u32 mce-s32))
(defun mce-u32 (x)
  (declare (type fixnum x)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (logand x #xFFFFFFFF))

(defun mce-s32 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (if (>= x #x80000000)
      (- x #x100000000)
      x))

(defun mce-int32-min (a b)
  (declare (type (unsigned-byte 32) a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (if (< (logxor a #x80000000) (logxor b #x80000000)) a b))

(defun mce-int32-sort (vec)
  "Stable LSD radix sort of VEC by signed 32-bit value."
  (declare (type (array (unsigned-byte 32) (*)) vec)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length vec))
         (work (make-array n :element-type '(unsigned-byte 32)))
         (tmp (make-array n :element-type '(unsigned-byte 32)))
         (cnt (make-array 256 :element-type 'fixnum :initial-element 0)))
    (declare (type fixnum n)
             (type (simple-array (unsigned-byte 32) (*)) work tmp)
             (type (simple-array fixnum (*)) cnt))
    (dotimes (i n)
      (setf (aref work i) (aref vec i)))
    (macrolet ((pass (shift)
                 `(progn
                    (dotimes (b 256)
                      (setf (aref cnt b) 0))
                    (dotimes (i n)
                      (let* ((v (aref work i))
                            (k (logxor v #x80000000))
                            (b (logand (ash k ,(- shift)) #xFF)))
                        (declare (type fixnum b))
                        (incf (aref cnt b))))
                    (let ((sum 0))
                      (declare (type fixnum sum))
                      (dotimes (b 256)
                        (let ((c (aref cnt b)))
                          (setf (aref cnt b) sum)
                          (incf sum c))))
                    (dotimes (i n)
                      (let* ((v (aref work i))
                            (k (logxor v #x80000000))
                            (b (logand (ash k ,(- shift)) #xFF))
                            (p (aref cnt b)))
                        (declare (type fixnum b p))
                        (setf (aref tmp p) v)
                        (setf (aref cnt b) (1+ p))))
                    (dotimes (i n)
                      (setf (aref work i) (aref tmp i))))))
      (pass 0) (pass 8) (pass 16) (pass 24))
    (dotimes (i n)
      (setf (aref vec i) (aref work i)))
    vec))

(defun mce-cblayer (p cb ptr s n)
  "Apply one int16 Benes layer with control bits CB at byte offset PTR."
  (declare (type (simple-array fixnum (*)) p)
           (type (simple-array (unsigned-byte 8) (*)) cb)
           (type fixnum ptr s n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((stride (ash 1 s))
        (index 0))
    (declare (type fixnum stride index))
    (loop for i from 0 below n by (* stride 2)
          do (dotimes (j stride)
               (let* ((a (aref p (+ i j)))
                      (b (aref p (+ i j stride)))
                      (d (logxor a b))
                      (m (ldb (byte 1 (logand index 7))
                              (aref cb (+ ptr (ash index -3))))))
                 (unless (zerop m)
                   (setf (aref p (+ i j)) (logxor a d)
                         (aref p (+ i j stride)) (logxor b d)))
                 (incf index)))))
  (values))

(defun mce-cb-small (a b n w)
  "Refinement loop for widths <= 10."
  (declare (type (array (unsigned-byte 32) (*)) a b)
           (type fixnum n w)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
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
  (declare (type (array (unsigned-byte 32) (*)) a b)
           (type fixnum n w)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
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
  (declare (type (simple-array (unsigned-byte 8) (*)) out)
           (type fixnum pos step w n)
           (type (array fixnum (*)) pil)
           (type (simple-array (unsigned-byte 32) (*)) temp)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
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
                                 (logxor (aref out o)
                                          (if (zerop fj) 0
                                              (aref *mce-bit-values* (logand pos 7))))))
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
                                 (logxor (aref out o)
                                         (if (zerop lk) 0
                                             (aref *mce-bit-values* (logand pos 7))))))
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
  (declare (type (simple-array (unsigned-byte 8) (*)) out)
           (type (simple-array fixnum (*)) pil)
           (type fixnum w n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((temp (make-array (* 2 n) :element-type '(unsigned-byte 32)
                                     :initial-element 0))
        (ptest (make-array n :element-type 'fixnum :initial-element 0))
        (nbytes (truncate (+ (truncate (* (1- (* 2 w)) n) 2) 7) 8)))
    (declare (type (simple-array (unsigned-byte 32) (*)) temp)
             (type (simple-array fixnum (*)) ptest)
             (type fixnum nbytes))
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
  (declare (type (simple-array fixnum (*)) piv)
           (type (simple-array (unsigned-byte 32) (*)) perm)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (mce-perm-len))
         (keys (make-array n :element-type '(unsigned-byte 64)))
         (tmp (make-array n :element-type '(unsigned-byte 64)))
         (cnt (make-array 4096 :element-type 'fixnum :initial-element 0)))
    (declare (type fixnum n)
             (type (simple-array (unsigned-byte 64) (*)) keys tmp)
             (type (simple-array fixnum (*)) cnt))
    (dotimes (i n)
      (setf (aref keys i)
            (logior (ash (aref perm i) 16) i)))
    (macrolet ((pass (shift)
                 `(progn
                    (dotimes (b 4096)
                      (setf (aref cnt b) 0))
                    (dotimes (i n)
                      (incf (aref cnt (logand (ash (aref keys i) ,(- shift))
                                              #xFFF))))
                    (let ((sum 0))
                      (dotimes (b 4096)
                        (let ((c (aref cnt b)))
                          (setf (aref cnt b) sum)
                          (incf sum c))))
                    (dotimes (i n)
                      (let* ((v (aref keys i))
                             (b (logand (ash v ,(- shift)) #xFFF))
                             (p (aref cnt b)))
                        (setf (aref tmp p) v)
                        (setf (aref cnt b) (1+ p))))
                    (dotimes (i n)
                      (setf (aref keys i) (aref tmp i))))))
      (pass 0) (pass 12) (pass 24) (pass 36))
    (loop for j from 1 below n
          do (when (= (ash (aref keys (1- j)) -16)
                      (ash (aref keys j) -16))
               (return-from mce-perm-check nil)))
    (dotimes (j n)
      (setf (aref piv j) (logand (aref keys j) #xFFFF)))
    t))

(declaim (inline mce-word-row-byte mce-word-row-bit))
(defun mce-row-byte-to-words (bytes nbytes wordlen)
  "Pack an octet row into 64-bit words, zero-padding the tail."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type fixnum nbytes wordlen)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((row (make-array wordlen :element-type '(unsigned-byte 64)
                        :initial-element 0)))
    (declare (type (simple-array (unsigned-byte 64) (*)) row))
    (dotimes (i nbytes row)
      (setf (aref row (ash i -3))
            (dpb (aref bytes i)
                 (byte 8 (* 8 (logand i 7)))
                 (aref row (ash i -3)))))))

(declaim (inline mce-row-xor!))
(defun mce-row-xor! (dst src start end)
  "DST[START..END) := DST[START..END) XOR SRC[START..END), word by word.
The McEliece elimination calls this once per eliminated row, so the
inner loop is worth vectorizing."
  (declare (type (simple-array (unsigned-byte 64) (*)) dst src)
           (type index start end)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (mce-xor-words dst src start (- end start))
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  ;; ABCL's LOOP refuses `of-type index' here ("couldn't verify that
  ;; INDEX is a subtype of NUMBER") and turns the warning into a
  ;; compile failure; FIXNUM is accepted everywhere.
  (loop for c of-type fixnum from start below end
        do (setf (aref dst c) (logxor (aref dst c) (aref src c))))
  (values))

(declaim (inline mce-word-row-byte mce-word-row-bit))
(defun mce-word-row-byte (row byte-index)
  (declare (type (simple-array (unsigned-byte 64) (*)) row)
           (type fixnum byte-index)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (ldb (byte 8 (* 8 (logand byte-index 7)))
       (aref row (ash byte-index -3))))

(defun mce-word-row-bit (row byte-index bit-index)
  (declare (type (simple-array (unsigned-byte 64) (*)) row)
           (type fixnum byte-index bit-index)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (ldb (byte 1 (+ (* 8 (logand byte-index 7)) bit-index))
       (aref row (ash byte-index -3))))

(defun mce-pk-gen (pk sk perm piv)
  "PK := public key for secret Goppa bytes SK and permutation PERM.
PIV is permutation-sized scratch/output. Returns T on success, NIL on failure."
  (declare (type (simple-array (unsigned-byte 8) (*)) pk sk)
           (type (simple-array (unsigned-byte 32) (*)) perm)
           (type (simple-array fixnum (*)) piv)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (mce-perm-check piv perm)
    (return-from mce-pk-gen nil))
  (let ((g (make-array (1+ (mce-sys-t)) :element-type 'fixnum :initial-element 0))
        (l (make-array (mce-sys-n) :element-type 'fixnum))
        (inv (make-array (mce-sys-n) :element-type 'fixnum))
        (rows (make-array (mce-pk-nrows)))
        (wordrows (make-array (mce-pk-nrows)))
        (nbytes (ash (mce-sys-n) -3))
        (wordlen (ceiling (ash (mce-sys-n) -3) 8)))
    (declare (type (simple-array fixnum (*)) g l inv)
             (type simple-vector rows wordrows)
             (type index nbytes wordlen))
    (setf (aref g (mce-sys-t)) 1)
    (dotimes (i (mce-sys-t))
      (setf (aref g i) (mce-load-gf sk (* i 2))))
    (dotimes (i (mce-sys-n))
      (setf (aref l i) (mce-bitrev (aref piv i))))
    (dotimes (i (mce-pk-nrows))
      (setf (aref rows i)
            (make-array nbytes :element-type '(unsigned-byte 8)
                        :initial-element 0)))
    (mce-root inv g l)
    (dotimes (i (mce-sys-n))
      (setf (aref inv i) (mce-gf-inv (aref inv i))))
    (dotimes (i (mce-sys-t))
      (loop for j from 0 below (mce-sys-n) by 8
            do (let* ((base (truncate j 8))
                      (v0 (aref inv j)) (v1 (aref inv (+ j 1)))
                      (v2 (aref inv (+ j 2))) (v3 (aref inv (+ j 3)))
                      (v4 (aref inv (+ j 4))) (v5 (aref inv (+ j 5)))
                      (v6 (aref inv (+ j 6))) (v7 (aref inv (+ j 7))))
                 (declare (type fixnum base v0 v1 v2 v3 v4 v5 v6 v7))
                 ;; One byte per bit plane, eight elements at a time.
                 ;; Building the byte with a chain of (ash b 1) and a
                 ;; variable-position ldb cost eight times as much as
                 ;; this single or-tree; it was most of the keypair
                 ;; generation time.
                 (dotimes (k (mce-gfbits))
                   (let* ((shift (- k))
                          (b (logior
                              (ash (logand 1 (ash v7 shift)) 7)
                              (ash (logand 1 (ash v6 shift)) 6)
                              (ash (logand 1 (ash v5 shift)) 5)
                              (ash (logand 1 (ash v4 shift)) 4)
                              (ash (logand 1 (ash v3 shift)) 3)
                              (ash (logand 1 (ash v2 shift)) 2)
                              (ash (logand 1 (ash v1 shift)) 1)
                              (logand 1 (ash v0 shift))))
                          (rk (aref rows (+ (* i (mce-gfbits)) k))))
                     (declare (type (simple-array (unsigned-byte 8) (*)) rk)
                              (type (unsigned-byte 8) b))
                     (setf (aref rk base) b)))))
      (dotimes (j (mce-sys-n))
        (setf (aref inv j) (mce-gf-mul (aref inv j) (aref l j)))))
    (dotimes (i (mce-pk-nrows))
      (setf (aref wordrows i)
            (mce-row-byte-to-words (aref rows i) nbytes wordlen)))
    (setf rows (make-array 0))
    (loop for i from 0 below (ceiling (mce-pk-nrows) 8)
          do (dotimes (j 8)
                 (let ((row (+ (* i 8) j)))
                   (when (>= row (mce-pk-nrows))
                     (return))
                   ;; The pivot column is the global column I*8+J, which
                   ;; lives in word (ASH I -3) at bit (I&7)*8+J.  Every
                   ;; column left of it is already reduced to zero in all
                   ;; rows, so the row XORs can start at that word.
                   ;; NB: 64-bit words must not be used directly as an
                   ;; IF condition: SBCL treats the type as always true.
                   (let* ((w (ash i -3))
                          (mask (aref *mce-bit-masks* (+ (* 8 (logand i 7)) j)))
                          (rr (aref wordrows row)))
                     (declare (type index w)
                              (type (unsigned-byte 64) mask)
                              (type (simple-array (unsigned-byte 64) (*)) rr))
                     (let ((rbit (if (zerop (logand (aref rr w) mask)) 0 1)))
                       (declare (type bit rbit))
                       (loop for k from (1+ row) below (mce-pk-nrows)
                             do (let ((rk (aref wordrows k)))
                                  (declare (type (simple-array (unsigned-byte 64) (*)) rk))
                                  (when (/= rbit (if (zerop (logand (aref rk w) mask))
                                                      0 1))
                                    (mce-row-xor! rr rk w wordlen)
                                    (setf rbit 1))))
                       (when (zerop rbit)
                         (return-from mce-pk-gen nil)))
                     (dotimes (k (mce-pk-nrows))
                       (unless (= k row)
                         (let ((rk (aref wordrows k)))
                           (declare (type (simple-array (unsigned-byte 64) (*)) rk))
                           (when (not (zerop (logand (aref rk w) mask)))
                             (mce-row-xor! rk rr w wordlen)))))))))
    (let ((tail (mod (mce-pk-nrows) 8)))
      (if (zerop tail)
          (dotimes (i (mce-pk-nrows))
            (let ((rr (aref wordrows i)))
              (declare (type (simple-array (unsigned-byte 64) (*)) rr))
              (dotimes (j (mce-pk-row-bytes))
                (setf (aref pk (+ (* i (mce-pk-row-bytes)) j))
                      (mce-word-row-byte rr
                                         (+ (truncate (mce-pk-nrows) 8)
                                            j))))))
          (let ((base (truncate (1- (mce-pk-nrows)) 8)))
            (dotimes (i (mce-pk-nrows))
              (let ((rr (aref wordrows i))
                    (po (* i (mce-pk-row-bytes))))
                (declare (type (simple-array (unsigned-byte 64) (*)) rr))
                (loop for j from base below (1- nbytes)
                      do (setf (aref pk po)
                               (logand #xFF
                                       (logior
                                        (ash (mce-word-row-byte rr j)
                                             (- tail))
                                        (ash (mce-word-row-byte rr (1+ j))
                                             (- 8 tail)))))
                         (incf po))
                (setf (aref pk po)
                      (ash (mce-word-row-byte rr (1- nbytes))
                           (- tail))))))))
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
        (pk (make-array (mce-pk-bytes) :element-type '(unsigned-byte 8)
                                          :initial-element 0))
        (sk (make-array (mce-sk-bytes) :element-type '(unsigned-byte 8)
                                          :initial-element 0))
        (f (make-array (mce-sys-t) :element-type 'fixnum :initial-element 0))
        (irr (make-array (mce-sys-t) :element-type 'fixnum :initial-element 0))
        (irr-bytes (make-array (mce-irr-bytes)
                               :element-type '(unsigned-byte 8)
                               :initial-element 0))
        (perm (make-array (ash 1 (mce-gfbits)) :element-type '(unsigned-byte 32)
                                                     :initial-element 0))
        (piv (make-array (ash 1 (mce-gfbits)) :element-type 'fixnum
                                                   :initial-element 0))
        (cond-bytes (make-array (mce-cond-bytes)
                                :element-type '(unsigned-byte 8)
                                :initial-element 0)))
    (setf (aref seed 0) 64)
    (replace seed seed32 :start1 1)
    (loop
      (let* ((rlen (mce-r-len))
             (f-off (- rlen 32 (* 2 (mce-sys-t))))
             (perm-off (- rlen 32 (* 2 (mce-sys-t)) (* 4 (mce-perm-len))))
             (nbytes (ash (mce-sys-n) -3))
             (irr-off 40)
             (cond-off (+ 40 (mce-irr-bytes)))
             (s-off (+ 40 (mce-irr-bytes) (mce-cond-bytes)))
             (r (mce-shake256 seed rlen)))
        (replace sk seed :start2 1 :end2 33)
        (replace seed r :start1 1 :start2 (- rlen 32))
        (dotimes (i (mce-sys-t))
          (setf (aref f i) (mce-load-gf r (+ f-off (* i 2)))))
        (when (mce-genpoly irr f)
          (dotimes (i (mce-sys-t))
            (mce-store-gf irr-bytes (* i 2) (aref irr i)))
          (dotimes (i (ash 1 (mce-gfbits)))
            (setf (aref perm i) (mce-load4 r (+ perm-off (* i 4)))))
          (when (mce-pk-gen pk irr-bytes perm piv)
            (replace sk irr-bytes :start1 irr-off)
            (mce-controlbits cond-bytes piv (mce-gfbits) (ash 1 (mce-gfbits)))
            (replace sk cond-bytes :start1 cond-off)
            (replace sk r :start1 s-off :end2 nbytes)
            (mce-store8 sk 32 #xFFFFFFFF)
            (return (values pk sk))))))))

(defun mce-gen-e (e random-fn)
  "Random weight-SYS_T error vector into E (436 bytes)."
  (loop
    (let ((buf (funcall random-fn (* 4 (mce-sys-t))))
          (ind (make-array (mce-sys-t) :element-type 'fixnum))
          (count 0))
      (dotimes (i (* 2 (mce-sys-t)))
        (when (< count (mce-sys-t))
          (let ((tgt (mce-load-gf buf (* i 2))))
            (when (< tgt (mce-sys-n))
              (setf (aref ind count) tgt)
              (incf count)))))
      (when (= count (mce-sys-t))
        (let ((distinct t))
          (loop for i from 1 below (mce-sys-t)
                do (loop for j from 0 below i
                         do (when (= (aref ind i) (aref ind j))
                              (setf distinct nil))))
          (when distinct
            (fill e 0)
            (dotimes (j (mce-sys-t))
              (let ((tgt (aref ind j)))
                (setf (aref e (ash tgt -3))
                      (logior (aref e (ash tgt -3))
                              (aref *mce-bit-values* (logand tgt 7))))))
            (return e)))))))

(declaim (inline mce-parity-byte))
(defun mce-parity-byte (b)
  "Parity bit of B (octet); only the final bit is meaningful."
  (declare (type (unsigned-byte 8) b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf b (logxor b (ash b -4)))
  (setf b (logxor b (ash b -2)))
  (setf b (logxor b (ash b -1)))
  (logand b 1))

(defun mce-syndrome-bytes-aligned (s pk e)
  "Fast syndrome computation for byte-aligned public-key row counts."
  (declare (type (simple-array (unsigned-byte 8) (*)) s pk e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((nbytes (ash (mce-sys-n) -3))
         (nrows (mce-pk-nrows))
         (rowbytes (mce-pk-row-bytes))
         (offset (- nbytes rowbytes))
         (id-pos (make-array nbytes :element-type 'fixnum :initial-element 0))
         (row-pos (make-array nbytes :element-type 'fixnum :initial-element 0))
         (n-id 0)
         (n-row 0))
    (declare (type fixnum nbytes nrows rowbytes offset n-id n-row)
             (type (simple-array fixnum (*)) id-pos row-pos))
    (dotimes (j nbytes)
      (unless (zerop (aref e j))
        (if (< j offset)
            (progn
              (setf (aref id-pos n-id) j)
              (incf n-id))
            (progn
              (setf (aref row-pos n-row) j)
              (incf n-row)))))
    (dotimes (i (mce-synd-bytes))
      (setf (aref s i) 0))
    (dotimes (i nrows)
      (let ((b 0)
            (q (ash i -3)))
        (dotimes (k n-id)
          (let ((j (aref id-pos k)))
            (when (and (= j q)
                       (logbitp (logand i 7) (aref e q)))
              (setf b (logxor b 1)))))
        (let ((base (* i rowbytes)))
          (dotimes (k n-row)
            (let ((j (aref row-pos k)))
              (setf b (logxor b (logand (aref pk (+ base (- j offset)))
                                        (aref e j)))))))
        (setf b (mce-parity-byte b))
        (setf (aref s q)
              (logior (aref s q) (logand (logand b 1) (aref *mce-bit-values* (logand i 7)))))))
    (values)))

(defun mce-syndrome-bytes-shifted (s pk e)
  "Fast syndrome computation for bit-shifted public-key row counts."
  (declare (type (simple-array (unsigned-byte 8) (*)) s pk e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((nbytes (ash (mce-sys-n) -3))
         (nrows (mce-pk-nrows))
         (rowbytes (mce-pk-row-bytes))
         (tail (mod nrows 8))
         (offset (- nbytes rowbytes))
         (id-pos (make-array nbytes :element-type 'fixnum :initial-element 0))
         (row-pos (make-array nbytes :element-type 'fixnum :initial-element 0))
         (n-id 0)
         (n-row 0))
    (declare (type fixnum nbytes nrows rowbytes tail offset n-id n-row)
             (type (simple-array fixnum (*)) id-pos row-pos))
    (dotimes (j nbytes)
      (unless (zerop (aref e j))
        (if (< j offset)
            (progn
              (setf (aref id-pos n-id) j)
              (incf n-id))
            (progn
              (setf (aref row-pos n-row) j)
              (incf n-row)))))
    (dotimes (i (mce-synd-bytes))
      (setf (aref s i) 0))
    (dotimes (i nrows)
      (let ((b 0)
            (q (ash i -3))
            (ib (aref *mce-bit-values* (logand i 7)))
            (base (* i rowbytes)))
        (dotimes (k n-id)
          (let ((j (aref id-pos k)))
            (when (= j q)
              (setf b (logxor b (logand (aref e q) ib))))))
        (dotimes (k n-row)
          (let* ((j (aref row-pos k))
                 (m (- j offset))
                 (row-byte (logand #xFF
                                   (logior (ash (aref pk (+ base m)) tail)
                                           (if (plusp m)
                                               (ash (aref pk (+ base (1- m)))
                                                    (- tail 8))
                                               0)))))
            (when (and (= j offset) (= q offset))
              (setf row-byte (logior row-byte ib)))
            (setf b (logxor b (logand row-byte (aref e j))))))
        (setf b (mce-parity-byte b))
        (setf (aref s q)
              (logior (aref s q) (logand (logand b 1) (aref *mce-bit-values* (logand i 7)))))))
    (values)))

(defun mce-syndrome-bytes (s pk e)
  "Niederreiter syndrome S of error vector E under PK."
  (if (zerop (mod (mce-pk-nrows) 8))
      (mce-syndrome-bytes-aligned s pk e)
      (mce-syndrome-bytes-shifted s pk e)))

(defun mce-encrypt (ct pk e)
  "Syndrome ciphertext CT of the given error vector E under PK."
  (mce-syndrome-bytes ct pk e)
  (values))

(defun mce-pk-transpose (pk)
  "Column-major copy of the public key's parity part.
Entry (c, i) is bit C of row I of the packed parity matrix."
  (declare (type (simple-array (unsigned-byte 8) (*)) pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((nrows (mce-pk-nrows))
         (rowbytes (mce-pk-row-bytes))
         (sbytes (mce-synd-bytes))
         (ncols (- (mce-sys-n) nrows))
         (out (make-array (* ncols sbytes)
                          :element-type '(unsigned-byte 8) :initial-element 0)))
    (declare (type fixnum nrows rowbytes sbytes ncols)
             (type (simple-array (unsigned-byte 8) (*)) out))
    (dotimes (i nrows)
      (let ((base (* i rowbytes))
            (q (ash i -3))
            (bit (logand i 7)))
        (declare (type fixnum base q bit))
        (dotimes (c ncols)
          (declare (type fixnum c))
          (when (logbitp (logand c 7) (aref pk (+ base (ash c -3))))
            (let ((idx (+ (* c sbytes) q)))
              (declare (type fixnum idx))
              (setf (aref out idx)
                    (logior (aref out idx) (aref *mce-bit-values* bit))))))))
    out))

(defun mce-encrypt-transposed (s pk-t e)
  "Syndrome S = PK*E using the column-major parity copy PK-T."
  (declare (type (simple-array (unsigned-byte 8) (*)) s pk-t e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((nrows (mce-pk-nrows))
         (sbytes (mce-synd-bytes))
         (ncols (- (mce-sys-n) nrows))
         (rem (mod nrows 8)))
    (declare (type fixnum nrows sbytes ncols rem))
    (dotimes (i sbytes)
      (setf (aref s i) (aref e i)))
    (when (plusp rem)
      (setf (aref s (1- sbytes))
            (logand (aref s (1- sbytes)) (1- (ash 1 rem)))))
    (dotimes (c ncols)
      (let ((p (+ nrows c)))
        (declare (type fixnum c p))
        (when (logbitp (logand p 7) (aref e (ash p -3)))
          (let ((base (* c sbytes)))
            (declare (type fixnum base))
            (dotimes (i sbytes)
              (setf (aref s i)
                    (logxor (aref s i) (aref pk-t (+ base i))))))))))
  (values))

(defun mce-decrypt (e sk c)
  "Niederreiter decrypt C under SK into E; T on success."
  (let* ((tt (mce-sys-t))
         (nbytes (ash (mce-sys-n) -3))
         (r (make-array nbytes :element-type '(unsigned-byte 8) :initial-element 0))
         (g (make-array (1+ tt) :element-type 'fixnum :initial-element 0))
         (l (make-array (mce-sys-n) :element-type 'fixnum))
         (s (make-array (* 2 tt) :element-type 'fixnum))
         (s-cmp (make-array (* 2 tt) :element-type 'fixnum))
         (locator (make-array (1+ tt) :element-type 'fixnum))
         (images (make-array (mce-sys-n) :element-type 'fixnum))
         (irr-off 40)
         (cond-off (+ 40 (mce-irr-bytes))))
    (replace r c :end2 (mce-synd-bytes))
    (dotimes (i (mce-sys-t))
      (setf (aref g i) (mce-load-gf sk (+ irr-off (* i 2)))))
    (setf (aref g (mce-sys-t)) 1)
    (mce-support-gen l (subseq sk cond-off (+ cond-off (mce-cond-bytes))))
    (mce-synd s g l r)
    (mce-bm locator s)
    (mce-root images locator l)
    (fill e 0)
    (let ((w 0))
      (dotimes (i (mce-sys-n))
        (let ((tgt (if (zerop (aref images i)) 1 0)))
          (setf (aref e (ash i -3))
                (logior (aref e (ash i -3)) (ash tgt (logand i 7))))
          (incf w tgt)))
      (mce-synd s-cmp g l e)
      (and (= w (mce-sys-t))
           (dotimes (i (* 2 tt) t)
             (unless (= (aref s i) (aref s-cmp i))
               (return nil)))))))

(defun mce-check-pk-padding (pk)
  "T when pk row padding bits are all zero (vacuous if byte-aligned)."
  (let ((rem (mod (- (mce-sys-n) (mce-pk-nrows)) 8)))
    (if (zerop rem)
        t
        (let ((b 0)
              (rb (mce-pk-row-bytes)))
          (dotimes (i (mce-pk-nrows))
            (setf b (logior b (aref pk (+ (* i rb) (1- rb))))))
          (zerop (ash b (- rem)))))))

(defun mce-check-c-padding (ct)
  "T when ct padding bits are all zero (vacuous if byte-aligned)."
  (let ((rem (mod (mce-pk-nrows) 8)))
    (if (zerop rem)
        t
        (zerop (ash (aref ct (1- (mce-synd-bytes))) (- rem))))))

(defun mce-encaps-from-error (e pk &optional pk-t)
  "Deterministic encapsulation with error vector E; returns (ct ss).
When PK-T (a column-major copy of PK's parity part) is supplied, use it."
  (let* ((nbytes (ash (mce-sys-n) -3))
         (ct (make-array (mce-ct-bytes) :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
    (if pk-t
        (mce-encrypt-transposed ct pk-t e)
        (mce-encrypt ct pk e))
    (let ((pre (make-array (+ 1 nbytes (mce-synd-bytes))
                           :element-type '(unsigned-byte 8)
                           :initial-element 0)))
      (setf (aref pre 0) 1)
      (replace pre e :start1 1)
      (replace pre ct :start1 (+ 1 nbytes))
      (let ((ss (mce-shake256 pre 32)))
        (unless (mce-check-pk-padding pk)
          (fill ct 0)
          (fill ss 0))
        (values ct ss)))))

(defun mce-decapsulate (ct sk)
  "Decapsulation with implicit rejection; returns 32-byte secret."
  (let* ((nbytes (ash (mce-sys-n) -3))
         (e (make-array nbytes :element-type '(unsigned-byte 8) :initial-element 0))
         (pre (make-array (+ 1 nbytes (mce-synd-bytes))
                          :element-type '(unsigned-byte 8)
                          :initial-element 0))
         (s-off (+ 40 (mce-irr-bytes) (mce-cond-bytes))))
    (if (mce-decrypt e sk ct)
        (progn (setf (aref pre 0) 1)
               (replace pre e :start1 1))
        (progn (setf (aref pre 0) 0)
               (replace pre sk :start1 1 :start2 s-off :end2 (mce-sk-bytes))))
    (replace pre ct :start1 (+ 1 nbytes))
    (let ((ss (mce-shake256 pre 32)))
      (unless (mce-check-c-padding ct)
        (fill ss #xFF))
      ss)))


;;;
;;; Public API: key classes, generation, encapsulation.
;;;

(defclass mceliece-key ()
  ((kind :initarg :kind :reader mceliece-key-kind)
   (bytes :initarg :bytes :reader mceliece-key-bytes)))

(defclass mceliece-public-key (mceliece-key)
  ((transposed :initform nil :accessor mceliece-public-key-transposed)))

(defclass mceliece-private-key (mceliece-key)
  ())

(defclass mceliece348864-public-key (mceliece-public-key)
  ())

(defclass mceliece348864-private-key (mceliece-private-key)
  ())

(defclass mceliece460896-public-key (mceliece-public-key)
  ())

(defclass mceliece460896-private-key (mceliece-private-key)
  ())

(defclass mceliece6688128-public-key (mceliece-public-key)
  ())

(defclass mceliece6688128-private-key (mceliece-private-key)
  ())

(defclass mceliece6960119-public-key (mceliece-public-key)
  ())

(defclass mceliece6960119-private-key (mceliece-private-key)
  ())

(defclass mceliece8192128-public-key (mceliece-public-key)
  ())

(defclass mceliece8192128-private-key (mceliece-private-key)
  ())

(defun mce-check-bytes (bytes length kind)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) length))
    (error 'missing-key-parameter
           :kind kind
           :parameter 'bytes
           :description "McEliece key bytes"))
  (copy-seq bytes))

(defmacro mce-define-key-constructors (kind public-class private-class)
  `(progn
     (defmethod make-public-key ((kind (eql ,kind)) &key bytes &allow-other-keys)
       (let ((*mce-params* (mce-params-for-kind ,kind)))
         (make-instance ',public-class :kind ,kind
                                          :bytes (mce-check-bytes bytes
                                                                  (mce-pk-bytes)
                                                                  ,kind))))
     (defmethod make-private-key ((kind (eql ,kind)) &key bytes &allow-other-keys)
       (let ((*mce-params* (mce-params-for-kind ,kind)))
         (make-instance ',private-class :kind ,kind
                                           :bytes (mce-check-bytes bytes
                                                                   (mce-sk-bytes)
                                                                   ,kind))))
     (defmethod generate-key-pair ((kind (eql ,kind)) &key &allow-other-keys)
       (let ((*mce-params* (mce-params-for-kind ,kind)))
         (multiple-value-bind (pk sk)
             (mce-keypair-from-seed (random-data 32))
           (values (make-private-key ,kind :bytes sk)
                   (make-public-key ,kind :bytes pk)))))))

(mce-define-key-constructors :mceliece348864 mceliece348864-public-key mceliece348864-private-key)
(mce-define-key-constructors :mceliece460896 mceliece460896-public-key mceliece460896-private-key)
(mce-define-key-constructors :mceliece6688128 mceliece6688128-public-key mceliece6688128-private-key)
(mce-define-key-constructors :mceliece6960119 mceliece6960119-public-key mceliece6960119-private-key)
(mce-define-key-constructors :mceliece8192128 mceliece8192128-public-key mceliece8192128-private-key)

(defmethod destructure-public-key ((public-key mceliece-public-key))
  (list :bytes (copy-seq (mceliece-key-bytes public-key))))

(defmethod destructure-private-key ((private-key mceliece-private-key))
  (list :bytes (copy-seq (mceliece-key-bytes private-key))))

(defmethod encapsulate-key ((public-key mceliece-public-key))
  (let ((*mce-params* (mce-params-for-kind (mceliece-key-kind public-key))))
    (let ((e (make-array (ash (mce-sys-n) -3) :element-type '(unsigned-byte 8)
                                                     :initial-element 0))
          (pk (mceliece-key-bytes public-key)))
      (mce-gen-e e (lambda (k) (random-data k)))
      (unless (mceliece-public-key-transposed public-key)
        (setf (mceliece-public-key-transposed public-key)
              (mce-pk-transpose pk)))
      (mce-encaps-from-error e pk
                             (mceliece-public-key-transposed public-key)))))

(defmethod decapsulate-key ((private-key mceliece-private-key) ciphertext)
  (let ((*mce-params* (mce-params-for-kind (mceliece-key-kind private-key))))
    (unless (and (typep ciphertext '(simple-array (unsigned-byte 8) (*)))
                 (= (length ciphertext) (mce-ct-bytes)))
      (error 'invalid-message-length :kind (mceliece-key-kind private-key)))
    (mce-decapsulate ciphertext (mceliece-key-bytes private-key))))
