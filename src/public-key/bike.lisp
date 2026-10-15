;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; bike.lisp -- BIKE KEM family (bike-l1/l3/l5).
;;;;
;;;; Direct translation of the portable (non-AVX) paths of the AWS
;;;; bike-kem reference implementation: QC-MDPC codes with BGF decoder.

(in-package :crypto)


;;;
;;; Parameters: one struct per level, selected via *BIKE-PARAMS*.
;;;

(defstruct bike-params
  kind r-bits r-bytes r-qwords r-padded-qwords d tt
  thr-coeff0 thr-coeff1 thr-min
  last-qword-lead last-qword-trail last-qword-mask last-byte-mask
  sk-bytes pk-bytes ct-bytes ss-bytes
  max-i exp0-k exp0-l exp1-k exp1-l)

(defparameter +bike-l1-params+
  (make-bike-params :kind :bike-l1 :r-bits 12323 :r-bytes 1541 :r-qwords 193
                   :r-padded-qwords 256 :d 71 :tt 134
                   :thr-coeff0 1353000000 :thr-coeff1 697220 :thr-min 36
                   :last-qword-lead 35 :last-qword-trail 29
                   :last-qword-mask #x7FFFFFFFF
                   :last-byte-mask #x07
                   :sk-bytes 5223 :pk-bytes 1541 :ct-bytes 1573 :ss-bytes 32
                   :max-i 14
                   :exp0-k #(1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192)
                   :exp0-l #(6162 3081 3851 5632 22 484 119 1838 1742 3106
                             10650 1608 10157 8816)
                   :exp1-k #(0 0 0 0 0 1 0 0 0 0 0 0 33 4129)
                   :exp1-l #(0 0 0 0 0 6162 0 0 0 0 0 0 242 5717)))

(defparameter +bike-l3-params+
  (make-bike-params :kind :bike-l3 :r-bits 24659 :r-bytes 3083 :r-qwords 386
                   :r-padded-qwords 512 :d 103 :tt 199
                   :thr-coeff0 1525880000 :thr-coeff1 526500 :thr-min 52
                   :last-qword-lead 19 :last-qword-trail 45
                   :last-qword-mask #x7FFFF
                   :last-byte-mask #x07
                   :sk-bytes 10105 :pk-bytes 3083 :ct-bytes 3115 :ss-bytes 32
                   :max-i 15
                   :exp0-k #(1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192
                             16384)
                   :exp0-l #(12330 6165 7706 3564 2711 1139 15053 1258 4388
                             20524 9538 6393 10486 1715 6804)
                   :exp1-k #(0 0 0 0 1 0 17 0 0 0 0 0 0 81 8273)
                   :exp1-l #(0 0 0 0 12330 0 13685 0 0 0 0 0 0 23678 19056)))

(defparameter +bike-l5-params+
  (make-bike-params :kind :bike-l5 :r-bits 40973 :r-bytes 5122 :r-qwords 641
                   :r-padded-qwords 768 :d 137 :tt 264
                   :thr-coeff0 1787850000 :thr-coeff1 402312 :thr-min 69
                   :last-qword-lead 13 :last-qword-trail 51
                   :last-qword-mask #x1FFF
                   :last-byte-mask #x1F
                   :sk-bytes 16494 :pk-bytes 5122 :ct-bytes 5154 :ss-bytes 32
                   :max-i 16
                   :exp0-k #(1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192
                             16384 32768)
                   :exp0-l #(20487 30730 28169 9443 13001 12376 8302 6618
                             38760 21582 1660 10409 14669 30338 17745 7520)
                   :exp1-k #(0 1 0 3 0 0 0 0 0 0 0 0 0 11 0 8203)
                   :exp1-l #(0 20487 0 15365 0 0 0 0 0 0 0 0 0 6302 0 10058)))

(defparameter *bike-params* +bike-l1-params+)

(defun bike-params-for-kind (kind)
  (case kind
    (:bike-l1 +bike-l1-params+)
    (:bike-l3 +bike-l3-params+)
    (:bike-l5 +bike-l5-params+)
    (otherwise (error "unknown BIKE kind ~A" kind))))

(declaim (inline bike-r-bits bike-r-bytes bike-r-qwords bike-r-padded-qwords
                 bike-dd bike-tt bike-thr-min bike-last-qword-lead
                 bike-last-qword-trail bike-last-qword-mask bike-last-byte-mask
                 bike-sk-bytes bike-pk-bytes bike-ct-bytes bike-ss-bytes))

(defun bike-r-bits () (bike-params-r-bits *bike-params*))
(defun bike-r-bytes () (bike-params-r-bytes *bike-params*))
(defun bike-r-qwords () (bike-params-r-qwords *bike-params*))
(defun bike-r-padded-qwords () (bike-params-r-padded-qwords *bike-params*))
(defun bike-dd () (bike-params-d *bike-params*))
(defun bike-tt () (bike-params-tt *bike-params*))
(defun bike-thr-min () (bike-params-thr-min *bike-params*))
(defun bike-last-qword-lead () (bike-params-last-qword-lead *bike-params*))
(defun bike-last-qword-trail () (bike-params-last-qword-trail *bike-params*))
(defun bike-last-qword-mask () (bike-params-last-qword-mask *bike-params*))
(defun bike-last-byte-mask () (bike-params-last-byte-mask *bike-params*))
(defun bike-sk-bytes () (bike-params-sk-bytes *bike-params*))
(defun bike-pk-bytes () (bike-params-pk-bytes *bike-params*))
(defun bike-ct-bytes () (bike-params-ct-bytes *bike-params*))
(defun bike-ss-bytes () (bike-params-ss-bytes *bike-params*))

(declaim (inline bike-u64vec))
(defun bike-u64vec (n)
  (make-array n :element-type '(unsigned-byte 64) :initial-element 0))

(declaim (inline bike-u64eq))
(defun bike-u64eq (a b)
  (if (= (logand a #xFFFFFFFFFFFFFFFF) (logand b #xFFFFFFFFFFFFFFFF))
      #xFFFFFFFFFFFFFFFF 0))


;;;
;;; GF(2)[x] mod (x^r - 1): 64x64 base multiply (windowing, s=3).
;;;

(defun bike-mul-base (c a b)
  (let ((h 0) (l 0) (g1 0) (g2 0)
        (u (make-array 8 :initial-element 0))
        (w 64) (s 3)
        (a0 (aref a 0)) (b0 (aref b 0)))
    (let ((b0m (logand b0 #x1FFFFFFFFFFFFFFF)))
      (setf (aref u 0) 0
            (aref u 1) b0m
            (aref u 2) (ash b0m 1)
            (aref u 3) (logxor (ash b0m 1) b0m)
            (aref u 4) (ash b0m 2)
            (aref u 5) (logxor (ash b0m 2) b0m)
            (aref u 6) (ash (logxor (ash b0m 1) b0m) 1)
            (aref u 7) (logxor (ash (logxor (ash b0m 1) b0m) 1) b0m))
      (dotimes (i 8)
        (setf l (logxor l (logand (aref u i)
                                  (bike-u64eq (logand a0 7) i))))
        (setf l (logxor l (logand (ash (aref u i) 3)
                                  (bike-u64eq (logand (ash a0 -3) 7) i))))
        (setf h (logxor h (logand (ash (aref u i) -61)
                                  (bike-u64eq (logand (ash a0 -3) 7) i)))))
      (loop for i from (* 2 s) below w by (* 2 s)
            do (let ((i2 (+ i s)))
                 (setf g1 0 g2 0)
                 (dotimes (j 8)
                   (setf g1 (logxor g1 (logand (aref u j)
                                               (bike-u64eq (logand (ash a0 (- i)) 7) j))))
                   (setf g2 (logxor g2 (logand (aref u j)
                                               (bike-u64eq (logand (ash a0 (- i2)) 7) j)))))
                 (setf l (logxor l (ash g1 i) (ash g2 i2)))
                 (setf h (logxor h (ash g1 (- i w)) (ash g2 (- i2 w))))))
      (loop for i from 61 below 64
            do (let ((mask (if (zerop (logand (ash b0 (- i)) 1)) 0 #xFFFFFFFFFFFFFFFF)))
                 (setf l (logxor l (logand (ash a0 i) mask)))
                 (setf h (logxor h (logand (ash a0 (- i w)) mask)))))
      (setf (aref c 0) (logand l #xFFFFFFFFFFFFFFFF)
            (aref c 1) (logand h #xFFFFFFFFFFFFFFFF))
      (values))))


;;;
;;; Karatsuba multiply over padded length (power of two).
;;;

(defun bike-kara-add1 (alah blbh a b half)
  (dotimes (i half)
    (setf (aref alah i) (logxor (aref a i) (aref a (+ i half))))
    (setf (aref blbh i) (logxor (aref b i) (aref b (+ i half)))))
  (values))

(defun bike-kara-add2 (z x y half)
  (dotimes (i half)
    (setf (aref z i) (logxor (aref x i) (aref y i))))
  (values))

(defun bike-kara-add3 (c mid half)
  (let ((c0 c)
        (c1 (make-array half :element-type '(unsigned-byte 64)))
        (c2 (make-array half :element-type '(unsigned-byte 64)))
        (c3 (make-array half :element-type '(unsigned-byte 64))))
    (dotimes (i half)
      (setf (aref c1 i) (aref c (+ half i))
            (aref c2 i) (aref c (+ (* 2 half) i))
            (aref c3 i) (aref c (+ (* 3 half) i))))
    (dotimes (i half)
      (let ((vt (aref mid i)))
        (setf (aref c (+ half i)) (logxor vt (aref c1 i) (aref c0 i)))
        (setf (aref c (+ (* 2 half) i)) (logxor vt (aref c2 i) (aref c3 i)))))
    (values)))

(defun bike-karatsuba (c a b qwords-len qwords-len-pad sec-buf)
  (if (<= qwords-len 1)
      (let ((aa (bike-u64vec 1))
            (bb (bike-u64vec 1))
            (cc (bike-u64vec 2)))
        (setf (aref aa 0) (aref a 0)
              (aref bb 0) (aref b 0))
        (bike-mul-base cc aa bb)
        (setf (aref c 0) (aref cc 0)
              (aref c 1) (aref cc 1))
        (values))
      (let* ((half (ash qwords-len-pad -1))
             (alah sec-buf)
             (blbh (make-array half :element-type '(unsigned-byte 64)
                                     :displaced-to sec-buf
                                     :displaced-index-offset half))
             (tmp (make-array half :element-type '(unsigned-byte 64)
                                    :displaced-to sec-buf
                                    :displaced-index-offset (* 2 half)))
             (sec-next (make-array (max 1 (- (length sec-buf) (* 3 half)))
                                   :element-type '(unsigned-byte 64)
                                   :displaced-to sec-buf
                                   :displaced-index-offset (* 3 half))))
        (bike-karatsuba c a b half half sec-next)
        (when (> qwords-len half)
          (let ((a-hi (make-array (max 1 (- (length a) half))
                                  :element-type '(unsigned-byte 64)
                                  :displaced-to a
                                  :displaced-index-offset half))
                (b-hi (make-array (max 1 (- (length b) half))
                                  :element-type '(unsigned-byte 64)
                                  :displaced-to b
                                  :displaced-index-offset half))
                (c2 (make-array (* 2 half) :element-type '(unsigned-byte 64)
                                      :displaced-to c
                                      :displaced-index-offset (* 2 half))))
            (bike-karatsuba c2 a-hi b-hi (- qwords-len half) half sec-next))
          (bike-kara-add1 alah blbh a b half)
          (let ((c1 (make-array (* 2 half) :element-type '(unsigned-byte 64)
                                      :displaced-to c
                                      :displaced-index-offset half))
                (c2 (make-array (* 2 half) :element-type '(unsigned-byte 64)
                                      :displaced-to c
                                      :displaced-index-offset (* 2 half))))
            (bike-kara-add2 tmp c1 c2 half))
          (let ((c1 (make-array (* 2 half) :element-type '(unsigned-byte 64)
                                      :displaced-to c
                                      :displaced-index-offset half)))
            (bike-karatsuba c1 alah blbh half half sec-next))
          (bike-kara-add3 c tmp half))
        (values))))

(defun bike-gf2x-mul-raw (t2 a b)
  (let* ((pad (bike-r-padded-qwords))
         (sec (bike-u64vec (* 3 pad))))
    (bike-karatsuba t2 a b (bike-r-qwords) pad sec)
    (values)))

(defun bike-gf2x-red (c a)
  (let ((rq (bike-r-qwords))
        (trail (bike-last-qword-trail))
        (lead (bike-last-qword-lead)))
    (dotimes (i rq)
      (let ((vt0 (aref a i))
            (vt1 (ash (aref a (+ i rq)) trail))
            (vt2 (ash (aref a (+ i rq -1)) (- lead))))
        (setf (aref c i) (logand (logxor vt0 vt1 vt2) #xFFFFFFFFFFFFFFFF))))
    (setf (aref c (1- rq))
          (logand (aref c (1- rq)) (bike-last-qword-mask)))
    (dotimes (i (- (bike-r-padded-qwords) rq))
      (setf (aref c (+ rq i)) 0))
    (values)))

(defun bike-gf2x-mul (c a b)
  (let ((tmp (bike-u64vec (* 2 (bike-r-padded-qwords)))))
    (bike-gf2x-mul-raw tmp a b)
    (bike-gf2x-red c tmp)
    (values)))

(defun bike-gf2x-sqr (c a)
  (let* ((rq (bike-r-qwords))
         (tmp (bike-u64vec (* 2 (bike-r-padded-qwords)))))
    (dotimes (i rq)
      (let ((aa (bike-u64vec 1))
            (cc (bike-u64vec 2)))
        (setf (aref aa 0) (aref a i))
        (bike-mul-base cc aa aa)
        (setf (aref tmp (* 2 i)) (aref cc 0)
              (aref tmp (1+ (* 2 i))) (aref cc 1))))
    (values tmp)))

(defun bike-gf2x-ksqr (c a l-param)
  (let ((r (bike-r-bits)))
    (dotimes (i (bike-r-padded-qwords))
      (setf (aref c i) 0))
    (dotimes (idx r)
      (let* ((pos (mod (* l-param idx) r))
             (bit (logand (ash (aref a (ash pos -6)) (- (logand pos 63))) 1)))
        (setf (aref c (ash idx -6))
              (logior (aref c (ash idx -6)) (ash bit (logand idx 63))))))
    (values)))


;;;
;;; Inversion in F_2[x]/(x^r - 1) (Fermat chain, Algorithm 2).
;;;

(defun bike-gf2x-sqr-mod (c a)
  (let ((tmp (bike-gf2x-sqr c a)))
    (bike-gf2x-red c tmp)
    (values)))

(defun bike-gf2x-repeated-sqr (c a n)
  (let ((pad (bike-r-padded-qwords)))
    (dotimes (i pad)
      (setf (aref c i) (aref a i)))
    (dotimes (i n)
      (bike-gf2x-sqr-mod c c))
    (values)))

(defun bike-gf2x-mul-mod (c a b)
  (bike-gf2x-mul c a b)
  (values))

(defun bike-gf2x-inv (c a)
  (let* ((pad (bike-r-padded-qwords))
         (max-i (bike-params-max-i *bike-params*))
         (exp0-k (bike-params-exp0-k *bike-params*))
         (exp0-l (bike-params-exp0-l *bike-params*))
         (exp1-k (bike-params-exp1-k *bike-params*))
         (exp1-l (bike-params-exp1-l *bike-params*))
         (tvec (bike-u64vec pad)))
    (dotimes (i pad)
      (setf (aref c i) (aref a i)
            (aref tvec i) (aref a i)))
    (let ((g (bike-u64vec pad)))
      (loop for i from 1 below max-i
            do (if (<= (aref exp0-k (1- i)) 64)
                   (bike-gf2x-repeated-sqr g c (aref exp0-k (1- i)))
                   (bike-gf2x-ksqr g c (aref exp0-l (1- i))))
               (bike-gf2x-mul-mod c g c)
               (unless (zerop (aref exp1-k i))
                 (if (<= (aref exp1-k i) 64)
                     (bike-gf2x-repeated-sqr g c (aref exp1-k i))
                     (bike-gf2x-ksqr g c (aref exp1-l i)))
                 (bike-gf2x-mul-mod tvec g tvec))))
    (bike-gf2x-sqr-mod tvec tvec)
    (dotimes (i pad)
      (setf (aref c i) (aref tvec i)))
    (values)))
