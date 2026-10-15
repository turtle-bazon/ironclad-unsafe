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


;;;
;;; AES-256-CTR PRF.
;;;

(defstruct bike-prf
  (ctx nil)
  (ctr (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
  (buffer (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
  (pos 16 :type fixnum)
  (rem-calls #xFFFFFFFF :type (unsigned-byte 32)))

(defun bike-prf-init (seed32)
  (let ((ctx (make-cipher :aes :key (copy-seq seed32) :mode :ecb)))
    (make-bike-prf :ctx ctx)))

(defun bike-prf-perform (out out-start prf)
  (when (zerop (bike-prf-rem-calls prf))
    (error "BIKE PRF overused"))
  (aes-encrypt-block (bike-prf-ctx prf) (bike-prf-ctr prf) 0 out out-start)
  (let ((c 1))
    (dotimes (i 8)
      (let ((s (+ (aref (bike-prf-ctr prf) i) c)))
        (setf (aref (bike-prf-ctr prf) i) (logand s #xFF))
        (setf c (ash s -8)))))
  (decf (bike-prf-rem-calls prf))
  (values))

(defun bike-prf-output (out out-len prf)
  (let ((pos (bike-prf-pos prf)))
    (if (<= (+ out-len pos) 16)
        (progn
          (replace out (bike-prf-buffer prf)
                   :start1 0 :end1 out-len :start2 pos :end2 (+ pos out-len))
          (setf (bike-prf-pos prf) (+ pos out-len))
          (values))
        (let ((idx (- 16 pos)))
          (replace out (bike-prf-buffer prf)
                   :start1 0 :end1 idx :start2 pos :end2 16)
          (setf (bike-prf-pos prf) 0)
          (loop while (>= (- out-len idx) 16)
                do (bike-prf-perform out idx prf)
                   (incf idx 16))
          (bike-prf-perform (bike-prf-buffer prf) 0 prf)
          (let ((tail (- out-len idx)))
            (replace out (bike-prf-buffer prf)
                     :start1 idx :end1 out-len :start2 0 :end2 tail))
          (setf (bike-prf-pos prf) (- out-len idx))
          (values)))))


;;;
;;; Sparse sampling: Fisher-Yates indices + constant-time set-bits.
;;;

(declaim (inline bike-u32eq))
(defun bike-u32eq (a b)
  (if (= (logand a #xFFFFFFFF) (logand b #xFFFFFFFF))
      #xFFFFFFFF 0))

(defun bike-sample-fisher-yates (out num-indices max-idx prf)
  (let ((tmp (make-array 4 :element-type '(unsigned-byte 8))))
    (loop for i from (1- num-indices) downto 0
          do (bike-prf-output tmp 4 prf)
             (let* ((rand (logior (aref tmp 0)
                                  (ash (aref tmp 1) 8)
                                  (ash (aref tmp 2) 16)
                                  (ash (aref tmp 3) 24)))
                    (prod (* rand (- max-idx i)))
                    (l (+ i (ash prod -32)))
                    (is-dup 0))
               (loop for j from (1+ i) below num-indices
                     do (setf is-dup (logior is-dup
                                             (if (= l (aref out j)) 1 0))))
               (let ((mask (if (zerop is-dup) 0 #xFFFFFFFF)))
                 (setf (aref out i)
                       (logand #xFFFFFFFF
                               (logxor (logand mask i) (logand (lognot mask) l))))))))
  (values))

(defun bike-secure-set-bits (r first-pos wlist w-size)
  (let ((nwords (bike-r-padded-qwords)))
    (let ((pos-qw (make-array w-size :element-type '(unsigned-byte 32))))
      (let ((pos-bit (make-array w-size :element-type '(unsigned-byte 64))))
        (dotimes (i w-size)
          (let ((w (- (aref wlist i) first-pos)))
            (setf (aref pos-qw i) (logand (ash w -6) #xFFFFFFFF))
            (setf (aref pos-bit i) (ash 1 (logand w 63)))))
        (dotimes (i nwords)
          (let ((val 0))
            (dotimes (j w-size)
              (let ((w (- (aref wlist j) first-pos)))
                (when (>= w 0)
                  (setf val (logior val (logand (aref pos-bit j)
                                               (bike-u64eq-mask (aref pos-qw j) i)))))))
            (setf (aref r i) (logand val #xFFFFFFFFFFFFFFFF))))
        (values)))))

(defun bike-u64eq-mask (a b)
  (if (= (logand a #xFFFFFFFF) (logand b #xFFFFFFFF))
      #xFFFFFFFFFFFFFFFF 0))

(defun bike-generate-secret-key (h0 h1 wlist0 wlist1 seed32)
  (let ((prf (bike-prf-init seed32))
        (dd (bike-dd)))
    (let ((wt (make-array dd :element-type '(unsigned-byte 32) :initial-element 0)))
      (bike-sample-fisher-yates wt dd (bike-r-bits) prf)
      (dotimes (i dd) (setf (aref wlist0 i) (aref wt i)))
      (bike-secure-set-bits h0 0 wlist0 dd))
    (let ((wt (make-array dd :element-type '(unsigned-byte 32) :initial-element 0)))
      (bike-sample-fisher-yates wt dd (bike-r-bits) prf)
      (dotimes (i dd) (setf (aref wlist1 i) (aref wt i)))
      (bike-secure-set-bits h1 0 wlist1 dd))
    (values)))

(defun bike-mask-tail (e)
  (let* ((rb (bike-r-bytes))
         (pad (bike-r-padded-qwords))
         (lw (ash (1- rb) -3))
         (lp (logand (1- rb) 7)))
    (loop for i from (1+ lw) below pad
          do (setf (aref e i) 0))
    (let ((m (logior (1- (ash 1 (* 8 lp)))
                     (ash (bike-last-byte-mask) (* 8 lp)))))
      (setf (aref e lw) (logand (aref e lw) m))))
  (values))

(defun bike-generate-error-vector (e0 e1 seed32)
  (let ((prf (bike-prf-init seed32))
        (tt (bike-tt))
        (nbits (* 2 (bike-r-bits))))
    (let ((wlist (make-array tt :element-type '(unsigned-byte 32) :initial-element 0)))
      (bike-sample-fisher-yates wlist tt nbits prf)
      (bike-secure-set-bits e0 0 wlist tt)
      (bike-secure-set-bits e1 (bike-r-bits) wlist tt))
    (bike-mask-tail e0)
    (bike-mask-tail e1)
    (values)))
;;; BIKE decode helpers, chunk A.

(defun bike-l32-mask (v1 v2)
  (if (>= (logand v1 #xFFFFFFFF) (logand v2 #xFFFFFFFF))
      #xFFFFFFFF 0))

(defun bike-r-weight (r)
  (let ((acc 0))
    (let ((rb (bike-r-bytes)))
      (dotimes (i (1- rb))
        (setf acc (+ acc (logcount (bike-get-u8 r i)))))
      (setf acc (+ acc (logcount (logand (bike-get-u8 r (1- rb))
                                        (bike-last-byte-mask)))))
      acc)))

(defun bike-get-u8 (v j)
  (ldb (byte 8 (* (mod j 8) 8)) (aref v (ash j -3))))

(defun bike-syndrome-dup (s)
  (let ((rq (bike-r-qwords)))
    (let ((lead (bike-last-qword-lead)))
      (let ((trail (bike-last-qword-trail)))
        (setf (aref s (1- rq))
              (logior (logand (ash (aref s 0) lead) #xFFFFFFFFFFFFFFFF)
                      (logand (aref s (1- rq)) (bike-last-qword-mask))))
        (dotimes (i (1- (* 2 rq)))
          (setf (aref s (+ rq i))
                (logior (ash (aref s i) (- trail))
                        (logand (ash (aref s (1+ i)) lead) #xFFFFFFFFFFFFFFFF))))
        (values)))))

(defun bike-rotr-big (out inn qw-num)
  (let ((rq (bike-r-qwords)))
    (dotimes (i (* 3 rq))
      (setf (aref out i) (aref inn i)))
    (let ((half-log 1))
      (loop while (< half-log (ash rq -1))
            do (setf half-log (ash half-log 1)))
      (loop for idx = half-log then (ash idx -1)
            while (>= idx 1)
            do (let ((mask (if (>= qw-num idx) #xFFFFFFFFFFFFFFFF 0)))
                 (setf qw-num (- qw-num (logand idx mask)))
                 (dotimes (i (+ rq idx))
                   (setf (aref out i)
                         (logior (logand (aref out i) (lognot mask))
                                 (logand (aref out (+ i idx)) mask))))))))
    (values))

(defun bike-rotr-small (out inn bits)
  (let ((rq (bike-r-qwords)))
    (let ((mask 0))
      (let ((high-shift 0))
        (setf mask (if (zerop bits) 0 #xFFFFFFFFFFFFFFFF))
        (setf high-shift (if (zerop bits) 0 (- 64 bits)))
        (dotimes (i rq)
          (setf (aref out i)
                (logior (ash (aref inn i) (- bits))
                        (logand (ash (aref inn (1+ i)) high-shift) mask))))
        (values)))))

(defun bike-rotate-right (out inn bitscount)
  (bike-rotr-big out inn (ash bitscount -6))
  (bike-rotr-small out out (logand bitscount 63))
  (values))

(defun bike-bit-sliced-adder (upc rotated num-slices)
  (let ((rq (bike-r-qwords)))
    (dotimes (j num-slices)
      (dotimes (i rq)
        (let ((carry (logand (aref (aref upc j) i) (aref rotated i))))
          (setf (aref (aref upc j) i)
                (logxor (aref (aref upc j) i) (aref rotated i)))
          (setf (aref rotated i) carry)))))
  (values))

(defun bike-sub-word (upc br j i b)
  (let ((a (aref (aref upc j) i)))
    (let ((nbr (aref br i)))
      (let ((na (logand (lognot a) #xFFFFFFFFFFFFFFFF)))
        (let ((nnbr (logand (lognot nbr) #xFFFFFFFFFFFFFFFF)))
          (let ((t1 (logand na b nnbr)))
            (let ((t2 (logand (logior na b) nbr)))
              (setf (aref (aref upc j) i)
                    (logand (logxor a b nbr) #xFFFFFFFFFFFFFFFF))
              (setf (aref br i)
                    (logand (logior t1 t2) #xFFFFFFFFFFFFFFFF)))))))))

(defun bike-slice-subtract (upc threshold)
  (let ((rq (bike-r-qwords)))
    (let ((nslices (length upc)))
      (let ((br (bike-u64vec (bike-r-qwords))))
        (let ((val threshold))
          (dotimes (j nslices)
            (let ((lsb (if (zerop (logand val 1)) 0 #xFFFFFFFFFFFFFFFF)))
              (setf val (ash val -1))
              (dotimes (i rq)
                (bike-sub-word upc br j i lsb))))
          (values))))))

(defun bike-log2-msb (v)
  (cond ((zerop v) 0)
        ((< v 2) 1)
        ((< v 4) 2)
        ((< v 8) 3)
        ((< v 16) 4)
        ((< v 32) 5)
        ((< v 64) 6)
        ((< v 128) 7)
        ((< v 256) 8)
        (t 9)))

(defun bike-slices ()
  (1+ (bike-log2-msb (bike-dd))))

(defun bike-delta ()
  3)

(defun bike-upc-byte (upc j)
  (ldb (byte 8 (* (mod j 8) 8)) (aref (aref upc (1- (bike-slices))) (ash j -3))))

(defun bike-threshold (s)
  (let ((w 0))
    (setf w (bike-r-weight s))
    (let ((coeff0 0))
      (let ((coeff1 0))
        (setf coeff0 (bike-params-thr-coeff0 *bike-params*))
        (setf coeff1 (bike-params-thr-coeff1 *bike-params*))
        (let ((thr 0))
          (setf thr (logand (+ coeff0 (* coeff1 w)) #xFFFFFFFFFFFFFFFF))
          (let ((a-lo 0))
            (let ((a-hi 0))
              (setf a-lo (logand thr #xFFFFFFFF))
              (setf a-hi (ash thr -32))
              (let ((mulc 12379400392853802749))
                (let ((b-lo 0))
                  (let ((b-hi 0))
                    (setf b-lo (logand mulc #xFFFFFFFF))
                    (setf b-hi (ash mulc -32))
                    (setf thr (logand (+ (* a-hi b-hi)
                                         (ash (+ (* a-hi b-lo) (* a-lo b-hi)) -32))
                                      #xFFFFFFFFFFFFFFFF))
                    (setf thr (ash thr -26))
                    (if (>= thr (bike-thr-min)) thr (bike-thr-min))))))))))))

(defun bike-compute-syndrome (s c0 h0)
  (let ((pad-s (bike-u64vec (bike-r-padded-qwords))))
    (bike-gf2x-mul pad-s c0 h0)
    (dotimes (i (bike-r-qwords))
      (setf (aref s i) (aref pad-s i)))
    (setf (aref s (1- (bike-r-qwords)))
          (logand (aref s (1- (bike-r-qwords))) (bike-last-qword-mask)))
    (bike-syndrome-dup s)
    (values)))

(defun bike-recompute-syndrome (s c0 h0 pk e0 e1)
  (let ((pad (bike-r-padded-qwords)))
    (let ((tmp (bike-u64vec (bike-r-padded-qwords))))
      (let ((pe0 (bike-u64vec (bike-r-padded-qwords))))
        (let ((pe1 (bike-u64vec (bike-r-padded-qwords))))
          (dotimes (i pad)
            (setf (aref pe0 i) (aref e0 i))
            (setf (aref pe1 i) (aref e1 i)))
          (bike-gf2x-mul tmp pe1 pk)
          (bike-gf2x-add tmp tmp c0 pad)
          (bike-gf2x-add tmp tmp pe0 pad)
          (bike-compute-syndrome s tmp h0)
          (values))))))

(defun bike-gf2x-add (c a b n)
  (dotimes (i n c)
    (setf (aref c i) (logxor (aref a i) (aref b i)))))

(defun bike-get-byte (v j)
  (ldb (byte 8 (* (mod j 8) 8)) (aref v (ash j -3))))

(defun bike-set-byte (v j b)
  (let ((wi (ash j -3)))
    (let ((sh (* (mod j 8) 8)))
      (setf (aref v wi)
            (logior (logand (aref v wi) (lognot (ash #xFF sh)))
                    (ash (logand b #xFF) sh)))
      (values))))
;;; BIKE error search, chunk B.

(defun bike-new-upc ()
  (let ((ns (bike-slices)))
    (let ((upc (make-array ns)))
      (dotimes (j ns)
        (setf (aref upc j) (bike-u64vec (bike-r-qwords))))
      upc)))

(defun bike-accumulate-upc (upc rot s wlist)
  (let ((dd (bike-dd)))
    (dotimes (j dd)
      (bike-rotate-right rot s (aref wlist j))
      (bike-bit-sliced-adder upc rot (bike-log2-msb (1+ j))))
    (values)))

(defun bike-err1-black (e black upc)
  (let ((rb (bike-r-bytes)))
    (dotimes (j rb)
      (let ((sum 0))
        (setf sum (logand (lognot (bike-upc-byte upc j)) #xFF))
        (bike-set-ebyte black j sum)
        (bike-set-ebyte e j (logxor (bike-get-ebyte e j) sum))))
    (bike-set-ebyte e (1- rb)
                    (logand (bike-get-ebyte e (1- rb))
                            (bike-last-byte-mask)))
    (values)))

(defun bike-err1-gray (gray black upc)
  (let ((rb (bike-r-bytes)))
    (dotimes (j rb)
      (let ((sum 0))
        (setf sum (logand (lognot (bike-upc-byte upc j)) #xFF))
        (bike-set-ebyte gray j
                        (logand (lognot (bike-get-ebyte black j)) sum))))
    (values)))

(defun bike-delta-ones (upc rot)
  (dotimes (l (bike-delta))
    (dotimes (i (bike-r-bytes))
      (bike-set-byte rot i #xFF))
    (bike-bit-sliced-adder upc rot (bike-slices)))
  (values))

(defun bike-find-err1 (e black gray s wlists threshold)
  (dotimes (ii 2)
    (let ((upc (bike-new-upc)))
      (let ((rot (bike-u64vec (* 3 (bike-r-qwords)))))
        (bike-accumulate-upc upc rot s (aref wlists ii))
        (bike-slice-subtract upc threshold)
        (bike-err1-black (aref e ii) (aref black ii) upc)
        (bike-delta-ones upc rot)
        (bike-err1-gray (aref gray ii) (aref black ii) upc))))
  (values))

(defun bike-err2-update (e pos-e upc)
  (let ((rb (bike-r-bytes)))
    (dotimes (j rb)
      (let ((sum 0))
        (setf sum (logand (lognot (bike-upc-byte upc j)) #xFF))
        (bike-set-ebyte e j
                        (logxor (bike-get-ebyte e j)
                                (logand (bike-get-ebyte pos-e j) sum)))))
    (bike-set-ebyte e (1- rb)
                    (logand (bike-get-ebyte e (1- rb))
                            (bike-last-byte-mask)))
    (values)))

(defun bike-find-err2 (e pos-e s wlists threshold)
  (dotimes (ii 2)
    (let ((upc (bike-new-upc)))
      (let ((rot (bike-u64vec (* 3 (bike-r-qwords)))))
        (bike-accumulate-upc upc rot s (aref wlists ii))
        (bike-slice-subtract upc threshold)
        (bike-err2-update (aref e ii) (aref pos-e ii) upc))))
  (values))
;;; BIKE decode driver, chunk C.

(defun bike-bytes-to-words (words bytes nbytes)
  (dotimes (i (bike-r-padded-qwords))
    (setf (aref words i) 0))
  (dotimes (i nbytes)
    (let ((wi (ash i -3)))
      (let ((sh (* (mod i 8) 8)))
        (setf (aref words wi)
              (logior (aref words wi) (ash (aref bytes i) sh))))))
  (values))

(defun bike-fresh-ebytes ()
  (let ((rb (bike-r-bytes)))
    (vector (make-array rb :element-type '(unsigned-byte 8) :initial-element 0)
            (make-array rb :element-type '(unsigned-byte 8) :initial-element 0))))

(defun bike-err2-threshold ()
  (1+ (ash (1+ (bike-dd)) -1)))

(defun bike-decode-refresh (s c0 h0 pk e pe0 pe1 rb)
  (bike-bytes-to-words pe0 (aref e 0) rb)
  (bike-bytes-to-words pe1 (aref e 1) rb)
  (bike-recompute-syndrome s c0 h0 pk pe0 pe1)
  (values))

(defun bike-decode (e0 e1 c0-bytes h0-bytes pk-bytes wlist0 wlist1)
  (let ((pad (bike-r-padded-qwords)))
    (let ((rb (bike-r-bytes)))
      (let ((rq (bike-r-qwords)))
        (let ((c0 (bike-u64vec pad)))
          (let ((h0 (bike-u64vec pad)))
            (let ((pk (bike-u64vec pad)))
              (bike-bytes-to-words c0 c0-bytes rb)
              (bike-bytes-to-words h0 h0-bytes rb)
              (bike-bytes-to-words pk pk-bytes rb)
              (let ((s (bike-u64vec (* 3 rq))))
                (let ((e (bike-fresh-ebytes)))
                  (let ((black (bike-fresh-ebytes)))
                    (let ((gray (bike-fresh-ebytes)))
                      (let ((wlists (vector wlist0 wlist1)))
                        (let ((pe0 (bike-u64vec pad)))
                          (let ((pe1 (bike-u64vec pad)))
                            (bike-compute-syndrome s c0 h0)
                            (bike-syndrome-dup s)
                            (dotimes (iter 5)
                              (let ((threshold (bike-threshold s)))
                                (bike-find-err1 e black gray s wlists threshold)
                                (bike-decode-refresh s c0 h0 pk e pe0 pe1 rb)
                                (unless (>= iter 1)
                                  (bike-find-err2 e black s wlists (bike-err2-threshold))
                                  (bike-decode-refresh s c0 h0 pk e pe0 pe1 rb)
                                  (bike-find-err2 e gray s wlists (bike-err2-threshold))
                                  (bike-decode-refresh s c0 h0 pk e pe0 pe1 rb))))
                            (dotimes (i rb)
                              (setf (aref e0 i) (aref (aref e 0) i))
                              (setf (aref e1 i) (aref (aref e 1) i)))
                            (values)))))))))))))))
;;; BIKE byte-direct accessors, chunk D.

(defun bike-get-ebyte (v j)
  (aref v j))

(defun bike-set-ebyte (v j b)
  (setf (aref v j) (logand b #xFF))
  (values))
