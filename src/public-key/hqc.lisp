;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; hqc.lisp -- HQC KEM family (hqc-128/192/256).
;;;;
;;;; Direct translation of the PQClean clean implementations:
;;;; quasi-cyclic codes with concatenated Reed-Muller/Reed-Solomon codec.

(in-package :crypto)


;;; m_val tables for fixed-weight sampling.
;;;

(defparameter +hqc-m-val-128+
  #(
    243079 243093 243106 243120 243134 243148 243161 243175
    243189 243203 243216 243230 243244 243258 243272 243285
    243299 243313 243327 243340 243354 243368 243382 243396
    243409 243423 243437 243451 243465 243478 243492 243506
    243520 243534 243547 243561 243575 243589 243603 243616
    243630 243644 243658 243672 243686 243699 243713 243727
    243741 243755 243769 243782 243796 243810 243824 243838
    243852 243865 243879 243893 243907 243921 243935 243949
    243962 243976 243990 244004 244018 244032 244046 244059
    244073 244087 244101
    ))

(defparameter +hqc-m-val-192+
  #(
    119800 119803 119807 119810 119813 119817 119820 119823
    119827 119830 119833 119837 119840 119843 119847 119850
    119853 119857 119860 119864 119867 119870 119874 119877
    119880 119884 119887 119890 119894 119897 119900 119904
    119907 119910 119914 119917 119920 119924 119927 119930
    119934 119937 119941 119944 119947 119951 119954 119957
    119961 119964 119967 119971 119974 119977 119981 119984
    119987 119991 119994 119997 120001 120004 120008 120011
    120014 120018 120021 120024 120028 120031 120034 120038
    120041 120044 120048 120051 120054 120058 120061 120065
    120068 120071 120075 120078 120081 120085 120088 120091
    120095 120098 120101 120105 120108 120112 120115 120118
    120122 120125 120128 120132 120135 120138 120142 120145
    120149 120152 120155 120159 120162 120165 120169 120172
    120175 120179
    ))

(defparameter +hqc-m-val-256+
  #(
    74517 74518 74520 74521 74522 74524 74525 74526
    74527 74529 74530 74531 74533 74534 74535 74536
    74538 74539 74540 74542 74543 74544 74545 74547
    74548 74549 74551 74552 74553 74555 74556 74557
    74558 74560 74561 74562 74564 74565 74566 74567
    74569 74570 74571 74573 74574 74575 74577 74578
    74579 74580 74582 74583 74584 74586 74587 74588
    74590 74591 74592 74593 74595 74596 74597 74599
    74600 74601 74602 74604 74605 74606 74608 74609
    74610 74612 74613 74614 74615 74617 74618 74619
    74621 74622 74623 74625 74626 74627 74628 74630
    74631 74632 74634 74635 74636 74637 74639 74640
    74641 74643 74644 74645 74647 74648 74649 74650
    74652 74653 74654 74656 74657 74658 74660 74661
    74662 74663 74665 74666 74667 74669 74670 74671
    74673 74674 74675 74676 74678 74679 74680 74682
    74683 74684 74685 74687 74688 74689 74691 74692
    74693 74695 74696 74697 74698 74700 74701 74702
    74704 74705 74706 74708 74709
    ))


;;;
;;; Parameters: one struct per set, selected via *HQC-PARAMS*.
;;;

(defstruct hqc-params
  kind n n1 n2 n1n2 omega omega-e omega-r m k g fft delta
  red-mask seed-bytes salt-bytes ss-bytes sk-bytes pk-bytes ct-bytes
  vec-n-bytes vec-k-bytes vec-n1-bytes vec-n1n2-bytes
  vec-n-64 vec-n1-64 vec-n1n2-64 multiplicity
  rs-poly m-val)

(defparameter +hqc-128-params+
  (make-hqc-params :kind :hqc-128 :n 17669 :n1 46 :n2 384 :n1n2 17664
                   :omega 66 :omega-e 75 :omega-r 75 :m 8 :k 16 :g 31
                   :fft 4 :delta 15 :red-mask #x1F
                   :seed-bytes 40 :salt-bytes 16 :ss-bytes 64
                   :sk-bytes 2305 :pk-bytes 2249 :ct-bytes 4433
                   :vec-n-bytes 2209 :vec-k-bytes 16 :vec-n1-bytes 46
                   :vec-n1n2-bytes 2208 :vec-n-64 277 :vec-n1-64 6
                   :vec-n1n2-64 276 :multiplicity 3
                   :rs-poly #(                              89 69 153 116 176 117 111 75 73 233 242 233 65
                              210 21 139 103 173 67 118 105 210 174 110 74 69
                              228 82 255 181 1)
                   :m-val +hqc-m-val-128+))

(defparameter +hqc-192-params+
  (make-hqc-params :kind :hqc-192 :n 35851 :n1 56 :n2 640 :n1n2 35840
                   :omega 100 :omega-e 114 :omega-r 114 :m 8 :k 24 :g 33
                   :fft 5 :delta 16 :red-mask #x7FF
                   :seed-bytes 40 :salt-bytes 16 :ss-bytes 64
                   :sk-bytes 4586 :pk-bytes 4522 :ct-bytes 8978
                   :vec-n-bytes 4482 :vec-k-bytes 24 :vec-n1-bytes 56
                   :vec-n1n2-bytes 4480 :vec-n-64 561 :vec-n1-64 7
                   :vec-n1n2-64 560 :multiplicity 5
                   :rs-poly #(                              45 216 239 24 253 104 27 40 107 50 163 210 227
                              134 224 158 119 13 158 1 238 164 82 43 15 232
                              246 142 50 189 29 232 1)
                   :m-val +hqc-m-val-192+))

(defparameter +hqc-256-params+
  (make-hqc-params :kind :hqc-256 :n 57637 :n1 90 :n2 640 :n1n2 57600
                   :omega 131 :omega-e 149 :omega-r 149 :m 8 :k 32 :g 59
                   :fft 5 :delta 29 :red-mask #x1FFFFFFFFF
                   :seed-bytes 40 :salt-bytes 16 :ss-bytes 64
                   :sk-bytes 7317 :pk-bytes 7245 :ct-bytes 14421
                   :vec-n-bytes 7205 :vec-k-bytes 32 :vec-n1-bytes 90
                   :vec-n1n2-bytes 7200 :vec-n-64 901 :vec-n1-64 12
                   :vec-n1n2-64 900 :multiplicity 5
                   :rs-poly #(                              49 167 49 39 200 121 124 91 240 63 148 71 150
                              123 87 101 32 215 159 71 201 115 97 210 186 183
                              141 217 123 12 31 243 180 219 152 239 99 141 4
                              246 191 144 8 232 47 27 141 178 130 64 124 47
                              39 188 216 48 199 187 1)
                   :m-val +hqc-m-val-256+))

(defparameter *hqc-params* +hqc-128-params+)

(defun hqc-params-for-kind (kind)
  (case kind
    (:hqc-128 +hqc-128-params+)
    (:hqc-192 +hqc-192-params+)
    (:hqc-256 +hqc-256-params+)
    (otherwise (error "unknown HQC kind ~A" kind))))

(declaim (inline hqc-n hqc-n1 hqc-n2 hqc-n1n2 hqc-omega hqc-omega-e hqc-omega-r
                 hqc-gf-m hqc-k hqc-gg hqc-fft-bits hqc-delta hqc-red-mask
                 hqc-seed-bytes hqc-salt-bytes hqc-ss-bytes hqc-sk-bytes
                 hqc-pk-bytes hqc-ct-bytes hqc-vec-n-bytes hqc-vec-k-bytes
                 hqc-vec-n1-bytes hqc-vec-n1n2-bytes hqc-vec-n-64
                 hqc-vec-n1-64 hqc-vec-n1n2-64 hqc-multiplicity
                 hqc-rs-poly hqc-m-val))

(defun hqc-n () (hqc-params-n *hqc-params*))
(defun hqc-n1 () (hqc-params-n1 *hqc-params*))
(defun hqc-n2 () (hqc-params-n2 *hqc-params*))
(defun hqc-n1n2 () (hqc-params-n1n2 *hqc-params*))
(defun hqc-omega () (hqc-params-omega *hqc-params*))
(defun hqc-omega-e () (hqc-params-omega-e *hqc-params*))
(defun hqc-omega-r () (hqc-params-omega-r *hqc-params*))
(defun hqc-gf-m () (hqc-params-m *hqc-params*))
(defun hqc-k () (hqc-params-k *hqc-params*))
(defun hqc-gg () (hqc-params-g *hqc-params*))
(defun hqc-fft-bits () (hqc-params-fft *hqc-params*))
(defun hqc-delta () (hqc-params-delta *hqc-params*))
(defun hqc-red-mask () (hqc-params-red-mask *hqc-params*))
(defun hqc-seed-bytes () (hqc-params-seed-bytes *hqc-params*))
(defun hqc-salt-bytes () (hqc-params-salt-bytes *hqc-params*))
(defun hqc-ss-bytes () (hqc-params-ss-bytes *hqc-params*))
(defun hqc-sk-bytes () (hqc-params-sk-bytes *hqc-params*))
(defun hqc-pk-bytes () (hqc-params-pk-bytes *hqc-params*))
(defun hqc-ct-bytes () (hqc-params-ct-bytes *hqc-params*))
(defun hqc-vec-n-bytes () (hqc-params-vec-n-bytes *hqc-params*))
(defun hqc-vec-k-bytes () (hqc-params-vec-k-bytes *hqc-params*))
(defun hqc-vec-n1-bytes () (hqc-params-vec-n1-bytes *hqc-params*))
(defun hqc-vec-n1n2-bytes () (hqc-params-vec-n1n2-bytes *hqc-params*))
(defun hqc-vec-n-64 () (hqc-params-vec-n-64 *hqc-params*))
(defun hqc-vec-n1-64 () (hqc-params-vec-n1-64 *hqc-params*))
(defun hqc-vec-n1n2-64 () (hqc-params-vec-n1n2-64 *hqc-params*))
(defun hqc-multiplicity () (hqc-params-multiplicity *hqc-params*))
(defun hqc-rs-poly () (hqc-params-rs-poly *hqc-params*))
(defun hqc-m-val () (hqc-params-m-val *hqc-params*))


;;;
;;; GF(256) = GF(2)[x]/(x^8 + x^4 + x^3 + x + 1).
;;;

(declaim (inline hqc-gf-add))
(defun hqc-gf-add (a b)
  (logxor a b))

(defun hqc-gf-reduce (x deg-x)
  "Reduce X (degree < 64) modulo the primitive polynomial."
  (let ((steps (ceiling (- deg-x 7) 4)))
    (dotimes (i steps)
      (let ((mod (ash x -8)))
        (setf x (logand x #xFF))
        (setf x (logxor x mod))
        (let ((z1 0)
              (rmdr (logxor #x11D 1)))
          (loop for j from 3 downto 1
                do (let* ((z2 (hqc-tzcount rmdr))
                          (dist (- z2 z1)))
                     (setf mod (ash mod dist))
                     (setf x (logxor x mod))
                     (setf rmdr (logxor rmdr (ash 1 z2)))
                     (setf z1 z2)))))))
  (logand x #xFFFF))

(defun hqc-tzcount (a)
  (let ((tmp 0)
        (mask #xFFFF))
    (dotimes (i 14)
      (let ((bit (logand (ash a (- i)) 1)))
        (setf tmp (+ tmp (logand (- 1 bit) mask)))
        (setf mask (logand mask (- (- 1 bit))))))
    tmp))

(declaim (inline hqc-u32-eq-mask hqc-u64-eq-mask))
(defun hqc-u32-eq-mask (a b)
  "All-ones (32-bit) iff A equals B; mirrors (0 - (1 - (((a-b)|(-(a-b)))>>31)))."
  (let* ((d (logand (- a b) #xFFFFFFFF))
         (s (ldb (byte 1 31) (logior d (logand (- d) #xFFFFFFFF)))))
    (if (zerop s) #xFFFFFFFF 0)))

(defun hqc-u64-eq-mask (a b)
  "All-ones (64-bit) iff A equals B; mirrors the 64-bit mask idiom."
  (let* ((d (logand (- a b) #xFFFFFFFFFFFFFFFF))
         (s (ldb (byte 1 63) (logior d (logand (- d) #xFFFFFFFFFFFFFFFF)))))
    (if (zerop s) #xFFFFFFFFFFFFFFFF 0)))

(defun hqc-gf-cmul (a b)
  "Carryless multiply of bytes A B; returns (low high)."
  (let ((h 0) (l 0) (g 0)
        (u (make-array 4 :initial-element 0))
        (tmp1 0) (mask 0))
    (setf (aref u 0) 0
          (aref u 1) (logand b #x7F)
          (aref u 2) (ash (aref u 1) 1)
          (aref u 3) (logxor (aref u 2) (aref u 1)))
    (setf tmp1 (logand a 3))
    (dotimes (i 4)
      (setf g (logxor g (logand (aref u i) (hqc-u32-eq-mask tmp1 i)))))
    (setf l g h 0)
    (loop for i from 2 below 8 by 2
          do (setf g 0
                   tmp1 (logand (ash a (- i)) 3))
             (dotimes (j 4)
               (setf g (logxor g (logand (aref u j) (hqc-u32-eq-mask tmp1 j)))))
             (setf l (logxor l (ash g i)))
             (setf h (logxor h (ash g (- i 8)))))
    (setf mask (if (zerop (logand (ash b -7) 1)) 0 #xFFFFFFFF))
    (setf l (logxor l (logand (ash a 7) mask)))
    (setf h (logxor h (logand (ash a -1) mask)))
    (values (logand l #xFF) (logand h #xFF))))

(defun hqc-gf-mul (a b)
  (multiple-value-bind (lo hi) (hqc-gf-cmul a b)
    (hqc-gf-reduce (logior lo (ash hi 8)) 14)))

(defun hqc-gf-square (a)
  (let ((b a)
        (s (logand a 1)))
    (dotimes (i 7)
      (setf b (ash b 1))
      (setf s (logxor s (logand b (ash 1 (* 2 (1+ i)))))))
    (hqc-gf-reduce s 14)))

(defun hqc-gf-inv (a)
  (let* ((inv (hqc-gf-square a))
         (tmp1 (hqc-gf-mul inv a)))
    (setf inv (hqc-gf-square inv))
    (let ((tmp2 (hqc-gf-mul inv tmp1)))
      (setf tmp1 (hqc-gf-mul inv tmp2))
      (setf inv (hqc-gf-mul tmp1 inv))
      (setf inv (hqc-gf-square inv))
      (setf inv (hqc-gf-square inv))
      (setf inv (hqc-gf-square inv))
      (setf inv (hqc-gf-mul inv tmp2))
      (setf inv (hqc-gf-square inv))
      inv)))


;;;
;;; u64 vectors: allocation, loads, basic ops.
;;;

(declaim (inline hqc-u64vec))
(defun hqc-u64vec (n)
  (make-array n :element-type '(unsigned-byte 64) :initial-element 0))

(defun hqc-vec-add (o v1 v2 size)
  (dotimes (i size o)
    (setf (aref o i) (logxor (aref v1 i) (aref v2 i)))))

(defun hqc-vec-compare (v1 v2 size-bytes)
  "0 if equal over SIZE-BYTES, 1 otherwise."
  (let ((r #x100))
    (dotimes (i size-bytes)
      (setf r (logior r (logxor (aref v1 i) (aref v2 i)))))
    (ash (1- r) -8)))

(defun hqc-load8-arr (out64 outlen in8 inlen)
  (let ((index-in 0)
        (index-out 0))
    (when (and (>= inlen 8) (>= outlen 1))
      (loop while (and (< index-out outlen) (<= (+ index-in 8) inlen))
            do (setf (aref out64 index-out) (mce-load8 in8 index-in))
               (incf index-in 8)
               (incf index-out)))
    (when (or (>= index-in inlen) (>= index-out outlen))
      (return-from hqc-load8-arr (values)))
    (setf (aref out64 index-out) (aref in8 (1- inlen)))
    (loop for i from (- (- inlen index-in) 2) downto 0
          do (setf (aref out64 index-out)
                   (logior (ash (aref out64 index-out) 8)
                           (aref in8 (+ index-in i)))))
    (values)))

(defun hqc-store8-arr (out8 outlen in64 inlen)
  (let ((index-out 0)
        (index-in 0))
    (loop while (and (< index-out outlen) (< index-in inlen))
          do (setf (aref out8 index-out)
                   (ldb (byte 8 (* (mod index-out 8) 8)) (aref in64 index-in)))
             (incf index-out)
             (when (zerop (mod index-out 8))
               (incf index-in)))
    (values)))

(defun hqc-vec-resize (o size-o v size-v)
  (let ((mask #x7FFFFFFFFFFFFFFF)
        (val 0))
    (if (< size-o size-v)
        (progn
          (unless (zerop (mod size-o 64))
            (setf val (- 64 (mod size-o 64))))
          (let ((nwords (truncate (hqc-vec-n1n2-bytes) 8)))
            (dotimes (i nwords)
              (setf (aref o i) (aref v i))))
          (dotimes (i val)
            (setf mask (ash mask -1))
            (setf (aref o (1- (hqc-vec-n1n2-64)))
                  (logand (aref o (1- (hqc-vec-n1n2-64))) mask))))
        (let ((nwords (ceiling size-v 64)))
          (dotimes (i nwords)
            (setf (aref o i) (aref v i)))))
    (values)))


;;;
;;; SHAKE-256 seed expander (incremental squeeze via re-production).
;;;

(defstruct hqc-seedexpander
  (seed #() :type (simple-array (unsigned-byte 8) (*)))
  (done 0 :type fixnum))

(defun hqc-shake256 (input output-length)
  (let ((d (make-digest :shake256 :output-length output-length)))
    (update-digest d input)
    (produce-digest d)))

(defun hqc-seedexpander-init (seed)
  (let ((with-domain (make-array (1+ (length seed)) :element-type '(unsigned-byte 8))))
    (replace with-domain seed)
    (setf (aref with-domain (length seed)) 2)
    (make-hqc-seedexpander :seed with-domain :done 0)))

(defun hqc-seedexpander-squeeze (expander outlen)
  "Squeeze OUTLEN fresh bytes, advancing the stream.
Mirrors the reference: partial 8-byte blocks are fully consumed."
  (let* ((done (hqc-seedexpander-done expander))
         (rem (mod outlen 8))
         (consumed (if (zerop rem) outlen (+ outlen (- 8 rem))))
         (full (hqc-shake256 (hqc-seedexpander-seed expander) (+ done outlen)))
         (out (make-array outlen :element-type '(unsigned-byte 8))))
    (replace out full :start2 done)
    (setf (hqc-seedexpander-done expander) (+ done consumed))
    out))

(defun hqc-shake256-512-ds (input domain)
  "One-shot SHAKE-256(input || domain) to 64 bytes."
  (let ((in (make-array (1+ (length input)) :element-type '(unsigned-byte 8))))
    (replace in input)
    (setf (aref in (length input)) domain)
    (hqc-shake256 in 64)))


;;;
;;; Fixed-weight vector sampling.
;;;

(declaim (inline hqc-u32))
(defun hqc-u32 (x)
  (logand x #xFFFFFFFF))

(defun hqc-cond-sub (r n)
  (let ((rr (hqc-u32 (- r n))))
    (if (zerop (ldb (byte 1 31) rr))
        rr
        (hqc-u32 (+ rr n)))))

(defun hqc-support-reduce (a i)
  (let* ((m (aref (hqc-m-val) i))
         (q (ash (* a m) -32))
         (n (- (hqc-n) i))
         (r (- a (* q n))))
    (hqc-cond-sub (hqc-u32 r) n)))

(defun hqc-vec-set-random-fixed-weight (expander v weight)
  (let* ((rand-bytes (hqc-seedexpander-squeeze expander (* 4 weight)))
         (support (make-array weight :element-type '(unsigned-byte 32)
                                       :initial-element 0))
         (index-tab (make-array weight :element-type 'fixnum :initial-element 0))
         (bit-tab (make-array weight :element-type '(unsigned-byte 64)
                                        :initial-element 0)))
    (dotimes (i weight)
      (let ((w (logior (aref rand-bytes (* 4 i))
                       (ash (aref rand-bytes (+ (* 4 i) 1)) 8)
                       (ash (aref rand-bytes (+ (* 4 i) 2)) 16)
                       (ash (aref rand-bytes (+ (* 4 i) 3)) 24))))
        (setf (aref support i) (hqc-u32 (+ i (hqc-support-reduce w i))))))
    (loop for i from (- weight 2) downto 0
          do (let ((found nil))
               (loop for j from (1+ i) below weight
                     do (when (= (aref support j) (aref support i))
                          (setf found t)))
               (when found
                 (setf (aref support i) i))))
    (dotimes (i weight)
      (setf (aref index-tab i) (ash (aref support i) -6))
      (setf (aref bit-tab i) (ash 1 (logand (aref support i) #x3F))))
    (dotimes (i (hqc-vec-n-64))
      (setf (aref v i) 0))
    (dotimes (i (hqc-vec-n-64))
      (let ((val 0))
        (dotimes (j weight)
          (when (= i (aref index-tab j))
            (setf val (logior val (aref bit-tab j)))))
        (setf (aref v i) (logior (aref v i) val))))
    (values)))

(defun hqc-vec-set-random (expander v)
  (let* ((nbytes (hqc-vec-n-bytes))
         (rand-bytes (hqc-seedexpander-squeeze expander nbytes))
         (n64 (hqc-vec-n-64)))
    (hqc-load8-arr v n64 rand-bytes nbytes)
    (setf (aref v (1- n64)) (logand (aref v (1- n64)) (hqc-red-mask)))
    (values)))


;;;
;;; GF(2)[x] Karatsuba multiply + reduce mod x^n - 1.
;;;

(defconstant +hqc-low-bit-masks+
  (let ((masks (make-array 64 :element-type '(unsigned-byte 64))))
    (setf (aref masks 0) #xFFFFFFFFFFFFFFFF)
    (loop for j from 1 to 63
          do (setf (aref masks j) (1- (ash 1 (- 64 j)))))
    masks))

(declaim (inline hqc-base-mul))
(defun hqc-base-mul (c a b)
  "Constant-time bit-serial carryless 64x64 -> 128-bit product into C[0..1]."
  (let ((l 0) (h 0))
    (dotimes (j 64)
      (let ((bmask (- (ldb (byte 1 j) b))))
        (if (zerop j)
            (setf l (logxor l (logand a bmask)))
            (let ((low-bits (logand a (aref +hqc-low-bit-masks+ j))))
              (setf l (logxor l (logand (ash low-bits j) bmask)))
              (setf h (logxor h (logand (ash a (- (- 64 j))) bmask)))))))
    (setf (aref c 0) l
          (aref c 1) h)
    (values)))

(declaim (inline hqc-karatsuba-add1 hqc-karatsuba-add2 hqc-vec-reduce))
(defun hqc-karatsuba-add1 (alh blh a b size-l size-h)
  (dotimes (i size-h)
    (setf (aref alh i) (logxor (aref a i) (aref a (+ i size-l))))
    (setf (aref blh i) (logxor (aref b i) (aref b (+ i size-l)))))
  (when (< size-h size-l)
    (setf (aref alh size-h) (aref a size-h))
    (setf (aref blh size-h) (aref b size-h)))
  (values))

(defun hqc-karatsuba-add2 (o tmp1 tmp2 size-l size-h)
  (dotimes (i (* 2 size-l))
    (setf (aref tmp1 i) (logxor (aref tmp1 i) (aref o i))))
  (dotimes (i (* 2 size-h))
    (setf (aref tmp1 i) (logxor (aref tmp1 i) (aref tmp2 i))))
  (dotimes (i (* 2 size-l))
    (setf (aref o (+ i size-l)) (logxor (aref o (+ i size-l)) (aref tmp1 i))))
  (values))

(defun hqc-karatsuba (o a b size)
  (if (= size 1)
      (let ((c (hqc-u64vec 2)))
        (hqc-base-mul c (aref a 0) (aref b 0))
        (setf (aref o 0) (aref c 0)
              (aref o 1) (aref c 1))
        (values))
      (let* ((size-h (truncate size 2))
         (size-l (truncate (1+ size) 2))
         (alh (hqc-u64vec (1+ size-l)))
         (blh (hqc-u64vec (1+ size-l)))
         (tmp1 (hqc-u64vec (* 2 size-l)))
         (ah (make-array size-h :element-type '(unsigned-byte 64)
                             :displaced-to a :displaced-index-offset size-l))
         (bh (make-array size-h :element-type '(unsigned-byte 64)
                             :displaced-to b :displaced-index-offset size-l))
         (tmp2 (make-array (* 2 size-h) :element-type '(unsigned-byte 64)
                               :displaced-to o :displaced-index-offset (* 2 size-l))))
    (hqc-karatsuba o a b size-l)
    (hqc-karatsuba tmp2 ah bh size-h)
    (hqc-karatsuba-add1 alh blh a b size-l size-h)
    (hqc-karatsuba tmp1 alh blh size-l)
    (hqc-karatsuba-add2 o tmp1 tmp2 size-l size-h)
    (values))))

(defun hqc-vec-reduce (o a)
  (let ((n64 (hqc-vec-n-64))
        (rem (mod (hqc-n) 64)))
    (dotimes (i n64)
      (let ((r (ash (aref a (+ i n64 -1)) (- rem)))
            (carry (logand (ash (aref a (+ i n64)) (- 64 rem)) #xFFFFFFFFFFFFFFFF)))
        (setf (aref o i) (logxor (aref a i) r carry))))
    (setf (aref o (1- n64)) (logand (aref o (1- n64)) (hqc-red-mask)))
    (values)))

(defun hqc-vec-mul (o v1 v2)
  (let* ((n64 (hqc-vec-n-64))
         (karat (hqc-u64vec (* 2 n64))))
    (hqc-karatsuba karat v1 v2 n64)
    (hqc-vec-reduce o karat)
    (values)))


;;;
;;; Reed-Muller RM(1,7) codec (duplicated).
;;;

(defun hqc-rm-encode-word (cword message)
  (let ((first 0))
    (setf first (logxor (if (logbitp 7 message) #xFFFFFFFF 0)
                        (logand (if (logbitp 0 message) #xAAAAAAAA 0) #xFFFFFFFF)
                        (logand (if (logbitp 1 message) #xCCCCCCCC 0) #xFFFFFFFF)
                        (logand (if (logbitp 2 message) #xF0F0F0F0 0) #xFFFFFFFF)
                        (logand (if (logbitp 3 message) #xFF00FF00 0) #xFFFFFFFF)
                        (logand (if (logbitp 4 message) #xFFFF0000 0) #xFFFFFFFF)))
    (setf first (logand first #xFFFFFFFF))
    (setf (aref cword 0) first)
    (setf first (logxor first (if (logbitp 5 message) #xFFFFFFFF 0)))
    (setf (aref cword 0) (logior (aref cword 0) (ash (logand first #xFFFFFFFF) 32)))
    (setf first (logxor first (if (logbitp 6 message) #xFFFFFFFF 0)))
    (setf (aref cword 1) (logior (ash (logand first #xFFFFFFFF) 32) 0))
    (setf first (logxor first (if (logbitp 5 message) #xFFFFFFFF 0)))
    (setf (aref cword 1) (logior (aref cword 1) (logand first #xFFFFFFFF)))
    (values)))

(defun hqc-rm-hadamard (src dst)
  (let ((p1 src) (p2 dst))
    (dotimes (pass 7)
      (dotimes (i 64)
        (setf (aref p2 i) (+ (aref p1 (* 2 i)) (aref p1 (+ (* 2 i) 1))))
        (setf (aref p2 (+ i 64)) (- (aref p1 (* 2 i)) (aref p1 (+ (* 2 i) 1)))))
      (let ((p3 p1))
        (setf p1 p2
              p2 p3))))
  (values))

(defun hqc-rm-expand-and-sum (dest src mult)
  (dotimes (part 2)
    (dotimes (bit 64)
      (setf (aref dest (+ (* part 64) bit))
            (ldb (byte 1 bit) (aref src part)))))
  (loop for copy from 1 below mult
        do (dotimes (part 2)
             (dotimes (bit 64)
               (incf (aref dest (+ (* part 64) bit))
                     (ldb (byte 1 bit) (aref src (+ (* 2 copy) part)))))))
  (values))

(defun hqc-rm-find-peaks (transform)
  (let ((best-abs -1)
        (best-pos 0)
        (best-peak 0))
    (dotimes (i 128)
      (let* ((raw (aref transform i))
             (tv (if (>= raw #x8000) (- raw #x10000) raw))
             (av (abs tv)))
        (when (> av best-abs)
          (setf best-abs av
                best-pos i
                best-peak tv))))
    (logior best-pos (if (minusp best-peak) 0 128))))

(defun hqc-rm-encode (cdw msg)
  (let ((mult (hqc-multiplicity))
        (n1 (hqc-vec-n1-bytes)))
    (dotimes (i n1)
      (let ((w (hqc-u64vec 2)))
        (hqc-rm-encode-word w (aref msg i))
        (setf (aref cdw (* 2 i mult)) (aref w 0)
              (aref cdw (+ (* 2 i mult) 1)) (aref w 1))
        (loop for copy from 1 below mult
              do (setf (aref cdw (+ (* 2 i mult) (* 2 copy))) (aref w 0)
                       (aref cdw (+ (* 2 i mult) (* 2 copy) 1)) (aref w 1)))))
    (values)))

(defun hqc-rm-decode (msg cdw)
  (let ((mult (hqc-multiplicity))
        (n1 (hqc-vec-n1-bytes))
        (expanded (make-array 128 :element-type 'fixnum :initial-element 0))
        (transform (make-array 128 :element-type 'fixnum :initial-element 0)))
    (dotimes (i n1)
      (let ((src (make-array (* 2 mult) :element-type '(unsigned-byte 64))))
        (dotimes (k (* 2 mult))
          (setf (aref src k) (aref cdw (+ (* 2 i mult) k))))
        (hqc-rm-expand-and-sum expanded src mult)
        (hqc-rm-hadamard expanded transform)
        (setf (aref transform 0) (- (aref transform 0) (* 64 mult)))
        (setf (aref msg i) (hqc-rm-find-peaks transform))))
    (values)))
(defparameter +hqc-gf-exp+
  #(
    1 2 4 8 16 32 64 128 29 58 116 232 205 135 19 38
    76 152 45 90 180 117 234 201 143 3 6 12 24 48 96 192
    157 39 78 156 37 74 148 53 106 212 181 119 238 193 159 35
    70 140 5 10 20 40 80 160 93 186 105 210 185 111 222 161
    95 190 97 194 153 47 94 188 101 202 137 15 30 60 120 240
    253 231 211 187 107 214 177 127 254 225 223 163 91 182 113 226
    217 175 67 134 17 34 68 136 13 26 52 104 208 189 103 206
    129 31 62 124 248 237 199 147 59 118 236 197 151 51 102 204
    133 23 46 92 184 109 218 169 79 158 33 66 132 21 42 84
    168 77 154 41 82 164 85 170 73 146 57 114 228 213 183 115
    230 209 191 99 198 145 63 126 252 229 215 179 123 246 241 255
    227 219 171 75 150 49 98 196 149 55 110 220 165 87 174 65
    130 25 50 100 200 141 7 14 28 56 112 224 221 167 83 166
    81 162 89 178 121 242 249 239 195 155 43 86 172 69 138 9
    18 36 72 144 61 122 244 245 247 243 251 235 203 139 11 22
    44 88 176 125 250 233 207 131 27 54 108 216 173 71 142 1
    2 4
    ))
(defparameter +hqc-gf-log+
  #(
    0 0 1 25 2 50 26 198 3 223 51 238 27 104 199 75
    4 100 224 14 52 141 239 129 28 193 105 248 200 8 76 113
    5 138 101 47 225 36 15 33 53 147 142 218 240 18 130 69
    29 181 194 125 106 39 249 185 201 154 9 120 77 228 114 166
    6 191 139 98 102 221 48 253 226 152 37 179 16 145 34 136
    54 208 148 206 143 150 219 189 241 210 19 92 131 56 70 64
    30 66 182 163 195 72 126 110 107 58 40 84 250 133 186 61
    202 94 155 159 10 21 121 43 78 212 229 172 115 243 167 87
    7 112 192 247 140 128 99 13 103 74 222 237 49 197 254 24
    227 165 153 119 38 184 180 124 17 68 146 217 35 32 137 46
    55 63 209 91 149 188 207 205 144 135 151 178 220 252 190 97
    242 86 211 171 20 42 93 158 132 60 57 83 71 109 65 162
    31 45 67 216 183 123 164 118 196 23 73 236 127 12 111 246
    108 161 59 82 41 157 85 170 251 96 134 177 187 204 62 90
    203 89 95 176 156 169 160 81 11 245 22 235 122 117 44 215
    79 174 213 233 230 231 173 232 116 214 244 234 168 80 88 175
    ))


;;;
;;; Reed-Solomon codec over GF(256).
;;;

(defun hqc-rs-encode (cdw msg)
  (let* ((n1 (hqc-n1))
         (kk (hqc-k))
         (gg (hqc-gg))
         (poly (hqc-rs-poly))
         (tmp (make-array gg :element-type '(unsigned-byte 16) :initial-element 0))
         (gate 0))
    (dotimes (i n1)
      (setf (aref cdw i) 0))
    (dotimes (ii kk)
      (let ((i ii))
        (setf gate (logxor (aref msg (- kk 1 i)) (aref cdw (- n1 kk 1))))
        (dotimes (j gg)
          (setf (aref tmp j) (hqc-gf-mul gate (aref poly j))))
        (loop for k from (- n1 kk 1) downto 1
              do (setf (aref cdw k) (logand #xFF (logxor (aref cdw (1- k)) (aref tmp k)))))
        (setf (aref cdw 0) (logand #xFF (aref tmp 0)))))
    (dotimes (i kk)
      (setf (aref cdw (+ (- n1 kk) i)) (aref msg i)))
    (values)))

(defun hqc-rs-syndromes (syndromes cdw)
  (let ((n1 (hqc-n1))
        (delta (hqc-delta)))
    (dotimes (i (* 2 delta))
      (setf (aref syndromes i) 0))
    (dotimes (i (* 2 delta))
      (loop for j from 1 below n1
            do (setf (aref syndromes i)
                     (logxor (aref syndromes i)
                             (hqc-gf-mul (aref cdw j)
                                         (aref +hqc-gf-exp+
                                               (mod (* (1+ i) j) 255))))))
      (setf (aref syndromes i) (logxor (aref syndromes i) (aref cdw 0))))
    (values)))

(defun hqc-u16-nonzero-mask (x)
  "0xFFFF iff (-X mod 2^16) has high bit set (nonzero for small values)."
  (if (zerop (ldb (byte 1 15) (logand (- x) #xFFFF))) 0 #xFFFF))

(defun hqc-u16-lt-mask (a b)
  "0xFFFF iff (A-B mod 2^16) has high bit set (a<b for small values)."
  (if (zerop (ldb (byte 1 15) (logand (- a b) #xFFFF))) 0 #xFFFF))

(defun hqc-rs-elp (sigma syndromes)
  (let* ((delta (hqc-delta))
         (deg-sigma 0)
         (deg-sigma-p 0)
         (deg-sigma-copy 0)
         (sigma-copy (make-array (1+ delta) :element-type '(unsigned-byte 16)
                                                   :initial-element 0))
         (x-sigma-p (make-array (1+ delta) :element-type '(unsigned-byte 16)
                                                   :initial-element 0))
         (pp #xFFFF)
         (d-p 1)
         (d (aref syndromes 0))
         (mask1 0) (mask2 0) (mask12 0)
         (deg-x 0) (deg-x-sigma-p 0)
         (dd 0) (mu 0))
    (setf (aref x-sigma-p 0) 0)
    (when (> delta 0)
      (setf (aref x-sigma-p 1) 1))
    (setf (aref sigma 0) 1)
    (dotimes (muloop (* 2 delta))
      (setf mu muloop)
      (dotimes (i delta)
        (setf (aref sigma-copy i) (aref sigma i)))
      (setf deg-sigma-copy deg-sigma)
      (setf dd (hqc-gf-mul d (hqc-gf-inv d-p)))
      (loop for i from 1 to (min (1+ mu) delta)
            do (setf (aref sigma i)
                     (logxor (aref sigma i)
                             (hqc-gf-mul dd (aref x-sigma-p i)))))
      (setf deg-x (logand (- mu pp) #xFFFF))
      (setf deg-x-sigma-p (logand (+ deg-x deg-sigma-p) #xFFFF))
      (setf mask1 (hqc-u16-nonzero-mask d))
      (setf mask2 (hqc-u16-lt-mask deg-sigma deg-x-sigma-p))
      (setf mask12 (logand mask1 mask2))
      (setf deg-sigma (logxor deg-sigma (logand mask12 (logxor deg-x-sigma-p deg-sigma))))
      (when (= mu (1- (* 2 delta)))
        (return deg-sigma))
      (setf pp (logxor pp (logand mask12 (logxor mu pp))))
      (setf d-p (logxor d-p (logand mask12 (logxor d d-p))))
      (loop for i from delta downto 1
            do (setf (aref x-sigma-p i)
                     (logior (logand mask12 (aref sigma-copy (1- i)))
                             (logand (logxor mask12 #xFFFF) (aref x-sigma-p (1- i))))))
      (setf deg-sigma-p (logxor deg-sigma-p (logand mask12 (logxor deg-sigma-copy deg-sigma-p))))
      (setf d (aref syndromes (1+ mu)))
      (loop for i from 1 to (min (1+ mu) delta)
            do (setf d (logxor d (hqc-gf-mul (aref sigma i) (aref syndromes (- (1+ mu) i)))))))
    deg-sigma))


;;;
;;; Additive FFT over GF(256) (Gao-Mateer).
;;;

(defun hqc-fft-betas (betas)
  (let ((m (hqc-gf-m)))
    (dotimes (i (1- m))
      (setf (aref betas i) (ash 1 (- (1- m) i)))))
  (values))

(defun hqc-subset-sums (sums set set-size)
  (setf (aref sums 0) 0)
  (dotimes (i set-size)
    (dotimes (j (ash 1 i))
      (setf (aref sums (+ (ash 1 i) j))
            (logxor (aref set i) (aref sums j)))))
  (values))

(defun hqc-radix (f0 f1 f m-f)
  (case m-f
    (4 (setf (aref f0 4) (logxor (aref f 8) (aref f 12))
             (aref f0 6) (logxor (aref f 12) (aref f 14))
             (aref f0 7) (logxor (aref f 14) (aref f 15))
             (aref f1 5) (logxor (aref f 11) (aref f 13))
             (aref f1 6) (logxor (aref f 13) (aref f 14))
             (aref f1 7) (aref f 15)
             (aref f0 5) (logxor (aref f 10) (aref f 12) (aref f1 5))
             (aref f1 4) (logxor (aref f 9) (aref f 13) (aref f0 5))
             (aref f0 0) (aref f 0)
             (aref f1 3) (logxor (aref f 7) (aref f 11) (aref f 15))
             (aref f0 3) (logxor (aref f 6) (aref f 10) (aref f 14) (aref f1 3))
             (aref f0 2) (logxor (aref f 4) (aref f0 4) (aref f0 3) (aref f1 3))
             (aref f1 1) (logxor (aref f 3) (aref f 5) (aref f 9) (aref f 13) (aref f1 3))
             (aref f1 2) (logxor (aref f 3) (aref f1 1) (aref f0 3))
             (aref f0 1) (logxor (aref f 2) (aref f0 2) (aref f1 1))
             (aref f1 0) (logxor (aref f 1) (aref f0 1))))
    (3 (setf (aref f0 0) (aref f 0)
             (aref f0 2) (logxor (aref f 4) (aref f 6))
             (aref f0 3) (logxor (aref f 6) (aref f 7))
             (aref f1 1) (logxor (aref f 3) (aref f 5) (aref f 7))
             (aref f1 2) (logxor (aref f 5) (aref f 6))
             (aref f1 3) (aref f 7)
             (aref f0 1) (logxor (aref f 2) (aref f0 2) (aref f1 1))
             (aref f1 0) (logxor (aref f 1) (aref f0 1))))
    (2 (setf (aref f0 0) (aref f 0)
             (aref f0 1) (logxor (aref f 2) (aref f 3))
             (aref f1 0) (logxor (aref f 1) (aref f0 1))
             (aref f1 1) (aref f 3)))
    (1 (setf (aref f0 0) (aref f 0)
             (aref f1 0) (aref f 1)))
    (otherwise (hqc-radix-big f0 f1 f m-f)))
  (values))

(defun hqc-radix-big (f0 f1 f m-f)
  (let* ((qsize (1+ (* 2 (ash 1 (- (hqc-fft-bits) 2)))))
         (hsize (ash 1 (- (hqc-fft-bits) 2)))
         (q (make-array qsize :element-type '(unsigned-byte 16) :initial-element 0))
         (r (make-array qsize :element-type '(unsigned-byte 16) :initial-element 0))
         (q0 (make-array hsize :element-type '(unsigned-byte 16) :initial-element 0))
         (q1 (make-array hsize :element-type '(unsigned-byte 16) :initial-element 0))
         (r0 (make-array hsize :element-type '(unsigned-byte 16) :initial-element 0))
         (r1 (make-array hsize :element-type '(unsigned-byte 16) :initial-element 0))
         (n (ash 1 (- m-f 2))))
    (dotimes (i n)
      (setf (aref q i) (aref f (+ (* 3 n) i))
            (aref q (+ n i)) (aref f (+ (* 3 n) i))))
    (dotimes (i (* 2 n))
      (setf (aref r i) (aref f i)))
    (dotimes (i n)
      (setf (aref q i) (logxor (aref q i) (aref f (+ (* 2 n) i))))
      (setf (aref r (+ n i)) (logxor (aref r (+ n i)) (aref q i))))
    (hqc-radix q0 q1 q (1- m-f))
    (hqc-radix r0 r1 r (1- m-f))
    (dotimes (i n)
      (setf (aref f0 i) (aref r0 i))
      (setf (aref f0 (+ n i)) (aref q0 i))
      (setf (aref f1 i) (aref r1 i))
      (setf (aref f1 (+ n i)) (aref q1 i)))
    (values)))

(defun hqc-fft-rec (w f f-coeffs m m-f betas)
  (let* ((hsize (ash 1 (- (hqc-gf-m) 2)))
         (f0 (make-array hsize :element-type '(unsigned-byte 16) :initial-element 0))
         (f1 (make-array hsize :element-type '(unsigned-byte 16) :initial-element 0))
         (gammas (make-array (- (hqc-gf-m) 2) :element-type '(unsigned-byte 16)
                                                :initial-element 0))
         (deltas (make-array (- (hqc-gf-m) 2) :element-type '(unsigned-byte 16)
                                                :initial-element 0))
         (gammas-sums (make-array hsize :element-type '(unsigned-byte 16)
                                                   :initial-element 0))
         (u (make-array hsize :element-type '(unsigned-byte 16) :initial-element 0))
         (tvec (make-array hsize :element-type '(unsigned-byte 16) :initial-element 0))
         (tmp (make-array (- (hqc-gf-m) (1- (hqc-fft-bits))) :element-type '(unsigned-byte 16)
                                                              :initial-element 0)))
    (when (= m-f 1)
      (dotimes (i m)
        (setf (aref tmp i) (hqc-gf-mul (aref betas i) (aref f 1))))
      (setf (aref w 0) (aref f 0))
      (let ((x 1))
        (dotimes (j m)
          (dotimes (k x)
            (setf (aref w (+ x k)) (logxor (aref w k) (aref tmp j))))
          (setf x (ash x 1))))
      (return-from hqc-fft-rec (values)))
    (when (/= (aref betas (1- m)) 1)
      (let ((beta-m-pow 1)
            (x (ash 1 m-f)))
        (dotimes (ii (1- x))
          (let ((i (1+ ii)))
            (setf beta-m-pow (hqc-gf-mul beta-m-pow (aref betas (1- m))))
            (setf (aref f i) (hqc-gf-mul beta-m-pow (aref f i)))))))
    (hqc-radix f0 f1 f m-f)
    (dotimes (i (1- m))
      (setf (aref gammas i)
            (hqc-gf-mul (aref betas i) (hqc-gf-inv (aref betas (1- m)))))
      (setf (aref deltas i)
            (logxor (hqc-gf-square (aref gammas i)) (aref gammas i))))
    (hqc-subset-sums gammas-sums gammas (1- m))
    (hqc-fft-rec u f0 (truncate (1+ f-coeffs) 2) (1- m) (1- m-f) deltas)
    (let ((k (ash 1 (logand (1- m) #xF))))
      (if (<= f-coeffs 3)
          (progn
            (setf (aref w 0) (aref u 0))
            (setf (aref w k) (logxor (aref u 0) (aref f1 0)))
            (dotimes (i k)
              (unless (zerop i)
                (setf (aref w i)
                      (logxor (aref u i)
                              (hqc-gf-mul (aref gammas-sums i) (aref f1 0))))
                (setf (aref w (+ k i)) (logxor (aref w i) (aref f1 0))))))
          (progn
            (hqc-fft-rec tvec f1 (truncate f-coeffs 2) (1- m) (1- m-f) deltas)
            (dotimes (i k)
              (setf (aref w (+ k i)) (aref tvec i)))
            (setf (aref w 0) (aref u 0))
            (setf (aref w k) (logxor (aref w k) (aref u 0)))
            (dotimes (i k)
              (unless (zerop i)
                (setf (aref w i)
                      (logxor (aref u i)
                              (hqc-gf-mul (aref gammas-sums i) (aref tvec i))))
                (setf (aref w (+ k i)) (logxor (aref w (+ k i)) (aref w i))))))))
    (values)))

(defun hqc-fft (w f f-coeffs)
  (let* ((mm (hqc-gf-m))
         (ff (hqc-fft-bits))
         (betas (make-array (1- mm) :element-type '(unsigned-byte 16)
                                         :initial-element 0))
         (betas-sums (make-array (ash 1 (1- mm)) :element-type '(unsigned-byte 16)
                                                       :initial-element 0))
         (f0 (make-array (ash 1 (1- ff)) :element-type '(unsigned-byte 16)
                                               :initial-element 0))
         (f1 (make-array (ash 1 (1- ff)) :element-type '(unsigned-byte 16)
                                               :initial-element 0))
         (deltas (make-array (1- mm) :element-type '(unsigned-byte 16)
                                            :initial-element 0))
         (u (make-array (ash 1 (1- mm)) :element-type '(unsigned-byte 16)
                                              :initial-element 0))
         (v (make-array (ash 1 (1- mm)) :element-type '(unsigned-byte 16)
                                              :initial-element 0)))
    (hqc-fft-betas betas)
    (hqc-subset-sums betas-sums betas (1- mm))
    (hqc-radix f0 f1 f ff)
    (dotimes (i (1- mm))
      (setf (aref deltas i)
            (logxor (hqc-gf-square (aref betas i)) (aref betas i))))
    (hqc-fft-rec u f0 (truncate (1+ f-coeffs) 2) (1- mm) (1- ff) deltas)
    (hqc-fft-rec v f1 (truncate f-coeffs 2) (1- mm) (1- ff) deltas)
    (let ((k (ash 1 (1- mm))))
      (dotimes (i k)
        (setf (aref w (+ k i)) (aref v i)))
      (setf (aref w 0) (aref u 0))
      (setf (aref w k) (logxor (aref w k) (aref u 0)))
      (dotimes (i k)
        (unless (zerop i)
          (setf (aref w i)
                (logxor (aref u i)
                        (hqc-gf-mul (aref betas-sums i) (aref v i))))
          (setf (aref w (+ k i)) (logxor (aref w (+ k i)) (aref w i))))))
    (values)))

(defun hqc-fft-retrieve-error-poly (error w)
  (let* ((mm (hqc-gf-m))
         (gammas (make-array (1- mm) :element-type '(unsigned-byte 16)
                                            :initial-element 0))
         (gammas-sums (make-array (ash 1 (1- mm)) :element-type '(unsigned-byte 16)
                                                        :initial-element 0))
         (k (ash 1 (1- mm))))
    (hqc-fft-betas gammas)
    (hqc-subset-sums gammas-sums gammas (1- mm))
    (setf (aref error 0)
          (logxor (aref error 0)
                  (logxor 1 (if (zerop (ldb (byte 1 15) (logand (- (aref w 0)) #xFFFF))) 0 1))))
    (setf (aref error 0)
          (logxor (aref error 0)
                  (logxor 1 (if (zerop (ldb (byte 1 15) (logand (- (aref w k)) #xFFFF))) 0 1))))
    (dotimes (ii (1- k))
      (let ((i (1+ ii)))
        (let ((index (- 255 (aref +hqc-gf-log+ (aref gammas-sums i)))))
          (setf (aref error index)
                (logxor (aref error index)
                        (logxor 1 (if (zerop (ldb (byte 1 15) (logand (- (aref w i)) #xFFFF))) 0 1)))))
        (let ((index (- 255 (aref +hqc-gf-log+ (logxor (aref gammas-sums i) 1)))))
          (setf (aref error index)
                (logxor (aref error index)
                        (logxor 1 (if (zerop (ldb (byte 1 15) (logand (- (aref w (+ k i))) #xFFFF))) 0 1)))))))
    (values)))


;;;
;;; Reed-Solomon decode driver + concatenated codec.
;;;

(defun hqc-rs-compute-z (z sigma degree syndromes)
  (let ((delta (hqc-delta)))
    (setf (aref z 0) 1)
    (dotimes (ii delta)
      (let ((i (1+ ii)))
        (setf (aref z i)
              (if (<= i degree) (aref sigma i) 0))))
    (setf (aref z 1) (logxor (aref z 1) (aref syndromes 0)))
    (loop for i from 2 to delta
          do (when (<= i degree)
               (setf (aref z i) (logxor (aref z i) (aref syndromes (1- i))))
               (loop for j from 1 below i
                     do (setf (aref z i)
                              (logxor (aref z i)
                                      (hqc-gf-mul (aref sigma j)
                                                  (aref syndromes (- i j 1))))))))
    (values)))

(defun hqc-rs-error-values (error-values z error)
  (let* ((delta (hqc-delta))
         (n1 (hqc-n1))
         (beta-j (make-array delta :element-type '(unsigned-byte 16)
                                         :initial-element 0))
         (e-j (make-array delta :element-type '(unsigned-byte 16)
                                       :initial-element 0))
         (delta-counter 0)
         (delta-real-value 0))
    (dotimes (i n1)
      (unless (zerop (aref error i))
        (when (< delta-counter delta)
          (setf (aref beta-j delta-counter)
                (logand #xFFFF
                        (+ (aref beta-j delta-counter)
                           (aref +hqc-gf-exp+ i))))
          (incf delta-counter))))
    (setf delta-real-value delta-counter)
    (dotimes (i delta)
      (let ((tmp1 1)
            (tmp2 1)
            (inverse (hqc-gf-inv (aref beta-j i)))
            (inverse-power-j 1))
        (dotimes (jj delta)
          (let ((j (1+ jj)))
            (setf inverse-power-j (hqc-gf-mul inverse-power-j inverse))
            (setf tmp1 (logxor tmp1 (hqc-gf-mul inverse-power-j (aref z j))))))
        (loop for k from 1 below delta
              do (setf tmp2
                       (hqc-gf-mul tmp2
                                   (logxor 1 (hqc-gf-mul inverse
                                                         (aref beta-j (mod (+ i k) delta)))))))
        (when (< i delta-real-value)
          (setf (aref e-j i) (hqc-gf-mul tmp1 (hqc-gf-inv tmp2))))))
    (setf delta-counter 0)
    (dotimes (i n1)
      (unless (zerop (aref error i))
        (when (< delta-counter delta)
          (setf (aref error-values i) (aref e-j delta-counter))
          (incf delta-counter))))
    (values)))

(defun hqc-rs-correct (cdw error-values)
  (dotimes (i (hqc-n1))
    (setf (aref cdw i) (logxor (aref cdw i) (aref error-values i))))
  (values))

(defun hqc-rs-decode (msg cdw)
  (let* ((delta (hqc-delta))
         (n1 (hqc-n1))
         (syndromes (make-array (* 2 delta) :element-type '(unsigned-byte 16)
                                                   :initial-element 0))
         (sigma (make-array (ash 1 (hqc-fft-bits)) :element-type '(unsigned-byte 16)
                                                     :initial-element 0))
         (error (make-array (ash 1 (hqc-gf-m)) :element-type '(unsigned-byte 8)
                                                       :initial-element 0))
         (z (make-array n1 :element-type '(unsigned-byte 16) :initial-element 0))
         (error-values (make-array n1 :element-type '(unsigned-byte 16)
                                                 :initial-element 0)))
    (hqc-rs-syndromes syndromes cdw)
    (let ((deg (hqc-rs-elp sigma syndromes)))
      (hqc-rs-compute-roots error sigma)
      (hqc-rs-compute-z z sigma deg syndromes)
      (hqc-rs-error-values error-values z error)
      (hqc-rs-correct cdw error-values)
      (dotimes (i (hqc-k))
        (setf (aref msg i) (aref cdw (+ (1- (hqc-gg)) i))))
      (values))))

(defun hqc-rs-compute-roots (error sigma)
  (let ((w (make-array (ash 1 (hqc-gf-m)) :element-type '(unsigned-byte 16)
                                                 :initial-element 0)))
    (hqc-fft w sigma (1+ (hqc-delta)))
    (hqc-fft-retrieve-error-poly error w)
    (values)))

(defun hqc-code-encode (em m)
  (let ((tmp (make-array (hqc-vec-n1-bytes) :element-type '(unsigned-byte 8)
                                                   :initial-element 0)))
    (hqc-rs-encode tmp m)
    (hqc-rm-encode em tmp)
    (values)))

(defun hqc-code-decode (m em)
  (let ((tmp (make-array (hqc-vec-n1-bytes) :element-type '(unsigned-byte 8)
                                                   :initial-element 0)))
    (hqc-rm-decode tmp em)
    (hqc-rs-decode m tmp)
    (values)))


;;;
;;; HQC PKE: keygen / encrypt / decrypt.
;;;

(defun hqc-public-key-to-string (pk-bytes pk-seed s)
  (replace pk-bytes pk-seed)
  (let ((tmp (make-array (hqc-vec-n-bytes) :element-type '(unsigned-byte 8) :initial-element 0)))
    (hqc-store8-arr tmp (hqc-vec-n-bytes) s (hqc-vec-n-64))
    (replace pk-bytes tmp :start1 (hqc-seed-bytes)))
  pk-bytes)

(defun hqc-public-key-from-string (h s pk-bytes)
  (let ((expander (hqc-seedexpander-init (subseq pk-bytes 0 (hqc-seed-bytes)))))
    (hqc-vec-set-random expander h)
    (hqc-load8-arr s (hqc-vec-n-64)
                   (subseq pk-bytes (hqc-seed-bytes)
                           (+ (hqc-seed-bytes) (hqc-vec-n-bytes)))
                   (hqc-vec-n-bytes)))
  (values))

(defun hqc-secret-key-to-string (sk-bytes sk-seed sigma pk-bytes)
  (replace sk-bytes sk-seed)
  (replace sk-bytes sigma :start1 (hqc-seed-bytes))
  (replace sk-bytes pk-bytes :start1 (+ (hqc-seed-bytes) (hqc-vec-k-bytes)))
  sk-bytes)

(defun hqc-keypair-from-seeds (sk-seed pk-seed sigma)
  (let* ((seed-bytes (hqc-seed-bytes))
         (sk-exp (hqc-seedexpander-init (subseq sk-seed 0 seed-bytes)))
         (pk-exp (hqc-seedexpander-init (subseq pk-seed 0 seed-bytes)))
         (x (hqc-u64vec (hqc-vec-n-64)))
         (y (hqc-u64vec (hqc-vec-n-64)))
         (h (hqc-u64vec (hqc-vec-n-64)))
         (s (hqc-u64vec (hqc-vec-n-64))))
    (hqc-vec-set-random-fixed-weight sk-exp x (hqc-omega))
    (hqc-vec-set-random-fixed-weight sk-exp y (hqc-omega))
    (hqc-vec-set-random pk-exp h)
    (hqc-vec-mul s y h)
    (hqc-vec-add s x s (hqc-vec-n-64))
    (let ((pk (make-array (hqc-pk-bytes) :element-type '(unsigned-byte 8) :initial-element 0))
          (sk (make-array (hqc-sk-bytes) :element-type '(unsigned-byte 8) :initial-element 0)))
      (hqc-public-key-to-string pk (subseq pk-seed 0 seed-bytes) s)
      (hqc-secret-key-to-string sk (subseq sk-seed 0 seed-bytes) sigma pk)
      (values pk sk))))

(defun hqc-generate-keypair ()
  (let ((sk-seed (random-data (hqc-seed-bytes)))
        (pk-seed (random-data (hqc-seed-bytes)))
        (sigma (random-data (hqc-vec-k-bytes))))
    (let* ((sk-exp (hqc-seedexpander-init sk-seed))
           (pk-exp (hqc-seedexpander-init pk-seed))
           (x (hqc-u64vec (hqc-vec-n-64)))
           (y (hqc-u64vec (hqc-vec-n-64)))
           (h (hqc-u64vec (hqc-vec-n-64)))
           (s (hqc-u64vec (hqc-vec-n-64))))
      (hqc-vec-set-random-fixed-weight sk-exp x (hqc-omega))
      (hqc-vec-set-random-fixed-weight sk-exp y (hqc-omega))
      (hqc-vec-set-random pk-exp h)
      (hqc-vec-mul s y h)
      (hqc-vec-add s x s (hqc-vec-n-64))
      (let ((pk (make-array (hqc-pk-bytes) :element-type '(unsigned-byte 8) :initial-element 0))
            (sk (make-array (hqc-sk-bytes) :element-type '(unsigned-byte 8) :initial-element 0)))
        (hqc-public-key-to-string pk pk-seed s)
        (hqc-secret-key-to-string sk sk-seed sigma pk)
        (values pk sk)))))

(defun hqc-pke-encrypt-vecs (u v m theta pk-bytes)
  (let ((expander (hqc-seedexpander-init (subseq theta 0 (hqc-seed-bytes))))
        (h (hqc-u64vec (hqc-vec-n-64)))
        (s (hqc-u64vec (hqc-vec-n-64)))
        (r1 (hqc-u64vec (hqc-vec-n-64)))
        (r2 (hqc-u64vec (hqc-vec-n-64)))
        (e (hqc-u64vec (hqc-vec-n-64)))
        (tmp1 (hqc-u64vec (hqc-vec-n-64)))
        (tmp2 (hqc-u64vec (hqc-vec-n-64))))
    (hqc-public-key-from-string h s pk-bytes)
    (hqc-vec-set-random-fixed-weight expander r1 (hqc-omega-r))
    (hqc-vec-set-random-fixed-weight expander r2 (hqc-omega-r))
    (hqc-vec-set-random-fixed-weight expander e (hqc-omega-e))
    (hqc-vec-mul u r2 h)
    (hqc-vec-add u r1 u (hqc-vec-n-64))
    (hqc-code-encode v m)
    (hqc-vec-resize tmp1 (hqc-n) v (hqc-n1n2))
    (hqc-vec-mul tmp2 r2 s)
    (hqc-vec-add tmp2 e tmp2 (hqc-vec-n-64))
    (hqc-vec-add tmp2 tmp1 tmp2 (hqc-vec-n-64))
    (hqc-vec-resize v (hqc-n1n2) tmp2 (hqc-n))
    (values)))

(defun hqc-pke-decrypt-vecs (m sigma-out u v sk-bytes)
  (let* ((seed-bytes (hqc-seed-bytes))
         (kbytes (hqc-vec-k-bytes))
         (sk-seed (subseq sk-bytes 0 seed-bytes))
         (expander (hqc-seedexpander-init sk-seed))
         (x (hqc-u64vec (hqc-vec-n-64)))
         (y (hqc-u64vec (hqc-vec-n-64)))
         (tmp1 (hqc-u64vec (hqc-vec-n-64)))
         (tmp2 (hqc-u64vec (hqc-vec-n-64))))
    (replace sigma-out (subseq sk-bytes seed-bytes (+ seed-bytes kbytes)))
    (hqc-vec-set-random-fixed-weight expander x (hqc-omega))
    (hqc-vec-set-random-fixed-weight expander y (hqc-omega))
    (hqc-vec-resize tmp1 (hqc-n) v (hqc-n1n2))
    (hqc-vec-mul tmp2 y u)
    (hqc-vec-add tmp2 tmp1 tmp2 (hqc-vec-n-64))
    (hqc-code-decode m tmp2)
    (values)))


;;;
;;; KEM layer (FO transform with domains 3/4).
;;;

(defun hqc-ciphertext-to-string (ct u v salt)
  (let ((nbytes (hqc-vec-n-bytes))
        (n1n2bytes (hqc-vec-n1n2-bytes)))
    (hqc-store8-arr ct nbytes u (hqc-vec-n-64))
    (let ((tmp (make-array n1n2bytes :element-type '(unsigned-byte 8) :initial-element 0)))
      (hqc-store8-arr tmp n1n2bytes v (hqc-vec-n1n2-64))
      (replace ct tmp :start1 nbytes))
    (replace ct salt :start1 (+ nbytes n1n2bytes)))
  ct)

(defun hqc-ciphertext-from-string (u v salt-out ct)
  (let ((nbytes (hqc-vec-n-bytes))
        (n1n2bytes (hqc-vec-n1n2-bytes)))
    (hqc-load8-arr u (hqc-vec-n-64) (subseq ct 0 nbytes) nbytes)
    (hqc-load8-arr v (hqc-vec-n1n2-64)
                   (subseq ct nbytes (+ nbytes n1n2bytes)) n1n2bytes)
    (replace salt-out (subseq ct (+ nbytes n1n2bytes)
                              (+ nbytes n1n2bytes (hqc-salt-bytes)))))
  (values))

(defun hqc-kem-encaps-deterministic (m salt pk-bytes)
  (let* ((kbytes (hqc-vec-k-bytes))
         (nbytes (hqc-vec-n-bytes))
         (n1n2bytes (hqc-vec-n1n2-bytes))
         (g-in (make-array (+ kbytes (hqc-pk-bytes) (hqc-salt-bytes))
                           :element-type '(unsigned-byte 8))))
    (replace g-in m)
    (replace g-in pk-bytes :start1 kbytes)
    (replace g-in salt :start1 (+ kbytes (hqc-pk-bytes)))
    (let ((theta (hqc-shake256-512-ds g-in 3)))
      (let ((u (hqc-u64vec (hqc-vec-n-64)))
            (v (hqc-u64vec (hqc-vec-n1n2-64))))
        (hqc-pke-encrypt-vecs u v m theta pk-bytes)
        (let ((mc (make-array (+ kbytes nbytes n1n2bytes)
                              :element-type '(unsigned-byte 8)))
              (ct (make-array (hqc-ct-bytes) :element-type '(unsigned-byte 8)
                                                   :initial-element 0)))
          (replace mc m)
          (let ((ub (make-array nbytes :element-type '(unsigned-byte 8)
                                            :initial-element 0)))
            (hqc-store8-arr ub nbytes u (hqc-vec-n-64))
            (replace mc ub :start1 kbytes))
          (let ((tmp (make-array n1n2bytes :element-type '(unsigned-byte 8)
                                                   :initial-element 0)))
            (hqc-store8-arr tmp n1n2bytes v (hqc-vec-n1n2-64))
            (replace mc tmp :start1 (+ kbytes nbytes)))
          (let ((ss (hqc-shake256-512-ds mc 4)))
            (hqc-ciphertext-to-string ct u v salt)
            (values ct ss)))))))

(defun hqc-kem-decaps (ct sk-bytes)
  (let* ((kbytes (hqc-vec-k-bytes))
         (nbytes (hqc-vec-n-bytes))
         (n1n2bytes (hqc-vec-n1n2-bytes))
         (pk (subseq sk-bytes (+ (hqc-seed-bytes) kbytes)))
         (u (hqc-u64vec (hqc-vec-n-64)))
         (v (hqc-u64vec (hqc-vec-n1n2-64)))
         (salt (make-array (hqc-salt-bytes) :element-type '(unsigned-byte 8)))
         (m (make-array kbytes :element-type '(unsigned-byte 8) :initial-element 0))
         (sigma (make-array kbytes :element-type '(unsigned-byte 8) :initial-element 0)))
    (hqc-ciphertext-from-string u v salt ct)
    (hqc-pke-decrypt-vecs m sigma u v sk-bytes)
    (let ((g-in (make-array (+ kbytes (hqc-pk-bytes) (hqc-salt-bytes))
                            :element-type '(unsigned-byte 8))))
      (replace g-in m)
      (replace g-in pk :start1 kbytes)
      (replace g-in salt :start1 (+ kbytes (hqc-pk-bytes)))
      (let ((theta (hqc-shake256-512-ds g-in 3)))
        (let ((u2 (hqc-u64vec (hqc-vec-n-64)))
              (v2 (hqc-u64vec (hqc-vec-n1n2-64))))
          (hqc-pke-encrypt-vecs u2 v2 m theta pk)
          (let ((match (and (equalp (subseq u 0 (hqc-vec-n-64))
                                    (subseq u2 0 (hqc-vec-n-64)))
                            (equalp (subseq v 0 (hqc-vec-n1n2-64))
                                    (subseq v2 0 (hqc-vec-n1n2-64))))))
            (let ((mc (make-array (+ kbytes nbytes n1n2bytes)
                                  :element-type '(unsigned-byte 8))))
              (replace mc (if match m sigma))
              ;; NOTE: mc uses the RECEIVED (u,v), per reference.
              (let ((ub (make-array nbytes :element-type '(unsigned-byte 8)
                                                 :initial-element 0))
                    (vb (make-array n1n2bytes :element-type '(unsigned-byte 8)
                                                     :initial-element 0)))
                (hqc-store8-arr ub nbytes u (hqc-vec-n-64))
                (hqc-store8-arr vb n1n2bytes v (hqc-vec-n1n2-64))
                (replace mc ub :start1 kbytes)
                (replace mc vb :start1 (+ kbytes nbytes)))
              (hqc-shake256-512-ds mc 4))))))))


;;;
;;; Public API: key classes, generation, encapsulation.
;;;

(defclass hqc-key ()
  ((kind :initarg :kind :reader hqc-key-kind)
   (bytes :initarg :bytes :reader hqc-key-bytes)))

(defclass hqc-public-key (hqc-key)
  ())

(defclass hqc-private-key (hqc-key)
  ())

(defclass hqc-128-public-key (hqc-public-key)
  ())

(defclass hqc-128-private-key (hqc-private-key)
  ())

(defclass hqc-192-public-key (hqc-public-key)
  ())

(defclass hqc-192-private-key (hqc-private-key)
  ())

(defclass hqc-256-public-key (hqc-public-key)
  ())

(defclass hqc-256-private-key (hqc-private-key)
  ())

(defun hqc-check-bytes (bytes length kind)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) length))
    (error 'missing-key-parameter
           :kind kind
           :parameter 'bytes
           :description "HQC key bytes"))
  (copy-seq bytes))

(defmacro hqc-define-key-constructors (kind public-class private-class)
  `(progn
     (defmethod make-public-key ((kind (eql ,kind)) &key bytes &allow-other-keys)
       (let ((*hqc-params* (hqc-params-for-kind ,kind)))
         (make-instance ',public-class :kind ,kind
                        :bytes (hqc-check-bytes bytes (hqc-pk-bytes) ,kind))))
     (defmethod make-private-key ((kind (eql ,kind)) &key bytes &allow-other-keys)
       (let ((*hqc-params* (hqc-params-for-kind ,kind)))
         (make-instance ',private-class :kind ,kind
                        :bytes (hqc-check-bytes bytes (hqc-sk-bytes) ,kind))))
     (defmethod generate-key-pair ((kind (eql ,kind)) &key &allow-other-keys)
       (let ((*hqc-params* (hqc-params-for-kind ,kind)))
         (multiple-value-bind (pk sk) (hqc-generate-keypair)
           (values (make-private-key ,kind :bytes sk)
                   (make-public-key ,kind :bytes pk)))))))

(hqc-define-key-constructors :hqc-128 hqc-128-public-key hqc-128-private-key)
(hqc-define-key-constructors :hqc-192 hqc-192-public-key hqc-192-private-key)
(hqc-define-key-constructors :hqc-256 hqc-256-public-key hqc-256-private-key)

(defmethod destructure-public-key ((public-key hqc-public-key))
  (list :bytes (copy-seq (hqc-key-bytes public-key))))

(defmethod destructure-private-key ((private-key hqc-private-key))
  (list :bytes (copy-seq (hqc-key-bytes private-key))))

(defun hqc-encaps-from-parts (m salt pk-bytes kind)
  (let ((*hqc-params* (hqc-params-for-kind kind)))
    (hqc-kem-encaps-deterministic m salt pk-bytes)))

(defmethod encapsulate-key ((public-key hqc-public-key))
  (let* ((kind (hqc-key-kind public-key))
         (*hqc-params* (hqc-params-for-kind kind))
         (m (random-data (hqc-vec-k-bytes)))
         (salt (random-data (hqc-salt-bytes))))
    (hqc-kem-encaps-deterministic m salt (hqc-key-bytes public-key))))

(defmethod decapsulate-key ((private-key hqc-private-key) ciphertext)
  (let* ((kind (hqc-key-kind private-key))
         (*hqc-params* (hqc-params-for-kind kind)))
    (unless (and (typep ciphertext '(simple-array (unsigned-byte 8) (*)))
                 (= (length ciphertext) (hqc-ct-bytes)))
      (error 'invalid-message-length :kind kind))
    (hqc-kem-decaps ciphertext (hqc-key-bytes private-key))))
