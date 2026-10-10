;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ml-dsa.lisp -- ML-DSA-44/65/87 digital signatures (FIPS 204)
;;;;
;;;; Constant-time discipline is NOT claimed (like the rest of
;;;; Ironclad).  The arithmetic replicates the pqcrystals Dilithium
;;;; reference implementation exactly, including its Montgomery-domain
;;;; representation inside the NTT, so all intermediate values and
;;;; all byte encodings match the reference vectors.
;;;; Polynomial coefficients are small signed integers; packing
;;;; routines truncate to 8-bit bytes exactly like the C code.
;;;;
;;;; (generate-key-pair :ml-dsa-65) => private-key, public-key
;;;; (sign-message private-key message) => signature-bytes
;;;; (verify-signature public-key message signature) => boolean
;;;;
;;;; Sizes (44/65/87):
;;;;   public key 1312/1952/2592, private key 2560/4032/4896,
;;;;   signature 2420/3309/4627 octets.

(in-package :crypto)


(defconstant +ml-dsa-q+ 8380417)
(defconstant +ml-dsa-n+ 256)
(defconstant +ml-dsa-d+ 13)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defstruct ml-dsa-params
    kind k l eta tau beta gamma1 gamma2 omega ctilde
    pkbytes skbytes sigbytes etapacked zpacked w1packed)

  (defun ml-dsa-make-params (kind k l eta tau beta gamma1 gamma2 omega ctilde)
    (make-ml-dsa-params
     :kind kind :k k :l l :eta eta :tau tau :beta beta
     :gamma1 gamma1 :gamma2 gamma2 :omega omega :ctilde ctilde
     :pkbytes (+ 32 (* 320 k))
     :skbytes (+ 128 (* (+ l k) (if (= eta 2) 96 128)) (* 416 k))
     :sigbytes (+ ctilde (* l (if (= gamma1 (ash 1 17)) 576 640)) omega k)
     :etapacked (if (= eta 2) 96 128)
     :zpacked (if (= gamma1 (ash 1 17)) 576 640)
     :w1packed (if (= gamma2 (truncate (1- +ml-dsa-q+) 88)) 192 128)))

  (defparameter +ml-dsa-44-params+
    (ml-dsa-make-params :ml-dsa-44 4 4 2 39 78 (ash 1 17)
                        (truncate (1- +ml-dsa-q+) 88) 80 32))
  (defparameter +ml-dsa-65-params+
    (ml-dsa-make-params :ml-dsa-65 6 5 4 49 196 (ash 1 19)
                        (truncate (1- +ml-dsa-q+) 32) 55 48))
  (defparameter +ml-dsa-87-params+
    (ml-dsa-make-params :ml-dsa-87 8 7 2 60 120 (ash 1 19)
                        (truncate (1- +ml-dsa-q+) 32) 75 64))

  (defun ml-dsa-params-for-kind (kind)
    (ecase kind
      (:ml-dsa-44 +ml-dsa-44-params+)
      (:ml-dsa-65 +ml-dsa-65-params+)
      (:ml-dsa-87 +ml-dsa-87-params+))))

;;; Signed representative table, exactly as in the reference code.
(defconst +ml-dsa-zetas+
  (make-array 256 :element-type '(signed-byte 32)
                  :initial-contents
                  '(0 25847 -2608894 -518909 237124 -777960 -876248 466468
                    1826347 2353451 -359251 -2091905 3119733 -2884855 3111497 2680103
                    2725464 1024112 -1079900 3585928 -549488 -1119584 2619752 -2108549
                    -2118186 -3859737 -1399561 -3277672 1757237 -19422 4010497 280005
                    2706023 95776 3077325 3530437 -1661693 -3592148 -2537516 3915439
                    -3861115 -3043716 3574422 -2867647 3539968 -300467 2348700 -539299
                    -1699267 -1643818 3505694 -3821735 3507263 -2140649 -1600420 3699596
                    811944 531354 954230 3881043 3900724 -2556880 2071892 -2797779
                    -3930395 -1528703 -3677745 -3041255 -1452451 3475950 2176455 -1585221
                    -1257611 1939314 -4083598 -1000202 -3190144 -3157330 -3632928 126922
                    3412210 -983419 2147896 2715295 -2967645 -3693493 -411027 -2477047
                    -671102 -1228525 -22981 -1308169 -381987 1349076 1852771 -1430430
                    -3343383 264944 508951 3097992 44288 -1100098 904516 3958618
                    -3724342 -8578 1653064 -3249728 2389356 -210977 759969 -1316856
                    189548 -3553272 3159746 -1851402 -2409325 -177440 1315589 1341330
                    1285669 -1584928 -812732 -1439742 -3019102 -3881060 -3628969 3839961
                    2091667 3407706 2316500 3817976 -3342478 2244091 -2446433 -3562462
                    266997 2434439 -1235728 3513181 -3520352 -3759364 -1197226 -3193378
                    900702 1859098 909542 819034 495491 -1613174 -43260 -522500
                    -655327 -3122442 2031748 3207046 -3556995 -525098 -768622 -3595838
                    342297 286988 -2437823 4108315 3437287 -3342277 1735879 203044
                    2842341 2691481 -2590150 1265009 4055324 1247620 2486353 1595974
                    -3767016 1250494 2635921 -3548272 -2994039 1869119 1903435 -1050970
                    -1333058 1237275 -3318210 -1430225 -451100 1312455 3306115 -1962642
                    -1279661 1917081 -2546312 -1374803 1500165 777191 2235880 3406031
                    -542412 -2831860 -1671176 -1846953 -2584293 -3724270 594136 -3776993
                    -2013608 2432395 2454455 -164721 1957272 3369112 185531 -1207385
                    -3183426 162844 1616392 3014001 810149 1652634 -3694233 -1799107
                    -3038916 3523897 3866901 269760 2213111 -975884 1717735 472078
                    -426683 1723600 -1803090 1910376 -1667432 -1104333 -260646 -3833893
                    -2939036 -2235985 -420899 -2286327 183443 -976891 1612842 -3545687
                    -554416 3919660 -48306 -1362209 3937738 1400424 -846154 1976782)))

;;; mont^2/256, final scale of the inverse NTT.
(defconstant +ml-dsa-invntt-f+ 41978)

(deftype ml-dsa-poly () '(simple-array fixnum (256)))

(defun ml-dsa-new-poly ()
  (make-array 256 :element-type 'fixnum :initial-element 0))

(defun ml-dsa-new-polyvec (n)
  (let ((v (make-array n)))
    (dotimes (i n v)
      (setf (aref v i) (ml-dsa-new-poly)))))


;;;
;;; Modular reduction (exact translations of reduce.c)
;;;

(defun ml-dsa-montgomery-reduce (a)
  "Montgomery reduction; returns integer congruent to A * 2^-32 mod q."
  (declare (type (signed-byte 64) a))
  (let* ((w (ldb (byte 32 0) (* (ldb (byte 32 0) a) 58728449)))
         (t32 (if (>= w (ash 1 31)) (- w (ash 1 32)) w)))
    (ash (- a (* t32 +ml-dsa-q+)) -32)))

(defun ml-dsa-reduce32 (a)
  "Reduce to a representative in [-6283008, 6283008]."
  (declare (type fixnum a))
  (let ((tt (ash (+ a (ash 1 22)) -23)))
    (- a (* tt +ml-dsa-q+))))

(defun ml-dsa-caddq (a)
  "Add Q if A is negative."
  (declare (type fixnum a))
  (if (minusp a) (+ a +ml-dsa-q+) a))

(defun ml-dsa-freeze (a)
  "Standard representative of A in [0, q)."
  (declare (type fixnum a))
  (ml-dsa-caddq (ml-dsa-reduce32 a)))

(defun ml-dsa-fqmul (a b)
  "Multiplication followed by Montgomery reduction."
  (declare (type fixnum a b))
  (ml-dsa-montgomery-reduce (* a b)))

(defun ml-dsa-poly-reduce (r)
  (declare (type ml-dsa-poly r))
  (dotimes (i 256)
    (setf (aref r i) (ml-dsa-reduce32 (aref r i))))
  (values))

(defun ml-dsa-poly-caddq (r)
  (declare (type ml-dsa-poly r))
  (dotimes (i 256)
    (setf (aref r i) (ml-dsa-caddq (aref r i))))
  (values))

(defun ml-dsa-poly-add (r a b)
  (declare (type ml-dsa-poly r a b))
  (dotimes (i 256 r)
    (setf (aref r i) (+ (aref a i) (aref b i)))))

(defun ml-dsa-poly-sub (r a b)
  (declare (type ml-dsa-poly r a b))
  (dotimes (i 256 r)
    (setf (aref r i) (- (aref a i) (aref b i)))))

(defun ml-dsa-poly-shiftl (r)
  "Multiply R by 2^D in place."
  (declare (type ml-dsa-poly r))
  (dotimes (i 256)
    (setf (aref r i) (ash (aref r i) +ml-dsa-d+)))
  (values))


;;;
;;; Number-theoretic transform (exact translations of ntt.c)
;;;

(defun ml-dsa-ntt (r)
  "In-place forward NTT.  No modular reduction after adds/subs."
  (declare (type ml-dsa-poly r))
  (let ((k 0))
    (declare (type fixnum k))
    (loop for len = 128 then (ash len -1)
          while (> len 0)
          do (loop for start from 0 below 256 by (+ len len)
                   do (let ((zeta (aref +ml-dsa-zetas+ (incf k))))
                        (loop for j from start below (+ start len)
                              do (let ((tt (ml-dsa-fqmul zeta (aref r (+ j len)))))
                                   (setf (aref r (+ j len)) (- (aref r j) tt)
                                         (aref r j) (+ (aref r j) tt))))))))
  (values))

(defun ml-dsa-invntt-tomont (r)
  "In-place inverse NTT with Montgomery-domain output."
  (declare (type ml-dsa-poly r))
  (let ((k 256)
        (f +ml-dsa-invntt-f+))
    (declare (type fixnum k))
    (loop for len = 1 then (ash len 1)
          while (< len 256)
          do (loop for start from 0 below 256 by (+ len len)
                   do (let ((zeta (- (aref +ml-dsa-zetas+ (decf k)))))
                        (loop for j from start below (+ start len)
                       do (let ((tt (aref r j)))
                            (setf (aref r j) (+ tt (aref r (+ j len)))
                                  (aref r (+ j len))
                                  (ml-dsa-fqmul zeta (- tt (aref r (+ j len))))))))))
    (dotimes (j 256)
      (setf (aref r j) (ml-dsa-fqmul (aref r j) f))))
  (values))

(defun ml-dsa-pointwise-montgomery (r a b)
  (declare (type ml-dsa-poly r a b))
  (dotimes (i 256)
    (setf (aref r i) (ml-dsa-fqmul (aref a i) (aref b i))))
  (values))

(defun ml-dsa-pointwise-acc (w u v n)
  "W = sum over N of pointwise products (no final reduction)."
  (declare (type ml-dsa-poly w)
           (type fixnum n))
  (ml-dsa-pointwise-montgomery w (aref u 0) (aref v 0))
  (dotimes (i (1- n))
    (let ((tt (ml-dsa-new-poly)))
      (ml-dsa-pointwise-montgomery tt (aref u (1+ i)) (aref v (1+ i)))
      (ml-dsa-poly-add w w tt)))
  (values))


;;;
;;; Rounding (exact translations of rounding.c)
;;;

(defun ml-dsa-power2round (a)
  "Returns (A1 A0) with A = A1*2^D + A0, A standard representative."
  (declare (type fixnum a))
  (let ((a1 (ash (+ a (1- (ash 1 (1- +ml-dsa-d+)))) (- +ml-dsa-d+))))
    (values a1 (- a (ash a1 +ml-dsa-d+)))))

(defun ml-dsa-decompose (a gamma2)
  "Returns (A1 A0); branches on which GAMMA2 is configured."
  (declare (type fixnum a gamma2))
  (let ((a1 (ash (+ a 127) -7)))
    (if (= gamma2 (truncate (1- +ml-dsa-q+) 32))
        (setf a1 (logand (ash (+ (* a1 1025) (ash 1 21)) -22) 15))
        (progn
          (setf a1 (ash (+ (* a1 11275) (ash 1 23)) -24))
          (setf a1 (logxor a1 (logand (ash (- 43 a1) -31) a1)))))
    (let ((a0 (- a (* a1 2 gamma2))))
      (decf a0 (logand (ash (- (truncate (1- +ml-dsa-q+) 2) a0) -31) +ml-dsa-q+))
      (values a1 a0))))

(defun ml-dsa-make-hint (a0 a1 gamma2)
  (declare (type fixnum a0 a1 gamma2))
  (if (or (> a0 gamma2) (< a0 (- gamma2))
          (and (= a0 (- gamma2)) (not (zerop a1))))
      1 0))

(defun ml-dsa-use-hint (a hint gamma2)
  (declare (type fixnum a gamma2)
           (type (integer 0 1) hint))
  (multiple-value-bind (a1 a0) (ml-dsa-decompose a gamma2)
    (if (zerop hint)
        a1
        (if (= gamma2 (truncate (1- +ml-dsa-q+) 32))
            (if (plusp a0) (logand (1+ a1) 15) (logand (1- a1) 15))
            (if (plusp a0)
                (if (= a1 43) 0 (1+ a1))
                (if (zerop a1) 43 (1- a1)))))))

(defun ml-dsa-chknorm-p (r n bound)
  "T when any of the N polynomial coefficients has abs >= BOUND."
  (dotimes (vi n nil)
    (let ((p (aref r vi)))
      (dotimes (i 256)
        (when (>= (abs (aref p i)) bound)
          (return-from ml-dsa-chknorm-p t))))))


;;;
;;; Sampling
;;;

(defun ml-dsa-shake128 (input output-length)
  (let ((d (make-digest :shake128 :output-length output-length)))
    (update-digest d input)
    (produce-digest d)))

(defun ml-dsa-shake256 (input output-length)
  (let ((d (make-digest :shake256 :output-length output-length)))
    (update-digest d input)
    (produce-digest d)))

(defun ml-dsa-stream-init-input (seed nonce-bytes seed-length)
  "Absorb-input equivalent of stream init: SEED || NONCE-LE16."
  (let ((input (make-array (+ seed-length 2) :element-type '(unsigned-byte 8))))
    (replace input seed :end2 seed-length)
    (setf (aref input seed-length) (ldb (byte 8 0) nonce-bytes)
          (aref input (1+ seed-length)) (ldb (byte 8 8) nonce-bytes))
    input))

(defun ml-dsa-rej-uniform (r rstart buf start buflen)
  "Rejection-sample 23-bit values < q into R at RSTART; returns new count."
  (declare (type ml-dsa-poly r)
           (type (simple-array (unsigned-byte 8) (*)) buf)
           (type fixnum rstart start buflen))
  (let ((ctr 0)
        (pos start))
    (declare (type fixnum ctr pos))
    (loop while (and (< (+ rstart ctr) 256) (<= (+ pos 3) (+ start buflen)))
          do (let ((tt (logand (logior (aref buf pos)
                                       (ash (aref buf (+ pos 1)) 8)
                                       (ash (aref buf (+ pos 2)) 16))
                               #x7FFFFF)))
               (incf pos 3)
               (when (< tt +ml-dsa-q+)
                 (setf (aref r (+ rstart ctr)) tt)
                 (incf ctr))))
    ctr))

(defun ml-dsa-sample-uniform (seed32 nonce)
  "Uniform polynomial from 32-byte SEED and 16-bit NONCE."
  (let* ((nonce16 (ldb (byte 16 0) nonce))
         (input (ml-dsa-stream-init-input seed32 nonce16 32))
         (outlen (* 5 168))
         (out (ml-dsa-shake128 input outlen))
         (r (ml-dsa-new-poly))
         (count (ml-dsa-rej-uniform r 0 out 0 outlen)))
    (loop while (< count 256)
          do (setf outlen (+ outlen 168)
                   out (ml-dsa-shake128 input outlen))
             (incf count (ml-dsa-rej-uniform r count out (- outlen 168) 168)))
    r))

(defun ml-dsa-rej-eta (r rstart buf start buflen eta)
  "Rejection-sample [-ETA,ETA] values into R at RSTART; returns new count."
  (declare (type ml-dsa-poly r)
           (type (simple-array (unsigned-byte 8) (*)) buf)
           (type fixnum rstart start buflen eta))
  (let ((ctr 0)
        (pos start))
    (declare (type fixnum ctr pos))
    (loop while (and (< (+ rstart ctr) 256) (< pos (+ start buflen)))
          do (let ((t0 (logand (aref buf pos) #xF))
                   (t1 (ash (aref buf pos) -4)))
               (incf pos)
               (if (= eta 2)
                   (progn
                     (when (< t0 15)
                       (setf t0 (- t0 (* (ash (* 205 t0) -10) 5)))
                       (setf (aref r (+ rstart ctr)) (- 2 t0))
                       (incf ctr))
                     (when (and (< t1 15) (< (+ rstart ctr) 256))
                       (setf t1 (- t1 (* (ash (* 205 t1) -10) 5)))
                       (setf (aref r (+ rstart ctr)) (- 2 t1))
                       (incf ctr)))
                   (progn
                     (when (< t0 9)
                       (setf (aref r (+ rstart ctr)) (- 4 t0))
                       (incf ctr))
                     (when (and (< t1 9) (< (+ rstart ctr) 256))
                       (setf (aref r (+ rstart ctr)) (- 4 t1))
                       (incf ctr))))))
    ctr))

(defun ml-dsa-sample-eta (seed64 nonce eta)
  "ETA-noise polynomial from 64-byte SEED and 16-bit NONCE."
  (let* ((nonce16 (ldb (byte 16 0) nonce))
         (input (ml-dsa-stream-init-input seed64 nonce16 64))
         (outlen (if (= eta 2) 136 272))
         (out (ml-dsa-shake256 input outlen))
         (r (ml-dsa-new-poly))
         (count (ml-dsa-rej-eta r 0 out 0 outlen eta)))
    (loop while (< count 256)
          do (setf outlen (+ outlen 136)
                   out (ml-dsa-shake256 input outlen))
             (incf count (ml-dsa-rej-eta r count out (- outlen 136) 136 eta)))
    r))

(defun ml-dsa-sample-gamma1 (seed64 nonce gamma1 zpacked)
  "Masking polynomial with coefficients in [-(GAMMA1-1), GAMMA1]."
  (let* ((nonce16 (ldb (byte 16 0) nonce))
         (input (ml-dsa-stream-init-input seed64 nonce16 64))
         (outlen (* 5 136))
         (out (ml-dsa-shake256 input outlen))
         (r (ml-dsa-new-poly)))
    (ml-dsa-polyz-unpack r out 0 gamma1 zpacked)
    r))

(defun ml-dsa-challenge (seed ctilde tau)
  "Challenge polynomial with TAU nonzero +-1 coefficients from SEED."
  (let* ((outlen 136)
         (out (ml-dsa-shake256 seed outlen))
         (signs 0)
         (pos 8)
         (r (ml-dsa-new-poly))
         (start (- 256 tau)))
    (dotimes (i 8)
      (setf signs (logior signs (ash (aref out i) (* 8 i)))))
    (do ((i start (1+ i)))
        ((>= i 256))
      (let ((b nil))
        (loop do (when (>= pos outlen)
                   (setf outlen (+ outlen 136)
                         out (ml-dsa-shake256 seed outlen))
                   (setf pos (- outlen 136)))
                 (setf b (aref out pos))
                 (incf pos)
              while (> b i))
        (setf (aref r i) (aref r b)
              (aref r b) (if (logbitp 0 signs) -1 1))
        (setf signs (ash signs -1))))
    r))


;;;
;;; Serialization
;;;

(defun ml-dsa-poly-tobytes-320 (r out out-start)
  "10-bit packing (t1) of R into 320 octets."
  (dotimes (i 64)
    (let ((t0 (aref r (* 4 i)))
          (t1 (aref r (+ (* 4 i) 1)))
          (t2 (aref r (+ (* 4 i) 2)))
          (t3 (aref r (+ (* 4 i) 3))))
      (setf (aref out (+ out-start (* 5 i))) (ldb (byte 8 0) t0)
            (aref out (+ out-start (* 5 i) 1)) (ldb (byte 8 0)
                                                   (logior (ash t0 -8) (ash t1 2)))
            (aref out (+ out-start (* 5 i) 2)) (ldb (byte 8 0)
                                                   (logior (ash t1 -6) (ash t2 4)))
            (aref out (+ out-start (* 5 i) 3)) (ldb (byte 8 0)
                                                   (logior (ash t2 -4) (ash t3 6)))
            (aref out (+ out-start (* 5 i) 4)) (ldb (byte 8 0) (ash t3 -2)))))
  (values))

(defun ml-dsa-poly-frombytes-320 (r data start)
  (dotimes (i 64)
    (let ((b0 (aref data (+ start (* 5 i))))
          (b1 (aref data (+ start (* 5 i) 1)))
          (b2 (aref data (+ start (* 5 i) 2)))
          (b3 (aref data (+ start (* 5 i) 3)))
          (b4 (aref data (+ start (* 5 i) 4))))
      (setf (aref r (* 4 i)) (ldb (byte 10 0) (logior b0 (ash b1 8)))
            (aref r (+ (* 4 i) 1)) (ldb (byte 10 0) (logior (ash b1 -2) (ash b2 6)))
            (aref r (+ (* 4 i) 2)) (ldb (byte 10 0) (logior (ash b2 -4) (ash b3 4)))
            (aref r (+ (* 4 i) 3)) (ldb (byte 10 0) (logior (ash b3 -6) (ash b4 2))))))
  (values))

(defun ml-dsa-polyeta-pack (r out out-start eta)
  (if (= eta 2)
      (dotimes (i 32)
        (let ((t0 (- 2 (aref r (* 8 i))))
              (t1 (- 2 (aref r (+ (* 8 i) 1))))
              (t2 (- 2 (aref r (+ (* 8 i) 2))))
              (t3 (- 2 (aref r (+ (* 8 i) 3))))
              (t4 (- 2 (aref r (+ (* 8 i) 4))))
              (t5 (- 2 (aref r (+ (* 8 i) 5))))
              (t6 (- 2 (aref r (+ (* 8 i) 6))))
              (t7 (- 2 (aref r (+ (* 8 i) 7)))))
          (setf (aref out (+ out-start (* 3 i)))
                (ldb (byte 8 0) (logior t0 (ash t1 3) (ash t2 6)))
                (aref out (+ out-start (* 3 i) 1))
                (ldb (byte 8 0) (logior (ash t2 -2) (ash t3 1)
                                        (ash t4 4) (ash t5 7)))
                (aref out (+ out-start (* 3 i) 2))
                (ldb (byte 8 0) (logior (ash t5 -1) (ash t6 2) (ash t7 5))))))
      (dotimes (i 128)
        (let ((t0 (- 4 (aref r (* 2 i))))
              (t1 (- 4 (aref r (+ (* 2 i) 1)))))
          (setf (aref out (+ out-start i)) (logior t0 (ash t1 4))))))
  (values))

(defun ml-dsa-polyeta-unpack (r data start eta)
  (if (= eta 2)
      (dotimes (i 32)
        (let ((b0 (aref data (+ start (* 3 i))))
              (b1 (aref data (+ start (* 3 i) 1)))
              (b2 (aref data (+ start (* 3 i) 2))))
          (setf (aref r (* 8 i)) (- 2 (ldb (byte 3 0) b0))
                (aref r (+ (* 8 i) 1)) (- 2 (ldb (byte 3 3) b0))
                (aref r (+ (* 8 i) 2)) (- 2 (ldb (byte 3 0)
                                                 (logior (ash b0 -6) (ash b1 2))))
                (aref r (+ (* 8 i) 3)) (- 2 (ldb (byte 3 1) b1))
                (aref r (+ (* 8 i) 4)) (- 2 (ldb (byte 3 4) b1))
                (aref r (+ (* 8 i) 5)) (- 2 (ldb (byte 3 0)
                                                 (logior (ash b1 -7) (ash b2 1))))
                (aref r (+ (* 8 i) 6)) (- 2 (ldb (byte 3 2) b2))
                (aref r (+ (* 8 i) 7)) (- 2 (ldb (byte 3 5) b2)))))
      (dotimes (i 128)
        (let ((b (aref data (+ start i))))
          (setf (aref r (* 2 i)) (- 4 (ldb (byte 4 0) b))
                (aref r (+ (* 2 i) 1)) (- 4 (ldb (byte 4 4) b))))))
  (values))

(defun ml-dsa-polyt0-pack (r out out-start)
  "13-bit packing (t0, offset by 2^12) into 416 octets."
  (dotimes (i 32)
    (let ((t0 (- 4096 (aref r (* 8 i))))
          (t1 (- 4096 (aref r (+ (* 8 i) 1))))
          (t2 (- 4096 (aref r (+ (* 8 i) 2))))
          (t3 (- 4096 (aref r (+ (* 8 i) 3))))
          (t4 (- 4096 (aref r (+ (* 8 i) 4))))
          (t5 (- 4096 (aref r (+ (* 8 i) 5))))
          (t6 (- 4096 (aref r (+ (* 8 i) 6))))
          (t7 (- 4096 (aref r (+ (* 8 i) 7)))))
      (setf (aref out (+ out-start (* 13 i))) (ldb (byte 8 0) t0)
            (aref out (+ out-start (* 13 i) 1)) (ldb (byte 8 0)
                                                    (logior (ash t0 -8) (ash t1 5)))
            (aref out (+ out-start (* 13 i) 2)) (ldb (byte 8 0) (ash t1 -3))
            (aref out (+ out-start (* 13 i) 3)) (ldb (byte 8 0)
                                                    (logior (ash t1 -11) (ash t2 2)))
            (aref out (+ out-start (* 13 i) 4)) (ldb (byte 8 0)
                                                    (logior (ash t2 -6) (ash t3 7)))
            (aref out (+ out-start (* 13 i) 5)) (ldb (byte 8 0) (ash t3 -1))
            (aref out (+ out-start (* 13 i) 6)) (ldb (byte 8 0)
                                                    (logior (ash t3 -9) (ash t4 4)))
            (aref out (+ out-start (* 13 i) 7)) (ldb (byte 8 0) (ash t4 -4))
            (aref out (+ out-start (* 13 i) 8)) (ldb (byte 8 0)
                                                    (logior (ash t4 -12) (ash t5 1)))
            (aref out (+ out-start (* 13 i) 9)) (ldb (byte 8 0)
                                                    (logior (ash t5 -7) (ash t6 6)))
            (aref out (+ out-start (* 13 i) 10)) (ldb (byte 8 0) (ash t6 -2))
            (aref out (+ out-start (* 13 i) 11)) (ldb (byte 8 0)
                                                     (logior (ash t6 -10) (ash t7 3)))
            (aref out (+ out-start (* 13 i) 12)) (ldb (byte 8 0) (ash t7 -5)))))
  (values))

(defun ml-dsa-polyt0-unpack (r data start)
  (dotimes (i 32)
    (let* ((o (+ start (* 13 i)))
           (b0 (aref data o)) (b1 (aref data (+ o 1)))
           (b2 (aref data (+ o 2))) (b3 (aref data (+ o 3)))
           (b4 (aref data (+ o 4))) (b5 (aref data (+ o 5)))
           (b6 (aref data (+ o 6))) (b7 (aref data (+ o 7)))
           (b8 (aref data (+ o 8))) (b9 (aref data (+ o 9)))
           (b10 (aref data (+ o 10))) (b11 (aref data (+ o 11)))
           (b12 (aref data (+ o 12))))
      (setf (aref r (* 8 i)) (- 4096 (ldb (byte 13 0) (logior b0 (ash b1 8))))
            (aref r (+ (* 8 i) 1)) (- 4096 (ldb (byte 13 0)
                                                (logior (ash b1 -5) (ash b2 3) (ash b3 11))))
            (aref r (+ (* 8 i) 2)) (- 4096 (ldb (byte 13 0)
                                                (logior (ash b3 -2) (ash b4 6))))
            (aref r (+ (* 8 i) 3)) (- 4096 (ldb (byte 13 0)
                                                (logior (ash b4 -7) (ash b5 1) (ash b6 9))))
            (aref r (+ (* 8 i) 4)) (- 4096 (ldb (byte 13 0)
                                                (logior (ash b6 -4) (ash b7 4) (ash b8 12))))
            (aref r (+ (* 8 i) 5)) (- 4096 (ldb (byte 13 0)
                                                (logior (ash b8 -1) (ash b9 7))))
            (aref r (+ (* 8 i) 6)) (- 4096 (ldb (byte 13 0)
                                                (logior (ash b9 -6) (ash b10 2) (ash b11 10))))
            (aref r (+ (* 8 i) 7)) (- 4096 (ldb (byte 13 0)
                                                (logior (ash b11 -3) (ash b12 5)))))))
  (values))

(defun ml-dsa-polyz-pack (r out out-start gamma1 zpacked)
  (if (= zpacked 576)
      (dotimes (i 64)
        (let ((t0 (- gamma1 (aref r (* 4 i))))
              (t1 (- gamma1 (aref r (+ (* 4 i) 1))))
              (t2 (- gamma1 (aref r (+ (* 4 i) 2))))
              (t3 (- gamma1 (aref r (+ (* 4 i) 3)))))
          (setf (aref out (+ out-start (* 9 i))) (ldb (byte 8 0) t0)
                (aref out (+ out-start (* 9 i) 1)) (ldb (byte 8 8) t0)
                (aref out (+ out-start (* 9 i) 2)) (ldb (byte 8 0)
                                                       (logior (ash t0 -16) (ash t1 2)))
                (aref out (+ out-start (* 9 i) 3)) (ldb (byte 8 0) (ash t1 -6))
                (aref out (+ out-start (* 9 i) 4)) (ldb (byte 8 0)
                                                       (logior (ash t1 -14) (ash t2 4)))
                (aref out (+ out-start (* 9 i) 5)) (ldb (byte 8 0) (ash t2 -4))
                (aref out (+ out-start (* 9 i) 6)) (ldb (byte 8 0)
                                                       (logior (ash t2 -12) (ash t3 6)))
                (aref out (+ out-start (* 9 i) 7)) (ldb (byte 8 0) (ash t3 -2))
                (aref out (+ out-start (* 9 i) 8)) (ldb (byte 8 0) (ash t3 -10)))))
      (dotimes (i 128)
        (let ((t0 (- gamma1 (aref r (* 2 i))))
              (t1 (- gamma1 (aref r (+ (* 2 i) 1)))))
          (setf (aref out (+ out-start (* 5 i))) (ldb (byte 8 0) t0)
                (aref out (+ out-start (* 5 i) 1)) (ldb (byte 8 8) t0)
                (aref out (+ out-start (* 5 i) 2)) (ldb (byte 8 0)
                                                       (logior (ash t0 -16) (ash t1 4)))
                (aref out (+ out-start (* 5 i) 3)) (ldb (byte 8 0) (ash t1 -4))
                (aref out (+ out-start (* 5 i) 4)) (ldb (byte 8 0) (ash t1 -12))))))
  (values))

(defun ml-dsa-polyz-unpack (r data start gamma1 zpacked)
  (if (= zpacked 576)
      (dotimes (i 64)
        (let* ((o (+ start (* 9 i)))
               (b0 (aref data o)) (b1 (aref data (+ o 1)))
               (b2 (aref data (+ o 2))) (b3 (aref data (+ o 3)))
               (b4 (aref data (+ o 4))) (b5 (aref data (+ o 5)))
               (b6 (aref data (+ o 6))) (b7 (aref data (+ o 7)))
               (b8 (aref data (+ o 8))))
          (setf (aref r (* 4 i)) (- gamma1 (ldb (byte 18 0)
                                                 (logior b0 (ash b1 8) (ash b2 16))))
                (aref r (+ (* 4 i) 1)) (- gamma1 (ldb (byte 18 0)
                                                      (logior (ash b2 -2) (ash b3 6)
                                                              (ash b4 14))))
                (aref r (+ (* 4 i) 2)) (- gamma1 (ldb (byte 18 0)
                                                      (logior (ash b4 -4) (ash b5 4)
                                                              (ash b6 12))))
                (aref r (+ (* 4 i) 3)) (- gamma1 (ldb (byte 18 0)
                                                      (logior (ash b6 -6) (ash b7 2)
                                                              (ash b8 10)))))))
      (dotimes (i 128)
        (let* ((o (+ start (* 5 i)))
               (b0 (aref data o)) (b1 (aref data (+ o 1)))
               (b2 (aref data (+ o 2))) (b3 (aref data (+ o 3)))
               (b4 (aref data (+ o 4))))
          (setf (aref r (* 2 i)) (- gamma1 (ldb (byte 20 0)
                                                 (logior b0 (ash b1 8) (ash b2 16))))
                (aref r (+ (* 2 i) 1)) (- gamma1 (logior (ash b2 -4)
                                                         (ash b3 4)
                                                         (ash b4 12)))))))
  (values))

(defun ml-dsa-polyw1-pack (r out out-start gamma2)
  (if (= gamma2 (truncate (1- +ml-dsa-q+) 88))
      (dotimes (i 64)
        (let ((t0 (aref r (* 4 i)))
              (t1 (aref r (+ (* 4 i) 1)))
              (t2 (aref r (+ (* 4 i) 2)))
              (t3 (aref r (+ (* 4 i) 3))))
          (setf (aref out (+ out-start (* 3 i))) (ldb (byte 8 0)
                                                     (logior t0 (ash t1 6)))
                (aref out (+ out-start (* 3 i) 1)) (ldb (byte 8 0)
                                                       (logior (ash t1 -2) (ash t2 4)))
                (aref out (+ out-start (* 3 i) 2)) (ldb (byte 8 0)
                                                       (logior (ash t2 -4) (ash t3 2))))))
      (dotimes (i 128)
        (let ((t0 (aref r (* 2 i)))
              (t1 (aref r (+ (* 2 i) 1))))
          (setf (aref out (+ out-start i)) (logior t0 (ash t1 4))))))
  (values))


;;;
;;; Key and signature codec
;;;

(defun ml-dsa-pack-pk (pk rho t1 k)
  (replace pk rho :end2 32)
  (dotimes (i k)
    (ml-dsa-poly-tobytes-320 (aref t1 i) pk (+ 32 (* 320 i))))
  (values))

(defun ml-dsa-unpack-pk (rho t1 pk k)
  (replace rho pk :end2 32)
  (dotimes (i k)
    (ml-dsa-poly-frombytes-320 (aref t1 i) pk (+ 32 (* 320 i))))
  (values))

(defun ml-dsa-pack-sk (sk rho key tr s1 s2 t0 k l etapacked)
  (replace sk rho :end2 32)
  (replace sk key :start1 32 :end1 64)
  (replace sk tr :start1 64 :end1 128)
  (let ((off 128))
    (dotimes (i l)
      (ml-dsa-polyeta-pack (aref s1 i) sk off (if (= etapacked 96) 2 4))
      (incf off etapacked))
    (dotimes (i k)
      (ml-dsa-polyeta-pack (aref s2 i) sk off (if (= etapacked 96) 2 4))
      (incf off etapacked))
    (dotimes (i k)
      (ml-dsa-polyt0-pack (aref t0 i) sk off)
      (incf off 416)))
  (values))

(defun ml-dsa-unpack-sk (rho key tr s1 s2 t0 sk k l etapacked)
  (replace rho sk :end2 32)
  (replace key sk :start2 32 :end2 64)
  (replace tr sk :start2 64 :end2 128)
  (let ((off 128)
        (eta (if (= etapacked 96) 2 4)))
    (dotimes (i l)
      (ml-dsa-polyeta-unpack (aref s1 i) sk off eta)
      (incf off etapacked))
    (dotimes (i k)
      (ml-dsa-polyeta-unpack (aref s2 i) sk off eta)
      (incf off etapacked))
    (dotimes (i k)
      (ml-dsa-polyt0-unpack (aref t0 i) sk off)
      (incf off 416)))
  (values))

(defun ml-dsa-pack-sig (sig cseed z h k l zpacked omega ctilde)
  (replace sig cseed :end2 ctilde)
  (ml-dsa-polyz-pack-into sig ctilde z l zpacked)
  (let ((hoff (+ ctilde (* l zpacked)))
        (kk 0))
    (loop for i from hoff below (+ hoff omega k)
          do (setf (aref sig i) 0))
    (dotimes (i k)
      (let ((p (aref h i)))
        (dotimes (j 256)
          (unless (zerop (aref p j))
            (setf (aref sig (+ hoff kk)) j)
            (incf kk)))
        (setf (aref sig (+ hoff omega i)) kk))))
  (values))

(defun ml-dsa-polyz-pack-into (sig off z l zpacked)
  (let ((gamma1 (if (= zpacked 576) (ash 1 17) (ash 1 19))))
    (dotimes (i l)
      (ml-dsa-polyz-pack (aref z i) sig off gamma1 zpacked)
      (incf off zpacked)))
  (values))

(defun ml-dsa-unpack-sig (sig-c z h sig k l zpacked omega ctilde)
  "Returns T when the signature encoding is malformed."
  (replace sig-c sig :end2 ctilde)
  (ml-dsa-polyz-unpack-into sig ctilde z l zpacked)
  (let ((hoff (+ ctilde (* l zpacked)))
        (kk 0))
    (dotimes (i k)
      (let ((p (aref h i)))
        (dotimes (j 256)
          (setf (aref p j) 0))
        (let ((end (aref sig (+ hoff omega i))))
          (when (or (< end kk) (> end omega))
            (return-from ml-dsa-unpack-sig t))
          (loop for j from kk below end
                do (when (and (> j kk) (<= (aref sig (+ hoff j))
                                           (aref sig (+ hoff (1- j)))))
                     (return-from ml-dsa-unpack-sig t))
                   (setf (aref p (aref sig (+ hoff j))) 1))
          (setf kk end))))
    (loop for j from kk below omega
          do (unless (zerop (aref sig (+ hoff j)))
               (return-from ml-dsa-unpack-sig t))))
  nil)

(defun ml-dsa-polyz-unpack-into (sig off z l zpacked)
  (let ((gamma1 (if (= zpacked 576) (ash 1 17) (ash 1 19))))
    (dotimes (i l)
      (ml-dsa-polyz-unpack (aref z i) sig off gamma1 zpacked)
      (incf off zpacked)))
  (values))


;;;
;;; Matrix and vector operations
;;;

(defun ml-dsa-gen-matrix (rho k l)
  "KxL matrix; entry [i][j] sampled with nonce (i<<8)+j."
  (let ((a (make-array (list k l))))
    (dotimes (i k)
      (dotimes (j l)
        (setf (aref a i j) (ml-dsa-sample-uniform rho (logior (ash i 8) j)))))
    a))

(defun ml-dsa-matrix-row (a i l)
  (let ((row (make-array l)))
    (dotimes (j l row)
      (setf (aref row j) (aref a i j)))))

(defun ml-dsa-sample-eta-vec (v n seed start-nonce eta)
  (dotimes (i n)
    (setf (aref v i) (ml-dsa-sample-eta seed (+ start-nonce i) eta)))
  (values))

(defun ml-dsa-sample-gamma1-vec (v n seed outer-nonce l dp)
  (let ((gamma1 (ml-dsa-params-gamma1 dp))
        (zpacked (ml-dsa-params-zpacked dp)))
    (dotimes (i n)
      (setf (aref v i) (ml-dsa-sample-gamma1 seed (+ (* l outer-nonce) i)
                                             gamma1 zpacked))))
  (values))

(defun ml-dsa-vec-ntt (v n)
  (dotimes (i n)
    (ml-dsa-ntt (aref v i)))
  (values))

(defun ml-dsa-vec-invntt-tomont (v n)
  (dotimes (i n)
    (ml-dsa-invntt-tomont (aref v i)))
  (values))

(defun ml-dsa-vec-reduce (v n)
  (dotimes (i n)
    (ml-dsa-poly-reduce (aref v i)))
  (values))

(defun ml-dsa-vec-caddq (v n)
  (dotimes (i n)
    (ml-dsa-poly-caddq (aref v i)))
  (values))

(defun ml-dsa-vec-add (r a b n)
  (dotimes (i n)
    (ml-dsa-poly-add (aref r i) (aref a i) (aref b i)))
  (values))

(defun ml-dsa-vec-sub (r a b n)
  (dotimes (i n)
    (ml-dsa-poly-sub (aref r i) (aref a i) (aref b i)))
  (values))

(defun ml-dsa-vec-shiftl (v n)
  (dotimes (i n)
    (ml-dsa-poly-shiftl (aref v i)))
  (values))

(defun ml-dsa-vec-pointwise (r a v n)
  (dotimes (i n)
    (ml-dsa-pointwise-montgomery (aref r i) a (aref v i)))
  (values))

(defun ml-dsa-vec-decompose (v1 v0 v n gamma2)
  (dotimes (i n)
    (let ((p1 (aref v1 i))
          (p0 (aref v0 i))
          (p (aref v i)))
      (dotimes (j 256)
        (multiple-value-bind (a1 a0) (ml-dsa-decompose (aref p j) gamma2)
          (setf (aref p1 j) a1
                (aref p0 j) a0)))))
  (values))

(defun ml-dsa-vec-power2round (v1 v0 v n)
  (dotimes (i n)
    (let ((p1 (aref v1 i))
          (p0 (aref v0 i))
          (p (aref v i)))
      (dotimes (j 256)
        (multiple-value-bind (a1 a0) (ml-dsa-power2round (aref p j))
          (setf (aref p1 j) a1
                (aref p0 j) a0)))))
  (values))

(defun ml-dsa-vec-make-hint (h v0 v1 n gamma2)
  (let ((s 0))
    (dotimes (i n)
      (let ((ph (aref h i))
            (p0 (aref v0 i))
            (p1 (aref v1 i)))
        (dotimes (j 256)
          (let ((hh (ml-dsa-make-hint (aref p0 j) (aref p1 j) gamma2)))
            (setf (aref ph j) hh)
            (incf s hh)))))
    s))

(defun ml-dsa-vec-use-hint (w u h n gamma2)
  (dotimes (i n)
    (let ((pw (aref w i))
          (pu (aref u i))
          (ph (aref h i)))
      (dotimes (j 256)
        (setf (aref pw j) (ml-dsa-use-hint (aref pu j) (aref ph j) gamma2)))))
  (values))

(defun ml-dsa-pack-w1 (out w1 k w1packed gamma2)
  (dotimes (i k)
    (ml-dsa-polyw1-pack (aref w1 i) out (+ (* i w1packed)) gamma2))
  (values))


;;;
;;; Key generation, signing, verification
;;;

(defun ml-dsa-keygen-from-coins (coins32 dp)
  "Deterministic keypair from 32 coins; returns (pk sk)."
  (let* ((k (ml-dsa-params-k dp))
         (l (ml-dsa-params-l dp))
         (eta (ml-dsa-params-eta dp))
         (ginput (let ((b (make-array 34 :element-type '(unsigned-byte 8))))
                   (replace b coins32 :end2 32)
                   (setf (aref b 32) k
                         (aref b 33) l)
                   b))
         (gout (ml-dsa-shake256 ginput 128))
         (rho (subseq gout 0 32))
         (rhoprime (subseq gout 32 96))
         (key (subseq gout 96 128))
         (mat (ml-dsa-gen-matrix rho k l))
         (s1 (ml-dsa-new-polyvec l))
         (s2 (ml-dsa-new-polyvec k))
         (t1 (ml-dsa-new-polyvec k))
         (t0 (ml-dsa-new-polyvec k))
         (s1hat (ml-dsa-new-polyvec l)))
    (ml-dsa-sample-eta-vec s1 l rhoprime 0 eta)
    (ml-dsa-sample-eta-vec s2 k rhoprime l eta)
    (dotimes (i l)
      (setf (aref s1hat i) (copy-seq (aref s1 i))))
    (ml-dsa-vec-ntt s1hat l)
    (dotimes (i k)
      (ml-dsa-pointwise-acc (aref t1 i) (ml-dsa-matrix-row mat i l) s1hat l))
    (ml-dsa-vec-reduce t1 k)
    (ml-dsa-vec-invntt-tomont t1 k)
    (ml-dsa-vec-add t1 t1 s2 k)
    (ml-dsa-vec-caddq t1 k)
    (ml-dsa-vec-power2round t1 t0 t1 k)
    (let ((pk (make-array (ml-dsa-params-pkbytes dp) :element-type '(unsigned-byte 8)))
          (sk (make-array (ml-dsa-params-skbytes dp) :element-type '(unsigned-byte 8)))
          (tr nil))
      (ml-dsa-pack-pk pk rho t1 k)
      (setf tr (ml-dsa-shake256 pk 64))
      (ml-dsa-pack-sk sk rho key tr s1 s2 t0 k l (ml-dsa-params-etapacked dp))
      (values pk sk))))

(defun ml-dsa-sign-with-rnd (msg sk rnd dp pre)
  "Deterministic signing of MSG with 32-byte RND and PRE prefix bytes."
  (let* ((k (ml-dsa-params-k dp))
         (l (ml-dsa-params-l dp))
         (eta (ml-dsa-params-eta dp))
         (beta (ml-dsa-params-beta dp))
         (gamma1 (ml-dsa-params-gamma1 dp))
         (gamma2 (ml-dsa-params-gamma2 dp))
         (omega (ml-dsa-params-omega dp))
         (ctilde (ml-dsa-params-ctilde dp))
         (tau (ml-dsa-params-tau dp))
         (zpacked (ml-dsa-params-zpacked dp))
         (w1packed (ml-dsa-params-w1packed dp))
         (rho (make-array 32 :element-type '(unsigned-byte 8)))
         (tr (make-array 64 :element-type '(unsigned-byte 8)))
         (key (make-array 32 :element-type '(unsigned-byte 8)))
         (t0 (ml-dsa-new-polyvec k))
         (s1 (ml-dsa-new-polyvec l))
         (s2 (ml-dsa-new-polyvec k))
         (y (ml-dsa-new-polyvec l))
         (z (ml-dsa-new-polyvec l))
         (w1 (ml-dsa-new-polyvec k))
         (w0 (ml-dsa-new-polyvec k))
         (h (ml-dsa-new-polyvec k))
         (cp (ml-dsa-new-poly))
         (sig (make-array (ml-dsa-params-sigbytes dp) :element-type '(unsigned-byte 8))))
    (ml-dsa-unpack-sk rho key tr s1 s2 t0 sk k l (ml-dsa-params-etapacked dp))
    (let* ((mu (ml-dsa-shake256 (concatenate '(simple-array (unsigned-byte 8) (*))
                                             tr pre msg)
                                64))
           (rhoprime (ml-dsa-shake256 (concatenate '(simple-array (unsigned-byte 8) (*))
                                                  key rnd mu)
                                      64))
           (amat (ml-dsa-gen-matrix rho k l)))
      (ml-dsa-vec-ntt s1 l)
      (ml-dsa-vec-ntt s2 k)
      (ml-dsa-vec-ntt t0 k)
      (loop for nonce from 0
            do (ml-dsa-sample-gamma1-vec y l rhoprime nonce l dp)
               (dotimes (i l)
                 (setf (aref z i) (copy-seq (aref y i))))
               (ml-dsa-vec-ntt z l)
               (dotimes (i k)
                 (ml-dsa-pointwise-acc (aref w1 i) (ml-dsa-matrix-row amat i l) z l))
               (ml-dsa-vec-reduce w1 k)
               (ml-dsa-vec-invntt-tomont w1 k)
               (ml-dsa-vec-caddq w1 k)
               (ml-dsa-vec-decompose w1 w0 w1 k gamma2)
               (ml-dsa-pack-w1 sig w1 k w1packed gamma2)
               (let* ((cseed (ml-dsa-shake256 (concatenate '(simple-array (unsigned-byte 8) (*))
                                                           mu (subseq sig 0 (* k w1packed)))
                                              ctilde))
                      (rej nil))
                 (setf cp (ml-dsa-challenge cseed ctilde tau))
                 (ml-dsa-ntt cp)
                 (ml-dsa-vec-pointwise z cp s1 l)
                 (ml-dsa-vec-invntt-tomont z l)
                 (ml-dsa-vec-add z z y l)
                 (ml-dsa-vec-reduce z l)
                 (when (ml-dsa-chknorm-p z l (- gamma1 beta))
                   (setf rej t))
                 (unless rej
                   (ml-dsa-vec-pointwise h cp s2 k)
                   (ml-dsa-vec-invntt-tomont h k)
                   (ml-dsa-vec-sub w0 w0 h k)
                   (ml-dsa-vec-reduce w0 k)
                   (when (ml-dsa-chknorm-p w0 k (- gamma2 beta))
                     (setf rej t)))
                 (unless rej
                   (ml-dsa-vec-pointwise h cp t0 k)
                   (ml-dsa-vec-invntt-tomont h k)
                   (ml-dsa-vec-reduce h k)
                   (when (ml-dsa-chknorm-p h k gamma2)
                     (setf rej t)))
                 (unless rej
                   (ml-dsa-vec-add w0 w0 h k)
                   (when (> (ml-dsa-vec-make-hint h w0 w1 k gamma2) omega)
                     (setf rej t)))
                 (unless rej
                   (ml-dsa-pack-sig sig cseed z h k l zpacked omega ctilde)
                   (return sig)))))))

(defun ml-dsa-verify-internal (sig msg pk dp pre)
  "Returns T when SIG is a valid signature on MSG under PK."
  (let* ((k (ml-dsa-params-k dp))
         (l (ml-dsa-params-l dp))
         (gamma1 (ml-dsa-params-gamma1 dp))
         (beta (ml-dsa-params-beta dp))
         (gamma2 (ml-dsa-params-gamma2 dp))
         (ctilde (ml-dsa-params-ctilde dp))
         (tau (ml-dsa-params-tau dp))
         (omega (ml-dsa-params-omega dp))
         (zpacked (ml-dsa-params-zpacked dp))
         (w1packed (ml-dsa-params-w1packed dp))
         (siglen (ml-dsa-params-sigbytes dp)))
    (when (/= (length sig) siglen)
      (return-from ml-dsa-verify-internal nil))
    (let ((rho (make-array 32 :element-type '(unsigned-byte 8)))
          (t1 (ml-dsa-new-polyvec k))
          (cseed (make-array ctilde :element-type '(unsigned-byte 8)))
          (z (ml-dsa-new-polyvec l))
          (h (ml-dsa-new-polyvec k))
          (cp (ml-dsa-new-poly))
          (w1 (ml-dsa-new-polyvec k)))
      (ml-dsa-unpack-pk rho t1 pk k)
      (when (ml-dsa-unpack-sig cseed z h sig k l zpacked omega ctilde)
        (return-from ml-dsa-verify-internal nil))
      (when (ml-dsa-chknorm-p z l (- gamma1 beta))
        (return-from ml-dsa-verify-internal nil))
      (let* ((tr (ml-dsa-shake256 pk 64))
             (mu (ml-dsa-shake256 (concatenate '(simple-array (unsigned-byte 8) (*))
                                               tr pre msg)
                                  64))
             (mat (ml-dsa-gen-matrix rho k l)))
        (setf cp (ml-dsa-challenge cseed ctilde tau))
        (ml-dsa-vec-ntt z l)
        (dotimes (i k)
          (ml-dsa-pointwise-acc (aref w1 i) (ml-dsa-matrix-row mat i l) z l))
        (ml-dsa-ntt cp)
        (ml-dsa-vec-shiftl t1 k)
        (ml-dsa-vec-ntt t1 k)
        (ml-dsa-vec-pointwise t1 cp t1 k)
        (ml-dsa-vec-sub w1 w1 t1 k)
        (ml-dsa-vec-reduce w1 k)
        (ml-dsa-vec-invntt-tomont w1 k)
        (ml-dsa-vec-caddq w1 k)
        (ml-dsa-vec-use-hint w1 w1 h k gamma2)
        (let ((buf (make-array (* k w1packed) :element-type '(unsigned-byte 8))))
          (ml-dsa-pack-w1 buf w1 k w1packed gamma2)
          (let ((c2 (ml-dsa-shake256 (concatenate '(simple-array (unsigned-byte 8) (*))
                                                  mu buf)
                                     ctilde)))
            (equalp cseed c2)))))))


;;;
;;; Public API: key classes, generation, signing
;;;

(defclass ml-dsa-key ()
  ((kind :initarg :kind :reader ml-dsa-key-kind)
   (bytes :initarg :bytes :reader ml-dsa-key-bytes)))

(defclass ml-dsa-public-key (ml-dsa-key)
  ())

(defclass ml-dsa-private-key (ml-dsa-key)
  ())

(defclass ml-dsa-44-public-key (ml-dsa-public-key)
  ())

(defclass ml-dsa-44-private-key (ml-dsa-private-key)
  ())

(defclass ml-dsa-65-public-key (ml-dsa-public-key)
  ())

(defclass ml-dsa-65-private-key (ml-dsa-private-key)
  ())

(defclass ml-dsa-87-public-key (ml-dsa-public-key)
  ())

(defclass ml-dsa-87-private-key (ml-dsa-private-key)
  ())

(defun ml-dsa-check-bytes (bytes length kind)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) length))
    (error 'missing-key-parameter
           :kind kind
           :parameter 'bytes
           :description "ML-DSA key bytes"))
  (copy-seq bytes))

(defmacro ml-dsa-define-key-constructors (kind public-class private-class)
  (let ((pklen (ml-dsa-params-pkbytes (ml-dsa-params-for-kind kind)))
        (sklen (ml-dsa-params-skbytes (ml-dsa-params-for-kind kind))))
    `(progn
       (defmethod make-public-key ((kind (eql ,kind)) &key bytes &allow-other-keys)
         (make-instance ',public-class :kind ,kind
                        :bytes (ml-dsa-check-bytes bytes ,pklen ,kind)))
       (defmethod make-private-key ((kind (eql ,kind)) &key bytes &allow-other-keys)
         (make-instance ',private-class :kind ,kind
                        :bytes (ml-dsa-check-bytes bytes ,sklen ,kind)))
       (defmethod generate-key-pair ((kind (eql ,kind)) &key &allow-other-keys)
         (multiple-value-bind (pk sk)
             (ml-dsa-keygen-from-coins (random-data 32)
                                       (ml-dsa-params-for-kind ,kind))
           (values (make-private-key ,kind :bytes sk)
                   (make-public-key ,kind :bytes pk)))))))

(ml-dsa-define-key-constructors :ml-dsa-44 ml-dsa-44-public-key ml-dsa-44-private-key)
(ml-dsa-define-key-constructors :ml-dsa-65 ml-dsa-65-public-key ml-dsa-65-private-key)
(ml-dsa-define-key-constructors :ml-dsa-87 ml-dsa-87-public-key ml-dsa-87-private-key)

(defmethod destructure-public-key ((public-key ml-dsa-public-key))
  (list :bytes (copy-seq (ml-dsa-key-bytes public-key))))

(defmethod destructure-private-key ((private-key ml-dsa-private-key))
  (list :bytes (copy-seq (ml-dsa-key-bytes private-key))))

(defun ml-dsa-pre-bytes (ctx)
  "FIPS 204 domain-separation prefix: (0, ctxlen, ctx)."
  (let* ((ctxlen (if ctx (length ctx) 0))
         (pre (make-array (+ 2 ctxlen) :element-type '(unsigned-byte 8))))
    (setf (aref pre 0) 0
          (aref pre 1) ctxlen)
    (when ctx
      (replace pre ctx :start1 2))
    pre))

(defmethod sign-message ((key ml-dsa-private-key) message &key (start 0) end ctx &allow-other-keys)
  (let ((end (or end (length message))))
    (ml-dsa-sign-with-rnd (subseq message start end)
                          (ml-dsa-key-bytes key)
                          (random-data 32)
                          (ml-dsa-params-for-kind (ml-dsa-key-kind key))
                          (ml-dsa-pre-bytes ctx))))

(defmethod verify-signature ((key ml-dsa-public-key) message signature &key (start 0) end ctx &allow-other-keys)
  (let ((end (or end (length message))))
    (and (typep signature '(simple-array (unsigned-byte 8) (*)))
         (ml-dsa-verify-internal signature
                                 (subseq message start end)
                                 (ml-dsa-key-bytes key)
                                 (ml-dsa-params-for-kind (ml-dsa-key-kind key))
                                 (ml-dsa-pre-bytes ctx)))))
