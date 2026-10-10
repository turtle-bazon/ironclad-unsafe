;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ml-kem.lisp -- ML-KEM-512/768/1024 key encapsulation (FIPS 203)
;;;;
;;;; Constant-time discipline is NOT claimed (like the rest of
;;;; Ironclad).  The arithmetic replicates the pqcrystals reference
;;;; implementation exactly, including its Montgomery-domain
;;;; representation inside the NTT, so all intermediate values and
;;;; all byte encodings match the reference and the FIPS 203 vectors.
;;;; Polynomial coefficients are small signed integers (centered or
;;;; standard representatives); serialization freezes them to [0, q).
;;;;
;;;; (generate-key-pair :ml-kem-768) => private-key, public-key
;;;; (encapsulate-key public-key) => ciphertext, shared-secret
;;;; (decapsulate-key private-key ciphertext) => shared-secret
;;;;
;;;; Sizes depend on the parameter set (k = 2/3/4):
;;;;   512:  public key 800,  private key 1632, ciphertext 768
;;;;   768:  public key 1184, private key 2400, ciphertext 1088
;;;;   1024: public key 1568, private key 3168, ciphertext 1568
;;;; Shared secret: 32 octets in all sets.

(in-package :crypto)


(defconstant +ml-kem-q+ 3329)
(defconstant +ml-kem-n+ 256)
(defconstant +ml-kem-ssbytes+ 32)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defstruct ml-kem-params
    kind k eta1 eta2 du dv pkbytes skbytes ctbytes)

  (defun ml-kem-make-params (kind k eta1 du dv)
    (make-ml-kem-params :kind kind :k k :eta1 eta1 :eta2 2 :du du :dv dv
                        :pkbytes (+ (* 384 k) 32)
                        :skbytes (+ (* 768 k) 96)
                        :ctbytes (* 32 (+ (* du k) dv))))

  (defparameter +ml-kem-512-params+ (ml-kem-make-params :ml-kem-512 2 3 10 4))
  (defparameter +ml-kem-768-params+ (ml-kem-make-params :ml-kem-768 3 2 10 4))
  (defparameter +ml-kem-1024-params+ (ml-kem-make-params :ml-kem-1024 4 2 11 5))

  (defun ml-kem-params-for-kind (kind)
    (ecase kind
      (:ml-kem-512 +ml-kem-512-params+)
      (:ml-kem-768 +ml-kem-768-params+)
      (:ml-kem-1024 +ml-kem-1024-params+))))

;;; Signed representative table, exactly as in the reference code.
(defconst +ml-kem-zetas+
  (make-array 128 :element-type '(signed-byte 32)
                  :initial-contents
                  '(-1044 -758 -359 -1517 1493 1422 287 202
                    -171 622 1577 182 962 -1202 -1474 1468
                    573 -1325 264 383 -829 1458 -1602 -130
                    -681 1017 732 608 -1542 411 -205 -1571
                    1223 652 -552 1015 -1293 1491 -282 -1544
                    516 -8 -320 -666 -1618 -1162 126 1469
                    -853 -90 -271 830 107 -1421 -247 -951
                    -398 961 -1508 -725 448 -1065 677 -1275
                    -1103 430 555 843 -1251 871 1550 105
                    422 587 177 -235 -291 -460 1574 1653
                    -246 778 1159 -147 -777 1483 -602 1119
                    -1590 644 -872 349 418 329 -156 -75
                    817 1097 603 610 1322 -1285 -1465 384
                    -1215 -136 1218 -1335 -874 220 -1187 -1659
                    -1185 -1530 -1278 794 -1510 -854 -870 478
                    -108 -308 996 991 958 -1460 1522 1628)))

;;; 2^32 mod q, Montgomery-domain conversion factor (poly_tomont).
(defconstant +ml-kem-mont-f+ 1353)
;;; mont^2/128 mod q, final scale of the inverse NTT (invntt_tomont).
(defconstant +ml-kem-invntt-f+ 1441)

(deftype ml-kem-poly () '(simple-array fixnum (256)))

(defun ml-kem-new-poly ()
  (make-array 256 :element-type 'fixnum :initial-element 0))

(defun ml-kem-new-polyvec (k)
  (let ((v (make-array k)))
    (dotimes (i k v)
      (setf (aref v i) (ml-kem-new-poly)))))


;;;
;;; Modular reduction (exact translations of reduce.c)
;;;

(defun ml-kem-montgomery-reduce (a)
  "Montgomery reduction; returns integer in (-q, q) congruent to
A * 2^-16 mod q.  A must fit in a signed 32-bit word."
  (declare (type (signed-byte 32) a)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let* ((w (ldb (byte 16 0) (* (ldb (byte 16 0) a) -3327)))
         (t16 (if (>= w 32768) (- w 65536) w)))
    (ash (- a (* t16 +ml-kem-q+)) -16)))

(defun ml-kem-barrett-reduce (a)
  "Barrett reduction; returns centered representative in
(-(q-1)/2, (q-1)/2] congruent to A mod q."
  (declare (type fixnum a)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((tt (ash (+ (* 20159 a) (ash 1 25)) -26)))
    (- a (* tt +ml-kem-q+))))

(defun ml-kem-fqmul (a b)
  "Multiplication followed by Montgomery reduction: A*B*2^-16 mod q."
  (declare (type fixnum a b)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (ml-kem-montgomery-reduce (* a b)))

(defun ml-kem-freeze (u)
  "Map a signed representative to the standard [0, q) representative."
  (declare (type fixnum u))
  (if (minusp u) (+ u +ml-kem-q+) u))

(defun ml-kem-poly-reduce (r)
  (declare (type ml-kem-poly r))
  (dotimes (i 256)
    (setf (aref r i) (ml-kem-barrett-reduce (aref r i))))
  (values))


;;;
;;; Number-theoretic transform (exact translations of ntt.c)
;;;

(defun ml-kem-ntt (r)
  "In-place NTT (standard order in, bitreversed order out),
followed by Barrett reduction, like poly_ntt."
  (declare (type ml-kem-poly r)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((k 1))
    (declare (type fixnum k))
    (dolist (len '(128 64 32 16 8 4 2))
      (loop for start from 0 below 256 by (* 2 len)
            do (let ((zeta (aref +ml-kem-zetas+ k)))
                 (incf k)
                 (loop for j from start below (+ start len)
                       do (let ((tt (ml-kem-fqmul zeta (aref r (+ j len)))))
                            (setf (aref r (+ j len)) (- (aref r j) tt)
                                  (aref r j) (+ (aref r j) tt)))))))
    (ml-kem-poly-reduce r))
  (values))

(defun ml-kem-invntt-tomont (r)
  "In-place inverse NTT (bitreversed order in, standard order out)
with output in Montgomery domain, like poly_invntt_tomont."
  (declare (type ml-kem-poly r)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((k 127)
        (f +ml-kem-invntt-f+))
    (declare (type fixnum k))
    (dolist (len '(2 4 8 16 32 64 128))
      (loop for start from 0 below 256 by (* 2 len)
            do (let ((zeta (aref +ml-kem-zetas+ k)))
                 (decf k)
                 (loop for j from start below (+ start len)
                       do (let ((tt (aref r j)))
                            (setf (aref r j)
                                  (ml-kem-barrett-reduce (+ tt (aref r (+ j len))))
                                  (aref r (+ j len))
                                  (ml-kem-fqmul zeta (- (aref r (+ j len)) tt))))))))
    (dotimes (j 256)
      (setf (aref r j) (ml-kem-fqmul (aref r j) f))))
  (values))

(defun ml-kem-basemul-acc (r avec bvec k)
  "R += AVEC * BVEC in the NTT domain, like
polyvec_basemul_acc_montgomery (result Barrett-reduced)."
  (declare (type ml-kem-poly r)
           (type fixnum k)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (fill r 0)
  (dotimes (kk k)
    (let ((a (aref avec kk))
          (b (aref bvec kk)))
      (declare (type ml-kem-poly a b))
      (dotimes (i 64)
        (let* ((base (* 4 i))
               (z (aref +ml-kem-zetas+ (+ 64 i)))
               (zn (- z))
               (a0 (aref a base)) (a1 (aref a (+ base 1)))
               (a2 (aref a (+ base 2))) (a3 (aref a (+ base 3)))
               (b0 (aref b base)) (b1 (aref b (+ base 1)))
               (b2 (aref b (+ base 2))) (b3 (aref b (+ base 3))))
          (setf (aref r base)
                (+ (aref r base)
                   (ml-kem-fqmul (ml-kem-fqmul a1 b1) z)
                   (ml-kem-fqmul a0 b0))
                (aref r (+ base 1))
                (+ (aref r (+ base 1))
                   (ml-kem-fqmul a0 b1)
                   (ml-kem-fqmul a1 b0))
                (aref r (+ base 2))
                (+ (aref r (+ base 2))
                   (ml-kem-fqmul (ml-kem-fqmul a3 b3) zn)
                   (ml-kem-fqmul a2 b2))
                (aref r (+ base 3))
                (+ (aref r (+ base 3))
                   (ml-kem-fqmul a2 b3)
                   (ml-kem-fqmul a3 b2)))))))
  (ml-kem-poly-reduce r)
  (values))

(defun ml-kem-tomont (r)
  "Convert R to Montgomery domain in place, like poly_tomont."
  (declare (type ml-kem-poly r))
  (dotimes (i 256)
    (setf (aref r i)
          (ml-kem-montgomery-reduce (* (aref r i) +ml-kem-mont-f+))))
  (values))

(defun ml-kem-poly-add (r a b)
  (declare (type ml-kem-poly r a b)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (dotimes (i 256 r)
    (setf (aref r i) (+ (aref a i) (aref b i)))))

(defun ml-kem-poly-sub (r a b)
  (declare (type ml-kem-poly r a b)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (dotimes (i 256 r)
    (setf (aref r i) (- (aref a i) (aref b i)))))


;;;
;;; Sampling
;;;

(defun ml-kem-cbd2 (r buf start)
  "Centered binomial distribution, eta = 2, from 128 octets at START."
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) buf)
           (type fixnum start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (dotimes (i 32)
    (let ((tval (logior (ash (aref buf (+ start (* 4 i) 3)) 24)
                        (ash (aref buf (+ start (* 4 i) 2)) 16)
                        (ash (aref buf (+ start (* 4 i) 1)) 8)
                        (aref buf (+ start (* 4 i))))))
      (declare (type (unsigned-byte 32) tval))
      (let ((d (+ (logand tval #x55555555)
                  (logand (ash tval -1) #x55555555))))
        (dotimes (j 8)
          (setf (aref r (+ (* 8 i) j))
                (- (ldb (byte 2 (* 4 j)) d)
                   (ldb (byte 2 (+ (* 4 j) 2)) d)))))))
  (values))

(defun ml-kem-cbd3 (r buf start)
  "Centered binomial distribution, eta = 3, from 192 octets at START."
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) buf)
           (type fixnum start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (dotimes (i 64)
    (let ((tval (logior (ash (aref buf (+ start (* 3 i) 2)) 16)
                        (ash (aref buf (+ start (* 3 i) 1)) 8)
                        (aref buf (+ start (* 3 i))))))
      (declare (type (unsigned-byte 24) tval))
      (let ((d (+ (logand tval #x249249)
                  (logand (ash tval -1) #x249249)
                  (logand (ash tval -2) #x249249))))
        (dotimes (j 4)
          (setf (aref r (+ (* 4 i) j))
                (- (ldb (byte 3 (* 6 j)) d)
                   (ldb (byte 3 (+ (* 6 j) 3)) d)))))))
  (values))

(defun ml-kem-rej-uniform (r rstart buf start buflen)
  "Rejection-sample coefficients < q from BUF into R at RSTART;
returns the number of coefficients written."
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) buf)
           (type fixnum rstart start buflen)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((ctr 0)
        (pos start)
        (q +ml-kem-q+))
    (declare (type fixnum ctr pos))
    (loop while (and (< (+ rstart ctr) 256) (<= (+ pos 3) (+ start buflen)))
          do (let ((val0 (logand (logior (aref buf pos)
                                         (ash (aref buf (+ pos 1)) 8))
                                 #xFFF))
                   (val1 (logand (logior (ash (aref buf (+ pos 1)) -4)
                                         (ash (aref buf (+ pos 2)) 4))
                                 #xFFF)))
               (incf pos 3)
               (when (< val0 q)
                 (setf (aref r (+ rstart ctr)) val0)
                 (incf ctr))
               (when (and (< (+ rstart ctr) 256) (< val1 q))
                 (setf (aref r (+ rstart ctr)) val1)
                 (incf ctr))))
    ctr))


;;;
;;; Serialization
;;;

(defun ml-kem-poly-tobytes (r out out-start)
  "12-bit packing of R into 384 octets at OUT-START."
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) out)
           (type fixnum out-start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (dotimes (i 128)
    (let ((t0 (ml-kem-freeze (aref r (* 2 i))))
          (t1 (ml-kem-freeze (aref r (+ (* 2 i) 1)))))
      (setf (aref out (+ out-start (* 3 i))) (ldb (byte 8 0) t0)
            (aref out (+ out-start (* 3 i) 1)) (logior (ldb (byte 8 8) t0)
                                                      (ash (ldb (byte 4 0) t1) 4))
            (aref out (+ out-start (* 3 i) 2)) (ldb (byte 8 4) t1))))
  (values))

(defun ml-kem-poly-frombytes (r data start)
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (dotimes (i 128)
    (let ((b0 (aref data (+ start (* 3 i))))
          (b1 (aref data (+ start (* 3 i) 1)))
          (b2 (aref data (+ start (* 3 i) 2))))
      (setf (aref r (* 2 i)) (ldb (byte 12 0) (logior b0 (ash b1 8)))
            (aref r (+ (* 2 i) 1)) (ldb (byte 12 0) (logior (ash b1 -4) (ash b2 4))))))
  (values))

(defun ml-kem-compress-4-value (u)
  (declare (type fixnum u))
  (logand (ash (mod (* (mod (+ (ash u 4) 1665) #x100000000) 80635) #x100000000) -28) #xF))

(defun ml-kem-poly-compress-4 (r out out-start)
  "4-bit compression of R into 128 octets at OUT-START."
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) out)
           (type fixnum out-start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (dotimes (i 32)
    (let ((t0 (ml-kem-compress-4-value (ml-kem-freeze (aref r (* 8 i)))))
          (t1 (ml-kem-compress-4-value (ml-kem-freeze (aref r (+ (* 8 i) 1)))))
          (t2 (ml-kem-compress-4-value (ml-kem-freeze (aref r (+ (* 8 i) 2)))))
          (t3 (ml-kem-compress-4-value (ml-kem-freeze (aref r (+ (* 8 i) 3)))))
          (t4 (ml-kem-compress-4-value (ml-kem-freeze (aref r (+ (* 8 i) 4)))))
          (t5 (ml-kem-compress-4-value (ml-kem-freeze (aref r (+ (* 8 i) 5)))))
          (t6 (ml-kem-compress-4-value (ml-kem-freeze (aref r (+ (* 8 i) 6)))))
          (t7 (ml-kem-compress-4-value (ml-kem-freeze (aref r (+ (* 8 i) 7))))))
      (setf (aref out (+ out-start (* 4 i))) (logior t0 (ash t1 4))
            (aref out (+ out-start (* 4 i) 1)) (logior t2 (ash t3 4))
            (aref out (+ out-start (* 4 i) 2)) (logior t4 (ash t5 4))
            (aref out (+ out-start (* 4 i) 3)) (logior t6 (ash t7 4)))))
  (values))

(defun ml-kem-poly-decompress-4 (r data start)
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((q +ml-kem-q+))
    (dotimes (i 128)
      (let ((b (aref data (+ start i))))
        (setf (aref r (* 2 i)) (ash (+ (* (logand b #xF) q) 8) -4)
              (aref r (+ (* 2 i) 1)) (ash (+ (* (ash b -4) q) 8) -4)))))
  (values))

(defun ml-kem-compress-5-value (u)
  (declare (type fixnum u))
  (logand (ash (mod (* (mod (+ (ash u 5) 1664) #x100000000) 40318) #x100000000) -27) #x1F))

(defun ml-kem-poly-compress-5 (r out out-start)
  "5-bit compression of R into 160 octets at OUT-START."
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) out)
           (type fixnum out-start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (dotimes (i 32)
    (let ((t0 (ml-kem-compress-5-value (ml-kem-freeze (aref r (* 8 i)))))
          (t1 (ml-kem-compress-5-value (ml-kem-freeze (aref r (+ (* 8 i) 1)))))
          (t2 (ml-kem-compress-5-value (ml-kem-freeze (aref r (+ (* 8 i) 2)))))
          (t3 (ml-kem-compress-5-value (ml-kem-freeze (aref r (+ (* 8 i) 3)))))
          (t4 (ml-kem-compress-5-value (ml-kem-freeze (aref r (+ (* 8 i) 4)))))
          (t5 (ml-kem-compress-5-value (ml-kem-freeze (aref r (+ (* 8 i) 5)))))
          (t6 (ml-kem-compress-5-value (ml-kem-freeze (aref r (+ (* 8 i) 6)))))
          (t7 (ml-kem-compress-5-value (ml-kem-freeze (aref r (+ (* 8 i) 7))))))
      (setf (aref out (+ out-start (* 5 i))) (ldb (byte 8 0)
                                                   (logior t0 (ash t1 5)))
            (aref out (+ out-start (* 5 i) 1)) (ldb (byte 8 0)
                                                   (logior (ash t1 -3)
                                                           (ash t2 2)
                                                           (ash t3 7)))
            (aref out (+ out-start (* 5 i) 2)) (ldb (byte 8 0)
                                                   (logior (ash t3 -1)
                                                           (ash t4 4)))
            (aref out (+ out-start (* 5 i) 3)) (ldb (byte 8 0)
                                                   (logior (ash t4 -4)
                                                           (ash t5 1)
                                                           (ash t6 6)))
            (aref out (+ out-start (* 5 i) 4)) (logior (ash t6 -2)
                                                      (ash t7 3)))))
  (values))

(defun ml-kem-poly-decompress-5 (r data start)
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((q +ml-kem-q+))
    (dotimes (i 32)
      (let* ((base (+ start (* 5 i)))
             (b0 (aref data base))
             (b1 (aref data (+ base 1)))
             (b2 (aref data (+ base 2)))
             (b3 (aref data (+ base 3)))
             (b4 (aref data (+ base 4)))
             (t0 (ldb (byte 5 0) b0))
             (t1 (ldb (byte 5 0) (logior (ash b0 -5) (ash b1 3))))
             (t2 (ldb (byte 5 0) (ash b1 -2)))
             (t3 (ldb (byte 5 0) (logior (ash b1 -7) (ash b2 1))))
             (t4 (ldb (byte 5 0) (logior (ash b2 -4) (ash b3 4))))
             (t5 (ldb (byte 5 0) (ash b3 -1)))
             (t6 (ldb (byte 5 0) (logior (ash b3 -6) (ash b4 2))))
             (t7 (ldb (byte 5 0) (ash b4 -3))))
        (setf (aref r (* 8 i)) (ash (+ (* t0 q) 16) -5)
              (aref r (+ (* 8 i) 1)) (ash (+ (* t1 q) 16) -5)
              (aref r (+ (* 8 i) 2)) (ash (+ (* t2 q) 16) -5)
              (aref r (+ (* 8 i) 3)) (ash (+ (* t3 q) 16) -5)
              (aref r (+ (* 8 i) 4)) (ash (+ (* t4 q) 16) -5)
              (aref r (+ (* 8 i) 5)) (ash (+ (* t5 q) 16) -5)
              (aref r (+ (* 8 i) 6)) (ash (+ (* t6 q) 16) -5)
              (aref r (+ (* 8 i) 7)) (ash (+ (* t7 q) 16) -5)))))
  (values))

(defun ml-kem-poly-compress (r out out-start dv)
  (ecase dv
    (4 (ml-kem-poly-compress-4 r out out-start))
    (5 (ml-kem-poly-compress-5 r out out-start))))

(defun ml-kem-poly-decompress (r data start dv)
  (ecase dv
    (4 (ml-kem-poly-decompress-4 r data start))
    (5 (ml-kem-poly-decompress-5 r data start))))

(defun ml-kem-compress-10-value (u)
  (declare (type fixnum u))
  ;; d0 is 64-bit in C (no wrapping); take bits [41:32].
  (logand (ash (* (+ (ash u 10) 1665) 1290167) -32) #x3FF))

(defun ml-kem-polyvec-compress-10 (vec k out out-start)
  "10-bit compression of a K-polynomial vector into 320*K octets."
  (dotimes (vi k)
    (let ((base (+ out-start (* vi 320)))
          (r (aref vec vi)))
      (declare (type ml-kem-poly r))
      (dotimes (j 64)
        (let ((t0 (ml-kem-compress-10-value (ml-kem-freeze (aref r (* 4 j)))))
              (t1 (ml-kem-compress-10-value (ml-kem-freeze (aref r (+ (* 4 j) 1)))))
              (t2 (ml-kem-compress-10-value (ml-kem-freeze (aref r (+ (* 4 j) 2)))))
              (t3 (ml-kem-compress-10-value (ml-kem-freeze (aref r (+ (* 4 j) 3))))))
          (setf (aref out (+ base (* 5 j))) (ldb (byte 8 0) t0)
                (aref out (+ base (* 5 j) 1)) (logior (ldb (byte 2 8) t0)
                                                      (ash (ldb (byte 6 0) t1) 2))
                (aref out (+ base (* 5 j) 2)) (logior (ldb (byte 4 6) t1)
                                                      (ash (ldb (byte 4 0) t2) 4))
                (aref out (+ base (* 5 j) 3)) (logior (ldb (byte 6 4) t2)
                                                      (ash (ldb (byte 2 0) t3) 6))
                (aref out (+ base (* 5 j) 4)) (ldb (byte 8 2) t3))))))
  (values))

(defun ml-kem-polyvec-decompress-10 (vec k data start)
  (let ((q +ml-kem-q+))
    (dotimes (vi k)
      (let ((base (+ start (* vi 320)))
            (r (aref vec vi)))
        (declare (type ml-kem-poly r))
        (dotimes (j 64)
          (let ((t0 (ldb (byte 10 0) (logior (aref data (+ base (* 5 j)))
                                             (ash (aref data (+ base (* 5 j) 1)) 8))))
                (t1 (ldb (byte 10 0) (logior (ash (aref data (+ base (* 5 j) 1)) -2)
                                             (ash (aref data (+ base (* 5 j) 2)) 6))))
                (t2 (ldb (byte 10 0) (logior (ash (aref data (+ base (* 5 j) 2)) -4)
                                             (ash (aref data (+ base (* 5 j) 3)) 4))))
                (t3 (ldb (byte 10 0) (logior (ash (aref data (+ base (* 5 j) 3)) -6)
                                             (ash (aref data (+ base (* 5 j) 4)) 2)))))
            (setf (aref r (* 4 j)) (ash (+ (* t0 q) 512) -10)
                  (aref r (+ (* 4 j) 1)) (ash (+ (* t1 q) 512) -10)
                  (aref r (+ (* 4 j) 2)) (ash (+ (* t2 q) 512) -10)
                  (aref r (+ (* 4 j) 3)) (ash (+ (* t3 q) 512) -10)))))))
  (values))

(defun ml-kem-compress-11-value (u)
  (declare (type fixnum u))
  ;; d0 is 64-bit in C (no wrapping); take bits [41:31].
  (logand (ash (* (+ (ash u 11) 1664) 645084) -31) #x7FF))

(defun ml-kem-polyvec-compress-11 (vec k out out-start)
  "11-bit compression of a K-polynomial vector into 352*K octets."
  (dotimes (vi k)
    (let ((base (+ out-start (* vi 352)))
          (r (aref vec vi)))
      (declare (type ml-kem-poly r))
      (dotimes (j 32)
        (let ((t0 (ml-kem-compress-11-value (ml-kem-freeze (aref r (* 8 j)))))
              (t1 (ml-kem-compress-11-value (ml-kem-freeze (aref r (+ (* 8 j) 1)))))
              (t2 (ml-kem-compress-11-value (ml-kem-freeze (aref r (+ (* 8 j) 2)))))
              (t3 (ml-kem-compress-11-value (ml-kem-freeze (aref r (+ (* 8 j) 3)))))
              (t4 (ml-kem-compress-11-value (ml-kem-freeze (aref r (+ (* 8 j) 4)))))
              (t5 (ml-kem-compress-11-value (ml-kem-freeze (aref r (+ (* 8 j) 5)))))
              (t6 (ml-kem-compress-11-value (ml-kem-freeze (aref r (+ (* 8 j) 6)))))
              (t7 (ml-kem-compress-11-value (ml-kem-freeze (aref r (+ (* 8 j) 7))))))
          (setf (aref out (+ base (* 11 j))) (ldb (byte 8 0) t0)
                (aref out (+ base (* 11 j) 1)) (logior (ldb (byte 3 8) t0)
                                                       (ash (ldb (byte 5 0) t1) 3))
                (aref out (+ base (* 11 j) 2)) (logior (ldb (byte 6 5) t1)
                                                       (ash (ldb (byte 2 0) t2) 6))
                (aref out (+ base (* 11 j) 3)) (ldb (byte 8 2) t2)
                (aref out (+ base (* 11 j) 4)) (logior (ldb (byte 1 10) t2)
                                                       (ash (ldb (byte 7 0) t3) 1))
                (aref out (+ base (* 11 j) 5)) (logior (ldb (byte 4 7) t3)
                                                       (ash (ldb (byte 4 0) t4) 4))
                (aref out (+ base (* 11 j) 6)) (logior (ldb (byte 7 4) t4)
                                                       (ash (ldb (byte 1 0) t5) 7))
                (aref out (+ base (* 11 j) 7)) (ldb (byte 8 1) t5)
                (aref out (+ base (* 11 j) 8)) (logior (ldb (byte 2 9) t5)
                                                       (ash (ldb (byte 6 0) t6) 2))
                (aref out (+ base (* 11 j) 9)) (logior (ldb (byte 5 6) t6)
                                                       (ash (ldb (byte 3 0) t7) 5))
                (aref out (+ base (* 11 j) 10)) (ldb (byte 8 3) t7))))))
  (values))

(defun ml-kem-polyvec-decompress-11 (vec k data start)
  (let ((q +ml-kem-q+))
    (dotimes (vi k)
      (let ((base (+ start (* vi 352)))
            (r (aref vec vi)))
        (declare (type ml-kem-poly r))
        (dotimes (j 32)
          (let* ((o (+ base (* 11 j)))
                 (b0 (aref data o))
                 (b1 (aref data (+ o 1)))
                 (b2 (aref data (+ o 2)))
                 (b3 (aref data (+ o 3)))
                 (b4 (aref data (+ o 4)))
                 (b5 (aref data (+ o 5)))
                 (b6 (aref data (+ o 6)))
                 (b7 (aref data (+ o 7)))
                 (b8 (aref data (+ o 8)))
                 (b9 (aref data (+ o 9)))
                 (b10 (aref data (+ o 10)))
                 (t0 (ldb (byte 11 0) (logior b0 (ash b1 8))))
                 (t1 (ldb (byte 11 0) (logior (ash b1 -3) (ash b2 5))))
                 (t2 (ldb (byte 11 0) (logior (ash b2 -6) (ash b3 2) (ash b4 10))))
                 (t3 (ldb (byte 11 0) (logior (ash b4 -1) (ash b5 7))))
                 (t4 (ldb (byte 11 0) (logior (ash b5 -4) (ash b6 4))))
                 (t5 (ldb (byte 11 0) (logior (ash b6 -7) (ash b7 1) (ash b8 9))))
                 (t6 (ldb (byte 11 0) (logior (ash b8 -2) (ash b9 6))))
                 (t7 (ldb (byte 11 0) (logior (ash b9 -5) (ash b10 3)))))
            (setf (aref r (* 8 j)) (ash (+ (* t0 q) 1024) -11)
                  (aref r (+ (* 8 j) 1)) (ash (+ (* t1 q) 1024) -11)
                  (aref r (+ (* 8 j) 2)) (ash (+ (* t2 q) 1024) -11)
                  (aref r (+ (* 8 j) 3)) (ash (+ (* t3 q) 1024) -11)
                  (aref r (+ (* 8 j) 4)) (ash (+ (* t4 q) 1024) -11)
                  (aref r (+ (* 8 j) 5)) (ash (+ (* t5 q) 1024) -11)
                  (aref r (+ (* 8 j) 6)) (ash (+ (* t6 q) 1024) -11)
                  (aref r (+ (* 8 j) 7)) (ash (+ (* t7 q) 1024) -11)))))))
  (values))

(defun ml-kem-polyvec-compress (vec k out out-start du)
  (ecase du
    (10 (ml-kem-polyvec-compress-10 vec k out out-start))
    (11 (ml-kem-polyvec-compress-11 vec k out out-start))))

(defun ml-kem-polyvec-decompress (vec k data start du)
  (ecase du
    (10 (ml-kem-polyvec-decompress-10 vec k data start))
    (11 (ml-kem-polyvec-decompress-11 vec k data start))))

(defun ml-kem-polyvec-tobytes (vec k out out-start)
  (dotimes (vi k)
    (ml-kem-poly-tobytes (aref vec vi) out (+ out-start (* vi 384))))
  (values))

(defun ml-kem-polyvec-frombytes (vec k data start)
  (dotimes (vi k)
    (ml-kem-poly-frombytes (aref vec vi) data (+ start (* vi 384))))
  (values))

(defun ml-kem-poly-frommsg (r msg start)
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) msg)
           (type fixnum start))
  (dotimes (i 32)
    (let ((b (aref msg (+ start i))))
      (dotimes (j 8)
        (setf (aref r (+ (* 8 i) j))
              (if (logbitp j b) 1665 0)))))
  (values))

(defun ml-kem-poly-tomsg (r out out-start)
  "Exact translation of poly_tomsg, including its 32-bit wrapping
arithmetic on the (possibly negative) coefficients."
  (declare (type ml-kem-poly r)
           (type (simple-array (unsigned-byte 8) (*)) out)
           (type fixnum out-start))
  (dotimes (i 32)
    (let ((b 0))
      (dotimes (j 8)
        (let* ((s0 (logand (aref r (+ (* 8 i) j)) #xFFFFFFFF))
               (s1 (logand (ash s0 1) #xFFFFFFFF))
               (s2 (logand (+ s1 1665) #xFFFFFFFF))
               (s3 (logand (* s2 80635) #xFFFFFFFF))
               (bit (logand (ash s3 -28) 1)))
          (setf b (logior b (ash bit j)))))
      (setf (aref out (+ out-start i)) b)))
  (values))


;;;
;;; Symmetric primitives (SHAKE128 XOF, SHAKE256 PRF, SHA3-256/512)
;;;

(defun ml-kem-shake128 (input output-length)
  "SHAKE128 XOF squeeze of INPUT to OUTPUT-LENGTH octets."
  (declare (type (simple-array (unsigned-byte 8) (*)) input)
           (type fixnum output-length))
  (let ((d (make-digest :shake128 :output-length output-length)))
    (update-digest d input)
    (produce-digest d)))

(defun ml-kem-shake256 (input output-length)
  (declare (type (simple-array (unsigned-byte 8) (*)) input)
           (type fixnum output-length))
  (let ((d (make-digest :shake256 :output-length output-length)))
    (update-digest d input)
    (produce-digest d)))

(defun ml-kem-sha3-256 (input)
  (digest-sequence :sha3/256 input))

(defun ml-kem-sha3-512 (input)
  (digest-sequence :sha3 input))

(defun ml-kem-prf (seed nonce out-length)
  "SHAKE256(SEED || NONCE) squeezed to OUT-LENGTH octets."
  (declare (type (simple-array (unsigned-byte 8) (32)) seed)
           (type (unsigned-byte 8) nonce))
  (let ((input (make-array 33 :element-type '(unsigned-byte 8))))
    (replace input seed)
    (setf (aref input 32) nonce)
    (ml-kem-shake256 input out-length)))

(defun ml-kem-rkprf (key input)
  "SHAKE256(KEY || INPUT) squeezed to 32 octets."
  (ml-kem-shake256 (concatenate '(simple-array (unsigned-byte 8) (*)) key input) 32))


;;;
;;; Matrix generation and CPA operations
;;;

(defun ml-kem-sample-entry (seed x y)
  "One uniform polynomial from SEED with domain separation (X, Y)."
  (let* ((input (make-array 34 :element-type '(unsigned-byte 8)))
         (outlen 504)
         (out (progn (replace input seed)
                     (setf (aref input 32) x
                           (aref input 33) y)
                     (ml-kem-shake128 input outlen)))
         (r (ml-kem-new-poly))
         (count (ml-kem-rej-uniform r 0 out 0 outlen)))
    (loop while (< count 256)
          do (setf outlen (+ outlen 168)
                   out (progn (replace input seed)
                              (setf (aref input 32) x
                                    (aref input 33) y)
                              (ml-kem-shake128 input outlen)))
             (incf count (ml-kem-rej-uniform r count out (- outlen 168) 168)))
    r))

(defun ml-kem-gen-matrix (seed transposed k)
  "KxK matrix; entry [i][j] sampled with (x=j,y=i), or (x=i,y=j)
when TRANSPOSED, exactly like the reference gen_matrix."
  (declare (type (simple-array (unsigned-byte 8) (32)) seed)
           (type fixnum k))
  (let ((a (make-array (list k k))))
    (dotimes (i k)
      (dotimes (j k)
        (setf (aref a i j)
              (if transposed
                  (ml-kem-sample-entry seed i j)
                  (ml-kem-sample-entry seed j i)))))
    a))

(defun ml-kem-matrix-row (a i k)
  (let ((row (make-array k)))
    (dotimes (j k row)
      (setf (aref row j) (aref a i j)))))

(defun ml-kem-noise-poly (seed nonce eta)
  "ETA = 2/3 noise polynomial from a PRF buffer of ETA*64 octets."
  (let ((buf (ml-kem-prf seed nonce (* eta 64)))
        (r (ml-kem-new-poly)))
    (ecase eta
      (2 (ml-kem-cbd2 r buf 0))
      (3 (ml-kem-cbd3 r buf 0)))
    r))


;;; CPA key generation, encryption, decryption (deterministic cores)
;;;

(defun ml-kem-polyvec-ntt (vec k)
  (dotimes (vi k)
    (ml-kem-ntt (aref vec vi)))
  (values))

(defun ml-kem-polyvec-invntt-tomont (vec k)
  (dotimes (vi k)
    (ml-kem-invntt-tomont (aref vec vi)))
  (values))

(defun ml-kem-polyvec-add (r a b k)
  (dotimes (vi k)
    (ml-kem-poly-add (aref r vi) (aref a vi) (aref b vi)))
  (values))

(defun ml-kem-polyvec-reduce (vec k)
  (dotimes (vi k)
    (ml-kem-poly-reduce (aref vec vi)))
  (values))

(defun ml-kem-indcpa-keypair (coins64 publicseed-out kp)
  "From 64 COINS fills PUBLICSEED-OUT (32B) and returns (pk sk-indcpa)."
  (let* ((kk (ml-kem-params-k kp))
         (ginput (let ((b (make-array 33 :element-type '(unsigned-byte 8))))
                   (replace b coins64 :end2 32)
                   (setf (aref b 32) kk)
                   b))
         (gout (ml-kem-sha3-512 ginput))
         (publicseed (subseq gout 0 32))
         (noiseseed (subseq gout 32 64))
         (a (ml-kem-gen-matrix publicseed nil kk))
         (skpv (ml-kem-new-polyvec kk))
         (e (ml-kem-new-polyvec kk))
         (pkpv (ml-kem-new-polyvec kk))
         (eta1 (ml-kem-params-eta1 kp)))
    (replace publicseed-out publicseed)
    (dotimes (i kk)
      (setf (aref skpv i) (ml-kem-noise-poly noiseseed i eta1))
      (setf (aref e i) (ml-kem-noise-poly noiseseed (+ i kk) eta1)))
    (ml-kem-polyvec-ntt skpv kk)
    (ml-kem-polyvec-ntt e kk)
    (dotimes (i kk)
      (ml-kem-basemul-acc (aref pkpv i) (ml-kem-matrix-row a i kk) skpv kk)
      (ml-kem-tomont (aref pkpv i)))
    (ml-kem-polyvec-add pkpv pkpv e kk)
    (ml-kem-polyvec-reduce pkpv kk)
    (let ((pk-enc (make-array (* 384 kk) :element-type '(unsigned-byte 8)))
          (sk-enc (make-array (* 384 kk) :element-type '(unsigned-byte 8))))
      (ml-kem-polyvec-tobytes pkpv kk pk-enc 0)
      (ml-kem-polyvec-tobytes skpv kk sk-enc 0)
      (values pk-enc sk-enc))))

(defun ml-kem-indcpa-encrypt (message pk coins32 kp)
  "From 32-byte MESSAGE, public key PK and 32-byte COINS returns ct."
  (let* ((kk (ml-kem-params-k kp))
         (du (ml-kem-params-du kp))
         (dv (ml-kem-params-dv kp))
         (eta1 (ml-kem-params-eta1 kp))
         (eta2 (ml-kem-params-eta2 kp))
         (pkpv (ml-kem-new-polyvec kk))
         (seed (make-array 32 :element-type '(unsigned-byte 8)))
         (sp (ml-kem-new-polyvec kk))
         (ep (ml-kem-new-polyvec kk))
         (epp (ml-kem-new-poly))
         (b (ml-kem-new-polyvec kk))
         (v (ml-kem-new-poly))
         (kpoly (ml-kem-new-poly))
         at)
    (ml-kem-polyvec-frombytes pkpv kk pk 0)
    (replace seed pk :start2 (* 384 kk))
    (setf at (ml-kem-gen-matrix seed t kk))
    (ml-kem-poly-frommsg kpoly message 0)
    (dotimes (i kk)
      (setf (aref sp i) (ml-kem-noise-poly coins32 i eta1))
      (setf (aref ep i) (ml-kem-noise-poly coins32 (+ i kk) eta2)))
    (setf epp (ml-kem-noise-poly coins32 (* 2 kk) eta2))
    (ml-kem-polyvec-ntt sp kk)
    (dotimes (i kk)
      (ml-kem-basemul-acc (aref b i) (ml-kem-matrix-row at i kk) sp kk))
    (ml-kem-basemul-acc v pkpv sp kk)
    (ml-kem-polyvec-invntt-tomont b kk)
    (ml-kem-invntt-tomont v)
    (ml-kem-polyvec-add b b ep kk)
    (ml-kem-poly-add v v epp)
    (ml-kem-poly-add v v kpoly)
    (ml-kem-polyvec-reduce b kk)
    (ml-kem-poly-reduce v)
    (let ((ct (make-array (* 32 (+ (* du kk) dv)) :element-type '(unsigned-byte 8))))
      (ml-kem-polyvec-compress b kk ct 0 du)
      (ml-kem-poly-compress v ct (* du kk 32) dv)
      ct)))

(defun ml-kem-indcpa-decrypt (ct sk kp)
  "From ciphertext CT and IND-CPA secret key SK returns the 32-byte message."
  (let* ((kk (ml-kem-params-k kp))
         (du (ml-kem-params-du kp))
         (dv (ml-kem-params-dv kp))
         (b (ml-kem-new-polyvec kk))
         (v (ml-kem-new-poly))
         (skpv (ml-kem-new-polyvec kk))
         (mp (ml-kem-new-poly))
         (m (make-array 32 :element-type '(unsigned-byte 8))))
    (ml-kem-polyvec-decompress b kk ct 0 du)
    (ml-kem-poly-decompress v ct (* du kk 32) dv)
    (ml-kem-polyvec-frombytes skpv kk sk 0)
    (ml-kem-polyvec-ntt b kk)
    (ml-kem-basemul-acc mp skpv b kk)
    (ml-kem-invntt-tomont mp)
    (ml-kem-poly-sub mp v mp)
    (ml-kem-poly-reduce mp)
    (ml-kem-poly-tomsg mp m 0)
    m))


;;;
;;; KEM: key generation, encapsulation, decapsulation
;;;

(defun ml-kem-keypair-from-coins (coins64 kp)
  "Deterministic keypair from 64 coins; returns (pk sk)."
  (let* ((kk (ml-kem-params-k kp))
         (pklen (ml-kem-params-pkbytes kp))
         (sklen (ml-kem-params-skbytes kp))
         (polyvecbytes (* 384 kk))
         (publicseed (make-array 32 :element-type '(unsigned-byte 8))))
    (multiple-value-bind (pk-indcpa sk-indcpa)
        (ml-kem-indcpa-keypair coins64 publicseed kp)
      (let ((pk (make-array pklen :element-type '(unsigned-byte 8)))
            (sk (make-array sklen :element-type '(unsigned-byte 8)))
            (pk-end (+ polyvecbytes pklen)))
        (replace pk pk-indcpa :end2 polyvecbytes)
        (replace pk publicseed :start1 polyvecbytes)
        (replace sk sk-indcpa :end2 polyvecbytes)
        (replace sk pk :start1 polyvecbytes :end1 pk-end)
        (replace sk (ml-kem-sha3-256 pk) :start1 pk-end :end1 (+ pk-end 32))
        (replace sk coins64 :start1 (+ pk-end 32) :start2 32 :end2 64)
        (values pk sk)))))

(defun ml-kem-encaps-from-message (message pk kp)
  "Deterministic encapsulation of 32-byte MESSAGE under PK;
returns (ct ss-32)."
  (let* ((hpk (ml-kem-sha3-256 pk))
         (buf (concatenate '(simple-array (unsigned-byte 8) (*)) message hpk))
         (kr (ml-kem-sha3-512 buf))
         (ct (ml-kem-indcpa-encrypt message pk (subseq kr 32 64) kp)))
    (values ct (subseq kr 0 32))))

(defun ml-kem-decapsulate (ct sk kp)
  "Decapsulation with implicit rejection; returns 32-byte secret."
  (let* ((kk (ml-kem-params-k kp))
         (polyvecbytes (* 384 kk))
         (pk-end (+ polyvecbytes (ml-kem-params-pkbytes kp)))
         (m (ml-kem-indcpa-decrypt ct (subseq sk 0 polyvecbytes) kp))
         (pk (subseq sk polyvecbytes pk-end))
         (hpk (subseq sk pk-end (+ pk-end 32)))
         (z (subseq sk (+ pk-end 32) (+ pk-end 64)))
         (buf (concatenate '(simple-array (unsigned-byte 8) (*)) m hpk))
         (kr (ml-kem-sha3-512 buf))
         (ct2 (ml-kem-indcpa-encrypt m pk (subseq kr 32 64) kp))
         (fail (not (equalp ct ct2)))
         (ss-reject (ml-kem-rkprf z ct)))
    (if fail ss-reject (subseq kr 0 32))))


;;;
;;; Public API: key classes, generation, encapsulation
;;;

(defclass ml-kem-key ()
  ((kind :initarg :kind :reader ml-kem-key-kind)
   (bytes :initarg :bytes :reader ml-kem-key-bytes)))

(defclass ml-kem-public-key (ml-kem-key)
  ())

(defclass ml-kem-private-key (ml-kem-key)
  ())

(defclass ml-kem-512-public-key (ml-kem-public-key)
  ())

(defclass ml-kem-512-private-key (ml-kem-private-key)
  ())

(defclass ml-kem-768-public-key (ml-kem-public-key)
  ())

(defclass ml-kem-768-private-key (ml-kem-private-key)
  ())

(defclass ml-kem-1024-public-key (ml-kem-public-key)
  ())

(defclass ml-kem-1024-private-key (ml-kem-private-key)
  ())

(defun ml-kem-check-bytes (bytes length kind)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) length))
    (error 'missing-key-parameter
           :kind kind
           :parameter 'bytes
           :description "ML-KEM key bytes"))
  (copy-seq bytes))

(defmacro ml-kem-define-key-constructors (kind public-class private-class)
  (let ((pklen (ml-kem-params-pkbytes (ml-kem-params-for-kind kind)))
        (sklen (ml-kem-params-skbytes (ml-kem-params-for-kind kind))))
    `(progn
       (defmethod make-public-key ((kind (eql ,kind)) &key bytes &allow-other-keys)
         (make-instance ',public-class :kind ,kind
                        :bytes (ml-kem-check-bytes bytes ,pklen ,kind)))
       (defmethod make-private-key ((kind (eql ,kind)) &key bytes &allow-other-keys)
         (make-instance ',private-class :kind ,kind
                        :bytes (ml-kem-check-bytes bytes ,sklen ,kind)))
       (defmethod generate-key-pair ((kind (eql ,kind)) &key &allow-other-keys)
         (multiple-value-bind (pk sk)
             (ml-kem-keypair-from-coins (random-data 64)
                                        (ml-kem-params-for-kind ,kind))
           (values (make-private-key ,kind :bytes sk)
                   (make-public-key ,kind :bytes pk)))))))

(ml-kem-define-key-constructors :ml-kem-512 ml-kem-512-public-key ml-kem-512-private-key)
(ml-kem-define-key-constructors :ml-kem-768 ml-kem-768-public-key ml-kem-768-private-key)
(ml-kem-define-key-constructors :ml-kem-1024 ml-kem-1024-public-key ml-kem-1024-private-key)

(defmethod destructure-public-key ((public-key ml-kem-public-key))
  (list :bytes (copy-seq (ml-kem-key-bytes public-key))))

(defmethod destructure-private-key ((private-key ml-kem-private-key))
  (list :bytes (copy-seq (ml-kem-key-bytes private-key))))

(defmethod encapsulate-key ((public-key ml-kem-public-key))
  (ml-kem-encaps-from-message (random-data 32)
                              (ml-kem-key-bytes public-key)
                              (ml-kem-params-for-kind (ml-kem-key-kind public-key))))

(defmethod decapsulate-key ((private-key ml-kem-private-key) ciphertext)
  (let* ((kp (ml-kem-params-for-kind (ml-kem-key-kind private-key)))
         (ctlen (ml-kem-params-ctbytes kp)))
    (unless (and (typep ciphertext '(simple-array (unsigned-byte 8) (*)))
                 (= (length ciphertext) ctlen))
      (error 'invalid-message-length :kind (ml-kem-key-kind private-key)))
    (ml-kem-decapsulate ciphertext (ml-kem-key-bytes private-key) kp)))
