;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; falcon.lisp -- Falcon signatures (FIPS 206, Falcon-512/1024)
;;;;
;;;; Direct translation of the falcon.py reference: NTT arithmetic mod
;;;; 12289, SHAKE256 hash-to-point, compression codec, FFT sampling.
;;;; Staged: verify first, then sign, then keygen.

(in-package :crypto-unsafe)


;;;
;;; Parameters
;;;

(defconstant +falcon-q+ 12289)
(defconstant +falcon-head-len+ 1)
(defconstant +falcon-salt-len+ 40)

(defstruct falcon-params
  kind n logn sigma sigmin sig-bound sig-bytelen vk-bytes)

(defparameter +falcon-512-params+
  (make-falcon-params :kind :falcon-512 :n 512 :logn 9
                      :sigma 165.7366171829776d0
                      :sigmin 1.2778336969128337d0
                      :sig-bound 34034726 :sig-bytelen 666
                      :vk-bytes 897))

(defparameter +falcon-1024-params+
  (make-falcon-params :kind :falcon-1024 :n 1024 :logn 10
                      :sigma 168.38857144654395d0
                      :sigmin 1.298280334344292d0
                      :sig-bound 70265242 :sig-bytelen 1280
                      :vk-bytes 1793))

(defvar *falcon-params* nil)

(defun falcon-params-for-kind (kind)
  (ecase kind
    (:falcon-512 +falcon-512-params+)
    (:falcon-1024 +falcon-1024-params+)))

(declaim (inline falcon-n falcon-q))
(defun falcon-n () (falcon-params-n *falcon-params*))
(defun falcon-q () +falcon-q+)


;;;
;;; Polynomial helpers. Polys are simple-vectors of fixnums (coefficients).
;;;

(defun falcon-ntt-roots (n)
  (ecase n
    (2 +falcon-ntt-roots-2+)
    (4 +falcon-ntt-roots-4+)
    (8 +falcon-ntt-roots-8+)
    (16 +falcon-ntt-roots-16+)
    (32 +falcon-ntt-roots-32+)
    (64 +falcon-ntt-roots-64+)
    (128 +falcon-ntt-roots-128+)
    (256 +falcon-ntt-roots-256+)
    (512 +falcon-ntt-roots-512+)
    (1024 +falcon-ntt-roots-1024+)))

(defconstant +falcon-ntt-i2+ 6145)
(defconstant +falcon-ntt-sqr1+ 1479)

(declaim (inline falcon-addmod falcon-submod falcon-mulmod))

(defun falcon-addmod (a b)
  "The sum of A and B modulo the falcon prime.
A and B are reduced residues, so the sum needs one subtraction."
  (declare (type (integer 0 12288) a b))
  (let ((s (+ a b)))
    (if (>= s +falcon-q+) (- s +falcon-q+) s)))

(defun falcon-submod (a b)
  "The difference of A and B modulo the falcon prime.
A and B are reduced residues, so the difference needs one addition."
  (declare (type (integer 0 12288) a b))
  (let ((d (- a b)))
    (if (< d 0) (+ d +falcon-q+) d)))

(defconstant +falcon-mu+ 1431539266
  "The reciprocal of the prime, for the reduction of a product.
The product of two residues is below 2^28, and this is 2^44
divided by the prime, so the quotient that the reciprocal gives is
never more than one below the true quotient, and one subtraction of
the prime at most brings the remainder back.")

(defun falcon-mulmod (a b)
  "The product of A and B modulo the falcon prime.
The product of two reduced residues is below 2^28, so it is reduced
by a multiplication by the reciprocal of the prime and a shift, and
one subtraction at most: the quotient that the reciprocal gives is
never more than one below the true quotient, so the remainder is
below twice the prime."
  ;; The bounds let the compiler prove both products stay fixnums; with
  ;; plain FIXNUM declarations it emits overflow-checked (boxing) code,
  ;; and the three multiplies here are the whole cost of the NTT.
  (declare (type (integer 0 12288) a b))
  (let* ((p (* a b))
         (qh (ash (* p +falcon-mu+) -44))
         (r (- p (* qh +falcon-q+))))
    (if (>= r +falcon-q+) (- r +falcon-q+) r)))

(defun falcon-make-twiddles (n)
  "The twiddles of the merge of a transform of size N.
The merge multiplies the element I by the entry 2I of the roots
table, so the table of the twiddles is the even-indexed entries of
the roots table, in order."
  (let ((w (falcon-ntt-roots n))
        (tw (make-array (ash n -1) :element-type 'fixnum
                          :initial-element 0)))
    (dotimes (i (ash n -1) tw)
      (setf (aref tw i) (aref w (* 2 i))))))

(defvar +falcon-ntt-twiddles+
  (let ((v (make-array 10)))
    (dotimes (i 10 v)
      (setf (aref v i) (falcon-make-twiddles (ash 1 (1+ i))))))
  "The twiddles of the merges, by the size of the transform.
The entry for the size 2^k is at the index k-1.")

(defun falcon-ntt-twiddles (n)
  "The twiddles of the merge of a transform of size N."
  (aref +falcon-ntt-twiddles+ (- (integer-length n) 2)))

;;; Iterative negacyclic NTT.
;;;
;;; The transform is the standard one for arithmetic in Z_q[x]/(x^n + 1):
;;; twist the coefficients by the powers of a primitive 2n-th root of
;;; unity PSI, run an ordinary cyclic NTT of size n with OMEGA = PSI^2,
;;; and untwist on the way back.  The earlier implementation was a
;;; recursive split-and-merge transform; it was correct but copied the
;;; whole polynomial twice per level and allocated a buffer pool on every
;;; call.  The iterative form does one in-place pass over a bit-reversed
;;; array and reuses precomputed stage twiddles.

(defun falcon-powmod (b e)
  "B^E modulo the Falcon prime, for a reduced B."
  (declare (type fixnum b e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r 1) (b (mod b +falcon-q+)))
    (loop while (plusp e) do
      (when (oddp e) (setf r (falcon-mulmod r b)))
      (setf b (falcon-mulmod b b) e (ash e -1)))
    r))

(defun falcon-ntt-primitive-root ()
  "The smallest primitive root modulo the Falcon prime."
  (let ((q-1 (1- +falcon-q+)))
    (loop for g of-type fixnum from 2 do
      (when (and (= (falcon-powmod g (ash q-1 -1)) (1- +falcon-q+))
                 (/= (falcon-powmod g (floor q-1 3)) 1))
        (return g)))))

(defvar *falcon-ntt-primitive-root* (falcon-ntt-primitive-root))

(defstruct falcon-ntt-plan
  brev twist untwist stages istages ninv)

(defvar *falcon-ntt-plans* nil
  "Alist of N -> falcon-ntt-plan, built on first use.")

(defun falcon-ntt-plan-for (n)
  "The transform plan for size N (a power of two)."
  (declare (type fixnum n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (or (cdr (assoc n *falcon-ntt-plans*))
      (let* ((logn (1- (integer-length n)))
             (g *falcon-ntt-primitive-root*)
             (q-1 (1- +falcon-q+))
             (psi (falcon-powmod g (floor q-1 (* 2 n))))
             (psi-inv (falcon-powmod psi (1- (* 2 n))))
             (omega (falcon-mulmod psi psi))
             (omega-inv (falcon-powmod omega (1- n)))
             (ninv (falcon-powmod n (- +falcon-q+ 2)))
             (brev (make-array n :element-type 'fixnum))
             (twist (make-array n :element-type 'fixnum))
             (untwist (make-array n :element-type 'fixnum))
             (stages (make-array logn))
             (istages (make-array logn)))
        (declare (type fixnum logn g psi psi-inv omega omega-inv ninv)
                 (type (simple-array fixnum (*)) brev twist untwist)
                 (type simple-vector stages istages))
        ;; Bit-reversal permutation, LOGlogn bits per index.
        (dotimes (i n)
          (let ((r 0) (x i))
            (declare (type fixnum r x))
            (loop repeat logn do
              (setf r (+ (* r 2) (logand x 1))
                    x (ash x -1)))
            (setf (aref brev i) r)))
        ;; Twist factors PSI^i and PSI^-i.
        (let ((w 1) (wi 1))
          (dotimes (i n)
            (setf (aref twist i) w
                  (aref untwist i) wi)
            (setf w (falcon-mulmod w psi)
                  wi (falcon-mulmod wi psi-inv))))
        ;; Stage twiddles: OMEGA^(n/len * j) for the forward pass and the
        ;; same with OMEGA^-1 for the inverse.
        (loop for level of-type fixnum from 1 to logn do
          (let* ((len (ash 1 level))
                 (half (ash len -1))
                 (wlen (falcon-powmod omega (ash n (- level))))
                 (iwlen (falcon-powmod omega-inv (ash n (- level))))
                 (ws (make-array half :element-type 'fixnum))
                 (iws (make-array half :element-type 'fixnum)))
            (declare (type fixnum len half wlen iwlen)
                     (type (simple-array fixnum (*)) ws iws))
            (let ((w 1) (iw 1))
              (dotimes (j half)
                (setf (aref ws j) w
                      (aref iws j) iw)
                (setf w (falcon-mulmod w wlen)
                      iw (falcon-mulmod iw iwlen))))
            (setf (aref stages (1- level)) ws
                  (aref istages (1- level)) iws)))
        (let ((plan (make-falcon-ntt-plan :brev brev :twist twist
                                           :untwist untwist
                                           :stages stages :istages istages
                                           :ninv ninv)))
          (push (cons n plan) *falcon-ntt-plans*)
          plan))))

(defun falcon-ntt (f)
  "Forward negacyclic NTT: coefficients -> NTT domain."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length f))
         (plan (falcon-ntt-plan-for n))
         (a (make-array n :element-type 'fixnum))
         (brev (falcon-ntt-plan-brev plan))
         (twist (falcon-ntt-plan-twist plan))
         (stages (falcon-ntt-plan-stages plan)))
    (declare (type fixnum n)
             (type (simple-array fixnum (*)) a brev twist)
             (type simple-vector stages))
    (dotimes (i n)
      (setf (aref a i)
            (falcon-mulmod (mod (aref f i) +falcon-q+) (aref twist i))))
    (dotimes (i n)
      (let ((j (aref brev i)))
        (when (< i j)
          (let ((tmp (aref a i)))
            (setf (aref a i) (aref a j)
                  (aref a j) tmp)))))
    (loop for len of-type fixnum = 2 then (ash len 1)
          while (<= len n)
          do (let* ((half (ash len -1))
                    (ws (aref stages (- (integer-length len) 2))))
               (declare (type fixnum half)
                        (type (simple-array fixnum (*)) ws))
               (loop for start of-type fixnum from 0 below n by len
                     do (dotimes (j half)
                          (let* ((u (aref a (+ start j)))
                                 (v (falcon-mulmod
                                     (aref a (+ start j half))
                                     (aref ws j))))
                            (setf (aref a (+ start j)) (falcon-addmod u v)
                                  (aref a (+ start j half)) (falcon-submod u v)))))))
    a))

(defun falcon-intt (f-ntt)
  "Inverse negacyclic NTT: NTT domain -> coefficients."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length f-ntt))
         (plan (falcon-ntt-plan-for n))
         (a (make-array n :element-type 'fixnum))
         (brev (falcon-ntt-plan-brev plan))
         (untwist (falcon-ntt-plan-untwist plan))
         (istages (falcon-ntt-plan-istages plan))
         (ninv (falcon-ntt-plan-ninv plan)))
    (declare (type fixnum n ninv)
             (type (simple-array fixnum (*)) a brev untwist)
             (type simple-vector istages))
    (dotimes (i n) (setf (aref a i) (aref f-ntt i)))
    (dotimes (i n)
      (let ((j (aref brev i)))
        (when (< i j)
          (let ((tmp (aref a i)))
            (setf (aref a i) (aref a j)
                  (aref a j) tmp)))))
    (loop for len of-type fixnum = 2 then (ash len 1)
          while (<= len n)
          do (let* ((half (ash len -1))
                    (ws (aref istages (- (integer-length len) 2))))
               (declare (type fixnum half)
                        (type (simple-array fixnum (*)) ws))
               (loop for start of-type fixnum from 0 below n by len
                     do (dotimes (j half)
                          (let* ((u (aref a (+ start j)))
                                 (v (falcon-mulmod
                                     (aref a (+ start j half))
                                     (aref ws j))))
                            (setf (aref a (+ start j)) (falcon-addmod u v)
                                  (aref a (+ start j half)) (falcon-submod u v)))))))
    ;; Scale by N^-1 and untwist by PSI^-j.
    (dotimes (i n)
      (setf (aref a i)
            (falcon-mulmod (falcon-mulmod (aref a i) ninv)
                           (aref untwist i))))
    a))

(defun falcon-mul-ntt (a b)
  (declare (type (simple-array fixnum (*)) a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a))
         (r (make-array n :element-type 'fixnum)))
    (declare (type fixnum n)
             (type (simple-array fixnum (*)) r))
    (dotimes (i n r)
      (setf (aref r i) (falcon-mulmod (aref a i) (aref b i))))))

(defun falcon-mul-zq-ntt (f g-ntt)
  "Multiply F by G, whose transform is already made."
  (falcon-intt (falcon-mul-ntt (falcon-ntt f) g-ntt)))

(defun falcon-mul-zq (f g)
  "Multiply polys mod (x^n+1, q) via NTT."
  (falcon-intt (falcon-mul-ntt (falcon-ntt f) (falcon-ntt g))))

(defun falcon-sub-zq (f g)
  (declare (type (simple-array fixnum (*)) f g)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length f))
         (r (make-array n :element-type 'fixnum)))
    (declare (type fixnum n)
             (type (simple-array fixnum (*)) r))
    (dotimes (i n r)
      (setf (aref r i) (falcon-submod (aref f i) (aref g i))))))

(defun falcon-serialize (poly)
  "14-bit LE-group packing written as a big-endian byte string."
  (let ((buf 0))
    (dotimes (i (length poly))
      (setf buf (logior buf (ash (aref poly i) (* 14 i)))))
    (let* ((nbytes (ceiling (* (length poly) 14) 8))
           (out (make-array nbytes :element-type '(unsigned-byte 8)
                                   :initial-element 0)))
      (dotimes (i nbytes out)
        (setf (aref out (- nbytes 1 i)) (ldb (byte 8 (* 8 i)) buf))))))

(defun falcon-deserialize (bytes n)
  "Inverse of falcon-serialize: big-endian bytes, 14-bit LE groups."
  (let ((buf 0)
        (poly (make-array n :element-type 'fixnum :initial-element 0)))
    (dotimes (i (length bytes))
      (setf buf (+ (ash buf 8) (aref bytes i))))
    (dotimes (i n poly)
      (setf (aref poly i) (ldb (byte 14 (* 14 i)) buf)))))


;;;
;;; Hash-to-point: SHAKE256(salt || m), 16-bit BE rejection to mod q.
;;;

(defun falcon-hash-to-point (msg salt n)
  (let* ((k (ash 1 16))
         (kq (* (floor k +falcon-q+) +falcon-q+))
         ;; Squeeze generously; XOF prefix property keeps values identical.
         (need-bytes (* 6 n))
         (d (make-digest :shake256 :output-length need-bytes))
         (out (make-array n :element-type 'fixnum :initial-element 0)))
    (update-digest d salt)
    (update-digest d msg)
    (let ((buf (produce-digest d)))
      (loop with i = 0 and pos = 0
            while (< i n)
            do (let ((elt (+ (ash (aref buf pos) 8) (aref buf (+ pos 1)))))
                 (incf pos 2)
                 (when (< elt kq)
                   (setf (aref out i) (mod elt +falcon-q+))
                   (incf i)))
            finally (return out)))))


;;;
;;; Compression codec (decompress only for verify).
;;;

(defun falcon-decompress (enc slen n)
  "Decode ENC (<= slen bytes) into an n-coefficient poly, or NIL if invalid."
  (declare (type (simple-array (unsigned-byte 8) (*)) enc)
           (type fixnum slen n))
  (when (> (length enc) slen)
    (return-from falcon-decompress nil))
  ;; Work directly on the bytes with a bit index instead of expanding the
  ;; whole encoding into a bit vector.  A coefficient is one sign bit,
  ;; seven low bits, then the unary-coded high part: as many zero bits as
  ;; the high value, followed by a one.
  (let ((nbytes (length enc)))
    (declare (type fixnum nbytes))
    ;; Skip trailing zero bytes, then the trailing zero bits of the last
    ;; byte that is not zero; the decoder must not read past that point.
    (loop while (and (plusp nbytes) (zerop (aref enc (1- nbytes))))
          do (decf nbytes))
    (when (zerop nbytes)
      (return-from falcon-decompress nil))
    (let* ((last (aref enc (1- nbytes)))
           ;; The decoder must stop just after the last one bit, which is
           ;; the lowest set bit of the last nonzero byte.
           (tz (1- (integer-length (logand last (- last)))))
           (len (- (* 8 nbytes) tz))
           (v (make-array n :element-type 'fixnum :initial-element 0))
           (nv 0)
           (pos 0)
           (start 0))
      (declare (type fixnum len nv pos start)
               (type (simple-array fixnum (*)) v))
      (labels ((bit-at (i)
                 (ldb (byte 1 (- 7 (logand i 7))) (aref enc (ash i -3))))
               ;; The seven bits that follow START, as an integer.
               (low7 ()
                 (let* ((p (1+ start))
                        (idx (ash p -3))
                        (off (logand p 7))
                        (b0 (aref enc idx))
                        (b1 (if (< (1+ idx) nbytes) (aref enc (1+ idx)) 0)))
                   (declare (type fixnum idx off))
                   (ldb (byte 7 (- 9 off)) (logior (ash b0 8) b1)))))
        (loop while (and (< pos len) (< nv n))
              do (setf start pos)
                 (when (> (+ start 8) len)
                   (return-from falcon-decompress nil))
                 (let ((sign (if (= (bit-at start) 1) -1 1))
                       (i (+ start 8)))
                   (declare (type fixnum sign i))
                   (setf pos (1+ start))
                   (let ((low (low7)))
                     (declare (type fixnum low))
                     (loop while (and (< i len) (zerop (bit-at i)))
                           do (incf i))
                     (when (>= i len)
                       (return-from falcon-decompress nil))
                     (let* ((high (- i (+ start 8)))
                            (coef (* sign (+ low (ash high 7)))))
                       (declare (type fixnum high coef))
                       (when (and (zerop coef) (minusp sign))
                         (return-from falcon-decompress nil))
                       (setf (aref v nv) coef)
                       (incf nv)
                       (setf pos (1+ i))))))
        (if (= nv n) v nil)))))


;;;
;;; Verify
;;;

(defun falcon-verify (msg sig pk &optional (params +falcon-512-params+) pk-ntt)
  "Verify SIG over MSG under PK (FIPS 206 wire format); returns T/nil."
  (let ((*falcon-params* params))
    (let* ((n (falcon-n))
           (logn (falcon-params-logn params))
           (sig-bytelen (falcon-params-sig-bytelen params))
           (bound (falcon-params-sig-bound params)))
      (unless (and (= (length pk) (falcon-params-vk-bytes params))
                   (= (aref pk 0) logn))
        (return-from falcon-verify nil))
      (unless (and (= (length sig) sig-bytelen)
                   (= (aref sig 0) (+ #x30 logn)))
        (return-from falcon-verify nil))
      (let* ((h (or pk-ntt
                  (falcon-ntt (falcon-deserialize (subseq pk 1) n))))
             (salt (subseq sig +falcon-head-len+
                           (+ +falcon-head-len+ +falcon-salt-len+)))
             (enc (subseq sig (+ +falcon-head-len+ +falcon-salt-len+)))
             (s1 (falcon-decompress enc (- sig-bytelen +falcon-head-len+
                                           +falcon-salt-len+) n)))
        (when (null s1)
          (return-from falcon-verify nil))
        (let* ((c (falcon-hash-to-point msg salt n))
               (s0raw (falcon-sub-zq c (falcon-mul-zq-ntt s1 h)))
               (half (ash +falcon-q+ -1))
               (norm 0))
          (dotimes (i n)
            (let ((s0i (- (mod (+ (aref s0raw i) half) +falcon-q+) half)))
              (incf norm (* s0i s0i))))
          (dotimes (i n)
            (incf norm (* (aref s1 i) (aref s1 i))))
          (<= norm bound))))))


;;;
;;; Public API (verify first; keygen/sign follow in later steps).
;;;

(defclass falcon-512-public-key ()
  ((bytes :initarg :bytes :reader falcon-key-bytes
          :type (simple-array (unsigned-byte 8) (*)))
   (h :initform nil :accessor falcon-512-key-h
       :documentation "The transform of the public key, made once."))
  (:documentation "897-byte Falcon-512 public key."))

(defclass falcon-1024-public-key ()
  ((bytes :initarg :bytes :reader falcon-key-bytes
          :type (simple-array (unsigned-byte 8) (*)))
   (h :initform nil :accessor falcon-1024-key-h
       :documentation "The transform of the public key, made once."))
  (:documentation "1793-byte Falcon-1024 public key."))

(defmethod make-public-key ((kind (eql :falcon-512))
                            &key bytes &allow-other-keys)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) 897))
    (error 'missing-key-parameter
           :kind :falcon-512 :parameter 'bytes
           :description "Falcon-512 public key bytes"))
  (make-instance 'falcon-512-public-key :bytes (copy-seq bytes)))

(defmethod make-public-key ((kind (eql :falcon-1024))
                            &key bytes &allow-other-keys)
  (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
               (= (length bytes) 1793))
    (error 'missing-key-parameter
           :kind :falcon-1024 :parameter 'bytes
           :description "Falcon-1024 public key bytes"))
  (make-instance 'falcon-1024-public-key :bytes (copy-seq bytes)))

(defmethod destructure-public-key ((key falcon-512-public-key))
  (list :bytes (copy-seq (falcon-key-bytes key))))

(defmethod destructure-public-key ((key falcon-1024-public-key))
  (list :bytes (copy-seq (falcon-key-bytes key))))

(defmethod verify-signature ((key falcon-512-public-key) message signature
                             &key (start 0) end &allow-other-keys)
  (falcon-verify (subseq message start (or end (length message)))
                 signature (falcon-key-bytes key)
                 +falcon-512-params+
                 (or (falcon-512-key-h key)
                     (setf (falcon-512-key-h key)
                           (falcon-ntt (falcon-deserialize
                                        (subseq (falcon-key-bytes key) 1) 512))))))

(defmethod verify-signature ((key falcon-1024-public-key) message signature
                             &key (start 0) end &allow-other-keys)
  (falcon-verify (subseq message start (or end (length message)))
                 signature (falcon-key-bytes key)
                 +falcon-1024-params+
                 (or (falcon-1024-key-h key)
                     (setf (falcon-1024-key-h key)
                           (falcon-ntt (falcon-deserialize
                                        (subseq (falcon-key-bytes key) 1) 1024))))))


;;;
;;; FFT over complex doubles (signing path).
;;;

(defun falcon-specialize-croots (v)
  "Copy the complex roots V into a specialized array."
  (let ((r (make-array (length v) :element-type '(complex double-float))))
    (dotimes (i (length v) r)
      (setf (aref r i) (aref v i)))))

(defvar +falcon-fft-croots-2+ (falcon-specialize-croots +falcon-fft-roots-2+))
(defvar +falcon-fft-croots-4+ (falcon-specialize-croots +falcon-fft-roots-4+))
(defvar +falcon-fft-croots-8+ (falcon-specialize-croots +falcon-fft-roots-8+))
(defvar +falcon-fft-croots-16+ (falcon-specialize-croots +falcon-fft-roots-16+))
(defvar +falcon-fft-croots-32+ (falcon-specialize-croots +falcon-fft-roots-32+))
(defvar +falcon-fft-croots-64+ (falcon-specialize-croots +falcon-fft-roots-64+))
(defvar +falcon-fft-croots-128+ (falcon-specialize-croots +falcon-fft-roots-128+))
(defvar +falcon-fft-croots-256+ (falcon-specialize-croots +falcon-fft-roots-256+))
(defvar +falcon-fft-croots-512+ (falcon-specialize-croots +falcon-fft-roots-512+))
(defvar +falcon-fft-croots-1024+ (falcon-specialize-croots +falcon-fft-roots-1024+))

(declaim (ftype (function (fixnum)
                          (simple-array (complex double-float) (*)))
               falcon-fft-croots))
(defun falcon-fft-croots (n)
  (ecase n
    (2 +falcon-fft-croots-2+)
    (4 +falcon-fft-croots-4+)
    (8 +falcon-fft-croots-8+)
    (16 +falcon-fft-croots-16+)
    (32 +falcon-fft-croots-32+)
    (64 +falcon-fft-croots-64+)
    (128 +falcon-fft-croots-128+)
    (256 +falcon-fft-croots-256+)
    (512 +falcon-fft-croots-512+)
    (1024 +falcon-fft-croots-1024+)))

(defun falcon-fft-roots (n)
  (ecase n
    (2 +falcon-fft-roots-2+)
    (4 +falcon-fft-roots-4+)
    (8 +falcon-fft-roots-8+)
    (16 +falcon-fft-roots-16+)
    (32 +falcon-fft-roots-32+)
    (64 +falcon-fft-roots-64+)
    (128 +falcon-fft-roots-128+)
    (256 +falcon-fft-roots-256+)
    (512 +falcon-fft-roots-512+)
    (1024 +falcon-fft-roots-1024+)))

(deftype falcon-cvec () '(simple-array (complex double-float) (*)))
(deftype falcon-dvec () '(simple-array double-float (*)))

(defun falcon-cvec (n &optional (init #C(0d0 0d0)))
  (make-array n :element-type '(complex double-float) :initial-element init))

(defun falcon-dvec (n)
  (make-array n :element-type 'double-float :initial-element 0d0))

(defun falcon-double-vec (v)
  "V as a specialized double-float vector."
  (declare (type (simple-array * (*)) v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length v))
         (r (falcon-dvec n)))
    (declare (type falcon-dvec r))
    (dotimes (i n r)
      (setf (aref r i) (float (aref v i) 0d0)))))

(defun falcon-scaled-vec (v shift)
  "V scaled by 2^SHIFT as a specialized double-float vector."
  (declare (type (simple-array * (*)) v)
           (type fixnum shift)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length v))
         (r (falcon-dvec n)))
    (declare (type falcon-dvec r))
    (dotimes (i n r)
      (setf (aref r i) (float (ash (aref v i) shift) 0d0)))))

(defun falcon-cdiv-vec (v qfc)
  "V divided by the complex constant QFC, elementwise."
  (declare (type falcon-cvec v)
           (type (complex double-float) qfc)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length v))
         (r (falcon-cvec n)))
    (declare (type falcon-cvec r))
    (dotimes (i n r)
      (setf (aref r i) (falcon-cdiv (aref v i) qfc)))))

(defun falcon-split-fft (f)
  (declare (type falcon-cvec f)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length f))
         (h (ash n -1))
         (w (falcon-fft-croots n))
         (f0 (falcon-cvec h))
         (f1 (falcon-cvec h)))
    (declare (type (simple-array (complex double-float) (*)) w))
    (dotimes (i h (values f0 f1))
      (setf (aref f0 i) (* 0.5d0 (+ (aref f (* 2 i)) (aref f (+ (* 2 i) 1))))
            (aref f1 i) (* (* 0.5d0 (- (aref f (* 2 i)) (aref f (+ (* 2 i) 1))))
                           (conjugate (aref w (* 2 i))))))))

(defun falcon-merge-fft (f0 f1)
  (declare (type falcon-cvec f0 f1)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((h (length f0))
         (n (* 2 h))
         (w (falcon-fft-croots n))
         (f (falcon-cvec n)))
    (declare (type (simple-array (complex double-float) (*)) w))
    (dotimes (i h f)
      (setf (aref f (* 2 i)) (+ (aref f0 i) (* (aref w (* 2 i)) (aref f1 i)))
            (aref f (+ (* 2 i) 1)) (- (aref f0 i) (* (aref w (* 2 i)) (aref f1 i)))))))

(defun falcon-fft (f)
  "Forward FFT: coefficient reals -> FFT domain.

F may be any vector of reals.  The iterative form replicates the old
recursive transform bit for bit (same butterflies, same twiddles, same
order); see falcon-fft-iter."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (falcon-fft-iter f))

(defstruct falcon-cfft-plan
  (brev nil :type (simple-array fixnum (*)))
  (stages nil :type simple-vector))

(defvar *falcon-cfft-plans* nil
  "Alist of N -> falcon-cfft-plan, built on first use.")

(defun falcon-cfft-plan-for (n)
  "Iterative-FFT plan for size N: bit reversal plus one twiddle pair
per stage, taken from the existing roots tables so the constants are
identical to the recursive transform's."
  (declare (type fixnum n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (or (cdr (assoc n *falcon-cfft-plans*))
      (let* ((logn (1- (integer-length n)))
             (brev (make-array n :element-type 'fixnum))
             (stages (make-array logn)))
        (dotimes (i n)
          (let ((r 0) (x i))
            (declare (type fixnum r x))
            (loop repeat logn do
              (setf r (+ (* r 2) (logand x 1))
                    x (ash x -1)))
            (setf (aref brev i) r)))
        (loop for level of-type fixnum from 1 to logn do
          (let* ((len (ash 1 level))
                 (half (ash len -1))
                 (w (falcon-fft-roots len))
                 (re (make-array half :element-type 'double-float))
                 (im (make-array half :element-type 'double-float)))
            (dotimes (j half)
              (let ((tw (aref w (* 2 j))))
                (setf (aref re j) (float (realpart tw) 0d0)
                      (aref im j) (float (imagpart tw) 0d0))))
            (setf (aref stages (1- level)) (cons re im))))
        (let ((plan (make-falcon-cfft-plan :brev brev :stages stages)))
          (push (cons n plan) *falcon-cfft-plans*)
          plan))))

(defun falcon-fft-iter (f)
  "Forward FFT into a fresh cvec, bit-identical to the recursive transform.

The recursion bit-reverses the reals, packs pairs as (x+iy, x-iy) and
merges with an interleaved write; the loop below does the same stages
bottom-up, ping-ponging two buffers because the interleaved write is
not in place.  Twiddles come from the plan, i.e. from the same roots
tables in the same order."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length f))
         (plan (falcon-cfft-plan-for n))
         (brev (falcon-cfft-plan-brev plan))
         (stages (falcon-cfft-plan-stages plan))
         (ra (make-array n :element-type 'double-float :initial-element 0d0))
         (ia (make-array n :element-type 'double-float :initial-element 0d0))
         (rb (make-array n :element-type 'double-float :initial-element 0d0))
         (ib (make-array n :element-type 'double-float :initial-element 0d0)))
    (declare (type fixnum n)
             (type (simple-array fixnum (*)) brev)
             (type simple-vector stages)
             (type (simple-array double-float (*)) ra ia rb ib))
    ;; Bit-reversed pack: pair (brev[2k], brev[2k+1]) becomes
    ;; (x+iy, x-iy), exactly the recursion's size-2 nodes.
    (loop for k of-type fixnum from 0 below (ash n -1) do
      (let ((x (float (aref f (aref brev (* 2 k))) 0d0))
            (y (float (aref f (aref brev (+ (* 2 k) 1))) 0d0)))
        (setf (aref ra (* 2 k)) x (aref ia (* 2 k)) y
              (aref ra (+ (* 2 k) 1)) x (aref ia (+ (* 2 k) 1)) (- y))))
    ;; Merge stages len = 4 .. n, reading (ra, ia), writing (rb, ib).
    (loop for len of-type fixnum = 4 then (ash len 1)
          while (<= len n)
          do (let* ((half (ash len -1))
                    (tw (aref stages (- (integer-length len) 2)))
                    (twre (car tw))
                    (twim (cdr tw)))
               (declare (type fixnum half)
                        (type (simple-array double-float (*)) twre twim))
               (loop for start of-type fixnum from 0 below n by len
                     do (dotimes (j half)
                          (let* ((ur (aref ra (+ start j)))
                                 (ui (aref ia (+ start j)))
                                 (vr (aref ra (+ start j half)))
                                 (vi (aref ia (+ start j half)))
                                 (wr (aref twre j))
                                 (wi (aref twim j))
                                 (tr (- (* wr vr) (* wi vi)))
                                 (ti (+ (* wr vi) (* wi vr))))
                            (setf (aref rb (+ start (* 2 j))) (+ ur tr)
                                  (aref ib (+ start (* 2 j))) (+ ui ti)
                                  (aref rb (+ start (* 2 j) 1)) (- ur tr)
                                  (aref ib (+ start (* 2 j) 1)) (- ui ti))))))
             (rotatef ra rb)
             (rotatef ia ib))
    ;; The last stage wrote into (rb, ib) after the final rotate...
    ;; track: after each stage ra/rb swap; result is in ra.
    (let ((out (falcon-cvec n)))
      (dotimes (i n out)
        (setf (aref out i) (complex (aref ra i) (aref ia i)))))))

(declaim (inline falcon-cifft-stage))
(defun falcon-cifft-stage (ra ia rb ib n len stages)
  "One inverse merge stage of size LEN: halves with conjugated twiddles."
  (declare (type (simple-array double-float (*)) ra ia rb ib)
           (type fixnum n len)
           (type simple-vector stages)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((half (ash len -1))
         (tw (aref stages (- (integer-length len) 2)))
         (twre (car tw))
         (twim (cdr tw)))
    (declare (type fixnum half)
             (type (simple-array double-float (*)) twre twim))
    (loop for start of-type fixnum from 0 below n by len
          do (dotimes (j half)
               (let* ((o0r (aref ra (+ start (* 2 j))))
                      (o0i (aref ia (+ start (* 2 j))))
                      (o1r (aref ra (+ start (* 2 j) 1)))
                      (o1i (aref ia (+ start (* 2 j) 1)))
                      (ur (* 0.5d0 (+ o0r o1r)))
                      (ui (* 0.5d0 (+ o0i o1i)))
                      (dr (* 0.5d0 (- o0r o1r)))
                      (di (* 0.5d0 (- o0i o1i)))
                      (wr (aref twre j))
                      (wi (aref twim j)))
                 ;; conj(w) = (wr, -wi): re = wr*dr + wi*di,
                 ;; im = wr*di - wi*dr.
                 (setf (aref rb (+ start j)) ur
                       (aref ib (+ start j)) ui
                       (aref rb (+ start j half))
                       (+ (* wr dr) (* wi di))
                       (aref ib (+ start j half))
                       (- (* wr di) (* wi dr)))))))
  (values))

(defun falcon-ifft-iter (f)
  "Inverse FFT into fresh doubles, bit-identical to the recursive transform.

Reverses the forward pipeline: inverse merges from the top stage down
(the twiddle is conjugated and each stage halves, matching split-fft),
then unpacks each (x+iy, x-iy) pair and undoes the bit reversal."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length f))
         (plan (falcon-cfft-plan-for n))
         (brev (falcon-cfft-plan-brev plan))
         (stages (falcon-cfft-plan-stages plan))
         (ra (make-array n :element-type 'double-float :initial-element 0d0))
         (ia (make-array n :element-type 'double-float :initial-element 0d0))
         (rb (make-array n :element-type 'double-float :initial-element 0d0))
         (ib (make-array n :element-type 'double-float :initial-element 0d0)))
    (declare (type fixnum n)
             (type (simple-array fixnum (*)) brev)
             (type simple-vector stages)
             (type (simple-array double-float (*)) ra ia rb ib))
    (dotimes (i n)
      (let ((v (aref f i)))
        (setf (aref ra i) (float (realpart v) 0d0)
              (aref ia i) (float (imagpart v) 0d0))))
    (loop for len of-type fixnum = n then (ash len -1)
          while (>= len 4)
          do (falcon-cifft-stage ra ia rb ib n len stages)
             (rotatef ra rb)
             (rotatef ia ib))
    (let ((out (make-array n :element-type 'double-float)))
      (dotimes (k (ash n -1) out)
        (let ((x (aref ra (* 2 k)))
              (y (aref ia (* 2 k))))
          (setf (aref out (aref brev (* 2 k))) x
                (aref out (aref brev (+ (* 2 k) 1))) y))))))

(defun falcon-ifft (f)
  "Inverse FFT: FFT domain -> real coefficients (doubles).
The iterative form replicates the old recursive transform bit for
bit; see falcon-ifft-iter."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (falcon-ifft-iter f))

(defun falcon-add-fft (a b)
  (declare (type falcon-cvec a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a)) (r (falcon-cvec n)))
    (dotimes (i n r) (setf (aref r i) (+ (aref a i) (aref b i))))))

(defun falcon-sub-fft (a b)
  (declare (type falcon-cvec a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a)) (r (falcon-cvec n)))
    (dotimes (i n r) (setf (aref r i) (- (aref a i) (aref b i))))))

(defun falcon-mul-fft (a b)
  (declare (type falcon-cvec a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a)) (r (falcon-cvec n)))
    (dotimes (i n r) (setf (aref r i) (* (aref a i) (aref b i))))))

(defun falcon-div-fft (a b)
  (let* ((n (length a)) (r (falcon-cvec n)))
    (dotimes (i n r) (setf (aref r i) (falcon-cdiv (aref a i) (aref b i))))))

(declaim (inline falcon-cdiv))
(defun falcon-cdiv (a b)
  "Complex division replicating CPython's Smith algorithm op-for-op,
so results are bit-identical to the reference."
  (let* ((ar (realpart a)) (ai (imagpart a))
         (br (realpart b)) (bi (imagpart b))
         (abre (abs br)) (abim (abs bi)))
    (if (>= abre abim)
        (let* ((ratio (/ bi br))
               (denom (+ br (* bi ratio))))
          (complex (/ (+ ar (* ai ratio)) denom)
                   (/ (- ai (* ar ratio)) denom)))
        (let* ((ratio (/ br bi))
               (denom (+ (* br ratio) bi)))
          (complex (/ (+ (* ar ratio) ai) denom)
                   (/ (- (* ai ratio) ar) denom))))))

(defun falcon-adj-fft (a)
  (declare (type falcon-cvec a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a)) (r (falcon-cvec n)))
    (dotimes (i n r) (setf (aref r i) (conjugate (aref a i))))))

(defun falcon-add (a b)
  (let* ((n (length a)) (r (make-array n :element-type 'double-float)))
    (dotimes (i n r) (setf (aref r i) (+ (aref a i) (aref b i))))))

(defun falcon-sub (a b)
  (let* ((n (length a)) (r (make-array n :element-type 'double-float)))
    (dotimes (i n r) (setf (aref r i) (- (aref a i) (aref b i))))))

(defun falcon-mul (a b)
  "Coefficient multiplication via FFT (matches reference rounding)."
  (falcon-ifft (falcon-mul-fft (falcon-fft a) (falcon-fft b))))

(defun falcon-adj (a)
  "Adjoint via FFT (matches reference rounding)."
  (falcon-ifft (falcon-adj-fft (falcon-fft a))))

(defun falcon-div (a b)
  "Coefficient division via FFT (matches reference rounding)."
  (falcon-ifft (falcon-div-fft (falcon-fft a) (falcon-fft b))))


;;;
;;; Discrete Gaussian sampler over Z (exact port of samplerz.py).
;;;

(defconstant +falcon-max-sigma+ 1.8205d0)
(defconstant +falcon-inv-2sigma2+ (/ 1d0 (* 2d0 (expt +falcon-max-sigma+ 2))))
(defconstant +falcon-rcdt-prec+ 72)
(defconstant +falcon-ln2+ 0.69314718056d0)
(defconstant +falcon-iln2+ 1.44269504089d0)

(defconst +falcon-rcdt+
  #(3024686241123004913666 1564742784480091954050 636254429462080897535
    199560484645026482916 47667343854657281903 8595902006365044063
    1163297957344668388 117656387352093658 8867391802663976 496969357462633
    20680885154299 638331848991 14602316184 247426747 3104126 28824 198 1))

(defconst +falcon-sampler-c+
  #(#x00000004741183A3 #x00000036548CFC06 #x0000024FDCBF140A #x0000171D939DE045
    #x0000D00CF58F6F84 #x000680681CF796E3 #x002D82D8305B0FEA #x011111110E066FD0
    #x0555555555070F00 #x155555555581FF00 #x400000000002B400 #x7FFFFFFFFFFF4800
    #x8000000000000000))

(defun falcon-basesampler (randbytes)
  (let ((u 0))
    (let ((raw (funcall randbytes (ash +falcon-rcdt-prec+ -3))))
      (dotimes (i (length raw))
        (setf u (+ u (ash (aref raw i) (* 8 i))))))
    (let ((z0 0))
      (dotimes (i (length +falcon-rcdt+) z0)
        (when (< u (aref +falcon-rcdt+ i))
          (incf z0))))))

(defun falcon-approxexp (x ccs)
  (declare (type double-float x ccs)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((y (aref +falcon-sampler-c+ 0))
        (z (truncate (* x (ash 1 63)))))
    (declare (type integer y z))
    (dotimes (i (1- (length +falcon-sampler-c+)))
      (setf y (- (aref +falcon-sampler-c+ (+ i 1)) (ash (* z y) -63))))
    (setf z (ash (truncate (* ccs (ash 1 63))) 1))
    (ash (* z y) -63)))

(defun falcon-berexp (x ccs randbytes)
  ;; int() in the reference truncates toward zero (x may be negative).
  (declare (type double-float x ccs)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((s (truncate (* x +falcon-iln2+)))
         (r (- x (* s +falcon-ln2+))))
    (declare (type integer s) (type double-float r))
    (setf s (min s 63))
    (let ((z (ash (- (falcon-approxexp r ccs) 1) (- s))))
      (loop for i = 56 then (- i 8)
            while (>= i 0)
            for p = (aref (funcall randbytes 1) 0)
            for w = (- p (ldb (byte 8 i) z))
            when (/= w 0) do (return (< w 0))
            finally (return nil)))))

(defun falcon-samplerz (mu sigma sigmin randbytes)
  (declare (type double-float mu sigma sigmin)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((s (floor mu))
        (r (- mu (floor mu)))
        (dss (/ 1d0 (* 2d0 sigma sigma)))
        (ccs (/ sigmin sigma)))
    (declare (type integer s) (type double-float r dss ccs))
    (loop
      (let* ((z0 (falcon-basesampler randbytes))
             (b (ldb (byte 1 0) (aref (funcall randbytes 1) 0)))
             (z (+ b (* (- (* 2 b) 1) z0)))
             (x (- (* (- z r) (- z r) dss) (* z0 z0 +falcon-inv-2sigma2+))))
        (declare (type fixnum z0 b z) (type double-float x))
        (when (falcon-berexp x ccs randbytes)
          (return (+ z s)))))))


;;;
;;; Falcon ChaCha20 PRG (exact port of rng.py; KAT determinism).
;;;

(defstruct falcon-prng
  (s (make-array 14 :element-type '(unsigned-byte 32) :initial-element 0)
     :type (simple-array (unsigned-byte 32) (*)))
  (ctr 0 :type unsigned-byte)
  (bytes (make-array 0 :element-type '(unsigned-byte 8))
         :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type fixnum))

(defun falcon-prng-init (seed-bytes)
  "SEED-BYTES: 56 bytes."
  (let ((prng (make-falcon-prng)))
    (dotimes (i 14)
      (setf (aref (falcon-prng-s prng) i)
            (+ (ash (aref seed-bytes (+ (* 4 i) 3)) 24)
               (ash (aref seed-bytes (+ (* 4 i) 2)) 16)
               (ash (aref seed-bytes (+ (* 4 i) 1)) 8)
               (aref seed-bytes (* 4 i)))))
    (setf (falcon-prng-ctr prng) (+ (aref (falcon-prng-s prng) 12)
                                    (ash (aref (falcon-prng-s prng) 13) 32)))
    prng))

(declaim (inline falcon-roll32))
(defun falcon-roll32 (x n)
  (logior (ldb (byte 32 0) (ash x n)) (ash x (- n 32))))

(defconst +falcon-chacha-cw+ #(#x61707865 #x3320646e #x79622d32 #x6b206574))

(defun falcon-prng-qround (state a b c d)
  (let ((x (aref state a)) (y (aref state b))
        (z (aref state c)) (w (aref state d)))
    (setf x (ldb (byte 32 0) (+ x y))
          w (falcon-roll32 (logxor w x) 16)
          z (ldb (byte 32 0) (+ z w))
          y (falcon-roll32 (logxor y z) 12)
          x (ldb (byte 32 0) (+ x y))
          w (falcon-roll32 (logxor w x) 8)
          z (ldb (byte 32 0) (+ z w))
          y (falcon-roll32 (logxor y z) 7))
    (setf (aref state a) x (aref state b) y
          (aref state c) z (aref state d) w))
  (values))

(defun falcon-prng-update (prng)
  (let ((state (make-array 16 :element-type '(unsigned-byte 32)))
        (s (falcon-prng-s prng))
        (ctr (falcon-prng-ctr prng)))
    (replace state +falcon-chacha-cw+ :end2 4)
    (dotimes (i 10) (setf (aref state (+ 4 i)) (aref s i)))
    (setf (aref state 14) (logxor (aref s 10) (ldb (byte 32 0) ctr))
          (aref state 15) (logxor (aref s 11) (ldb (byte 32 0) (ash ctr -32))))
    (let ((init (copy-seq state)))
      (dotimes (r 10)
        (falcon-prng-qround state 0 4 8 12)
        (falcon-prng-qround state 1 5 9 13)
        (falcon-prng-qround state 2 6 10 14)
        (falcon-prng-qround state 3 7 11 15)
        (falcon-prng-qround state 0 5 10 15)
        (falcon-prng-qround state 1 6 11 12)
        (falcon-prng-qround state 2 7 8 13)
        (falcon-prng-qround state 3 4 9 14))
      (dotimes (i 16)
        (setf (aref state i) (ldb (byte 32 0) (+ (aref state i) (aref init i))))))
    (setf (falcon-prng-ctr prng) (1+ ctr))
    state))

(defun falcon-prng-block-bytes (prng)
  "512 pseudorandom bytes from eight ChaCha blocks, little-endian words
interleaved exactly as the reference hex construction (word j of block
i lands at words[8j+i], then each word is emitted little-endian).
Produces bytes identical to the old hex-string path, without FORMAT."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((words (make-array 128 :element-type '(unsigned-byte 32)))
        (out (make-array 512 :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 32) (*)) words)
             (type (simple-array (unsigned-byte 8) (*)) out))
    (dotimes (i 8)
      (let ((blk (falcon-prng-update prng)))
        (declare (type (simple-array (unsigned-byte 32) (*)) blk))
        (dotimes (j 16)
          (setf (aref words (+ (* j 8) i)) (aref blk j)))))
    ;; Reference: elt.to_bytes(4, "little").hex() per word.
    (dotimes (m 128 out)
      (let ((w (aref words m))
            (p (* 4 m)))
        (setf (aref out p) (ldb (byte 8 0) w)
              (aref out (+ p 1)) (ldb (byte 8 8) w)
              (aref out (+ p 2)) (ldb (byte 8 16) w)
              (aref out (+ p 3)) (ldb (byte 8 24) w))))))

(defun falcon-prng-randombytes (prng k)
  "K pseudorandom bytes from PRNG, buffering 512-byte blocks.
On refill the remainder is dropped and fresh blocks are made, exactly
like the old hex-string path (which replaced its buffer)."
  (declare (type fixnum k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((buf (falcon-prng-bytes prng))
        (pos (falcon-prng-pos prng)))
    (declare (type (simple-array (unsigned-byte 8) (*)) buf)
             (type fixnum pos))
    (when (> (+ pos k) (length buf))
      (let* ((nblocks (max 1 (ceiling k 512)))
             (nb (make-array (* 512 nblocks) :element-type '(unsigned-byte 8))))
        (declare (type fixnum nblocks)
                 (type (simple-array (unsigned-byte 8) (*)) nb))
        (dotimes (b nblocks)
          (replace nb (falcon-prng-block-bytes prng) :start1 (* b 512)))
        (setf buf nb
              pos 0
              (falcon-prng-bytes prng) buf
              (falcon-prng-pos prng) 0)))
    (let ((out (subseq buf pos (+ pos k))))
      (setf (falcon-prng-pos prng) (+ pos k))
      out)))

(defun falcon-make-randbytes (prng-or-nil)
  "Closure returning K random bytes; random-data when PRNG is NIL."
  (if (null prng-or-nil)
      (lambda (k) (random-data k))
      (lambda (k) (falcon-prng-randombytes prng-or-nil k))))

(defun falcon-buffered-randbytes (randbytes &optional (size 4096))
  "Wrap RANDBYTES with a refillable buffer; serves the identical byte
stream with far fewer underlying calls.  The sampler reads 9 bytes,
then single bytes; without buffering every one is a full call."
  (declare (type fixnum size)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((buf (make-array 0 :element-type '(unsigned-byte 8)))
        (pos 0))
    (declare (type (simple-array (unsigned-byte 8) (*)) buf)
             (type fixnum pos))
    (lambda (k)
      (declare (type fixnum k))
      (when (> (+ pos k) (length buf))
        (let* ((have (- (length buf) pos))
               (need (max size (+ have k)))
               (nb (make-array need :element-type '(unsigned-byte 8))))
          (replace nb buf :start2 pos)
          (replace nb (funcall randbytes (- need have)) :start1 have)
          (setf buf nb
                pos 0)))
      (prog1 (subseq buf pos (+ pos k))
        (incf pos k)))))


;;;
;;; ffSampling (exact port of ffsampling.py, FFT domain).
;;;

(defun falcon-gram (b0 b1 b2 b3)
  "Gram matrix of [[b0 b1] [b2 b3]] (coefficient floats)."
  (let ((g00 (falcon-add (falcon-mul b0 b0) (falcon-mul b1 b1)))
        (g01 (falcon-add (falcon-mul b0 b2) (falcon-mul b1 b3)))
        (g11 (falcon-add (falcon-mul b2 b2) (falcon-mul b3 b3))))
    (list (list g00 g01) (list g01 g11))))

(defun falcon-ldl-fft (g00 g10 g11)
  (let* ((l10 (falcon-div-fft g10 g00))
         (d11 (falcon-sub-fft g11 (falcon-mul-fft (falcon-mul-fft l10 (falcon-adj-fft l10)) g00))))
    (values l10 d11)))

(defun falcon-ffldl-fft (g00 g10 g11)
  "ffLDL decomposition tree: (L10 T0 T1); bottom holds the LDL diagonals.
G10 is the FFT of the (1,0) Gram entry at top level, elementwise-adjoint
diagonals below (matching the reference construction)."
  (multiple-value-bind (l10 d11) (falcon-ldl-fft g00 g10 g11)
    (let ((n (length g00)))
      (if (> n 2)
          (multiple-value-bind (d00 d01) (falcon-split-fft g00)
            (multiple-value-bind (d10 d11s) (falcon-split-fft d11)
              (list l10
                    (falcon-ffldl-fft d00 (falcon-adj-fft d01) d00)
                    (falcon-ffldl-fft d10 (falcon-adj-fft d11s) d10))))
          (list l10 g00 d11)))))

(defun falcon-normalize-vec (vec sigma)
  (setf (aref vec 0) (complex (/ sigma (sqrt (realpart (aref vec 0)))) 0d0))
  (setf (aref vec 1) #C(0d0 0d0))
  (values))

(defun falcon-normalize-tree (tree sigma)
  "In place: bottom 2-vectors [x y] become [sigma/sqrt(x) 0]."
  (if (vectorp (second tree))
      (progn (falcon-normalize-vec (second tree) sigma)
             (falcon-normalize-vec (third tree) sigma))
      (progn (falcon-normalize-tree (second tree) sigma)
             (falcon-normalize-tree (third tree) sigma))))

(defun falcon-ffsampling (t0 t1 tree sigmin randbytes)
  "Returns (z0 z1) in FFT domain. TREE is (L10 T0 T1)."
  (let ((n (length t0)))
    (if (> n 1)
        (destructuring-bind (l10 t0sub t1sub) tree
          (multiple-value-bind (s10 s11) (falcon-split-fft t1)
            (multiple-value-bind (z10 z11)
                (falcon-ffsampling-2 s10 s11 t1sub sigmin randbytes)
              (let* ((z1 (falcon-merge-fft z10 z11))
                     (t0b (falcon-add-fft t0 (falcon-mul-fft (falcon-sub-fft t1 z1) l10))))
                (multiple-value-bind (s00 s01) (falcon-split-fft t0b)
                  (multiple-value-bind (z00 z01)
                      (falcon-ffsampling-2 s00 s01 t0sub sigmin randbytes)
                    (values (falcon-merge-fft z00 z01) z1)))))))
        (let ((z0 (falcon-cvec 1))
              (z1 (falcon-cvec 1)))
          (setf (aref z0 0)
                (complex (falcon-samplerz (realpart (aref t0 0))
                                          (realpart (aref tree 0))
                                          sigmin randbytes)
                         0d0)
                (aref z1 0)
                (complex (falcon-samplerz (realpart (aref t1 0))
                                          (realpart (aref tree 0))
                                          sigmin randbytes)
                         0d0))
          (values z0 z1)))))

(defun falcon-ffsampling-2 (s0 s1 tree sigmin randbytes)
  "Helper: same as falcon-ffsampling (split halves already)."
  (falcon-ffsampling s0 s1 tree sigmin randbytes))


;;;
;;; Compression codec (encoding for signing).
;;;

(defun falcon-compress (v slen)
  "Encode integer vector V into SLEN bytes, or NIL if too long."
  (let ((bits (make-array 0 :element-type 'bit :adjustable t :fill-pointer 0)))
    (dotimes (i (length v))
      (let ((coef (aref v i)))
        (vector-push-extend (if (minusp coef) 1 0) bits)
        (let ((low (mod (abs coef) 128)))
          (dotimes (b 7)
            (vector-push-extend (ldb (byte 1 (- 6 b)) low) bits)))
        (dotimes (j (ash (abs coef) -7))
          (vector-push-extend 0 bits))
        (vector-push-extend 1 bits)))
    (when (> (length bits) (* 8 slen))
      (return-from falcon-compress nil))
    (let ((out (make-array slen :element-type '(unsigned-byte 8) :initial-element 0)))
      (dotimes (i (length bits) out)
        (when (= (aref bits i) 1)
          (setf (aref out (ash i -3))
                (logior (aref out (ash i -3)) (ash 1 (- 7 (mod i 8))))))))))


;;;
;;; Secret-key expansion and signing.
;;;

(defun falcon-expand-sk (f g ff gg params)
  "Full sk expansion: B0-fft, normalized LDL tree."
  (declare (ignore params))
  (flet ((dbl (v) (coerce (map 'vector (lambda (x) (float x 0d0)) v)
                          '(simple-array double-float (*)))))
    (let ((poly-f (dbl f)) (poly-g (dbl g)) (poly-ff (dbl ff)) (poly-gg (dbl gg)))
      ;; Gram matrix of B0 = [[g -f] [G -F]]: G[i][j] = sum B[i][k]*adj(B[j][k]).
      (let* ((g00 (falcon-add (falcon-mul poly-g (falcon-adj poly-g))
                              (falcon-mul poly-f (falcon-adj poly-f))))
             (g10 (falcon-add (falcon-mul poly-gg (falcon-adj poly-g))
                              (falcon-mul (falcon-neg poly-ff)
                                          (falcon-adj (falcon-neg poly-f)))))
             (g11 (falcon-add (falcon-mul poly-gg (falcon-adj poly-gg))
                              (falcon-mul poly-ff (falcon-adj poly-ff))))
             (g00f (falcon-fft g00)) (g10f (falcon-fft g10)) (g11f (falcon-fft g11))
             (b0f (falcon-fft poly-g)) (b1f (falcon-fft (falcon-neg poly-f)))
             (b2f (falcon-fft poly-gg)) (b3f (falcon-fft (falcon-neg poly-ff)))
             (tree (falcon-ffldl-fft g00f g10f g11f)))
        (falcon-normalize-tree tree (falcon-params-sigma *falcon-params*))
        (values (list (list b0f b1f) (list b2f b3f)) tree)))))

(defun falcon-neg (v)
  (let* ((n (length v)) (r (make-array n :element-type 'double-float)))
    (dotimes (i n r) (setf (aref r i) (- (aref v i))))))

(defun falcon-sample-preimage (b0fft tree hashed sigmin randbytes)
  "Returns (s0 s1) integer vectors with s0+s1*h = hashed."
  (destructuring-bind ((a b) (c d)) b0fft
    ;; t = (point*d/q, -point*b/q) in FFT domain (scalar q division).
    (let* ((pointf (falcon-fft (falcon-double-vec hashed)))
           (qf (float +falcon-q+ 0d0))
           (qfc (complex qf 0d0))
           (tt0 (falcon-cdiv-vec (falcon-mul-fft pointf d) qfc))
           (tt1 (falcon-cdiv-vec (falcon-mul-fft (falcon-negate-fft pointf) b) qfc)))
      (multiple-value-bind (z0f z1f)
          (falcon-ffsampling tt0 tt1 tree sigmin randbytes)
        (let* ((v0f (falcon-add-fft (falcon-mul-fft z0f a) (falcon-mul-fft z1f c)))
               (v1f (falcon-add-fft (falcon-mul-fft z0f b) (falcon-mul-fft z1f d)))
               (v0 (map 'vector #'round (falcon-ifft v0f)))
               (v1 (map 'vector #'round (falcon-ifft v1f)))
               (s0 (map 'vector #'- hashed v0))
               (s1 (map 'vector #'- v1)))
          (values s0 s1))))))

(defun falcon-negate-fft (v)
  (let* ((n (length v)) (r (falcon-cvec n)))
    (dotimes (i n r) (setf (aref r i) (- (aref v i))))))

(defun falcon-sample-preimage-seeded (b0fft tree hashed sigmin randbytes seed)
  "Per-attempt fresh ChaCha20 PRNG from SEED (NIL = use RANDBYTES directly)."
  (if (null seed)
      (falcon-sample-preimage b0fft tree hashed sigmin randbytes)
      (falcon-sample-preimage b0fft tree hashed sigmin
                              (falcon-make-randbytes (falcon-prng-init seed)))))

(defun falcon-sign-kat (fbytes gbytes ffbytes ggbbytes msg randbytes
                         &optional (params +falcon-512-params+))
  "KAT driver: salt and per-attempt seeds come from the caller's stream,
and each attempt uses a fresh ChaCha20 PRNG (as the reference does).
Inputs are the raw little-endian int16 NTRU polynomials."
  (let* ((*falcon-params* params)
         (n (falcon-params-n *falcon-params*))
         (decode (lambda (bytes)
                   (let ((v (make-array n :element-type 'fixnum)))
                     (dotimes (i n v)
                       (let ((lo (aref bytes (* 2 i))) (hi (aref bytes (+ (* 2 i) 1))))
                         (setf (aref v i) (if (logbitp 7 hi)
                                              (- (logior (ash hi 8) lo) #x10000)
                                              (logior (ash hi 8) lo))))))))
         (f (funcall decode fbytes))
         (g (funcall decode gbytes))
         (ff (funcall decode ffbytes))
         (gg (funcall decode ggbbytes))
         (salt (funcall randbytes 40))
         (sigmin (falcon-params-sigmin *falcon-params*))
         (bound (falcon-params-sig-bound *falcon-params*))
         (sig-bytelen (falcon-params-sig-bytelen *falcon-params*))
         (logn (falcon-params-logn *falcon-params*)))
    (multiple-value-bind (b0fft tree) (falcon-expand-sk f g ff gg *falcon-params*)
      (let ((hashed (coerce (falcon-hash-to-point msg salt n)
                            '(simple-array fixnum (*)))))
        (loop
          (let ((seed (funcall randbytes 56)))
            (multiple-value-bind (s0 s1)
                (falcon-sample-preimage b0fft tree hashed sigmin
                                        (falcon-make-randbytes (falcon-prng-init seed)))
              (let ((norm (+ (reduce #'+ (map 'vector (lambda (x) (* x x)) s0))
                             (reduce #'+ (map 'vector (lambda (x) (* x x)) s1)))))
                (when (<= norm bound)
                  (let ((enc (falcon-compress s1 (- sig-bytelen 1 40))))
                    (when enc
                      (let ((sig (make-array sig-bytelen :element-type '(unsigned-byte 8)
                                                            :initial-element 0)))
                        (setf (aref sig 0) (+ #x30 logn))
                        (replace sig salt :start1 1)
                        (replace sig enc :start1 41)
                      (return sig)))))))))))))

(defun falcon-sign-raw (f g ff gg msg randbytes params)
  "Sign MSG with explicit RANDBYTES byte-stream closure. Returns the
padded signature bytes. RANDBYTES supplies salt then per-attempt seeds,
exactly like the reference."
  (let* ((*falcon-params* params)
         (n (falcon-params-n params))
         (logn (falcon-params-logn params))
         (sigmin (falcon-params-sigmin params))
         (bound (falcon-params-sig-bound params))
         (sig-bytelen (falcon-params-sig-bytelen params))
         (rb (falcon-buffered-randbytes randbytes))
         (salt (funcall rb 40))
         (hashed (coerce (falcon-hash-to-point msg salt n)
                         '(simple-array fixnum (*)))))
    (multiple-value-bind (b0fft tree)
        (falcon-expand-sk f g ff gg params)
      (loop
        (let ((seed (funcall rb 56)))
          (multiple-value-bind (s0 s1)
              (falcon-sample-preimage-seeded b0fft tree hashed sigmin rb seed)
            (let ((norm (+ (reduce #'+ (map 'vector (lambda (x) (* x x)) s0))
                           (reduce #'+ (map 'vector (lambda (x) (* x x)) s1)))))
              (when (<= norm bound)
                (let ((enc (falcon-compress s1 (- sig-bytelen 1 40))))
                  (when enc
                    (let ((sig (make-array sig-bytelen :element-type '(unsigned-byte 8)
                                                          :initial-element 0)))
                      (setf (aref sig 0) (+ #x30 logn))
                      (replace sig salt :start1 1)
                      (replace sig enc :start1 41)
                      (return sig))))))))))))


;;;
;;; NTRU key generation (exact port of ntrugen.py; integer arithmetic).
;;;

(declaim (inline falcon-add-vectors))
(defun falcon-add-vectors (a b)
  (declare (type (simple-array integer (*)) a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a))
         (r (make-array n :element-type 'integer :initial-element 0)))
    (dotimes (i n r)
      (setf (aref r i) (+ (aref a i) (aref b i))))))

(defun falcon-add-vectors-range (a b ao bo n)
  "Elementwise sum of A[AO..AO+N) and B[BO..BO+N)."
  (declare (type (simple-array integer (*)) a b)
           (type fixnum ao bo n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (make-array n :element-type 'integer :initial-element 0)))
    (declare (type (simple-array integer (*)) r))
    (dotimes (i n r)
      (setf (aref r i) (+ (aref a (+ ao i)) (aref b (+ bo i)))))))

(defun falcon-karatsuba (a b ao bo n)
  "Karatsuba product of A[AO..AO+N) and B[BO..BO+N); the result has 2N
elements, the low half followed by the high half."
  (declare (type (simple-array integer (*)) a b)
           (type fixnum ao bo n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (if (<= n 4)
      (let ((ab (make-array (* 2 n) :element-type 'integer :initial-element 0)))
        (declare (type (simple-array integer (*)) ab))
        (dotimes (i n ab)
          (let ((ai (aref a (+ ao i))))
            (unless (zerop ai)
              (dotimes (j n)
                (setf (aref ab (+ i j))
                      (+ (aref ab (+ i j)) (* ai (aref b (+ bo j))))))))))
      (let* ((n2 (ash n -1))
             (ax (falcon-add-vectors-range a a ao (+ ao n2) n2))
             (bx (falcon-add-vectors-range b b bo (+ bo n2) n2))
             (a0b0 (falcon-karatsuba a b ao bo n2))
             (a1b1 (falcon-karatsuba a b (+ ao n2) (+ bo n2) n2))
             (axbx (falcon-karatsuba ax bx 0 0 n2))
             (ab (make-array (* 2 n) :element-type 'integer :initial-element 0)))
        (declare (type (simple-array integer (*)) ax bx a0b0 a1b1 axbx ab))
        (dotimes (i n)
          (decf (aref axbx i) (+ (aref a0b0 i) (aref a1b1 i))))
        (dotimes (i n)
          (incf (aref ab i) (aref a0b0 i))
          (incf (aref ab (+ i n)) (aref a1b1 i))
          (incf (aref ab (+ i n2)) (aref axbx i)))
        ab)))

(defun falcon-karamul (a b)
  (declare (type (simple-array integer (*)) a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a))
         (ab (falcon-karatsuba a b 0 0 n))
         (r (make-array n :element-type 'integer :initial-element 0)))
    (declare (type (simple-array integer (*)) r))
    (dotimes (i n r)
      (setf (aref r i) (- (aref ab i) (aref ab (+ i n)))))))

(defun falcon-galois-conj (a)
  (declare (type (simple-array integer (*)) a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a))
         (r (make-array n :element-type 'integer :initial-element 0)))
    (declare (type (simple-array integer (*)) r))
    (dotimes (i n r)
      (setf (aref r i) (if (evenp i) (aref a i) (- (aref a i)))))))

(defun falcon-field-norm (a)
  (declare (type (simple-array integer (*)) a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a))
         (n2 (ash n -1))
         (ae (make-array n2 :element-type 'integer :initial-element 0))
         (ao (make-array n2 :element-type 'integer :initial-element 0)))
    (declare (type fixnum n n2)
             (type (simple-array integer (*)) ae ao))
    (dotimes (i n2)
      (setf (aref ae i) (aref a (* 2 i))
            (aref ao i) (aref a (+ (* 2 i) 1))))
    (let ((ae2 (falcon-karamul ae ae))
          (ao2 (falcon-karamul ao ao))
          (res (make-array n2 :element-type 'integer :initial-element 0)))
      (declare (type (simple-array integer (*)) ae2 ao2 res))
      (dotimes (i n2 res)
        (setf (aref res i) (aref ae2 i)))
      (dotimes (i (1- n2))
        (decf (aref res (1+ i)) (aref ao2 i)))
      (incf (aref res 0) (aref ao2 (1- n2)))
      res)))

(defun falcon-lift (a)
  (declare (type (simple-array integer (*)) a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((n (length a))
         (r (make-array (* 2 n) :element-type 'integer :initial-element 0)))
    (declare (type fixnum n)
             (type (simple-array integer (*)) r))
    (dotimes (i n r)
      (setf (aref r (* 2 i)) (aref a i)))))

(defun falcon-bitsize (a)
  "Number of bytes needed to hold A, rounded up to a byte boundary."
  (declare (type integer a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((val (abs a)))
    (if (zerop val)
        0
        (* 8 (ceiling (integer-length val) 8)))))

(defun falcon-xgcd (b n)
  (let ((x0 1) (x1 0) (y0 0) (y1 1))
    (loop while (not (zerop n))
          do (multiple-value-bind (q r) (floor b n)
               (setf b n n r)
               (psetf x0 x1 x1 (- x0 (* q x1))
                      y0 y1 y1 (- y0 (* q y1)))))
    (values b x0 y0)))

(defun falcon-babai-reduce (f g ff gg)
  (let* ((n (length f))
         (size (max 53 (falcon-bitsize (reduce #'min f))
                    (falcon-bitsize (reduce #'max f))
                    (falcon-bitsize (reduce #'min g))
                    (falcon-bitsize (reduce #'max g))))
         (f-adj (falcon-scaled-vec f (- 53 size)))
         (g-adj (falcon-scaled-vec g (- 53 size)))
         (fa (falcon-fft f-adj))
         (ga (falcon-fft g-adj))
         (rF (copy-seq ff))
         (rG (copy-seq gg)))
    (loop
      (let ((sz (max 53 (falcon-bitsize (reduce #'min rF))
                     (falcon-bitsize (reduce #'max rF))
                     (falcon-bitsize (reduce #'min rG))
                     (falcon-bitsize (reduce #'max rG)))))
        (when (< sz size)
          (return (values rF rG)))
        (let* ((big-f (falcon-scaled-vec rF (- 53 sz)))
               (big-g (falcon-scaled-vec rG (- 53 sz)))
               (big-fa (falcon-fft big-f))
               (big-ga (falcon-fft big-g))
               (den (falcon-add-fft (falcon-mul-fft fa (falcon-adj-fft fa))
                                    (falcon-mul-fft ga (falcon-adj-fft ga))))
               (num (falcon-add-fft (falcon-mul-fft big-fa (falcon-adj-fft fa))
                                    (falcon-mul-fft big-ga (falcon-adj-fft ga))))
               (k (map 'vector (lambda (x) (round x))
                                   (falcon-ifft (falcon-div-fft num den)))))
          (when (every #'zerop k)
            (return (values rF rG)))
          (let ((fk (falcon-karamul f k))
                (gk (falcon-karamul g k))
                (sh (- sz size)))
            (dotimes (i n)
              (decf (aref rF i) (ash (aref fk i) sh))
              (decf (aref rG i) (ash (aref gk i) sh)))))))))

(defun falcon-ntru-solve (f g)
  (declare (type (simple-array integer (*)) f g)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((n (length f)))
    (declare (type fixnum n))
    (if (= n 1)
        (multiple-value-bind (d u v) (falcon-xgcd (aref f 0) (aref g 0))
          (unless (= d 1)
            (error "NTRU equation unsolvable"))
          (let ((F (make-array 1 :element-type 'integer :initial-element 0))
                (G (make-array 1 :element-type 'integer :initial-element 0)))
            (setf (aref F 0) (- (* +falcon-q+ v))
                  (aref G 0) (* +falcon-q+ u))
            (values F G)))
        (let* ((fp (falcon-field-norm f))
               (gp (falcon-field-norm g)))
          (multiple-value-bind (Fp Gp) (falcon-ntru-solve fp gp)
            (let ((rF (falcon-karamul (falcon-lift Fp) (falcon-galois-conj g)))
                  (rG (falcon-karamul (falcon-lift Gp) (falcon-galois-conj f))))
              (falcon-babai-reduce f g rF rG)))))))

(defun falcon-gs-norm (f g)
  ;; SQNORM-FG and SQNORM-FG (the inverse) are the same symbol in CL:
  ;; the second binding used to shadow the first, so the MAX compared
  ;; the inverse norm with itself.  Keep the two names distinct.
  (let* ((fg (map 'vector (lambda (x) (float x 0d0)) f))
         (gg (map 'vector (lambda (x) (float x 0d0)) g))
         (sqnorm-fg (+ (reduce #'+ (map 'vector (lambda (x) (* x x)) fg))
                       (reduce #'+ (map 'vector (lambda (x) (* x x)) gg))))
         (ffgg (falcon-add (falcon-mul fg (falcon-adj fg))
                           (falcon-mul gg (falcon-adj gg))))
         (Ft (falcon-div (falcon-adj gg) ffgg))
         (Gt (falcon-div (falcon-adj fg) ffgg))
         (sqnorm-inv (* (expt +falcon-q+ 2)
                        (+ (reduce #'+ (map 'vector (lambda (x) (* x x)) Ft))
                           (reduce #'+ (map 'vector (lambda (x) (* x x)) Gt))))))
    (max sqnorm-fg sqnorm-inv)))

(defun falcon-gen-poly (n randbytes)
  (let ((f0 (make-array 4096 :element-type 'integer :initial-element 0))
        (f (make-array n :element-type 'integer :initial-element 0))
        (k (floor 4096 n)))
    (declare (type (simple-array integer (*)) f0 f)
             (type fixnum k))
    (dotimes (i 4096)
      (setf (aref f0 i) (falcon-samplerz 0d0 1.43300980528773d0 1.43200980528773d0 randbytes)))
    (dotimes (i n f)
      (let ((acc 0))
        (declare (type fixnum acc))
        (dotimes (j k)
          (incf acc (aref f0 (+ (* i k) j))))
        (setf (aref f i) acc)))))

(defun falcon-ntru-gen (n randbytes)
  (let ((rb (falcon-buffered-randbytes randbytes)))
    (loop
      (let ((f (falcon-gen-poly n rb))
            (g (falcon-gen-poly n rb)))
        (when (<= (falcon-gs-norm f g) (* (expt 1.17d0 2) +falcon-q+))
          (let ((fntt (falcon-ntt (map 'vector (lambda (x) (mod x +falcon-q+)) f))))
            (unless (find 0 fntt)
              (handler-case
                  (multiple-value-bind (sF sG) (falcon-ntru-solve f g)
                    (return (values f g sF sG)))
                (error () nil)))))))))


;;;
;;; NTT division, G recovery, and the trim-i8 key codec.
;;;

(defun falcon-modinv (a)
  "Inverse of A mod 12289 (prime)."
  (let ((t0 0) (t1 1) (r0 +falcon-q+) (r1 (mod a +falcon-q+)))
    (loop while (plusp r1)
          do (multiple-value-bind (q r) (floor r0 r1)
               (setf r0 r1 r1 r)
               (psetf t0 t1 t1 (- t0 (* q t1)))))
    (mod t0 +falcon-q+)))

(defun falcon-div-zq (f g)
  "Divide polys mod (x^n+1, q); signals an error if G not invertible."
  (let* ((fn (falcon-ntt f))
         (gn (falcon-ntt g))
         (n (length fn))
         (qn (make-array n :element-type 'fixnum)))
    (dotimes (i n)
      (when (zerop (aref gn i))
        (error "Falcon: divisor not invertible"))
      (setf (aref qn i) (mod (* (aref fn i) (falcon-modinv (aref gn i)))
                             +falcon-q+)))
    (falcon-intt qn)))

(defun falcon-complete-private (f g ff n)
  "Recover G from (f,g,F) via G = g*F/f mod q, centered, int8 range.
Returns G or NIL."
  (let* ((fn (falcon-ntt (map 'vector (lambda (x) (mod x +falcon-q+)) f)))
         (gn (falcon-ntt (map 'vector (lambda (x) (mod x +falcon-q+)) g)))
         (Fn (falcon-ntt (map 'vector (lambda (x) (mod x +falcon-q+)) ff)))
         (qn (make-array n :element-type 'fixnum))
         (half (ash +falcon-q+ -1)))
    (dotimes (i n)
      (when (zerop (aref fn i))
        (return-from falcon-complete-private nil))
      (setf (aref qn i) (mod (* (aref gn i) (aref Fn i)
                                (falcon-modinv (aref fn i)))
                             +falcon-q+)))
    (let ((Gv (falcon-intt qn))
          (out (make-array n :element-type 'fixnum)))
      (dotimes (i n)
        (let ((gi (- (mod (+ (aref Gv i) half) +falcon-q+) half)))
          (when (or (< gi -127) (> gi 127))
            (return-from falcon-complete-private nil))
          (setf (aref out i) gi)))
      out)))

(defun falcon-trim-i8-encode (poly bits)
  "Pack N coefficients of BITS each (two's complement), big-endian bits."
  (let* ((n (length poly))
         (mask (1- (ash 1 bits)))
         (outlen (ash (+ (* n bits) 7) -3))
         (out (make-array outlen :element-type '(unsigned-byte 8) :initial-element 0))
         (acc 0) (acc-len 0) (pos 0))
    (dotimes (i n)
      (let ((v (aref poly i)))
        (unless (<= (- (ash 1 (1- bits))) v (1- (ash 1 (1- bits))))
          (error "Falcon: coefficient out of range for trim encoding"))
        (setf acc (logior (ash acc bits) (logand v mask))
              acc-len (+ acc-len bits))
        (loop while (>= acc-len 8)
              do (decf acc-len 8)
                 (setf (aref out pos) (ldb (byte 8 acc-len) acc))
                 (incf pos))))
    (when (plusp acc-len)
      (setf (aref out pos) (ldb (byte 8 0) (ash acc (- 8 acc-len)))))
    out))

(defun falcon-trim-i8-decode (bytes n bits)
  "Unpack N BITS-wide two's-complement coefficients, big-endian bits.
Returns NIL if any coefficient is the forbidden -2^(bits-1)."
  (let ((out (make-array n :element-type 'fixnum :initial-element 0))
        (acc 0) (acc-len 0) (pos 0))
    (dotimes (i n)
      (loop while (< acc-len bits)
            do (setf acc (logior (ash acc 8) (aref bytes pos))
                     acc-len (+ acc-len 8))
               (incf pos))
      (decf acc-len bits)
      (let ((v (ldb (byte bits acc-len) acc)))
        (setf acc (ldb (byte acc-len 0) acc))
        (when (= v (ash 1 (1- bits)))
          (return-from falcon-trim-i8-decode nil))
        (setf (aref out i) (if (logbitp (1- bits) v) (- v (ash 1 bits)) v))))
    out))


;;;
;;; Key generation and private-key API (FIPS 206 wire formats).
;;;

(defun falcon-sk-encode (f g ff logn small-bits big-bits)
  (let ((n (ash 1 logn))
        (out (make-array (if (= logn 9) 1281 2305)
                         :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref out 0) (+ #x50 logn))
    (let ((pos 1))
      (dolist (pair (list (cons f small-bits) (cons g small-bits) (cons ff big-bits)))
        (let ((enc (falcon-trim-i8-encode (car pair) (cdr pair))))
          (replace out enc :start1 pos)
          (incf pos (length enc)))))
    out))

(defun falcon-pk-encode (h logn)
  (let ((out (make-array (if (= logn 9) 897 1793)
                         :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref out 0) logn)
    (replace out (falcon-serialize (map 'vector (lambda (x) (mod x +falcon-q+)) h))
             :start1 1)
    out))

(defun falcon-keygen (params randbytes)
  "Generate (sk-bytes pk-bytes f g F G) in FIPS 206 formats."
  (let* ((*falcon-params* params)
         (n (falcon-params-n params))
         (logn (falcon-params-logn params))
         (small-bits (if (= logn 9) 6 5)))
    (loop
      (multiple-value-bind (f g ff gg)
          (falcon-ntru-gen n randbytes)
        ;; FIPS sizes require f,g,F in range; retry otherwise.
        (when (and (every (lambda (x) (<= (- 1 (ash 1 (1- small-bits))) x (1- (ash 1 (1- small-bits)))))
                          f)
                   (every (lambda (x) (<= (- 1 (ash 1 (1- small-bits))) x (1- (ash 1 (1- small-bits)))))
                          g)
                   (every (lambda (x) (<= -127 x 127)) ff))
          (return (values (falcon-sk-encode f g ff logn small-bits 8)
                          f g ff gg)))))))

(defclass falcon-512-private-key ()
  ((bytes :initarg :bytes :reader falcon-key-bytes
          :type (simple-array (unsigned-byte 8) (*)))
   (poly-f :initarg :poly-f :reader falcon-sk-poly-f)
   (poly-g :initarg :poly-g :reader falcon-sk-poly-g)
   (poly-ff :initarg :poly-ff :reader falcon-sk-poly-ff)
   (poly-gg :initarg :poly-gg :reader falcon-sk-poly-gg))
  (:documentation "Falcon-512 private key (FIPS 1281-byte encoding + basis)."))

(defclass falcon-1024-private-key ()
  ((bytes :initarg :bytes :reader falcon-key-bytes
          :type (simple-array (unsigned-byte 8) (*)))
   (poly-f :initarg :poly-f :reader falcon-sk-poly-f)
   (poly-g :initarg :poly-g :reader falcon-sk-poly-g)
   (poly-ff :initarg :poly-ff :reader falcon-sk-poly-ff)
   (poly-gg :initarg :poly-gg :reader falcon-sk-poly-gg))
  (:documentation "Falcon-1024 private key (FIPS 2305-byte encoding + basis)."))

(defun falcon-decode-sk (bytes params)
  "Decode FIPS sk bytes to (f g F G); NIL on failure."
  (let* ((*falcon-params* params)
         (n (falcon-params-n params))
         (logn (falcon-params-logn params))
         (small-bits (if (= logn 9) 6 5))
         (sklen (if (= logn 9) 1281 2305)))
    (when (and (= (length bytes) sklen) (= (aref bytes 0) (+ #x50 logn)))
      (let* ((flen (ash (+ (* n small-bits) 7) -3))
             (Flen (ash (+ (* n 8) 7) -3))
             (f (falcon-trim-i8-decode (subseq bytes 1 (+ 1 flen)) n small-bits))
             (g (falcon-trim-i8-decode (subseq bytes (+ 1 flen) (+ 1 (* 2 flen))) n small-bits))
             (ff (falcon-trim-i8-decode (subseq bytes (+ 1 (* 2 flen)) (+ 1 (* 2 flen) Flen)) n 8)))
        (when (and f g ff)
          (let ((gg (falcon-complete-private f g ff n)))
            (when gg
              (values f g ff gg))))))))

(defmethod make-private-key ((kind (eql :falcon-512)) &key bytes &allow-other-keys)
  (multiple-value-bind (f g ff gg) (falcon-decode-sk bytes +falcon-512-params+)
    (unless f
      (error 'missing-key-parameter :kind :falcon-512 :parameter 'bytes
             :description "Falcon-512 private key bytes"))
    (make-instance 'falcon-512-private-key :bytes (copy-seq bytes)
                   :poly-f f :poly-g g :poly-ff ff :poly-gg gg)))

(defmethod make-private-key ((kind (eql :falcon-1024)) &key bytes &allow-other-keys)
  (multiple-value-bind (f g ff gg) (falcon-decode-sk bytes +falcon-1024-params+)
    (unless f
      (error 'missing-key-parameter :kind :falcon-1024 :parameter 'bytes
             :description "Falcon-1024 private key bytes"))
    (make-instance 'falcon-1024-private-key :bytes (copy-seq bytes)
                   :poly-f f :poly-g g :poly-ff ff :poly-gg gg)))

(defmethod destructure-private-key ((key falcon-512-private-key))
  (list :bytes (copy-seq (falcon-key-bytes key))))

(defmethod destructure-private-key ((key falcon-1024-private-key))
  (list :bytes (copy-seq (falcon-key-bytes key))))

(defmethod generate-key-pair ((kind (eql :falcon-512)) &key &allow-other-keys)
  (multiple-value-bind (sk-bytes f g ff gg)
      (falcon-keygen +falcon-512-params+ (lambda (k) (random-data k)))
    (let* ((h (falcon-div-zq (map 'vector (lambda (x) (mod x +falcon-q+)) g)
                             (map 'vector (lambda (x) (mod x +falcon-q+)) f)))
           (pk-bytes (falcon-pk-encode h 9)))
      (values (make-instance 'falcon-512-private-key :bytes sk-bytes
                             :poly-f f :poly-g g :poly-ff ff :poly-gg gg)
              (make-instance 'falcon-512-public-key :bytes pk-bytes)))))

(defmethod generate-key-pair ((kind (eql :falcon-1024)) &key &allow-other-keys)
  (multiple-value-bind (sk-bytes f g ff gg)
      (falcon-keygen +falcon-1024-params+ (lambda (k) (random-data k)))
    (let* ((h (falcon-div-zq (map 'vector (lambda (x) (mod x +falcon-q+)) g)
                             (map 'vector (lambda (x) (mod x +falcon-q+)) f)))
           (pk-bytes (falcon-pk-encode h 10)))
      (values (make-instance 'falcon-1024-private-key :bytes sk-bytes
                             :poly-f f :poly-g g :poly-ff ff :poly-gg gg)
              (make-instance 'falcon-1024-public-key :bytes pk-bytes)))))

(defmethod sign-message ((key falcon-512-private-key) message
                         &key (start 0) end &allow-other-keys)
  (falcon-sign-raw (falcon-sk-poly-f key) (falcon-sk-poly-g key)
                   (falcon-sk-poly-ff key) (falcon-sk-poly-gg key)
                   (subseq message start (or end (length message)))
                   (lambda (k) (random-data k))
                   +falcon-512-params+))

(defmethod sign-message ((key falcon-1024-private-key) message
                         &key (start 0) end &allow-other-keys)
  (falcon-sign-raw (falcon-sk-poly-f key) (falcon-sk-poly-g key)
                   (falcon-sk-poly-ff key) (falcon-sk-poly-gg key)
                   (subseq message start (or end (length message)))
                   (lambda (k) (random-data k))
                   +falcon-1024-params+))
