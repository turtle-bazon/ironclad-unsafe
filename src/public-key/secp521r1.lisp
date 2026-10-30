;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; secp521r1.lisp -- secp521r1 (a.k.a. NIST P-521) elliptic curve


(in-package :crypto-unsafe)


;;; class definitions

(defclass secp521r1-public-key ()
  ((y :initarg :y :reader secp521r1-key-y
      :type (simple-array (unsigned-byte 8) (*)))
   (q-table :initform nil :accessor secp521r1-key-q-table)))

(defclass secp521r1-private-key ()
  ((x :initarg :x :reader secp521r1-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader secp521r1-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass secp521r1-point ()
    ;; Internally, a point (x, y) is represented using the Jacobian projective
    ;; coordinates (X, Y, Z), with x = X / Z^2 and y = Y / Z^3.
    ((x :initarg :x :type integer)
     (y :initarg :y :type integer)
     (z :initarg :z :type integer)))
  (defmethod make-load-form ((p secp521r1-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constant and function definitions

(defconstant +secp521r1-bits+ 521)
(defconstant +secp521r1-p+ 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151)
(defconstant +secp521r1-b+ 1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984)
(defconstant +secp521r1-l+ 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449)
(defconstant +secp521r1-i+ 5148598245097957286236425599311044912952076475107479057045847594389157387548242039091919730496090916232972233543610643527841490999787482859430521218336292863)

(defconst +secp521r1-g+
  (make-instance 'secp521r1-point
                 :x 2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846
                 :y 3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784
                 :z 1))
(defconst +secp521r1-point-at-infinity+
  (make-instance 'secp521r1-point :x 1 :y 1 :z 0))


;;; The field of P-521.
;;;
;;; The prime is 2^521 - 1, a Mersenne prime, so 2^521 is congruent to
;;; one, and the reduction of a value is a fold: the low five hundred
;;; and twenty-one bits of the value, plus the high ones.  The sum is
;;; below 2^522, so one more fold finishes it, and the division that
;;; the generic arithmetic does is not needed.

(defconstant +secp521r1-p-mask+ (1- (ash 1 521))
  "The low five hundred and twenty-one bits, all ones.")

(defun secp521r1-reduce (x)
  "X modulo the prime of P-521, for X of any size."
  (declare (type integer x)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; The fold keeps the residue and makes the value smaller, until it
  ;; is below 2^521; a negative value is made positive by the fold.
  (loop while (or (minusp x) (> x +secp521r1-p-mask+))
        do (setf x (+ (logand x +secp521r1-p-mask+) (ash x -521))))
  ;; The value is now below 2^521, and the prime is one less, so one
  ;; subtraction may be needed.
  (when (>= x +secp521r1-p+)
    (setf x (- x +secp521r1-p+)))
  x)

(defun secp521r1-mulmod (x y)
  "The product of X and Y, modulo the prime of P-521."
  (declare (type integer x y)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((p (* x y)))
    (declare (type integer p))
    ;; The product is below 2^1042, so the high part is below 2^521
    ;; and the sum of the two parts is below 2^522.
    (setf p (+ (logand p +secp521r1-p-mask+) (ash p -521)))
    (when (>= p +secp521r1-p+)
      (setf p (- p +secp521r1-p+)))
    p))

(defun secp521r1-addmod (x y)
  "The sum of X and Y, modulo the prime of P-521.
X and Y are reduced, so the sum needs one subtraction at most."
  (declare (type integer x y)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((s (+ x y)))
    (declare (type integer s))
    (if (>= s +secp521r1-p+)
        (- s +secp521r1-p+)
        s)))

(defun secp521r1-submod (x y)
  "The difference of X and Y, modulo the prime of P-521.
X and Y are reduced, so the difference needs one addition at most."
  (declare (type integer x y)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((s (- x y)))
    (declare (type integer s))
    (if (minusp s)
        (+ s +secp521r1-p+)
        s)))

(defun secp521r1-dblmod (x)
  "Twice X, modulo the prime of P-521.
X is reduced, so the double needs one subtraction at most."
  (declare (type integer x)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((s (+ x x)))
    (declare (type integer s))
    (if (>= s +secp521r1-p+)
        (- s +secp521r1-p+)
        s)))

;;; Limb field for P-521 (nine 64-bit words, Montgomery form).
;;;
;;; R = 2^576, so R mod P is 2^55 and R^-1 mod P is 2^466 (Mersenne
;;; arithmetic: 2^521 == 1).  Residues stay in Montgomery form between
;;; operations; conversion happens only at the curve boundary.
;;; Bignum intermediates never appear inside the hot path.

(deftype secp521r1-fe () '(simple-array (unsigned-byte 64) (9)))

(defconstant +secp521r1-r-mod-p+ #x80000000000000
  "R = 2^576 modulo P, i.e. 2^55.")

(defconstant +secp521r1-r-inv-mod-p+
  #x400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
  "R^-1 modulo P, i.e. 2^466.")

(defconstant +secp521r1-n0+ 1
  "Montgomery word: -P^-1 mod 2^64.  P[0] is all ones (-1), so N0 is 1.")

(defconst +secp521r1-modulus-limbs+
  (integer-to-limbs64 +secp521r1-p+ 9))
;; The prime as nine little-endian 64-bit limbs, for the VOP.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun secp521r1-fe-zero ()
    (make-array 9 :element-type '(unsigned-byte 64) :initial-element 0)))

(defun secp521r1-fe-from-int (n)
  "The Montgomery form of N modulo P."
  (declare (type integer n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; NB: the limb split is unrolled by hand.  SBCL 2.6.7 miscompiles
  ;; (LDB (BYTE 64 (* I 64)) V) with a variable position at safety 0.
  (let* ((v (mod (* (mod n +secp521r1-p+) +secp521r1-r-mod-p+)
                 +secp521r1-p+))
         (r (secp521r1-fe-zero)))
    (setf (aref r 0) (ldb (byte 64 0) v)
          (aref r 1) (ldb (byte 64 64) v)
          (aref r 2) (ldb (byte 64 128) v)
          (aref r 3) (ldb (byte 64 192) v)
          (aref r 4) (ldb (byte 64 256) v)
          (aref r 5) (ldb (byte 64 320) v)
          (aref r 6) (ldb (byte 64 384) v)
          (aref r 7) (ldb (byte 64 448) v)
          (aref r 8) (ldb (byte 64 512) v))
    r))

(defun secp521r1-fe-to-int (a)
  "The value of the Montgomery field element A, an integer below P."
  (declare (type secp521r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((v (+ (aref a 0)
              (ash (aref a 1) 64)
              (ash (aref a 2) 128)
              (ash (aref a 3) 192)
              (ash (aref a 4) 256)
              (ash (aref a 5) 320)
              (ash (aref a 6) 384)
              (ash (aref a 7) 448)
              (ash (aref a 8) 512))))
    (mod (* v +secp521r1-r-inv-mod-p+) +secp521r1-p+)))

(defun secp521r1-fe-copy (a)
  (declare (type secp521r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (secp521r1-fe-zero)))
    (dotimes (i 9 r)
      (setf (aref r i) (aref a i)))))

(declaim (inline secp521r1-fe-add secp521r1-fe-sub secp521r1-fe-mul
                         secp521r1-fe-sq secp521r1-fe-mul-buf
                         secp521r1-fe-sq-buf))

(defun secp521r1-fe-add (r a b)
  "R := (A + B) mod P, all reduced residues in Montgomery form."
  (declare (type secp521r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (secp521r1-fe-add-asm r a b)
    r)
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (let ((v (secp521r1-addmod (secp521r1-fe-to-int a)
                               (secp521r1-fe-to-int b))))
      (let ((mont (secp521r1-fe-from-int v)))
        (dotimes (i 9 r)
          (setf (aref r i) (aref mont i)))))))

(defun secp521r1-fe-sub (r a b)
  "R := (A - B) mod P, all reduced residues in Montgomery form."
  (declare (type secp521r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (secp521r1-fe-sub-asm r a b)
    r)
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (let ((v (secp521r1-submod (secp521r1-fe-to-int a)
                               (secp521r1-fe-to-int b))))
      (let ((mont (secp521r1-fe-from-int v)))
        (dotimes (i 9 r)
          (setf (aref r i) (aref mont i)))))))

(defun secp521r1-fe-mont-mul (r a b c)
  "R := A * B * R^-1 mod P, with C a scratch of nineteen 64-bit words."
  (declare (type secp521r1-fe r a b)
           (type (simple-array (unsigned-byte 64) (*)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (if (and (adx-supported-p) (bmi2-supported-p))
        (mont-mul-9-cios-mulx-asm r a b +secp521r1-modulus-limbs+
                                  +secp521r1-n0+ c)
        (mont-mul-9-asm r a b +secp521r1-modulus-limbs+ +secp521r1-n0+ c))
    r)
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (let ((v (secp521r1-mulmod (secp521r1-fe-to-int a)
                               (secp521r1-fe-to-int b))))
      ;; Back to Montgomery form.
      (let ((mont (secp521r1-fe-from-int v)))
        (dotimes (i 9 r)
          (setf (aref r i) (aref mont i)))))))

(defun secp521r1-fe-mul (r a b)
  "R := A * B in Montgomery form, allocating the scratch."
  (declare (type secp521r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((c (make-array 19 :element-type '(unsigned-byte 64)
                       :initial-element 0)))
    ;; NB: the scratch must stay in the heap.  The assembly multiply
    ;; assumes the usual heap layout of a simple vector.
    (secp521r1-fe-mont-mul r a b c)
    r))

(defun secp521r1-fe-mul-buf (r a b c)
  "R := A * B in Montgomery form, using the scratch C.  C holds
nineteen 64-bit words; the caller reuses it, so a multiply inside a
point operation allocates nothing."
  (declare (type secp521r1-fe r a b)
           (type (simple-array (unsigned-byte 64) (*)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp521r1-fe-mont-mul r a b c)
  r)

(defun secp521r1-fe-sq (r a)
  "R := A^2 in Montgomery form, allocating the scratch."
  (declare (type secp521r1-fe r a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp521r1-fe-mul r a a))

(defun secp521r1-fe-sq-buf (r a c)
  "R := A^2 in Montgomery form, using the scratch C."
  (declare (type secp521r1-fe r a)
           (type (simple-array (unsigned-byte 64) (*)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp521r1-fe-mul-buf r a a c)
  r)

(defun secp521r1-fe-equal (a b)
  "Whether the field elements A and B hold the same residue."
  (declare (type secp521r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 9 t)
    (unless (= (aref a i) (aref b i))
      (return nil))))

(defun secp521r1-fe-is-zero (a)
  "Whether the field element A is zero."
  (declare (type secp521r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 9 t)
    (unless (zerop (aref a i))
      (return nil))))

(defun secp521r1-fe-inv (r a)
  "R := A^-1 mod P, in Montgomery form.  A must be nonzero."
  (declare (type secp521r1-fe r a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; Fermat: A^(P-2), binary square-and-multiply in Montgomery form.
  ;; The addition chain in EC-SCALAR-INV does fewer multiplies; this
  ;; straightforward version validates the field layer first.
  (let ((acc (secp521r1-fe-from-int 1))
        (base (secp521r1-fe-copy a))
        (e (- +secp521r1-p+ 2))
        (c (make-array 19 :element-type '(unsigned-byte 64)
                       :initial-element 0)))
    (declare (type integer e)
             (type secp521r1-fe acc base)
             (type (simple-array (unsigned-byte 64) (*)) c))
    ;; Binary square-and-multiply, msb to lsb.
    (loop for i of-type fixnum downfrom (1- (integer-length e)) to 0 do
      (secp521r1-fe-mont-mul acc acc acc c)
      (when (logbitp i e)
        (secp521r1-fe-mont-mul acc acc base c)))
    (dotimes (i 9 r)
      (setf (aref r i) (aref acc i)))))

(defun secp521r1-fe-copy! (dst src)
  "Copy field element SRC into DST."
  (declare (type secp521r1-fe dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (aref dst 0) (aref src 0)
        (aref dst 1) (aref src 1)
        (aref dst 2) (aref src 2)
        (aref dst 3) (aref src 3)
        (aref dst 4) (aref src 4)
        (aref dst 5) (aref src 5)
        (aref dst 6) (aref src 6)
        (aref dst 7) (aref src 7)
        (aref dst 8) (aref src 8))
  dst)

(defstruct (secp521r1-limb-point
            (:constructor %make-secp521r1-limb-point)
            (:copier nil))
  "A P-521 Jacobian point with Montgomery-form limb coordinates."
  (x (secp521r1-fe-zero) :type secp521r1-fe :read-only t)
  (y (secp521r1-fe-zero) :type secp521r1-fe :read-only t)
  (z (secp521r1-fe-zero) :type secp521r1-fe :read-only t))

(defun secp521r1-limb-point (x y z)
  "A limb point from Montgomery field elements (copied in)."
  (declare (type secp521r1-fe x y z)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((p (%make-secp521r1-limb-point)))
    (secp521r1-fe-copy! (secp521r1-limb-point-x p) x)
    (secp521r1-fe-copy! (secp521r1-limb-point-y p) y)
    (secp521r1-fe-copy! (secp521r1-limb-point-z p) z)
    p))

(defun secp521r1-point-copy! (dst src)
  "Copy limb point SRC into DST."
  (declare (type secp521r1-limb-point dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp521r1-fe-copy! (secp521r1-limb-point-x dst) (secp521r1-limb-point-x src))
  (secp521r1-fe-copy! (secp521r1-limb-point-y dst) (secp521r1-limb-point-y src))
  (secp521r1-fe-copy! (secp521r1-limb-point-z dst) (secp521r1-limb-point-z src))
  dst)

(defun secp521r1-point-set-inf! (dst)
  "Set DST to the point at infinity (1, 1, 0)."
  (declare (type secp521r1-limb-point dst)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x (secp521r1-limb-point-x dst))
        (y (secp521r1-limb-point-y dst))
        (z (secp521r1-limb-point-z dst)))
    (declare (type secp521r1-fe x y z))
    (dotimes (i 9)
      (setf (aref x i) 0
            (aref y i) 0
            (aref z i) 0))
    ;; One in Montgomery form is R mod P = 2^55.
    (setf (aref x 0) +secp521r1-r-mod-p+
          (aref y 0) +secp521r1-r-mod-p+))
  dst)

(defun secp521r1-limb-point-from-ints (x y z)
  "A limb point from integer residues."
  (declare (type integer x y z)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp521r1-limb-point (secp521r1-fe-from-int x)
                        (secp521r1-fe-from-int y)
                        (secp521r1-fe-from-int z)))

(defun secp521r1-make-scratch ()
  "A fresh scratch pool for the limb point operations: forty field
elements plus the 19-word product buffer, so the point operations
allocate nothing."
  (let ((s (make-array 41)))
    (dotimes (i 40 s)
      (setf (svref s i) (secp521r1-fe-zero)))
    (setf (svref s 40)
          (make-array 19 :element-type '(unsigned-byte 64)
                      :initial-element 0))
    s))

(defun secp521r1-point-double! (dx dy dz x1 y1 z1 s)
  "DX:DY:DZ := 2*X1:Y1:Z1 reusing scratch pool S. DST must differ from SRC."
  (declare (type secp521r1-fe dx dy dz x1 y1 z1)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((xx (svref s 0))
        (yy (svref s 1))
        (yyyy (svref s 2))
        (zz (svref s 3))
        (x1+yy (svref s 4))
        (y1+z1 (svref s 5))
        (s2 (svref s 6))
        (ss (svref s 7))
        (m1 (svref s 8))
        (mm (svref s 9))
        (uu (svref s 10))
        (y2yyyy (svref s 11))
        (y4yyyy (svref s 12))
        (y2 (svref s 13))
        (z2 (svref s 14))
        (cbuf (svref s 40)))
    (declare (type secp521r1-fe x1 y1 z1 xx yy yyyy zz x1+yy y1+z1
                               s2 ss m1 mm uu y2yyyy y4yyyy y2 z2))
    (if (secp521r1-fe-is-zero z1)
        ;; Infinity is all-zero limbs (Z = 0).
        (progn
          (dotimes (i 9)
            (setf (aref dx i) 0
                  (aref dy i) 0
                  (aref dz i) 0))
          (values dx dy dz))
        (progn
          (secp521r1-fe-sq-buf xx x1 cbuf)
          (secp521r1-fe-sq-buf yy y1 cbuf)
          (secp521r1-fe-sq-buf yyyy yy cbuf)
          (secp521r1-fe-sq-buf zz z1 cbuf)
          (secp521r1-fe-add x1+yy x1 yy)
          (secp521r1-fe-add y1+z1 y1 z1)
          ;; s = 2*((x1+yy)^2 - xx - yyyy).
          (secp521r1-fe-mul-buf s2 x1+yy x1+yy cbuf)
          (secp521r1-fe-sub s2 s2 xx)
          (secp521r1-fe-sub s2 s2 yyyy)
          (secp521r1-fe-add ss s2 s2)
          ;; m = 3*(xx - zz^2).
          (secp521r1-fe-mul-buf m1 zz zz cbuf)
          (secp521r1-fe-sub m1 xx m1)
          (secp521r1-fe-add mm m1 m1)
          (secp521r1-fe-add mm mm m1)
          ;; u = m^2 - 2*s; x2 = u.
          (secp521r1-fe-mul-buf uu mm mm cbuf)
          (secp521r1-fe-sub uu uu ss)
          (secp521r1-fe-sub uu uu ss)
          (secp521r1-fe-copy! dx uu)
            ;; y2 = m*(s-u) - 8*yyyy.
            (secp521r1-fe-sub y2 ss uu)
            (secp521r1-fe-mul-buf y2 mm y2 cbuf)
            (secp521r1-fe-add y2yyyy yyyy yyyy)
            (secp521r1-fe-add y4yyyy y2yyyy y2yyyy)
            (secp521r1-fe-add y4yyyy y4yyyy y4yyyy)
            (secp521r1-fe-sub y2 y2 y4yyyy)
            (secp521r1-fe-copy! dy y2)
            ;; z2 = (y1+z1)^2 - yy - zz.
            (secp521r1-fe-mul-buf z2 y1+z1 y1+z1 cbuf)
            (secp521r1-fe-sub z2 z2 yy)
            (secp521r1-fe-sub z2 z2 zz)
            (secp521r1-fe-copy! dz z2)
            (values dx dy dz)))))

(defun secp521r1-point-add! (dx dy dz x1 y1 z1 x2 y2 z2 s)
  "DX:DY:DZ := X1:Y1:Z1 + X2:Y2:Z2 reusing scratch pool S.
DST must differ from both inputs."
  (declare (type secp521r1-fe dx dy dz x1 y1 z1 x2 y2 z2)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((z1z1 (svref s 0))
        (z2z2 (svref s 1))
        (u1 (svref s 2))
        (u2 (svref s 3))
        (s1 (svref s 4))
        (s2 (svref s 5))
        (h (svref s 6))
        (hh (svref s 7))
        (hh2 (svref s 8))
        (ii (svref s 9))
        (jj (svref s 10))
        (s2-s1 (svref s 11))
        (rr (svref s 12))
        (r2 (svref s 24))
        (vv (svref s 13))
        (vv2 (svref s 14))
        (x3 (svref s 15))
        (rvx (svref s 16))
        (y3 (svref s 17))
        (s1d (svref s 18))
        (t2 (svref s 19))
        (z1+z2 (svref s 20))
        (d1 (svref s 21))
        (d2 (svref s 22))
        (z3 (svref s 23))
        (cbuf (svref s 40)))
    (declare (type secp521r1-fe z1z1 z2z2 u1 u2 s1 s2 h hh hh2 ii jj
                               s2-s1 rr r2 vv vv2 x3 rvx y3 s1d t2
                               z1+z2 d1 d2 z3))
    (cond ((secp521r1-fe-is-zero z1)
           (secp521r1-fe-copy! dx x2)
           (secp521r1-fe-copy! dy y2)
           (secp521r1-fe-copy! dz z2)
           (values dx dy dz))
          ((secp521r1-fe-is-zero z2)
           (secp521r1-fe-copy! dx x1)
           (secp521r1-fe-copy! dy y1)
           (secp521r1-fe-copy! dz z1)
           (values dx dy dz))
          (t
           (secp521r1-fe-mul-buf z1z1 z1 z1 cbuf)
           (secp521r1-fe-mul-buf z2z2 z2 z2 cbuf)
           (secp521r1-fe-mul-buf u1 x1 z2z2 cbuf)
           (secp521r1-fe-mul-buf u2 x2 z1z1 cbuf)
           (secp521r1-fe-mul-buf s1 y1 z2 cbuf)
           (secp521r1-fe-mul-buf s1 s1 z2z2 cbuf)
           (secp521r1-fe-mul-buf s2 y2 z1 cbuf)
           (secp521r1-fe-mul-buf s2 s2 z1z1 cbuf)
           (if (secp521r1-fe-equal u1 u2)
               (if (secp521r1-fe-equal s1 s2)
                   (secp521r1-point-double! dx dy dz x1 y1 z1 s)
                   (progn
                     (dotimes (i 9)
                       (setf (aref dx i) 0
                             (aref dy i) 0
                             (aref dz i) 0))
                     (values dx dy dz)))
               (progn
                 (secp521r1-fe-sub h u2 u1)
                 (secp521r1-fe-mul-buf hh h h cbuf)
                 (secp521r1-fe-add hh2 hh hh)
                 (secp521r1-fe-add ii hh2 hh2)
                 (secp521r1-fe-mul-buf jj h ii cbuf)
                 (secp521r1-fe-sub s2-s1 s2 s1)
                 (secp521r1-fe-add rr s2-s1 s2-s1)
                 (secp521r1-fe-mul-buf vv u1 ii cbuf)
                 (secp521r1-fe-mul-buf r2 rr rr cbuf)
                 (secp521r1-fe-add vv2 vv vv)
                 (secp521r1-fe-sub x3 r2 jj)
                 (secp521r1-fe-sub x3 x3 vv2)
                 (secp521r1-fe-copy! dx x3)
                 (secp521r1-fe-sub rvx vv x3)
                 (secp521r1-fe-add s1d s1 s1)
                 (secp521r1-fe-mul-buf t2 s1d jj cbuf)
                 (secp521r1-fe-mul-buf y3 rr rvx cbuf)
                 (secp521r1-fe-sub y3 y3 t2)
                 (secp521r1-fe-copy! dy y3)
                 (secp521r1-fe-add z1+z2 z1 z2)
                 (secp521r1-fe-mul-buf d1 z1+z2 z1+z2 cbuf)
                 (secp521r1-fe-sub d1 d1 z1z1)
                 (secp521r1-fe-sub d2 d1 z2z2)
                 (secp521r1-fe-mul-buf z3 d2 h cbuf)
                 (secp521r1-fe-copy! dz z3)
                 (values dx dy dz)))))))

(defun secp521r1-make-window-table-limbs (bx by bz)
  "The table V * (BX:BY:BZ) for V in [0, 32), as vectors of three
Montgomery limb arrays.  Entry 0 is infinity (0, R, R)."
  (declare (type secp521r1-fe bx by bz)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((tabl (make-array 32))
        (sc (secp521r1-make-scratch)))
    (declare (type simple-vector tabl sc))
    (let ((zero (secp521r1-fe-zero))
          (one (secp521r1-fe-from-int 1)))
      (setf (aref tabl 0) (vector (secp521r1-fe-copy zero)
                                  (secp521r1-fe-copy one)
                                  (secp521r1-fe-copy one)))
      (setf (aref tabl 1) (vector (secp521r1-fe-copy bx)
                                  (secp521r1-fe-copy by)
                                  (secp521r1-fe-copy bz))))
    (loop for v of-type fixnum from 2 below 32 do
      (let ((dx (secp521r1-fe-zero))
            (dy (secp521r1-fe-zero))
            (dz (secp521r1-fe-zero)))
        (declare (type secp521r1-fe dx dy dz))
        (if (evenp v)
            (let ((e (aref tabl (ash v -1))))
              (declare (type simple-vector e))
              (secp521r1-point-double! dx dy dz
                                       (aref e 0) (aref e 1) (aref e 2) sc))
            (let ((e (aref tabl (1- v))))
              (declare (type simple-vector e))
              (secp521r1-point-add! dx dy dz
                                    (aref e 0) (aref e 1) (aref e 2)
                                    bx by bz sc)))
        (setf (aref tabl v) (vector dx dy dz))))
    tabl))

(defun secp521r1-shamir-mult-limbs (px py pz qx qy qz a b)
  "A * P + B * Q in the limb field, public only, five-bit windows.  All
coordinates are Montgomery field elements; the result is integers."
  (declare (type secp521r1-fe px py pz qx qy qz)
           (type integer a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((w 5)
         (abit (integer-length a))
         (bbit (integer-length b))
         (bits (max abit bbit 1))
         (nwin (ceiling bits w))
         (tp (secp521r1-make-window-table-limbs px py pz))
         (tq (secp521r1-make-window-table-limbs qx qy qz))
         (s (secp521r1-make-scratch))
         (rx (secp521r1-fe-zero))
         (ry (secp521r1-fe-zero))
         (rz (secp521r1-fe-zero))
         (tx (secp521r1-fe-zero))
         (ty (secp521r1-fe-zero))
         (tz (secp521r1-fe-zero)))
    (declare (type fixnum w abit bbit bits nwin)
             (type simple-vector tp tq s)
             (type secp521r1-fe rx ry rz tx ty tz))
    ;; Accumulator starts at infinity (all-zero limbs).
    (loop for wi of-type fixnum downfrom (1- nwin) to 0 do
      (unless (= wi (1- nwin))
        (dotimes (i w)
          (declare (ignore i))
          (secp521r1-point-double! tx ty tz rx ry rz s)
          (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))
      (let* ((shift (* wi w))
             (va (if (< shift abit) (ldb (byte w shift) a) 0))
             (vb (if (< shift bbit) (ldb (byte w shift) b) 0)))
        (declare (type fixnum shift)
                 (type (unsigned-byte 5) va vb))
        (unless (zerop va)
          (let ((e (aref tp va)))
            (declare (type simple-vector e))
            (secp521r1-point-add! tx ty tz rx ry rz
                                  (aref e 0) (aref e 1) (aref e 2) s)
            (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))
        (unless (zerop vb)
          (let ((e (aref tq vb)))
            (declare (type simple-vector e))
            (secp521r1-point-add! tx ty tz rx ry rz
                                  (aref e 0) (aref e 1) (aref e 2) s)
            (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))))
    (list (secp521r1-fe-to-int rx)
          (secp521r1-fe-to-int ry)
          (secp521r1-fe-to-int rz))))

(defvar *secp521r1-limb-base-table* nil
  "Positional limb table ROWS[J][V] = V * 256^J * G, built on first use
by converting the bignum positional table.")

(defun secp521r1-ensure-limb-base-table ()
  "The cached limb positional table for the generator."
  (or *secp521r1-limb-base-table*
      (let ((bignum-table (secp521r1-ensure-base-table))
            (limb-table (make-array 66)))
        (declare (type simple-vector bignum-table limb-table))
        (dotimes (j 66 limb-table)
          (declare (type fixnum j))
          (let ((brow (aref bignum-table j))
                (lrow (make-array 256)))
            (declare (type simple-vector brow lrow))
            (dotimes (v 256)
              (let ((p (aref brow v)))
                (declare (type secp521r1-point p))
                (setf (aref lrow v)
                      (vector (secp521r1-fe-from-int (slot-value p 'x))
                              (secp521r1-fe-from-int (slot-value p 'y))
                              (secp521r1-fe-from-int (slot-value p 'z))))))
            (setf (aref limb-table j) lrow)))
        (setf *secp521r1-limb-base-table* limb-table))))

(declaim (inline secp521r1-select-limb-base))
(defun secp521r1-select-limb-base (table v)
  "Select index V from the limb positional table.  Linear scan over all
256 entries of the row, so the memory access pattern does not depend
on V."
  (declare (type simple-vector table)
           (type (unsigned-byte 8) v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((sel (aref table 0)))
    (dotimes (i 256 sel)
      (when (= i v)
        (setf sel (aref table i))))))

(defun secp521r1-base-mult-limbs (k)
  "Fixed-base multiplication K*G via the limb positional table: 66
additions and no doublings.  Returns three Montgomery limbs."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  (let ((table (secp521r1-ensure-limb-base-table))
        (acc (vector (secp521r1-fe-zero) (secp521r1-fe-zero) (secp521r1-fe-zero)))
        (tx (secp521r1-fe-zero))
        (ty (secp521r1-fe-zero))
        (tz (secp521r1-fe-zero))
        (s (secp521r1-make-scratch)))
    (declare (type simple-vector table acc)
             (type secp521r1-fe tx ty tz)
             (type simple-vector s))
    (loop for j of-type fixnum from 65 downto 0 do
      (let ((v (ldb (byte 8 (* j 8)) k)))
        (declare (type (unsigned-byte 8) v))
        (unless (zerop v)
          (let ((sel (secp521r1-select-limb-base (aref table j) v)))
            (declare (type simple-vector sel))
            (secp521r1-point-add! tx ty tz
                                  (aref acc 0) (aref acc 1) (aref acc 2)
                                  (aref sel 0) (aref sel 1) (aref sel 2) s)
            (rotatef (aref acc 0) tx)
            (rotatef (aref acc 1) ty)
            (rotatef (aref acc 2) tz)))))
    (values (aref acc 0) (aref acc 1) (aref acc 2))))

(defmethod ec-scalar-inv ((kind (eql :secp521r1)) n)
  "The inverse of N modulo the prime of P-521, via the reference
addition chain (ecp_nistp521.c), far fewer multiplications than Fermat."
  (declare (type integer n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((ftmp 0) (ftmp2 0) (ftmp3 0) (ftmp4 0))
    (declare (type integer ftmp ftmp2 ftmp3 ftmp4))
    (setf ftmp (secp521r1-mulmod n n))
    (setf ftmp (secp521r1-mulmod n ftmp))
    (setf ftmp2 ftmp)
    (setf ftmp (secp521r1-mulmod ftmp ftmp))
    (setf ftmp (secp521r1-mulmod n ftmp))
    (setf ftmp (secp521r1-mulmod ftmp ftmp))
    (setf ftmp3 (secp521r1-mulmod ftmp2 ftmp2))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp2))
    (setf ftmp2 ftmp3)
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3))
    (setf ftmp4 (secp521r1-mulmod ftmp3 ftmp))
    (setf ftmp4 (secp521r1-mulmod ftmp4 ftmp4))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp2))
    (setf ftmp2 ftmp3)
    (dotimes (i 8) (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3)))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp2))
    (setf ftmp2 ftmp3)
    (dotimes (i 16) (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3)))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp2))
    (setf ftmp2 ftmp3)
    (dotimes (i 32) (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3)))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp2))
    (setf ftmp2 ftmp3)
    (dotimes (i 64) (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3)))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp2))
    (setf ftmp2 ftmp3)
    (dotimes (i 128) (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3)))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp2))
    (setf ftmp2 ftmp3)
    (dotimes (i 256) (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3)))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp2))
    (dotimes (i 9) (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp3)))
    (setf ftmp3 (secp521r1-mulmod ftmp3 ftmp4))
    (setf ftmp3 (secp521r1-mulmod ftmp3 n))
    ftmp3))

(defmethod ec-point-equal ((p secp521r1-point) (q secp521r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (let ((z1z1 (secp521r1-mulmod z1 z1))
            (z2z2 (secp521r1-mulmod z2 z2)))
        (and (zerop (secp521r1-submod
                     (secp521r1-mulmod x1 z2z2)
                     (secp521r1-mulmod x2 z1z1)))
             (zerop (secp521r1-submod
                     (secp521r1-mulmod (secp521r1-mulmod y1 z2) z2z2)
                     (secp521r1-mulmod (secp521r1-mulmod y2 z1) z1z1))))))))

(defmethod ec-double ((p secp521r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (if (zerop z1)
        +secp521r1-point-at-infinity+
        (let* ((xx (secp521r1-mulmod x1 x1))
               (yy (secp521r1-mulmod y1 y1))
               (yyyy (secp521r1-mulmod yy yy))
               (zz (secp521r1-mulmod z1 z1))
               (x1+yy (secp521r1-addmod x1 yy))
               (y1+z1 (secp521r1-addmod y1 z1))
               (s0 (secp521r1-submod
                    (secp521r1-submod (secp521r1-mulmod x1+yy x1+yy) xx) yyyy))
               (s (secp521r1-dblmod s0))
               (m0 (secp521r1-submod xx (secp521r1-mulmod zz zz)))
               (m (secp521r1-addmod (secp521r1-dblmod m0) m0))
               (u (secp521r1-submod
                   (secp521r1-mulmod m m) (secp521r1-dblmod s)))
               (x2 u)
               (y2 (secp521r1-submod
                    (secp521r1-mulmod m (secp521r1-submod s u))
                    (secp521r1-mulmod 8 yyyy)))
               (z2 (secp521r1-submod
                    (secp521r1-submod (secp521r1-mulmod y1+z1 y1+z1) yy) zz)))
          (make-instance 'secp521r1-point :x x2 :y y2 :z z2)))))

(defmethod ec-add ((p secp521r1-point) (q secp521r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (cond
        ((zerop z1)
         q)
        ((zerop z2)
         p)
        (t
         (let* ((z1z1 (secp521r1-mulmod z1 z1))
                (z2z2 (secp521r1-mulmod z2 z2))
                (u1 (secp521r1-mulmod x1 z2z2))
                (u2 (secp521r1-mulmod x2 z1z1))
                (s1 (secp521r1-mulmod (secp521r1-mulmod y1 z2) z2z2))
                (s2 (secp521r1-mulmod (secp521r1-mulmod y2 z1) z1z1)))
           (if (= u1 u2)
               (if (= s1 s2)
                   (ec-double p)
                   +secp521r1-point-at-infinity+)
                (let* ((h (secp521r1-submod u2 u1))
                       (i (secp521r1-mulmod 4 (secp521r1-mulmod h h)))
                       (j (secp521r1-mulmod h i))
                       (r (secp521r1-dblmod (secp521r1-submod s2 s1)))
                       (v (secp521r1-mulmod u1 i))
                       (x3 (secp521r1-submod
                            (secp521r1-submod (secp521r1-mulmod r r) j)
                            (secp521r1-dblmod v)))
                       (y3 (secp521r1-submod
                            (secp521r1-mulmod r (secp521r1-submod v x3))
                            (secp521r1-dblmod (secp521r1-mulmod s1 j))))
                       (z1+z2 (secp521r1-addmod z1 z2))
                       (z3 (secp521r1-mulmod
                            (secp521r1-submod
                             (secp521r1-submod
                              (secp521r1-mulmod z1+z2 z1+z2) z1z1) z2z2) h)))
                 (make-instance 'secp521r1-point :x x3 :y y3 :z z3)))))))))


;;; Fixed-base positional table for the generator point.
;;;
;;; SIGN-MESSAGE and key generation always multiply G by a secret scalar.
;;; Row J holds V * 256^J * G for V in [0, 256), so a multiplication is
;;; 66 additions and no doublings (instead of the ladder's ~260 adds and
;;; 520 doublings, or a standard window's 66 adds and 528 doublings).
;;; The selection scans all 256 entries of a row, so the memory pattern
;;; does not depend on the secret scalar.
;;;
;;; The table is built lazily on first use: 66 rows of 256 points.

(defvar *secp521r1-base-table* nil
  "Positional table ROWS[J][V] = V * 256^J * G. Built on first use.")

(defun secp521r1-ensure-base-table ()
  (or *secp521r1-base-table*
      (setf *secp521r1-base-table*
            (let ((rows (make-array 66))
                  (base +secp521r1-g+))
              (dotimes (j 66 rows)
                (declare (type fixnum j))
                (let ((row (make-array 256)))
                  (setf (aref row 0) +secp521r1-point-at-infinity+
                        (aref row 1) base)
                  (loop for v of-type fixnum from 2 below 256 do
                    (setf (aref row v)
                          (if (evenp v)
                              (ec-double (aref row (ash v -1)))
                              (ec-add (aref row (1- v)) base))))
                  (setf (aref rows j) row)
                  ;; base := 256 * base for the next row.
                  (dotimes (i 8)
                    (declare (ignore i))
                    (setf base (ec-double base)))))))))

(declaim (inline secp521r1-select-base))
(defun secp521r1-select-base (row v)
  "Select index V from the positional-table ROW.  Linear scan over all
256 entries, so the memory access pattern does not depend on V."
  (declare (type simple-vector row)
           (type (unsigned-byte 8) v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((sel (aref row 0)))
    (dotimes (i 256 sel)
      (when (= i v)
        (setf sel (aref row i))))))

(defun secp521r1-base-mult (k)
  "Fixed-base multiplication K*G via the positional byte table: 66
additions and no doublings."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  (let ((table (secp521r1-ensure-base-table))
        (acc +secp521r1-point-at-infinity+))
    (declare (type simple-vector table))
    (loop for j of-type fixnum from 65 downto 0 do
      (let ((v (ldb (byte 8 (* j 8)) k)))
        (declare (type (unsigned-byte 8) v))
        (unless (zerop v)
          (setf acc (ec-add acc (secp521r1-select-base (aref table j) v))))))
    acc))

(defmethod ec-scalar-mult ((p secp521r1-point) e)
  ;; Secret scalars use the fixed-schedule ladder.  The generator G uses
  ;; the faster fixed-base comb.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (if (and (eq p +secp521r1-g+) (not (minusp e)))
      (secp521r1-base-mult e)
      (%ec-ladder-mult p e :bits +secp521r1-bits+)))

(defmethod ec-point-on-curve-p ((p secp521r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((y2 (secp521r1-mulmod y y))
           (x2 (secp521r1-mulmod x x))
           (x3 (secp521r1-mulmod x2 x))
           (z2 (secp521r1-mulmod z z))
           (z4 (secp521r1-mulmod z2 z2))
           (z6 (secp521r1-mulmod z4 z2))
           (xz4 (secp521r1-mulmod x z4))
           (a (secp521r1-addmod
               (secp521r1-submod x3 (secp521r1-addmod (secp521r1-dblmod xz4) xz4))
               (secp521r1-mulmod +secp521r1-b+ z6))))
      (declare (type integer y2 x3 z2 z4 z6 a))
      (zerop (secp521r1-submod y2 a)))))

(defmethod ec-make-point ((kind (eql :secp521r1)) &key x y)
  (unless x
    (error 'missing-point-parameter
           :kind 'secp521r1
           :parameter 'x
           :description "coordinate"))
  (unless y
    (error 'missing-point-parameter
           :kind 'secp521r1
           :parameter 'y
           :description "coordinate"))
  (let ((p (make-instance 'secp521r1-point :x x :y y :z 1)))
    (if (ec-point-on-curve-p p)
        p
        (error 'invalid-curve-point :kind 'secp521r1))))

(defmethod ec-destructure-point ((p secp521r1-point))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (when (zerop z)
      (error 'ironclad-unsafe-error
             :format-control "The point at infinity can't be encoded."))
    (let* ((invz (ec-scalar-inv :secp521r1 z))
           (invz2 (secp521r1-mulmod invz invz))
           (invz3 (secp521r1-mulmod invz2 invz))
           (x (secp521r1-mulmod x invz2))
           (y (secp521r1-mulmod y invz3)))
      (list :x x :y y))))

(defmethod ec-encode-scalar ((kind (eql :secp521r1)) n)
  (integer-to-octets n :n-bits +secp521r1-bits+ :big-endian t))

(defmethod ec-decode-scalar ((kind (eql :secp521r1)) octets)
  (octets-to-integer octets :big-endian t))

(defmethod ec-encode-point ((p secp521r1-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x))
         (y (getf coordinates :y)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (vector 4)
                 (ec-encode-scalar :secp521r1 x)
                 (ec-encode-scalar :secp521r1 y))))

(defmethod ec-decode-point ((kind (eql :secp521r1)) octets)
  (case (aref octets 0)
    ((2 3)
     ;; Compressed point
     (if (= (length octets) (1+ (ceiling +secp521r1-bits+ 8)))
         (let* ((x-bytes (subseq octets 1 (1+ (ceiling +secp521r1-bits+ 8))))
                (x (ec-decode-scalar :secp521r1 x-bytes))
                (y-sign (- (aref octets 0) 2))
                (y2 (secp521r1-reduce (+ (* x x x) (* -3 x) +secp521r1-b+)))
                (y (expt-mod y2 +secp521r1-i+ +secp521r1-p+))
                (y (if (= (logand y 1) y-sign) y (- +secp521r1-p+ y))))
           (ec-make-point :secp521r1 :x x :y y))
         (error 'invalid-curve-point :kind 'secp521r1)))
    ((4)
     ;; Uncompressed point
     (if (= (length octets) (1+ (* 2 (ceiling +secp521r1-bits+ 8))))
         (let* ((x-bytes (subseq octets 1 (1+ (ceiling +secp521r1-bits+ 8))))
                (x (ec-decode-scalar :secp521r1 x-bytes))
                (y-bytes (subseq octets (1+ (ceiling +secp521r1-bits+ 8))))
                (y (ec-decode-scalar :secp521r1 y-bytes)))
           (ec-make-point :secp521r1 :x x :y y))
         (error 'invalid-curve-point :kind 'secp521r1)))
    (t
     (error 'invalid-curve-point :kind 'secp521r1))))

(defun secp521r1-public-key (sk)
  (let ((a (ec-decode-scalar :secp521r1 sk)))
    (ec-encode-point (ec-scalar-mult +secp521r1-g+ a))))

(defmethod make-signature ((kind (eql :secp521r1)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'secp521r1
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'secp521r1
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :secp521r1)) signature)
  (let ((length (length signature)))
    (if (/= length (* 2 (ceiling +secp521r1-bits+ 8)))
        (error 'invalid-signature-length :kind 'secp521r1)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defmethod generate-signature-nonce ((key secp521r1-private-key) message &optional parameters)
  (or *signature-nonce-for-test*
      (rfc6979-generate-k (secp521r1-key-x key)
                          message
                          +secp521r1-l+
                          (integer-length +secp521r1-l+)
                          (ceiling (integer-length +secp521r1-l+) 8)
                          :digest (or parameters *ecdsa-rfc6979-digest*))))

;;; Note that hashing is not performed here.
(defmethod sign-message ((key secp521r1-private-key) message &key (start 0) end (digest *ecdsa-rfc6979-digest*) &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((end (min (or end (length message)) (ceiling +secp521r1-bits+ 8)))
         (sk (ec-decode-scalar :secp521r1 (secp521r1-key-x key)))
         (h (subseq message start end))
         (k (generate-signature-nonce key h digest))
         (invk (modular-inverse-with-blinding k +secp521r1-l+ :prime t)))
    ;; Fixed-base k*G in the limb field: 66 additions, no doublings,
    ;; no bignum allocation inside the loop.  Destructure with the
    ;; bignum addition-chain inverse.
    (multiple-value-bind (rx ry rz) (secp521r1-base-mult-limbs k)
      (declare (ignore ry))
      (if (zerop (secp521r1-fe-to-int rz))
          (sign-message key message :start start :end end)
          (let* ((ix (secp521r1-fe-to-int rx))
                 (iz (secp521r1-fe-to-int rz))
                 (invz (ec-scalar-inv :secp521r1 iz))
                 (x (secp521r1-mulmod ix (secp521r1-mulmod invz invz)))
                 (r (mod x +secp521r1-l+))
                 (e (ec-decode-scalar :secp521r1 h))
                 (s (mod (* invk (+ e (* sk r))) +secp521r1-l+)))
            (if (not (or (zerop r) (zerop s)))
                (make-signature :secp521r1
                                :r (ec-encode-scalar :secp521r1 r)
                                :s (ec-encode-scalar :secp521r1 s))
                (sign-message key message :start start :end end)))))))

;;; Windowed joint multiplication for verification.
;;;
;;; The plain Shamir trick does one doubled-and-add per set bit of either
;;; scalar, which is about 390 additions for two 521-bit scalars.  Five-bit
;;; windows use 105 windows with at most two additions each, and a
;;; thirty-two entry table for each base.  The generator's table is
;;; fixed and built once; the other base is public (the public key), so
;;; both tables are built without regard to timing.

(defun secp521r1-make-window-table (p)
  "The table V * P for V in [0, 32), built from doubles and adds."
  (declare (type secp521r1-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (make-array 32)))
    (setf (aref table 0) +secp521r1-point-at-infinity+
          (aref table 1) p)
    (loop for v of-type fixnum from 2 below 32 do
      (setf (aref table v)
            (if (evenp v)
                (ec-double (aref table (ash v -1)))
                (ec-add (aref table (1- v)) p))))
    table))

(defun secp521r1-shamir-mult (p q a b)
  "A * P + B * Q, public only, with five-bit windows."
  (declare (type secp521r1-point p q)
           (type integer a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((w 5)
         (abit (integer-length a))
         (bbit (integer-length b))
         (bits (max abit bbit 1))
         (nwin (ceiling bits w))
         ;; Row 0 of the positional table is V*G for V in [0, 256),
         ;; so its first 32 entries serve the five-bit windows directly.
         (tp (if (eq p +secp521r1-g+)
                 (aref (secp521r1-ensure-base-table) 0)
                 (secp521r1-make-window-table p)))
         (tq (secp521r1-make-window-table q))
         (acc +secp521r1-point-at-infinity+))
    (declare (type fixnum w abit bbit bits nwin)
             (type simple-vector tp tq))
    (loop for wi of-type fixnum downfrom (1- nwin) to 0 do
      (unless (= wi (1- nwin))
        (dotimes (i w)
          (declare (ignore i))
          (setf acc (ec-double acc))))
      (let* ((shift (* wi w))
             (va (if (< shift abit) (ldb (byte w shift) a) 0))
             (vb (if (< shift bbit) (ldb (byte w shift) b) 0)))
        (declare (type fixnum shift)
                 (type (unsigned-byte 5) va vb))
        (unless (zerop va) (setf acc (ec-add acc (aref tp va))))
        (unless (zerop vb) (setf acc (ec-add acc (aref tq vb))))))
    acc))

(defvar *secp521r1-limb-g-table* nil
  "32-entry limb window table V*G for five-bit windows. Built on first use.")

(defun secp521r1-ensure-limb-g-table ()
  "The cached limb window table for the generator."
  (or *secp521r1-limb-g-table*
      (setf *secp521r1-limb-g-table*
            (let ((gx (slot-value +secp521r1-g+ 'x))
                  (gy (slot-value +secp521r1-g+ 'y))
                  (gz (slot-value +secp521r1-g+ 'z)))
              (declare (type integer gx gy gz))
              (secp521r1-make-window-table-limbs (secp521r1-fe-from-int gx)
                                                 (secp521r1-fe-from-int gy)
                                                 (secp521r1-fe-from-int gz))))))

(defun secp521r1-shamir-mult-limbs-cached (qx qy qz a b &optional tq)
  "A * G + B * Q in the limb field, using the cached G table.
TQ, when given, is a previously built window table for Q."
  (declare (type secp521r1-fe qx qy qz)
           (type integer a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((w 5)
         (abit (integer-length a))
         (bbit (integer-length b))
         (bits (max abit bbit 1))
         (nwin (ceiling bits w))
         (tp (secp521r1-ensure-limb-g-table))
         (tq (or tq (secp521r1-make-window-table-limbs qx qy qz)))
         (s (secp521r1-make-scratch))
         (rx (secp521r1-fe-zero))
         (ry (secp521r1-fe-zero))
         (rz (secp521r1-fe-zero))
         (tx (secp521r1-fe-zero))
         (ty (secp521r1-fe-zero))
         (tz (secp521r1-fe-zero)))
    (declare (type fixnum w abit bbit bits nwin)
             (type simple-vector tp tq s)
             (type secp521r1-fe rx ry rz tx ty tz))
    (loop for wi of-type fixnum downfrom (1- nwin) to 0 do
      (unless (= wi (1- nwin))
        (dotimes (i w)
          (declare (ignore i))
          (secp521r1-point-double! tx ty tz rx ry rz s)
          (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))
      (let* ((shift (* wi w))
             (va (if (< shift abit) (ldb (byte w shift) a) 0))
             (vb (if (< shift bbit) (ldb (byte w shift) b) 0)))
        (declare (type fixnum shift)
                 (type (unsigned-byte 5) va vb))
        (unless (zerop va)
          (let ((e (aref tp va)))
            (declare (type simple-vector e))
            (secp521r1-point-add! tx ty tz rx ry rz
                                  (aref e 0) (aref e 1) (aref e 2) s)
            (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))
        (unless (zerop vb)
          (let ((e (aref tq vb)))
            (declare (type simple-vector e))
            (secp521r1-point-add! tx ty tz rx ry rz
                                  (aref e 0) (aref e 1) (aref e 2) s)
            (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))))
    (list (secp521r1-fe-to-int rx)
          (secp521r1-fe-to-int ry)
          (secp521r1-fe-to-int rz))))

(defmethod verify-signature ((key secp521r1-public-key) message signature &key (start 0) end &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length signature) (* 2 (ceiling +secp521r1-bits+ 8)))
    (error 'invalid-signature-length :kind 'secp521r1))
  (let* ((end (min (or end (length message)) (ceiling +secp521r1-bits+ 8)))
         (pk (ec-decode-point :secp521r1 (secp521r1-key-y key)))
         (signature-elements (destructure-signature :secp521r1 signature))
         (r (ec-decode-scalar :secp521r1 (getf signature-elements :r)))
         (s (ec-decode-scalar :secp521r1 (getf signature-elements :s))))
    ;; Degenerate (r = 0 or s = 0) signatures are invalid; answer NIL
    ;; before the W/RP computations, which assume nonzero operands.
    (unless (and (< 0 r +secp521r1-l+) (< 0 s +secp521r1-l+))
      (return-from verify-signature nil))
    (let* ((h (subseq message start end))
         (e (ec-decode-scalar :secp521r1 h))
         (w (modular-inverse-with-blinding s +secp521r1-l+ :prime t))
         (u1 (mod (* e w) +secp521r1-l+))
         (u2 (mod (* r w) +secp521r1-l+))
         ;; Joint multiplication in the limb field: one pass instead
         ;; of two, no bignum allocation inside the loop.
         (qx (slot-value pk 'x))
         (qy (slot-value pk 'y))
         (qz (slot-value pk 'z))
         (tq (or (secp521r1-key-q-table key)
                 (setf (secp521r1-key-q-table key)
                       (secp521r1-make-window-table-limbs
                        (secp521r1-fe-from-int qx)
                        (secp521r1-fe-from-int qy)
                        (secp521r1-fe-from-int qz)))))
         (rp (secp521r1-shamir-mult-limbs-cached (secp521r1-fe-from-int qx)
                                                 (secp521r1-fe-from-int qy)
                                                 (secp521r1-fe-from-int qz)
                                                 u1 u2 tq))
         (rz (third rp)))
      ;; RP is the point at infinity only for invalid signatures.
      (if (zerop rz)
          nil
          (let* ((invz (ec-scalar-inv :secp521r1 rz))
                 (x (secp521r1-mulmod (first rp)
                                      (secp521r1-mulmod invz invz)))
                 (v (mod x +secp521r1-l+)))
            (and (< 0 r +secp521r1-l+)
                 (< 0 s +secp521r1-l+)
                 (= v r)))))))

(defmethod make-public-key ((kind (eql :secp521r1)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'secp521r1
           :parameter 'y
           :description "public key"))
  ;; Reject malformed encodings and off-curve points now, at
  ;; construction time, rather than at first use.
  (ec-decode-point :secp521r1 y)
  (make-instance 'secp521r1-public-key :y y))

(defmethod destructure-public-key ((public-key secp521r1-public-key))
  (list :y (secp521r1-key-y public-key)))

(defmethod make-private-key ((kind (eql :secp521r1)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'secp521r1
           :parameter 'x
           :description "private key"))
  ;; The scalar must lie in [1, N-1]; 0 yields the point at infinity
  ;; and values >= N silently wrap to the wrong public key.
  (unless (< 0 (octets-to-integer x :big-endian t) +secp521r1-l+)
    (error 'invalid-private-key :kind 'secp521r1))
  (make-instance 'secp521r1-private-key :x x :y (or y (secp521r1-public-key x))))

(defmethod destructure-private-key ((private-key secp521r1-private-key))
  (list :x (secp521r1-key-x private-key)
        :y (secp521r1-key-y private-key)))

(defmethod generate-key-pair ((kind (eql :secp521r1)) &key &allow-other-keys)
  (let* ((sk (ec-encode-scalar :secp521r1 (1+ (strong-random (1- +secp521r1-l+)))))
         (pk (secp521r1-public-key sk)))
    (values (make-private-key :secp521r1 :x sk :y pk)
            (make-public-key :secp521r1 :y pk))))

(defmethod diffie-hellman ((private-key secp521r1-private-key) (public-key secp521r1-public-key))
  (let ((s (ec-decode-scalar :secp521r1 (secp521r1-key-x private-key)))
        (p (ec-decode-point :secp521r1 (secp521r1-key-y public-key))))
    (ec-encode-point (ec-scalar-mult p s))))
