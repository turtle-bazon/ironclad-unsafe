;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; secp384r1.lisp -- secp384r1 (a.k.a. NIST P-384) elliptic curve


(in-package :crypto-unsafe)


;;; class definitions

(defclass secp384r1-public-key ()
  ((y :initarg :y :reader secp384r1-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass secp384r1-private-key ()
  ((x :initarg :x :reader secp384r1-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader secp384r1-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass secp384r1-point ()
    ;; Internally, a point (x, y) is represented using the Jacobian projective
    ;; coordinates (X, Y, Z), with x = X / Z^2 and y = Y / Z^3.
    ((x :initarg :x :type integer)
     (y :initarg :y :type integer)
     (z :initarg :z :type integer)))
  (defmethod make-load-form ((p secp384r1-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constant and function definitions

(defconstant +secp384r1-bits+ 384)
(defconstant +secp384r1-p+ 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319)
(defconstant +secp384r1-b+ 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575)
(defconstant +secp384r1-l+ 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643)
(defconstant +secp384r1-i+ 29551504647295859409209280075107710353809804452849085000961220053184291328622652746785449566194203501396205229834239)

(defconst +secp384r1-g+
  (make-instance 'secp384r1-point
                 :x 26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087
                 :y 8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871
                 :z 1))
(defconst +secp384r1-point-at-infinity+
  (make-instance 'secp384r1-point :x 1 :y 1 :z 0))


(defconst +secp384r1-point-at-infinity+
  (make-instance 'secp384r1-point :x 1 :y 1 :z 0))


;;; Limb field for P-384 (six 64-bit words, Montgomery form).
;;;
;;; R = 2^384.  Residues stay in Montgomery form between operations;
;;; conversion happens only at the curve boundary.  Bignum intermediates
;;; never appear inside the hot loop.

(deftype secp384r1-fe () '(simple-array (unsigned-byte 64) (6)))

(defconstant +secp384r1-r-mod-p+ #x100000000ffffffffffffffff00000001
  "R = 2^384 modulo P, i.e. 2^128 + 2^96 - 2^32 + 1.")

(defconstant +secp384r1-r-inv-mod-p+
  #x14000000140000000c00000002fffffffcfffffffafffffffbfffffffdffffffebffffffd8ffffffe100000006
  "R^-1 mod P.")

(defconstant +secp384r1-n0+ #x100000001
  "Montgomery word: -P^-1 mod 2^64.")

(defconst +secp384r1-modulus-limbs+
  (integer-to-limbs64 +secp384r1-p+ 6))
;; The prime as six little-endian 64-bit limbs, for the VOP.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun secp384r1-fe-zero ()
    (make-array 6 :element-type '(unsigned-byte 64) :initial-element 0)))

(defun secp384r1-fe-from-int (n)
  "The Montgomery form of N modulo P."
  (declare (type integer n)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; NB: the limb split is unrolled by hand.  SBCL 2.6.7 miscompiles
  ;; (LDB (BYTE 64 (* I 64)) V) with a variable position at safety 0.
  (let* ((v (mod (* (mod n +secp384r1-p+) +secp384r1-r-mod-p+)
                 +secp384r1-p+))
         (r (secp384r1-fe-zero)))
    (setf (aref r 0) (ldb (byte 64 0) v)
          (aref r 1) (ldb (byte 64 64) v)
          (aref r 2) (ldb (byte 64 128) v)
          (aref r 3) (ldb (byte 64 192) v)
          (aref r 4) (ldb (byte 64 256) v)
          (aref r 5) (ldb (byte 64 320) v))
    r))

(defun secp384r1-fe-to-int (a)
  "The value of the Montgomery field element A, an integer below P."
  (declare (type secp384r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((v (+ (aref a 0)
              (ash (aref a 1) 64)
              (ash (aref a 2) 128)
              (ash (aref a 3) 192)
              (ash (aref a 4) 256)
              (ash (aref a 5) 320))))
    (mod (* v +secp384r1-r-inv-mod-p+) +secp384r1-p+)))

(defun secp384r1-fe-copy (a)
  (declare (type secp384r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((r (secp384r1-fe-zero)))
    (dotimes (i 6 r)
      (setf (aref r i) (aref a i)))))

(declaim (inline secp384r1-fe-add secp384r1-fe-sub secp384r1-fe-mul
                         secp384r1-fe-sq secp384r1-fe-mul-buf
                         secp384r1-fe-sq-buf))

(defun secp384r1-fe-add (r a b)
  "R := (A + B) mod P, all reduced residues in Montgomery form."
  (declare (type secp384r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (secp384r1-fe-add-asm r a b)
    r)
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (let ((v (mod (+ (secp384r1-fe-to-int a) (secp384r1-fe-to-int b))
                  +secp384r1-p+)))
      (let ((mont (secp384r1-fe-from-int v)))
        (dotimes (i 6 r)
          (setf (aref r i) (aref mont i)))))))

(defun secp384r1-fe-sub (r a b)
  "R := (A - B) mod P, all reduced residues in Montgomery form."
  (declare (type secp384r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (secp384r1-fe-sub-asm r a b)
    r)
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (let ((v (mod (- (secp384r1-fe-to-int a) (secp384r1-fe-to-int b))
                  +secp384r1-p+)))
      (let ((mont (secp384r1-fe-from-int v)))
        (dotimes (i 6 r)
          (setf (aref r i) (aref mont i)))))))

(defun secp384r1-fe-mont-mul (r a b c)
  "R := A * B * R^-1 mod P, with C a scratch of thirteen 64-bit words."
  (declare (type secp384r1-fe r a b)
           (type (simple-array (unsigned-byte 64) (*)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  #+(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (mont-mul-6-asm r a b +secp384r1-modulus-limbs+ +secp384r1-n0+ c)
    r)
  #-(and sbcl x86-64 ironclad-unsafe-assembly)
  (progn
    (let ((v (mod (* (secp384r1-fe-to-int a) (secp384r1-fe-to-int b))
                  +secp384r1-p+)))
      (let ((mont (secp384r1-fe-from-int v)))
        (dotimes (i 6 r)
          (setf (aref r i) (aref mont i)))))))

(defun secp384r1-fe-mul (r a b)
  "R := A * B in Montgomery form, allocating the scratch."
  (declare (type secp384r1-fe r a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((c (make-array 13 :element-type '(unsigned-byte 64)
                       :initial-element 0)))
    ;; NB: the scratch must stay in the heap.  The assembly multiply
    ;; assumes the usual heap layout of a simple vector.
    (secp384r1-fe-mont-mul r a b c)
    r))

(defun secp384r1-fe-mul-buf (r a b c)
  "R := A * B in Montgomery form, using the scratch C.  C holds thirteen
64-bit words; the caller reuses it, so a multiply inside a point
operation allocates nothing."
  (declare (type secp384r1-fe r a b)
           (type (simple-array (unsigned-byte 64) (*)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp384r1-fe-mont-mul r a b c)
  r)

(defun secp384r1-fe-sq (r a)
  "R := A^2 in Montgomery form, allocating the scratch."
  (declare (type secp384r1-fe r a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp384r1-fe-mul r a a))

(defun secp384r1-fe-sq-buf (r a c)
  "R := A^2 in Montgomery form, using the scratch C."
  (declare (type secp384r1-fe r a)
           (type (simple-array (unsigned-byte 64) (*)) c)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (secp384r1-fe-mul-buf r a a c)
  r)

(defun secp384r1-fe-equal (a b)
  "Whether the field elements A and B hold the same residue."
  (declare (type secp384r1-fe a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 6 t)
    (unless (= (aref a i) (aref b i))
      (return nil))))

(defun secp384r1-fe-is-zero (a)
  "Whether the field element A is zero."
  (declare (type secp384r1-fe a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 6 t)
    (unless (zerop (aref a i))
      (return nil))))

(defun secp384r1-fe-copy! (dst src)
  "Copy field element SRC into DST."
  (declare (type secp384r1-fe dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (aref dst 0) (aref src 0)
        (aref dst 1) (aref src 1)
        (aref dst 2) (aref src 2)
        (aref dst 3) (aref src 3)
        (aref dst 4) (aref src 4)
        (aref dst 5) (aref src 5))
  dst)

(defun secp384r1-fe-inv (r a)
  "R := A^-1 mod P, in Montgomery form.  A must be nonzero."
  (declare (type secp384r1-fe r a)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  ;; Fermat: A^(P-2), binary square-and-multiply in Montgomery form.
  (let ((acc (secp384r1-fe-from-int 1))
        (base (secp384r1-fe-copy a))
        (e (- +secp384r1-p+ 2))
        (c (make-array 13 :element-type '(unsigned-byte 64)
                       :initial-element 0)))
    (declare (type integer e)
             (type secp384r1-fe acc base)
             (type (simple-array (unsigned-byte 64) (*)) c))
    (loop for i of-type fixnum downfrom (1- (integer-length e)) to 0 do
      (secp384r1-fe-mont-mul acc acc acc c)
      (when (logbitp i e)
        (secp384r1-fe-mont-mul acc acc base c)))
    (dotimes (i 6 r)
      (setf (aref r i) (aref acc i)))))

;;; Limb point operations for P-384 (six 64-bit Montgomery coordinates).
;;; Destination-passing with a scratch pool: no allocation inside.

(defun secp384r1-fe-copy! (dst src)
  "Copy field element SRC into DST."
  (declare (type secp384r1-fe dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (aref dst 0) (aref src 0)
        (aref dst 1) (aref src 1)
        (aref dst 2) (aref src 2)
        (aref dst 3) (aref src 3)
        (aref dst 4) (aref src 4)
        (aref dst 5) (aref src 5))
  dst)

(defun secp384r1-make-scratch ()
  "A fresh scratch pool: forty field elements plus the 13-word product
buffer, so the point operations allocate nothing."
  (let ((s (make-array 41)))
    (dotimes (i 40 s)
      (setf (svref s i) (secp384r1-fe-zero)))
    (setf (svref s 40)
          (make-array 13 :element-type '(unsigned-byte 64)
                      :initial-element 0))
    s))

(defun secp384r1-point-double! (dx dy dz x1 y1 z1 s)
  "DX:DY:DZ := 2*X1:Y1:Z1 reusing scratch pool S. DST must differ from SRC."
  (declare (type secp384r1-fe dx dy dz x1 y1 z1)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((xx (svref s 0))
        (yy (svref s 1))
        (yyyy (svref s 2))
        (zz (svref s 3))
        (x1+yy (svref s 4))
        (y1+z1 (svref s 5))
        (s0 (svref s 6))
        (ss (svref s 7))
        (m0 (svref s 8))
        (mm (svref s 9))
        (uu (svref s 10))
        (y2yyyy (svref s 11))
        (y4yyyy (svref s 12))
        (y2 (svref s 13))
        (z2 (svref s 14))
        (cbuf (svref s 40)))
    (declare (type secp384r1-fe xx yy yyyy zz x1+yy y1+z1 s0 ss m0 mm
                               uu y2yyyy y4yyyy y2 z2))
    (if (secp384r1-fe-is-zero z1)
        ;; Infinity is all-zero limbs.
        (progn
          (dotimes (i 6)
            (setf (aref dx i) 0
                  (aref dy i) 0
                  (aref dz i) 0))
          (values dx dy dz))
        (progn
          (secp384r1-fe-sq-buf xx x1 cbuf)
          (secp384r1-fe-sq-buf yy y1 cbuf)
          (secp384r1-fe-sq-buf yyyy yy cbuf)
          (secp384r1-fe-sq-buf zz z1 cbuf)
          (secp384r1-fe-add x1+yy x1 yy)
          (secp384r1-fe-add y1+z1 y1 z1)
          ;; s = 2*((x1+yy)^2 - xx - yyyy).
          (secp384r1-fe-mul-buf s0 x1+yy x1+yy cbuf)
          (secp384r1-fe-sub s0 s0 xx)
          (secp384r1-fe-sub s0 s0 yyyy)
          (secp384r1-fe-add ss s0 s0)
          ;; m = 3*(xx - zz^2).
          (secp384r1-fe-mul-buf m0 zz zz cbuf)
          (secp384r1-fe-sub m0 xx m0)
          (secp384r1-fe-add mm m0 m0)
          (secp384r1-fe-add mm mm m0)
          ;; u = m^2 - 2*s.
          (secp384r1-fe-mul-buf uu mm mm cbuf)
          (secp384r1-fe-sub uu uu ss)
          (secp384r1-fe-sub uu uu ss)
          (secp384r1-fe-copy! dx uu)
          ;; y2 = m*(s-u) - 8*yyyy.
          (secp384r1-fe-sub y2 ss uu)
          (secp384r1-fe-mul-buf y2 mm y2 cbuf)
          (secp384r1-fe-add y2yyyy yyyy yyyy)
          (secp384r1-fe-add y4yyyy y2yyyy y2yyyy)
          (secp384r1-fe-add y4yyyy y4yyyy y4yyyy)
          (secp384r1-fe-sub y2 y2 y4yyyy)
          (secp384r1-fe-copy! dy y2)
          ;; z2 = (y1+z1)^2 - yy - zz.
          (secp384r1-fe-mul-buf z2 y1+z1 y1+z1 cbuf)
          (secp384r1-fe-sub z2 z2 yy)
          (secp384r1-fe-sub z2 z2 zz)
          (secp384r1-fe-copy! dz z2)
          (values dx dy dz)))))

(defun secp384r1-point-add! (dx dy dz x1 y1 z1 x2 y2 z2 s)
  "DX:DY:DZ := X1:Y1:Z1 + X2:Y2:Z2 reusing scratch pool S.
DST must differ from both inputs."
  (declare (type secp384r1-fe dx dy dz x1 y1 z1 x2 y2 z2)
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
    (declare (type secp384r1-fe z1z1 z2z2 u1 u2 s1 s2 h hh hh2 ii jj
                               s2-s1 rr r2 vv vv2 x3 rvx y3 s1d t2
                               z1+z2 d1 d2 z3))
    (cond ((secp384r1-fe-is-zero z1)
           (secp384r1-fe-copy! dx x2)
           (secp384r1-fe-copy! dy y2)
           (secp384r1-fe-copy! dz z2)
           (values dx dy dz))
          ((secp384r1-fe-is-zero z2)
           (secp384r1-fe-copy! dx x1)
           (secp384r1-fe-copy! dy y1)
           (secp384r1-fe-copy! dz z1)
           (values dx dy dz))
          (t
           (secp384r1-fe-mul-buf z1z1 z1 z1 cbuf)
           (secp384r1-fe-mul-buf z2z2 z2 z2 cbuf)
           (secp384r1-fe-mul-buf u1 x1 z2z2 cbuf)
           (secp384r1-fe-mul-buf u2 x2 z1z1 cbuf)
           (secp384r1-fe-mul-buf s1 y1 z2 cbuf)
           (secp384r1-fe-mul-buf s1 s1 z2z2 cbuf)
           (secp384r1-fe-mul-buf s2 y2 z1 cbuf)
           (secp384r1-fe-mul-buf s2 s2 z1z1 cbuf)
           (if (secp384r1-fe-equal u1 u2)
               (if (secp384r1-fe-equal s1 s2)
                   (secp384r1-point-double! dx dy dz x1 y1 z1 s)
                   (progn
                     (dotimes (i 6)
                       (setf (aref dx i) 0
                             (aref dy i) 0
                             (aref dz i) 0))
                     (values dx dy dz)))
               (progn
                 (secp384r1-fe-sub h u2 u1)
                 (secp384r1-fe-mul-buf hh h h cbuf)
                 (secp384r1-fe-add hh2 hh hh)
                 (secp384r1-fe-add ii hh2 hh2)
                 (secp384r1-fe-mul-buf jj h ii cbuf)
                 (secp384r1-fe-sub s2-s1 s2 s1)
                 (secp384r1-fe-add rr s2-s1 s2-s1)
                 (secp384r1-fe-mul-buf vv u1 ii cbuf)
                 (secp384r1-fe-mul-buf r2 rr rr cbuf)
                 (secp384r1-fe-add vv2 vv vv)
                 (secp384r1-fe-sub x3 r2 jj)
                 (secp384r1-fe-sub x3 x3 vv2)
                 (secp384r1-fe-copy! dx x3)
                 (secp384r1-fe-sub rvx vv x3)
                 (secp384r1-fe-add s1d s1 s1)
                 (secp384r1-fe-mul-buf t2 s1d jj cbuf)
                 (secp384r1-fe-mul-buf y3 rr rvx cbuf)
                 (secp384r1-fe-sub y3 y3 t2)
                 (secp384r1-fe-copy! dy y3)
                 (secp384r1-fe-add z1+z2 z1 z2)
                 (secp384r1-fe-mul-buf d1 z1+z2 z1+z2 cbuf)
                 (secp384r1-fe-sub d1 d1 z1z1)
                 (secp384r1-fe-sub d2 d1 z2z2)
                 (secp384r1-fe-mul-buf z3 d2 h cbuf)
                 (secp384r1-fe-copy! dz z3)
                 (values dx dy dz)))))))

(defun secp384r1-make-window-table-limbs (bx by bz)
  "The table V * (BX:BY:BZ) for V in [0, 32), as vectors of three
Montgomery limb arrays.  Entry 0 is all-zero (infinity)."
  (declare (type secp384r1-fe bx by bz)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (make-array 32))
        (sc (secp384r1-make-scratch)))
    (declare (type simple-vector table sc))
    (setf (aref table 0) (vector (secp384r1-fe-zero)
                                 (secp384r1-fe-zero)
                                 (secp384r1-fe-zero)))
    (setf (aref table 1) (vector (secp384r1-fe-copy bx)
                                 (secp384r1-fe-copy by)
                                 (secp384r1-fe-copy bz)))
    (loop for v of-type fixnum from 2 below 32 do
      (let ((dx (secp384r1-fe-zero))
            (dy (secp384r1-fe-zero))
            (dz (secp384r1-fe-zero)))
        (declare (type secp384r1-fe dx dy dz))
        (if (evenp v)
            (let ((e (aref table (ash v -1))))
              (declare (type simple-vector e))
              (secp384r1-point-double! dx dy dz
                                       (aref e 0) (aref e 1) (aref e 2) sc))
            (let ((e (aref table (1- v))))
              (declare (type simple-vector e))
              (secp384r1-point-add! dx dy dz
                                    (aref e 0) (aref e 1) (aref e 2)
                                    bx by bz sc)))
        (setf (aref table v) (vector dx dy dz))))
    table))

(defun secp384r1-shamir-mult-limbs (px py pz qx qy qz a b)
  "A * P + B * Q in the limb field, public only, five-bit windows.  All
coordinates are Montgomery field elements; the result is integers."
  (declare (type secp384r1-fe px py pz qx qy qz)
           (type integer a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((w 5)
         (abit (integer-length a))
         (bbit (integer-length b))
         (bits (max abit bbit 1))
         (nwin (ceiling bits w))
         (tp (secp384r1-make-window-table-limbs px py pz))
         (tq (secp384r1-make-window-table-limbs qx qy qz))
         (s (secp384r1-make-scratch))
         (rx (secp384r1-fe-zero))
         (ry (secp384r1-fe-zero))
         (rz (secp384r1-fe-zero))
         (tx (secp384r1-fe-zero))
         (ty (secp384r1-fe-zero))
         (tz (secp384r1-fe-zero)))
    (declare (type fixnum w abit bbit bits nwin)
             (type simple-vector tp tq s)
             (type secp384r1-fe rx ry rz tx ty tz))
    (loop for wi of-type fixnum downfrom (1- nwin) to 0 do
      (unless (= wi (1- nwin))
        (dotimes (i w)
          (declare (ignore i))
          (secp384r1-point-double! tx ty tz rx ry rz s)
          (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))
      (let* ((shift (* wi w))
             (va (if (< shift abit) (ldb (byte w shift) a) 0))
             (vb (if (< shift bbit) (ldb (byte w shift) b) 0)))
        (declare (type fixnum shift)
                 (type (unsigned-byte 5) va vb))
        (unless (zerop va)
          (let ((e (aref tp va)))
            (declare (type simple-vector e))
            (secp384r1-point-add! tx ty tz rx ry rz
                                  (aref e 0) (aref e 1) (aref e 2) s)
            (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))
        (unless (zerop vb)
          (let ((e (aref tq vb)))
            (declare (type simple-vector e))
            (secp384r1-point-add! tx ty tz rx ry rz
                                  (aref e 0) (aref e 1) (aref e 2) s)
            (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))))
    (list (secp384r1-fe-to-int rx)
          (secp384r1-fe-to-int ry)
          (secp384r1-fe-to-int rz))))



(defmethod ec-scalar-inv ((kind (eql :secp384r1)) n)
  (expt-mod n (- +secp384r1-p+ 2) +secp384r1-p+))

(defmethod ec-point-equal ((p secp384r1-point) (q secp384r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (let ((z1z1 (mod (* z1 z1) +secp384r1-p+))
            (z2z2 (mod (* z2 z2) +secp384r1-p+)))
        (and (zerop (mod (- (* x1 z2z2) (* x2 z1z1)) +secp384r1-p+))
             (zerop (mod (- (* y1 z2z2 z2) (* y2 z1z1 z1)) +secp384r1-p+)))))))

(defmethod ec-double ((p secp384r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (if (zerop z1)
        +secp384r1-point-at-infinity+
        (let* ((xx (mod (* x1 x1) +secp384r1-p+))
               (yy (mod (* y1 y1) +secp384r1-p+))
               (yyyy (mod (* yy yy) +secp384r1-p+))
               (zz (mod (* z1 z1) +secp384r1-p+))
               (x1+yy (mod (+ x1 yy) +secp384r1-p+))
               (y1+z1 (mod (+ y1 z1) +secp384r1-p+))
               (s (mod (* 2 (- (* x1+yy x1+yy) xx yyyy)) +secp384r1-p+))
               (m (mod (* 3 (- xx (* zz zz))) +secp384r1-p+))
               (u (mod (- (* m m) (* 2 s)) +secp384r1-p+))
               (x2 u)
               (y2 (mod (- (* m (- s u)) (* 8 yyyy)) +secp384r1-p+))
               (z2 (mod (- (* y1+z1 y1+z1) yy zz) +secp384r1-p+)))
          (make-instance 'secp384r1-point :x x2 :y y2 :z z2)))))

(defmethod ec-add ((p secp384r1-point) (q secp384r1-point))
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
         (let* ((z1z1 (mod (* z1 z1) +secp384r1-p+))
                (z2z2 (mod (* z2 z2) +secp384r1-p+))
                (u1 (mod (* x1 z2z2) +secp384r1-p+))
                (u2 (mod (* x2 z1z1) +secp384r1-p+))
                (s1 (mod (* y1 z2 z2z2) +secp384r1-p+))
                (s2 (mod (* y2 z1 z1z1) +secp384r1-p+)))
           (if (= u1 u2)
               (if (= s1 s2)
                   (ec-double p)
                   +secp384r1-point-at-infinity+)
               (let* ((h (mod (- u2 u1) +secp384r1-p+))
                      (i (mod (* 4 h h) +secp384r1-p+))
                      (j (mod (* h i) +secp384r1-p+))
                      (r (mod (* 2 (- s2 s1)) +secp384r1-p+))
                      (v (mod (* u1 i) +secp384r1-p+))
                      (x3 (mod (- (* r r) j (* 2 v)) +secp384r1-p+))
                      (y3 (mod (- (* r (- v x3)) (* 2 s1 j)) +secp384r1-p+))
                      (z1+z2 (mod (+ z1 z2) +secp384r1-p+))
                      (z3 (mod (* (- (* z1+z2 z1+z2) z1z1 z2z2) h) +secp384r1-p+)))
                 (make-instance 'secp384r1-point :x x3 :y y3 :z z3)))))))))


;;; Fixed-base positional table for the generator point.
;;;
;;; SIGN-MESSAGE and key generation always multiply G by a secret scalar.
;;; Row J holds V * 256^J * G for V in [0, 256), so a multiplication is
;;; 48 additions and no doublings (instead of the ladder's ~192 adds and
;;; 383 doublings, or a standard window's 48 adds and 376 doublings).
;;; The selection scans all 256 entries of a row, so the memory pattern
;;; does not depend on the secret scalar.
;;;
;;; The table is built lazily on first use: 48 rows of 256 points.

(defvar *secp384r1-base-table* nil
  "Positional table ROWS[J][V] = V * 256^J * G. Built on first use.")

(defun secp384r1-ensure-base-table ()
  (or *secp384r1-base-table*
      (setf *secp384r1-base-table*
            (let ((rows (make-array 48))
                  (base +secp384r1-g+))
              (dotimes (j 48 rows)
                (declare (type fixnum j))
                (let ((row (make-array 256)))
                  (setf (aref row 0) +secp384r1-point-at-infinity+
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

(declaim (inline secp384r1-select-base))
(defun secp384r1-select-base (row v)
  "Select index V from the positional-table ROW.  Linear scan over all
256 entries, so the memory access pattern does not depend on V."
  (declare (type simple-vector row)
           (type (unsigned-byte 8) v)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((sel (aref row 0)))
    (dotimes (i 256 sel)
      (when (= i v)
        (setf sel (aref row i))))))

(defun secp384r1-base-mult (k)
  "Fixed-base multiplication K*G via the positional byte table: 48
additions and no doublings."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  (let ((table (secp384r1-ensure-base-table))
        (acc +secp384r1-point-at-infinity+))
    (declare (type simple-vector table))
    (loop for j of-type fixnum from 47 downto 0 do
      (let ((v (ldb (byte 8 (* j 8)) k)))
        (declare (type (unsigned-byte 8) v))
        (unless (zerop v)
          (setf acc (ec-add acc (secp384r1-select-base (aref table j) v))))))
    acc))

(defmethod ec-scalar-mult ((p secp384r1-point) e)
  ;; Secret scalars use the fixed-schedule ladder.  The generator G uses
  ;; the faster fixed-base comb.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (if (and (eq p +secp384r1-g+) (not (minusp e)))
      (secp384r1-base-mult e)
      (%ec-ladder-mult p e :bits +secp384r1-bits+)))

(defmethod ec-point-on-curve-p ((p secp384r1-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((y2 (mod (* y y) +secp384r1-p+))
           (x3 (mod (* x x x) +secp384r1-p+))
           (z2 (mod (* z z) +secp384r1-p+))
           (z4 (mod (* z2 z2) +secp384r1-p+))
           (z6 (mod (* z4 z2) +secp384r1-p+))
           (a (mod (+ x3 (* -3 x z4) (* +secp384r1-b+ z6)) +secp384r1-p+)))
      (declare (type integer y2 x3 z2 z4 z6 a))
      (zerop (mod (- y2 a) +secp384r1-p+)))))

(defmethod ec-make-point ((kind (eql :secp384r1)) &key x y)
  (unless x
    (error 'missing-point-parameter
           :kind 'secp384r1
           :parameter 'x
           :description "coordinate"))
  (unless y
    (error 'missing-point-parameter
           :kind 'secp384r1
           :parameter 'y
           :description "coordinate"))
  (let ((p (make-instance 'secp384r1-point :x x :y y :z 1)))
    (if (ec-point-on-curve-p p)
        p
        (error 'invalid-curve-point :kind 'secp384r1))))

(defmethod ec-destructure-point ((p secp384r1-point))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (when (zerop z)
      (error 'ironclad-unsafe-error
             :format-control "The point at infinity can't be encoded."))
    (let* ((invz (ec-scalar-inv :secp384r1 z))
           (invz2 (mod (* invz invz) +secp384r1-p+))
           (invz3 (mod (* invz2 invz) +secp384r1-p+))
           (x (mod (* x invz2) +secp384r1-p+))
           (y (mod (* y invz3) +secp384r1-p+)))
      (list :x x :y y))))

(defmethod ec-encode-scalar ((kind (eql :secp384r1)) n)
  (integer-to-octets n :n-bits +secp384r1-bits+ :big-endian t))

(defmethod ec-decode-scalar ((kind (eql :secp384r1)) octets)
  (octets-to-integer octets :big-endian t))

(defmethod ec-encode-point ((p secp384r1-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x))
         (y (getf coordinates :y)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (vector 4)
                 (ec-encode-scalar :secp384r1 x)
                 (ec-encode-scalar :secp384r1 y))))

(defmethod ec-decode-point ((kind (eql :secp384r1)) octets)
  (case (aref octets 0)
    ((2 3)
     ;; Compressed point
     (if (= (length octets) (1+ (/ +secp384r1-bits+ 8)))
         (let* ((x-bytes (subseq octets 1 (1+ (/ +secp384r1-bits+ 8))))
                (x (ec-decode-scalar :secp384r1 x-bytes))
                (y-sign (- (aref octets 0) 2))
                (y2 (mod (+ (* x x x) (* -3 x) +secp384r1-b+) +secp384r1-p+))
                (y (expt-mod y2 +secp384r1-i+ +secp384r1-p+))
                (y (if (= (logand y 1) y-sign) y (- +secp384r1-p+ y))))
           (ec-make-point :secp384r1 :x x :y y))
         (error 'invalid-curve-point :kind 'secp384r1)))
    ((4)
     ;; Uncompressed point
     (if (= (length octets) (1+ (/ +secp384r1-bits+ 4)))
         (let* ((x-bytes (subseq octets 1 (1+ (/ +secp384r1-bits+ 8))))
                (x (ec-decode-scalar :secp384r1 x-bytes))
                (y-bytes (subseq octets (1+ (/ +secp384r1-bits+ 8))))
                (y (ec-decode-scalar :secp384r1 y-bytes)))
           (ec-make-point :secp384r1 :x x :y y))
         (error 'invalid-curve-point :kind 'secp384r1)))
    (t
     (error 'invalid-curve-point :kind 'secp384r1))))

(defun secp384r1-public-key (sk)
  (let ((a (ec-decode-scalar :secp384r1 sk)))
    (ec-encode-point (ec-scalar-mult +secp384r1-g+ a))))

(defmethod make-signature ((kind (eql :secp384r1)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'secp384r1
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'secp384r1
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :secp384r1)) signature)
  (let ((length (length signature)))
    (if (/= length (/ +secp384r1-bits+ 4))
        (error 'invalid-signature-length :kind 'secp384r1)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defmethod generate-signature-nonce ((key secp384r1-private-key) message &optional parameters)
  (or *signature-nonce-for-test*
      (rfc6979-generate-k (secp384r1-key-x key)
                          message
                          +secp384r1-l+
                          (integer-length +secp384r1-l+)
                          (ceiling (integer-length +secp384r1-l+) 8)
                          :digest (or parameters *ecdsa-rfc6979-digest*))))

;;; Note that hashing is not performed here.
(defmethod sign-message ((key secp384r1-private-key) message &key (start 0) end (digest *ecdsa-rfc6979-digest*) &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((end (min (or end (length message)) (/ +secp384r1-bits+ 8)))
         (sk (ec-decode-scalar :secp384r1 (secp384r1-key-x key)))
         (h (subseq message start end))
         (k (generate-signature-nonce key h digest))
         (invk (modular-inverse-with-blinding k +secp384r1-l+ :prime t))
         (r (ec-scalar-mult +secp384r1-g+ k))
         (x (subseq (ec-encode-point r) 1 (1+ (/ +secp384r1-bits+ 8))))
         (r (ec-decode-scalar :secp384r1 x))
         (r (mod r +secp384r1-l+))
         (e (ec-decode-scalar :secp384r1 h))
         (s (mod (* invk (+ e (* sk r))) +secp384r1-l+)))
    (if (not (or (zerop r) (zerop s)))
        (make-signature :secp384r1
                        :r (ec-encode-scalar :secp384r1 r)
                        :s (ec-encode-scalar :secp384r1 s))
        (sign-message key message :start start :end end))))

;;; Windowed joint multiplication for verification.
;;;
;;; The plain Shamir trick does one addition per set bit of either
;;; scalar (about 290 for two 384-bit scalars).  Five-bit windows need
;;; 77 windows with at most two additions each.

(defun secp384r1-make-window-table (p)
  "The table V * P for V in [0, 32), built from doubles and adds."
  (declare (type secp384r1-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (make-array 32)))
    (setf (aref table 0) +secp384r1-point-at-infinity+
          (aref table 1) p)
    (loop for v of-type fixnum from 2 below 32 do
      (setf (aref table v)
            (if (evenp v)
                (ec-double (aref table (ash v -1)))
                (ec-add (aref table (1- v)) p))))
    table))

(defun secp384r1-shamir-mult (p q a b)
  "A * P + B * Q, public only, with five-bit windows."
  (declare (type secp384r1-point p q)
           (type integer a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((w 5)
         (abit (integer-length a))
         (bbit (integer-length b))
         (bits (max abit bbit 1))
         (nwin (ceiling bits w))
         ;; Row 0 of the positional table is V*G for V in [0, 256),
         ;; so its first 32 entries serve the five-bit windows directly.
         (tp (if (eq p +secp384r1-g+)
                 (aref (secp384r1-ensure-base-table) 0)
                 (secp384r1-make-window-table p)))
         (tq (secp384r1-make-window-table q))
         (acc +secp384r1-point-at-infinity+))
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

(defmethod verify-signature ((key secp384r1-public-key) message signature &key (start 0) end &allow-other-keys)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length signature) (/ +secp384r1-bits+ 4))
    (error 'invalid-signature-length :kind 'secp384r1))
  (let* ((end (min (or end (length message)) (/ +secp384r1-bits+ 8)))
         (pk (ec-decode-point :secp384r1 (secp384r1-key-y key)))
         (signature-elements (destructure-signature :secp384r1 signature))
         (r (ec-decode-scalar :secp384r1 (getf signature-elements :r)))
         (s (ec-decode-scalar :secp384r1 (getf signature-elements :s))))
    ;; Degenerate (r = 0 or s = 0) signatures are invalid; answer NIL
    ;; before the W/RP computations, which assume nonzero operands.
    (unless (and (< 0 r +secp384r1-l+) (< 0 s +secp384r1-l+))
      (return-from verify-signature nil))
    (let* ((h (subseq message start end))
         (e (ec-decode-scalar :secp384r1 h))
         (w (modular-inverse-with-blinding s +secp384r1-l+ :prime t))
         (u1 (mod (* e w) +secp384r1-l+))
         (u2 (mod (* r w) +secp384r1-l+))
         ;; Joint multiplication in the limb field: one pass instead
         ;; of two, no bignum allocation inside the loop.
         (qx (slot-value pk 'x))
         (qy (slot-value pk 'y))
         (qz (slot-value pk 'z))
         (rp (secp384r1-shamir-mult-limbs (secp384r1-fe-from-int (slot-value +secp384r1-g+ 'x))
                                          (secp384r1-fe-from-int (slot-value +secp384r1-g+ 'y))
                                          (secp384r1-fe-from-int (slot-value +secp384r1-g+ 'z))
                                          (secp384r1-fe-from-int qx)
                                          (secp384r1-fe-from-int qy)
                                          (secp384r1-fe-from-int qz)
                                          u1 u2))
         (rz (third rp)))
      ;; RP is the point at infinity only for invalid signatures.
      (if (zerop rz)
          nil
          (let* ((invz (ec-scalar-inv :secp384r1 rz))
                 (x (mod (* (first rp) (mod (* invz invz) +secp384r1-p+))
                         +secp384r1-p+))
                 (v (mod x +secp384r1-l+)))
            (and (< 0 r +secp384r1-l+)
                 (< 0 s +secp384r1-l+)
                 (= v r)))))))

(defmethod make-public-key ((kind (eql :secp384r1)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'secp384r1
           :parameter 'y
           :description "public key"))
  ;; Reject malformed encodings and off-curve points now, at
  ;; construction time, rather than at first use.
  (ec-decode-point :secp384r1 y)
  (make-instance 'secp384r1-public-key :y y))

(defmethod destructure-public-key ((public-key secp384r1-public-key))
  (list :y (secp384r1-key-y public-key)))

(defmethod make-private-key ((kind (eql :secp384r1)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'secp384r1
           :parameter 'x
           :description "private key"))
  ;; The scalar must lie in [1, N-1]; 0 yields the point at infinity
  ;; and values >= N silently wrap to the wrong public key.
  (unless (< 0 (octets-to-integer x :big-endian t) +secp384r1-l+)
    (error 'invalid-private-key :kind 'secp384r1))
  (make-instance 'secp384r1-private-key :x x :y (or y (secp384r1-public-key x))))

(defmethod destructure-private-key ((private-key secp384r1-private-key))
  (list :x (secp384r1-key-x private-key)
        :y (secp384r1-key-y private-key)))

(defmethod generate-key-pair ((kind (eql :secp384r1)) &key &allow-other-keys)
  (let* ((sk (ec-encode-scalar :secp384r1 (1+ (strong-random (1- +secp384r1-l+)))))
         (pk (secp384r1-public-key sk)))
    (values (make-private-key :secp384r1 :x sk :y pk)
            (make-public-key :secp384r1 :y pk))))

(defmethod diffie-hellman ((private-key secp384r1-private-key) (public-key secp384r1-public-key))
  (let ((s (ec-decode-scalar :secp384r1 (secp384r1-key-x private-key)))
        (p (ec-decode-point :secp384r1 (secp384r1-key-y public-key))))
    (ec-encode-point (ec-scalar-mult p s))))
