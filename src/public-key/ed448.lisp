;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ed448.lisp -- implementation of the ed448 signature algorithm

(in-package :crypto-unsafe)


;;; class definitions

(defclass ed448-public-key ()
  ((y :initarg :y :reader ed448-key-y
      :type (simple-array (unsigned-byte 8) (*)))
   (point :initform nil :accessor ed448-key-point)
   (q-table :initform nil :accessor ed448-key-q-table)))

(defclass ed448-private-key ()
  ((x :initarg :x :reader ed448-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader ed448-key-y :type (simple-array (unsigned-byte 8) (*)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass ed448-point ()
    ;; Internally, a point (x, y) is represented using the projective
    ;; coordinates (X, Y, Z), with x = X / Z and y = Y / Z.
    ((x :initarg :x :type integer)
     (y :initarg :y :type integer)
     (z :initarg :z :type integer)))
  (defmethod make-load-form ((p ed448-point) &optional env)
    (declare (ignore env))
    (make-load-form-saving-slots p)))


;;; constant and function definitions

(defconstant +ed448-bits+ 456)
(defconstant +ed448-q+ 726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439)
(defconstant +ed448-l+ 181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779)
(defconstant +ed448-d+ -39081)

(defconst +ed448-b+
  (make-instance 'ed448-point
                 :x 224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710
                 :y 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660
                 :z 1))
(defconst +ed448-point-at-infinity+
  (make-instance 'ed448-point :x 0 :y 1 :z 1))

;;; ------------------------------------------------------------------
;;; The scalar multiplication in the limb field
;;;;
;;; The points stay as they are, as bignums, and the scalar
;;; multiplication is done in the limb field, where the product of two
;;; field elements is four times faster than the product of two
;;; bignums and the division that follows it.  The coordinates are
;;; converted at each end of the multiplication, which costs about a
;;; microsecond and is nothing next to the multiplication itself.

(defvar +ed448-d-limbs+
  (goldilocks-fe-from-int (+ +ed448-q+ +ed448-d+))
  "The constant d of the Ed448 curve, in limbs.")

(defvar +ed448-q-limbs+
  (goldilocks-fe-from-int +ed448-q+)
  "The prime of the Ed448 curve, in limbs.")

(defun ed448-point-double-limbs! (dx dy dz x1 y1 z1 s)
  "DST := 2*P, in place, using S as scratch."
  (declare (type goldilocks-fe dx dy dz x1 y1 z1)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((a (svref s 0)) (b (svref s 1)) (c (svref s 2)) (d (svref s 3))
         (e (svref s 4)) (f (svref s 5)) (g (svref s 6)) (t1 (svref s 7))
         (buf (svref s 13)))
    (declare (type goldilocks-fe a b c d e f g t1)
             (type goldilocks-product buf))
    (goldilocks-fe-add-buf a x1 y1)
    (goldilocks-fe-mul-buf b a a buf)
    (goldilocks-fe-mul-buf c x1 x1 buf)
    (goldilocks-fe-mul-buf d y1 y1 buf)
    (goldilocks-fe-add-buf e c d)
    (goldilocks-fe-mul-buf f z1 z1 buf)
    (goldilocks-fe-add-buf t1 f f)
    (goldilocks-fe-sub-buf g e t1)
    (goldilocks-fe-sub-buf t1 b e)
    (goldilocks-fe-mul-buf dx t1 g buf)
    (goldilocks-fe-sub-buf t1 c d)
    (goldilocks-fe-mul-buf dy t1 e buf)
    (goldilocks-fe-mul-buf dz e g buf))
  (values dx dy dz))

(defun ed448-point-double-limbs (x1 y1 z1)
  "The double of the point (X1 : Y1 : Z1), in limbs.
The three coordinates are returned as multiple values."
  (declare (type goldilocks-fe x1 y1 z1)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((a (goldilocks-fe-add x1 y1))
         (b (goldilocks-fe-mul a a))
         (c (goldilocks-fe-mul x1 x1))
         (d (goldilocks-fe-mul y1 y1))
         (e (goldilocks-fe-add c d))
         (f (goldilocks-fe-mul z1 z1))
         (g (goldilocks-fe-sub e (goldilocks-fe-add f f)))
         (x2 (goldilocks-fe-mul (goldilocks-fe-sub b e) g))
         (y2 (goldilocks-fe-mul (goldilocks-fe-sub c d) e))
         (z2 (goldilocks-fe-mul e g)))
    (values x2 y2 z2)))

(defun ed448-point-add-limbs! (dx dy dz x1 y1 z1 x2 y2 z2 s)
  "DST := P+Q, in place, using S as scratch."
  (declare (type goldilocks-fe dx dy dz x1 y1 z1 x2 y2 z2)
           (type simple-vector s)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((a (svref s 0)) (b (svref s 1)) (c (svref s 2)) (d (svref s 3))
         (k (svref s 4)) (e (svref s 5)) (f (svref s 6)) (g (svref s 7))
         (h (svref s 8)) (i (svref s 9)) (j (svref s 10))
         (t1 (svref s 11)) (t2 (svref s 12))
         (buf (svref s 13)))
    (declare (type goldilocks-fe a b c d k e f g h i j t1 t2)
             (type goldilocks-product buf))
    (goldilocks-fe-mul-buf a z1 z2 buf)
    (goldilocks-fe-mul-buf b a a buf)
    (goldilocks-fe-mul-buf c x1 x2 buf)
    (goldilocks-fe-mul-buf d y1 y2 buf)
    (goldilocks-fe-mul-buf k c d buf)
    (goldilocks-fe-mul-buf e +ed448-d-limbs+ k buf)
    (goldilocks-fe-sub-buf f b e)
    (goldilocks-fe-add-buf g b e)
    (goldilocks-fe-add-buf t1 x1 y1)
    (goldilocks-fe-add-buf t2 x2 y2)
    (goldilocks-fe-mul-buf h t1 t2 buf)
    (goldilocks-fe-mul-buf i a f buf)
    (goldilocks-fe-mul-buf j a g buf)
    (goldilocks-fe-sub-buf t1 h c)
    (goldilocks-fe-sub-buf t1 t1 d)
    (goldilocks-fe-mul-buf dx i t1 buf)
    (goldilocks-fe-sub-buf t1 d c)
    (goldilocks-fe-mul-buf dy j t1 buf)
    (goldilocks-fe-mul-buf dz f g buf))
  (values dx dy dz))

(defun ed448-point-add-limbs (x1 y1 z1 x2 y2 z2)
  "The sum of the points (X1 : Y1 : Z1) and (X2 : Y2 : Z2), in limbs.
The three coordinates are returned as multiple values."
  (declare (type goldilocks-fe x1 y1 z1 x2 y2 z2)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((a (goldilocks-fe-mul z1 z2))
         (b (goldilocks-fe-mul a a))
         (c (goldilocks-fe-mul x1 x2))
         (d (goldilocks-fe-mul y1 y2))
         (k (goldilocks-fe-mul c d))
         (e (goldilocks-fe-mul +ed448-d-limbs+ k))
         (f (goldilocks-fe-sub b e))
         (g (goldilocks-fe-add b e))
         (h (goldilocks-fe-mul (goldilocks-fe-add x1 y1) (goldilocks-fe-add x2 y2)))
         (i (goldilocks-fe-mul a f))
         (j (goldilocks-fe-mul a g))
         (x3 (goldilocks-fe-mul i (goldilocks-fe-sub (goldilocks-fe-sub h c) d)))
         (y3 (goldilocks-fe-mul j (goldilocks-fe-sub d c)))
         (z3 (goldilocks-fe-mul f g)))
    (values x3 y3 z3)))

(defun ed448-ladder-mult-limbs (x y z e)
  "E times the point (X : Y : Z), in the limb field.
X, Y and Z are bignums, and the result is a point."
  (declare (type integer x y z e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (when (minusp e)
    (error "negative scalars are not supported by ed448-ladder-mult-limbs"))
  (if (zerop e)
      +ed448-point-at-infinity+
      (let* ((r0x (goldilocks-fe-from-int 0))
             (r0y (goldilocks-fe-from-int 1))
             (r0z (goldilocks-fe-from-int 1))
             (r1x (goldilocks-fe-from-int x))
             (r1y (goldilocks-fe-from-int y))
             (r1z (goldilocks-fe-from-int z))
             (tx (goldilocks-fe-zero)) (ty (goldilocks-fe-zero)) (tz (goldilocks-fe-zero))
             (ux (goldilocks-fe-zero)) (uy (goldilocks-fe-zero)) (uz (goldilocks-fe-zero))
             (s (goldilocks-make-scratch)))
        (loop for i from (1- +ed448-bits+) downto 0 do
          (if (logbitp i e)
              (progn
                (ed448-point-add-limbs! tx ty tz r0x r0y r0z r1x r1y r1z s)
                (ed448-point-double-limbs! ux uy uz r1x r1y r1z s)
                (rotatef r0x tx) (rotatef r0y ty) (rotatef r0z tz)
                (rotatef r1x ux) (rotatef r1y uy) (rotatef r1z uz))
              (progn
                (ed448-point-add-limbs! tx ty tz r0x r0y r0z r1x r1y r1z s)
                (ed448-point-double-limbs! ux uy uz r0x r0y r0z s)
                (rotatef r1x tx) (rotatef r1y ty) (rotatef r1z tz)
                (rotatef r0x ux) (rotatef r0y uy) (rotatef r0z uz))))
        (make-instance 'ed448-point
                       :x (goldilocks-fe-to-int r0x)
                       :y (goldilocks-fe-to-int r0y)
                       :z (goldilocks-fe-to-int r0z)))))

(defvar *ed448-base-table-limbs* nil
  "Precomputed I * G for I in [0, 256), in limbs.")

(defun ed448-base-table-entry (table i)
  "Fresh I*G triple for the base TABLE, built with destination-passing
ops from earlier entries (which must already be present)."
  (declare (type simple-vector table)
           (type fixnum i)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((s (goldilocks-make-scratch))
        (x (goldilocks-fe-zero))
        (y (goldilocks-fe-zero))
        (z (goldilocks-fe-zero)))
    (declare (type simple-vector s)
             (type goldilocks-fe x y z))
    (cond ((zerop i)
           (setf (aref x 0) 0
                 (aref y 0) 1
                 (aref z 0) 1))
          ((= i 1)
           (replace x (goldilocks-fe-from-int (slot-value +ed448-b+ 'x)))
           (replace y (goldilocks-fe-from-int (slot-value +ed448-b+ 'y)))
           (setf (aref z 0) 1))
          (t
           (if (evenp i)
               (ed448-point-double-limbs! x y z
                                          (aref (aref table (ash i -1)) 0)
                                          (aref (aref table (ash i -1)) 1)
                                          (aref (aref table (ash i -1)) 2)
                                          s)
               (ed448-point-add-limbs! x y z
                                       (aref (aref table (1- i)) 0)
                                       (aref (aref table (1- i)) 1)
                                       (aref (aref table (1- i)) 2)
                                       (aref (aref table 1) 0)
                                       (aref (aref table 1) 1)
                                       (aref (aref table 1) 2)
                                       s))))
    (vector x y z)))

(defun ed448-ensure-base-table-limbs ()
  (or *ed448-base-table-limbs*
      (setf *ed448-base-table-limbs*
            (let ((table (make-array 256)))
              (dotimes (i 256 table)
                (setf (aref table i) (ed448-base-table-entry table i)))))))

(declaim (inline ed448-select-base-limbs))
(defun ed448-select-base-limbs (table v ax ay az)
  "Copy TABLE[V] into AX AY AZ.  Linear scan, timing independent of V."
  (declare (type simple-vector table)
           (type (unsigned-byte 8) v)
           (type goldilocks-fe ax ay az)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (dotimes (i 256)
    (when (= i v)
      (let ((e (aref table i)))
        (declare (type simple-vector e))
        (replace ax (aref e 0))
        (replace ay (aref e 1))
        (replace az (aref e 2)))))
  (values ax ay az))

(defun ed448-make-window-table-limbs (x y z)
  "32 multiples of the bignum point (X : Y : Z) for five-bit windows."
  (declare (type integer x y z)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (make-array 32))
        (s (goldilocks-make-scratch)))
    (declare (type simple-vector table s))
    (setf (aref table 0) (vector (goldilocks-fe-from-int 0)
                                 (goldilocks-fe-from-int 1)
                                 (goldilocks-fe-from-int 1))
          (aref table 1) (vector (goldilocks-fe-from-int x)
                                 (goldilocks-fe-from-int y)
                                 (goldilocks-fe-from-int z)))
    (loop for v of-type fixnum from 2 below 32 do
      (let ((dx (goldilocks-fe-zero))
            (dy (goldilocks-fe-zero))
            (dz (goldilocks-fe-zero)))
        (declare (type goldilocks-fe dx dy dz))
        (if (evenp v)
            (ed448-point-double-limbs! dx dy dz
                                       (aref (aref table (ash v -1)) 0)
                                       (aref (aref table (ash v -1)) 1)
                                       (aref (aref table (ash v -1)) 2)
                                       s)
            (ed448-point-add-limbs! dx dy dz
                                    (aref (aref table (1- v)) 0)
                                    (aref (aref table (1- v)) 1)
                                    (aref (aref table (1- v)) 2)
                                    (aref (aref table 1) 0)
                                    (aref (aref table 1) 1)
                                    (aref (aref table 1) 2)
                                    s))
        (setf (aref table v) (vector dx dy dz))))
    table))

(defun ed448-shamir-mult-limbs (ax ay az bx by bz a b &optional tq)
  "A*(AX:AY:AZ) + B*(BX:BY:BZ), public only, five-bit windows. The
input points use bignum coordinates; the result is an ed448-point."
  (declare (type integer ax ay az bx by bz a b)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((w 5)
         (abit (integer-length a))
         (bbit (integer-length b))
         (bits (max abit bbit 1))
         (nwin (ceiling bits w))
         ;; The generator's 256-entry table starts with V*G for V in
         ;; [0, 32), so it serves the five-bit windows directly.
         (tg (ed448-ensure-base-table-limbs))
         (tq (or tq (ed448-make-window-table-limbs bx by bz)))
         (rx (goldilocks-fe-from-int 0))
         (ry (goldilocks-fe-from-int 1))
         (rz (goldilocks-fe-from-int 1))
         (tx (goldilocks-fe-zero))
         (ty (goldilocks-fe-zero))
         (tz (goldilocks-fe-zero))
         (s (goldilocks-make-scratch)))
    (declare (type fixnum w abit bbit bits nwin)
             (type simple-vector tq)
             (type goldilocks-fe rx ry rz tx ty tz))
    (loop for wi of-type fixnum downfrom (1- nwin) to 0 do
      (unless (= wi (1- nwin))
        (dotimes (i w)
          (declare (ignore i))
          (ed448-point-double-limbs! tx ty tz rx ry rz s)
          (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))
      (let* ((shift (* wi w))
             (va (if (< shift abit) (ldb (byte w shift) a) 0))
             (vb (if (< shift bbit) (ldb (byte w shift) b) 0)))
        (declare (type fixnum shift)
                 (type (unsigned-byte 5) va vb))
        (unless (zerop va)
          (let ((e (aref tg va)))
            (declare (type simple-vector e))
            (ed448-point-add-limbs! tx ty tz rx ry rz
                                    (aref e 0) (aref e 1) (aref e 2) s)
            (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))
        (unless (zerop vb)
          (let ((e (aref tq vb)))
            (declare (type simple-vector e))
            (ed448-point-add-limbs! tx ty tz rx ry rz
                                    (aref e 0) (aref e 1) (aref e 2) s)
            (rotatef rx tx) (rotatef ry ty) (rotatef rz tz)))))
    (make-instance 'ed448-point
                   :x (goldilocks-fe-to-int rx)
                   :y (goldilocks-fe-to-int ry)
                   :z (goldilocks-fe-to-int rz))))

(defun ed448-base-mult-limbs (k)
  "The fixed-base comb for G, in the limb field: eight-bit windows."
  (declare (type integer k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (ed448-ensure-base-table-limbs))
        (ax (goldilocks-fe-from-int 0))
        (ay (goldilocks-fe-from-int 1))
        (az (goldilocks-fe-from-int 1))
        (tx (goldilocks-fe-zero))
        (ty (goldilocks-fe-zero))
        (tz (goldilocks-fe-zero))
        (sx (goldilocks-fe-zero))
        (sy (goldilocks-fe-zero))
        (sz (goldilocks-fe-zero))
        (s (goldilocks-make-scratch)))
    (declare (type simple-vector table s)
             (type goldilocks-fe ax ay az tx ty tz sx sy sz))
    (loop for j of-type fixnum from 56 downto 0 do ; 456 bits / 8
      (unless (= j 56)
        (dotimes (i 8)
          (declare (ignore i))
          (ed448-point-double-limbs! tx ty tz ax ay az s)
          (rotatef ax tx) (rotatef ay ty) (rotatef az tz)))
      ;; Linear scan: timing does not depend on the secret scalar.
      ;; Table entry 0 is infinity, so a zero window adds nothing.
      (let ((v (ldb (byte 8 (* j 8)) k)))
        (declare (type (unsigned-byte 8) v))
        (unless (zerop v)
          (ed448-select-base-limbs table v sx sy sz)
          (ed448-point-add-limbs! tx ty tz ax ay az sx sy sz s)
          (rotatef ax tx) (rotatef ay ty) (rotatef az tz))))
    (make-instance 'ed448-point
                   :x (goldilocks-fe-to-int ax)
                   :y (goldilocks-fe-to-int ay)
                   :z (goldilocks-fe-to-int az))))


(defvar *ed448-base-table-positional* nil
  "T[J][V] = V * 256^J * G, in limbs, as a 57-row 16x16 matrix.")

(defun ed448-build-base-table-positional ()
  "Build the positional table T[J][V] = V * 256^J * G."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((rows (make-array 57))
        (s (goldilocks-make-scratch))
        (bx (goldilocks-fe-from-int (slot-value +ed448-b+ 'x)))
        (by (goldilocks-fe-from-int (slot-value +ed448-b+ 'y)))
        (bz (goldilocks-fe-from-int 1)))
    (declare (type simple-vector rows)
             (type simple-vector s)
             (type goldilocks-fe bx by bz))
    (flet ((cp (a)
             (let ((c (goldilocks-fe-zero)))
               (replace c a)
               c)))
      (dotimes (j 57 (progn (setf *ed448-base-table-positional* rows) rows))
        (declare (type fixnum j))
        (let ((flat (make-array 256)))
          (declare (type simple-vector flat))
          (setf (aref flat 0)
                (vector (goldilocks-fe-from-int 0)
                        (goldilocks-fe-from-int 1)
                        (goldilocks-fe-from-int 1)))
          (setf (aref flat 1)
                (vector (cp bx) (cp by) (cp bz)))
          (loop for v of-type fixnum from 2 below 256 do
            (let ((x (goldilocks-fe-zero))
                  (y (goldilocks-fe-zero))
                  (z (goldilocks-fe-zero)))
              (if (evenp v)
                  (let ((src (aref flat (ash v -1))))
                    (ed448-point-double-limbs!
                     x y z (aref src 0) (aref src 1) (aref src 2) s))
                  (let ((src (aref flat (1- v)))
                        (one (aref flat 1)))
                    (ed448-point-add-limbs!
                     x y z
                     (aref src 0) (aref src 1) (aref src 2)
                     (aref one 0) (aref one 1) (aref one 2) s)))
              (setf (aref flat v) (vector x y z))))
          (let ((subs (make-array 16)))
            (dotimes (h 16)
              (let ((sub (make-array 16)))
                (dotimes (l 16)
                  (setf (aref sub l) (aref flat (+ (* 16 h) l))))
                (setf (aref subs h) sub)))
            (setf (aref rows j) subs))
          ;; base := 256 * base
          (dotimes (i 8)
            (declare (ignore i))
            (let ((x (goldilocks-fe-zero))
                  (y (goldilocks-fe-zero))
                  (z (goldilocks-fe-zero)))
              (ed448-point-double-limbs! x y z bx by bz s)
              (setf bx x by y bz z))))))))

(declaim (inline ed448-select-base-positional))
(defun ed448-select-base-positional (row v ax ay az)
  "Copy TABLE[V] into AX AY AZ with two linear sixteen-entry scans."
  (declare (type simple-vector row)
           (type (unsigned-byte 8) v)
           (type goldilocks-fe ax ay az)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((hi (ash v -4))
         (lo (logand v 15))
         (sub (aref row 0)))
    (declare (type (unsigned-byte 4) hi lo)
             (type simple-vector sub))
    (loop for i of-type fixnum from 1 below 16
          do (when (= i hi) (setf sub (aref row i))))
    (let ((sel (aref sub 0)))
      (loop for i of-type fixnum from 1 below 16
            do (when (= i lo) (setf sel (aref sub i))))
      (replace ax (aref sel 0))
      (replace ay (aref sel 1))
      (replace az (aref sel 2))))
  (values ax ay az))

(defun ed448-base-mult-positional (k)
  "K*G from the positional byte table: fifty-seven additions and no
doublings."
  (declare (type integer k)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((table (or *ed448-base-table-positional*
                   (setf *ed448-base-table-positional*
                         (ed448-build-base-table-positional))))
        (ax (goldilocks-fe-from-int 0))
        (ay (goldilocks-fe-from-int 1))
        (az (goldilocks-fe-from-int 1))
        (tx (goldilocks-fe-zero))
        (ty (goldilocks-fe-zero))
        (tz (goldilocks-fe-zero))
        (sx (goldilocks-fe-zero))
        (sy (goldilocks-fe-zero))
        (sz (goldilocks-fe-zero))
        (s (goldilocks-make-scratch)))
    (declare (type simple-vector table s)
             (type goldilocks-fe ax ay az tx ty tz sx sy sz))
    (loop for j of-type fixnum from 56 downto 0 do
      (let ((v (ldb (byte 8 (* j 8)) k)))
        (declare (type (unsigned-byte 8) v))
        (unless (zerop v)
          (ed448-select-base-positional (aref table j) v sx sy sz)
          (ed448-point-add-limbs! tx ty tz ax ay az sx sy sz s)
          (rotatef ax tx) (rotatef ay ty) (rotatef az tz))))
    (make-instance 'ed448-point
                   :x (goldilocks-fe-to-int ax)
                   :y (goldilocks-fe-to-int ay)
                   :z (goldilocks-fe-to-int az))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun ed448-dom (x y)
    (declare (type (unsigned-byte 8) x)
             (type (simple-array (unsigned-byte 8) (*)) y)
             (optimize (speed 3) (safety 0) (space 0) (debug 0)))
    (when (> (length y) 255)
      (error 'ironclad-unsafe-error
             :format-control "The Y array is to big."))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (map 'vector #'char-code "SigEd448")
                 (vector x)
                 (vector (length y))
                 y)))
;; Ed448 (x = 0), no context (y = #())
(defconst +ed448-dom+ (ed448-dom 0 (make-array 0 :element-type '(unsigned-byte 8))))

(defmethod ec-scalar-inv ((kind (eql :ed448)) n)
  (expt-mod n (- +ed448-q+ 2) +ed448-q+))

(defun ed448-recover-x (y)
  "Recover the X coordinate of a point on ed448 curve from the Y coordinate."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer y))
  (let* ((yl (goldilocks-fe-from-int y))
         (u (goldilocks-fe-sub (goldilocks-fe-mul yl yl) (goldilocks-fe-one)))
         (v (goldilocks-fe-sub
             (goldilocks-fe-mul +ed448-d-limbs+
                               (goldilocks-fe-add u (goldilocks-fe-one)))
             (goldilocks-fe-one)))
         (uv (goldilocks-fe-mul u v))
         (u3v (goldilocks-fe-mul (goldilocks-fe-mul u u) uv))
         (u5v3 (goldilocks-fe-mul u3v (goldilocks-fe-mul uv uv)))
         ;; The value recovered here depends only on the public key, so
         ;; the variable-time sliding-window exponentiation is safe.
         (x (goldilocks-fe-mul
             u3v (goldilocks-fe-expt u5v3 (/ (- +ed448-q+ 3) 4)))))
    (declare (type goldilocks-fe u v uv u3v u5v3 x))
    ;; The X coordinate is the one with the even parity.
    (if (evenp (goldilocks-fe-to-int x))
        x
        (goldilocks-fe-sub +ed448-q-limbs+ x))))

(defmethod ec-add ((p ed448-point) (q ed448-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (let* ((a (goldilocks-reduce (* z1 z2)))
             (b (goldilocks-reduce (* a a)))
             (c (goldilocks-reduce (* x1 x2)))
             (d (goldilocks-reduce (* y1 y2)))
             (k (goldilocks-reduce (* c d)))
             (e (goldilocks-reduce (* +ed448-d+ k)))
             (f (goldilocks-reduce (- b e)))
             (g (goldilocks-reduce (+ b e)))
             (h (goldilocks-reduce (* (+ x1 y1) (+ x2 y2))))
             (i (goldilocks-reduce (* a f)))
             (j (goldilocks-reduce (* a g)))
             (x3 (goldilocks-reduce (* i (- h c d))))
             (y3 (goldilocks-reduce (* j (- d c))))
             (z3 (goldilocks-reduce (* f g))))
        (declare (type integer a b c d e f g h i j k x3 y3 z3))
        (make-instance 'ed448-point :x x3 :y y3 :z z3)))))

(defmethod ec-double ((p ed448-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (let* ((a (goldilocks-reduce (+ x1 y1)))
           (b (goldilocks-reduce (* a a)))
           (c (goldilocks-reduce (* x1 x1)))
           (d (goldilocks-reduce (* y1 y1)))
           (e (goldilocks-reduce (+ c d)))
           (f (goldilocks-reduce (* z1 z1)))
           (g (goldilocks-reduce (- e (* 2 f))))
           (x2 (goldilocks-reduce (* (- b e) g)))
           (y2 (goldilocks-reduce (* (- c d) e)))
           (z2 (goldilocks-reduce (* e g))))
      (declare (type integer a b c d e f g x2 y2 z2))
      (make-instance 'ed448-point :x x2 :y y2 :z z2))))

(defun ed448-double! (dst p)
  "DST := 2*P. No consing."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (let* ((a (goldilocks-reduce (+ x1 y1)))
           (b (goldilocks-reduce (* a a)))
           (c (goldilocks-reduce (* x1 x1)))
           (d (goldilocks-reduce (* y1 y1)))
           (e (goldilocks-reduce (+ c d)))
           (f (goldilocks-reduce (* z1 z1)))
           (g (goldilocks-reduce (- e (* 2 f))))
           (x2 (goldilocks-reduce (* (- b e) g)))
           (y2 (goldilocks-reduce (* (- c d) e)))
           (z2 (goldilocks-reduce (* e g))))
      (declare (type integer x2 y2 z2))
      (setf (slot-value dst 'x) x2
            (slot-value dst 'y) y2
            (slot-value dst 'z) z2)
      dst)))

(defun ed448-add! (dst p q)
  "DST := P + Q. No consing."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (let* ((a (goldilocks-reduce (* z1 z2)))
             (b (goldilocks-reduce (* a a)))
             (c (goldilocks-reduce (* x1 x2)))
             (d (goldilocks-reduce (* y1 y2)))
             (k (goldilocks-reduce (* c d)))
             (e (goldilocks-reduce (* +ed448-d+ k)))
             (f (goldilocks-reduce (- b e)))
             (g (goldilocks-reduce (+ b e)))
             (h (goldilocks-reduce (* (+ x1 y1) (+ x2 y2))))
             (i (goldilocks-reduce (* a f)))
             (j (goldilocks-reduce (* a g)))
             (x3 (goldilocks-reduce (* i (- h c d))))
             (y3 (goldilocks-reduce (* j (- d c))))
             (z3 (goldilocks-reduce (* f g))))
        (declare (type integer x3 y3 z3))
        (setf (slot-value dst 'x) x3
              (slot-value dst 'y) y3
              (slot-value dst 'z) z3)
        dst))))

(declaim (inline ed448-point-copy!))
(defun ed448-point-copy! (dst src)
  "Copy point SRC into DST."
  (declare (type ed448-point dst src)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (setf (slot-value dst 'x) (slot-value src 'x)
        (slot-value dst 'y) (slot-value src 'y)
        (slot-value dst 'z) (slot-value src 'z))
  dst)

;;; Scalar multiplication for arbitrary points (not the generator).
;;; Uses destination-based Montgomery ladder to avoid consing intermediate
;;; points.  This is used by ed448-verify for the public-key multiplication.
(defun ed448-scalar-mult-general (p e)
  "Compute E*P for arbitrary point P, in the limb field."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (ed448-ladder-mult-limbs (slot-value p 'x) (slot-value p 'y)
                           (slot-value p 'z) e))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Fixed-base comb for the generator point.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SIGN-MESSAGE and key generation always multiply G by a secret scalar.
;;; A 4-bit window needs 114 adds and 456 doublings instead of the
;;; ladder's ~228 adds and 455 doublings.

(defvar *ed448-base-table* nil
  "Precomputed I * G for I in [0, 16). Built on first use.")

(defun ed448-ensure-base-table ()
  (or *ed448-base-table*
      (setf *ed448-base-table*
            (let ((table (make-array 16)))
              (setf (aref table 0) +ed448-point-at-infinity+)
              (setf (aref table 1) +ed448-b+)
              (loop for i from 2 below 16
                    do (setf (aref table i)
                             (if (evenp i)
                                 (ec-double (aref table (ash i -1)))
                                 (ec-add (aref table (1- i)) +ed448-b+))))
              table))))

(declaim (inline ed448-select-base))
(defun ed448-select-base (table v)
  "Select TABLE[V].  Linear scan over the small cached table."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type (integer 0 15) v))
  (let ((sel +ed448-point-at-infinity+))
    (dotimes (i 16 sel)
      (when (= i v)
        (setf sel (aref table i))))))

(defun ed448-base-mult (k)
  "Fixed-base multiplication by G (secret scalar, fixed schedule)."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer k))
  (ed448-base-mult-positional k))

(defmethod ec-scalar-mult ((p ed448-point) e)
  ;; Secret scalars use the fixed-schedule ladder, except for the fixed
  ;; base point G (signing nonces, key generation), which uses the
  ;; constant-iteration comb above.  Public-only callers can keep using
  ;; %EC-WINDOW-MULT or %EC-SHAMIR-MULT directly.
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer e))
  (if (and (eq p +ed448-b+) (not (minusp e)))
      (ed448-base-mult e)
      (ed448-ladder-mult p e)))

(defun ed448-ladder-mult (point e)
  "Fixed-schedule Montgomery ladder, in the limb field."
  (declare (type ed448-point point)
           (type integer e)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (ed448-ladder-mult-limbs (slot-value point 'x) (slot-value point 'y)
                           (slot-value point 'z) e))

(defmethod ec-point-on-curve-p ((p ed448-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((xx (goldilocks-reduce (* x x)))
           (yy (goldilocks-reduce (* y y)))
           (zz (goldilocks-reduce (* z z)))
           (zzzz (goldilocks-reduce (* zz zz)))
           (a (goldilocks-reduce (* zz (+ yy xx))))
           (b (goldilocks-reduce (+ zzzz (* +ed448-d+ xx yy)))))
      (declare (type integer xx yy zz zzzz a b))
      (zerop (goldilocks-reduce (- a b))))))

(defmethod ec-point-equal ((p ed448-point) (q ed448-point))
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (with-slots ((x1 x) (y1 y) (z1 z)) p
    (declare (type integer x1 y1 z1))
    (with-slots ((x2 x) (y2 y) (z2 z)) q
      (declare (type integer x2 y2 z2))
      (and (zerop (goldilocks-reduce (- (* x1 z2) (* x2 z1))))
           (zerop (goldilocks-reduce (- (* y1 z2) (* y2 z1))))))))

(defmethod ec-make-point ((kind (eql :ed448)) &key x y)
  (unless x
    (error 'missing-point-parameter
           :kind 'ed448
           :parameter 'x
           :description "coordinate"))
  (unless y
    (error 'missing-point-parameter
           :kind 'ed448
           :parameter 'y
           :description "coordinate"))
  (let ((p (make-instance 'ed448-point :x x :y y :z 1)))
    (if (ec-point-on-curve-p p)
        p
        (error 'invalid-curve-point :kind 'ed448))))

(defmethod ec-destructure-point ((p ed448-point))
  (with-slots (x y z) p
    (declare (type integer x y z))
    (let* ((xl (goldilocks-fe-from-int x))
           (yl (goldilocks-fe-from-int y))
           (zl (goldilocks-fe-from-int z))
           (invz (goldilocks-fe-expt zl (- +ed448-q+ 2)))
           (x (goldilocks-fe-mul xl invz))
           (y (goldilocks-fe-mul yl invz)))
      (list :x (goldilocks-fe-to-int x) :y (goldilocks-fe-to-int y)))))

(defmethod ec-encode-scalar ((kind (eql :ed448)) n)
  (integer-to-octets n :n-bits +ed448-bits+ :big-endian nil))

(defmethod ec-decode-scalar ((kind (eql :ed448)) octets)
  (octets-to-integer octets :big-endian nil))

(defmethod ec-encode-point ((p ed448-point))
  (let* ((coordinates (ec-destructure-point p))
         (x (getf coordinates :x))
         (y (getf coordinates :y)))
    (declare (type integer x y))
    (setf (ldb (byte 1 (- +ed448-bits+ 1)) y) (ldb (byte 1 0) x))
    (ec-encode-scalar :ed448 y)))

(defmethod ec-decode-point ((kind (eql :ed448)) octets)
  (let* ((y (ec-decode-scalar :ed448 octets))
         (b (ldb (byte 1 (- +ed448-bits+ 1)) y)))
    (setf (ldb (byte 1 (- +ed448-bits+ 1)) y) 0)
    (let ((x (ed448-recover-x y)))
      (declare (type goldilocks-fe x))
      (unless (= (ldb (byte 1 0) (goldilocks-fe-to-int x)) b)
        (setf x (goldilocks-fe-sub +ed448-q-limbs+ x)))
      (ec-make-point :ed448 :x (goldilocks-fe-to-int x) :y y))))

(defun ed448-hash (&rest messages)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((digest (make-digest :shake256 :output-length 114)))
    (dolist (m messages)
      (update-digest digest m))
    (produce-digest digest)))

(defun ed448-public-key (sk)
  "Compute the public key associated to the private key SK."
  (let ((h (ed448-hash sk)))
    (setf h (subseq h 0 (ceiling +ed448-bits+ 8)))
    (setf (ldb (byte 2 0) (elt h 0)) 0)
    (setf (ldb (byte 1 7) (elt h (- (ceiling +ed448-bits+ 8) 2))) 1)
    (setf (elt h (- (ceiling +ed448-bits+ 8) 1)) 0)
    (let ((a (ec-decode-scalar :ed448 h)))
      (ec-encode-point (ec-scalar-mult +ed448-b+ a)))))

(defmethod make-signature ((kind (eql :ed448)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'ed448
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'ed448
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :ed448)) signature)
  (let ((length (length signature)))
    (if (/= length (/ +ed448-bits+ 4))
        (error 'invalid-signature-length :kind 'ed448)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defun ed448-sign (m sk pk)
  (declare (type (simple-array (unsigned-byte 8) (*)) m sk pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((h (ed448-hash sk)))
    (setf (ldb (byte 2 0) (elt h 0)) 0)
    (setf (ldb (byte 1 7) (elt h (- (ceiling +ed448-bits+ 8) 2))) 1)
    (setf (elt h (- (ceiling +ed448-bits+ 8) 1)) 0)
    (let* ((a (ec-decode-scalar :ed448 (subseq h 0 (ceiling +ed448-bits+ 8))))
           (rh (ed448-hash +ed448-dom+ (subseq h (ceiling +ed448-bits+ 8) (ceiling +ed448-bits+ 4)) m))
           (ri (mod (ec-decode-scalar :ed448 rh) +ed448-l+))
           (r (ec-scalar-mult +ed448-b+ ri))
           (rp (ec-encode-point r))
           (k (mod (ec-decode-scalar :ed448 (ed448-hash +ed448-dom+ rp pk m)) +ed448-l+))
           (s (mod (+ (* k a) ri) +ed448-l+)))
      (make-signature :ed448 :r rp :s (ec-encode-scalar :ed448 s)))))

(defun ed448-verify (s m pk &optional key)
  (declare (type (simple-array (unsigned-byte 8) (*)) s m pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length s) (ceiling +ed448-bits+ 4))
    (error 'invalid-signature-length :kind 'ed448))
  (unless (= (length pk) (ceiling +ed448-bits+ 8))
    (error 'invalid-public-key-length :kind 'ed448))
  (let* ((signature-elements (destructure-signature :ed448 s))
         (r (getf signature-elements :r))
         (rp (ec-decode-point :ed448 r))
         (s (ec-decode-scalar :ed448 (getf signature-elements :s)))
         (a (or (and key (ed448-key-point key))
                (ec-decode-point :ed448 pk)))
         (h (mod (ec-decode-scalar :ed448 (ed448-hash +ed448-dom+ r pk m)) +ed448-l+))
         ;; Joint multiplication for s*B - h*A == R: negate h modulo
         ;; the order and check the sum against R in one pass instead
         ;; of a fixed-base mult plus a ladder plus an add.
         (tq (and key
                  (or (ed448-key-q-table key)
                      (setf (ed448-key-q-table key)
                            (ed448-make-window-table-limbs
                             (slot-value a 'x)
                             (slot-value a 'y)
                             (slot-value a 'z))))))
         (res1 (with-slots ((ax x) (ay y) (az z)) +ed448-b+
                 (declare (type integer ax ay az))
                 (with-slots ((bx x) (by y) (bz z)) a
                   (declare (type integer bx by bz))
                   (ed448-shamir-mult-limbs ax ay az bx by bz
                                            s (mod (- h) +ed448-l+) tq))))
         (res2 rp))
    (declare (type (simple-array (unsigned-byte 8) (*)) r)
             (type integer s h)
             (type ed448-point rp a res1 res2))
    (when (and key (null (ed448-key-point key)))
      (setf (ed448-key-point key) a))
    (and (< s +ed448-l+)
         (ec-point-equal res1 res2))))

(defmethod make-public-key ((kind (eql :ed448)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'ed448
           :parameter 'y
           :description "public key"))
  (make-instance 'ed448-public-key :y y))

(defmethod destructure-public-key ((public-key ed448-public-key))
  (list :y (ed448-key-y public-key)))

(defmethod make-private-key ((kind (eql :ed448)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'ed448
           :parameter 'x
           :description "private key"))
  (make-instance 'ed448-private-key :x x :y (or y (ed448-public-key x))))

(defmethod destructure-private-key ((private-key ed448-private-key))
  (list :x (ed448-key-x private-key)
        :y (ed448-key-y private-key)))

(defmethod sign-message ((key ed448-private-key) message &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (sk (ed448-key-x key))
        (pk (ed448-key-y key)))
    (ed448-sign (subseq message start end) sk pk)))

(defmethod verify-signature ((key ed448-public-key) message signature &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (pk (ed448-key-y key)))
    (ed448-verify signature (subseq message start end) pk key)))

(defmethod generate-key-pair ((kind (eql :ed448)) &key &allow-other-keys)
  (let* ((sk (random-data (ceiling +ed448-bits+ 8)))
         (pk (ed448-public-key sk)))
    (values (make-private-key :ed448 :x sk :y pk)
            (make-public-key :ed448 :y pk))))
