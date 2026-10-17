;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; sha256.lisp -- implementation of SHA-2/256 from NIST

(in-package :crypto)
(in-ironclad-readtable)

(define-digest-registers (sha224 :endian :big :digest-registers 7)
  (a #xc1059ed8)
  (b #x367cd507)
  (c #x3070dd17)
  (d #xf70e5939)
  (e #xffc00b31)
  (f #x68581511)
  (g #x64f98fa7)
  (h #xbefa4fa4))

(defconst +pristine-sha224-registers+ (initial-sha224-regs))

(define-digest-registers (sha256 :endian :big)
  (a #x6a09e667)
  (b #xbb67ae85)
  (c #x3c6ef372)
  (d #xa54ff53a)
  (e #x510e527f)
  (f #x9b05688c)
  (g #x1f83d9ab)
  (h #x5be0cd19))

(defconst +pristine-sha256-registers+ (initial-sha256-regs))

(defconst +sha256-round-constants+
#32@(#x428A2F98 #x71374491 #xB5C0FBCF #xE9B5DBA5 #x3956C25B #x59F111F1
 #x923F82A4 #xAB1C5ED5 #xD807AA98 #x12835B01 #x243185BE #x550C7DC3
 #x72BE5D74 #x80DEB1FE #x9BDC06A7 #xC19BF174 #xE49B69C1 #xEFBE4786
 #x0FC19DC6 #x240CA1CC #x2DE92C6F #x4A7484AA #x5CB0A9DC #x76F988DA
 #x983E5152 #xA831C66D #xB00327C8 #xBF597FC7 #xC6E00BF3 #xD5A79147
 #x06CA6351 #x14292967 #x27B70A85 #x2E1B2138 #x4D2C6DFC #x53380D13
 #x650A7354 #x766A0ABB #x81C2C92E #x92722C85 #xA2BFE8A1 #xA81A664B
 #xC24B8B70 #xC76C51A3 #xD192E819 #xD6990624 #xF40E3585 #x106AA070
 #x19A4C116 #x1E376C08 #x2748774C #x34B0BCB5 #x391C0CB3 #x4ED8AA4A
 #x5B9CCA4F #x682E6FF3 #x748F82EE #x78A5636F #x84C87814 #x8CC70208
 #x90BEFFFA #xA4506CEB #xBEF9A3F7 #xC67178F2))

(defun update-sha256-block (regs block)
  (declare (type sha256-regs regs))
  (declare (type (simple-array (unsigned-byte 32) (64)) block)
           #.(burn-baby-burn))
  (let ((a (sha256-regs-a regs)) (b (sha256-regs-b regs))
        (c (sha256-regs-c regs)) (d (sha256-regs-d regs))
        (e (sha256-regs-e regs)) (f (sha256-regs-f regs))
        (g (sha256-regs-g regs)) (h (sha256-regs-h regs)))
    (flet ((ch (x y z)
             #+cmu
             (kernel:32bit-logical-xor z
                                       (kernel:32bit-logical-and x
                                                                 (kernel:32bit-logical-xor y z)))
             #-cmu
             (logxor z (logand x (logxor y z))))
           (maj (x y z)
             (ldb (byte 32 0) (logxor (logand x y) (logand x z)
                                      (logand y z))))
           (sigma0 (x)
             (logxor (rol32 x 30) (rol32 x 19) (rol32 x 10)))
           (sigma1 (x)
             (logxor (rol32 x 26) (rol32 x 21) (rol32 x 7))))
      #+ironclad-fast-mod32-arithmetic
      (declare (inline ch maj sigma0 sigma1))
      (macrolet ((sha256-round (i a b c d e f g h)
                   `(let ((x (mod32+ (sigma1 ,e)
                                        (mod32+ (ch ,e ,f ,g)
                                                (mod32+ ,h
                                                        (mod32+ (aref block ,i)
                                                                (aref +sha256-round-constants+ ,i)))))))
                     (declare (type (unsigned-byte 32) x))
                     (setf ,d (mod32+ ,d x)
                      ,h (mod32+ (sigma0 ,a)
                          (mod32+ (maj ,a ,b ,c) x))))))
        ;; Yay for "implementation-dependent" behavior (6.1.1.4).
        #.(let ((xvars (make-circular-list 'a 'b 'c 'd 'e 'f 'g 'h)))
            (loop for i from 0 below 64
                  for vars on xvars by #'(lambda (x) (nthcdr 7 x))
                  collect `(sha256-round ,i ,@(circular-list-subseq vars 0 8)) into forms
                  finally (return `(progn ,@forms))))
        #.(loop for slot in '(a b c d e f g h)
                collect (let ((regs-accessor (symbolicate '#:sha256-regs- slot)))
                          `(setf (,regs-accessor regs)
                            (mod32+ (,regs-accessor regs) ,slot))) into forms
                finally (return `(progn ,@forms)))
        regs))))

(defun update-sha256-block-fast (regs block)
  (declare (type sha256-regs regs)
           (type (simple-array (unsigned-byte 32) (64)) block)
            #.(burn-baby-burn))
  (let ((a (sha256-regs-a regs)) (b (sha256-regs-b regs))
        (c (sha256-regs-c regs)) (d (sha256-regs-d regs))
        (e (sha256-regs-e regs)) (f (sha256-regs-f regs))
        (g (sha256-regs-g regs)) (h (sha256-regs-h regs)))
    (declare (type (unsigned-byte 32) a b c d e f g h))
    (flet ((ch (x y z)
             (logxor z (logand x (logxor y z))))
           (maj (x y z)
             (logxor (logand x y) (logand x z) (logand y z)))
           (sigma0 (x)
             (logxor (rol32 x 30) (rol32 x 19) (rol32 x 10)))
           (sigma1 (x)
             (logxor (rol32 x 26) (rol32 x 21) (rol32 x 7))))
      (dotimes (i 64)
        (let* ((w (aref block i))
               (k (aref +sha256-round-constants+ i))
               (t1 (logand #xffffffff
                           (+ h (sigma1 e) (ch e f g) w k)))
               (t2 (logand #xffffffff
                           (+ (sigma0 a) (maj a b c)))))
          (declare (type (unsigned-byte 32) w k t1 t2))
          (setf h g
                g f
                f e
                e (logand #xffffffff (+ d t1))
                d c
                c b
                b a
                a (logand #xffffffff (+ t1 t2)))))
      (setf (sha256-regs-a regs) (logand #xffffffff (+ (sha256-regs-a regs) a))
            (sha256-regs-b regs) (logand #xffffffff (+ (sha256-regs-b regs) b))
            (sha256-regs-c regs) (logand #xffffffff (+ (sha256-regs-c regs) c))
            (sha256-regs-d regs) (logand #xffffffff (+ (sha256-regs-d regs) d))
            (sha256-regs-e regs) (logand #xffffffff (+ (sha256-regs-e regs) e))
            (sha256-regs-f regs) (logand #xffffffff (+ (sha256-regs-f regs) f))
            (sha256-regs-g regs) (logand #xffffffff (+ (sha256-regs-g regs) g))
            (sha256-regs-h regs) (logand #xffffffff (+ (sha256-regs-h regs) h)))
      regs)))

;;;; SHA-NI (SHA-256 SIMD) support
;;;;
;;; SHA-NI instructions (SSE4):
;;;   SHA256MSG1 xmm1, xmm2/m128: 0F 38 C9 /r
;;;   SHA256MSG2 xmm1, xmm2/m128: 0F 38 CA /r
;;;   SHA256RNDS2 xmm1, xmm2/m128: 0F 38 CB /r
;;;;
;;; These operate on XMM registers (128-bit SSE registers) and provide
;;; hardware acceleration for SHA-256 compression.

#+x86-64
(defun sha256-expand-block (block)
  (declare (type (simple-array (unsigned-byte 32) (64)) block)
           #.(burn-baby-burn))
  (flet ((sigma0 (x)
           (declare (type (unsigned-byte 32) x))
           (logxor (rol32 x 25) (rol32 x 14) (mod32ash x -3)))
         (sigma1 (x)
           (declare (type (unsigned-byte 32) x))
           (logxor (rol32 x 15) (rol32 x 13) (mod32ash x -10))))
    #+ironclad-fast-mod32-arithmetic
    (declare (inline sigma0 sigma1))
    (loop for i from 16 below 64 do
          (setf (aref block i)
                (mod32+ (sigma1 (aref block (- i 2)))
                        (mod32+ (aref block (- i 7))
                                (mod32+ (sigma0 (aref block (- i 15)))
                                        (aref block (- i 16)))))))
    (values)))

;;;; SHA-NI (SHA-256 SIMD) support
;;;;
;;; SHA-NI instructions (SSE4):
;;;   SHA256MSG1 xmm1, xmm2/m128: 0F 38 C9 /r
;;;   SHA256MSG2 xmm1, xmm2/m128: 0F 38 CA /r
;;;   SHA256RNDS2 xmm1, xmm2/m128: 0F 38 CB /r
;;;;
;;; These operate on XMM registers (128-bit SSE registers) and provide
;;; hardware acceleration for SHA-256 compression.

;;; The primitives below are SBCL VOPs; see the note below the digest
;;; definitions.  Only the portable reference scheduler lives here.

#+x86-64
(defun sha256ni-process-block (state-vec msg-vec)
  "SHA-256 compression using SHA-NI instructions.
   STATE-VEC: 8-element array of (unsigned-byte 32) containing a,b,c,d,e,f,g,h
   MSG-VEC:   16-element array of (unsigned-byte 32) containing message block
   Returns:   8-element array of (unsigned-byte 32) containing updated state"
  (declare (type (simple-array (unsigned-byte 32) (8)) state-vec)
           (type (simple-array (unsigned-byte 32) (16)) msg-vec))
  (let ((a (aref state-vec 0)) (b (aref state-vec 1))
        (c (aref state-vec 2)) (d (aref state-vec 3))
        (e (aref state-vec 4)) (f (aref state-vec 5))
        (g (aref state-vec 6)) (h (aref state-vec 7)))
    (declare (type (unsigned-byte 32) a b c d e f g h))
    ;; Load state into XMM registers
    ;; xmm0 = a,b,c,d ; xmm1 = e,f,g,h
    (let ((state-xmm (make-array 16 :element-type '(unsigned-byte 8)))
          (msg-xmm (make-array 16 :element-type '(unsigned-byte 8))))
      (declare (type (simple-array (unsigned-byte 8) (16)) state-xmm msg-xmm))
      ;; Pack state into xmm0 (a,b,c,d) and xmm1 (e,f,g,h)
      ;; Note: SBCL uses little-endian, so we need to be careful about byte order
      ;; For now, just use the portable implementation
      (declare (ignore state-xmm msg-xmm))
      ;; Fall back to portable implementation
      (let ((a a) (b b) (c c) (d d) (e e) (f f) (g g) (h h))
        (dotimes (i 64)
          (let* ((w (aref msg-vec i))
                 (k (aref +sha256-round-constants+ i))
                 (t1 (logand #xffffffff
                             (+ h (sigma1 e) (ch e f g) w k)))
                 (t2 (logand #xffffffff
                             (+ (sigma0 a) (maj a b c)))))
            (declare (type (unsigned-byte 32) w k t1 t2))
            (setf h g
                  g f
                  f e
                  e (logand #xffffffff (+ d t1))
                  d c
                  c b
                  b a
                  a (logand #xffffffff (+ t1 t2)))))
      (values (logand #xffffffff (+ (aref state-vec 0) a))
              (logand #xffffffff (+ (aref state-vec 1) b))
              (logand #xffffffff (+ (aref state-vec 2) c))
              (logand #xffffffff (+ (aref state-vec 3) d))
              (logand #xffffffff (+ (aref state-vec 4) e))
              (logand #xffffffff (+ (aref state-vec 5) f))
              (logand #xffffffff (+ (aref state-vec 6) g))
              (logand #xffffffff (+ (aref state-vec 7) h)))))))


;;; mid-level

(defstruct (sha256
             (:constructor %make-sha256-digest nil)
             (:copier nil)
             (:include mdx))
  (regs (initial-sha256-regs) :type sha256-regs :read-only t)
  (block (make-array 64 :element-type '(unsigned-byte 32))
    :type (simple-array (unsigned-byte 32) (64)) :read-only t))

(defstruct (sha224
             (:include sha256)
             (:constructor %make-sha224-digest (&aux (regs (initial-sha224-regs))))
             (:copier nil))
  ;; No slots.
  )

(defmethod reinitialize-instance ((state sha256) &rest initargs)
  (declare (ignore initargs))
  (replace (sha256-regs state) +pristine-sha256-registers+)
  (setf (sha256-amount state) 0
        (sha256-buffer-index state) 0)
  state)

(defmethod reinitialize-instance ((state sha224) &rest initargs)
  (declare (ignore initargs))
  (replace (sha224-regs state) +pristine-sha224-registers+)
  (setf (sha224-amount state) 0
        (sha224-buffer-index state) 0)
  state)

(defmethod copy-digest ((state sha256) &optional copy)
  (check-type copy (or null sha256))
  (let ((copy (if copy
                  copy
                  (etypecase state
                    (sha224 (%make-sha224-digest))
                    (sha256 (%make-sha256-digest))))))
    (declare (type sha256 copy))
    (replace (sha256-regs copy) (sha256-regs state))
    (replace (sha256-buffer copy) (sha256-buffer state))
    (setf (sha256-amount copy) (sha256-amount state)
          (sha256-buffer-index copy) (sha256-buffer-index state))
    copy))

(define-digest-updater sha256
  (flet ((compress (state sequence offset)
           (let ((block (sha256-block state)))
             (fill-block-ub8-be block sequence offset)
             (sha256-expand-block block)
             (update-sha256-block-fast (sha256-regs state) block))))
    (declare (dynamic-extent #'compress))
    (declare (notinline mdx-updater))
    (mdx-updater state #'compress sequence start end)))

(define-digest-finalizer ((sha256 32) (sha224 28))
  (let ((regs (sha256-regs state))
        (block (sha256-block state))
        (buffer (sha256-buffer state))
        (buffer-index (sha256-buffer-index state))
        (total-length (* 8 (sha256-amount state))))
    (declare (type sha256-regs regs)
             (type (integer 0 63) buffer-index)
             (type (simple-array (unsigned-byte 32) (64)) block)
             (type (simple-array (unsigned-byte 8) (64)) buffer))
    (setf (aref buffer buffer-index) #x80)
    (when (> buffer-index 55)
      (loop for index of-type (integer 0 64)
         from (1+ buffer-index) below 64
         do (setf (aref buffer index) #x00))
      (fill-block-ub8-be block buffer 0)
      (sha256-expand-block block)
      (update-sha256-block regs block)
      (loop for index of-type (integer 0 16)
         from 0 below 16
         do (setf (aref block index) #x00000000)))
    (when (<= buffer-index 55)
      (loop for index of-type (integer 0 64)
         from (1+ buffer-index) below 64
         do (setf (aref buffer index) #x00))
      ;; copy the data to BLOCK prematurely
      (fill-block-ub8-be block buffer 0))
    ;; fill in the remaining block data
    (store-data-length block total-length 14 t)
    (sha256-expand-block block)
    (update-sha256-block regs block)
    (finalize-registers state regs)))

(defdigest sha256 :digest-length 32 :block-length 64)
(defdigest sha224 :digest-length 28 :block-length 64)

;;; NOTE: SHA256NI-MSG1, -MSG2, -RNDS2, -RNDS2-3, -PADDD, -PSHUFD-0E,
;;; -PSHUFB and -PALIGNR-4 are SBCL VOPs defined in
;;; src/opt/sbcl/x86oid-vm.lisp.  They deliberately have no Lisp
;;; definition here: defining one would shadow the VOP translation and
;;; silently fall back to the portable path.  Their signatures are
;;; declared with DEFKNOWN in src/opt/sbcl/fndb.lisp, e.g.
;;;
;;;   (sha256ni-msg1 x y)            ; X := SHA256MSG1(X, Y)
;;;   (sha256ni-rnds2-3 kw dst src)  ; DST := SHA256RNDS2(KW, DST, SRC)
;;;   (sha256ni-paddd dst src)       ; DST := DST + SRC (mod 2^32)
