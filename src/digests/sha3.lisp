;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; sha3.lisp -- implementation of SHA-3 from NIST

(in-package :crypto-unsafe)


;;;
;;; Keccak state and parameters
;;;

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defconstant +keccak-state-columns+ 5)
  (defconstant +keccak-state-rows+ 5)
  (defconstant +keccak-state-lanes+ 25)
  (defconstant +keccak-lane-width+ 64)
  (defconstant +keccak-lane-byte-width+ 8)
  (defconstant +keccak-rounds+ 24))

(deftype keccak-lane ()
  `(unsigned-byte ,+keccak-lane-width+))

(deftype keccak-state ()
  `(simple-array keccak-lane (,+keccak-state-lanes+)))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defconst +keccak-rotate-offsets+
    (make-array (list +keccak-state-columns+ +keccak-state-rows+)
                :element-type '(unsigned-byte 8)
                :initial-contents '(( 0 36  3 41 18)
                                    ( 1 44 10 45  2)
                                    (62  6 43 15 61)
                                    (28 55 25 21 56)
                                    (27 20 39  8 14))))

  (defconst +keccak-round-constants+
    (make-array 24
                :element-type 'keccak-lane
                :initial-contents '(#x0000000000000001
                                    #x0000000000008082
                                    #x800000000000808a
                                    #x8000000080008000
                                    #x000000000000808b
                                    #x0000000080000001
                                    #x8000000080008081
                                    #x8000000000008009
                                    #x000000000000008a
                                    #x0000000000000088
                                    #x0000000080008009
                                    #x000000008000000a
                                    #x000000008000808b
                                    #x800000000000008b
                                    #x8000000000008089
                                    #x8000000000008003
                                    #x8000000000008002
                                    #x8000000000000080
                                    #x000000000000800a
                                    #x800000008000000a
                                    #x8000000080008081
                                    #x8000000000008080
                                    #x0000000080000001
                                    #x8000000080008008))))

(defmacro get-keccak-rotate-offset (x y &environment env)
  (aref +keccak-rotate-offsets+
        (eval (trivial-macroexpand-all x env))
        (eval (trivial-macroexpand-all y env))))

(declaim (inline get-keccak-round-constant)
         (ftype (function ((integer 0 23)) keccak-lane) get-keccak-round-constant))
(defun get-keccak-round-constant (i)
  (declare (type (integer 0 23) i)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((constants (load-time-value +keccak-round-constants+ t)))
    (declare (type (simple-array keccak-lane (24)) constants))
    (aref constants i)))

(declaim (inline make-keccak-state)
         (ftype (function () keccak-state) make-keccak-state))
(defun make-keccak-state ()
  (declare (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (make-array #.+keccak-state-lanes+ :element-type 'keccak-lane :initial-element 0))


;;;
;;; Transforming linear input/output to state array
;;;

(defun keccak-state-merge-input (state bit-rate input start)
  (declare (type keccak-state state)
           (type (integer 0 1600) bit-rate)
           (type (simple-array (unsigned-byte 8) (*)) input)
           (type fixnum start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((rate-bytes (truncate bit-rate 8)))
    (declare (type (integer 0 200) rate-bytes))
    (dotimes (y +keccak-state-rows+)
      (dotimes (x +keccak-state-columns+)
        (let* ((element (+ (the fixnum (* y +keccak-state-columns+)) x))
               (offset (* element +keccak-lane-byte-width+))
               (index (the fixnum (+ start offset))))
          (when (>= offset rate-bytes)
            (return-from keccak-state-merge-input))
          ;; Build the lane as two fixnum halves; the old code shifted
          ;; each byte into place separately, boxing intermediately.
          (let ((lo (+ (aref input index)
                       (ash (aref input (+ index 1)) 8)
                       (ash (aref input (+ index 2)) 16)
                       (ash (aref input (+ index 3)) 24)))
                (hi (+ (aref input (+ index 4))
                       (ash (aref input (+ index 5)) 8)
                       (ash (aref input (+ index 6)) 16)
                       (ash (aref input (+ index 7)) 24))))
            (declare (type (unsigned-byte 32) lo hi))
            (setf (aref state element)
                  (logxor (aref state element)
                          (+ lo (ash hi 32))))))))))

(defun keccak-state-extract-output (state output-bytes &optional (digest nil) (start 0))
  (let* ((digest (or digest
                     (make-array (list output-bytes) :element-type '(unsigned-byte 8))))
         (lanes (min (* +keccak-state-columns+ +keccak-state-rows+)
                     (ceiling output-bytes +keccak-lane-byte-width+))))
    (declare (type keccak-state state)
             (type fixnum output-bytes start)
             (type (simple-array (unsigned-byte 8) (*)) digest))
    ;; Only the first LANES elements can contribute output: the digest is
    ;; the little-endian state array, so element N lives at byte 8N.  When
    ;; the whole lane fits, store it with one unaligned 64-bit write; the
    ;; tail lane, if any, still goes out byte by byte.
    (dotimes (element lanes)
      (let* ((offset (* element +keccak-lane-byte-width+))
             (base (+ start offset))
             (lane (aref state element)))
        (declare (type fixnum offset base))
        (if (<= (+ offset +keccak-lane-byte-width+) output-bytes)
            (setf (ub64ref/le digest base) lane)
            ;; Split the lane once and store the remaining bytes with
            ;; constant shift counts.  A variable (byte 8 (* 8 i)) put
            ;; SBCL on the generic path, which cost a quarter of ML-DSA
            ;; verification.
            (let* ((lo (ldb (byte 32 0) lane))
                   (hi (ldb (byte 32 32) lane))
                   (limit (+ start output-bytes)))
              (declare (type (unsigned-byte 32) lo hi)
                       (type fixnum limit))
              (macrolet ((put (at shift value)
                           `(when (< (+ base ,at) limit)
                              (setf (aref digest (+ base ,at))
                                    (ldb (byte 8 ,shift) ,value)))))
                (put 0 0 lo) (put 1 8 lo) (put 2 16 lo) (put 3 24 lo)
                (put 4 0 hi) (put 5 8 hi) (put 6 16 hi) (put 7 24 hi))))))
    digest))


;;;
;;; Keccak rounds
;;;

(defmacro with-keccak-state-accessors ((&rest states) &body body)
  "Bind the contents of the state(s) array(s) to local variables, and save
the content on normal form exit."
  (let ((bindings nil) (mappings nil) (save-forms nil))
    (loop for state in states
          for map = (make-array '(#.+keccak-state-columns+ #.+keccak-state-rows+))
          do
       (dotimes (y +keccak-state-rows+)
         (dotimes (x +keccak-state-columns+)
           (let ((sym (make-symbol (format nil "~A-~D-~D" state x y))))
             (setf (aref map x y) sym)
             (push `(,sym (aref ,state ,(+ x (* y +keccak-state-columns+))))
                   bindings)
             (push `(setf (aref ,state ,(+ x (* y +keccak-state-columns+))) ,sym)
                   save-forms))))
       (push (cons state map) mappings))
    `(let (,@bindings)
       (declare (ignorable ,@(mapcar #'car bindings))
                (type keccak-lane ,@(mapcar #'car bindings)))
       (macrolet ((state-aref (state x y &environment env)
                    (let ((entry (assoc state ',mappings)))
                      (unless entry (error 'ironclad-unsafe-error
                                           :format-control "Strange: ~S!"
                                           :format-arguments (list state)))
                      (aref (cdr entry)
                            (eval (trivial-macroexpand-all x env))
                            (eval (trivial-macroexpand-all y env))))))
         (multiple-value-prog1 (progn ,@body)
           ,@save-forms)))))

(defmacro with-temp-keccak-state ((&rest temps) &body body)
  "Bind local variables for each temporary state."
  (let ((bindings nil) (mappings nil))
    (loop for temp in temps
          for map = (make-array '(#.+keccak-state-columns+ #.+keccak-state-rows+))
          do
       (dotimes (y +keccak-state-rows+)
         (dotimes (x +keccak-state-columns+)
           (let ((sym (make-symbol (format nil "~A-~D-~D" temp x y))))
             (setf (aref map x y) sym)
             (push `(,sym 0) bindings))))
       (push (cons temp map) mappings))
    `(let (,@bindings)
       (declare (ignorable ,@(mapcar #'car bindings))
                (type keccak-lane ,@(mapcar #'car bindings)))
       (macrolet ((temp-state-aref (temp x y &environment env)
                    (let ((entry (assoc temp ',mappings)))
                      (unless entry (error 'ironclad-unsafe-error
                                           :format-control "Strange: ~S!"
                                           :format-arguments (list temp)))
                      (aref (cdr entry)
                            (eval (trivial-macroexpand-all x env))
                            (eval (trivial-macroexpand-all y env))))))
         ,@body))))

(defmacro with-temp-keccak-rows ((&rest rows) &body body)
  "Bind local variables for each temporary row."
  (let ((bindings nil) (mappings nil))
    (loop for row in rows
          for map = (make-array '(#.+keccak-state-columns+))
          do
       (dotimes (x +keccak-state-columns+)
         (let ((sym (make-symbol (format nil "~A-~D" row x))))
           (setf (aref map x) sym)
           (push `(,sym 0) bindings)))
       (push (cons row map) mappings))
    `(let (,@bindings)
       (declare (ignorable ,@(mapcar #'car bindings))
                (type keccak-lane ,@(mapcar #'car bindings)))
       (macrolet ((temp-row-aref (row x &environment env)
                    (let ((entry (assoc row ',mappings)))
                      (unless entry (error 'ironclad-unsafe-error
                                           :format-control "Strange: ~S!"
                                           :format-arguments (list row)))
                      (aref (cdr entry)
                            (eval (trivial-macroexpand-all x env))))))
         ,@body))))

(declaim (ftype (function (keccak-state)) keccak-rounds))
(defun keccak-rounds (state)
  (declare (type keccak-state state)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (with-keccak-state-accessors (state)
    (with-temp-keccak-state (b)
      (with-temp-keccak-rows (c d)
        (dotimes (i #.+keccak-rounds+)
          (dotimes-unrolled (x +keccak-state-columns+)
            (setf (temp-row-aref c x)
                  (logxor (state-aref state x 0)
                          (state-aref state x 1)
                          (state-aref state x 2)
                          (state-aref state x 3)
                          (state-aref state x 4))))
          (dotimes-unrolled (x +keccak-state-columns+)
            (setf (temp-row-aref d x)
                  (logxor (temp-row-aref c (mod (+ +keccak-state-columns+ (1- x)) +keccak-state-columns+))
                          (rol64 (temp-row-aref c (mod (1+ x) +keccak-state-columns+)) 1))))
          (dotimes-unrolled (x +keccak-state-columns+)
            (dotimes-unrolled (y +keccak-state-rows+)
              (setf (state-aref state x y)
                    (logxor (state-aref state x y) (temp-row-aref d x)))))
          (dotimes-unrolled (x +keccak-state-columns+)
            (dotimes-unrolled (y +keccak-state-rows+)
              (setf (temp-state-aref b y (mod (+ (* 2 x) (* 3 y)) +keccak-state-rows+))
                    (rol64 (state-aref state x y) (get-keccak-rotate-offset x y)))))
          (dotimes-unrolled (x +keccak-state-columns+)
            (dotimes-unrolled (y +keccak-state-rows+)
              (setf (state-aref state x y)
                    (logxor (temp-state-aref b x y)
                            (logandc1 (temp-state-aref b (mod (1+ x) +keccak-state-columns+) y)
                                      (temp-state-aref b (mod (+ x 2) +keccak-state-columns+) y))))))
          (setf (state-aref state 0 0) (logxor (state-aref state 0 0)
                                               (get-keccak-round-constant i)))))))
  (values))




;;;
;;; SHA-3
;;;

(defstruct (sha3
             (:constructor %make-sha3-digest nil)
             (:copier nil))
  (state (make-keccak-state) :type keccak-state)
  (bit-rate 576 :type (integer 0 1600))
  (buffer (make-array 200 :element-type '(unsigned-byte 8))
          :type (simple-array (unsigned-byte 8) (200)))
  (buffer-index 0 :type (integer 0 199))
  (output-length 64))

(defstruct (sha3/384
             (:include sha3)
             (:constructor %make-sha3/384-digest
                           (&aux (bit-rate 832)
                                 (output-length 48)))
             (:copier nil)))

(defstruct (sha3/256
             (:include sha3)
             (:constructor %make-sha3/256-digest
                           (&aux (bit-rate 1088)
                                 (output-length 32)))
             (:copier nil)))

(defstruct (sha3/224
             (:include sha3)
             (:constructor %make-sha3/224-digest
                           (&aux (bit-rate 1152)
                                 (output-length 28)))
             (:copier nil)))

(defstruct (keccak
             (:include sha3)
             (:constructor %make-keccak-digest
                           (&aux (bit-rate 576)
                                 (output-length 64)))
             (:copier nil)))

(defstruct (keccak/384
             (:include sha3)
             (:constructor %make-keccak/384-digest
                           (&aux (bit-rate 832)
                                 (output-length 48)))
             (:copier nil)))

(defstruct (keccak/256
             (:include sha3)
             (:constructor %make-keccak/256-digest
                           (&aux (bit-rate 1088)
                                 (output-length 32)))
             (:copier nil)))

(defstruct (keccak/224
             (:include sha3)
             (:constructor %make-keccak/224-digest
                           (&aux (bit-rate 1152)
                                 (output-length 28)))
             (:copier nil)))

(defstruct (shake256
             (:include sha3)
             (:constructor %make-shake256 (bit-rate output-length))
             (:copier nil)))

(defstruct (shake128
             (:include sha3)
             (:constructor %make-shake128 (bit-rate output-length))
             (:copier nil)))

(defun %make-shake256-digest (&key (output-length 32))
  (%make-shake256 1088 output-length))

(defun %make-shake128-digest (&key (output-length 16))
  (%make-shake128 1344 output-length))

(defmethod block-length ((state shake256))
  136)

(defmethod block-length ((state shake128))
  168)

(defmethod digest-length ((state shake256))
  (sha3-output-length state))

(defmethod digest-length ((state shake128))
  (sha3-output-length state))

(defmethod reinitialize-instance ((state sha3) &rest initargs)
  (declare (ignore initargs))
  (setf (sha3-state state) (make-keccak-state))
  (setf (sha3-buffer-index state) 0)
  state)

(defmethod copy-digest ((state sha3) &optional copy)
  (check-type copy (or null sha3))
  (let ((copy (if copy
                  copy
                  (etypecase state
                    (shake128 (%make-shake128-digest))
                    (shake256 (%make-shake256-digest))
                    (keccak/224 (%make-keccak/224-digest))
                    (keccak/256 (%make-keccak/256-digest))
                    (keccak/384 (%make-keccak/384-digest))
                    (keccak (%make-keccak-digest))
                    (sha3/224 (%make-sha3/224-digest))
                    (sha3/256 (%make-sha3/256-digest))
                    (sha3/384 (%make-sha3/384-digest))
                    (sha3 (%make-sha3-digest))))))
    (declare (type sha3 copy))
    (replace (sha3-state copy) (sha3-state state))
    (setf (sha3-bit-rate copy) (sha3-bit-rate state))
    (replace (sha3-buffer copy) (sha3-buffer state))
    (setf (sha3-buffer-index copy) (sha3-buffer-index state))
    (setf (sha3-output-length copy) (sha3-output-length state))
    copy))

(defun sha3-update (state vector start end)
  (declare (type sha3 state)
           (type (simple-array (unsigned-byte 8) (*)) vector)
           (type fixnum start end)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((keccak-state (sha3-state state))
         (buffer (sha3-buffer state))
         (buffer-index (sha3-buffer-index state))
         (bit-rate (sha3-bit-rate state))
         (rate-bytes (truncate bit-rate 8)))
    (declare (type keccak-state keccak-state)
             (type (simple-array (unsigned-byte 8) (200)) buffer)
             (type (integer 0 199) buffer-index)
             (type (integer 0 1600) bit-rate)
             (type (integer 0 200) rate-bytes))

    ;; Handle potential remaining bytes
    (unless (zerop buffer-index)
      (let ((remainder (- rate-bytes buffer-index))
            (length (- end start)))
        (declare (type fixnum remainder length))
        (replace buffer vector :start1 buffer-index :end1 rate-bytes :start2 start :end2 end)

        ;; Return if still unfilled buffer
        (when (< length remainder)
          (incf (sha3-buffer-index state) length)
          (return-from sha3-update))

        ;; Else handle now complete buffer
        (keccak-state-merge-input keccak-state bit-rate buffer 0)
        (keccak-rounds keccak-state)
        (setf (sha3-buffer-index state) 0)
        (setf start (+ start remainder))))

    ;; Now handle full blocks, stuff any remainder into buffer
    (loop for block-offset of-type fixnum from start below end by rate-bytes
          do (cond
               ((<= (+ block-offset rate-bytes) end)
                (keccak-state-merge-input keccak-state bit-rate vector block-offset)
                (keccak-rounds keccak-state))
               (t
                (replace buffer vector :start1 0 :end1 rate-bytes :start2 block-offset :end2 end)
                (setf (sha3-buffer-index state) (- end block-offset))))))
  (values))

(defun sha3-finalize (state digest digest-start)
  (declare (type sha3 state)
           (type (simple-array (unsigned-byte 8) (*)) digest)
           (type integer digest-start)
           (optimize (speed 3) (safety 1) (space 0) (debug 0)))
  (let ((padding-type (cond ((typep state '(or shake128 shake256))
                                 :xof)
                                ;; cshake lives in a later-loaded subsystem;
                                ;; resolve it dynamically so standalone SHA-3
                                ;; keeps working.  Empty cSHAKE degrades to
                                ;; SHAKE entirely, padding included.
                                ((let ((cshake-class (find-class 'cshake nil)))
                                   (and cshake-class (typep state cshake-class)))
                                 (if (and (zerop (length (slot-value state 'function-name)))
                                          (zerop (length (slot-value state 'customization))))
                                     :xof
                                     :cshake))
                                ((typep state '(or keccak/224 keccak/256 keccak/384 keccak))
                                 :keccak)
                                (t :sha3)))
        (keccak-state (sha3-state state))
        (buffer (sha3-buffer state))
        (buffer-index (sha3-buffer-index state))
        (bit-rate (sha3-bit-rate state))
        (output-byte-length (digest-length state)))
    (declare (type keccak-state keccak-state)
             (type (simple-array (unsigned-byte 8) (200)) buffer)
             (type (integer 0 199) buffer-index)
             (type (integer 0 1600) bit-rate)
             (type integer output-byte-length))

    ;; Pad in place and absorb only the lanes that can be nonzero.
    ;; PAD-MESSAGE-TO-WIDTH used to allocate a fresh padded block, copy
    ;; the message into it and absorb the whole rate; an SLH-DSA hash
    ;; pads a 16-octet message in a 136-octet rate, so 14 of the 17
    ;; lanes were zeros absorbed thousands of times per operation.
    (let* ((rate-bytes (truncate bit-rate 8))
           (last-byte (1- rate-bytes))
           (last-lane (1- (truncate rate-bytes +keccak-lane-byte-width+)))
           (pad-lane (truncate buffer-index +keccak-lane-byte-width+))
           (pad-lane-end (1- (* +keccak-lane-byte-width+ (1+ pad-lane))))
           (pad-byte (ecase padding-type
                       (:xof #x1f) (:cshake #x04) (:keccak #x01) (:sha3 #x06))))
      (declare (type fixnum rate-bytes last-byte last-lane
                     pad-lane pad-lane-end)
               (type (unsigned-byte 8) pad-byte))
      (setf (aref buffer buffer-index) pad-byte)
      (loop for index of-type fixnum from (1+ buffer-index) to pad-lane-end
            do (setf (aref buffer index) #x00))
      (when (= pad-lane last-lane)
        (setf (aref buffer last-byte)
              (logior #x80 (aref buffer last-byte))))
      (keccak-state-merge-input keccak-state
                                (* 8 +keccak-lane-byte-width+ (1+ pad-lane))
                                buffer 0)
      ;; The 0x80 terminator sits in the last lane; add it directly
      ;; instead of absorbing the run of zeros between the two lanes.
      (unless (= pad-lane last-lane)
        (setf (aref keccak-state last-lane)
              (logxor (aref keccak-state last-lane) (ash #x80 56)))))
    (keccak-rounds keccak-state)
    (setf (sha3-buffer-index state) 0)

    ;; Get output
    (let ((output-size 0)
          (chunk-size (truncate bit-rate 8)))
      (loop until (= output-size output-byte-length) do
        (let ((n (min (- output-byte-length output-size) chunk-size)))
          (keccak-state-extract-output keccak-state n digest (+ digest-start output-size))
          (incf output-size n)
          (keccak-rounds keccak-state))))
    digest))

(define-digest-updater sha3
  (sha3-update state sequence start end))

(define-digest-finalizer ((sha3 64)
                          (sha3/384 48)
                          (sha3/256 32)
                          (sha3/224 28)
                          (keccak 64)
                          (keccak/384 48)
                          (keccak/256 32)
                          (keccak/224 28))
  (sha3-finalize state digest digest-start))

(defdigest sha3 :digest-length 64 :block-length 72)
(defdigest sha3/384 :digest-length 48 :block-length 104)
(defdigest sha3/256 :digest-length 32 :block-length 136)
(defdigest sha3/224 :digest-length 28 :block-length 144)

(defdigest keccak :digest-length 64 :block-length 72)
(defdigest keccak/384 :digest-length 48 :block-length 104)
(defdigest keccak/256 :digest-length 32 :block-length 136)
(defdigest keccak/224 :digest-length 28 :block-length 144)

(defmethod produce-digest ((state shake256) &key digest (digest-start 0))
  (let ((digest-size (digest-length state))
        (state-copy (copy-digest state)))
    (if digest
        (if (> digest-size (- (length digest) digest-start))
            (error 'insufficient-buffer-space
                   :buffer digest :start digest-start
                   :length digest-size)
            (sha3-finalize state-copy digest digest-start))
        (sha3-finalize state-copy
                       (make-array digest-size :element-type '(unsigned-byte 8))
                       0))))

(defmethod produce-digest ((state shake128) &key digest (digest-start 0))
  (let ((digest-size (digest-length state))
        (state-copy (copy-digest state)))
    (if digest
        (if (> digest-size (- (length digest) digest-start))
            (error 'insufficient-buffer-space
                   :buffer digest :start digest-start
                   :length digest-size)
            (sha3-finalize state-copy digest digest-start))
        (sha3-finalize state-copy
                       (make-array digest-size :element-type '(unsigned-byte 8))
                       0))))

(setf (get 'shake256 '%digest-length) 32)
(setf (get 'shake256 '%make-digest) (symbol-function '%make-shake256-digest))
(setf (get 'shake128 '%digest-length) 16)
(setf (get 'shake128 '%make-digest) (symbol-function '%make-shake128-digest))
