;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; blake3.lisp -- BLAKE3 hash function
;;;;
;;;; Sequential portable implementation following the reference
;;;; (https://github.com/BLAKE3-team/BLAKE3): 1024-octet chunks of
;;;; 64-octet blocks feeding a binary tree of parent nodes, with
;;;; keyed and key-derivation modes.  Extendable output via
;;;; (MAKE-DIGEST :BLAKE3 :OUTPUT-LENGTH N).
;;;;
;;;; (MAKE-DIGEST :BLAKE3 &key output-length key context) where KEY is
;;;; a 32-octet secret and CONTEXT a string or octet vector naming the
;;;; derivation context; KEY and CONTEXT are mutually exclusive.

(in-package :crypto)


(eval-when (:compile-toplevel :load-toplevel :execute)
  (defconstant +blake3-block-size+ 64)
  (defconstant +blake3-chunk-size+ 1024)
  (defconstant +blake3-chunk-start+ 1)
  (defconstant +blake3-chunk-end+ 2)
  (defconstant +blake3-parent+ 4)
  (defconstant +blake3-root+ 8)
  (defconstant +blake3-keyed-hash+ 16)
  (defconstant +blake3-derive-key-context+ 32)
  (defconstant +blake3-derive-key-material+ 64)
  (defconst +blake3-iv+
    (make-array 8
                :element-type '(unsigned-byte 32)
                :initial-contents '(#x6A09E667
                                    #xBB67AE85
                                    #x3C6EF372
                                    #xA54FF53A
                                    #x510E527F
                                    #x9B05688C
                                    #x1F83D9AB
                                    #x5BE0CD19)))
  (defconst +blake3-schedule+
    (make-array '(7 16)
                :element-type '(integer 0 15)
                :initial-contents '((0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
                                    (2 6 3 10 7 0 4 13 1 11 12 5 9 14 15 8)
                                    (3 4 10 12 13 2 7 14 6 5 9 0 11 15 8 1)
                                    (10 7 12 9 14 3 13 15 4 0 11 2 5 8 1 6)
                                    (12 13 9 11 15 10 14 8 7 2 5 3 0 1 6 4)
                                    (9 14 11 5 8 12 15 1 13 3 0 10 2 6 4 7)
                                    (11 15 5 0 1 9 8 6 14 10 2 12 3 4 7 13)))))


;;;
;;; Compression function
;;;

(defun blake3-compress-state (cv block start counter block-len flags)
  "Seven-round BLAKE3 compression; returns the 16-word state array.
CV holds 8 words; BLOCK holds 16 little-endian words from START."
  (declare (type (simple-array (unsigned-byte 32) (8)) cv)
           (type (simple-array (unsigned-byte 8) (*)) block)
           (type fixnum start)
           (type (unsigned-byte 64) counter)
           (type (unsigned-byte 8) block-len)
           (type (unsigned-byte 8) flags)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (macrolet ((blake3-g (va vb vc vd x y)
               `(setf ,va (mod32+ (mod32+ ,va ,vb) ,x)
                      ,vd (rol32 (logxor ,vd ,va) 16)
                      ,vc (mod32+ ,vc ,vd)
                      ,vb (rol32 (logxor ,vb ,vc) 20)
                      ,va (mod32+ (mod32+ ,va ,vb) ,y)
                      ,vd (rol32 (logxor ,vd ,va) 24)
                      ,vc (mod32+ ,vc ,vd)
                      ,vb (rol32 (logxor ,vb ,vc) 25))))
    (let ((v0 (aref cv 0))
          (v1 (aref cv 1))
          (v2 (aref cv 2))
          (v3 (aref cv 3))
          (v4 (aref cv 4))
          (v5 (aref cv 5))
          (v6 (aref cv 6))
          (v7 (aref cv 7))
          (v8 (aref +blake3-iv+ 0))
          (v9 (aref +blake3-iv+ 1))
          (v10 (aref +blake3-iv+ 2))
          (v11 (aref +blake3-iv+ 3))
          (v12 (ldb (byte 32 0) counter))
          (v13 (ldb (byte 32 32) counter))
          (v14 block-len)
          (v15 flags)
          (m (make-array 16 :element-type '(unsigned-byte 32) :initial-element 0))
          (state (make-array 16 :element-type '(unsigned-byte 32) :initial-element 0)))
      (declare (type (unsigned-byte 32) v0 v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 v11 v12 v13 v14 v15)
               (type (simple-array (unsigned-byte 32) (16)) m state)
               ;; NB: only M has dynamic extent; STATE is returned.
               (dynamic-extent m))
      (dotimes-unrolled (i 16)
        (setf (aref m i) (ub32ref/le block (+ start (* i 4)))))
      (dotimes (round 7)
        (blake3-g v0 v4 v8 v12
                  (aref m (aref +blake3-schedule+ round 0))
                  (aref m (aref +blake3-schedule+ round 1)))
        (blake3-g v1 v5 v9 v13
                  (aref m (aref +blake3-schedule+ round 2))
                  (aref m (aref +blake3-schedule+ round 3)))
        (blake3-g v2 v6 v10 v14
                  (aref m (aref +blake3-schedule+ round 4))
                  (aref m (aref +blake3-schedule+ round 5)))
        (blake3-g v3 v7 v11 v15
                  (aref m (aref +blake3-schedule+ round 6))
                  (aref m (aref +blake3-schedule+ round 7)))
        (blake3-g v0 v5 v10 v15
                  (aref m (aref +blake3-schedule+ round 8))
                  (aref m (aref +blake3-schedule+ round 9)))
        (blake3-g v1 v6 v11 v12
                  (aref m (aref +blake3-schedule+ round 10))
                  (aref m (aref +blake3-schedule+ round 11)))
        (blake3-g v2 v7 v8 v13
                  (aref m (aref +blake3-schedule+ round 12))
                  (aref m (aref +blake3-schedule+ round 13)))
        (blake3-g v3 v4 v9 v14
                  (aref m (aref +blake3-schedule+ round 14))
                  (aref m (aref +blake3-schedule+ round 15))))
      (setf (aref state 0) v0
            (aref state 1) v1
            (aref state 2) v2
            (aref state 3) v3
            (aref state 4) v4
            (aref state 5) v5
            (aref state 6) v6
            (aref state 7) v7
            (aref state 8) v8
            (aref state 9) v9
            (aref state 10) v10
            (aref state 11) v11
            (aref state 12) v12
            (aref state 13) v13
            (aref state 14) v14
            (aref state 15) v15)
      state)))

(defun blake3-chaining-value (cv block start counter block-len flags)
  "32-octet chaining value for the node."
  (let ((state (blake3-compress-state cv block start counter block-len flags))
        (out (make-array 8 :element-type '(unsigned-byte 32))))
    (dotimes-unrolled (i 8)
      (setf (aref out i) (logxor (aref state i) (aref state (+ i 8)))))
    out))

(defun blake3-chaining-bytes (cv block start counter block-len flags)
  "Little-endian octets of BLAKE3-CHAINING-VALUE."
  (let ((words (blake3-chaining-value cv block start counter block-len flags))
        (out (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes-unrolled (i 8)
      (setf (ub32ref/le out (* i 4)) (aref words i)))
    out))

(defun blake3-root-block (cv block start counter block-len flags)
  "64-octet root output block (compress_xof)."
  (let ((state (blake3-compress-state cv block start counter block-len flags)))
    (dotimes-unrolled (i 8)
      (setf (aref state i) (logxor (aref state i) (aref state (+ i 8)))))
    (dotimes-unrolled (i 8)
      (setf (aref state (+ i 8)) (logxor (aref state (+ i 8)) (aref cv i))))
    (let ((out (make-array 64 :element-type '(unsigned-byte 8))))
      (dotimes-unrolled (i 16)
        (setf (ub32ref/le out (* i 4)) (aref state i)))
      out)))


;;;
;;; Digest structure
;;;

(defstruct (blake3
            (:constructor %make-blake3-state)
            (:copier nil))
  (key (copy-seq +blake3-iv+)
       :type (simple-array (unsigned-byte 32) (8)))
  (flags 0 :type (unsigned-byte 8))
  (chunk-cv (copy-seq +blake3-iv+)
            :type (simple-array (unsigned-byte 32) (8)))
  (chunk-counter 0 :type (unsigned-byte 64))
  (chunk-buffer (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)
                :type (simple-array (unsigned-byte 8) (64)))
  (chunk-buffer-length 0 :type (integer 0 64))
  (chunk-blocks 0 :type (unsigned-byte 64))
  ;; Completed subtree chaining values, newest first, as (SIZE . CV)
  ;; pairs; sizes are powers of two in chunks.
  (stack nil :type list)
  (output-length 32 :type (integer 0 *)))

(defun blake3-derive-context-key (context)
  "Hash CONTEXT (string or octets) into a 32-octet derived key."
  (let ((bytes (etypecase context
                 (string (ascii-string-to-byte-array context))
                 ((simple-array (unsigned-byte 8) (*)) context))))
    (let ((state (%make-blake3-state)))
      (setf (blake3-flags state) +blake3-derive-key-context+)
      (blake3-update state bytes 0 (length bytes))
      (let ((key (make-array 32 :element-type '(unsigned-byte 8))))
        (blake3-finalize state key 0)
        key))))

(defun %make-blake3-digest (&key (output-length 32) key context)
  (unless (and (integerp output-length) (plusp output-length))
    (error 'ironclad-error
           :format-control "BLAKE3 output length must be a positive integer, not ~A."
           :format-arguments (list output-length)))
  (when (and key context)
    (error 'ironclad-error
           :format-control "BLAKE3 accepts only one of :KEY and :CONTEXT."))
  (let ((state (%make-blake3-state)))
    (setf (blake3-output-length state) output-length)
    (cond (key
           (check-type key (simple-array (unsigned-byte 8) (32)))
           (dotimes-unrolled (i 8)
             (setf (aref (blake3-key state) i) (ub32ref/le key (* i 4))
                   (aref (blake3-chunk-cv state) i) (ub32ref/le key (* i 4))))
           (setf (blake3-flags state) +blake3-keyed-hash+))
          (context
           (let ((derived (blake3-derive-context-key context)))
             (dotimes-unrolled (i 8)
               (setf (aref (blake3-key state) i) (ub32ref/le derived (* i 4))
                     (aref (blake3-chunk-cv state) i) (ub32ref/le derived (* i 4)))))
           (setf (blake3-flags state) +blake3-derive-key-material+)))
    state))

(defmethod reinitialize-instance ((state blake3) &rest initargs)
  (declare (ignore initargs))
  (replace (blake3-chunk-cv state) (blake3-key state))
  (setf (blake3-chunk-counter state) 0)
  (fill (blake3-chunk-buffer state) 0)
  (setf (blake3-chunk-buffer-length state) 0
        (blake3-chunk-blocks state) 0
        (blake3-stack state) nil)
  state)

(defmethod copy-digest ((state blake3) &optional copy)
  (check-type copy (or null blake3))
  (let ((copy (or copy (%make-blake3-state))))
    (replace (blake3-key copy) (blake3-key state))
    (setf (blake3-flags copy) (blake3-flags state))
    (replace (blake3-chunk-cv copy) (blake3-chunk-cv state))
    (setf (blake3-chunk-counter copy) (blake3-chunk-counter state))
    (replace (blake3-chunk-buffer copy) (blake3-chunk-buffer state))
    (setf (blake3-chunk-buffer-length copy) (blake3-chunk-buffer-length state)
          (blake3-chunk-blocks copy) (blake3-chunk-blocks state)
          (blake3-stack copy) (loop for (size . cv) in (blake3-stack state)
                                    collect (cons size (copy-seq cv)))
          (blake3-output-length copy) (blake3-output-length state))
    copy))

(defmethod digest-length ((state blake3))
  (blake3-output-length state))

(defmethod block-length ((state blake3))
  +blake3-block-size+)


;;;
;;; Updating
;;;

(defun blake3-chunk-start-flag (state)
  (if (zerop (blake3-chunk-blocks state))
      +blake3-chunk-start+
      0))

(defun blake3-compress-chunk-block (state block start)
  "Compress one full chunk block (no END flag); BLOCK holds 64 octets."
  (let ((cv (blake3-chunk-cv state))
        (words (blake3-chaining-value (blake3-chunk-cv state) block start
                                      (blake3-chunk-counter state)
                                      +blake3-block-size+
                                      (logior (blake3-flags state)
                                              (blake3-chunk-start-flag state)))))
    (replace cv words)
    (incf (blake3-chunk-blocks state)))
  (values))

(defun blake3-chunk-count (state)
  (+ (* +blake3-block-size+ (blake3-chunk-blocks state))
     (blake3-chunk-buffer-length state)))

(defun blake3-chunk-feed (state data start end)
  "Absorb DATA[START,END) into the current chunk."
  (declare (type blake3 state)
           (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum start end)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((buffer (blake3-chunk-buffer state))
        (buffer-length (blake3-chunk-buffer-length state)))
    ;; Fill a partial buffer first.
    (when (plusp buffer-length)
      (let ((take (min (- +blake3-block-size+ buffer-length) (- end start))))
        (replace buffer data :start1 buffer-length :start2 start :end2 (+ start take))
        (incf buffer-length take)
        (incf start take)
        (setf (blake3-chunk-buffer-length state) buffer-length)
        (when (and (= buffer-length +blake3-block-size+) (< start end))
          (blake3-compress-chunk-block state buffer 0)
          (fill buffer 0)
          (setf (blake3-chunk-buffer-length state) 0))))
    ;; Compress full blocks straight from the input.
    (loop while (> (- end start) +blake3-block-size+)
          do (blake3-compress-chunk-block state data start)
             (incf start +blake3-block-size+))
    ;; Buffer the rest.
    (let ((take (- end start)))
      (replace buffer data
               :start1 (blake3-chunk-buffer-length state) :start2 start :end2 end)
      (incf (blake3-chunk-buffer-length state) take)))
  (values))

(defun blake3-parent-bytes (state left right)
  "Parent chaining value (32 octets) of LEFT and RIGHT child CVs."
  (let ((block (make-array 64 :element-type '(unsigned-byte 8))))
    (replace block left :end2 32)
    (replace block right :start1 32)
    (blake3-chaining-bytes (blake3-key state) block 0 0
                           +blake3-block-size+
                           (logior (blake3-flags state) +blake3-parent+))))

(defun blake3-stack-push (state cv total-chunks)
  "Push the completed-chunk CV, merging equal-sized subtrees."
  (let ((stack (cons (cons 1 cv) (blake3-stack state))))
    (loop while (evenp total-chunks)
          do (let ((b (pop stack))
                   (a (pop stack)))
               (unless (= (car a) (car b))
                 (error 'ironclad-error
                        :format-control "BLAKE3 subtree size mismatch during merge."))
               (push (cons (* 2 (car a))
                           (blake3-parent-bytes state (cdr a) (cdr b)))
                     stack)
               (setf total-chunks (ash total-chunks -1))))
    (setf (blake3-stack state) stack))
  (values))

(defun blake3-push-chunk (state)
  "Complete the current chunk: merge its CV, start chunk COUNTER+1."
  (let ((output (blake3-chunk-output state)))
    (blake3-stack-push state
                       (blake3-output-chaining-bytes output)
                       (1+ (blake3-out-counter output))))
  (incf (blake3-chunk-counter state))
  (replace (blake3-chunk-cv state) (blake3-key state))
  (fill (blake3-chunk-buffer state) 0)
  (setf (blake3-chunk-buffer-length state) 0
        (blake3-chunk-blocks state) 0)
  (values))

(defun blake3-update (state data start end)
  (declare (type blake3 state)
           (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum start end)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((remaining (- end start)))
    ;; Finish a partial chunk.
    (when (plusp (blake3-chunk-count state))
      (let ((take (min (- +blake3-chunk-size+ (blake3-chunk-count state))
                       remaining)))
        (blake3-chunk-feed state data start (+ start take))
        (incf start take)
        (decf remaining take)
        (cond ((and (= (blake3-chunk-count state) +blake3-chunk-size+)
                    (plusp remaining))
               (blake3-push-chunk state))
              (t
               (return-from blake3-update (values))))))
    ;; Whole chunks.
    (loop while (>= remaining +blake3-chunk-size+)
          do (blake3-chunk-feed state data start (+ start +blake3-chunk-size+))
             (incf start +blake3-chunk-size+)
             (decf remaining +blake3-chunk-size+)
             (if (zerop remaining)
                 (return-from blake3-update (values))
                 (blake3-push-chunk state)))
    ;; Tail.
    (when (plusp remaining)
      (blake3-chunk-feed state data start (+ start remaining))))
  (values))


;;;
;;; Output objects and finalization
;;;

(defstruct (%blake3-output
            (:constructor %make-blake3-output (cv block length counter flags))
            (:conc-name blake3-out-)
            (:copier nil))
  (cv nil :type (simple-array (unsigned-byte 32) (8)))
  (block nil :type (simple-array (unsigned-byte 8) (64)))
  (length 0 :type (integer 0 64))
  (counter 0 :type (unsigned-byte 64))
  (flags 0 :type (unsigned-byte 8)))

(defun blake3-chunk-output (state)
  "Output object for the current (possibly partial) chunk."
  (%make-blake3-output (copy-seq (blake3-chunk-cv state))
                       (copy-seq (blake3-chunk-buffer state))
                       (blake3-chunk-buffer-length state)
                       (blake3-chunk-counter state)
                       (logior (blake3-flags state)
                               (blake3-chunk-start-flag state)
                               +blake3-chunk-end+)))

(defun blake3-output-chaining-bytes (output)
  (blake3-chaining-bytes (blake3-out-cv output)
                         (blake3-out-block output)
                         0
                         (blake3-out-counter output)
                         (blake3-out-length output)
                         (blake3-out-flags output)))

(defun blake3-parent-output (state left right)
  (%make-blake3-output (blake3-key state)
                       (let ((block (make-array 64 :element-type '(unsigned-byte 8))))
                         (replace block left :end2 32)
                         (replace block right :start1 32)
                         block)
                       +blake3-block-size+
                       0
                       (logior (blake3-flags state) +blake3-parent+)))

(defun blake3-final-output (state)
  (let ((stack (blake3-stack state)))
    (if (null stack)
        (blake3-chunk-output state)
        (let ((output (blake3-chunk-output state)))
          (dolist (entry stack output)
            (setf output (blake3-parent-output
                          state
                          (cdr entry)
                          (blake3-output-chaining-bytes output))))))))

(defun blake3-finalize (state digest digest-start)
  (let ((output (blake3-final-output state))
        (remaining (blake3-output-length state))
        (position digest-start)
        (counter 0))
    (declare (type fixnum remaining position))
    (loop while (plusp remaining)
          do (let* ((block (blake3-root-block (blake3-out-cv output)
                                             (blake3-out-block output)
                                             0
                                             counter
                                             (blake3-out-length output)
                                             (logior (blake3-out-flags output)
                                                     +blake3-root+)))
                    (take (min 64 remaining)))
               (replace digest block :start1 position :end2 take)
               (incf position take)
               (decf remaining take)
               (incf counter))))
  digest)

(define-digest-updater blake3
  (blake3-update state sequence start end))

(defmethod produce-digest ((state blake3) &key digest (digest-start 0))
  (let ((digest-size (blake3-output-length state))
        (state-copy (copy-digest state)))
    (etypecase digest
      (simple-octet-vector
       (if (<= digest-size (- (length digest) digest-start))
           (blake3-finalize state-copy digest digest-start)
           (error 'insufficient-buffer-space
                  :buffer digest
                  :start digest-start
                  :length digest-size)))
      (null
       (blake3-finalize state-copy
                        (make-array digest-size :element-type '(unsigned-byte 8))
                        0)))))

(setf (get 'blake3 '%digest-length) 32)
(setf (get 'blake3 '%make-digest) (symbol-function '%make-blake3-digest))
