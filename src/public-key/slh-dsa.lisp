;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; slh-dsa.lisp -- SLH-DSA-SHA2-128s (SPHINCS+, FIPS 205)
;;;;
;;;; Direct translation of the reference implementation for the
;;;; SHA2-128s parameter set: n=16, d=7, h=63, a=12, k=14, w=16,
;;;; SHA-256 for every hash.  Sizes: sk 64, pk 32, signature 7856.
;;;;
;;;;   (generate-key-pair :slh-dsa-sha2-128s) => private, public
;;;;   (sign-message private-key message) => signature bytes
;;;;   (verify-signature public-key message signature) => boolean

(in-package :crypto)


;;;
;;; Parameters.  All numeric per-set values live in a SLH-PARAMS struct
;;; bound to *SLH-PARAMS* by the entry points; inline accessors below
;;; preserve the call-site shape.  Address layout constants are for the
;;; SHA-2 family (22-byte addresses); the SHAKE family overrides them.
;;;

(defstruct slh-params
  kind family n d fors-height fors-trees wots-w wots-logw tree-height
  wots-len1 wots-len2 wots-len fors-msg-bytes
  tree-bits tree-bytes leaf-bits leaf-bytes dgst-bytes
  sk-bytes pk-bytes sig-bytes)

(defvar *slh-params* nil)

(defun slh-make-params (kind family n d fors-height fors-trees
                        wots-w wots-logw tree-height
                        wots-len1 wots-len2 fors-msg-bytes)
  (let* ((wots-len (+ wots-len1 wots-len2))
         (tree-bits (* tree-height (1- d)))
         (tree-bytes (ceiling tree-bits 8))
         (leaf-bits tree-height)
         (leaf-bytes (ceiling leaf-bits 8))
         (dgst-bytes (+ fors-msg-bytes tree-bytes leaf-bytes))
         (sk-bytes (* 4 n))
         (pk-bytes (* 2 n))
         (sig-bytes (+ n
                       (* (1+ fors-height) fors-trees n)
                       (* d (+ (* wots-len n)
                               (* tree-height n))))))
    (make-slh-params :kind kind :family family :n n :d d
                     :fors-height fors-height :fors-trees fors-trees
                     :wots-w wots-w :wots-logw wots-logw
                     :tree-height tree-height
                     :wots-len1 wots-len1 :wots-len2 wots-len2
                     :wots-len wots-len :fors-msg-bytes fors-msg-bytes
                     :tree-bits tree-bits :tree-bytes tree-bytes
                     :leaf-bits leaf-bits :leaf-bytes leaf-bytes
                     :dgst-bytes dgst-bytes
                     :sk-bytes sk-bytes :pk-bytes pk-bytes
                     :sig-bytes sig-bytes)))

(defparameter +slh-sha2-128s-params+
  (slh-make-params :slh-dsa-sha2-128s :sha2 16 7 12 14 16 4 9 32 3 21))

(defparameter +slh-sha2-128f-params+
  (slh-make-params :slh-dsa-sha2-128f :sha2 16 22 6 33 16 4 3 32 3 25))

(defparameter +slh-sha2-192s-params+
  (slh-make-params :slh-dsa-sha2-192s :sha2-512 24 7 14 17 16 4 9 48 3 30))

(defparameter +slh-sha2-192f-params+
  (slh-make-params :slh-dsa-sha2-192f :sha2-512 24 22 8 33 16 4 3 48 3 33))

(defun slh-params-for-kind (kind)
  (ecase kind
    (:slh-dsa-sha2-128s +slh-sha2-128s-params+)
    (:slh-dsa-sha2-128f +slh-sha2-128f-params+)
    (:slh-dsa-sha2-192s +slh-sha2-192s-params+)
    (:slh-dsa-sha2-192f +slh-sha2-192f-params+)))

(declaim (inline slh-n slh-d slh-fors-height slh-fors-trees
                 slh-wots-w slh-wots-logw slh-tree-height
                 slh-wots-len1 slh-wots-len2 slh-wots-len
                 slh-fors-msg-bytes slh-sig-bytes slh-sk-bytes
                 slh-pk-bytes slh-dgst-bytes slh-tree-bytes
                 slh-leaf-bytes slh-tree-bits slh-leaf-bits))
(defun slh-n () (slh-params-n *slh-params*))
(defun slh-d () (slh-params-d *slh-params*))
(defun slh-fors-height () (slh-params-fors-height *slh-params*))
(defun slh-fors-trees () (slh-params-fors-trees *slh-params*))
(defun slh-wots-w () (slh-params-wots-w *slh-params*))
(defun slh-wots-logw () (slh-params-wots-logw *slh-params*))
(defun slh-tree-height () (slh-params-tree-height *slh-params*))
(defun slh-wots-len1 () (slh-params-wots-len1 *slh-params*))
(defun slh-wots-len2 () (slh-params-wots-len2 *slh-params*))
(defun slh-wots-len () (slh-params-wots-len *slh-params*))
(defun slh-fors-msg-bytes () (slh-params-fors-msg-bytes *slh-params*))
(defun slh-sig-bytes () (slh-params-sig-bytes *slh-params*))
(defun slh-sk-bytes () (slh-params-sk-bytes *slh-params*))
(defun slh-pk-bytes () (slh-params-pk-bytes *slh-params*))
(defun slh-dgst-bytes () (slh-params-dgst-bytes *slh-params*))
(defun slh-tree-bytes () (slh-params-tree-bytes *slh-params*))
(defun slh-leaf-bytes () (slh-params-leaf-bytes *slh-params*))
(defun slh-tree-bits () (slh-params-tree-bits *slh-params*))
(defun slh-leaf-bits () (slh-params-leaf-bits *slh-params*))

;;; Address field offsets (SHA2 instantiation).
(defconstant +slh-offset-layer+ 0)
(defconstant +slh-offset-tree+ 1)
(defconstant +slh-offset-type+ 9)
(defconstant +slh-offset-kp-addr+ 10)
(defconstant +slh-offset-chain-addr+ 17)
(defconstant +slh-offset-hash-addr+ 21)
(defconstant +slh-offset-tree-hgt+ 17)
(defconstant +slh-offset-tree-index+ 18)

(defconstant +slh-addr-type-wots+ 0)
(defconstant +slh-addr-type-wots-pk+ 1)
(defconstant +slh-addr-type-hashtree+ 2)
(defconstant +slh-addr-type-forstree+ 3)
(defconstant +slh-addr-type-fors-pk+ 4)
(defconstant +slh-addr-type-wots-prf+ 5)
(defconstant +slh-addr-type-fors-prf+ 6)


;;;
;;; Address helpers.  Addresses are 32-byte byte arrays manipulated
;;; exactly like the uint32_t[8] of the reference (little endian).
;;;

(defun slh-make-addr ()
  (make-array 22 :element-type '(unsigned-byte 8) :initial-element 0))

(defparameter *slh-current-ctx* nil)

(defun slh-seeded-input (data &optional (block-bytes 64))
  "Reproduce the reference seed_state midstate: hash input begins with
pub_seed padded to one full block (64 bytes for SHA-256, 128 for SHA-512)."
  (let ((block (make-array block-bytes :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
    (replace block (slh-ctx-pub-seed *slh-current-ctx*))
    (concatenate '(simple-array (unsigned-byte 8) (*)) block data)))

(defun slh-thash (ctx out data addr)
  "Reference thash: SHA-256(pub_seed||pad||addr||M) for single-block
input; SHA-512(pub_seed||pad128||addr||M) when the SHA2-512 family
hashes more than one n-byte block. First n bytes in both cases."
  (let* ((*slh-current-ctx* ctx)
         (n (slh-n))
         (use-512 (and (eq (slh-params-family *slh-params*) :sha2-512)
                       (> (length data) n)))
         (md (if use-512
                 (digest-sequence
                  :sha512
                  (slh-seeded-input
                   (concatenate '(simple-array (unsigned-byte 8) (*))
                                addr data)
                   128))
                 (digest-sequence
                  :sha256
                  (slh-seeded-input
                   (concatenate '(simple-array (unsigned-byte 8) (*))
                                addr data))))))
    (replace out md :end2 n)
    out))

(defun slh-prf-addr (ctx addr)
  "Reference prf_addr: SHA-256(pub_seed||pad||addr||sk_seed)."
  (let* ((*slh-current-ctx* ctx)
         (md (digest-sequence
              :sha256
              (slh-seeded-input
               (concatenate '(simple-array (unsigned-byte 8) (*))
                            addr (slh-ctx-sk-seed ctx)))))
         (out (make-array (slh-n) :element-type '(unsigned-byte 8))))
    (replace out md :end2 (slh-n))
    out))

;;; The reference address integers are stored big-endian (u32_to_bytes,
;;; ull_to_bytes).
(defun slh-u32-to-bytes (out out-start n)
  (declare (type (simple-array (unsigned-byte 8) (*)) out)
           (type (integer 0 #xFFFFFFFF) n))
  (dotimes (i 4)
    (setf (aref out (+ out-start i)) (ldb (byte 8 (* 8 (- 3 i))) n)))
  (values))

(defun slh-ull-to-bytes (out out-start n)
  (dotimes (i 8)
    (setf (aref out (+ out-start i)) (ldb (byte 8 (* 8 (- 7 i))) n)))
  (values))

;;; Big-endian, matching the reference bytes_to_ull.
(defun slh-bytes-to-ull (data start len)
  (let ((n 0))
    (dotimes (i len n)
      (setf n (logior n (ash (aref data (+ start i)) (* 8 (- len 1 i))))))))

(defun slh-set-layer (addr layer)
  (setf (aref addr +slh-offset-layer+) layer)
  (values))

(defun slh-set-tree (addr tree)
  (slh-ull-to-bytes addr +slh-offset-tree+ tree)
  (values))

(defun slh-set-type (addr type)
  (setf (aref addr +slh-offset-type+) type)
  (values))

(defun slh-copy-subtree (out in)
  (replace out in :end2 (+ +slh-offset-tree+ 8))
  (values))

(defun slh-set-keypair (addr keypair)
  (slh-u32-to-bytes addr +slh-offset-kp-addr+ keypair)
  (values))

(defun slh-copy-keypair (out in)
  (replace out in :end2 (+ +slh-offset-tree+ 8))
  (slh-u32-to-bytes out +slh-offset-kp-addr+
                    (slh-bytes-to-ull in +slh-offset-kp-addr+ 4))
  (values))

(defun slh-set-chain (addr chain)
  (setf (aref addr +slh-offset-chain-addr+) chain)
  (values))

(defun slh-set-hash (addr hash)
  (setf (aref addr +slh-offset-hash-addr+) hash)
  (values))

(defun slh-set-tree-height (addr h)
  (setf (aref addr +slh-offset-tree-hgt+) h)
  (values))

(defun slh-set-tree-index (addr idx)
  (slh-u32-to-bytes addr +slh-offset-tree-index+ idx)
  (values))


;;;
;;; Hash context: carries sk_seed and pub_seed like spx_ctx.
;;;

(defstruct slh-ctx
  (sk-seed (make-array (slh-n) :element-type '(unsigned-byte 8) :initial-element 0)
           :type (simple-array (unsigned-byte 8) (*)))
  (pub-seed (make-array (slh-n) :element-type '(unsigned-byte 8) :initial-element 0)
            :type (simple-array (unsigned-byte 8) (*))))

(defun slh-sha256 (data)
  (digest-sequence :sha256 data))

(defun slh-sha512 (data)
  (digest-sequence :sha512 data))

(defun slh-mgf1-512 (out outlen in)
  "MGF1-SHA-512 (reference: mgf1_512)."
  (declare (type (simple-array (unsigned-byte 8) (*)) out in)
           (type fixnum outlen))
  (let ((inlen (length in))
        (count 0)
        (pos 0)
        (buf (make-array (+ (length in) 4) :element-type '(unsigned-byte 8))))
    (replace buf in)
    (loop while (< (* (1+ count) 64) outlen)
          do (slh-u32-to-bytes buf inlen count)
             (replace out (slh-sha512 buf) :start1 pos)
             (incf pos 64)
             (incf count))
    (when (> outlen (* count 64))
      (slh-u32-to-bytes buf inlen count)
      (replace out (slh-sha512 buf) :start1 pos :end2 (- outlen pos)))
    out))

(defun slh-mgf1-256 (out outlen in)
  "MGF1-SHA-256 (reference: mgf1_256)."
  (declare (type (simple-array (unsigned-byte 8) (*)) out in)
           (type fixnum outlen))
  (let ((inlen (length in))
        (count 0)
        (pos 0)
        (buf (make-array (+ (length in) 4) :element-type '(unsigned-byte 8))))
    (replace buf in)
    (loop while (< (* (1+ count) 32) outlen)
          do (slh-u32-to-bytes buf inlen count)
             (replace out (slh-sha256 buf) :start1 pos)
             (incf pos 32)
             (incf count))
    (when (> outlen (* count 32))
      (slh-u32-to-bytes buf inlen count)
      (replace out (slh-sha256 buf) :start1 pos :end2 (- outlen pos)))
    out))

(defun slh-gen-message-random (sk-prf optrand m)
  "Reference gen_message_random: HMAC(sk_prf, optrand||m)[0,n).
SHA-256/64-byte block for the SHA2 family, SHA-512/128-byte block
for the SHA2-512 (N=24/32) family."
  (let* ((use-512 (eq (slh-params-family *slh-params*) :sha2-512))
         (block-bytes (if use-512 128 64))
         (hash (if use-512 #'slh-sha512 #'slh-sha256))
         (a (concatenate '(simple-array (unsigned-byte 8) (*)) optrand m))
         (key1 (make-array block-bytes :element-type '(unsigned-byte 8)
                                        :initial-element #x36))
         (key2 (make-array block-bytes :element-type '(unsigned-byte 8)
                                        :initial-element #x5c))
         (out (make-array (slh-n) :element-type '(unsigned-byte 8))))
    (dotimes (i (slh-n))
      (setf (aref key1 i) (logxor #x36 (aref sk-prf i))
            (aref key2 i) (logxor #x5c (aref sk-prf i))))
    (let* ((inner (funcall hash (concatenate '(simple-array (unsigned-byte 8) (*))
                                             key1 a))))
      (replace out (funcall hash (concatenate '(simple-array (unsigned-byte 8) (*))
                                              key2 inner))
               :end2 (slh-n)))
    out))

(defun slh-hash-message (r pk-seed pk-root m)
  "Reference hash_message: returns (mhash tree leaf-idx).
Plain SHA-X (fresh state, no pub_seed prefix) of R || pk.seed ||
pk.root || M, then MGF1-SHA-X(R || pk.seed || digest). SHA-256 for
the SHA2 family, SHA-512 for the SHA2-512 (N=24/32) family."
  (let* ((use-512 (eq (slh-params-family *slh-params*) :sha2-512))
         (hash-out (if use-512 64 32))
         (buf (make-array (slh-dgst-bytes) :element-type '(unsigned-byte 8)))
         (seed (make-array (+ (* 2 (slh-n)) hash-out) :element-type '(unsigned-byte 8))))
    (let ((digest (digest-sequence
                   (if use-512 :sha512 :sha256)
                   (concatenate '(simple-array (unsigned-byte 8) (*))
                                r pk-seed pk-root m))))
      (replace seed r)
      (replace seed pk-seed :start1 (slh-n))
      (replace seed digest :start1 (* 2 (slh-n)))
      (if use-512
          (slh-mgf1-512 buf (slh-dgst-bytes) seed)
          (slh-mgf1-256 buf (slh-dgst-bytes) seed))
      (values (subseq buf 0 (slh-fors-msg-bytes))
              (logand (slh-bytes-to-ull buf (slh-fors-msg-bytes) (slh-tree-bytes))
                      (1- (ash 1 (slh-tree-bits))))
              (logand (slh-bytes-to-ull buf (+ (slh-fors-msg-bytes) (slh-tree-bytes))
                                       (slh-leaf-bytes))
                      (1- (ash 1 (slh-leaf-bits))))))))

(defun slh-chain-lengths (msg)
  "Reference chain_lengths: LEN1 message digits plus LEN2 checksum digits."
  (let ((digits (make-array (slh-wots-len) :element-type 'fixnum :initial-element 0))
        (csum 0))
    (replace digits (slh-base-w-digits msg (slh-wots-len1)))
    (dotimes (i (slh-wots-len1))
      (incf csum (- (1- (slh-wots-w)) (aref digits i))))
    (setf csum (ash csum (mod (- 8 (mod (* (slh-wots-len2) (slh-wots-logw)) 8)) 8)))
    (let* ((nbytes (ceiling (* (slh-wots-len2) (slh-wots-logw)) 8))
           (csum-bytes (make-array nbytes :element-type '(unsigned-byte 8)
                                          :initial-element 0)))
      (dotimes (j nbytes)
        (setf (aref csum-bytes j)
              (ldb (byte 8 (* 8 (- nbytes 1 j))) csum)))
      (replace digits (slh-base-w-digits csum-bytes (slh-wots-len2))
               :start1 (slh-wots-len1))
      digits)))

(defun slh-base-w-digits (input count)
  "Read COUNT w-bit digits out of INPUT (reference base_w, MSB first)."
  (let ((digits (make-array count :element-type 'fixnum))
        (in 0)
        (total 0)
        (bits 0))
    (dotimes (i count digits)
      (when (zerop bits)
        (setf total (if (< in (length input)) (aref input in) 0))
        (incf in)
        (incf bits 8))
      (decf bits (slh-wots-logw))
      (setf (aref digits i)
            (logand (ash total (- bits)) (1- (slh-wots-w)))))))

(defun slh-wots-gen-chain (out out-start in start steps ctx addr)
  "Reference gen_chain: iterate thash(STEP) times starting at START.
Writes the 16-byte result at OUT[OUT-START] (subseq of a simple-array
is a copy, so an explicit offset is required for write-through)."
  (let ((x (copy-seq in)))
    (loop for i from start below (+ start steps)
          do (slh-set-hash addr i)
             (slh-thash ctx x x addr))
    (replace out x :start1 out-start)
    (values)))


;;;
;;; Generic Merkle treehash (reference treehashx1).  GEN-LEAF is
;;; called as (GEN-LEAF OUT CTX IDX INFO) and must fill OUT with the
;;; leaf for the index IDX + idx-offset.
;;;

(defun slh-treehash (root auth-path ctx leaf-idx offset height gen-leaf tree-addr
                    &optional info)
  "Reference treehashx1: fill ROOT (n bytes) and AUTH-PATH (height*n).
GEN-LEAF is called as (GEN-LEAF OUT OUT-START CTX IDX TREE-ADDR) and
must fill OUT[OUT-START, OUT-START+n)."
  (declare (type fixnum leaf-idx offset height))
  (let* ((stack (make-array (* height (slh-n)) :element-type '(unsigned-byte 8)
                            :initial-element 0))
         (current (make-array (* 2 (slh-n)) :element-type '(unsigned-byte 8)
                              :initial-element 0))
         (node (make-array (* 2 (slh-n)) :element-type '(unsigned-byte 8)
                           :initial-element 0))
         (hash-out (make-array (slh-n) :element-type '(unsigned-byte 8)
                                :displaced-to current
                                :displaced-index-offset (slh-n)))
         (max-idx (1- (ash 1 height)))
         (internal-idx-offset offset)
         (internal-idx 0)
         (internal-leaf leaf-idx)
         (idx 0)
         (h 0))
    (flet ((write-stack ()
             (replace stack current :start1 (* h (slh-n))
                      :start2 (slh-n) :end2 (* 2 (slh-n)))))
      (block outer
        (loop
          ;; current[n, 2n) = freshly generated leaf
          (funcall gen-leaf current (slh-n) ctx (+ idx offset) tree-addr info)
          (setf internal-idx-offset offset
                internal-idx idx
                internal-leaf leaf-idx
                h 0)
          (block inner
            (loop
              (when (= h height)
                ;; top of the tree: copy the logical node into ROOT
                (replace root current :start2 (slh-n) :end2 (* 2 (slh-n)))
                (return-from outer))
              ;; authentication path element
              (when (= (logxor internal-idx internal-leaf) 1)
                (replace auth-path current
                         :start1 (* h (slh-n))
                         :start2 (slh-n) :end2 (* 2 (slh-n))))
              ;; left child (and not the final leaf): stop ascending
              (when (and (evenp internal-idx) (< idx max-idx))
                (return-from inner))
              ;; combine with the left sibling from the stack
              (setf internal-idx-offset (ash internal-idx-offset -1))
              (slh-set-tree-height tree-addr (1+ h))
              (slh-set-tree-index tree-addr
                                  (+ (ash internal-idx -1) internal-idx-offset))
              (replace node stack :start2 (* h (slh-n))
                       :end2 (+ (* h (slh-n)) (slh-n)))
              (replace node current
                       :start1 (slh-n) :start2 (slh-n) :end2 (* 2 (slh-n)))
              (slh-thash ctx hash-out node tree-addr)
              (incf h)
              (setf internal-idx (ash internal-idx -1)
                    internal-leaf (ash internal-leaf -1))))
          ;; hit a left child: remember it for the matching right child
          (write-stack)
          (incf idx)))))
  (values))


;;;
;;; compute_root: fold a FORS/XMSS authentication path into a root
;;; (reference utils.c).
;;;


;;; compute_root needs the final node after the loop; recompute it by
;;; restructuring: emit the final thash outside the loop instead.


;;;
;;; compute_root: fold a FORS/XMSS authentication path into a root
;;; (reference utils.c).
;;;

(defun slh-compute-root (root root-start leaf leaf-idx idx-offset auth-path height ctx addr)
  "Reference compute_root: fold AUTH-PATH into ROOT[root-start] from LEAF."
  (declare (type fixnum leaf-idx idx-offset height)
           (type (simple-array (unsigned-byte 8) (*)) leaf auth-path))
  (let ((buffer (make-array (* 2 (slh-n)) :element-type '(unsigned-byte 8)
                            :initial-element 0))
        (li leaf-idx)
        (off idx-offset)
        (auth-pos 0))
    (labels ((take-auth ()
               (let ((chunk (make-array (slh-n) :element-type '(unsigned-byte 8))))
                 (replace chunk auth-path :start2 auth-pos)
                 (incf auth-pos (slh-n))
                 chunk)))
      (cond
        ((oddp li)
         (replace buffer leaf :start1 (slh-n))
         (replace buffer (take-auth) :start1 0))
        (t
         (replace buffer leaf :start1 0)
         (replace buffer (take-auth) :start1 (slh-n))))
      (dotimes (i (1- height))
        (setf li (ash li -1)
              off (ash off -1))
        (slh-set-tree-height addr (1+ i))
        (slh-set-tree-index addr (+ li off))
        (let ((node (make-array (slh-n) :element-type '(unsigned-byte 8))))
          (slh-thash ctx node buffer addr)
          (if (oddp li)
              (progn
                (replace buffer node :start1 (slh-n))
                (replace buffer (take-auth) :start1 0))
              (progn
                (replace buffer node :start1 0)
                (replace buffer (take-auth) :start1 (slh-n))))))
      (setf li (ash li -1)
            off (ash off -1))
      (slh-set-tree-height addr height)
      (slh-set-tree-index addr (+ li off))
      (let ((out (make-array (slh-n) :element-type '(unsigned-byte 8))))
        (slh-thash ctx out buffer addr)
        (replace root out :start1 root-start))))
  (values))


;;;
;;; FORS: forest of random subtrees
;;;

(defun slh-message-to-indices (m)
  "Reference message_to_indices: take a=12 bits from M per tree."
  (let ((indices (make-array (slh-fors-trees) :element-type 'fixnum :initial-element 0))
        (offset 0))
    (declare (type fixnum offset))
    (dotimes (i (slh-fors-trees) indices)
      (dotimes (j (slh-fors-height))
        (let ((byte (aref m (truncate offset 8))))
          (setf (aref indices i)
                (logior (aref indices i)
                        (ash (ldb (byte 1 (mod offset 8)) byte) j))))
        (incf offset)))))

(defun slh-fors-sk-to-leaf (leaf sk ctx leaf-addr)
  "Reference fors_sk_to_leaf: thash(leaf, sk) with FORSTREE address type.
SK is used as given (from prf_addr during signing, from the signature
during verification); it is NOT recomputed here."
  (let ((addr (copy-seq leaf-addr)))
    (slh-set-type addr +slh-addr-type-forstree+)
    (let ((node (make-array (slh-n) :element-type '(unsigned-byte 8))))
      (slh-thash ctx node sk addr)
      (replace leaf node))))

(defun slh-fors-sign (sig sig-start pk ctx fors-addr m roots)
  "Reference fors_sign.  Fills SIG from SIG-START and ROOTS (k * n)."
  (let ((indices (slh-message-to-indices m)))
    (dotimes (i (slh-fors-trees))
      (let* ((idx-offset (* i (ash 1 (slh-fors-height))))
             (tree-addr (copy-seq fors-addr))
             (sk-buf (make-array (slh-n) :element-type '(unsigned-byte 8)))
             (auth-path (make-array (* (slh-fors-height) (slh-n))
                                    :element-type '(unsigned-byte 8)
                                    :initial-element 0))
             (leaf (make-array (slh-n) :element-type '(unsigned-byte 8))))
        (slh-set-type tree-addr +slh-addr-type-fors-prf+)
        (slh-set-tree-height tree-addr 0)
        (slh-set-tree-index tree-addr (+ (aref indices i) idx-offset))
        (replace sk-buf (slh-prf-addr ctx tree-addr))
        (replace sig sk-buf :start1 sig-start)
        (incf sig-start (slh-n))
        (slh-set-type tree-addr +slh-addr-type-forstree+)
        (flet ((gen-leaf (out out-start ctx2 idx local-addr tree-addr2)
                 (declare (ignore tree-addr2))
                 ;; Use a private copy: the reference keeps a separate
                 ;; fors_leaf_addr, while tree-addr must retain FORSTREE type.
                 (let ((la (copy-seq local-addr))
                       (tmp (make-array (slh-n) :element-type '(unsigned-byte 8))))
                   (slh-set-tree-height la 0)
                   (slh-set-tree-index la idx)
                   (slh-set-type la +slh-addr-type-fors-prf+)
                   (slh-fors-sk-to-leaf tmp (slh-prf-addr ctx2 la) ctx2 la)
                   (replace out tmp :start1 out-start)))
               (gen-leaf-tree (out out-start ctx2 idx local-addr tree-addr2)
                 (declare (ignore tree-addr2))
                 (let ((la (copy-seq local-addr))
                       (tmp (make-array (slh-n) :element-type '(unsigned-byte 8))))
                   (slh-set-tree-height la 0)
                   (slh-set-tree-index la idx)
                   (slh-set-type la +slh-addr-type-fors-prf+)
                   (slh-fors-sk-to-leaf tmp (slh-prf-addr ctx2 la) ctx2 la)
                   (replace out tmp :start1 out-start))))
          (slh-treehash leaf auth-path ctx (aref indices i) idx-offset
                        (slh-fors-height) #'gen-leaf tree-addr))
        (replace sig auth-path :start1 sig-start)
        (incf sig-start (* (slh-fors-height) (slh-n)))
        (replace roots leaf :start1 (* i (slh-n)))))
    (slh-set-type (copy-seq fors-addr) +slh-addr-type-fors-pk+)
    (let ((fors-pk-addr (copy-seq fors-addr)))
      (slh-set-type fors-pk-addr +slh-addr-type-fors-pk+)
      (slh-thash ctx pk roots fors-pk-addr))
    (values)))

(defun slh-fors-pk-from-sig (pk sig sig-start m ctx fors-addr roots)
  "Reference fors_pk_from_sig: recompute the FORS public key."
  (let ((indices (slh-message-to-indices m)))
    (dotimes (i (slh-fors-trees))
      (let* ((idx-offset (* i (ash 1 (slh-fors-height))))
             (tree-addr (copy-seq fors-addr))
             (leaf (make-array (slh-n) :element-type '(unsigned-byte 8)))
             (auth-path (make-array (* (slh-fors-height) (slh-n))
                                    :element-type '(unsigned-byte 8)
                                    :initial-element 0))
             (sk-buf (make-array (slh-n) :element-type '(unsigned-byte 8))))
        (slh-set-type tree-addr +slh-addr-type-forstree+)
        (slh-set-tree-height tree-addr 0)
        (slh-set-tree-index tree-addr (+ (aref indices i) idx-offset))
        (replace sk-buf sig :start2 sig-start)
        (incf sig-start (slh-n))
        (slh-fors-sk-to-leaf leaf sk-buf ctx tree-addr)
        (replace auth-path sig :start2 sig-start)
        (incf sig-start (* (slh-fors-height) (slh-n)))
        (slh-compute-root roots (* i (slh-n)) leaf (aref indices i) idx-offset
                          auth-path (slh-fors-height) ctx
                          (copy-seq tree-addr))))
    (let ((fors-pk-addr (copy-seq fors-addr)))
      (slh-set-type fors-pk-addr +slh-addr-type-fors-pk+)
      (slh-thash ctx pk roots fors-pk-addr))
  (values)))


;;;
;;; XMSS: hypertrees over WOTS+ (reference merkle.c / wotsx1.c)
;;;

(defstruct slh-wots-info
  (leaf-addr nil)
  (pk-addr nil)
  (wots-steps nil)
  (wots-sig nil)
  (wots-sig-start 0)
  (wots-sign-leaf #xFFFFFFFF))

(defun slh-wots-gen-leaf (dest dest-start ctx idx info)
  "Reference wots_gen_leafx1: build one XMSS leaf (WOTS+ pk)."
  (let* ((leaf-addr (slh-wots-info-leaf-addr info))
         (pk-addr (slh-wots-info-pk-addr info))
         (steps (slh-wots-info-wots-steps info))
         (sign-leaf (slh-wots-info-wots-sign-leaf info))
         (pk-buffer (make-array (* (slh-wots-len) (slh-n))
                                :element-type '(unsigned-byte 8)
                                :initial-element 0))
         (out (make-array (slh-n) :element-type '(unsigned-byte 8))))
    (slh-set-keypair leaf-addr idx)
    (slh-set-keypair pk-addr idx)
    (let ((wots-k-mask (if (= idx sign-leaf) 0 #xFFFFFFFF)))
      (dotimes (i (slh-wots-len))
        (let ((buf (make-array (slh-n) :element-type '(unsigned-byte 8) :initial-element 0))
              (wots-k (logior (aref steps i) wots-k-mask)))
          (slh-set-chain leaf-addr i)
          (slh-set-hash leaf-addr 0)
          (slh-set-type leaf-addr +slh-addr-type-wots-prf+)
          (replace buf (slh-prf-addr ctx leaf-addr))
          (slh-set-type leaf-addr +slh-addr-type-wots+)
          (loop for k from 0
                do (when (= k wots-k)
                     (let ((slot (+ (* i (slh-n)) (slh-wots-info-wots-sig-start info))))
                       (replace (slh-wots-info-wots-sig info) buf :start1 slot)))
                   (when (= k (1- (slh-wots-w)))
                     (return))
                   (slh-set-hash leaf-addr k)
                   (slh-thash ctx buf buf leaf-addr))
          (replace pk-buffer buf :start1 (* i (slh-n))))))
    (slh-thash ctx out pk-buffer pk-addr)
    (replace dest out :start1 dest-start)
    (values)))

(defun slh-wots-pk-from-sig-into (pk sig sig-start m ctx wots-addr)
  "Reference wots_pk_from_sig + thash leaf for XMSS verification.
Returns the WOTS leaf (thash of the WOTS pk buffer)."
  (let ((lengths (slh-chain-lengths m))
        (leaf-addr (copy-seq wots-addr))
        (out (make-array (* (slh-wots-len) (slh-n)) :element-type '(unsigned-byte 8)
                         :initial-element 0)))
    (dotimes (i (slh-wots-len))
      (slh-set-chain leaf-addr i)
      (slh-wots-gen-chain out (* i (slh-n))
                          (subseq sig sig-start (+ sig-start (slh-n)))
                          (aref lengths i)
                          (- (1- (slh-wots-w)) (aref lengths i))
                          ctx leaf-addr)
      (incf sig-start (slh-n)))
    ;; The WOTS-pk hash uses a fresh address (chain/height/index zeroed),
    ;; matching the reference wots_pk_addr. NOT leaf-addr (chain=34).
    (let ((pk-addr (copy-seq wots-addr)))
      (slh-set-type pk-addr +slh-addr-type-wots-pk+)
      (slh-thash ctx pk out pk-addr)))
  (values))

(defun slh-merkle-sign (sig sig-start root ctx wots-addr tree-addr idx-leaf)
  "Reference merkle_sign for one XMSS layer."
  (let* ((steps (slh-chain-lengths root))
         (auth-path (make-array (* (slh-tree-height) (slh-n))
                                :element-type '(unsigned-byte 8)
                                :initial-element 0))
         (info (make-slh-wots-info
                :leaf-addr (slh-copy-subtree-addr wots-addr)
                :pk-addr (slh-copy-subtree-addr wots-addr)
                :wots-steps steps
                :wots-sig sig
                :wots-sig-start sig-start
                :wots-sign-leaf idx-leaf)))
    (slh-set-type tree-addr +slh-addr-type-hashtree+)
    (slh-set-type (slh-wots-info-pk-addr info) +slh-addr-type-wots-pk+)
    (slh-treehash root auth-path ctx idx-leaf 0 (slh-tree-height)
                  (lambda (out out-start ctx2 idx inf tree-addr)
                    (declare (ignore inf))
                    (slh-wots-gen-leaf out out-start ctx2 idx tree-addr))
                  tree-addr info)
    (values auth-path sig-start)))

(defun slh-copy-subtree-addr (in)
  (let ((out (slh-make-addr)))
    (replace out in :end2 (+ +slh-offset-tree+ 8))
    out))

(defun slh-keygen-with-seed (sk-seed sk-prf pub-seed
                             &optional (params +slh-sha2-128s-params+))
  "Deterministic keygen from 48 seed bytes; returns (pk sk root)."
  (let ((*slh-params* params))
   (let* ((sk (make-array (slh-sk-bytes) :element-type '(unsigned-byte 8)))
         (ctx (make-slh-ctx :sk-seed sk-seed :pub-seed pub-seed))
         (root (make-array (slh-n) :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; top layer addresses: compute the root of the topmost subtree
    (let* ((top-tree-addr (slh-make-addr))
           (wots-addr (slh-make-addr))
           (sig-dummy (make-array (* (slh-wots-len) (slh-n))
                                  :element-type '(unsigned-byte 8)
                                  :initial-element 0))
           (auth-dummy (make-array (* (slh-tree-height) (slh-n))
                                   :element-type '(unsigned-byte 8)
                                   :initial-element 0)))
      (slh-set-layer top-tree-addr (1- (slh-d)))
      (slh-set-layer wots-addr (1- (slh-d)))
      ;; sign-leaf #xFFFFFFFF: no WOTS signature is emitted
      (slh-merkle-sign sig-dummy 0 root ctx wots-addr top-tree-addr #xFFFFFFFF))
    (setf sk (concatenate '(simple-array (unsigned-byte 8) (*))
                          sk-seed sk-prf pub-seed root))
    (let ((pk (concatenate '(simple-array (unsigned-byte 8) (*))
                           pub-seed root)))
      (values pk sk root)))))

(defun slh-sign (m sk &optional (params +slh-sha2-128s-params+))
  "Deterministic signature over M with 64-byte SK; returns the sig bytes."
  (let ((*slh-params* params))
  (let* ((sk-seed (subseq sk 0 (slh-n)))
         (sk-prf (subseq sk (slh-n) (* 2 (slh-n))))
         (pub-seed (subseq sk (* 2 (slh-n)) (* 3 (slh-n))))
         (pk-root (subseq sk (* 3 (slh-n)) (* 4 (slh-n))))
         (ctx (make-slh-ctx :sk-seed sk-seed :pub-seed pub-seed))
         (optrand (make-array (slh-n) :element-type '(unsigned-byte 8) :initial-element 0))
         (sig (make-array (slh-sig-bytes) :element-type '(unsigned-byte 8)))
         (mhash (make-array (slh-fors-msg-bytes) :element-type '(unsigned-byte 8)))
         (tree 0)
         (idx-leaf 0)
         (pos (slh-n)))
    ;; R = PRF(sk_prf, optrand, m)
    (replace sig (slh-gen-message-random sk-prf optrand m) :end2 (slh-n))
    ;; mhash, tree, idx_leaf
    (multiple-value-setq (mhash tree idx-leaf)
      (slh-hash-message (subseq sig 0 (slh-n)) pub-seed pk-root m))
    (let* ((roots (make-array (* (slh-fors-trees) (slh-n))
                              :element-type '(unsigned-byte 8)))
           (fors-pk (make-array (slh-n) :element-type '(unsigned-byte 8)))
           (wots-addr (slh-make-addr)))
      (slh-set-type wots-addr +slh-addr-type-wots+)
      (slh-set-tree wots-addr tree)
      (slh-set-keypair wots-addr idx-leaf)
      (slh-fors-sign sig pos fors-pk ctx wots-addr mhash roots)
      (incf pos (* (1+ (slh-fors-height)) (slh-fors-trees) (slh-n)))
      (let ((root fors-pk))
        (dotimes (i (slh-d))
          (let* ((tree-addr (slh-make-addr))
                 (layer-wots-addr (slh-make-addr)))
            (slh-set-layer tree-addr i)
            (slh-set-tree tree-addr tree)
            (slh-copy-subtree layer-wots-addr tree-addr)
            (slh-set-keypair layer-wots-addr idx-leaf)
            (multiple-value-bind (auth-path sig-start)
                (slh-merkle-sign sig pos root ctx layer-wots-addr tree-addr idx-leaf)
              (declare (ignore sig-start))
              ;; merkle_sign layout: WOTS sig at pos, auth path after it.
              (replace sig auth-path
                       :start1 (+ pos (* (slh-wots-len) (slh-n))))
              (incf pos (+ (* (slh-wots-len) (slh-n))
                           (* (slh-tree-height) (slh-n)))))
          (setf idx-leaf (logand tree (1- (ash 1 (slh-tree-height))))
                tree (ash tree (- (slh-tree-height))))))))
    sig)))

(defun slh-verify (m sig pk &optional (params +slh-sha2-128s-params+))
  "Verify SIG over M under PK; returns T/nil."
  (let ((*slh-params* params))
  (unless (and (typep sig '(simple-array (unsigned-byte 8) (*)))
               (= (length sig) (slh-sig-bytes)))
    (return-from slh-verify nil))
  (let* ((pub-seed (subseq pk 0 (slh-n)))
         (pk-root (subseq pk (slh-n) (* 2 (slh-n))))
         (ctx (make-slh-ctx :sk-seed (make-array (slh-n) :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                            :pub-seed pub-seed))
         (mhash (make-array (slh-fors-msg-bytes) :element-type '(unsigned-byte 8)))
         (tree 0)
         (idx-leaf 0))
    (multiple-value-bind (mhash-val tree-val leaf-val)
        (slh-hash-message (subseq sig 0 (slh-n)) pub-seed pk-root m)
      (setf mhash mhash-val
            tree tree-val
            idx-leaf leaf-val))
    (let ((pos (slh-n))
          (roots (make-array (* (slh-fors-trees) (slh-n))
                             :element-type '(unsigned-byte 8)))
          (root (make-array (slh-n) :element-type '(unsigned-byte 8))))
      (let* ((fors-addr (slh-make-addr)))
        (slh-set-type fors-addr +slh-addr-type-wots+)
        (slh-set-tree fors-addr tree)
        (slh-set-keypair fors-addr idx-leaf)
        (slh-fors-pk-from-sig root sig pos mhash ctx fors-addr roots)
        (incf pos (* (1+ (slh-fors-height)) (slh-fors-trees) (slh-n))))
      (dotimes (i (slh-d))
        (let* ((tree-addr (slh-make-addr))
               (layer-wots-addr (slh-make-addr))
               (leaf (make-array (slh-n) :element-type '(unsigned-byte 8)))
               (auth-path (make-array (* (slh-tree-height) (slh-n))
                                      :element-type '(unsigned-byte 8)
                                      :initial-element 0)))
          (slh-set-layer tree-addr i)
          (slh-set-tree tree-addr tree)
          (slh-copy-subtree layer-wots-addr tree-addr)
          (slh-set-keypair layer-wots-addr idx-leaf)
          (slh-set-type tree-addr +slh-addr-type-hashtree+)
          (slh-wots-pk-from-sig-into leaf sig pos root ctx layer-wots-addr)
          (incf pos (* (slh-wots-len) (slh-n)))
          (replace auth-path sig :start2 pos)
          (incf pos (* (slh-tree-height) (slh-n)))
          (slh-compute-root root 0 leaf idx-leaf 0 auth-path
                            (slh-tree-height) ctx (copy-seq tree-addr))
          (setf idx-leaf (logand tree (1- (ash 1 (slh-tree-height))))
                tree (ash tree (- (slh-tree-height))))))
      (constant-time-equal root pk-root)))))


;;;
;;; Public API.  One key class pair + method suite per parameter set,
// generated by DEFINE-SLH-DSA-KIND so the 12 FIPS 205 sets share code.

(defmacro define-slh-dsa-kind (kind priv-class pub-class params doc-sk doc-pk)
  `(progn
     (defclass ,priv-class ()
       ((bytes :initarg :bytes :reader slh-dsa-key-bytes
               :type (simple-array (unsigned-byte 8) (*))))
       (:documentation ,doc-sk))
     (defclass ,pub-class ()
       ((bytes :initarg :bytes :reader slh-dsa-key-bytes
               :type (simple-array (unsigned-byte 8) (*))))
       (:documentation ,doc-pk))
     (defmethod make-private-key ((kind (eql ,kind))
                                  &key bytes &allow-other-keys)
       (let ((*slh-params* ,params))
         (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
                      (= (length bytes) (slh-sk-bytes)))
           (error 'missing-key-parameter
                  :kind ,kind :parameter 'bytes
                  :description "SLH-DSA secret key bytes"))
         (make-instance ',priv-class :bytes (copy-seq bytes))))
     (defmethod make-public-key ((kind (eql ,kind))
                                 &key bytes &allow-other-keys)
       (let ((*slh-params* ,params))
         (unless (and (typep bytes '(simple-array (unsigned-byte 8) (*)))
                      (= (length bytes) (slh-pk-bytes)))
           (error 'missing-key-parameter
                  :kind ,kind :parameter 'bytes
                  :description "SLH-DSA public key bytes"))
         (make-instance ',pub-class :bytes (copy-seq bytes))))
     (defmethod destructure-private-key ((key ,priv-class))
       (list :bytes (copy-seq (slh-dsa-key-bytes key))))
     (defmethod destructure-public-key ((key ,pub-class))
       (list :bytes (copy-seq (slh-dsa-key-bytes key))))
     (defmethod generate-key-pair ((kind (eql ,kind)) &key &allow-other-keys)
       (let* ((*slh-params* ,params)
              (n (slh-n))
              (seed (random-data (* 3 n))))
         (multiple-value-bind (pk sk root)
             (slh-keygen-with-seed (subseq seed 0 n) (subseq seed n (* 2 n))
                                   (subseq seed (* 2 n) (* 3 n))
                                   *slh-params*)
           (declare (ignore root))
           (values (make-instance ',priv-class :bytes sk)
                   (make-instance ',pub-class :bytes pk)))))
     (defmethod sign-message ((key ,priv-class) message
                              &key (start 0) end &allow-other-keys)
       (slh-sign (subseq message start (or end (length message)))
                 (slh-dsa-key-bytes key)
                 ,params))
     (defmethod verify-signature ((key ,pub-class) message signature
                                  &key (start 0) end &allow-other-keys)
       (slh-verify (subseq message start (or end (length message)))
                   signature
                   (slh-dsa-key-bytes key)
                   ,params))))

(define-slh-dsa-kind :slh-dsa-sha2-128s
  slh-dsa-sha2-128s-private-key slh-dsa-sha2-128s-public-key
  +slh-sha2-128s-params+
  "64-byte SLH-DSA-SHA2-128s secret key."
  "32-byte SLH-DSA-SHA2-128s public key.")

(define-slh-dsa-kind :slh-dsa-sha2-128f
  slh-dsa-sha2-128f-private-key slh-dsa-sha2-128f-public-key
  +slh-sha2-128f-params+
  "64-byte SLH-DSA-SHA2-128f secret key."
  "32-byte SLH-DSA-SHA2-128f public key.")

(define-slh-dsa-kind :slh-dsa-sha2-192s
  slh-dsa-sha2-192s-private-key slh-dsa-sha2-192s-public-key
  +slh-sha2-192s-params+
  "96-byte SLH-DSA-SHA2-192s secret key."
  "48-byte SLH-DSA-SHA2-192s public key.")

(define-slh-dsa-kind :slh-dsa-sha2-192f
  slh-dsa-sha2-192f-private-key slh-dsa-sha2-192f-public-key
  +slh-sha2-192f-params+
  "96-byte SLH-DSA-SHA2-192f secret key."
  "48-byte SLH-DSA-SHA2-192f public key.")
