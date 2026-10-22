;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
#+sbcl
(in-package :sb-c)

#+(and sbcl (or x86 x86-64) ironclad-assembly)
(progn

(defknown (ironclad::fill-block-ub8-le ironclad::fill-block-ub8-be)
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.(- array-dimension-limit 64))) (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::fill-block-ub8-le/64
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.(- array-dimension-limit 64))) (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::fill-block-ub8-be/64
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.(- array-dimension-limit 128))) (values)
  (any) :overwrite-fndb-silently t)

(defknown ironclad::expand-block
  ((simple-array (unsigned-byte 32) (*)))
  (values)
  (any) :overwrite-fndb-silently t)

(defknown ironclad::%update-sha1-block
  ((simple-array (unsigned-byte 32) (*)) (simple-array (unsigned-byte 32) (*)))
  (simple-array (unsigned-byte 32) (*))
  (any) :overwrite-fndb-silently t)

(defknown ironclad::sha256-expand-block
  ((simple-array (unsigned-byte 32) (*)))
  (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::x-salsa-core
  ((signed-byte 61) (simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::x-chacha-core
  ((signed-byte 61) (simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::pclmulqdq-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::bmi2-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::adx-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::avx2-cpu-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha-ni-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha256ni-compress-block
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values (simple-array (unsigned-byte 32) (8)))
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha256ni-compress-block-amd
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values (simple-array (unsigned-byte 32) (8)))
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::aes-ni-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::aes-ni-generate-round-keys
  ((simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::aes-ni-encrypt
  ((simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 32) (*))
   (integer 0 14))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::aes-ni-decrypt
  ((simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 32) (*))
   (integer 0 14))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::fast-blake2s-mixing
  ((unsigned-byte 32)
   (unsigned-byte 32)
   (unsigned-byte 32)
   (unsigned-byte 32)
   (unsigned-byte 32)
   (unsigned-byte 32))
  (values (unsigned-byte 32)
          (unsigned-byte 32)
          (unsigned-byte 32)
          (unsigned-byte 32))
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::gmac-mul-fast
  ((simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 8) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::hqc-clmul64
  ((unsigned-byte 64) (unsigned-byte 64))
  (values (unsigned-byte 64) (unsigned-byte 64))
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::secp256r1-fe-mul
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::secp256r1-fe-mul-raw-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::secp224r1-fe-mul-limbs-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::ed25519-fe-mul-raw-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::ed25519-fe-sqr-raw-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::goldilocks-fe-mul-raw-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::goldilocks-fe-reduce-asm
  ((simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::ed25519-comb-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::ed25519-inv-asm
  ((simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::ed25519-gen-mult-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::ed25519-pow22523-asm
  ((simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::secp256r1-fe-add-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::secp256r1-fe-sub-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::secp256r1-fe-sqr-raw-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::secp256r1-fe-reduce-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad::secp256r1-fe-reduce-fast-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::secp256r1-fe-mul-raw-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::secp256r1-fe-reduce-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad::secp256r1-fe-reduce-fast-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::xor128
  ((simple-array (unsigned-byte 8) (*))
   (integer 0 #.array-dimension-limit)
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.array-dimension-limit)
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.array-dimension-limit))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::mov128
  ((simple-array (unsigned-byte 8) (*))
   (integer 0 #.array-dimension-limit)
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.array-dimension-limit))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad::swap32
  ((unsigned-byte 32))
  (unsigned-byte 32)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::swap64
  ((unsigned-byte 64))
  (unsigned-byte 64)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad::inc-counter-block
  ((integer 0 #.most-positive-fixnum)
   (simple-array (unsigned-byte 8) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha256ni-msg1
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha256ni-msg2
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha256ni-rnds2
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

);#+sbcl

#+x86-64
(defknown ironclad::sha256ni-rnds2-3
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha256ni-paddd
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha256ni-pshufd-0e
  ((simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha256ni-pshufb
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 8) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad::sha256ni-palignr-4
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)
