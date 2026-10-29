;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
#+sbcl
(in-package :sb-c)

#+(and sbcl (or x86 x86-64) ironclad-unsafe-assembly)
(progn

(defknown (ironclad-unsafe::fill-block-ub8-le ironclad-unsafe::fill-block-ub8-be)
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.(- array-dimension-limit 64))) (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::fill-block-ub8-le/64
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.(- array-dimension-limit 64))) (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::fill-block-ub8-be/64-8
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.(- array-dimension-limit 64))) (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::fill-block-ub8-be/64
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.(- array-dimension-limit 128))) (values)
  (any) :overwrite-fndb-silently t)

(defknown ironclad-unsafe::expand-block
  ((simple-array (unsigned-byte 32) (*)))
  (values)
  (any) :overwrite-fndb-silently t)

(defknown ironclad-unsafe::%update-sha1-block
  ((simple-array (unsigned-byte 32) (*)) (simple-array (unsigned-byte 32) (*)))
  (simple-array (unsigned-byte 32) (*))
  (any) :overwrite-fndb-silently t)

(defknown ironclad-unsafe::sha256-expand-block
  ((simple-array (unsigned-byte 32) (*)))
  (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::x-salsa-core
  ((signed-byte 61) (simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::x-chacha-core
  ((signed-byte 61) (simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any) :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::pclmulqdq-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::bmi2-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::adx-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::avx2-cpu-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sha-ni-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
#+x86-64
(defknown ironclad-unsafe::sha1ni-compress-block
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad-unsafe::sha256ni-compress-block
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values (simple-array (unsigned-byte 32) (8)))
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sha256ni-compress-block-amd
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values (simple-array (unsigned-byte 32) (8)))
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::aes-ni-support-p
  ()
  (boolean)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::aes-ni-generate-round-keys
  ((simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::chacha-core-2x
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (unsigned-byte 8))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::chacha-core-4x-avx2
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (unsigned-byte 8)
   (simple-array (unsigned-byte 8) (32))
   (simple-array (unsigned-byte 8) (32)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::chacha-core-2x-avx2
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (unsigned-byte 8))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::ripemd-160-block-asm
  ((simple-array (unsigned-byte 32) (5))
   (simple-array (unsigned-byte 32) (16))
   (simple-array (unsigned-byte 32) (5)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::md5-block-asm
  ((simple-array (unsigned-byte 32) (4))
   (simple-array (unsigned-byte 32) (16)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::aes-ni-mac-blocks
  ((simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (unsigned-byte 64)
   (simple-array (unsigned-byte 32) (*))
   (unsigned-byte 8))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::aes-ni-mac-block
  ((simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 32) (*))
   (unsigned-byte 8))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::aes-ni-encrypt-8x
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
(defknown ironclad-unsafe::aes-ni-ctr-encrypt-8x
  ((simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 32) (*))
   (integer 0 14))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad-unsafe::aes-ni-encrypt
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
(defknown ironclad-unsafe::aes-ni-decrypt
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
(defknown ironclad-unsafe::fast-blake2s-mixing
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
(defknown ironclad-unsafe::gmac-mul-fast
  ((simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 8) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mce-xor-words-avx2
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (unsigned-byte 64))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad-unsafe::mce-xor-words
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (unsigned-byte 64))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
#+x86-64
(defknown ironclad-unsafe::gmac-mul-8-fast
  ((simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 8) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad-unsafe::gmac-mul-4-fast
  ((simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (simple-array (unsigned-byte 8) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::clmul64
  ((unsigned-byte 64) (unsigned-byte 64))
  (values (unsigned-byte 64) (unsigned-byte 64))
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-mul
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-add64-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-sub64-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp521r1-fe-add-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp521r1-fe-sub-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-9-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-6-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp384r1-fe-add-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp384r1-fe-sub-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-16-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-48-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-64-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-32-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-16-cios-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-32-cios-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-48-cios-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::mont-mul-64-cios-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-mont-mul-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-scalar-mont-mul-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-mul-raw-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-double-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)



#+x86-64
(defknown ironclad-unsafe::secp224r1-fe-contract-limbs-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp224r1-fe-reduce-limbs-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp224r1-fe-mul-limbs-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::ed25519-fe-mul-raw-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::ed25519-fe-sqr-raw-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::goldilocks-fe-mul-raw-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::goldilocks-fe-reduce-asm
  ((simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::goldilocks-fe-add-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::goldilocks-fe-sub-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::ed25519-comb-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::ed25519-inv-asm
  ((simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::ed25519-gen-mult-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::ed25519-pow22523-asm
  ((simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-add-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-sub-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-sqr-raw-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-reduce-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad-unsafe::secp256r1-fe-reduce-fast-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-mul-raw-asm
  ((simple-array (unsigned-byte 64) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::secp256r1-double-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)



#+x86-64
(defknown ironclad-unsafe::secp256r1-fe-reduce-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad-unsafe::secp256r1-fe-reduce-fast-asm
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 64) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::xor128
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
(defknown ironclad-unsafe::mov128
  ((simple-array (unsigned-byte 8) (*))
   (integer 0 #.array-dimension-limit)
   (simple-array (unsigned-byte 8) (*))
   (integer 0 #.array-dimension-limit))
  (values)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad-unsafe::swap32
  ((unsigned-byte 32))
  (unsigned-byte 32)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::swap64
  ((unsigned-byte 64))
  (unsigned-byte 64)
  (any)
  :overwrite-fndb-silently t)

(defknown ironclad-unsafe::inc-counter-block
  ((integer 0 #.most-positive-fixnum)
   (simple-array (unsigned-byte 8) (*)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sha256ni-msg1
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sha256ni-msg2
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sha256ni-rnds2
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

);#+sbcl

#+x86-64
(defknown ironclad-unsafe::sha256ni-rnds2-3
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sha256ni-paddd
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sha256ni-pshufd-0e
  ((simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sha256ni-pshufb
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 8) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sha256ni-palignr-4
  ((simple-array (unsigned-byte 32) (*))
   (simple-array (unsigned-byte 32) (*)))
  (values simple-array)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::whirlpool-block-vop
  ((simple-array (unsigned-byte 64) (32))
   (simple-array (unsigned-byte 64) (8))
   (simple-array (unsigned-byte 64) (2064)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::cast5-encrypt-block-asm
  ((simple-array (unsigned-byte 32) (1056))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::blowfish-encrypt-block-asm
  ((simple-array (unsigned-byte 32) (18))
   (simple-array (unsigned-byte 32) (1024))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sm4-encrypt-block-asm
  ((simple-array (unsigned-byte 32) (1056))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::poly1305-blocks-asm
  ((simple-array (unsigned-byte 32) (5))
   (simple-array (unsigned-byte 64) (8))
   (simple-array (unsigned-byte 8) (*))
   (unsigned-byte 64)
   (unsigned-byte 64))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sm3-block-asm
  ((simple-array (unsigned-byte 32) (140)))
  (values)
  (any)
  :overwrite-fndb-silently t)

#+x86-64
(defknown ironclad-unsafe::sm3-schedule-asm
  ((simple-array (unsigned-byte 32) (140)))
  (values)
  (any)
  :overwrite-fndb-silently t)
