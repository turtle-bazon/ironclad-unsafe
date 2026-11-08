#!/bin/sh
# Build the local C reference benchmarks used by benchmark/benchmark-all.lisp.
#
# Sources are the unmodified upstream trees:
#   PQClean          HQC, Classic McEliece, ML-KEM, ML-DSA, Falcon-512 and
#                    SPHINCS+ (the *simple* variants, which are what FIPS 205
#                    SLH-DSA standardizes; the robust ones are about 2x slower
#                    and made the Lisp rows look better than they are)
#   xmss-reference   XMSS-SHA2_10_256 (linked against OpenSSL's libcrypto)
#
# They are downloaded into $SRC when missing.  Each scheme is built from its
# portable "clean" implementation, which is the reference the benchmark
# table compares against, and from its AVX2 implementation where PQClean has
# one (suffix -avx2), for a second, tougher comparison.
#
# Usage (from the repository root):
#   benchmark/build-c-benchmarks.sh
# Environment overrides: SRC, OUT, CC, CFLAGS.

set -eu

SRC="${SRC:-/tmp/ironclad-c-refs}"
OUT="${OUT:-benchmark/c-bin}"
CC="${CC:-gcc}"
CFLAGS="${CFLAGS:--O3 -march=native -std=gnu99 -w}"
BENCH=benchmark/c

fetch() {  # github-owner/repo
    dest="$SRC/$(basename "$1")"
    [ -d "$dest" ] && return 0
    echo "FETCH $1"
    mkdir -p "$dest"
    curl -sSfL "https://github.com/$1/archive/refs/heads/master.tar.gz" |
        tar -xz -C "$dest" --strip-components=1
}

mkdir -p "$SRC" "$OUT"
fetch PQClean/PQClean
fetch XMSS/xmss-reference

PQ="$SRC/PQClean"
COMMON="$PQ/common"
FAILED=""

# Implementation sources, PQClean common code (minus its OS randombytes: the
# bench harness supplies a deterministic one), and the 4-way Keccak for the
# AVX2 builds.
sources() {
    s=""
    for f in "$1"/*.c "$1"/*.S "$1"/*.s; do
        [ -f "$f" ] && s="$s $f"
    done
    for f in "$COMMON"/*.c; do
        case "$(basename "$f")" in
            randombytes.c) ;;
            *) s="$s $f" ;;
        esac
    done
    case "$1" in
        */avx2) s="$s $COMMON/keccak4x/KeccakP-1600-times4-SIMD256.c" ;;
    esac
    printf '%s' "$s"
}

# PQClean namespace: crypto_kem/ml-kem-768/avx2 -> PQCLEAN_MLKEM768_AVX2.
namespace() {
    printf 'PQCLEAN_%s_%s' "$(echo "$1" | tr 'a-z' 'A-Z' | tr -d '-')" \
        "$(echo "$2" | tr 'a-z' 'A-Z')"
}

kem() {  # output-name scheme impl
    dir="$PQ/crypto_kem/$2/$3"
    [ -d "$dir" ] || { FAILED="$FAILED $1(missing)"; return 0; }
    echo "CC $1"
    # shellcheck disable=SC2046
    "$CC" $CFLAGS -I"$dir" -I"$COMMON" -DPREFIX="$(namespace "$2" "$3")" \
        -DALG="\"$1\"" "$BENCH/kem_bench.c" $(sources "$dir") \
        -o "$OUT/$1" || FAILED="$FAILED $1"
}

sig() {  # output-name scheme impl
    dir="$PQ/crypto_sign/$2/$3"
    [ -d "$dir" ] || { FAILED="$FAILED $1(missing)"; return 0; }
    ns="$(namespace "$2" "$3")"
    echo "CC $1"
    # shellcheck disable=SC2046
    "$CC" $CFLAGS -I"$dir" -I"$COMMON" -DPREFIX="${ns}_crypto_sign" \
        -DSIZE_PREFIX="$ns" -DALG="\"$1\"" "$BENCH/sign_bench.c" \
        $(sources "$dir") -o "$OUT/$1" || FAILED="$FAILED $1"
}

for v in 128 192 256; do
    kem "hqc-$v" "hqc-$v" clean
done

kem mceliece348864-clean mceliece348864 clean
kem mceliece348864-avx2 mceliece348864 avx2
for v in 460896 6688128 6960119 8192128; do
    kem "mceliece$v" "mceliece$v" clean
    kem "mceliece$v-avx2" "mceliece$v" avx2
done

for v in 512 768 1024; do
    kem "ml-kem-$v" "ml-kem-$v" clean
    kem "ml-kem-$v-avx2" "ml-kem-$v" avx2
done

sig falcon-512-clean falcon-512 clean
sig falcon-512-avx2 falcon-512 avx2

for v in 44 65 87; do
    sig "mldsa-$v-ref" "ml-dsa-$v" clean
    sig "mldsa-$v-avx2" "ml-dsa-$v" avx2
done

for h in sha2 shake; do
    for p in 128s 128f 192s 192f 256s 256f; do
        sig "slh-dsa-$h-$p" "sphincs-$h-$p-simple" clean
        sig "slh-dsa-$h-$p-avx2" "sphincs-$h-$p-simple" avx2
    done
done

X="$SRC/xmss-reference"
echo "CC xmss-sha2_10_256"
"$CC" $CFLAGS -I"$X" -DALG="\"xmss-sha2_10_256\"" "$BENCH/xmss_bench.c" \
    "$X/params.c" "$X/hash_address.c" "$X/utils.c" "$X/wots.c" \
    "$X/xmss_core.c" "$X/xmss_commons.c" "$X/xmss.c" "$X/fips202.c" \
    "$X/hash.c" -lcrypto -o "$OUT/xmss-sha2_10_256" ||
    FAILED="$FAILED xmss-sha2_10_256"

echo "Built C benchmarks in $OUT"
if [ -n "$FAILED" ]; then
    echo "Failed:$FAILED" >&2
    exit 1
fi
