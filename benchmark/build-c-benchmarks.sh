#!/bin/sh
# Build C reference benchmarks for algorithms that have a local C reference.
#
# Expected source trees:
#   /tmp/pqc            HQC and Classic McEliece references
#   /tmp/pqc/PQClean-master  PQClean McEliece 348864 and Falcon-512
#   /tmp/xmss           XMSS reference
#   /tmp/opencode/mldsa-ref/dilithium-master
#   /tmp/opencode/sphincs-ref/sphincsplus-master/ref
#
# Override with PQC_SRC, XMSS_SRC, DILITHIUM_SRC, SPHINCS_SRC, OUT, CC, CFLAGS.

set -eu

PQC_SRC="${PQC_SRC:-/tmp/pqc}"
XMSS_SRC="${XMSS_SRC:-/tmp/xmss}"
DILITHIUM_SRC="${DILITHIUM_SRC:-/tmp/opencode/mldsa-ref/dilithium-master}"
SPHINCS_SRC="${SPHINCS_SRC:-/tmp/opencode/sphincs-ref/sphincsplus-master/ref}"
OUT="${OUT:-benchmark/c-bin}"
CC="${CC:-gcc}"
CFLAGS="${CFLAGS:--O3 -march=native -std=gnu99}"
PQCOMMON="$PQC_SRC/PQClean-master/common"

mkdir -p "$OUT"

# List .c and .S files, excluding tests, debug programs and source RNG.
# List PQClean common .c sources, excluding the source RNG.
pqclean_common_sources() {
    for f in "$PQCOMMON"/*.c; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        case "$base" in
            randombytes.c) continue ;;
        esac
        printf '%s ' "$f"
    done
}

list_sources() {
    dir="$1"
    for f in "$dir"/*.c "$dir"/*.S; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        case "$base" in
            randombytes.c|PQCgenKAT_sign.c|det-gen.c|rbstub.c) continue ;;
            *_inc.c) continue ;;
            *test*.c|*dbg*.c|*dump*.c|*health*.c|*stages*.c) continue ;;
        esac
        if grep -q '^int main' "$f" 2>/dev/null; then
            continue
        fi
        printf '%s ' "$f"
    done
}

build_kem() {
    name="$1"; prefix="$2"; dir="$3"; shift 3
    sources="$(list_sources "$dir") $(pqclean_common_sources)"
    echo "CC $name"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS -I"$dir" -I"$PQCOMMON" \
        -DPREFIX="$prefix" -DALG="\"$name\"" \
        benchmark/c/kem_bench.c $sources "$@" -o "$OUT/$name"
}

build_sign() {
    name="$1"; prefix="$2"; size_prefix="$3"; dir="$4"; shift 4
    sources="$(list_sources "$dir") $(pqclean_common_sources)"
    echo "CC $name"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS -I"$dir" -I"$PQCOMMON" \
        -DPREFIX="$prefix" -DSIZE_PREFIX="$size_prefix" -DALG="\"$name\"" \
        benchmark/c/sign_bench.c $sources "$@" -o "$OUT/$name"
}

build_dilithium() {
    name="$1"; mode="$2"; dir="$3"; shift 3
    sources=$(list_sources "$dir")
    echo "CC $name"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS -I"$dir" -DDILITHIUM_MODE="$mode" \
        -DPREFIX=pqcrystals_dilithium"${mode}_ref" \
        -DALG="\"$name\"" \
        benchmark/c/dilithium_bench.c $sources "$@" -o "$OUT/$name"
}

build_dilithium_avx2() {
    name="$1"; mode="$2"; dir="$3"; shift 3
    # Explicit source list from the Dilithium AVX2 Makefile.
    set -- sign.c packing.c polyvec.c poly.c ntt.S invntt.S pointwise.S \
        shuffle.S consts.c rejsample.c rounding.c \
        fips202.c fips202x4.c f1600x4.S symmetric-shake.c
    sources=""
    for f in "$@"; do
        sources="$sources $dir/$f"
    done
    echo "CC $name"
    # shellcheck disable=SC2086
    "$CC" -O3 -march=native -mavx2 -mpopcnt -std=gnu99 -I"$dir" \
        -DDILITHIUM_MODE="$mode" \
        -DPREFIX=pqcrystals_dilithium"${mode}_avx2" \
        -DALG="\"$name\"" \
        benchmark/c/dilithium_bench.c $sources -o "$OUT/$name"
}

build_sphincs() {
    name="$1"; params="$2"; dir="$3"; shift 3
    base="address.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c"
    case "$params" in
        *shake*) extra="fips202.c hash_shake.c thash_shake_robust.c" ;;
        *haraka*) extra="haraka.c hash_haraka.c thash_haraka_robust.c" ;;
        *sha2*) extra="sha2.c hash_sha2.c thash_sha2_robust.c" ;;
        *) echo "unknown SPHINCS+ params: $params" >&2; return 1 ;;
    esac
    sources=""
    for f in $base $extra; do
        sources="$sources $dir/$f"
    done
    echo "CC $name"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS -I"$dir" \
        -DSPHINCS=1 -DPARAMS="$params" \
        -DALG="\"$name\"" \
        benchmark/c/sign_bench.c $sources -o "$OUT/$name"
}


# The Classic McEliece reference trees in /tmp/pqc have a copied namespace
# header that always maps symbols to the 348864 implementation.  Copy the
# source and correct the namespace before building.
prepare_mce_source() {
    name="$1"; prefix="$2"; dir="$3"
    dest="$OUT/src-$name"
    rm -rf "$dest"
    mkdir -p "$dest"
    cp "$dir"/*.c "$dir"/*.h "$dest"/
    sed -i "s/PQCLEAN_MCELIECE348864_CLEAN_/${prefix}_/g" "$dest"/*
    printf '%s' "$dest"
}

# HQC references.
build_kem hqc-128 PQCLEAN_HQC128_CLEAN "$PQC_SRC/hqc-128"
build_kem hqc-192 PQCLEAN_HQC192_CLEAN "$PQC_SRC/hqc-192"
build_kem hqc-256 PQCLEAN_HQC256_CLEAN "$PQC_SRC/hqc-256"

# Classic McEliece references.
build_kem mceliece348864-clean PQCLEAN_MCELIECE348864_CLEAN "$PQCOMMON/../crypto_kem/mceliece348864/clean"
build_kem mceliece348864-avx2 PQCLEAN_MCELIECE348864_AVX2 "$PQCOMMON/../crypto_kem/mceliece348864/avx2"
build_kem mceliece460896 PQCLEAN_MCELIECE460896_CLEAN "$(prepare_mce_source mceliece460896 PQCLEAN_MCELIECE460896_CLEAN "$PQC_SRC/mce460896")"
build_kem mceliece6688128 PQCLEAN_MCELIECE6688128_CLEAN "$(prepare_mce_source mceliece6688128 PQCLEAN_MCELIECE6688128_CLEAN "$PQC_SRC/mce6688128")"
build_kem mceliece6960119 PQCLEAN_MCELIECE6960119_CLEAN "$(prepare_mce_source mceliece6960119 PQCLEAN_MCELIECE6960119_CLEAN "$PQC_SRC/mce6960119")"
build_kem mceliece8192128 PQCLEAN_MCELIECE8192128_CLEAN "$(prepare_mce_source mceliece8192128 PQCLEAN_MCELIECE8192128_CLEAN "$PQC_SRC/mce8192128")"

# Falcon-512.
build_sign falcon-512-clean PQCLEAN_FALCON512_CLEAN_crypto_sign PQCLEAN_FALCON512_CLEAN "$PQCOMMON/../crypto_sign/falcon-512/clean"
build_sign falcon-512-avx2 PQCLEAN_FALCON512_AVX2_crypto_sign PQCLEAN_FALCON512_AVX2 "$PQCOMMON/../crypto_sign/falcon-512/avx2"

# ML-DSA / Dilithium.
build_dilithium mldsa-44-ref 2 "$DILITHIUM_SRC/ref"
build_dilithium mldsa-65-ref 3 "$DILITHIUM_SRC/ref"
build_dilithium mldsa-87-ref 5 "$DILITHIUM_SRC/ref"
build_dilithium_avx2 mldsa-44-avx2 2 "$DILITHIUM_SRC/avx2"
build_dilithium_avx2 mldsa-65-avx2 3 "$DILITHIUM_SRC/avx2"
build_dilithium_avx2 mldsa-87-avx2 5 "$DILITHIUM_SRC/avx2"

# SLH-DSA / SPHINCS+.
build_sphincs slh-dsa-sha2-128s sphincs-sha2-128s "$SPHINCS_SRC"
build_sphincs slh-dsa-sha2-128f sphincs-sha2-128f "$SPHINCS_SRC"
build_sphincs slh-dsa-sha2-192s sphincs-sha2-192s "$SPHINCS_SRC"
build_sphincs slh-dsa-sha2-192f sphincs-sha2-192f "$SPHINCS_SRC"
build_sphincs slh-dsa-sha2-256s sphincs-sha2-256s "$SPHINCS_SRC"
build_sphincs slh-dsa-sha2-256f sphincs-sha2-256f "$SPHINCS_SRC"
build_sphincs slh-dsa-shake-128s sphincs-shake-128s "$SPHINCS_SRC"
build_sphincs slh-dsa-shake-128f sphincs-shake-128f "$SPHINCS_SRC"
build_sphincs slh-dsa-shake-192s sphincs-shake-192s "$SPHINCS_SRC"
build_sphincs slh-dsa-shake-192f sphincs-shake-192f "$SPHINCS_SRC"
build_sphincs slh-dsa-shake-256s sphincs-shake-256s "$SPHINCS_SRC"
build_sphincs slh-dsa-shake-256f sphincs-shake-256f "$SPHINCS_SRC"

# XMSS.
xmss_sources="params.c hash_address.c utils.c wots.c xmss_core.c xmss_commons.c xmss.c fips202.c hash.c shim_sha256.c"
sources=""
for f in $xmss_sources; do
    sources="$sources $XMSS_SRC/$f"
done
echo "CC xmss-sha2_10_256"
# shellcheck disable=SC2086
"$CC" $CFLAGS -I"$XMSS_SRC" -I"$XMSS_SRC/shiminc" \
    -DALG="\"xmss-sha2_10_256\"" \
    benchmark/c/xmss_bench.c $sources -o "$OUT/xmss-sha2_10_256"

echo "Built C benchmarks in $OUT"
