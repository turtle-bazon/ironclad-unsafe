/* Generic NIST KEM benchmark template.
 *
 * Build with:
 *   -DPREFIX=<implementation prefix>
 *   -DALG="\"<display name>\""
 *
 * Example:
 *   gcc -O3 -march=native -std=gnu99 -I/tmp/pqc/hqc-128 \
 *       -DPREFIX=PQCLEAN_HQC128_CLEAN -DALG="\"HQC-128\"" \
 *       benchmark/c/kem_bench.c /tmp/pqc/hqc-128/*.c \
 *       -o benchmark/c-bin/hqc-128
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "randombytes.h"
#include "api.h"

#ifndef PREFIX
#define PREFIX PQCLEAN_HQC128_CLEAN
#endif

#ifndef ALG
#define ALG "unknown"
#endif

#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)

#define KEYPAIR CAT(PREFIX, _crypto_kem_keypair)
#define ENCAPS CAT(PREFIX, _crypto_kem_enc)
#define DECAPS CAT(PREFIX, _crypto_kem_dec)

#define PK_BYTES CAT(PREFIX, _CRYPTO_PUBLICKEYBYTES)
#define SK_BYTES CAT(PREFIX, _CRYPTO_SECRETKEYBYTES)
#define CT_BYTES CAT(PREFIX, _CRYPTO_CIPHERTEXTBYTES)
#define SS_BYTES CAT(PREFIX, _CRYPTO_BYTES)

/* Deterministic PRNG so timings are not dominated by OS entropy. */
static uint64_t bench_rng_state = 0x123456789abcdef0ULL;
int randombytes(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        bench_rng_state = bench_rng_state * 6364136223846793005ULL
                          + 1442695040888963407ULL;
        out[i] = (uint8_t)(bench_rng_state >> 33);
    }
    return 0;
}

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

int main(int argc, char **argv) {
    int iterations = argc > 1 ? atoi(argv[1]) : 20;

    uint8_t *pk = malloc(PK_BYTES);
    uint8_t *sk = malloc(SK_BYTES);
    uint8_t *ct = malloc(CT_BYTES);
    uint8_t *ss = malloc(SS_BYTES);
    uint8_t *ss2 = malloc(SS_BYTES);

    double keygen = 0.0, encaps = 0.0, decaps = 0.0;
    double t0, t1;

    t0 = now_seconds();
    if (KEYPAIR(pk, sk) != 0) { fprintf(stderr, "keypair failed\n"); return 1; }
    t1 = now_seconds();
    keygen += t1 - t0;

    if (ENCAPS(ct, ss, pk) != 0) { fprintf(stderr, "encaps failed\n"); return 1; }
    if (DECAPS(ss2, ct, sk) != 0) { fprintf(stderr, "decaps failed\n"); return 1; }
    if (memcmp(ss, ss2, SS_BYTES) != 0) {
        fprintf(stderr, "KEM roundtrip failed\n");
        return 1;
    }

    for (int i = 0; i < iterations; i++) {
        t0 = now_seconds();
        if (ENCAPS(ct, ss, pk) != 0) { fprintf(stderr, "encaps failed\n"); return 1; }
        t1 = now_seconds();
        encaps += t1 - t0;

        t0 = now_seconds();
        if (DECAPS(ss2, ct, sk) != 0) { fprintf(stderr, "decaps failed\n"); return 1; }
        t1 = now_seconds();
        decaps += t1 - t0;
    }

    printf("algorithm=%s\n", ALG);
    printf("keygen_ms=%.6f\n", keygen * 1000.0);
    printf("encaps_ms=%.6f\n", encaps * 1000.0 / iterations);
    printf("decaps_ms=%.6f\n", decaps * 1000.0 / iterations);
    printf("iterations=%d\n", iterations);

    free(pk); free(sk); free(ct); free(ss); free(ss2);
    return 0;
}
