/* Dilithium/ML-DSA signature benchmark template.
 *
 * Build with:
 *   -DPREFIX=pqcrystals_dilithium2_ref (or 3/5 and avx2)
 *   -DALG="\"ML-DSA-44\""
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "randombytes.h"
#include "api.h"

#ifndef PREFIX
#define PREFIX pqcrystals_dilithium2_ref
#endif

#ifndef ALG
#define ALG "unknown"
#endif

#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)

#define KEYPAIR CAT(PREFIX, _keypair)
#define SIGN CAT(PREFIX, _signature)
#define VERIFY CAT(PREFIX, _verify)
#define PK_BYTES CAT(PREFIX, _PUBLICKEYBYTES)
#define SK_BYTES CAT(PREFIX, _SECRETKEYBYTES)
#define SIG_BYTES CAT(PREFIX, _BYTES)

static uint64_t bench_rng_state = 0x123456789abcdef0ULL;
void randombytes(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        bench_rng_state = bench_rng_state * 6364136223846793005ULL
                          + 1442695040888963407ULL;
        out[i] = (uint8_t)(bench_rng_state >> 33);
    }
}

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

int main(int argc, char **argv) {
    int iterations = argc > 1 ? atoi(argv[1]) : 20;
    const size_t mlen = 32;

    uint8_t *pk = malloc(PK_BYTES);
    uint8_t *sk = malloc(SK_BYTES);
    uint8_t *sig = malloc(SIG_BYTES);
    uint8_t *m = malloc(mlen);
    size_t siglen = 0;

    for (size_t i = 0; i < mlen; i++) {
        m[i] = (uint8_t)(i * 7 + 3);
    }

    double keygen = 0.0, sign = 0.0, verify = 0.0;
    double t0, t1;

    t0 = now_seconds();
    if (KEYPAIR(pk, sk) != 0) { fprintf(stderr, "keypair failed\n"); return 1; }
    t1 = now_seconds();
    keygen += t1 - t0;

    if (SIGN(sig, &siglen, m, mlen, NULL, 0, sk) != 0) {
        fprintf(stderr, "sign failed\n"); return 1;
    }
    if (VERIFY(sig, siglen, m, mlen, NULL, 0, pk) != 0) {
        fprintf(stderr, "verify failed\n"); return 1;
    }

    for (int i = 0; i < iterations; i++) {
        t0 = now_seconds();
        if (SIGN(sig, &siglen, m, mlen, NULL, 0, sk) != 0) {
            fprintf(stderr, "sign failed\n"); return 1;
        }
        t1 = now_seconds();
        sign += t1 - t0;

        t0 = now_seconds();
        if (VERIFY(sig, siglen, m, mlen, NULL, 0, pk) != 0) {
            fprintf(stderr, "verify failed\n"); return 1;
        }
        t1 = now_seconds();
        verify += t1 - t0;
    }

    printf("algorithm=%s\n", ALG);
    printf("keygen_ms=%.6f\n", keygen * 1000.0);
    printf("sign_ms=%.6f\n", sign * 1000.0 / iterations);
    printf("verify_ms=%.6f\n", verify * 1000.0 / iterations);
    printf("iterations=%d\n", iterations);

    free(pk); free(sk); free(sig); free(m);
    return 0;
}
