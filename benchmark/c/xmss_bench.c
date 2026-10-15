/* XMSS-SHA2_10_256 benchmark for the reference C implementation. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "randombytes.h"
#include "xmss.h"
#include "params.h"

#ifndef ALG
#define ALG "XMSS-SHA2_10_256"
#endif

#ifndef VARIANT
#define VARIANT "XMSS-SHA2_10_256"
#endif

static uint64_t bench_rng_state = 0x123456789abcdef0ULL;
void randombytes(unsigned char *out, unsigned long long len) {
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

    xmss_params params;
    uint32_t oid;
    if (xmss_str_to_oid(&oid, VARIANT) != 0) { fprintf(stderr, "bad variant\n"); return 1; }
    if (xmss_parse_oid(&params, oid) != 0) { fprintf(stderr, "bad oid\n"); return 1; }

    unsigned char *pk = malloc(XMSS_OID_LEN + params.pk_bytes);
    unsigned char *sk = malloc(XMSS_OID_LEN + params.sk_bytes);
    unsigned char *m = malloc(mlen);
    unsigned char *sm = malloc(params.sig_bytes + mlen);
    unsigned char *mout = malloc(params.sig_bytes + mlen);
    unsigned long long smlen, moutlen;

    for (size_t i = 0; i < mlen; i++) {
        m[i] = (uint8_t)(i * 7 + 3);
    }

    double keygen = 0.0, sign = 0.0, verify = 0.0;
    double t0, t1;

    t0 = now_seconds();
    if (xmss_keypair(pk, sk, oid) != 0) { fprintf(stderr, "keypair failed\n"); return 1; }
    t1 = now_seconds();
    keygen += t1 - t0;

    if (xmss_sign(sk, sm, &smlen, m, mlen) != 0) { fprintf(stderr, "sign failed\n"); return 1; }
    if (xmss_sign_open(mout, &moutlen, sm, smlen, pk) != 0) {
        fprintf(stderr, "verify failed\n"); return 1;
    }

    for (int i = 0; i < iterations; i++) {
        t0 = now_seconds();
        if (xmss_sign(sk, sm, &smlen, m, mlen) != 0) { fprintf(stderr, "sign failed\n"); return 1; }
        t1 = now_seconds();
        sign += t1 - t0;

        t0 = now_seconds();
        if (xmss_sign_open(mout, &moutlen, sm, smlen, pk) != 0) {
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

    free(pk); free(sk); free(m); free(sm); free(mout);
    return 0;
}
