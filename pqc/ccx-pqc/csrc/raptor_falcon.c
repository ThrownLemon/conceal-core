/*
 * raptor_falcon.c — clean-room C shim bridging PQClean Falcon-512 (MIT, public-domain-
 * compatible) to the Raptor linkable-ring-signature construction (eprint 2018/857).
 *
 * This file is ORIGINAL work (MIT). It calls into the vendored, MIT-licensed PQClean
 * Falcon-512 "clean" sources (Copyright 2017-2019 Falcon Project / Thomas Pornin).
 * No GPL code (e.g. zhenfeizhang/raptor) was read or copied.
 *
 * What it exposes to Rust (plain C ABI, fixed names):
 *   - deterministic Falcon-512 keygen seeded by a caller-supplied SHAKE256 byte stream
 *   - target-driven Falcon "preimage" signing: given a target polynomial u (mod q),
 *     produce a short (r0, r1) with r0 + r1*a = u  (a = public key = g/f).  [Raptor step 6]
 *   - integer polynomial arithmetic mod q = 12289 in R = Z_q[x]/(x^n+1), n=512
 *     (add/sub and NTT-based negacyclic multiply) for recomputing c_i during verify
 *   - H1: arbitrary bytes -> uniform ring element in R_q (random-oracle mask), via SHAKE256
 *   - thin wrappers over Falcon's comp/modq codecs for compact packing
 *
 * Falcon q = 12289, n = 512, logn = 9.  q = 12*1024 + 1, so the multiplicative group
 * has a 2n=1024-th root of unity => negacyclic NTT exists.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "inner.h"   /* PQCLEAN_FALCON512_CLEAN_* prototypes + inner_shake256 macros */
#include "fips202.h" /* shake256 */

#define RF_N    512u
#define RF_LOGN 9u
#define RF_Q    12289u

/* ---- public sizes (queried at runtime by the Rust layer) ---- */
size_t rfalcon_n(void)     { return RF_N; }
unsigned rfalcon_logn(void){ return RF_LOGN; }
uint32_t rfalcon_q(void)   { return RF_Q; }

/* PQClean Falcon raw key element sizes (private f,g,F: int8_t[n]; public h: uint16_t[n]). */
size_t rfalcon_pk_modq_bytes(void) { return 7u * RF_N / 4u + 1u; } /* 14 bits/coeff -> not used; see modq_encode */

/* =====================================================================================
 *  Deterministic key generation.
 *  The Rust side gives us a 48-byte (or any length) seed; we run SHAKE256 over it inside
 *  an inner_shake256 context (init/inject/flip) exactly as Falcon's own keygen expects,
 *  then call PQCLEAN_FALCON512_CLEAN_keygen.  Same seed => same (f,g,F,G,h) on a given
 *  platform (FP-rounding caveat documented in the report).
 *
 *  Outputs raw key elements so the Rust layer can encode them canonically:
 *    f,g (int8_t[n]), F (int8_t[n]), G (int8_t[n]), h (uint16_t[n])  (h = g/f mod q)
 *  Returns 0 on success, negative on failure.
 * ===================================================================================== */
int rfalcon_keygen_det(const uint8_t *seed, size_t seed_len,
                       int8_t *f, int8_t *g, int8_t *F, int8_t *G, uint16_t *h)
{
    /* tmp must be 64-bit aligned and >= FALCON_KEYGEN_TEMP_9 (14336). */
    union { uint8_t b[FALCON_KEYGEN_TEMP_9]; uint64_t align; } tmp;
    inner_shake256_context rng;
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, seed_len);
    inner_shake256_flip(&rng);
    PQCLEAN_FALCON512_CLEAN_keygen(&rng, f, g, F, G, h, RF_LOGN, tmp.b);
    inner_shake256_ctx_release(&rng);
    return 0;
}

/* =====================================================================================
 *  Target-driven preimage signing.  Raptor needs:  given target u in R_q (as uint16_t
 *  coeffs in [0,q)), use the trapdoor (f,g,F,G) to sample a SHORT (r0,r1) with
 *      r0 + r1 * a = u  (mod q, mod x^n+1),   a = g/f = public key.
 *
 *  Falcon's PQCLEAN_FALCON512_CLEAN_sign_dyn(sig, rng, f,g,F,G, hm, logn, tmp):
 *    - hm[] is the target hashed point (uint16_t[n], coeffs mod q).  We pass u directly.
 *    - writes s2 into sig[] (int16_t[n]); writes s1 into the START of tmp[] (int16_t[n]).
 *    - Falcon guarantees s1 + s2*h = hm with (s1,s2) short, where h is the public key.
 *  Map: r0 = s1, r1 = s2, a = h.  Exactly Raptor's requirement.
 *
 *  Signing randomness: Falcon's Gaussian sampler is seeded from `rng`.  We seed it from a
 *  caller-provided per-signature randomness buffer (so the spike is reproducible in tests
 *  AND so a real wallet could derive it deterministically).  Returns 0 on success.
 * ===================================================================================== */
int rfalcon_sign_target(const uint8_t *sign_seed, size_t seed_len,
                        const int8_t *f, const int8_t *g, const int8_t *F, const int8_t *G,
                        const uint16_t *u_target,
                        int16_t *r0_out, int16_t *r1_out)
{
    /* MEDIUM-2: reject null pointers rather than letting PQClean fault on them. */
    if (sign_seed == NULL || f == NULL || g == NULL || F == NULL || G == NULL ||
        u_target == NULL || r0_out == NULL || r1_out == NULL) {
        return -1;
    }

    /* sign_dyn tmp must be >= 72*2^logn bytes, 64-bit aligned. 72*512 = 36864. */
    union { uint8_t b[72u * RF_N]; uint64_t align; } tmp;
    inner_shake256_context rng;
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, sign_seed, seed_len);
    inner_shake256_flip(&rng);

    /* PQCLEAN_FALCON512_CLEAN_sign_dyn returns void in this PQClean release (it cannot fail:
     * it loops internally until a short signature is found), so there is no rc to check here.
     * The real robustness guard is the algebraic preimage check r0 + r1*a == u_target on the
     * Rust FFI boundary (see falcon_ffi::FalconKey::sign_target), which catches a silent
     * PQClean-internal-layout break that would scramble where s1/s2 land. */
    PQCLEAN_FALCON512_CLEAN_sign_dyn(r1_out, &rng, f, g, F, G, u_target, RF_LOGN, tmp.b);
    /* s1 (=r0) is now at the start of tmp.b, as int16_t[n]. */
    memcpy(r0_out, tmp.b, RF_N * sizeof(int16_t));
    inner_shake256_ctx_release(&rng);
    return 0;
}

/* =====================================================================================
 *  Integer polynomial arithmetic mod q in R = Z_q[x]/(x^n + 1), n=512.
 *  Used by verify to recompute c_i = r0 + a*r1 + h*b.  Original code (not copied from
 *  Falcon's static mq_* routines).  A direct O(n^2) negacyclic multiply is used: for a
 *  spike with ring size <= 16 and a handful of multiplies per signature, n=512 schoolbook
 *  is microseconds — correctness over speed.  (Production would swap in an NTT.)
 *  x^n = -1, so coefficient products that wrap past degree n are subtracted.
 * ===================================================================================== */
void rfalcon_polymul_modq(const uint16_t *a, const uint16_t *b, uint16_t *out) {
    uint32_t acc[RF_N];
    for (uint32_t i = 0; i < RF_N; i++) acc[i] = 0;
    for (uint32_t i = 0; i < RF_N; i++) {
        if (a[i] == 0) continue;
        uint64_t ai = a[i];
        for (uint32_t j = 0; j < RF_N; j++) {
            uint32_t k = i + j;
            uint64_t prod = (ai * b[j]) % RF_Q;
            if (k < RF_N) acc[k] = (uint32_t)((acc[k] + prod) % RF_Q);
            else          acc[k - RF_N] = (uint32_t)((acc[k - RF_N] + RF_Q - prod) % RF_Q); /* x^n = -1 */
        }
    }
    for (uint32_t i = 0; i < RF_N; i++) out[i] = (uint16_t)(acc[i] % RF_Q);
}

void rfalcon_polyadd_modq(const uint16_t *a, const uint16_t *b, uint16_t *out) {
    for (uint32_t i = 0; i < RF_N; i++) out[i] = (uint16_t)((a[i] + b[i]) % RF_Q);
}
void rfalcon_polysub_modq(const uint16_t *a, const uint16_t *b, uint16_t *out) {
    for (uint32_t i = 0; i < RF_N; i++) out[i] = (uint16_t)((a[i] + RF_Q - (b[i] % RF_Q)) % RF_Q);
}

/* Center a signed short poly (int16_t) into [0,q) representation for arithmetic. */
void rfalcon_center_to_modq(const int16_t *s, uint16_t *out) {
    for (uint32_t i = 0; i < RF_N; i++) {
        int32_t v = (int32_t)s[i] % (int32_t)RF_Q;
        if (v < 0) v += RF_Q;
        out[i] = (uint16_t)v;
    }
}

/* Squared L2 norm of an int16_t poly (for the short-vector acceptance bound check). */
uint64_t rfalcon_sqnorm(const int16_t *s) {
    uint64_t n = 0;
    for (uint32_t i = 0; i < RF_N; i++) { int64_t v = s[i]; n += (uint64_t)(v * v); }
    return n;
}

/* =====================================================================================
 *  H1 : bytes -> uniform ring element in R_q (used to mask a0 = a + H1(aots)).
 *  Rejection-sample uint16 values < q from a SHAKE256 stream keyed by the input.
 * ===================================================================================== */
void rfalcon_hash_to_rq(const uint8_t *in, size_t inlen, const char *domain, uint16_t *out) {
    shake256incctx sc;
    shake256_inc_init(&sc);
    if (domain) shake256_inc_absorb(&sc, (const uint8_t *)domain, strlen(domain));
    shake256_inc_absorb(&sc, in, inlen);
    shake256_inc_finalize(&sc);
    uint32_t got = 0;
    uint8_t buf[2];
    while (got < RF_N) {
        shake256_inc_squeeze(buf, 2, &sc);
        uint32_t v = ((uint32_t)buf[0] << 8) | buf[1]; /* 16 bits */
        v &= 0x3FFF; /* 14 bits, range [0,16383] */
        if (v < RF_Q) out[got++] = (uint16_t)v;
    }
}

/* SHAKE256 helper: absorb -> squeeze `outlen` bytes (for H over the c_i list, and b_i). */
void rfalcon_shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    shake256incctx sc;
    shake256_inc_init(&sc);
    shake256_inc_absorb(&sc, in, inlen);
    shake256_inc_finalize(&sc);
    shake256_inc_squeeze(out, outlen, &sc);
}

/* =====================================================================================
 *  Codec wrappers (compact packing).  Falcon's comp_encode is the Golomb-style compressor
 *  used to reach ~666 B signatures; we apply it to each short poly r0, r1.
 * ===================================================================================== */
size_t rfalcon_comp_encode(const int16_t *x, uint8_t *out, size_t max_out) {
    return PQCLEAN_FALCON512_CLEAN_comp_encode(out, max_out, x, RF_LOGN);
}
size_t rfalcon_comp_decode(int16_t *x, const uint8_t *in, size_t max_in) {
    return PQCLEAN_FALCON512_CLEAN_comp_decode(x, RF_LOGN, in, max_in);
}
/* public key a (uint16_t[n], coeffs mod q) <-> 14-bit modq encoding (897 bytes for n=512). */
size_t rfalcon_modq_encode(const uint16_t *x, uint8_t *out, size_t max_out) {
    return PQCLEAN_FALCON512_CLEAN_modq_encode(out, max_out, x, RF_LOGN);
}
size_t rfalcon_modq_decode(uint16_t *x, const uint8_t *in, size_t max_in) {
    return PQCLEAN_FALCON512_CLEAN_modq_decode(x, RF_LOGN, in, max_in);
}
