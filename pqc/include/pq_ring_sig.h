/* CIP-0001 §5.3 — swappable PQ linkable-ring-signature backend (C ABI). DRAFT. */
#ifndef CCX_PQ_RING_SIG_H
#define CCX_PQ_RING_SIG_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { CCX_PQ_OK=0, CCX_PQ_ERR_NULL=-1, CCX_PQ_ERR_BUFFER=-2, CCX_PQ_ERR_VERIFY=-3, CCX_PQ_ERR_PARAM=-4 };
uint32_t ccx_pq_scheme_id(void);
size_t ccx_pq_pubkey_bytes(void);
size_t ccx_pq_seckey_bytes(void);
size_t ccx_pq_nullifier_bytes(void);
int32_t ccx_pq_keygen(const uint8_t *seed, size_t seed_len,
                      uint8_t *pk_out, size_t pk_cap, uint8_t *sk_out, size_t sk_cap);
int32_t ccx_pq_nullifier(const uint8_t *sk, size_t sk_len, const uint8_t *pk, size_t pk_len,
                         uint8_t *nf_out, size_t nf_cap);
int32_t ccx_pq_sign(const uint8_t *msg, size_t msg_len,
                    const uint8_t *ring, size_t ring_count, size_t member_stride,
                    const uint8_t *sk, size_t sk_len, size_t signer_index,
                    uint8_t *sig_out, size_t *sig_len);
int32_t ccx_pq_verify(const uint8_t *msg, size_t msg_len,
                      const uint8_t *ring, size_t ring_count, size_t member_stride,
                      const uint8_t *sig, size_t sig_len, uint8_t *nf_out, size_t nf_cap);
/* ML-KEM-768 stealth one-time outputs (Gap 4): sender derives a one-time signing seed + ciphertext;
   recipient re-derives the seed by decapsulating. Real PQ recipient-unlinkability. */
size_t ccx_pq_kem_pubkey_bytes(void);
size_t ccx_pq_kem_seckey_bytes(void);
size_t ccx_pq_kem_ct_bytes(void);
int32_t ccx_pq_kem_keypair(uint8_t *pk_out, size_t pk_cap, uint8_t *sk_out, size_t sk_cap);
int32_t ccx_pq_kem_derive_output(const uint8_t *kem_pk, size_t kem_pk_len,
                                 uint8_t *ct_out, size_t ct_cap, uint8_t *seed_out, size_t seed_cap);
int32_t ccx_pq_kem_scan(const uint8_t *kem_sk, size_t kem_sk_len,
                        const uint8_t *ct, size_t ct_len, uint8_t *seed_out, size_t seed_cap);
/* ML-KEM-768 encrypted on-chain messages (tx-extra 0x06): same KEM as the stealth pair but with a
   distinct message domain ("ccx-msg-kem-v1") so a key reused for both never yields the same secret.
   The 32-byte secret is index-independent; the caller mixes in the per-message index. */
int32_t ccx_pq_msg_kem_encap(const uint8_t *kem_pk, size_t kem_pk_len,
                             uint8_t *ct_out, size_t ct_cap, uint8_t *key_out, size_t key_cap);
int32_t ccx_pq_msg_kem_decap(const uint8_t *kem_sk, size_t kem_sk_len,
                             const uint8_t *ct, size_t ct_len, uint8_t *key_out, size_t key_cap);
/* ChaCha20-Poly1305 AEAD for the PQ message field (tx-extra 0x06): real authenticated encryption.
   Key + 12-byte nonce are derived from (the 32-byte KEM seed, index) via SHAKE256 "ccx-msg-aead-v1".
   seal() writes pt_len + 16 bytes (ciphertext || Poly1305 tag); open() verifies the tag and writes
   NOTHING on authentication failure. Both return 0 on success, negative on error. */
int32_t ccx_pq_msg_seal(const uint8_t *seed, size_t seed_len, uint64_t index,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t *ct_out, size_t ct_cap, size_t *ct_len_out);
int32_t ccx_pq_msg_open(const uint8_t *seed, size_t seed_len, uint64_t index,
                        const uint8_t *ct, size_t ct_len,
                        uint8_t *pt_out, size_t pt_cap, size_t *pt_len_out);
/* Real PQ primitives self-tests — sizes via out-struct. */
typedef struct { size_t pk, sk, ct_or_sig, ss; int32_t ok; } ccx_pq_sizes;
ccx_pq_sizes ccx_mlkem768_selftest(void);
ccx_pq_sizes ccx_mldsa_selftest(void);
ccx_pq_sizes ccx_pq_ringsig_selftest(void);
ccx_pq_sizes ccx_pq_kem_stealth_selftest(void);
ccx_pq_sizes ccx_pq_msg_kem_selftest(void);
ccx_pq_sizes ccx_pq_msg_aead_selftest(void);
#ifdef __cplusplus
}
#endif
#endif
