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
/* Returns 1 iff pk is a well-formed lattice ring-sig public key: exactly ccx_pq_pubkey_bytes() long
   AND every coefficient canonically encoded. Output-acceptance (check_outs_valid) MUST call this so a
   non-canonical PQ output key is rejected at acceptance — prevents algebraic-key-aliasing (t / t+q
   sharing one secret+nullifier => only one ever spendable) and the consensus split a non-canonical
   ring member would cause (nodes hash it differently). Returns 0 on malformed key or null pointer. */
int32_t ccx_pq_pubkey_is_canonical(const uint8_t *pk, size_t pk_len);
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
/* DETERMINISTIC, seed-based FIPS-203 (ML-KEM-768) / FIPS-204 (ML-DSA-65) keygen — so PQ wallet keys
   are mnemonic-restorable (the RNG keypairs above are not). The caller passes the wallet master seed
   (any length); it is domain-separated + SHAKE256-expanded to the FIPS seed, so the same seed always
   yields the SAME keypair across processes/machines. pk/sk are emitted in the SAME byte encoding the
   pqcrypto encap/decap (KEM) and sign/verify (DSA) paths consume (pk; *expanded* sk), so a
   deterministic keypair is a drop-in for the existing on-chain code path. Return 0 on success.
   KEM: pk=1184 (ccx_pq_kem_pubkey_bytes), sk=2400 (ccx_pq_kem_seckey_bytes).
   DSA: pk=1952 (ccx_pq_multisig_pubkey_bytes), sk=4032 (ccx_pq_multisig_seckey_bytes). */
int32_t ccx_pq_kem_keygen_det(const uint8_t *seed, size_t seed_len,
                              uint8_t *pk_out, size_t pk_cap, uint8_t *sk_out, size_t sk_cap);
int32_t ccx_pq_multisig_keygen_det(const uint8_t *seed, size_t seed_len,
                                   uint8_t *pk_out, size_t pk_cap, uint8_t *sk_out, size_t sk_cap);
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
/* ML-DSA-65 (FIPS 204 / dilithium3) PQ MULTISIG for post-quantum deposits (CIP-0001
   UPGRADE_HEIGHT_V9). Plain m-of-n detached signatures over the tx prefix hash — no ring, no
   nullifier (double-spend caught by the chain isUsed flag). Standardized NIST primitive, used as-is
   for the deposit path (distinct from the experimental lattice ring sig above). */
size_t ccx_pq_multisig_pubkey_bytes(void);
size_t ccx_pq_multisig_seckey_bytes(void);
size_t ccx_pq_sig_bytes(void);
int32_t ccx_pq_multisig_keypair(uint8_t *pk_out, size_t pk_cap, uint8_t *sk_out, size_t sk_cap);
int32_t ccx_pq_multisig_sign(const uint8_t *msg, size_t msg_len,
                             const uint8_t *sk, size_t sk_len,
                             uint8_t *sig_out, size_t *sig_len);
int32_t ccx_pq_multisig_verify(const uint8_t *msg, size_t msg_len,
                               const uint8_t *pk, size_t pk_len,
                               const uint8_t *sig, size_t sig_len);
/* Wallet-file at-rest encryption (CIP-0001 Q2 §1b — CLIENT-SIDE ONLY, no consensus): Argon2id KDF
   (RFC 9106, salt + tunable cost) replacing the unsalted single-pass cn_slow_hash_v0 wallet KDF, and
   XChaCha20-Poly1305 AEAD (24-byte nonce, 16-byte Poly1305 tag) replacing the unauthenticated 8-round
   chacha8 container cipher. The wallet stores the salt + cost params + nonce in a versioned header. */
size_t ccx_wallet_key_bytes(void);        /* 32 */
size_t ccx_wallet_nonce_bytes(void);      /* 24 (XChaCha20 extended nonce) */
size_t ccx_wallet_aead_tag_bytes(void);   /* 16 (Poly1305 tag) — sealed len = pt_len + this */
/* CSPRNG (OS entropy) for the wallet salt + nonce — never use mt19937 for key/salt/nonce material. */
int32_t ccx_wallet_random_bytes(uint8_t *out, size_t out_len);
int32_t ccx_wallet_kdf_argon2id(const uint8_t *password, size_t password_len,
                                const uint8_t *salt, size_t salt_len,
                                uint32_t mem_kib, uint32_t iterations, uint32_t parallelism,
                                uint8_t *key_out, size_t key_cap);
int32_t ccx_wallet_aead_seal(const uint8_t *key, size_t key_len,
                             const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *pt, size_t pt_len,
                             uint8_t *ct_out, size_t ct_cap, size_t *ct_len_out);
int32_t ccx_wallet_aead_open(const uint8_t *key, size_t key_len,
                             const uint8_t *nonce, size_t nonce_len,
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
ccx_pq_sizes ccx_pq_multisig_selftest(void);
ccx_pq_sizes ccx_pq_detkeygen_selftest(void);
ccx_pq_sizes ccx_pqr_ringsig_selftest(void);
/* EXPERIMENTAL lattice ring-sig adversarial tests (testnet only — unaudited). forgery_test returns 1
   iff a no-secret universal forgery VERIFIES (BROKEN); soundness_test returns 1 iff EVERY modelled
   forgery/malleation is correctly rejected and an honest signature still verifies. Expect
   forgery_test==0 and soundness_test==1. HEURISTIC: empirical checks, not a proof or a security audit. */
int32_t ccx_pqr_forgery_test(void);
int32_t ccx_pqr_soundness_test(void);
/* Returns the number of MISMATCHES between the NTT poly_mul and the reference schoolbook multiply over
   the scheme's real input distributions + edge cases (0 == NTT is a verified pure speedup). Guards
   against a future twiddle/sign/bitrev regression silently changing signature bytes. Runs `iters`
   random trials. Expect 0. */
uint32_t ccx_pqr_ntt_equiv_test(uint32_t iters);
/* Wallet-file at-rest crypto selftest (Argon2id KDF + XChaCha20-Poly1305 AEAD). ok=1 iff derive is
   reproducible + salt-sensitive and seal/open round-trips with tamper/wrong-key rejected. */
ccx_pq_sizes ccx_wallet_crypto_selftest(void);
#ifdef __cplusplus
}
#endif
#endif
