/* CIP-0001 §5.3 — Swappable PQ linkable-ring-signature backend (C ABI).
 *
 * DRAFT interface. The Rust crypto module (librustzcash-style) implements this;
 * the C++ daemon links it across the FFI seam. Backends (MatRiCT-Au lineage,
 * etc.) sit behind this one stable header. Object sizes are scheme- and
 * parameter-dependent, so every variable-length output uses the standard
 * two-call pattern: call with out=NULL to learn the length, then with a buffer.
 *
 * Status: DRAFT (B3). Not final until the scheme + params are audit-fixed.
 */
#ifndef CCX_PQ_RING_SIG_H
#define CCX_PQ_RING_SIG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes. */
typedef enum {
  CCX_PQ_OK            = 0,
  CCX_PQ_ERR_NULL      = -1,  /* null pointer */
  CCX_PQ_ERR_BUFFER    = -2,  /* output buffer too small (see *len) */
  CCX_PQ_ERR_VERIFY    = -3,  /* signature did not verify */
  CCX_PQ_ERR_PARAM     = -4,  /* bad parameter (ring size, index, malformed key) */
  CCX_PQ_ERR_INTERNAL  = -5
} ccx_pq_status;

/* Identifies the active backend/parameter set (for versioning the wire format). */
uint32_t ccx_pq_scheme_id(void);

/* Fixed sizes for the chosen parameter set (bytes). 0 ⇒ variable (use the
 * length-out functions below). */
size_t ccx_pq_pubkey_bytes(void);     /* one-time output public key */
size_t ccx_pq_seckey_bytes(void);     /* one-time output secret key */
size_t ccx_pq_nullifier_bytes(void);  /* serial number / key-image equivalent */

/* ---- One-time output keypair (used as a ring member / spend key) ---- */
ccx_pq_status ccx_pq_keygen(const uint8_t *seed, size_t seed_len,
                            uint8_t *pk_out, size_t pk_cap,
                            uint8_t *sk_out, size_t sk_cap);

/* ---- Nullifier (double-spend tag) — deterministic in the spent output ----
 * MUST be collision-free, unique per output, non-malleable (one output ⇒ one
 * valid nullifier). Inserted into the spent-set index. */
ccx_pq_status ccx_pq_nullifier(const uint8_t *sk, size_t sk_len,
                               const uint8_t *pk, size_t pk_len,
                               uint8_t *nf_out, size_t nf_cap);

/* ---- Linkable ring signature ----
 * msg          = tx_prefix_hash (32 bytes) — binds the signature to the tx.
 * ring         = concatenated member public keys; ring_count = N (>= MINIMUM_MIXIN_V2+1).
 * member_stride= bytes per member pubkey (== ccx_pq_pubkey_bytes()).
 * signer_index = position of the real signer's key in `ring`.
 * Two-call: sig_out=NULL ⇒ *sig_len set to required size, returns CCX_PQ_OK. */
ccx_pq_status ccx_pq_sign(const uint8_t *msg, size_t msg_len,
                          const uint8_t *ring, size_t ring_count, size_t member_stride,
                          const uint8_t *sk, size_t sk_len, size_t signer_index,
                          uint8_t *sig_out, size_t *sig_len);

/* Verify. Recomputes/validates the proof over `ring` at `msg`. The nullifier is
 * carried inside `sig`; *nf_out (optional, may be NULL) returns it for indexing.
 * Returns CCX_PQ_OK iff valid, CCX_PQ_ERR_VERIFY otherwise. */
ccx_pq_status ccx_pq_verify(const uint8_t *msg, size_t msg_len,
                            const uint8_t *ring, size_t ring_count, size_t member_stride,
                            const uint8_t *sig, size_t sig_len,
                            uint8_t *nf_out, size_t nf_cap);

/* Constant-time, audited backends only. No global mutable state; thread-safe.
 * Memory: the library never frees caller buffers; caller owns all I/O memory. */

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* CCX_PQ_RING_SIG_H */
