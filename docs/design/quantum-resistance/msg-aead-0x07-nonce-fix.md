# F5 — 0x07 Authenticated-Message AEAD: Nonce-Reuse Fix Spec

**Status: SPEC (not yet implemented). Audit finding F5 (Claude/Opus). Wire-format change — needs a versioned, height-gated rollout decision before implementation.**

## 1. The problem

The PQ message layer has two tx-extra fields:

- **0x06 `tx_extra_pq_message`** — encrypts to a **fresh per-message ML-KEM-768 shared secret** (a new encapsulation每 message). Key/nonce are derived together via `derive_aead_key_nonce(seed, index)` = `SHAKE256("ccx-msg-aead-v1" ‖ seed ‖ index)` (lib.rs:420), splitting the 44-byte output into a 32-byte key + 12-byte ChaCha20-Poly1305 nonce. Because `seed` is fresh per message, `(key, nonce)` is unique. **0x06 is SAFE.**

- **0x07 `tx_extra_authenticated_message`** (classical sender-authenticated memo) — derives `seed` from a **Curve25519 ECDH** of (recipient spend-pub, **tx secret key**) and the AEAD `(key, nonce)` from `SHAKE256(... ‖ seed ‖ output_index)` (TransactionExtra.cpp ~784-814; lib.rs:413-420). **No AAD is bound.**

The 0x07 nonce is therefore a deterministic function of `(ECDH(R, txsec), output_index)`. ChaCha20-Poly1305 is **catastrophically broken under (key, nonce) reuse**: keystream reuse destroys confidentiality, and a single nonce-repeat enables Poly1305 one-time-key recovery → **memo forgery**. Reuse occurs whenever a transaction **reuses its tx secret key to the same recipient at the same output index** — CryptoNote normally samples a fresh tx key per transaction, so this rests entirely on that unchecked invariant, with **no defence-in-depth** in the 0x07 path.

Severity: **HIGH** for the memo layer (not consensus/funds, but a total break of memo confidentiality + authenticity on the reuse condition). 0x06 is unaffected.

## 2. The fix (defence-in-depth + uniqueness guarantee)

Two independent hardenings; implement **both**:

### 2.1 Make the nonce unique regardless of tx-key reuse

Source the nonce from a value that is unique per *ciphertext*, not derived solely from the (possibly-reused) ECDH seed:

- **Preferred:** prepend a fresh **24-byte random salt** to the 0x07 field and switch to **XChaCha20-Poly1305** (192-bit nonce). Derive `nonce = salt` (random, stored in the field) and `key = SHAKE256("ccx-msg-aead-v2" ‖ seed ‖ output_index)`. A 192-bit random nonce makes collision negligible even under full tx-key reuse. This matches the wallet-at-rest construction (`walletcrypto.rs`, already XChaCha20 with `OsRng` 24-byte nonce — F4-clean per the usage audit).
- **Alternative (no new field bytes):** bind the **tx public key** and the **global output index** into the nonce derivation: `nonce = SHAKE256("ccx-msg-aead-v2-nonce" ‖ seed ‖ tx_pubkey ‖ global_output_index)`. This is unique as long as `(tx_pubkey, global_output_index)` is unique — which is enforced by consensus (no two outputs share a global index) — so it does **not** rely on the tx-key-uniqueness invariant. Cheaper (no extra bytes) but weaker than a random nonce if `tx_pubkey` is ever reused with a colliding index.

### 2.2 Bind AAD

Pass `AAD = "ccx-msg-aead-v2-aad" ‖ tx_pubkey ‖ global_output_index` to the AEAD `encrypt`/`decrypt`. This cryptographically binds the ciphertext to its position and transaction, so a memo cannot be **relocated** to another output/tx (context-confusion) and a nonce-repeat across *different* AAD no longer yields a Poly1305 forgery on the other context.

## 3. Wire-format / rollout

This **breaks decryption of existing 0x07 memos** (new key/nonce derivation + AAD + possibly a new salt field). Therefore:

1. Introduce a **new field tag** `0x08` (or a `version` byte inside 0x07) for the v2 AEAD; keep the 0x07 reader for historical memos (read-only).
2. **Height-gate** v2 emission behind `UPGRADE_HEIGHT_V10` (testnet resets, so no migration burden there). Wallets emit v2 only at/after activation.
3. Bump the domain string to `ccx-msg-aead-v2` (already used above) so v1 and v2 keys/nonces never collide.

## 4. Acceptance checks

- Two memos to the same recipient with a **reused tx key** at different indices, and with a forced-reused tx key at the **same** index, both produce distinct `(key, nonce)` (assert in a unit test).
- A v2 memo relocated to a different output index / tx fails to `open` (AAD binding).
- Round-trip encrypt/decrypt for v2; v1 memos still decrypt via the legacy reader.
- No `(key, nonce)` pair is derivable twice across 10⁶ randomized (seed, index, tx_pubkey) draws.

## 5. Why not applied in the audit pass

It is a **memo wire-format change** with backward-incompatible decryption and a height-gated rollout decision (new tag vs in-field version; testnet reset timing). That is a product/consensus-rollout call for the team, not a unilateral edit on money-adjacent crypto. The 0x06 PQ path is already safe; 0x07 is the classical-compat memo path.
