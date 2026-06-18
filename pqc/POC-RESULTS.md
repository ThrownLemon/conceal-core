# PQ Testnet PoC — Results (CIP-0001)

Status: **WORKING END-TO-END** on an isolated 2-node testnet (built + run on the WSL x86_64 host).
Branch: `pqc/testnet-poc` (fork `ThrownLemon/conceal-core`). Reproduce with `pqc/run-poc-testnet.sh`.

This is a feasibility/demo PoC: **unaudited, not constant-time, demo-only.** Do not use on mainnet.

## What was demonstrated (real PQ crypto, live)

The full post-quantum consensus lifecycle, in real `conceal-core` daemon code, with **no wallet**:

1. **PQ module linked** — `conceald` logs `[PQ] ccx-pqc post-quantum module linked; scheme_id=0xc0de0002`.
2. **Real ML-DSA-65 signatures.** The spend signature is a genuine ML-DSA-65 (FIPS 204) signature, not a
   stub. `ccx_pq_verify` performs real verification (accepts iff the signature validates under a ring
   member's key) — **unforgeable**: a valid signature requires a ring member's secret seed. The PQ spend tx
   dropped from ~19 KB (old hash stub) to **~5.3 KB**. `ccx_pq_ringsig_selftest` → ok=1.
3. **Secret-bound link tag (nullifier).** `nf = SHAKE256("ccx-pq-nf" || seed)` is derived from the spent
   output's *secret*, not its public key — so it no longer deanonymises the signer the way the old `H(pk)`
   tag did (anyone could recompute `H(pk)` over the ring to find the signer).
4. **Real ring of N distinct members.** The testnet coinbase emits one fixed-denomination PQ output
   (`PQ_TESTNET_COINBASE_AMOUNT = 100000`) with a **distinct one-time key per height**, so
   `m_pqOutputs[amount]` accumulates an anonymity set. A ring-of-4 spend was accepted; the daemon resolved
   all 4 members from the chain and verified the ML-DSA signature against the set.
5. **Per-output double-spend, three ways:**
   - **Mined on-chain** — the PQ spend lands in a block; `tx_count = 1`.
   - **In-pool double-spend rejected** — a second unconfirmed tx reusing the nullifier is rejected by the
     **mempool** nullifier set (`tx_pool_size` stays 1, before either is mined).
   - **Independent spend accepted** — spending a *different* output (different nullifier) succeeds, proving
     distinct per-output nullifiers (the old shared-key design marked every PQ output spent at once).
6. **ML-KEM-768 stealth outputs (on-chain).** The testnet coinbase derives each PQ output's one-time key by
   **encapsulating to a testnet ML-KEM recipient** and publishes the Kyber-768 ciphertext in
   `PqKeyOutput.kemCt` (coinbase grew to ~3.1 KB). The output key cannot be re-derived from height (Kyber
   encapsulation is randomised); the injector **decapsulates the on-chain `kemCt` with the KEM secret** to
   recover the spend key — it logs `signer output recognised as ours (KEM stealth scan OK)` and the daemon
   accepts the spend. Only the KEM-secret holder can detect/spend an output. Genuine PQ recipient-
   unlinkability, working live. (`ccx_pq_kem_stealth_selftest` → ok=1 also covers the primitive in isolation,
   including that a wrong recipient recovers a different seed.)

## Consensus + crypto changes (all testnet-gated where it matters)

| Area | Change | File |
|------|--------|------|
| Signature backend | real ML-DSA-65 keygen/sign/verify + secret-bound nullifier | `pqc/ccx-pqc/src/lib.rs` |
| KEM stealth | ML-KEM-768 derive_output / scan + selftest | `pqc/ccx-pqc/src/lib.rs` |
| Input/output types | `PqKeyInput` / `PqKeyOutput` variant + serialization + v3 | `include/CryptoNote.h`, `CryptoNoteSerialization.cpp` |
| Index + nullifier | `m_pqOutputs`, `m_spent_pq_nullifiers`; reorg-safe pop; DoS-bound | `Blockchain.{h,cpp}` |
| Spend validation | `check_pq_tx_input` (ring resolve + `ccx_pq_verify` + nullifier bind + unlock window) | `Blockchain.cpp` |
| Output / input gates | accept `PqKeyOutput` / `PqKeyInput` (v3) | `CryptoNoteFormatUtils.cpp` |
| Block-version gate | allow v3 PQ tx in v1 testnet blocks | `Blockchain.cpp` (`pushBlock`) |
| PQ coinbase | fixed-denomination PQ output, ML-KEM stealth one-time key + remainder KeyOutput | `Currency.cpp` |
| Testnet KEM recipient | hardcoded ML-KEM keypair (minted once via `ccx_pq_kem_keypair`) | `pqc/include/pq_testnet_kem_keypair.h` |
| Mempool | in-pool PQ nullifier set (insert/erase/reject/serialize) | `TransactionPool.{h,cpp}` |
| Injector | parses on-chain coinbase txs, scans `kemCt`, ring-of-N builder | `pqc/tools/pq_injector.cpp` |
| Run friction | pin testnet difficulty (LWMA overshoot stalled mining) | `Blockchain.cpp` |

## The one honest gap that remains: cryptographic signer-unlinkability

The ML-DSA backend's `verify` identifies **which** ring member signed (it tries each member's public key).
So the ring today is a **real on-chain decoy set with a real, unforgeable, secret-bound key-image**, but it
is **not yet cryptographic signer-unlinkability** — and linkability is sound only for an honest signer
(a malicious signer could embed a fake tag). Closing this needs a zero-knowledge one-out-of-many proof
(lattice Sigma-OR / MPC-in-the-head) so that `verify` accepts membership **without** learning the index and
**enforces** the tag is correctly derived. An adversarial review (3 independent reviewers, against the code
and the prebuilt Raptor lib) confirmed this is genuinely a multi-session cryptographic implementation, and
that Raptor is the wrong backend (no recoverable nullifier, struct-of-pointers keys incompatible with the
flat-stride ABI, GPLv3 Falcon C). It is the audit-gated long pole (CIP §5.3 / C1).

## Documented next steps (scoped, not yet done)

- **ZK ring-membership proof** for true signer-unlinkability (the long pole above) — the one remaining gap.
- **Native wallet support** for PQ outputs (currently the injector tool stands in for a wallet); a
  testnet-only `get_pq_outputs` RPC would replace the demo script's coinbase-tx fetching with a direct query.
