# PQ Testnet PoC — Results (CIP-0001)

Status: **WORKING END-TO-END** on an isolated 2-node testnet (built + run on the WSL x86_64 host).
Branch: `pqc/testnet-poc` (fork `ThrownLemon/conceal-core`). Reproduce with `pqc/run-poc-testnet.sh`.

This is a feasibility/demo PoC: **unaudited, not constant-time, demo-only.** Do not use on mainnet.

## What was demonstrated (real PQ crypto, live)

The full post-quantum consensus lifecycle, in real `conceal-core` daemon code, with **no wallet**:

1. **PQ module linked** — `conceald` logs `[PQ] ccx-pqc post-quantum module linked; scheme_id=0xc0de0002`.
2. **Anonymous lattice ring signature (experimental).** The spend signature is an AOS/LSAG lattice linkable
   ring signature (module-SIS, Dilithium-style aborts) — see the dedicated section below. `verify` walks a
   symmetric ring chain and **does not learn which member signed** (real anonymity), and it is unforgeable
   (non-member/tampered/wrong-message all fail). Ring-of-4 spend tx ≈ 24.7 KB.
3. **Soundly-bound link tag (nullifier).** `nf = SHAKE256(I)` where `I = A₂·s` is the lattice tag bound
   *inside* the proof to the signer's secret — deterministic per output (links double-spends), enforced by
   verification (a malicious signer cannot swap it), and it does not reveal which ring member signed.
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
| Signature backend | EXPERIMENTAL lattice AOS/LSAG anonymous linkable ring signature | `pqc/ccx-pqc/src/ringsig.rs` |
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

## Signer-unlinkability: addressed (EXPERIMENTAL lattice ring signature)

The signature backend is now a genuinely **anonymous, soundly-linkable** post-quantum ring signature
(`pqc/ccx-pqc/src/ringsig.rs`): an AOS/LSAG hash-chained ring of Fiat-Shamir-with-aborts (Dilithium-style)
Sigma proofs over module-SIS `t = A·s`, with a linking tag `I = A₂·s` bound into every branch.

- **Anonymous:** `verify` walks the symmetric ring chain and **never learns which member signed** — the old
  ML-DSA backend tried each member's key (revealing the signer); the lattice backend does not.
- **Soundly linkable:** the real branch forces `I = A₂·s_signer`, so the tag is deterministic in the secret
  and a malicious signer cannot swap it. The daemon nullifier is `SHAKE256(I)`. Same output → same tag →
  double-spend caught; different output → different tag → independent spend works (both shown live).
- **Unforgeable:** `ccx_pqr_ringsig_selftest` (ok=1) confirms a non-member, a tampered signature, and a
  wrong-message signature all fail, plus linkability and signer-distinctness.

**EXPERIMENTAL / UNVERIFIED / NOT CONSTANT-TIME / DEMO-GRADE PARAMETERS** (R_q = Z_q[X]/(X²⁵⁶+1),
q=8380417, K=L=4 — small dimensions, biased matrix sampling; **not** a calibrated security level). This
demonstrates the construction is structurally real and works end-to-end on the chain; production needs
calibrated parameters, constant-time implementation, and an audit (CIP §5.3 / C1). An earlier adversarial
review (3 reviewers) had flagged the prebuilt Raptor lib as the wrong backend (no recoverable nullifier,
struct-of-pointers keys vs the flat-stride ABI, GPLv3 Falcon C) — hence this from-scratch lattice scheme.

## Security review + hardening (multi-agent)

Seven parallel agents reviewed the branch (security, performance, crypto) and blueprinted the
uncovered surfaces (`docs/reviews/`, `docs/design/quantum-resistance/`). Findings addressed:

- **Restart double-spend (CRITICAL) — FIXED + verified.** `m_pqOutputs` + `m_spent_pq_nullifiers`
  are now persisted and rebuilt; after a restart a re-spend of a spent output is rejected by the
  reloaded nullifier set.
- **Mixed-tx signature desync (CRITICAL) — FIXED.** PQ inputs now advance the positional
  `tx.signatures` index.
- **Ring bounds + duplicate offsets (HIGH) — FIXED.** Min/max ring size enforced; duplicate ring
  members rejected (a zero offset collapsed the ring to size 1).
- **Output length / index-poisoning (MED) — FIXED.** `check_outs_valid` enforces exact PQ key/kemCt
  lengths.
- **Lattice crypto:** the reviewer's CRITICAL universal-forgery claim was **tested and refuted**
  (`ccx_pqr_forgery_test` runs the exact attack; verify rejects it). The real HIGH findings — nonce
  reuse and modulo bias — are **fixed** (message-bound mask, unbiased rejection sampling).

**Known issues still open** (documented, not yet fixed): a non-deterministic crash when the
block-explorer RPCs (`f_block_json`/`gettransactions`) serialize a *reloaded* PQ block (heap/uninit,
masked under gdb — needs ASAN; does NOT affect the consensus path, which is verified working after a
restart); money-conservation check in `pushBlock` for v3 (MED); FFI `catch_unwind`. Plus the
production hardening below.

## Documented next steps (scoped, not yet done)

- **Production-grade ring signature:** the lattice scheme is structurally complete but demo-grade — calibrate
  parameters to a real security level (NIST cat-1+), make it constant-time, optimise (NTT instead of
  schoolbook), shrink signatures, and audit. CIP-0001 C1.
- **Native wallet support** for PQ outputs (currently the injector tool stands in for a wallet); a
  testnet-only `get_pq_outputs` RPC would replace the demo script's coinbase-tx fetching with a direct
  query. Blueprint: `docs/design/quantum-resistance/wallet-address-v2.md`.
- **Deposits → ML-DSA-65** (still Ed25519 multisig — Shor-broken). Blueprint:
  `docs/design/quantum-resistance/deposits-mldsa.md` (height-gated `UPGRADE_HEIGHT_V9`).
- **Encrypted on-chain messages → ML-KEM-768** (still Curve25519 ECDH — Shor-broken). Blueprint:
  `docs/design/quantum-resistance/messages-mlkem.md`.
- **PoW / hashing:** no change needed — the symmetric/hash layer is already Grover-adequate (256-bit
  hashes, unbounded search space). Documented in `docs/design/quantum-resistance/pow-grover-widening.md`.

## Coverage: PQ-protected vs. still-vulnerable surfaces

| Surface | Status |
|---|---|
| Spend auth (ring sig, key image) | ✅ lattice anonymous ring sig (experimental params) |
| Output stealth (ECDH) | ✅ ML-KEM-768 |
| Double-spend (mempool + chain + restart) | ✅ |
| Deposits (Ed25519 multisig) | ❌ blueprint only |
| Encrypted messages (Curve25519 ECDH) | ❌ blueprint only |
| PoW / hashing (Grover) | ✅ already adequate (no change) |
| Wallet keys / address format | ❌ blueprint only (injector stands in) |
| Amount confidentiality | n/a — plaintext amounts (team-deferred) |
