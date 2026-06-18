# PQ Testnet PoC — Results (CIP-0001)

Status: **WORKING END-TO-END** on an isolated 2-node testnet (built + run on the WSL x86_64 host).
Branch: `pqc/testnet-poc` (fork `ThrownLemon/conceal-core`). Reproduce with `pqc/run-poc-testnet.sh`.

## What was demonstrated

The full post-quantum consensus lifecycle, in real `conceal-core` daemon code, with **no wallet**:

1. **PQ module linked** — `conceald` starts and logs `[PQ] ccx-pqc post-quantum module linked; scheme_id=0xc0de0001`.
2. **PQ coinbase** — on testnet, each block's coinbase (`Currency::constructMinerTx`, height > 0) emits a
   single `PqKeyOutput` (1312-byte lattice public key) instead of the usual `KeyOutput`. Observed coinbase
   tx size **1360 bytes** (vs ~119 for a normal coinbase). These outputs are indexed into `m_pqOutputs`.
3. **PQ spend built + signed** — `pq_injector <amount> <fee>` derives the deterministic testnet PQ keypair,
   resolves the ring (the referenced output's key), computes the cleared-ringSig signing hash exactly as the
   daemon does, signs via `ccx_pq_sign`, and prints the raw v3 transaction hex (~19 KB at ring size 1).
4. **Daemon validation + accept** — submitting via `sendrawtransaction` returns `{"status":"OK"}`. The daemon
   ran the full path: `check_inputs_types_supported` → `checkTransactionInputs` → `check_pq_tx_input`
   (ring resolution from `m_pqOutputs` → `ccx_pq_verify` → recovered-nullifier == declared-nullifier).
5. **Mined on-chain** — the PQ spend was included in **block 14**, which contained two transactions:
   - coinbase `PqKeyOutput`, size **1360**;
   - the PQ spend, `amount_out` 11999999000000 (= 12000000000000 − 1000000 fee), size **19406**.
6. **Double-spend rejected** — replaying a *distinct* transaction (different fee ⇒ different bytes/hash) that
   spends the **same** output (same nullifier) returns `{"status":"Failed"}`; `tx_pool_size` stays 0 and
   `tx_count` stays 1. The rejection is the nullifier check (`m_spent_pq_nullifiers`), not tx-hash dedup.

## Consensus changes that made it run (all testnet-gated where it matters)

| Area | Change | File |
|------|--------|------|
| Input/output types | `PqKeyInput` / `PqKeyOutput` variant + serialization + v3 | `include/CryptoNote.h`, `CryptoNoteSerialization.cpp` |
| Index maintenance | `m_pqOutputs` + `m_spent_pq_nullifiers`; reorg-safe pop; DoS-bounded nullifier | `Blockchain.{h,cpp}` |
| Spend validation | `check_pq_tx_input` (ring resolve + `ccx_pq_verify` + nullifier bind + unlock window) | `Blockchain.cpp` |
| Output validation | accept `PqKeyOutput` | `CryptoNoteFormatUtils.cpp` (`check_outs_valid`) |
| Input-type gate | accept `PqKeyInput` from v3 | `CryptoNoteFormatUtils.cpp` (`check_inputs_types_supported`) |
| Block-version gate | allow v3 PQ tx in v1 testnet blocks | `Blockchain.cpp` (`pushBlock`) |
| PQ coinbase | testnet coinbase emits a `PqKeyOutput` | `Currency.cpp` (`constructMinerTx`) |
| Run friction | pin testnet difficulty (LWMA overshoot stalled mining) | `Blockchain.cpp` (`getDifficultyForNextBlock`) |

## Honest limitations (PoC, not production)

- **Stub ring signature.** `ccx-pqc`'s ring sig is a deterministic `H(pubkey)` nullifier stub, not a real
  lattice linkable ring signature. It provides **no anonymity**. The real scheme (MatRiCT-Au lineage) is the
  audit-gated long pole (`docs/design/quantum-resistance/`).
- **Single shared coinbase key.** All testnet PQ coinbase outputs use one deterministic keypair (no stealth /
  KEM). Real outputs need per-output KEM-derived one-time keys.
- **Mempool nullifier set.** The tx pool does not track PQ nullifiers for *in-pool* (not-yet-mined)
  double-spends; the blockchain nullifier set + per-block validation still make an on-chain double-spend
  impossible. Closing this needs PQ-aware `tx_memory_pool`.
- **Testnet-only difficulty / block-version shims.** Real deployment needs a proper `UPGRADE_HEIGHT_V*` +
  block major version for PQ, and normal difficulty retargeting.
- **Isolation is operational** (mutual exclusive peers), not cryptographic — a real PoC net would also bump
  the network id / genesis so real nodes reject the handshake.
