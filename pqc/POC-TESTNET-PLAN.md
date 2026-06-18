# PQ PoC Testnet — build plan (co-agent-reviewed)

Reviewed by codex (gpt-5.5), gemini-3.1-pro, GLM-5.2. Architecture: **testnet + v3 PQ txs + PQ coinbase outputs + PQ output index + PQ validation + injector**. No simpler path validates the full consensus lifecycle.

## Gap decisions (my best judgment — testnet PoC)
- **Ring size:** fixed 4 for the PoC (small, fast).
- **PQ coinbase key:** a deterministic testnet **consensus constant** (PQ pubkey from a fixed seed in CryptoNoteConfig), NOT local config — else nodes split.
- **tx_prefix_hash:** signed message = hash of the prefix with every `PqKeyInput.ringsig` **cleared** (avoids the circular/self-referential hash). nullifier IS signed (binds it).
- **nullifier:** 32 bytes (stub H(pk)); **separate** spent-set `m_spent_pq_nullifiers` (chain) + a mempool set.
- **key_offsets:** RELATIVE/cumulative (same as legacy); decode before `m_pqOutputs` lookup; bounds-check.
- **testnet params:** raise `MAX_TX_SIZE_LIMIT` + `BLOCK_GRANTED_FULL_REWARD_ZONE`; low/zero min-fee so big PQ txs are accepted.
- **version gating:** v3 = PQ; reject PQ variants in v1/v2; guard `boost::get` by version to avoid crashes.
- **FFI safety:** Rust returns error codes, never panics across the C ABI; malformed input = validation failure, not crash.
- **reorg:** single mining node PoC won't reorg; still implement `popTransaction` PQ rollback for correctness.
- **persistence:** add `m_pqOutputs` + nullifier set to the existing blockchain-cache serialization (simplest).

## Build phases (each committed)
3a output index: `m_pqOutputs` + `m_spent_pq_nullifiers` (Blockchain.h) + pushTransaction/popTransaction + serialization.
3b validation: `check_pq_tx_input` (scan→ring→ccx_pq_verify) + nullifier checks in checkTransactionInputs; mempool PQ set.
4  coinbase PQ output (constructMinerTx, testnet, deterministic) + isolated network-id + raised testnet params.
5  injector tool (build+sign+submit v3 PQ tx via sendrawtransaction).
6  run: mine → inject → validate → mine → double-spend reject → restart-survives.

## CURRENT STATE (checkpoint) + precise continuation
**Done + committed on `pqc/testnet-poc` (builds clean):**
- P1: ccx-pqc linked into conceald (CMake+cargo); startup logs scheme_id.
- P2: PqKeyInput/PqKeyOutput variant types + serialization + v3 + 4 visitor overloads; v3 PQ tx round-trips real serialization (pqc/tests/tx_roundtrip).
- P3a: m_pqOutputs index + m_spent_pq_nullifiers; pushTransaction indexes PQ outputs + inserts nullifier.

**NEXT — Phase 3b (validation), exact approach:**
- In `Blockchain::checkTransactionInputs` (Blockchain.cpp ~2228 loop), add `else if (txin.type()==typeid(PqKeyInput))`: check `m_spent_pq_nullifiers.count(nf)` (reject if spent) + `check_pq_tx_input(...)`. Do NOT touch tx.signatures for PQ (getSignaturesCount=0; Release build, assert is no-op).
- New `Blockchain::check_pq_tx_input(const PqKeyInput&, prefixHash)`: resolve ring keys by mirroring `scanOutputKeysForIndexes` against `m_pqOutputs` (relative/cumulative offsets → absolute → m_pqOutputs[amount][idx] = (TransactionIndex, outIdx) → fetch tx via m_blocks[ti.block].transactions[ti.transaction] → boost::get<PqKeyOutput>(tx.outputs[outIdx].target).key). Concat keys → ring blob. Call `ccx_pq_verify(msg, ring.data(), N, ccx_pq_pubkey_bytes(), sig, siglen, nullptr, 0)`.
- **tx_prefix_hash:** signed msg = getObjectHash of a TransactionPrefix COPY with every PqKeyInput.ringsig cleared (avoid circular). Injector + validator MUST match.
- `#include "pq_ring_sig.h"` in Blockchain.cpp. Symbols resolve at executable link (Daemon links libccx_pqc.a) — build Daemon (not just CryptoNoteCore) to verify.

**Phase 4:** constructMinerTx (Currency.cpp) — on testnet add a PqKeyOutput; PQ recipient key = deterministic testnet consensus constant (NOT local config — codex: nodes split otherwise). Change CRYPTONOTE_NETWORK id (P2p/CryptoNoteConfig) for isolation. Raise TESTNET MAX_TX_SIZE_LIMIT + BLOCK_GRANTED_FULL_REWARD_ZONE; low min-fee.

**Phase 5:** injector cmd tool — Currency::Initialize, build v3 Transaction{PqKeyInput(offsets→mined PQ coinbase outputs, nullifier, ringSig=ccx_pq_sign over cleared-ringsig prefix hash)}, toBinaryArray→hex, POST /sendrawtransaction.

**Phase 6:** run conceald --testnet; start_mining; wait for PQ coinbase outputs; run injector; expect verify-OK + mined; replay → DOUBLE-SPEND reject.

**Gotchas (co-agent):** mempool needs its own PQ nullifier set (tx_pool add_tx/remove_tx); fee-per-byte may reject big PQ tx (raise testnet limits); Rust never panics across C ABI; version-gate boost::get (reject PQ in v1/v2); reorg-pop of m_pqOutputs+nullifiers is TODO (single-node fwd-only PoC won't hit it).
