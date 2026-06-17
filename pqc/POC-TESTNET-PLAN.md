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
