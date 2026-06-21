# Codex PQ Follow-Up Audit Checklist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Continue the researcher-grade PQ audit after other remediation passes, focusing on additional issues rather than re-reporting already-fixed findings.

**Architecture:** This is an evidence-first audit pass. Each task inspects one risk surface, records exact commands/files/line evidence, and updates `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md` only when there is a finding or material verification result.

**Tech Stack:** Rust `ccx-pqc`, C++ Conceal daemon/wallet, GoogleTest unit binary on WSL host `100.100.90.103`, cargo tests/fuzz metadata, markdown audit artifacts.

## Global Constraints

- Do not revert or overwrite Claude/model remediation code.
- Treat dirty worktree files as current state; do not assume the original audit commit still reflects behavior.
- Every clean/pass claim needs a fresh command or exact source inspection evidence.
- Mainnet remains no-go unless Tasks 1-5 of the original research checklist have independently reviewable evidence.
- Prefer documenting audit deltas over changing production code unless a small regression test or doc correction is necessary.

---

### Task 1: Rebaseline Current State and Audit Inputs

**Files:**
- Read: `git status --short`
- Read: `docs/design/quantum-resistance/security-audit-brief.md`
- Read: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`

**Produces:** Current worktree map and audit scope alignment.

- [x] Record current HEAD and dirty-file scope.
- [x] Confirm WSL tree parity for files used in remote tests.
- [x] Identify changed files not covered by the last delta audit.
- [x] Update this checklist status.

**Task 1 result:** Current HEAD is `411c848f7276ae5099b7e5c7e0fd01977f6ae243` with dirty remediation files. `src/Transfers/TransfersConsumer.cpp` was a changed source file not covered by the previous delta audit; local and WSL SHA-256 hashes match, and WSL regression `lookup_acc_outs.finds_testnet_pq_coinbase_remainder` passed.

### Task 2: Raptor Transcript, Versioning, and Compatibility

**Files:**
- Inspect: `pqc/ccx-pqc/src/raptor.rs`
- Inspect: `pqc/ccx-pqc/src/raptor_abi.rs`
- Inspect: `pqc/ccx-pqc/src/lib.rs`
- Inspect: `src/CryptoNoteConfig.h`
- Update if needed: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`

**Produces:** Verdict on whether current Raptor transcript changes are safely versioned and non-malleable.

- [x] Verify challenge hash inputs and OTS transcript inputs match verifier.
- [x] Check whether scheme IDs/version bytes changed for the ring-key-bound transcript.
- [x] Check signature decoder canonicality and trailing-garbage rejection.
- [x] Run targeted Raptor tests.
- [x] Record finding or clean result.

**Task 2 result:** Sign and verify both use `H(msg, ring, c_1..c_L)`, and the OTS target binds members, ring, and `aots`. The ABI decoder rejects non-canonical `aots`, non-canonical varints, wrong ring count, and trailing garbage. `cargo test --offline raptor:: -- --nocapture` passed 3/3. Residual: the ring-bound transcript changed inside `"RAPT"` with no sub-version, so durable pre-fix `"RAPT"` artifacts require reset or explicit versioning; several design docs still mention stale scheme IDs.

### Task 3: Proof and B1 Claims Audit

**Files:**
- Inspect: `docs/design/quantum-resistance/raptor-formal-proofs.md`
- Inspect: `docs/design/quantum-resistance/raptor-b1-derivation.md`
- Inspect: `docs/reviews/quantum-resistance-research/01-raptor-proof-analysis.md`
- Update if needed: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`

**Produces:** List of proof/document claims that are valid, unsupported, or contradictory.

- [x] Check whether the proof document contains unresolved proof breaks.
- [x] Check B1 document consistency against source constants and estimator artifacts.
- [x] Search for raw estimator scripts/results promised by docs.
- [x] Record remaining mainnet blockers.

**Task 3 result:** The proof and B1 docs remain evidence-blocked for mainnet. `raptor-formal-proofs.md` still contains unresolved reduction caveats and an unsupported empirical anonymity/statistics claim. `raptor-b1-derivation.md` is internally inconsistent: it says the estimator run is pending, later says it completed with raw output archived, then recommends running it because it was not installable. `docs/reviews/quantum-resistance-research/` contains only `01-raptor-proof-analysis.md` and the delta audit, so no raw estimator script/output artifact was available for review.

### Task 4: 0x07 Message Migration and Parser Semantics

**Files:**
- Inspect: `src/CryptoNoteCore/TransactionExtra.cpp`
- Inspect: `src/CryptoNoteCore/TransactionExtra.h`
- Inspect: `tests/UnitTests/TestAuthenticatedMessage.cpp`
- Inspect: `src/Transfers/TransfersConsumer.cpp`
- Update if needed: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`

**Produces:** Verdict on nonce-v2 behavior, legacy decode behavior, and parser bounds.

- [x] Verify encrypt/decrypt AAD construction is symmetric.
- [x] Verify parser minimums match or intentionally allow old fields.
- [x] Check wallet/consumer paths for old 0x07 compatibility assumptions.
- [x] Run targeted authenticated-message tests on WSL.
- [x] Record finding or clean result.

**Task 4 result:** `tx_extra_authenticated_message::encrypt` and `decrypt` both derive AAD as tx public key bytes plus little-endian message index, and WSL `AuthenticatedMessage.*:MixedMessageIndex.*` passed 18/18. Production receive paths in `TransfersConsumer` and `WalletGreen` use `get_all_messages_from_extra`, which preserves the global mixed-message index. Residual remains `L-new-1`: parser/append accept the old 16-byte minimum while v2 decrypt requires `24-byte nonce + 16-byte tag`, so old 0x07 fields are parse-valid but undecryptable unless a migration/reset story is explicit.

### Task 5: Fuzz Harness Buildability and Coverage Quality

**Files:**
- Inspect: `pqc/ccx-pqc/fuzz/Cargo.toml`
- Inspect: `pqc/ccx-pqc/fuzz/fuzz_targets/*.rs`
- Inspect: `.github/workflows/check.yml`
- Update if needed: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`

**Produces:** Verdict on whether fuzzing targets build and exercise intended boundaries.

- [x] Check local cargo-fuzz availability and CI install path.
- [x] Inspect each fuzz target for early returns that avoid the target surface.
- [x] Attempt build where tooling exists.
- [x] Record coverage gaps and missing C++ fuzz target if any.

**Task 5 result:** Local macOS lacks `cargo-fuzz`, but WSL `~/.cargo/bin/cargo +nightly fuzz build` succeeded for all Rust fuzz targets. CI installs `cargo-fuzz` and runs `verify`, `unpack`, `pubkey_canonical`, and `ffi_boundary` as 30-second smoke jobs. Residual remains `L-new-2`: `verify.rs` often returns before `ccx_pq_verify` unless fuzz input includes at least one full 896-byte public key. No C++ transaction-extra/parser fuzz harness was found under `tests/` or `src/`, so the brief's parser robustness ask is not fully covered.

### Task 6: Side-Channel Evidence Quality

**Files:**
- Inspect: `pqc/ccx-pqc/src/falcon_ffi.rs`
- Inspect: `pqc/ccx-pqc/src/lib.rs`
- Inspect: `.github/workflows/check.yml`
- Update if needed: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`

**Produces:** Verdict on whether CT/dudect claims are evidence-grade.

- [x] Identify ignored timing tests and thresholds.
- [x] Check CI ctgrind policy scope versus full secret-key path.
- [x] Run ignored timing tests only if environment is suitable; otherwise document blocker.
- [x] Record remaining side-channel gate.

**Task 6 result:** WSL smoke timing runs passed: Falcon `ct_dudect` reported cropped t=-2.37 at n=4000, and ML-KEM `f6_mlkem` reported cropped t=-2.45 at n=4000. These remain smoke/regression evidence only: both tests are ignored by default and assert only `abs(t) < 500`. CI `ct-tripwire` filters ctgrind output to new branches in `raptor_falcon.c` glue and explicitly does not prove the full Falcon/PQClean/ML-KEM secret-key paths constant-time. Residual remains `M-new-1`.

### Task 7: Consensus Nullifier, Pool, Rollback, and Reorg State

**Files:**
- Inspect: `src/Blockchain/BlockchainStorage.cpp`
- Inspect: `src/Blockchain/BlockchainValidation.cpp`
- Inspect: `src/Blockchain/BlockchainPq.cpp`
- Inspect: `src/CryptoNoteCore/TransactionPool.cpp`
- Update if needed: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`

**Produces:** Source-backed verdict on double-spend state symmetry and rollback safety.

- [x] Trace valid block push state mutations.
- [x] Trace failure rollback paths.
- [x] Trace `popTransaction`/reorg paths.
- [x] Trace mempool add/remove/haveSpent paths.
- [x] Run available PQ nullifier/deposit-cell unit tests.

**Task 7 result:** No new nullifier/reorg state bug found. `pushTransaction` marks key images, then PQ nullifiers with rollback of prior key-image state if PQ marking fails. `markPqNullifiersSpent` rolls back prior PQ inserts on invalid length or duplicate. Rejected-block rollback pops previously pushed txs plus coinbase; `popTransaction` removes PQ outputs, erases PQ nullifiers, and clears PQ deposit-cell usage. Mempool add/remove/haveSpent paths track `PqKeyInput` nullifiers and `PqMultisigInput` cells. WSL tests passed: PQ duplicate/deposit group 23/23 and `PqSpendGate.*:PqOutputValidation.*` 8/8.

### Task 8: Cross-Architecture Determinism and KAT Matrix

**Files:**
- Inspect: `.github/workflows/check.yml`
- Inspect: `docs/design/quantum-resistance/cross-arch-kat-matrix.md`
- Inspect: `pqc/ccx-pqc/src/raptor.rs`
- Update if needed: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`

**Produces:** Verdict on whether the matrix covers all seed-derived PQ artifacts required by the brief.

- [x] Confirm which artifacts the current KAT actually pins.
- [x] Compare against audit brief requirement for ML-KEM, ML-DSA, Raptor, addresses, and serialized transactions.
- [x] Run local KAT where feasible.
- [x] Record coverage gaps.

**Task 8 result:** Existing CI and `cross-arch-kat-matrix.md` pin only the Raptor/Falcon keygen digest `SHAKE256_32(modq_encode(a0) || modq_encode(aots))`. WSL `cargo test --release keygen_kat -- --nocapture` passed and printed `8f245c82dc7390f3cb4d8955556a45d56af41c83a37fc0388b996b58f295745e`. Residual `M-new-4`: the brief's full matrix is still open for deterministic ML-KEM, ML-DSA, PQ address bytes, wallet PQ-section bytes, and serialized representative PQ transactions.

### Task 9: Standard-Scheme Usage and Scheme-ID Pinning

**Files:**
- Inspect: `pqc/ccx-pqc/src/lib.rs`
- Inspect: `src/CryptoNoteConfig.h`
- Inspect: `src/CryptoNoteCore/CryptoNoteSerialization.cpp`
- Inspect: `src/Wallet/PqAccount.cpp`
- Update if needed: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`

**Produces:** Verdict on FIPS/legacy scheme claims and on-chain agility.

- [x] Recheck ML-DSA/FIPS claim language against actual verifier.
- [x] Check KEM/ring/DSA IDs in addresses, outputs, and inputs.
- [x] Check whether any changed scheme uses old IDs.
- [x] Record finding or clean result.

**Task 9 result:** Address-level KEM and ring scheme pinning is implemented and WSL `PqAddress.*:PqAccountKeygen.*:PqWalletSection.*` passed 20/20; `PqDepositPrimitive.*` passed 2/2. Residual `M-new-5`: `PQ_DSA_SCHEME_ID` exists in config/account metadata, but `PqMultisigOutput`/`PqMultisigInput` do not serialize a DSA scheme ID, so deposit agility is not per-cell pinned. Residual `L-new-4`: deterministic keygen uses RustCrypto `ml-dsa`, but deposit sign/verify uses `pqcrypto_dilithium::dilithium3`; docs should qualify FIPS wording unless conformance/validation artifacts are provided. Existing `L-new-3` stale ring-scheme docs still applies.

### Task 10: Final Gate Matrix and Open-Item Triage

**Files:**
- Update: `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`
- Update: `docs/superpowers/plans/2026-06-21-codex-pq-followup-audit-checklist.md`

**Produces:** Short gate matrix: public testnet, private testnet, mainnet.

- [x] Summarize findings found in Tasks 1-9.
- [x] Separate code bugs from documentation/evidence gaps.
- [x] List exact next recommended fix/test for each open item.
- [x] Run final verification commands before claiming checklist status.

**Task 10 result:** Final report now separates code bugs from evidence/documentation gaps. New/remaining medium items: side-channel campaign evidence (`M-new-1`), Raptor proof reduction (`M-new-2`), B1 estimator artifacts (`M-new-3`), incomplete cross-arch PQ artifact KAT matrix (`M-new-4`), and non-serialized DSA scheme ID for deposit cells (`M-new-5`). Low items: 0x07 migration/versioning (`L-new-1`), Raptor verify fuzz coverage plus missing C++ parser fuzz (`L-new-2`), stale Raptor scheme-ID docs (`L-new-3`), and ML-DSA/FIPS wording qualification (`L-new-4`). Public testnet remains experimental/reset-required for incompatible transcript/message changes; mainnet remains no-go pending external proof, estimator, side-channel, KAT, and scheme-agility evidence.
