# Independent Verification of Claude/Opus Audit Findings

**Reviewer:** GLM (opencode, zai/glm-5.2)  
**Date:** 2026-06-21  
**Scope:** Independent cross-check of all findings from the Claude/Opus second audit pass, plus deep edge-case analysis for gaps both audits may have missed.

---

## 1. Claude findings — verification results

| Finding | Claim | My verification | Status |
|---------|-------|-----------------|--------|
| **F1** | Ring keys not bound into FS challenge → forgery | Independently found by us as HIGH-1. Fix verified: `programmed_key_forgery_is_rejected` passes, `cargo test` 15/15. | ✅ **Confirmed** |
| **F4** | PQ spends lack explicit `UPGRADE_HEIGHT_V10` gate | Verified: `transactionContainsPqSpend()` checks both `PqKeyInput` and `PqKeyOutput`. Block-level gate at `BlockchainStorage.cpp:456-463` is mainnet-only with proper testnet carve-out. Coinbase path also gated (`:290-302`). **This was a real gap we missed.** | ✅ **Confirmed** |
| **F5** | 0x07 AEAD nonce reuse on tx-key reuse | Verified: spec is thorough (`msg-aead-0x07-nonce-fix.md`). v2 implementation test `f5_aead_v2::v2_roundtrip_and_nonce_aad_safety` passes. The nonce-reuse path is real (deterministic from ECDH seed + index). | ✅ **Confirmed** |
| **F8** | `ringsig.rs` is structurally broken (key recovery) | Verified: the PoC test `secret_is_recoverable_from_public_key` passes. Mathematically sound — `t = A·s` with square A (K=L=6) and no LWE error → Gauss-Jordan recovers `s`. Not live (only `ccx_pqr_*` selftests use it). | ✅ **Confirmed** |
| **F12** | `raptor_abi::unpack` integer overflow | Verified: `checked_add` fix at `raptor_abi.rs:96` is correct. Fuzzed 13.4M runs crash-free. | ✅ **Confirmed** |
| **B1 §5.1** | Our "<1 bit" claim was wrong | **Confirmed** — the δ-shift of 0.001 maps to ~120 fewer BKZ blocks, not ≤2. However, the conclusion is still correct because the forgery SIS bound is vacuous (13.6× GH). Security comes from NTRU key-recovery (~2^141), unchanged by the ring. Claude's correction is accurate. | ✅ **Confirmed** |
| **Estimator** | Forgery R-SIS vacuous; NTRU ≈ 2^141 | Verified: the estimator results are consistent with the Gaussian heuristic analysis. `β=483, d=1019` for uSVP is reasonable for Falcon-512's NTRU lattice. | ✅ **Confirmed** |
| **Cross-arch KAT** | 6 platforms match | Independently re-ran linux-x86_64, linux-aarch64 (QEMU), linux-i686 — all produce `8f245c82…f295745e`. | ✅ **Confirmed** |
| **Fuzz** | 3 targets crash-free | Independently ran all 3: `unpack` 13.4M runs, `verify` 39.6M runs, `pubkey_canonical` 31.8M runs — **0 crashes**. | ✅ **Confirmed** |

**Verdict: All of Claude's findings are correct and accurately described.**

---

## 2. Edge-case analysis — areas neither audit previously covered

### 2.1 Reorg rollback of PQ state — ✅ SOUND

| Check | Result |
|-------|--------|
| `markPqNullifiersSpent` / pop symmetry | `popTransaction` (`BlockchainStorage.cpp:784-790`) erases each `PqKeyInput` nullifier. All three reorg entry points call `popBlock`. |
| `m_pqOutputs` LIFO | `popPqKeyOutput` (`:934-947`) enforces back-matches-txIndex before `pop_back`. |
| `m_pqMultisigOutputs` LIFO | `popPqMultisigOutput` (`:950-965`) mirrors the above. |

### 2.2 Nullifier set persistence — ✅ SOUND (by design)

`m_spentPqNullifiers` is in-memory only, rebuilt by full-chain replay on restart (`rebuildMdbxIndex`). Same pattern as classical `m_spent_keys`. Consensus-safe as long as no pruning is introduced (none exists). **Future pruning would require MDBX persistence.**

### 2.3 Mixed v4 transactions — ✅ SOUND (one minor gap)

Classical + PQ inputs/outputs in one tx are allowed and properly accounted. Money conservation sums all input types with overflow guards.

**Minor gap (Low):** `PqKeyOutput` is not version-gated on `tx.version >= 4` (unlike `PqKeyInput` and `PqMultisigOutput`). A pre-v4 tx could theoretically create a `PqKeyOutput`. **Mitigated** by the F4 block-level gate on mainnet. Testnet intentionally allows it (coinbase already creates PqKeyOutput from height 1).

### 2.4 Height-gate coverage — ✅ COMPLETE

| PQ type | Pre-V10 mainnet | Pre-V10 testnet | Post-V10 |
|---------|-----------------|-----------------|----------|
| PqKeyInput (spend) | ❌ rejected (F4) | ✅ allowed (PoC) | ✅ |
| PqKeyOutput (stealth) | ❌ rejected (F4) | ✅ allowed (PoC) | ✅ |
| PqMultisigInput (deposit) | ❌ rejected | ❌ rejected | ✅ |
| PqMultisigOutput (deposit) | ❌ rejected | ❌ rejected (until testnet V10=120) | ✅ |
| Classical deposit (term≠0) | ✅ allowed | ✅ allowed | ❌ frozen |

### 2.5 Coinbase maturity — ✅ SOUND

`check_pq_tx_input` calls `is_tx_spendtime_unlocked` for every ring member (`BlockchainPq.cpp:113-118`). Same for deposits (`:211-216`). Coinbase unlock window (10 blocks) enforced identically to classical outputs.

---

## 3. Deep-dive: attack vectors considered and ruled out

| Vector | Assessment |
|--------|------------|
| **Nullifier collision** (two outputs → same nullifier) | Negligible: `SHAKE256(aots)` over 896-byte Falcon keys, birthday bound ~2^-448. |
| **Ring member reuse** (same output as decoy in multiple inputs) | Anonymity-only concern; double-spend caught by nullifier set. |
| **Signature determinism across platforms** | Verification is deterministic (integer modular arithmetic, no FP). Signing can differ (randomized), but verification always agrees. |
| **Comp encoding malleability** | Varint length-prefix + canonical-length check in `unpack` prevents it. |
| **Resource exhaustion via PQ verification** | PQ ring-16 spend ≈ 50 KB; max 2 per 100 KB zone. Bounded. |
| **Transaction replay across chains** | Ring members differ across chains → signature won't verify. |
| **OTS nullifier swapping** | `aots` is bound to output via `a0 = a + H1(aots)`; verify recomputes mask from `sig.aots` and checks nullifier match (`BlockchainPq.cpp:170`). |
| **Interest manipulation via term field** | `input.term != output.term` check at `BlockchainPq.cpp:237`. |
| **`pushBlock` mid-loop rollback leak** | Pre-existing (not PQ-specific): if tx[i] fails, tx[0..i-1] mutations leak into indices. Low severity — next inclusion attempt fails double-spend check. |

---

## 4. Items requiring external auditor sign-off (unchanged)

These cannot be closed by engineering alone:

1. **Formal unforgeability reduction** — extractor sketch in `raptor-b1-derivation.md`; estimator confirms ~2^141 NTRU hardness.
2. **Anonymity statistical-distance bound** — sketch in `raptor-anonymity-proof.md`; empirical 0.2% match.
3. **dudect on Falcon sampler + ML-KEM decap** — harness exists (`ct_dudext`, `f6_mlkem_dudect`), needs ≥1M samples on a quiesced host.
4. **F5 mainnet rollout decision** — new tag vs in-place; migration plan.
5. **paramch_h ceremony** — beacon/MPC/frozen-spec selection.

---

## 5. Build/test verification (final)

| Suite | Result |
|-------|--------|
| `cargo test --release` | **15 passed, 2 ignored** (dudect), 0 failed |
| `unit_tests --gtest_filter=*Pq*` | **82 passed**, 0 failed |
| Full daemon + wallet build | **[100%]** green |
| Fuzz `unpack` | **13.4M runs**, 0 crashes |
| Fuzz `verify` | **39.6M runs**, 0 crashes |
| Fuzz `pubkey_canonical` | **31.8M runs**, 0 crashes |
| Cross-arch KAT (x86_64 + aarch64 + i686) | **3/3 match** pinned digest |

---

## 6. Conclusion

All of Claude's findings (F1, F4, F5, F8, F12, B1 correction, estimator, cross-arch, fuzz) are **independently confirmed correct**. The edge-case analysis found **no new critical or high issues** — the PQ integration faithfully twins the classical CryptoNote accounting in every direction (push, pop, reorg, rebuild, validate, height-gate).

One **Low** item: gate `PqKeyOutput` on `tx.version >= 4` for symmetry (mitigated by F4 block-level gate). One **pre-existing Low**: `pushBlock` mid-loop rollback leak (not PQ-specific).

**Recommendation:** the codebase is ready for the external cryptographic auditor. The engineering surface is closed; the remaining gates are formal proofs, dudect timing confirmation, and rollout decisions.
