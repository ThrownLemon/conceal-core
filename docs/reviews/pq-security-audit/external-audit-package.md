# Conceal PQ — External Cryptographic Audit Package (Phase 7)

> **Canonical entry point:** [`../pqc-mdbx-merge/HANDOFF.md`](../pqc-mdbx-merge/HANDOFF.md) consolidates
> BOTH audits (GLM + Claude) + the current go/no-go — start there. This document is the **Claude/Opus
> side** of the cross-audit (detailed findings register F1–F14, verdicts, estimator/CT/determinism
> evidence); it and `HANDOFF.md` are kept consistent.

**Branch:** `pqc/mdbx-merge-poc` (audited at `411c848f`; fixes applied on top, uncommitted working tree).
**Status:** UNAUDITED testnet-only PoC. This package is the hand-off for an external cryptographic auditor and the evidence base for the mainnet go/no-go gate. `UPGRADE_HEIGHT_V10` stays a far-future sentinel until this gate passes.

This is an **index + evidence summary**. It assembles two independent internal audits, the in-flight remediation, dynamic verification run on the WSL host, and the specs for the items deliberately left open. Detailed artifacts are linked.

---

## 1. Audit corpus & independent convergence

| Audit | Reviewer | File |
|-------|----------|------|
| A | GLM (z.ai) | `docs/reviews/pqc-mdbx-merge/glm-security-audit.md` |
| B | Claude / Opus | `docs/reviews/pq-security-audit/claude-opus.md` |

The two were produced independently and **converged on the top finding** (Raptor ring-not-bound forgery — GLM HIGH-1 ≡ Claude F1), with the **same root cause and same fix**. Cross-reference matrix and divergences are in §1 of `claude-opus.md` (addendum §0.5) and summarized in the findings register below. Net: GLM covered the mempool/serialization consensus surface in more depth; Claude uniquely found the PQ-spend height-gate gap (F4), the 0x07 AEAD nonce reuse (F5), the broken selftest-only `ringsig.rs` (F8), and a quantitative error in the B1 derivation (since corrected).

---

## 2. Findings register (consolidated, with status)

| ID (B/A) | Title | Severity | Status |
|----------|-------|----------|--------|
| F1 / HIGH-1 | Ring keys not bound into the Fiat-Shamir challenge → standalone forgery | HIGH (live) / CRITICAL (primitive) | **FIXED** (ring bound into `hash_transcript_to_b`; forgery test inverted; verified — forgery rejected, 13/13 `cargo test`) |
| F2 / MED-2 | Unforgeability unproven; B1 not re-derived; concrete bits unknown | mainnet-blocker | **CLOSED for the PoC gate:** B1 derived (`raptor-b1-derivation.md`), estimator run (§4), unforgeability extractor sketch documented. Formal reduction = external-audit deliverable. |
| F3 | Keygen-determinism KAT + det-keygen selftest dormant (dead code) | HIGH | **FIXED** (Daemon.cpp startup PQ-selftest gate, aborts on KAT drift). Follow-up: wire the same gate into the wallet binary. |
| F4 | PQ **spends** lack an explicit `UPGRADE_HEIGHT_V10` gate | HIGH | **FIXED** (mainnet-only spend gate, `transactionContainsPqSpend`, per-tx + coinbase; build-verified). Add a mainnet-params unit test. |
| F5 | 0x07 authenticated-message AEAD nonce reuse on tx-key reuse | HIGH (memo layer) | **SPEC'd, not applied** — `msg-aead-0x07-nonce-fix.md` (wire-format change, height-gated rollout decision). 0x06 PQ path is safe. |
| F6 / INFO-2 | Signing Gaussian sampler + ML-KEM FO-decap CT unverified | MEDIUM (wallet) | **OPEN** — ctgrind maps the regions (§5); **dudect** is the missing confirmation (§5.2 procedure). |
| F7 / LOW-3 | `ringSig` canonicality FFI-delegated; parse-time length bound loose | MEDIUM / LOW | **Mitigated** (double-bounded by `ccx_pq_verify` + `CRYPTONOTE_MAX_TX_SIZE`); tighter parse-time bound = low-priority framework hardening. |
| F8 | Selftest-only `ringsig.rs` (K=L=6, `t=A·s`, no error) structurally broken | INFO (dead) / MEDIUM (false assurance) | **FIXED + PROVEN** (DANGER header; key-recovery PoC test `secret_is_recoverable_from_public_key` PASSES — recovers `s` from the public key). Not live on either branch. Recommend feature-gating/deleting. |
| F9 / LOW-1 | `paramch_h` NUMS ceremony undocumented | LOW / MED (mainnet) | **Doc'd** (`paramch-h-spec.md`). Pick a beacon/MPC/frozen-spec ceremony before mainnet. |
| F10 | `NETWORK_TAG="ccx-testnet"`; deprecated RustCrypto pins | LOW | Pre-mainnet checklist item (finalize tag; the det-keygen selftest now runs at startup — F3). |
| F11 | Spend artifacts carry no scheme/version tag; `dsaSchemeId` not on-chain | INFO / LOW | Documented agility gap; per-output scheme byte recommended for true agility. |
| **F12** (NEW, fuzz-found) | `raptor_abi::unpack` integer-overflow (`*pos + len`, untrusted varint) | MEDIUM | **FIXED** (`checked_add`; re-fuzzed 19.3M runs crash-free). Contained on the live path by `ffi_guard` `catch_unwind` (if `panic=unwind`); silent wrap in release. Found by the (now-fixed) Phase-5 fuzz harness. |
| **F13** (NEW, GLM cross-verify) | `PqKeyOutput` not tx-version-gated (`>= 4`) unlike `PqKeyInput`/`PqMultisigOutput` — a non-coinbase pre-v4 tx could carry one | LOW | **FIXED** (`check_outs_valid` v4 gate with a coinbase exemption — the v1 testnet coinbase legitimately carries the PQ stealth output; real spends always have a v4-gated `PqKeyInput`). Tested (`PqSpendGate.PqKeyOutputRejectedInNonCoinbasePreV4Tx`); already mitigated on mainnet by the F4 block gate (defense-in-depth). |
| **F14** (NEW, GLM cross-verify; pre-existing/non-PQ) | `Blockchain::pushBlock` mid-loop rollback leak: on `tx[i]` validation failure only the coinbase was popped, leaking `tx[0..i-1]`'s key-image/nullifier/output mutations into in-memory indices (rejected block → false double-spend on retry until resync) | LOW | **FIXED** (targeted reverse rollback of `tx[0..i-1]` + coinbase; not `popTransactions()`, which would erase the failed tx's key image). UnitTests 100% + CoreTests pass. |
| HIGH-2 (A) | `m_spent_pq_nullifiers` not persisted in mempool serialize | HIGH | **FIXED** (`KV_MEMBER` added). |
| MED-1 (A) | `BlockTemplate` lacked `PqKeyInput` nullifier tracking | MED | **FIXED** (`m_pqNullifiers` template-set). |
| — | Per-spend signing randomness = raw concat (lattice nonce-reuse risk) | (Codex C-1) | **FIXED** (HKDF-like extract-then-expand over SHAKE256, lib.rs). |

---

## 3. Cryptographic soundness package (Raptor ring signature)

- **Construction & faithfulness:** linkable Raptor (eprint 2018/857 §6.5) over PQClean Falcon-512, `n=512`, `q=12289`. Source: `pqc/ccx-pqc/src/raptor.rs`. Nullifier = `SHAKE256(domain ‖ modq(aots))`.
- **Unforgeability:** post-fix, the FS challenge binds `(msg, ring, commitments)` — the rewinding extractor (`raptor-b1-derivation.md §3`) yields an inhomogeneous Ring-SIS witness; reduction relies on Falcon preimage / NTRU hardness. A **formal reduction remains an external-audit deliverable** (the in-tree forgery test now confirms *rejection*, not soundness).
- **Anonymity:** `raptor-anonymity-proof.md` — non-signer `(r0,r1)` drawn from Falcon's own preimage sampler under a throwaway key; marginally identical to the signer's (provably `D_{Z^{2n},σ}` over a uniform target, key-independent; the `pair_is_valid` filter is key-independent too). Empirically σ-matched within 0.2%. **Formal statistical/Rényi-distance bound at scale = external-audit deliverable.**
- **Linkability / nullifier soundness:** SOUND modulo Falcon-trapdoor unforgeability (same-output ⇒ same `aots` ⇒ same nullifier; distinct outputs ⇒ distinct via SHAKE; non-canonical `aots` rejected).
- **B1 norm bound:** re-derived for the ring setting = `4·β²_Falcon` (extractor slack); verify enforces the tight single-Falcon `β²` for acceptance (no false rejections). `raptor-b1-derivation.md` (with the §5.1 correction + §5.3 estimator run).

---

## 4. Concrete security — lattice-estimator run (Phase 2.2, COMPLETED)

SageMath 10.9 + Albrecht et al. `lattice-estimator` (MATZOV cost model), WSL x86_64:

| Instance | Estimator output | Meaning |
|----------|------------------|---------|
| Forgery R-SIS, `‖v‖₂ ≤ 2·β_Falcon = 11668`, dim 1024, q=12289 | **"SIS trivially easy"** (refused; bound ≈ 13.6× Gaussian heuristic) | The homogeneous forgery bound is **vacuous** — the ring's 2× relaxation is irrelevant to concrete security. |
| Falcon-512 NTRU key-recovery (LWE-modeled, σ=1.17·√(q/2n)=4.05) | **uSVP: rop ≈ 2^141, β=483, d=1019**; dual-hybrid ≈ 2^146 | The **real** unforgeability hardness ≈ **2^141 classical** ⇒ **NIST Category 1 (≥128-bit)** with margin, unchanged by the ring. |

**Verdict:** unforgeability hardness = Falcon-512's NTRU/preimage instance (~2^141 classical). The ring construction does not weaken it.

---

## 5. Constant-time / side-channel posture

Threat model: daemon verify-only (no SK ops on consensus path); wallet vs local attacker; ephemeral per-spend Falcon keys.

### 5.1 ctgrind/TIMECOP map (run under valgrind, this audit)
- **0 secret-dependent memory accesses** on the Raptor path (no cache/table-lookup leaks).
- Flagged control-flow-on-secret regions, with disposition:
  - **`keygen.c`** (NTRU `(f,g)` rejection) — **blessed** under ephemeral, use-once keys.
  - **`sign.c` Gaussian/BerExp sampler** — **OPEN**, secret path every spend; ephemeral argument does **not** cover it. **Highest-priority CT item with ML-KEM decap.**
  - **`codec.c`, `raptor_falcon.c:177 hash_to_rq`, `raptor.rs hash_transcript_to_b`** — public-data-derived → **benign** (CI filter already excludes `hash_to_rq`).
- The F1 ring-binding fix is **CT-clean** (no secret-dependent memory access introduced).
- The CI tripwire (`check.yml` "ctgrind") guards **only** the `raptor_falcon.c` glue — it does **not** watch keygen, the sampler, ML-KEM, or the encoders.

### 5.2 dudect harness — SPEC (the missing confirmation for F6)

ctgrind proves *no secret-dependent memory access* but **cannot bless the sampler's timing** (isochronous code still has data-dependent values, not time). Add a statistical-timing harness:

```
# pqc/ccx-pqc/Cargo.toml
[dev-dependencies]
dudect-bencher = "0.6"
```
Harness design:
- Two input classes: **fixed** (one pinned signer seed) vs **random** (fresh seeds each iteration).
- Per iteration, time the **secret-key operation in isolation**: `FalconKey::sign_target(seed, target)` (the sampler), not the whole `sign` (whose rejection-loop iteration count is a known, documented, accepted lattice-signature variability — measure it separately).
- dudect crops timing percentiles and runs **Welch's t-test**; `|t| > 10` over ≥10⁶ samples ⇒ a timing dependence to investigate.
- Calibrate with a known-CT baseline (constant-time `memcmp`) and a known-variable baseline (data-dependent early return) on the same machine.
- Run pinned to one quiesced core (`taskset -c N`), governor=performance, repeat ×3.
- **ML-KEM FO-decap:** same methodology on `ccx_pq_kem_scan`/decap (long-term KEM key, runs every wallet-sync scan — the one CT-sensitive ML-KEM region that repeats).

Expected: PQClean's isochronous sampler should show `|t| < 10` (no timing dependence); a positive result is a finding. **This is an external-audit deliverable, not yet run.**

---

## 6. Determinism / consensus-split posture

- **x86_64 build-level determinism: VERIFIED.** Keygen KAT digest `8f245c82…745e` reproduces across `-O0/-O3/±fast-math/±ffp-contract/-march` and on the WSL build this audit (13/13 `cargo test`). Vendored Falcon is integer-emulated FP (no native `double`).
- **Cross-arch matrix (Phase 6) — PROCEDURE (toolchain verified ready on WSL: `aarch64-unknown-linux-gnu` target + `qemu-aarch64-static` present):**
  ```
  rustup target add aarch64-unknown-linux-gnu          # installed
  sudo apt-get install -y gcc-aarch64-linux-gnu         # cross-linker for the vendored Falcon C
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
  export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=qemu-aarch64-static
  cargo test --release --target aarch64-unknown-linux-gnu keygen_kat_matches_reference -- --nocapture
  # Compare printed KEYGEN_KAT_DIGEST to the pinned 8f245c82…745e.
  ```
  Also recommended: 32-bit `i686` and a big-endian target (`s390x` via qemu) to stress the FP-emulation byte order. **A digest match across arches confirms determinism; any mismatch is the Falcon FP-keygen cross-platform hazard → a mainnet blocker** (the real fix being an audited integer/emulated-FP keygen, already the vendored "clean" path on x86_64).
- Consensus integration (double-spend completeness, height-gate off-by-one, overflow, freeze, serialization canonicality) — verified clean in both audits; the one gap (F4) is fixed.

---

## 7. Fixes applied this cycle + build verification

All applied to the working tree and **build-verified on WSL** (`cmake -DBUILD_TESTS=ON && make -j16` → `BUILD_EXIT=0`, full daemon + UnitTests; crate `cargo test` 14/14):
- **F4** mainnet-only PQ-spend height gate (`BlockchainStorage.cpp`).
- **F8** DANGER header + passing key-recovery PoC (`ringsig.rs`).
- **B1 §5.1** correction + **§5.3 estimator results** (`raptor-b1-derivation.md`).
- (GLM track, verified) F1 ring-binding, F3 startup selftest gate, per-spend HKDF, mempool nullifier persist/track.

---

## 8. Go / no-go gates

**Public testnet — GO** (F3, F4 fixed; chain resettable).

**Mainnet — NO-GO until:**
1. External cryptographer signs off the **formal unforgeability reduction** and the **anonymity statistical-distance bound** (F2 sketches + estimator are inputs, not a substitute).
2. **F5** implemented (0x07 AEAD v2, height-gated) — `msg-aead-0x07-nonce-fix.md`.
3. **F6** closed: dudect on the sampler + ML-KEM decap (§5.2); masking decision recorded.
4. **Phase 6** cross-arch KAT matrix green (aarch64 + 32-bit; §6).
5. `paramch_h` ceremony executed (F9); per-output scheme tag decision (F11); wallet startup selftest gate (F3 follow-up); mainnet-params unit test for the F4 gate.
6. Fuzzing (Phase 5 targets in `pqc/ccx-pqc/fuzz/`) run to a crash-free corpus on the FFI boundary.

---

## 9. Manifest for the external auditor

| Artifact | Path |
|----------|------|
| This package | `docs/reviews/pq-security-audit/external-audit-package.md` |
| Audit B (Claude) + dynamic verification | `docs/reviews/pq-security-audit/claude-opus.md` |
| Audit A (GLM) | `docs/reviews/pqc-mdbx-merge/glm-security-audit.md` |
| B1 derivation + estimator | `docs/design/quantum-resistance/raptor-b1-derivation.md` |
| Anonymity proof sketch | `docs/design/quantum-resistance/raptor-anonymity-proof.md` |
| paramch_h ceremony spec | `docs/design/quantum-resistance/paramch-h-spec.md` |
| F5 AEAD fix spec | `docs/design/quantum-resistance/msg-aead-0x07-nonce-fix.md` |
| CT status + checklist | `docs/design/quantum-resistance/constant-time-status.md` |
| Remediation plan | `docs/design/quantum-resistance/production-readiness-prompt.md` |
| Ring sig (live) | `pqc/ccx-pqc/src/raptor.rs` |
| Consensus PQ checks | `src/Blockchain/BlockchainPq.cpp`, `src/Blockchain/BlockchainStorage.cpp` |
| Fuzz targets | `pqc/ccx-pqc/fuzz/fuzz_targets/` |
| Source diff for review | `git diff development...pqc/mdbx-merge-poc` |
