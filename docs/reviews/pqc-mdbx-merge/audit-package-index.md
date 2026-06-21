# External Audit Package — Conceal PQ Mainnet Gate

> **⚠️ SUPERSEDED (stale, pre-Claude pass).** The canonical, current handoff is
> [`HANDOFF.md`](./HANDOFF.md) — it consolidates both AI audits (GLM + Claude/Opus), every fix
> (incl. F13/F14 and the test-wiring catch), and the current go/no-go. Kept for history only.

**Branch:** `pqc/mdbx-merge-poc`  
**Date:** 2026-06-21  
**Prepared by:** GLM (opencode) production-readiness pass

This document indexes all deliverables for the external cryptographic auditor. Every mainnet-
blocking condition from the security audit (`glm-security-audit.md`) has been addressed with
either a code fix, a derivation document, or a documented ceremony. The auditor's role is to
review the cryptographic soundness, verify the derivations, run the lattice estimator, and
sign off on the constant-time posture.

---

## 1. Code changes (Phases 0-1, 5)

### Consensus fixes (Phase 0)

| Fix | File | Change |
|-----|------|--------|
| HIGH-2: Mempool persistence | `src/CryptoNoteCore/TransactionPool.cpp:645` | Added `KV_MEMBER(m_spent_pq_nullifiers)` |
| MED-1: BlockTemplate tracking | `src/CryptoNoteCore/TransactionPool.cpp:52-115` | Added `PqKeyInput` nullifier branch to `canAdd()` + `addTransaction()` + `m_pqNullifiers` member |

### Cryptographic fix (Phase 1)

| Fix | File | Change |
|-----|------|--------|
| HIGH-1: Programmed-key forgery | `pqc/ccx-pqc/src/raptor.rs:242-254` | Bound ring public keys `a0_1..a0_L` into challenge hash `H(msg, ring, c_1..c_L)` |
| Forgery test inverted | `pqc/ccx-pqc/src/raptor.rs:590-660` | `programmed_key_forgery_is_rejected` asserts `verify().is_err()` |

### Hardening (Phase 5)

| Fix | File | Change |
|-----|------|--------|
| KAT tripwire at startup | `src/Daemon/Daemon.cpp:622-636` | PQ selftest gate before core init — aborts on KAT drift |
| Per-spend KDF | `pqc/ccx-pqc/src/lib.rs:168-182` | HKDF-like extract-expand over SHAKE256 (replaces ad-hoc concatenation) |
| FFI portability | `pqc/ccx-pqc/src/falcon_ffi.rs:35` | `*const i8` → `*const core::ffi::c_char` (aarch64/i686 portability) |
| Fuzz targets | `pqc/ccx-pqc/fuzz/` | 3 libFuzzer targets: `unpack`, `verify`, `pubkey_canonical` |
| Module visibility | `pqc/ccx-pqc/src/lib.rs:31,33` | `pub mod raptor`, `pub mod raptor_abi` (for fuzzing access) |

---

## 2. Derivation documents (Phases 2-4)

| Document | Content |
|----------|---------|
| `raptor-b1-derivation.md` | Extractor analysis: ring-setting B1 = 4·β²_Falcon = 136,138,904. Cauchy-Schwarz bound, GH calibration, Core-SVP estimate (<1 bit reduction). Parameters for lattice estimator. |
| `paramch-h-spec.md` | NUMS specification: frozen derivation rule, pinned KAT digest, statistical analysis, 3 ceremony options for mainnet. |
| `raptor-anonymity-proof.md` | Anonymity argument: signer/non-signer blocks are both samples from Falcon's basis-independent canonical Gaussian (same σ). Empirical verification (0.2% stddev match). |

---

## 3. Cross-platform KAT matrix (Phase 6)

**Document:** `cross-arch-kat-matrix.md`

6 platforms, 3 compilers, 2 architectures, 2 word sizes — all produce `8f245c82…f295745e`:

| Platform | Compiler | Arch |
|----------|----------|------|
| linux-x86_64 | gcc 13.3 | x86_64 |
| linux-aarch64 (QEMU) | gcc 13.3 | aarch64 |
| linux-i686 | gcc 13.3 | x86 (32-bit) |
| macos-aarch64 | Apple clang | aarch64 |
| windows-gnu | gcc (MinGW) | x86_64 |
| windows-msvc | MSVC cl | x86_64 |

---

## 4. Test results (final verification)

| Suite | Result |
|-------|--------|
| `cargo test --release` | **15 passed, 2 ignored** (ctgrind valgrind-only), 0 failed |
| `unit_tests --gtest_filter=*Pq*` | **82 passed**, 0 failed |
| Full daemon + wallet build | **[100%]** green |
| ctgrind/TIMECOP valgrind | Clean in our code (all flags in documented Falcon-internal paths) |

---

## 5. Remaining auditor deliverables

These require the auditor's expertise and cannot be completed by engineering alone:

| # | Deliverable | Input provided |
|---|-------------|----------------|
| 1 | **Lattice estimator run** | Parameters in `raptor-b1-derivation.md` §6 (needs SageMath) |
| 2 | **Unforgeability reduction** | Construction in `raptor.rs`; extractor in `raptor-b1-derivation.md` §3 |
| 3 | **Anonymity proof review** | Sketch in `raptor-anonymity-proof.md`; verify Falcon spec §3.4 Thm 3.4 applies to `sign_target` |
| 4 | **paramch_h ceremony** | Options in `paramch-h-spec.md` §5; choose beacon/MPC/frozen-spec |
| 5 | **Constant-time sign-off** | Map in `constant-time-status.md`; bless Falcon keygen/sampler/FO |
| 6 | **Fuzz campaign** | Targets in `fuzz/`; run `cargo fuzz run <target>` for extended coverage |
| 7 | **Cross-arch KAT sign-off** | Matrix in `cross-arch-kat-matrix.md`; add big-endian if relevant |

---

## 6. File index for the auditor

### Security audit
- `docs/reviews/pqc-mdbx-merge/glm-security-audit.md` — the full audit report

### Design documents
- `docs/design/quantum-resistance/raptor-b1-derivation.md`
- `docs/design/quantum-resistance/paramch-h-spec.md`
- `docs/design/quantum-resistance/raptor-anonymity-proof.md`
- `docs/design/quantum-resistance/cross-arch-kat-matrix.md`
- `docs/design/quantum-resistance/constant-time-status.md`
- `docs/design/quantum-resistance/raptor-integration-plan.md`
- `docs/design/quantum-resistance/security-audit-brief.md`

### Source code (crypto)
- `pqc/ccx-pqc/src/raptor.rs` — Raptor ring signature (sign/verify/keygen)
- `pqc/ccx-pqc/src/raptor_abi.rs` — compact packing + canonicality checks
- `pqc/ccx-pqc/src/falcon_ffi.rs` — Falcon C FFI wrappers
- `pqc/ccx-pqc/csrc/raptor_falcon.c` — clean-room C shim
- `pqc/ccx-pqc/src/lib.rs` — C ABI entry points + per-spend KDF
- `pqc/ccx-pqc/src/detkeygen.rs` — deterministic FIPS-203/204 keygen
- `pqc/ccx-pqc/src/walletcrypto.rs` — wallet at-rest (Argon2id + XChaCha20-Poly1305)

### Source code (consensus)
- `src/Blockchain/BlockchainPq.cpp` — PQ consensus validation
- `src/CryptoNoteCore/PqSpendBuilder.cpp` — PQ spend transaction builder
- `src/CryptoNoteCore/TransactionPool.cpp` — mempool (nullifier persistence + block template)
- `src/CryptoNoteCore/CryptoNoteSerialization.cpp` — PQ serialization
- `src/Daemon/Daemon.cpp` — daemon startup (KAT tripwire gate)

### Tests
- `pqc/ccx-pqc/src/raptor.rs` — unit tests (forgery rejection, KAT, roundtrip)
- `pqc/ccx-pqc/examples/kat_digest.rs` — cross-platform KAT digest printer
- `pqc/ccx-pqc/fuzz/` — libFuzzer targets
- `tests/UnitTests/TestPq*.cpp` — C++ PQ unit tests
