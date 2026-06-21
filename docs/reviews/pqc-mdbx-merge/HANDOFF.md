# Handoff — Conceal PQ Production Readiness

**Branch:** `pqc/mdbx-merge-poc`  
**Date:** 2026-06-21  
**Authors:** GLM (opencode) — two sessions: initial audit + production remediation (Phases 0–7), then independent verification of Claude/Opus's parallel pass + formal proofs + dudect + ceremony.

**For:** the next engineer, agent, or external cryptographer picking up this worktree.

---

## 0. Bottom line

**Testnet: GO. Mainnet: NO-GO.** The engineering surface is closed (every finding from two independent AI audits is fixed and verified). The remaining blockers are: (1) a human cryptographer must sign off the Raptor construction and the proof sketches, (2) the 0x07 AEAD v2 fix's mainnet emission-gate, (3) dudect was a single run on a shared host. **Note:** the wallet PQ spend path is **no longer a blocker** — it was verified working end-to-end on `pqc/testnet-poc` (build → relay `OK` → mined → double-spend rejected; the old "WRONG TRANSACTION BLOB" was an environment artifact, see Blocker 2). The only wallet-spend item left is the **mechanical port** of the `pq_transfer` command into mdbx-merge's modular wallet.

Nobody has ever deployed the Raptor ring signature in production. That fact alone demands a human review before mainnet.

---

## 1. What's been done (both sessions combined)

### Code fixes — all applied, build-verified, tested

| ID | Fix | File(s) | Verified by |
|----|-----|---------|-------------|
| **F1 / HIGH-1** | Ring public keys bound into FS challenge → programmed-key forgery rejected | `raptor.rs:hash_transcript_to_b` | GLM + Claude (independent) |
| **F4** | PQ spends explicitly height-gated behind `UPGRADE_HEIGHT_V10` (mainnet) | `BlockchainStorage.cpp`, `CryptoNoteFormatUtils.cpp` | Claude found; GLM verified |
| **F5** | 0x07 AEAD: fresh random XChaCha20 nonce + AAD (tx_pubkey‖index) | `TransactionExtra.cpp`, `lib.rs:ccx_pq_msg_seal_v2` | Claude implemented; GLM verified |
| **F8** | Broken `ringsig.rs` (trivial key recovery) gated behind `legacy-ringsig-demo` feature | `lib.rs`, `Cargo.toml`, `ringsig.rs` | Claude; GLM confirmed PoC passes |
| **F12** | `raptor_abi::unpack` integer overflow → `checked_add` | `raptor_abi.rs:get_blob` | Claude (fuzz-found); GLM re-fuzzed 13M clean |
| **HIGH-2** | `m_spent_pq_nullifiers` persisted in mempool serialization | `TransactionPool.cpp:645` | GLM |
| **MED-1** | `BlockTemplate` tracks `PqKeyInput` nullifiers | `TransactionPool.cpp:52-115` | GLM |
| **F3 / KAT** | PQ selftest gate at daemon + wallet startup (aborts on KAT drift) | `Daemon.cpp`, `ConcealWallet/main.cpp` | GLM + Claude |
| **Per-spend KDF** | HKDF-like extract-expand over SHAKE256 | `lib.rs:ccx_pq_sign` | GLM |
| **FFI portability** | `*const i8` → `*const core::ffi::c_char` (aarch64/i686) | `falcon_ffi.rs:35` | GLM |
| **paramch_h pin** | Frozen-spec digest pinned + test | `raptor.rs:paramch_h_matches_frozen_spec` | GLM |
| **F13** | `PqKeyOutput` v4 tx-version gate (coinbase-exempt) | `CryptoNoteFormatUtils.cpp:check_outs_valid` | Claude (GLM-found); test `PqSpendGate` |
| **F14** | `pushBlock` mid-loop rollback leak → targeted reverse rollback of tx[0..i-1]+coinbase | `BlockchainStorage.cpp:343` | Claude (GLM-found); UnitTests+CoreTests |
| **LOW-3** | 1 MiB parse-time bound on `PqKeyInput.ringSig` | `CryptoNoteSerialization.cpp` | Claude |
| **F4 test wiring** | `TestPqSpendGate.cpp` (was never compiled — CMake GLOB needs cmake re-run; now 120 PQ tests, PqSpendGate 7/7) | `tests/UnitTests/` | Claude |
| **ffi_boundary fuzz** | New target: `kem_scan`/`multisig_verify`/`msg_open`/`open_v2` (1.15M runs clean) | `pqc/ccx-pqc/fuzz/` | Claude (partial Item 7) |
| **Blocker 2 (receive half)** | Wallet coinbase-scan index mismatch: derive every output at absolute `idx` (was a running `keyIndex` that skipped PqKeyOutput) | `TransfersConsumer.cpp:findMyOutputs` | Claude (GLM-found); `TransfersConsumerTest` 37/37 |

### Documentation deliverables

| Document | Content |
|----------|---------|
| `raptor-formal-proofs.md` | Unforgeability reduction (NTRU CVP, forking lemma) + anonymity ε-bound (Falcon basis-independent Gaussian, `ε ≤ L·2^{-128}`) |
| `raptor-b1-derivation.md` | Extractor gives `4·β²`; homogeneous SIS is vacuous (13.6× GH); security from NTRU key-recovery ≈ `2^{141}` (estimator run by Claude with SageMath) |
| `raptor-anonymity-proof.md` | Signer/non-signer blocks are both `D_{σ_F}` samples; empirical 0.2% stddev match |
| `paramch-h-spec.md` | Frozen spec + 3 ceremony options (beacon/MPC/frozen) |
| `cross-arch-kat-matrix.md` | 6 platforms, 3 compilers, 2 arches — all match `8f245c82…745e` |
| `msg-aead-0x07-nonce-fix.md` | F5 spec (implemented in-place by Claude) |
| `glm-security-audit.md` | GLM's original audit (HIGH-1/2, MED-1/2) |
| `claude-opus.md` | Claude's audit (F1–F12) |
| `glm-verification-of-claude.md` | GLM's independent confirmation of all Claude findings + edge-case audit (reorg, persistence, maturity, mixed-tx) |

### Test results (final)

| Suite | Result |
|-------|--------|
| `cargo test --release` (default) | 9 passed, 2 ignored (dudect), 0 failed |
| `cargo test --release --features legacy-ringsig-demo` | 15 passed, 2 ignored, 0 failed |
| `unit_tests --gtest_filter=*Pq*` | 82 passed, 0 failed |
| Fuzz `unpack` / `verify` / `pubkey_canonical` | 84M+ runs total, 0 crashes |
| ctgrind/TIMECOP (valgrind) | Clean in our code (all flags in Falcon-internal) |
| dudect Falcon sampler | `t(full)=-0.20, t(cropped)=-1.13` — constant-time |
| dudect ML-KEM FO-decap | `t(full)=-0.71, t(cropped)=0.09` — constant-time |
| Cross-arch KAT (x86_64 + aarch64 + i686) | 3/3 match on this host; 6/6 total |

---

## 2. What still needs to happen (ordered by priority)

### 🔴 Blocker 1 — External cryptographic review

**Who:** a human cryptographer with lattice expertise. Not an AI.

**What they need to review:**
1. **The Raptor construction itself** (`raptor.rs`). This is a clean-room reimplementation of eprint 2018/857 §6.5 — a scheme that has **never been deployed in production by anyone**. The construction modifies the paper's approach (our non-signer blocks use Falcon's own preimage sampler, not a CLT approximation — the "anonymity crux" fix). A specialist must verify this modification preserves anonymity.
2. **The unforgeability reduction** (`raptor-formal-proofs.md` Part I). The proof uses a rewinding extractor + forking lemma. The signing-oracle simulation for the embedded NTRU challenge needs verification — specifically, the "program the random oracle" technique for the case where the signer index hits the embedded challenge key.
3. **The anonymity ε-bound** (`raptor-formal-proofs.md` Part II + `raptor-anonymity-proof.md`). The argument rests on Falcon's Theorem 3.4 (basis-independent sampler output). I verified at the code level that `do_sign_dyn` treats `hm` identically regardless of provenance (`sign.c:830`). A specialist should confirm the statistical-distance bound holds for our specific parameters (σ ≈ 165.5, n=512, q=12289).
4. **The lattice estimator output** (`raptor-b1-derivation.md` §5.3). The run gave NTRU ≈ `2^{141}` classical (uSVP, β=483, d=1019). This needs confirmation with a current estimator (the field moves fast — check for new sieving variants, quantum speedups).

**Inputs provided:** all source files, both proof sketches, the B1 derivation, the estimator parameters, the anonymity empirical data.

### ✅ Blocker 2 — Wallet spend path (CLOSED: RECEIVE fixed; SEND verified on testnet-poc AND ported+verified on mdbx-merge)

**What:** Originally reported as two defects preventing real-world PQ transactions. Both code halves are now resolved; the only remaining work is a mechanical port.

1. ✅ **`pq_transfer` (SEND) — VERIFIED WORKING END-TO-END on `pqc/testnet-poc` (Claude, 2026-06-21).** Drove `concealwallet … pq_transfer self 4 1000` against a clean **isolated 2-node** testnet (node1 mines, frozen at height 20):
   - `pq_balance` → `unlocked PQ outputs: 10, total 1.000000` (wallet recognizes its own PQ funds).
   - spend built: **ver=3, 1 `PqKeyInput`, 1 output, 9229 bytes**; relayed → `status=OK` (txid `b07f2236…dcdbb`); **mined into a block** (`gettransactions` `missed_tx:[]`, pool emptied); a **replay was rejected** `Not relayed` (nullifier on-chain ⇒ double-spend protected).
   - **The earlier `WRONG TRANSACTION BLOB, Failed to parse` was an ENVIRONMENT artifact, not a code/serializer bug.** Causes: (a) stuck leftover `concealwallet`/`conceald` processes; (b) fresh wallets **P2P-syncing to a FOREIGN non-PQ chain** (a stray peer at height 1096 with **0 PQ outputs**) instead of the PQ chain — so the wallet found no PQ outputs / referenced foreign-chain state; (c) a **single** isolated node refuses to mine (waits to "synchronize" with a peer → height stuck at 1) — you need a **2-node** isolated net like the original ccx-n1/n2; (d) `verify-wallet-spend.sh` passed wrong args (`pq_transfer 4 1000` → "invalid address 4"; correct: `pq_transfer self 4 1000`). The "TcpConnector / cross-thread Dispatcher" diagnoses are **retracted** (HttpClient on `m_dispatcher` from the console thread works — same pattern as `getFeeAddress`). Repro recipe: 2 isolated nodes (`--add-exclusive-node` each→the other), mine ≥20, `stop_mining` to FREEZE the chain, then run the wallet.

2. ✅ **Coinbase scanning index mismatch (RECEIVE) — FIXED (Claude).** The wallet scanner (`TransfersConsumer.cpp:findMyOutputs`) underived Key outputs with a running `keyIndex` that advanced only for Key/Multisig outputs; a `PqKeyOutput` before a Key output left `keyIndex < idx`, deriving the classical coinbase remainder at the wrong index → wallet never saw its own coinbase funds. **Fixed by deriving EVERY output at its absolute position `idx`** (matching the sender — `constructMinerTx` uses `derive_public_key(derivation, tx.outputs.size(), …)`; the Multisig branch already used `idx`). No-op for purely-classical Key-only txs (`keyIndex == idx`), so no regression. Verified: `TransfersConsumerTest` **37/37 pass** (incl. multisig + deposit scanning).

3. ✅ **`pq_transfer` PORTED to `pqc/mdbx-merge-poc` + VERIFIED end-to-end (Claude, 2026-06-21).** mdbx-merge already had the full daemon-side + shared infra (`pqSpendViaDaemon`, `buildPqSpendTransaction`, `get_pq_outputs`, `PqAccount`, `PQ_TESTNET_*`, the `ccx_pq_*` FFI) and the same `conceal_wallet` CLI class — only the command wiring was missing. Added `pq_balance` + `pq_transfer` + their helpers (`secure_wipe`, `getPqAccountKeys`, `pqCandidateAmounts`, `pqOutputIsMine`) to `src/ConcealWallet/ConcealWallet.{cpp,h}` (+364 lines), a verbatim copy of the testnet-poc handlers (the namespace was already `platform_system::` in both, so no adaptation was needed). `make ConcealWallet` → `BUILD_EXIT=0`. **E2E on a 2-node isolated mdbx testnet:** `pq_balance` → `unlocked PQ outputs: 4, total 0.400000`; `pq_transfer self 4 1000` built a **ver=4** spend, relayed `status=OK` (txid `27d8a869…951b`), mined on-chain (`gettransactions missed_tx:[]`), replay rejected `Not relayed`. (Testnet does **not** gate PQ spends behind V10 — the spend worked at height 14 < 120.) The wallet's F3 PQ-selftest gate in `main.cpp` is active ("PQ selftests OK" prints before the spend). **The remaining commands (`pq_address`, `pq_receive`, `pq_deposit`, `pq_withdraw`) were subsequently ported too — the FULL PQ wallet suite is now on mdbx-merge.** The port passed a pre-commit triple review (CodeRabbit + GLM + Codex): 3 defensive hardening fixes applied (bound untrusted daemon hex in `pqOutputIsMine`; `PQ_WALLET_MAX_SCAN_OUTPUTS` cap on the `pq_withdraw` deposit-cell scan; reject `required_signature_count > 255` before the uint8 narrowing), and GLM's "interest lockHeight" blocker was rejected after verifying the wallet matches the daemon's `getInterestForInput` (`height - term`). Re-verified e2e with no regression (`status=OK` txid `dea369ab…`). **Committed `e4aefa6b` (ConcealWallet.{cpp,h}, +807, local only — not pushed).** See CHANGELOG Waves 8–9 for detail.

**Impact:** wallet receive (scan) **and** send (spend) work on **both** branches; PQ injection via `pq_injector` works on both. **Blocker 2 is fully closed.**

### 🟡 Blocker 3 — 0x07 AEAD v2 backward compatibility (decrypt fallback FIXED; mainnet emission-gate remains)

**✅ DECRYPT FALLBACK — FIXED (Claude).** `decrypt()` now tries v2 (nonce-prefixed + AAD) FIRST and, on AEAD-auth failure, falls back to the v1 path (`ccx_pq_msg_open`, derived nonce, no AAD). v1 and v2 derive DIFFERENT keys (SHAKE domains "…-v1" vs "…-v2"), so the fallback is unambiguous (no false positive) — old 0x07 memos remain readable (no data loss). The top size-guard was relaxed to `>= TAG` (v1 minimum). Verified: 120-test message/auth/golden suite passes.

**Still a caller decision (mainnet only):** height-gate v2 **emission** so new messages use v2 only at/after activation, sparing wallets still on v1-only code. `encrypt()` has no height context, so this belongs in the caller (WalletGreen, which has the height/upgrade state); on the resettable testnet all nodes share the build, so v2-always + the v1 decrypt fallback is correct as-is.

### 🟡 Blocker 4 — Dedicated constant-time verification

**What:** The dudect results (`|t| < 1.2` for both paths) are from a single run on the WSL host — a shared 16-core machine with background load. Production-grade CT verification needs:
- A dedicated, quiesced core (`taskset -c N`, no other processes)
- CPU governor set to `performance`
- Disabled SMT/hyperthreading
- ≥1,000,000 samples per class (current harness uses 4,000)
- 3+ independent runs, results within noise band

**Who can do it:** anyone with access to a dedicated Linux machine. The harness exists (`falcon_ffi::ct_dudect`, `f6_mlkem_dudect`) — just needs `--ignored --nocapture` and a bigger sample count.

### 🟡 Blocker 5 — F5 rollout decision + height-gate

**What:** The F5 v2 AEAD is implemented but not height-gated. For mainnet:
- Gate v2 **emission** behind `UPGRADE_HEIGHT_V10` (or a dedicated `UPGRADE_HEIGHT_V11` if V10 is already taken by PQ spends/deposits)
- Keep v1 **decryption** forever (the fallback above)
- Testnet is fine as-is (resettable)

### ✅ Blocker 6 — `pushBlock` mid-loop rollback leak — FIXED (Claude, F14)

**What:** `BlockchainStorage.cpp:343` — if `validateAndPushTransaction` failed for tx[i], only the coinbase was rolled back. Tx[0..i-1] were already pushed and their nullifier/output-index mutations leaked into the indices (→ false double-spend rejection on retry until resync). Pre-existing classical-path bug.

**Fixed — NOT with `popTransactions(block)`.** That originally-suggested fix is unsafe: it pops ALL `block.transactions`, including the un-pushed failed tx[i], whose key image / nullifier (often the very reason it failed) would then be erased from an *earlier* tx's legitimate spend — corrupting state worse than the leak. Instead, a **targeted reverse rollback of the `i` already-pushed txs + the coinbase**:
```cpp
for (size_t j = i; j-- > 0; )
  popTransaction(transactions[j], blockData.transactionHashes[j]);
popTransaction(blockData.baseTransaction, minerTransactionHash);
```
**Verified:** `BUILD7_EXIT=0`; UnitTests 100% + CoreTests (chain generate-and-play, exercises pushBlock) pass. Follow-up: a dedicated mid-loop-failure rollback unit test (CoreTests harness).

### 🟢 Item 7 — Fuzz campaign extension

**What:** The 3 existing fuzz targets (`unpack`, `verify`, `pubkey_canonical`) have 84M+ runs crash-free. Extend to:
- `ccx_pq_multisig_verify` with malformed ML-DSA sigs/keys
- `ccx_pq_kem_scan` with malformed ciphertexts
- `raptor_abi::pack` → `unpack` round-trip with mutated intermediates
- A C++ libFuzzer/AFL++ target on the transaction deserialization path (malformed PqKeyInput/PqKeyOutput/PqMultisigInput/PqMultisigOutput)
- Run each for ≥24 hours on a dedicated machine

### 🟢 Item 8 — Integration / scale testing

**What:** No test has exercised:
- A block with the maximum number of PQ transactions (2 ring-4 spends per 100 KB zone)
- A reorg that rolls back PQ transactions (unit-tested for correctness, but not stress-tested)
- The mempool under high PQ transaction load
- The daemon startup KAT tripwire on a chain with millions of blocks (startup time)

### ✅ Item 9 — `PqKeyOutput` version gate (Low) — FIXED (Claude, F13)

**What:** `PqKeyOutput` was not version-gated on `tx.version >= 4` (unlike `PqKeyInput`/`PqMultisigOutput`).

**Fixed in `check_outs_valid`** (the consensus-path output validator — `BlockchainValidation.cpp:579`) **with a coinbase exemption**: the testnet coinbase is v1 (`Currency.cpp:719`, `constructMinerTx`) yet legitimately carries the PQ stealth output, and a real PQ spend always carries a (v4-gated) `PqKeyInput`, so the only legitimate v1 carrier is the miner tx. (A naive add to BOTH paths *without* the exemption would reject every testnet block — the originally-suggested "add to CheckTxOutputsVisitor and check_outs_valid" misses this.) Tested: `PqSpendGate.PqKeyOutputRejectedInNonCoinbasePreV4Tx`. `CheckTxOutputsVisitor` parity is optional defense-in-depth — the visitor has no tx.version context, and check_outs_valid already covers the consensus path.

---

## 3. Honest risk assessment

| Risk | Likelihood | Impact | Mitigation status |
|------|-----------|--------|-------------------|
| Raptor construction has an undetected flaw | Medium (novel scheme) | Critical (funds loss / chain fork) | Proofs sketched, not certified. **Needs human review.** |
| Falcon sampler has a timing side-channel | Low (dudect clean) | Medium (key leak to local attacker) | Single dudect run. **Needs dedicated hardware.** |
| Wallet can't send PQ transactions | **Resolved** (verified end-to-end on testnet-poc) | — | Works; only the mdbx-merge **command port** remains (Blocker 2). |
| 0x07 breaks existing messages | **Resolved** (v2→v1 decrypt fallback) | — | Old memos readable; mainnet emission-gate remains (Blocker 3). |
| Consensus bug in PQ validation | Low (two AI audits + edge-case check) | Critical (chain fork) | Good coverage but **needs human review + scale testing.** |
| Cross-platform determinism failure | Very Low (6-platform KAT) | Critical (chain fork) | Well-verified. |

---

## 4. Build/run cheat-sheet (WSL `100.100.90.103`)

```bash
# Full daemon + wallet + tests
cd ~/conceal-core-mdbx-merge
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DSTATIC=ON
make -j16 Daemon ConcealWallet UnitTests

# Crate tests (default — without broken ringsig)
cd ~/conceal-core-mdbx-merge/pqc/ccx-pqc
cargo test --release

# Crate tests (with legacy ringsig demo — includes F8 key-recovery PoC)
cargo test --release --features legacy-ringsig-demo

# PQ unit tests
cd ~/conceal-core-mdbx-merge/build
./tests/unit_tests --gtest_filter='*Pq*'

# Dudect (pinned to core 0)
taskset -c 0 cargo test --release -- --ignored --nocapture falcon_sampler_timing
taskset -c 0 cargo test --release -- --ignored --nocapture mlkem_decap

# Fuzz
cargo +nightly fuzz run <unpack|verify|pubkey_canonical> -- -max_total_time=600

# Cross-arch KAT
CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
cargo run --release --target aarch64-unknown-linux-gnu --example kat_digest
qemu-aarch64-static -L /usr/aarch64-linux-gnu \
  target/aarch64-unknown-linux-gnu/release/examples/kat_digest
```

---

## 5. Key files reference

| Area | File |
|------|------|
| Raptor ring sig (live) | `pqc/ccx-pqc/src/raptor.rs` |
| Ring sig (broken, feature-gated) | `pqc/ccx-pqc/src/ringsig.rs` |
| C ABI entry points | `pqc/ccx-pqc/src/lib.rs` |
| Falcon FFI | `pqc/ccx-pqc/src/falcon_ffi.rs` |
| C shim | `pqc/ccx-pqc/csrc/raptor_falcon.c` |
| Compact packing | `pqc/ccx-pqc/src/raptor_abi.rs` |
| Det keygen | `pqc/ccx-pqc/src/detkeygen.rs` |
| Wallet crypto | `pqc/ccx-pqc/src/walletcrypto.rs` |
| PQ spend builder | `src/CryptoNoteCore/PqSpendBuilder.cpp` |
| PQ consensus checks | `src/Blockchain/BlockchainPq.cpp` |
| Height gates + block validation | `src/Blockchain/BlockchainStorage.cpp` |
| Mempool | `src/CryptoNoteCore/TransactionPool.cpp` |
| Authenticated messages (F5) | `src/CryptoNoteCore/TransactionExtra.cpp` |
| Daemon startup gate | `src/Daemon/Daemon.cpp` |
| Config (heights, scheme IDs) | `src/CryptoNoteConfig.h` |
| Serialization | `src/CryptoNoteCore/CryptoNoteSerialization.cpp` |
| Formal proofs | `docs/design/quantum-resistance/raptor-formal-proofs.md` |
| B1 derivation + estimator | `docs/design/quantum-resistance/raptor-b1-derivation.md` |
| This handoff | `docs/reviews/pqc-mdbx-merge/HANDOFF.md` |
