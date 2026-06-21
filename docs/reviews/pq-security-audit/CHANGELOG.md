# PQ Security Audit — Change Log

Running log of every file changed (and verification run) during the Claude/Opus audit + remediation of `pqc/mdbx-merge-poc`. Audited at `411c848f`; changes are on top (uncommitted working tree). Companion to `claude-opus.md` (findings) and `external-audit-package.md` (Phase 7).

## Code changes

| File | Finding | Change |
|------|---------|--------|
| `src/Blockchain/BlockchainStorage.cpp` | **F4** | Added `transactionContainsPqSpend(tx)` helper (matches `PqKeyInput`/`PqKeyOutput`) + a **mainnet-only** `< UPGRADE_HEIGHT_V10 → reject` gate in both the per-tx path (`validateAndPushTransaction`) and the coinbase path (`addNewBlock`), mirroring the existing PQ-deposit gate. Mainnet-only (`!isTestnet()`) because the testnet PoC emits coinbase `PqKeyOutput` from height 1 (`Currency.cpp:610`) — a blanket gate would break the running testnet. Build-verified. |
| `pqc/ccx-pqc/src/ringsig.rs` | **F8** | Added a DANGER header documenting the structural key-recovery break (`t=A·s`, square invertible `A`, no error) and that the selftests certify a broken scheme; recommend feature-gating/deletion. Added `#[cfg(test)] mod f8_key_recovery_poc` with `secret_is_recoverable_from_public_key` — recovers `s` from the public key slot-wise in the NTT domain. **Test PASSES** (proves the break). `ringsig.rs` is selftest-only on both branches (not live). |
| `pqc/ccx-pqc/src/falcon_ffi.rs` | **F6** | Added `#[cfg(test)] mod ct_dudect` — self-contained dudect-style timing test for `sign_target` (the Falcon sampler ctgrind flagged): fixed-vs-random trapdoor, slow-tail-cropped Welch's t. `#[ignore]` (run explicitly). Result: `|t|≈0.2` → **no detectable timing dependence on the key** (sampler isochronous). |
| `pqc/ccx-pqc/src/lib.rs` | **F5** | Added `ccx_pq_msg_seal_v2`/`ccx_pq_msg_open_v2` — XChaCha20-Poly1305 with a **caller-supplied 24-byte nonce** (fresh per message, removes the derived-nonce reuse hazard) + **bound AAD** (anti-relocation); key `=SHAKE256("ccx-msg-aead-v2"‖seed)`, domain-separated from v1. Added `#[cfg(test)] mod f5_aead_v2` proving round-trip, no-keystream-reuse, AAD-rejection, tamper/wrong-seed rejection — **PASSES**. (Crypto core only; C++ wire integration = new tag + height-gate, still pending per the spec.) |

## Doc changes

| File | Change |
|------|--------|
| `docs/reviews/pq-security-audit/claude-opus.md` | **NEW** — full audit (surfaces A–E, findings F1–F11, verdicts, go/no-go) + §0.5 dynamic-verification & in-flight-remediation addendum (incl. fixes applied + estimator). |
| `docs/reviews/pq-security-audit/external-audit-package.md` | **NEW** — Phase 7 master package: findings register, soundness package, estimator results, CT posture + dudect harness spec, determinism + cross-arch KAT procedure, go/no-go, manifest. |
| `docs/reviews/pq-security-audit/CHANGELOG.md` | **NEW** — this file. |
| `docs/design/quantum-resistance/raptor-b1-derivation.md` | **EDITED** — §5.1 correction (the "<1 bit / ≤2 blocks" claim is unsupported; right argument is the vacuous-SIS §5.2) + **NEW §5.3** recording the lattice-estimator run results. |
| `docs/design/quantum-resistance/msg-aead-0x07-nonce-fix.md` | **NEW** — F5 fix spec (0x07 AEAD nonce reuse): XChaCha20 + random nonce / bound AAD, new tag, height-gated rollout. |

## Verification log (dynamic, WSL `100.100.90.103` x86_64 + aarch64/qemu)

| When | Check | Result |
|------|-------|--------|
| audit | C++ build (`cmake -DBUILD_TESTS=ON && make -j16`) with F4 applied | `BUILD_EXIT=0` — full daemon + UnitTests compile clean |
| audit | Crate `cargo test --release` (incl. F8 PoC) | **14/14 pass** |
| audit | F1 forgery test (`programmed_key_forgery_is_rejected`) | PASS — forgery rejected (fix works) |
| audit | F8 key-recovery PoC (`secret_is_recoverable_from_public_key`) | PASS — secret recovered from public key (break confirmed) |
| audit | Keygen KAT (x86_64) | digest `8f24…745e` matches pinned reference |
| audit | **Cross-arch KAT (aarch64 via qemu-aarch64-static)** | digest `8f24…745e` **identical** → determinism holds on aarch64 |
| audit | ctgrind/TIMECOP under valgrind | 0 secret-dependent memory accesses; open item = `sign.c` sampler (needs dudect); F1 fix CT-clean |
| audit | Lattice estimator (SageMath 10.9 + Albrecht/MATZOV) | forgery R-SIS "trivially easy" (vacuous); Falcon-512 NTRU uSVP ≈ 2^141 (β=483) = NIST L1 |
| audit | **dudect** Falcon `sign_target` (taskset-pinned, n=4000) | Welch `t(full)=-0.20`, `t(cropped)=0.21` → **no timing dependence on the key** (sampler isochronous) |
| audit | **F5 v2 AEAD** test (`v2_roundtrip_and_nonce_aad_safety`) | PASS — round-trip; distinct nonce⇒distinct ct (no keystream reuse); wrong-AAD/seed/tamper reject |

## Done this cycle (implemented + verified)
- **F6 (sampler):** dudect harness added + run → no leak detected. (ML-KEM-decap dudect still a follow-up; lower risk — goes through pqcrypto/RustCrypto CT FO.)
- **F5 (crypto core):** `seal_v2`/`open_v2` + test. **C++ wire integration pending** (new tag 0x08, OsRng 24-byte nonce in `tx_extra_authenticated_message::encrypt`, AAD=tx_pubkey‖output_index, height-gate) — gated change per `msg-aead-0x07-nonce-fix.md`.
- **Phase 6 (aarch64):** cross-arch KAT digest matches x86_64 → determinism holds on aarch64.

## Wave 2 — implemented + verified

| File | Item | Change / result |
|------|------|-----------------|
| `src/ConcealWallet/main.cpp` | **F3** | Added the PQ selftest gate (incl. keygen KAT + det-keygen) at wallet startup, before any key op — funds-loss-on-restore guard, twin of the daemon gate. **Builds clean** (`BUILD2_EXIT=0`). |
| `pqc/include/pq_ring_sig.h`, `src/CryptoNoteCore/TransactionExtra.{h,cpp}` | **F5** | Wired the v2 AEAD into the 0x07 authenticated-message path (in-place, no new variant): FFI decls; `NONCE_SIZE=24`; `encrypt` now generates a fresh `crypto::generate_random_bytes` 24-byte nonce, binds AAD = tx-pubkey‖output-index, `data = nonce‖sealed`; `decrypt` mirrors. **Builds clean.** *Caveat: full tx-path integration round-trip not yet run; not back-compat with pre-upgrade 0x07 memos (testnet resets).* |
| `pqc/ccx-pqc/src/lib.rs` | **F6** | Added `f6_mlkem_dudect` — FO implicit-reject timing test (valid vs invalid ct decap). |
| `pqc/ccx-pqc/src/raptor_abi.rs` | **F12** (NEW, fuzz-found) | `get_blob` used `*pos + len` with an attacker-controlled varint `len` → overflow panic (debug) / silent wrap (release). Fixed with `checked_add` → clean reject. |
| `pqc/ccx-pqc/fuzz/fuzz_targets/{verify,unpack,pubkey_canonical}.rs`, `fuzz/Cargo.toml` | Phase 5 | The fuzz targets **did not compile** (missing `#![no_main]`; `verify.rs` passed `&[u8;8]` for `*const u8`; manifest lacked `[package.metadata] cargo-fuzz=true`). Fixed all → fuzzers run. |

### F12 — new finding (found by fuzzing)
**`raptor_abi::unpack` integer-overflow on a malformed signature blob.** `get_blob` (raptor_abi.rs:93) computed `*pos + len` with `len` from an untrusted varint (up to `usize::MAX`). On the consensus path `ccx_pq_verify` wraps `unpack` in `ffi_guard` (`catch_unwind`, lib.rs:44), so a *debug* overflow-panic is contained to a `-99` reject **iff the crate builds `panic=unwind`**; a *release* build (no overflow-checks) wraps silently instead. Severity **MEDIUM** (DoS/parse-robustness; contained on the live path but a latent wrap). **Fixed** with `checked_add`.

### Wave-2 verification log
| Check | Result |
|-------|--------|
| C++ build (F3 + F5 wiring) `make -j16 -DBUILD_TESTS=ON` | `BUILD2_EXIT=0` — daemon + wallet + tests compile/link clean |
| Crate `cargo test` after F5/F6/F12 | 15 passed + 2 ignored (dudect); no regression |
| ML-KEM decap dudect (pinned core) | `t(full)=-0.17`, `t(cropped)=-5.17` — below the \|t\|=10 leak line; no clear validity oracle (larger run recommended) |
| **Cross-arch KAT — i686 (32-bit)** | digest `8f24…745e` **match** |
| **Cross-arch KAT — s390x (BIG-ENDIAN)** | digest `8f24…745e` **match** |
| Fuzz `verify` | 31.7M runs **crash-free** |
| Fuzz `pubkey_canonical` | 26.6M runs **crash-free** |
| Fuzz `unpack` (pre-fix → post-fix) | crash (F12) → **19.3M runs crash-free** |

**Determinism matrix COMPLETE:** x86_64 + aarch64 + i686 + s390x(BE) all reproduce `8f24…745e` — the Falcon FP-keygen cross-platform/byte-order hazard is empirically refuted.

## Wave 3 — the remaining follow-ups, implemented + verified

| Item | Change | Result |
|------|--------|--------|
| **F4 test** | Promoted `transactionContainsPqSpend` from a static-local to a **shared free function** in `CryptoNoteFormatUtils.{h,cpp}` (mirroring `transactionContainsClassicalDeposit`, the codebase's stated pattern) — single source of truth + unit-testable. New `tests/UnitTests/TestPqSpendGate.cpp` (7 tests: detects PqKeyInput/PqKeyOutput; ignores classical + PQ-deposit; empty; mixed). | **7/7 pass** (113/113 PQ+auth+golden suite green). |
| **F5 tests** | Updated `TestAuthenticatedMessage` (overhead now TAG+NONCE=40) and `TestMixedMessageIndex` (cap −NONCE) for the v2 format; the existing wrong-index test now exercises the AAD anti-relocation binding. | **pass**; round-trip / wrong-index / wrong-recipient / tamper all covered. |
| **F8 gate** | Feature-gated the broken `ringsig.rs` + its 4 `ccx_pqr_*` exports behind a non-default `legacy-ringsig-demo` cargo feature. Default/production build **excludes** it; the daemon relinks clean (`BUILD4_EXIT=0`). PoC runs via `--features legacy-ringsig-demo`. | default `cargo test` = 8 tests (no broken code); with feature = 15 (+F8 PoC). |
| **LOW-3** | `CryptoNoteSerialization.cpp`: 1 MiB parse-time bound on `PqKeyInput.ringSig` (far above any valid sig, far below the tx cap; redundant with verify's tighter bound but trims the allocation window). | builds clean. |
| **Fuzz (new target)** | `ffi_boundary.rs` (+ Cargo.toml) covering `ccx_pq_kem_scan` / `ccx_pq_multisig_verify` / `ccx_pq_msg_open` / `ccx_pq_msg_open_v2`. | **1.15M runs crash-free**. |
| **CI** | `.github/workflows/check.yml`: added `pq-fuzz` (smoke-runs all 4 targets) + `pq-determinism` (cross-arch keygen KAT on aarch64 / i686 / s390x). Commands validated on the WSL ubuntu-24.04 runner. | jobs added (run on GitHub Actions). |
| **Rigorous dudect** | Made iters env-configurable (`CCX_DUDECT_ITERS`). Sampler **n=50k: t(full)=−0.05, t(cropped)=−1.19** (clean — isochronous confirmed). | — |

### ML-KEM decap dudect — the n=4k t≈−5 hint, investigated
At n=1e6 the cropped t spiked to **−188** → looked like an FO timing oracle. **Triaged: mostly a harness artifact** — the invalid class did extra `to_vec`/`from_bytes` work. With **matched pools** (both classes built identically via `from_bytes`, timed region = decap only), n=1e6 gives **t(full)=0.31, t(cropped)=−24.15**. Full-distribution t is ~0 (no leak); the residual cropped −24 (>10) is most likely further measurement bias (two ciphertext pools in different memory), not a crypto branch, since fixing the harness cut it ~8×. **Not a confirmed leak**; flagged for the external CT audit — the canonical fix is a single-interleaved-buffer dudect (Reparaz methodology) on a dedicated quiesced host.

## Still genuinely open (need external sign-off, not codeable here)
- The **formal unforgeability reduction** + **anonymity statistical-distance bound** (F2 / anonymity proofs) — external cryptographer.
- **F5 mainnet rollout decision** (the in-place 0x07 upgrade breaks pre-upgrade memos on a non-resettable chain — testnet is fine; a new tag vs in-place + migration is a product call). The full end-to-end memo-through-a-real-tx integration (vs the unit-level round-trip already covered) is an e2e-harness item.
- **ML-KEM decap** canonical single-buffer dudect on a dedicated host (residual cropped t≈−24 above).
- **paramch_h** NUMS ceremony (F9); per-output scheme tag (F11).

## Wave 4 — GLM cross-verification of Claude's fixes (`docs/reviews/pqc-mdbx-merge/glm-verification-of-claude.md`)

GLM independently re-verified the fixes: no new critical/high; confirmed reorg rollback symmetry, nullifier persistence (in-memory, rebuilt by full-chain replay = classical parity), height-gate coverage for all 4 PQ types, coinbase maturity, mixed-v4 accounting. **One new Low**, actioned:

| Item | Change | Result |
|------|--------|--------|
| **PqKeyOutput tx-version gate** (GLM Low) | `PqKeyInput`/`PqMultisigOutput` require `tx.version >= 4`; `PqKeyOutput` did **not** (a non-coinbase pre-v4 tx could carry one). Added a v4 gate in `check_outs_valid` (CryptoNoteFormatUtils.cpp PqKeyOutput branch) **with a coinbase exemption** — the testnet coinbase is v1 (`constructMinerTx`, `tx.version=TRANSACTION_VERSION_1`) yet legitimately carries the PQ stealth output; a real PQ spend always has a (v4-gated) `PqKeyInput`, so only the miner tx is a legit v1 carrier. | builds clean (`BUILD5_EXIT=0`); new test `PqSpendGate.PqKeyOutputRejectedInNonCoinbasePreV4Tx` **passes**; testnet coinbase still validates. |
| **Test-harness bug found** | `TestPqSpendGate.cpp` (the F4 test, new file) was **never compiled** — CMake `GLOB_RECURSE` only re-globs on a `cmake` re-run, and the wave-3 `make`-only builds missed it (so the F4 tests had been silently absent, not "113 passing incl. them"). Re-ran cmake → the file compiles. | PQ unit suite **113 → 120** tests; PqSpendGate **7/7 run + pass**. Lesson logged: re-run cmake after adding test files. |

| **`pushBlock` mid-loop rollback leak** (GLM Low, pre-existing/non-PQ) | When `tx[i]` fails validation in `Blockchain::pushBlock`, the rollback popped **only the coinbase** (`popTransaction(baseTransaction)`), **leaking `tx[0..i-1]`'s** key-image / nullifier / output-index mutations into the in-memory indices even though the block is rejected (→ false double-spend on legit retries until resync). Replaced with a **targeted reverse rollback of `tx[0..i-1]` + coinbase**. `popTransactions()` was unusable (pops ALL incl. the un-pushed `tx[i]`, whose key image — likely the very reason it failed — would then be erased from an earlier tx's spend, corrupting state). | `BUILD6_EXIT=0`; **UnitTests 100%** + **CoreTests pass** (full chain generate-and-play exercises pushBlock). Dedicated mid-loop-failure rollback test = CoreTests-harness follow-up. |

**Net:** GLM↔Claude cross-verification converged with no new critical/high. **Both** of GLM's Lows fixed + verified (PqKeyOutput version-gate; pushBlock rollback leak). The F4 tests are now actually compiled + exercised (caught a CMake GLOB gap). All **120 PQ unit tests + CoreTests + crate tests pass**; daemon builds clean across builds 1–6.

## Wave 5 — handoff reconciliation + merged-tree verification

GLM did a further session (formal proofs, dudect, ceremony) and consolidated everything into `docs/reviews/pqc-mdbx-merge/HANDOFF.md` (the canonical cross-audit handoff). Reconciled the now-redundant docs and verified the merged tree:

- **Merged-tree build+test (build7, `cmake` re-glob + `make -j16`): `BUILD7_EXIT=0`** — GLM's later changes (FFI `*const i8`→`c_char`, `paramch_h` frozen-spec pin, `raptor-formal-proofs.md`, `cross-arch-kat-matrix.md`) coexist with all my changes (F4/F5/F8/F12/F13/F14/LOW-3/dudect) with **no conflict**; **120 PQ unit tests + 9 crate tests (default, ringsig gated) pass**. Both agents' work is consistent in one tree.
- **HANDOFF.md corrected:** it listed my already-applied fixes as open TODOs — marked **Blocker 6 (pushBlock)** and **Item 9 (PqKeyOutput gate)** as ✅ FIXED (with the corrected fixes: targeted reverse-rollback, NOT GLM's `popTransactions`; and the coinbase-exempt v4 gate GLM's suggestion missed). Added F13/F14/LOW-3/F4-test-wiring/ffi_boundary to the done-table.
- **De-scattered:** `pqc-mdbx-merge/audit-package-index.md` (stale Phase-7 manifest) → SUPERSEDED banner; my `pq-security-audit/external-audit-package.md` → "Claude side; canonical = HANDOFF.md"; my `pq-security-audit/HANDOFF-glm.md` → HISTORICAL banner. Single entry point = `HANDOFF.md`.
- **Cross-confirmation from GLM's later work:** GLM's independent ML-KEM FO-decap dudect = `t(full)=-0.71, t(cropped)=0.09` (constant-time) — **resolves the residual cropped −24 I saw as measurement bias** (GLM's clean run agrees the decap is CT). GLM's `raptor-formal-proofs.md` supplies the unforgeability reduction + anonymity ε-bound (`ε ≤ L·2^-128`) — still pending external-cryptographer sign-off.

**Blocker 2 (GLM HANDOFF) — RECEIVE half FIXED; SEND half open.** The wallet coinbase scanner (`TransfersConsumer::findMyOutputs`) underived Key outputs with a running `keyIndex` that advanced only for Key/Multisig outputs, so a `PqKeyOutput` before a Key output left `keyIndex < idx` → the classical coinbase remainder was derived at the wrong index → the wallet never saw its own coinbase funds. **Fixed: derive every output at its absolute position `idx`** (matching the sender; the Multisig branch already did). No-op for classical Key-only txs; verified `TransfersConsumerTest` **37/37** + build clean. The `WalletApi.*` "failures" seen when bypassing the gtest filter are pre-existing/skip-listed, not a regression. **Still open:** the SEND path (`pq_transfer` / `PqSpendClient` TcpConnector) — see Wave 6.

## Wave 6 — validated GLM's 3 "actionable changes"; one was a real gap, one was wrong

GLM's handoff listed 3 changes the next person should make. Verified each against the code:

| GLM-suggested change | Verdict | Action |
|----------------------|---------|--------|
| **pushBlock**: "use `popTransactions` instead of single `popTransaction`" | **INVALID** — `popTransactions` pops ALL `block.transactions` incl. the un-pushed failed `tx[i]`, erasing a key image an earlier tx legitimately spent → worse corruption | Already fixed correctly (F14, targeted reverse rollback of `tx[0..i-1]`+coinbase, CoreTests-verified). GLM's suggestion not applied. |
| **TransfersConsumer**: handle `PqKeyOutput` scanning | **VALID — already done** (the absolute-`idx` derivation fix; `TransfersConsumerTest` 37/37). | — |
| **0x07 v1 decrypt fallback** (try v2, fall back to v1) | **VALID — real gap I'd left** (my F5 replaced v1 decrypt entirely → old memos unreadable) | **IMPLEMENTED** in `TransactionExtra.cpp::decrypt` (v2-then-v1, unambiguous via distinct SHAKE-domain keys). Verified: 120-test suite passes. Height-gate v2 *emission* = mainnet caller decision (encrypt has no height; testnet uniform). |
| **PqSpendClient TcpConnector fix** | **MISDIAGNOSED by GLM + unported here** | See below. |

**`pq_transfer` send path — diagnosis corrected.** (1) The command is **NOT PORTED to mdbx-merge** — `pqSpendViaDaemon` has no caller; it's fully wired only on `testnet-poc` (ConcealWallet.cpp:352/2154/2257). Nothing to run/debug here until it's ported. (2) The TcpConnector failure GLM saw (on testnet-poc) is **not a port/config mismatch** — the caller passes the same `m_daemon_host/m_daemon_port` NodeRpcProxy used fine. Real cause: `pqSpendViaDaemon` does `HttpClient`/`TcpConnector` I/O on `m_dispatcher` from the **console-command thread**, but `System::Dispatcher` is single-threaded (all I/O must run on its event-loop thread; NodeRpcProxy works because it owns its own dispatcher thread). Fix = run the spend on the dispatcher thread / a fresh local dispatcher / via the existing INode connection — needs a live repro to verify. Recorded in HANDOFF.md Blocker 2.

## Wave 7 — `pq_transfer` SEND verified working end-to-end (Blocker 2 send-half RESOLVED; cross-thread theory retracted)

Ran the live repro on `pqc/testnet-poc` (WSL). **The wallet's native PQ spend works end-to-end** — the Wave-6 "cross-thread Dispatcher" hypothesis and the earlier "WRONG TRANSACTION BLOB / serializer bug" were both wrong; the failures were an **environment artifact**.

- **Verified:** `concealwallet … pq_transfer self 4 1000` against a clean **isolated 2-node** testnet (node1 mining, frozen at height 20 via `stop_mining`):
  - `pq_balance` → `unlocked PQ outputs: 10, total 1.000000`.
  - spend built **ver=3, 1 `PqKeyInput`, 1 output, 9229 B** → relayed **`status=OK`** (txid `b07f2236e11721b9850702bbc8da2eb124fcc7b950ef4cd189603cf8b43dcdbb`) → **mined into a block** (`gettransactions` `missed_tx:[]`, `tx_pool_size` back to 0) → **replay rejected `Not relayed`** (nullifier on-chain ⇒ double-spend protected). Full lifecycle build→relay→mine→double-spend-protect confirmed.
- **Root cause of all prior failures = environment, NOT code:**
  1. Stuck leftover `concealwallet`/`conceald` processes (hung on a dead RPC port) from earlier backgrounded attempts.
  2. Fresh wallets **P2P-syncing to a FOREIGN non-PQ chain** — a stray testnet peer at height **1096 with 0 PQ outputs** — so the wallet found no PQ outputs (the "no PQ outputs for amount 100000" / parse confusion). The original ccx-n1 found 356 outputs *because it was isolated* (`--add-exclusive-node` pinned to its own 2-node net).
  3. A **single** isolated node refuses to mine (it waits to "synchronize" with a peer → height stuck at 1). You need a **2-node** isolated net.
  4. `verify-wallet-spend.sh` passed wrong args (`pq_transfer 4 1000` → "invalid address 4"); correct is `pq_transfer self 4 1000`.
- **Retractions:** "TcpConnector connection bug" (GLM) and "cross-thread `System::Dispatcher` violation" (Wave 6) are both **withdrawn** — `pqSpendViaDaemon` does `HttpClient(m_dispatcher)` I/O from the console thread exactly like `getFeeAddress()`, and both work.
- **Repro recipe (for the record):** 2 isolated nodes (each `--add-exclusive-node`→the other, one `--start-mining`), mine ≥20 blocks, `curl /stop_mining` to FREEZE the chain, then run the wallet against the mining node. Detached-script + file-output is advisable (the WSL SSH link drops on long commands and silently eats stdout).
- **Cleanup:** removed the temporary `PQDBG` `fprintf` I had added at `src/Rpc/PqSpendClient.cpp` relay; `make ConcealWallet` rebuild `BUILD_EXIT=0`.
- **Remaining (mechanical, not a bug):** port the `pq_transfer` command + handler into mdbx-merge (the `pqSpendViaDaemon` backend already exists there; it just has no caller). *(Done in Wave 8.)*

## Wave 8 — `pq_transfer` ported to mdbx-merge + verified end-to-end (Blocker 2 fully CLOSED)

Ported the PQ spend path from `pqc/testnet-poc` to `pqc/mdbx-merge-poc` and verified it on the mdbx daemon. (Correction to Wave 7: mdbx-merge keeps the **same `conceal_wallet` CLI class**, not a modular `WalletGreen`/`RpcServer` — so the port was a direct handler copy, not a rewrite.)

- **Files changed (mdbx-merge tree):** `src/ConcealWallet/ConcealWallet.cpp` (+350), `src/ConcealWallet/ConcealWallet.h` (+14). Added `pq_balance` + `pq_transfer` console commands + their helpers (`secure_wipe`, `getPqAccountKeys`, `pqCandidateAmounts`, `pqOutputIsMine`), the 3 PQ includes, the 2 `setHandler` registrations, and the matching header declarations. (`main.cpp`'s +21 is the pre-existing F3 wallet-selftest gate, not part of this port.)
- **Verbatim copy — no logic change.** All called symbols already existed on mdbx-merge with identical signatures (`pqSpendViaDaemon` is `platform_system::Dispatcher&`, matching `m_dispatcher`; `COMMAND_RPC_GET_PQ_OUTPUTS::pq_out_entry`, `PqAccountKeys`, `parsePqAccountAddressString`, `PQ_TESTNET_KEM_SK`, the `ccx_pq_*` FFI, all address prefixes — byte-identical). The namespace was already `platform_system::` in both trees, so **zero** `System::`→`platform_system::` edits were needed; the handler bodies were copied byte-for-byte.
- **Build:** `make ConcealWallet` → `BUILD_EXIT=0` (no new files → no cmake re-glob needed).
- **E2E (2-node isolated mdbx testnet, node1 mining, frozen):** `pq_balance` → `unlocked PQ outputs: 4, total 0.400000`; `pq_transfer self 4 1000` → **ver=4** spend, relayed `status=OK` (txid `27d8a869f1d3ff53bc31daad783af3a60f98f83aa352eb9dcbfe79366c17951b`) → **mined on-chain** (`gettransactions missed_tx:[]`, pool 0) → **replay `Not relayed`** (nullifier on-chain). Worked at **height 14 < V10 (120)** → testnet does not height-gate PQ spends. The wallet's F3 selftest gate ran ("PQ selftests OK") before the spend.
- **Scope:** only the spend path (`pq_balance`/`pq_transfer`) was ported, as requested. The PQ `deposit`/`withdraw`/`receive`/`address` commands remain testnet-poc-only (follow-up if wanted).
- **Status:** edits are uncommitted in the working tree (pre-PR triple-review + commit = maintainer's call). **Blocker 2 is fully closed on both branches.**

## Wave 9 — full PQ wallet command suite ported, triple-reviewed, hardened, committed

Extended the Wave-8 spend-path port to the **full** PQ command suite and ran the required pre-commit triple review.

- **Ported the remaining 4 commands** (verbatim from testnet-poc, all backend symbols already present): `pq_address`, `pq_receive`, `pq_deposit`, `pq_withdraw` + `#include "Rpc/PqDepositClient.h"` + 4 registrations + 4 header decls. `make ConcealWallet` → `BUILD_EXIT=0`. Smoke-tested on a 2-node mdbx testnet: `pq_address` prints the `ctp1…` address; `pq_receive` enumerates received PQ outputs (e.g. "Received PQ outputs: 11"); `pq_deposit` validates amount/term and errors cleanly on bad input; `pq_withdraw` resolves deposit cells and errors cleanly when none match.
- **Triple review (CodeRabbit + GLM-consult + Codex):**
  - **GLM** — flagged a BLOCKER (pq_withdraw interest `lockHeight = currentHeight - cell->term`). **Rejected after verification:** the daemon's `Currency::getInterestForInput` uses exactly `height - input.term` (Currency.cpp:420 and :435 for the PQ path), so the wallet matches the daemon; GLM's suggested `cell->height` would diverge and get the withdraw **rejected**. Also: DoS (unbounded `get_pq_multisig_outputs` scan) — VALID; secret-wipe/RAII — confirmed correct; missing unit tests — noted.
  - **CodeRabbit** — major: `pqOutputIsMine` decodes `e.kem`/`e.key` hex before size-checking (hostile-node large-alloc) — VALID; minor: `pq_withdraw` narrows `required_signature_count` (uint32) to uint8 without a guard — VALID.
  - **Codex** — completed all reads, corroborated "ported bodies text-equivalent to source, no behavioral divergence" and "`*ViaDaemon` returns are checked"; stalled in its output phase before emitting the full list (cancelled at 25 min). Its covered axes agree with GLM/CR.
- **Fixes applied (3, to the mdbx-merge port) + verified no-regression:**
  1. `pqOutputIsMine` — bound `e.kem`/`e.key` to `ccx_pq_kem_ct_bytes()*2` / `ccx_pq_pubkey_bytes()*2` **before** `fromHex`.
  2. `pq_withdraw` — `totalOuts > PQ_WALLET_MAX_SCAN_OUTPUTS` guard on the deposit-cell scan (mirrors `pq_balance`).
  3. `pq_withdraw` — reject `required_signature_count > 0xFF` before the uint8 cast.
  - Rebuild `BUILD_EXIT=0`; re-ran e2e: `pq_balance` still found 2 unlocked / `pq_receive` 11 received (fix 1 does **not** reject legit outputs), and at height 22 `pq_transfer self 4 1000` relayed `status=OK` (txid `dea369ab…`). The smoke-run segfault was a **sync race** (daemon mid-mine at height 5), not reproducible against a frozen chain (clean under gdb twice) — a pre-existing NodeRpcProxy-sync robustness issue, not the PQ port.
- **Committed:** `e4aefa6b feat(pqc): port PQ wallet command suite to mdbx-merge` (ConcealWallet.{cpp,h}, +807; local only, **not pushed**). The audit working tree (crate + daemon fixes, incl. main.cpp's F3 gate) remains uncommitted/separate.
- **Tree-parity DONE (testnet-poc):** the same 3 defensive hardening guards were applied to the testnet-poc original (`/Users/travis/Projects/conceal-core`), build `BUILD_EXIT=0`, re-verified e2e (pq_balance 17 unlocked / pq_receive 28 / `pq_transfer self` → `status=OK` txid `b7a6e7f6…`). Committed `e45a78a7 fix(pqc): harden PQ wallet commands against untrusted daemon data` (local only, not pushed). Both trees now carry the identical hardening.
