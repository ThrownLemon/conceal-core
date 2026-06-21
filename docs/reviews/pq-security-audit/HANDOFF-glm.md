# Handoff / Catch-up for the GLM agent

> **⚠️ HISTORICAL.** This was Claude's catch-up handoff *to* GLM. GLM has since completed that work
> (verification pass + formal proofs + dudect + ceremony) and consolidated everything into the canonical
> [`../pqc-mdbx-merge/HANDOFF.md`](../pqc-mdbx-merge/HANDOFF.md). Use HANDOFF.md; this is kept for history.

You (GLM) ran the production-readiness remediation (`production-readiness-prompt.md`) through Phase 5, then paused (out of credits). A second reviewer (Claude/Opus) then did an independent audit + a remediation/verification pass on the same worktree (`pqc/mdbx-merge-poc`). This brings you current and assigns the next work. **Read this first, then the reports in §4.**

## 1. TL;DR — where things stand

- Your top finding (HIGH-1, the Raptor programmed-key forgery) was **independently confirmed** by the second reviewer (its F1) — same root cause, same fix. The fix (bind the ring into the FS challenge) is in and **verified** (forgery test now rejects; `cargo test` green).
- Phases 0–5 of your plan are largely done; the second pass **completed Phase 2.2 (estimator), Phase 5.2 (KAT tripwire — also wired into the wallet), Phase 6 (cross-arch matrix), and fixed your fuzz harness (it didn't compile)**.
- **New findings the second pass added: F4, F5, F8, F12** (details §3) — F4/F5/F8/F12 were **not** in your audit. All are fixed or spec'd.
- Everything is **build-verified on WSL** (`BUILD2_EXIT=0`, full daemon + wallet + tests) and **determinism is proven on 4 architectures incl. big-endian**.

## 2. What changed since you stopped (do NOT redo these)

Fixes applied + verified on top of your work:
- **F1 ring-binding** (your HIGH-1) — confirmed working: `programmed_key_forgery_is_rejected` passes.
- **F4** — PQ *spends* now have an explicit `UPGRADE_HEIGHT_V10` gate (mainnet-only) in `BlockchainStorage.cpp` (`transactionContainsPqSpend` + per-tx + coinbase). You never gated `PqKeyInput`/`PqKeyOutput`; this closes it.
- **F3** — the keygen-KAT / det-keygen selftest gate is now wired at **both** daemon (`Daemon.cpp`) and **wallet** (`ConcealWallet/main.cpp`) startup.
- **F5** — the 0x07 authenticated-message AEAD nonce-reuse hazard: crypto core (`ccx_pq_msg_seal_v2`/`open_v2`, XChaCha20 + caller nonce + AAD) implemented + unit-tested, and wired in-place into `TransactionExtra.cpp` encrypt/decrypt (random nonce + AAD=tx_pubkey‖index).
- **F8** — `ringsig.rs` (the K=L=6 demo) is now marked DANGER (it's cryptographically broken — `t=A·s`, no error → key recovery) with a **passing PoC that recovers the secret from the public key**. It is selftest-only on both branches (not live).
- **F12** (NEW, found by fuzzing) — integer-overflow in `raptor_abi::unpack`; fixed with `checked_add`, re-fuzzed crash-free.
- **B1 §5.1** — your `raptor-b1-derivation.md` had a wrong sub-claim ("<1 bit via ≤2 blocks"); corrected, and the **lattice estimator was actually run** (§5.3 of that doc): forgery R-SIS is "trivially easy" (vacuous); Falcon-512 NTRU ≈ 2^141 classical = NIST L1.
- **Phase 5 fuzz** — your three targets (`verify`/`unpack`/`pubkey_canonical`) **did not compile** (missing `#![no_main]`, a `&[u8;8]` vs `*const u8` bug in `verify.rs`, missing `[package.metadata] cargo-fuzz=true`). All fixed; they now run.
- **Phase 6** — cross-arch keygen KAT run on **aarch64, i686 (32-bit), s390x (big-endian)** via qemu — all reproduce the pinned digest `8f24…745e`.
- **Constant-time** — dudect run on both secret paths: Falcon sampler `|t|≈0.2` (clean); ML-KEM decap `t(full)≈0, t(cropped)≈−5` (below the leak line).

## 3. Cross-reference: your audit ↔ the second audit

- **Convergence:** HIGH-1≡F1, MED-2≡F2 (B1), LOW-1≡F9 (paramch NUMS), linkability/determinism/serialization verdicts agree.
- **Only the second pass found:** F4 (spend height-gate), F5 (0x07 nonce), F8 (broken `ringsig.rs`), F12 (unpack overflow), and the B1 §5.1 error.
- **Only you found (now resolved):** HIGH-2 (`m_spent_pq_nullifiers` persist), MED-1 (BlockTemplate nullifier track) — both already fixed in-tree; LOW-3 (ringSig length bound) — still open, low priority.

## 4. Reports to read (in order)
1. `docs/reviews/pq-security-audit/external-audit-package.md` — master: findings register (F1–F12), verdicts, estimator, CT, determinism, go/no-go, manifest.
2. `docs/reviews/pq-security-audit/CHANGELOG.md` — every code/doc change + the full WSL verification log.
3. `docs/reviews/pq-security-audit/claude-opus.md` — the second audit in full (incl. §0.5 dynamic-verification addendum).
4. `docs/design/quantum-resistance/raptor-b1-derivation.md` (§5.1 correction + §5.3 estimator), `raptor-anonymity-proof.md`, `msg-aead-0x07-nonce-fix.md` (F5 spec).

## 5. Your assignments (prioritized) — what to pick up next

Matched to where a careful-but-verify-everything pass adds most value. **Verify each against the code before acting; treat the second audit's claims as hypotheses to re-check, exactly as it did to yours.**

**A. Re-verify the second pass's fixes (your strength: independent cross-check).**
- Confirm the **F4 mainnet-only gate** logic in `BlockchainStorage.cpp` is correct and that the `!isTestnet()` carve-out doesn't leave a mainnet hole (read the gate; trace `transactionContainsPqSpend`).
- Confirm the **F5** AAD is computed identically in `encrypt` (tx_pubkey from `KeyPair`) and `decrypt` (the `txkey` param) — byte-for-byte — else memos won't open. Write a C++ round-trip unit test (see B below).
- Re-run the **fuzz** targets longer (`-max_total_time=600`) with a seeded corpus; confirm no new crashes beyond F12.

**B. Build the two deferred tests (clear, mechanical — good fit).**
- **F4 unit test:** mirror the deposit-gate test in `tests/UnitTests/TestPqDeposits.cpp` for the spend path — a `CurrencyBuilder(...).testnet(false)` (mainnet) currency, a tx carrying `PqKeyInput`/`PqKeyOutput`, assert block-connect **rejects** below `UPGRADE_HEIGHT_V10` and accepts at/after.
- **F5 integration test:** in `tests/UnitTests/TestPqMessage*.cpp`, encrypt a 0x07 v2 memo and decrypt it round-trip through a real tx-extra serialize/parse; assert wrong-recipient and a relocated (different index) memo both fail.

**C. Run the rigorous dudect (mechanical, just needs a quiesced host + patience).**
- Re-run `falcon_ffi::ct_dudect` and `f6_mlkem_dudect` with the sample count raised to ≥1e6, pinned (`taskset`), governor=performance. Report the stabilized `|t|`. The ML-KEM cropped `t≈−5` specifically needs confirmation it's noise, not a small FO-decap oracle.

**D. LOW-3 (optional, low priority):** a parse-time `ringSig` length bound — only if you also confirm it needs a `serializer.binary` max-length param (framework change); it's already double-bounded, so skip unless asked.

**NOT for GLM (flag to Opus/Codex + an external cryptographer instead):** the formal unforgeability *reduction* and the anonymity *statistical-distance bound* (the two mainnet-blocking proofs — F2/anonymity); and the **F5 mainnet rollout decision** (new tag vs in-place, migration). These need the strongest reasoning + a human call, per the go/no-go gates in the package.

## 6. Build/run cheat-sheet (WSL `100.100.90.103`)
- C++: `cd ~/conceal-core-mdbx-merge/build && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON && make -j16`.
- Crate: `cd ~/ccx-pqc-audit-claude && cargo test --release [-- --include-ignored]`.
- Cross-arch KAT: `export CARGO_TARGET_<ARCH>_LINKER=<arch>-linux-gnu-gcc CC_<arch>=... RUNNER=qemu-<arch>-static QEMU_LD_PREFIX=/usr/<arch>-linux-gnu; cargo test --release --target <arch> keygen_kat -- --nocapture`.
- Fuzz: `cd ~/ccx-pqc-audit-claude && cargo +nightly fuzz run <verify|unpack|pubkey_canonical> -- -max_total_time=N`.
- Estimator: `~/miniforge3/envs/sage/bin/sage /tmp/est.py` (SageMath env; `lattice-estimator` cloned at `~/lattice-estimator`).
