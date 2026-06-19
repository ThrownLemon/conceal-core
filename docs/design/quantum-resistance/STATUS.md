# CIP-0001 post-quantum PoC — status & architecture (handoff)

*One-page reference for the PQ proof-of-concept on branch `pqc/testnet-poc` (fork
`ThrownLemon/conceal-core`, **not pushed** — local for human review). For the decision/economics view
see [`poc-vs-mainnet-report.md`](poc-vs-mainnet-report.md); for the accepted-limitations list see
[`hardening-notes.md`](hardening-notes.md).*

## What's implemented (all merged, integrated `UnitTests` green)

| Capability | What | Key files |
|---|---|---|
| **PQ spend** | v3 tx with `PqKeyInput`/`PqKeyOutput`; anonymous + linkable lattice ring signature; nullifier double-spend protection (mempool + chain + restart) | `pqc/ccx-pqc/src/ringsig.rs`, `CryptoNoteCore/Blockchain.cpp` (`check_pq_tx_input`), `CryptoNoteCore/PqSpendBuilder.{h,cpp}` |
| **Stealth outputs** | ML-KEM-768 KEM-encapsulated one-time keys (real recipient unlinkability) | `lib.rs` (`ccx_pq_kem_derive_output`/`_scan`), `Currency.cpp` (coinbase) |
| **Deterministic keygen** | FIPS-203/204 seed-based ML-KEM/ML-DSA keygen (mnemonic-restorable) | `pqc/ccx-pqc/src/detkeygen.rs` |
| **Deposits** | ML-DSA-65 PQ multisig deposits, height-gated `UPGRADE_HEIGHT_V9` | `CryptoNote.h` (`PqMultisig*`), `Blockchain.cpp` |
| **Deposit freeze (Option 3)** | classical (Ed25519) deposit creation frozen at/after V9 — PQ-only deposits after the fork; creation-side only (existing deposits stay spendable). 4 gates: `pushBlock` per-tx + coinbase, `add_tx` acceptance, `fill_block_template` skip (anti-stall) | predicate `transactionContainsClassicalDeposit` shared in `CryptoNoteFormatUtils`; `Blockchain.cpp`, `TransactionPool.cpp`; see [`deposit-freeze-impl.md`](deposit-freeze-impl.md) |
| **PQ deposit wallet** *(merged; live e2e pending)* | `concealwallet` `pq_deposit`/`pq_withdraw` — create/withdraw an ML-DSA-65 (`PqMultisig*`) deposit. Builders + `get_pq_multisig_outputs` RPC + account-level ML-DSA key derivation. **Unit-tested + GLM-reviewed (0 findings)**; merged `17e4f0b`. **Live e2e RED** — `pq_deposit` funding-discovery bug (finds 0 spendable PQ outputs; `pq_transfer` on the same path works) — **under debug**. walletd RPC not yet done | `CryptoNoteCore/PqDepositBuilder.{h,cpp}`, `Rpc/PqDepositClient.{h,cpp}`, `Wallet/PqAccount.{h,cpp}`, `ConcealWallet.cpp`; see [`pq-deposit-wallet-blueprint.md`](pq-deposit-wallet-blueprint.md) |
| **Messages** | 0x06 ML-KEM PQ messages + 0x07 authenticated classical (ChaCha20-Poly1305); 0x04 decrypt-only | `CryptoNoteCore/TransactionExtra.{h,cpp}` |
| **Wallet file v8** | Argon2id KDF + XChaCha20-Poly1305 AEAD + authenticated prefix MAC (downgrade-proof) | `Wallet/WalletKdf.{h,cpp}`, `Wallet/WalletGreen.cpp`, `pqc/ccx-pqc/src/walletcrypto.rs` |
| **Wallet-native PQ** | `concealwallet`: `pq_address`, `pq_transfer <addr\|self>`, `pq_receive`, `pq_balance mine`; `walletd`: `sendPqTransaction`; daemon `get_pq_outputs` RPC | `ConcealWallet/ConcealWallet.cpp`, `Rpc/PqSpendClient.{h,cpp}`, `Rpc/RpcServer.cpp`, `PaymentGate/WalletService.cpp` |
| **Address v2** | `ccxp`/`ccxh` (+ testnet `ctp`/`cth`) Base58 prefixes carrying the 1184 B ML-KEM key | `CryptoNoteCore/CryptoNoteBasicImpl.cpp`, `Wallet/PqAccount.{h,cpp}` |

## Architecture

- **Crypto island (Rust → C-ABI FFI).** All PQ crypto lives in `pqc/ccx-pqc` (Rust), exposed via the
  `pqc/include/pq_ring_sig.h` C ABI. Every `extern "C"` entry is wrapped in a `catch_unwind` guard
  (`ffi_guard`) so a Rust panic can't cross into the C++ daemon as UB. Primitives: `pqcrypto-kyber`/
  `pqcrypto-dilithium` (KEM/DSA), RustCrypto `ml-kem`/`ml-dsa` (deterministic keygen, exact-pinned),
  `argon2`/`chacha20poly1305` (wallet), and a bespoke lattice ring sig in `ringsig.rs`.
- **Consensus gating.** New rules are height-gated (`UPGRADE_HEIGHT_V9` / `TESTNET_..._V9=80`) behind
  `BLOCK_MAJOR_VERSION_9`; variant tags `0x4` (PqKey), `0x5` (PqMultisig); tx-extra `0x06`/`0x07`. PQ
  output index `m_pqOutputs` + spent set `m_spent_pq_nullifiers` are persisted + rebuilt on restart.
  The lattice ring sig wire format is versioned by `SCHEME_ID` (`0xC0DE_0004`, K=L=6).
- **Wallet file** is a versioned container (v6 legacy → v7 AEAD → v8 authenticated-prefix), migrate-on-
  save, atomic writes.
- **C++ never hardcodes PQ sizes** — it queries `ccx_pq_pubkey_bytes()` etc. at runtime, so a param
  change in Rust flows through without C++ edits.

## How to build / run / demo

- **Build (WSL x86_64 only; Mac arm64 can't compile this):** `.claude/wsl-build.sh [build|test]`
  (rsync + `cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON` + `make -j16`). Tests:
  `ctest -R UnitTests`.
- **Self-spend demo:** `pqc/run-poc-testnet.sh build/src` — 2-node isolated testnet, mines PQ coinbase,
  spends via `pq_injector`, shows double-spend rejection.
- **Wallet self-spend A/B:** `pqc/verify-wallet-spend.sh build/src` — `concealwallet pq_balance` +
  `pq_transfer` (the wallet builds/relays an accepted PQ tx).
- **Wallet↔wallet A/B:** `pqc/verify-wallet-w2w.sh build/src` — wallet B publishes a `pq_address`,
  wallet A `pq_transfer`s to it (verified accepted), B `pq_receive` scans it.

## Verified

- Integrated build green; `UnitTests` pass (incl. PQ ring-sig, serializer golden, wallet KDF v8 +
  brick/downgrade, message round-trip). The 2 always-failing ctest suites (`IntegrationTests`,
  `TransfersTests`) are a pre-existing staged-daemon env issue ("daemon binary wasn't found"),
  unrelated.
- e2e: PQ spend accepted + double-spend rejected; lattice ring-sig soundness empirically refuted the
  universal-forgery claim + a canonical-tag double-spend; wallet self-spend + wallet↔wallet **send**
  live-verified. Multi-model review on every consensus/money diff (CodeRabbit + Codex + GLM + Gemini),
  which caught e.g. a wallet-file brick-on-close (W11) before merge.

## Deferred / gates (see `poc-vs-mainnet-report.md` §6)

1. Lattice ring-sig: constant-time [in progress], parameter calibration, **professional audit** —
   mainnet blocker.
2. Ring-sig size scales linearly (ring-16 ≈ 111 KB > max tx) — needs a ring-size/limit policy or a
   log-proof scheme.
3. Human line-by-line review of the ML-DSA deposit money paths + the consensus PQ-input validator.
4. Retire the fixed `PQ_TESTNET_KEM` ("Option B") for per-recipient keys on mainnet (wallet↔wallet
   path already does this).
5. RustCrypto PQ crates to 1.0 / FIPS-validated.

**Flaky crashes — root-caused + fixed** (ASan; `docs/reviews/flaky-crash-analysis.md`). The
intermittent `System`-dispatcher abort (`read(remoteSpawnEvent) EAGAIN`, drained-eventfd double-read →
unconditional throw) is fixed in `Platform/Linux/System/Dispatcher.cpp`; the flaky `UnitTests` segfault
was a deterministic heap-use-after-free in `WalletGreen::deleteAddress` (freed `multi_index` iterator),
fixed. 109/109 System + 1029 `UnitTests` green under ASan. **Remaining (diagnosed, human-review):** a
WalletLegacy deposit-test detached-thread `std::ref`-to-freed-stream flake (touches money code);
TestPqDeposits.cpp static-member ODR-use breaks sanitizer/`-O1` UnitTests links. (TSan is unusable on
this binary — the `ucontext` green-thread runtime desyncs its fiber shadow, which is why these races
escaped detection for so long.)
