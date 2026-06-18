# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Conceal Core — the C++ CryptoNote daemon and CLI wallet for the Conceal Network (`₡CCX`), a privacy-preserving coin (ring signatures, encrypted messages, on-chain deposits). Forked from the CryptoNote/Bytecoin lineage. **This is consensus- and money-critical code: a bug can lose funds or fork the chain.** The codebase is deliberately legacy C++11 — match the surrounding style; do **not** modernize unless explicitly asked.

## Build & test

> **Build on Linux x86_64, not this Mac.** The repo does **not** build on Apple Silicon (macOS arm64): `src/crypto/pow_hash/hw_detect.hpp` pulls Linux-only `<asm/hwcap.h>`/`<sys/auxv.h>` for `__aarch64__`, and `cn_slow_hash_hard_arm.cpp` then redefines `hardware_hash_3` because the code assumes `aarch64 ⟹ Linux`. (macOS CI passes only because GitHub's macOS runner is Intel x86_64.) Workflow here: **edit on the Mac, build/test/run on the WSL host** (`100.100.90.103`, Ubuntu 24.04 x86_64, 16c/54 GB) via `.claude/wsl-build.sh [build|test|clean|shell]`, which rsyncs the tree and builds at `-j16`. Native macOS-arm64 support is a real porting task (run `/multi-agent` for it), not a quick patch.

Out-of-source build; binaries land in `build/src/` (Linux/macOS) or `build/src/Release/` (MSVC). Built binary names: `conceald` (daemon), `concealwallet` (CLI wallet), `walletd` (PaymentGateService), `optimizer`.

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release           # add -DSTATIC=ON for fully static binaries (CI does)
make -j2                                        # the build can use up to ~13GB RAM; keep -j low on small machines
```

- **Tests are OFF by default.** The `BUILD_TESTS` option is commented out, so a bare `cmake ..` builds no tests. To get them you must pass it explicitly:
  ```bash
  cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
  make -j2
  ctest --output-on-failure              # runs the suite registered in tests/CMakeLists.txt
  ```
- **Run one test target** (after building with `-DBUILD_TESTS=ON`): `ctest -R UnitTests --output-on-failure`, or invoke the binary directly: `./build/tests/UnitTests --gtest_filter=...`. Targets: `CoreTests`, `CryptoTests`, `IntegrationTests`, `NodeRpcProxyTests`, `PerformanceTests`, `SystemTests`, `TransfersTests`, `UnitTests`, `DifficultyTests`, `HashTargetTests`, `HashTests`.
- **`UnitTests` ships with a baked-in skip list** in `tests/CMakeLists.txt` (`add_test(UnitTests ... --gtest_filter=-WalletApi.*:...)`) — several wallet/tx-pool tests are known-excluded. Don't "fix" the filter to re-enable them without understanding why they're disabled.
- **Deps:** Boost ≥ 1.55 (static: `Boost_USE_STATIC_LIBS ON`), CMake, gcc/g++ or MSVC 2019/2022, Python, make. `external/` vendors `gtest`, `miniupnpc`, `parallel_hashmap`.
- **AES:** enabled via `-maes` on x86; `-DNO_AES=ON` disables it. ARM builds pull flags from `arm.cmake` (needs Neon/AES).
- **No formatter/linter config** in-repo (no `.clang-format`/`.clang-tidy`). `clang-tidy`/`cppcheck`/`clang-format` are **not installed** on this machine — install before relying on them in review/verify steps.

## Architecture

**Layered static libraries feeding four executables** (`src/CMakeLists.txt`). Roughly bottom-up — depend downward, never upward:

```
crypto ─► CryptoNoteCore ─► P2P (CryptoNoteProtocol + P2p) ─► Rpc / NodeRpcProxy ─► Wallet (+ WalletLegacy) ─► PaymentGate
   (Serialization, Common, Logging, System, Http, Transfers, BlockchainExplorer, Mnemonics, InProcessNode are cross-cutting)
```

Executables: **`Daemon`** (full node, `src/Daemon`), **`ConcealWallet`** (CLI wallet, `src/ConcealWallet`), **`PaymentGateService`** (walletd / RPC wallet service, `src/PaymentGate` + `PaymentGateService`), **`Optimizer`** (fusion-tx dust optimizer).

Key subsystems and why they matter:

- **`src/CryptoNoteConfig.h` is the consensus rulebook.** Hard-fork activation heights (`UPGRADE_HEIGHT_V3..V8`, each tied to a `BLOCK_MAJOR_VERSION_*`), `MONEY_SUPPLY` (200M, 6 decimals), `DIFFICULTY_TARGET` (120s), genesis constants, and default ports (P2P 15000 / RPC 16000; testnet 15500 / 16600) all live here. **Changing any value here is a consensus change** — it changes what blocks/txs nodes accept and can fork the network. New rules must be height-gated behind a new `UPGRADE_HEIGHT_*` + block major version, never applied retroactively. There's a parallel `TESTNET_*` set.
- **`src/CryptoNoteCore`** — the heart: blockchain storage/validation, transaction validation, tx mempool, difficulty (LWMA variants), block templates. Difficulty/validation logic is fork-sensitive.
- **`src/CryptoNoteCore/Checkpoints.{h,cpp}`** — hardcoded block checkpoints (the recurring "update checkpoints" commits). These pin canonical history.
- **`src/Serialization`** — the binary wire/storage format (`ISerializer` pattern). Changing serialization affects P2P wire compatibility AND on-disk blockchain/wallet format. Treat as a compatibility surface.
- **`src/System`** — a custom async runtime (`Dispatcher`, `TcpConnection`, timers): green-thread/coroutine-style concurrency used throughout networking. Networking code is written against this, not raw threads/asio directly.
- **`src/CryptoNoteProtocol` + `src/P2p`** — peer protocol and gossip; compiled together into the `P2P` lib. Protocol message/handshake changes are compatibility-sensitive.
- **`src/Rpc` / `src/NodeRpcProxy`** — JSON/binary RPC server and the client-side proxy wallets use to talk to a node. This is the external API surface.
- **`src/Wallet` + `src/WalletLegacy`** — current and legacy wallet engines, compiled into one `Wallet` lib; the wallet file format is a compatibility surface.

## Conventions & gotchas

- **C++11 only** (`CMAKE_CXX_STANDARD 11`, `-std=c++11`). Do not use C++14/17 features — they won't compile on the targeted toolchains.
- **Match the legacy CryptoNote style.** `WalletLegacy` and much of the tree are kept intentionally old. Don't refactor to modern idioms as a side effect of a change.
- **Consensus/serialization/networking changes need extra scrutiny.** Anything touching `CryptoNoteConfig.h`, `CryptoNoteCore` validation/difficulty, `Serialization`, `CryptoNoteProtocol`/`P2p`, or `Checkpoints` can fork the chain or break node/wallet compatibility. Call this out explicitly and prefer height-gated, backward-compatible changes.
- **Git workflow** (`CONTRIBUTING.md`): default branch is `master`; **PRs target the `development` branch**, not master. Branch names follow `<id-3letter>/<topic>` (e.g. `jdo/fix-difficulty`). Conventional-Commits style messages.
- **Version** is set in `CMakeLists.txt` (`VERSION` + `VERSION_BUILD_NO` codename); commit id is folded into the version string at configure time.
- **CI** (`.github/workflows/`): `ubuntu22.yml`, `ubuntu24.yml`, `macOS.yml`, `windows.yml` build release binaries; `check.yml` is a Windows build-check with `-DBUILD_TESTS=ON`. Linux CI builds with `-DSTATIC=ON` and does **not** enable tests, so green CI ≠ tests ran — build with `-DBUILD_TESTS=ON` locally to actually exercise the suite.

## Multi-agent collaborative workflow

For non-trivial features/fixes, this repo uses a multi-model workflow (spec → design-gate → implement → parallel review → verify → PR) driven by `/multi-agent` (see `.claude/commands/multi-agent.md`). Co-agent CLIs available here: `codex`, `agy` (Antigravity/Gemini), `opencode` (GLM), plus a Claude Opus subagent and `coderabbit`. Claude drives all source edits; co-agents run read-only/advisory and each writes only its own findings file under `docs/{specs,design,reviews}/<feature>/`.
