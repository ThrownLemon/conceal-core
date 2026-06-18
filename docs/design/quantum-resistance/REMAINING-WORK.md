# PQ migration — remaining work + hand-off (CIP-0001)

Branch: `pqc/testnet-poc` (fork `ThrownLemon/conceal-core`). Status as of the multi-agent review pass.
The working PoC + its hardening are committed; this file tracks what is left and how to pick it up
cleanly in a fresh session.

## MERGED into `pqc/testnet-poc` (done — `make -j12` green, `ctest -R UnitTests` 100%)

- **Bug fix + 2 small fixes** — the "reload crash" was a **pre-existing, non-PQ** null-deref in
  `gettransactions` on a malformed hash (fixed); + a v3 money-conservation check on the block-import
  path (Codex/GLM review caught + fixed a CRITICAL output-sum-overflow bypass); + uniform
  `catch_unwind` guards on every panicking Rust FFI entry point (incl. the new message + multisig fns).
- **Messages → ML-KEM-768** (tag `0x06`) **+ ChaCha20-Poly1305 AEAD** — real authenticated encryption
  (tampering any byte now fails), beyond the legacy chacha8 owner-test. Send/scan glue + unit tests.
- **Deposits → ML-DSA-65** (tag `0x5`, `UPGRADE_HEIGHT_V9`) — faithful PQ analogue of the Ed25519
  deposit path; interest/lock/reorg semantics byte-identical; +11 tests. **GATE BEFORE ANY PR to
  development/master:** the required pre-PR triple review + a line-by-line human read of the
  interest-minting / reorg money paths (money-critical; tested + agent-reviewed, not yet human-reviewed).

## Still queued (sequential; shared core files)

Assigned-tag table (so future work never collides): PQ key in/out = variant `0x4`; messages = tx-extra
`0x06`; deposits = variant `0x5` + `BLOCK_MAJOR_VERSION_9`/`UPGRADE_HEIGHT_V9`; wallet = `ccxpq`/`ccxh`
address prefixes. (`0x4`/`0x06`/`0x5` are now in the tree.)

1. **Wallet / address v2** — blueprint `wallet-address-v2.md` (medium; **BLOCKER**: deterministic
   ML-KEM keygen from the mnemonic seed is unbuilt — `kyber768::keypair()` is RNG-based; needs a
   FIPS-203 `KeyGen(d,z)` crate path). Address carries the **1184-byte ML-KEM pubkey only** (NOT the
   4096-byte ring-sig key, which is per-output/derived). Adds the `get_pq_outputs` RPC to replace the
   demo script's coinbase-tx fetching, and `createPqTransaction` in WalletGreen to retire `pq_injector`.

## Not needed

- **PoW / hashing** — already Grover-adequate (256-bit hashes, unbounded search space). See
  `pow-grover-widening.md`. Documentation only; **do not** widen the nonce or migrate any hash.

## Build / test conventions

- Edit on Mac, build on WSL (`ssh 100.100.90.103`); Mac arm64 cannot build. `pkill -x conceald`
  (never `-f`). Tests: `-DBUILD_TESTS=ON`, `ctest -R UnitTests`. Demo: `pqc/run-poc-testnet.sh`.
- **Before any PR**: required pre-PR triple review (CodeRabbit + Codex + GLM) on the consensus/crypto
  diff, plus ASAN on the reload path. The lattice ring sig stays **experimental / testnet-only** until
  parameters are calibrated, made constant-time, and audited (CIP-0001 C1).
