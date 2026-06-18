# PQ migration — remaining work + hand-off (CIP-0001)

Branch: `pqc/testnet-poc` (fork `ThrownLemon/conceal-core`). Status as of the multi-agent review pass.
The working PoC + its hardening are committed; this file tracks what is left and how to pick it up
cleanly in a fresh session.

## In flight (background agents)

- **Bug fix + 2 small fixes** (independent of variant tags): the non-deterministic crash when
  `f_block_json`/`gettransactions` serialize a RELOADED PQ block (ASAN root-cause), the
  money-conservation check in `pushBlock` for v3 txs, and `catch_unwind` on the Rust FFI. Commits
  land directly on `pqc/testnet-poc`.
- **Messages → ML-KEM-768** (blueprint `messages-mlkem.md`): new tx-extra **tag 0x06**
  (`tx_extra_pq_message`), message-domain KEM in `ccx-pqc`, send/scan glue, unit tests. On a separate
  worktree branch — review + merge carefully (shares `CryptoNoteSerialization.cpp`, `CryptoNoteConfig.h`).

## Queued — do SEQUENTIALLY (shared core files; coordinate tags)

These all edit `include/CryptoNote.h` (variants), `CryptoNoteSerialization.cpp` (tags), and
`CryptoNoteConfig.h`. Do one at a time, rebasing on the prior, to avoid conflicts. **Pre-assigned
identifiers so they never collide:**

| Work | tx-input/output variant tag | tx-extra tag | block major / upgrade height | address prefix |
|---|---|---|---|---|
| (existing) PQ key in/out | 0x4 | — | testnet v1 (PoC) | — |
| Messages (in flight) | — | 0x06 | — | (uses KEM pubkey, step 4) |
| **Deposits → ML-DSA** | **0x5** | — | **BLOCK_MAJOR_VERSION_9 / UPGRADE_HEIGHT_V9** | — |
| **Wallet / address v2** | — | — | — | **`ccxpq` / `ccxh` prefixes** |

1. **Deposits → ML-DSA-65** — blueprint `deposits-mldsa.md` (high feasibility, ~15 files). Add
   `PqMultisigInput`/`PqMultisigOutput` (variant tag **0x5**), an `m_pqMultisigOutputs` index (mirror
   of `m_multisignatureOutputs`), `check_pq_multisig` (port of `validateInput(MultisignatureInput)`
   with ML-DSA m-of-n via new `ccx_pq_multisig_sign/verify` FFI), term/interest reused unchanged.
   **Money-critical** — the blueprint flags CRITICAL interest-minting + reorg-symmetry risks; bind
   `input.term == output.term`, mirror the reorg push/pop, and pre-PR review the interest path.
2. **Wallet / address v2** — blueprint `wallet-address-v2.md` (medium; **BLOCKER**: deterministic
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
