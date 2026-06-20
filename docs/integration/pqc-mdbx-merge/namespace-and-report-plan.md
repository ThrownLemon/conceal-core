# PQC ⊕ MDBX/conceal-wallet — integration spec

**Status:** UNAUDITED integration spike. NOT mainnet-ready. NOT a consensus
proposal. Demonstration that the post-quantum (CIP-0001) work and the
`nullcryptodev` MDBX + `Acktarius` conceal-wallet fork can coexist in one build.

**Branch:** `pqc/mdbx-merge-poc` (isolated worktree).
**Base (wins):** `nullcryptodev/conceal-core` PR #14 head (`ack/wallet` =
MDBX storage + domain v9 + GPU + multiwallet `conceal-rpc` + conceal-wallet TUI).
**Replayed on top:** the PQ work from `pqc/testnet-poc`.
**Tag policy:** the fork has priority on the consensus namespace. PQ yields —
every PQ identifier that collided is moved to free space above theirs.

Both source branches remain untouched. Nothing is pushed without explicit
direction. Money/consensus code — every reassignment below is a consensus
decision, height-gated, never retroactive.

---

## 1. Unified namespace table (the four collisions + the resolution)

Discovered by auditing both forks' `CryptoNoteSerialization.cpp`,
`include/CryptoNote.h`, `CryptoNoteConfig.h`, `TransactionExtra.h`.

### 1.1 Transaction **output** variant tags
| Tag | Fork (PR#14, keep) | PQ (was) | PQ (now) |
|-----|--------------------|----------|----------|
| 0x02 | KeyOutput | KeyOutput | KeyOutput (shared, unchanged) |
| 0x03 | MultisignatureOutput | MultisignatureOutput | MultisignatureOutput (shared) |
| 0x04 | **StandardPaymentOutput** | PqKeyOutput | → **0x08** |
| 0x05 | **MultisigPaymentOutput** | PqMultisigOutput | → **0x09** |
| 0x06 | **DomainRegistrationOutput** | — | — |
| 0x07 | **DomainDeletionOutput** | — | — |
| 0x08 | *(free)* | — | **PqKeyOutput** |
| 0x09 | *(free)* | — | **PqMultisigOutput** |

### 1.2 Transaction **input** variant tags
Their fork adds no new input tags (uses 0xff Base, 0x02 Key, 0x03 Multisig).
PQ inputs were at 0x04/0x05 (no real collision), but are moved to 0x08/0x09
to keep the PQ block contiguous and reserve 0x04–0x07 for the fork's future
domain *inputs*.
| Tag | PQ (was) | PQ (now) |
|-----|----------|----------|
| 0x04 | PqKeyInput | → **0x08** |
| 0x05 | PqMultisigInput | → **0x09** |

### 1.3 Hardfork version  ⚠️ hard collision
| | Fork (PR#14, keep) | PQ (was) | PQ (now) |
|--|--------------------|----------|----------|
| `UPGRADE_HEIGHT_V9` | self-describing outputs + encrypted memos + on-chain DNS | PQ deposits (ML-DSA-65) | — |
| `BLOCK_MAJOR_VERSION_9` | 9 (theirs) | 9 (ours) | — |
| `UPGRADE_HEIGHT_V10` | — | — | **PQ deposits / CIP-0001** |
| `BLOCK_MAJOR_VERSION_10` | — | — | **10** |

PQ becomes the **v10** layer stacked above the fork's **v9**. Mainnet
`UPGRADE_HEIGHT_V10` stays an audit-gated sentinel; testnet activates after
their v9.

### 1.4 Transaction version  ⚠️ hard collision
| | Fork (PR#14, keep) | PQ (was) | PQ (now) |
|--|--------------------|----------|----------|
| `TRANSACTION_VERSION_3` | new self-describing outputs | PQ transactions | — |
| `TRANSACTION_VERSION_4` | — | — | **PQ transactions (CIP-0001)** |

The tx-version byte gates the output-deserialization path. PQ txs carry
version **4**; their self-describing-output txs keep version 3. Output tags
are *also* globally unique (1.1) so the variant is unambiguous regardless of
version dispatch — defence in depth.

### 1.5 TransactionExtra tags — no collision ✅ VERIFIED
Fork `TransactionExtra.h` uses 0x00 PADDING, 0x01 PUBKEY, 0x02 NONCE,
0x03 MERGE_MINING, 0x04 MESSAGE, **0x05 TTL**. PQ's `PQ_MESSAGE` 0x06 and
`AUTH_MESSAGE` 0x07 are free → **kept as-is** (port additively above the fork's
0x05). The fork's "encrypted memos" are carried in the self-describing **output**
(`EncryptedMemo.h` + `NewOutputSerialization.cpp`), NOT a tx-extra tag — confirmed
the extra parse loop handles only ≤ 0x05, so 0x06/0x07 do not collide.

### 1.6 Scheme IDs (agility pins) — no collision
`PQ_KEM_SCHEME_ID 0xC0DE0203`, `PQ_RING_SCHEME_ID 0x52415054`,
`PQ_DSA_SCHEME_ID 0xC0DE0204` — unique, kept.

---

## 2. Re-port map (the fork deleted the homes our hooks lived in)

**Verified fork structure** (the old monolithic `CryptoNoteCore/Blockchain.cpp`
is DELETED and split into a modular `src/Blockchain/*` backed by MDBX — confirmed
by direct inspection, not the stale auto-map):

| PQ hook | Old home (pqc/testnet-poc) | New home (PR#14 base) — VERIFIED |
|---------|----------------------------|-----------------------|
| Tx **input** validation (PqKeyInput ring-sig + nullifier dup-check; PqMultisigInput ML-DSA) | `Blockchain.cpp` `checkTransactionInputs` ~2418–2531 | `src/Blockchain/BlockchainValidation.cpp` (+ `ITransactionValidator.h`) |
| Tx **output** validation (visitor) | `Blockchain.h` `check_tx_outputs_visitor` 451–538 | `src/Blockchain/CheckTxOutputsVisitor.h` |
| Output indexing by amount (`m_pqOutputs`, `m_pqMultisigOutputs`) | `Blockchain.cpp` pushBlock 778–800 | `src/Storage/MDBXBlockchainStorage.cpp` + `src/Blockchain/BlockchainStorage.cpp` |
| Nullifier double-spend set (32-byte) | `Blockchain.h:288` `m_spent_pq_nullifiers` (in-mem) | new MDBX table or in-mem set in `src/Blockchain/` + storage |
| Tx accept / version gate | `Core.cpp` | `src/CryptoNoteCore/Core.cpp` `handle_incoming_tx` ~282; `TransactionPool.cpp` |
| PQ RPC (`get_pq_outputs`, `get_pq_multisig_outputs`) | `PaymentGate/*` | **`src/Rpc/RpcServer.cpp`** (daemon RPC still present): JSON-RPC map ~295, decls `RpcServer.h`, structs `CoreRpcServerCommandsDefinitions.h`; follow the fork's `get_domain` pattern |
| PQ spend builder (`PqSpendBuilder`, `PqSpendClient`) | `Wallet/WalletGreen.cpp` | **`src/Wallet/WalletGreen.cpp`** (still active in Daemon + ConcealWallet CLI; NOT superseded by BoltCore). `selectTransfers` ~2815, `prepareInputs` ~2956. BoltCore TUI = later/stretch |
| Serialization (PQ variants) | `CryptoNoteSerialization.cpp/.h`, `CryptoNote.h` | ✅ done (0x08/0x09 alongside fork's 0x04–0x07) |
| PQ config (heights/versions/schemes) | `CryptoNoteConfig.h` | ✅ done (V10 / BLOCK_MAJOR_10 / TX_V4) |
| PQ message extra | `TransactionExtra.cpp/.h` | ⚠️ 0x06/0x07 free on fork — verify their memo impl; port `TransactionExtra` PQ paths |
| `pqc/ccx-pqc` Rust crate | `pqc/` | ✅ imported; still must wire into fork `CMakeLists.txt` (P2b) |

Clean adds (no conflict): entire `pqc/` crate + all PQ docs (≈138 files).
Hand-resolve: ≈25 files (7 consensus-core content conflicts, Blockchain +
PaymentGate modify/deletes, build files).

---

## 3. Execution checklist

- [x] **P0** Namespace audit + this spec — *done (4 collisions found)*
- [x] **P1** Import `pqc/ccx-pqc` crate + PQ docs into worktree — *done (144 files, commit b1417e15)*
- [x] **P2** Apply unified table: PQ output/input → 0x08/0x09, hardfork → V10/BLOCK_MAJOR_10, tx → V4 — *done (commit cb366ec5; CryptoNote.h variants, serialization, config)*
- [x] **P2b** Wire `pqc/ccx-pqc` into the fork's `CMakeLists.txt` — *done (commit 7355674d)*
- [~] **P3** Re-port validation hooks into the fork's `src/Blockchain/*`:
  - [x] P3a output validation — `CheckTxOutputsVisitor.h` PQ operators + `Currency::validateOutput(PqMultisigOutput)` (tx-v4 gate)
  - [ ] P3b input validation — `BlockchainValidation.cpp`: PqKeyInput Raptor ring-sig verify (ccx FFI) + 32-byte nullifier double-spend; PqMultisigInput ML-DSA verify
  - [ ] P3c output index + nullifier set — `MDBXBlockchainStorage.cpp` per-amount PQ buckets + spent-nullifier table
  - [ ] P3d tx-accept/version gate — `Core.cpp handle_incoming_tx` / `TransactionPool.cpp` admit tx-v4
- [x] **P4** PQ RPC (get_pq_outputs / get_pq_multisig_outputs) into `src/Rpc/RpcServer` — *done*
- [x] **P5** PqSpendBuilder/PqSpendClient compiled into the daemon path (pq_injector e2e harness) — *done*
- [x] **P6** Build GREEN on WSL — conceald + concealwallet + pq_injector + UnitTests link clean
- [~] **P7** Tests: 130/130 unit tests pass (PQ: WalletKdf×21, PqWalletSection, deposits — 2 WalletLegacy flaky-pass-isolated). Live consensus: PQ coinbase validates, blocks connect (caught+fixed check_outs_valid). Live spend: grinding (fork 120s testnet blocks).
- [ ] **P8** Triple review (CodeRabbit + Codex + GLM) — NEXT (vet)
- [ ] **P9** Report; push only on direction

---

## 4. Coordination ask for the fork devs

We are yielding the namespace to your fork. To keep this **bidirectionally**
safe, please **reserve, in your tag table**, the PQ assignments:
output/input tags **0x08 / 0x09**, hardfork **v10 / BLOCK_MAJOR_VERSION_10**,
tx version **4**. Otherwise your next feature re-collides with PQ and we
repeat this exercise. Confirm your "encrypted memos" does not use extra tags
0x06 / 0x07 (PQ message tags).
