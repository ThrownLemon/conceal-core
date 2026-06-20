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

### 1.5 TransactionExtra tags — no collision
Fork uses ≤ 0x04 (PADDING/PUBKEY/MERGE_MINING/MESSAGE). PQ's `PQ_MESSAGE`
0x06 and `AUTH_MESSAGE` 0x07 are free → **kept as-is**.
⚠️ Verify the fork's "encrypted memos" feature does not claim 0x06/0x07 at
deserialize time before finalising.

### 1.6 Scheme IDs (agility pins) — no collision
`PQ_KEM_SCHEME_ID 0xC0DE0203`, `PQ_RING_SCHEME_ID 0x52415054`,
`PQ_DSA_SCHEME_ID 0xC0DE0204` — unique, kept.

---

## 2. Re-port map (the fork deleted the homes our hooks lived in)

| PQ hook | Old home (pqc/testnet-poc) | New home (PR#14 base) |
|---------|----------------------------|-----------------------|
| Tx/output validation | `CryptoNoteCore/Blockchain.cpp` (**deleted** by MDBX rewrite) | MDBX storage / `Blockchain/` + `Core.cpp` validation entry |
| PQ RPC (`get_pq_outputs`, …) | `PaymentGate/*` (**deleted**) | `conceal-rpc` / `BoltRPC` |
| PQ spend builder (`PqSpendBuilder`) | `Wallet/WalletGreen.cpp`, `WalletLegacy/*` | `Wallet/WalletGreen.cpp` (still present); conceal-wallet/BoltCore = stretch |
| Serialization (PQ variants) | `CryptoNoteSerialization.cpp/.h`, `CryptoNote.h` | same files, add 0x08/0x09 alongside their 0x04–0x07 |
| PQ config (heights/versions/schemes) | `CryptoNoteConfig.h` | same, add V10 / BLOCK_MAJOR_10 / TX_V4 |
| PQ message extra | `TransactionExtra.cpp/.h` | same (0x06/0x07 clean) |
| `pqc/ccx-pqc` Rust crate | `pqc/` (138 clean-add files) | drops in clean; wire `CMakeLists.txt` |

Clean adds (no conflict): entire `pqc/` crate + all PQ docs (≈138 files).
Hand-resolve: ≈25 files (7 consensus-core content conflicts, Blockchain +
PaymentGate modify/deletes, build files).

---

## 3. Execution checklist

- [ ] **P0** Namespace audit + this spec — *done*
- [ ] **P1** Import `pqc/ccx-pqc` crate + PQ docs into worktree; wire CMake/Cargo
- [ ] **P2** Apply unified table: remap PQ output/input → 0x08/0x09, hardfork → V10/BLOCK_MAJOR_10, tx → V4 (config + serialization + Rust scheme consts)
- [ ] **P3** Re-port validation hooks into MDBX `Blockchain`/`Core`
- [ ] **P4** Re-port PQ RPC into `conceal-rpc`
- [ ] **P5** Re-port `PqSpendBuilder` into `WalletGreen`
- [ ] **P6** Build green on WSL (MDBX + wxWidgets + Rust `pqc`, `-DWITH_OPENCL=OFF`)
- [ ] **P7** e2e: PQ spend accepted / double-spend rejected / nullifier independent; classical path intact
- [ ] **P8** Triple review (CodeRabbit + Codex + GLM); fix findings
- [ ] **P9** Report; push only on direction

---

## 4. Coordination ask for the fork devs

We are yielding the namespace to your fork. To keep this **bidirectionally**
safe, please **reserve, in your tag table**, the PQ assignments:
output/input tags **0x08 / 0x09**, hardfork **v10 / BLOCK_MAJOR_VERSION_10**,
tx version **4**. Otherwise your next feature re-collides with PQ and we
repeat this exercise. Confirm your "encrypted memos" does not use extra tags
0x06 / 0x07 (PQ message tags).
