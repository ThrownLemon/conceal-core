# Option-3 classical-deposit freeze — implementation (CIP-0001 UPGRADE_HEIGHT_V9)

*Implements the decision in [`deposit-term-policy-decision.md`](deposit-term-policy-decision.md) (Option 3,
"PQ-only deposits after the fork"). Commit `9c49864` on `pqc/testnet-poc`. This is the consensus half of
Option 3; the end-to-end demonstration and measured cost are in the §Verification and §Cost sections below.*

## The rule

Once the chain reaches `UPGRADE_HEIGHT_V9` — **the same block on which PQ deposits open** — creation of any
new **classical (Ed25519) deposit output** (a `MultisignatureOutput` with `term != 0`) is rejected. From that
height, `PqMultisigOutput` (ML-DSA-65) is the only new deposit path. The rule is **creation-side only**:
spending / withdrawing an already-existing classical deposit stays valid forever, so deposits minted before
the fork are never stranded.

This is the symmetric twin of the existing PQ-enable gate (which *rejects* PQ deposits **below** V9, i.e.
*opens* them at `height >= upgradeHeight(V9)`). The freeze *closes* classical deposits at the same boundary:

| Path | Below `upgradeHeight(V9)` | At / above `upgradeHeight(V9)` |
|---|---|---|
| Classical deposit (`MultisignatureOutput`, `term!=0`) | **allowed** | **frozen (rejected)** |
| PQ deposit (`PqMultisigOutput`) | rejected (PQ-enable gate) | **allowed** |

The classical path closes on exactly the block the PQ path opens — an atomic swap, no one-block gap.

## The predicate

```cpp
// True iff the tx CREATES a classical deposit output (MultisignatureOutput with term != 0).
static bool transactionContainsClassicalDeposit(const Transaction &tx) {
  for (const auto &out : tx.outputs)
    if (out.target.type() == typeid(MultisignatureOutput) &&
        boost::get<MultisignatureOutput>(out.target).term != 0)
      return true;
  return false;
}
```

Defined twice — `Blockchain.cpp:102` and `TransactionPool.cpp:43` (mempool twin, cross-referenced; keep in
sync). A non-deposit multisig (`term == 0`) is unaffected. It inspects **outputs only** — a withdraw tx
(which carries a `MultisignatureInput` and only normal `term==0` outputs) is *not* matched, which is why
withdrawing an existing deposit is never frozen.

## The three gate sites

| Site | File:line | Condition | Role |
|---|---|---|---|
| **Per-tx block-connection** | `Blockchain.cpp:~3158` (in `pushBlock`) | `transactionContainsClassicalDeposit(tx) && block.height >= upgradeHeight(V9)` → `isTransactionValid = false` | **Authoritative consensus rejection.** Directly mirrors the PQ-enable per-tx gate a few lines above. |
| **Coinbase guard** | `Blockchain.cpp:~3101` (in `pushBlock`) | same, on `blockData.baseTransaction`, `m_blocks.size() >= upgradeHeight(V9)` → `m_verification_failed` | Rejects a malicious post-V9 coinbase that tries to mint a classical deposit cell to bypass the freeze. A genuine coinbase never carries one. Mirrors the PQ coinbase guard. |
| **Mempool acceptance** | `TransactionPool.cpp:~283` (in `add_tx`) | `!keptByBlock && transactionContainsClassicalDeposit(tx) && height >= upgradeHeight(V9)` → `tvc.m_verification_failed`, reject | Keeps a frozen deposit out of the pool / relay / block templates, so it never **stalls mining**. Loose txs only — a tx returning from a popped block (`keptByBlock`) was valid when mined and must not be re-rejected. |

### Why `>=` (and never `>`)

The freeze uses `height >= upgradeHeight(BLOCK_MAJOR_VERSION_9)`, mirroring the PQ-enable gate's `<` so the
two activate on the same block. Changing it to `>` would shift the freeze one block relative to PQ-enable and
create a one-block window that is either double-open or double-closed — **a chain split.** This deliberately
differs from the adjacent deposit-term-band gate (`height > m_depositHeightV4`, `Currency.cpp`); the two must
not be "harmonized." (See the decision doc's "Concrete sketch" for the full rationale.)

### What is deliberately NOT gated (or pre-fork funds strand)

The freeze touches only the creation/output path. These remain untouched for already-existing classical
deposits:

- **Spend/withdraw** — `Blockchain::validateInput(MultisignatureInput)` and the deposit-lock rule inside it
  (`output.term != 0 && createBlock + term > height => reject`). The withdraw tx is not matched by the
  predicate (output-only), so it flows normally.
- **Interest accrual** — `getInterestForInput` / `calculateInterest*` / the `input_amount_visitor` deposit
  branch keep computing `amount + interest`.
- **The PQ output validator** (`validateOutput(PqMultisigOutput)`) — must stay the open path; the freeze is
  never applied to it, or *all* new deposits would be closed.

## Activation

No new constant. The freeze rides the existing `UPGRADE_HEIGHT_V9` / `BLOCK_MAJOR_VERSION_9` gate.
- **Mainnet:** `UPGRADE_HEIGHT_V9 = 5000000` — a far-future, audit-gated sentinel past the last checkpoint.
  The freeze is therefore inert on mainnet until V9 is deliberately lowered (an audit-gated, coordinated,
  hardcoded-height fork — no voting safety net; see decision doc §"Hard dependency sequencing").
- **Testnet:** `TESTNET_UPGRADE_HEIGHT_V9 = 80` — the freeze (and PQ deposits) activate at height 80, which
  is what the e2e demo exercises.

## Verification

- **Regression:** `UnitTests`, `CoreTests`, `DifficultyTests`, `HashTargetTests` — **100% pass** with the
  freeze compiled in (no behavioral change below V9; the 1007-gtest PQ-deposit suite still green).
- **End-to-end (live 2-node isolated testnet, `TESTNET_UPGRADE_HEIGHT_V9 = 80`):**
  [`verify-deposit-freeze.sh`](../../../pqc/verify-deposit-freeze.sh) — **PASS, 3 consecutive green runs** (and a
  4th after the anti-stall hardening). The three Option-3 behaviors, all live:

  | # | Behavior | Result | Proof |
  |---|---|---|---|
  | 1 | **Pre-V9** create classical deposit (`MultisignatureOutput`, term=30) | **ACCEPTED** | submitted height 15, mined by 17; `sendrawtransaction → status OK` |
  | 2 | **Post-V9** withdraw of the pre-V9 deposit | **ACCEPTED** | `withdraw` at height 84 → confirmed, deposit status `Withdrawn` (the withdraw tx makes only `term==0` outputs, so the freeze does not catch it) |
  | 3 | **Post-V9** create a *new* classical deposit | **REJECTED** | submitted at height 84 → `status Failed`, never confirmed |

  Literal daemon proof of behavior #3:
  ```
  INFO [txpool] Transaction <dd5b20d4…070d> rejected: classical deposit creation is frozen
  at/after height 80; use a PQ deposit
  ```
  Funding note: the demo builds the classical deposit tx with `pqc/tools/classical_deposit_injector` (a
  harness tool, classical twin of `pq_injector`) because a **pre-existing** testnet coinbase/wallet
  `keyIndex` quirk hides the miner's classical coinbase remainder from wallet scanners — see
  [§Known issue](#known-issue-pre-existing-not-the-freeze). That quirk is orthogonal to the freeze.

## Cost (Option 3)

The freeze itself is a predicate check — **zero size/throughput cost**. The cost of Option 3 is that the only
post-fork deposit is a **PQ (ML-DSA-65) deposit**, larger than the classical Ed25519 multisig it replaces.
Crucially, deposits use **standardized ML-DSA-65 (FIPS 204)** — *not* the experimental lattice ring sig — so
the deposit cost is modest next to a PQ *spend*:

| Deposit op | Classical | PQ (ML-DSA-65) | Ratio | Basis |
|---|---|---|---|---|
| Create deposit tx (1-in, 1 deposit out + change) | **217 B** | **≈ 2.1 KB** | ~10× | classical **[live]** (injector); PQ adds `1952 − 32 = 1920 B` for the ML-DSA pubkey **[FFI-live component]** |
| Withdraw signature | 64 B (Ed25519) | **3309 B** (ML-DSA-65) | ~52× | **[FFI-live]** (`measured-numbers.md` §D) |

For comparison a PQ *spend* (lattice ring sig) is ~25–61 KB (~68× a classical spend); a PQ *deposit* is only
~10× a classical deposit, because deposits need no anonymity ring — just one standardized signature per key.
So "PQ-only deposits after the fork" is one of the cheaper PQ surfaces. See
[`measured-numbers.md`](measured-numbers.md) §F for the full deposit-size table.

## Known issue (pre-existing, NOT the freeze)

Surfaced while building the e2e demo (independently confirmed by code reading): the testnet coinbase
(`Currency::constructMinerTx`, `m_testnet` branch) emits a PQ stealth output at output-index 0 plus a classical
"remainder" `KeyOutput` to the miner at index 1, but both wallet scanners (`TransfersConsumer::findMyOutputs`,
`CryptoNoteFormatUtils::lookup_acc_outs`) walk a `keyIndex` that does not advance over the leading PQ output —
so the miner's classical coinbase remainder is **invisible to every wallet** (wallet shows `0.000000`, `outputs
Count: 0`). The PoC therefore funds wallets only via the PQ path. This is a wallet/coinbase index bug, **not**
related to the deposit freeze and not modified here — flagged for separate human review (it touches money-path
output scanning). The demo works around it with the injector tool.
