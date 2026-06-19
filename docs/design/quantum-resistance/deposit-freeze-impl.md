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
- **End-to-end (live 2-node testnet):** see [`verify-deposit-freeze.sh`](../../../pqc/verify-deposit-freeze.sh).
  <!-- RESULTS PENDING: pre-V9 create height, V9 boundary, post-V9 withdraw, post-V9 reject + the daemon
       "classical deposit creation is frozen" log line. Fill from the passing run. -->

## Cost (Option 3)

The freeze itself is a predicate check — **zero size/throughput cost**. The real cost of Option 3 is that the
only post-fork deposit is a **PQ (ML-DSA-65) deposit**, which is larger and slower to verify than the
classical Ed25519 multisig it replaces.
<!-- BENCHMARK PENDING: classical deposit tx size vs PQ deposit tx size (create + withdraw), and ML-DSA-65
     verify vs Ed25519-multisig verify. Fill from the live benchmark; cross-link measured-numbers.md. -->
