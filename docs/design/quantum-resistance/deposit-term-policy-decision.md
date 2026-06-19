# Classical Deposit Terms During the Post-Quantum Transition — Policy Decision

## Executive summary

A classical (Ed25519) deposit created today with a long term matures *later* — possibly after a cryptographically-relevant quantum computer (CRQC) exists — and its funds cannot be moved to a PQ-safe form during the lockup. These long-dated classical deposits are the most quantum-exposed money on the chain. We recommend **Option 3 — PQ-only deposits after the V9 fork**: at `UPGRADE_HEIGHT_V9` / `BLOCK_MAJOR_VERSION_9`, reject the *creation* of any new classical deposit output, making ML-DSA-65 (`PqMultisigOutput`) the only new deposit path, while every already-existing classical deposit runs to maturity and **remains fully spendable on the classical path**. This is the strongest protection but hard-couples to the PQ deposit path being **audit-cleared and live at the same activation height** — that coupling is the central condition the team must confirm.

**Residual exposure (true under every option, state it plainly):** Option 3 makes every *new* deposit PQ-safe at activation, but it does **not** make the chain PQ-safe at activation. Pre-fork classical deposits keep their **Ed25519 spend authorization** until they drain — up to ~1 year past activation under the V3 term band. That draining tail is the irreducible quantum-exposed window, and it is identical under Options 1, 2, 3, and 4: none of them can force-migrate a time-locked deposit. Do not read Option 3 as "PQ-safe at activation"; read it as "no new exposure after activation, with a bounded ~1-year classical-spend tail."

---

## The problem: the maturity-horizon risk

A deposit locks funds for a fixed term; at maturity the spend is authorized by the deposit's signature. For a classical deposit that signature is Ed25519. If a CRQC arrives during the lockup, the spend key may be forgeable at maturity, and — because the deposit is time-locked — the owner **cannot** move the funds to a PQ-safe form mid-term. The exposure window is exactly `term`, set at creation and unchangeable.

**The actual enforced term band (do not overstate this).** For a new deposit at today's height (`height > DEPOSIT_HEIGHT_V4 = 1162162`), the enforced band is:

- **Minimum:** `DEPOSIT_MIN_TERM_V3 = 21900` blocks (~1 month) — `CryptoNoteConfig.h:73`
- **Maximum:** `DEPOSIT_MAX_TERM_V3 = 1*12*21900 = 262800` blocks (~1 year) — `CryptoNoteConfig.h:74`
- **Granularity:** `term % 21900 == 0` (whole-month multiples)

This is enforced in `Currency::validateOutput(uint64_t, const MultisignatureOutput&, uint32_t height)`, `src/CryptoNoteCore/Currency.cpp:1391-1415` (function span); the V3 term-band branch is `1393-1402`, taken when `height > m_depositHeightV4`.

The legacy **5-year** maximum (`DEPOSIT_MAX_TERM_V1 = 64800*20 = 1296000`, `CryptoNoteConfig.h:71`) is **NOT reachable for new deposits.** It applies only in the `else` branch (`height <= 1162162`), so it governed historical deposits only. So the worst-case exposure for a *new* deposit is bounded at ~1 year, not 5. That materially shrinks the problem: any deposit created at height *H* matures by `H + 262800` at the latest. The risk is real but bounded — which is exactly why a creation-time policy (rather than a forced sweep) is sufficient.

`DEPOSIT_HEIGHT_V3` vs `V4` nuance, for the record: V3 (`413400`) activated the current interest formula; V4 (`1162162`, "enforce deposit terms") is purely the term-band **enforcement** switch that tightened the band to 1mo–1yr month-multiples. This is the same height-gating pattern any new deposit-term rule would follow.

---

## What's already settled (do not relitigate)

These are implementation facts from the PQ-deposit PoC, not open policy questions:

- **PQ deposit type exists.** ML-DSA-65 (FIPS 204 / Dilithium-3) plain m-of-n deposits via `PqMultisigOutput` / `PqMultisigInput` (`include/CryptoNote.h:60-76`), gated behind `TRANSACTION_VERSION_3`, serialization tag `0x5`, `BLOCK_MAJOR_VERSION_9` (`CryptoNoteConfig.h:224`), and `UPGRADE_HEIGHT_V9`. Mainnet `UPGRADE_HEIGHT_V9 = 5000000` is a **far-future audit-gated sentinel** (`CryptoNoteConfig.h:118`); testnet activates at `80` (`TESTNET_UPGRADE_HEIGHT_V9`, `:132`).
- **PQ deposits REUSE the existing term band and interest curve.** No new term constant. `validateOutput(PqMultisigOutput)` (`Currency.cpp:1419-1442`) is byte-for-byte identical to the classical path; interest is the same `calculateInterest(amount, term, lockHeight)`.
- **The interest-minting safety item is implemented, not a policy choice.** `check_pq_multisig` binds `input.term == output.term` before any interest is computed (`Blockchain.cpp:3821-3825`), and `output.term` has already passed `validateOutput`'s band check — so interest is always derived from a consensus-validated term.
- **The PoC is built and unit-tested but NOT mainnet-ready.** Implemented and unit-tested on `pqc/testnet-poc` (1007/1007 gtest pass, 11 new PQ tests; `docs/design/quantum-resistance/deposits-mldsa-impl.md:3,218-242`), but testnet-gated + mainnet-sentinel-gated and pushed only as an **UNAUDITED backup branch** (not merged, not mainnet). The `dilithium3` primitive is production-grade NIST FIPS 204; the **integration** (detached-sig handling, message=prefix-hash, constant-time/side-channel) is explicitly **unaudited** and gates mainnet (CIP-0001 C1). Chain-level CoreTests for PQ deposits (spend-after-lock, early-withdrawal reject, deep-reorg integrity) are **not yet written** — the divergent surface has unit tests; the consensus equivalence to the Ed25519 path is asserted by line-for-line port, not directly tested.

The one open policy question is below.

---

## The options

The four core options below are the primary decision frame. One operationally-likely variant (3b, "enable now / freeze later") is added and rebutted, because the team may otherwise drift into it.

| # | Option | Consensus change? | Protection | Cost / UX | Mechanism |
|---|--------|-------------------|-----------|-----------|-----------|
| 1 | Status quo / market choice | **No** (deposit policy) | Weakest — risk sits on depositor | Lowest; no break | Keep classical band; offer PQ at V9; users choose |
| 2 | Cap classical terms as PQ nears | Yes (backward-compat) | Medium — closes the matures-past-horizon hole; keeps a live classical fallback path | Low–medium; classical deposits still allowed, just shorter | Height-gated rule: new classical deposit must mature before a horizon (`block+term < H`, or tighten the cap) |
| 3 | **PQ-only deposits after the fork (RECOMMENDED)** | Yes (backward-compat) | **Strongest** — no new quantum-exposed deposits | Highest; biggest UX/compat break; removes the classical fallback; hard-couples to PQ being live | At V9, reject creation of any new classical deposit output; PqMultisig is the only new deposit path |
| 3b | *(variant)* Enable PQ now, freeze classical in a later audited fork | Yes — but **two** forks | Same end-state as #3, delayed | Defers the freeze; two activation points | Ship V9/PQ now; freeze classical creation in a separate later fork |
| 4 | Term-tiered signature | Yes (backward-compat) | High & precise — targets exposed (long) deposits only; keeps a live short classical path | Highest validator complexity; two live paths | Short locks may stay classical; term beyond a threshold MUST be PqMultisig |

All four core options except #1 are consensus changes. All are **prospective only** — they validate the OUTPUT at *creation* height and never re-validate already-confirmed deposits.

### Option 1 — Status quo / market choice

Keep the classical band as-is; ship PQ deposits at V9; let users pick. **No fork** for the deposit policy itself (V9 still forks for the PQ type). Simplest, zero compatibility break, fully backward-compatible.

The cost: protection is the weakest and the risk sits entirely on the depositor. A user who picks a 1-year classical deposit shortly before a CRQC has no recourse. This is only defensible if we are confident V9 (and PQ adoption) lands well before any CRQC, and we are comfortable letting the market price the risk. Given that we can mechanically remove the hole at low cost, "do nothing" is hard to justify on money-critical code.

### Option 2 — Cap classical terms as PQ nears

A height-gated rule on the deposit OUTPUT validator: a new classical deposit must mature before a horizon. Two formulations (they reject *different* deposits near the boundary — pick deliberately):

- **Term cap:** tighten `m_depositMaxTermV3` for classical deposits created after activation (e.g. drop the 1-year max toward 1–3 months).
- **Horizon check:** reject when `creationHeight + term > H` for a fixed horizon height `H`.

Backward-compatible (new deposits only). It closes the matures-past-horizon hole **without** forcing migration and — critically — **without** requiring PQ deposits to be live: classical deposits still exist, just shorter-dated, so a working deposit product survives even if the PQ path is not ready. This is the softer alternative to #3. The cost is that it leaves classical (quantum-vulnerable) deposits on the chain indefinitely; it manages the risk rather than ending it.

### Option 3 — PQ-only deposits after the fork (RECOMMENDED)

At `UPGRADE_HEIGHT_V9` / `BLOCK_MAJOR_VERSION_9`, reject the **creation** of any new classical deposit output (`MultisignatureOutput` with `term != 0`). PqMultisig (ML-DSA-65) becomes the only new deposit path. This is a **creation freeze**, not a term cap — no new term constant is needed; it reuses the V9 gate the PQ type already rides on.

**Strongest protection:** after activation, no new quantum-exposed deposit can be created at all. The cost is the biggest UX/compat break (the classical deposit product simply ends), the removal of any classical fallback product, and a hard dependency: you **cannot** freeze classical creation unless the PQ deposit path is production-ready and live at the same height, or you leave users with no deposit product. See the concrete sketch and dependency sequencing below.

### Option 3b — *(variant)* Enable PQ now, freeze classical in a later audited fork

Ship V9 with the PQ type enabled but no classical freeze; freeze classical creation later, in a separate dedicated fork once PQ is proven in production. This is the natural hedge if the team is nervous about freezing on an unaudited PQ path, and it is the path the team is most likely to drift into by default — so it is named here explicitly.

**Why we reject it:** it produces two consensus activation points instead of one, doubling the coordinated-fork risk on money-critical code, and the bundling argument (below) applies in full — a single audited activation point is both safer and simpler than two. If the audit timeline is the worry, **Option 2 is the better hedge** than 3b: #2 caps exposure *now* in the same V9 fork with no PQ-liveness dependency and no second fork, whereas 3b leaves the full classical exposure open until a later fork that may itself slip. Treat 3b as the option to avoid, with #2 as its strictly-better substitute.

### Option 4 — Term-tiered signature

Short locks may stay classical; any term beyond a threshold MUST be `PqMultisig`. The most *precise* option — it targets exactly the long-dated deposits that carry the maturity-horizon risk, while preserving the classical path for short locks where the exposure window is negligible. It also keeps a live classical fallback for short terms, so a latent PQ-path bug does not strand all new deposits. The cost is the most validator complexity: two live deposit paths indefinitely, a threshold that itself becomes a consensus constant, and a larger test surface (both paths, plus the boundary). It also still relies on the PQ path being live for the long-tier — so it carries #3's dependency *and* #2's "classical stays on chain" residue.

---

## Recommendation and rationale

**Adopt Option 3.** Rationale:

1. **It is the only option that ends the exposure rather than managing it.** #1 leaves the hole open; #2 and #4 leave classical (vulnerable) deposits on-chain indefinitely. #3 guarantees that after activation, every *new* deposit is PQ-safe. (Existing deposits still drain on the classical path — see Residual exposure.)
2. **It reuses machinery we already have.** The V9 gate, `BLOCK_MAJOR_VERSION_9`, and the validator hook all exist. No new term constant, no new height constant, no second deposit code path to maintain (unlike #4).
3. **Bounded blast radius (for the policy).** The enforced classical band is already only ~1 year (`262800` blocks). Existing deposits run out within a year of activation, so the classical deposit path naturally drains rather than lingering.

**What #3 costs relative to the others, stated plainly:**
- vs **#1**: a real UX break — the classical deposit product ends. #1 keeps user choice; #3 removes it.
- vs **#2**: #2 lets users keep making (shorter) classical deposits with no dependency on PQ being live; #3 forbids classical deposits entirely and therefore **requires** the PQ path to be audited and live at activation. If PQ slips, #2 still ships; #3 cannot.
- vs **#4**: #4 is more surgical (keeps cheap, low-risk short classical locks) at the price of permanent two-path complexity. #3 trades that precision for a single clean path.
- **Single point of failure — the strongest honest argument for #2/#4 over #3.** Because #3 removes the classical fallback entirely, the unaudited PQ path becomes the **sole** deposit product after activation. Any latent bug in that path — detached-signature handling, message=prefix-hash binding, the inline-signature serialization at tag `0x5`, or reorg/index integrity — has **no fallback deposit product** under #3, whereas #2 and #4 keep a working classical path as a safety valve. This is not just a sequencing precondition; it is a standing cost of #3 that raises the bar on the PQ audit and chain-level test gate specifically for this option.

The decisive trade-off: **#3's strength is entirely contingent on PQ deposits being audit-cleared and live at the same activation height.** If the team cannot commit to that audit timeline, **#2 is the correct fallback** (it removes the worst exposure with no PQ-liveness dependency and keeps a live deposit product), and #3 can follow once PQ is audited.

---

## Concrete sketch — Option 3 (creation freeze, height + major-version + audit gated)

No new term constant. The freeze rides the **existing** V9 gate. It must close the classical deposit path on **exactly** the block the PQ deposit path opens — an atomic swap.

### The gate (mirror the existing PQ-enable gate, do NOT mirror the version ladder)

V9 activation is **not** decided by the block-major-version ladder. Both `get_block_major_version_for_height` (`Blockchain.cpp:1154-1180`) and its duplicate `getBlockMajorVersionForHeight` (`:1355-1381`) terminate at `m_upgradeDetectorV8` and have **no V9 branch** (there is no `m_upgradeDetectorV9`). V9 is enforced by a **direct height comparison** in `check_tx_outputs`/block-connection: a PQ deposit is rejected when `block.height < m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_9)` (the per-tx gate near `Blockchain.cpp:3116`, with a matching coinbase guard near `:3068`). `upgradeHeight(BLOCK_MAJOR_VERSION_9)` returns `m_upgradeHeightV9` (`Currency.cpp:196-221`, V9 case at `:218-221`).

So the convention to match is **the existing PQ-enable gate, not the version ladder.** That gate *rejects* PQ below `upgradeHeight(V9)`, i.e. *enables* PQ for `height >= upgradeHeight(V9)`. The classical freeze must therefore fire at:

```
block.height >= m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_9)
```

so the classical path closes on the same block the PQ path opens. Mirroring the version ladder's strict `>` here would be a **bug**: it would shift the freeze by one block relative to PQ-enable and create a one-block window that is either double-open or double-closed — a fork. (The ladder's `>` governs which major version a block *carries*, not output-validity gating; it is the wrong reference.)

**Convention, pinned with rationale:** freeze on `height >= m_upgradeHeightV9` (i.e. `>=`), matching the PQ-enable semantics and the `upgradeHeight()`-based gates used elsewhere — e.g. the V8 difficulty branch at `Currency.cpp:1291` (`height >= m_upgradeHeightV8 && ...`). This **deliberately differs** from the adjacent deposit-term gate, which uses strict `>` (`height > m_depositHeightV4`, `Currency.cpp:1395`). Do **not** "harmonize" the freeze to `>` to match the neighbouring term-band branch — that would silently shift activation by one block and desynchronize the freeze from PQ-enable.

### Placement — co-locate with the existing PQ-enable gate (preferred)

There are two viable hook sites; the choice is a real trade-off, so state it rather than defaulting silently:

- **Preferred — `check_tx_outputs` in `Blockchain.cpp`, adjacent to the existing PQ-enable gate (~`:3116`).** Both halves of the atomic swap — *close classical* and *open PQ* — then live in the same function, are reviewed together, and cannot drift apart in a future edit. All existing V9 deposit-policy gating already lives here (`:3068`, `:3116`); putting the freeze here keeps V9 deposit policy in one place. This is the recommended site.
- **Alternative — `Currency::validateOutput(MultisignatureOutput)` (`Currency.cpp:1391-1415`).** The plumbing works: the OUTPUT validator receives the creation height as `m_height` via `check_tx_outputs_visitor` (`Blockchain.h:452,458,489,521`), fed by `check_tx_outputs(tx, height)`. **But beware the height's provenance:** on the block-**connection** path the visitor is called with `block.height` (`Blockchain.cpp:3131`) — authoritative; on the **mempool** acceptance path it is called with `maxUsedBlock.height` (`Blockchain.cpp:421`, `check_tx_outputs(tx, maxUsedBlock.height)`) — the max height of the blocks the tx's *inputs* reference, which is **not** the height at which the freeze-relevant output will be mined. This is the **same** boundary fuzziness the existing `m_depositHeightV4` term-band gate already carries: a tx created just before activation can pass the freeze check in the mempool (using a lower max-input height) and still be **rejected at block-connection** when re-validated against the real, higher `block.height`. That is acceptable — block-connection (`:3131`) is the authoritative enforcement point — but if you place the freeze in `validateOutput`, name this explicitly rather than claiming the validator "sees the activation height" flatly. Putting the freeze in `Currency.cpp` also **scatters V9 deposit policy across two layers** (Currency term/amount validation vs Blockchain activation gating), inviting exactly the "edit one, forget the other" failure mode.

If the term-validator site is chosen anyway, add a cross-reference comment at **both** the freeze site and the PQ-enable gate so a future editor touches them together.

Illustrative check (C++11 pseudocode), shown at the preferred `check_tx_outputs` site:

```cpp
// Blockchain.cpp, in check_tx_outputs, adjacent to the existing PQ-enable gate (~:3116).
// PQ-ONLY DEPOSIT FREEZE (V9): block CREATION of new classical deposit outputs at/after activation.
// Symmetric with the PQ-enable reject below: classical closes on exactly the block PQ opens.
// Prospective only — never retroactive; never gate the spend/withdraw of existing deposits.
if (transactionContainsClassicalDeposit(tx) &&            // MultisignatureOutput with term != 0
    height >= m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_9)) {
  logger(INFO, BRIGHT_WHITE) << "classical deposit creation rejected at/after V9; use PQ deposit";
  return false;
}
// ... existing PQ-enable gate: reject PqMultisig when height < upgradeHeight(BLOCK_MAJOR_VERSION_9) ...
```

### What MUST NOT be gated (or pre-fork locked funds strand forever)

The freeze is **creation-side only**. Every input-side / interest / lock path for already-existing classical deposits must remain untouched, or deposits minted before the fork can never be withdrawn:

- **Spend/withdraw (input validation):** `Blockchain::validateInput(const MultisignatureInput&)` (`Blockchain.cpp:3680`; declared `Blockchain.h:368`) and the deposit-lock rule inside it at `Blockchain.cpp:3729-3733` (`output.term != 0 && createBlock + term > currentHeight => reject`) must stay valid for existing classical deposits. The PQ twin of this lock rule is at `Blockchain.cpp:3828-3832`; both input paths must keep the lock rule intact. Do **not** add a freeze/version gate to either spend-side validator — that is the load-bearing rule whose preservation prevents fund-stranding.
- **Interest accrual:** `getInterestForInput` (`Currency.cpp:416-425`), `calculateInterest`/`calculateInterestV3` (`Currency.cpp:255-273, 390-414`), and the `input_amount_visitor` deposit branch (`Currency.h:699-709`) must keep computing `amount + interest` for existing classical deposits. Do **not** touch these — the freeze belongs purely in the OUTPUT/creation path.
- **PQ overload:** because the freeze removes the classical path, the PQ OUTPUT validator (`validateOutput(PqMultisigOutput)`, `Currency.cpp:1419-1442`) must remain the open path. Do **NOT** add the freeze to it — that would close *all* new deposits and leave no deposit product.

### Two-duplicate-function caution (orthogonal to the freeze, noted for hygiene)

`get_block_major_version_for_height` (`Blockchain.cpp:1154`) and `getBlockMajorVersionForHeight` (`:1355`) are byte-for-byte duplicates; if you ever change *version selection*, edit **both** or the chain forks. The freeze above does **not** touch them (neither references V9, and the freeze reads `upgradeHeight(BLOCK_MAJOR_VERSION_9)` directly), so this is a general caution, not a step in this change.

### Hard dependency sequencing (the load-bearing condition)

Option 3 freezes the classical deposit product. It is only viable if the replacement is live at the same height. Sequence explicitly:

1. **PQ deposit integration audit-cleared** (CIP-0001 C1: detached-sig handling, message=prefix-hash, constant-time, side channels). Today this is explicitly unaudited.
2. **Chain-level CoreTests written and passing** for the PQ deposit path (spend-after-lock, early-withdrawal reject at `term-1`, deep-reorg index integrity) — currently absent. (Higher stakes under #3: post-freeze, this is the *only* deposit path.)
3. **`UPGRADE_HEIGHT_V9` lowered from the `5000000` sentinel** to a real mainnet height (with matching `TESTNET_UPGRADE_HEIGHT_V9`).
4. **The classical-creation freeze ships in the same fork**, gated on that same height — closing classical and opening PQ on one atomic block.

Steps 1–2 are preconditions; step 4 cannot precede them. If 1–2 slip, fall back to **Option 2** (no PQ-liveness dependency) for that fork.

**(d) coupling — this is a hardcoded-height fork, not a vote-gated one.** Lowering `UPGRADE_HEIGHT_V9` from the sentinel is itself a chain-affecting change that simultaneously activates **both** the PQ deposit type and (under Option 3) the classical freeze on the **same block**, by construction. Unlike the upgrade-*voting* path (`UPGRADE_VOTING_THRESHOLD = 90%`, `CryptoNoteConfig.h:119`, with its voting window/`UpgradeDetector` machinery), a hardcoded height set past the last checkpoint has **no voting safety net** — there is no soft-fork grace, so a botched or uncoordinated height is an **unrecoverable chain split**, not a recoverable soft fork. Set the V9 height with the same coordination discipline as a checkpoint. The sentinel's own comment (`CryptoNoteConfig.h:118`) flags this: do not lower it without an audit and a coordinated fork.

---

## Migration of existing classical deposits

- **No forced sweep.** Deposits are time-locked; they cannot be force-migrated mid-term. Any "sweep" is impossible by construction.
- **They run to maturity untouched, and stay spendable on the classical path.** The freeze is creation-side; existing deposits keep their already-validated terms and accrued interest, and **withdraw via the unchanged classical input path** (`Blockchain.cpp:3729-3733` lock rule + the interest paths above). Because the enforced band caps new classical terms at ~1 year, the classical deposit pool fully drains within ~1 year of activation.
- **Residual quantum exposure (unavoidable, identical across all options).** The classical **spend** authorization of these pre-fork deposits remains **Ed25519** until they drain — up to ~1 year post-activation (`DEPOSIT_MAX_TERM_V3 = 262800`, `CryptoNoteConfig.h:74`). This draining tail is the quantum-vulnerable surface that **no option (1/2/3/4) closes**, because none can force-migrate a time-locked deposit. State it once, plainly: Option 3 stops *new* exposure at activation; it does not retire the *existing* exposure, which retires itself over ~1 year. Do not let "freeze new classical deposits" be read as "spend path is PQ-safe" — the spend/withdraw path for existing classical deposits stays classical by design (and must, per the section above).
- **Grace window vs hard cutover (team decision).** A hybrid grace window would allow classical deposit *creation* for a fixed span after PQ goes live (giving wallets/exchanges time to integrate the PQ path) before the hard freeze. This is implementable as a second height (`freeze height >= activation height`) but adds a constant and a window where new quantum-exposed deposits can still be minted. Hard cutover (freeze == V9 activation) is simpler and maximizes protection; it demands wallet PQ support be ready *at* activation. Recommendation leans hard cutover, contingent on wallet readiness.
- **Encourage early PQ re-deposit.** No protocol mechanism needed: once a classical deposit matures (or for liquid funds), users can voluntarily re-deposit via the PQ path. Surface this in the wallet/UX as the recommended action; do not attempt to automate it on-chain.

---

## Open sub-questions for the team

1. **Boundary convention:** confirm `height >= m_upgradeHeightV9` (freeze live on the first V9 block, symmetric with PQ-enable), **not** `>`. Must match the network exactly and must match the PQ-enable gate, not the version ladder.
2. **Hook placement:** co-locate the freeze with the PQ-enable gate in `check_tx_outputs` (preferred), or place it in `Currency::validateOutput` with cross-reference comments? (See placement trade-off.)
3. **Grace window or hard cutover?** If grace: how long, and does it need its own height constant (and `TESTNET_*` twin)?
4. **Wallet readiness:** will `concealwallet` / `walletd` / block-explorer RPC support PQ deposits *at* activation? (Per the impl report, wallet integration and explorer RPC are currently **not built**.) A hard cutover with no wallet PQ support strands users at the UX layer even though funds are safe.
5. **PQ audit timeline:** can the ML-DSA deposit integration be audit-cleared (CIP-0001 C1) and the missing chain-level CoreTests be written before the chosen V9 height? If not, the team should pre-commit to the **Option 2 fallback** for that fork.
6. **Fallback trigger (with owner):** **the core maintainers** assess audit + chain-test status at **T-60 days** before the target V9 height; if not cleared by then, the named fallback (**Option 2**) ships for that fork instead of #3. Name the go/no-go holder for this assessment in the meeting.

### Decision requested

- [ ] **Confirm Option 3** (PQ-only deposits after the fork) as the policy, with **Option 2 as the named fallback** if the PQ audit/test gate is not met. (Explicitly reject variant 3b in favour of #2 as the hedge.)
- [ ] **Set the activation height** relative to the V9 fork (lower `UPGRADE_HEIGHT_V9` from the `5000000` sentinel to a real height; set matching `TESTNET_UPGRADE_HEIGHT_V9`) — with checkpoint-grade coordination discipline, since this is a hardcoded-height (non-vote-gated) fork.
- [ ] **Decide hook placement** (`check_tx_outputs` co-located vs `Currency::validateOutput`) and the **`>=` boundary convention**.
- [ ] **Decide grace-window vs hard cutover** (and the grace length if any).
- [ ] **Name the go/no-go owner and the T-60d fallback checkpoint.**
- [ ] **Confirm PQ deposits will be audit-cleared, chain-tested, and wallet-supported by that height.**

---

## Consensus / bundling note

**All options except #1 are consensus changes** — they change which deposit outputs nodes accept and can fork the chain if constants or gate conventions diverge between nodes. They are prospective-only (creation-height gated; existing outputs are never re-validated, and existing-deposit spend/interest paths are untouched). Whatever the team picks (#2, #3, or #4) should be **bundled into the V9 fork behind the same audit gate** as the PQ deposit type, plumbed through `CryptoNoteConfig.h` (mainnet + `TESTNET_*`) → `CurrencyBuilder` → `Currency` exactly like `DEPOSIT_HEIGHT_V4` and `UPGRADE_HEIGHT_V9`. Do **not** ship a deposit-policy fork separately from the V9 PQ-deposit fork (this is precisely why variant 3b is rejected) — a single audited activation point is both safer and simpler, and it is the only way to guarantee classical-close and PQ-open land on the same block.

<!-- Finding dispositions:
- HIGH (two-function lockstep is the V9 gate): FIXED — verified both ladders stop at m_upgradeDetectorV8, no V9 branch; retargeted gate to check_tx_outputs height comparison (3068/3116) and demoted the duplicate-function point to a hygiene caution.
- HIGH (gate-convention warning anchored on wrong reference): FIXED — rewrote boundary warning to anchor on the PQ-enable gate (reject when height < upgradeHeight(V9)) and explicitly flagged the ladder's '>' as the wrong reference.
- HIGH (validator placement scatters V9 policy): FIXED — added placement trade-off, recommend check_tx_outputs co-location with the PQ-enable gate; documented the Currency.cpp alternative with cross-ref requirement.
- MEDIUM (mempool maxUsedBlock.height vs connection block.height): FIXED — named the provenance split (Blockchain.cpp:421 vs :3131), authoritative enforcement at connection, same fuzziness as existing term-band gate.
- MEDIUM (residual ~1yr Ed25519 spend tail): FIXED — added to exec summary and migration as an explicit residual-exposure line, identical across all options.
- MEDIUM (missing enable-now-freeze-later variant): FIXED — added Option 3b and rebutted via bundling, with #2 as the better hedge.
- MEDIUM (PQ sole-path blast radius for #3): FIXED — added as an explicit standing cost line in 'What #3 costs', not just a sequencing precondition.
- MEDIUM/LOW (decision owner/deadline): FIXED — added owner (core maintainers) + T-60d checkpoint to sub-question 6 and decision checklist.
- LOW (validateInput line): FIXED — added Blockchain.cpp:3680.
- LOW (deposit-lock 3730-3734 -> 3729-3733 + PQ twin 3828-3832): FIXED.
- LOW (Currency.cpp 1391-1407 range): FIXED — normalized to 1391-1415 function span, term-band branch 1393-1402 (verified: 'if (output.term != 0)' at 1393, V3 branch returns false at 1402).
- LOW (>= vs > convention rationale): FIXED — pinned with Currency.cpp:1291 (V8 >=) precedent and explicit note it differs from the adjacent '>' term gate by design.
- LOW ((d) hardcoded-height vs vote-gated fork): FIXED — added; cited UPGRADE_VOTING_THRESHOLD=90 at CryptoNoteConfig.h:119 (verified line; review said :122 but actual is :119) and sentinel comment :118.
Note: the band granularity uses m_depositMinTermV3 (==21900) for both the lower bound and the modulus, matching the verified code at Currency.cpp:1397; described as 'min 21900 / whole-month multiples' which is faithful.
-->
