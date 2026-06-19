# Post-quantum migration — decisions for the team

*A single dashboard of the open strategic choices for Conceal's post-quantum (CIP-0001) work. Each decision
links to the detailed doc that backs it. Status legend: **OPEN** (team must choose) · **PROVISIONAL** (a lean
exists, needs ratification) · **DECIDED** (this session). Numbers are live/measured where marked — see
[`measured-numbers.md`](measured-numbers.md).*

> **One framing for all of these:** the PoC has removed the *integration* risk (tx format, serialization,
> double-spend set, stealth, wallet send/receive, deposits, messages, the swappable backend slot). What
> remains is **policy + the production crypto + an audit**. Treat every "OPEN" below as a thing to settle
> *before* `UPGRADE_HEIGHT_V9` is lowered to a real height — they converge on that one fork.

---

## D1 — Production privacy scheme  ·  **PROVISIONAL (lean: keep privacy / MatRiCT-Au)**

**The choice.** What signs a *spend* on mainnet. Three families, measured/cited in
[`poc-vs-mainnet-report.md`](poc-vs-mainnet-report.md) §3:

| Option | Privacy | Spend size | Verify | Storage/yr | Maturity | Notes |
|---|---|---|---|---|---|---|
| **A — MatRiCT-Au** (lattice RingCT, log-size) | **full ring + confidential amounts** | ~58 KB | ~45 ms | ~18 GB | research code, builds; **library-ized this session** (`~/matrict-lib`) | the privacy-preserving production target |
| B — keep the lattice **stand-in** | full ring, plaintext amounts | 25–61 KB (ring 2–8) | ~1 ms | ~13 GB | **experimental, unaudited, demo-grade** | the current PoC engine; **not mainnet-safe** |
| C — **Falcon, no ring** (stealth only) | **no sender anonymity** | 6.4 KB | 0.2 ms | ~1.9 GB | NIST-standardized | smallest/fastest, but drops Conceal's core privacy |

**Recommendation: A (MatRiCT-Au), keep privacy.** It's the only option that preserves Conceal's ring +
confidential-amount privacy on a (to-be-audited) lattice construction. Cost is real — a PQ spend is **~68×** a
classical spend (542 B → ~37 KB measured for the stand-in; MatRiCT-Au ~58 KB team-measured) — but C forfeits the
chain's reason to exist and B can't ship unaudited. The swappable backend (`pq_ring_sig.h` C-ABI) lets the
stand-in (B) stay the **testnet** engine while A is integrated + audited; see
[`matrict-integration-plan.md`](matrict-integration-plan.md).

**Depends on / unblocks:** the audit (**D7**), tx-size + fusion (**D3**). **Who decides:** core team — this is the
headline strategic call.

---

## D2 — `UPGRADE_HEIGHT_V9` fork timing & height  ·  **OPEN**

**The choice.** V9 is the single block on which PQ deposits **open** and (under Option 3, **D5**) classical
deposit creation **freezes** — an atomic swap. Mainnet `UPGRADE_HEIGHT_V9 = 5000000` is a far-future,
audit-gated **sentinel**; testnet is `80`. Lowering it to a real height *is* the fork.

- **No voting safety net.** Unlike the upgrade-voting path (`UPGRADE_VOTING_THRESHOLD = 90%`), a hardcoded
  height past the last checkpoint has no soft-fork grace — a botched/uncoordinated height is an
  **unrecoverable chain split**. Set it with checkpoint-grade coordination.
- **It cannot precede its preconditions** (see **D7**): the PQ deposit integration audit-cleared, chain-level
  CoreTests passing, and a working PQ deposit wallet path.

**Recommendation:** keep the sentinel until D7's gates clear; then set V9 to a specific height announced with
the same discipline as a checkpoint, activating PQ deposits + the Option-3 freeze together. **Who decides:**
core team + node operators (coordination). Backs: [`deposit-term-policy-decision.md`](deposit-term-policy-decision.md)
§"Hard dependency sequencing", [`deposit-freeze-impl.md`](deposit-freeze-impl.md).

---

## D3 — Tx-size limit, fusion redesign & denominations  ·  **OPEN**

**The choice.** PQ txs are tens of KB; the current limits don't fit them.

- **`CRYPTONOTE_MAX_TX_SIZE_LIMIT` (~99 KB)** — a MatRiCT-Au multi-input tx approaches it; must be raised (size
  budget depends on **D1**).
- **`FUSION_TX_MAX_SIZE` (~30 KB)** — **every** PQ scheme blows it, so dust consolidation breaks. Needs a new
  size budget *and* likely a **denomination scheme** (PQ output keys are ~1–4 KB; many small outputs are
  costly to fuse).
- **Free-reward zone** (100 KB) holds ~184 classical spends but only ~2 PQ ring-4 spends — fee/throughput
  model shifts (see [`measured-numbers.md`](measured-numbers.md) §E).

**Recommendation:** treat as a bundle gated on **D1** (the scheme sets the sizes); design the fusion +
denomination scheme before any mainnet PQ spend. **Who decides:** core team (consensus sizing). **Note:** the
Option-3 *deposit* path is cheaper (ML-DSA-65, ~2.1 KB, ~10×) and less affected than the *spend* path.

---

## D4 — Retire the fixed testnet KEM ("Option B") for per-recipient keys  ·  **OPEN (mostly done)**

**The choice.** The PoC's coinbase/stealth path uses a **fixed** `PQ_TESTNET_KEM` so any wallet can scan
testnet PQ coinbase. Mainnet must use **per-recipient** ML-KEM keys (real unlinkability). The wallet↔wallet PQ
send path **already** does per-recipient encapsulation; coinbase/stealth must follow on mainnet.

**Recommendation:** confirm per-recipient keys everywhere for mainnet; the fixed KEM is a testnet-only
convenience and must not ship. Low controversy — mostly an implementation cleanup. **Who decides:** core team
(confirm). Backs: [`poc-vs-mainnet-report.md`](poc-vs-mainnet-report.md) §"ecosystem changes".

---

## D5 — Classical deposit-term policy  ·  **DECIDED — Option 3 (this session)**

PQ-only deposits after the fork: classical deposit *creation* is frozen at V9; existing deposits stay
withdrawable. **Implemented + verified e2e** ([`deposit-freeze-impl.md`](deposit-freeze-impl.md),
[`deposit-term-policy-decision.md`](deposit-term-policy-decision.md)). Listed here for completeness — its only
open piece is the activation timing, which is **D2**.

---

## D6 — PQ deposit key privacy: account-key vs per-deposit  ·  **OPEN**

**The choice.** ML-DSA has no stealth-derivation analogue, so a PQ deposit must name a fixed public key.

| Option | Privacy | Restore | Use |
|---|---|---|---|
| **D6a — single account ML-DSA key** | deposits to one wallet are **linkable** by the shared key | trivial (re-derive from seed) | the PoC wallet default |
| **D6b — per-deposit indexed keys** | unlinkable | re-derive indices `0..N` + gap-limit scan on restore | mainnet target |

**Recommendation:** D6a is acceptable for the **testnet PoC** (flag the linkability); adopt **D6b for mainnet**
to preserve deposit privacy. **Who decides:** core team. Backs:
[`pq-deposit-wallet-blueprint.md`](pq-deposit-wallet-blueprint.md) §3.

---

## D7 — Audit scope & sequencing (the hard mainnet gate)  ·  **OPEN**

**The choice.** What must be professionally audited, and in what order, before mainnet. The non-negotiable
gate. Scope at minimum:
- the production ring-sig/RingCT construction (**MatRiCT-Au** per **D1**) + its integration;
- the **ML-DSA-65 deposit** money paths (interest/lock/reorg) + the consensus PQ-input validators;
- **constant-time / side-channel** review of the lattice code;
- the wallet money-path scanning (the output-index alignment fixed this session is wallet-side, but the whole
  scan surface should be in scope).

**Recommendation:** the external audit is **the** mainnet gate — nothing PQ activates on mainnet before it.
Sequence it after the MatRiCT-Au integration stabilizes (so the audited artifact is the shipping one), but
commission the auditor selection early (lead time). **Who decides:** core team + funding. Backs:
[`poc-vs-mainnet-report.md`](poc-vs-mainnet-report.md) §6, [`STATUS.md`](STATUS.md) "Deferred / gates".

---

## D8 — PQ dependency maturity  ·  **OPEN**

**The choice.** The Rust PQ primitives (ML-KEM/ML-DSA via RustCrypto) are pre-1.0. Gate mainnet on
**FIPS-validated / 1.0** crates? **Recommendation:** yes — require FIPS-validated (or equivalently
audited) PQ crate versions before mainnet activation; track upstream. Low-effort to state, real to honor.
**Who decides:** core team.

---

## At-a-glance

| # | Decision | Status | Recommendation | Gates mainnet? |
|---|---|---|---|---|
| D1 | Production privacy scheme | PROVISIONAL | **A — MatRiCT-Au (keep privacy)** | yes (via audit) |
| D2 | V9 fork timing/height | OPEN | set after D7 clears; checkpoint-grade coordination | **is** the fork |
| D3 | Tx-size / fusion / denominations | OPEN | bundle, gated on D1 | yes (for spends) |
| D4 | Retire fixed testnet KEM | OPEN (mostly done) | per-recipient everywhere on mainnet | yes |
| D5 | Deposit-term policy | **DECIDED (Option 3)** | — | timing = D2 |
| D6 | PQ deposit key privacy | OPEN | D6a testnet, **D6b mainnet** | no (privacy) |
| D7 | Audit scope & sequencing | OPEN | external audit = the gate | **the** gate |
| D8 | PQ dependency maturity | OPEN | require FIPS-validated/1.0 crates | yes |

**The critical path:** D1 (scheme) → integrate + D3 (sizing) → **D7 (audit)** → D2 (set V9 height) → coordinated
fork. D4/D6/D8 ride alongside. D5 is done and waits only on D2.
