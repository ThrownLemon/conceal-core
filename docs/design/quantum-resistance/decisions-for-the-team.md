# Post-quantum migration — decisions for the team

*A single dashboard of the open strategic choices for Conceal's post-quantum (CIP-0001) work. Each links to
the detailed doc that backs it. Numbers are live/measured where marked — see
[`measured-numbers.md`](measured-numbers.md).*

> **Nothing here is decided.** Each item below has a **selected default** — a working assumption chosen *only*
> so the PoC could keep moving — and every default **awaits team consensus** and is **reversible**. Where the
> PoC already *implements* a default (e.g. the deposit freeze), that is an engineering convenience to unblock
> testing, **not** a ratified choice; the team can still change it. The "firmness" tag says how settled a
> default feels, not that it is final: **firm** (clear best option, low controversy) · **lean** (a real
> trade-off to weigh) · **placeholder** (chosen just to unblock; expect debate).

> **One framing for all of these:** the PoC has removed the *integration* risk (tx format, serialization,
> double-spend set, stealth, wallet send/receive, deposits, messages, the swappable backend slot). What
> remains is **policy + the production crypto + an audit**. Every default below should be confirmed or changed
> *before* `UPGRADE_HEIGHT_V9` is lowered to a real height — they converge on that one fork.

---

## D1 — Production privacy scheme  ·  **default (resolved): small-ring PQ lattice linkable ring sig — *Raptor leading*; pending consensus**

> **RING-SIZE FORK DECIDED (team input): keep current ring size (small, ~mixin 6).** That selects the
> **small-ring branch** — **ELRS is out** (its flat ~25 KB STARK floor is *wasted flatness* at ring-6), and the
> scheme is a **small-ring lattice/NTRU linkable ring signature, plaintext amounts**. Leaderboard at Conceal's
> ring size (confirm the exact KB against the real PDFs — eprint was blocked, see
> [`pq-ringsig-verdict.md`](pq-ringsig-verdict.md)):
> - **Raptor** (NTRU, ACNS 2019) — **leading.** ~8–10 KB at ring-6/8 (≈ **5× smaller** than the PoC's in-house
>   lattice stand-in at ~43 KB @ ring-6), **natively linkable**, **NTRU/Ring-SIS reduction** (NTRU is the
>   Falcon/FIPS-205-adjacent family — well-studied), **public Rust PoC** (`zhenfeizhang/raptor`). Linear size,
>   which is *fine* now that rings stay small. Catch: unaudited; ring-6 KB needs confirming (cited at 100-bit).
> - **Harden the in-house lattice stand-in** (the PoC's K=L=6 LSAG) — fallback. Already integrated + working
>   end-to-end, but **demo-grade**: biased sampling, not constant-time, params not a calibrated 128-bit level,
>   and ~43 KB @ ring-6 (≈5× Raptor). Would need a security-level recalibration + constant-time rewrite for
>   mainnet anyway — so "adopt Raptor" vs "harden the stand-in" is the real choice.
> - **MatRiCT+ ring component** (Module-SIS/MLWE, C++, fast verify) — alternative with the *cleanest* assumption
>   (ML-DSA family) and the most mature code, **but** RingCT-coupled (must extract just the plaintext
>   linkable-membership proof; its standalone size isn't isolated in the paper).
>
> **Net:** ELRS demoted; the production target is a small-ring lattice linkable ring sig, **Raptor the leading
> candidate to replace the demo-grade stand-in**. Cheapest de-risk: build Raptor's Rust PoC + benchmark size +
> cold-verify + sign at rings 4/6/8 head-to-head vs the in-house stand-in.

> **DIRECTION UPDATE (team input + this session's benchmarks).** Conceal keeps **plaintext amounts** — its
> **verify-funds feature needs visible amounts** — so **confidential-amount RingCT (MatRiCT-Au) is the wrong
> target**: it *hides* amounts (breaking verify-funds) and costs ~107 KB for a feature Conceal does not want.
> The real PQ job is narrower: make the **ring signature** (untraceability) + **stealth one-time keys**
> (unlinkability, already ML-KEM in the PoC) + **nullifier** post-quantum, **amounts stay plaintext**. That is
> a **PQ linkable ring signature**, not RingCT. So the decision flips from "which RingCT" to "**which PQ ring
> sig**", and the candidates are: the PoC **lattice stand-in** (incumbent, ~6.1 KB/member linear, unaudited),
> **ELRS** (measured flat ~25–29 KB, the size win — gated on the single-verify experiment, §G), and other PQ
> ring sigs from the scan (SPRING, RingSLIP, …). **MatRiCT-Au is demoted** to "only if Conceal ever wants
> confidential amounts — which conflicts with verify-funds." This is a *much cheaper, smaller* PQ path than the
> RingCT route the doc previously defaulted to.

**The choice (original framing — what signs a *spend* on mainnet).** Three families, measured/cited in
[`poc-vs-mainnet-report.md`](poc-vs-mainnet-report.md) §3 — note A (MatRiCT-Au) is now demoted by the update
above because it hides amounts:

| Option | Privacy | Spend size | Verify | Storage/yr | Maturity | Notes |
|---|---|---|---|---|---|---|
| **A — MatRiCT-Au** (lattice RingCT, log-size) | **full ring + confidential amounts** | **~107 KB** *(58 KB only w/ compression — see note)* | ~45 ms | **~33–35 GB** | research code, builds; **library-ized this session** (`~/matrict-lib`) | the privacy-preserving production target |
| B — keep the lattice **stand-in** | full ring, plaintext amounts | 25–61 KB (ring 2–8) | ~1 ms | ~13 GB | **experimental, unaudited, demo-grade** | the current PoC engine; **not mainnet-safe** |
| C — **Falcon, no ring** (stealth only) | **no sender anonymity** | 6.4 KB | 0.2 ms | ~1.9 GB | NIST-standardized | smallest/fastest, but drops Conceal's core privacy |

**Selected default (pending consensus): A (MatRiCT-Au), keep privacy.** It's the only option that preserves
Conceal's ring + confidential-amount privacy on a (to-be-audited) lattice construction. But the cost is bigger
than first recorded — see the proof-size note below — and C forfeits the chain's reason to exist while B can't
ship unaudited. The swappable backend (`pq_ring_sig.h` C-ABI) lets the stand-in (B) stay the **testnet** engine
while A is integrated + audited; see [`matrict-integration-plan.md`](matrict-integration-plan.md).

> **Proof-size correction (measured this session, two independent passes).** The "58 KB" widely quoted for
> MatRiCT-Au is the **paper's *compressed* proof**, NOT a measurement — the reference code ships **no proof
> serializer** and only holds the proof as full in-memory arrays. Library-izing it + a canonical packed
> serializer yields **~107 KB** (n10m1, ring-10/1-in — the same params the paper's 58 KB describes), and that
> is the **information-theoretic floor**: a second pass *measured the realized coefficient distributions* and
> found Fiat-Shamir-with-aborts makes every response coefficient near-uniform over its full norm interval
> (entropy = packed width to <1 bit), so smarter encoding of the responses — which are **73%** of the proof —
> wins **~0 KB** (only a 304-byte safe split exists). **Re-encoding cannot reach 58 KB.**
> The paper's 58 KB instead comes from **high-bit *truncation of the commitments* `b`/`c` + a hint** (Dilithium
> `t1/t0`/`UseHint` style) — a **protocol / soundness-statement change**, not serialization: the FS hash binds
> the *full* commitments, so it needs the **verification equation rewritten + the MatRiCT-Au extractor proof
> redone + the audit**. And **truncating `b` breaks auditability** (`b` is the partially-decryptable commitment
> the audit trapdoor decrypts) — so it also collides with the accountability layer. **Plan on ~107 KB /
> ~33–35 GB/yr** as the realistic baseline; 58 KB / ~18 GB/yr is a *cryptographic-research-grade* sub-project
> (re-implement the paper's truncated construction + re-prove + audit), not a quick add. A PQ spend is **~89×**
> a classical spend at 107 KB.

> **Newer candidates (research scan this session — see [`pq-scheme-landscape.md`](pq-scheme-landscape.md)).**
> MatRiCT-Au is PKC 2022; the field moved. The scan surfaced two that change this decision:
> - **Gao et al. (FC/PKC 2025, eprint 2021/1674)** — looked like the strongest confidential-amounts successor
>   from the abstract, but **benchmarking it this session DID NOT hold up the claim** (see
>   [`measured-numbers.md`](measured-numbers.md) §H): the paper has **no absolute size/time tables** (only
>   plots); its "~50% smaller / ~20% faster" is vs the **original MatRiCT (2019)** — *not* MatRiCT-Au, which is
>   newer than Gao's baseline — and only ~15–20% vs MatRiCT+; under a shared param set the runnable Go ref came
>   out *slightly larger* (the advantage lives entirely in a parameter-set choice the code can't express); the
>   Go impl is **partial** (ring-sig only) and its **MatRiCT baseline doesn't even verify**, so no
>   apples-to-apples is possible. **Verdict: not a demonstrated win over MatRiCT-Au — do not treat as a
>   successor without a multi-week port of its param-set + balance-proof into the MatRiCT-Au C code.**
>   MatRiCT-Au remains the only full, verifying RingCT spend measured here (107.4 KB, ~12 ms verify, 63 ms
>   prove on a Ryzen 5950X).
> - **ELRS / STARK linkable ring sig (ESORICS 2024, eprint 2024/553)** — **measured this session** (built +
>   ran the reference impl): **flat ~25–29 KB at *any* ring size**, 32-byte keys, transparent hash-based. Vs
>   Conceal's lattice ring-sig stand-in (~6.1 KB *per member*, linear) it **wins on size at ring ≈ 5 and the
>   gap explodes** (≈14× smaller at ring-64, ≈225× at ring-1024). **No confidential amounts** — which fits,
>   because **Conceal has *plaintext* amounts today** (confidential was deferred to an optional L2). If amounts
>   stay plaintext, the privacy layer reduces to *PQ linkable ring sig + one-time key + nullifier*, and ELRS
>   could be a **bigger, cheaper win than confidential-amount RingCT at all**. **BUT the focused follow-up sweep
>   (see [`pq-ringsig-verdict.md`](pq-ringsig-verdict.md), confidence ~65%) walked back "ELRS wins outright" —
>   the answer hinges on max ring size, not the crypto:**
>   - **At Conceal's *small* rings (mixin 5–16) — ELRS does NOT win.** Its flat ~25 KB is *wasted flatness*;
>     **linear lattice schemes are SMALLER and have a CLEANER assumption** here: **Raptor** (NTRU, natively
>     linkable, Rust PoC) ~10 KB @ ring-8 / ~21 KB @ ring-16; *LAPQ-LRS* (MLWE/MSIS, ML-DSA family) ~4.4 KB @
>     ring-8 *if its numbers hold*. ELRS's security is *conjectured hash/FRI* (no reduction); the lattice
>     schemes reduce to **Module-SIS/MLWE — the NIST ML-DSA assumptions**. Cleaner footing.
>   - **Only if Conceal grows rings to ≥64–1024** does ELRS's flatness pay off (linear schemes hit MBs there).
>   - **And the verify advantage is CONTESTED** — measured 0.3 ms vs the paper's ~128 ms (amortized-vs-cold);
>     unresolved, needs re-measurement under Conceal's distinct-ring workload.
>   - **So decide *max ring size* first.** "Small rings forever" → a lattice linkable scheme (Raptor /
>     the in-house lattice stand-in), smaller + cleaner-assumption. "Rings may grow" → ELRS (or audit a log-size
>     lattice scheme like LAPQ-LRS). Everything here is unaudited research either way.
>
> **A prior question this forces (decide before locking D1):** *(i) are confidential amounts required, or can
> they stay plaintext?* and *(ii) is on-chain auditability in or out?* Those two answers select
> Gao-vs-ELRS-vs-MatRiCT-Au more than any benchmark. **Reality check:** *no* PQ confidential-anon-payment
> scheme is audited or standardized anywhere (NIST finalized only the FIPS 203/204/205 building blocks) — that
> gate is identical for every option, so it doesn't differentiate. **Cheapest de-risking step:** read Gao's
> real size/verify tables (PolyU PDF, reachable) + build/benchmark its Go reference vs the in-repo MatRiCT-Au
> at Conceal's ring size — before committing.

**Depends on / unblocks:** the audit (**D7**), tx-size + fusion (**D3**), the proof-compression sub-decision,
and the confidential-amounts/auditability fork above. **Who confirms:** core team — this is the headline
strategic call. **Where it stands after this session's benchmarks:** for **confidential amounts**, MatRiCT-Au
is still the only measured, full, verifying RingCT — no scanned alternative (incl. Gao et al.) demonstrably
beats it without major research effort. For **plaintext amounts**, **ELRS is a genuine measured win on size**
(flat ~25–29 KB vs the lattice stand-in's linear growth) — gated on the single-verify experiment. So the live
sub-decision is the **confidential-vs-plaintext fork**, not "which RingCT."

---

## D2 — `UPGRADE_HEIGHT_V9` fork timing & height  ·  **default: stay on the sentinel — placeholder, pending consensus**

**The choice.** V9 is the single block on which PQ deposits **open** and (under Option 3, **D5**) classical
deposit creation **freezes** — an atomic swap. Mainnet `UPGRADE_HEIGHT_V9 = 5000000` is a far-future,
audit-gated **sentinel** (the current default — i.e. PQ never activates on mainnet yet); testnet is `80`.
Lowering it to a real height *is* the fork.

- **No voting safety net.** Unlike the upgrade-voting path (`UPGRADE_VOTING_THRESHOLD = 90%`), a hardcoded
  height past the last checkpoint has no soft-fork grace — a botched/uncoordinated height is an
  **unrecoverable chain split**. Set it with checkpoint-grade coordination.
- **It cannot precede its preconditions** (see **D7**): the PQ deposit integration audit-cleared, chain-level
  CoreTests passing, and a working PQ deposit wallet path.

**Selected default (pending consensus):** keep the sentinel until D7's gates clear; then the team sets V9 to a
specific height, announced with the same discipline as a checkpoint, activating PQ deposits + the Option-3
freeze together. **Who confirms:** core team + node operators (coordination). Backs:
[`deposit-term-policy-decision.md`](deposit-term-policy-decision.md) §"Hard dependency sequencing",
[`deposit-freeze-impl.md`](deposit-freeze-impl.md).

---

## D3 — Tx-size limit, fusion redesign & denominations  ·  **default: deferred behind D1 — pending consensus**

**The choice.** PQ txs are tens of KB; the current limits don't fit them.

- **`CRYPTONOTE_MAX_TX_SIZE_LIMIT` (~99 KB)** — a MatRiCT-Au multi-input tx approaches it; must be raised (size
  budget depends on **D1**).
- **`FUSION_TX_MAX_SIZE` (~30 KB)** — **every** PQ scheme blows it, so dust consolidation breaks. Needs a new
  size budget *and* likely a **denomination scheme** (PQ output keys are ~1–4 KB; many small outputs are
  costly to fuse).
- **Free-reward zone** (100 KB) holds ~184 classical spends but only ~2 PQ ring-4 spends — fee/throughput
  model shifts (see [`measured-numbers.md`](measured-numbers.md) §E).

**Selected default (pending consensus):** treat as a bundle gated on **D1** (the scheme sets the sizes); design
the fusion + denomination scheme before any mainnet PQ spend. Nothing is set yet — placeholder pending the D1
confirmation. **Who confirms:** core team (consensus sizing). **Note:** the Option-3 *deposit* path is cheaper
(ML-DSA-65, ~2.1 KB, ~10×) and less affected than the *spend* path.

---

## D4 — Retire the fixed testnet KEM ("Option B") for per-recipient keys  ·  **default: retire on mainnet — firm, pending consensus**

**The choice.** The PoC's coinbase/stealth path uses a **fixed** `PQ_TESTNET_KEM` so any wallet can scan
testnet PQ coinbase. Mainnet must use **per-recipient** ML-KEM keys (real unlinkability). The wallet↔wallet PQ
send path **already** does per-recipient encapsulation; coinbase/stealth must follow on mainnet.

**Selected default (pending consensus):** per-recipient keys everywhere for mainnet; the fixed KEM is a
testnet-only convenience and must not ship. Low controversy — mostly an implementation cleanup, but still the
team's to confirm. **Who confirms:** core team. Backs:
[`poc-vs-mainnet-report.md`](poc-vs-mainnet-report.md) §"ecosystem changes".

---

## D5 — Classical deposit-term policy  ·  **default: Option 3 (built into the PoC) — pending ratification**

PQ-only deposits after the fork: classical deposit *creation* is frozen at V9; existing deposits stay
withdrawable. This is the default the PoC was **built and verified against** this session
([`deposit-freeze-impl.md`](deposit-freeze-impl.md)) — chosen to unblock end-to-end testing, **not** ratified.
The team can still switch to a softer policy (e.g. **Option 2**, cap classical terms instead of freezing) — the
full option set + trade-offs are in [`deposit-term-policy-decision.md`](deposit-term-policy-decision.md). Its
activation timing is **D2**.

---

## D6 — PQ deposit key privacy: account-key vs per-deposit  ·  **default: account-key (testnet) / per-deposit (mainnet) — pending consensus**

**The choice.** ML-DSA has no stealth-derivation analogue, so a PQ deposit must name a fixed public key.

| Option | Privacy | Restore | Use |
|---|---|---|---|
| **D6a — single account ML-DSA key** | deposits to one wallet are **linkable** by the shared key | trivial (re-derive from seed) | the PoC wallet default |
| **D6b — per-deposit indexed keys** | unlinkable | re-derive indices `0..N` + gap-limit scan on restore | mainnet target |

**Selected default (pending consensus):** D6a for the **testnet PoC** (flag the linkability), **D6b for
mainnet** to preserve deposit privacy. Reversible; team to confirm. **Who confirms:** core team. Backs:
[`pq-deposit-wallet-blueprint.md`](pq-deposit-wallet-blueprint.md) §3.

---

## D7 — Audit scope & sequencing (the hard mainnet gate)  ·  **default: external audit gates mainnet — firm, pending consensus**

**The choice.** What must be professionally audited, and in what order, before mainnet. The non-negotiable
gate. Scope at minimum:
- the production ring-sig/RingCT construction (**MatRiCT-Au** per **D1**) + its integration;
- the **ML-DSA-65 deposit** money paths (interest/lock/reorg) + the consensus PQ-input validators;
- **constant-time / side-channel** review of the lattice code;
- the wallet money-path scanning (the output-index alignment fixed this session is wallet-side, but the whole
  scan surface should be in scope).

**Selected default (pending consensus):** the external audit is **the** mainnet gate — nothing PQ activates on
mainnet before it. Sequence it after the MatRiCT-Au integration stabilizes (so the audited artifact is the
shipping one), but commission auditor selection early (lead time). **Who confirms:** core team + funding.
Backs: [`poc-vs-mainnet-report.md`](poc-vs-mainnet-report.md) §6, [`STATUS.md`](STATUS.md) "Deferred / gates".

---

## D8 — PQ dependency maturity  ·  **default: require FIPS-validated/1.0 crates — pending consensus**

**The choice.** The Rust PQ primitives (ML-KEM/ML-DSA via RustCrypto) are pre-1.0. Gate mainnet on
**FIPS-validated / 1.0** crates? **Selected default (pending consensus):** yes — require FIPS-validated (or
equivalently audited) PQ crate versions before mainnet activation; track upstream. Low-effort to state, real to
honor. **Who confirms:** core team.

---

## D9 — Repo organization for the PQ work  ·  **default: `pq-conceal` R&D fork in the org — pending setup**

**The choice.** Where the PQ work lives. **Hard constraint:** the consensus/wallet changes are *inline edits to
the conceal-core daemon* (`Blockchain.cpp`, `Currency`, `TransactionPool`, …), not a separable library — so
"all PQ in one repo" can only be a **full fork of conceal-core**, and PQ's *destination* is conceal-core itself
(height-gated upstream PRs), not a permanent separate coin.

| Option | What | Pro | Con |
|---|---|---|---|
| A | stay a personal fork branch (today) | zero setup | not an org home |
| **B (selected)** | **`pq-conceal` = full fork in the ConcealNetwork org** | one official R&D home; team CI + a PQ testnet build; everything together | a divergent daemon copy → periodic rebases on upstream; eventual merge-back effort |
| C | `pq-conceal` = only the *separable* parts (Rust `ccx-pqc` + MatRiCT lib + docs/site); consensus stays a conceal-core branch | clean, independently-auditable crypto libs | more repos; an extraction refactor |

**Selected default (team: yes to a repo):** **B for the active R&D phase** — give the work an org home as
`pq-conceal` (fork of conceal-core), understood as a **staging fork** that upstreams to conceal-core piecemeal
and needs periodic rebasing. **Then, as the crypto stabilizes, split out `ccx-pqc` + the MatRiCT lib as
standalone versioned/auditable libraries** (the part of C worth doing — the auditor will want the crypto as a
clean artifact anyway). The **docs + interactive site** move over immediately as the browsable PQ knowledge
base. **Action owner:** core team creates/transfers the org repo (not done by the assistant). **Who confirms:**
core team.

---

## At-a-glance

*All defaults are provisional and reversible — they await team consensus; "firmness" = how settled the default
feels, not that it is final.*

| # | Decision | Selected default | Firmness | Gates mainnet? |
|---|---|---|---|---|
| D1 | Production privacy scheme | **small-ring PQ lattice linkable ring sig — Raptor leading** (ring size decided small; ELRS demoted = wasted flatness; MatRiCT-Au demoted = hides amounts) | lean | yes (via audit) |
| D2 | V9 fork timing/height | stay on sentinel; set after D7 clears | placeholder | **is** the fork |
| D3 | Tx-size / fusion / denominations | deferred, gated on D1 | placeholder | yes (for spends) |
| D4 | Retire fixed testnet KEM | per-recipient everywhere on mainnet | firm | yes |
| D5 | Deposit-term policy | Option 3 (built into PoC) | lean — not ratified | timing = D2 |
| D6 | PQ deposit key privacy | D6a testnet, **D6b mainnet** | lean | no (privacy) |
| D7 | Audit scope & sequencing | external audit = the gate | firm | **the** gate |
| D8 | PQ dependency maturity | require FIPS-validated/1.0 crates | firm | yes |
| D9 | Repo organization | **`pq-conceal` R&D fork in the org** (then split out crypto libs) | lean — team said yes | no |

**The critical path:** D1 (scheme) → integrate + D3 (sizing) → **D7 (audit)** → D2 (set V9 height) → coordinated
fork. D4/D6/D8 ride alongside. D5's default is built but unratified; it waits only on D2 for timing.
