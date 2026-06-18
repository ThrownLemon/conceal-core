# Conceal Post-Quantum Strategy — The Decision

**Question:** Before bolting on more PQ fixes, what is the right path for *Conceal specifically*?
Three options:

- **(A) Incremental height-gated hard-fork bolt-ons** — the current path. Add PQ primitives behind new
  `UPGRADE_HEIGHT_*` gates, one surface at a time (spend, stealth, deposits, messages, wallet).
- **(B) Total redesign / new chain** — a clean PQ-native privacy coin, with a migration of existing
  ₡CCX balances onto it.
- **(C) PQ sidechain / L2** — keep the legacy chain as-is, build a PQ-protected sidechain or L2 and
  let value bridge across.

This document weighs them for *this* project — its money-critical legacy C++11 codebase, its small
team, its existing exposed UTXO set, and the experimental ring sig that needs an audit either way —
and gives a staged 3 / 12 / 36-month recommendation plus the migration mechanics if a new chain is
chosen.

**TL;DR recommendation: A now, converging to B later — "incremental on-ramp, planned new-chain
off-ramp."** Continue the height-gated bolt-on path for the next 3–12 months to buy harvest-now
protection for *new* funds and to de-risk the primitives, but treat it explicitly as a *bridge to a
v2 chain*, not the destination. The ring sig must be re-architected and audited before any mainnet
gate regardless of which option wins — that audit is the true critical-path cost and it does not go
away under any option. Do **not** attempt a "big-bang" total redesign as the first move, and do
**not** build a sidechain (it adds a second consensus + bridge to secure and protects nothing the
legacy chain holds).

---

## 1. The forces specific to Conceal

### 1.1 What is actually exposed today (the threat model that matters)

Conceal is a CryptoNote-lineage coin: **ring signatures + stealth addresses (ECDH) + plaintext
amounts** (no RingCT/Bulletproofs). Concretely, against a future cryptographically-relevant quantum
computer (CRQC) running Shor:

| Surface | Crypto | Quantum exposure |
|---|---|---|
| Spend authorization | Ed25519 ring signature + key image | **Broken** — Shor recovers the spend key from any output's one-time public key; key images become forgeable/linkable. This is theft of funds, not just deanonymization. |
| Output stealth | Curve25519 ECDH | **Broken** — Shor recovers view/spend keys, deanonymizing the recipient and enabling spend. |
| Deposits | Ed25519 multisig | **Broken** — same. (Money-critical: interest-bearing locked outputs.) |
| Encrypted messages | Curve25519 ECDH + chacha8 | **Broken confidentiality** (retroactive — every past message is decryptable). |
| Amounts | plaintext | n/a — already public by design. |
| PoW / block hash | CryptoNight (256-bit) | **Adequate.** Grover only halves the search space; 256-bit hashes stay ~128-bit hard. No change needed. (`pow-grover-widening.md` — do not widen the nonce.) |

The honest framing: a CRQC does not merely deanonymize Conceal — **it lets the holder of a quantum
computer spend everyone's coins.** That is a stronger and simpler threat than the "privacy erosion"
story Monero tells about FCMP++ (see §3). It also means **harvest-now-decrypt-later (HNDL) is only
half the problem** for Conceal:

- For **amounts** (plaintext) and **messages**, HNDL is the classic story: data on-chain today is
  decryptable the day a CRQC exists. Migrating *new* traffic does nothing for the historical record.
- For **spend keys**, the exposure is worse and more urgent: **every unspent output's one-time
  public key is on-chain right now.** The instant a CRQC exists, those keys are derivable and those
  coins are stealable — *whether or not the owner ever moves them.* The only defense is to move funds
  to PQ-protected outputs **before** the CRQC exists. This is the single fact that most shapes the
  decision: it strongly favors **getting a usable PQ spend/receive path live and giving users a
  migration window**, and it argues against a multi-year "perfect redesign" that ships nothing in the
  interim.

### 1.2 The codebase reality

- **Legacy C++11, consensus-critical, intentionally un-modernized.** Difficulty/validation/serialization
  are fork-sensitive (`CryptoNoteConfig.h`, `CryptoNoteCore`, `Serialization`). The home-grown KV binary
  format is a wire *and* on-disk compatibility surface.
- **Small team, multi-model-assisted.** No in-house cryptographers; the PoC already leaned on a
  multi-agent review loop. This is the decisive constraint: **the team cannot produce an audited
  novel lattice scheme on its own**, and audit budget/time is the bottleneck, not coding throughput.
- **The PoC works end-to-end** (`pqc/POC-RESULTS.md`): ML-KEM-768 stealth, lattice ring sig with a
  bound nullifier, mempool/chain/restart double-spend protection, all testnet-gated. The crypto-review
  (`docs/reviews/pq-ringsig-crypto-review.md`) found a **CRITICAL universal-forgery** in the ring sig
  (the tag `I` is never bound to a secret in `verify()`), since partially addressed but the scheme is
  **demo-grade params, not constant-time, unaudited** by self-attestation. The performance review puts
  it at **~10× slower verify and ~80× larger** than EC at ring-4 (20.5 KB/sig), with an unbounded-N
  CPU-DoS on the PQ path.

The takeaway from the reviews: **the bolt-on path has already produced a working, mostly-correct
consensus integration. The unsolved part is not the C++ plumbing — it is the cryptographic core (a
small-proof, audited, constant-time PQ linkable ring signature), and that problem is identical under
options A, B, and C.**

---

## 2. Why "is there a better primitive?" mostly doesn't change the decision

A natural instinct is to keep swapping in better primitives (as with the ChaCha20-Poly1305 AEAD that
replaced the legacy chacha8 owner-test — a clear win: real AEAD, tamper-detecting). For the
KEM/signature/AEAD layer this is genuinely worth doing and is low-controversy:

- **ML-KEM-768 (FIPS 203)**, **ML-DSA-65 (FIPS 204)**, **ChaCha20-Poly1305 / AES-256-GCM**,
  **SLH-DSA (FIPS 205)** as a conservative hash-based signature fallback — these are standardized,
  have audited implementations (liboqs, RustCrypto, dalek-adjacent crates), and are the obvious choice.
  Adopting them is the *easy 80%* and the bolt-on path already does it.

But the **hard wall is the anonymity layer**, and here no amount of primitive-shopping rescues you,
because **there is no mature, small-proof, audited post-quantum linkable ring signature or PQ
zk-proof.** Surveying the real options as of mid-2026:

- **Lattice linkable ring sigs (MatRiCT / MatRiCT+ / Raptor / DualRing-style, pqringct/Abelian).**
  Abelian is the only shipping PQ privacy coin built on this family. Signatures are **kilobytes to
  tens of KB** and scale with ring size; the schemes are research-grade and few have independent
  audits. This is exactly the territory our home-grown `ringsig.rs` sits in — and ours is *less*
  mature than pqringct. **If we go lattice-ring, the credible move is to adopt/port an existing,
  published, peer-reviewed scheme (pqringct family) rather than ship our own from scratch.**
- **PQ zk-proofs (STARKs, lattice SNARKs).** STARKs are plausibly PQ-ish (hash-based, no trusted
  setup) and are the most credible long-horizon foundation for a Zcash-style shielded pool, but
  proof sizes/costs are large and the privacy *circuit* still needs PQ commitments and PQ nullifiers
  inside it. Zcash itself is only *targeting* full PQ by **2027** (quantum-recoverable wallets
  shipping June 2026) — i.e. the best-funded shielded chain in the world has not solved this yet.
- **Halo2/Orchard, FCMP++ (Monero, live Q1 2026).** **Not post-quantum.** FCMP++ gives a huge
  anonymity set and forward secrecy for *past* privacy, but it still rests on discrete-log hardness;
  a CRQC still breaks it. Useful as a privacy upgrade, useless as a PQ answer. Mentioned because it is
  the headline 2026 privacy story and it is easy to mistake for a PQ solution — it is not.
- **Mimblewimble (Grin/Beam), FROST threshold sigs, Mina/Aleo.** Either not PQ (MW/Schnorr/FROST are
  discrete-log) or general-purpose proving systems that still need PQ primitives plumbed inside. Not
  drop-in answers.

**Conclusion for §2:** swap in standardized KEM/sig/AEAD primitives freely (do-it). But the ring-sig
choice is a *research selection* problem, not a *patch* problem — and selecting/porting a published
lattice scheme + auditing it is the cost that dominates every option below. **Picking a better
primitive does not let us skip the audit, and the audit is the schedule.**

### Should we port the codebase to Rust?

Separate from the crypto: the C++ daemon does **not** need a wholesale Rust rewrite, and attempting
one would be the most expensive way to *not* improve quantum safety. The right shape — which the PoC
already uses — is a **thin, audited Rust crypto core behind a C-ABI FFI** (`pqc/ccx-pqc`), with the
consensus daemon staying C++11. Rust is the correct language for the *crypto module* (constant-time
discipline, mature lattice/KEM crates, `zeroize`, fuzzing) and the wrong project to take on for the
*whole node* right now. Keep the FFI boundary; harden it (`catch_unwind` on every entry point — partly
done; no panics across FFI; fuzz the deserializers). A full Rust node is a possible **v2-chain**
decision (Zebra demonstrates a Rust consensus node is viable), not a reason to stall the current work.

---

## 3. The three options, scored for Conceal

### Option A — Incremental height-gated hard-fork bolt-ons (current path)

**What it is:** new `PqKeyInput`/`PqKeyOutput` variants, `UPGRADE_HEIGHT_V9+` gates, PQ deposits/messages,
wallet v2 with `ccxpq` addresses, all backward-compatible and replay-via-rebuildCache safe. Users opt
into PQ outputs over a migration window; legacy outputs keep working until a later flag-day.

**Pros (Conceal-specific):**
- **Ships protection for *new* funds fastest** — directly attacks the spend-key HNDL urgency (§1.1).
  A user can move coins into a PQ output *today-ish* and be safe from a future CRQC. No other option
  delivers that sooner.
- **Reuses the existing, mostly-correct consensus integration.** The hard, money-critical plumbing
  (nullifier persistence, reorg-safe index, mempool double-spend, signature-index desync) is **already
  built and reviewed** — the security review's two CRITICALs are documented and fixed.
- **Preserves the chain, the checkpoints, the community, the brand, the exchange listings, the deposit
  history.** Zero migration risk to existing funds (they stay where they are).
- **Governance-light.** Hard forks are the normal upgrade path for this chain; no token migration vote,
  no new ticker, no exchange re-listing campaign.
- **Matches what the strongest peers are doing.** Zcash's actual 2026/2027 plan *is* an incremental
  "quantum-recoverable wallets now, full PQ at the next network upgrade" path on the existing chain —
  not a new chain. We should mirror that staging.

**Cons:**
- **Accretes complexity and dual surfaces.** Every PQ surface doubles a code path (legacy + PQ) in
  consensus-critical files. The KV serialization, validation, and wallet all carry two formats. Long
  term this is a maintenance and audit-surface tax.
- **You inherit the legacy design's bad bones.** Plaintext amounts stay plaintext (HNDL on amounts is
  unfixable by bolt-on — only confidential-amount redesign fixes it, and that's a much larger change
  the team has deferred). The ring-based anonymity model (small rings) is weaker than chain-membership
  proofs and harder to make PQ-efficient than a clean design would be.
- **The 20.5 KB/ring-4 sig and ~10× verify cost** are baked into block size / sync time. Tolerable on
  an opt-in basis; ugly if PQ ever becomes mandatory for all spends.
- **Does nothing for already-exposed historical data** (true of all options).

**Verdict:** **The correct *first* move.** It is the only path that converts the HNDL urgency into
action this year, and it banks the consensus work already done.

### Option B — Total redesign / new chain (with migration)

**What it is:** a clean PQ-native privacy coin — confidential amounts done right, an audited PQ
anonymity layer (lattice ring/RingCT à la pqringct, or a STARK-based shielded pool), PQ wallet/address
format from day one, possibly a Rust node. Existing ₡CCX migrates via burn-and-mint, atomic swap, or a
checkpoint snapshot (mechanics in §5).

**Pros:**
- **No legacy debt.** Single PQ format, confidential amounts, modern anonymity model, clean audit
  surface. This is the *only* option that can also fix the plaintext-amount HNDL problem and adopt a
  larger anonymity set.
- **Strategically honest endpoint.** If Conceal intends to be a serious PQ privacy coin for the next
  decade, this is where it has to land. Bolt-ons asymptotically approach a worse version of this.

**Cons (Conceal-specific, and they are heavy):**
- **Migration is the highest-risk event in a coin's life.** Any burn-and-mint / swap / snapshot risks
  stranding funds, double-issuance bugs, exchange coordination failure, and community splits (chain
  splits are common when a subset rejects the migration). For a small-team coin this is existential
  risk, not just engineering risk.
- **Slowest to deliver HNDL protection.** A from-scratch audited chain is a **24–36+ month** effort
  (Abelian and Zcash timelines confirm the order of magnitude). During that whole window, *new* funds
  are as exposed as old ones. Given §1.1's spend-key urgency, "ship nothing for 3 years then migrate"
  is the worst outcome if a CRQC arrives early.
- **Same audit dependency, larger scope.** You still need the audited PQ ring sig — plus now an audited
  confidential-amount scheme, plus a new consensus, plus migration code. The audit bill multiplies.
- **Throws away working, reviewed consensus integration** from the PoC.

**Verdict:** **The right *destination*, the wrong *first move*.** Pursue it as a planned v2, informed
by what the bolt-on phase teaches about the primitives — not as a big-bang.

### Option C — PQ sidechain / L2

**What it is:** keep the legacy chain; build a PQ-secured sidechain (or rollup) and a two-way bridge;
users move value to the PQ side for safety.

**Cons (decisive for Conceal):**
- **Protects nothing that stays on the legacy chain** — and the legacy chain is where all the exposed
  spend keys live. To be safe a user must bridge, which is exactly the same user action as "move to a
  PQ output" in Option A, but now also requires trusting a bridge.
- **A bridge is the single most-exploited construct in crypto** and would itself need PQ-safe locking
  on the legacy side — which is the very problem we can't solve on the legacy chain. You'd be securing
  funds behind an Ed25519 multisig peg the CRQC breaks.
- **Doubles the consensus + networking + ops burden** for a small team that already can't staff an
  audit.
- **The sidechain still needs the same unsolved PQ anonymity primitive.** No primitive is saved.

**Verdict:** **Not worth it.** It adds a bridge and a second chain to secure while solving none of the
hard problems. Discard.

---

## 4. Staged recommendation (3 / 12 / 36 months)

The audit of the anonymity layer is the critical path under every option, so the plan front-loads
*de-risking the primitive* and *protecting new funds*, and defers the irreversible new-chain decision
until those are known.

### Next 3 months — stabilize the bolt-on testnet; choose the ring-sig strategy
1. **Decide the ring-sig sourcing question (highest-leverage decision in this whole document).**
   Strongly prefer **adopting/porting a published, peer-reviewed lattice scheme (pqringct/MatRiCT+
   family)** over shipping the home-grown `ringsig.rs`. Re-implementing a from-scratch novel scheme +
   getting it audited is a multi-year cryptographer-grade effort the team cannot resource; a published
   scheme has a paper to audit *against*. If a published scheme can't be ported cleanly, the honest
   conclusion is "PQ anonymity is not ready to ship to mainnet yet" — and the message/deposit/stealth
   PQ work (which *can* ship) should proceed independently of it.
2. **Land the non-anonymity PQ surfaces toward mainnet readiness** behind height gates, since they use
   standardized, auditable primitives: **deposits → ML-DSA-65** (`UPGRADE_HEIGHT_V9`), **messages →
   ML-KEM-768 + ChaCha20-Poly1305**, **stealth → ML-KEM-768**. These give real HNDL protection on
   confidentiality and deposit-auth with far less audit risk than the ring sig. Complete the wallet-v2
   blocker (deterministic FIPS-203 `KeyGen(d,z)` from the mnemonic seed).
3. **Fix the documented open items** before any PR off testnet: unbounded-N CPU-DoS cap on the PQ
   path, v3 money-conservation on `pushBlock`, the mixed-tx signature-index desync, ASAN on the reload
   path, uniform `catch_unwind`. Run the required pre-PR triple review on the consensus/crypto diff.
4. **Communicate the threat honestly to the community** (the spend-key HNDL framing of §1.1) and float
   the staged plan, so governance for an eventual flag-day/migration starts forming now.

### Next 12 months — ship opt-in PQ on mainnet for the auditable surfaces; budget the audit
5. **Hard-fork opt-in PQ stealth + deposits + messages onto mainnet** behind `UPGRADE_HEIGHT_*`,
   *if and only if* their primitives are standardized and the integration passed audit/triple-review.
   Give users a way to move funds into PQ-protected outputs — this is the concrete HNDL win.
6. **Get the anonymity layer audited** (the chosen lattice scheme + its consensus integration:
   nullifier binding, ring resolution, constant-time verify). **Budget real money and 6–12 months of
   calendar for this** — it is the gate for *any* PQ spend on mainnet, and it is unavoidable under A
   and B alike. Treat "the ring sig needs an audit either way" as a fixed cost already on the books.
7. **Run the v2-chain feasibility study in parallel** (confidential amounts, anonymity model, Rust
   node, migration mechanics) so the 36-month decision is informed, not rushed.

### 36 months — decide and execute the endpoint
8. **Branch point:** if the bolt-on path has produced a clean, audited, performant PQ spend path that
   the team is comfortable maintaining, the new chain may be unnecessary — keep iterating
   incrementally (Zcash-style). If the legacy debt (plaintext amounts, small rings, dual formats,
   serialization tax) has become the dominant problem, **execute the planned v2 new-chain migration**
   (§5) — now de-risked because the primitives and wallet were proven on the bolt-on chain first.
9. **Whichever endpoint:** by here, *new* funds should have been PQ-protectable for ~2 years, so the
   migration (if chosen) is unhurried and can use the safest mechanics rather than a panic flag-day.

**Why this ordering beats "just pick B now":** it delivers HNDL protection for new funds in year 1
(addressing the spend-key urgency), it spends the scarce audit budget on a primitive that's reusable
under either endpoint, and it keeps the irreversible, community-splitting new-chain decision until
after the hard cryptographic question is answered.

---

## 5. Migration mechanics (if/when a new chain is chosen)

If Option B is executed (year 3), the migration must move ₡CCX onto the v2 chain without stranding
funds, double-issuing, or splitting the community. Three mechanisms, in increasing order of safety for
*this* coin:

1. **Checkpoint snapshot + genesis allocation (recommended).** Pick a flag-day height on the legacy
   chain (a hardcoded checkpoint — Conceal already maintains these). Snapshot the UTXO set; the v2
   genesis credits each legacy output a claimable v2 output. **Crucial PQ subtlety:** the claim must be
   authorized by something a CRQC can't forge by the claim deadline — ideally users *pre-register* a
   PQ claim key on the legacy chain *before* the snapshot (via the Option-A PQ output path), so the
   claim is PQ-authenticated, not Ed25519-authenticated. This is the strongest argument for doing
   Option A *first*: it lets the eventual migration be quantum-safe instead of relying on the broken
   legacy keys at claim time.
   - *Pros:* no live bridge, no double-issuance window, clean ledger.
   - *Cons:* one-time coordination; unclaimed funds need a long (multi-year) or indefinite claim window
     and a clear policy; exchanges must support the snapshot.

2. **Burn-and-mint.** Users send legacy ₡CCX to a provably-unspendable burn output; a relayer/bridge
   mints the equivalent on v2 against a PQ-authenticated claim. More flexible timing than a snapshot,
   but introduces a minting authority/bridge to secure and a double-mint failure mode. Acceptable only
   with the same PQ pre-registration so the burn proof can't be forged by a CRQC.

3. **Atomic swap.** Trustless cross-chain swaps (HTLC-style) let holders move at will. *Poor fit here:*
   HTLCs rely on hash-locks (fine, PQ-ok) **and** signatures (Ed25519 on the legacy side — CRQC-broken),
   and they require a liquid counterparty/market. Useful as a *supplementary* exit, not the primary
   migration path.

**Recommended combination:** checkpoint-snapshot as the primary, PQ-pre-registered claim path, with a
long claim window and an optional burn-and-mint relay for stragglers. **Do not** make migration depend
on legacy Ed25519 signatures being valid at claim time, because the entire premise is that those
signatures may be forgeable by then.

---

## 6. Honest limits

- **None of this protects already-exposed historical data.** Past amounts (plaintext) and past
  messages (ECDH) are HNDL-lost the day a CRQC exists, under every option. Only *future* traffic and
  *unspent, migrated* funds can be protected. Set expectations accordingly.
- **The audit is the schedule and the budget.** Every option requires an audited PQ anonymity layer;
  the team cannot self-certify a novel lattice scheme. If audit money/time isn't real, the realistic
  scope shrinks to the standardized surfaces (KEM stealth, ML-DSA deposits, AEAD messages) and the
  anonymous PQ *spend* stays testnet-only — which is still a meaningful, honest improvement.
- **No CRQC-timing certainty.** The plan hedges: it ships protection early (good if quantum is near)
  while deferring the irreversible new-chain bet (good if quantum is far). It is deliberately not
  optimized for either extreme.
- **Confidential amounts are out of scope of this decision** (team-deferred) but are the strongest
  reason a v2 chain would eventually be worth it; revisit when scoping Option B.

## Sources / precedents

- Monero FCMP++ (live Q1 2026) — large anonymity set + forward secrecy, **explicitly not post-quantum**
  (still discrete-log). [xgram.io](https://xgram.io/blog/is-my-monero-quantum-proof),
  [quasa.io](https://quasa.io/media/monero-s-privacy-revolution-fcmp-ushers-in-the-largest-anonymity-set-in-crypto-history)
- Zcash post-quantum roadmap — quantum-recoverable wallets June 2026, full PQ targeted **2027**;
  incremental on the existing chain, not a new chain.
  [Decrypt](https://decrypt.co/367250/zcash-targeting-post-quantum-crypto-milestone-by-2027),
  [CoinDesk](https://www.coindesk.com/tech/2026/05/08/zcash-to-roll-out-quantum-recoverable-wallets-within-a-month-go-quantum-proof-by-2027)
- Abelian / pqringct — the lattice-based PQ privacy precedent (MatRiCT family); kilobyte-scale sigs.
  [Abelian/Medium](https://medium.com/abelian/from-post-quantum-cryptography-to-post-quantum-blockchains-and-cryptocurrencies-an-introduction-eb0b50ed129a)
- SoK on PQ attackers vs blockchain. [arXiv 2512.13333](https://arxiv.org/html/2512.13333v1)
- Internal: `pqc/POC-RESULTS.md`, `docs/reviews/pq-{security,ringsig-crypto,performance}-review.md`,
  `docs/design/quantum-resistance/{REMAINING-WORK,pow-grover-widening,wallet-address-v2}.md`,
  `src/CryptoNoteConfig.h`.
