# Conceal Post-Quantum Strategy — Synthesis & Recommendation

**Status:** Decision brief. Synthesizes four sub-analyses (Rust port, crypto
modernization, greenfield design, the strategic decision) into one
recommendation answering the three questions the team asked before continuing
to bolt PQ fixes onto `pqc/testnet-poc`.

**Date:** 2026-06. **Scope:** analysis only — no source changes.

Companion documents (read for detail):
- `strategy-rust-port.md` — Q1, port to Rust
- `strategy-crypto-modernization.md` — Q2, modern crypto options
- `strategy-greenfield-design.md` — Q3, ideal from-scratch design
- `strategy-decision.md` — incremental vs. new-chain vs. sidechain

---

## TL;DR

1. **Port the daemon to Rust? No.** Keep growing the small Rust crypto island
   you already run behind C-ABI FFI. This is exactly what Zcash (`librustzcash`
   behind `zcashd`) and Monero (FCMP++/Carrot Rust libs over `monerod`) did —
   **neither rewrote its C++ daemon.** A rewrite delivers zero quantum
   resistance and buys chain-fork risk.

2. **Adopt better modern crypto? Yes — and you already started.** The
   ChaCha20-Poly1305 AEAD you swapped into the PQ `0x06` message field is the
   right call; reuse it. Then do the cheap, high-value, **non-consensus** wallet
   fixes now (Argon2id KDF, deterministic seed-based PQ keygen, an AEAD tag for
   legacy messages, golden-vector tests around the serializer).

3. **Ideal greenfield redesign? It hits the same wall.** A from-scratch Rust PQ
   privacy coin lands on the *same cryptographic core* the PoC already targets,
   because the ceiling is cryptographic, not architectural. Greenfield buys
   safety and maintainability, **not more privacy.**

**The one hard truth, true under every option:** there is **no mature,
small-proof, audited post-quantum linkable ring signature or PQ zero-knowledge
proof** as of mid-2026. Our experimental `ringsig.rs` is unaudited,
non-constant-time, demo-grade — *by necessity, not by neglect.* Even
better-funded peers confirm this: Zcash's full PQ protocol (Project Tachyon) is
only **targeted for 2027**; Monero's FCMP++ (live Q1 2026) is explicitly **not
post-quantum**; the only shipping lattice-PQ privacy chain, **Abelian/pqringct**,
pays for it with kilobyte-to-tens-of-kilobyte transactions and a dedicated
cryptography team.

**Recommended posture:** *Incremental on-ramp now, planned new-chain off-ramp
later.* Ship the standardized PQ surfaces (stealth, deposits, messages) on the
existing chain via height-gated hard forks this year; treat a v2 chain as the
honest eventual destination, not the first move. The single deliverable that
gates "real PQ privacy" under **all** options is an **audited anonymity layer** —
fund that, and strongly prefer porting a published scheme over shipping the
home-grown ring sig.

---

## The four analyses agreed more than they disagreed

All four independently converged on the same load-bearing fact: **the blocker is
cryptographic, not linguistic and not architectural.** Rust does not solve it
(Q1). Modern AEAD/KDF do not touch it (Q2). Starting over does not conjure it
(Q3). Every path routes through the same gate — an anonymous + linkable +
constant-time + calibrated + **audited** lattice ring signature — and that gate,
not lines of code, dominates the timeline.

### The two apparent disagreements, resolved

**(a) "do-it-incrementally" (Q1, Q2, decision) vs. "depends" (Q3 greenfield).**
Not a real conflict. Q3's "depends" is conditional: greenfield is justified
*only if the legacy C++/serialization/FFI debt is itself the dominant pain* — and
even then it does not improve privacy. The decision analysis already absorbs this
as the **planned off-ramp**: incremental now *because* it ships protection this
year, new chain later *because* it is the only path that can also fix plaintext
amounts and a stronger anonymity model. Resolution: **incremental first, v2 as a
deliberate, de-risked destination — not either/or.**

**(b) "harden the ring sig in Rust" (Q1) vs. "port a published scheme"
(decision).** Q1 says make the ring sig production-grade in Rust as the
high-value work; the decision analysis says *prefer porting a published,
peer-reviewed scheme (pqringct/MatRiCT family) over the home-grown `ringsig.rs`.*
These are the same conclusion at different resolution. Resolution: **the venue is
Rust; the source should be a published scheme, not our hand-rolled one.** The
crypto review found a CRITICAL universal-forgery class in the home-grown
construction — that settles it. *Do not* self-certify a novel lattice ring sig.

---

## Q1 — Should we port conceal-core to Rust?

**Answer: No daemon rewrite. Grow the island.**

The ratio is the whole argument: **~92,400 LOC of C++** across 19+ libs vs. a
**~1,022 LOC Rust island** (`pqc/ccx-pqc`) behind **33 hardened `extern "C"`
entry points**. The new, attacker-facing, quantum-relevant crypto is already tiny
and isolated in Rust. The large, battle-tested, **consensus-byte-defining** C++
should stay put.

- **Precedent is unanimous.** `librustzcash` behind `zcashd`; Monero's
  FCMP++/Carrot Rust libs over C++ `monerod`. Neither rewrote the node. The
  island model the PoC already built (staticlib, `#[no_mangle]`, `catch_unwind`,
  `panic=unwind` pinned) matches them.
- **A full rewrite is a Zebra-scale, multi-year, fork-risk-dominated program**
  (Zebra took ~3+ years with a *funded foundation team*) and delivers **zero**
  quantum resistance. Reaching byte-parity on just the consensus subset
  (crypto + CryptoNoteCore + Serialization + P2p, ~37k LOC) is ~15–40
  engineer-months / 2–4 calendar years at this team's staffing.
- **Fork risk, not LOC, is the real cost.** Any one-byte divergence in the
  homemade KV serializer, CryptoNight, LWMA difficulty, or a hard-fork height
  gate splits the chain. A rewrite needs a full historical-chain
  differential-replay harness as its own major deliverable.
- **Where C++ MUST remain the source of truth:** `src/Serialization`
  (wire+disk byte format), `CryptoNoteConfig.h` + `CryptoNoteCore` validation
  (what blocks the network accepts), `crypto/` PoW + ed25519 ops, P2p/protocol
  framing. **Rule: if changing the output by one byte forks the chain, C++
  owns it.**

**What this does NOT solve:** memory safety for the 92k LOC of C++ block
validation / mempool / P2P-RPC parsing / serialization — the classic CVE surface
stays in C++. Each new FFI seam is a hand-audited `unsafe` boundary (we already
hit ABI-shape and panic-boundary bugs). And **no amount of Rust solves the
quantum blocker.**

---

## Q2 — Are there better modern crypto options to adopt?

**Answer: Yes — and the AEAD swap you just did was the right instinct. Do the
non-consensus Tier-1 fixes now; gate everything consensus behind hard fork +
audit.**

The stack splits cleanly into safe wallet/message fixes and dangerous consensus
changes.

### Tier 1 — do now (non-consensus, client-side, ~2–4 weeks + targeted review)

- **Wallet file KDF/cipher (highest value-to-risk).** Confirmed in code: wallet
  is encrypted with **chacha8 (8-round, unauthenticated)** keyed by a **single
  unsalted pass of `cn_slow_hash_v0`** over the raw password — a genuinely weak
  KDF protecting funds at rest. Replace with **Argon2id (salt + tunable cost) +
  XChaCha20-Poly1305 AEAD**; load-only legacy support + migrate-on-open. No fork.
- **Deterministic, seed-based PQ keygen (must precede PQ funds).**
  `kyber768::keypair()` / `dilithium3::keypair()` currently use the **library
  RNG, not the wallet seed** → **PQ keys are not mnemonic-restorable**, a
  funds-loss regression. FIPS 203/204 specify deterministic seed-based keygen;
  derive a PQ seed from the master seed via domain-separated SHAKE. Bundle with
  the wallet-format change.
- **Legacy `0x04` message field.** chacha8 + a 4-zero-byte "owner check" that is
  **not a MAC** (unauthenticated/malleable). Freeze `0x04` to decrypt-only; add a
  ChaCha20-Poly1305 AEAD tag for classical messages — **reuse the PQ `0x06` AEAD
  code already written and tested.** Tx-extra is not consensus-validated, so this
  is backward-compatible.
- **Golden-vector tests around the KV serializer (urgent).** It is
  simultaneously the wire, disk, and tx-extra format and is
  consensus-hash-observable. **Do NOT refactor it** — that forks the chain and
  resets all checkpoints. Add golden-vector + round-trip tests + a canonical-
  layout spec. Urgent *because PQ fields are being added to it by hand* (silent-
  fork risk).

### Tier 2 — policy/economics decision, NOT a bug (consensus hard fork)

- **PoW is CryptoNight v0** — the oldest, most ASIC-saturated variant. **RandomX**
  is the proven successor (Monero abandoned the whole CN family for it), but it is
  a disruptive consensus hard fork (new `UPGRADE_HEIGHT_V*`, ~2 GB dataset,
  pool/miner coordination, its own audit). **PoW needs no PQ change** — Grover
  only halves hash security and difficulty absorbs it. Do this *only* if ASIC
  centralization is a real CCX problem, and **never combine it with the PQ fork**
  (two large consensus changes at once multiplies fork risk).

### Tier 3 — owned by the PQ track / a greenfield concern

- **Ed25519/Curve25519** are classically strong and Shor-broken; their
  replacement *is* the lattice ring-sig + ML-KEM migration. No separate action;
  do not churn the curve layer. The **wholesale serializer swap** to a schema'd
  format (Protobuf/SSZ/Borsh) = effectively launching a new chain → belongs to
  Q3, not a fix.

**What this does NOT solve:** none of Tier 1 touches **amount confidentiality**
(amounts stay plaintext — no RingCT/Bulletproofs) or the **PQ-ring-sig maturity**
problem. It hardens the wallet and messages; it does not modernize the consensus
serializer (stays schema-less forever unless you launch a new chain).

---

## Q3 — What would an ideal from-scratch PQ privacy coin look like?

**Answer: It looks like the PoC's target architecture — minus the legacy C++
chassis, FFI seam, and CryptoNote per-amount tables; plus a clean codec and a
global commitment tree. Same cryptographic ambition, because the ceiling is the
same.**

- **Ledger:** UTXO is unambiguously correct (natural privacy, local nullifiers,
  parallel validation). One refinement CryptoNote lacks: a **single global
  output-commitment tree + nullifier accumulator** (Zcash-shaped), which
  future-proofs for an eventual zk one-of-many proof.
- **The wall (most important):** every privacy coin needs sender-ambiguity +
  recipient-stealth + amount-hiding **simultaneously with small artifacts.** PQ
  replaces recipient-stealth (ML-KEM) and auth (ML-DSA) **cleanly and small.** It
  **cannot** replace sender-ambiguity proofs or amount-range proofs small —
  lattice ZK is 1–2 orders of magnitude larger, and **there is no production
  small PQ zk-SNARK.** Greenfield does not touch this.
- **Sender-privacy options, rated:** (a) PQ lattice linkable ring sig —
  buildable but research-to-bespoke; Abelian/pqringct is the only production
  instance; the PoC's ring-of-4 is ~24.7 KB and demo-grade. (b) PQ zk shielded
  pool — **not mature**; even Zcash leads with quantum-*recoverable* (not
  quantum-*resistant*) wallets and schedules the real PQ proof for ~2027.
  (c) Decoy/CoinJoin — mature crypto, weaker operational privacy. (d) FHE —
  research-grade, too slow for an L1 base layer.
- **Amounts:** **plaintext is the honest best-achievable-2026 choice** (Monero
  ran plaintext 2014–2017). Lattice confidential amounts cost tens of KB and only
  make sense if you've already paid for the full heavy lattice-RingCT core.
  **Pedersen + Bulletproofs (Monero/Grin/Beam) are Shor-broken — must NOT be used
  in a PQ design.**
- **Settled/easy primitives (validates Q2):** ML-DSA-65 workhorse signatures;
  Falcon/FN-DSA only where its 0.65 KB sig dominates *and* a constant-time impl
  exists; SLH-DSA/SPHINCS+ for long-lived genesis/governance keys; **ML-KEM-768 +
  ChaCha20-Poly1305 AEAD** for key agreement and messages — *the PoC's choices
  here are already ideal.*
- **Consensus & language:** PoW is the lower-risk PQ choice (256-bit hash stays
  ~128-bit under Grover, no nonce widening). Rust end-to-end is the strongest
  greenfield decision (memory safety in money code, no FFI seam) but does **not**
  retire the audit requirement on the novel lattice crypto.

**Verdict:** do not greenfield to chase better PQ privacy — the cryptographic
ceiling is identical. Greenfield only if the legacy chassis debt is the dominant
pain. It buys safety/maintainability, not privacy.

---

## The decisive Conceal-specific fact: spend-key harvest-now

For Conceal the dominant force is that **every unspent output's one-time public
key is already on-chain.** A future cryptographically-relevant quantum computer
(CRQC) does not merely *deanonymize* — it lets an attacker **spend everyone's
coins**, whether or not they ever move. This **spend-key HNDL urgency** strongly
favors *speed*: get a usable PQ receive/spend path live and give users a
migration window. **Only the incremental path delivers that this year.**

Corollary for any eventual v2 migration: use checkpoint-snapshot + genesis
allocation with **PQ-pre-registered claim keys** (registered via the incremental
PQ output path *before* the snapshot), so claims are quantum-authenticated, not
Ed25519-authenticated. **Never make migration depend on legacy signatures being
valid at claim time** — that is the single strongest reason to do incremental
first.

**Sidechain/L2 is rejected:** it protects nothing left on the legacy chain, adds
a bridge pegged behind CRQC-breakable Ed25519, doubles ops burden, and still
needs the same unsolved PQ anonymity primitive. Near-zero quantum benefit.

---

## The one hard truth, and what it means for ALL options

> **There is no mature, small-proof, audited post-quantum linkable ring
> signature or PQ zk-proof anywhere as of mid-2026.**

This is *the* constraint. It means:

- **Patching conceal-core** can ship the standardized 80% (ML-KEM stealth,
  ML-DSA deposits, AEAD messages) **on audited primitives** — but PQ anonymous
  *spend* stays testnet-grade until the ring sig is audited.
- **Rewriting in Rust** changes none of this. (Q1)
- **Greenfield** changes none of this — the ceiling is identical. (Q3)
- **A sidechain** changes none of this and protects nothing already on-chain.
- **Better-funded peers confirm it:** Zcash full-PQ → **2027 target**; Monero
  FCMP++ (Q1 2026) → **explicitly not post-quantum**; Abelian/pqringct → the lone
  production lattice-privacy precedent, at **kilobyte-scale transactions.**

Therefore the **audit of the anonymity layer is the schedule** under every
option (6–12 months + real money), and the home-grown `ringsig.rs` (CRITICAL
forgery class found in review, non-constant-time, ~10× slower / ~80× larger than
EC) should be **replaced by a ported, published, peer-reviewed scheme**, not
shipped as-is. **If that audit budget is not real, PQ anonymous spend stays
testnet-only and scope shrinks to the standardized surfaces** — which is still a
genuine, shippable improvement and the correct fallback.

**What nothing protects:** already-exposed historical data. Past plaintext
amounts and past ECDH-encrypted messages are harvest-now-decrypt-later-lost the
day a CRQC exists, under every option. Only *future* traffic and *unspent,
migrated* funds can be protected — which again argues for shipping the
incremental receive/spend path and migration window **soon.**

---

## Staged plan for Conceal

### Next 3 months — land the cheap wins, choose the ring-sig sourcing, communicate

- **Tier-1 crypto modernization (non-consensus, no fork):** wallet
  Argon2id + XChaCha20-Poly1305 (migrate-on-open); deterministic seed-based PQ
  keygen (FIPS 203/204) **before any PQ funds exist**; AEAD tag for legacy `0x04`
  messages reusing the `0x06` code; **golden-vector + round-trip tests around the
  KV serializer** (urgent — PQ fields added by hand).
- **Harden the FFI island:** audit the 33 `extern "C"` boundaries; fix the open
  review items (null-deref, output-sum overflow bypass, heap/uninit crash,
  sig-index, DoS/money-conservation).
- **Decision gate — ring-sig sourcing:** commit to **porting a published lattice
  scheme (pqringct/MatRiCT family) into the Rust island**, or formally scope PQ
  anonymous spend *out* of mainnet until funded. **Do not ship `ringsig.rs`.**
- **Communicate the threat honestly** to the community (spend-key HNDL, what is
  and isn't protected).

### Next 12 months — incremental PQ hard fork for the standardized surfaces

- **Hard-fork, opt-in PQ stealth + deposits + messages + wallet-v2** onto
  mainnet, height-gated behind a new `UPGRADE_HEIGHT_V*` and length-bounded
  exactly as the PoC does — on **audited standardized primitives** (ML-KEM-768,
  ML-DSA-65, ChaCha20-Poly1305, SLH-DSA fallback). This gives users a PQ
  receive/spend path and a **migration window** addressing spend-key HNDL.
- **Fund and run the anonymity-layer audit** of the ported ring sig (the real
  critical path). PQ anonymous *spend* reaches mainnet **only if/when audited;**
  otherwise it stays on `pqc/testnet-poc`.
- **Run v2 (new-chain) feasibility in parallel** — Rust-everywhere, clean codec,
  global commitment tree, plaintext-or-confidential-amounts decision, PQ-pre-
  registered claim-key migration design. Feasibility only; no commitment yet.
- **Keep RandomX (if pursued at all) as a separate fork** — never bundled with
  the PQ fork.

### Next 36 months — decide: keep iterating, or execute the v2 off-ramp

- With the anonymity layer audited (or definitively shown immature), **decide
  between continuing to iterate the existing chain vs. executing the v2 migration**
  — now de-risked by 12 months of pre-registered PQ claim keys.
- The v2 chain is the only path that can *also* fix **plaintext amounts** (lattice
  confidential amounts, Abelian-class) and a **stronger anonymity model** — but it
  is a 24–36+ month, existential-migration-risk effort (stranded funds, double-
  issuance, exchange coordination, chain-split). Execute **only** when the PQ
  privacy primitive is proven and a migration with PQ-pre-registered, quantum-
  authenticated claim keys is ready.
- **Migration mechanics if chosen:** checkpoint-snapshot + genesis allocation to
  PQ-pre-registered claim keys; burn-and-mint as a straggler relay; atomic swaps
  only supplementary (HTLCs lean on CRQC-broken Ed25519). **Never** depend on
  legacy signatures being valid at claim time.

---

## Bottom line

Stop debating Rust-rewrite vs. greenfield as if either unlocks PQ privacy —
**neither does.** Do the cheap, high-value, non-consensus wallet/message
modernization now (you already started, correctly, with the AEAD swap). Keep the
new crypto in the small audited Rust island behind FFI, exactly like Zcash and
Monero. Ship the standardized PQ surfaces incrementally this year to open a
migration window against the **spend-key harvest-now** threat that is uniquely
urgent for Conceal. And recognize that the **single deliverable gating real PQ
privacy under every option — patch, rewrite, or greenfield — is an audited
anonymity layer.** Fund that audit and port a published scheme; if you cannot,
scope PQ anonymous spend to testnet and ship the standardized surfaces anyway.
Treat the v2 chain as a deliberate, de-risked off-ramp — the honest destination,
not the first move.

---

## Sources (peer-timeline verification, mid-2026)

- [Zcash to roll out quantum-recoverable wallets within a month, go quantum-proof by 2027 — CoinDesk](https://www.coindesk.com/tech/2026/05/08/zcash-to-roll-out-quantum-recoverable-wallets-within-a-month-go-quantum-proof-by-2027)
- [Zcash Targeting Post-Quantum Crypto Milestone by 2027 — Decrypt](https://decrypt.co/367250/zcash-targeting-post-quantum-crypto-milestone-by-2027)
- [Is My Monero Quantum-Proof? — xgram.io](https://xgram.io/blog/is-my-monero-quantum-proof) (FCMP++ live Q1 2026, explicitly not a complete PQ solution)
- [Monero FCMP++ Upgrade Explained — baltex.io](https://baltex.io/blog/ecosystem/monero-fcmp-plus-plus-upgrade-explained-xmr-users)
- [Abelian (ABEL) Whitepaper — lattice RingCT, LWE-based](https://download.pqabelian.io/release/docs/whitepaper.pdf)
- [A Survey and Comparison of Post-quantum and Quantum Blockchains — arXiv:2409.01358](https://arxiv.org/pdf/2409.01358)
