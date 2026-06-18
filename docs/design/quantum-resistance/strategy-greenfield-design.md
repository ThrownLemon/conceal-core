# Q3 — The Ideal Greenfield Post-Quantum Privacy Coin

**Scope.** If you threw away the CryptoNote codebase and designed a privacy coin from
scratch *today* (June 2026) for post-quantum (PQ) security, what is the ideal
architecture? This document answers that concretely — ledger model, privacy mechanism,
amount confidentiality, signatures, key agreement, consensus, serialization, language —
and rates each option by **real-world maturity**, grounded in both the conceal-core PoC
(`pqc/`, branch `pqc/testnet-poc`) and external precedents (Monero, Zcash/Orchard/Tachyon,
Iron Fish, Grin/Beam Mimblewimble, Abelian/pqringct, MatRiCT/LRCT/Raptor, FIPS 203/204/205).

**The one-sentence answer up front.** A greenfield design hits the **exact same wall** the
PoC hit: *there is no mature, small-proof, audited post-quantum privacy primitive.* Starting
over buys you a clean architecture and removes legacy debt, but it does **not** unlock a
better cryptographic core. The best *buildable-today* PQ privacy coin in 2026 looks
remarkably like what the PoC already targets — **bigger decoy rings + plaintext amounts +
ML-KEM stealth + ML-DSA auth** — just cleanly architected instead of bolted onto a
2014-era C++ fork. The only materially better core (lattice RingCT, à la Abelian) exists in
production exactly once, is heavy (multi-KB to tens-of-KB transactions), and is not the kind
of thing you bootstrap quickly or safely without a cryptography team.

---

## 1. The wall, stated precisely (read this first)

Every privacy coin needs three secrets kept simultaneously: **who sent** (sender ambiguity),
**who received** (recipient unlinkability / stealth), and **how much** (amount
confidentiality). The classical toolbox solves all three with small artifacts:

| Property | Classical primitive | Size | PQ status |
|---|---|---|---|
| Sender ambiguity | LSAG/CLSAG ring sig (Monero), or zk one-of-many (Zcash) | ~1–2 KB ring; ~200 B SNARK | **no small PQ equivalent** |
| Recipient stealth | ECDH one-time keys | 32 B | **ML-KEM replaces cleanly (1.1 KB)** |
| Amount hiding | Pedersen commitment + Bulletproof range proof | ~700 B | **no small PQ equivalent** |
| Spend auth / no double-spend | EdDSA + key image / nullifier | 64 B | **ML-DSA/Falcon replace cleanly (0.7–3.3 KB)** |

The two rows with "**no small PQ equivalent**" are the whole problem. They rely on the
discrete-log group (` G` over Curve25519/BN254/Pallas), which Shor breaks. The PQ
replacements are **lattice** constructions, and lattice zero-knowledge is **orders of
magnitude larger** than its discrete-log counterpart:

- A Bulletproof range proof is ~700 bytes. A lattice range proof is **single-digit to
  low-tens of KB**.
- A CLSAG ring signature over 16 decoys is ~2 KB. A lattice one-out-of-many proof over the
  same ring is **tens of KB** even with the best 2024–2025 academic schemes.
- A Halo2/Groth16 zk-SNARK proof (Zcash, Iron Fish) is a few hundred bytes — but the SNARK
  itself rests on elliptic-curve pairings/IPA, so it is **not** post-quantum. There is **no
  production, recursive, succinct, post-quantum zk-proof system** suitable for a shielded
  pool today. (STARKs are PQ-plausibly-sound but are 10s–100s of KB and have their own
  hash-soundness caveats; nobody runs a shielded pool on them.)

So the greenfield architect faces the same fork in the road as the PoC:

1. **Accept big.** Use a lattice RingCT / lattice ring signature and pay tens of KB per
   transaction (Abelian's actual answer).
2. **Accept less privacy.** Keep plaintext amounts and lean entirely on decoy-set sender
   ambiguity + PQ stealth (the PoC's pragmatic answer, and effectively Monero-minus-RingCT).
3. **Wait.** Bet on a future small-proof PQ primitive that does not yet exist in audited,
   constant-time form.

Greenfield does not give you a fourth door. It just lets you walk through door 1 or door 2
without dragging a decade of CryptoNote serialization debt behind you.

---

## 2. Ledger model: **UTXO**, not account

This is the one easy, unambiguous call — and notably it is **not** what conceal-core would
need to change, since CryptoNote is already UTXO.

**Choose UTXO (one-time-output model).** Reasons, all of which survive the PQ transition:

- **Privacy is natural in UTXO.** Each output is a fresh one-time key; there is no long-lived
  on-chain "account" to correlate. Account-based privacy (à la Aleo/Mina records, or
  Zcash's note commitments) is achievable but essentially *re-introduces* a UTXO-like
  note/record set underneath, so you pay the complexity anyway.
- **Nullifier/double-spend logic is local.** A spend reveals a per-output nullifier (PQ:
  derived from the lattice tag `I = A₂·s`, as the PoC already does — `nf = SHAKE256(I)`),
  checked against a global spent-set. This is exactly Zcash's nullifier model and the PoC's
  `m_spent_pq_nullifiers`. Accounts force a global mutable-balance state that is harder to
  make private and harder to parallelise.
- **Parallel validation & pruning.** UTXO validation is embarrassingly parallel and the
  output/commitment set can be a Merkle/accumulator that prunes spent state.

**Account model only wins** if you want rich smart-contract state (Ethereum/Aleo-style). A
privacy *coin* (payments, deposits, messages — conceal-core's actual feature set) does not
need it, and account state is a privacy liability. **Verdict: UTXO. Maturity: production
(every major privacy coin).**

One refinement worth adopting greenfield that CryptoNote lacks: **a single output-commitment
accumulator** (Merkle tree of all outputs, Zcash-style) rather than CryptoNote's
"global-index per amount" table. This is what makes large, uniform anonymity sets cheap to
reference and is the structural prerequisite for ever upgrading to a zk one-of-many proof
later. The PoC's `m_pqOutputs[amount]` table is the CryptoNote pattern; a greenfield design
should use one global tree instead.

---

## 3. Privacy mechanism (sender ambiguity) — the hard core

This is the decision that defines the coin. Honest maturity ratings:

### 3a. PQ linkable ring signatures (decoy-set, lattice) — **buildable, heavy, the realistic core**

The family the PoC is reaching for. You hide the real spender in a ring of `N` decoy outputs
and prove "I own one of these and here is its nullifier" without revealing which.

| Scheme | Type | Signature/proof size (ring ~ tens) | Maturity |
|---|---|---|---|
| **Naïve "try-each-key" ML-DSA + tag** (PoC's `lib.rs` baseline) | decoy SET, *not* anonymous | ~3.3 KB × ring | works, but verify learns the signer → **not real anonymity** |
| **AOS/LSAG lattice ring** (PoC's `ringsig.rs`) | anonymous + linkable | ring-of-4 ≈ **24.7 KB** | **experimental, demo params, not constant-time, unaudited** |
| **Raptor** (Lu–Au–Zhang, eprint 2020/1121) | anonymous + linkable | grows ~linearly in ring; tens of KB | published, prototype, not productionised |
| **MatRiCT / MatRiCT⁺** (Esgin et al., Monash/QANplatform line) | full RingCT (ring + amounts) | ~tens–low-hundreds of KB depending on ring; verify ~23 ms | **most mature lattice RingCT research**; basis of Abelian |
| **LRCT v1/v2 (Lattice RingCT)** | RingCT, MIMO wallets | hundreds of KB historically | research, Hcash-targeted |
| **Falafl / DualRing-LB / one-of-many lattice Σ-OR** | logarithmic-ish ring proofs | tens of KB, log-ish in `N` | active 2023–2025 research; not in production |

**Real-world anchor — Abelian (pqringct).** This is the *only* production cryptocurrency
shipping lattice linkable ring signatures + lattice confidential amounts (it descends from
the MatRiCT/RingCT-lattice line and uses CRYSTALS-Dilithium/Kyber primitives). It proves the
category is *deployable* — and also proves the cost: Abelian transactions are large, its
crypto is bespoke, and its privacy/throughput tradeoffs (multi-tier privacy with an opt-in
"full" mode) exist precisely because the heavy mode is heavy. **If you want a genuinely
PQ-confidential greenfield coin, Abelian's pqringct is the closest existing blueprint, and
forking/learning-from it beats reinventing the ring sig.**

**Honest rating:** *buildable today but research-grade-to-bespoke.* A correct, constant-time,
calibrated-parameter, **audited** anonymous lattice linkable ring signature is a
cryptography-team, multi-quarter, six-figure-audit effort — not an application-engineering
task. The PoC's `ringsig.rs` is structurally real (it *is* an AOS/LSAG-over-module-SIS
construction with a sound link tag) but explicitly demo-grade: small dimensions, schoolbook
(non-NTT) multiplication, biased sampling fixed only partially, no constant-time guarantees,
no audit. Greenfield does not change this one bit — you would write the *same* primitive.

### 3b. PQ zk-proofs (shielded pool) — **not mature; do not bet the design on it**

The Zcash/Iron Fish model: a single shielded pool where a succinct zk-proof attests
"I spent a valid note and created valid notes, balances preserved" with a ~200-byte proof and
a huge (whole-chain) anonymity set. **This is the gold standard for privacy — and it has no
post-quantum instantiation in production.**

- Zcash's Groth16 (Sapling) and Halo2 (Orchard) both rest on elliptic curves → **Shor-broken.**
- Zcash's actual PQ plan (**Project Tachyon**, roadmap targeting ~2027) leads with
  **"quantum-recoverable wallets"** — a migration/safety layer, *not* a deployed PQ shielded
  proof — and openly schedules the real PQ proof system for later. Even the best-funded
  shielded-pool team in the space is **not** claiming a production PQ zk-SNARK in 2026.
- Lattice-based zk-SNARKs/STARKs exist on paper (LaBRADOR, Greyhound, lattice IOPs, and
  hash-based STARKs which are plausibly PQ). None is a drop-in, audited, small-proof shielded
  pool. STARK proofs are 10s–100s of KB; recursive lattice SNARKs are early research.

**Honest rating:** *research-grade.* A greenfield coin that *requires* a small PQ zk-proof to
hit its privacy target is betting on cryptography that does not yet exist in deployable form.
Designing the **ledger** so it *could* adopt such a proof later (a global commitment tree,
nullifier accumulator, note-based outputs) is wise and cheap. Designing the **privacy
guarantee** to depend on it today is not.

### 3c. Decoy-set / CoinJoin (no special PQ primitive) — **mature, the safe floor**

Strip the fancy crypto: get sender ambiguity from **mixing** rather than from a per-tx ring
proof.

- **CoinJoin / collaborative transactions** (Wasabi/JoinMarket style, Mimblewimble's interactive
  aggregation): privacy comes from many parties co-signing one transaction. The only crypto
  needed is **a PQ signature (ML-DSA/Falcon)** — which is mature. Privacy quality depends on
  coordination and participation, not on a heavy proof.
- This is fully PQ-ready *today* with zero exotic primitives, because it leans only on
  signatures + hashing. The cost is UX/liveness (you need counterparties) and weaker, more
  heuristic privacy than ring sigs or shielded pools.

**Honest rating:** *production-mature crypto, weaker/operational privacy.* A pragmatic
greenfield coin can use this as a **fallback or complementary** layer and ship immediately.

### 3d. FHE (fully homomorphic encryption) — **not for an L1 base layer**

FHE-based confidential transactions (encrypt balances, compute on ciphertext) are advancing
(Zama's fhEVM, TFHE) and most FHE schemes are lattice-based hence plausibly PQ. But FHE is
**orders of magnitude too slow and too large** for a base-layer privacy coin's per-tx hot
path, and the privacy model (threshold-decryption / committee) reintroduces trust. Useful for
confidential-compute L2s; **not** the privacy core of a payment coin.

**Honest rating:** *research-grade for this use case.* Do not base a coin on it in 2026.

### Verdict on 3

A greenfield coin in 2026 picks **one of two honest cores**:

- **Heavy/private:** lattice linkable ring sig + lattice amount commitments (Abelian's path).
  Genuinely confidential, genuinely PQ, **tens of KB per tx**, needs a crypto team + audit.
- **Light/pragmatic:** large decoy ring (or CoinJoin) for sender ambiguity, **plaintext
  amounts**, PQ stealth + PQ auth. Buildable now with mature primitives, weaker privacy
  (amounts visible), KB-scale tx. **This is essentially what the PoC targets.**

There is no third "small *and* fully private *and* PQ *and* audited" option. That is the wall.

---

## 4. Amount confidentiality

| Option | What it costs | PQ maturity | Recommendation |
|---|---|---|---|
| **Plaintext amounts** (PoC choice; conceal-core today) | amounts public; relies on denomination/decoys for partial cover | trivially PQ (it's just an integer) | **Best-achievable-2026 default.** Honest, simple, sound. Monero *before* RingCT (2014–2017) ran this way for years. |
| **Lattice commitments + lattice range proof** (MatRiCT/Abelian) | tens of KB per output; bespoke crypto + audit | research-to-bespoke (Abelian ships it) | Only if you commit to the heavy/private core in §3a and have the crypto team. |
| **Pedersen commitments + Bulletproofs** (Monero/Grin/Beam) | small & beautiful | **Shor-broken** (discrete log). Grin's "switch commitments" only ease a *future* migration; they are not PQ confidentiality. | **Do not use in a PQ design.** This is a classical-only answer. |
| **No amounts at all** (fixed-denomination outputs only, Zerocoin-style) | huge UTXO bloat, poor UX | PQ-fine | niche; not recommended as the only mechanism |

**Verdict.** If you take the pragmatic core, **plaintext amounts are the correct, honest
choice** — and crucially they are the *same* engineering whether you patch conceal-core or
start fresh. Confidential amounts are only worth it if you have already paid for the heavy
lattice RingCT core, since the range proof is the bulk of that cost anyway. Bolting
lattice-confidential amounts onto an otherwise-light design buys little privacy for enormous
size. **Plaintext now; design the output format so a `v2` confidential-amount field can be
height-gated in later** (exactly the PoC's variant-tagged, upgrade-height-gated discipline).

---

## 5. Signatures (spend auth, deposits, coinbase)

This is the **mature, easy** part — NIST standardised it (FIPS 204/205, with Falcon as FN-DSA
forthcoming). Choose per-use-case by the size/speed tradeoff:

| Scheme | Pub key | Sig | Notes | Best use |
|---|---|---|---|---|
| **ML-DSA-65** (Dilithium, FIPS 204) | 1.95 KB | ~3.3 KB | fast, no float, RNG-free keygen possible; the PoC's deposit + auth backend | **Default for spend auth & deposits.** Conservative, no constant-time float hazards. |
| **Falcon / FN-DSA-512** (FIPS 206 draft) | 0.9 KB | **0.65 KB** | **smallest** PQ sig; but **floating-point Gaussian sampling** → constant-time hazard, hard to implement safely | Where size dominates (e.g. address/UTXO-heavy paths) **and** you can use a vetted constant-time impl. |
| **SLH-DSA** (SPHINCS+, FIPS 205) | 32 B | 8–50 KB | **hash-based, most conservative security** (no lattice assumption), stateless, slow, large sigs | **Genesis/checkpoint/governance keys, long-lived high-value keys** where you want zero lattice risk and rarely sign. |

**Verdict.** A greenfield design uses **ML-DSA-65 as the workhorse** (matches the PoC),
**Falcon only where its 0.65 KB sig materially helps and a constant-time impl is available**,
and **SLH-DSA for the handful of long-lived, rarely-used keys** (genesis, emergency
governance) to hedge against a future lattice break. This "hybrid by role" posture is the
2026 best practice and is identical greenfield-vs-patched. Note: in a *ring* context the
spend signature is the lattice ring sig from §3a, **not** a bare ML-DSA — ML-DSA is for the
non-anonymous auth paths (deposits, coinbase, governance).

---

## 6. Key agreement / stealth (recipient unlinkability)

**ML-KEM-768 (Kyber, FIPS 203). Settled, mature, fast, small-ish.** This is the cleanest win
in the entire PQ transition and the PoC already does it end-to-end:

- Stealth one-time output keys: sender encapsulates to the recipient's ML-KEM public key,
  publishes the ciphertext (`PqKeyOutput.kemCt`, ~1.1 KB), recipient decapsulates to recover
  the spend key. Only the KEM-secret holder can detect/spend → genuine recipient
  unlinkability. The PoC demonstrates this live.
- Encrypted on-chain messages / memos: ML-KEM-768 + **ChaCha20-Poly1305 AEAD** (the modern
  AEAD the PoC just swapped in — authenticated, tamper-evident, replacing the legacy
  chacha8 owner-test). This is exactly right and is itself an example of "adopt the modern
  option": ChaCha20-Poly1305 is the current best-practice symmetric AEAD, PQ-fine (symmetric),
  and constant-time by design.

**One greenfield refinement worth the cost:** address format carries the **1184-byte ML-KEM
public key** (as `wallet-address-v2.md` plans). Greenfield, you would also bake in
**deterministic FIPS-203 `KeyGen(d,z)` from the mnemonic seed** from day one — the PoC notes
this as an unbuilt blocker (`kyber768::keypair()` is RNG-based; you need a crate exposing the
derand keygen). Starting fresh lets you pick that crate up front instead of retrofitting.

**Verdict:** ML-KEM-768 for KEM/stealth, ChaCha20-Poly1305 for AEAD. **Mature. Same answer
greenfield or patched.** The PoC's choices here are already the ideal ones.

---

## 7. Consensus: PoW vs PoS in a quantum world

A common myth is that quantum computers break PoW. They do not, meaningfully:

- **PoW (hash-based) is Grover-soft, not Shor-broken.** Grover gives at best a quadratic
  speedup on preimage search; with a 256-bit hash and an unbounded nonce space the effective
  margin stays ~128-bit — fine. Conceal-core's own `pow-grover-widening.md` reaches this
  conclusion: **no change needed**, do *not* widen the nonce. A greenfield PoW coin keeps a
  256-bit hash (memory-hard CryptoNight-class or a modern equivalent) and is PQ-adequate.
- **PoS depends on signatures**, which Shor *does* break — so a PoS chain **must** use PQ
  signatures (ML-DSA/Falcon) for block proposals, attestations, and validator keys. That is
  achievable (it's just §5 applied to consensus), but it makes the signature choice
  consensus-critical and the validator-set messages larger.

**Verdict.** Neither is disqualified. **PoW is the lower-risk PQ choice** because its security
rests on hashing (Grover-adequate) rather than signatures, and it avoids making the lattice
signature a consensus-liveness dependency. A greenfield coin that wants PoS can have it, but
must treat PQ-signature performance/size as a first-class consensus parameter and likely wants
**aggregatable PQ signatures** (an active research area; lattice aggregation is immature) to
avoid attestation bloat. **Recommendation: PoW with a 256-bit memory-hard hash** — matches
conceal-core, minimises new PQ risk surface, and keeps the only lattice dependency in the
*spend* path, not the *block-production* path.

---

## 8. Serialization & wire format

Conceal-core's homemade KV-binary serializer (`src/Serialization`, the `ISerializer` pattern)
is a genuine liability the PoC has to work around: it is a hand-rolled compatibility surface
where one mistake breaks consensus or on-disk format. **Greenfield, do not hand-roll it.**

- Use a **canonical, deterministic, length-prefixed binary codec** with an explicit,
  versioned schema. Determinism (one byte-string per object) is **consensus-critical** —
  signatures and nullifiers are computed over serialized bytes, so any ambiguity is a fork or
  a forgery vector. The PoC's review already caught output-length/index-poisoning bugs that a
  schema-checked codec prevents structurally.
- Make every record **explicitly versioned and tag-gated** so confidential-amount and new
  signature versions can be added behind an upgrade height without ambiguity — the PoC's
  variant-tag discipline (`0x4`/`0x5`/`0x06`, `UPGRADE_HEIGHT_V9`) is the right *idea*; a
  greenfield codec just makes it safe by construction rather than by careful review.
- PQ artifacts are **big** (KEM cts ~1.1 KB, ML-DSA sigs ~3.3 KB, ring sigs tens of KB), so
  the format must be size-aware: enforce exact/bounded lengths at the boundary (the PoC's
  `check_outs_valid` does this manually; greenfield, the schema enforces it).

**Verdict.** Canonical deterministic codec with a versioned schema and boundary-enforced
lengths. This is one of the **clearest wins of starting fresh** — but note it is an
*engineering* win, not a *cryptographic* one.

---

## 9. Language: **Rust** for the whole node, not just the crypto

The PoC already proved the model: the PQ crypto lives in a **Rust module (`pqc/ccx-pqc`)
behind a C-ABI FFI**, with `catch_unwind` panic guards on every entry point and a flat-stride
ABI. That FFI seam is *itself* a source of the PoC's hardest bugs (struct-of-pointers vs
flat-stride key layout mismatch, panic-across-FFI UB, the reload/explorer crash). Greenfield,
you delete the seam.

- **Rust end-to-end.** Memory safety matters enormously in consensus/money code (conceal-core
  is C++11 with all the attendant footgun surface). Rust's crate ecosystem (`RustCrypto`,
  `pqcrypto`, `ml-dsa`, `ml-kem`, `dalek` successors, hash-based stuff) is where the PQ
  primitives actually live and are maintained — the PoC pulls `sha3`, `chacha20poly1305`,
  `pqcrypto-kyber`, `pqcrypto-dilithium`, `ml-dsa`. Writing the node in Rust means **no FFI
  boundary** around the most dangerous code.
- **Precedent.** Zebra (the Rust Zcash node), Grin, and most new-generation chains are Rust;
  this is the industry default for new privacy-coin infrastructure in 2026.
- **Caveat — Rust is not a security oracle.** Rust prevents memory-corruption classes; it does
  **not** make a hand-rolled lattice ring sig constant-time, correctly-sampled, or sound.
  Those require the same cryptographer review whether the code is Rust or C++. "Port to Rust"
  buys safety and maintainability; it does **not** retire the audit requirement on the novel
  crypto.

**Verdict.** Rust for the entire node. This is the single most defensible greenfield decision
*and* it directly answers the partner's Q1 ("is it worth porting to Rust"): **yes for a
greenfield rewrite, where you get a unified memory-safe codebase with no FFI seam.** For the
*existing* conceal-core, full porting is a separate, large effort whose payoff is mostly
maintainability — the crypto module is already Rust, which is where it matters most.

---

## 10. The honest "best-achievable-2026" reference design

Putting the buildable-today choices together, a pragmatic greenfield PQ privacy coin is:

```
Ledger:        UTXO, one-time outputs, single global output-commitment tree +
               nullifier accumulator (Zcash-shaped, not CryptoNote per-amount tables).
Sender hiding: Large decoy ring (target N = 16–64) via a lattice linkable ring signature.
               Ship v1 with experimental-but-isolated params behind a "testnet/beta"
               gate; do NOT call it mainnet-private until calibrated + constant-time +
               AUDITED. (Same wall as the PoC — no shortcut.)
Recipient:     ML-KEM-768 stealth one-time keys (mature). [PoC: done]
Amounts:       PLAINTEXT, with a reserved, height-gateable confidential-amount field for a
               future lattice-commitment upgrade. (Confidential amounts only if/when you
               adopt the full heavy lattice-RingCT core.)
Auth/deposit:  ML-DSA-65 workhorse; Falcon where size dominates + constant-time impl exists;
               SLH-DSA for genesis/governance long-lived keys. [PoC: ML-DSA done]
Messages:      ML-KEM-768 + ChaCha20-Poly1305 AEAD. [PoC: done]
Consensus:     PoW, 256-bit memory-hard hash, no nonce widening (Grover-adequate).
Serialization: Canonical deterministic versioned binary codec, boundary-enforced lengths.
Language:      Rust, single codebase, no FFI seam.
```

Notice what this is: **it is the conceal-core PoC's target architecture, minus the legacy C++
chassis, minus the FFI seam, minus the CryptoNote per-amount index, plus a global commitment
tree and a clean codec.** The *cryptographic ambition is identical* because the cryptographic
ceiling is identical. The delta greenfield buys you is **architectural cleanliness and
safety**, not more privacy.

If instead you want the **maximally-private** greenfield coin (confidential amounts + real
ring anonymity), the only proven blueprint is **Abelian/pqringct (lattice RingCT)** — adopt or
fork that line rather than reinvent it, accept tens-of-KB transactions, and budget for a
cryptography team and a formal audit. That is a *different, much larger* project than either
the PoC or the pragmatic design above.

---

## 11. Buildable-today vs research-grade — the scorecard

| Component | Greenfield choice | Maturity | Same as PoC? |
|---|---|---|---|
| UTXO ledger + global commitment tree | UTXO + Zcash-style tree | **Production** | Mostly (PoC uses CryptoNote tables) |
| Recipient stealth | ML-KEM-768 | **Production (FIPS 203)** | **Yes — PoC done** |
| Spend/deposit auth | ML-DSA-65 (+Falcon/SLH by role) | **Production (FIPS 204/205)** | **Yes — PoC done** |
| Encrypted messages | ML-KEM-768 + ChaCha20-Poly1305 | **Production** | **Yes — PoC done** |
| Amount confidentiality (plaintext) | plaintext + reserved upgrade field | **Production (trivial)** | **Yes — PoC choice** |
| PoW consensus | 256-bit memory-hard hash | **Production, Grover-adequate** | Yes |
| Serialization | canonical deterministic codec | **Production (engineering)** | No (clean win of rewrite) |
| Language | Rust, no FFI | **Production** | Partial (PoC: Rust crypto only) |
| **Sender anonymity (lattice ring sig)** | **lattice LSAG/Raptor/MatRiCT-class** | **RESEARCH→BESPOKE** | Yes — *same wall* |
| **Amount confidentiality (lattice commit)** | **lattice RingCT (Abelian-class)** | **BESPOKE (Abelian only)** | n/a (PoC deferred) |
| **Small PQ zk shielded pool** | **none** | **RESEARCH (not deployable)** | n/a |

Everything green is buildable now and is *already what the PoC targets*. The two red rows are
the wall, and **they are red whether you patch or start fresh.**

---

## 12. Bottom line for the decision at hand

- **Starting greenfield does not break the wall.** The privacy ceiling is set by the absence
  of a mature small-proof PQ primitive, which is a *cryptography* fact, not an *architecture*
  fact. A from-scratch coin lands on the **same** pragmatic core the PoC targets: bigger rings
  + plaintext amounts + ML-KEM stealth + ML-DSA auth.
- **What greenfield genuinely buys:** Rust-everywhere memory safety with no FFI seam, a clean
  deterministic codec, a global commitment tree (future-proofing for an eventual zk upgrade),
  and freedom from CryptoNote legacy debt. These are real, but they are **safety/maintainability
  wins, not privacy wins.**
- **The PoC's crypto choices are already the ideal ones** for the mature layers: ML-KEM-768,
  ML-DSA-65, ChaCha20-Poly1305, plaintext amounts, unchanged PoW. A greenfield design would
  pick the *same* primitives. (This directly validates Q2: yes, adopt the modern options — and
  the PoC already has, with the ChaCha20-Poly1305 swap as the model.)
- **The one irreducible hard problem** — an anonymous, linkable, *constant-time, calibrated,
  audited* lattice ring signature (and, for full confidentiality, lattice RingCT) — is **the
  same deliverable** in both worlds. It needs a cryptography team and a formal audit no matter
  which chassis it sits in. Abelian is the proof it can be done and the proof of what it costs.

**Pragmatic recommendation:** do **not** greenfield *to chase better PQ privacy* — you would
rebuild the same core and re-hit the same wall, spending 12–24+ months to arrive where the PoC
already is cryptographically. Greenfield is justified only if the **legacy C++/serialization/
FFI debt itself** is the dominant pain, in which case it is a clean rewrite with a known target
(the §10 reference design) — and even then, the experimental lattice ring sig remains the
critical path and the audit gate, ported essentially as-is from the PoC's `ringsig.rs`.

---

### Sources

- MatRiCT (Esgin–Steinfeld–Liu–Liu, CCS 2019 / eprint 2019/1287) — lattice RingCT, proof
  length ~2 orders shorter than prior PQ proposals, verify ~23 ms.
- Raptor: Post-Quantum Linkable Ring Signature (Lu–Au–Zhang, eprint 2020/1121).
- Lattice RingCT v2.0 (MIMO wallets, Hcash-targeted).
- Abelian / pqringct (pqabelian.io; github.com/pqabelian; CryptoBLK/Abelian) — production
  lattice linkable ring sig + lattice confidential amounts, multi-tier privacy, QDay mainnet
  2025.
- Zcash post-quantum roadmap / Project Tachyon (quantum-recoverable wallets first, full PQ
  targeted ~2027) — decrypt.co, coinjournal.net, tradingview/coinpedia coverage, May 2026.
- Iron Fish (zk-proof shielded, Groth16-class → not PQ) — ironfish.network.
- Grin/Beam Mimblewimble: Pedersen commitments Shor-broken; Grin switch commitments are a
  *migration* aid, not PQ confidentiality — docs.grin.mw, arxiv 2105.01815.
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA); FN-DSA/Falcon draft.
- conceal-core PoC: `pqc/POC-RESULTS.md`, `pqc/ccx-pqc/src/{lib.rs,ringsig.rs}`,
  `docs/design/quantum-resistance/{wallet-address-v2,pow-grover-widening,deposits-mldsa,
  messages-mlkem}.md`, `docs/reviews/pq-*.md`.
