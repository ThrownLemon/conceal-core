*Focused web sweep (4 angles + synthesis) answering: is anything newer/better than ELRS as a PQ **linkable** ring signature for plaintext-amounts CryptoNote? **Confidence ~65%** — eprint PDFs were Cloudflare-blocked, so several KB figures are abstract/formula-derived (verify against the real tables before committing). Frames provisional defaults, not decisions.*

# PQ Linkable Ring Signature Verdict for Conceal (Plaintext-Amounts Path)

**Question:** Is ELRS (ESORICS 2024, eprint 2024/553) the right PQ linkable ring signature to proceed with, or is something newer/better available?

**Short answer:** Proceed with ELRS as the working target **only if Conceal commits to growing rings beyond ~32** — otherwise ELRS is genuinely *oversized and over-engineered* for Conceal's actual operating point (mixin 5–16), where a linear lattice scheme is smaller **and** rests on a cleaner assumption. The decision hinges almost entirely on one committed parameter: **maximum ring size.**

---

## Critical correction to the brief's premise

The research surfaced a factual error in the baseline you handed me, and it matters for the verdict:

> **ELRS's "0.3 ms cold single verify" is wrong.** Per the authors, **0.3 ms is the *amortized* online cost** (the offline FRI phase is shared across many signatures verified against the *same* ring). A **single *cold* verify is ~128 ms.** For a blockchain validating many *different* small rings, that amortization may not fully apply — which materially narrows ELRS's headline verify advantage. Cold, ELRS (~128 ms) is *slower* than Raptor / ChipmunkRing / DualRing-family single-signature verify (single-digit ms). This was independently flagged by two of the four research angles, so I treat it as high-confidence.

This does not disqualify ELRS, but it removes "0.3 ms beats everything" as a clean argument. Whether Conceal gets the amortized number depends on whether validators verify many sigs against identical rings — which in CryptoNote, with per-transaction decoy selection, they generally do **not**.

---

## 1. The honest leaderboard (ranked for Conceal's exact need)

Ranked by fitness for *small-ring (5–16), plaintext-amounts, natively-linkable, money-critical*. KB figures are at the stated security level; mark where asymptotic/derived.

**Tier A — real contenders for the small-ring path**

1. **Raptor** (NTRU lattice, ACNS 2019) — *the proven incumbent-beater at small rings.*
   - Beats ELRS on: **size@small-ring** (~10 KB @ ring-8, ~21 KB @ ring-16, *natively linkable*), **assumption** (NTRU/Ring-SIS reduction vs ELRS's hash/FRI conjecture), **maturity** (public Rust PoC `zhenfeizhang/raptor`, most-cited PQ linkable ring sig with code).
   - Catch: **linear** — ~83 KB @ ring-64, **~1.3 MB @ ring-1024** (catastrophic). ELRS overtakes on size at ring ~16–32. Benchmarked at 100-bit (not 128) in ELRS's own comparison table, so the 10 KB is a slight under-count vs a 128-bit ELRS. NTRU is a real but more-structured assumption than Module-SIS.

2. **ChipmunkRing** (Ring-LWE, arXiv 2510.09617, 2025) — *the only thing close to shipping.*
   - Beats ELRS on: **assumption** (Ring-LWE reduction with EUF-CMA forking-lemma proof), **cold verify** (0.4–4.5 ms @ ring 2–64 vs ELRS ~128 ms cold), **maturity** (open **C** in Cellframe DAP SDK with test vectors, live in a production chain — more inspectable than ELRS's Rust PoC). Native 32-byte SHA3 nullifier — exactly Conceal's model.
   - Catch: **linear** (~24 KB @ ring-8 *level with* ELRS, 279.7 KB @ ring-64, multi-MB @ 1024); only **112-bit (NIST L1, below 128)**; "Acorn Verification" is a **bespoke, unproven-in-standard-model, single-author (vendor CEO)** ZK protocol; its comparison tables use placeholder ">100 KB" strawmen — a rigor red flag. *Watch/inspect, do not adopt as-is.*

3. **LAPQ-LRS** (Module-SIS/MLWE + Dilithium aggregation, MDPI Entropy 2026) — *best on-paper size+assumption combo, slow & unverified.*
   - Beats ELRS on: **size@small-ring** (~4.4 KB @ ring-8, ~5.8 KB @ ring-16 per the 1.45·log₂n KB formula), **size@large-ring** (~14.5 KB @ 1024, log-size), **assumption** (MLWE/MSIS — same family as NIST ML-DSA/FIPS 204), **natively linkable + log-size**.
   - Catch: **verify 30.7–109 ms** (~100× ELRS amortized); **Python prototype only**, single lighter-venue (MDPI) paper, **novel unvetted "aggregation-replaces-ZKP" anonymity argument**; small-ring KB is **formula/figure-derived, not a clean measured table** (medium confidence).

**Tier B — assumption-clean but loses on size/speed**

4. **MatRiCT+** (Module-SIS/MLWE, IEEE S&P 2022) — natively linkable (RingCT serial number = nullifier), **C++ implementation** (most mature lattice option), real reduction, fast verify (2–8 ms). Catch: it's **RingCT-coupled** — bundles confidential-amount machinery Conceal does *not* want on the plaintext path; the standalone plaintext-amount linkable-membership-proof KB is **not isolated in the paper** (inferred smaller than ELRS at small rings, not measured).

5. **SMILE** (Module/Ring-SIS, CRYPTO 2021) — compact (~16 KB @ ring-32, ~18–22 KB @ large rings, often smaller than ELRS at large rings), real M-SIS reduction. Catch: **linkability is NOT native** — needs a key-image + well-formedness proof bolted on (real cryptographic work + its own security proof); verify slower than ELRS.

6. **Falafl** (MLWE/MSIS, ASIACRYPT 2020) — natively linkable, real lattice reduction. Catch: **~50 KB flat @ ring-8, 53–56 KB at large rings** — *larger than ELRS at every ring size relevant to Conceal*. Pick only if a clean reduction is mandatory and size is acceptable. ELRS itself cites this as the prior art it improves on.

**Tier C — same-assumption-family as ELRS (symmetric/conjectured), but worse**

7. **PegaRing** (power-residue PRF, eprint 2025/1841, Nov 2025) — *the most interesting genuinely-new same-axis contender.* First practical symmetric-primitive ring sig with **provable QROM security** (strictly better security *modeling* than ELRS's heuristic FRI soundness); ~29–32 KB @ ring-1024. Catch: verify **6–31 ms** (not flat, grows with ring); small-ring KB **unpublished** (medium/low confidence); newest, unvetted.

8. **DualRing-PRF / DualRingL-PRF** (Legendre/power-residue PRF, ACISP 2024) — competitive small-ring size, pure symmetric-key assumption. Catch: **signing 26–88 *seconds* @ ring-256** (MPC-in-the-head — check *sign* time, not just verify), linkable variant 42 KB @ ring-16 (larger than ELRS), Legendre PRF has active key-recovery cryptanalysis (May–Zweydinger). **Superseded by PegaRing.**

**Tier D — ruled out (do not chase)**
- **Calamari** (CSIDH isogeny): smallest size (~5.5 KB @ ring-8) but **~79 s signing**, slow verify, and **CSIDH PQ-security contested post-SIDH-break (2022)**. Disqualified.
- **LIP-based LRS** (SPACE 2023) and **LLRing** (ESORICS 2024): a follow-up (**eprint 2025/1375**) reported a **linkable-anonymity / unlinkability break** in this cluster. LLRing is also DL/pairing in its main instantiation = **not PQ**. *Caution flag, not candidates.*
- **Gandalf / DualRing-LB**: smallest small-ring sizes found (4.8 KB / 4.6 KB @ ring-8) but **NOT linkable** — Conceal needs a nullifier; bolting one on is non-trivial and unbenchmarked.
- **XMSS/WOTS+ hash LRS** (Sensors 2025): **stateful** OTS = catastrophic key-reuse risk in a coin. Disqualifying.

---

## 2. The one genuine trade-off to flag

**ELRS's conjectured hash/STARK security vs a clean lattice-reduction alternative.**

This is the real story, and it is unambiguous in one direction:

- **ELRS rests on a heuristic** — ethSTARK = FRI proximity-gap conjectures + ROM. There is **no reduction to a standard hard problem.** Security is "we believe FRI is sound and the hash is collision-resistant."
- **The lattice alternatives reduce to Module-SIS/MLWE** — *the exact assumptions NIST standardized in ML-DSA (FIPS 204).* That is a strictly cleaner, better-studied footing.

**Is there a lattice linkable ring sig competitive enough to be worth the cleaner assumption?** Yes, conditionally — and the answer differs by ring size:

- **Most credible, slow:** **LAPQ-LRS** (MLWE/MSIS, natively linkable, ~4.4 KB @ ring-8 *and* ~14.5 KB @ 1024, log-size). On paper it beats ELRS on **both** size axes **and** assumption. The price is **verify 30–109 ms** and that it is a **Python prototype in a single lighter-venue paper with a novel unvetted anonymity argument.** If its numbers survive independent scrutiny, it is the strongest "clean-assumption replacement." Today: medium confidence, not adoptable.
- **Most mature, RingCT-coupled:** **MatRiCT+** (M-SIS/MLWE, C++, fast verify). The grown-up choice *if* you can extract just the plaintext linkable-membership proof — real engineering, but real code and a real reduction.
- **Small-ring + clean, but linear:** **Raptor** (NTRU) — smaller than ELRS at ring ≤16 with a real reduction and a Rust PoC, dying only at large rings.

**Net:** Yes, a lattice linkable ring sig with a cleaner assumption *is* competitive — but **none simultaneously matches ELRS on flat-large-ring-size AND sub-ms verify.** The lattice tax is real: you trade ELRS's flat ~29 KB-at-any-ring for either (a) linear growth that's smaller only at small rings, or (b) log-size that's still 100× slower to verify.

---

## 3. Ring-size design note

This is the crux for Conceal.

- **At Conceal's current rings (5–16): ELRS does NOT win.** Its ~25 KB is a **STARK-proof floor**, not a small-ring optimum — it is essentially *wasted flatness*. A linear lattice scheme is physically smaller here: **Raptor ~10 KB @ ring-8 / ~21 KB @ ring-16**, both *below* ELRS's ~25 KB, *and* with a cleaner assumption. ChipmunkRing is roughly level. LAPQ-LRS (if trusted) is ~5× smaller. So at the *actual operating point*, a small-ring/linear scheme wins on size and assumption; ELRS wins only on (amortized) verify and transparency.
- **The crossover is ~ring 16–32** for Raptor, lower for ChipmunkRing. Below that, linear wins; above it, ELRS's flatness takes over.
- **The answer flips hard if Conceal grows rings for stronger anonymity (≥64–1024).** Every linear scheme (Raptor 1.3 MB, ChipmunkRing multi-MB, DualRing-PRF) becomes **unusable**. There, ELRS's flat ~29 KB is genuinely strong, and only **log-size lattice schemes** compete: SMILE (~18–22 KB, M-SIS, but not natively linkable), LAPQ-LRS (~14.5 KB, MLWE, but slow/unverified), Falafl (~30–56 KB, larger). ELRS is the safest *flat* option at large rings.

**Design implication:** This is a fork in the road that Conceal must decide *first*. "Small rings forever" → adopt a linear lattice linkable scheme (Raptor-family / the session's own LSAG-style PoC), smaller *and* cleaner-assumption than ELRS. "Rings may grow" → ELRS (or a log-size lattice scheme once one is audited). Picking ELRS *and* keeping rings at 8 is paying ELRS's floor for flatness you never use.

---

## 4. Verdict + confidence

**Verdict (conditional, two-branch):**

- **If Conceal commits to rings ≤ ~16 indefinitely:** *Do not default to ELRS.* Evaluate **Raptor** (proven, native-linkable, Rust PoC, NTRU reduction, smaller at these sizes) as the primary, with the session's existing LSAG/Module-SIS PoC as the same-family in-house variant. ELRS is oversized and assumption-weaker here.
- **If Conceal wants the option to grow rings to 64–1024:** *ELRS is a defensible working target* — it is the only scheme that is flat-size *and* transparent *and* (amortized) fast at large rings. But proceed knowing its security is **conjectured (no reduction)** and **evaluate LAPQ-LRS first** as the cleaner-assumption log-size alternative before locking in.

**In both branches, the honest recommendation before any adoption decision is:** pull the actual size tables from the PDFs (ELRS 2024/553, Raptor, LAPQ-LRS, MatRiCT+) via browser/institutional access — the eprint PDFs were **Cloudflare-blocked** this sweep — and **re-benchmark ELRS vs the top-2 challengers at Conceal's real ring sizes 4/8/16**, measuring **cold single-verify** (not amortized) and **sign time** (not just verify).

**Confidence: ~65% (moderate).** I am confident in the *shape* of the answer (no scheme dominates ELRS on all of {small-ring size, native linkability, fast verify, clean reduction, maturity}; ELRS's flatness is wasted at small rings; the assumption trade is real and one-directional). I am *not* confident in several load-bearing numbers.

**Residual unknowns a web sweep cannot rule out:**
- **Unpublished/very-recent work.** RingSLIP (eprint 2026/889, LIP/HAWK lattice) and PegaRing (2025/1841) are too new to have public small-ring KB or linkability confirmation; an unindexed 2026 eprint could change the leaderboard.
- **The unverified ELRS tx-overhead.** ~25–29 KB is the *signature*; the per-transaction on-chain overhead in a CryptoNote context (multiple inputs, integration with existing tx format) was **not measured** and could be materially larger.
- **The cold-vs-amortized verify gap.** Whether Conceal realizes ~0.3 ms or ~128 ms depends on validator/ring-reuse behavior — unmeasured for Conceal's actual workload.
- **Every scheme here is research-grade and unaudited**, including ELRS. There is **no production-grade, audited PQ linkable ring signature library in existence.** Switching to Raptor or ChipmunkRing gives *more inspectable* code but does **not** close the audit gap.
- **Several derived KB figures** (LAPQ-LRS small-ring, MatRiCT+ standalone, DualRing-PRF per-ring, PegaRing small-ring) are formula/abstract-derived because the PDFs were CAPTCHA-blocked — they must be confirmed against the real tables before trusting.

---

## 5. Ranked summary table

Sizes at 128-bit unless noted; *italic* = asymptotic/derived/single-datapoint, not a clean measured table. "Verify" = single cold verify where known.

| Scheme | Family | Size @ ring-8 | Size @ ring-1024 | Verify (cold) | Assumption | Impl | Beats ELRS? |
|---|---|---|---|---|---|---|---|
| **ELRS** *(baseline)* | hash-STARK | ~25 KB | ~29 KB (flat) | ~128 ms (0.3 ms amortized) | Conjectured hash/FRI (no reduction) | Exp. Rust, unaudited | — |
| **Raptor** | NTRU lattice | ~10 KB | *~1.3 MB* | ms-range (fast) | NTRU/Ring-SIS (reduction) | Rust PoC | **Yes @ small ring** (size+assumption+maturity); no @ large |
| **ChipmunkRing** | Ring-LWE | ~24 KB | *multi-MB* | 0.4–4.5 ms | Ring-LWE 112-bit + bespoke "Acorn" ZK | **C in Cellframe (live)** | Partly (assumption, cold-verify, impl); no on size@large, 112-bit |
| **LAPQ-LRS** | MLWE/MSIS (Dilithium agg.) | *~4.4 KB* | *~14.5 KB* | 30.7 ms | **MLWE/MSIS** (clean, ML-DSA family) | Python proto | **On paper yes** (size both axes + assumption); no on verify-speed/maturity |
| **MatRiCT+** | Module-SIS/MLWE | *inferred < ELRS* | *~3 KB pubkeys; tx-coupled* | 2–8 ms | **M-SIS/M-LWE** (clean) | **C++** (most mature) | Yes on assumption+verify; RingCT-coupled, standalone KB unmeasured |
| **SMILE** | Module/Ring-SIS | *~16 KB @ ring-32* | ~18–22 KB | slower than ELRS | **M-SIS** (clean) | Paper proto | Yes on assumption + size@large; **not natively linkable** |
| **PegaRing** | power-residue PRF | *~8–15 KB (derived)* | ~29–32 KB | 6–31 ms | PRF, **QROM-proven** (better modeling, no reduction) | Paper proto | Yes on security-modeling; no on verify-speed; small-ring unconfirmed |
| **Falafl** | MLWE/MSIS | ~50 KB | ~53–56 KB | moderate | **MLWE/MSIS** (clean) | Paper proto | Assumption only; **larger everywhere** |
| **DualRingL-PRF** | Legendre/PR PRF | 42 KB @ ring-16 | 64 KB | sign 26–88 s | Symmetric PRF (no reduction) | Paper proto | No (larger + seconds-slow) |
| **Calamari** | CSIDH isogeny | ~5.5 KB | ~3.5–8 KB | seconds (slow) | CSIDH (**contested post-SIDH**) | Paper proto | Size only; **disqualified** (speed+assumption) |

**One-line bottom line:** Nothing dominates ELRS on all axes; ELRS's flat-size virtue is *wasted* at Conceal's small rings, where Raptor (and, if its numbers hold, LAPQ-LRS) are smaller *and* cleaner-assumption. **Decide max ring size first** — that single choice, not the cryptography, determines whether ELRS is the right pick. Confidence ~65%; verify the size tables and cold-verify numbers against the real PDFs before committing.
