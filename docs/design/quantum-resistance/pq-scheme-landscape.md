*Deep web-research scan (5 parallel angles + synthesis), generated this session. Newer PQ private/confidential-transaction schemes vs the MatRiCT-Au baseline. **Source caveat:** eprint.iacr.org blocks automated fetch, so most absolute KB/ms are from abstracts, not tables read — treat as hypotheses to confirm. Frames a provisional default, not a decision (see decisions-for-the-team.md).*

# Post-Quantum Confidential-Transaction Crypto: Decision-Grade Scan for Conceal

> **⚠ BENCHMARK FOLLOW-UP (supersedes the abstract-level rankings below).** Two candidates from this scan were
> then *measured* (built + run); see [`measured-numbers.md`](measured-numbers.md) §G/§H:
> - **Gao et al. — DOWNGRADED.** The "~50% smaller / ~20% faster" is vs the *original* MatRiCT (2019), **not
>   MatRiCT-Au**; the paper has no absolute tables; under a shared param set the Go ref was *slightly larger*;
>   the Go impl is partial (ring-sig only) and its MatRiCT baseline doesn't verify. **Not a demonstrated win
>   over MatRiCT-Au.** The "#1 successor" ranking below is retracted.
> - **ELRS — NOT the clear winner after the focused follow-up sweep** ([`pq-ringsig-verdict.md`](pq-ringsig-verdict.md),
>   ~65% confidence). Flat ~25–29 KB is a real win at *large* rings, but **at Conceal's small rings (5–16) it's
>   wasted flatness — linear lattice schemes (Raptor ~10 KB @ ring-8) are SMALLER and rest on a CLEANER
>   (Module-SIS/NIST) assumption** vs ELRS's conjectured hash/FRI. And the **verify is contested** (0.3 ms
>   measured vs 128 ms paper). **The choice hinges on max ring size, not the crypto.** §G + the verdict doc.
> - **MatRiCT-Au measured:** 107.4 KB, ~12 ms verify, 63 ms prove (Ryzen 5950X) — remains the only full,
>   verifying RingCT measured. Treat the per-scheme numbers below as *abstract-level hypotheses* unless §G/§H
>   marks them measured.

**Scope:** Find a post-quantum (PQ) private-payment scheme that beats Conceal's provisional default — **MatRiCT-Au** (lattice linkable-ring RingCT; ~107 KB measured proof floor, ~45 ms verify, unaudited research code) — on size/verify/maturity while keeping the four things Conceal actually needs: **sender anonymity (ring/set), confidential amounts, a double-spend nullifier, and a real implementation + credible audit path.**

**Source-access caveat (applies to every absolute number below):** all five research angles independently reported that `eprint.iacr.org` hard-blocks automated fetches (HTTP 403/Cloudflare). The only primary PDFs read end-to-end were the PolyU-hosted Gao et al. copy ([polyu.edu.hk PDF](https://www4.comp.polyu.edu.hk/~shanggao/publications/Lattice-based_Zero-knowledge_Proofs_for_Blockchain_Confidential_Transactions.pdf)), the USENIX BulletCT paper, and arXiv (ChipmunkRing, the SoK). **Every other absolute KB/ms figure comes from abstracts and search summaries, not from tables the researchers read.** Treat them as hypotheses to confirm against the PDF for Conceal's exact transaction shape (1-in / multi-in, ring size) before relying on them. The MatRiCT-Au baseline itself was *not* independently re-derived from `2022/142`; it is grounded in this repo's own prior library-ization measurements under `docs/design/quantum-resistance/`.

---

## Candidate-by-candidate (deduplicated across angles)

### The baseline — MatRiCT-Au (lattice-RingCT)
What it is: MatRiCT+ core + accountable/auditable anonymity (a chosen authority can de-anonymize via verifiable partially-decryptable commitments). Ring one-out-of-many for sender anonymity, lattice commitments + balance proof for confidential amounts, serial number = nullifier.
Size/verify: **~107 KB packed floor** (raw `sizeof` 274–370 KB); the cited ~58 KB needs an **unbuilt** commitment high-bit truncation that is a soundness-statement change **and conflicts with auditability**. **~45 ms verify**, ~33–35 GB prover memory (in-repo bench).
Maturity: peer-reviewed (PKC 2022); research C, library-ized in-repo, **unaudited**.
Source: [eprint 2022/142](https://eprint.iacr.org/2022/142) (Esgin–Steinfeld–Zhao).
This is the only existing scheme that bundles all four required properties out of the box. Everything else is judged against it.

### Gao et al. — "Lattice-based ZK Proofs for Blockchain Confidential Transactions" (the standout)
What it is: a **full PQ RingCT in the exact MatRiCT model** — ring + confidential 64-bit amounts + serial-number nullifier — that replaces MatRiCT's costly one-out-of-many binary proof with a cheaper **logarithmic linear-sum proof**, and removes the **"corrector values"** from the balance proof (the part that dominates MatRiCT's 64-bit range cost, >90 KB).
Size/verify: authors' headline **~50% smaller proof than MatRiCT, ~20% smaller than MatRiCT+**; **~20% faster verify** (≈36 ms-class if MatRiCT-Au is ~45 ms), ~15–30% faster proving. **No single absolute KB was extractable even from the PDF that was read** — the comparison is reported as plots/percentages; the ~50–90 KB extrapolation is *inference, not a quoted number.*
Maturity: **real open-source Golang reference impl** ([github.com/GoldSaintEagle/RingCT_Implementation](https://github.com/GoldSaintEagle/RingCT_Implementation)) on the LaGo polynomial-ring lib, benchmarked on i7-8750H; peer-reviewed (FC/PKC 2025, Springer). **Unaudited.** Techniques are explicitly "compilable with MatRiCT/MatRiCT+."
vs MatRiCT-Au: strict efficiency win on the exact axes Conceal cares about, and the corrector-value removal specifically helps **multi-input/multi-output** txs = Conceal's fusion/deposit pattern. **Catch: no built-in auditability** (Au's distinguishing feature would have to be re-ported), it's still kilobyte-scale, and the absolute size is unconfirmed.
Source: [eprint 2021/1674](https://eprint.iacr.org/2021/1674) / [Springer](https://link.springer.com/chapter/10.1007/978-3-031-91832-2_5).

### MatRiCT+ (the conservative fallback)
The faster/smaller core of the family without auditability: **2–18× shorter proofs and 3–11× faster verify than MatRiCT** (proof O(log M) in input accounts). MatRiCT-Au = MatRiCT+ + accountability. Most mature lattice-RingCT codebase; **unaudited**, not in a live coin. If auditability is dropped, MatRiCT+ (or Gao-on-MatRiCT+) is already smaller/faster than MatRiCT-Au. Source: [eprint 2021/545](https://eprint.iacr.org/2021/545) (IEEE S&P 2022).

### Efficient Linkable Ring Signatures (ELRS, STARK/ethSTARK) — anonymity layer only
What it is: a signature-of-knowledge linkable ring sig over a Merkle accumulator, compiled through ethSTARK. **Transparent setup, hash-based (conservative PQ assumption), 32-byte public keys.** **No confidential amounts.**
Size/verify: reported **~29 KB at ring 1024**, smallest PQ linkable-ring-sig with non-slanderability for ring ≥ 32; **~0.3 ms amortized verify at ring 8192**, but **~128 ms single-signature verify** (only fast when many are batched).
Maturity: research code; ethSTARK core is well-studied. Unaudited.
vs MatRiCT-Au: beats the *ring component* on size and (amortized) verify with a more conservative assumption — but **gives you anonymity + nullifier only**, so confidential amounts need a separate PQ range/balance proof bolted on. **Highly relevant precisely because the in-repo study confirms Conceal currently has plaintext amounts.** Source: [eprint 2024/553](https://eprint.iacr.org/2024/553) (ESORICS 2024).

### Lether — account-based, paradigm mismatch
PQ private payments via event-oriented linkable ring sig + refreshable additively-homomorphic mmPKE; ~**68 KB tx / ~51 KB ZK proof**, verify "a fraction of a second" (no ms). Newest (CCS 2026) and smallest-proof full PQ private-payment design — **but account-based (Anonymous-Zether), not CryptoNote UTXO/ring.** Its ~51 KB is in the same band as MatRiCT-Au's floor, not dramatically smaller, and adopting it means re-architecting away from rings+stealth. Track as an idea source (mmPKE, refresh trick), not a drop-in. Source: [eprint 2024/1615](https://eprint.iacr.org/2024/1615) / [2026/076](https://eprint.iacr.org/2026/076).

### SMILE — foundational set-membership building block
Log-size lattice set-membership → ring sig (**16 KB at 2⁵, 22 KB at 2²⁵ members**), shown to compose into a MatRiCT-style CT with ~4–10× smaller tx proofs than prior work. Predates MatRiCT-Au (CRYPTO 2021), so not "newer," but it's the lineage behind the LaZer toolkit and an excellent log-size membership engine for large anonymity sets. Needs amount + tag layers to become full RingCT; verify-ms not reported. Source: [eprint 2021/564](https://eprint.iacr.org/2021/564).

### LaZer / LaBRADOR / Greyhound / LatticeFold+ — engines, not schemes
- **LaZer** (CCS 2024): the most production-hardened PQ-ZK codebase — C backends + Python interface, auto-builds proofs via succinct **LaBRADOR** or linear **LNP22**; ships ring-sig/credential demos. **The natural substrate to *build* a next-gen RingCT** (SMILE-style membership + Gao-style inner-product balance + nullifier). No ready confidential-tx number. Source: [eprint 2024/1846](https://eprint.iacr.org/2024/1846).
- **LaBRADOR** (CRYPTO 2023): transparent lattice zkSNARK, **~58 KB for a 2²⁰-constraint R1CS**, but verifier not succinct in base form; **a full shielded-spend circuit (membership + range + nullifier) would likely exceed that and has never been built/benchmarked.** **Adoption hazard:** zksecurity (Apr 2026) found multiple public LaBRADOR implementations **broken — soundness collapsing to ~1 bit** from bad modulus choices; official impl is **C/AVX512-only** (no ARM without a port). Sources: [eprint 2022/1341](https://eprint.iacr.org/2022/1341), [zksecurity blog](https://blog.zksecurity.xyz/posts/greyhound/).
- **Greyhound** (CRYPTO 2024): fast lattice polynomial commitment, **~53 KB eval proof at 2³⁰, sublinear O(√N) verify** — attractive engine, same impl caveats, no confidential-tx instantiation. Source: [eprint 2024/1293](https://eprint.iacr.org/2024/1293).
- **LatticeFold+** (CRYPTO 2025): folding/IVC for recursion/aggregation — relevant only for batching, **not** shrinking a single tx. Source: [eprint 2025/247](https://eprint.iacr.org/2025/247).

### Abelian (PQRingCT) — the only shipping PQ confidential coin (and a warning)
The **only live mainnet PQ confidential-transaction coin** (CryptoNote-lineage fork): lattice linkable ring sig + lattice commitments + ML-KEM-style stealth. **But the construction is LINEAR**, measured in-repo on the shipped Go libs at **~130–150 KB per ring member → ~525 KB @ring2, ~2.6 MB @ring16**, and **~0.3–1.4 s verify per input**. **No public third-party audit.** It is a deployability existence proof, **strictly worse than MatRiCT-Au on every cost axis** — not a scheme to beat it. Source: [github.com/pqabelian](https://github.com/pqabelian).

### Explicit negatives (do NOT mistake for PQ candidates)
- **BulletCT** (USENIX 2025): ~2–3 KB tx, transparent — but **classical DLOG, NOT PQ.** Useful only as the size target showing PQ proofs remain 1–2 orders larger. [usenix PDF](https://www.usenix.org/system/files/usenixsecurity25-wang-nan.pdf).
- **Monero FCMP++**: full-chain anonymity set (~10⁸), production-track — **elliptic-curve Curve Trees, NOT PQ** (only symmetric forward-secrecy via Carrot); MRL says full PQ is a separate multi-year effort. [getmonero.org/2024/04/27](https://www.getmonero.org/2024/04/27/fcmps.html).
- **Zcash Project Tachyon**: PQ is **roadmap only** (target ~2027, lattice commitments + likely STARK to replace Halo2); nothing built. [coindesk coverage](https://www.coindesk.com/tech/2026/05/08/zcash-to-roll-out-quantum-recoverable-wallets-within-a-month-go-quantum-proof-by-2027).
- **LLRing, Omniring, RingCT 3.0**: log-size linkable rings but **discrete-log/pairing → Shor-breakable.** [eprint 2024/421](https://eprint.iacr.org/2024/421).
- **Anonymity-only PQ ring sigs** (RingSLIP ~46 KB@4096 but on the younger Lattice-Isomorphism assumption; SPRING ~17 KB@2²⁰; DualRing-PRF symmetric-key; Gandalf ~1.2 KB but linear/small-ring; **ChipmunkRing 20.5–280 KB linear, single-author non-peer-reviewed**): all lack confidential amounts and most lack a verify-ms; lower priority than ELRS for the membership half.
- **LACT+**: optimizes tx I/O count, **not** sender-anonymity-set size — wrong axis for CryptoNote untraceability. [MDPI 2023](https://www.mdpi.com/2410-387X/7/2/24).

---

## 1. Top candidates worth deeper evaluation (ranked)

1. **Gao et al. (eprint 2021/1674)** — *the* concrete MatRiCT-Au successor. **Reason:** same RingCT model (ring + confidential amounts + nullifier), measured (not asymptotic) ~50%/~20% smaller and ~20% faster vs MatRiCT/MatRiCT+, corrector-value-free balance proof that specifically helps Conceal's multi-input fusion/deposit txs, **and real Golang code**. **Catch:** no built-in auditability (must re-port Au's layer); absolute KB unconfirmed even from the PDF; Go reference impl ≠ C++11/consensus-grade; unaudited.
2. **ELRS / STARK linkable ring sig (eprint 2024/553)** — best for the **anonymity+nullifier half** *if amounts stay plaintext* (Conceal's actual current state). **Reason:** ~29 KB @ring 1024, 32-byte keys, transparent hash-based (the most conservative PQ assumption here), huge fast-verify anonymity sets. **Catch:** no confidential amounts; **~128 ms single-verify** (needs batching to amortize); the membership-only path is a 1-piece build only if Conceal commits to never hiding amounts.
3. **MatRiCT+ (eprint 2021/545)** — **lowest-risk** PQ RingCT if auditability is dropped. **Reason:** smaller/faster than MatRiCT-Au, same lineage as the in-repo library, most mature lattice-RingCT code. **Catch:** still ~tens of KB, unaudited, no accountability.
4. **Build-your-own on LaZer** (SMILE-style membership + Gao-style balance proof + nullifier) — **highest ceiling.** **Reason:** the only path that could plausibly collapse size below the ~50 KB band using succinct LaBRADOR/Greyhound. **Catch:** unsolved research+engineering (no one has shipped a confidential *ring* tx on these engines), the LaBRADOR soundness-bug class, and AVX512-only code needing a port. Months-to-years, not a port.

*Not recommended as next steps:* Lether (paradigm change to accounts), Abelian (strictly worse), all anonymity-only sigs lacking amounts.

## 2. Honest maturity reality check

- **Production / shipping in a coin:** only **Abelian** ships a PQ confidential tx on mainnet — and it's linear, MB-scale, sub-second-to-second verify, **no public audit**. Monero (FCMP++) and Zcash (Tachyon) are **NOT PQ** for the privacy layer today (EC-based / roadmap).
- **Paper-with-real-code (unaudited):** Gao et al. (Go), MatRiCT family (research C), LaZer/LaBRADOR/Greyhound (C/AVX512), SMILE, ELRS, LLRing (DL, non-PQ).
- **Paper-only / thin:** Lether, SPRING, RingSLIP, DualRing-PRF; **ChipmunkRing is single-author and non-peer-reviewed** — treat with caution.
- **The blunt truth:** **no audited PQ confidential-anonymous-payment scheme exists.** NIST finalized only the *building blocks* in Aug 2024 (FIPS 203/204/205); there is **no NIST/IETF standard for PQ ring signatures, set-membership, or confidential transactions.** That is the structural reason every candidate is unaudited. **An "audit path" means commissioning one — not adopting a pre-vetted scheme.** This gate is identical for MatRiCT-Au and every alternative, so it does **not** differentiate the choice.

## 3. Paradigm view — stay lattice-ring-RingCT, or pivot to a succinct shielded pool?

The evidence points to **staying in the lattice ring-RingCT (MatRiCT) family for the near term**, with the succinct-argument engines as a *research track*, not a current adoption:

- **Lattice ring-RingCT (MatRiCT/Gao):** ✅ direct CryptoNote fit (ring + stealth + nullifier already map), ✅ standardized Module-SIS/LWE assumptions (same family as NIST FIPS 203/204), ✅ real code, ✅ no trusted setup. ❌ stuck in the **~50–100 KB band** — no verified scheme breaks an order of magnitude below it. The 2024–2025 literature delivers **2–18× multiplicative** gains that all land in the same tens-of-KB regime, *not* a collapse.
- **PQ STARK/SNARK shielded pool (LaBRADOR/Greyhound circuit, or STARK):** higher size *ceiling* (succinct engines exist at ~53–58 KB for generic R1CS, sublinear verify) but ❌ **no complete confidential-anonymous-payment scheme has been built and benchmarked** on them — wiring membership + range + nullifier into a circuit is the unsolved gap; ❌ STARK PQ-security is **conjectured** (ROM/collision-resistance, no reduction to a hard problem) and production STARK shielded pools (Starknet STRK20) lean on Falcon for spend-auth and are L2/Cairo-bound; ❌ documented **LaBRADOR soundness-collapse bugs** and AVX512-only code; ❌ a paradigm change away from CryptoNote rings.

**Net:** the better *long* bet may be a succinct lattice engine, but it is not adoptable today. The right posture is **lattice ring-RingCT now, LaZer-based succinct RingCT as a tracked R&D bet.**

## 4. Recommendation for Conceal

**Keep MatRiCT-Au as the provisional default for now, but make the cheapest possible move to confirm Gao et al. as the successor — and decide the auditability and confidential-amounts questions first, because they change the answer.**

- **If confidential amounts are required** → Gao-et-al. techniques (ideally layered on MatRiCT+) are the **most concrete win available today**: ~half the size, faster verify, real Go code, and the corrector-value removal directly helps Conceal's fusion/deposit pattern. Re-port Au's auditability only if a regulator demands it.
- **If amounts can stay plaintext** (the in-repo study confirms Conceal has *no* RingCT/Pedersen/Bulletproofs today, and confidential amounts were already deferred to an optional L2) → the problem **reduces to a PQ linkable ring sig + PQ one-time key + PQ nullifier**, and **ELRS/STARK (2024/553)** becomes very attractive: biggest anonymity sets, fast amortized verify, conservative hash-based assumption, no heavy range proofs. This is potentially a *bigger* win than chasing Gao, and it sidesteps the band entirely.

**Cheapest next step to de-risk (do this before any integration commitment):**
1. **Read the actual tables.** Open the Gao et al. PDF from the PolyU host (it's reachable; eprint is the blocked mirror) and **extract the exact proof size + verify ms for Conceal's transaction shape** (1-in vs multi-in, target ring size). This is the single highest-value, lowest-cost action — it converts the load-bearing "~50% / ~50–90 KB" *inference* into a number, and the whole ranking hinges on it.
2. **Build + benchmark the Gao Go reference impl** ([GoldSaintEagle/RingCT_Implementation](https://github.com/GoldSaintEagle/RingCT_Implementation)) on the WSL host at Conceal's ring size, head-to-head against the already-library-ized MatRiCT-Au, on identical hardware. Measure size, verify, prover memory.
3. **Resolve the requirements fork explicitly** with the team: *is auditability in or out, and are amounts confidential or plaintext?* That decision selects Gao-vs-ELRS-vs-keep-MatRiCT-Au more than any benchmark will.

Do **not** commit to building on LaZer/LaBRADOR yet (research-grade gap + soundness-bug class + AVX512/ARM port), and do **not** adopt Abelian (strictly worse) or pivot to Lether (account-based re-architecture). Whatever is chosen remains **audit-gated** — that cost is unavoidable and equal across all options.

## 5. Summary table

| Scheme | Type | Proof size | Verify | Implementation | Audit | Verdict |
|---|---|---|---|---|---|---|
| **MatRiCT-Au** *(baseline)* | lattice ring-RingCT + auditability | ~107 KB floor (58 KB unbuilt) | ~45 ms | research C, in-repo lib | none | Incumbent; full feature set, heavy |
| **Gao et al.** | lattice ring-RingCT | ~50% < MatRiCT (abs. unconfirmed) | ~20% faster (~36 ms-class) | **Golang, open** | none | **Top successor — evaluate next** |
| MatRiCT+ | lattice ring-RingCT | 2–18× < MatRiCT | 3–11× faster | research C | none | Conservative fallback (no auditability) |
| **ELRS (STARK)** | linkable ring sig (no amounts) | ~29 KB @ring 1024 | 0.3 ms amortized / 128 ms single | research | none | **Strong if amounts stay plaintext** |
| SMILE | lattice set-membership | 16–22 KB ring sig | not reported | research | none | Good membership building block |
| LaZer / LaBRADOR / Greyhound | succinct lattice engines | ~53–58 KB (generic R1CS) | sublinear (no tx ms) | C/AVX512 lib | none + soundness bugs | R&D substrate, not a scheme |
| Lether | account-based PQ payments | ~51 KB proof | sub-second (no ms) | research | none | Paradigm mismatch (accounts) |
| Abelian (PQRingCT) | lattice ring-RingCT (linear) | 525 KB@2 → 2.6 MB@16 | 0.3–1.4 s/input | **mainnet** Go | none | Only shipping PQ coin; strictly worse |
| BulletCT | DLOG ring-RingCT | 2–3 KB | sub-second | lib | none | **NOT PQ** — size target only |
| Monero FCMP++ | EC full-chain membership | O(log n) | optimized | mainnet | community | **NOT PQ** — reference only |
| LLRing / Omniring | DLOG/pairing linkable ring | log-size | log | lib | none | **NOT PQ** — Shor-breakable |

**One-line bottom line:** No audited PQ confidential-tx scheme exists anywhere; within that reality, **Gao et al. (2021/1674)** is the strongest drop-in to beat MatRiCT-Au if amounts must be hidden, **ELRS/STARK (2024/553)** is the strongest path if Conceal keeps plaintext amounts, and the cheapest de-risking step is to read Gao's real size/verify tables from the PolyU PDF and benchmark its open Go code against the in-repo MatRiCT-Au — before deciding anything.
