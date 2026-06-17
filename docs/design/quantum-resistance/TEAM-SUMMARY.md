# Conceal Post-Quantum Ring Signature — Options Summary

**TL;DR:** Quantum computers (Shor) will break every signature/privacy guarantee in Conceal (ring sigs, key images, stealth addresses) — enabling theft + retroactive deanonymization. Fixing it is feasible but costs size/speed. The real decision is a **privacy fork**: keep ring untraceability (big txs, bigger blocks, more storage) **or** go transparent-input (small/fast, lose sender privacy).

All figures below are **measured** (on a Ryzen 9 5950X) or computed with **Conceal's own wire formula + live chain data** (avg tx = 2.39 in / 2.22 out, mixin 5 / ring 6).

## The options

| Scheme | Privacy | Avg tx size | Verify/tx | Chain growth/yr* | Maturity |
|---|---|---|---|---|---|
| **Ed25519 ring** (today) | full untraceable | **1.2 KB** | 2.3 ms | 0.37 GB | shipped — ❌ **NOT quantum-safe** |
| **Raptor** ring (lattice, linear) | full untraceable | 43 KB | **1.9 ms** | 13 GB | research PoC, unaudited |
| **MatRiCT-Au** ring (lattice, log + input-amortized) | full untraceable | 58 KB | 45 ms | 18 GB | research code, builds; needs ring-sig extraction |
| **Falafl** ring (lattice, log) | full untraceable | 95 KB | 77 ms | 29 GB | research artifact, fully measured |
| **Falcon — NO RING** (Falcon sig + H(pk) nullifier) | **stealth only** (inputs traceable) | **6.4 KB** | **0.2 ms** | 1.9 GB | NIST-standard primitive |
| **SPHINCS+ — NO RING** | stealth only | 21 KB | 3.6 ms | 6.5 GB | NIST-standard, conservative |

\* Chain growth at **current demand** (~1.16 tx/block). Scales with usage.

## Key facts the team needs

1. **Block size is dynamic** (`max = 2× median`, floored at the 100 KB zone) — so there's **no "1 tx/block" cliff**; throughput self-adjusts to demand via the reward-penalty mechanism. Earlier "1 tx/block" framing was wrong.
2. **The real walls are per-tx consensus caps** (both must be raised in the fork):
   - **`MAX_TX_SIZE` ~99 KB** — a single tx can't exceed this. Raptor's fusion txs, and MatRiCT/Falafl p90 + fusion txs, **blow past it** → rejected as-is.
   - **`FUSION_TX_MAX_SIZE` = 30 KB** — **every** PQ scheme blows this. Fusion (defragmentation) must be redesigned; MatRiCT's input-amortization helps most.
3. **Any PQ swap is a coordinated hard fork**, not just a signature change: variable-length `Signature`/`KeyImage`/output-key types (today they're fixed 32/64 B), new tx version, height-gated activation, raised size caps.
4. **Conceal-specific extra cost:** big PQ **output keys** (0.9–4.4 KB each vs 32 B), and amount **decomposition** creates many outputs — so the denomination scheme is now a real cost lever. **Deposits** add a second PQ job (their multisig path needs a PQ ordinary signature too).
5. **The "small logarithmic ~16 KB" promise (SMILE) has no public code** — the smallest *runnable* logarithmic ring sig is ~18 KB (MatRiCT-Au core) / ~35 KB (Falafl). Production code (Abelian pqringct) is linear ~130 KB/member — a non-starter.

## The decision (a product/privacy call, not just crypto)

- **A — Keep ring untraceability:** 43–95 KB/tx, 13–29 GB/yr storage, raise size caps + redesign fusion + bigger blocks. **MatRiCT-Au** = best fit (small core + input amortization) but hardest integration; **Raptor** = smallest/fastest at ring 6 but linear + needs nullifier redesign; **Falafl** = clean reference.
- **B — No-ring (Falcon + H(pk)):** 6.4 KB/tx, 1.9 GB/yr, fits all current caps, ~10× faster. **Cost: inputs become traceable** — keep stealth-address recipient privacy, lose CryptoNote sender untraceability.

**Recommendation:** decide A vs B first (it's a privacy-product decision). Engineering-wise, the variable-length wire-format refactor + a swappable ring-sig backend is needed either way and can start now.

---
*Source: measured PQ prototypes (Raptor/Falafl/MatRiCT-Au built + benchmarked) + Conceal's wire formula + live chain sample. Full detail in `comparison-chart.md`, `prototype-benchmarks.md`, `ringsig-pqc-design.md`. All PQ candidates are unaudited — none ship without a security audit.*
