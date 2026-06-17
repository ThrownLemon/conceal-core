# PQ Ring-Signature Methods — Comparison for the Conceal Chain

> Generated 2026-06-16; **corrected after measuring at Conceal's real ring size and separating ring-sig from confidential-amount cost.** Primitive figures measured on the WSL host (Ryzen 9 5950X, single-thread); transaction figures modeled from **live Conceal chain data**. Companion to [`ringsig-pqc-design.md`](./ringsig-pqc-design.md) and [`prototype-benchmarks.md`](./prototype-benchmarks.md). All PQ candidates are unaudited research code — **decision-support, not a ship decision.**

## What Conceal transactions actually look like (live sample)

80 recent blocks (height ~2,096,165), 93 non-coinbase txs:

| metric | median | average | p90 | max |
|---|---|---|---|---|
| inputs / tx | 1 | **2.40** | 4 | **45** (fusion) |
| outputs / tx | 1 | **2.11** | 7 | 12 |

Mixin floor `MINIMUM_MIXIN = 5` → **ring 6**. Each input = 1 ring signature; each output = 1 stealth key. **Conceal-specific extras:** deposits (separate `Multisignature` type — extra Shor-broken ordinary signatures) and output decomposition/fusion (inflate input counts). Amounts are **plaintext** — so only the **ring-signature** PQ cost applies, *not* confidential-amount machinery.

## Per-input ring-signature cost at ring 6 (plaintext amounts)

| Method | Ring-sig / input | Verify / input | Sign / input | Ring scaling | Measured? |
|---|---|---|---|---|---|
| **Today — Ed25519 LSAG** | **384 B** | **0.95 ms**ᴬ | 0.91 ms | linear (~150 µs/member) | ✅ measured in conceal-core |
| **Raptor** (linear, bit-packed) | **~16.6 KB** | **0.8 ms** | ~1.2 ms | linear | ✅ measured |
| **MatRiCT-Au** (ring-sig core, input-amortized) | **~18–19 KB**¹ | **~19 ms** | ~150 ms+ (variable) | **log + amortizes inputs** | verify/scaling ✅; size from paper Table 3 |
| **Falafl** (logarithmic) | **~35 KB** | **~32 ms** | ~115 ms | **log (flat)** | ✅ fully measured |
| **pqringct/pqringctx** (production RingCT) | ~130–150 KB/member | 0.3–20 s | linear | linear | ✅ measured — non-starter |

¹ **MatRiCT-Au size — the important nuance.** Its shipped code is *full RingCT* (with confidential amounts): I measured the real packed proof at **111 / 118 / 128 KB** for ring 10 / 50 / 100 (verify-gated; logarithmic, +16% per 10× ring) — matching the MatRiCT paper's 120 KB. **Conceal doesn't need the amount machinery**, so the relevant number is MatRiCT's *standalone ring signature* (ePrint 2019/1287 Table 3): **18 KB @ring 2, 19 KB @ring 8, 31 KB @ring 64** — logarithmic. Realizing that for Conceal means **extracting the ring-sig core from the RingCT code** (real engineering, not free). The famous "47 KB" is **MatRiCT+**, a more-compressed *different* scheme with **no public code**.

ᴬ **Measured in conceal-core (Level-1 harness).** A C++ benchmark linked against conceal-core's `libcrypto.a` runs the real `generate_ring_signature`/`check_ring_signature` at Conceal's ring sizes: ring 6 → **384 B, 0.95 ms verify, 0.91 ms sign**; and it scales linearly (16 → 2.5 ms, 64 → 10.2 ms, 256 → 41.8 ms). This *corrects* the earlier "tens of µs" estimate — Conceal's current LSAG verify is already ~1 ms at mixin 5 and grows ~150 µs per ring member. (So a PQ scheme like Raptor at 0.8 ms/ring-6 is actually *on par* with today's verify speed.) The harness is the bridge to a real integration: the next step is linking each PQ candidate + Conceal's variable-length serialization to get full in-code tx/block numbers.

## Per-transaction cost on the real chain (ring 6 + ML-KEM-768 stealth ~1.1 KB/output)

| Tx profile | Today | Raptor | MatRiCT-Au (core) | Falafl |
|---|---|---|---|---|
| **median** 1-in/1-out | 0.45 KB | ~18 KB | ~19 KB | ~36 KB |
| **average** 2.4-in/2.1-out | ~1.1 KB | **~42 KB** | **~30–45 KB**² | **~86 KB** |
| **p90** 4-in/7-out | ~2 KB | ~74 KB | ~40–60 KB² | ~147 KB |
| **fusion** 45-in/2-out | ~4.9 KB | ~750 KB | **~60–150 KB**² | **~1.6 MB** |

² MatRiCT-Au **amortizes across inputs in one proof** (cost grows ~log in #inputs, not linearly) — so multi-input/fusion txs are dramatically cheaper than N separate ring sigs. This is its decisive advantage for Conceal's fusion + decomposition reality. (Range reflects extrapolation from its `m1`/`m2` 1-vs-2-input configs; needs a multi-input proof model, a deeper integration change than per-input ring sigs.)

## Verify time per transaction (full nodes re-verify every input)

| Tx profile | Today | Raptor | MatRiCT-Au | Falafl |
|---|---|---|---|---|
| average (2.4-in) | <1 ms | ~2 ms | ~20–45 ms | ~77 ms |
| **fusion (45-in)** | ~ms | ~36 ms | **~0.1–0.5 s** (amortized) | **~1.4 s** |

*(Falafl verify is per-input: 27 ms @ring 4, 38 ms @ring 8, 209 ms @ring 64 — it grows with ring size. At Conceal's ring 6 it's ~32 ms, NOT the 209 ms an earlier draft wrongly used.)*

## Full architecture comparison — Conceal's own wire formula + measured PQ object sizes

Computed with Conceal's exact tx-size structure (`Currency::getApproximateMaximumInputCount`: header 42 B, output 1+key+10[+KEM], input 16+nullifier+ring·sig+mixin·4), substituting measured PQ object sizes. Ed25519 reproduces Conceal's real ~1.2 KB avg tx (validated). Avg tx = **2.39 in / 2.22 out** (468 live txs); ring 6; block reward zone = 100 KB.

| Architecture | median tx | **avg tx** | p90 tx | fusion (45-in) | avg verify | **txs / block** |
|---|---:|---:|---:|---:|---:|---:|
| **Ed25519 ring** (today) | 0.5 KB | **1.2 KB** | 2.2 KB | 20.5 KB | 2.3 ms | **82** |
| Raptor ring (linear) | 18 KB | **43 KB** | 78 KB | 726 KB | 1.9 ms | **2** |
| MatRiCT-Au ring (log) | 25 KB | **58 KB** | 115 KB | 879 KB | 45 ms | **1** |
| Falafl ring (log) | 40 KB | **95 KB** | 177 KB | 1.6 MB | 77 ms | **1** |
| **Falcon — NO RING** (dev's idea) | 2.8 KB | **6.4 KB** | 17 KB | 40 KB | **0.2 ms** | **15** |
| SPHINCS+-128f — no ring | 18 KB | 44 KB | 77 KB | 773 KB | 1.2 ms | 2 |
| SPHINCS+-128s — no ring | 9 KB | 21 KB | 40 KB | 358 KB | 3.6 ms | 4 |

### The number that should drive the decision: throughput

Today a 100 KB block holds **~82 average txs**. With any **ring-based PQ** scheme it holds **1–2** — a **~40–80× throughput collapse**. So adopting PQ ring signatures forces a **large block-size increase** (and the fee/propagation consequences), independent of which ring scheme you pick. This is the dominant systemic cost, bigger than any per-tx number.

### The no-ring option (the dev's proposal) — a real third path

A **Falcon witness + `H(pubkey)` nullifier with NO ring** is **6–15× smaller and ~10× faster than any ring option** (6.4 KB avg tx, 0.2 ms verify, **15 txs/block**). The **entire cost is privacy**: revealing the spending key makes **inputs traceable** — you keep stealth-address recipient privacy but lose CryptoNote's sender/output untraceability. It is the quantum-safe path *if* Conceal is willing to trade ring untraceability for feasibility. Done *with* untraceability (add a ZK ring-membership proof over the Falcon keys) it becomes **Raptor**. SPHINCS+ is a worse witness (fat sigs → 21–44 KB even without a ring; ZK-hostile).

**The strategic fork is now explicit:** keep ring untraceability (43–95 KB/tx, 1–2 txs/block, big block-size hike) **vs** accept transparent inputs (6.4 KB/tx, 15 txs/block, stealth-only privacy). That is a *product/privacy* decision, not just a crypto one.

## Pros / cons for Conceal

**Today — Ed25519 LSAG** — ✅ sub-KB, instant. ❌ **Shor-broken** (theft + retroactive deanonymization). The reason for all this.

**Raptor — linear lattice, packed**
- ✅ **Smallest + fastest at ring 6** (~17 KB, 0.8 ms verify); verify scales fine with fusion (36 ms @45-in).
- ❌ **Linear in ring size** (explodes if mixin rises for privacy); tag is **per-signer not per-output** → CryptoNote key-image semantics need redesign; unaudited PoC, not constant-time. Most crypto work to make sound.

**MatRiCT-Au — logarithmic, input-amortized** *(strongest fit, hardest integration)*
- ✅ **Small ring-sig core (~18–19 KB), fast verify (19 ms), and amortizes inputs** — uniquely suited to Conceal's fusion (≤45-in) + decomposition + deposits, where inputs pile up. Real nullifier, no trusted setup, builds + verifies on x86.
- ❌ Ships as full RingCT — **must extract the ring-sig core** (engineering); multi-input amortization means a **different tx model** (one proof per tx, not per input); variable/large sign time; unaudited research; most complex.

**Falafl — logarithmic, clean**
- ✅ **Fully measured, self-contained linkable ring sig + nullifier**, transparent setup, **flat in ring size** (makes large anonymity sets cheap). At ring 6: ~35 KB, ~32 ms verify — viable.
- ❌ **No input amortization** — N inputs = N×35 KB, so **fusion txs balloon (45-in ≈ 1.6 MB, ~1.4 s verify)**. Bigger than Raptor/MatRiCT-core at ring 6. Unaudited 2020 artifact, x86, no license.

**pqringct/pqringctx — production RingCT** — ✅ only deployed code. ❌ **linear ~130–150 KB/member → MB-scale, seconds to verify.** Non-starter as-is.

## Verdict for the actual Conceal chain

- **PQ is affordable at Conceal's mixin 5** (corrected): a PQ ring sig is **~17–35 KB/input, 0.8–32 ms verify** — *not* the MB/seconds an earlier draft implied (that came from using ring 64 timings and full-RingCT sizes). The **average tx lands ~30–86 KB** vs ~1 KB today (**~40–80×**); still requires **block-size/fee changes** in the same fork, but it is not disqualifying.
- **The differentiator is multi-input behavior (fusion + decomposition + deposits):**
  - **Falafl** — cleanest, fully measured, but **per-input → fusion txs are brutal** (1.6 MB / 1.4 s).
  - **MatRiCT-Au** — **amortizes inputs** → fusion stays small/fast, and its ring-sig core is the smallest logarithmic option (~18 KB). **Best fit for Conceal's input-heavy reality, but needs the most integration work** (extract ring-sig core, adopt one-proof-per-tx model).
  - **Raptor** — smallest/fastest at ring 6 today, but linear (no privacy headroom) and needs a nullifier redesign.
- **Recommendation for the decision:** if Conceal keeps small rings and wants the least crypto risk → **Raptor-style**; if Conceal wants real privacy headroom (bigger rings) and efficient fusion/deposits → **MatRiCT-Au-style ring-sig core** is the target, with **Falafl as the clean reference** to prototype against. Whichever: **prototype the chosen core to constant-time + audit before any mainnet decision.**
- **Deposits add a second PQ job** regardless: the multisig deposit path needs a PQ ordinary signature (ML-DSA/Falcon), separate from the ring sig.

*All PQ figures are unaudited-prototype measurements, single-thread on a Ryzen 9 5950X (~3.4 GHz). MatRiCT-Au ring-sig-core sizes are paper-derived (Table 3); its full-RingCT sizes and all verify times are measured here. Re-verify before deciding.*
