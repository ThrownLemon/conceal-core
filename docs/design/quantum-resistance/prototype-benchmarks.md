# PQ Ring-Signature Prototype — Measured Benchmarks

> **Status:** empirical / prototype evidence for [`ringsig-pqc-design.md`](./ringsig-pqc-design.md). All numbers measured on the WSL build host (Ubuntu 24.04 x86_64, 16c/54 GB), 2026-06-16. Raw liboqs report: [`measured-pq-sizes.txt`](./measured-pq-sizes.txt). This validates the **linear fallback**; the **logarithmic primary** (MatRiCT⁺/SMILE) is not yet prototyped — see "Next target".

## What was built

- **Raptor** — lattice **linkable ring signature** PoC (Zhenfei Zhang, `github.com/zhenfeizhang/raptor`), the design's **fallback** construction. C, Falcon-512 base (NTRU ring `x^512+1`, q=12289). Built with gcc -O2 + libssl-dev. Ring size = compile-time `NOU`; benchmarked at 6/16/64, 100 iterations/config.
- **liboqs** — NIST primitive sizes (ML-DSA, Falcon, ML-KEM), built from source, measured via the library API (reference baseline for one-time keys + KEM).

Both repos are cloned and built under `~/pqc-bench/` on the WSL host. The full production-precedent node, **Abelian** (`cryptoblk/Abelian`, a Monero/CryptoNote fork; lattice RingCT / MatRiCT lineage), is cloned for source reference but **not** built (full node, CT-entangled — design reference only).

## Measured timings (Raptor, avg over 100 iters)

Clock ticks ≈ microseconds (Linux `CLOCKS_PER_SEC`=1e6). Single-threaded.

**Linkable ring signature** (the construction that matters — provides the nullifier/key-image equivalent):

| Ring size | keygen | sign | verify |
|---:|---:|---:|---:|
| 6 (Conceal min today) | 8.55 ms | 1.17 ms | **0.80 ms** |
| 16 | 8.66 ms | 2.63 ms | 2.13 ms |
| 64 | 8.58 ms | 9.78 ms | 8.61 ms |

**Non-linkable ring signature** (reference, lighter):

| Ring size | keygen | sign | verify |
|---:|---:|---:|---:|
| 6 | 4.16 ms | 0.76 ms | 0.53 ms |
| 16 | 4.33 ms | 1.85 ms | 1.42 ms |
| 64 | 4.36 ms | 7.02 ms | 5.59 ms |

### Reading the results

- **Sign and verify scale linearly in ring size** (sign 1.17 → 9.78 ms ≈ 8.4× over a 10.7× ring increase; verify 0.80 → 8.61 ms ≈ 10.8×). This is exactly the expected behaviour of a *linear* ring signature and is the core reason the design prefers a *logarithmic* primary for large anonymity sets.
- **Keygen is ring-independent** (~8.5 ms linkable / ~4.3 ms non-linkable) — dominated by Falcon-512 trapdoor keygen, paid once per output, off the validation hot path.
- **Verification is cheap at small rings** — 0.80 ms/input at ring 6, ~2.1 ms at ring 16. A full node re-verifies every input; even at ring 16 this is well within budget vs today's ~tens of µs Ed25519 ring check (a ~100× slowdown, but absolute cost is still sub-3 ms/input). At ring 64 (8.6 ms/input) block-validation cost becomes a real consideration and argues for batching/optimization.

## Sizes (analytic — the PoC does not pack)

The Raptor PoC stores polynomials as raw `int64` arrays with **no NTT and no compression** (its own TODO list flags "signature size compression", "efficient discrete Gaussian sampler", "replace Karatsuba with NTT"). So its in-memory buffers (~8× inflated) are **not** a meaningful size measurement. Packed analytic sizes:

- Per ring member: 2 polynomials × 512 coeffs × ~14 bits (mod q=12289) ≈ **~1.75 KB/member** packed (the paper's optimized figure is ~1.26 KB/member).
- One-time Falcon-512 component (measured, liboqs/this PoC): pk 897 B, sig ~690–752 B.
- **At ring 6 ⇒ ≈ 7.5–12 KB/input**, vs **384 B** today (6 × 64 B). A ~20–30× blowup, growing ~1.3–1.75 KB per extra mixin.

Reference base sizes (liboqs, measured):

| Primitive | pubkey | sig / ct |
|---|---:|---:|
| Ed25519 (today) | 32 B | 64 B |
| Falcon-512 | 897 B | 752 B |
| ML-DSA-44 | 1312 B | 2420 B |
| ML-KEM-768 | 1184 B | ct 1088 B |

## Fenced size optimization — measured (Raptor packing)

A first iteration of the "fenced auto-loop" idea: shrink size **without changing what the crypto computes**. The Raptor PoC stores each signature polynomial as 8-byte `int64`; here the real coefficient ranges of an *actually-verifying* signature were measured and the minimal lossless bit-packing computed. **Fence: the measured signature must verify** (`verify_ok=0`) — it did, at every ring size. Packing integers to their minimal bit width is lossless and changes nothing the verifier computes.

Measured coefficient ranges (per signature polynomial): `d` = ±1 (2 bits, a near-ternary response), `r0`/`r1` = ±~550 (11 bits), `h` = ±12286 (15 bits, full mod-q=12289).

| ring | naive (`int64`) | **packed** | naive/member | **packed/member** | shrink |
|---:|---:|---:|---:|---:|---:|
| 6 | 98.3 KB | **16.6 KB** | 16384 B | **2760 B** | 5.9× |
| 64 | 1.05 MB | **161 KB** | 16384 B | **2520 B** | 6.5× |

- **~6× size reduction, fence held** (signature still verifies). This is the safe, measurable win the fenced loop is for — it confirms the loop pattern works *and* that the optimization is honest (verify gate, lossless packing).
- Lands at **~2.5 KB/ring-member**, in the same order as the Raptor paper's ~1.26 KB — confirming the paper's per-member figure is real for the *linear* scheme. The remaining gap is the `h` polynomial (15 bits, full mod-q, ~38% of the packed bytes). **If `h` is verifier-recomputable** (it is derived from public ring data), omitting it would reach ~1.7 KB/member — but that is a protocol change, not lossless packing, so it sits *outside* the safe fence and needs cryptographic review before claiming it.
- **Still linear.** ~16.6 KB at ring 6, ~161 KB at ring 64. Packing makes the heavy cloak ~6× lighter; it does not make it logarithmic. The light cloak remains a different-scheme question (Task 1, in progress).

### Pushing further — the lossless floor

A third iteration measured the *true lossless minimum* of the real signature coefficients: Shannon-entropy coding (the arithmetic-coding floor) and generic gzip, still gated on `verify_ok=0`.

| per ring member | fixed-pack | **entropy floor** | gzip |
|---:|---:|---:|---:|
| ring 6 | 2760 B | **2190 B** | 2850 B |
| ring 64 | 2521 B | **2089 B** | 2555 B |

- **The compaction is near exhausted.** Entropy coding buys only ~20% over plain fixed-width packing — fixed-packing already reaches ~83% of the lossless limit. The lossless floor is **~2.1 KB/ring-member** (still linear).
- **Generic compression does not help** — gzip came out *larger* than bit-packing (the packed data is already high-entropy; gzip adds framing overhead). "Just zip the signature" is a dead end; only scheme-aware packing helps.
- **Where the bytes are:** the `h` polynomial (full-range mod-q=12289, ~11–13 bits of entropy/coeff, near-uniform) is the dominant, **incompressible** chunk. `d` is ~1 bit (ternary), `r0`/`r1` are Gaussian (~9 bits). So the only large remaining lever is **omitting `h` if it is verifier-recomputable** (~38% → ~1.3 KB/member) — but that is a protocol change needing cryptographic review, *outside* the lossless fence.
- **Conclusion:** the fenced loop hit its own ceiling. Safe, lossless compaction takes Raptor from ~16 KB/member to a **~2.1 KB/member floor, linear** — a real ~8× total, but it cannot reach the logarithmic light cloak. Beyond this floor requires either a crypto-reviewed structural change (drop `h`) or a fundamentally different (logarithmic) scheme. **This is the honest limit of "get the size down" on the linear fallback.**

## Audit / constant-time readiness

**Not production-ready — by the authors' own statement.** Raptor's README: *"Prototype, non-audited (use at your own risk)."* Outstanding work it itself lists: size compression, a constant-time/efficient discrete Gaussian sampler, NTT (currently Karatsuba), unified PRNG/XOF/hash. Implications:

- The Gaussian sampler and Falcon FFT are **floating-point and not constant-time** → side-channel exposure (cf. the documented Falcon FP-sampler attacks). A consensus-grade implementation needs a constant-time integer sampler.
- No serialization/packing → wire format must be designed from scratch.
- This prototype is a **feasibility and performance vehicle only**, not a code path to ship.

## Production lattice RingCT — measured (Abelian pqringct & pqringctx)

To check the design's "logarithmic primary" assumption against shipped code, both of Abelian's production crypto libraries were patched to a pure-Go Kyber KEM (to drop the broken liboqs cgo dependency) and measured on the WSL host.

**`pqringct`** (Lattice-RingCT-v2.0 lineage) — real full transfer transactions built, verified `ok`, and serialized (`TransferTxSerializeSize`, withWitness), 1 input, ring of size N, 1 output:

| ring N | gen (ms) | verify (ms) | tx size | bytes/member |
|---:|---:|---:|---:|---:|
| 2 | 834 | 306 | 525 KB | 263 KB |
| 8 | 1055 | 775 | 1.42 MB | 178 KB |
| 16 | 2210 | 1408 | 2.62 MB | 163 KB |
| 64 | 5567 | 5179 | 9.78 MB | 153 KB |
| 256 | 23032 | 20266 | 38.4 MB | 150 KB |

**`pqringctx`** (newer "extended" lib, MatRiCT⁺-era) — transfer-witness size via the library's own `GetTrTxWitnessSerializeSizeApprox` (validated within ~0.2% of `pqringct`'s real size at ring 2):

| ring N | witness size | bytes/member |
|---:|---:|---:|
| 2 | 524 KB | 262 KB |
| 16 | 2.33 MB | 145 KB |
| 64 | 8.50 MB | 133 KB |
| 256 | 33.2 MB | 130 KB |
| 1024 | 132 MB | 129 KB |

A linear fit gives **size ≈ 267 KB + 128.7 KB × ringSize** — i.e. **linear, ~130 KB per ring member**, *not* logarithmic.

### ⚠️ The headline correction

**The only production-deployed PQ privacy code is linear at ~130–150 KB per ring member — transactions of ~0.5 MB at ring 2 and tens of MB at large rings — NOT the logarithmic ~16–30 KB that the SMILE / MatRiCT⁺ *papers* claim.** Both Abelian libraries agree. This contradicts the optimistic sizing in the design's recommendation and is the single most important empirical result here. Caveats: these include confidential-amount machinery (Conceal is plaintext-amount, which trims per-output overhead but **not** the dominant per-ring-member cost); and `pqringctx`'s figure is the library's own approximation (but it matches `pqringct`'s real measured size). The gap between the logarithmic *papers* and the linear *shipped code* is itself the finding: logarithmic lattice ring signatures at small constants are **not yet realized in production-grade code**.

## Verdict

- **A PQ linkable ring signature is buildable and functions** (Raptor green; pqringct full transfers verify `ok`). Feasibility is not in doubt.
- **Size is the gating problem, and it is worse than the paper-based design assumed.** Measured production lattice RingCT is **~130–150 KB/member, linear** → **~0.5–2.6 MB per typical transaction at ring 2–16**, vs **384 B today** (a **1000×+** blow-up). Verify is **0.3–1.4 s/input at ring ≤ 16** — orders of magnitude beyond today's ~tens of µs and a real full-node DoS concern.
- **Raptor (the linear fallback) is actually the *smaller* measured option** at small rings (~7.5–12 KB/input vs pqringct's ~525 KB) — because pqringct bundles full RingCT confidential amounts and heavier proofs. For Conceal's plaintext-amount model, a **stripped linear lattice linkable ring signature (Raptor-style) is the more realistic near-term target than full lattice RingCT.**
- **Revised recommendation input:** the "logarithmic primary at ~16–30 KB" target should be treated as **research-aspirational, not currently shippable**. A go decision should assume **MB-scale transactions** (and the block-size/fee/throughput consequences) unless/until a logarithmic scheme with small constants is implemented and audited. This materially raises the cost/risk estimate in [`ringsig-pqc-design.md`](./ringsig-pqc-design.md) §4–5.

## Next target

Measure a **research logarithmic scheme** (SMILE/MatRiCT⁺ academic implementation, not the production Abelian libs) to confirm whether the paper's ~16–30 KB is achievable in *any* runnable code, or whether the constants balloon as the production libraries suggest. Until then, plan around the measured linear reality.

---

*Measured on the WSL host. Raptor: `clock()` averages, gcc -O2. pqringct/pqringctx: Go `time.Now()` wall-clock, pure-Go Kyber KEM backend (liboqs cgo stubbed out — KEM is a minor per-output component, not the ring-size-scaling term). Harnesses + raw output under `~/pqc-bench/` on the WSL host. Unoptimized research/production code — order-of-magnitude figures.*
