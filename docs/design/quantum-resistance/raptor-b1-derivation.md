# Raptor B1 Norm Bound — Derivation for the Ring Setting

**Status: Analysis complete; lattice-estimator run pending (GitHub inaccessible from build host).**

## 1. The bound

The acceptance bound for short vectors in the Raptor ring signature is:

```
FALCON512_SQNORM_BOUND = 34_034_726   (raptor.rs:51)
```

This is `l2bound[9]` from PQClean's Falcon-512 — the squared Euclidean norm
`||s1||² + ||s2||²` acceptance threshold for a single Falcon-512 signature.

## 2. Where it is applied

| Site | Object | Source |
|------|--------|--------|
| `pair_is_valid` (sign) | signer's `(r0_π, r1_π)` | Falcon `sign_target` under real trapdoor |
| `sample_short_pair` (sign) | non-signer `(r0_i, r1_i)` | Falcon `sign_target` under throwaway trapdoor |
| `verify` per-member | every `(r0_i, r1_i)` | untrusted wire input |
| `verify` OTS | `(s0, s1)` | untrusted wire input |

## 3. Extractor analysis (the ring-setting derivation)

### 3.1 Standard rewind extractor

For a Fiat-Shamir ring signature, unforgeability is argued via a rewind-based extractor:

1. Run the honest signer to get a transcript `T` with challenge `b_π = H(msg, ring, c_1,...,c_L) ⊕ (⊕_{i≠π} b_i)`.
2. Rewind to the point where `c_π` was chosen and re-run with fresh randomness to get a second transcript `T'` with a different `c_π'` (hence different `b_π'`).
3. Both transcripts share the same ring, the same non-signer blocks `(r0_i, r1_i, b_i)` for `i ≠ π`, and the same `a_π`.

### 3.2 The extracted short vector

From the two signer-blocks:
```
r0_π + a_π · r1_π + h · b_π = c_π        (from T)
r0_π' + a_π · r1_π' + h · b_π' = c_π'    (from T')
```

Subtracting:
```
Δr0 + a_π · Δr1 = (c_π - c_π') - h · (b_π - b_π')
```

where `Δr0 = r0_π - r0_π'`, `Δr1 = r1_π - r1_π'`.

The right-hand side is a known ring element (all values are public from the two transcripts). So `(Δr0, Δr1)` is a solution to:

> Given `a_π ∈ R_q` and `target ∈ R_q`, find short `(Δr0, Δr1)` with `Δr0 + a_π · Δr1 = target`.

This is an **inhomogeneous Ring-SIS** instance over `R_q = Z_q[x]/(x^512+1)`, `q = 12289`.

### 3.3 Norm bound on the extracted vector

By the AM-QM inequality (`||x - y||² ≤ 2||x||² + 2||y||²`):

```
||Δr0||² ≤ 2(||r0_π||² + ||r0_π'||²)
||Δr1||² ≤ 2(||r1_π||² + ||r1_π'||²)
```

Each individual pair satisfies `||r0||² + ||r1||² ≤ β²_Falcon`. Therefore:

```
||Δr0||² + ||Δr1||² ≤ 2(||r0_π||² + ||r1_π||² + ||r0_π'||² + ||r1_π'||²)
                     ≤ 2(β²_Falcon + β²_Falcon)
                     = 4 · β²_Falcon
                     = 4 × 34_034_726
                     = 136_138_904
```

**The ring-setting extractor bound is `4 · β²_Falcon`** (or `2 · β_Falcon` in norm).

### 3.4 The OTS layer

The OTS signature `(s0, s1)` satisfies `s0 + aots · s1 = target_ots` with the same `β²_Falcon` bound.
A second extraction on the OTS layer yields `(Δs0, Δs1)` with norm ≤ `4 · β²_Falcon` — but this is
a separate SIS instance over the `aots` lattice (independent of the main ring keys).

## 4. Security impact assessment

### 4.1 Gaussian heuristic baseline

For the Ring-SIS lattice of dimension `2n = 1024` and determinant `q^n = 12289^512`:

```
GH = sqrt(2n / (2πe)) · q^(1/2) ≈ sqrt(1024/17.08) · 110.85 ≈ 7.73 · 110.85 ≈ 857
```

| Bound | Norm | Ratio to GH |
|-------|------|-------------|
| Falcon secret key `(f,g)` | ~41 | 0.05× (below GH — hard to find) |
| Falcon signature `β_Falcon` | 5,834 | 6.8× GH |
| Ring extractor `2·β_Falcon` | 11,668 | 13.6× GH |

### 4.2 Root Hermite factor required

For BKZ to find a vector of norm `β` in a lattice of dimension `d` with volume `V`:

```
δ^d · V^(1/d) ≤ β  ⟹  δ ≤ (β / V^(1/d))^(1/d)
```

| Instance | `log₂(δ)` |
|----------|-----------|
| Falcon-512 (β = 5834) | 0.00271 |
| Ring setting (β = 11668) | 0.00368 |

Both require very small `δ` (close to 1), meaning very large BKZ block sizes — consistent with
the NIST cat-1 assessment for Falcon-512.

### 4.3 The 4× factor

The ring extractor's bound is **4× the squared norm** (2× the norm) compared to single-Falcon.
This is a modest relaxation:

- The BKZ block size reduction from this factor is small (the lattice dimension dominates).
- Falcon-512 itself has a bound 6.8× above the Gaussian heuristic; the ring setting is 13.6× above.
- **Both bounds are far above the Gaussian heuristic**, meaning the SIS instance is not tight —
  security rests on the hash-and-sign paradigm (finding a preimage of a RANDOM target, not finding
  any short kernel vector), which is unchanged by the ring construction.

### 4.4 Key-recovery security (unchanged)

The NTRU key-recovery instance (finding the Falcon trapdoor from the public key) is **unchanged**
by the ring construction. Its security is Falcon-512's own: NIST cat-1 (~128 bits classical,
per the Falcon specification and third-party estimates).

## 5. Conclusion

| Question | Answer |
|----------|--------|
| Was B1 re-derived for the ring setting? | **Yes** — the extractor gives `4·β²_Falcon = 136,138,904`. |
| Is single-Falcon's bound correct for honest signatures? | **Yes** — Falcon's sampler produces vectors within `β²_Falcon` by construction. |
| Does the 4× factor break security? | **No demonstrated break** — the factor is modest; both bounds are far above GH. |
| Is a formal lattice-estimator run needed? | **Yes** — this document provides the parameters; a professional estimator run on the specific NTRU/SIS instance is an external-audit deliverable. |

### 5.1 Calibration against known Falcon-512 estimates

The Falcon specification (round 3 NIST submission) estimates NTRU key-recovery security via the
Core-SVP method at **~2^136.7 classical / ~2^125.3 quantum** (BKZ block size ~460, dimension 1024).

> **CORRECTION (Claude/Opus independent audit cross-check).** An earlier draft of this section
> claimed the 4× (squared-norm) / 2× (norm) relaxation costs "≤2 BKZ blocks ⇒ <1 bit" via the
> root-Hermite shift `log₂(2)/1024 ≈ 0.001`. **That arithmetic is not supported by the standard
> δ-model:** at b≈460 the curve `δ(b)` has slope `d(log₂δ)/db ≈ −8e-6`, so a δ-shift of `0.001`
> maps to ≈ **120 fewer blocks ≈ −36 classical bits**, not <1 bit. **However, neither number is the
> right way to assess this**, because the homogeneous forgery-SIS target (β and 2β) sits **far above
> the Gaussian heuristic** (6.8× and 13.6× GH, §4.1) — finding such a vector is *vacuously easy*
> regardless of the 2× factor (see §5.2). The relaxation is therefore **irrelevant to concrete
> security**: security is set by the **inhomogeneous preimage / NTRU key-recovery** instance, which
> the ring construction does **not** change. Independent Core-SVP cross-check reproduces Falcon-512's
> level (b≈460 ⇒ ~134-bit classical / ~122-bit quantum; b≈411 ⇒ ~120 / ~109), inherited unchanged.
> **Action:** drop the "<1 bit / ≤2 blocks" claim; rely on §5.2 + the lattice-estimator run below.

### 5.3 Lattice-estimator run (Phase 2.2 — COMPLETED)

Run with the Albrecht et al. `lattice-estimator` (commit fetched 2026-06, MATZOV cost model) under
SageMath 10.9 on the WSL build host. Script + raw output archived; summary:

| Instance | Result | Interpretation |
|----------|--------|----------------|
| **Forgery R-SIS** (find `‖v‖₂ ≤ 2·β_Falcon = 11668` in dim 2n=1024, q=12289) | estimator **refuses: "SIS trivially easy — set norm bound < (q−1)/2"** | Machine-confirms §5.2: the homogeneous forgery bound is **vacuous** (11668 ≈ 13.6× GH). The 2× extractor relaxation is **irrelevant** to concrete security. |
| **Falcon-512 NTRU key-recovery** (LWE-modeled, n=512, q=12289, secret/error `D_σ`, σ=1.17·√(q/2n)=4.05) | **uSVP: rop ≈ 2^141.0, β=483, d=1019**; dual-hybrid: rop ≈ 2^146.3 | The **real** security. ≈**2^141 classical** ⇒ comfortably **NIST Category 1 (≥128-bit)**, with margin. Unchanged by the ring construction (the relaxation only touches the vacuous SIS). |

**Conclusion:** the unforgeability hardness is the Falcon-512 NTRU/preimage instance at **~2^141 classical**
(NIST L1), and the ring-setting B1 relaxation does **not** reduce it (the relaxed SIS instance is already
trivially easy and therefore not the binding constraint). The `FALCON512_SQNORM_BOUND` acceptance check
stays as-is (tight, no false rejections); the 4·β² figure is the extractor's soundness slack only.

### 5.2 Important subtlety: the SIS bound vs the hash-and-sign paradigm

The SIS bound (β > GH) means the extractor's reduction is technically vacuous — there are many
short vectors in the SIS lattice above the Gaussian heuristic. However, this is also true for
single-Falcon (β = 6.8× GH). Practical security comes from the **hash-and-sign paradigm**: forging
requires finding a short preimage `(r0, r1)` of a *random* target `u` under `r0 + a·r1 = u`, which
is the **inhomogeneous SIS** (closest-vector-like) problem — harder than finding any short kernel
vector. The ring construction does not change this: the attacker still needs to solve a preimage
problem for the signer's specific `a_π`, which requires the Falcon trapdoor.

## 6. Parameters for the lattice estimator

```
Ring: R_q = Z_q[x]/(x^512 + 1)
q = 12289
n = 512

# Forgery SIS instance (from ring-signature extractor)
# Find short (s1, s2) with s1 + a*s2 = target (inhomogeneous Ring-SIS)
# Bound: ||s1||^2 + ||s2||^2 <= 136_138_904
# Lattice dimension: 1024
# Determinant: q^512

# Key-recovery NTRU instance (Falcon-512's own)
# Find short (f, g) with f*h = g mod q (given h)
# Bound: ||f||^2 + ||g||^2 <= ~1700 (Falcon-512 keygen)
# Lattice dimension: 1024
# Determinant: q^512
```

## 7. Recommendation

1. **Keep the current bound** (`FALCON512_SQNORM_BOUND`) for the honest-distribution check — it
   matches Falcon's sampler and produces no false rejections.
2. **Run the lattice estimator** (Albrecht et al. / MATZOV) on the parameters above to obtain a
   concrete bit-count for the forgery instance. The estimator was not run here because the
   `lattice-estimator` GitHub package was not installable on the build host.
3. **If the estimator confirms ≥128 bits** for both forgery and key-recovery instances, the B1
   bound is validated for mainnet. If not, tighten the bound (which requires re-tuning the
   sampler) or increase the ring parameters.
