# Lattice linkable ring signature — hardening pass

Status: **EXPERIMENTAL / TESTNET-ONLY / UNAUDITED.** This document records a hardening pass over
`pqc/ccx-pqc/src/ringsig.rs` (CIP-0001 §5.3): a soundness re-verification, an NTT performance rewrite,
and a heuristic parameter bump. **Nothing here makes the scheme audited or mainnet-ready.** The
remaining gate (constant-time implementation + professional cryptographic audit, or a decision to port
a published scheme) is stated explicitly at the end.

The construction is an AOS/LSAG hash-chained ring of Fiat-Shamir-with-aborts (Dilithium-style) Sigma
proofs over Module-SIS `t = A·s` (`s` short, `‖s‖∞ ≤ η`), with a linking tag `I = A2·s` bound into
every branch's verification. `verify` walks a symmetric ring chain and never learns which member
signed (anonymity is structural); the real branch forces `I = A2·s_signer`, so the tag is
deterministic in the signer's secret (linkable; a malicious signer cannot swap it). The nullifier the
daemon stores is `SHAKE256(I)`.

---

## 1. Soundness re-verification (Task 2a)

### 1.1 The refuted "universal forgery"

An earlier adversarial crypto review (`docs/reviews/pq-ringsig-crypto-review.md`, finding §1) claimed a
**CRITICAL universal forgery**: simulate all `n` branches with no secret, walk the chain forward, then
"publish `seed0 := seed_n`", and the ring closes for any ring and any tag `I`. We implemented that exact
attack (`ringsig::forge_no_secret`, exposed as `ccx_pqr_forgery_test`) and `verify` **rejects it**
(`forgery_test = 0`).

**Why the attack fails — the AOS/CDS soundness argument holds here.** The only acceptance condition is
`seed_n == seed0`, *and `seed0` is the seed that produces branch 0's challenge*
`c_0 = SampleInBall(seed0)`. The forger's forward walk computed every `w_i = A·z_i − c_i·t_i` using
`c_0 = SampleInBall(seed_start)` for some arbitrary `seed_start`. To "close the loop" they set the
*published* `seed0 := seed_n`. But `verify` then recomputes branch 0 with
`c_0' = SampleInBall(seed_n) ≠ SampleInBall(seed_start)`, so the recomputed `w_0` differs from the
committed one, `seed_1' ≠ seed_1`, and the chain diverges — it does **not** close.

Closing the loop therefore requires either:
- a hash preimage/fixed point of the whole walk (H = SHAKE256 modelled as a random oracle ⇒ infeasible), or
- a branch where the prover commits `w_j = A·y` *before* learning `c_j` and can answer the derived
  `c_j` with a short `z_j = y + c_j·s` — i.e. **knowledge of a witness `s`** with `A·s = t_j` for a
  ring member `j` (Module-SIS hard otherwise).

This is exactly the standard AOS/CDS one-out-of-many soundness invariant: there is exactly one branch
that cannot be simulated without a witness. The review conflated "the verifier only checks
`seed_n == seed0`" (true) with "the prover may freely choose `seed0`" (false — `seed0` feeds `c_0`,
which determines the entire walk). **Verdict: the universal-forgery claim is refuted; the construction
is sound against it in the random-oracle model, at the demo's modelling level.**

### 1.2 New adversarial test vectors

`ringsig::adversarial_soundness_ok` (exposed as `ccx_pqr_soundness_test`, expected `= 1`) adds the
vectors the task requested, each asserting `verify` **rejects** the forgery and that an honest signature
still verifies:

| Vector | What it forges | Why it must fail |
|---|---|---|
| no-secret universal forgery | the review's §1 attack | no witness branch ⇒ chain can't close (see 1.1) |
| **chosen-tag forgery** | splice an attacker-chosen tag `I` (all-zero) into a *valid* sig | `I` is hashed into every `seed_{i+1}`; changing it desynchronises the chain |
| **non-member ring** | sign with a real secret whose `t ∉ ring` | the witness branch needs `A·s = t_j` for a *member* `t_j` |
| **cross-ring replay** | verify a valid sig for ring `R'` against a different ring `R` | ring blob is hashed into every seed; the chain is ring-bound |
| **malleation** | flip a byte in `seed0` / a `z_i` / the tag; swap two `z_i` | Fiat-Shamir binds every serialized field into the chain |

All pass (`soundness_test = 1`). These are **HEURISTIC empirical checks**, not a proof. They exercise
the failure modes a deployment most fears (forged nullifier, outsider spend, replay, malleability), but
they do not bound the adversary's success probability.

### 1.3 Linkability binding

The tag `I` is recomputed by `verify` only as the published bytes and is hashed into the chain, while
the *real* branch in `sign` is the only place `I = A2·s` is enforced (via `w2_j = A2·y`, answered by
`z_j = y + c_j·s` so that `A2·z_j − c_j·I = A2·y`). A malicious signer who publishes an *algebraically*
different `I' ≠ A2·s` cannot produce a valid witness branch for `I'` (that would require a second secret
`s'` with `A2·s' = I'` *and* `A·s' = t_j`), so the linkable tag is bound to the spending secret. Honest
double-spends therefore collide (`SHAKE256(I)` equal); distinct outputs produce distinct nullifiers. The
chosen-tag vector above is the empirical witness for this.

#### 1.3.1 Non-canonical tag break — FOUND in review and FIXED

A fresh `codex` review of this pass found a **real malicious-signer linkability break** that the prior
review and the initial soundness vectors missed: `verify` deserialized the tag `I` coefficients as raw
`i32` with **no canonical-range check**, while the arithmetic reduces coefficients mod `q`. A malicious
signer could therefore encode the *same algebraic tag* with one coefficient as `I + q`: the arithmetic
still accepts (same residue), but the nullifier `SHAKE256(tag_bytes)` hashes the raw bytes, so it
**changes** — letting the same output be spent twice under two different nullifiers (a double-spend).

**Fix:** `verify` now rejects any non-canonically-encoded coefficient in the tag (and, defensively, in
the responses `z`) before hashing — a coefficient is canonical iff `c == cmod(c)`. The wire format
already serializes `cmod`'d values, so honest signatures are unaffected (verified: honest sigs still
verify and are byte-deterministic after the fix). An empty ring (`n == 0`, which would close trivially)
is now rejected in `verify` as well (it was already rejected at the C ABI, but the Rust `verify` was
unsound). Regression vectors `forge_noncanonical_tag_rejected` and the empty-ring check are added to
`adversarial_soundness_ok` (`ccx_pqr_soundness_test`), which still returns `1`. This is exactly why the
construction needs a professional audit before mainnet: a subtle encoding-vs-arithmetic gap, invisible
to the algebraic soundness argument, was a live funds break.

### 1.4 Honest residual soundness caveats

- **Random-oracle / Fiat-Shamir-with-aborts model.** Soundness is argued in the ROM; there is no
  machine-checked or reduction-level proof. The abort distribution and the simulator's decoy `z`
  distribution are argued uniform (the accept region equals the decoy support), not proven
  indistinguishable to a calibrated bound.
- **Not constant-time** (see §4). Soundness ≠ side-channel resistance.
- **Parameters are heuristic** (see §3) — soundness arguments assume Module-SIS/LWE are hard *at the
  chosen dimension*, which is not yet estimator-calibrated.

---

## 2. Performance: schoolbook → NTT (Task 2b)

The hot operation is polynomial multiplication in `R_q = Z_q[X]/(X²⁵⁶+1)`. The old `poly_mul` was
`O(N²)` negacyclic schoolbook. `q = 8380417` is the Dilithium prime and `ζ = 1753` is a primitive
512-th root of unity (`ζ²⁵⁶ ≡ −1`, `ζ⁵¹² ≡ 1 mod q`), so a length-256 **negacyclic NTT** diagonalises
the convolution. We replaced schoolbook with an in-place Cooley-Tukey forward / Gentleman-Sande inverse
NTT.

**This is a PURE speedup — signature bytes are unchanged.** The NTT computes the same residue mod `q`
and the result is canonicalised with the identical `cmod` (centered representative in `(−q/2, q/2]`), so
`poly_mul` returns byte-identical polynomials for every input. We verified this two ways:
1. NTT vs schoolbook over thousands of random vectors across the input ranges the scheme uses (`z`-range
   masks, sparse `±1` challenges, uniform `t ∈ [0,q)`) → **0 mismatches**.
2. Deterministic signatures (fixed seed/ring/message) hashed and compared between the NTT build and the
   pre-NTT (schoolbook) build → **identical fingerprints for all four signers**.

Further mechanical speedups, all bit-identical:
- **Cached matrices.** `A`, `A2` and their NTT-domain forms are generated once (`OnceLock`) instead of
  re-deriving via SHAKE on every sign/verify.
- **Shared forward transform.** `mat_vec2_ntt` forward-transforms `z` once and applies both `A` and
  `A2` (the loop always needs `A·z` and `A2·z`).
- **Pre-transformed operands.** Each ring member's `t_i` and the tag `I` are forward-transformed once
  per call; only the challenge `c` is transformed per branch (`veck_scale_ntt`).
- **`i64` modular arithmetic + single-step reduction.** `q < 2²³`, so products of residues fit in
  `i64` (no `i128` division); butterfly add/sub use conditional `±q` instead of `%`.

### Measured (WSL x86_64, release, ring-of-4)

| Build | params | verify | sign | ring-4 sig | pk |
|---|---|---:|---:|---:|---:|
| baseline (schoolbook) | K=L=4 | **6.54 ms** | 7.36 ms | 20 512 B | 4 096 B |
| NTT, same params | K=L=4 | **0.69 ms** | 0.93 ms | 20 512 B (identical) | 4 096 B |
| NTT + hardened params (shipped) | **K=L=6** | **0.89 ms** | 3.80 ms | 30 752 B | 6 144 B |

The NTT gives a **~9.5× verify speedup at fixed params**; the parameter bump (§3) then spends part of
that on security, leaving verify at **0.89 ms** — still well below the old 6.9 ms and under the 1 ms
target *even with the larger module*. `sign` is wallet-side (rejection sampling over `L=6` masks
dominates) and is not the consensus hot path; `verify` is what every validating node runs.

---

## 3. Parameters: heuristic bump toward NIST cat-1-ish (Task 2c)

**These parameters are HEURISTIC and explicitly NOT a calibrated security level.** They were chosen to
lift the demo's module rank; they have **not** been run through a lattice estimator. A cryptographer
**must** estimate the actual bit-security before this scheme is considered for anything beyond testnet.

Change: `K = L = 4 → 6` (other bounds unchanged: `N=256`, `q=8380417`, `η=2`, `τ=39`, `γ=2¹⁷`,
`β=τη=78`, `ZBOUND=γ−β`).

Rationale:
- Unforgeability binding rests on **Module-SIS** over the rank-`K` module (and the tag's `A2`), and
  key-recovery on **Module-LWE** for `t = A·s`. At fixed `N, q`, the **module rank** (here `K, L`) is
  the dominant lever on lattice-attack cost. Raising the block dimension from `4·256 = 1024` to
  `6·256 = 1536` materially increases the estimated cost of both BKZ-style attacks.
- `K = 6` mirrors **Dilithium-3's** row count (a NIST cat-3 standardized primitive) as a sanity anchor.
  We deliberately keep `η, τ, γ` at the Dilithium-2-ish demo values, so the honest claim is
  **"cat-1-ish heuristic"**, *not* "equals Dilithium-3 cat-3".
- Cost: public key (`K·N·4`) and per-member signature share (`L·N·4`) grow ~50%; a ring-of-4 signature
  goes 20 512 → 30 752 B. The ABI exposes sizes dynamically (`ccx_pq_pubkey_bytes`, the two-call
  `ccx_pq_sign` size query), so the C++ consensus path adapts with no code change — verified by a clean
  `conceald` link at the new sizes.

What "calibration" actually requires before mainnet (out of scope here):
- Run a current lattice estimator (APS / "lattice-estimator" / MATZOV refinements) over **both** the
  MSIS forgery instance and the MLWE key-recovery instance, for the *negacyclic* ring, targeting a
  concrete security level (e.g. ≥128-bit classical / cat-1) with margin.
- Re-tune `(K, L, η, τ, γ)` jointly: the abort/rejection probability, the `‖z‖∞ ≤ ZBOUND` soundness
  slack, and the `β = τη` bound all interact with the security estimate. The current set is internally
  consistent for *correctness* (the abort probability is fine) but that says nothing about bit-security.

---

## 4. Remaining gate (Task 2d): the honest recommendation

This scheme **must not ship to mainnet** until, at minimum:

1. **Constant-time implementation.** The current code is not constant-time: `cmod`/rejection sampling
   and the secret-dependent abort leak timing; `poly_mul` operand-independence needs auditing. A
   deployment needs constant-time modular arithmetic, sampling, and challenge handling.
2. **Professional cryptographic audit.** The soundness argument in §1 is correct *as an argument* and
   survives our adversarial vectors, but it is not a proof and has not been reviewed by cryptographers.
   Anonymity (decoy/real `z` indistinguishability) and the linkable-tag soundness need formal treatment.
3. **Estimator-calibrated parameters** (§3).

### Harden-this vs. port a published scheme

**Recommendation: keep hardening this construction for the testnet research track, but do NOT commit to
it for mainnet without the audit gate — and seriously evaluate a published scheme in parallel.** The
honest trade-offs:

- **Harden-this.** Pros: it already fits the flat-stride C ABI, yields a recoverable nullifier
  (`SHAKE256(A2·s)`), is anonymous + linkable end-to-end on testnet, and is now fast (0.89 ms verify).
  The signature is compact and roughly **constant in ring size for the fixed part** plus a `L·N·4`
  per-member share — a ring-of-4 is ~30 KB. Cons: it is a *bespoke* scheme; bespoke lattice ring
  signatures are exactly the kind of thing that needs heavy peer review before trusting funds to it.
  The soundness/anonymity claims, while argued, are unproven.

- **Port `pqringct` / RingCT-style lattice schemes.** `pqringct` is a *published, peer-reviewed* lattice
  RingCT. But its proofs are **LINEAR in ring size and ~130 KB per ring member** — far too large for a
  CryptoNote transaction (a ring-of-11 would be >1 MB). It also bundles amount-hiding (RingCT) we don't
  need here. **Not viable as-is for tx size.**

- **Port `MatRiCT` / `MatRiCT+` / `MatRiCT-Au`.** These are the state-of-the-art compact lattice RingCT
  designs (logarithmic-ish proofs). **There is no public, production-grade, audited implementation** —
  porting means implementing a research paper from scratch, which is *more* audit surface than hardening
  what we have, not less.

- **Net.** For a *near-term testnet PoC*, hardening this scheme is the pragmatic choice and is what this
  pass delivers. For *mainnet*, the decision should be made **after** a cryptographer reviews both this
  construction and the then-current published options; if a compact, audited lattice ring/RingCT with a
  recoverable linking tag and tractable tx size exists at that time, **porting an audited scheme is
  preferable to trusting funds to a bespoke one**. Until then this backend stays testnet-only and must
  never be presented as audited.

---

## Review provenance

This pass was reviewed by a fresh `codex` crypto pass (which **confirmed** the universal-forgery
refutation and the NTT-is-a-pure-speedup conclusion, and **found** the non-canonical-tag linkability
break fixed in §1.3.1) plus the author's own adversarial analysis and test vectors. A parallel
`opencode`/GLM-5.2 review was attempted but the tool hung without producing analysis. The soundness
claims here remain HEURISTIC and have **not** had a professional cryptographic audit.

## Selftests (all green at time of writing)

`ccx_pqr_ringsig_selftest` ok=1 · `ccx_pq_ringsig_selftest` ok=1 · `ccx_pqr_forgery_test` = 0
(refuted) · `ccx_pqr_soundness_test` = 1 (all adversarial vectors rejected) · KEM/DSA/multisig/
detkeygen selftests ok=1. Ring-4 verify 0.89 ms, sign 3.80 ms (K=L=6, NTT).
