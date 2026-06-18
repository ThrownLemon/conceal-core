# Lattice linkable ring signature — hardening pass

Status: **EXPERIMENTAL / TESTNET-ONLY / UNAUDITED.** This document records a hardening pass over
`pqc/ccx-pqc/src/ringsig.rs` (CIP-0001 §5.3): a soundness re-verification, an NTT performance rewrite,
a heuristic parameter bump, and a **constant-time rewrite of the modular-arithmetic hot paths** (§5 —
one of the documented mainnet activation gates). **Nothing here makes the scheme audited or
mainnet-ready.** The remaining gate (professional cryptographic audit; estimator-calibrated parameters;
constant-time *sampling/challenge handling* and a decision on the rejection-loop residual — see §5 — or
a decision to port a published scheme) is stated explicitly at the end.

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

#### 1.3.2 Four-reviewer hardening pass (Codex + Gemini + GLM + CodeRabbit)

A second round of four independent reviews strongly corroborated each other and surfaced further fixes,
applied here. The most-corroborated (CodeRabbit ×2 + Codex + Gemini + GLM) is the **ring-member key
validation**, the root cause behind two distinct losses:

- **Algebraic key aliasing → loss of funds (Gemini).** The same non-canonical encoding gap as the tag
  also applied to ring-member public keys `t`: an output key `t` and `t+q` are algebraically equal (one
  secret, one nullifier) but bytewise different, so only one of the two outputs is ever spendable while
  both can be accepted on-chain.
- **Consensus split (Codex + GLM).** A non-canonical `t_i` lands differently in the hashed `ring_blob`,
  so two honest nodes derive different `seed_{i+1}` from the *same* on-chain ring → they disagree on
  validity → the chain forks.
- **DoS (CodeRabbit).** A ring member `Vec` shorter than `PK_BYTES` made `get_veck` read out of bounds.

**Fix (defence in depth, three layers):**
1. `ringsig::sign`/`verify` now decode every ring member through `decode_ring_member`, which checks
   `p.len() >= PK_BYTES` (DoS) **and** `veck_is_canonical(t)` (aliasing/split) before use; either failure
   aborts with `None`.
2. A new C ABI `ccx_pq_pubkey_is_canonical(pk, len) -> i32` is called in the daemon's `check_outs_valid`
   (`PqKeyOutput` case), so a non-canonical PQ output key is **rejected at output-acceptance** — kept out
   of the chain index entirely (the root fix).
3. The `adversarial_soundness_ok` vectors now include a non-canonical ring-member check, and run across
   ring sizes 2, 4, 8.

Other corroborated fixes in this pass:
- **Integer-overflow guard (Codex HIGH + Gemini + GLM).** `ccx_pq_sign`/`ccx_pq_verify` computed
  `ring_count * member_stride` (fed to `from_raw_parts`) with no overflow guard — a wrapped product
  yields a tiny slice and an OOB read in `split_ring`. Now bounded by `MAX_RING_COUNT = 32` (a superset
  of the consensus `PQ_MAX_RING_SIZE = 16`) and computed with `checked_mul`, returning `-4` on
  overflow/over-max.
- **NTT-equivalence is now CI-verifiable (GLM HIGH).** The deleted schoolbook `poly_mul` left the
  pure-speedup claim untested in-tree. A reference `poly_mul_schoolbook` is restored and
  `ccx_pqr_ntt_equiv_test(iters)` asserts NTT == schoolbook over the scheme's real input distributions
  (z masks, sparse ±1 challenges, uniform `t`, secret-range) plus edge cases — exercised by the daemon
  build, **0 mismatches**.
- **Crate pinning + committed lockfile (GLM HIGH + Gemini HIGH).** `detkeygen`'s `#[allow(deprecated)]`
  rides `ml-kem 0.3` / `ml-dsa 0.1` encoding entry points that upstream will change; a `cargo update`
  could silently alter the wallet-key byte encoding → mnemonics unrestorable → funds loss. `Cargo.toml`
  now pins **exact** `=0.3.2` / `=0.1.1` / `hybrid-array =0.4.12`, and `pqc/ccx-pqc/Cargo.lock` is
  committed (gitignore exception). The detkeygen-through-pqcrypto interop selftest stays the runtime net.

### 1.4 Honest residual soundness caveats

- **Random-oracle / Fiat-Shamir-with-aborts model.** Soundness is argued in the ROM; there is no
  machine-checked or reduction-level proof. The abort distribution and the simulator's decoy `z`
  distribution are argued uniform (the accept region equals the decoy support), not proven
  indistinguishable to a calibrated bound.
- **Side-channels: hot paths now constant-time, residual remains** (see §5). The modular-arithmetic
  hot paths are constant-time; sampling/challenge handling and the secret-dependent rejection-loop
  abort count are not yet addressed. Soundness ≠ side-channel resistance.
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

The constant-time rewrite (§5) costs a small, measured amount on top of these figures — see §5's
before/after table; it does **not** change the outputs (bit-identical).

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

**Wire-format version signal (consensus implication — `SCHEME_ID` bump).** The `K=L=4→6` change altered
the pk/sig byte sizes with no version signal, so an old client could mis-parse a wrong-sized buffer.
`SCHEME_ID` is therefore bumped `0xC0DE_0003 → 0xC0DE_0004`: an old client now rejects the new format
cleanly at the version check. Because the testnet PoC is **experimental and resettable**, a clean scheme
bump is the right gate here; on mainnet a format change of this kind would instead be a height-gated hard
fork (new `BLOCK_MAJOR_VERSION` / `UPGRADE_HEIGHT_*`), never a silent in-place change.

**Chain-bound keys (consensus implication — network tag).** The deterministic wallet keygen
(`detkeygen`) now binds a `NETWORK_TAG` (`b"ccx-testnet"`) into its SHAKE domain, so the same mnemonic
yields **different** PQ keys on testnet vs a future mainnet (and keys are chain-bound). This is pinned
NOW because the wallet derives keys via the `*_det` FFIs as we speak — it calls them opaquely, so only
the resulting address bytes change, which is harmless pre-launch but **must be final before any wallet
ships**. The tag is a named const, so a mainnet variant is a one-line change.

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

1. **Constant-time implementation.** *Partially done — see §5.* The modular-arithmetic **hot paths**
   (`mulmod`, `cmod`/`pmod`, `addq`/`subq`, hence the NTT butterflies and all reductions on the secret
   `s`, masks `y`, responses `z`) are now division-free and branchless (constant-time), bit-identically.
   **Still open** before mainnet: constant-time **sampling** and **challenge handling**, an audit of
   `poly_mul` operand-independence at the instruction level, and a decision on the **rejection-loop
   abort-count residual** (the `sign()` Fiat-Shamir-with-aborts iteration count is secret-dependent —
   a known lattice-signature consideration, documented in §5).
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

## 5. Constant-time modular arithmetic (mainnet activation gate — DONE for the hot paths)

The scheme was testnet-only **partly because the modular reductions branched on / divided by
secret-dependent data**: the secret key `s`, the per-signature masks `y`, and the responses `z` all flow
through `cmod`/`pmod`/`mulmod`/`addq`/`subq` in the NTT butterflies and reductions. This pass makes those
**hot paths constant-time**, with **bit-identical outputs** (no wire/format/scheme change).

### 5.1 What was non-constant-time, and the fix

| Function | Was | Side channel | Now (constant-time) | Bit-identical over |
|---|---|---|---|---|
| `mulmod(a,b)` | `(a*b) % Q` | hardware `idiv` latency is data-dependent | **Barrett**: `i128` multiply by `BARRETT_M = ⌊2⁴⁶/Q⌋`, arithmetic `>> 46`, then **two masked subtracts** | both operands in `[0,Q)` (every call site) |
| `cmod(a)` | `a % Q` + two `if` folds | `idiv` + 2 secret branches | `reduce_to_0q(a)` then one **branchless** centered fold | full `i64` (covers centered sums/diffs, intt outputs, and the i32/u32 adversarial ranges) |
| `pmod(a)` | `a % Q` + one `if` fold | `idiv` + 1 secret branch | `reduce_to_0q(a)` (division-free) | full `i64` |
| `addq(a)` | `if a>=Q {a-Q} else {a}` | secret-dependent branch | `let t=a-Q; t + (Q & (t>>63))` | `[0, 2Q)` (butterfly sum range) |
| `subq(a)` | `if a<0 {a+Q} else {a}` | secret-dependent branch | `a + (Q & (a>>63))` | `(-Q, Q)` (butterfly diff range) |

`reduce_to_0q(a)` is a general division-free reduction of an arbitrary `i64` to `[0,Q)`: estimate
`⌊a/Q⌋` with a fixed-point reciprocal `RECIP = ⌊2⁸⁴/Q⌋` (`i128` multiply, arithmetic `>> 84` which floors
toward −∞), then correct with a fixed, branchless `±Q` masked-select count. The estimate error is `< 1`
over the whole `i64` range (`|a|·(2⁸⁴/Q − RECIP)/2⁸⁴ < |a|/2⁸⁴ ≤ 2⁶³/2⁸⁴ < 1`), plus at most 1 from the
two floors, so a single correction each side suffices; two each side are applied as a proven-ample
constant-count margin. The masked-select idiom is `(v >> 63)` (arithmetic shift → all-ones iff `v<0`)
ANDed with `Q`, so there is **no secret-dependent branch and no `idiv`** anywhere on the hot path.

### 5.2 Bit-identical proof (no output changed)

The whole point is that the constant-time rewrite changed **nothing** observable — signatures, public
keys, tags and nullifiers are byte-for-byte unchanged and the format is wire-compatible. Evidence:

- **NTT-vs-schoolbook equivalence: `ccx_pqr_ntt_equiv_test(5000) = 0` mismatches.** The transform (which
  is where all the reductions live) still equals the reference `O(N²)` schoolbook multiply over the
  scheme's real input distributions plus edge cases. This is the same end-to-end oracle the NTT speedup
  was proven against — 0 means the arithmetic is unchanged.
- **Unit tests (`cargo test`, in `ringsig.rs`'s `#[cfg(test)] mod tests`)** assert each new primitive is
  bit-identical to the *old* `%`/branch-based definition over the exact input ranges it is reachable
  with: `addq`/`subq` exhaustively over their butterfly ranges; `mulmod` over edges + 2 M random pairs
  in `[0,Q)²`; `cmod`/`pmod` densely around 0 and ±multiples of `Q`, at the i32/u32 edges, and over 6 M
  random i64/i32/u32 — **0 mismatches**.
- **C-ABI selftests (against the compiled `libccx_pqc.a`):** `ccx_pqr_ringsig_selftest` ok=1 ·
  `ccx_pq_ringsig_selftest` ok=1 · `ccx_pqr_forgery_test` = 0 · `ccx_pqr_soundness_test` = 1 ·
  `ccx_pqr_ntt_equiv_test` = 0. Sizes unchanged (pk 6144, sig 30752 for ring-4). `conceald` links clean.

### 5.3 Cost (before → after, ring-4, WSL x86_64, release, median of 200)

| Build | sign (median) | verify (median) |
|---|---:|---:|
| before (division/branch `%` + `idiv`) | **2.09 ms** | **0.95 ms** |
| after (constant-time Barrett + branchless) | **2.46 ms** | **1.12 ms** |
| delta | +0.37 ms (≈ +17 %) | +0.17 ms (≈ +18 %) |

The before figure was measured by running the *identical* timing harness against the pre-rewrite
primitives (original `%`-based `mulmod`/`cmod`/`pmod`/`addq`/`subq`, same test module). Both builds
produce identical signatures; only the timing differs. Verify stays near ~1.1 ms — still well under the
old 6.9 ms schoolbook verify, so the constant-time tax is comfortably absorbed. (Barrett costs an `i128`
multiply + shift where the divide used to be; the branchless folds add a couple of ALU ops per coeff.)

### 5.4 Residual: secret-dependent rejection-loop iteration count (NOT fixed here — documented)

`sign()` is Fiat-Shamir-**with-aborts**: it loops sampling a fresh mask `y` until the real-branch
response `z_j = y + c_j·s` passes `‖z_j‖∞ ≤ ZBOUND`, otherwise it restarts (up to 256 attempts, else
`None`). The **number of attempts is data-dependent** — it depends on `c_j·s`, i.e. on the secret — so the
*wall-clock time and the attempt count of `sign` leak information about `s`* via a timing/observable
channel, independent of the now-constant-time arithmetic inside each attempt.

**Assessment: acceptable to leave as a documented residual for the testnet track; revisit at the audit
gate.** Rationale:

- This is a **well-known, standard property of Fiat-Shamir-with-aborts lattice signatures** (Dilithium,
  qTESLA, BLISS-lineage). The abort decision is a norm check on a masked value; the accepted-`z`
  distribution is independent of `s` (that is what underpins anonymity/zero-knowledge), and the leak is
  about *how many tries it took*, not *which secret*. The literature treatment ranges from "benign in
  practice for a signing oracle the attacker cannot finely time" to "mask it for high-assurance".
- `sign` is **wallet-side**, not the consensus hot path. `verify` — which every validating node runs on
  attacker-supplied input — has **no rejection loop** and is now fully constant-time on its arithmetic.
- Fully removing the leak (e.g. constant-iteration signing with a fixed attempt budget and dummy work,
  or a different sampler) is a **non-trivial change to the signing procedure** and was explicitly out of
  scope for this bit-identical pass — doing it naively risks changing the abort statistics (hence which
  signatures are produced) or introducing its own bias. It belongs with the constant-time
  sampling/challenge-handling work under the audit gate (§4), where the sampler can be co-designed.

So: **the modular-arithmetic hot paths are constant-time and done; the abort-count residual is the one
remaining secret-dependent timing dependency in `sign`, left as a documented, scoped follow-up.**

---

## Review provenance

Two rounds of review informed this document:
1. An initial `codex` crypto pass that **confirmed** the universal-forgery refutation and the
   NTT-is-a-pure-speedup conclusion and **found** the non-canonical-tag linkability break (§1.3.1).
2. A second round of **four independent reviews — Codex, Gemini, GLM, and CodeRabbit** — that strongly
   corroborated each other and drove the §1.3.2 hardening pass (ring-member key validation, ABI
   integer-overflow guard, CI-verifiable NTT equivalence, exact crate pinning, scheme-id bump, network
   tag, low-entropy-seed rejection).

The soundness claims here remain **HEURISTIC** and have **not** had a professional cryptographic audit;
the construction stays testnet-only and is never to be presented as audited.

## Selftests (all green at time of writing)

After the constant-time rewrite (§5), re-run on WSL x86_64 / release against the compiled
`libccx_pqc.a` via a C-ABI harness AND `cargo test`:

`ccx_pqr_ringsig_selftest` ok=1 · `ccx_pq_ringsig_selftest` ok=1 · `ccx_pqr_forgery_test` = 0
(refuted) · `ccx_pqr_soundness_test` = 1 (all adversarial vectors rejected, rings 2/4/8) ·
`ccx_pqr_ntt_equiv_test` = 0 mismatches (NTT == schoolbook, 5000 trials + edge cases — the
bit-identical proof that the constant-time rewrite changed no output) · constant-time-equivalence unit
tests (`addq`/`subq`/`mulmod`/`cmod`/`pmod` vs the old `%`/branch definitions) = 0 mismatches ·
KEM/DSA/multisig/detkeygen selftests ok=1 · `scheme_id` = `0xC0DE_0004` (unchanged — no wire change). Sizes
unchanged (pk 6144, sig 30752 for ring-4). Constant-time ring-4 timing: verify median 1.12 ms, sign
median 2.46 ms (before the rewrite: 0.95 ms / 2.09 ms — §5.3). `conceald` builds and links clean with the
constant-time staticlib (`make -j8 Daemon` → `[100%] Built target Daemon`), exercising the C++
`ccx_pq_pubkey_is_canonical` output-acceptance path.
