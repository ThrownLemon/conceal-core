# Adversarial crypto review — `pqc/ccx-pqc/src/ringsig.rs`

EXPERIMENTAL lattice AOS/LSAG linkable ring signature. Scope: anonymity,
soundness/unforgeability, linkability, sampling bias / param consistency.
Read against the real code at `pqc/ccx-pqc/src/ringsig.rs` and its callers
`pqc/ccx-pqc/src/lib.rs` and `src/CryptoNoteCore/Blockchain.cpp`.

Bottom line: the construction is structurally close to a correct AOS ring of
Dilithium Sigma proofs, and for an **honest** signer it works (anonymity is
*almost* right, links correctly). But against a **malicious** signer it is
**BROKEN on soundness AND linkability**: a prover with **no secret at all** can
forge a valid signature against any ring and choose an arbitrary link tag. That
defeats double-spend protection (the security property the whole PQ-input scheme
exists to provide). Several smaller anonymity/bias bugs compound this.

Severity legend: CRITICAL = breaks money/consensus, HIGH = breaks a stated
security property, MEDIUM = weakens it, LOW/INFO = hygiene.

---

## 1. CRITICAL — Universal forgery: the tag `I` is never bound to a secret; an attacker with no secret forges and picks any nullifier

### Where
- `verify()` lines 231-261 — the verifier only re-walks the chain and checks
  `seed == seed0`. It checks `||z_i||_inf <= ZBOUND` and chain closure. It does
  **NOT** check that the supplied tag `I` (read at line 238) equals `A2*s` for
  any `s`, nor that any branch was a "real" Sigma response.
- `sign()` lines 188-194 — the simulation of a non-signer branch is
  `w_i = A*z_i - c*t_i`, `w2_i = A2*z_i - c*I`, using **only public `t_i` and the
  chosen `I`**. No secret is used in the simulated path.
- The "real" branch (lines 200-204) is the *only* place a secret enters, and it
  is structurally indistinguishable to the verifier from a simulated branch.

### The attack
In an AOS ring, soundness rests on exactly one branch being un-simulatable
without a witness: you commit `w` *before* you learn its challenge `c`, so to
answer you need `z` with `A*z = w + c*t`, which requires the secret (or breaking
MSIS). Here the attacker never needs such a branch:

1. Pick the ring (all public `t_i`), pick an **arbitrary** tag `I` (e.g. all
   zeros, or `A2*s'` for a secret `s'` the attacker *does* own but that is not
   in the ring — or simply random bytes).
2. Pick a starting branch index `0`, choose a uniform short `z_0 in [-ZBOUND,ZBOUND]`.
3. Set `seed = seed0` to an arbitrary 32-byte value. Compute
   `c_0 = SampleInBall(seed0)`, `w_0 = A*z_0 - c_0*t_0`,
   `w2_0 = A2*z_0 - c_0*I`, then `seed_1 = hash_seed(...,w_0,w2_0,1)`.
4. Repeat the simulate step for `i = 1..n-1`, each time drawing a fresh short
   `z_i` and computing `(w_i,w2_i)` from the *current* `seed`, then advancing.
5. After branch `n-1` the chain wraps to index `0` and produces
   `seed_n = hash_seed(...,w_{n-1},w2_{n-1},0)`.

The only closure condition is `seed_n == seed0`. The attacker simply runs the
loop *forward* and **defines `seed0 := seed_n`** — i.e. there is a free fixed
point. Concretely: do steps 3-4 starting from a *guess* of `seed0`; you don't
even need a fixed point because you can choose to start the published chain at
the branch whose incoming seed you computed last. The standard "no-secret AOS
forgery" is: simulate **all `n` branches**, which yields `n` equations
`seed_{i+1} = H(..., w_i, w2_i, i+1)`; pick `z_0..z_{n-1}` freely, walk the
chain, and output `seed0 = seed_0`. Because every branch is simulatable with
public data, there is no branch that pins down a secret, so the ring closes for
**any** ring and **any** `I`.

Why the usual AOS proof does *not* save this: in a sound AOS/LSAG, the simulator
for a *fake* branch must choose `w_i` to *match* a `c_i` it does not yet control,
which is why only the witness-holder can close the loop at their index. Here the
prover controls the entire walk because `seed0` (hence `c_0`) is **attacker-chosen
output, not a commitment**. There is no commitment that is fixed *before* its own
challenge for any branch. The construction is missing the AOS invariant that the
real signer commits `w_j = A*y` (independent of `c_j`) and is *forced* to answer
the derived `c_j`; a cheater just never creates such a branch.

### Consensus impact (money-critical)
`src/CryptoNoteCore/Blockchain.cpp:2522-2542`: the daemon takes the nullifier
**straight out of the signature** (`recoveredNf` = whatever `I` the signer
embedded) and only checks `recoveredNf == txin.nullifier`. Since the attacker
chooses `I` freely, they choose the nullifier freely. Consequences:

- **Forge a spend of any PQ output you do not own.** Build a ring containing a
  victim PQ output, forge as above, attach a fresh attacker-chosen nullifier →
  the input verifies. Combined with the coinbase emitting fixed-denomination PQ
  outputs, this is direct theft on the PQ path.
- **Double-spend.** The same real output can be spent twice with two different
  attacker-chosen `I` values; the double-spend set keys on `I`, so it never
  collides. Linkability (§3) is fully bypassed.

This is the single most important finding: **the property the scheme exists to
provide — one-spend-per-output via the link tag — does not hold against a
malicious signer.** The code/comments claim "malicious-signer-sound" (file
header lines 5-7); that claim is false.

### Fix (direction — non-trivial, needs the real ZK proof)
There is no local patch that makes this AOS variant sound, because the flaw is
the absence of a binding commitment. Options:
- Replace with a genuine one-out-of-many / Sigma-OR proof where the tag `I` is
  proven (in zero knowledge) to satisfy `I = A2*s` for the *same* `s` whose `t`
  is one of the ring members — i.e. bind `I` to the ring, not just publish it.
  This is exactly the audit-gated milestone the `lib.rs` header (lines 13-17)
  already flags; the `ringsig.rs` header's stronger "sound" claim contradicts it.
- At minimum, the verifier must be unable to accept a chain that has *no*
  witness branch. The current chain has no such constraint.

Until then this backend must stay testnet-only and must not be presented as
sound; the POC writeup should state the forgery explicitly.

---

## 2. HIGH — Anonymity: real vs simulated `z` are NOT identically distributed (different modulo-bias profiles); also `y` and `z_sim` derive deterministically from `sk_seed`

### 2a. Distribution mismatch from modulo bias
For anonymity the accepted real response `z_j` (lines 201-204) and each simulated
`z_i` (lines 184-186, sampler lines 221-227) must be identically distributed.

- Real path: `y` uniform on `[-GAMMA, GAMMA]` (sampler `sample_mask`, lines
  104-110), `z_j = y + c*s`, accepted iff `||z_j||_inf <= ZBOUND`. With a *truly
  uniform* `y` and accept region exactly `[-ZBOUND, ZBOUND]` (= `[-(GAMMA-BETA),
  GAMMA-BETA]`), rejection sampling makes `z_j` uniform on `[-ZBOUND,ZBOUND]^{LN}`
  — the standard Dilithium argument, and here the bounds line up (`ZBOUND =
  GAMMA - BETA`, `BETA = TAU*ETA`, verified). So the *idealized* distributions
  match. Good.
- But neither sampler is uniform. `sample_mask` (line 108) does
  `read_u32() % (2*GAMMA+1) - GAMMA`; `2^32 mod (2*GAMMA+1) = 245761` low values
  get extra weight (relative bias ~1/16383). `sample_mask_bounded` (line 225)
  does `read_u32() % (2*ZBOUND+1) - ZBOUND`; `2^32 mod (2*ZBOUND+1) = 181619`
  low values get extra weight (~1/16393). The two biases have **different
  support sizes and different skew**, so after the real-path convolution+rejection
  the real `z_j` and the simulated `z_i` have *measurably different* coefficient
  distributions. An adversary collecting many signatures from the same ring can
  build a per-index statistical test and bias the guess of which branch is real —
  i.e. partial deanonymization. Small per-sample, but it is a real, non-uniform,
  index-correlated signal, so it does not average away across a fixed signer.

Fix: use rejection sampling to remove modulo bias in *all* of `sample_mask`,
`sample_mask_bounded`, `sample_secret`, and `gen_matrix` (reject draws `>=
floor(2^32 / span) * span`). Then real and simulated supports are both exactly
uniform on `[-ZBOUND, ZBOUND]` and the AOS anonymity argument applies.

### 2b. Simulated `z_i` is a deterministic function of `sk_seed`
`sample_mask_bounded(sk_seed, attempt, idx)` (line 186/221) derives the *decoy*
responses from the **signer's secret seed**. They are still ~uniform, so this
does not directly leak to a third party, but it is a footgun: it makes the decoy
responses correlated with the signer across signatures (same `sk_seed` →
deterministic decoys per `(attempt, idx)`), and it conflates the secret with
public randomness. A correct construction samples decoy `z_i` from fresh public
randomness (or at least from a seed independent of `sk_seed`). At minimum this
should be documented; ideally use a per-signature random seed.

### 2c. The `y` mask is also deterministic in `(sk_seed, attempt)`
`sample_mask(sk_seed, attempt)` (line 172/104) is deterministic. Dilithium does
this deliberately (derandomized) but mixes in the message; here `y` does **not**
depend on the message or ring, so signing two different messages with the same
`(sk_seed, attempt)` reuses the same commitment `w_j = A*y`. If for two messages
`m, m'` the same `attempt` is accepted, the signer reveals
`z = y + c*s` and `z' = y + c'*s` with the same `y` → `z - z' = (c - c')*s`,
leaking `(c-c')*s` and enabling secret recovery (a classic nonce-reuse break).
Because `attempt` starts at 0 every call and acceptance probability is high, the
*same* `attempt=0` `y` is very likely reused across messages. This is a
secret-key recovery path independent of §1.

Fix: derive `y` (and the decoy seeds) from `H(sk_seed || msg || ring || attempt)`
so the mask is unique per message/ring, as in Dilithium's deterministic signing.

---

## 3. HIGH — Linkability is not enforced and is forgeable (consequence of §1)

The tag `I` is supposed to be `A2*s` and deterministic in the signer's secret,
so two spends of the same output collide and are rejected. In the real code:

- For an **honest** signer, `I = A2*s` (lines 161, 144) and the chain only
  closes with that `I` (the real branch's `w2_j = A2*y` forces
  `A2*z_j - c*I = w2_j` iff `I = A2*s`). So honest signers link correctly.
- For a **malicious** signer, §1 shows `I` is free. So a cheater can:
  - **Avoid linkage / double-spend**: spend the same output twice with two
    different `I` (different nullifiers) — neither the chain check nor the
    daemon's `m_spent_pq_nullifiers` set (Blockchain.cpp:2280, 3145) catches it.
  - **Duplicate/grief**: set `I` to a *victim's* tag to pre-spend their
    nullifier, locking the victim out (the daemon inserts the nullifier on the
    attacker's tx; the victim's later legitimate spend then collides). This is a
    denial-of-service against honest holders.

There is also no proof that `I` uses the **same** `s` as any ring member's `t`
even in spirit — `A` and `A2` are independent public matrices (lines 92-93) and
nothing ties the `s` in `t=A*s` to the `s` in `I=A2*s`. A correct LSAG-style
tag must be bound to the *signing key in the ring*; here it is an unbound,
free-floating value.

Fix: same as §1 — the tag must be proven equal to `A2*s` for the same `s` whose
`A*s` is a ring member, inside the zero-knowledge proof. There is no way to make
linkability sound while soundness (§1) is broken.

---

## 4. MEDIUM — Challenge binding is incomplete: `seed0` (hence `c_0`) is not committed; `idx` is hashed into the chain

### 4a. `seed0` is a free input, not derived from a commitment
`verify()` reads `seed0` from the signature (line 237) and uses it directly as
the first challenge seed (line 250). In a Fiat-Shamir ring the *closure* is
supposed to be the only free seed, and the binding to message/ring/tag must make
the chain infeasible to satisfy without a witness. Because every branch is
simulatable (§1), `seed0` being attacker-chosen is what enables the forgery. The
challenge *is* bound to `msg`, `ring_blob`, `tag_bytes`, and all `w_i/w2_i` via
`hash_seed` (lines 148-152) — that part is fine and prevents message/ring/tag
substitution (confirmed by the selftest `wrongmsg_rejected`, lib.rs:289). The
defect is structural (no committed branch), not a missing hash input.

### 4b. `idx` mixed into `hash_seed`
`hash_seed(..., idx)` (line 150) includes the branch index. This is fine for
domain separation and does **not** leak the signer (the index hashed at step `i`
is the *position* in the walk, applied uniformly to every branch in both sign and
verify), but note the next-seed uses `nx` (the *target* index) consistently in
both sign (line 196) and verify (line 258) — verified consistent, so this is not
a verify/sign mismatch. No index leak in `verify` itself. (INFO.)

---

## 5. MEDIUM — Modulo bias in matrix and secret sampling

- `gen_matrix` line 86: `(read_u32() as i64) % Q - Q/2`. `2^32 mod Q = 4193792`,
  so the matrix entries are biased; worse, the range produced is
  `[-Q/2, Q-1-Q/2] = [-4190208, 4190208]` which is **not** a centered
  representative mod `Q` (it spans `Q` values but offset; top value `4190208 =
  Q/2` and `-Q/2` both appear, i.e. `±Q/2` are both representable — a 1-off
  asymmetry, not reduced into `(-Q/2, Q/2]`). The bias is cosmetic for a *public*
  matrix in a demo, but it means `A` is not uniform mod `Q` and `±Q/2`
  collision exists. Low security impact (public, fixed), but fix with rejection
  sampling and `cmod` for cleanliness and to match the documented ring.
- `sample_secret` line 100: `read_u32() % (2*ETA+1) - ETA`, span 5,
  `2^32 mod 5 = 1` → coefficient `-ETA` is very slightly favored
  (~1 part in 2^30). Negligible but real; the secret is then *not* uniform on
  `[-ETA,ETA]`, marginally shrinking key entropy. Fix with rejection sampling.

---

## 6. Parameter consistency check (demo-grade, as labeled)

Verified internally consistent for *correctness* (not security level):
- `BETA = TAU*ETA = 39*2 = 78` is the exact max `||c*s||_inf` (TAU nonzero
  `±1` challenge coeffs each times `|s| <= ETA`). Correct worst-case bound.
- `ZBOUND = GAMMA - BETA = 131072 - 78 = 130994`. The accept region equals the
  decoy support, so the idealized rejection-uniformity argument holds (modulo §2
  bias). Correct.
- Rejection acceptance prob per coeff `~ (2*ZBOUND+1)/(2*GAMMA+1) ≈ 0.9994`, over
  `L*N = 1024` coeffs `~ 0.54` per attempt; 256 attempts → abort prob negligible.
  Internally fine.
- `K=L=4`, `N=256`, `q=8380417` (Dilithium prime). These are coherent as a ring
  but, as the header states, give **no calibrated security level** — MSIS/MLWE
  with these dims is not 128-bit; treat as structural demo only. The negacyclic
  schoolbook mul (lines 40-53) is `O(N^2)` and correct for `X^N+1`.
- `SampleInBall` (lines 112-121) places exactly `TAU` nonzero `±1` coeffs;
  Fisher–Yates-free but the "skip if occupied" loop is fine for uniformity of the
  *set* of positions, though the sign bit is drawn from a *separate* u32 (line
  118) — correct, no bias there beyond the `&1` low-bit which is unbiased.

So params are *self-consistent for correctness*; they are explicitly NOT a
security level, which the code says. No bug here beyond the sampling biases above.

---

## 7. INFO / hygiene

- `sign()` carries a dead `seed: [[u8;32];1]` scaffold (lines 175, 207-208, 215
  `let _ = seed;`) — confusing, remove.
- `verify()` returns the tag bytes on success and the caller hashes them to the
  nullifier (lib.rs:137). Because the tag is attacker-chosen (§1), this nullifier
  is attacker-chosen — already covered, but worth noting the daemon trusts it
  (Blockchain.cpp:2538).
- Not constant-time (documented). `poly_mul` early-outs on zero coeffs (line 43),
  and `sample_challenge` branches on secret-independent data; the secret-dependent
  rejection (line 204) leaks acceptance timing. For a real deployment this needs
  constant-time treatment, but it is moot while §1 stands.
- `gen_matrix` / samplers read `u32` per coeff with no rejection — combine with §5.

---

## Property verdicts (against the current code)

| Property | Honest signer | Malicious signer | Verdict |
|---|---|---|---|
| Anonymity (signer hidden) | almost (idealized OK; broken by §2 bias + §2c nonce reuse) | n/a | **WEAK / BROKEN** (§2) |
| Soundness / unforgeability | n/a | forgeable with **no secret**, any ring (§1) | **BROKEN** |
| Linkability (one tag per output) | holds | tag is free → avoid/duplicate (§3) | **BROKEN** |
| Param/rejection-bound consistency | — | — | **HOLDS** (demo-grade; biases in §5) |

The honest-path machinery is wired correctly (it links, it round-trips, it binds
msg/ring/tag), which is why the selftest passes — the selftest only exercises
honest signing. None of the stated *adversarial* properties (unforgeability,
sound linkability) hold. The `ringsig.rs` header claim "malicious-signer-sound"
is incorrect and should be retracted; `lib.rs`'s more cautious header is closer
to the truth but still understates the universal forgery.
