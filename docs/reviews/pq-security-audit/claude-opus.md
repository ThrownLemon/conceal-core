# Conceal Post-Quantum PoC — External Security Audit

**Reviewer:** Claude (Opus) acting as cryptographic-algorithm security researcher
**Branch / HEAD:** `pqc/mdbx-merge-poc` @ `411c848f`
**Scope:** `docs/design/quantum-resistance/security-audit-brief.md` §4 surfaces A–E + deliverables §6
**Method:** manual code review (Rust crate `pqc/ccx-pqc/src/*`, C shim, C++ consensus glue) + structural cryptanalysis. No code built or run on the audited tree (other researchers/agents were working the same trees concurrently; this pass is static). Items needing a build/run/estimator are explicitly flagged **[DEFERRED — needs tooling]**.
**Status of target:** UNAUDITED, testnet-only, height-gated PoC. This report is input to the mainnet go/no-go gate, not a clearance.

---

## 0. TL;DR

The **live consensus spend path is `raptor.rs`** (clean-room linkable ring signature over Falcon-512), wired via `ccx_pq_sign/verify/nullifier` (lib.rs:107,127,182,215). `ringsig.rs` (a Dilithium/Module-SIS AOS ring signature, K=L=6) is **exposed only through `ccx_pqr_*` self-test ABI** and is **not** on any consensus path.

Headline results:

1. **The Raptor verifier is forgeable as a standalone primitive.** A **committed, non-ignored unit test** (`raptor.rs:586`, `ring_not_bound_into_challenge_allows_programmed_key_forgery`) builds a **no-secret forgery** and asserts `verify(...).is_ok()`. Root cause: the Fiat-Shamir challenge `hash_transcript_to_b` (raptor.rs:242) **does not bind the ring `{a0_i}`**, contradicting eprint 2018/857. On the live chain this is **contained — not fixed** — by the C++ caller hashing the ring (via output indexes) and `aots` (via the in-prefix nullifier) into `msg`. **HIGH** on the live path; **CRITICAL** as a primitive / for mainnet / for any other verify caller.
2. **No valid unforgeability proof exists for the as-built construction**, and the **norm bound `B1` was never re-derived/quantified**. The paper's reduction does not transfer (two-layer hashing). This is the brief's central open gate and a **mainnet blocker**.
3. **Determinism guards are dormant** on this branch: the Falcon-keygen KAT tripwire and the deterministic-keygen interop selftest are dead code → a funds-loss/chain-split guard is not enforced at runtime/CI.
4. Consensus glue is otherwise solid (double-spend, overflow, freeze, off-by-one all verified clean), with **one real asymmetry**: PQ *spends* lack the explicit `UPGRADE_HEIGHT_V10` gate that PQ *deposits* have.
5. Anonymity and the non-signer-sampling (CRITICAL-1) fix appear **sound** under standard assumptions; constant-time has **two genuinely-open secret-key paths** (signing sampler, ML-KEM decap) not covered by the CI tripwire.

**Mainnet: NO-GO.** **Public testnet: GO with conditions** (§9).

> **Static audit was performed at `411c848f`. While auditing, a concurrent remediation track
> (`production-readiness-prompt.md`) began fixing findings in the working tree. §0.5 records what I
> then verified dynamically on the WSL host and the live remediation status. Read §0.5 with §1.**

---

## 0.5 Dynamic verification & in-flight remediation (ADDENDUM)

Ran on WSL `100.100.90.103` (x86_64, Ubuntu 24.04) against an **isolated rsync** of the crate from the
audited Mac worktree (`~/ccx-pqc-audit-claude`), so no shared build was disturbed.

**Dynamic results:**

- **`cargo test --release`: 13/13 pass.** `KEYGEN_KAT_DIGEST = 8f245c82…745e` reproduces the pinned
  reference → Falcon keygen is **deterministic on WSL x86_64** (build-level determinism holds; ARM/MSVC
  still unverified — F3 residual).
- **F1 forgery test re-verified.** The forgery test is now `programmed_key_forgery_is_rejected` and
  **passes** (the no-secret forgery is now *rejected*). So F1 was real at `411c848f` and the fix works.
- **ctgrind under valgrind (F6): map confirmed.** Flagged origins are exactly: `sign.c` (Gaussian/BerExp
  sampler — **the genuine open item**, secret path on every spend), `keygen.c` (NTRU keygen — blessed
  under ephemeral-key), `codec.c` + `raptor_falcon.c:177 hash_to_rq` + `raptor.rs:251/255
  hash_transcript_to_b` (public-derived → benign, already CI-excluded). **The F1 fix is CT-clean** (no
  secret-dependent memory access introduced). ctgrind is necessary-not-sufficient for the sampler
  (isochronous code still has data-dependent values); **dudect is the missing tool** (cargo-fuzz/dudect
  not installed here).
- **Concrete security (Core-SVP hand cross-check; full estimator needs SageMath, not apt-installable on
  24.04):** reproduces Falcon-512 ~**134-bit classical / 122-bit quantum** (BKZ b≈460; 120/109 at
  b≈411) = NIST Level 1, inherited unchanged by the ring construction.
  - **Correction to `raptor-b1-derivation.md` §5.1:** its "2× norm relaxation ⇒ ≤2 BKZ blocks ⇒ <1 bit"
    is unsupported — the standard δ-model maps the δ-shift `log₂2/1024` to ~120 fewer blocks (~−36 bits)
    if applied naively. The right statement (the doc's own §5.2) is that the homogeneous forgery-SIS is
    **above the Gaussian heuristic (vacuous)**, so the relaxation is irrelevant and security is set by
    the **inhomogeneous preimage/NTRU** instance, unchanged. Drop the §5.1 number; keep §5.2.

**In-flight remediation (concurrent, uncommitted working tree) — verified status:**

| Finding | Remediation | My verification |
|---------|-------------|-----------------|
| **F1** ring-binding | `hash_transcript_to_b(msg, ring, cs)` binds the ring (raptor.rs:249-253), wired through sign(:473)+verify(:552); test inverted to assert rejection | **RESOLVED** — fix matches my recommendation; primitive is now sound standalone (no longer depends on caller `msg`-binding); forgery test passes as "rejected". Needs commit + the formal reduction (F2). |
| **F3** dormant guards | `Daemon.cpp` PQ selftest gate at startup (incl. `ccx_pq_ringsig_selftest` "incl. keygen KAT" + `ccx_pq_detkeygen_selftest`), aborts on failure | **RESOLVED for the daemon.** Follow-up: confirm the **wallet** binary (`concealwallet`/walletd) runs the same det-keygen gate — restore-determinism is wallet-side. |
| Open gate #6 per-spend KDF | `lib.rs` raw-concat → HKDF-like extract-then-expand over SHAKE256 (PRK=SHAKE(sk‖os_rand); seed=SHAKE(PRK‖msg)) | **Sound** — no nonce-reuse even under OsRng compromise (msg-bound expand). |
| double-spend (mempool) | `TransactionPool.cpp` adds `m_pqNullifiers` template-set + persists `m_spent_pq_nullifiers` | Tightens template selection; consistent with the block-validation set. OK. |
| **F2** B1 / proofs | new `raptor-b1-derivation.md`, `raptor-anonymity-proof.md`, `paramch-h-spec.md` (F9) | **Reviewed — concur with caveats.** B1 extractor `4·β²` correct; anonymity sketch correct (Falcon basis-independence; provable more crisply as identical `D_{Z^{2n},σ}` marginals). **Still pending:** a formal unforgeability *reduction* (not just the extractor sketch), a formal anonymity ε/Rényi bound at scale, and a real estimator run. Fix the §5.1 error above. |

**Fixes I applied in this pass (GLM track had stopped — out of credits — so no collision), all build-verified on WSL (`BUILD_EXIT=0`, full daemon + UnitTests):**

- **F4 — APPLIED.** `BlockchainStorage.cpp`: new `transactionContainsPqSpend` helper + a **mainnet-only** `< V10 → reject` gate for `PqKeyInput`/`PqKeyOutput`, in both the per-tx and coinbase paths, mirroring the existing PQ-deposit gate. Mainnet-only because `constructMinerTx` emits a coinbase `PqKeyOutput` every block under `m_testnet` (Currency.cpp:610, no V10 gate) and the injector spends from height 1 — a blanket gate would break the running testnet PoC. *Caveat:* the `!isTestnet()` gate is **not exercised by the testnet test suite**; add a mainnet-params unit test (pre-V10 PQ spend → rejected) before mainnet.
- **F8 — APPLIED + PROVEN.** Added a loud DANGER header to `ringsig.rs` (broken, never wire to consensus; selftests certify a broken scheme; recommend feature-gating) and a **key-recovery PoC test** `f8_key_recovery_poc::secret_is_recoverable_from_public_key` that recovers `s` from the public key slot-wise in the NTT domain — it **PASSES** (`cargo test`, 14/14), dynamically confirming the break. Cross-branch question resolved: `ringsig.rs` is selftest-only on **both** branches; not live anywhere.
- **B1 §5.1 — CORRECTED**, and **lattice-estimator run (Phase 2.2) COMPLETED** (SageMath 10.9 + Albrecht estimator/MATZOV on WSL): forgery R-SIS is **"trivially easy"** (estimator refuses it — confirms the relaxation is vacuous); Falcon-512 NTRU key-recovery is **uSVP rop ≈ 2^141 (β=483)** = NIST Level 1, unchanged by the ring. Recorded in `raptor-b1-derivation.md` §5.3.

**Still OPEN (deliberately not applied — need a human decision or are research follow-ups):**
- **F5** (0x07 AEAD derived-nonce reuse) — the fix (bind tx-pubkey+output-index as AAD and/or fresh nonce salt) is a **message wire-format change** that breaks existing 0x07 memo decryption → needs a format-version-bump decision. Not rushed on money-adjacent crypto.
- **F6** (signing Gaussian sampler + ML-KEM decap CT) — ctgrind already maps the regions; **dudect** (statistical timing) is the missing confirmation and is a research harness (add `dudect-bencher` dev-dep + per-secret-class timing test). Documented as the remaining CT gate.
- **F7 / LOW-3** (`ringSig` canonicality + parse-time length bound) — already double-bounded by `ccx_pq_verify` (`sig_len ≤ ring_sig_size`) + `CRYPTONOTE_MAX_TX_SIZE`; a tighter *parse-time* bound needs a change to the compatibility-sensitive serialization framework — disproportionate for a LOW, recommended as low-priority hardening.
- **Phase 6** (cross-arch KAT: ARM/MSVC — needs hardware) and **Phase 7** (compile the external-audit package).

---

## 1. Severity-rated findings

| ID | Sev (live) | Sev (mainnet/primitive) | Surface | Title |
|----|-----------|------------------------|---------|-------|
| **F1** | **HIGH** | **CRITICAL** | A | Ring not bound into the FS challenge → primitive is forgeable (committed PoC) |
| **F2** | — | **CRITICAL** | A | Unforgeability unproven for the as-built construction; `B1` unquantified |
| **F3** | **HIGH** | **HIGH** | C/D | Keygen-determinism KAT + det-keygen interop selftest are dead code (dormant guard) |
| **F4** | **HIGH** | **HIGH** | D | PQ *spends* lack an explicit `UPGRADE_HEIGHT_V10` height gate |
| **F5** | **HIGH** | **HIGH** | C | 0x07 message AEAD: derived nonce, no AAD → reuse iff tx-key reused |
| **F6** | **MEDIUM** | **HIGH** | B | Signing Gaussian sampler + ML-KEM FO-decap CT unverified; CI tripwire guards only the C glue |
| **F7** | **MEDIUM** | **MEDIUM** | D | `ringSig` canonicality delegated to FFI; no C++ assertion → possible txid malleability |
| **F8** | INFO | **MEDIUM** | A | `ringsig.rs` (selftest-only) is structurally broken; its "soundness"/"forgery" selftests certify a broken scheme |
| **F9** | LOW | MEDIUM | A | `paramch_h` NUMS lacks a documented derivation ceremony |
| **F10** | LOW | LOW | C | `NETWORK_TAG="ccx-testnet"` pre-launch tripwire; deprecated RustCrypto entry points |
| **F11** | INFO | LOW | E | Spend artifacts carry no scheme/version tag; `dsaSchemeId` not committed on-chain |

---

## 2. Surface A — Raptor ring signature (highest priority)

### Construction (as built, `raptor.rs`)

Over Falcon-512 (`R_q = Z_q[x]/(x^512+1)`, `q=12289`). Public param `h = paramch_h()`. Per signer: main Falcon key (`a = main.h`), OTS Falcon key (`aots = ots.h`), `mask = H1(aots)`, public key `a0 = a + H1(aots)`, nullifier `= SHAKE256(DOM ‖ modq(aots))`.

Sign(msg, ring={a0_i}, π): for `i≠π` draw random `b_i` and a short `(r0_i,r1_i)`, set `c_i = r0_i + a_i·r1_i + h·b_i` (`a_i = a0_i − mask`); pick random `c_π`, set `b_π = H(msg,c_1..c_L) ⊕ ⊕_{i≠π}b_i`, `u_π = c_π − h·b_π`, and Falcon-preimage `(r0_π,r1_π)` s.t. `r0_π + r1_π·a_π = u_π`. Append a Falcon OTS over `ots_target(members,ring,aots)` under `aots`. Verify recomputes `c_i`, checks `⊕b_i == H(msg,c_1..c_L)`, norm bounds, `b_i∈{0,1}^256`, and the OTS; returns the nullifier.

### F1 — Ring not bound into the Fiat-Shamir challenge (forgeable primitive)

**Evidence (reproducer is in-tree):** `hash_transcript_to_b` (raptor.rs:242-254) absorbs only `DOM ‖ len(msg) ‖ msg ‖ {modq(c_i)}` — **the ring members `{a0_i}` are absent.** The committed test `ring_not_bound_into_challenge_allows_programmed_key_forgery` (raptor.rs:586-644, a plain `#[test]`, not `#[ignore]`/`#[should_panic]`) constructs a signature with **no signer secret**:

- victim branch: `r0=r1=0` ⇒ `c_victim = h·b_victim` (the `r1=0` trick removes the key term);
- second member: choose `c` freely, set `b = challenge ⊕ b_victim`, then **solve the effective key** `a = c − h·b` *after* seeing the challenge and publish `a0 = a + mask`;
- close the OTS with the attacker's own `aots`.

`assert!(verify(...).is_ok())` passes. This is a universal forgery of the primitive: the verifier accepts a ring signature for a ring containing a key whose secret the forger does not hold.

**Why the live chain is (currently) contained — not fixed.** `ccx_pq_verify` has exactly one caller, `BlockchainPq.cpp:156`, and:

- `msg = getTransactionPqSigningHash` = `getObjectHash(prefix)` with only `ringSig` cleared (BlockchainPq.cpp:28-46) → the input's `outputIndexes` are in the signed prefix;
- ring members are **resolved from chain storage** `m_pqOutputs` by absolute offset into real `PqKeyOutput.key`s (BlockchainPq.cpp:60-150) → the attacker cannot inject a chosen `a0`;
- the nullifier is in the prefix and `recoveredNf != txin.nullifier → reject` (BlockchainPq.cpp:189) → `aots`, hence `mask`, is hash-bound into `msg`;
- duplicate/non-increasing offsets are rejected (anti ring-collapse).

With `{a0_i}` (via offsets), the outputs, and `aots` (via nullifier) all transitively bound into `msg`, the "program a key after the challenge" escape is circular and blocked, and the all-`r1=0` variant reduces to finding a hash fixed-point. So the *specific* forgery is not directly mountable on-chain **today**.

**Why this is still HIGH (and CRITICAL as a primitive):**

- The security of money-critical code rests on an **emergent property of the caller's transaction hashing**, not on the signature scheme. That is a layering violation and is **unproven** (see F2): the paper hashes the ring *into* the challenge precisely so the primitive is sound standalone; here the ring is bound only by an *outer* hash, and the inner challenge omits it — the paper's reduction does not cover this.
- It is **fragile**: it breaks to full theft (CRITICAL) the moment *any* verify path uses a `msg` that doesn't bind the ring + nullifier — e.g. a future RPC verify endpoint, a wallet-side preview, the **standalone ring-sig PoC** the brief mentions, or a refactor of `getTransactionPqSigningHash`.
- A working forgery test is **committed and green**, which is a latent footgun (a reader may assume a green suite means "sound").

**Fix (standard, small, mandatory before mainnet):** bind the ring into the challenge — `hash_transcript_to_b(msg, ring={a0_i}, cs)` — exactly as eprint 2018/857 specifies, and convert the forgery test to `#[should_panic]`/assert-rejection. This makes the primitive sound standalone and removes the dependence on caller behavior. **Recommend treating F1 as the #1 cross-reference item.**

### F2 — No unforgeability proof; `B1` never re-derived

**Unforgeability:** there is no formal reduction for the as-built scheme, and (per F1) the paper's proof does not transfer because the FS hash input differs. Even granting the on-chain `msg`-binding, a fresh reduction would have to account for the two-layer hashing and the AOS-over-Falcon-preimage structure. **Verdict: UNPROVEN.** Conjecturally rests on Falcon/NTRU (preimage hardness) + ROM; this must be either proven or the construction simplified to a provable one (e.g. proper ring-bound FS).

**Norm bound `B1`:** the acceptance bound is `FALCON512_SQNORM_BOUND = 34_034_726` (raptor.rs:51) — **Falcon-512's single-signature β²**, applied per-member and to the OTS. The brief explicitly asks whether the bound was **re-derived for the ring setting**; it was not. Reusing the single-Falcon bound is plausible because each `(r0_i,r1_i)` is an independent Falcon-style preimage and the relation is checked per-member (not as an aggregate), but this is an assertion, not a derivation. A loose bound → forgery latitude; a tight one → valid-sig rejection → chain split. **[DEFERRED — needs derivation + lattice-estimator.] Mainnet blocker.**

**Concrete security level [DEFERRED — needs the lattice estimator]:** run APS/MATZOV over (i) the Falcon-512 base (key recovery / preimage) and (ii) the AOS soundness instance, against current BKZ/sieving, and report bits. The docs claim "NIST Cat-1 (~128-bit) because Falcon-512 is standardized" — that anchors the *base primitive*, not the *ring construction*; the ring layer's soundness margin is unquantified.

### Anonymity — appears SOUND (verify empirically)

- **Decoy = signer distribution.** The CRITICAL-1 fix (raptor.rs:294-358) samples every non-signer `(r0,r1)` from **Falcon's own preimage sampler** on a random target under a per-signature throwaway key, discarding key+target. Because Falcon's GPV sampler output is (designed to be) a spherical discrete Gaussian **independent of the basis**, signer and non-signer marginals coincide; the signer's `u_π = c_π − h·b_π` is uniform (since `c_π` is uniform), matching the non-signer's uniform target; both apply the same `pair_is_valid` reject filter. **Sound in principle.** Residual: indistinguishability is only up to Falcon's sampler statistical distance; over many on-chain sigs tiny biases could accumulate. **[DEFERRED — confirm with the `stats` harness at high N + a Rényi-divergence argument.]**
- **`b_i` uniformity:** non-signer `b_i` are random; `b_π = H ⊕ b_acc` is uniform → all `b_i` look alike. OK.
- **Tag/key unlinkability:** `a0_π − H1(aots) = main.h` is a valid NTRU key while `a0_decoy − H1(aots)` is not; distinguishing requires deciding NTRU-validity (hard for Falcon params). **Sound under decisional-NTRU.** *Open question to resolve:* whether `aots`/the wallet seed is **per-output** (good) or **per-wallet** (would link all of a wallet's spends). Confirm the seed derivation feeding `keygen` per output.

### Linkability / nullifier soundness — SOUND modulo Falcon-trapdoor unforgeability

`nullifier = SHAKE256(modq(aots))`, `aots` deterministic from the secret. (a) Same output → same `aots` → same nullifier (no double-spend-via-different-tag): an alternate `(main',aots')` with `main'.h + H1(aots') = a0` would require a Falcon trapdoor for a *chosen* `h` (infeasible). (b) Distinct outputs → distinct `aots` (SHAKE collision resistance). Canonicality of `aots` is enforced (`b_is_canonical` + `modq_encode`), closing the non-canonical-tag double-spend. **Caveat:** this soundness is *subsumed by F1* — if the ring sig is forgeable (any unbound-`msg` caller), the attacker chooses `aots` freely and double-spend prevention collapses with it.

### F9 — `paramch_h` NUMS

`paramch_h = hash_to_rq("conceal-raptor-paramch-v0", DOM_PARAMCH)` (raptor.rs:55-57). A single SHAKE of a fixed string is a reasonable nothing-up-my-sleeve choice (no trapdoor), but the brief asks for a **documented derivation/ceremony**. **LOW** — formalize and document the rationale; confirm domain separation across all SHAKE uses (DOM_H1/PARAMCH/NULLIFIER/H_TRANSCRIPT/ots-target are distinct — OK).

### F8 — `ringsig.rs` (selftest-only) is structurally insecure

Not on any consensus path (exposed only via `ccx_pqr_ringsig_selftest`/`forgery_test`/`soundness_test`/`ntt_equiv`). **But it is cryptographically broken:** the key is `t = A·s` with `A` a **random square `K=L=6` matrix over `R_q`** and **no LWE error term** (ringsig.rs:479-485). For `q=8380417` (fully-split, NTT-friendly), a random 6×6 matrix over `R_q` is invertible with overwhelming probability, so `s = A⁻¹·t` is the **unique** preimage — and it is short because it equals the true `s`. Hence **the secret is trivially recoverable from the public key**, breaking unforgeability, anonymity, and linkability of that construction. Its in-crate `forge_no_secret`/`adversarial_soundness_ok` tests pass and therefore **certify a broken scheme** (they only model the naive hash-chain attack, not key recovery). **Recommendation:** delete `ringsig.rs` or quarantine it out of the shipped crate so it can never be wired to consensus and cannot be mistaken for assurance. **[DEFERRED — optional 10-line PoC: compute `A⁻¹·t` and compare to `s`.]** *(Note for the cross-referencing researcher: confirm which branch's spend path is `ringsig.rs` vs `raptor.rs` — on `pqc/testnet-poc`, memory indicates the K=L=6 construction was the live one; on this branch it is not.)*

---

## 3. Surface B — Constant-time / side-channel

Threat model (verify-only daemon; wallet vs local attacker; ephemeral per-spend Falcon keys) is correct. The ctgrind/TIMECOP harness (`Cargo.toml` `ctgrind` feature; `ct_leakmap` poisons the 48-byte signer seed) and CI job (`check.yml`, "ctgrind (constant-time)") are real, and one genuine glue leak (`a[i]==0 continue` in mod-q polymul) was found and fixed.

**F6 — the gate is narrow, and two secret-key paths are genuinely open.** The CI awk filter fails only on "uninitialised" origins in `raptor_falcon.c` **and not** `hash_to_rq` — i.e. it guards **only the hand-written C glue**, excluding keygen, the sampler, ML-KEM, and the public encoders.

| Region | Verdict |
|--------|---------|
| Falcon **keygen** (non-CT NTRU solve) | **Blessed — sound** *given* keys are ephemeral and never re-derived on load. **Condition to verify:** `ccx_pq_keygen` is never called in a wallet open/refresh/rescan loop on a persisted seed (would turn one-shot into many-traces-same-key). |
| Signing **Gaussian sampler** (isochronous `BerExp`) | **OPEN.** Runs on the secret on **every spend**; ephemeral-key argument does **not** cover a per-signature repeated path. CI tripwire does not watch it. **Needs positive CT confirmation** (dudect / specialist review of the vendored sampler), not "PQClean says so." |
| **ML-KEM FO-decap comparison** | **OPEN and highest-priority.** ML-KEM decap runs on the **long-term** KEM secret in the wallet **scan loop** (`ccx_pq_kem_scan`, every output during sync) → a repeatable-trace path. Confirm the actual path is the CT implicit-rejection variant end-to-end. |
| Public-output encoders / `hash_to_rq` on `aots` | **Benign — correctly classified.** Operates on public data only. |

**Masking:** only required if a hardware wallet/HSM becomes a target; defer. If pursued, scope is large (higher-order + belief-propagation pitfalls).

---

## 4. Surface C — Standard-scheme usage

**Wallet at-rest (Argon2id + XChaCha20 + prefix-MAC): SOUND.** 192-bit XChaCha20 nonce + salt from `OsRng` (`walletcrypto.rs:46-48`), fresh per save; Argon2id 64 MiB/t=3/p=1 (RFC 9106-adequate), bounds-validated on load; prefix-MAC = `SHAKE256(dom_tag ‖ SHAKE256(dom_key ‖ master) ‖ prefix)` (Keccak sponge → no length-extension; KMAC-style domain separation); **encrypt-then-MAC**, MAC verified before use via a real constant-time compare (`WalletGreen.cpp:75-83`, `:1201`). No `mt19937`/`thread_rng`/`StdRng` anywhere in the crate.

**F5 — 0x07 message AEAD nonce derivation (HIGH).** Nonce `= SHAKE256("ccx-msg-aead-v1" ‖ seed ‖ index)` with `seed = ECDH(recipient.spendPub, txkey.sec)`, `index = output position` (TransactionExtra.cpp:784-787,814; lib.rs:413-420), **no AAD**. If a wallet ever reuses a tx secret key to the same recipient, `(key,nonce)` recurs → catastrophic ChaCha20-Poly1305 break (keystream reuse + Poly1305 forgery). Rests entirely on the unchecked CryptoNote "unique tx key per tx" invariant, **not enforced here**. The 0x06 PQ path is safe (fresh ML-KEM secret per message). **Fix:** bind a unique per-message value (tx pubkey + output index) as AAD and/or include fresh randomness in the nonce; document/enforce tx-key uniqueness.

**Deterministic keygen exactness — coded correctly but UNVERIFIED at runtime (see F3).** Plumbing is right: seed → SHAKE256(domain ‖ NETWORK_TAG ‖ seed) → ML-KEM `d‖z` (64 B), ML-DSA `ξ` (32 B), pqcrypto-compatible encodings; `ccx_pq_kem_keygen_det`/`multisig_keygen_det` are pure functions of the seed. `ccx_pq_detkeygen_selftest` *does* assert byte-equality + pqcrypto interop + seed-separation — **but it is dead code** (no caller). **Funds-loss-critical guarantee never executed.**

**KEM CCA: OK.** ML-KEM via pqcrypto-kyber FO transform (internal, not bypassed); no decapsulation oracle — every decap feeds the shared secret into SHAKE then AEAD-opens (generic failure) or compares a re-derived key; the secret never leaves the FFI.

**F10 (LOW):** `NETWORK_TAG="ccx-testnet"` (detkeygen.rs:45) — correct for testnet, but flipping it changes every derived address → a pre-mainnet funds-loss tripwire; finalize before any wallet ships. Deterministic encodings ride `#[allow(deprecated)]` RustCrypto entry points (ml-kem 0.3.2 / ml-dsa 0.1.1, pinned) whose only empirical guard is the dead selftest (F3).

---

## 5. Surface D — Consensus / integration

**Verified clean:** height-gate off-by-one (deposit-enable `<V10` vs classical-freeze `>=V10` are complementary; comment warns against `>=`→`>`); double-spend (nullifier checked in **both** mempool and block validation; chain spent-set check runs even in checkpoint zone; the 3 previously-fixed holes are closed and **no 4th found**); integer overflow (PQ paths run `check_inputs_overflow`/`check_outs_overflow` with `mul128`/`div128_32` guards, byte-identical to Ed25519); term-binding (`input.term==output.term` before interest); classical-freeze (creation-side only; PQ and classical cells separately indexed → no value duplication/loss); byte-level serialization (`endOfStream()` rejects trailing bytes, varint length-prefixes, `PQ_MULTISIG_MAX_KEYS` bound before alloc); FFI lengths validated before every call.

**F4 — PQ spends lack an explicit V10 gate (HIGH).** `transactionContainsPqMultisig` matches only `PqMultisig{Input,Output}`, so a pure ring-sig spend (`PqKeyInput`/`PqKeyOutput`) gets **no explicit `>= UPGRADE_HEIGHT_V10` reject** (BlockchainStorage.cpp:26-44; BlockchainValidation.cpp:153-196); the only generic version gate (`majorVersion==V1 && tx.version>1`, BlockchainStorage.cpp:408-409) is skipped at today's block majors. Activation relies on **implicit** block-version coupling rather than the explicit gate deposits get. If any path admits a `v4` tx into a sub-V10 block, PQ spends activate early/asymmetrically. **Fix:** add a symmetric `PqKeyInput/PqKeyOutput ⇒ height >= V10` reject (+ coinbase twin). Masked on testnet (V10=120); a real gap on mainnet.

**F7 — `ringSig` canonicality delegated to FFI (MEDIUM).** Unlike `PqKeyOutput.key` (canonicality-checked at the C++ acceptance visitor), `PqKeyInput.ringSig` is an opaque blob whose only check is `ccx_pq_verify==0` (CryptoNoteSerialization.cpp:386-391; BlockchainPq.cpp:155-165). The stored/relayed txid commits to the exact `ringSig` bytes. If `raptor_abi::unpack` accepts any non-unique encoding of a valid signature (Falcon's compressor can carry malleable trailing bits), an attacker mints a 2nd tx with a different txid but the **same nullifier** → txid malleability (mempool/relay confusion). Value duplication is blocked by the nullifier set, so this is MEDIUM not HIGH. **Verify:** `raptor_abi::unpack`'s canonical re-encode (claimed at raptor_abi.rs:99/119/140) actually covers `aots`, `b`, and the compressed `r0/r1` for **every** field; if it does, downgrade to LOW. Otherwise add an `is_canonical` assertion at the verify boundary.

**Determinism (consensus):** x86_64 build-level reproducibility is independently established by the docs' compiler sweep (identical keygen digest across `-O0/-O3/±fast-math/-march`; vendored Falcon is integer-FP). **But** the runtime guard is dormant (F3), and **ARM/MSVC/32-bit/big-endian are unverified** — extend the KAT matrix. The Falcon symbol-rename (`shake256`→`ccxfalcon_*`) should be re-confirmed complete across all vendored TUs (a missed symbol silently cross-links two SHAKEs).

### F3 — Determinism guards are dead code (HIGH)

`assert_keygen_kat()` is **never called**; `keygen_kat_ok()` runs only in a `#[cfg(test)]` test (raptor.rs:586) and inside `ccx_pq_detkeygen_selftest` (lib.rs:658) — which has **no C++ caller** (grep of `src/` for any selftest/KAT symbol is empty). So:

- the **cross-platform Falcon-keygen determinism tripwire** does not fire at daemon/wallet startup — if Falcon FP keygen drifts on a user's platform, they silently get incompatible keys/nullifiers (chain split / unspendable restore) with no alarm;
- the **deterministic-keygen + interop selftest** (the funds-loss guarantee for mnemonic restore) is never executed in build/CI/startup.

Memory indicates `f36c1d03` "activated the dormant KAT" on `pqc/testnet-poc`; **that did not carry to `pqc/mdbx-merge-poc`.** **Fix:** call `assert_keygen_kat()` (and a det-keygen interop self-check) at daemon and wallet startup, and wire both into CI; fail closed.

---

## 6. Surface E — Crypto-agility / migration

Scheme IDs (`PQ_KEM_SCHEME_ID=0xC0DE0203`, `PQ_RING_SCHEME_ID="RAPT"`, `PQ_DSA_SCHEME_ID=0xC0DE0204`, CryptoNoteConfig.h:203-205) are serialized + **fail-closed validated at the address layer** (CryptoNoteSerialization.cpp:469-470; CryptoNoteBasicImpl.cpp:110-119 reject unknown scheme/version) with **no negotiation/downgrade path** — good.

**F11 (LOW/INFO):** the on-chain **spend artifacts carry no scheme/version tag** — `PqKeyInput`/`PqKeyOutput` hold only sig+nullifier+key; `ccx_pq_verify` takes no scheme-id; the active primitive is the compiled `SCHEME_ID` constant. And **`dsaSchemeId` is not committed on-chain at all** (only in the wallet keystore). Consequence: a broken-primitive swap is a **height-gated flag-day** (new variant tag + tx version + fork height), **not** per-output agility — a node cannot validate a pre-fork output under the old scheme and a post-fork output under the new one by reading the output itself. Workable for a clean cutover; document it and consider a per-output scheme byte for true agility.

---

## 7. Deliverable verdicts (brief §6)

2. **Ring-sig verdict.** Unforgeability: **BROKEN as a primitive** (F1, reproducer in-tree); **contingently holds on-chain** via caller-side `msg`-binding but **UNPROVEN** and fragile (F2). Anonymity: **sound** under decisional-NTRU + Falcon-sampler basis-independence (verify stats). Linkability: **sound** modulo Falcon-trapdoor unforgeability (subsumed-broken if F1 is reachable). `B1`: **not re-derived/quantified** (open). Concrete bits: **not estimated** (open).
3. **Constant-time verdict.** Bless: keygen (ephemeral condition), public encoders. **Refute/OPEN:** signing sampler + ML-KEM decap (repeated secret-key paths, not CI-guarded). Masking: defer unless HW-wallet target.
4. **Usage verdict.** Wallet-at-rest KDF/MAC/nonce: **sound**. 0x06: sound. **0x07 AEAD nonce: HIGH risk** (F5). Det-keygen: **coded but unverified at runtime** (F3).
5. **Consensus verdict.** Determinism: x86_64 build-level closed, runtime guard **dormant** (F3), other arches open. Height-gate: off-by-one clean; **PQ-spend gate missing** (F4). Double-spend: **complete** (no 4th hole). Serialization: byte-level canonical; **`ringSig` canonicality FFI-delegated** (F7).
6. **Go/no-go:** §9.

---

## 8. What I could not complete (needs tooling / a build host)

- **[DEFERRED]** Lattice-estimator run for concrete bits (F2) and a derived `B1` for the ring setting.
- **[DEFERRED]** Re-run/extend ctgrind under valgrind + dudect on the **sampler** and **ML-KEM decap** (F6); confirm the keygen call-graph "no reload" condition.
- **[DEFERRED]** Build + `cargo test`/e2e on the WSL x86_64 host to reproduce the forgery test (F1) and the ringsig key-recovery PoC (F8); extend the keygen KAT to ARM/MSVC (F3).
- **[DEFERRED]** Fuzz the FFI/deserialization boundary (`raptor_abi::unpack`, wire parsers) to settle F7 canonicality.
- **[DEFERRED]** FIPS 203/204 KAT cross-checks for ML-KEM/ML-DSA against independent reference vectors.

---

## 9. Go / no-go gates

**Public testnet — GO, conditions:**
- Fix **F4** (explicit PQ-spend height gate) and **F3** (wire `assert_keygen_kat` + det-keygen selftest into startup/CI) before opening a non-resettable testnet.
- Document that this is unaudited research crypto; keep the chain resettable.

**Mainnet — NO-GO until all of:**
1. **F1** fixed: bind the ring into the FS challenge (primitive sound standalone); forgery test inverted.
2. **F2** closed: a written unforgeability reduction (or a simpler provable construction) **and** a re-derived, documented `B1` **and** an estimator-backed concrete security level.
3. **F6** closed: positive CT verification of the signing sampler and ML-KEM decap; masking decision recorded.
4. **F5** fixed: 0x07 AEAD nonce/AAD hardened.
5. **F3** permanent: runtime + CI determinism enforcement; KAT matrix extended to every shipped architecture.
6. **F7/F8/F9/F11** resolved or formally accepted; **professional external cryptographic audit** sign-off.

---

## 10. Notes for the cross-referencing researcher

- **Confirm the live spend path on each branch.** Here it is `raptor.rs` (Falcon); `ringsig.rs` (K=L=6 MSIS) is selftest-only and **separately broken** (F8). On `pqc/testnet-poc`, memory suggests the K=L=6 construction was live — if so, **F8 may be a live CRITICAL there**; please verify.
- **Primary disagreement axis on F1 is severity, not existence.** If you find *any* `ccx_pq_verify` caller (RPC, wallet, standalone PoC) whose `msg` does not bind the ring + nullifier, F1 is **CRITICAL exploitable theft**, not HIGH. I found only the single consensus caller (BlockchainPq.cpp:156) on this branch.
- **All "consensus verified-clean" items assume the Rust C-ABI treats every length/pointer as untrusted and is byte-deterministic.** I read the FFI guards (lib.rs `ffi_guard`, `checked_mul`, exact-length checks) and they look correct, but a fuzzing pass is the right confirmation.
