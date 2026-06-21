# Production-Readiness Prompt — Conceal PQ Mainnet Gate

> **Paste this as the opening prompt for a new session to drive the work from testnet PoC to mainnet-ready.**
> It is ordered by dependency: consensus fixes first (quick, unblock testnet quality), then the
> cryptographic soundness track (the long pole), then hardening/fuzzing, then the formal audit gate.

---

You are a senior cryptography engineer and blockchain protocol developer working on the Conceal
Network's post-quantum crypto integration. The codebase is a C++11 CryptoNote daemon + CLI wallet
with a Rust PQ crypto crate (`pqc/ccx-pqc`) linked via C ABI. The current state is a **testnet-only
PoC on branch `pqc/mdbx-merge-poc`** — unaudited, height-gated behind `UPGRADE_HEIGHT_V10`.

A full external security audit has been completed
(`docs/reviews/pqc-mdbx-merge/glm-security-audit.md`). Read it before starting. The audit found
3 new issues not caught by prior reviews, plus corroborated known-open gates.

**Your goal: close every mainnet-blocking condition identified in the audit, in dependency order,
so this codebase is ready for an external cryptographic audit and eventual mainnet activation.**

Work on the `pqc/mdbx-merge-poc` worktree at `/Users/travis/Projects/conceal-core-mdbx-merge`.
Build/test on the WSL host at `100.100.90.103` (Ubuntu 24.04 x86_64, 16c/54GB) via SSH.
Edit on the Mac; rsync + build on WSL. See `AGENTS.md` for the workflow.

---

## Phase 0 — Quick consensus fixes (unblock testnet quality, ~1 hour)

These are one-line / small changes with no cryptographic implications. Do these first.

### 0.1 Persist `m_spent_pq_nullifiers` across daemon restart (HIGH-2)

**File:** `src/CryptoNoteCore/TransactionPool.cpp`, function `tx_memory_pool::serialize()` (~line 642).

Add `KV_MEMBER(m_spent_pq_nullifiers);` alongside the existing `m_spent_pq_deposit_cells`:

```cpp
KV_MEMBER(m_spent_key_images);
KV_MEMBER(m_spentOutputs);
KV_MEMBER(m_spent_pq_deposit_cells);
KV_MEMBER(m_spent_pq_nullifiers);          // <-- ADD THIS
KV_MEMBER(m_recentlyDeletedTransactions);
```

Verify: restart the daemon with pooled PQ txs and confirm `haveSpentInputs()` still detects the
nullifier.

### 0.2 Add `PqKeyInput` nullifier tracking to `BlockTemplate` (MED-1)

**File:** `src/CryptoNoteCore/TransactionPool.cpp`, class `BlockTemplate` (~line 42-123).

Add a `std::set<std::vector<uint8_t>> m_pqNullifiers;` member. Add a `PqKeyInput` branch to both
`canAdd()` and `addTransaction()`:

```cpp
// In canAdd():
else if (in.type() == typeid(PqKeyInput))
{
  const auto &pkin = boost::get<PqKeyInput>(in);
  if (m_pqNullifiers.count(pkin.nullifier))
    return false;
}

// In addTransaction():
else if (in.type() == typeid(PqKeyInput))
{
  const auto &pkin = boost::get<PqKeyInput>(in);
  auto r = m_pqNullifiers.insert(pkin.nullifier);
  assert(r.second);
}
```

Verify: construct a block template with two PQ txs sharing a nullifier; confirm the second is rejected.

### 0.3 Tighten `ringSig` length bound (LOW-3, optional)

**File:** `src/CryptoNoteCore/CryptoNoteSerialization.cpp` (~line 390).

Add a per-field cap on `PqKeyInput.ringSig` to `ccx_pq_verify`'s DoS guard
(`ring_count * 4096 + 8192`) rather than the 128 MiB string default. Reject early in deserialization
before allocating memory.

---

## Phase 1 — Fix the Raptor programmed-key forgery (HIGH-1, ~1 day)

This is the most critical cryptographic finding. The Raptor ring signature's standalone unforgeability
is broken: an attacker can forge a valid signature over a ring containing a "programmed" key without
knowing any member's trapdoor. The test at `raptor.rs:583` demonstrates this.

### 1.1 Bind ring public keys into the challenge hash

**File:** `pqc/ccx-pqc/src/raptor.rs`, function `hash_transcript_to_b()` (~line 242).

The current challenge is `H(msg, c_1,...,c_L)` — the ring public keys `a0_1,...,a0_L` enter only
indirectly through the c-values. Add the ring keys directly into the hash input so that programming
a key after seeing the challenge is impossible:

```rust
fn hash_transcript_to_b(msg: &[u8], ring: &[[u16; N]], cs: &[[u16; N]]) -> [u8; 32] {
    let mut input = Vec::from(DOM_H_TRANSCRIPT);
    input.extend_from_slice(&(msg.len() as u64).to_le_bytes());
    input.extend_from_slice(msg);
    input.extend_from_slice(&(ring.len() as u64).to_le_bytes());    // <-- ADD
    for a0 in ring {                                                 // <-- ADD
        let e = fc::modq_encode(a0).expect("encode a0");
        input.extend_from_slice(&e);
    }
    for c in cs {
        let e = fc::modq_encode(c).expect("encode c");
        input.extend_from_slice(&e);
    }
    // ...
}
```

Update `sign()` and `verify()` to pass `ring` (the list of `a0` polynomials) to
`hash_transcript_to_b`. Both already have the ring available.

### 1.2 Remove or invert the forgery test

After the fix, the test `ring_not_bound_into_challenge_allows_programmed_key_forgery` must **FAIL**
(the forged signature must be rejected). Rename it to `programmed_key_forgery_is_rejected` and assert
`verify(msg, &ring, &forged).is_err()`.

### 1.3 Update the OTS target to include the ring

The `ots_target()` function (`raptor.rs:264`) already includes the ring (`ring` parameter). Confirm
it still does after the challenge hash change. The OTS transcript and the ring-challenge must both
bind the ring — defense in depth.

### 1.4 Verify with the full test suite

```bash
# On WSL:
cd ~/conceal-core-mdbx-merge/pqc/ccx-pqc && cargo test --release
cd ~/conceal-core-mdbx-merge/build && ./tests/unit_tests --gtest_filter='*Pq*'
```

All tests must pass. The renamed forgery test must confirm rejection.

---

## Phase 2 — B1 norm bound derivation (MED-2, ~1-2 days research)

The acceptance bound `FALCON512_SQNORM_BOUND = 34_034_726` is copied from single-Falcon. For the
ring setting, the unforgeability reduction's extractor produces a vector with Cauchy-Schwarz blowup.

### 2.1 Derive the ring-setting B1

Work through the standard rewind-based extractor for the Raptor construction:
- Two accepting transcripts for the same first commitment yield `(Δr0, Δr1)` where
  `||Δr0||² + ||Δr1||² ≤ 2·(||r0||² + ||r1||² + ||r0'||² + ||r1'||²)`.
- Map this to the R-SIS / NTRU instance over `R_q = Z_q[x]/(x^512+1)`, `q=12289`.
- Determine whether single-Falcon's `β²` suffices or a tighter bound is needed.

Document the derivation in `docs/design/quantum-resistance/raptor-b1-derivation.md`.

### 2.2 Run the lattice estimator

Install and run the [lattice estimator](https://github.com/cr-marcstevens/lattice-estimator) or
[Albrecht et al.'s estimator](https://latticeestimator.github.io/) on:
- The R-SIS forgery instance at the extracted witness bound.
- The NTRU key-recovery instance (Falcon-512's own instance, for cross-reference).

Target: ≥128-bit classical security (NIST cat-1) with margin.

### 2.3 Re-tune if necessary

If the estimator shows <128 bits, adjust parameters (ring size, bound tightening) and re-run.
If the current bound suffices, document the proof and the estimator output.

---

## Phase 3 — `paramch_h` NUMS ceremony (LOW-1, ~half day)

### 3.1 Choose a ceremony approach

For mainnet, pick one:
- **Random beacon:** `h = hash_to_rq(SHA256(block_hash_at_pre_announced_height))`.
- **Multi-party:** N contributors each commit-then-reveal seeds; ≥1 honest destroys their seed.
- **At minimum:** publish a versioned, immutable specification (input string, domain, hash,
  expected polynomial digest, change-control policy) as an external artifact before mainnet.

### 3.2 Implement and document

If using a beacon: implement the beacon-derivation in `paramch_h()`, add a height parameter, and
document the pre-announcement height in `CryptoNoteConfig.h`.

If using a fixed specification: freeze the derivation, compute and publish the expected `h`
polynomial, and add a test that asserts the exact coefficients.

---

## Phase 4 — Formal anonymity proof (audit gate, ~2-3 days research)

The anonymity crux (non-signer `(r0,r1)` drawn from Falcon's genuine preimage distribution via
throwaway key) is empirically verified (signer vs non-signer stddev match within 0.2%). A formal
statistical-distance bound is absent.

### 4.1 Bound the statistical distance

Prove (or bound) that the distribution of non-signer `(r0,r1)` samples — produced by Falcon's
preimage sampler on random targets under a throwaway lattice — is computationally indistinguishable
from the signer's `(r0,r1)` distribution (produced under the signer's real lattice).

Key insight: both use the same Falcon sampler with the same parameters; only the trapdoor (lattice
basis) differs. Falcon's sampler output distribution is determined by the sampler parameters, not
the specific basis (this is the standard lattice-sampler independence argument). Formalize this.

### 4.2 Document in a formal writeup

Write the proof sketch in `docs/design/quantum-resistance/raptor-anonymity-proof.md`, suitable for
external audit review.

---

## Phase 5 — Fuzzing + hardening (~2-3 days)

### 5.1 Fuzz the FFI boundary

Set up `cargo-fuzz` targets for:
- `ccx_pq_verify` with malformed signatures (truncated, non-canonical, oversized ringSig, wrong
  ring count, corrupted aots/ots_sig).
- `raptor_abi::unpack` with arbitrary byte streams (varint edge cases, blob length overflows,
  comp_decode on garbage).
- `ccx_pq_kem_scan` / `ccx_pq_kem_derive_output` with malformed ciphertexts/keys.
- `ccx_pq_multisig_verify` with malformed signatures/keys.

Goal: crash-safety (no panics cross the FFI boundary) and clean rejection (negative return codes).

### 5.2 Wire the KAT tripwire into daemon startup

Currently `assert_keygen_kat()` exists but is only called in the selftest. Wire it into daemon
startup (`src/Daemon/main.cpp` or equivalent) as a hard abort if the keygen KAT drifts. This catches
cross-platform FP divergence before any key-dependent operation.

### 5.3 Production per-spend KDF

Replace the `OsRng`-mixed sign seed (`lib.rs:175-181`) with a hardened per-spend KDF derived from
wallet state (e.g., `HKDF(wallet_master_key, "ccx-per-spend" || output_nullifier || counter)`).
Document the construction and why it prevents nonce reuse without introducing determinism that
could leak the trapdoor.

---

## Phase 6 — Cross-platform determinism matrix expansion (~1 day)

Extend the 4-platform keygen KAT matrix to:
- ARM Linux (aarch64, e.g., Raspberry Pi or ARM cloud instance).
- 32-bit x86 (if any deployment targets 32-bit).
- Big-endian (if relevant — likely not for x86/ARM, but document the assumption).

Add the new digests to the pinned KAT constants. Run the full test suite on each platform.

---

## Phase 7 — External audit preparation (~half day)

Compile the following package for the external auditor:
1. The B1 derivation document (`raptor-b1-derivation.md`).
2. The anonymity proof sketch (`raptor-anonymity-proof.md`).
3. The lattice estimator output (concrete bit-counts for forgery + key-recovery).
4. The `paramch_h` ceremony record (beacon value / MPC transcript / frozen spec).
5. The fuzzing results (crash-free summary + coverage).
6. The cross-platform KAT matrix (all digests match).
7. This audit report (`glm-security-audit.md`) with all HIGH/MED items marked FIXED.
8. The full source diff from `development` to `pqc/mdbx-merge-poc`.

The external auditor reviews the cryptographic soundness (unforgeability, anonymity, linkability
reductions), the constant-time posture (Falcon keygen/sampler sign-off), and the integration
correctness (consensus determinism, serialization canonicality, double-spend completeness).

---

## Definition of Done

- [ ] Phase 0: HIGH-2 + MED-1 fixed, tests green.
- [ ] Phase 1: programmed-key forgery rejected, ring keys bound into challenge, test inverted.
- [ ] Phase 2: B1 derived, lattice estimator run, ≥128-bit confirmed.
- [ ] Phase 3: `paramch_h` ceremony implemented/documented.
- [ ] Phase 4: anonymity statistical-distance bound written up.
- [ ] Phase 5: fuzz targets crash-free, KAT tripwire wired to startup, per-spend KDF.
- [ ] Phase 6: cross-arch KAT matrix expanded.
- [ ] Phase 7: audit package compiled and ready for external review.

**Until all phases are done and the external audit passes, `UPGRADE_HEIGHT_V10` stays unset
(placeholder `999999999`) and the code remains testnet-only.**

---

## Key files to reference

| Area | File |
|------|------|
| Raptor ring sig | `pqc/ccx-pqc/src/raptor.rs` |
| Raptor ABI packing | `pqc/ccx-pqc/src/raptor_abi.rs` |
| Falcon FFI | `pqc/ccx-pqc/src/falcon_ffi.rs` |
| C shim | `pqc/ccx-pqc/csrc/raptor_falcon.c` |
| C ABI entry points | `pqc/ccx-pqc/src/lib.rs` |
| Det keygen | `pqc/ccx-pqc/src/detkeygen.rs` |
| Wallet crypto | `pqc/ccx-pqc/src/walletcrypto.rs` |
| PQ spend builder | `src/CryptoNoteCore/PqSpendBuilder.cpp` |
| PQ consensus checks | `src/Blockchain/BlockchainPq.cpp` |
| Mempool | `src/CryptoNoteCore/TransactionPool.cpp` / `.h` |
| Config (height gates) | `src/CryptoNoteConfig.h` |
| Serialization | `src/CryptoNoteCore/CryptoNoteSerialization.cpp` |
| This audit | `docs/reviews/pqc-mdbx-merge/glm-security-audit.md` |
| Prior vet summary | `docs/reviews/raptor-integration/VET-SUMMARY.md` |
| Integration plan | `docs/design/quantum-resistance/raptor-integration-plan.md` |
| CT status | `docs/design/quantum-resistance/constant-time-status.md` |
