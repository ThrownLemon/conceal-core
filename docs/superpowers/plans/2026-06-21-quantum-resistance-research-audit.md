# Quantum-Resistance Research Audit Execution Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close or precisely bound every research and dynamic-testing gap disclosed by the quantum-resistance security audit.

**Architecture:** Each task is an independent evidence gate with a versioned artifact under `docs/reviews/quantum-resistance-research/`. A task may end as proved/passed, refuted/failed, or blocked with an exact external dependency; unsupported security claims are never treated as completion.

**Tech Stack:** Rust/C/C++ source review, SageMath/Python estimator tooling, Rust statistical harnesses, Valgrind/ctgrind, dudect, cargo-fuzz/libFuzzer, CMake/GoogleTest, Linux/WSL/QEMU or CI architecture runners.

## Global Constraints

- Keep findings pinned to the reviewed commit or record the new commit explicitly.
- Do not modify or revert Claude's concurrent remediation changes.
- Store generated raw data, tool versions, commands, seeds, and summarized results together.
- A test pass is not a cryptographic proof; a failed attempt is recorded rather than suppressed.
- Mainnet remains no-go while Tasks 1, 2, or 3 are unresolved.

---

### Task 1: Exact Raptor Specification and Security Reductions

**Files:**
- Create: `docs/reviews/quantum-resistance-research/01-raptor-proof-analysis.md`
- Inspect: `pqc/ccx-pqc/src/raptor.rs`
- Inspect: `pqc/ccx-pqc/csrc/raptor_falcon.c`
- Inspect: `pqc/ccx-pqc/src/ringsig.rs`

**Produces:** A complete implemented algorithm specification, paper-to-code mapping, and separate unforgeability, anonymity, and linkability proof ledgers.

- [x] Extract every key-generation, signing, verification, OTS, mask, transcript, and nullifier equation from the implementation.
- [x] Map each equation and distribution to the corresponding Raptor paper algorithm and theorem.
- [x] Enumerate all deltas, including transcript inputs, XOR/mask representation, response sampling, shared throwaway trapdoor, norm checks, and OTS message binding.
- [x] Attempt reductions for unforgeability, anonymity, and linkability under explicitly named assumptions and random-oracle queries.
- [x] For every failed reduction step, state the missing lemma or construct a concrete distinguishing/forgery strategy to test.
- [ ] Obtain external cryptographer review before marking a novel reduction as established.

**Current Task 1 status (2026-06-21):** current worktree rejects the old programmed-key Raptor forgery after binding ring keys into `H`; however, the available proof document is still exploratory and not an externally reviewed reduction. Mainnet blocker remains open. See `docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`.

**Completion rule:** Mark complete only with a reviewed reduction for the exact implementation, a demonstrated break, or a precise blocker identifying the theorem or design change required.

### Task 2: Raptor Response-Bound Derivation

**Files:**
- Create: `docs/reviews/quantum-resistance-research/02-raptor-b1-bound.md`
- Create: `pqc/ccx-pqc/tests/raptor_norm_distribution.rs`

**Consumes:** Task 1's exact response distribution and acceptance equations.

**Produces:** A mathematically derived acceptance bound, target rejection probability, and empirical validation data.

- [ ] Derive the norm distribution for signer and decoy responses under the exact Falcon sampler parameters.
- [ ] Select and justify the target honest-rejection and soundness probabilities.
- [ ] Convert the paper's distribution-membership requirement and reduction norm into the implementation's joint squared-norm representation.
- [ ] Generate deterministic Monte Carlo data across supported ring sizes and independent keys.
- [ ] Compare the current `34,034,726` threshold to the derived quantiles and proof requirement.
- [ ] Add boundary tests for exactly-at, below, and above the selected encoded threshold.

**Completion rule:** A derivation reviewed independently and tests showing the implementation encodes that bound exactly.

### Task 3: Concrete Lattice Security Estimate

**Files:**
- Create: `docs/reviews/quantum-resistance-research/03-lattice-security-estimate.md`
- Create: `docs/reviews/quantum-resistance-research/tools/estimate_raptor.py`
- Create: `docs/reviews/quantum-resistance-research/results/estimator.json`

**Consumes:** Tasks 1 and 2's exact hardness instances and reduction losses.

**Produces:** Reproducible classical and quantum security estimates with attack models and estimator version pinned.

- [ ] Express each required SIS/NTRU/ISIS instance with exact `n`, `q`, dimensions, norm bound, module/ring structure, and sample count.
- [ ] Pin the lattice-estimator commit and runtime environment.
- [ ] Run primal, dual, hybrid, and applicable NTRU attacks with classical and quantum cost models.
- [ ] Include reduction and multi-target losses for maximum supported ring size and transaction volume.
- [ ] Sensitivity-test estimator assumptions and report the weakest credible result.
- [ ] Have the model and interpretation independently reviewed.

**Completion rule:** Publish reproducible estimator inputs/results, or state that no defensible estimate exists because Task 1 cannot define the required hard instance.

### Task 4: Signer-versus-Decoy Classifier

**Files:**
- Create: `pqc/ccx-pqc/tests/raptor_anonymity_stats.rs`
- Create: `docs/reviews/quantum-resistance-research/04-anonymity-statistics.md`
- Create: `docs/reviews/quantum-resistance-research/results/anonymity/`

**Produces:** Pre-registered statistical tests and raw signer/decoy feature data.

- [ ] Define features before viewing labels: response norms, coefficient moments/tails, correlations, retry counts where observable, and per-ring rank statistics.
- [ ] Generate balanced data across independent signer keys, throwaway keys, messages, positions, and ring sizes.
- [ ] Split train/test data by key and seed to prevent leakage.
- [ ] Run univariate tests plus regularized and tree-based classifiers with permutation baselines.
- [ ] Correct for multiple comparisons and publish confidence intervals and power.
- [ ] Re-run with fresh held-out seeds and retain all raw aggregate data needed for reproduction.

**Completion rule:** No statistically or practically meaningful held-out advantage at the pre-registered power threshold, or a reproducible distinguisher finding.

### Task 5: Extended Side-Channel Analysis

**Files:**
- Create: `pqc/ccx-pqc/benches/pq_dudect.rs`
- Create: `docs/reviews/quantum-resistance-research/05-side-channel-analysis.md`
- Modify only if required: `.github/workflows/pq-ct.yml`

**Produces:** Per-operation timing verdicts and documented feasibility/results for cache and formal tools.

- [ ] Add dudect-style fixed-versus-random tests for Raptor signing, Falcon keygen/sampling, ML-KEM decapsulation, and ML-DSA signing.
- [ ] Run sufficient traces on an isolated Linux CPU and report Welch t-statistics over time, not only the terminal value.
- [ ] Re-run ctgrind without hiding Falcon-internal contexts and classify every context.
- [ ] Run Flush+Reload or an equivalent cache experiment on secret-indexed tables and branch targets where hardware permits.
- [ ] Evaluate ct-verif, Binsec-Rel, haybale-pitchfork, and SideTrail against the compiled functions; record exact incompatibilities for tools that cannot model them.
- [ ] State the accepted software-wallet leakage model and prohibit hardware-wallet claims unless a masked implementation is separately assessed.

**Completion rule:** Each flagged operation is blessed, refuted, or explicitly unsupported with commands, trace counts, environment, and residual risk.

### Task 6: Coverage-Guided Fuzzing

**Files:**
- Create: `pqc/ccx-pqc/fuzz/Cargo.toml`
- Create: `pqc/ccx-pqc/fuzz/fuzz_targets/raptor_decode.rs`
- Create: `pqc/ccx-pqc/fuzz/fuzz_targets/pq_ffi_lengths.rs`
- Create: `tests/fuzz/PqTransactionFuzzer.cpp`
- Create: `docs/reviews/quantum-resistance-research/06-fuzzing.md`

**Produces:** Buildable fuzz targets, seed corpora, minimized regressions, and run statistics.

- [ ] Fuzz Raptor signature decoding and canonical re-encoding.
- [ ] Fuzz every PQ FFI function across null pointers, truncated buffers, oversized lengths, aliasing, and malformed encodings.
- [ ] Fuzz C++ transaction wire deserialization for all PQ input/output fields and nested counts.
- [ ] Seed corpora with valid minimum/maximum ring transactions and each known malformed reproducer.
- [ ] Run ASan/UBSan builds for a documented minimum CPU time and preserve coverage/crash summaries.
- [ ] Convert every unique crash, timeout, or excessive allocation into a deterministic regression test.

**Completion rule:** Targets build in CI, complete the declared campaign without unresolved crashes, and cover the known malformed-input classes.

### Task 7: Cross-Architecture Determinism Matrix

**Files:**
- Create: `docs/reviews/quantum-resistance-research/07-determinism-matrix.md`
- Modify: `.github/workflows/pq-kat.yml`

**Produces:** Byte-identical KAT output for every seed-derived PQ scheme across the feasible architecture matrix.

- [ ] Extend the KAT output to ML-KEM, ML-DSA/Dilithium, Falcon/Raptor keys, signatures where deterministic, addresses, and serialized transaction artifacts.
- [ ] Run x86_64 Linux and ARM64 Linux with pinned compiler/toolchain versions.
- [ ] Run a 32-bit little-endian target under native hardware or QEMU.
- [ ] Run a big-endian target under QEMU if all dependencies compile; otherwise document the exact unsupported dependency and ensure wire parsing is endian-independent by construction/tests.
- [ ] Diff raw artifacts, not only hashes, and localize any mismatch.
- [ ] Pin expected digests and fail CI on drift.

**Completion rule:** Required artifacts are byte-identical across supported targets; unsupported targets have an explicit support-policy decision.

### Task 8: Live Activation, Fork, and Reorg Testing

**Files:**
- Create: `pqc/run-poc-consensus-e2e.sh`
- Create: `docs/reviews/quantum-resistance-research/08-consensus-e2e.md`

**Produces:** Reproducible multi-node tests spanning V10 activation, conflicting spends, checkpoints, restart, and reorg.

- [ ] Start isolated nodes with short deterministic activation and maturity parameters.
- [ ] Exercise the last pre-V10 block and first V10 block for PQ admission and classical-deposit freeze boundaries.
- [ ] Submit conflicting PQ nullifiers and PQ deposit-cell spends through separate nodes and verify mempool/template behavior.
- [ ] Create competing branches containing conflicting valid spends, force a reorg, and verify rollback/reapplication of nullifier and deposit-cell state.
- [ ] Restart and rescan nodes after each state transition and compare chain/state digests.
- [ ] Exercise checkpoint behavior around the activation boundary and document the permitted policy.

**Completion rule:** All nodes converge on the same chain and spent-state after activation, conflict, restart, and reorg scenarios, with failures preserved as regression tests.
