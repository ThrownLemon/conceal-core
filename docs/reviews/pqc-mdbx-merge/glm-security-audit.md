# Post-Quantum Security Audit — Conceal `pqc/mdbx-merge-poc`

**Researcher:** GLM (opencode, zai/glm-5.2) — external crypto-algorithm security researcher  
**Branch:** `pqc/mdbx-merge-poc` (commit `411c848f`)  
**Date:** 2026-06-21  
**Scope:** Full PQ crypto audit per `docs/design/quantum-resistance/security-audit-brief.md`  
**Method:** Manual source review + test execution + ctgrind valgrind analysis on WSL x86_64

---

## Executive Summary

The engineering is hardened, functionally tested, and the C++ consensus integration is careful. **Three new findings not caught by prior reviews**, plus corroboration of known-open gates. The two genuinely-open questions remain (1) the Raptor ring-sig's cryptographic soundness and (2) the constant-time posture of secret-key paths — exactly as the brief anticipated.

**Test execution:** `cargo test` 13/13 pass · `unit_tests --gtest_filter=*Pq*` 67/67 pass · ctgrind/TIMECOP valgrind map clean (all flags in documented Falcon-internal paths) · keygen KAT tripwire green · full daemon build `[100%]`.

### Severity summary

| Sev | Count | Headline |
|-----|-------|----------|
| **High** | 2 | (1) Raptor programmed-key forgery — scheme standalone unforgeability broken; (2) `m_spent_pq_nullifiers` not persisted across daemon restart |
| **Medium** | 2 | (1) BlockTemplate doesn't track PqKeyInput nullifiers; (2) B1 norm bound not re-derived for ring setting |
| **Low** | 3 | paramch_h NUMS ceremony; V9/V10 ordering confusion; ringSig length bound loose |
| **Info** | 5 | Domain-separator methodology; CT residual items; FO/CCA OK; nonce derivation OK; serialization canonical |

---

## 1. Severity-Rated Findings

### HIGH-1: Raptor programmed-key (rogue-key) forgery — standalone unforgeability broken

**Severity: High (mainnet blocker; mitigated at consensus layer for testnet)**  
**Location:** `pqc/ccx-pqc/src/raptor.rs:583-644` (test `ring_not_bound_into_challenge_allows_programmed_key_forgery`)

**Description:** The Raptor ring signature scheme does not enforce standard unforgeability in isolation. A test in the codebase explicitly demonstrates that an attacker can produce a valid signature over a ring containing a "programmed" key — one constructed without a valid Falcon trapdoor — using only their own OTS (linking-tag) key:

1. The attacker creates a ring `[victim_a0, programmed_a0]` where `programmed_a0` is algebraically derived to satisfy the verification equation without a trapdoor.
2. For the victim member, `(r0=0, r1=0)` eliminates the `a_i·r1` term, making `c = h·b` (no secret needed).
3. For the programmed member, `(r0=0, r1=e_0)` (unit vector) lets the attacker solve `a_i = c - h·b` after seeing the challenge hash.
4. The OTS signature uses the attacker's own throwaway `aots` key.
5. `verify()` returns `Ok(nullifier)`.

The test `assert!(verify(msg, &ring, &forged).is_ok());` passes — the forged signature verifies.

**Why this matters:** The scheme's standalone unforgeability (the property that "a valid signature requires knowledge of a ring member's trapdoor") is **broken**. Security against forgery rests entirely on the consensus layer enforcing that all ring members are real, confirmed on-chain outputs. No formal proof exists that the hash-challenge circularity prevents forging when all ring members are real.

**Consensus mitigation (verified):** `BlockchainPq.cpp:62-150` resolves every ring member from `m_pqOutputs` (the on-chain PQ output index), preventing injected/programmed keys. Each member must be a real `PqKeyOutput` with canonical encoding. An attacker cannot inject a programmed key.

**Residual risk:** If any path allows a non-standard output key onto the chain (e.g., a raw crafted transaction bypassing `check_outs_valid`, or a consensus edge case during reorg), the scheme's unforgeability guarantee evaporates. The scheme should bind ring public keys into the challenge hash directly (as standard ring signatures do), not just through the c-values.

**Prior reviewers did not flag this.** The test exists as documentation, but no prior review (Codex, Claude, GLM-consult, CodeRabbit) identified it as a security finding.

**Recommended fix:** Add the ring public keys `a0_1,...,a0_L` directly into the challenge hash `H(msg, a0_1,...,a0_L, c_1,...,c_L)` so that programming a key after seeing the challenge is impossible. This is the standard rogue-key defense in ring signatures.

---

### HIGH-2: `m_spent_pq_nullifiers` not persisted in mempool serialization

**Severity: High (mainnet); Medium (testnet)**  
**Location:** `src/CryptoNoteCore/TransactionPool.cpp:642-645`

**Description:** The mempool serialization (`tx_memory_pool::serialize`) persists `m_spent_key_images`, `m_spentOutputs`, `m_spent_pq_deposit_cells`, and `m_recentlyDeletedTransactions`, but **omits `m_spent_pq_nullifiers`**. After a daemon restart:

1. Transactions are restored from disk into `m_transactions`.
2. The PQ nullifier double-spend set (`m_spent_pq_nullifiers`) is **empty**.
3. `haveSpentInputs()` checks `m_spent_pq_nullifiers.count(nf)` (line 888) and returns false for nullifiers already in pooled transactions.
4. A second transaction spending the same nullifier is admitted to the mempool.

**Impact:** Mempool pollution — a restarted daemon accepts duplicate-nullifier transactions that it would have rejected before restart. Not consensus-fatal (the chain's `check_pq_tx_input` at block-connect time catches double-spends via the on-chain nullifier set), but enables:
- Wasted validation work on transactions that will be rejected at connect time.
- Potential for invalid block templates (pairs with MED-1 below).
- A denial-of-service vector: an attacker pre-fills the mempool with double-spend txs right after a targeted restart.

**Classical key images do NOT have this bug** — `m_spent_key_images` is persisted (line 642).

**Fix:** Add `KV_MEMBER(m_spent_pq_nullifiers);` at line 645.

---

### MED-1: BlockTemplate does not track `PqKeyInput` nullifiers

**Severity: Medium**  
**Location:** `src/CryptoNoteCore/TransactionPool.cpp:52-74` (`addTransaction`), `86-115` (`canAdd`)

**Description:** The `BlockTemplate` class tracks `KeyInput.keyImage`, `MultisignatureInput` (amount, outputIndex), and `PqMultisigInput` (amount, outputIndex) to prevent two conflicting txs from being selected into the same block template. However, there is **no `PqKeyInput` branch** — two transactions spending the same PQ nullifier can both pass `canAdd()` and be selected into a single block template. The resulting block fails at `markPqNullifiersSpent()` on connect.

**Impact:** Wasted miner work / orphaned blocks. Exploitable trivially after a restart (pairs with HIGH-2) or via two `keptByBlock=true` reorged transactions.

**Fix:** Add a `PqKeyInput` branch to both `canAdd()` and `addTransaction()` tracking `PqKeyInput.nullifier` in a `std::unordered_set<std::vector<uint8_t>> m_pqNullifiers` member.

---

### MED-2: B1 norm bound copied from single-Falcon, not re-derived for ring setting

**Severity: Medium (mainnet blocker; not a demonstrated break)**  
**Location:** `pqc/ccx-pqc/src/raptor.rs:51` — `FALCON512_SQNORM_BOUND = 34_034_726`

**Description:** The acceptance bound for short vectors is `l2bound[9]` from PQClean's Falcon-512 — the single-signature squared-norm bound. In the Raptor ring construction, this bound is applied to four different objects: signer-block (r0,r1), non-signer-block (r0,r1), verify-side per-member (r0,r1), and OTS (s0,s1).

The honest distribution fits the bound by construction (Falcon's sampler is tuned to it). But the **unforgeability proof** requires a reduction from a forged signature to a short lattice vector via rewinding, and the extracted vector's norm scales with Cauchy-Schwarz: `||Δr||² ≤ 8·B1`. Whether this falls within the R-SIS/NTRU hardness bound at Falcon-512's security level is **not derived anywhere** in this codebase or in the paper.

**Consequence:** The concrete security level is "no defensible number" — not because there's a known attack, but because the proof doesn't close. This matches the existing audit's finding (H-1 item 2).

**Fix:** Derive B1 from the ring parameters (n=512, q=12289, R=x^512+1), the supported ring sizes, and the extractor's Cauchy-Schwarz blowup. Run the lattice estimator on the extracted witness bound.

---

### LOW-1: `paramch_h` lacks external NUMS ceremony

**Severity: Low (testnet); Medium (mainnet gate)**  
**Location:** `pqc/ccx-pqc/src/raptor.rs:53-57`

**Description:** The system parameter `h` is derived as `SHAKE256("RAPTOR-CCX-paramch-h" || "conceal-raptor-paramch-v0")`. This is deterministic and reproducible, but:
- No external pre-commitment exists for the input string.
- No multi-party ceremony or random beacon was used.
- The string-chooser could theoretically have tried many strings.

Under the SHAKE256 random-oracle model, the statistical risk of a maliciously-chosen string producing a backdoored `h` is negligible (finding an `h` with a known NTRU trapdoor requires ~2^106 string trials). The concern is procedural/audit-trail, not a known weakness.

**Fix:** For mainnet, derive `h` from a public random beacon or multi-party ceremony. At minimum, publish a frozen specification with the expected polynomial digest.

---

### LOW-2: `UPGRADE_HEIGHT_V9` vs `V10` ordering confusion

**Severity: Low (informational)**  
**Location:** `src/CryptoNoteConfig.h:124,128`

V9 mainnet height = 999999999 but V10 = 5000000. V10 numerically precedes V9. The gates are independent height comparisons and work correctly, but the naming implies a sequence that doesn't hold. Someone reading the code might assume V10 activates after V9.

---

### LOW-3: No per-field length bound on `PqKeyInput.ringSig`

**Severity: Low (DoS)**  
**Location:** `src/CryptoNoteCore/CryptoNoteSerialization.cpp:390`

The blob deserializer caps strings at 128 MiB, but a real PQ ring-8 signature is ~12 KB. An attacker can submit a multi-MB ringSig that allocates memory before validation rejects it. Bounded by `CRYPTONOTE_MAX_TX_SIZE` (100 MB) at the network layer, but looser than necessary for PQ signatures which are orders of magnitude larger than Ed25519.

---

### INFO-1 through INFO-5: Verified-sound items

| ID | Item | Verdict |
|----|------|---------|
| INFO-1 | Domain separators | All 9 formal tags are lexically distinct; no prefix collisions. Ad-hoc methodology (no length-prefixing in `hash_to_rq`) is not exploitable today but fragile for evolution. |
| INFO-2 | CT residual (Falcon keygen non-CT, sampler, rejection loop) | All documented, all in wallet-side code (not consensus hot path). Ephemeral per-spend keys make the one-shot argument hold by construction. Needs formal sign-off, not engineering. |
| INFO-3 | ML-KEM FO decapsulation | Uses PQClean's CCA-secure construction with constant-time comparison. No decapsulation oracle exposed via RPC. Sound. |
| INFO-4 | Nonce derivation (messages + wallet) | Per-message KEM fresh secret + index-derived (key, nonce) via domain-separated SHAKE256. No nonce reuse. XChaCha20 192-bit nonce is collision-safe. Sound. |
| INFO-5 | Serialization canonicality | Varint encoding rejects non-minimal forms. PQ variant tags (0x08, 0x09) collision-free. Canonical aots round-trip check in `unpack`. Sound. |

---

## 2. Ring-Signature Verdict

### Unforgeability: **UNPROVEN** (HIGH-1)

The clean-room Raptor implementation faithfully instantiates eprint 2018/857 §6.5 (verified by code walkthrough). However:

- **Standalone unforgeability is broken** (HIGH-1): the programmed-key forgery test demonstrates a valid signature without knowledge of any ring member's trapdoor. Security relies entirely on consensus-layer enforcement of ring membership.
- **No formal reduction** exists from a forgery to a hard lattice problem for this construction.
- **B1 is inherited, not derived** (MED-2): the acceptance bound is single-Falcon's, not calibrated for the ring setting.
- The hash-challenge circularity argument (that prevents forging with all-real ring members) is a heuristic, not a proof.

### Anonymity: **CONDITIONALLY SOUND** (with anonymity crux verified)

- The anonymity crux (non-signer (r0,r1) drawn from Falcon's genuine preimage distribution via throwaway key) is correctly implemented and empirically verified (signer vs non-signer stddev match within 0.2%).
- **Formal statistical-distance bound is absent** — the empirical match does not prove indistinguishability.
- The `paramch_h` parameter and `H1` mask are public random oracles — no anonymity leak through them.
- The nullifier (`SHAKE256(aots)`) is derived from the signer's OTS key, not the ring member key — it does not deanonymize the signer within the ring.

### Linkability: **SOUND**

- Nullifier = `SHAKE256(DOM_NULLIFIER || modq_encode(aots))` is deterministic in the signer's secret.
- `BlockchainPq.cpp:170-174` binds the recovered nullifier to the declared nullifier (prevents nullifier swapping).
- The canonical-encoding check on `aots` in `unpack` (`raptor_abi.rs:142-145`) prevents algebraic-aliasing double-spends.
- The intra-tx duplicate-nullifier guard (`checkPqNullifiersDiff`) runs before per-input validation.

### Concrete security level: **UNDEFINED**

No lattice estimator has been run on these parameters. Falcon-512 itself is NIST cat-1 (~128-bit), but the ring construction's security depends on the unproven reduction. Cannot report a defensible bit-count.

### Corrected B1 bound: **NOT PROVIDED**

Requires deriving from (n=512, q=12289, R=x^512+1) with the extractor's Cauchy-Schwarz blowup and running the lattice estimator. This is a human-audit deliverable.

---

## 3. Constant-Time Verdict

### What was verified

| Item | Verdict | Evidence |
|------|---------|----------|
| ctgrind/TIMECOP harness | **Clean in our code** | 99 flagged contexts, ALL in Falcon-internal C (keygen, sampler, comp_encode, modq_encode) or the glue assertion comparison. Zero in raptor.rs/raptor_falcon.c arithmetic. |
| `rfalcon_polymul_modq` data-dependent `continue` | **FIXED** | Now unconditional inner loop (raptor_falcon.c:127). Branchless on data. |
| Modular arithmetic hot paths (ringsig.rs legacy) | **CT, bit-identical** | Barrett mulmod, branchless cmod/pmod/addq/subq. Verified against schoolbook: 0 mismatches over 5000+ trials. |
| 0 secret-dependent memory accesses | **Confirmed** | No table-lookup/cache-timing leaks. |

### Items to bless (audit gate, not engineering)

| Item | Assessment |
|------|------------|
| Falcon keygen non-CT region | NTRU solve is research-grade; **one-shot per ephemeral key** (never re-derived on wallet load — verified: `WalletGreen`/`Transfers` are ML-KEM only). Standard argument holds. **Bless.** |
| BerExp isochronous sampler | PQClean's construction; CT by design. Flagged by valgrind (false positive — the seed is poisoned). **Bless.** |
| ML-KEM FO decapsulation comparison | PQClean's constant-time comparison. Not exposed via RPC. **Bless.** |
| Fiat-Shamir-with-aborts rejection count (sign) | Secret-dependent iteration count. Standard lattice-signature property. Wallet-side only; `verify` (consensus hot path) has no rejection loop. **Bless for software wallet; revisit for hardware.** |

### Masking recommendation

**Not needed** for a software wallet. Only relevant if hardware wallets/HSMs become a target — at which point a full masking effort is required (belief-propagation/higher-order pitfalls are real and documented). Explicitly out of scope per the threat model.

---

## 4. Standard-Scheme Usage Verdict

| Scheme | Verdict | Notes |
|--------|---------|-------|
| **ML-KEM-768** (stealth outputs) | **Correct** | FIPS 203. CCA-secure FO transform (PQClean). Stealth derivation: `SHAKE256("ccx-stealth-otk" ‖ ss)`. Domain-separated from message KEM. |
| **ML-DSA-65** (deposits) | **Correct** | FIPS 204. Detached signatures over prefix hash. m-of-n greedy match (same as Ed25519 path). |
| **Deterministic keygen** | **Verified** | `ccx_pq_detkeygen_selftest` proves determinism + pqcrypto interop (encap/decap + sign/verify through both libraries). Exact crate pins prevent silent encoding drift. |
| **ChaCha20-Poly1305** (messages) | **Correct** | Per-message fresh KEM secret + index-bound (key, nonce) via SHAKE256. No nonce reuse. Tamper detection verified (flip any byte → reject). |
| **XChaCha20-Poly1305** (wallet at-rest) | **Correct** | 24-byte random nonce (collision-safe). Argon2id KDF with tunable cost. CSPRNG salt/nonce via OsRng. |
| **Argon2id** | **Correct** | RFC 9106. Rejects salt < 8 bytes, iterations = 0. Client-side only (no consensus impact). |
| **Prefix-MAC** | **Sound** | Keyed SHAKE256 sponge MAC (immune to length-extension). Domain-separated subkey. Stored inside AEAD suffix (confidential + authenticated). |
| **Parameter sets** | **Correct** | ML-KEM-768, ML-DSA-65, Falcon-512 — all cat-1 NIST standardized. |

**Nonce/IV uniqueness:** Verified — no reuse path exists. Each message gets a fresh KEM ciphertext (hence fresh shared secret). Wallet nonce is random 192-bit.

**CCA security:** ML-KEM decapsulation is behind the FO transform with constant-time comparison. No decapsulation oracle exposed via RPC (the wallet calls `ccx_pq_kem_scan` locally).

**Deterministic keygen exactness:** `ccx_pq_detkeygen_selftest` proves byte-identical keys from the same seed through both RustCrypto and pqcrypto paths. Network tag prevents testnet/mainnet key collision. The `keygen_kat_ok()` tripwire fires at selftest time.

---

## 5. Consensus Verdict

### Determinism: **VERIFIED**

- Falcon keygen uses integer-emulated FP (no `double`/`float`). 4-platform KAT matrix (linux-x86, windows-gnu, windows-msvc, macos-arm64) produces identical digests.
- ML-KEM/ML-DSA are seed-based deterministic FIPS constructions.
- NTT is bit-identical to schoolbook (0 mismatches over 5000+ trials + edge cases).
- Serialization is canonical (varint, PQ tags, round-trip aots check).

### Height-gate: **CORRECT**

- PQ enable: `block.height < UPGRADE_HEIGHT_V10` rejects PQ txs below the fork (mainnet 5M, testnet 120).
- Classical freeze: `block.height >= UPGRADE_HEIGHT_V10` freezes classical deposit creation.
- Both gates activate at the **same block** — the source explicitly warns against changing `>=` to `>`.
- No off-by-one found.

### Double-spend prevention: **PARTIALLY BROKEN** (HIGH-2, MED-1)

- **On-chain:** `m_spent_pq_nullifiers` set + `checkPqNullifiersDiff` intra-tx guard + `check_pq_tx_input` recovered-nullifier bind. **Sound.**
- **Mempool:** `m_spent_pq_nullifiers` **not persisted** across restart (HIGH-2). Restart opens a window where duplicate-nullifier txs are admitted.
- **Block template:** `PqKeyInput` nullifier tracking **absent** from `BlockTemplate` (MED-1). Two conflicting PQ spends can be co-selected into one template.

### Serialization canonicality: **SOUND**

- Varint encoding rejects non-minimal forms.
- PQ variant tags (0x08 input/output, 0x09 multisig) are collision-free (input/output tag spaces are independent).
- `PqKeyOutput.kemCt` can be empty (coinbase) or fixed-size — both canonical.
- PQ multisig key array bounded at deserialization (`PQ_MULTISIG_MAX_KEYS = 16`).

### Integer overflow: **GUARDED**

- v4 money-conservation explicitly checks `check_inputs_overflow` + `check_outs_overflow` before the `outputs > inputs` comparison.
- `relative_output_offsets_to_absolute()` guards uint32 overflow.
- `ccx_pq_sign`/`ccx_pq_verify` bound `ring_count * member_stride` with `checked_mul`.

### Parser robustness / FFI boundary: **ADEQUATE**

- `ffi_guard()` catches all panics at the `extern "C"` boundary (no UB).
- Null pointer checks before every `slice::from_raw_parts`.
- Ring count bounded at `MAX_RING_COUNT = 32` (superset of consensus `PQ_MAX_RING_SIZE = 16`).
- Sig length bounded by `ring_sig_size(n)` DoS guard.
- **Not fuzzed** — the brief recommends `cargo-fuzz`/libFuzzer on deserialization + FFI paths. This is still open.

---

## 6. Crypto-Agility / Migration Verdict

### Scheme-ID pinning: **CORRECT**

- `PQ_RING_SCHEME_ID = 0x52415054` ("RAPT") in both `lib.rs:SCHEME_ID` and `CryptoNoteConfig.h:PQ_RING_SCHEME_ID`.
- `PQ_KEM_SCHEME_ID` and `PQ_DSA_SCHEME_ID` similarly pinned.
- Scheme IDs are version signals — an old client rejects a new format cleanly at the version check.
- On mainnet, a scheme change would be a height-gated hard fork (new `BLOCK_MAJOR_VERSION` / `UPGRADE_HEIGHT_*`).

### Classical→PQ migration: **SOUND**

- Classical deposit creation frozen at `UPGRADE_HEIGHT_V10` (`term != 0` output check gated on height).
- No value duplication: classical outputs remain spendable via classical ring signatures; new outputs are PQ-only.
- The freeze enforcement has zero size/throughput cost.

---

## 7. Go/No-Go Gates

### (a) Public testnet: **GO** (conditional)

**Conditions met:**
- Engineering is hardened (FFI guards, canonical encoding, overflow guards, DoS bounds).
- 67/67 PQ unit tests pass; cargo test 13/13 pass.
- ctgrind map is clean in our code.
- Cross-platform keygen KAT verified (4 platforms).
- Live e2e consensus green (spend accepted → double-spend rejected → independent nullifier accepted).

**Conditions to fix before public testnet:**
1. **HIGH-2:** Add `KV_MEMBER(m_spent_pq_nullifiers)` to `TransactionPool::serialize()`. One-line fix.
2. **MED-1:** Add `PqKeyInput` nullifier tracking to `BlockTemplate::canAdd()`/`addTransaction()`.

These are not consensus-breaking (the chain catches double-spends at connect time), but they degrade testnet quality (mempool pollution, wasted templates).

### (b) Mainnet: **NO-GO**

**Blocking conditions (all from the brief, all confirmed):**

1. **Raptor unforgeability proof** — the programmed-key forgery (HIGH-1) shows standalone unforgeability is broken. Either:
   - Bind ring public keys into the challenge hash (fix the construction), AND
   - Provide a formal unforgeability reduction to R-SIS/NTRU.
2. **B1 calibration** — derive the acceptance bound for the ring setting and run the lattice estimator (MED-2).
3. **`paramch_h` ceremony** — external NUMS commitment or random beacon (LOW-1).
4. **Constant-time sign-off** — bless Falcon keygen/sampler under formal audit (INFO-2).
5. **Fuzzing** — `cargo-fuzz`/libFuzzer on deserialization + FFI boundary paths.
6. **Anonymity proof** — formal statistical-distance bound for the non-signer distribution match.
7. **Production per-spend KDF** — replace the `OsRng` mix with a hardened per-spend KDF over wallet state.
8. **Fix HIGH-2 and MED-1** — mempool persistence and block template nullifier tracking.

---

## Cross-Reference Notes

### Findings corroborated by prior reviews
- Codex C-1 (nonce reuse → FIXED), H-1 (sk_len → FIXED), H-2 (aots canonicality → FIXED), M-3 (varint → FIXED) — all verified fixed.
- GLM KAT tripwire activation — verified active (`ccx_pq_ringsig_selftest` ANDs `keygen_kat_ok()`).
- B1 norm bound — matches prior audit H-1 item 2 ("Response bound: Not established").
- paramch_h ceremony — matches prior audit L-2.

### Findings NEW to this audit (not in prior reviews)
- **HIGH-1:** Programmed-key forgery in Raptor — no prior reviewer identified the `adaptive_ring_forgery` test as a security finding.
- **HIGH-2:** `m_spent_pq_nullifiers` mempool persistence gap.
- **MED-1:** BlockTemplate missing PqKeyInput nullifier tracking.
- **INFO-1:** Domain-separator methodology analysis (no length-prefixing in `hash_to_rq`).

---

*End of report.*
