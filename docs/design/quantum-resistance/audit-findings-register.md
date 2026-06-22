# PQ Security-Audit Findings Register

> **Status:** UNAUDITED, testnet-only, height-gated PoC. **Mainnet: NO-GO** pending an external
> cryptographer's sign-off on the Raptor construction and its proofs. This register is an input to
> the mainnet go/no-go gate, **not** a clearance.

This document is the consolidated, human-readable register of **every** security finding raised
against the Conceal post-quantum (PQ) proof-of-concept across all internal review rounds. It is a
*docs* artifact: it gathers and organizes findings that are already recorded in the review reports
under `docs/reviews/`; it does not introduce new findings or fixes. Each row cites the source
report and (where a fix landed) the commit(s) that closed it.

## Where the code lives

The PoC exists on **two local branches; nothing is pushed**:

| Branch | Repo / worktree | What it is |
|--------|-----------------|------------|
| `pqc/testnet-poc` | `/Users/travis/Projects/conceal-core` | The **original / monolithic** PoC tree (PQ ring-sig + deposits bolted onto the classic single-tree Conceal Core). |
| `pqc/mdbx-merge-poc` | `/Users/travis/Projects/conceal-core-mdbx-merge` | The **nullcryptodev MDBX-storage / `conceal-wallet` fork**, with the PQ PoC merged in. The audit ran here (`411c848f`); modular `src/Blockchain/*` validators. |

Most fixes were applied to **both** branches for parity (commit hashes differ per branch; the
register notes the per-branch hash where the task pinned them). The PQ live consensus spend path is
the clean-room **Raptor** linkable ring signature over Falcon-512 (`pqc/ccx-pqc/src/raptor.rs`),
wired through `ccx_pq_sign/verify/nullifier`. `ringsig.rs` (a `K=L=6` Module-SIS AOS ring signature)
is **self-test only** and not on any consensus path (see F8).

---

## Provenance legend

Every finding carries **exactly one** provenance tag answering *"whose defect is this?"* — so that
fork-introduced regressions, upstream-inherited issues, and genuine PQ-code defects are not
conflated.

| Tag | Meaning |
|-----|---------|
| **`[our-pq]`** | The defect is in PQ code **this project added** — the Rust crate (`pqc/ccx-pqc`: `raptor.rs`/`ringsig.rs`/`lib.rs`/`raptor_abi.rs`), PQ serialization of `PqKey*`/`PqMultisig*`, PQ validation (`check_pq_*`, the PQ branches of `check_outs_valid`), PQ RPC (`get_pq_*`), the PQ deposit/spend builders, the PQ wallet commands, PQ messages 0x06/0x07, deterministic keygen, and the KAT tripwires. |
| **`[dev-fork]`** | Introduced by the **nullcryptodev MDBX / `conceal-wallet` fork refactor**, *not* present in the original `pqc/testnet-poc` tree. Evidence required: the fix was needed **only** on `mdbx-merge`; `testnet-poc` was already correct. |
| **`[inherited]`** | Pre-existing in the **upstream / current-Conceal lineage**, *surfaced* (not introduced) by the PQ work; affects all transaction types, not PQ-specific. |
| **`[verify]`** | Provenance is **genuinely unclear or contradicted** by the source docs vs. the git history. Listed separately at the end for the maintainer to resolve — **not guessed**. |

Where a report carries its own `Provenance:` line (e.g. H-new-1), this register uses it verbatim.

---

## Round 1 — Original audit (`claude-opus.md` + `external-audit-package.md`)

Two independent internal audits (Claude/Opus + GLM/z.ai) converged on the top finding. The
consolidated register below is F1–F14 plus the GLM-side items (HIGH-2, MED-1) and the Codex
per-spend-randomness item (C-1). Severities are shown as **live / mainnet-or-primitive** where the
audit distinguished them.

| ID | Severity | Title | Status | Provenance | Fix (file / mechanism) + commit(s) | Source doc |
|----|----------|-------|--------|------------|-------------------------------------|------------|
| **F1** | HIGH (live) / CRITICAL (primitive) | Ring keys not bound into the Fiat-Shamir challenge → standalone forgery (committed PoC) | **Fixed** | `[our-pq]` | `raptor.rs:hash_transcript_to_b` now absorbs `ring.len()` + every ring public key before the `c_i`; wired through `sign`/`verify`; forgery test inverted to assert rejection (`programmed_key_forgery_is_rejected`). `32b87095` (mdbx) | claude-opus.md §2; external-pkg §2 |
| **F2** | CRITICAL (mainnet-blocker) | Unforgeability unproven for the as-built construction; norm bound `B1` never re-derived; concrete bits unknown | **Open** (closed for the *PoC gate* only) | `[our-pq]` | `B1` re-derived = `4·β²` (`raptor-b1-derivation.md`); lattice-estimator run (NTRU uSVP ≈ 2^141 = NIST L1; forgery R-SIS vacuous); extractor + anonymity ε-bound sketched (`raptor-formal-proofs.md`, `ε ≤ L·2^-128`). **Formal reduction + anonymity statistical bound remain an external-cryptographer deliverable.** Docs: `ce712cbc`, `b766e4c0` | claude-opus.md §2; external-pkg §3–4 |
| **F3** | HIGH | Keygen-determinism KAT + det-keygen interop selftest are dead code (dormant funds-loss / chain-split guard) | **Fixed** | `[our-pq]` | PQ selftest gate (incl. keygen KAT + det-keygen) at **daemon** startup (`Daemon.cpp`) and **wallet** startup (`ConcealWallet/main.cpp`), aborts on KAT drift. `32b87095` (mdbx) | claude-opus.md §5; external-pkg §2 |
| **F4** | HIGH | PQ **spends** (`PqKeyInput`/`PqKeyOutput`) lack an explicit `UPGRADE_HEIGHT_V10` height gate (deposits had one) | **Fixed** | `[our-pq]` | `transactionContainsPqSpend` helper (promoted to `CryptoNoteFormatUtils.{h,cpp}`) + **mainnet-only** `< V10 → reject` gate in per-tx + coinbase paths (`BlockchainStorage.cpp`). Test `TestPqSpendGate.cpp` (7/7). `32b87095` (mdbx) | claude-opus.md §5; external-pkg §2 |
| **F5** | HIGH (memo layer) | 0x07 authenticated-message AEAD: derived nonce, no AAD → keystream reuse iff tx-key reused | **Fixed** | `[our-pq]` | `ccx_pq_msg_seal_v2`/`open_v2` (`lib.rs`): caller-supplied 24-byte random XChaCha20 nonce + bound AAD (tx-pubkey‖output-index), v2-domain key; wired into `TransactionExtra.cpp` with a v2-then-v1 decrypt fallback (old memos stay readable). `32b87095` (mdbx). **Mainnet emission height-gate = caller decision (still open).** | claude-opus.md §4; external-pkg §2; msg-aead-0x07-nonce-fix.md |
| **F6** | MEDIUM (wallet) / HIGH (mainnet) | Signing Gaussian sampler + ML-KEM FO-decap constant-time unverified; CI ctgrind tripwire guards only the C glue | **Open** | `[our-pq]` | dudect harness added (`falcon_ffi::ct_dudect`, `lib.rs::f6_mlkem_dudect`); runs show no timing dependence (Falcon `t≈-0.05…-0.67`; ML-KEM `t(full)≈0` after matched pools). `32b87095`. **Researcher-grade million-sample, dedicated-host campaign still required.** | claude-opus.md §3; external-pkg §5; reports 09 (M-new-1), 13 |
| **F7 / LOW-3** | MEDIUM / LOW | `PqKeyInput.ringSig` canonicality delegated to FFI (no C++ assertion) → possible txid malleability; parse-time length bound loose | **Fixed** (mitigated) | `[our-pq]` | Double-bounded by `ccx_pq_verify` (`sig_len ≤ ring_sig_size`) + `CRYPTONOTE_MAX_TX_SIZE`; added a 1 MiB parse-time bound on `ringSig` in `CryptoNoteSerialization.cpp`. `32b87095` (LOW-3 part) | claude-opus.md §5; external-pkg §2 |
| **F8** | INFO (dead) / MEDIUM (false assurance) | Self-test-only `ringsig.rs` (`K=L=6`, `t=A·s`, no error term) is structurally broken — secret trivially recoverable from the public key; its selftests certify a broken scheme | **Fixed** (quarantined + proven) | `[our-pq]` | DANGER header + key-recovery PoC test `secret_is_recoverable_from_public_key` (PASSES, proves the break); whole module + its `ccx_pqr_*` exports feature-gated behind non-default `legacy-ringsig-demo`. Not live on either branch. `32b87095` (mdbx) | claude-opus.md §2; external-pkg §2 |
| **F9** | LOW / MEDIUM (mainnet) | `paramch_h` nothing-up-my-sleeve value lacks a documented derivation ceremony | **Open** (documented) | `[our-pq]` | Frozen-spec digest pinned + test (`raptor.rs:paramch_h_matches_frozen_spec`); ceremony options documented (`paramch-h-spec.md`). **Pick a beacon/MPC/frozen-spec ceremony before mainnet.** | claude-opus.md §2; external-pkg §2 |
| **F10** | LOW | `NETWORK_TAG="ccx-testnet"` pre-launch tripwire (flipping it changes every derived address); deprecated RustCrypto entry points | **Open** (checklist) | `[our-pq]` | Pre-mainnet checklist item; the det-keygen selftest that guards the encodings now runs at startup (via F3). | claude-opus.md §4; external-pkg §2 |
| **F11** | INFO / LOW | Spend artifacts carry no scheme/version tag; `dsaSchemeId` not committed on-chain → agility is a height-gated flag-day, not per-output | **Open** (documented) | `[our-pq]` | Documented agility gap; per-output scheme byte recommended for true agility. (Address-layer scheme IDs *are* serialized + fail-closed validated.) | claude-opus.md §6; external-pkg §2; report 09 (M-new-5) |
| **F12** | MEDIUM | `raptor_abi::unpack` integer overflow (`*pos + len` with an untrusted varint) → panic (debug) / silent wrap (release) | **Fixed** | `[our-pq]` | `get_blob` uses `checked_add` → clean reject; contained on the live path by `ffi_guard` `catch_unwind`. Found by the (now-fixed) Phase-5 fuzz harness; re-fuzzed 19.3M runs crash-free. `32b87095` (mdbx) | external-pkg §2; CHANGELOG Wave 2 |
| **F13** | LOW | `PqKeyOutput` not tx-version-gated (`>= 4`) unlike `PqKeyInput`/`PqMultisigOutput` — a non-coinbase pre-v4 tx could carry one | **Fixed** | `[our-pq]` | v4 gate in `check_outs_valid` **with a coinbase exemption** (the v1 testnet coinbase legitimately carries the PQ stealth output). Test `PqSpendGate.PqKeyOutputRejectedInNonCoinbasePreV4Tx`. Defense-in-depth over the F4 block gate. `32b87095` (mdbx) | external-pkg §2; CHANGELOG Wave 4; HANDOFF Item 9 |
| **F14** | LOW | `Blockchain::pushBlock` mid-loop rollback leak: on `tx[i]` validation failure only the coinbase was popped, leaking `tx[0..i-1]`'s key-image/nullifier/output mutations into in-memory indices (false double-spend on retry until resync) | **Fixed** | `[inherited]` *(CHANGELOG / external-pkg call it "pre-existing / non-PQ"; PQ nullifier conflicts merely reproduce it)* | Targeted **reverse rollback** of `tx[0..i-1]` + coinbase (`BlockchainStorage.cpp`) — **not** `popTransactions()` (which would erase the failed tx's own key image). UnitTests 100% + CoreTests. `32b87095` (mdbx) | external-pkg §2; CHANGELOG Wave 4; HANDOFF Blocker 6 |
| **HIGH-2** (GLM) | HIGH | `m_spent_pq_nullifiers` not persisted in the mempool serialize | **Fixed** | `[our-pq]` | `KV_MEMBER` added to mempool serialization (`TransactionPool.cpp`). GLM-found; verified. | external-pkg §2; HANDOFF §1 |
| **MED-1** (GLM) | MEDIUM | `BlockTemplate` lacked `PqKeyInput` nullifier tracking | **Fixed** | `[our-pq]` | `m_pqNullifiers` template-set (`TransactionPool.cpp`). GLM-found; verified. | external-pkg §2; HANDOFF §1 |
| **C-1** (Codex) | (advisory) | Per-spend signing randomness = raw concat (lattice nonce-reuse risk) | **Fixed** | `[our-pq]` | HKDF-like extract-then-expand over SHAKE256 (PRK = SHAKE(sk‖os_rand); seed = SHAKE(PRK‖msg)) in `lib.rs:ccx_pq_sign` — no nonce reuse even under OsRng compromise. | external-pkg §2; claude-opus.md §0.5 |
| **B1** | (mainnet-blocker; part of F2) | Acceptance norm bound `FALCON512_SQNORM_BOUND` reused from single-Falcon β², never re-derived for the ring setting | **Fixed** (derived) | `[our-pq]` | Extractor gives `4·β²` slack; verify enforces the tight single-Falcon β² (no false rejections). §5.1 quantitative error corrected; §5.3 estimator run added. `raptor-b1-derivation.md`; docs `ce712cbc` | claude-opus.md §0.5/§2; external-pkg §3 |

> **Note on F2/B1 "Fixed":** the *derivation, estimator run, and proof sketches* are complete, but
> the source docs are explicit that the **formal unforgeability reduction and the anonymity
> statistical-distance bound are still pending an external cryptographer** — they are inputs, not a
> substitute. F2 is therefore tracked as **Open** at the mainnet gate (see Still-open). Report 09
> (M-new-2, M-new-3) additionally flags the proof/B1 documents as not-yet-complete reductions.

---

## Round 2 — Post-remediation delta audit (`09-post-remediation-delta-audit.md`)

Independent re-audit of the remediated worktree at `411c848f`. Confirmed F1/F3/F5 fixes and the
malformed-PQ-output rejection; raised new residual items.

| ID | Severity | Title | Status | Provenance | Fix (file / mechanism) + commit(s) | Source doc |
|----|----------|-------|--------|------------|-------------------------------------|------------|
| **M-new-4** | MEDIUM | Cross-architecture KAT matrix covers Raptor/Falcon keygen only — not ML-KEM, ML-DSA, address-v2, wallet PQ-section, or serialized PQ transactions | **Open** | `[our-pq]` | Raptor keygen KAT (`8f24…745e`) reproduces on aarch64 / i686 / s390x(BE); a `pq-determinism` CI job pins that one digest. **Pinned fixtures for the other seed-derived artifacts still missing.** Partial step in `830c97be` (mdbx) / `459be83e` (testnet-poc). | report 09 (M-new-4); reports 11, 13 |
| **M-new-5** | MEDIUM | PQ deposit outputs do not serialize a DSA scheme ID (`dsaSchemeId`) → deposit agility is height/tag-based only | **Fixed** | `[our-pq]` | `dsaSchemeId` is now serialized into `PqMultisigOutput`; PQ artifact KAT + DSA scheme IDs pinned. `830c97be` (mdbx) / `459be83e` (testnet-poc). **Consensus/wire change — see below.** | report 09 (M-new-5); report 11 |
| **L-new-1** | LOW | 0x07 AEAD v2 reuses the same extra tag without an explicit sub-version; old v1 memos parse-valid but not decryptable by v2 | **Fixed** | `[our-pq]` | v1 `0x07` decrypt fallback kept (v2-then-v1, unambiguous via distinct SHAKE-domain keys) for historical memo readability. `b766e4c0` | report 09 (L-new-1); report 11 |
| **L-new-2** | LOW | Raptor `verify` fuzz target usually returns before reaching verification (poor malformed-ring coverage) | **Fixed** | `[our-pq]` | Fuzz target reworked to synthesize a valid-length ring so every iteration reaches `ccx_pq_verify`. `b766e4c0` | report 09 (L-new-2); report 11 |
| **L-new-3** | LOW | Raptor scheme-ID documentation stale (`0xC0DE0003/0004` vs. code's `"RAPT"`/`0x52415054`) | **Fixed** | `[our-pq]` | Stale design docs corrected to `0x52415054` / `"RAPT"`. `b766e4c0` | report 09 (L-new-3); report 11 |
| **L-new-4** | LOW | ML-DSA / FIPS wording implies a validated verifier stack (deposit sign/verify still uses `pqcrypto-dilithium`) | **Fixed** | `[our-pq]` | Wording qualified to "Dilithium3 / ML-DSA-65-compatible via pqcrypto"; det-keygen RustCrypto claim kept separate from the pqcrypto sign/verify claim. `b766e4c0` | report 09 (L-new-4); report 11 |

> Report 09 also raised **M-new-1** (dudect threshold `|t|<500` too loose to be a CT gate),
> **M-new-2** (the formal-proofs doc is proof *exploration*, not a completed reduction), and
> **M-new-3** (the B1 doc is internally inconsistent / overstates completion). These are
> documentation-quality / proof-completeness observations on the F2/F6 work rather than separate
> code defects; they roll up into the Still-open F2 (external proof sign-off) and F6 (side-channel)
> gates. All `[our-pq]`.

---

## Round 3 — Adversarial parser audit (`10-adversarial-parser-audit.md`)

Targeted at the C++ PQ transaction-extra and transaction serialization parser surfaces.

| ID | Severity | Title | Status | Provenance | Fix (file / mechanism) + commit(s) | Source doc |
|----|----------|-------|--------|------------|-------------------------------------|------------|
| **M-new-6** | MEDIUM | PQ multisig deserialization materializes oversized inner PQ blobs (`PqKeyInput.ringSig`, `PqMultisigInput.signatures[]`, `PqMultisigOutput.keys[]`) before semantic size checks → parse-time heap-exhaustion | **Fixed** | `[our-pq]` | Bounded binary reads that reject the length prefix **before** allocation (`PqKeyInputOverDeclaredRingSigPrefixRejectedBeforeMaterialization`). Initial bound `c3c5b751`; per-element/ring hardening `162b12ca` + `f6eb6de8`; **pre-materialization closure `c9ab9e4b`** (mdbx) | report 10 (M-new-6); report 11 |
| **M-new-7** | MEDIUM | `PqKeyInput.outputIndexes` (the ring-index vector) materialized via generic `serializeVarintVector` before `PQ_MAX_RING_SIZE` is enforced → parse-time allocation of an impossible ring | **Fixed** | `[our-pq]` | Rejects PQ ring counts above `PQ_MAX_RING_SIZE` before `vector.resize`. `162b12ca` (mdbx) | report 10 (M-new-7); report 11 |
| **M-new-8** | MEDIUM | PQ multisig outputs accept malformed (wrong-length) ML-DSA deposit public keys into validated output state (`check_outs_valid` + block-connect visitor) → unspendable cells / burnt funds / index pollution | **Fixed** | `[our-pq]` | Rejects wrong-length deposit keys in both `check_outs_valid` and the block-connect visitor (`PqMultisigOutputWrongKeyLengthRejectedByCheckOutsValid`). `162b12ca` (mdbx) | report 10 (M-new-8); report 11 |

> Report 10 also recorded **clean** results: unknown adjacent PQ variant tags (`0x0a`) reject;
> `PqMultisigOutput` count over `PQ_MULTISIG_MAX_KEYS` rejects before inner blobs are read; truncated
> 0x06 PQ tx-extra rejects cleanly. Parity hardening was ported to testnet-poc in `ede63416` /
> `2bd547e2`.

---

## Round 4 — Reorg / pool / KAT follow-ups (`11`, `12`, `13`)

| ID | Severity | Title | Status | Provenance | Fix (file / mechanism) + commit(s) | Source doc |
|----|----------|-------|--------|------------|-------------------------------------|------------|
| **M-new-9** | MEDIUM | PQ output-enumeration RPCs lacked pagination / bounded the locked-bucket walk → unbounded scan DoS | **Fixed** | `[our-pq]` | Bounded blockchain queries + `start_index`/`limit`/`next_index` + shared wallet/client pagination. `95f8352b` (mdbx) | report 11 (closure table) |
| **Checkpoint structural/crypto decouple** | (consensus correctness) | Inside the checkpoint-trusted zone, PQ structural/reference validation was being skipped together with signature verification | **Fixed** | `[our-pq]` | Always execute PQ structural/reference validation; skip **only** cryptographic verification when checkpoint trust applies. `3a5c07a9` (mdbx) / `2bd547e2` (testnet-poc parity; `skipSignatureVerify` present in both `Blockchain.cpp`). **Consensus-validation change — see below.** | report 11 (closure table) |
| **H-new-1** | HIGH (BLOCKER) | A heavier valid fork is rejected unless it repeats every displaced main-chain transaction (`verifyAlternativeChainTransactions` subset rule) → nodes can stick on incompatible tips; PQ nullifier conflicts reproduce it but it affects **all** tx types | **Fixed** | `[inherited]` *(report 12, verbatim: "the same main-transaction subset rule exists in the monolithic pre-MDBX implementation at `aa4dbe96^`; the MDBX refactor preserved rather than introduced it")* | Removed the displaced-main-tx subset rule; verify each alt block's referenced txs are available instead. `59f8425f` (mdbx) / `601ede69` (testnet-poc parity). **Reorg-semantics consensus change — see below.** | report 12 (H-new-1); report 11 |
| **M-new-10** | MEDIUM | Fixed testnet difficulty (`TESTNET_PQ_POC_DIFFICULTY`) not applied to **alternative** blocks (`get_next_difficulty_for_alternative_chain` runs the normal retarget) → testnet nodes reject each other's validly-mined fork blocks | **Fixed** | `[our-pq]` *(defect is in the PoC's testnet fixed-difficulty path the project added)* | Return `TESTNET_PQ_POC_DIFFICULTY` from the alt-chain difficulty path when `isTestnet()`. `59f8425f` (mdbx) / `601ede69` (testnet-poc parity). **Testnet alt-difficulty change — see below.** | report 12 (M-new-10) |
| **M-new-11** | MEDIUM | Removing a `keptByBlock` PQ withdrawal clears a **different** normal withdrawal's deposit-cell reservation (`removeTransactionInputs` erased `m_spent_pq_deposit_cells` unconditionally, unlike the add path and the classical `MultisignatureInput` branch) → conflicting withdrawals admitted/relayed (mempool/relay invariant break, not a consensus inflation path) | **Fixed** | **`[dev-fork]`** *(verified: `1d4f4b81` is on **mdbx-merge only** — `git branch --contains`; there is **no** M-new-11 commit on testnet-poc, and testnet-poc's `m_spentPqDeposits` erase is already inside an `if (!keptByBlock)` guard. So the original tree was always correct; the **MDBX fork's `TransactionPool` refactor dropped the guard** — i.e. fork-introduced)* | Guard the erase on `!keptByBlock`, mirroring the add path + classical branch (`TransactionPool.cpp`). Reproducer `PqTransactionPool.RemovingKeptByBlockWithdrawalPreservesNormalReservation`. `1d4f4b81` (mdbx-merge only; testnet-poc unaffected). | report 13 (M-new-11); report 11 |

> Report 13 also recorded a **clean** path: a partial alternative-chain push rolls back atomically
> (`PqChainState.FailedAlternativePushRestoresMainPqState` passes) — no state-atomicity defect in
> the missing-transaction failure path.

---

## Consensus / wire-format changes

These remediations alter what nodes **accept** (validation) or how data is **serialized** — i.e.
they are not behaviour-preserving bug fixes. Each has a testnet-reset / coordination implication.

| Change | Finding(s) / commit(s) | Nature | Reset / coordination implication |
|--------|------------------------|--------|----------------------------------|
| `dsaSchemeId` serialized into `PqMultisigOutput` | M-new-5 — `830c97be` (mdbx) / `459be83e` (testnet-poc) | **Wire/on-disk format change** — deposit cells now carry the DSA scheme ID on-chain | Old deposit-cell bytes are not forward-compatible. Requires a testnet reset (or a documented height/tag rule for spending pre-change deposits after a DSA swap). |
| PQ-spend & `PqKeyOutput` tx-version / height gates | F4 (`< V10 → reject`, mainnet-only) + F13 (`PqKeyOutput` requires `tx.version >= 4`, coinbase-exempt) — `32b87095` / parity | **Validation-rule change** — defines when PQ spends/outputs are admissible | Activation is height-gated behind `UPGRADE_HEIGHT_V10` (mainnet); on testnet PQ is active from height 1, so no reset needed, but the mainnet gate must be coordinated as a fork. The F4 mainnet gate is **not exercised by the testnet suite** — a mainnet-params unit test is required before mainnet. |
| Reorg semantics: drop the displaced-main-tx subset rule | H-new-1 — `59f8425f` (mdbx) / `601ede69` (testnet-poc) | **Consensus chain-selection change** — nodes can now switch to a heavier valid fork with a different tx set | All nodes must run the new rule before a contentious reorg, or they will disagree on the canonical tip. Coordinate the upgrade network-wide; testnet should be reset/announced. |
| Checkpoint structural-vs-cryptographic decouple | Checkpoint coupling — `3a5c07a9` (mdbx) / `2bd547e2` (testnet-poc) | **Validation-rule change** — structural/reference PQ checks now always run inside the checkpoint zone | Changes which blocks pass inside the checkpoint zone. Land before any non-resettable testnet. Parity present on both trees. |
| Testnet alternative-block fixed difficulty | M-new-10 — `59f8425f` (mdbx) / `601ede69` (testnet-poc) | **Testnet difficulty-rule change** (testnet-only) | Makes alt-block difficulty match the active-chain template on testnet. Requires a coordinated testnet restart so all nodes apply the same rule to forks. |
| 0x07 AEAD v2 (nonce + AAD) | F5 / L-new-1 — `32b87095` | **Message-format change** (tx-extra, **non-consensus**) | New 0x07 memos are not decryptable by pre-change wallets; a v2-then-v1 decrypt fallback keeps old memos readable. Mainnet **emission** must be height-gated (caller decision — still open). Testnet is resettable, so v2-always is fine there. |

---

## Still open (mainnet gating)

These are deliberately **not closeable in code by this project** — they need external review,
dedicated hardware, or a product decision. Mainnet stays **NO-GO** until all are resolved.

1. **External cryptographer sign-off on the Raptor proofs (F2).** A human lattice specialist must
   review (a) the Raptor construction itself (a clean-room reimplementation of eprint 2018/857 §6.5,
   never deployed in production), (b) the unforgeability reduction (rewinding extractor + forking
   lemma), (c) the anonymity statistical-distance / Rényi bound (`ε ≤ L·2^-128`), and (d) the
   lattice-estimator output (NTRU ≈ 2^141 classical) against current sieving variants. The in-tree
   proof sketches and estimator run are **inputs, not a clearance** (reports 09 M-new-2/M-new-3
   explicitly flag them as not-yet-complete reductions).
2. **Full cross-architecture KAT fixture matrix (M-new-4).** Only the Raptor/Falcon keygen digest
   (`8f24…745e`) is pinned and run across aarch64 / i686 / s390x(BE). Pinned digest fixtures are
   still needed for ML-KEM keygen, ML-DSA keygen, address-v2 bytes, the wallet PQ-section, and
   complete seed-derived signed PQ deposit/spend transactions — then run on the same targets. A
   determinism gap here is a chain-split risk.
3. **Million-sample side-channel campaign (F6).** dudect runs (4k–50k samples, single shared host)
   show no leakage but do not meet the brief's bar: the Falcon signing Gaussian sampler and the
   ML-KEM FO-decap (which runs on the long-term KEM key every wallet scan) need a dedicated quiesced
   core, `performance` governor, SMT disabled, ≥10^6 samples per class, and 3+ runs — plus
   ctgrind/TIMECOP and a specialist review of the secret-dependent paths. A masking decision must be
   recorded.
4. **`dsaSchemeId` agility disposition (M-new-5 / F11) and `paramch_h` ceremony (F9).** Decide
   whether per-output scheme tags (true crypto-agility) are required before public persistence, and
   execute a documented NUMS ceremony (beacon / MPC / frozen-spec) for `paramch_h`.
5. **F5 mainnet rollout decision.** Height-gate 0x07 v2 **emission** (and keep v1 decrypt forever);
   a non-resettable chain cannot break pre-upgrade memos.
6. **Mainnet rollout gating.** `UPGRADE_HEIGHT_V10` stays a far-future sentinel until the above pass;
   the F4 mainnet-only gate needs a mainnet-params unit test; extended fuzzing (≥24h on a dedicated
   host, plus a C++ libFuzzer/AFL++ target on the transaction deserializer) and scale/reorg stress
   testing remain outstanding (HANDOFF Items 7–8).

---

## `[verify]` — resolved

The draft tagged **M-new-11** `[verify]` on a mistaken reading that the fix commit `1d4f4b81` touched
both branches. Resolved to **`[dev-fork]`** against the git evidence:

- `git branch --contains 1d4f4b81` → **`pqc/mdbx-merge-poc` only**; `git log --all | grep M-new-11`
  returns only that one mdbx commit. There is **no** M-new-11 commit on `pqc/testnet-poc`.
- testnet-poc's `removeTransactionInputs` already guards the deposit-cell erase — the
  `m_spentPqDeposits.erase(...)` sits inside an `if (!keptByBlock)` block (predating this work; no fix
  was needed there).
- So the original/monolithic tree was always correct; the **unconditional** erase exists **only** on
  the MDBX fork, whose `TransactionPool` refactor renamed the set (`m_spent_pq_deposit_cells`) and
  dropped the `!keptByBlock` guard → **fork-introduced (`[dev-fork]`)**.

No findings remain in `[verify]`.

---

## Provenance summary

| Tag | Count | Findings |
|-----|-------|----------|
| `[our-pq]` | 27 | F1, F2, F3, F4, F5, F6, F7/LOW-3, F8, F9, F10, F11, F12, F13, HIGH-2, MED-1, C-1, B1, M-new-4, M-new-5, M-new-9, M-new-10, M-new-6, M-new-7, M-new-8, L-new-1, L-new-2, L-new-3, L-new-4, checkpoint decouple *(see note)* |
| `[dev-fork]` | 1 | M-new-11 (the MDBX `TransactionPool` refactor dropped the `!keptByBlock` deposit-cell-reservation guard; testnet-poc unaffected) |
| `[inherited]` | 2 | F14 (pushBlock mid-loop rollback leak), H-new-1 (alt-chain subset rule) |
| `[verify]` | 0 | — (M-new-11 resolved to `[dev-fork]`) |

> The counts above treat L-new-1..4, M-new-6/7/8, M-new-9, the checkpoint decouple, and B1 as
> distinct `[our-pq]` rows alongside F1–F14 / HIGH-2 / MED-1 / C-1 / M-new-4/5/10. The
> documentation-quality observations M-new-1/2/3 (report 09) are not counted as separate rows — they
> roll into the F2 and F6 still-open gates.
