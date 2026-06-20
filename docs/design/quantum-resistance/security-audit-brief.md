# Security Audit Brief — Conceal Post-Quantum PoC

**For an external cryptography / security researcher. Status: UNAUDITED, testnet-only PoC. This audit is the gate before mainnet is considered.**

This brief is self-contained: context, scope, what is already done (so you don't redo it),
what to check per surface (prioritized), tools/methods, and the deliverables we want back.

## 0. Context (read first)

Conceal is a CryptoNote privacy coin (C++11 daemon + wallet; ring signatures, stealth addresses,
encrypted messages, on-chain deposits). This is a **post-quantum proof-of-concept branch** that adds a
PQ replacement for every quantum-vulnerable (Shor-breakable) surface. It is **unaudited, testnet-only,
and height-gated**.

- **Branch:** `ThrownLemon/conceal-core @ pqc/mdbx-merge-poc` (full daemon + wallet). A standalone
  ring-sig PoC is also available separately.
- **All PQ crypto lives in one Rust crate** (`pqc/ccx-pqc`) exposed over a **C-ABI**, consumed by the
  C++ daemon/wallet. Vendored C: PQClean Falcon-512 ("clean", integer-emulated FP) + a clean-room shim
  (`csrc/raptor_falcon.c`). ML-KEM/ML-DSA via `pqcrypto` (PQClean) + RustCrypto `ml-kem`/`ml-dsa` for
  deterministic keygen.
- **Consensus is money-critical:** a validation bug can lose funds or fork the chain. All PQ rules are
  gated behind a future hard-fork height (`UPGRADE_HEIGHT_V10`).

## 1. Crypto inventory (what to audit), in priority order

| # | Surface | Scheme | Standardized? | Risk |
|---|---|---|---|---|
| **1** | **Spend / sender anonymity** | **Raptor** — clean-room linkable lattice **ring signature** over Falcon-512 + nullifier | ❌ academic (eprint 2018/857), heuristic | **HIGHEST — research-grade** |
| 2 | Side-channel / constant-time | cross-cutting (all secret-key ops) | — | High |
| 3 | Recipient stealth | ML-KEM-768 one-time keys | ✅ FIPS 203 | Usage |
| 4 | Deposits | ML-DSA-65 multisig + classical-freeze | ✅ FIPS 204 | Usage |
| 5 | Messages | ML-KEM-768 + ChaCha20-Poly1305 | ✅ | Usage (nonce/AEAD) |
| 6 | Wallet at-rest | Argon2id + XChaCha20 + prefix-MAC | ✅ | Usage |
| 7 | Key restore | FIPS-203/204 deterministic seed keygen (mnemonic) | ✅ | Funds-loss if non-deterministic |
| 8 | Address v2 | carries ML-KEM pubkey | — | Encoding |
| 9 | PoW / hashes | CryptoNight 256-bit (unchanged) | — | Low (Grover-adequate) |

**Amounts are plaintext (public by design)** — out of scope. Raptor hides the *signer*, not amounts
(no RingCT).

## 2. Threat model (scopes your effort)

- **Daemon = verify-only.** No secret-key operations on the network/consensus path → side-channels there
  do not apply. The side-channel surface is the **wallet**, and only vs a **local** attacker.
- **Consensus = every node must validate identically.** Any non-determinism in PQ validation /
  serialization / keygen → **chain split**. Treat cross-platform determinism as a first-class
  correctness property.
- **Adversary classes:** remote forger / de-anonymizer (network-only); local timing/cache attacker
  (wallet machine); and — only if hardware wallets become a target — power/EM/DPA.

## 3. What is already done (don't redo — verify / extend instead)

- **Functional tests** (sign/verify/roundtrip/determinism/double-spend) green on **6 platforms**
  (Linux ×3, macOS, Windows MSVC + MinGW) + a live testnet spend e2e.
- **Cross-platform Falcon keygen determinism KAT** — byte-identical digest on linux-x86 / windows-gnu /
  windows-msvc / macos-arm64 (3 compilers, 2 architectures).
- **Constant-time first pass** — a ctgrind/TIMECOP harness (valgrind, poisons the secret seed) + a CI
  tripwire. One real glue leak found and fixed (a data-dependent `continue` in the mod-q polymul).
  Current map: **0 secret-dependent memory accesses**; remaining flags are Falcon-internal (non-CT
  keygen, isochronous sampler) and public-output encoding.
- **4-reviewer adversarial vet** of the integration (Codex ×2, CodeRabbit, GLM) — 3 consensus holes
  found+fixed (intra-tx duplicate-nullifier inflation, duplicate multisig double-count, coinbase term
  injection).
- **Build-level reproducibility** (integer-emulated FP; identical digest across opt levels / `-march` /
  fast-math).

Known-open list: `measured-numbers.md` ("still requires humans") and `constant-time-status.md`.

## 4. What to check (the work), by area

### A. Raptor ring signature — highest priority, this is the research-grade piece
1. **Faithfulness** — does the clean-room reimplementation correctly instantiate the claimed scheme
   (eprint 2018/857 / the linkable ring sig)? Diff the construction against the paper.
2. **Unforgeability** — formal reduction: can a spend be forged without the signer's secret? Under what
   assumption (Module-NTRU / Falcon's SIS)?
3. **Anonymity** — does the ring actually hide the signer? Look for de-anonymization via the mask, the
   OTS public key `aots`, the nullifier, or the non-signer preimages. We sample non-signer `(r0,r1)` via
   **Falcon's own preimage sampler with a throwaway key** (not a CLT) specifically so signer/non-signer
   distributions match — **verify this holds** (statistically and theoretically).
4. **Linkability / nullifier soundness** — (a) can two spends of the **same** output yield **different**
   nullifiers (→ double-spend)? (b) can two **different** outputs **collide** nullifiers (→ false
   double-spend / fund freeze)? Nullifier = `SHAKE256(domain ‖ modq(aots))` — check `aots` uniqueness +
   binding to the secret.
5. **Norm bound `B1`** — the short-vector acceptance bound. Was it **re-derived for the ring setting**,
   not copied from single-Falcon? A loose bound → forgery; a tight one → valid-sig rejection (chain
   split).
6. **Parameters** — `paramch_h` (public ring element) needs a **nothing-up-my-sleeve
   derivation/ceremony**; check domain separation between all SHAKE uses.
7. **Concrete security level** — run the lattice estimator on the actual parameters (Falcon-512 base +
   the ring construction) against current BKZ/sieving; report bits of security.

### B. Constant-time / side-channel
1. Re-run + extend our ctgrind harness (`cargo test --features ctgrind` under valgrind; CI job
   `ctgrind (constant-time)`). **Bless or refute:** Falcon keygen's documented non-CT region (one-shot
   argument — note our keys are **ephemeral per-spend**, never a long-term key re-derived on load); the
   isochronous `BerExp` sampler's CT claim; the **ML-KEM FO-decapsulation comparison** (the classic
   CCA/timing hole).
2. Decide the **masking** question — only needed if a hardware wallet / HSM is a target; if so, scope
   the (large) masking effort and the belief-propagation / higher-order pitfalls.

### C. Standard-scheme usage (ML-KEM / ML-DSA / Argon2id / ChaCha)
The schemes are NIST-standard; the **usage** is the question:
- Correct parameter sets (ML-KEM-768, ML-DSA-65, Falcon-512).
- **Nonce/IV uniqueness** for ChaCha20-Poly1305 / XChaCha20 — any reuse is catastrophic; check the
  derivation.
- KEM used CCA-securely (FO transform; no decapsulation oracle exposed via RPC).
- **Deterministic keygen exactness** — does mnemonic restore the **byte-identical** key (FIPS `d‖z` / `ξ`
  seeds)? **Funds-loss-critical.** Verify `ccx_pq_detkeygen_selftest` proves it and that the on-chain key
  encoding matches what `pqcrypto` produces (the interop selftest).
- Argon2id cost parameters adequate for a wallet KDF; the **prefix-MAC** construction is a sound MAC
  (no length-extension / canonicalization gaps).

### D. Consensus / integration (C++ side)
- **Validation determinism** across nodes/platforms (the chain-split risk). Falcon keygen is
  KAT-verified; confirm ML-KEM/ML-DSA + the **serialization** are deterministic and **canonical**
  (non-canonical encodings → disagreement).
- **Height-gate + classical-freeze** logic — off-by-one (`>=` vs `>`) → chain split. Audit
  `UPGRADE_HEIGHT_V10` gating + the Option-3 freeze.
- **Double-spend prevention** — the nullifier set + mempool conflict tracking + the intra-tx
  duplicate-input guards (we fixed 3 here; re-verify completeness).
- **Integer overflow** in amount/term/fee handling on the PQ paths.
- **Parser robustness** — the FFI boundary + wire deserialization (fuzz it).

### E. Crypto-agility / migration
- Scheme-ID pinning (`PQ_KEM_SCHEME_ID`, `PQ_RING_SCHEME_ID`, `PQ_DSA_SCHEME_ID`) — can a broken
  primitive be swapped at a height-gated fork?
- The classical→PQ migration (freeze classical at the fork) — soundness, no value duplication/loss.

## 5. Tools & methods

- **Manual code review** — the Rust crate (`raptor.rs`, `ringsig.rs`, `falcon_ffi.rs`, `detkeygen.rs`,
  `walletcrypto.rs`), the C shim (`csrc/raptor_falcon.c`), and the C++ consensus glue.
- **Constant-time:** valgrind **ctgrind/TIMECOP** (extend ours), **dudect** (statistical timing); formal:
  **ct-verif / Binsec-Rel / haybale-pitchfork / SideTrail**; microarchitectural: Flush+Reload cache
  analysis.
- **Cryptanalysis:** the **lattice estimator** (Albrecht et al.) for concrete security of the parameter
  sets; check against known Module-LWE / NTRU attacks (BKZ, sieving, hybrid, dual).
- **Differential / KAT testing:** cross-check ML-KEM/ML-DSA against the **FIPS 203/204 test vectors** and
  against an independent reference impl; cross-check Falcon against the reference.
- **Fuzzing:** `cargo-fuzz` / libFuzzer / AFL++ on the deserialization + FFI-boundary paths (malformed
  sig/key/ciphertext, wire format).
- **Determinism matrix:** extend our keygen KAT to more architectures (ARM Linux, 32-bit, big-endian if
  relevant) for all seed-derived schemes.
- **Formal proofs** (ring sig): unforgeability + anonymity + linkability reductions, or a documented
  refutation.

## 6. Deliverables we want back

1. **Severity-rated findings report** (Critical/High/Medium/Low) with reproducers.
2. **Ring-sig verdict:** unforgeability, anonymity, and linkability — proofs or breaks; the corrected
   `B1` bound; the concrete security level (bits).
3. **Constant-time verdict:** bless/refute each flagged item; masking recommendation.
4. **Usage verdict** for the standard schemes (nonces, CCA, deterministic-keygen exactness, KDF/MAC).
5. **Consensus verdict:** determinism, height-gate, double-spend, serialization canonicality.
6. **Go/no-go gates:** (a) public testnet, (b) mainnet — each with explicit conditions.

## 7. Where to look (orientation)

- **Crypto:** `pqc/ccx-pqc/src/*` + `pqc/ccx-pqc/csrc/raptor_falcon.c` + `pqc/ccx-pqc/vendor/falcon/*`.
- **Consensus glue:** `src/CryptoNoteCore/{PqSpendBuilder,PqDepositBuilder,CryptoNoteFormatUtils}.cpp`,
  `src/Blockchain/BlockchainPq.cpp`, `src/CryptoNoteCore/TransactionPool.*`, `src/Serialization`.
- **Design docs / known-open:** `docs/design/quantum-resistance/` (browsable HTML site) — start with
  `measured-numbers.md`, `constant-time-status.md`, `raptor-integration-plan.md`, `pq-scheme-landscape.md`.
- **Existing tests** (your starting oracle): `tests/UnitTests/TestPq*.cpp`, the crate's `cargo test`, and
  `pqc/run-poc-testnet.sh` (live e2e).

## Bottom line for the researcher

The engineering is hardened and functionally tested across platforms. The two genuinely-open gates are
**(1) the Raptor ring-sig's cryptographic soundness** — heuristic / NTRU-based, never formally proven for
this construction — and **(2) the constant-time / side-channel posture of the secret-key paths**.
Concentrate there.
