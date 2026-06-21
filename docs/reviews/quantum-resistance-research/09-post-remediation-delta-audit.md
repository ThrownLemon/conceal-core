# Post-Remediation Delta Audit

Date: 2026-06-21
Current HEAD: `411c848f7276ae5099b7e5c7e0fd01977f6ae243`
Scope: current dirty worktree after Claude remediation, focused on additional issues and audit-brief coverage.

## Verification Run

Local Rust crate:

```text
cd pqc/ccx-pqc
cargo test --offline -- --nocapture

Result: 9 passed, 0 failed, 2 ignored.
Ignored: Falcon sampler dudect, ML-KEM decap dudect.
```

Targeted Raptor regression:

```text
cargo test --offline adaptive_ring_forgery::programmed_key_forgery_is_rejected -- --nocapture

Result: passed.
```

WSL source parity check:

```text
sha256(local files) == sha256(100.100.90.103:/home/travis/conceal-core-mdbx-merge files)
Files checked:
  src/CryptoNoteCore/TransactionExtra.cpp
  src/Blockchain/BlockchainStorage.cpp
  pqc/ccx-pqc/src/raptor.rs
  tests/UnitTests/TestAuthenticatedMessage.cpp
```

WSL C++ targeted tests:

```text
./build/tests/unit_tests --gtest_filter="AuthenticatedMessage.*:MixedMessageIndex.*:PqSpendGate.*:PqOutputValidation.*"
Result: 26 passed.

./build/tests/unit_tests --gtest_filter="PqDepositTxTest.*:PqDepositPrimitive.*:PqDepositSerialization.*:PqDepositCurrencyTest.*:PqMessage.*:PqMessageDefaultSendPath.*:PqAddress.*:PqWalletSection.*:checkPqNullifiersDiff.*:checkPqMultisigInputsDiff.*"
Result: 51 passed.
```

## Fixed or Improved Since the First Report

1. **Adaptive programmed-key Raptor forgery path is closed in the current worktree.**
   `hash_transcript_to_b` now absorbs `ring.len()` and every ring public key before the `c_i` values.
   The old construction's forged transcript is rejected by
   `raptor::adaptive_ring_forgery::programmed_key_forgery_is_rejected`.

2. **Malformed PQ output-key indexing is remediated in current code.**
   The current `check_outs_valid`/visitor path rejects wrong-sized or non-canonical `PqKeyOutput.key`
   values and wrong-sized non-empty `kemCt` values. The targeted regression
   `PqOutputValidation.RejectsMalformedPqKeyOutput` passes.

3. **PQ nullifier and PQ deposit-cell duplicate checks are covered by unit tests.**
   `checkPqNullifiersDiff.*` and `checkPqMultisigInputsDiff.*` both pass on the WSL build.

4. **0x07 authenticated-message nonce reuse is remediated for newly emitted messages.**
   New 0x07 fields use a 24-byte random XChaCha20 nonce plus AAD binding to `(tx public key, output index)`.
   Authenticated-message and mixed-message-index tests pass.

## Additional Findings / Residual Issues

### M-new-1: The new dudect-style tests cannot certify constant-time behavior

**Affected files:** `pqc/ccx-pqc/src/falcon_ffi.rs`, `pqc/ccx-pqc/src/lib.rs`

The added timing tests are useful smoke harnesses, but they are ignored by default and use
`abs(t) < 500` as the assertion threshold:

- `falcon_ffi.rs:209-233`
- `lib.rs:622-654`

For dudect-style leakage detection, `|t|` near or above roughly 10 is already a strong signal in a
controlled campaign. A threshold of 500 would allow very large timing differences to pass and should
not be used as a security gate. This means Task 5 remains open even though harness code exists.

Required follow-up:

- Keep the tests ignored for local developer runs, or make them report-only.
- For an audit gate, run pinned-core/high-sample dudect externally and fail on a conventional threshold
  with trace counts, CPU model, governor, and raw time-series artifacts.
- Do not describe these tests as blessing Falcon or ML-KEM constant-time behavior.

WSL smoke run evidence:

```text
cargo test --release ct_dudect -- --ignored --nocapture
DUDECT falcon sign_target: Welch t(full)=-0.04  t(fast-70%-cropped)=-2.37  n=4000
Result: 1 passed.

cargo test --release f6_mlkem -- --ignored --nocapture
DUDECT mlkem768 decap valid-vs-invalid: t(full)=-0.76 t(cropped)=-2.45 n=4000
Result: 1 passed.
```

These results are useful regression tripwires, but they do not close the side-channel gate because the
tests are ignored by default, use 4000 samples unless overridden, and accept `abs(t) < 500`.

### M-new-2: The current Raptor proof document is not a valid completed reduction

**Affected file:** `docs/design/quantum-resistance/raptor-formal-proofs.md`

The document is useful as proof exploration, but it still contains unresolved reduction breaks and
should not be treated as an established theorem. Examples:

- Lines 79-87 state an embedding approach, then acknowledge it does not work and switch to programming
  `H1(aots*)` after the forgery.
- Lines 136-140 acknowledge the extracted target is not the reduction challenge target, then assert
  that any known-target preimage is enough.
- Lines 161-167 call a bound around `2^-38.5` "negligible" while also claiming real security is set by
  `2^141`; that is not a mainnet-grade reduction statement.
- Lines 352-361 cite a `stats` harness and claim the observed 0.2% standard-deviation match is
  within a `2^-128` theoretical bound, but this audit tree does not contain the referenced raw
  statistical artifact in `docs/reviews/quantum-resistance-research/`.

Required follow-up:

- Keep Task 1 open until an external cryptographer reviews a cleaned reduction.
- State the exact hard problem solved by extraction. Do not silently replace a random-target preimage
  assumption with an arbitrary-target or structured-target assumption.
- Preserve the old programmed-key attack as a negative test, but do not count the regression as a proof.

### M-new-3: The B1/norm-bound document is internally inconsistent and overstates completion

**Affected file:** `docs/design/quantum-resistance/raptor-b1-derivation.md`

The document says the lattice-estimator run is pending at line 3, then later says it completed at
lines 159-167, then recommends running the estimator at lines 204-213. It also acknowledges the
homogeneous SIS bound is vacuous while still presenting the bound as validated for mainnet if the
estimator confirms sufficient bits.

Follow-up search evidence: `docs/reviews/quantum-resistance-research/` currently contains only
`01-raptor-proof-analysis.md` and this delta audit. No estimator script, SageMath transcript, raw
output, commit pin, or machine-readable result artifact was found there.

Required follow-up:

- Move raw estimator scripts/output into the Task 3 artifact path required by the audit plan.
- Separate three claims: honest-rejection threshold, extractor slack, and concrete hardness.
- Do not mark Task 2 or Task 3 complete until the raw estimator data and independent review exist.

### M-new-4: The cross-architecture KAT matrix covers Raptor/Falcon keygen only, not all seed-derived PQ artifacts

**Affected files:** `.github/workflows/check.yml`,
`docs/design/quantum-resistance/cross-arch-kat-matrix.md`

The audit brief asks for a determinism matrix over all seed-derived schemes and artifacts: ML-KEM,
ML-DSA, Raptor, PQ addresses, and serialized transactions. The current CI matrix runs only
`cargo test --release ... keygen_kat` on aarch64, i686, and s390x, and the design doc describes only
`SHAKE256_32(modq_encode(a0) || modq_encode(aots))` for the Raptor/Falcon keygen output.

Verification evidence:

```text
cargo test --release keygen_kat -- --nocapture
KEYGEN_KAT_DIGEST=8f245c82dc7390f3cb4d8955556a45d56af41c83a37fc0388b996b58f295745e
Result: 1 passed.
```

This proves the current Raptor keygen KAT still passes, but it does not pin deterministic ML-KEM
account keys, ML-DSA deposit keys, address-v2 bytes, wallet PQ-section bytes, or signed serialized
PQ transaction fixtures. Treat the matrix as partial coverage, not a complete cross-platform
determinism gate.

Required follow-up:

- Add pinned digest fixtures for ML-KEM, ML-DSA, address-v2, wallet PQ-section, and representative
  serialized PQ deposit/spend transactions.
- Run those fixtures across the same little-endian, 32-bit, and big-endian CI targets.
- Update the matrix status from "COMPLETE" to "Raptor keygen complete; full PQ artifact matrix open"
  until those fixtures exist.

### M-new-5: PQ deposit outputs do not serialize a DSA scheme ID, so deposit agility is height/tag-based only

**Affected files:** `include/CryptoNote.h`, `src/CryptoNoteCore/CryptoNoteSerialization.cpp`,
`src/CryptoNoteConfig.h`

`PQ_DSA_SCHEME_ID = 0xC0DE0204` exists and `PqAccountKeys` stores `dsaSchemeId`, but the serialized
on-chain deposit cell does not carry that scheme ID. `PqMultisigOutput` contains only `keys`,
`requiredSignatureCount`, and `term`; `PqMultisigInput` contains only `amount`, `signatureCount`,
`outputIndex`, `term`, and `signatures`. The serializer mirrors that field set, with no DSA scheme
field.

This does not make current deposits invalid: validators check key/signature lengths and route
`PqMultisigInput` through the current `ccx_pq_multisig_verify` implementation. It does mean the DSA
agility story is not per-output/per-input pinned. If ML-DSA is swapped, old and new deposit cells must
be distinguished by transaction version, block height, variant tag, or a new serialized field; otherwise
future code has to infer the verifier from context.

Verification evidence:

```text
PqAddress.*:PqAccountKeygen.*:PqWalletSection.*
Result: 20 passed.
PqDepositPrimitive.*
Result: 2 passed.
```

Required follow-up:

- Decide whether deposit cells need an on-chain `dsaSchemeId` before public persistence.
- If keeping height/tag-based agility, document the exact future fork rule for spending old deposits
  after a DSA replacement.
- Do not describe `PQ_DSA_SCHEME_ID` as an on-chain agility pin until it is serialized or a height rule
  is specified.

### L-new-1: 0x07 authenticated-message v2 changes the same tag without an explicit sub-version

**Affected file:** `src/CryptoNoteCore/TransactionExtra.cpp`

New encryption emits `data = nonce24 || ciphertext || tag`, and decrypt requires at least 40 bytes
(`TransactionExtra.cpp:850`). The parser and append helper still accept the old minimum of 16 bytes
(`TransactionExtra.cpp:171-181`, `413-418`), so an old v1 0x07 field remains parse-valid but is no
longer decryptable by the current v2 decrypt path.

This is not a consensus split because tx-extra messages are non-consensus, and testnet may be reset.
It is still a migration/UX risk if any existing 0x07 messages are expected to remain decryptable.

Required follow-up:

- If old 0x07 history matters, add a version byte or legacy fallback decrypt.
- If old 0x07 history is intentionally abandoned, document that explicitly and tighten parser/append
  minimums to `TX_EXTRA_AUTH_MESSAGE_NONCE_SIZE + TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE`.

### L-new-2: The Raptor verify fuzz target usually returns before reaching verification

**Affected file:** `pqc/ccx-pqc/fuzz/fuzz_targets/verify.rs`

The `verify` fuzz target derives `ring_count = ring_blob.len() / 896` and returns when the random input
does not contain at least one full encoded public key. That means most mutated inputs below 896 bytes
never call `ccx_pq_verify`, so the target is poor at exercising malformed rings, member-stride handling,
signature unpacking, and error paths.

Build note:

```text
Local macOS: cargo-fuzz not installed.
WSL 100.100.90.103: ~/.cargo/bin/cargo +nightly fuzz build
Result: fuzz targets built successfully.
```

The CI workflow installs `cargo-fuzz`, so this is not evidence that CI fails; it is a harness-coverage
gap. Seed corpora with at least one valid-length ring blob, or synthesize a fixed-size malformed ring
from fuzz bytes so every iteration reaches the verifier.

No C++ libFuzzer/AFL harness was found under `tests/` or `src/` for transaction-extra/wire parser
coverage. The Rust FFI smoke fuzzing is useful, but it does not satisfy the whole brief's parser
robustness target for the C++ transaction-extra decoder.

### L-new-3: Raptor scheme-ID documentation is stale in several design docs

**Affected files:** `docs/design/quantum-resistance/STATUS.md`,
`docs/design/quantum-resistance/wallet-address-v2.md`, generated `site/` HTML copies.

Current code pins the ring scheme as `"RAPT"` / `0x52415054` in both `pqc/ccx-pqc/src/raptor_abi.rs`
and `src/CryptoNoteConfig.h`. Some design docs still describe older IDs (`0xC0DE0003` or
`0xC0DE0004`). This is not a consensus bug because the parser compares runtime constants, but it is
dangerous audit/operator documentation drift.

Raptor verification run:

```text
cargo test --offline raptor:: -- --nocapture
Result: 3 passed, 0 failed.
```

Required follow-up:

- Regenerate or edit stale design docs so every user-facing/current-status page says `0x52415054`
  `"RAPT"`.
- If the ring-bound challenge hash remains under the same `"RAPT"` ID, document that existing pre-fix
  `"RAPT"` testnet signatures are invalid and require a clean reset; otherwise assign a sub-version or
  new scheme ID before producing durable network artifacts.

### L-new-4: ML-DSA/FIPS wording should be qualified to avoid implying a validated verifier stack

**Affected files:** `pqc/ccx-pqc/src/lib.rs`,
`docs/design/quantum-resistance/deposits-mldsa-impl.md`, `docs/design/quantum-resistance/STATUS.md`

The deterministic wallet keygen path uses exact-pinned RustCrypto `ml-kem = 0.3.2` and
`ml-dsa = 0.1.1` for FIPS seed-based key generation, then proves interop with the pqcrypto path.
However, deposit signing and verification still call `pqcrypto_dilithium::dilithium3` from
`pqcrypto-dilithium = 0.5`. The implementation may be Dilithium3/ML-DSA-65-compatible, but the docs
and comments should not read as a FIPS-validated verifier claim unless the exact crate/version and
validation status are established.

Required follow-up:

- Phrase the current deposit primitive as "Dilithium3 / ML-DSA-65-compatible via pqcrypto" unless a
  FIPS 204 conformance/validation artifact is provided.
- Keep the RustCrypto deterministic keygen claim separate from the pqcrypto sign/verify claim.
- Track the planned RustCrypto PQ crates upgrade/conformance work as a mainnet evidence item.

## Current Go / No-Go Delta

Public testnet can continue as an experimental network after a clean reset or explicit incompatibility
notice for the Raptor transcript and 0x07 message changes.

Mainnet remains no-go. The old concrete Raptor programmed-key break is fixed in code, but the required
research deliverables are still incomplete: reviewed reduction, response-bound derivation, concrete
lattice estimate with raw artifacts, signer/decoy classifier, and real side-channel campaign.
