# Quantum-Resistance Research Security Audit

Date: 2026-06-21  
Branch: `pqc/mdbx-merge-poc`  
Reviewed commit: `1d5cda1483c70f51b081c9513b9497ec602ddb16`  
Audit brief: `docs/design/quantum-resistance/security-audit-brief.md`

## Current worktree addendum

Claude's remediation pass has changed the worktree after the reviewed commit. I rechecked the current
HEAD `411c848f7276ae5099b7e5c7e0fd01977f6ae243` plus dirty remediation files and recorded the delta in
`docs/reviews/quantum-resistance-research/09-post-remediation-delta-audit.md`.

Current delta:

- The old adaptive Raptor programmed-key forgery path is rejected after binding ring public keys into
  the challenge hash.
- The malformed `PqKeyOutput` indexing issue is remediated in the current worktree.
- Targeted Rust and WSL C++ PQ tests pass.
- Mainnet remains no-go because the Raptor proof, B1/concrete-security artifacts, signer/decoy
  statistics, and side-channel campaign are still not complete.
- New residual issues were found in the remediation deliverables: ignored dudect-style tests use an
  over-permissive `|t| < 500` threshold, the new proof document is not a completed reduction, the B1
  document is internally inconsistent about estimator status, and 0x07 v2 lacks an explicit sub-version
  or legacy-decrypt path.

## Scope and assurance

This report covers the Raptor/Falcon construction, standardized PQ schemes, wallet cryptography,
C/Rust FFI, transaction serialization, consensus validation, mempool conflict handling, activation,
and migration logic requested by the audit brief.

This is a code/specification audit with differential tests. It is not a peer-reviewed cryptanalytic
proof, a complete side-channel laboratory evaluation, or a production mainnet certification.

Primary specifications:

- Raptor paper: <https://eprint.iacr.org/2018/857.pdf>
- FIPS 203, ML-KEM: <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf>
- FIPS 204, ML-DSA: <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf>
- Falcon implementation paper: <https://falcon-sign.info/falcon-impl-20190918.pdf>

## Executive verdict

**Public testnet: conditional go.** It may continue as an explicitly experimental network after the
three implementation findings marked testnet-blocking are fixed. Testnet documentation must not call
the deposit signature path FIPS 204 or describe Raptor as proven secure.

**Mainnet: no-go.** Raptor's proof obligations, acceptance bound, decoy distribution, and concrete
security estimate are unresolved. The active deposit verifier is not FIPS 204 ML-DSA. Secret-key
side-channel claims have not been validated dynamically on the reviewed platform.

Severity count:

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 3 |
| Medium | 4 |
| Low | 2 |

## Findings

### H-1: Raptor's published security argument does not transfer to this instantiation

**Severity:** High  
**Affected properties:** unforgeability proof, anonymity proof, acceptance soundness  
**Mainnet blocker:** Yes  
**Testnet blocker:** No, if the network remains explicitly experimental

Three material proof obligations are unresolved.

1. **The published generic proof does not exactly cover the full instantiation.** The implementation
   computes the ring challenge from the message and reconstructed `c_i` values
   (`pqc/ccx-pqc/src/raptor.rs:241-254`) and binds the ring through the OTS target
   (`raptor.rs:264-291`). That matches the paper's full construction in Section 5.4. However, the
   generic construction and proof in Sections 3.3-4.2 include the public-key list directly in the
   challenge oracle. No reduction is supplied for moving that binding into the OTS composition.
2. **The ring norm bound was copied from Falcon.** Both signing and verification accept a pair when
   `||r0||^2 + ||r1||^2 <= 34,034,726` (`raptor.rs:51`, `raptor.rs:367-371`,
   `raptor.rs:521-529`). The reviewed paper specifies membership in its response distribution but
   does not define the audit brief's named `B1` or formula. No derivation maps the implementation's
   joint Falcon bound to the exact R-SIS/R-ISIS bound or an honest-rejection target.
3. **The non-signer distribution is changed.** The paper samples independent response pairs from its
   stated discrete Gaussian. The implementation samples preimages under one fresh throwaway Falcon
   trapdoor shared by every decoy in a signature (`raptor.rs:294-365`, `raptor.rs:412-421`). GPV/Falcon
   sampling may be statistically trapdoor-independent above the smoothing parameter, but this repo
   contains neither a theorem for the exact sampler and parameters nor the claimed `stats` harness.
   Reusing one hidden lattice also creates a conditional common-key structure across all decoys.

No practical forgery or signer classifier was found in this audit. The finding is that the claimed
proof and security level are unestablished, not that a break has been demonstrated.

**Required remediation**

- Freeze a complete mathematical specification of the exact implemented transcript and distributions.
- Produce a reduction covering the OTS composition and public-key-list binding.
- Derive a concrete verifier bound for the exact response distribution, R-SIS/R-ISIS reduction,
  target failure probability, and ring-size range.
- Prove or replace the shared-throwaway-key decoy sampler. At minimum, publish a high-powered,
  independently reviewed classifier test comparing signer and decoy blocks across keys and rings.
- Obtain independent cryptanalysis before mainnet.

**Reproducer / inspection**

```text
Implementation ring hash:
  domain || len(message) || message || c_1 || ... || c_L

Implementation response check:
  sqnorm(r0) + sqnorm(r1) <= 34,034,726

Paper verifier:
  checks each response belongs to D x D x Db, without a concrete verifier bound
```

### H-2: The consensus deposit signature path is pre-standard Dilithium3, not FIPS 204 ML-DSA-65

**Severity:** High  
**Affected properties:** standards compliance, interoperability, migration safety  
**Mainnet blocker:** Yes  
**Testnet blocker:** Yes, unless renamed and explicitly version-pinned as experimental Dilithium3

The active signing and verification ABI calls `pqcrypto_dilithium::dilithium3`
(`pqc/ccx-pqc/src/lib.rs:663-752`). The pinned PQClean code computes
`mu = CRH(tr || message)` directly. FIPS 204 pure ML-DSA first constructs
`M' = 0x00 || len(ctx) || ctx || M`; with empty context, the two leading zero bytes are still present.

An independent differential program generated FIPS 204 keys and checked signatures in both
directions:

```text
old_dilithium_signature_verifies_as_fips204=false
fips204_signature_verifies_as_old_dilithium=false
```

The equal public/secret/signature byte sizes and deterministic-keygen roundtrip therefore do not
prove algorithm-level FIPS 204 interoperability. The comments at `lib.rs:663-680` and
`detkeygen.rs:18-24` overclaim compliance.

Changing the verifier in place would invalidate existing deposits. Remediation requires a new
height/transaction/scheme version and explicit legacy verification for already-created outputs.

**Reproducer**

The audit used an out-of-tree Rust program with:

```text
ml-dsa = 0.1.1
pqcrypto-dilithium = 0.5.0
```

It generated an `MlDsa65` key from a fixed seed, imported the same encoded key into Dilithium3,
signed the same message with each implementation, and cross-verified both signatures. Both
cross-verifications failed.

### H-3: Committed consensus accepts malformed PQ output keys into the global ring index

**Severity:** High  
**Affected properties:** output-index integrity, spendability, wallet/ring liveness  
**Mainnet blocker:** Yes  
**Testnet blocker:** Yes  
**Status:** A remediation is present but uncommitted in the reviewed worktree

At the reviewed commit, `CheckTxOutputsVisitor::operator(PqKeyOutput)` accepts every non-empty key
(`src/Blockchain/CheckTxOutputsVisitor.h` at HEAD, lines 141-153). The generic precheck repeats only
that test (`src/CryptoNoteCore/CryptoNoteFormatUtils.cpp:424-435`). The output is then indexed as a
ring member, but spending rejects it later when its length is not the expected Raptor public-key size
(`src/Blockchain/BlockchainPq.cpp:127-140`).

An attacker can create consensus-valid, permanently unspendable entries in an amount bucket. These
entries shift global indices and can make wallets select unusable decoys. This is not direct
inflation, but it is consensus-index poisoning and a PQ spend-liveness attack.

The dirty worktree adds exact length, canonical encoding, and optional KEM-ciphertext length checks
using `ccx_pq_pubkey_is_canonical`. That direction is correct, but it was not part of the reviewed
commit and needs tests plus commit review.

**Reproducer**

Construct a v4 transaction with a nonzero `PqKeyOutput.amount`, `key = {0x01}`, and empty `kemCt`.
At HEAD, `check_tx_outputs` accepts it and block connection indexes it. Any later ring spend that
references that index fails because the member key is not 896 bytes.

### M-1: Tiny malformed transaction blobs can trigger a 128 MiB allocation before validation

**Severity:** Medium  
**Affected properties:** remote daemon availability, parser robustness  
**Mainnet blocker:** Yes  
**Testnet blocker:** Yes

PQ key, KEM ciphertext, ring signature, nullifier, ML-DSA key, and ML-DSA signature fields are
serialized through `serializeAsBinary` (`src/CryptoNoteCore/CryptoNoteSerialization.cpp:386-430`).
The generic input serializer reads an attacker-controlled varint, allocates that many bytes, and only
then discovers that the stream is truncated (`src/Serialization/BinaryInputStreamSerializer.cpp:94-105`).
Its ceiling is 128 MiB.

The outer PQ multisig element count is bounded before resize, but each inner opaque field retains the
128 MiB limit. A short network blob can therefore request a 128 MiB temporary allocation before exact
cryptographic lengths are checked.

**Reproducer**

Place a canonical varint encoding of `134217728` as the length of a PQ binary field, followed by no
payload. Deserialization executes `temp.resize(134217728)` before `checkedRead` reports EOF.

**Required remediation**

- Add field-specific maximum lengths before allocation.
- For fixed-size key/ciphertext/nullifier/signature fields, read exactly the expected length.
- For variable Raptor signatures, derive the cap from ring size via `ccx_pq_sig_max_bytes`.
- Add allocation-failure and truncated-input fuzz cases.

### M-2: Mempool and block-template conflict tracking omits PQ deposit cells

**Severity:** Medium  
**Affected properties:** miner work, mempool consistency, network nuisance resistance  
**Mainnet blocker:** Yes  
**Testnet blocker:** Yes  
**Status:** Remediation is in progress outside this audit; the finding is against the reviewed commit

Chain validation correctly rejects a used PQ deposit cell (`src/Blockchain/BlockchainPq.cpp:179-209`)
and marks a successful spend used (`src/Blockchain/BlockchainStorage.cpp:884-895`). Intra-transaction
duplicates are also rejected.

The mempool and `BlockTemplate` handle classical key images, classical multisig cells, and PQ
nullifiers, but never `PqMultisigInput` (`src/CryptoNoteCore/TransactionPool.cpp:45-103`,
`TransactionPool.cpp:703-855`).

Two unconfirmed withdrawals of the same `(amount, outputIndex)` can coexist and enter one candidate
block. The second fails only during sequential block validation after the first marks the cell used.
There is no inflation, but miners can build invalid templates and waste work.

**Required remediation**

Track PQ deposit cells in `BlockTemplate::addTransaction/canAdd` and in
`addTransactionInputs`, `removeTransactionInputs`, and `haveSpentInputs`.

### M-3: Falcon secret-key operations do not meet a strict constant-time claim

**Severity:** Medium  
**Affected properties:** wallet secrets against a local timing/cache attacker  
**Mainnet blocker:** Yes, pending an explicit threat/risk decision

The vendored key generation contains documented non-constant-time rejection and conversion paths
(`pqc/ccx-pqc/vendor/falcon/keygen.c:2046-2069`, `keygen.c:3161-3201`). Raptor re-derives two Falcon
trapdoors from the output secret seed and creates a throwaway key for decoys.

The Falcon sampler performs variable-iteration rejection and a lazy byte comparison in `BerExp`
(`vendor/falcon/sign.c:1016-1070`, `sign.c:1107-1162`). Its design aims to decorrelate rejection rate
from secret center and standard deviation; that supports an isochronous/statistical timing argument,
not a fixed-control-flow proof.

The reviewed macOS host has no Valgrind headers/runtime. The same source snapshot was therefore run
on an authorized Ubuntu 24.04 WSL2 host with Valgrind 3.22. The feature-gated harness passed its
existing CI policy ("no new secret-dependent branch in `raptor_falcon.c`"), but Valgrind reported
65,271 errors from 93 secret-dependent contexts in the deliberately poisoned end-to-end keygen/sign
path. Those contexts include the documented Falcon internals and are excluded by the current CI
allowlist. No dudect harness was found. The result verifies the glue tripwire; it does not bless the
whole secret-key path.

For software wallets, require repeatable ctgrind plus dudect results on supported Linux targets and
document the accepted leakage model. Hardware-wallet/HSM support requires a separate masked design;
the current code is not suitable for power/EM/DPA claims.

The ML-KEM FO ciphertext comparison itself is branchless in the pinned clean implementation, using
an accumulator comparison and conditional move.

### M-4: The ML-DSA scheme ID is dead wallet metadata, not an on-chain agility pin

**Severity:** Medium  
**Affected properties:** crypto agility, safe migration  
**Mainnet blocker:** Yes

`PQ_DSA_SCHEME_ID` is assigned to `PqAccountKeys.dsaSchemeId`
(`src/Wallet/PqAccount.cpp:55-63`), but it is not serialized in `PqAccountPublicAddress`,
`PqMultisigOutput`, or `PqMultisigInput`. Consensus hardcodes one verifier. The KEM and ring IDs are
serialized in the PQ address, but the deposit scheme ID is not
(`src/CryptoNoteCore/CryptoNoteSerialization.cpp:463-473`).

The current constant therefore does not permit per-artifact dispatch or identify whether a deposit
uses pre-standard Dilithium3 or FIPS 204 ML-DSA. Migration must be height/transaction-version based,
or the output format must carry and validate a scheme ID.

### L-1: ML-KEM operations interoperate with FIPS 203, but the pinned backend is not fully final-FIPS

**Severity:** Low  
**Affected properties:** standards claims, malformed public-key handling

Positive differential result:

```text
fips203_ciphertext_decapsulates_to_same_old_kyber_secret=true
```

The pinned Kyber backend implements the final-style FO ciphertext re-encryption check and constant-time
fallback selection. Wallet deterministic key generation uses RustCrypto `ml-kem` and is byte-compatible
with the active encapsulation/decapsulation path.

However:

- The backend's randomized keygen hashes 32 random bytes without the final ML-KEM parameter-set domain
  byte (`pqcrypto-kyber-0.8.1/.../kyber768/clean/indcpa.c:201-212`).
- Its Rust `from_bytes` checks only object length, not FIPS encapsulation-key validity.

Honest deterministic wallet keys are unaffected. Random test/injector key generation and claims of
complete FIPS 203 conformance should be corrected or migrated to the final implementation.

### L-2: `paramch_h` is deterministic but lacks a frozen external derivation specification

**Severity:** Low  
**Affected properties:** parameter transparency, reproducibility

`paramch_h` is generated by domain-separated SHAKE/hash-to-ring code, which is preferable to an
opaque constant. The exact domains and rejection mapping are not, however, frozen in an external
versioned specification with a published test vector. Mainnet should publish the derivation input,
mapping, expected polynomial digest, and change-control rule. A multi-party ceremony is optional for
a deterministic nothing-up-my-sleeve string; transparent reproducibility is mandatory.

## Raptor verdict

| Property | Verdict |
|---|---|
| Correctness | Functional sign/verify tests pass; algebraic relation is rechecked at the FFI boundary. |
| Unforgeability | **Unproven for this instantiation.** No forgery found, but the paper's reduction cannot be imported unchanged. |
| Anonymity | **Unproven.** No classifier found, but shared-trapdoor decoys lack an exact distribution bound and the claimed statistics harness is absent. |
| Linkability | **Plausible under stated assumptions.** The nullifier canonically hashes `aots`; the OTS binds `aots`, member responses, and ring. A second nullifier for the same secret would require changing the bound `aots` or a SHAKE collision. |
| False-link resistance | **Plausible.** Distinct `aots` values collide only through the 256-bit nullifier hash, subject to key-generation uniqueness. |
| Response bound | **Not established.** `34,034,726` is Falcon's joint squared-norm bound, not a bound derived for the Raptor reduction and honest-response distribution. |
| Concrete security | **No defensible current number.** The paper's 2018 Raptor-512 estimate was 114 classical / 103 quantum bits under its then-current model. This audit does not endorse those numbers for the modified implementation. |

A generic lattice-estimator invocation would not resolve the construction-level attack model,
transcript, and distribution gaps. Reporting a fresh bit number without specifying the exact SIS/NTRU
instance and reduction loss would be false precision.

## Standard-scheme and wallet verdict

| Surface | Verdict |
|---|---|
| ML-KEM-768 stealth/messages | Operationally interoperable with FIPS 203 keys/ciphertexts; FO compare is constant-time at source. Full final-FIPS input/keygen semantics are not universal. |
| Deposit signatures | Not FIPS 204; active path is incompatible pre-standard Dilithium3. |
| Deterministic restore | Deterministic RustCrypto key generation and byte-level interop tests are useful. The ML-DSA selftest proves compatibility with the old verifier, not FIPS signature compatibility. |
| Message AEAD | Key and 96-bit nonce are jointly derived from a fresh KEM secret plus message index under a dedicated SHAKE domain. No nonce-reuse path found for honest fresh encapsulations. |
| Wallet at rest | Argon2id defaults to 64 MiB, three passes, one lane; per-wallet salt and per-save XChaCha nonce use `OsRng`. Header cost bounds prevent trivial hostile-header KDF DoS. |
| Prefix MAC | Fixed-domain keyed SHAKE with a derived subkey is structurally sound as a sponge-prefix MAC. It is bespoke, not NIST KMAC; using KMAC or a standard keyed hash would reduce assurance burden. |
| Masking | Not required for the stated software-wallet threat model. Required before hardware-wallet/HSM power/EM claims. |

## Consensus verdict

Clean checks:

- V10 activation rejects PQ deposits below the fork height and freezes new classical deposits at the
  same height using the correct `<` / `>=` boundary.
- Coinbase receives the equivalent activation/freeze checks.
- Duplicate PQ nullifiers and duplicate PQ deposit cells are rejected within one transaction.
- Chain state tracks spent nullifiers and used PQ deposit cells, with rollback/rebuild support.
- The recovered ring-signature nullifier must equal the declared input nullifier.
- A PQ deposit input's term must equal the referenced output term before lock and interest handling.
- V4 input/output sums have overflow checks and output value cannot exceed input value.
- Raptor signature decoding rejects noncanonical varints, noncanonical `aots`, and trailing bytes.
- FFI entry points inspected are panic-guarded and return rejection codes to C++.

Residual consensus conditions:

- The malformed-output, parser-allocation, and mempool/template findings must be fixed.
- PQ cryptographic verification is skipped in checkpoint zones like classical verification. No
  checkpoint may cover an activated V10+ region unless those transactions were independently trusted.
- Mainnet migration must explicitly version the Dilithium3-to-ML-DSA change and preserve spendability
  of old deposit outputs.

## Go/no-go gates

### Public testnet

**Conditional go after:**

1. Commit and test canonical `PqKeyOutput` and KEM-ciphertext admission.
2. Add field-specific parser caps before allocation.
3. Add PQ deposit-cell conflict tracking to mempool and block templates.
4. Rename/document the active deposit scheme as pre-standard Dilithium3, or introduce a new versioned
   FIPS 204 path.
5. Keep Raptor and side-channel status explicitly experimental.

### Mainnet

**No-go until all testnet conditions plus:**

1. Independent Raptor proof/cryptanalysis covers the exact transcript, OTS composition, decoy
   distribution, linkability, and ring-size range.
2. The verifier response bound is derived and tested from that specification.
3. A current, reproducible concrete-security analysis is published for the exact construction.
4. Deposit signatures use a versioned FIPS 204 implementation with independent KAT/differential tests.
5. ctgrind and dudect results cover Falcon/Raptor, ML-KEM decapsulation, ML-DSA signing, and FFI glue
   on supported production targets.
6. Scheme migration and checkpoint policy are documented and tested through fork/reorg scenarios.
7. Fuzzing covers transaction wire fields, Raptor packing, all PQ FFI lengths, and allocation limits.

## Verification performed

- Manual source/specification comparison of all surfaces named in the brief.
- Independent ML-DSA/ML-KEM differential test:
  - old Dilithium signatures fail FIPS 204 verification;
  - FIPS 204 signatures fail old Dilithium verification;
  - FIPS 203 ML-KEM ciphertext decapsulates to the same secret through the pinned Kyber backend.
- Rust crate unit tests on macOS and Ubuntu WSL2: 12 passed on each host.
- WSL2 ctgrind run of the feature-gated Raptor leak map: one test passed; 93 flagged contexts;
  existing CI allowlist reported no new secret-dependent branch in `raptor_falcon.c`.
- Ubuntu 24.04 WSL2 C++ `UnitTests` target built successfully with GCC 13.3. The focused native
  filter covering PQ consensus, deposits, messages, addresses, serialization, wallet KDF, and wallet
  prefix authentication passed 104/104 tests from 18 suites.
- macOS ARM C++ configure/build attempt, which reached the platform-specific include failure described
  below.
- Static constant-time review of Falcon keygen/sampler and ML-KEM FO compare.
- `git diff --check` and worktree review.

## Limitations

- Valgrind/ctgrind is unavailable on the reviewed macOS ARM host; it was run on Ubuntu WSL2 instead.
- The local macOS ARM C++ build fails on the Linux-only `asm/hwcap.h` include before linking the test
  binary. The equivalent Linux build/test was used to close this host limitation.
- No dudect, cache-attack, power/EM, or masked-hardware evaluation was performed.
- No broad coverage-guided fuzz campaign was run.
- No formal proof or independently reviewed lattice-estimator model was produced.
- Live multi-node fork/reorg and testnet spend tests were not repeated in this local audit.
