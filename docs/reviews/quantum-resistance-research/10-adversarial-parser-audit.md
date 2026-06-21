# Adversarial Parser Audit Follow-Up

Date: 2026-06-22
Scope: C++ PQ transaction-extra and transaction serialization parser surfaces.

## Verification Added

New test file:

- `tests/UnitTests/TestPqAdversarialParser.cpp`

WSL verification:

```text
./build/tests/unit_tests --gtest_filter="PqAdversarialParser.*"
Result: 11 passed.

./build/tests/unit_tests --gtest_filter="PqAdversarialParser.*:TransactionSerializationGolden.*:TransactionExtraGolden.*:AuthenticatedMessage.*:PqAddress.*:PqAccountKeygen.*:PqWalletSection.*:PqDepositPrimitive.*:PqDepositSerialization.*"
Result: 70 passed.
```

## New Findings

### M-new-6: PQ multisig deserialization still materializes oversized inner PQ blobs before semantic size checks

**Affected files:**

- `src/CryptoNoteCore/CryptoNoteSerialization.cpp`
- `src/Serialization/SerializationOverloads.h`
- `src/Serialization/BinaryInputStreamSerializer.cpp`
- `src/CryptoNoteCore/CryptoNoteFormatUtils.cpp`
- `src/CryptoNoteCore/TransactionPool.cpp`

Current remediation now rejects oversized `PqKeyInput.nullifier`, `PqKeyOutput.key`, and
`PqKeyOutput.kemCt` at parse time, and the generic string reader no longer allocates the full declared
length before a short read fails. The remaining exposed PQ transaction fields still deserialize
attacker-controlled complete byte blobs through the generic `serializeAsBinary(std::vector<T>&)` helper
before semantic size validation:

- `PqKeyInput.ringSig`
- `PqMultisigInput.signatures[]`
- `PqMultisigOutput.keys[]`

The generic helper reads a length-prefixed string, materializes it, then copies it into the target
vector. `BinaryInputStreamSerializer` still allows complete strings up to 128 MiB before throwing.
The PQ-specific checks are incomplete:

- `PqKeyInput.ringSig` is capped at 1 MiB, but only after `serializeAsBinary` has already materialized
  and copied the declared blob. The adversarial test confirms the over-cap value rejects; the control is
  post-read rather than pre-materialization.
- `serializePqMultisigArray` caps the outer item count at `PQ_MULTISIG_MAX_KEYS`, but each inner
  signature/key still reaches the same generic binary-vector reader. The adversarial tests demonstrate
  1 MiB inner multisig signature/key blobs parse successfully into the object.

Reachability matters because `parse_tx_from_blob` calls
`parseAndValidateTransactionFromBinaryArray`, which calls `fromBinaryArray` before mempool
transaction-size validation. Mempool `checkTransactionSize(blobSize)` happens later, after input
validation starts. Therefore parse-time allocation is part of the exposed transaction ingestion path,
not merely an internal object construction detail.

Executable evidence:

```text
PqAdversarialParser.PqKeyInputOversizedNullifierRejectsAtParseBound
PqAdversarialParser.PqKeyOutputOversizedKeyAndKemRejectAtParseBound
PqAdversarialParser.PqMultisigInputOversizedSignatureStillParses
PqAdversarialParser.PqMultisigOutputOversizedKeyStillParses
PqAdversarialParser.PqKeyInputRingSigOverOneMiBCapRejects
```

The first two tests confirm the current partial remediation for fixed-size key-input/key-output fields.
The multisig tests show oversized inner PQ blobs are still accepted into memory. The final test confirms
the `ringSig` cap rejects over-limit blobs, but only after the blob has already been parsed.

Impact:

This is a residual resource-exhaustion hardening issue, not a consensus acceptance bug. Later validation
still rejects malformed PQ signatures and multisig keys. However, an attacker who can submit large
transaction blobs can force avoidable heap allocation/copying on remaining PQ fields before those
semantic checks run. The practical impact depends on outer P2P/RPC message limits, but the serializer
should not rely on downstream validation for fixed-size or tightly bounded PQ wire objects.

Required follow-up:

- For `PqKeyInput.ringSig`, read the declared length first and reject over the current cap before
  materializing the blob.
- For `PqMultisigInput.signatures[]` and `PqMultisigOutput.keys[]`, keep the outer count guard and add
  per-element parse-time caps or exact lengths before materializing each blob.
- Keep the fixed-size key-input/key-output rejection tests. After fixing multisig, invert the multisig
  oversized tests so they expect rejection.

### M-new-7: PQ key-input ring array is materialized before PQ ring-size limits are enforced

**Affected files:**

- `src/CryptoNoteCore/CryptoNoteSerialization.cpp`
- `src/Serialization/BinaryInputStreamSerializer.cpp`
- `src/Blockchain/BlockchainPq.cpp`

`PqKeyInput.outputIndexes` is read by `serializeVarintVector`. That helper trusts the serialized array
length, calls `vector.resize(size)`, then reads every element. The binary input serializer only applies
the generic 128 MiB array-count cap. PQ consensus later rejects ring sizes outside
`[PQ_MIN_RING_SIZE, PQ_MAX_RING_SIZE]` in `Blockchain::check_pq_tx_input`, but that check happens after
the oversized vector has already been materialized by transaction parsing.

Executable evidence:

```text
PqAdversarialParser.PqKeyInputOversizedRingIndexVectorStillParses
```

The test builds a `PqKeyInput` with 1,048,576 encoded ring indexes. `fromBinaryArray` succeeds and the
resulting `PqKeyInput.outputIndexes.size()` is 1,048,576, even though such a ring is far beyond
`PQ_MAX_RING_SIZE` and would be rejected later by consensus validation.

Impact:

This is a parser resource-exhaustion hardening issue, not a consensus acceptance bug. The current
validator prevents an oversized PQ ring from being accepted, but an attacker can still force parse-time
allocation and element decoding for an impossible ring before the validator reaches the small PQ ring
limit.

Required follow-up:

- Replace the generic `serializeVarintVector` path for `PqKeyInput.outputIndexes` with a PQ-specific
  bounded reader that rejects serialized counts over `PQ_MAX_RING_SIZE` before resizing.
- Keep a regression test for the current 1,048,576-entry vector case and invert it after the fix so it
  expects parse rejection.

### M-new-8: PQ multisig outputs accept malformed deposit public keys into validated output state

**Affected files:**

- `src/CryptoNoteCore/CryptoNoteFormatUtils.cpp`
- `src/Blockchain/CheckTxOutputsVisitor.h`
- `src/Blockchain/BlockchainPq.cpp`

`check_outs_valid` validates `PqMultisigOutput` version, required-signature count, and max key count,
but does not validate each multisig public key length. The block-connect output visitor has the same gap:
it applies the term/amount rules, threshold checks, and max key count, but does not reject a wrong-size
ML-DSA public key. Spend-side validation later checks `output.keys[outputKeyIndex].size() !=
ccx_pq_multisig_pubkey_bytes()` before FFI verification, and its comment says the key was already
length-checked in `check_outs_valid`; that earlier check is absent.

Executable evidence:

```text
PqAdversarialParser.PqMultisigOutputWrongKeyLengthPassesCheckOutsValid
```

The test constructs a v4 transaction output containing a `PqMultisigOutput` with one one-byte key,
`requiredSignatureCount = 1`, and `term = 0`. `check_outs_valid` returns true.

Impact:

This is not a signature-forgery bug because `check_pq_multisig` rejects wrong-size keys before calling
the FFI. The bug is that malformed PQ deposit cells can pass output validation and be indexed as PQ
multisig outputs, only becoming unspendable later. That creates invalid PQ state, burns funds sent to the
malformed cell, and gives an attacker a way to pollute the PQ multisig output index with unspendable
entries at normal transaction cost.

Required follow-up:

- In both `check_outs_valid` and `CheckTxOutputsVisitor::operator()(const PqMultisigOutput&)`, require
  every `out.keys[i].size() == ccx_pq_multisig_pubkey_bytes()` before accepting the output.
- Add or invert the regression so `PqMultisigOutputWrongKeyLengthPassesCheckOutsValid` expects rejection
  after the fix.

## Clean Results From This Pass

- Unknown adjacent PQ variant tags (`0x0a`) reject for both transaction inputs and output targets.
- `PqMultisigOutput` array count over `PQ_MULTISIG_MAX_KEYS` rejects before inner blobs are read.
- Truncated 0x06 PQ tx-extra rejects and does not leave partially parsed fields.
- Existing serialization golden, tx-extra, authenticated-message, PQ address, PQ keygen, and wallet-section
  tests remained green in the targeted 70-test slice.
