# Serializer / tx-extra review response (tier-1)

Response to the three independent reviews (Codex, Gemini, CodeRabbit) of the golden-vector serializer
guard (TASK 1) and the authenticated classical message field 0x07 (TASK 2). Records what was fixed
in-tree and what is deliberately documented-not-fixed, with rationale.

## Fixed in this branch

- **FIX 1 — DoS via huge declared length prefix (Codex HIGH + Gemini CRITICAL).** The 0x06 / 0x07
  parser cases delegated to the generic string / `serializeAsBinary` readers, which resize to the
  declared varint length (capped only at 128 MiB) BEFORE the post-parse size guard ran — a tiny tx
  with a huge length prefix forced a multi-MB allocation. Now `parseTransactionExtra` reads each
  length-prefixed sub-field via a `readBoundedExtraBlob` helper that rejects when the declared length
  exceeds `min(field max, bytes remaining in the stream)` BEFORE allocating. On-wire layout is
  unchanged — only the rejection moved earlier. Tests:
  `AuthenticatedMessage.HugeLengthPrefixRejectedWithoutAllocation_0x07` / `_0x06`,
  `AuthenticatedMessage.LengthPrefixOverFieldMaxButUnderStreamRejected_0x07`.
- **FIX 2 — tautological round-trip goldens (Codex CRITICAL + Gemini MEDIUM + CR minor).** Added
  hardcoded hex goldens for the composite envelope: a full v3 `Transaction`
  (`FullTransactionV3Golden`), the mixed-variant tx (`MixedInputsOutputsTransactionGolden`), and the
  `Block` (`BlockWithMixedBaseTxGolden`), keeping the existing round-trip asserts. The
  `EachFieldTypeRoundTrips` golden suite now also includes the 0x06 and 0x07 tx-extra fields, and a
  focused `PqAndAuthMessageFramingGolden` pins the 0x06/0x07 framing. Goldens were verified to bite by
  temporarily corrupting one byte (confirmed FAIL) then restoring.
- **FIX 3 — 0x07 AEAD domain separation (Codex HIGH + Gemini HIGH/MED).** The 0x07 seed previously
  used the same `message_key_data` magic bytes as legacy 0x04 `(0x80, 0x00)`, so a 0x04 and a 0x07 to
  the same recipient+index derived the same ECDH seed. 0x07 now sets `magic2 = TX_EXTRA_AUTH_MESSAGE_TAG`
  `(0x80, 0x07)`, so the two fields can never share a seed. The 0x04 decrypt path is untouched. Tests:
  `AuthenticatedMessage.DomainSeparatedFromLegacy0x04` (same recipient+index+plaintext -> different
  sealed bytes, no shared keystream prefix) plus the existing tamper / wrong-recipient / bounds tests.

## Documented, deliberately NOT fixed

- **Missing `default:` case in `parseTransactionExtra` (Codex MED + Gemini CRITICAL).** This is the
  LEGACY parser design and affects EVERY tag, not just the PQ additions. The parser's `switch` has no
  `default`, so an unrecognised tag byte simply stops field recognition (the loop continues reading,
  and unknown/foreign tx-extra "fails soft"). Adding a blanket `default: return false` would REJECT
  historical and foreign tx-extra that the network currently accepts — i.e. it would change which
  transactions are valid, a **consensus change** that could fork the chain and invalidate
  checkpoints. It must not be a drive-by fix. The correct long-term remedy is a height-gated,
  length-framed tx-extra container format (every field carries an explicit length, so unknown fields
  are skippable without desync) introduced behind a new `UPGRADE_HEIGHT_*` + block major version.
  Tracked as a future consensus-format task; out of scope for this additive, non-consensus branch.
  Mitigation already in place for the fields we own: every NEW variable-length field (0x06, 0x07) is
  explicitly length-bounded at parse time so it cannot over-read into following fields.

- **Legacy 0x04 still emitted by the wallet send path (Codex HIGH + Gemini HIGH).** `WalletGreen.cpp`
  and `CryptoNoteFormatUtils.cpp` still construct 0x04 messages when sending. Migrating the send path
  to emit 0x07 instead is the WALLET's responsibility (a different agent owns `WalletGreen`); the
  daemon/serialization layer in this branch only adds the 0x07 type + parser/serializer + decrypt and
  freezes 0x04 to decrypt-only at the field level. Cross-cutting wiring follow-up, not a fix in this
  branch. (No consensus impact: tx-extra is not consensus-validated.)

- **0x07 AEAD nonce uniqueness under tx-key reuse.** The AEAD nonce is derived from `(seed, index)`;
  seed uniqueness rests on the protocol's existing per-tx-key uniqueness invariant — identical
  posture to the legacy 0x04 field, which is no worse than the status quo. Recommended FUTURE
  hardening: bind the tx prefix hash as AEAD AAD so a message can never be replayed/relocated into a
  different transaction even under a key-reuse fault. That needs an FFI signature change
  (`ccx_pq_msg_seal/open` would take an AAD pointer+len), so it is out of scope here and noted for the
  ccx-pqc crate owner.
