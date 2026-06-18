# PQ Messages (ML-KEM-768) — implementation notes (steps 1–3)

Implements the self-contained, low-risk core of `messages-mlkem.md`: a new additive tx-extra field
under **tag `0x06`** that protects Conceal's encrypted on-chain messages with an ML-KEM-768 KEM
instead of the Shor-broken Curve25519 ECDH. The legacy `0x04` path is untouched.

Blueprint steps **1, 2, 3** are done. Step **4** (address format + wallet-format key distribution)
is intentionally **not** done — see "Remaining (step 4)" below.

## What was built

### Step 1 — Rust message-domain KEM (`pqc/ccx-pqc/src/lib.rs`, `pqc/include/pq_ring_sig.h`)

- `ccx_pq_msg_kem_encap(kem_pk, …, ct_out, key_out)` — encapsulate to a 1184-byte ML-KEM-768 public
  key; writes the 1088-byte Kyber ciphertext and a 32-byte secret
  `key = SHAKE256("ccx-msg-kem-v1" || ss)`.
- `ccx_pq_msg_kem_decap(kem_sk, …, ct, key_out)` — decapsulate and re-derive the same 32-byte secret.
- `ccx_pq_msg_kem_selftest()` — encap→decap round-trips to the same secret; a wrong KEM secret yields
  a different secret; the message domain does **not** collide with the stealth domain
  (`"ccx-stealth-otk"`) for the same ciphertext.
- The two functions mirror `ccx_pq_kem_derive_output` / `ccx_pq_kem_scan` exactly but with a distinct
  domain string, so a KEM key reused for both stealth outputs and messages never yields the same
  secret (domain separation lives inside the audited crypto module). The secret is
  **index-independent**; the per-message index is mixed in C++-side.
- Also declared the pre-existing `ccx_pq_kem_keypair` in the header (it was exported from Rust but not
  declared in `pq_ring_sig.h`).

### Step 2 — C++ core (`src/CryptoNoteCore/TransactionExtra.{h,cpp}`)

- `#define TX_EXTRA_PQ_MESSAGE_TAG 0x06` and `TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE 8192`.
- `struct tx_extra_pq_message { std::vector<uint8_t> kemCt; std::string data; encrypt/decrypt/serialize }`
  added to the `TransactionExtraField` boost::variant.
- Parser case for `0x06` (`ar(pqMessage, "pq_message")`) with a **size bound**: rejects the field
  (parser returns `false`, fail-closed) if `kemCt.size() != ccx_pq_kem_ct_bytes()` (1088) or
  `data.size() > TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE`. This is required because the extra parser has no
  `default:` case (blueprint R1/R4) — an unbounded/wrong-length field could mis-frame later fields.
- `ExtraSerializerVisitor::operator()(const tx_extra_pq_message&)` → `append_pq_message_to_extra`.
- `append_pq_message_to_extra` (mirrors `append_message_to_extra`) and
  `get_pq_messages_from_extra(extra, recipientKemSec)` (mirrors `get_messages_from_extra`, but takes
  only the recipient's KEM secret — the KEM ciphertext is self-contained, no tx pubkey needed).
- `encrypt`/`decrypt` reuse the **exact** legacy symmetric construction: chacha8 over
  `msg || 0x00000000`, IV = `LE64(index)`, with the 4-trailing-zero owner-test. Only the 32-byte key
  changes: `h = cn_fast_hash("ccx-msg-v1" || seed32 || LE64(index))` where `seed32` is the KEM secret.
  `cn_fast_hash` is reused (as in the legacy path) to avoid a second XOF impl in C++.

Wire format (matches §4): `0x06 [varint len_kemCt][kemCt 1088][varint len_data][data]`, via
`serializeAsBinary(kemCt)` + `s(data)` (same precedent as `PqKeyOutput::kemCt`).

### Step 3 — send/scan glue (testnet-gated, Option B hardcoded key)

- `tx_message_entry` (`CryptoNoteFormatUtils.h`) gains `bool pq` + `std::vector<uint8_t> kemPub`
  (kept an aggregate; existing brace-init sites value-initialize the new trailing members).
- `constructTransaction` (`CryptoNoteFormatUtils.cpp`): if `msg.pq && !msg.kemPub.empty()`, emit a
  `tx_extra_pq_message` (0x06) and **not** a legacy `0x04` copy (no transcript downgrade, §5).
- `WalletTransactionSender.cpp`: on **testnet** and with env flag **`CCX_PQ_MESSAGES`** set, populate
  `kemPub` from the hardcoded `PQ_TESTNET_KEM_PK` and set `pq=true`. Default **OFF** so legacy testnet
  behavior is unchanged.
- `TransfersConsumer.cpp`: on testnet, additionally scan with `get_pq_messages_from_extra(extra,
  PQ_TESTNET_KEM_SK)` and merge into the legacy result.
- CMake: added `${CCX_PQC_INCLUDE}` to the `Wallet` and `Transfers` libs (they now reference the
  testnet KEM-key header) and to the test include dirs.

## Tests

Rust: `ccx_pq_msg_kem_selftest` (exercised from C++ — `cargo build/test --release` is clean).

C++ (`tests/UnitTests/TestPqMessage.cpp`, auto-globbed into `UnitTests`; run `ctest -R UnitTests`):

- `RustMsgKemSelftestPasses` — FFI selftest ok=1, sizes correct.
- `RoundTripVariousSizesAndIndices` — empty / short / odd / 4 KB / NUL messages × indices
  {0,1,5,123,65535}, each through `writeTransactionExtra`→`parseTransactionExtra`→`decrypt`.
- `WrongIndexFailsDecrypt` — index is bound into the key/IV.
- `WrongRecipientReturnsFalseNoCrash` — different KEM secret → `false`, no crash.
- `MixedExtraParsesAllAndFiltersPqOnly` — `[pubkey, 0x04, 0x06, TTL]` parses all four;
  `get_pq_messages_from_extra` returns only the PQ payload, `get_messages_from_extra` only the legacy.
- `TamperedCiphertextFailsNoFfiPanic` — flipping the trailing checksum byte, or a KEM-ciphertext byte
  (ML-KEM implicit rejection → different secret), makes `decrypt` return `false` with no FFI panic.
  (Flipping a *plaintext* byte is undetected by design — chacha8 has no MAC; see Limitations.)
- `OversizeDataRejectedByParser` / `WrongKemCtLengthRejectedByParser` — the bound rejects both.
- `RawExtraBytesAreCanonicalAndHashStable` — parse→re-serialize reproduces identical bytes and an
  identical `cn_fast_hash`, confirming the tx hash (taken over raw `tx.extra`) is unaffected by 0x06.

Result: 9/9 PqMessage tests pass; full `ctest -R UnitTests` passes (with the repo's baked-in skip
list), no regressions.

## Security notes / limitations (carried from the blueprint)

- **Confidentiality** now rests on ML-KEM-768 (NIST L3, IND-CCA2), not on the on-chain tx pubkey →
  closes the Shor break for messages.
- **Integrity is unchanged** from the legacy scheme: chacha8 + a 4-zero-byte owner-test, **no MAC**.
  Corrupting a message (plaintext) byte is not detected; only the checksum region / KEM ciphertext is.
  A clean future step is an AEAD (ChaCha20-Poly1305) keyed by the KEM secret.
- **Consensus posture:** `tx.extra` is opaque to block validation and carried verbatim, so adding
  `0x06` does not change block acceptance. Emission is gated to testnet (+ env flag). The parser bound
  mitigates R1 mis-framing; for mainnet the `0x06` parser handler should ship to all nodes before any
  wallet emits the tag (quiet client update), or PQ messages should be placed last in `extra`.

## Remaining (step 4 — NOT done, larger consensus/compat surface)

Key distribution so a real recipient (not the hardcoded testnet key) can be addressed:

- **Address format:** publish the recipient's 1184-byte ML-KEM public key — either a new Base58 prefix
  carrying `AccountPublicAddress + kemPub` (Option A) or derive `kemPub` from the wallet seed
  (`SHAKE("ccx-msg-kem-id" || spendSecretKey)`) and expose it on the address (derivation alternative).
- **Wallet format:** persist the KEM keypair (2400 B sk / 1184 B pk) on `AccountKeys`, behind a
  wallet-format version bump (optional field, generate-on-first-load), so `TransfersConsumer` scans
  with the account's own KEM secret instead of `PQ_TESTNET_KEM_SK`.
- **Send glue:** `WalletTransactionSender` should set `tx_message_entry.kemPub` from the parsed PQ
  destination address instead of the env-flag/testnet shortcut; thread a `pq`/`address` field through
  `IWalletLegacy::TransactionMessage` and the RPC/wallet surfaces.

Search markers: `TODO` comments in `WalletTransactionSender.cpp` and `TransfersConsumer.cpp` point at
the testnet shortcuts to replace. This shares `CryptoNoteConfig.h` (new Base58 prefix) and wallet
serialization with other PQ work — coordinate per `REMAINING-WORK.md`.
