# PQ Messages (ML-KEM-768) — implementation notes (steps 1–3 + default routing)

Implements the self-contained, low-risk core of `messages-mlkem.md`: a new additive tx-extra field
under **tag `0x06`** that protects Conceal's encrypted on-chain messages with an ML-KEM-768 KEM
instead of the Shor-broken Curve25519 ECDH. The legacy `0x04` path is untouched.

Blueprint steps **1, 2, 3** are done, and the send path now **defaults to `0x06`** for encrypted
messages whenever a recipient KEM pubkey is obtainable (Step 3b below) — replacing the original
opt-in `CCX_PQ_MESSAGES` env flag. The remaining step **4** items (wallet-format KEM-key persistence
+ full per-recipient mainnet key distribution) are still **not** done — see "Remaining (step 4)".

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

**ChaCha20-Poly1305 AEAD (integrity upgrade for 0x06).** Adds the `chacha20poly1305` crate (0.10,
matching the RustCrypto 0.10 generation used by `sha3`) and:

- `ccx_pq_msg_seal(seed32, index, pt, …, ct_out, ct_len_out)` — derive a 32-byte key + 12-byte nonce
  from `(seed32, index)` via one SHAKE256 with domain `"ccx-msg-aead-v1"` (index bound into **both**
  key and nonce → no nonce reuse across indices), then ChaCha20-Poly1305 seal. Writes
  `pt_len + 16` bytes (ciphertext || Poly1305 tag).
- `ccx_pq_msg_open(seed32, index, ct, …, pt_out, pt_len_out)` — same derivation, then AEAD open;
  returns a negative code and writes **nothing** to `pt_out` on authentication failure (no plaintext
  on failure). Null/length guards on all raw pointers; `pt_out` may be null only for an empty
  plaintext.
- `ccx_pq_msg_aead_selftest()` — seal→open round-trip; flipping **any** sealed byte (ciphertext or
  tag) makes open fail; wrong seed fails; wrong index fails.

### Step 2 — C++ core (`src/CryptoNoteCore/TransactionExtra.{h,cpp}`)

- `#define TX_EXTRA_PQ_MESSAGE_TAG 0x06`, `TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE 16`, and
  `TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE 8192` (the latter bounds the AEAD-sealed `data` blob).
- `struct tx_extra_pq_message { std::vector<uint8_t> kemCt; std::string data; encrypt/decrypt/serialize }`
  added to the `TransactionExtraField` boost::variant.
- Parser case for `0x06` (`ar(pqMessage, "pq_message")`) with a **size bound**: rejects the field
  (parser returns `false`, fail-closed) if `kemCt.size() != ccx_pq_kem_ct_bytes()` (1088), or `data`
  is shorter than the 16-byte tag, or `data.size() > TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE`. This is
  required because the extra parser has no `default:` case (blueprint R1/R4) — an unbounded/wrong-
  length field could mis-frame later fields.
- `ExtraSerializerVisitor::operator()(const tx_extra_pq_message&)` → `append_pq_message_to_extra`.
- `append_pq_message_to_extra` (mirrors `append_message_to_extra`) and
  `get_pq_messages_from_extra(extra, recipientKemSec)` (mirrors `get_messages_from_extra`, but takes
  only the recipient's KEM secret — the KEM ciphertext is self-contained, no tx pubkey needed).
- `encrypt`/`decrypt`: the KEM (`ccx_pq_msg_kem_encap`/`decap`) derives a 32-byte seed; that seed +
  the per-message index then key **ChaCha20-Poly1305 AEAD** (`ccx_pq_msg_seal`/`open`). `data` carries
  the sealed blob (`plaintext || 16-byte Poly1305 tag`). This replaces the original chacha8 +
  4-zero-byte owner-test for 0x06 with **real authenticated encryption** — tampering any byte is
  detected. The legacy 0x04 path (chacha8 + checksum, in `tx_extra_message`) is untouched.

Wire format: `0x06 [varint len_kemCt][kemCt 1088][varint len_data][data]`, via
`serializeAsBinary(kemCt)` + `s(data)` (same precedent as `PqKeyOutput::kemCt`), where `data` is the
AEAD-sealed ciphertext (`|msg| + 16`).

### Step 3 — send/scan glue (testnet-gated, Option B hardcoded key)

- `tx_message_entry` (`CryptoNoteFormatUtils.h`) gains `bool pq` + `std::vector<uint8_t> kemPub`
  (kept an aggregate; existing brace-init sites value-initialize the new trailing members).
- `constructTransaction` (`CryptoNoteFormatUtils.cpp`): if `msg.pq && !msg.kemPub.empty()`, emit a
  `tx_extra_pq_message` (0x06) and **not** a legacy `0x04` copy (no transcript downgrade, §5).
- `WalletTransactionSender.cpp`: originally gated behind env flag **`CCX_PQ_MESSAGES`** (testnet
  opt-in). **Superseded by Step 3b** — `0x06` is now the **default** (env flag removed); see Step 3b
  for the current recipient-key resolution.
- `TransfersConsumer.cpp`: on testnet, additionally scan with `get_pq_messages_from_extra(extra,
  PQ_TESTNET_KEM_SK)` and merge into the legacy result.
- CMake: added `${CCX_PQC_INCLUDE}` to the `Wallet` and `Transfers` libs (they now reference the
  testnet KEM-key header) and to the test include dirs.

### Step 3b — 0x06 is now the DEFAULT for encrypted messages (not opt-in)

**Rationale.** Conceal's encrypted on-chain messages are **permanent**: a message written today is
stored on the chain forever. Under the classical authenticated field (`0x07`) the key agreement is
still Curve25519 ECDH — **Shor-breakable** — so `0x07` protects **integrity but not confidentiality**
against a future CRQC. That makes every permanent `0x07` message a **harvest-now-decrypt-later**
target: an adversary records the chain now and decrypts once a CRQC exists. Only the `0x06` ML-KEM
field gives **true post-quantum confidentiality**. So the send path now **defaults to `0x06`**
whenever a recipient ML-KEM public key is obtainable, and only falls back to `0x07` when none is.

**Recipient-KEM-key resolution** (new shared helper `cn::resolveMessageRecipientKemPub(recipientAddress,
testnet, kemPub)` in `CryptoNoteCore/CryptoNoteBasicImpl.{h,cpp}`), per encrypted, non-broadcast
message:

- **(a)** the message's recipient address parses as a PQ/hybrid address
  (`parsePqAccountAddressString` succeeds) → use its `kemPublicKey` (works on **any** network,
  including mainnet);
- **(b)** else on **testnet** (`m_currency.isTestnet()`) → use the fixed `PQ_TESTNET_KEM_PK`
  (Option-B bootstrap), so testnet permanent messages are PQ-encrypted by default;
- **(c)** else (mainnet, no PQ key obtainable for the recipient) → **no** KEM key → the caller falls
  back to the authenticated classical `0x07` field.

For (a)/(b) the send path sets `tx_message_entry.pq = true` + `kemPub = <that key>`, so
`constructTransaction` emits a `tx_extra_pq_message` (`0x06`) and **not** `0x07`/`0x04`.

**Call sites changed:**

- `WalletLegacy/WalletTransactionSender.cpp` (concealwallet / WalletLegacy path): the per-message
  loop calls `resolveMessageRecipientKemPub(message.address, m_testnet, …)` and sets `entry.pq` +
  `entry.kemPub` from the result. **The `CCX_PQ_MESSAGES` env-flag gate is removed** — `0x06` is the
  default, not opt-in. (The legacy `parseAccountAddressString` is still required for `entry.addr` and
  the `0x07` fallback.)
- `Wallet/WalletGreen.cpp::makeTransaction` (walletd / PaymentGate path, which builds `tx.extra`
  directly instead of via `tx_message_entry`): the message loop now first calls
  `resolveMessageRecipientKemPub(messages[i].address, m_currency.isTestnet(), …)`; on success it
  encrypts a `tx_extra_pq_message` and `append_pq_message_to_extra` (`0x06`); otherwise it falls back
  to the existing authenticated `tx_extra_authenticated_message` (`0x07`). The PQ ciphertext is
  self-contained (no tx-pubkey / `AccountPublicAddress` needed), so a PQ-only recipient the legacy
  parser rejects is still served.

**Where `0x07`/`0x04` are still legitimately emitted:** `0x07` for an encrypted message to a
**mainnet legacy recipient** with no obtainable KEM key (case c — integrity-only classical fallback);
`0x04` for an **unencrypted / broadcast** message (no recipient ECDH, so neither `0x06` nor `0x07`
can be produced). The receive path is unchanged and already decodes `0x06`
(`get_pq_messages_from_extra`) + `0x07` + `0x04`. Wire formats and the consensus serializer are
untouched — this is an add-only routing change.

## Tests

Rust: `ccx_pq_msg_kem_selftest` and `ccx_pq_msg_aead_selftest` (exercised from C++ —
`cargo build/test --release` is clean).

C++ (`tests/UnitTests/TestPqMessage.cpp`, auto-globbed into `UnitTests`; run `ctest -R UnitTests`):

- `RustMsgKemSelftestPasses` / `RustAeadSelftestPasses` — both FFI selftests ok=1, sizes correct.
- `RoundTripVariousSizesAndIndices` — empty / short / odd / 4 KB / NUL messages × indices
  {0,1,5,123,65535}, each through `writeTransactionExtra`→`parseTransactionExtra`→`decrypt`
  (asserts `data.size() == |msg| + 16`).
- `WrongIndexFailsDecrypt` — index is bound into the AEAD key + nonce, so a wrong index fails the tag.
- `WrongRecipientReturnsFalseNoCrash` — different KEM secret → tag fails → `false`, no crash, no
  plaintext exposed.
- `MixedExtraParsesAllAndFiltersPqOnly` — `[pubkey, 0x04, 0x06, TTL]` parses all four;
  `get_pq_messages_from_extra` returns only the PQ payload, `get_messages_from_extra` only the legacy.
- `TamperedAnyByteFailsNoFfiPanic` — **full sweep**: flipping ANY byte of the sealed `data`
  (ciphertext or Poly1305 tag), or any KEM-ciphertext byte, makes `decrypt` return `false` with no
  FFI panic. This is the integrity guarantee the AEAD upgrade provides.
- `OversizeDataRejectedByParser` / `WrongKemCtLengthRejectedByParser` / `ShortSealedDataRejectedByParser`
  — the bound rejects all three (over-max, wrong kemCt length, and shorter than the 16-byte tag).
- `RawExtraBytesAreCanonicalAndHashStable` — parse→re-serialize reproduces identical bytes and an
  identical `cn_fast_hash`, confirming the tx hash (taken over raw `tx.extra`) is unaffected by 0x06.

Result: 11/11 PqMessage tests pass; full `ctest -R UnitTests` passes (with the repo's baked-in skip
list), no regressions.

## Security notes / limitations (carried from the blueprint)

- **Confidentiality** now rests on ML-KEM-768 (NIST L3, IND-CCA2), not on the on-chain tx pubkey →
  closes the Shor break for messages.
- **Integrity is now provided** for the 0x06 field via **ChaCha20-Poly1305 AEAD**: tampering ANY byte
  of the sealed ciphertext (including the Poly1305 tag) makes `decrypt`/`open` fail, and no plaintext
  is exposed on failure. This closes the no-MAC limitation that the original chacha8 + 4-zero-byte
  owner-test had. **The legacy 0x04 path still has that weak owner-test** but is now **decrypt-only**:
  the classical successor is the authenticated `0x07` field (`tx_extra_authenticated_message`, same
  Curve25519 ECDH key agreement as 0x04 but ChaCha20-Poly1305 AEAD with a domain-separated seed). The
  wallet send path (`CryptoNoteFormatUtils.cpp`, `WalletGreen.cpp`) now **defaults to `0x06`**
  (true PQ confidentiality) whenever a recipient KEM pubkey is obtainable (PQ address, or the fixed
  testnet key on testnet — see Step 3b), emits the authenticated `0x07` only as the classical fallback
  for a mainnet legacy recipient, and falls back to `0x04` only for unencrypted broadcast messages (no
  recipient ECDH); the receive path decodes all three. 0x04 is kept for wire compatibility with
  historical messages.
- **Consensus posture:** `tx.extra` is opaque to block validation and carried verbatim, so adding
  `0x06` does not change block acceptance. `0x06` emission is the default on testnet (Option-B
  bootstrap key) and on mainnet whenever a recipient PQ address supplies a KEM key; otherwise the
  classical `0x07` is used. The parser bound mitigates R1 mis-framing; for mainnet rollout the `0x06`
  parser handler should ship to all nodes before any wallet emits the tag (quiet client update), or PQ
  messages should be placed last in `extra`.

## Remaining (step 4 — NOT done, larger consensus/compat surface)

Key distribution so a real recipient (not the hardcoded testnet key) can be addressed:

- **Address format:** publish the recipient's 1184-byte ML-KEM public key — either a new Base58 prefix
  carrying `AccountPublicAddress + kemPub` (Option A) or derive `kemPub` from the wallet seed
  (`SHAKE("ccx-msg-kem-id" || spendSecretKey)`) and expose it on the address (derivation alternative).
- **Wallet format:** persist the KEM keypair (2400 B sk / 1184 B pk) on `AccountKeys`, behind a
  wallet-format version bump (optional field, generate-on-first-load), so `TransfersConsumer` scans
  with the account's own KEM secret instead of `PQ_TESTNET_KEM_SK`.
- **Send glue:** *(done in Step 3b)* both send paths now resolve the recipient KEM key from a parsed
  PQ address (case a) or the testnet bootstrap key (case b) via `resolveMessageRecipientKemPub`, with
  the env-flag shortcut removed. Still open: threading a dedicated PQ recipient field through
  `IWalletLegacy::TransactionMessage` / `WalletMessage` and the RPC surfaces so a caller can target a
  PQ recipient distinct from the fund-recipient address, and the wallet-format KEM-secret persistence
  above (so mainnet receivers can scan their own `0x06` messages without `PQ_TESTNET_KEM_SK`).

Search markers: `TODO` comments in `WalletTransactionSender.cpp` and `TransfersConsumer.cpp` point at
the testnet shortcuts to replace. This shares `CryptoNoteConfig.h` (new Base58 prefix) and wallet
serialization with other PQ work — coordinate per `REMAINING-WORK.md`.
