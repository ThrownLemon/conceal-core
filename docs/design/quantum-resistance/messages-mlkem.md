# PQ for Conceal Encrypted On-Chain Messages — ML-KEM-768 KEM Blueprint

Status: DESIGN / advisory (read-only analysis). Targets the working PoC on `pqc/testnet-poc`.
Scope: replace the Curve25519-ECDH-derived symmetric key that protects Conceal's encrypted
tx-extra messages with an ML-KEM-768 (Kyber) KEM, reusing the already-wired
`ccx_pq_kem_derive_output` / `ccx_pq_kem_scan` FFI. Gate behind testnet + a new
`TX_EXTRA_PQ_MESSAGE_TAG`, do not touch the legacy `0x04` path.

---

## 1. What exists today (grounded in code)

### 1.1 The message field and its crypto

`src/CryptoNoteCore/TransactionExtra.h:51-58` — the on-chain field:

```cpp
struct tx_extra_message {
  std::string data;                  // ciphertext (msg || 4 zero-byte checksum), chacha8
  bool encrypt(std::size_t index, const std::string &message,
               const AccountPublicAddress* recipient, const KeyPair &txkey);
  bool decrypt(std::size_t index, const crypto::PublicKey &txkey,
               const crypto::SecretKey *recepient_secret_key, std::string &message) const;
  bool serialize(ISerializer& serializer);
};
```

Tag `TX_EXTRA_MESSAGE_TAG = 0x04` (`TransactionExtra.h:25`), parsed at
`TransactionExtra.cpp:94-100` (reads `message.data` as a length-prefixed blob), written via
`append_message_to_extra` (`TransactionExtra.cpp:242-255`).

The crypto that Shor breaks lives in `TransactionExtra.cpp:369-443`:

```cpp
struct message_key_data { KeyDerivation derivation; uint8_t magic1, magic2; }; // 34 bytes

// encrypt (sender):
generate_key_derivation(recipient->spendPublicKey, txkey.secretKey, key_data.derivation);
key_data.magic1 = 0x80; key_data.magic2 = 0;
Hash h = cn_fast_hash(&key_data, sizeof(message_key_data));   // 32-byte chacha8 key
uint64_t nonce = SWAP64LE(index);                             // chacha8 IV (8 bytes)
chacha8(buf, mlen, &h, &nonce, buf);                          // mlen = msg + 4-byte checksum

// decrypt (recipient):
generate_key_derivation(txkey /*tx pubkey*/, *recepient_secret_key /*spendSecretKey*/, ...);
// same h, same chacha8, then verify the 4 trailing zero bytes (auth/owner test)
```

Key facts that drive the design:

- The **symmetric layer is already exactly what we want**: chacha8 over `msg || 0x00000000`,
  keyed by a 32-byte hash, IV = the message `index`. The 4 zero bytes are a weak
  checksum/owner-test (decrypt succeeds iff the trailing 4 bytes decrypt to zero). The ML-KEM
  variant keeps this construction verbatim and only swaps how the 32-byte key `h` is produced.
- The **quantum-broken part is solely the key agreement**:
  `generate_key_derivation(spendPublicKey, txkey.secretKey)` is X25519-style ECDH
  (`8 * txSecret * spendPublic`). Shor recovers `txkey.secretKey` from the on-chain tx pubkey
  (`TX_EXTRA_TAG_PUBKEY`, `getTransactionPublicKeyFromExtra`), then re-derives `h` and decrypts
  every message addressed with that tx key. Confidentiality only; integrity here is informal.
- Recipient identification is via the **spend key** (sender uses `recipient->spendPublicKey`,
  recipient uses its `spendSecretKey`). This is deliberate: messages go to the spend address.
  It is NOT the view-key channel used for output scanning.

### 1.2 Callers (the full surface we must extend)

Send path:
- `src/CryptoNoteCore/CryptoNoteFormatUtils.cpp:205-213` — `constructTransaction` loops
  `messages` (`std::vector<tx_message_entry>`), calls `tag.encrypt(i, msg.message,
  msg.encrypt ? &msg.addr : NULL, txkey)` then `append_message_to_extra`. `txkey` is the
  transaction keypair (deterministic, `generateDeterministicTransactionKeys`).
- `tx_message_entry { std::string message; bool encrypt; AccountPublicAddress addr; }`
  (`CryptoNoteFormatUtils.h:44-49`).
- `src/WalletLegacy/WalletTransactionSender.cpp:239-248` builds `tx_message_entry` from
  `TransactionMessage { message; address; }` (`include/IWalletLegacy.h:51-54`) by parsing the
  destination address string into an `AccountPublicAddress`.

Receive/scan path:
- `src/Transfers/TransfersConsumer.cpp:574-575` —
  `get_messages_from_extra(tx.getExtra(), tx.getTransactionPublicKey(),
  &sub.getKeys().spendSecretKey)` for each subscribed account.
- `get_messages_from_extra` (`TransactionExtra.cpp:257-280`) iterates extra fields, calls
  `decrypt(i, txkey, recipientSpendSecret, res)`, keeps the ones whose checksum validates.

RPC / wallet glue (string-level, no crypto): `src/PaymentGate/WalletService.cpp`,
`src/Wallet/WalletRpcServer.cpp`, `src/Wallet/WalletGreen.cpp`,
`src/WalletLegacy/WalletUserTransactionsCache.cpp`, `WalletLegacy.cpp`. These pass message
strings through and need no change beyond optionally selecting the PQ path.

### 1.3 The ML-KEM FFI we will reuse (already linked)

`pqc/include/pq_ring_sig.h:25-33` + `pqc/ccx-pqc/src/lib.rs:170-231`:

```c
size_t  ccx_pq_kem_pubkey_bytes(void);   // 1184  (ML-KEM-768 PK)
size_t  ccx_pq_kem_seckey_bytes(void);   // 2400  (ML-KEM-768 SK)
size_t  ccx_pq_kem_ct_bytes(void);       // 1088  (ML-KEM-768 ciphertext)
int32_t ccx_pq_kem_keypair(pk_out, pk_cap, sk_out, sk_cap);
int32_t ccx_pq_kem_derive_output(kem_pk, kem_pk_len, ct_out, ct_cap, seed_out/*32B*/, seed_cap);
int32_t ccx_pq_kem_scan(kem_sk, kem_sk_len, ct, ct_len, seed_out/*32B*/, seed_cap);
```

`derive_output` = `encapsulate(pk) -> (ss, ct)` then `SHAKE256("ccx-stealth-otk" || ss) -> 32B
seed`. `scan` = `decapsulate(ct, sk)` then the same SHAKE → same 32B seed. This is exactly a
KEM-derived 32-byte symmetric secret + a published ciphertext. **The seed is currently
domain-separated for stealth one-time keys (`"ccx-stealth-otk"`), so for messages we need a
distinct derivation (see §3.1) to avoid cross-purpose key reuse.**

CMake wiring already links `${CCX_PQC_LIB}` into every executable
(`src/CMakeLists.txt:74-92`); `CryptoNoteCore` already includes `${CCX_PQC_INCLUDE}` and
depends on `ccx_pqc`. **No new build wiring is required** — `TransactionExtra.cpp` lives in
`CryptoNoteCore`, which already sees `pq_ring_sig.h`.

Existing serialization precedent for variable PQ blobs:
`CryptoNoteSerialization.cpp:295-298` uses `serializeAsBinary(out.kemCt, "kem", serializer)` for
the 1088-byte Kyber ciphertext on `PqKeyOutput`. We mirror that.

---

## 2. Design overview

Add a **new, additive** tx-extra field `tx_extra_pq_message` under a new tag
`TX_EXTRA_PQ_MESSAGE_TAG = 0x06`. Each PQ message carries its own ML-KEM ciphertext (`kemCt`,
1088 B) plus the chacha8 ciphertext `data` (unchanged construction). The legacy `0x04`
field stays byte-for-byte as is for backward compatibility and is never emitted on PQ-message
transactions when the recipient is PQ-capable.

Why per-message ciphertext (not one tx-wide encapsulation): the existing field is per-recipient
(`recipient->spendPublicKey`) and a tx can address different messages to different recipients
(the loop in `CryptoNoteFormatUtils.cpp` re-keys per entry). One `kemCt` per message keeps that
property and keeps the change strictly local to the field. Cost: +1088 B per PQ message
(acceptable; messages are an opt-in feature, and `TX_EXTRA` is not consensus-size-limited the
way outputs are — but see Risk R4 on tx size / relay).

```
Sender (has recipient PQ-address -> kemPub 1184B):
  ccx_pq_kem_derive_output(kemPub) -> (kemCt 1088B, ss-seed 32B)
  h = SHAKE256("ccx-msg-v1" || ss-seed || LE64(index))            # 32-byte chacha8 key
  data = chacha8(msg || 0x00000000, key=h, iv=LE64(index))
  emit tx_extra_pq_message{ kemCt, data }

Recipient (has kemSec 2400B):
  for each pq-message field i:
     ccx_pq_kem_scan(kemSec, kemCt) -> ss-seed 32B
     h = SHAKE256("ccx-msg-v1" || ss-seed || LE64(i))
     plain = chacha8(data, key=h, iv=LE64(i)); check 4 trailing zero bytes
```

The 32-byte seed already includes a SHAKE step in Rust; we add a second C++-side derivation
binding the message `index` and a message-specific domain tag (§3.1) so the chacha8 key is not
the raw stealth seed.

---

## 3. Concrete changes (files / steps)

### 3.1 FFI: add a message-domain KEM derivation (Rust)

File: `pqc/ccx-pqc/src/lib.rs`. The current `derive_output`/`scan` hardcode the stealth domain
`"ccx-stealth-otk"`. Add a thin message-domain pair (preferred — keeps domain separation inside
the audited crypto module and returns the **same `ss`-derived secret** regardless of `index`,
with `index` mixed in C++ side per message):

```rust
// Messages KEM: identical to derive_output/scan but domain "ccx-msg-kem-v1".
#[no_mangle] pub extern "C" fn ccx_pq_msg_kem_encap(
    kem_pk: *const u8, kem_pk_len: usize,
    ct_out: *mut u8, ct_cap: usize, key_out: *mut u8, key_cap: usize) -> i32 { /* shake "ccx-msg-kem-v1" */ }
#[no_mangle] pub extern "C" fn ccx_pq_msg_kem_decap(
    kem_sk: *const u8, kem_sk_len: usize,
    ct: *const u8, ct_len: usize, key_out: *mut u8, key_cap: usize) -> i32 { /* shake "ccx-msg-kem-v1" */ }
```

Declare both in `pqc/include/pq_ring_sig.h` (alongside `ccx_pq_kem_*`). Add a selftest
`ccx_pq_msg_kem_selftest()` (encap→decap round-trip + wrong-key-fails) following
`ccx_pq_kem_stealth_selftest` (`lib.rs:236-258`).

Acceptable alternative (zero Rust change): reuse `ccx_pq_kem_derive_output`/`scan` as-is and do
ALL domain separation + index binding in C++:
`h = cn_fast_hash("ccx-msg-v1" || seed32 || LE64(index))`. This is simpler to land but mixes the
stealth-domain seed into messages; if outputs and messages ever target the same KEM key this
reuses one `ss` across two purposes (still safe because the SHAKE inputs differ, but it is
cleaner to domain-separate inside Rust). **Recommend the explicit Rust pair.**

### 3.2 New tag + struct (TransactionExtra.h)

```cpp
#define TX_EXTRA_PQ_MESSAGE_TAG 0x06   // after TX_EXTRA_TTL = 0x05

struct tx_extra_pq_message {
  std::vector<uint8_t> kemCt;   // ML-KEM-768 ciphertext (1088 B)
  std::string data;             // chacha8(msg || 4x00), same construction as tx_extra_message

  bool encrypt(std::size_t index, const std::string& message,
               const std::vector<uint8_t>& recipientKemPub);
  bool decrypt(std::size_t index, const std::vector<uint8_t>& recipientKemSec,
               std::string& message) const;
  bool serialize(ISerializer& serializer);
};
```

Add `tx_extra_pq_message` to the `TransactionExtraField` boost::variant
(`TransactionExtra.h:68`). Add declarations for `append_pq_message_to_extra` and
`get_pq_messages_from_extra(extra, recipientKemSec)` (note: **no tx pubkey argument** — the
KEM ciphertext is self-contained; the recipient only needs its own KEM secret).

### 3.3 Parse / write / encrypt / decrypt (TransactionExtra.cpp)

- Parser (`TransactionExtra.cpp:42` switch): add
  ```cpp
  case TX_EXTRA_PQ_MESSAGE_TAG: {
    tx_extra_pq_message m;
    ar(m.kemCt, "kem");   // BinaryArray length-prefixed
    ar(m.data,  "data");
    transactionExtraFields.push_back(m);
    break;
  }
  ```
  Guard `kemCt.size() == ccx_pq_kem_ct_bytes()` and bound `data.size()` (reject oversize early;
  see R4). Reuse the existing `try/catch` that already makes the parser fail-closed.
- `ExtraSerializerVisitor` (`TransactionExtra.cpp:122-164`): add
  `bool operator()(const tx_extra_pq_message& t){ return append_pq_message_to_extra(extra, t); }`.
- `append_pq_message_to_extra`: mirror `append_message_to_extra` (`:242-255`) — push tag, then
  `toBinaryArray(message_struct)`.
- `serialize`: `s(kemCt,"kem"); s(data,"data");` — but `kemCt` is `vector<uint8_t>`, use the same
  `serializeAsBinary` style as `PqKeyOutput::kemCt` for compactness/consistency.
- `encrypt`:
  ```cpp
  bool tx_extra_pq_message::encrypt(size_t index, const std::string& message,
                                    const std::vector<uint8_t>& recipientKemPub) {
    size_t mlen = message.size();
    std::vector<char> buf(mlen + TX_EXTRA_MESSAGE_CHECKSUM_SIZE, 0);
    memcpy(buf.data(), message.data(), mlen);
    mlen += TX_EXTRA_MESSAGE_CHECKSUM_SIZE;
    kemCt.assign(ccx_pq_kem_ct_bytes(), 0);
    uint8_t seed[32];
    if (ccx_pq_msg_kem_encap(recipientKemPub.data(), recipientKemPub.size(),
                             kemCt.data(), kemCt.size(), seed, sizeof(seed)) != 0) return false;
    Hash h = deriveMsgKey(seed, index);          // SHAKE/cn_fast_hash("ccx-msg-v1"||seed||LE64(index))
    uint64_t nonce = SWAP64LE(index);
    chacha8(buf.data(), mlen, reinterpret_cast<uint8_t*>(&h),
            reinterpret_cast<uint8_t*>(&nonce), buf.data());
    data.assign(buf.data(), mlen);
    return true;
  }
  ```
- `decrypt`: symmetric — `ccx_pq_msg_kem_decap(recipientKemSec, kemCt, seed)`, same `deriveMsgKey`,
  chacha8, then the 4 trailing-zero checksum test (the owner test). On any FFI error or short
  buffer return false (so non-recipients silently skip).
- `get_pq_messages_from_extra`: same shape as `get_messages_from_extra` (`:257-280`) but iterate
  `typeid(tx_extra_pq_message)` and call the new `decrypt`.

Keep `TX_EXTRA_MESSAGE_CHECKSUM_SIZE` (4) and the chacha8 construction identical so the symmetric
layer is unchanged and independently reviewable.

### 3.4 Address carries a KEM public key (key distribution)

This is the substantive consensus/format surface. A recipient must publish a 1184-byte ML-KEM
public key. Options, recommended order:

**Option A (recommended, additive): a separate "PQ message key" sub-address / appendix.**
Do NOT widen `AccountPublicAddress` (`include/CryptoNote.h:91-94`) on mainnet — it is serialized
into the Base58 address and into many on-disk/wire structures (`getAccountAddressAsStr`,
`CryptoNoteBasicImpl.cpp:54-82`). Instead introduce a parallel optional structure:

- `struct AccountPublicAddressPq { AccountPublicAddress base; std::vector<uint8_t> kemPub; };`
- Encode with a **new Base58 prefix** (`TESTNET_*` first) so old wallets cleanly reject it and
  new wallets recognize "this is a PQ-message-capable address." Add e.g.
  `CRYPTONOTE_PUBLIC_PQ_ADDRESS_BASE58_PREFIX` + `TESTNET_*` in `CryptoNoteConfig.h`.
- Extend `AccountKeys` storage (`include/CryptoNote.h:96-100`) with an optional
  `kemSecretKey`/`kemPublicKey` (2400 B / 1184 B), persisted in the wallet file. Generate it in
  `AccountBase`/`generate` (`src/CryptoNoteCore/Account.cpp`) via `ccx_pq_kem_keypair`. **Wallet
  file is a compatibility surface** — add the KEM keypair as a new optional serialized member
  guarded by a wallet-format version bump, never mutate existing fields.

**Option B (PoC-only shortcut, what the current testnet already does):** a single hardcoded
testnet recipient KEM key (`pqc/include/pq_testnet_kem_keypair.h`, `PQ_TESTNET_KEM_PK`). For the
message PoC, the sender can encapsulate to `PQ_TESTNET_KEM_PK` and the injector/recipient
decapsulates with `PQ_TESTNET_KEM_SK`. This proves the end-to-end message path with **zero
address-format work** and is the fastest route to a working demo. Production needs Option A.

**Derivation alternative (no new key material):** derive the recipient KEM keypair
deterministically from the existing wallet seed (e.g. `ccx_pq_keygen`-style seed =
`SHAKE("ccx-msg-kem-id" || spendSecretKey)`), and publish only the resulting `kemPub` in the
address. This avoids storing a second independent secret but ties message confidentiality to the
spend key (acceptable — that matches today's spend-key-addressed semantics). Recommended if the
team wants to minimize wallet-format churn. Document the binding clearly: whoever holds the spend
secret can read messages, exactly as today.

### 3.5 Send/scan glue

- `tx_message_entry` (`CryptoNoteFormatUtils.h:44-49`): add `std::vector<uint8_t> kemPub;` and a
  `bool pq;` flag. In `constructTransaction` (`CryptoNoteFormatUtils.cpp:205-213`), if
  `msg.pq && !msg.kemPub.empty()`, build a `tx_extra_pq_message` and
  `append_pq_message_to_extra`; else keep the legacy branch.
- `WalletTransactionSender.cpp:239-248`: when the parsed destination is a PQ address (Option A
  prefix), set `kemPub`/`pq` on the `tx_message_entry`.
- `TransfersConsumer.cpp:574-575`: additionally call
  `get_pq_messages_from_extra(tx.getExtra(), sub.getKeys().kemSecretKey)` and merge with the
  legacy result before `sub.addTransaction(...)`. The scan needs the account's KEM secret, which
  Option A/derivation makes available on `AccountKeys`.

### 3.6 Testnet gating (consensus posture)

Per CLAUDE.md, anything affecting accepted tx format is consensus-sensitive. The PQ message field
is **inside `TX_EXTRA`, which is opaque to validation** (the daemon does not parse message
semantics during block validation — it only relays/stores `extra`). So adding `0x06` does not by
itself change block acceptance; old daemons will store and relay the field as opaque extra bytes
and simply fail to parse the new tag (the parser switch falls through unknown tags... — verify:
the current parser has **no default case**, so an unknown tag byte is consumed as the next
field's tag, which can desync parsing). **Important correctness note:** the existing
`parseTransactionExtra` loop (`:39-112`) has no `default:` and treats every byte as a known tag;
an unrecognized `0x06` on an old node makes the following bytes mis-parse and the whole
`parseTransactionExtra` likely returns the partial/garbled set or throws → fields after it are
lost, but `parse` returning `false` only drops message extraction, not block validation. Confirm
that `extra` is NOT re-serialized canonically during validation (it is stored as the raw byte
vector `tx.extra`), so consensus/tx-hash is over the raw bytes and is unaffected. Gate emission
behind `m_testnet` (and a config flag) so mainnet never produces `0x06` until a coordinated
upgrade height.

---

## 4. Wire format

```
tx_extra_pq_message (after tag byte 0x06):
  [varint len_kemCt][kemCt bytes (1088)]
  [varint len_data ][data  bytes (mlen = |msg| + 4)]
```

Use `serializeAsBinary` for both members (length-prefixed), matching `PqKeyOutput`
(`CryptoNoteSerialization.cpp:295-298`). Fixed `kemCt` size is enforced on parse, not on the
wire (defense in depth: reject `len_kemCt != 1088`).

---

## 5. Security analysis

- **Confidentiality (the goal):** message key is `KDF(ML-KEM-768 shared secret, index)`. Recovering
  it requires breaking ML-KEM-768 (NIST level 3, IND-CCA2) — Shor-resistant. The on-chain tx
  pubkey no longer participates in the message key, closing the X25519 break for messages.
- **No transcript downgrade:** the legacy `0x04` field and the PQ `0x06` field are independent.
  A PQ-addressed message must be sent ONLY as `0x06`; never emit a parallel `0x04` copy (that
  would leak the plaintext under the quantum-broken channel). Enforce in `constructTransaction`.
- **Integrity:** unchanged from today — the 4-byte zero checksum is a weak owner-test, not a MAC.
  ML-KEM is IND-CCA2 so ciphertext malleability of `kemCt` is bounded, but `data` (chacha8) has no
  MAC. This matches existing behavior; flag as a known limitation. A clean future step: replace
  chacha8 + 4-zero-byte check with an AEAD (ChaCha20-Poly1305) keyed by the KEM secret. Out of
  scope for "drop-in KEM replacement" but worth noting in the spec.
- **Domain separation:** the message KDF MUST use a distinct domain string from stealth outputs
  (`"ccx-msg-kem-v1"` vs `"ccx-stealth-otk"`) so a KEM key reused for both purposes never yields
  the same secret. §3.1 handles this.
- **Metadata:** a `0x06` field is publicly visible (reveals "this tx carries a PQ message" and its
  ~1088+N byte size). Same observability class as today's `0x04`. Optional `TX_EXTRA_TAG_PADDING`
  can normalize sizes.
- **No nullifier/replay concern:** messages are not spends; no double-spend surface.

---

## 6. Risks

- **R1 (consensus/format, HIGH):** `parseTransactionExtra` has no `default:` case
  (`TransactionExtra.cpp:42-111`); an unknown `0x06` on an un-upgraded node mis-frames subsequent
  extra fields. Mitigation: gate to testnet; for mainnet, ship the parser-side `0x06` handler to
  ALL nodes (a quiet, non-consensus client update) BEFORE any wallet emits the tag, OR place PQ
  messages last in `extra` so mis-framing only affects the PQ field itself. Verify tx-hash is over
  raw `tx.extra` bytes (it is — `extra` is `std::vector<uint8_t>` carried verbatim) so block
  validity is unaffected regardless.
- **R2 (wallet-format compatibility, MED):** storing the 2400-byte KEM secret in the wallet file
  changes the wallet format. Bump wallet version, make the field optional, and provide migration
  (generate-on-first-load). Old wallets opening a PQ wallet must fail cleanly, not corrupt.
- **R3 (address format / UX, MED):** new Base58 prefix means PQ addresses are visibly different and
  ~1.5 KB longer (1184 B encoded). Wallets/exchanges/explorers must recognize the prefix. The
  derive-from-seed variant (§3.4) lets a single address optionally expose a `kemPub`.
- **R4 (tx size / relay, MED):** +1088 B per PQ message. Confirm against any
  `MAX_TX_EXTRA`/`max blob size`/fee-per-byte rules. Add an explicit upper bound on `data` length
  in the parser. Multiple messages multiply the cost.
- **R5 (FFI/ABI, LOW-MED):** new Rust exports must be rebuilt (`cargo build --release`) and the
  `.a` relinked. The `ss`→seed SHAKE is inside Rust; ensure the C++ `deriveMsgKey` uses a
  hash/XOF consistent across platforms (prefer SHAKE256 in Rust to avoid a second hash impl in
  C++; or reuse `cn_fast_hash` which is already used at `:396`).
- **R6 (key reuse, LOW):** if the KEM key is derived from the spend secret, message
  confidentiality == spend-key secrecy. This matches current semantics (spend-key-addressed
  messages) but should be stated explicitly so users don't assume a separate compromise boundary.
- **R7 (timing/oracle, LOW):** the 4-zero-byte owner-test runs per candidate message per
  subscribed account; ML-KEM decaps is constant-time in the Rust lib. Avoid leaking via
  early-return differences beyond what the legacy path already does.

---

## 7. Test plan

Rust (`pqc/ccx-pqc`, `cargo build --release` + `cargo test`):
- `ccx_pq_msg_kem_selftest`: encap→decap round-trip yields equal 32-byte secret; wrong KEM secret
  yields a different secret. Mirror `ccx_pq_kem_stealth_selftest` (`lib.rs:236-258`).
- Property: secret independent of `index` (index is mixed C++-side), ciphertext is 1088 B.

C++ unit (add to `tests/`, build with `-DBUILD_TESTS=ON`, run `ctest -R UnitTests`):
- `tx_extra_pq_message` round-trip: `encrypt(index, msg, kemPub)` →
  `parseTransactionExtra(writeTransactionExtra(...))` → `decrypt(index, kemSec)` == `msg`, for
  empty / short / multi-KB messages and indices 0..N.
- Wrong recipient: `decrypt` with a different KEM secret returns false (checksum fails), no crash.
- Mixed extra: a tx with `[pubkey, 0x04 legacy msg, 0x06 pq msg, TTL]` parses all fields and
  `get_pq_messages_from_extra` returns only the PQ ones; `get_messages_from_extra` only the legacy.
- Tamper: flip a byte in `kemCt` or `data` → `decrypt` returns false (no panic across the FFI).
- Bounds: oversize `len_kemCt`/`len_data` rejected by the parser (returns false, no OOM).
- Old-parser framing: feed a `0x06` field to a parser without the new case (simulate old node) and
  assert block-level tx-hash over `tx.extra` is unchanged (raw-bytes invariant).

Integration (2-node testnet, `pqc/run-poc-testnet.sh ~/conceal-core/build/src`):
- Send a PQ message to `PQ_TESTNET_KEM_PK` (Option B), confirm `TransfersConsumer`'s
  `get_pq_messages_from_extra` surfaces it with the matching `PQ_TESTNET_KEM_SK`, and a wrong key
  does not. Measure tx size delta and relay/accept across both nodes.

Build/measure host: `ssh 100.100.90.103`; `cd ~/conceal-core/build && make -j16 CryptoNoteCore
Daemon ConcealWallet`; Rust: `cd ~/conceal-core/pqc/ccx-pqc && ~/.cargo/bin/cargo build
--release`.

---

## 8. Recommended landing order (smallest reviewable steps)

1. Rust: add `ccx_pq_msg_kem_encap/decap` + selftest; declare in `pq_ring_sig.h`; rebuild `.a`.
2. C++: add `TX_EXTRA_PQ_MESSAGE_TAG`, `tx_extra_pq_message` (struct, variant, parse/write,
   encrypt/decrypt, get_/append_), with unit tests. **No address/wallet changes yet** — test with
   a literal KEM keypair in the unit test. This is the self-contained, low-risk core.
3. Wire send/scan glue (`tx_message_entry`, `constructTransaction`, `TransfersConsumer`) behind a
   testnet flag, using Option B's hardcoded testnet KEM key for the first end-to-end demo.
4. Address/wallet key distribution (Option A or derive-from-seed) + wallet-format version bump.
   This is the larger consensus/compat surface and should be its own reviewed PR.

Steps 1–2 are a clean, isolated, well-testable unit; steps 3–4 are the compatibility-heavy work.
