# Conceal Consensus Serialization Format — Canonical Byte Layout (PQ additions + variant tag table)

Status: SPEC / normative reference for the on-wire + on-disk + consensus-hash binary format.
Scope: documents the exact byte layout produced by `src/CryptoNoteCore/CryptoNoteSerialization.cpp`
and `src/CryptoNoteCore/TransactionExtra.cpp`, with emphasis on the post-quantum additions
(`PqKeyInput/Output`, `PqMultisigInput/Output`, tx-extra `0x06` PQ message). The golden-vector and
round-trip guard for this format lives at
`tests/UnitTests/TestTransactionSerializationGolden.cpp` (suites `TransactionSerializationGolden`,
`TransactionExtraGolden`) and `tests/UnitTests/TestPqMessage.cpp`.

> **Why this is a spec, not tribal knowledge.** The homemade KV binary serializer is simultaneously
> (a) the P2P wire format, (b) the on-disk blockchain/wallet format, and (c)
> **consensus-hash-observable** — `getObjectHash(tx)` and `getObjectHash(block)` hash these exact
> bytes. The PQ fields were added to it BY HAND. Any byte drift silently forks the chain and
> invalidates every hardcoded checkpoint. Treat every layout below as frozen unless you are making a
> deliberate, height-gated, hard-fork consensus change.

---

## 1. Primitive encodings

| Primitive | Encoding |
|---|---|
| `uint8/16/32/64`, `int*` | **varint** (LEB128, base-128, little-endian, 7 data bits/byte, high bit = continuation) via `Common/Varint.h::writeVarint`. |
| `bool` | one raw byte (`0x00`/`0x01`). |
| POD blob (`crypto::PublicKey`, `crypto::SecretKey`, `crypto::Hash`, `crypto::KeyImage`, `crypto::Signature`, `chacha8_iv`) | **raw fixed-size bytes, NO length prefix** (`ISerializer::binary(ptr, size)`). PublicKey/SecretKey/Hash/KeyImage/Signature are 32 bytes each except `Signature` = 64 bytes. |
| `std::string` | `varint(size)` then `size` raw bytes (`operator()(std::string&)`). |
| `std::vector<uint8_t>` via `serializeAsBinary` | packed into a blob then emitted as a string: `varint(size)` + raw bytes. **Length-prefixed.** |
| `std::vector<uint32_t>` via `serializeVarintVector` | `varint(count)` then each element as a varint. |
| `std::vector<T>` (array of objects, e.g. `std::vector<PublicKey>`) | `beginArray` writes `varint(count)`, then each element serialized in order. For POD element types each element is its raw fixed-size blob (no per-element length). |
| variant element (`TransactionInput`, `TransactionOutputTarget`) | one **raw** tag byte (NOT a varint — written via `binary(&tag, 1)`) followed by the tagged value's body. |

`block.nonce` is the one integer written as a **raw 4-byte** field (`binary(&nonce, 4)`), not a
varint — see §5.

---

## 2. Variant tag table

### 2.1 Transaction input tag (`TransactionInput`, leading byte of each `vin` element)

| Tag (raw byte) | Type | Notes |
|---|---|---|
| `0xff` | `BaseInput` | coinbase / miner input |
| `0x02` | `KeyInput` | ordinary ring-signature spend |
| `0x03` | `MultisignatureInput` | legacy Ed25519 multisig / deposit |
| `0x04` | **`PqKeyInput`** | PQ linkable-ring-signature spend (CIP-0001) |
| `0x05` | **`PqMultisigInput`** | PQ ML-DSA-65 multisig / deposit (CIP-0001 UPGRADE_HEIGHT_V9) |

### 2.2 Transaction output target tag (`TransactionOutputTarget`, leading byte of each output `target`)

| Tag (raw byte) | Type | Notes |
|---|---|---|
| `0x02` | `KeyOutput` | one-time public key output |
| `0x03` | `MultisignatureOutput` | legacy multisig output |
| `0x04` | **`PqKeyOutput`** | PQ one-time output (ML-KEM stealth) |
| `0x05` | **`PqMultisigOutput`** | PQ ML-DSA-65 multisig output |

> Note the input/output tag namespaces are **separate**. Tag `0x04` means `PqKeyInput` in `vin` and
> `PqKeyOutput` in `vout`; tag `0x05` means `PqMultisigInput` vs `PqMultisigOutput`. The decoder
> dispatches on position (`getVariantValue` has one overload per side).

### 2.3 tx-extra field tag (leading byte of each tx-extra field)

| Tag | Field | Body |
|---|---|---|
| `0x00` | padding | run of zero bytes (no explicit length; consumed until non-zero / end, capped at 255) |
| `0x01` | public key | 32 raw bytes (no length prefix) |
| `0x02` | nonce | 1 raw length byte + that many raw bytes |
| `0x03` | merge-mining tag | length-prefixed string blob of `{varint depth, Hash merkleRoot}` |
| `0x04` | legacy message | length-prefixed string `data` (chacha8 ciphertext, see §6) |
| `0x05` | TTL | `varint(size)` + `varint(ttl)` |
| `0x06` | **PQ message** | `{serializeAsBinary kemCt, string data}` — see §4.3 |
| `0x07` | **authenticated message** | `tx_extra_authenticated_message` — classical Curve25519 ECDH + ChaCha20-Poly1305 AEAD; body is a single length-prefixed `string data` (the sealed blob). See §4.6 / §6. |

The extra parser (`parseTransactionExtra`) has **no `default` case**: an unknown tag stops further
field recognition, and a field that over-reads its declared length consumes bytes belonging to the
next field. New variable-length fields therefore MUST be bounded at parse time (see the 0x06 guard in
§4.3) before being added.

> **Known limitation — no `default:` rejection (consensus-sensitive).** Because the `switch` has no
> `default`, an unrecognised tag byte fails *soft* (field recognition stops; foreign/unknown tx-extra
> is tolerated). This is the legacy parser design and affects every tag. Adding a blanket
> `default: return false` would reject tx-extra the network currently accepts — a **consensus change**
> that could fork the chain — so it is deliberately NOT done here. The correct fix is a future,
> height-gated, length-framed tx-extra container format (every field self-describes its length, so
> unknown fields are skippable without desync) behind a new `UPGRADE_HEIGHT_*` + block major version.
> See `docs/reviews/tier1/serializer-review-response.md`. The fields we own (0x06, 0x07) are each
> explicitly length-bounded **before allocation** at parse time so a hostile length prefix can neither
> over-read into following fields nor force a large allocation (DoS-hardened — review FIX 1).

---

## 3. Input layouts (body after the tag byte)

### 3.1 `BaseInput` (tag `0xff`)
```
varint blockIndex            // uint32
```

### 3.2 `KeyInput` (tag `0x02`)
```
varint amount                // uint64
varint count, varint[count]  // outputIndexes (serializeVarintVector)
32 raw bytes                 // keyImage (POD, no length)
```

### 3.3 `MultisignatureInput` (tag `0x03`)
```
varint amount                // uint64
varint signatureCount        // uint8
varint outputIndex           // uint32
varint term                  // uint32
```

### 3.4 `PqKeyInput` (tag `0x04`)
```
varint amount                       // uint64
varint count, varint[count]         // outputIndexes (serializeVarintVector)
varint len, len raw bytes           // nullifier   (serializeAsBinary, length-prefixed)
varint len, len raw bytes           // ringSig      (serializeAsBinary, length-prefixed)
```
PQ ring sigs are carried INLINE in the input; `getSignaturesCount(PqKeyInput) == 0`, so this input
contributes NO entries to the positional `tx.signatures` array.

### 3.5 `PqMultisigInput` (tag `0x05`)
```
varint amount                       // uint64
varint signatureCount               // uint8  (== output.requiredSignatureCount, m)
varint outputIndex                  // uint32
varint term                         // uint32
varint m, then m × {varint len, len raw bytes}   // signatures (PQ multisig array, see §3.7)
```
`getSignaturesCount(PqMultisigInput) == 0` — the m ML-DSA-65 detached sigs (~3.3 KB each) live inline
here, not in the fixed-size `crypto::Signature` slots.

### 3.6 PQ multisig array (`serializePqMultisigArray`)
```
varint count                        // bounded to PQ_MULTISIG_MAX_KEYS on the INPUT path
count × { varint len, len raw bytes }   // each element via serializeAsBinary
```
The count is checked against `PQ_MULTISIG_MAX_KEYS` BEFORE allocation on decode, so a hostile length
prefix cannot drive an OOM.

---

## 4. Output layouts (body after the tag byte)

### 4.1 `KeyOutput` (tag `0x02`)
```
32 raw bytes                 // key (POD PublicKey)
```

### 4.2 `MultisignatureOutput` (tag `0x03`)
```
varint count, count × 32 raw bytes   // keys (array of POD PublicKey)
varint requiredSignatureCount        // uint8
varint term                          // uint32
```

### 4.3 `PqKeyOutput` (tag `0x04`)
```
varint len, len raw bytes    // key   (serializeAsBinary, variable-length PQ one-time pubkey)
varint len, len raw bytes    // kemCt (serializeAsBinary, ML-KEM ciphertext)
```

### 4.4 `PqMultisigOutput` (tag `0x05`)
```
varint n, then n × {varint len, len raw bytes}   // keys (PQ multisig array, §3.6)
varint requiredSignatureCount                    // uint8 (m)
varint term                                       // uint32
```

> **The full `vout` element** wraps the target: `varint amount` then `target` (tag byte + body
> above). The golden vectors in the test encode the bare `TransactionOutputTarget` variant (tag +
> body), i.e. without the leading `amount`, which is the unit under test for the variant serializers.

### 4.6 tx-extra `0x07` authenticated message body (`tx_extra_authenticated_message`)
After the `0x07` tag:
```
varint len, len raw bytes    // data (string) — ChaCha20-Poly1305 sealed blob = plaintext || 16-byte Poly1305 tag
```
No KEM ciphertext is carried (unlike `0x06`): the recipient re-derives the 32-byte AEAD seed from the
tx public key + their spend secret via classical Curve25519 ECDH (`generate_key_derivation`, then
`cn_fast_hash(derivation || 0x80 || 0x07)`). The key agreement is the same as the legacy `0x04` field,
but the seed is **domain-separated** by the second magic byte: `0x07` uses `0x07` where `0x04` uses
`0x00`, so a `0x04` and a `0x07` to the same recipient + index can never derive the same seed or share
a keystream (review FIX 3). The seed + the per-message index then key `ccx_pq_msg_seal/open`.
Parse-time bound (declared length bounded before allocation, same rationale as `0x06`):
`TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE (16) <= data.size() <= TX_EXTRA_AUTH_MESSAGE_MAX_DATA_SIZE (8192)`.

### 4.5 tx-extra `0x06` PQ message body (`tx_extra_pq_message`)
After the `0x06` tag:
```
varint len, len raw bytes    // kemCt (serializeAsBinary) — must equal ccx_pq_kem_ct_bytes() (1088)
varint len, len raw bytes    // data  (string) — ChaCha20-Poly1305 sealed blob = plaintext || 16-byte Poly1305 tag
```
Parse-time bounds (defense-in-depth, enforced in `parseTransactionExtra`):
`kemCt.size() == ccx_pq_kem_ct_bytes()`, and
`TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE (16) <= data.size() <= TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE (8192)`.
A field violating any bound makes the whole parse fail (returns `false`) rather than over-reading.
The declared length prefixes are bounded against `min(field max, bytes remaining in the stream)`
**before any allocation**, so a tiny tx with a huge varint length prefix is rejected without forcing
a large allocation (review FIX 1).

---

## 5. Transaction & Block layout

### 5.1 `TransactionPrefix`
```
varint version               // uint8, must be <= TRANSACTION_VERSION_3
varint unlockTime            // uint64
varint count, count × input  // inputs (vin); each input = tag byte + body (§3)
varint count, count × output // outputs (vout); each = varint amount + (tag byte + target body, §4)
varint len, len raw bytes    // extra (serializeAsBinary over the raw extra byte vector)
```

### 5.2 `Transaction`
`TransactionPrefix` (above) followed by positional signatures. For each input i, in order,
`getSignaturesCount(inputs[i])` `crypto::Signature` values (64 raw bytes each) are written with NO
count prefix:

| Input type | Signatures contributed |
|---|---|
| `BaseInput` | 0 |
| `KeyInput` | `outputIndexes.size()` |
| `MultisignatureInput` | `signatureCount` |
| `PqKeyInput` | 0 (inline ring sig) |
| `PqMultisigInput` | 0 (inline ML-DSA sigs) |

If `tx.signatures` is empty the signature section is omitted entirely; otherwise its layout must
match the per-input counts exactly or serialization throws.

### 5.3 `Block`
```
varint majorVersion          // uint8, must be <= BLOCK_MAJOR_VERSION_9
varint minorVersion          // uint8
varint timestamp             // uint64
32 raw bytes                 // previousBlockHash (POD Hash)
4 raw bytes                  // nonce (raw uint32, NOT varint)
Transaction baseTransaction  // miner tx (§5.2)
varint count, count × 32 raw bytes   // transactionHashes (array of POD Hash)
```

---

## 6. The legacy `0x04` message construction (for contrast)

`tx_extra_message` (`0x04`) symmetric layer: `chacha8(msg || 4 zero bytes)`, key =
`cn_fast_hash(Curve25519-ECDH-derivation || 0x80 || 0x00)`, nonce = `SWAP64LE(index)`. The 4 trailing
zero bytes are a **probabilistic owner check (~1-in-2³²), NOT a MAC** — the stream cipher is malleable
and tampering is generally undetected. This field is now treated as frozen legacy (decrypt-only) at
the serialization layer. The `0x06` PQ message and the `0x07` authenticated classical message (§4.6)
both replace this with real ChaCha20-Poly1305 AEAD integrity; `0x07` keeps the same classical ECDH key
agreement as `0x04` (but a domain-separated seed, §4.6), so it is the drop-in classical successor.

> **Send-path migration (done):** the wallet send path now *emits* the authenticated `0x07` field for
> new encrypted messages instead of the legacy `0x04` field. `src/CryptoNoteCore/CryptoNoteFormatUtils.cpp`
> (`constructTransaction`, WalletLegacy path) and `src/Wallet/WalletGreen.cpp` both build a
> `tx_extra_authenticated_message` via `append_authenticated_message_to_extra` whenever a message has a
> recipient (`tx_message_entry::encrypt == true`). The legacy `0x04` field is **decrypt-only**: it is no
> longer emitted for encrypted messages, only still produced for the rare *unencrypted broadcast*
> message (`encrypt == false`, no recipient ECDH) which cannot use the authenticated field. The receive
> path (`TransfersConsumer`, `WalletGreen::getMessagesFromExtra`, `PaymentGate/WalletService`) reads both
> `0x04` (history) and `0x07` (new) and merges the results. tx-extra is not consensus-validated, so the
> migration is backward-compatible and non-consensus. See `docs/reviews/tier1/serializer-review-response.md`.

---

## 7. The no-canonicalisation invariant (consensus-critical)

The transaction hash is taken over the **raw `tx.extra` byte vector** exactly as it appears on the
wire. `parseTransactionExtra` is a *reader*; it does NOT reorder, deduplicate, pad, or otherwise
canonicalise `extra`. Therefore:

- Two transactions with the same logical fields but different `extra` byte orderings are DIFFERENT
  transactions with DIFFERENT hashes.
- A wallet/daemon must never "rewrite" `extra` to a canonical form before hashing — it would change
  the txid. The `TransactionExtraGolden.HashIsOverRawExtraBytesNoCanonicalisation` test pins this.

---

## 8. Golden vectors (fixed examples)

These are the exact byte strings the guard asserts. Each uses the deterministic filler
`byte[i] = (base + i) & 0xff`. They encode the bare variant (tag byte + body). If any of these
change, the serializer output changed — investigate before touching the expected hex.

| Variant | Golden hex |
|---|---|
| `BaseInput` (blockIndex=0x01020304) | `ff84868808` |
| `KeyInput` (amount=1000000, idx=[1,2,3], keyImage base 0x10) | `02c0843d03010203` + keyImage32 |
| `MultisignatureInput` (amount=2000000, sigCount=2, outIdx=7, term=11) | `0380897a02070b` |
| `PqKeyInput` (amount=3000000, idx=[4,5], nullifier 8B@0xA0, ringSig 12B@0xB0) | `04c08db70102040508…0c…` |
| `PqMultisigInput` (amount=4000000, sigCount=2, outIdx=9, term=13, sigs 6B@0xC0 + 7B@0xD0) | `058092f40102090d0206…07…` |
| `KeyOutput` (key 32B@0x20) | `02` + key32 |
| `MultisignatureOutput` (2 keys @0x30/@0x40, reqSig=2, term=5) | `03022…2…0205` |
| `PqKeyOutput` (key 10B@0x50, kemCt 14B@0x60) | `040a…0e…` |
| `PqMultisigOutput` (keys 5B@0x70 + 6B@0x80, reqSig=3, term=17) | `0502057071727374068081828384850311` |

The authoritative, full-length strings live in `TestTransactionSerializationGolden.cpp`; the table
above is a human-readable digest. The test is the source of truth.
