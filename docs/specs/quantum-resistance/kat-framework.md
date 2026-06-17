# Known-Answer Tests (KAT) framework — CIP-0001 §11 (B4 draft)

> Deterministic test vectors so the spec, the Rust crypto module, and any independent implementation agree **byte-for-byte**. Format defined now; crypto vectors finalized with the chosen scheme.

## Format (JSON lines, one vector per record)
```json
{ "kind": "<serialization|kem|sign|ringsig|nullifier>",
  "scheme_id": <u32>, "params": "<name>",
  "input": { ... fixed inputs incl. fixed seeds ... },
  "output": { "<field>": "<hex>", ... },
  "notes": "" }
```
Each vector is reproducible from `input` alone (fixed seeds → fixed outputs).

## Coverage
| Layer | Deterministic now? | Status |
|---|---|---|
| **v2 serialization** (tx TLV encode/decode) | **Yes** — no randomness | **available now** — `spike/pqc/cpp/v2ser.cpp` round-trips deterministically; emit fixed tx → fixed serialized hex |
| **Stealth KEM** (ML-KEM-768) | with seeded `KeyGen`/`Encaps` | available (FIPS 203 has KATs; wrap via FFI with fixed seed) |
| **Deposit sig** (ML-DSA) | with seeded keygen | available (FIPS 204 KATs) |
| **Ring sig + nullifier** (final scheme) | needs seeded keygen in chosen backend | **deferred to scheme/audit (C1)** |

## What's blocking full crypto KATs
`pqcrypto` (used in the spike) keygen pulls internal randomness — deterministic KATs need a **seeded keygen** entry point. The chosen production backend (CIP §5.3) MUST expose seedable keygen (`ccx_pq_keygen(seed,...)` already takes a seed) so KATs are reproducible. NIST FIPS 203/204/205 ship official KATs to validate the KEM/sig primitives directly.

## Immediate deliverable (doable without the final scheme)
**Serialization KATs:** fix a canonical v2 tx (fixed field values + fixed-fill blobs), serialize, record the hex + total size. Any implementation must reproduce it. This pins the **wire format** (the consensus-critical encoding) independently of the crypto choice — and the `v2ser` round-trip already proves the encoder/decoder agree.

## Open
- `[DECISION]` canonical-encoding rules (blob length-prefix, varint, field order) must be frozen for KATs to be stable — see `wire-format-v2.md`.
- Crypto KATs land with the chosen backend + its seedable keygen.
