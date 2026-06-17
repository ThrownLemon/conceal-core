# v2 Transaction Wire Format (PQ) — CIP-0001 §6.2 detail (D6 draft)

> Replaces the fixed-size POD layout (32 B keys / 64 B sigs) with **length-prefixed, variable-length** fields, so PQ objects (kilobytes, scheme-dependent) fit. v1 (EC) txs are unchanged; the **transaction version** field selects v1 vs v2. Encoding follows CryptoNote conventions: **varint = LEB128**; "blob" = `varint length` + raw bytes. Status: **DRAFT**.

## Transaction (v2)
```
version            : varint   (= 2 ; distinguishes from v1)
unlock_time        : varint
input_count        : varint
inputs[]           : v2 KeyInput            (input_count of them)
output_count       : varint
outputs[]          : v2 KeyOutput           (output_count of them)
extra              : blob                   (length-prefixed)
signatures[]       : v2 RingSig blob        (one per input; see below)
```

## v2 KeyInput
```
tag                : u8       (= 0x03 ; v2 PQ key input)
amount             : varint   (PLAINTEXT — L1)
ring_size          : varint   (N ; must be >= MINIMUM_MIXIN_V2 + 1)
key_offsets[]      : varint   (N delta-encoded global output indexes)
nullifier          : blob     (PQ serial / key-image equiv; len = ccx_pq_nullifier_bytes)
```

## v2 KeyOutput
```
tag                : u8       (= 0x03 ; v2 PQ key output)
amount             : varint   (PLAINTEXT — L1)
one_time_pubkey    : blob     (PQ output key; len = ccx_pq_pubkey_bytes)
kem_ciphertext     : blob     (ML-KEM ct for stealth shared secret)
view_tag           : u8       (optional; fast scan)   [DECISION: keep?]
```

## Signatures section
```
signatures[i]      : blob     (the v2 RingSig for input i; ONE proof per input,
                               covers the whole ring — NOT one-sig-per-member)
```
This is the key structural change from v1 (which serialized `ring_size` fixed-64 B signatures per input). v2 is **one variable-length proof blob per input**, matching the logarithmic ring-sig backend (`pq_ring_sig.h`).

## Size accounting (per input/output, ring 6, ML-KEM-768)
Matches `wire-size-calc.py` + adds the varint/length-prefix overhead (≈ 1–3 B per blob/field):
- **input** ≈ `tag(1) + amount(~2) + ring_size(1) + N·offset_varint(~1.5) + nullifier(blob) + ringsig(blob)`
- **output** ≈ `tag(1) + amount(~2) + pubkey(blob) + kem(blob) + view_tag(1)`
- For concrete bytes per candidate scheme see `comparison-chart.md`.

## Validation (consensus, v2) — CIP-0001 §6.3
For each input: `ccx_pq_verify(tx_prefix_hash, ring, sig)` == OK; nullifier well-formed + unseen (spent-set insert); `ring_size >= floor`; ring members resolve to real on-chain outputs via `key_offsets`. Tx: Σin ≥ Σout + fee (plaintext); size ≤ raised `MAX_TX_SIZE`.

## Open
- `[DECISION] MINIMUM_MIXIN_V2` (ring-size floor, L1 "exceed").
- `[DECISION]` keep per-output `view_tag`? (scan speed vs size).
- `[DECISION]` exact tags / version number; whether deposits get a parallel v2 multisig layout.
- Endianness/canonicalization rules for blobs (must be canonical to keep tx hash deterministic).
