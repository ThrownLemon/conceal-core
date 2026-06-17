# v2 PQ Address Format — proposal (D3 draft)

> `[DECISION]` for the team. Current Conceal address = Base58 of `prefix || spend_pubkey(32) || view_pubkey(32) || checksum(4)`. PQ public keys are **kilobytes**, so the address is far larger — the main UX consideration.

## v2 address payload
```
version_prefix     : new CCX PQ prefix (distinct from v1, so wallets route v1/v2)   [DECISION]
scheme_id          : varint   (matches ccx_pq_scheme_id() — future scheme agility)
spend_pubkey       : PQ spend public key (scheme-dependent; ~1–4 KB)
view_pubkey        : PQ view / KEM public key (ML-KEM-768 = 1184 B)
checksum           : 4 bytes (Keccak truncation, as today)
```

## Encoding `[DECISION]`
- **Base58 (status quo):** consistent with v1, but a ~3–6 KB key → a **~4–8 KB Base58 string** (unwieldy to copy/paste, QR-heavy).
- **Bech32m / base32:** error-detecting, more QR-friendly, but a format change.
- **Recommendation:** given the size, prefer a **container with a short human-facing alias + a longer canonical blob** (e.g., display a truncated id + checksum; full key exchanged via payment URI / QR / address book). Pure copy-paste of multi-KB strings is poor UX.

## Hybrid period
- Wallets hold **both** a v1 (EC) and a v2 (PQ) address. `[DECISION]` whether to publish a **single dual address** (concatenated, lets senders pick v1/v2) or two separate addresses.
- Integrations key off `version_prefix`.

## Notes
- The `scheme_id` field future-proofs against a later scheme swap (CIP §5.3 swappable backend) without a new address version.
- QR capacity: a ~3 KB key fits a QR (max ~3 KB at low EC level) but is dense; the alias/URI approach sidesteps this.
- `[DECISION]` exact prefix bytes, encoding, dual-vs-split address, alias scheme.
