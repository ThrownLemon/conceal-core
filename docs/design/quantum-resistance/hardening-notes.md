# PQ PoC — hardening status & accepted limitations (CIP-0001)

Single reference for the documented hardening decisions on `pqc/testnet-poc`. "Closed" = fixed in
code; "Documented" = a deliberate accepted limitation (fixing it would be riskier than the gap for a
testnet PoC), with the path to close it noted.

## Closed (fixed in code)

- **Wallet-file at-rest crypto** — Argon2id + XChaCha20-Poly1305 (v7), CSPRNG salt/nonce (OsRng),
  KDF cost bounds, atomic save, load-failure no longer destroys keys. (Tier-1 round.)
- **Wallet-file PREFIX authentication (W11)** — v8 adds a keyed MAC over the prefix (view/spend key
  records), stored in the AEAD-sealed suffix, verified on load → prefix rollback/tamper now detected.
  Migrate-on-save v7→v8. (This round — see `wallet-v2-impl.md`.)
- **`get_pq_outputs` DoS** — capped request `amounts` + per-amount output count, `TransactionIndex`
  bounds-checked before deref, walk under `m_blockchain_lock`. (Wallet-spend review pass.)
- **PQ ring-sig**: canonical-pubkey acceptance check, `checked_mul` ring bound, NTT-equivalence
  in-tree test, pinned PQ crates + `Cargo.lock`, `SCHEME_ID` bump. (Tier-1 round.)
- **Relative-offset overflow** — commented at `CryptoNoteFormatUtils.cpp:relative_output_offsets_to_absolute`:
  the unchecked `uint32` running sum is non-exploitable (honest deltas can't wrap; a wrapped PQ index
  resolves a different ring key → `ccx_pq_verify` fails AND nullifier mismatch). Left unchecked to
  preserve exact legacy wire behavior; flagged for audit.

## Documented (accepted limitation — NOT fixed, with rationale)

- **tx-extra parser has no `default:` case** (`TransactionExtra.cpp::parseTransactionExtra`). An unknown
  tag makes the loop reinterpret following bytes as tags → parse desync vs nodes that know the tag.
  This is the LEGACY design and affects EVERY tx-extra tag (0x01–0x07), not just the PQ ones. Adding
  `default: return false` would reject historical/foreign tx-extra that today fails soft — a consensus
  behavior change. **Fix path:** a future height-gated, length-delimited container format for unknown
  tags so they can be skipped safely. Do NOT add a blanket default-reject without a coordinated fork.
  (Also in `docs/reviews/tier1/serializer-review-response.md`.)
- **Lattice linkable ring signature is EXPERIMENTAL / testnet-only / unaudited / not constant-time.**
  The `K=L=6` parameters are a heuristic, not estimator-calibrated; the modular arithmetic branches on
  secret data. **Mainnet blocker** — requires a professional cryptographic audit + parameter
  calibration + a constant-time implementation, OR porting an audited compact lattice scheme. Out of
  scope for the PoC by design. (See `ringsig-hardening.md`.)
- **Testnet PQ stealth uses ONE fixed `PQ_TESTNET_KEM` keypair** ("Option B") for the bootstrap
  coinbase outputs. Per-wallet seed-derived KEM keys are used for wallet↔wallet transfers; the fixed
  key only seeds the demo. Mainnet would mint to per-recipient keys only.
