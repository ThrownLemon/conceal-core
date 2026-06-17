# Conceal Post-Quantum Migration Roadmap (corrected)

> Corrected from the team's 3-stage draft. Fixes: Stage 1 is **classic CryptoNote LSAG + plaintext amounts** (not Monero MLSAG/CLSAG + commitments); amounts stay **plaintext** by default (hiding them is a separate, costly, optional decision); the ring-sig scheme is kept **swappable** (chosen post-audit, not hard-committed to Raptor); and the missing surfaces (PQ nullifier, stealth KEM, **deposits**, consensus caps, HNDL deadline) are folded in.

```
Stage 1 — Today
  Wallet:    { EC spend, EC view }
  Address:   EC base58 (CryptoNote)
  Tx in:     EC LSAG ring sig (classic CryptoNote, mixin 5/ring 6); EC key image I = x·Hp(P)
  Tx out:    EC stealth one-time key (ECDH);  AMOUNTS PLAINTEXT (no commitments/range proofs)
  Deposits:  EC multisignature (MultisignatureOutput/Input) — ordinary EC sigs
  PoW:       hash-based (CryptoNight/Keccak)
  Status:    fully Shor-vulnerable (every EC surface)

   │  HARD FORK PREP (one coordinated fork):
   │   • new variable-length serialization + tx VERSION tag (v2)   [kills fixed 32/64-B assumptions]
   │   • RAISE consensus caps: MAX_TX_SIZE (~99 KB), FUSION_TX_MAX_SIZE (30 KB), block-zone
   │   • add lattice (PQ) keys; PQ linkable-ring-sig behind a SWAPPABLE backend (candidate, not final)
   │   • PQ stealth KEM (ML-KEM) + PQ nullifier (H(pubkey) / scheme serial) for v2
   ▼

Stage 2 — Hybrid (both tx types valid, version-gated)
  Wallet:    { EC spend/view }  +  { L-spend, L-view }
  Address:   EC (v1)  +  lattice (v2)
  Tx in:     v1 = EC LSAG (spends existing EC funds)   |   v2 = PQ linkable ring sig (new funds)
             → NOT a dual-sig on one input: existing EC outputs have no lattice key,
               so they can only be spent v1 until MOVED to a v2 output.
  Tx out:    v1 = EC stealth   |   v2 = PQ stealth (ML-KEM);   AMOUNTS PLAINTEXT both
  Nullifier: EC key image (v1)  +  PQ nullifier (v2)
  Deposits:  EC multisig (v1)  +  PQ ordinary sig (ML-DSA / Falcon) for v2     ← don't forget deposits
  PoW:       unchanged (Grover-only; optional hash-widening can wait)
  ⚠ HNDL:    pre-fork EC funds stay quantum-exposed until moved to v2 — publish a migration window

   │  DEPRECATE EC:
   │   • after height H: reject NEW v1 (EC) outputs; all new funds must be v2 (PQ)
   │   • migration deadline for moving legacy EC funds → v2 (harvest-now-decrypt-later)
   ▼

Stage 3 — Lattice CryptoNote (PQ)
  Wallet:    { L-spend, L-view } only
  Address:   lattice only
  Tx in:     PQ linkable ring signature (FINAL scheme chosen POST-AUDIT — Raptor or MatRiCT-Au);
             PQ nullifier into the spent-key index
  Tx out:    PQ stealth one-time key (ML-KEM);   AMOUNTS PLAINTEXT (default)
  Deposits:  PQ ordinary sig (ML-DSA / Falcon)
  PoW:       unchanged
  Cost:      ~18–95 KB/tx (vs ~1.2 KB today); see comparison-chart.md

   ┌─ OPTIONAL, SEPARATE DECISION (NOT required for quantum resistance) ─────────────┐
   │  Add confidential AMOUNTS (lattice commitments + range proofs = full lattice    │
   │  RingCT). Cost: ~doubles tx size to ~120 KB+/tx. Only if Conceal wants to hide  │
   │  amounts (a NEW feature Conceal doesn't have today). Bulletproofs+ CANNOT be    │
   │  used — it's discrete-log-based and Shor-broken.                                │
   └─────────────────────────────────────────────────────────────────────────────────┘
```

## Scheme-choice note (Stage 2/3 backend)
Keep it swappable; decide after audit. Measured trade-offs (ring 6, our benchmarks):
- **Raptor** — smallest/fastest at ring 6 (~17 KB/input, 0.8 ms verify) but **linear** (bad if mixin rises), **not constant-time**, and its tag is **per-signer → the CryptoNote key-image/nullifier must be redesigned**.
- **MatRiCT-Au** — logarithmic, fast verify (19 ms), and **amortizes across inputs** → best for Conceal's fusion/multi-input/deposit reality; harder integration (extract ring-sig core, one-proof-per-tx).
- **Falafl** — clean reference; no input amortization → fusion txs balloon.
- All are **unaudited research code — none ships without a security audit + testnet.**

## What this roadmap deliberately does NOT do
- Does not use MLSAG/CLSAG or Bulletproofs (Monero constructs; the latter is Shor-broken).
- Does not hide amounts by default (keeps the migration in the ~18–95 KB range, not ~120 KB+).
- Does not commit to a final ring-sig scheme before audit.
- Does not go transparent-input / no-ring (preserves CryptoNote untraceability — the privacy-coin identity).
```
