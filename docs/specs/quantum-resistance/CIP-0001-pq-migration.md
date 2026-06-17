# CIP-0001 — Post-Quantum Migration of the Conceal Spend & Anonymity Layer

| | |
|---|---|
| **CIP** | 0001 |
| **Title** | Post-Quantum Migration (ring signatures, stealth, nullifier, deposits) |
| **Status** | **Draft** |
| **Type** | Consensus (hard fork) |
| **Created** | 2026-06-17 |
| **Supersedes activation** | adds `BLOCK_MAJOR_VERSION_9` / `UPGRADE_HEIGHT_V9` |
| **Backing research** | `docs/design/quantum-resistance/*`, `docs/specs/quantum-resistance/feasibility.md` |

> This spec fixes the **engineering, consensus, serialization, and migration** precisely (grounded in conceal-core + measured prototypes). The underlying **cryptographic scheme is referenced, not reinvented** — final algorithms/parameters come from the chosen peer-reviewed scheme and an independent audit. Every genuinely-open choice is tagged **`[DECISION NEEDED]`** and consolidated in §13.

## 1. Abstract
Migrate Conceal's spend-authorization and anonymity layer from Ed25519/Curve25519 (broken by Shor) to a post-quantum, lattice-based construction, via a staged, height-gated, backward-compatible hard fork. Target privacy level **L1: keep CryptoNote untraceability and *exceed* it with larger anonymity sets, amounts remain plaintext.** Confidential amounts (L2) are an optional future extension (Appendix A).

## 2. Motivation
A cryptographically-relevant quantum computer breaks every Ed25519/Curve25519 surface in Conceal — ring signatures, key images, stealth-address ECDH, ordinary (deposit) signatures — enabling **theft, double-spend, and full retroactive deanonymization**. "Harvest-now-decrypt-later" means today's chain is already exposed for a future adversary. See `feasibility.md`. No CRQC exists yet, so this is a *prepare-deliberately* migration, not an emergency; but the wire-format and surface work should start now.

## 3. Security goals & threat model
**Adversary:** classical now + a future CRQC (poly-time ECDLP/ECDH via Shor; Grover = √ speedup on hashes only).

**Properties the migration MUST preserve or strengthen:**
- **G1 — Spend unforgeability (PQ EUF-CMA):** only the holder of the PQ spend key can authorize spending an output.
- **G2 — Double-spend soundness:** each output yields exactly one valid, deterministic, collision-free **nullifier**; replay is rejected by the spent-set index.
- **G3 — Untraceability (≥ today):** a spend reveals nothing about *which* ring member is the real input. **Anonymity set ≥ current ring 6, with support for larger rings (L1 goal).**
- **G4 — Recipient privacy:** stealth one-time addresses remain unlinkable to the recipient's public address (PQ KEM-based).
- **G5 — No inflation:** validation guarantees inputs ≥ outputs + fee. (Amounts plaintext in baseline → checked directly.)

**Out of scope (baseline):** hiding amounts (plaintext; see Appendix A / L2); PoW changes (Grover-only — §10); network-layer privacy.

## 4. Design overview
- **Privacy: L1.** Ring-based untraceability preserved; ring-size floor **raised** for a real anonymity increase. Amounts plaintext.
- **Scheme:** a **module-lattice (MLWE/MSIS) logarithmic linkable ring signature, MatRiCT-Au lineage**, exposed behind a **swappable backend interface** (§5.3) so the final scheme is audit-gated, not hard-coded. Chosen for: logarithmic ring scaling (cheap big rings = exceed), input amortization (suits Conceal's fusion/multi-input txs), a native serial-number nullifier, and no trusted setup. `[DECISION NEEDED: final scheme + parameters, post-audit]`
- **Migration:** staged, height-gated, backward-compatible (§8), per `migration-roadmap.md`.

## 5. Cryptographic components (interface-level)
> Algorithms below are specified as **interfaces + invariants**. Concrete constructions come from the chosen scheme spec + audit. Sizes are measured prototype figures (`prototype-benchmarks.md`), not final.

### 5.1 Keys
- **PQ spend key** `(sk_spend, pk_spend)` and **PQ view key** `(sk_view, pk_view)` — module-lattice keypairs. `[DECISION NEEDED: security level — 128 vs 192-bit]`
- Address = encoding of `(pk_spend, pk_view)` + network prefix + checksum. New PQ address version/prefix. `[DECISION NEEDED: address format/encoding]`

### 5.2 Stealth one-time output keys (recipient privacy, G4)
Replace the Curve25519 ECDH derivation with a **post-quantum KEM** (ML-KEM / FIPS 203):
- Sender: `(ct, ss) ← KEM.Encaps(pk_view)`; derive one-time output key material from `ss` (+ output index, domain-separated hash); publish `ct` in the output.
- Recipient: `ss ← KEM.Decaps(sk_view, ct)`; re-derive; scan via a view-tag byte for efficiency.
- Per-output wire cost: KEM ciphertext (~1.1 KB ML-KEM-768) + PQ output key. `[DECISION NEEDED: ML-KEM param + view-tag length]`

### 5.3 PQ linkable ring signature (spend auth + anonymity, G1/G3) — swappable backend
Interface every backend MUST implement:
```
RS.KeyGen()                         -> (sk, pk)            // one-time output key
RS.Sign(msg, ring[pk_0..pk_{N-1}], sk, idx) -> sigma       // msg = tx_prefix_hash
RS.Verify(msg, ring[pk_0..pk_{N-1}], sigma) -> bool
RS.Nullifier(sigma) | RS.Tag(sk, pk)        -> nf          // deterministic per spent output
```
Invariants (consensus-binding): signature is over **`tx_prefix_hash`** (binds inputs+outputs+extra); ring members are **real on-chain outputs** referenced by global index; verification cost bounded for DoS. Backend = MatRiCT-Au lineage initially. `[DECISION NEEDED: final backend + params]`

### 5.4 PQ nullifier (double-spend, G2)
- A **deterministic serial number** per spent output (the scheme's `serialgen`, or `H(pk_oneTime)` with the membership proof binding it), inserted into the existing spent-set index (`m_spent_keys` equivalent).
- MUST be: deterministic in the output, unique, collision-free, non-malleable (one output cannot yield two valid nullifiers — replaces the Ed25519 subgroup check at `Blockchain.cpp:2366`). `[DECISION NEEDED: nullifier construction]`

### 5.5 Hashing / domain separation
Keccak/SHAKE for Fiat-Shamir, hash-to-point, view-tags, nullifier derivation, all **domain-separated** per use. Grover-only → 256-bit outputs adequate.

## 6. Consensus & serialization
### 6.1 Activation
- New `BLOCK_MAJOR_VERSION_9`; `UPGRADE_HEIGHT_V9 = ` `[DECISION NEEDED: height]`. Pre-height blocks/txs unchanged; post-height rules per below.

### 6.2 New transaction version (v2) — variable-length wire format
- The fixed-size POD assumptions (`PublicKey`/`KeyImage` 32 B, `Signature` 64 B) are replaced by **length-prefixed variable-length fields** for v2. New tx version tag distinguishes v1 (EC) from v2 (PQ).
- v2 `KeyInput`: input tag, amount (plaintext varint), **PQ nullifier (var-len)**, ring global-index list, **PQ ring signature blob (var-len)**.
- v2 `KeyOutput`: output tag, **PQ one-time key (var-len)**, amount (plaintext varint), **KEM ciphertext (var-len)**.
- Exact byte layout + length-prefix encoding: `[DECISION NEEDED: finalize TLV layout]` (see `comparison-chart.md` for size accounting).

### 6.3 Validation rules (v2)
A v2 tx is valid iff: every input's `RS.Verify` passes over the referenced ring at `tx_prefix_hash`; every nullifier is well-formed and **unseen** (spent-set); ring size ≥ floor (§6.4); Σ input amounts ≥ Σ output amounts + fee (G5); tx size ≤ cap (§6.5).

### 6.4 Ring size (L1 — exceed)
- Raise the mixin floor for v2: `MINIMUM_MIXIN_V2 = ` `[DECISION NEEDED: e.g. 15 → ring 16]` (today's `MINIMUM_MIXIN = 5`). Logarithmic scheme makes larger rings ~flat-cost.

### 6.5 Consensus parameter changes (required — current PQ-incompatible values)
| Param | Today | v2 (proposed) |
|---|---|---|
| `CRYPTONOTE_MAX_TX_SIZE_LIMIT` | ~99 KB | `[DECISION NEEDED: e.g. 1–2 MB]` |
| `FUSION_TX_MAX_SIZE` | 30 KB | `[DECISION NEEDED: raise; + redesign fusion]` |
| `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE` | 100 KB | `[DECISION NEEDED: e.g. 1 MB]` |
Block size stays **dynamic** (`max = 2× median`, median floored at the zone) — throughput self-adjusts; these caps are the real walls (see `comparison-chart.md`).

## 7. Deposits (Conceal-specific)
Conceal's term-deposit path uses `MultisignatureOutput`/`Input` with **ordinary signatures — also Shor-broken**. v2 deposits MUST use a **PQ ordinary signature** (ML-DSA / Falcon, FIPS 204/206-track). `[DECISION NEEDED: ML-DSA vs Falcon + params]`

## 8. Migration mechanics (staged)
Per `migration-roadmap.md`:
- **Stage 2 (Hybrid):** v1 (EC) and v2 (PQ) txs both accepted, version-gated. Wallets hold both keypairs and scan both. Legacy EC outputs spend v1 until **moved** to v2.
- **Stage 3 (Deprecate EC):** after height `H_deprecate` `[DECISION NEEDED]`, reject **new** v1 outputs; all new funds v2.
- **Legacy-fund migration:** a normal v2 tx that spends v1 inputs into v2 outputs. **Publish a migration deadline** (HNDL) `[DECISION NEEDED: deadline policy for un-migrated funds]`.

## 9. Backward compatibility
Pre-`UPGRADE_HEIGHT_V9` rules untouched. Old nodes/wallets cannot validate v2 → MUST upgrade before activation; daemons reject v2 before the height. Checkpoints span the fork.

## 10. Proof of Work
Unchanged. Grover gives only a √ speedup on Keccak/CryptoNight; 256-bit outputs remain adequate. Optional future hash-widening is out of scope here.

## 11. Test vectors & verification (required deliverables)
- **KATs:** deterministic test vectors (keygen, stealth derivation, sign/verify, nullifier) so spec + implementation agree byte-for-byte. *(TBD — produced with the reference implementation.)*
- Unit + integration tests; fuzzing of the v2 deserializer; ASan/UBSan; **constant-time review** of the signing path.
- **Long-running testnet** + bug bounty before mainnet activation; activation kill-switch if a flaw is found before `UPGRADE_HEIGHT_V9`.

## 12. Implementation language, reference implementation & audit

### 12.1 Language: Rust crypto module + C-ABI FFI (the `librustzcash` model)
- The new PQ crypto (ring signature, stealth KEM, nullifier, deposit signature) is implemented in **Rust**, compiled to a **static library with a C ABI** (header via `cbindgen`), and linked into the **unchanged C++11 `conceald`** across the FFI boundary. Rationale: memory safety on consensus-critical crypto (eliminates the C/C++ bug class that = silent theft/forks); a maturing Rust PQ ecosystem (`ml-kem`, `ml-dsa`, `pqcrypto`, `subtle` for constant-time); and the proven precedent of **Zcash's `librustzcash` called from C++ `zcashd`** — the same C++-chain-plus-Rust-crypto situation.
- The **swappable `IRingSignature` backend (§5.3) is defined at the C-ABI seam** — backends (MatRiCT-Au lineage, etc.) sit behind one stable header.
- **Build integration:** `cargo` builds the static lib; CMake invokes it and links the archive + generated header into the existing C++ targets. `[DECISION NEEDED: cargo↔CMake wiring; MSRV; vendoring/offline build for reproducibility]`
- **Scope guard (hard rule):** Rust is **only** the crypto module + its FFI shim. The daemon, P2P, RPC, serialization, and wallet stay **C++11** (per repo policy — do not rewrite `conceald` in Rust).
- **Crate reality:** ML-KEM / ML-DSA / Falcon have solid Rust crates (covers stealth + deposits). A production lattice **linkable ring signature** (MatRiCT-Au) has **no shippable Rust crate** → it is **new implementation work** (clean, constant-time) — which is required regardless of language, since the research C is unaudited and not constant-time. `[DECISION NEEDED: build vs commission vs port the ring-sig crate]`

### 12.2 Reference implementation & audit
- Chosen scheme integrated behind the FFI backend; **never in-house-from-scratch crypto on mainnet.**
- **Independent cryptographic audit** of (a) the scheme adaptation/parameters and (b) the constant-time Rust implementation + the FFI boundary — **gating mainnet activation.**

## 13. Open decisions register
1. Final ring-sig scheme + parameters (post-audit). Lead: MatRiCT-Au lineage.
2. Security level (128 vs 192-bit).
3. PQ address format/encoding + version prefix.
4. ML-KEM parameter + view-tag length (stealth).
5. Nullifier construction.
6. v2 TLV wire layout (exact bytes).
7. `MINIMUM_MIXIN_V2` (target ring size for L1 exceed).
8. New values for `MAX_TX_SIZE`, `FUSION_TX_MAX_SIZE`, block zone; fusion redesign.
9. `UPGRADE_HEIGHT_V9`, `H_deprecate`, legacy-fund migration deadline.
10. Deposit PQ signature (ML-DSA vs Falcon).
11. L1 vs L2 (amount privacy) — baseline = L1; L2 deferred (Appendix A).
12. Language **= Rust crypto module + C-ABI FFI (decided, §12)**; open: cargo↔CMake wiring, MSRV, and **build-vs-commission-vs-port** the lattice ring-sig crate (no shippable Rust crate exists).

## Appendix A — L2: confidential amounts (optional, deferred)
Hiding amounts post-quantum = **lattice commitments + lattice range proofs** (full lattice RingCT; MatRiCT-Au provides this natively). Cost: ~doubles tx size (~120 KB/tx vs ~18–40 KB for L1). **`Bulletproofs`/`Bulletproofs+` MUST NOT be used — discrete-log-based, Shor-broken.** Not required for quantum resistance; a separate privacy-feature decision. If adopted, replaces plaintext amounts with commitments and adds a balance proof to §6.3 (Σ checked in zero-knowledge instead of directly).

## References
See `docs/design/quantum-resistance/` (feasibility, ringsig design, prototype benchmarks, comparison chart, migration roadmap) and the cited IACR ePrints therein (MatRiCT 2019/1287, MatRiCT-Au 2022/142, NIST FIPS 203/204/205).
