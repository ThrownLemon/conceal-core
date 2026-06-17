# Conceal PQ Migration — Program Tracker

Single source of truth for decisions + tasks. **Owner key:** TEAM (Conceal core/community) · DEV (engineering) · ME (Claude — docs/grounding/build) · EXT (external cryptographers/auditor). Status: ☐ open · ◐ in progress · ☑ done.

> Locked so far: privacy = **keep-or-exceed** → **L1** (bigger rings, plaintext amounts; L2 amount-hiding deferred). Scheme lineage = **MatRiCT-Au** (swappable, audit-gated). Language = **Rust crypto + C-ABI FFI** into the unchanged C++ daemon. Migration = staged hybrid → deprecate EC → lattice-only. Spec = `CIP-0001-pq-migration.md`.

## A. Decisions (CIP-0001 §13) — mostly TEAM
| ID | Decision | Owner | Status | Notes |
|---|---|---|---|---|
| D1 | Final ring-sig scheme + parameters | TEAM+EXT | ☐ | Lead: MatRiCT-Au lineage; confirm post-audit |
| D2 | Security level (128 vs 192-bit) | TEAM | ☐ | 128 likely enough; 192 = margin |
| D3 | PQ address format + version prefix | ME draft → TEAM | ☐ | dual address during hybrid |
| D4 | ML-KEM param + view-tag length (stealth) | TEAM | ☐ | ML-KEM-768 default |
| D5 | Nullifier construction (serial / H(pk)) | TEAM+EXT | ☐ | must map to spent-set index |
| D6 | v2 TLV wire layout (exact bytes) | ME draft → DEV | ◐ | **drafted** `wire-format-v2.md`; finalize tags/view-tag/canonicalization w/ DEV |
| D7 | `MINIMUM_MIXIN_V2` (target ring size) | TEAM | ☐ | L1 "exceed" — e.g. ring 16/64 |
| D8 | New `MAX_TX_SIZE` / `FUSION_TX_MAX_SIZE` / block-zone + fusion redesign | TEAM (ME models) | ☐ | current 99KB/30KB/100KB all too small |
| D9 | `UPGRADE_HEIGHT_V9`, `H_deprecate`, migration deadline | TEAM | ☐ | HNDL policy for un-migrated funds |
| D10 | Deposit PQ signature (ML-DSA vs Falcon) | TEAM | ☐ | multisig path |
| D11 | L1 vs L2 (amount privacy) | TEAM | ☑ | **L1 baseline; L2 deferred** |
| D12 | Language (Rust + C-ABI FFI) | DEV | ☑ | **decided**; open: cargo↔CMake, MSRV, build-vs-commission ring-sig crate |

## B. Grounding / build — ME (buildable now, on WSL)
| ID | Task | Owner | Status | Notes |
|---|---|---|---|---|
| B1 | **Level-2 integration spike** — v2 variable-length serialize + validate in a modified `conceald` | ME | ☐ | surfaces every fixed-size landmine; produces first KATs |
| B2 | **FFI proof-of-concept** — Rust static lib ↔ C ABI ↔ C++ test, in our build | ME | ☑ | **proven on WSL** (Rust sha3 crate → C ABI → C++ links + runs, rc=0). Next: cargo↔CMake wiring + swap sha3 → ml-dsa/ml-kem |
| B3 | `IRingSignature` C-ABI header (keygen/sign/verify/nullifier) | ME draft → DEV | ☑ | **drafted** `interfaces/pq_ring_sig.h` — two-call var-len pattern; finalize at audit |
| B4 | KAT / test-vector framework | ME | ☐ | deterministic; spec+impl agree byte-for-byte |
| B5 | Wire-size + storage model (done; refine per chosen params) | ME | ◐ | `wire-size-calc.py` |

## C. The crypto — the LONG POLE (gated; needs cryptographers + budget)
| ID | Task | Owner | Status | Notes |
|---|---|---|---|---|
| C1 | **Audited, constant-time Rust lattice linkable ring sig** (build / commission / port) | EXT+DEV | ☐ | **no shippable Rust crate exists — critical path** |
| C2 | ML-KEM / ML-DSA / Falcon Rust integration (stealth + deposits) | DEV | ☐ | solid crates exist — easy |

## D. Process / review — EXTERNAL + community
| ID | Task | Owner | Status | Notes |
|---|---|---|---|---|
| P1 | Independent cryptographic audit (scheme + CT impl + FFI) | EXT | ☐ | **gates mainnet**; needs budget + vendor |
| P2 | Cryptographer peer review of the scheme adaptation | EXT | ☐ | |
| P3 | Long-running testnet + bug bounty; activation kill-switch | TEAM+DEV | ☐ | never mainnet without this |
| P4 | CIP governance — community review/approval of params + activation | TEAM | ☐ | |

## E. Ecosystem / ops (easy to forget — real blockers)
| ID | Task | Owner | Status | Notes |
|---|---|---|---|---|
| E1 | Fee model under 20–95 KB txs | TEAM | ☐ | |
| E2 | Signature pruning / storage strategy | DEV | ☐ | softens chain-growth |
| E3 | Wallet UX for hybrid dual-key + migration prompts/deadline | DEV | ☐ | |
| E4 | Exchange / integrator coordination (new address format, dual addresses) | TEAM | ☐ | |
| E5 | **Hardware-wallet PQ support** assessment | TEAM | ☐ | Ledger/Trezor lattice support is immature — real dependency |

## Critical path (what actually gates mainnet)
Decisions (A) → Grounding (B, me, now) → **Audited Rust crypto (C1) → Audit (P1) → Testnet (P3)** → mainnet. Everything in B/E is parallelizable now; **C1 + P1 are the long pole** (months, money, external).
