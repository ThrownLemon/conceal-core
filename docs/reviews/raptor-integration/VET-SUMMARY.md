# Raptor integration — multi-reviewer vet (commits a1df5a1 + fixes)

Four independent reviewers on the Raptor consensus integration (`pqc/ccx-pqc` + `CryptoNoteConfig.h`).
Branch `pqc/testnet-poc`, LOCAL (not pushed). All ACTIONABLE findings fixed + re-verified; the rest are
documented mainnet/audit gates.

## Reviewers + verdicts
| Reviewer | Verdict |
|---|---|
| **Claude** (integration-correctness) | FAITHFUL to the hardened spike, no consensus regression; key-identity invariant holds, C++ contract clean, malformed input rejects cleanly, build hygiene clean |
| **Codex** (deep crypto-soundness) | consensus-sound for a resettable testnet PoC; found 1 CRITICAL + 3 HIGH (all now fixed/verified) |
| **GLM** (consult) | ABI compat / canonicality / DoS guards correct; flagged the dormant KAT tripwire (now activated) + the rand-dependency surface (noted) |
| **CodeRabbit** | 3 findings, all in VENDORED PQClean C — 2 moot, 1 OOM-only (documented) |

## Findings + resolutions
| ID | Sev | Finding | Resolution |
|---|---|---|---|
| Codex C-1 | CRIT | per-spend sign seed was deterministic (`const‖sk`) → lattice nonce reuse leaks the trapdoor after 2 spends | **FIXED** — mix fresh `OsRng` + sk + msg; nullifier unaffected (from secret), e2e re-verified |
| Codex H-1 | HIGH | `ccx_pq_sign/nullifier` accepted `sk_len ≥ SK` and truncated → wrong key → silent double-spend break | **FIXED** — require `sk_len == SK` exactly |
| Codex H-2 | HIGH | `unpack` didn't re-canonicity-check decoded `aots` → sig/txid malleability | **FIXED** — round-trip re-encode == bytes (matches `pubkey_is_canonical`) |
| Codex H-3 | HIGH | `randombytes.h` self-`#define` may override the `-D` rename | **VERIFIED non-issue** (`nm`: no undefined randombytes refs; Falcon's seeded path never calls OS randombytes; det-keygen bit-exact); build.rs comment corrected |
| Codex M-3 | MED | overlong (non-canonical) varints accepted | **FIXED** — reject overlong encodings |
| Codex M-4 | MED | `decode_ring` relies on C++ canonical check at output acceptance | **VERIFIED satisfied** — `CryptoNoteFormatUtils.cpp:407` calls `ccx_pq_pubkey_is_canonical` |
| Codex L-2 | LOW | crate description said "INSECURE STUB" | **FIXED** — now "unaudited Raptor PoC" |
| GLM | BLOCKER* | KAT determinism tripwire was dead code (never called) | **FIXED** — `ccx_pq_ringsig_selftest` now ANDs `keygen_kat_ok()` (selftest fails on drift); verified ok=1 |
| CodeRabbit | crit | vendored `fips202.c` `exit(111)` on malloc failure | **Documented** — OOM-only (≈never under Linux overcommit), liveness-not-safety (no fork), vendored PQClean; mainnet-hardening item |
| CodeRabbit | crit | vendored `rng.c` `prng_get_bytes` buffer-offset bug | **Moot** — function has ZERO callers (Falcon uses `prng_get_u8/u64`); confirmed by bit-exact KAT + verifying sigs |
| CodeRabbit | major | vendored `pqclean.c` SHAKE-ctx leak | **Moot** — `pqclean.c` is NOT in build.rs's compiled set |

(*GLM's "BLOCKER" framing is overstated for a testnet PoC — the determinism is verified-by-construction
[integer-FP, KAT sweep] — but activating the tripwire is the right hardening.)

## Re-verification after fixes
ccx-pqc builds; `abi_test` ALL PASS (linkability intact); KAT selftest ok=1; full daemon+wallet+UnitTests
build green; core consensus e2e GREEN (spend accepted → double-spend rejected → independent nullifier
accepted); wallet↔wallet PASS. (Deposit e2e: BEHAVIOR #1 ACCEPTED; full run hits the documented pre-existing
`concealwallet` flake under rapid piped FIFO commands — ML-DSA path, unchanged by this swap.)

## Deferred (testnet-acceptable → mainnet/audit gates)
Codex M-1 (loose `sig_upper_bound`, doubly-capped by the tx-size limit) · M-2 (retained demo `ringsig.rs`
dead code) · L-1 (`AssertUnwindSafe` SAFETY comment) · L-4 (runtime `ccx_pq_scheme_id()==PQ_RING_SCHEME_ID`
assert) · GLM rand-dependency surface · CodeRabbit fips202 `exit(111)` (patch vendored PQClean or use a
stack-context variant) · wire the KAT tripwire into daemon STARTUP as a hard abort. These join the standing
human-only gates (external audit, formal anonymity/unforgeability proofs, B1 calibration, `paramch_h`
ceremony, production per-spend KDF, constant-time review, cross-arch KAT) — see `raptor-integration-plan.md` §5.
