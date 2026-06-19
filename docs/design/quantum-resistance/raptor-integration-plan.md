# Raptor integration plan — swap the demo stand-in ring-sig for clean-room Raptor

*Ordered port plan (multi-agent integration-surface map + verified synthesis, 2026-06-20). Replaces
conceal-core's demo-grade in-house lattice ring-sig stand-in (`pqc/ccx-pqc/src/ringsig.rs`,
SCHEME_ID `0xC0DE0004`) with the clean-room **Raptor** implementation (built + hardened isolated spike
at `~/raptor-spike` on WSL, same `ccx_pq_*` C ABI). **Target branch `pqc/testnet-poc` — LOCAL, NOT
pushed.** Every choice below (SCHEME_ID value, ring sizes, FP strategy) is a **provisional default
awaiting team + external-audit consensus**, never "decided." This wires an **UNAUDITED** research
construction into consensus-shaped code on a **resettable testnet** — it does NOT make conceal-core
mainnet-PQ-ready (see audit gates, §5).*

## 0. Verified facts that shape the plan
- **Current PK = 6144 B** (`ringsig::PK_BYTES = K*N*4 = 6*256*4`, `ringsig.rs:473`), surfaced via
  `ccx_pq_pubkey_bytes()`. Raptor PK = **896 B** (`spike abi.rs:25`) — a shrink, but still a
  wire-format change for `PqKeyOutput.key`.
- **Raptor SCHEME_ID = `0x52415054` ("RAPT")** in the spike, vs current `0xC0DE0004`. Pin deliberately;
  recommend adopting the spike's value (avoids spike-vs-prod KAT divergence) — *provisional default*.
- **Seckey 32 → 48 B** (wallet-local seed, never on-chain; all C++ `ccx_pq_seckey_bytes()` allocations
  already runtime-queried).
- **Nullifier stays 32 B** in both (`SHAKE256(aots)` for Raptor); confirmed opaque end-to-end → **no
  spent-set changes**.
- **Raptor ring-6 sig = 9,719 B** vs stand-in 43,040 B — both fit the 256 KB sign buffers + 99.4 KB tx
  limit. The sig-size *formula* changes but is comment-only, never enforced in C++.
- **The spike already vendors Falcon C + a working `build.rs`** — Phase 1 is a *transplant*, not
  greenfield. Current `ccx-pqc` is pure-Rust (no build.rs/csrc/vendor).
- **FP-determinism — RESOLVED at build level (the "native double" premise was a misread).** The vendored
  PQClean falcon-512 "clean" variant is integer-FP only (`typedef uint64_t fpr`, no `FALCON_FPNATIVE`/`FPEMU`
  toggle; the old `build.rs` define was a dead no-op). Verified (code + 7-config `-ffast-math`-invariant KAT
  sweep). So **no `build.rs` FP change is needed** and the SCHEME_ID pin is NOT gated on an FP fix. Only residual:
  a cross-arch (aarch64/MSVC) KAT confirmation run (belt-and-braces, §3).
- **Map correction:** the "1 hardcoded C++ constant to fix" (`PQ_KEM_PUBLIC_KEY_SIZE`) is an **ML-KEM
  red herring** — Raptor doesn't touch it. So Phase 4 collapses into Phase 3 (only the SCHEME_ID const).

## Phase 1 — Build/vendoring: Falcon C + Raptor Rust into `pqc/ccx-pqc`
Transplant from `~/raptor-spike` (CMake invocation unchanged — `cc` links the `.o`s into `libccx_pqc.a`):
1. Create `pqc/ccx-pqc/vendor/falcon/` — copy the 18 vendored Falcon files verbatim (keep `LICENSE.falcon`, MIT/CC0; record provenance).
2. Create `pqc/ccx-pqc/csrc/raptor_falcon.c` (the clean-room shim). Leave `abi_test.c` out.
3. Create `pqc/ccx-pqc/build.rs` — port from the spike. **Use the emulated-FP define (not `FALCON_FPNATIVE`)** once the FP task lands (§3).
4. `Cargo.toml`: add `[build-dependencies] cc`, `[dependencies] rand`/`rand_chacha` (verify no clash with the exact-pinned `ml-kem`/`ml-dsa`/`hybrid-array`); keep `panic="unwind"` (FFI guard) + `crate-type=["staticlib"]`.
5. Copy `raptor.rs`, `falcon_ffi.rs`, the relevant `abi.rs` body into `src/`. Don't import the spike's `src/bin/*`.
6. Re-pin `Cargo.lock` after deps settle.
- **Gate:** `cargo build --release` green on WSL; `nm libccx_pqc.a | grep -E 'ccx_pq_sign|falcon'`.

## Phase 2 — Swap the `ccx_pq_*` impl in `lib.rs` (ABI unchanged → no C++ call-site changes)
1. `lib.rs`: repoint `PK/SK/NF/ring_sig_size()` to Raptor; rewire `ccx_pq_keygen/nullifier/sign/verify/pubkey_is_canonical` to `raptor::*`/`abi::*`. **Preserve `ffi_guard()` panic-catch + the i32 0/negative contract** (a panic across FFI = UB).
2. `ringsig.rs`: **retire, don't delete** (keep behind `#[cfg(feature="legacy_ringsig")]` for A/B selftests; remove in a later cleanup — immutability-of-reference).
3. `pq_ring_sig.h`: no signature changes; update the size/scheme comments only.

## Phase 3 (+4 collapsed) — SCHEME_ID / wire bump
1. `src/CryptoNoteConfig.h:191` — `PQ_RING_SCHEME_ID` → chosen value (must equal `ccx_pq_scheme_id()` exactly or every PQ address parse fails).
2. `CryptoNoteConfig.h:199-201` — update the `sig_bytes` comment; re-confirm `PQ_MAX_RING_SIZE=8` headroom (Raptor ring-8 ≈ 12-13 KB, far under the tx limit).
3. **No** change at `CryptoNoteBasicImpl.cpp:124` (ML-KEM, not ring-sig). **No** serialization-code change (length-prefixed, variant `0x4`, absorbs new sizes). On-chain bytes differ → **testnet reset**.

## Phase 5 — Nullifier confirm (verify, don't edit)
Opaque 32-byte blob throughout `m_spent_pq_nullifiers` (pre-check/bind/insert/rollback/rebuild/persist). Raptor nullifier = 32 B, same. Action: confirm `recoveredNf == txin.nullifier` on a Raptor sig (covered by the Phase 6 round-trip test).

## Phase 6 — Tests / golden vectors
1. `pqc/tests/tx_roundtrip.cpp` — replace magic numbers (`ringSig 21104`, `key 1312→896`, assertion) with `ccx_pq_*_bytes()`/sign-then-measure.
2. `tests/UnitTests/TestTransactionSerializationGolden.cpp` — synthetic fixed-size payloads → hex should be **unchanged** (envelope, not size). Re-run, update only if it actually changes; don't pre-emptively rewrite.
3. `pqc/test_pqc.cpp` — auto-adapts; primary fast Raptor smoke.
4. Repoint the `ccx_pqr_*` selftests (forgery/soundness/ntt_equiv) to Raptor's adversarial harnesses + the KAT tripwire (the NTT-equiv test is stand-in-specific → replace with the keygen-KAT digest).
5. Shell e2e (`pqc/*.sh`) — **no edits** (RPC/wallet-level, scheme-agnostic); they are the acceptance gate.

## 3. FP-determinism — RESOLVED at build level (no longer a prerequisite) `[cross-arch confirm pending]`
The premise that Falcon keygen is non-deterministic (native `double`) was a **misread** and is corrected:
the vendored PQClean falcon-512 "clean" variant is **integer-FP only** (`typedef uint64_t fpr`; zero real
`double`/`float` arithmetic; no `FALCON_FPNATIVE`/`FPEMU` conditional — the old `build.rs` define was a dead
no-op). **Verified independently** (code inspection + a 7-config keygen-KAT sweep — `-O0`/`-O3`/`-ffast-math`/
`-ffp-contract=fast`/`-march` all yield the *identical* digest, which is direct proof there's no native FP in
the path). So keygen+signing are **bit-identical across compilers/opt/arch by construction**; there is **no
`build.rs` FP change to make**, and **Phase 3's SCHEME_ID pin is NOT gated on an FP fix.** Residual
(belt-and-braces, NOT a blocker): run an actual **aarch64/MSVC** build and confirm the KAT digest matches x86
(the `uint64` argument is sound — 32-bit targets use SW 64-bit helpers but still produce identical results).
Keep `assert_keygen_kat()` as the CI/boot tripwire (now expected to PASS everywhere). Falcon **constant-time /
side-channel** review remains separately open (that is about timing, not determinism).

## 4. Build + test sequence (WSL `100.100.90.103`, `.claude/wsl-build.sh`)
```
# 1. Phase 1 gate
ssh 100.100.90.103 'cd ~/conceal-core/pqc/ccx-pqc && cargo build --release && nm target/release/libccx_pqc.a | grep -E "ccx_pq_sign|falcon"'
# 2. Full build with tests
.claude/wsl-build.sh clean && .claude/wsl-build.sh build      # -DBUILD_TESTS=ON -DSTATIC=ON, -j16
# 3. Crypto smoke
ssh 100.100.90.103 'cd ~/conceal-core/build && ./pqc/test_pqc && ./pqc/tx_roundtrip'
# 4. Unit subset (respect the baked-in gtest skip list)
ssh 100.100.90.103 'cd ~/conceal-core/build && ./tests/UnitTests --gtest_filter="*Pq*:TransactionSerializationGolden.*"'
# 5. e2e on a fresh (resettable) testnet — wipe data dir between Raptor / pre-Raptor runs
ssh 100.100.90.103 'cd ~/conceal-core && pqc/run-poc-testnet.sh && pqc/verify-wallet-spend.sh && pqc/verify-wallet-w2w.sh && pqc/verify-pq-deposit.sh && pqc/verify-deposit-freeze.sh'
# 6. (FP gate) build emulated-FP crate on x86_64 + a 2nd target; assert equal KAT_KEYGEN_DIGEST
```
Load-bearing consensus checks: `run-poc-testnet.sh` double-spend rejection + ring-sig accept/reject.

## 5. Stays GATED for the external audit — NOT mainnet-ready
- **Raptor's cryptographic soundness** (linkability/anonymity/unforgeability proofs + the clean-room impl) needs an external cryptographer. In-crate adversarial tests are necessary, not sufficient.
- **FP-determinism** completed + cross-arch-verified before any chain is canonical.
- **Falcon constant-time / side-channel** review of the signing path.
- **Parameter / size review at consensus scale** (ring size, tx-size, verify-CPU-DoS under adversarial inputs).
- **SCHEME_ID as a permanent commitment** — mint only against the deterministic, audited build.
- **Wallet spend-path completeness** re-confirmed under Raptor.
