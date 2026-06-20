# PQ Constant-Time / Side-Channel — Status & Checklist

**Status: harness + CI gate in place; one real fix shipped; the remaining items are external-audit gates, not engineering.**

This tracks the constant-time (timing/cache) and side-channel posture of the post-quantum
crypto (Raptor ring-sig over Falcon-512, ML-DSA deposits, ML-KEM messages). It is a living
checklist for the team — not an audit. "Flagged" by tooling ≠ "exploitable"; the
exploitable-vs-benign call on the audit items below belongs to a side-channel specialist.

## Threat model (this scopes everything)

- **Daemon = out of scope.** The validating node does **verify-only** — no secret-key operations
  — so there is no side-channel surface on the network/consensus path.
- **Wallet = the surface**, and only against a **local** attacker (timing, cache, or power/EM).
  A software wallet defends timing + cache with **constant-time** code; **masking** (power/EM/DPA)
  matters only if/when a hardware wallet or HSM becomes a target.

## Done ✅

- [x] **ctgrind / TIMECOP harness** — valgrind memcheck poisons the secret seed; flags every
      secret-dependent branch across the Falcon C and our glue. (`ctgrind` cargo feature; the
      `ct_leakmap` test; gated off by default so normal builds never pull valgrind deps.)
- [x] **CI tripwire** — the `ctgrind (constant-time)` job runs the harness under valgrind and
      **fails on any *new* secret-dependent branch in our glue** (`raptor_falcon.c`), excluding
      the documented Falcon-internal and public-output flags. Green across the branch.
- [x] **Fixed the one real leak in our code** — `rfalcon_polymul_modq` had `if (a[i]==0) continue`,
      a data-dependent skip that leaked a secret polynomial's zero-coefficient pattern. Made
      branchless (`a[i]==0` contributes 0; identical result). Confirmed removed from the map.
- [x] **0 secret-dependent memory accesses** anywhere — no cache-timing (table-lookup) leaks.
- [x] **Determinism ⊗ constant-time both hold** — the integer-emulated FP layer is branch-free,
      so it is simultaneously deterministic (cross-platform consensus) and timing-invariant. No
      conflict between the two requirements.

## Verified-benign — no action ✅

- [x] **Gaussian sampler (`BerExp`)** — PQClean's isochronous sampler; constant-time by
      construction. Flagged by valgrind, but not a leak.
- [x] **ML-KEM / ML-DSA** (messages / deposits) — constant-time-policy implementations
      (pqcrypto / RustCrypto); not the Falcon concern. (The FO-decapsulation comparison is the
      classic risk class — covered by those impls' CT policy; reconfirm under audit.)
- [x] **Signature / public-key encoding** flags — operate on **public** outputs, not secrets.
- [x] **`rfalcon_hash_to_rq` rejection** — rejection-samples on `H1(aots)`; `aots` is the published
      linking tag (public), so the variable timing leaks nothing secret.
- [x] **Keygen-once-store** — *investigated, not needed.* Falcon `ccx_pq_keygen` appears only in
      the spend/deposit builders, coinbase, and the spend-time scan — **never in WalletGreen /
      Transfers**. The balance/incoming sync is **ML-KEM only** (CT). Falcon keys are **ephemeral
      per one-time output**, derived at spend/deposit time (when they're needed to sign anyway),
      never re-derived in a load/refresh loop. So Falcon's one-shot-keygen argument already holds
      for our usage by construction — there is no long-term key to cache.

## Open — needs a side-channel specialist + external audit ⏳

- [ ] **Bless Falcon keygen's non-CT region.** Keygen's NTRU `(f,g)` rejection + basis solve is
      documented non-constant-time. It is one-shot per key and our usage never re-derives a
      long-term key on load, so the standard argument applies — but it needs formal sign-off.
      **Do *not* rewrite keygen constant-time:** the NTRU solve is research-grade, and the perf
      cost is irrelevant (one-shot) — the rewrite is high-risk and unnecessary.
- [ ] **Bless the isochronous sampler** CT claim under audit (we rely on PQClean's construction).
- [ ] **Confirm ML-KEM / ML-DSA CT** end-to-end under audit (FO decapsulation comparison).
- [ ] **Masking decision** — only if a hardware wallet / HSM becomes a target. Masking lattice
      schemes is a large, specialized effort (and the belief-propagation / higher-order pitfalls
      are real); explicitly out of scope for a software wallet.
- [ ] **Ring-sig formal proofs** (anonymity + unforgeability) — separate from CT, same audit track.

## Bottom line

The measurable software-CT surface is **closed and now CI-guarded**. The residual is "an auditor
blesses Falcon keygen / sampler," **not new engineering** — unless we decide to target hardware
wallets, which adds the masking workstream.
