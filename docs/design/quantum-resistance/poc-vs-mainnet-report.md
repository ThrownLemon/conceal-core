---
title: "Conceal post-quantum migration — PoC vs. mainnet"
---

# Conceal post-quantum migration — PoC vs. mainnet (decision report)

*CIP-0001. Branch `pqc/testnet-poc` (not pushed; local for human review). **Decision: keep full
ring untraceability (Option A) — MatRiCT-Au is the best-fit production scheme.** Numbers are tagged
**[measured]** (live on the testnet binaries — `measured-numbers.md`), **[team]** (team evaluation of
production candidates, Ryzen 9 5950X / Conceal's wire formula at chain-avg 2.39-in/2.22-out, mixin-5/
ring-6, ~1.16 tx/block), **[constant]**, or **[published]** ([wiki](https://conceal.network/wiki/doku.php?id=about)).
Companion docs: [`STATUS.md`](STATUS.md), [`measured-numbers.md`](measured-numbers.md),
[`ringsig-hardening.md`](ringsig-hardening.md), [`hardening-notes.md`](hardening-notes.md).*

## 1. Executive summary

Two separate things were done and they meet in the middle:

1. **The PoC** proves an **end-to-end PQ privacy stack integrates into Conceal** — PQ ring spends,
   ML-KEM-768 stealth, **ML-DSA-65 deposits** (Conceal's banking), **ML-KEM messages** (Conceal's
   messenger), a v8 authenticated wallet file, wallet-native send **and** receive (both live-verified).
   It uses a **bespoke linear lattice ring sig as a swappable stand-in** to exercise the consensus +
   wallet plumbing end-to-end.
2. **The team evaluated the production PQ ring-sig candidates** (Raptor, MatRiCT-Au, Falafl, Falcon
   no-ring, SPHINCS+) with real measurements, and **decided to keep full ring untraceability
   (Option A)** rather than trade sender privacy for size. **MatRiCT-Au is the best-fit** production
   scheme (compact core + input amortization; research code that builds).

These connect via the PoC's **swappable backend** (`pq_ring_sig.h` C ABI, dynamic sizes): MatRiCT-Au
drops into the slot the bespoke stand-in occupies today, and the daemon/wallet retest against it.

**What's left is not "can it work" — it's the production scheme + its costs:** integrate + audit
MatRiCT-Au, and raise the per-tx caps it needs. The dominant cost is size (tens of KB/tx, ~18 GB/yr
chain growth) and the per-tx limits (`MAX_TX_SIZE`, `FUSION_TX_MAX_SIZE`) that every PQ scheme blows.

## 2. The decision: keep privacy (Option A)

Shor breaks **every** signature/privacy guarantee in Conceal — ring-sig unforgeability, key images,
Curve25519 stealth — enabling **theft + retroactive de-anonymisation** of the whole chain. Grover only
mildly affects 256-bit hashes / CN-GPU PoW [published] — **no PoW change needed**. The real fork is a
*product* choice, not just crypto:

- **Option A — keep ring untraceability (CHOSEN).** Full sender + recipient privacy preserved. Cost:
  big txs (tens of KB), ~13–29 GB/yr, must raise per-tx caps + redesign fusion. **MatRiCT-Au best fit.**
- **Option B — no-ring (Falcon + H(pk)) (rejected).** 6.4 KB/tx, ~1.9 GB/yr, fits all caps, ~10×
  faster — but inputs become **traceable** (keep recipient stealth, **lose sender untraceability**).
  Rejected: it abandons the privacy thesis Conceal is built on.

**HNDL urgency (why now):** Conceal stores **permanent encrypted messages** + **multi-year deposits**
(≤5 yr cold-staking) [published/constant]. Both create *retroactive* exposure — recorded today,
broken once a CRQC exists. Privacy is a break-it-once-applies-to-all-history risk; the clock is already
running.

## 3. Production-scheme evaluation (team measurements)

Avg tx at chain-average load (2.39-in / 2.22-out, ring-6); chain/yr at current ~1.16 tx/block, scales
with usage. **[team]**

| Scheme | Privacy | Avg tx | Verify/tx | Chain /yr | txs/block | Maturity |
|---|---|---:|---:|---:|---:|---|
| Ed25519 ring (today) | full untraceable | 1.2 KB | 2.3 ms | 0.37 GB | 82 | shipped — ❌ not PQ-safe |
| Raptor ring (linear) | full untraceable | ~24 KB *(measured 10.2 KB/sig @ ring-6 × 2.39 in)* | 1.9 ms | ~7 GB | ~4 | C reference, measured; clean-room reimpl planned |
| **MatRiCT-Au ring (log, input-amortized)** | **full untraceable** | **~107 KB** *(58 KB only w/ compression — §10.2)* | **45 ms** | **~33–35 GB** *(18 GB at 58 KB)* | **1** | **research code, builds** |
| Falafl ring (log) | full untraceable | 95 KB | 77 ms | 29 GB | 1 | research, fully measured |
| Falcon — NO RING (Falcon+H(pk)) | stealth only | 6.4 KB | 0.2 ms | 1.9 GB | 15 | NIST-standard |
| SPHINCS+ — NO RING | stealth only | 21 KB | 3.6 ms | 6.5 GB | 4 | NIST-standard, conservative |

Notes [team]: **MatRiCT-Au** = best fit for Option A (smallest *core* + amortizes across inputs;
hardest integration). **Raptor** = smallest/fastest ring but **linear** (grows with ring). **Falafl** =
clean fully-measured reference. **SMILE's "16 KB" has no public code**; smallest *runnable* ring scheme
is ~18 KB (MatRiCT-Au) / ~35 KB (Falafl). Production **Abelian** code is linear ~130 KB/member —
non-starter. (Verify cost: MatRiCT-Au's 45 ms is the real CPU price of the log-proof — ~20× Ed25519-ring.)

## 4. The PoC stand-in vs. the production target

The PoC's own **bespoke linear** ring sig (K=L=6) is *not* the mainnet candidate — it's the integration
proof. Its live-measured numbers (single tx, not chain-avg): **[measured]**

| | Classical (live) | PoC stand-in (live) |
|---|---:|---:|
| Tx 1-in/2-out | 542 B | 36,953 B (ring-4) |
| Tx 1-in/1-out / 2-in/2-out | 505 B / 972 B | 24,663 B (ring-2) / 61,533 B (ring-8) |
| Verify (ring-4, constant-time) | ~0.96 ms (ring-6) | 1.12 ms |
| Spend pubkey / sig (ring-4) | 32 B / ~384 B | 6,144 B / 30,752 B [constant] |
| Address | 98 ch (`ccx7…`) | 1,747 ch (`ctp…`) |

The stand-in is **linear** by design (simple + auditable for the PoC). For mainnet, MatRiCT-Au's
log-amortized proof replaces it via the swappable slot — trading the stand-in's linear growth for
MatRiCT-Au's compact core (at ~45 ms verify). Either way the PoC proved the *plumbing* (v3 tx, variant
tags, nullifier double-spend, stealth, wallet send/receive, deposits, messages) that any ring backend
needs.

## 5. The real walls (must change in the fork)

1. **Block size is dynamic** (max = 2× median, floored at the 100 KB zone) → **no "1 tx/block" cliff**;
   throughput self-adjusts via the reward penalty. The `txs/block` column is *at the floor*, not a hard
   limit.
2. **Per-tx caps are the real walls:**
   - `CRYPTONOTE_MAX_TX_SIZE_LIMIT` ≈ **99 KB** [constant] — MatRiCT-Au/Falafl p90 + fusion txs exceed
     it. **Must raise in the fork.**
   - `FUSION_TX_MAX_SIZE` ≈ **30 KB** [constant] — **every PQ scheme blows this** → **fusion (dust
     consolidation) needs a redesign.**
   - In the PoC we already took the small lever for the stand-in: **`PQ_MAX_RING_SIZE` 16 → 8** so a
     stand-in input fits 99 KB. MatRiCT-Au needs the cap *raised*, not lowered.
3. **PQ output keys are big** (0.9–4.4 KB vs 32 B) and amount-decomposition produces many outputs →
   the **denomination scheme is a cost lever** worth tuning.
4. **Deposits need a second PQ signature** (the deposit/TLC path on top of the spend) → deposit txs are
   the heaviest; given their multi-year lock they're also the most HNDL-urgent (§2).
5. **Any swap = a coordinated hard fork** — variable-length sig/key types, new tx version, height-gated,
   raised caps. Not "just a signature change."

## 6. What's done vs. what remains

**Done / proven (PoC, all merged, build green):** v3 PQ spend + nullifier double-spend; ML-KEM stealth;
ML-DSA deposits; ML-KEM/0x06 + 0x07 messages; v8 wallet file; wallet-native send **and** receive
(7/7 deterministic); constant-time ring-sig arithmetic (bit-identical, +17–18%); the flaky
`System`-dispatcher + `deleteAddress` crashes root-caused + fixed. Conceal-specific coverage (deposits,
messages) — not just generic CryptoNote.

**Remaining for mainnet (Option A / MatRiCT-Au):**
1. **Integrate MatRiCT-Au** into the swappable slot (variable-length keys/sig already supported by the
   ABI; the value model stays plaintext-amount unless you also adopt RingCT amount-hiding).
2. **Audit** — MatRiCT-Au construction + the integration. The hard blocker.
3. **Raise `MAX_TX_SIZE`, redesign `FUSION_TX`** (§5) + pick the denomination scheme.
4. **Human money-path review** — ML-DSA deposit interest/reorg; the consensus PQ-input validator.
5. **Per-recipient keys** — retire the Option-B fixed testnet KEM (wallet↔wallet already does this).
6. **Deposit policy** — activate PQ deposits early; cap classical deposit terms as PQ nears (≤5 yr
   classical deposits can mature past the security horizon).
7. **Dependency maturity** — RustCrypto PQ crates → 1.0 / FIPS-validated.

## 7. Cost of Option A (keep privacy) — accept these

- **Size:** **~107 KB/tx measured** this session (MatRiCT-Au, ring-10/1-in) vs 1.2 KB today (~89×); the
  oft-quoted ~58 KB is the paper's *compressed* proof and needs unbuilt prover+verifier compression — see §10.2.
- **Storage:** **~33–35 GB/yr** at today's demand at 107 KB (vs 0.37 GB); ~18 GB/yr only if 58 KB compression
  is built + audited.
- **Verify CPU:** ~45 ms/tx [team] (~20× Ed25519-ring) — node validation + IBD cost.
- **Fees:** size-coupled (0.001 ₡CCX min [published]); a ~48× larger tx ⇒ ~48× absolute fee at equal
  fee-per-byte. Deposits (extra sig) are the priciest.
- **Engineering:** raise caps, redesign fusion, denomination tuning, a coordinated hard fork.

The alternative (Option B / no-ring) was ~10× cheaper on every axis but **forfeits sender
untraceability** — rejected because privacy is the product.

## 8. Ecosystem changes introduced by the PoC

User/integrator-visible changes a rollout ships: **new address formats** (`ccxp`/`ccxh`/testnet
`ctp`/`cth`, ~1,747 ch carrying the ML-KEM key — ~18× longer; QR/URI/exchange tooling must adapt);
**tx version 3** + variant tags 0x4/0x5 + tx-extra 0x06/0x07; **`get_pq_outputs`/`sendPqTransaction`
RPC**; **`pq_address`/`pq_transfer`/`pq_receive`/`pq_balance mine` CLI**; **wallet-file v8** (Argon2id +
XChaCha20-Poly1305 + authenticated prefix); **a Rust crypto island** (`pqc/ccx-pqc`, C-ABI, new build
dep); **messages default → 0x06** PQ-KEM for PQ recipients (closes the permanent-message HNDL gap). For
mainnet add: **raised `MAX_TX_SIZE`, redesigned fusion, MatRiCT-Au, raised `PQ_MAX_RING_SIZE`.**

## 9. Bugs surfaced during measurement/verification (honest log)

- **`concealwallet` reopen** (`Wrong version`): the walletgreen migration (`d0ab5a9`) dropped the
  `.wallet`-extension resolution on `--wallet-file`. **Fixed.**
- **PoC-testnet coinbase scan gap:** a `PqKeyOutput` at coinbase index 0 isn't counted in the wallet's
  key-index, so the classical remainder's index mismatches the daemon's → a classical wallet can't see
  its own PoC-testnet coinbase. **Found, documented; testnet-only artifact.**
- **`PqSpendClient` second HTTP connector** can fail in some setups. **Found, documented.**
- **Flaky `System`-dispatcher abort + a `UnitTests` UAF segfault** — **root-caused + fixed**
  (`docs/reviews/flaky-crash-analysis.md`).

## 10. MatRiCT-Au integration path (from the author's reference code)

The MatRiCT-Au reference implementation (Esgin/Steinfeld/Zhao, PKC 2022) is **already on the WSL bench**
(`~/pqc-bench/repo-matrict`, C, builds with XKCP), and the team's **integration scaffold** exists too
(`~/ccx-pqc-impl`, branch `pqc/v2-impl`) — whose README already states the plan: real ML-KEM/ML-DSA +
an **insecure ring-sig stub** so the integration is built first, with "the audited lattice backend (C1)
dropping in behind the same ABI." Our `pqc/testnet-poc` is the evolution of that scaffold (stub → the
bespoke lattice stand-in we hardened). **MatRiCT-Au is the intended C1 backend. We wrap it, not recreate
it.** From reading its actual API, here is the concrete delta.

### 10.1 What MatRiCT-Au actually is (verified from source)

- **A RingCT confidential-transaction prover, not a bare ring signature.** An *account* = `pk + amount
  commitment`; `spend(ring, signerIdx, ask, amounts, recipientKeys, …) → {proof, serials, out
  commitments}` consumes input amounts + commitment randomness and emits output commitments + a balance
  proof + per-amount range proofs; `verify(…) → bool`. Shaped like Monero CLSAG+Bulletproof, not like
  `generate_ring_signature(prefixHash, ring, sk, idx)`.
- **The serial `s = H·sk` is the nullifier** — deterministic in the key, one per spent input. `verify`
  takes it as **input** (doesn't return it); the integrator enforces uniqueness. **This is exactly our
  model** (`check_pq_tx_input` + `m_spent_pq_nullifiers`) — a clean mapping.
- **Optional accountability layer** (TdRowGen/Audit partially-decrypts to recover signer + amounts):
  **strip it for a coin** (pass `t0=t1=t2=NULL`).

### 10.2 Sizes & cost (note the packing gap)

| | this session (measured) | paper (compressed) | raw reference `sizeof` |
|---|---:|---:|---:|
| Spend proof (ring-10, 1-in) | **~107 KB** [packed, this session] | ~58 KB *(needs compression — unbuilt)* | **~274 KB** [raw] |
| Account / pubkey | — | — | 18 KB / 9 KB |
| Serial (nullifier) | — | — | 512 B / input |
| Verify | — | 45 ms [paper] | — |

**CORRECTION (measured this session).** The earlier "58 KB avg" treated as authoritative is the **paper's
*compressed* proof, not a measurement** — the reference ships **no proof serializer**; it only holds the proof
as full in-memory arrays. Library-izing it + a canonical packed serializer gives **~107 KB** (n10m1, the same
ring-10/1-in params the 58 KB describes), and that is the **floor for the reference**: every coefficient is
already at its formal norm bound, so there is *no packing slack left*. The ~274 KB raw → ~107 KB packed is the
serialization win. A second pass **measured the realized coefficient distributions** (60 spend runs): FS-with-
aborts makes every response coefficient near-uniform over its full norm interval (entropy = packed width to
<1 bit), so the **responses — 73% of the proof — are at the information-theoretic floor** and re-encoding them
wins **~0 KB** (a single 304-byte safe split aside). **Re-encoding cannot reach 58 KB.** The paper's 58 KB
comes instead from **high-bit *truncation of the commitments* `b`/`c` + a hint** (Dilithium `t1/t0`/`UseHint`):
a **protocol/soundness-statement change** — the FS hash binds the *full* commitments, so it needs the
**verification equation rewritten + the extractor proof redone + the audit**; and **truncating `b` breaks
auditability** (`b` is the partially-decryptable commitment). So 58 KB is a **cryptographic-research-grade
sub-project**, not a serialization or re-encoding task.
**Plan on ~107 KB / ~33–35 GB/yr** as the realistic baseline; 58 KB / ~18 GB/yr is conditional on building +
auditing that compression. (Verify ~45 ms is the paper's figure, not re-measured here.)

### 10.3 The four adapter gaps (what the wrapper must bridge)

1. **Amount layer (the product fork).** Our `ccx_pq_*` ABI is signature-shaped (no amounts). MatRiCT-Au
   is inseparable from amounts — so **taking it ≈ adopting RingCT**: Conceal would gain *confidential
   amounts* (it has plaintext amounts today). That is a real value-model upgrade (commitments + balance
   proof in consensus), not a backend swap. Using only a "ring core" fights the design and forfeits the
   benefit. **Recommendation: treat MatRiCT-Au adoption as the RingCT migration it is.**
2. **Message binding.** There is no `msgHash` parameter — the tx body is what its Fiat-Shamir `hash()`
   covers. Binding a Conceal tx-prefix hash means **extending the FS hash input** in `spend.c`/`hash()`.
3. **Compile-time ring size.** `N_SPENT`/`BETA` (10/50/100) + `M_SPENT` are `#define`s with `static`
   fixed arrays; `spend`/`verify` take no runtime ring length. → either **compile per-(ring,inputs)
   variant + dispatch**, or **parameterize the macros into runtime args** (a substantial rewrite — every
   `static` buffer becomes heap/instance state).
4. **Serial/nullifier lift.** `s` is a `spend` output the daemon must extract + uniqueness-check — which
   we already do; smallest gap.

### 10.4 Library-ization (the reference is a benchmark, not a library)

Before it can live in the daemon: **(a)** make the CRS (`g`/`h`/`g_hat`) instance state, not file-scope
statics; **(b)** thread-safety — it has a global AES-CTR PRG (`static __m128i round_key_*`) + `static`
scratch arrays in `spend`/`verify` → not reentrant; serialize entry points or remove the statics (huge
stack frames otherwise); **(c)** **ARM portability** — it uses x86 AES-NI intrinsics + `-march=native`
(matters for mobile/wider nodes; needs an AES/SIMD shim); **(d)** a packed wire serializer (§10.2).

### 10.5 What the PoC already de-risked (the reuse)

tx v3 + variable-length TLV serialization; the **nullifier/serial double-spend set**
(`m_spent_pq_nullifiers` ↔ MatRiCT's serial); the swappable C-ABI island; ML-KEM stealth (orthogonal);
PQ deposits/messages; the constant-time discipline; wallet send/receive. The integration plumbing the
scaffold reserved for "C1" is built and tested — MatRiCT-Au plugs into it.

### 10.6 Work list & effort (honest)

Multi-month, not a swap: **(1)** library-ize MatRiCT-Au (§10.4); **(2)** a RingCT-shaped C-ABI + a C++
wrapper owning CRS lifetime, threading, ring-size dispatch, serialization, nullifier tracking; **(3)**
the **RingCT consensus value model** (commitments + balance proof; amounts → commitments) — the largest
new surface; **(4)** caps: **raise** `PQ_MAX_RING_SIZE` (we lowered it to 8 for the linear stand-in),
raise `MAX_TX_SIZE`, redesign `FUSION_TX`; **(5)** the **audit** (the C1 gate). The bespoke stand-in stays
the testnet backend until this lands behind the same slot.

## References

- Conceal wiki — chain specs/features/fees: <https://conceal.network/wiki/doku.php?id=about>
- MatRiCT-Au reference (author code): `~/pqc-bench/repo-matrict` — Esgin/Steinfeld/Zhao, PKC 2022
- Team integration scaffold: `~/ccx-pqc-impl` (branch `pqc/v2-impl`)
- **MatRiCT-Au integration plan + adapter design:** [`matrict-integration-plan.md`](matrict-integration-plan.md)
- Raw PoC measurements: [`measured-numbers.md`](measured-numbers.md)
- Architecture / how-to-run: [`STATUS.md`](STATUS.md)
- Ring-sig hardening + constant-time: [`ringsig-hardening.md`](ringsig-hardening.md)
- Accepted limitations: [`hardening-notes.md`](hardening-notes.md)
- Flaky-crash root-cause: [`../../reviews/flaky-crash-analysis.md`](../../reviews/flaky-crash-analysis.md)
