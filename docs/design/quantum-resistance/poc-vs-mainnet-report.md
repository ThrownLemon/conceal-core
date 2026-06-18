---
title: "Conceal post-quantum migration — PoC vs. mainnet"
---

# Conceal post-quantum migration — PoC vs. mainnet (decision report)

*CIP-0001. Branch `pqc/testnet-poc` (not pushed; local for human review). Numbers below are tagged
**[measured]** (live, on the testnet binaries — see `measured-numbers.md`), **[constant]** (from a code
constant / size formula), or **[published]** (from the [Conceal wiki](https://conceal.network/wiki/doku.php?id=about)).
Companion docs: [`STATUS.md`](STATUS.md) (architecture/how-to-run), [`measured-numbers.md`](measured-numbers.md)
(raw measurements), [`hardening-notes.md`](hardening-notes.md), [`ringsig-hardening.md`](ringsig-hardening.md).*

## 1. Executive summary

The PoC proves an **end-to-end post-quantum (PQ) privacy-coin stack is buildable on the existing Conceal
codebase**, and crucially it covers **Conceal's distinctive features** — not just generic CryptoNote:
PQ ring-signature spends (anonymous + linkable, double-spend-protected), ML-KEM-768 stealth addresses,
**ML-DSA-65 PQ deposits** (Conceal's banking/cold-staking), **ML-KEM PQ encrypted messages** (Conceal's
messenger), an Argon2id + XChaCha20-Poly1305 + authenticated-prefix wallet file, and wallet-native
send **and receive** (both live-verified). All height-gated, wire-additive, test-suite green.

**It is NOT mainnet-ready, by design.** The single blocking item is the **lattice ring signature**: a
bespoke, *unaudited*, heuristically-parameterised construction. Everything else (ML-KEM, ML-DSA, the
AEAD/KDF, the wallet format, the consensus plumbing) uses standardised NIST primitives and is
mainnet-shaped already.

**The headline cost is size:** a PQ ring-4 spend is **36,953 B [measured]** vs a classical 1-in/2-out
tx of **542 B [measured]** — **~68×** — and only **~2** PQ spends fit Conceal's 100 KB block reward zone
vs ~184 classical. Verify CPU is ~7× (1.12 ms vs ~0.16 ms). These are the real economics to design
around.

**Recommendation:** keep the PoC as the reference implementation; do **not** activate PQ spends on
mainnet until the ring sig is parameter-calibrated, constant-time [done for the hot paths], and
**professionally audited**. The PQ **deposit** and **message** paths use standardised primitives and —
given Conceal's *permanent* on-chain data and *multi-year* deposits — are the strongest candidates to
stage **first**, after a human money-path review.

## 2. The threat & why it matters *for Conceal specifically*

- **Shor** breaks Ed25519 signatures + Curve25519 ECDH (stealth keys) + ring-sig unforgeability → a CRQC
  could **forge spends and de-anonymise the whole chain history**. **Grover** only weakens hashes
  quadratically; Conceal's 256-bit hashes + **Cryptonight-GPU** PoW [published] keep ≥128-bit PQ
  security — **no PoW/hash change needed**.
- **Harvest-now-decrypt-later (HNDL)** is the sharp edge for Conceal, because two of its flagship
  features create *permanent* exposure:
  - **Encrypted messages are stored permanently on-chain** [published]. A message encrypted with
    *classical* key agreement can be recorded today and decrypted once a CRQC exists. → argues for the
    **PQ-KEM (0x06)** message path as the *default*, not classical.
  - **Deposits (cold staking) lock for up to ~5 years** (`DEPOSIT_MAX_TERM_V1 ≈ 1.3M blocks × 120 s`
    [constant]). A *classical* deposit made today matures years out — inside the plausible CRQC window.
    → argues for activating **PQ deposits early** and **capping classical deposit terms** as PQ nears.

## 3. Measured metrics (live, on the testnet binaries)

### 3.1 Transaction & artifact sizes

| Artifact | Classical | PoC PQ | Ratio | Source |
|---|---:|---:|---:|---|
| Tx, 1-in/1-out | 505 B | 24,663 B (ring-2) | ~49× | [measured] |
| Tx, 1-in/2-out | **542 B** | **36,953 B** (ring-4) | **~68×** | [measured] |
| Tx, 2-in/2-out | 972 B | 61,533 B (ring-8) | ~63× | [measured] |
| Spend public key | 32 B | 6,144 B (ring-sig `t`) | 192× | [constant] |
| Spend signature, ring-4 | ~384 B (LSAG, ring-6) | 30,752 B | ~80× | [constant] |
| Key image / nullifier | 32 B | 32 B | 1× | [constant] |
| Stealth KEM pubkey | 32 B (Curve25519) | 1,184 B (ML-KEM-768) | 37× | [constant] |
| Stealth ciphertext/output | 0 (implicit ECDH) | 1,088 B (ML-KEM ct) | — | [constant] |
| Deposit signature | 64 B (Ed25519) | 3,309 B (ML-DSA-65) | 52× | [constant] |
| Receive address | **98 chars** (`ccx7…`) | **1,747 chars** (`ctp…`) | ~18× | [measured] |

> Each extra PQ ring member adds **6,145 B [measured]** to the tx (matches `sig_bytes(n)=6176+n·6144`).

### 3.2 Per-operation CPU (single core)

| Operation | Classical | PoC PQ | Source |
|---|---:|---:|---|
| Ring-sig verify | ~160 µs / ring-member (ring-6 ≈ **0.96 ms**) | **1.12 ms** (ring-4, constant-time) | [measured] |
| Ring-sig sign / tx construct | tx construct (incl. sign) ~**0.55 ms** (1-in/2-out) | **2.46 ms** (ring-4, constant-time) | [measured] |
| Key-image gen / pubkey derive | 77 µs / 29 µs | n/a | [measured] |

> No isolated Ed25519 microbench exists in the tree, so classical *signature* timing is given via the
> live `PerformanceTests` ring-sig + key-image numbers rather than fabricated. The constant-time rewrite
> of the PQ ring-sig arithmetic added +17–18% (verify 0.95→1.12 ms, sign 2.09→2.46 ms), **bit-identical**.

### 3.3 Size scaling vs the per-tx limit (the dominant problem)

`PQ tx ≈ 13.4 KB + n·6.14 KB`; `CRYPTONOTE_MAX_TX_SIZE_LIMIT ≈ 99.4 KB` [constant]:

| Ring *n* | PQ tx | vs 99.4 KB tx cap |
|---:|---:|---|
| 2 (min) | 24.7 KB [measured] | ok |
| 4 | 37.0 KB [measured] | ok |
| 8 (**new `PQ_MAX_RING_SIZE`**) | 61.5 KB [measured] | ok (headroom) |
| 16 (old cap) | ~111.7 KB [constant] | **exceeded the per-tx cap** |

The signature is **linear** in ring size by *deliberate design* (a simple, auditable AOS/LSAG over a
module lattice). **Logarithmic-proof schemes (MatRiCT family) were evaluated and ruled out** — they
exist only on paper with no public, production-grade, *audited* implementation; porting one = shipping
unaudited research crypto (more audit surface, not less). So the realistic levers are **ring-size cap +
tx/block-size policy**, and we already acted: **`PQ_MAX_RING_SIZE` lowered 16 → 8** so a PQ input always
fits a transaction (§8).

### 3.4 Throughput / storage / fee

- **Block fill:** ~**184** classical (1-in/2-out) vs **2** PQ ring-4 spends per 100 KB reward zone
  [measured derivation] → effective PQ-spend TPS at constant block size is **~70–90× lower**.
- **Bandwidth/storage:** ~68× the bytes per PQ spend; relay + IBD grow proportionally.
- **Fees:** Conceal's fee is size-coupled (0.001 ₡CCX min [published] + size-penalty reward curve), so a
  ~68× larger tx implies a **~68× higher absolute fee** at equal fee-per-byte. **Deposits** (~3.3 KB
  sig) and **messages** (~1–2 KB) are far cheaper than ring spends.
- **Dynamic adaptive limits** [published] grow the *block* over time, easing block-level throughput —
  but the *per-tx* cap is fixed, which is why the ring-size cap (not the block limit) is the binding
  constraint.

## 4. Conceal vs. standard CryptoNote (baseline) — and where the PQ work plugs in

Conceal is not vanilla CryptoNote; the PQ work had to cover its extensions [published]:

| Conceal feature | vs stock CryptoNote | PQ-PoC coverage |
|---|---|---|
| **Cold-staking / banking deposits** (HTLC/TLC, 2.9–6% APR, ≤5 yr) | Conceal-specific | **ML-DSA-65 PQ deposits** (variant 0x5, `UPGRADE_HEIGHT_V9`) |
| **On-chain encrypted + self-destruct messages** | Conceal-specific | **ML-KEM 0x06** + authenticated 0x07; default→0x06 for PQ recipients (§8) |
| **Cryptonight-GPU** PoW (ASIC/botnet/FPGA-resistant) | custom PoW | unchanged (Grover-adequate) |
| **LWMA3 (Zawy) + DDA** difficulty, 120 s blocks | custom | unchanged |
| 200M supply / 6 ₡CCX fixed reward / 6 decimals | custom emission | unchanged |
| Ring signatures + one-time addresses | inherited CryptoNote | replaced by the PQ lattice ring sig + ML-KEM stealth |

## 5. What changes PoC → mainnet, and why

| Area | PoC | Mainnet requirement | Why |
|---|---|---|---|
| Ring-sig trust | bespoke, **unaudited**, heuristic K=L=6 | calibrated + **audited**, or an audited compact scheme | money + anonymity rest on it |
| Ring-sig timing | constant-time hot paths ✅; rejection-loop count residual | finish CT sampling at audit | timing side-channel on the key |
| Ring-sig size | linear (≤ ring-8 fits) | ring-cap + size policy (log schemes ruled out) | linear growth breaks size/fees (§3) |
| Testnet KEM identity | one fixed `PQ_TESTNET_KEM` ("Option B") | per-recipient ML-KEM keys (already built for wallet↔wallet) | a shared key = zero recipient privacy |
| Deposits | ML-DSA, tested + agent-reviewed | **human money-path review** + early activation + classical-term cap | longest-lived authority (≤5 yr) |
| Messages | default→0x06 for PQ recipients | per-recipient KEM key distribution via PQ address | permanent messages = HNDL-critical |
| Wallet file v8 | shippable (client-side) | ship ahead of consensus | strict improvement, non-consensus |
| Crypto deps | pre-1.0 RustCrypto, exact-pinned | 1.0 / FIPS-validated, reproducible | pre-1.0 encodings can change |

## 6. Upgrade vs. don't-upgrade

**Upgrade benefits:** forgery protection of spend authority; **retroactive-privacy** protection (the
HNDL property — only a PQ anonymity layer protects *today's* txs + permanent messages from *future*
de-anonymisation); first-mover credibility for a privacy project.
**Upgrade costs:** ~68× tx size, ~70–90× lower PQ-spend TPS, ~68× fees, ~7× verify CPU; trust shifts
onto an **unaudited** bespoke ring sig until audited; larger attack surface.
**Not upgrading:** all spend authority + **all historical privacy** + **all permanent messages** become
forgeable/decryptable once a CRQC exists — and HNDL means the privacy clock is *already* running.
**Net:** prepare now, activate carefully. The worst outcome is shipping the bespoke ring sig to mainnet
*unaudited* to chase a threat that's likely years out — trading a future probabilistic risk for a
present concrete one.

## 7. Remaining gates (priority order)

1. **Ring-sig constant-time** — ✅ done for the modular-arithmetic hot paths (Barrett + branchless
   selects, bit-identical, +17–18%). *Residual:* the Fiat-Shamir rejection-loop iteration count is
   secret-dependent (wallet-side; `verify` has no loop) — deferred to the audit/CT-sampling work.
2. **Ring-sig parameter calibration** — run a lattice estimator over the MSIS/MLWE instances; replace
   heuristic K=L=6.
3. **Ring-sig audit** — professional review of the construction *and* implementation. The hard blocker.
4. **Size/economics** — ring cap (now 8) + tx/block policy. (Log-proof schemes ruled out, §3.3.)
5. **Human money-path review** — ML-DSA deposit interest/reorg paths; the consensus PQ-input validator.
6. **Per-recipient keys** — retire the Option-B fixed testnet KEM key (wallet↔wallet already does this).
7. **Dependency maturity** — RustCrypto PQ crates to 1.0 / FIPS-validated.

## 8. Ecosystem changes introduced by the PoC

These are user/integrator-visible changes a mainnet rollout would ship:

- **New address formats.** Classical stays `ccx7…` (98 ch). PQ adds `ccxp…` (PQ-only) and `ccxh…`
  (hybrid: classical + ML-KEM), ~**1,747 ch** on testnet (`ctp…`/`cth…`) — they carry the 1,184 B
  ML-KEM key. *Implication:* QR/URI/exchange-integration tooling must handle ~18× longer addresses.
- **New transaction type.** Tx **version 3** with `PqKeyInput`/`PqKeyOutput` (variant tag 0x4) +
  `PqMultisig*` (0x5) for deposits; new tx-extra tags **0x06** (PQ-KEM message), **0x07** (authenticated
  classical message). `0x04` legacy messages are decrypt-only.
- **`PQ_MAX_RING_SIZE` lowered 16 → 8** (consensus) so a PQ input fits the tx-size limit (§3.3).
- **New RPC.** `get_pq_outputs` (daemon) enumerates spendable PQ outputs; `sendPqTransaction` (walletd).
- **New wallet CLI.** `pq_address`, `pq_transfer <addr|self>`, `pq_receive`, `pq_balance mine`.
- **New wallet-file format v8.** Argon2id + XChaCha20-Poly1305 + authenticated prefix (the legacy
  unsalted `cn_slow_hash`+chacha8 is retired). Migrate-on-save; non-consensus.
- **A Rust crypto island** (`pqc/ccx-pqc`) linked via a panic-guarded C ABI — a new build dependency
  (Rust toolchain) for every executable.
- **Message default → PQ-KEM (0x06)** when the recipient has a PQ key — closes HNDL exposure on
  Conceal's permanent messages. *[in progress]*

## 9. Bugs surfaced during measurement/verification (honest log)

- **`concealwallet` reopen broke** (`Failed to read wallet version: Wrong version`). Root cause: the
  walletgreen migration (`d0ab5a9`) dropped the `.wallet`-extension resolution on `--wallet-file`, so a
  bare path opened an empty stream. **Fixed.** (Would have hit real users reopening wallets.)
- **PoC-testnet coinbase scan gap.** The PoC coinbase emits a `PqKeyOutput` at index 0 + a classical
  remainder; the wallet's output scanner skips the PqKeyOutput *without advancing its key index*, so the
  classical remainder's wallet index (0) mismatches the daemon's absolute index (1) → a classical wallet
  never recognises its own PoC-testnet coinbase. **Found, documented; not yet fixed** (testnet-only
  artifact of the demo coinbase layout).
- **`PqSpendClient` second HTTP connector** can fail (`TcpConnector::connect`) in some setups even when
  `NodeRpcProxy` connects fine. **Found, documented**; the dedicated verify scripts use the shared
  builder path which works.
- **Flaky `System`-dispatcher abort + a `UnitTests` UAF segfault** — **root-caused + fixed** (drained
  eventfd double-read throwing on EAGAIN; a `WalletGreen::deleteAddress` use-after-free). See
  `docs/reviews/flaky-crash-analysis.md`.

## 10. Anything else worth flagging

- **The signature backend is swappable — a hedge, but a socket, not a supply.** The PQ ring sig sits
  behind a stable C ABI (`keygen`/`sign`/`verify`/`nullifier` + dynamic size queries), so any conforming
  backend drops in and the daemon retests — which is why we could re-parameterise and harden freely, and
  why a future audited scheme would integrate in days. But "drop in MatRiCT-Au" hits two walls: (1) *it
  doesn't exist as code* (papers, no audited implementation); (2) MatRiCT is **RingCT** (amount-hiding
  via commitments + range proofs), not a ring *signature* — Conceal has **plaintext amounts**, so it's a
  whole value-model migration, not a backend swap. The clean drop-in would be a *sublinear linkable ring
  **signature*** (Calamari/SMILE/DualRing-style) with a recoverable nullifier — but an **audited** one
  with those properties doesn't exist yet either. Swappability is real and worth keeping; it's gated on a
  conforming, audited backend *existing*.
- **Deposits & messages could ship first** — standardised primitives, smaller/cheaper than spends,
  independently height-gateable, and (per §2) the most HNDL-urgent given Conceal's permanent data +
  multi-year locks.
- **Hybrid period.** Activate classical + PQ in parallel (`ccxh` hybrid addresses prototyped) so users
  migrate before classical is deprecated — never a hard cutover.

## References

- Conceal wiki — chain specs, features, fees: <https://conceal.network/wiki/doku.php?id=about>
- Raw measurements: [`measured-numbers.md`](measured-numbers.md)
- Architecture / how-to-run: [`STATUS.md`](STATUS.md)
- Ring-sig hardening + constant-time: [`ringsig-hardening.md`](ringsig-hardening.md)
- Accepted limitations: [`hardening-notes.md`](hardening-notes.md)
- Flaky-crash root-cause: [`../../reviews/flaky-crash-analysis.md`](../../reviews/flaky-crash-analysis.md)
