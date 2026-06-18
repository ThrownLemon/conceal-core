# Conceal post-quantum migration — PoC vs. mainnet (decision report)

*CIP-0001. Status as of branch `pqc/testnet-poc` (not pushed; local for human review). This report
compares what the proof-of-concept demonstrates against what a mainnet deployment would require, with
measured metrics, the upgrade-vs-not tradeoff, and the gates that remain.*

---

## 1. Executive summary

The PoC proves an **end-to-end post-quantum (PQ) privacy-coin stack is buildable on the existing
Conceal codebase**: PQ ring-signature spends (anonymous + linkable, double-spend-protected), ML-KEM-768
stealth addresses, ML-DSA-65 deposits, ML-KEM encrypted messages, an Argon2id + XChaCha20-Poly1305 +
authenticated-prefix wallet file, and wallet-native send/receive — all height-gated, wire-additive, and
green on the test suite.

**It is NOT mainnet-ready, by design.** The single blocking item is the **lattice ring signature**: it
is a bespoke, *unaudited*, heuristically-parameterised construction. Everything else (ML-KEM, ML-DSA,
the AEAD/KDF, the wallet format, the consensus plumbing) uses standardised NIST primitives and is
mainnet-shaped already.

**Recommendation:** keep the PoC as the reference implementation; do **not** activate PQ spends on
mainnet until the ring signature is (a) parameter-calibrated with a lattice estimator, (b) made
constant-time [in progress], and (c) **professionally audited** — or replaced by an audited compact
lattice ring/RingCT scheme if one becomes available. The PQ **deposit** (ML-DSA) and **message/KDF**
paths are far closer to shippable and could be staged earlier behind their own height gates after a
human money-path review.

---

## 2. The threat & why it matters now

- **Shor's algorithm** breaks the discrete-log problem that Conceal's signatures and stealth addresses
  rest on: Ed25519 signatures, Curve25519 ECDH (one-time/stealth keys), and the ring-signature
  unforgeability all fall to a cryptographically-relevant quantum computer (CRQC). A CRQC could **forge
  spends and de-anonymise the entire chain history**.
- **Grover's algorithm** only weakens hashes quadratically; Conceal's 256-bit hashes (CN-GPU PoW, key
  images, Merkle) keep ≥128-bit post-quantum security. **No PoW/hash change is needed** — confirmed in
  `pow-grover-widening.md`.
- **Harvest-now-decrypt-later (HNDL):** the chain is public and permanent. An adversary can record
  today's transactions and *de-anonymise them retroactively* once a CRQC exists. For a **privacy** coin
  this is the sharp edge — confidentiality of *past* transactions cannot be retrofitted. Spend
  authority (forgery) is a "break at CRQC-time" risk; **privacy is a break-it-once-applies-to-all-history
  risk.** This argues for migrating the *stealth/anonymity* layer earlier than a pure
  forgery-prevention analysis would suggest.

---

## 3. Measured metrics (PoC, on the WSL x86_64 build)

### 3.1 Primitive & artifact sizes

| Artifact | Classical (Ed25519 / CryptoNote) | PoC PQ | Ratio |
|---|---:|---:|---:|
| Spend public key | 32 B | **6 144 B** (lattice ring-sig `t`, K=L=6) | 192× |
| One spend signature, ring-4 | ~160 B (LSAG, ~32·(n+1)) | **30 752 B** (`6176 + n·6144`) | ~190× |
| Key image / nullifier | 32 B | 32 B | 1× |
| Stealth KEM public key | 32 B (Curve25519) | 1 184 B (ML-KEM-768) | 37× |
| Stealth ciphertext per output | 0 (ECDH, implicit) | 1 088 B (ML-KEM ct) | — |
| Deposit signature | 64 B (Ed25519) | 3 293 B (ML-DSA-65) | 51× |
| **Transaction, ring-4, 1-in/1-out** | ~1.5 KB | **≈ 37 KB** (measured 36 953 B) | ~25× |
| Receive address | ~95 chars | ~2 000 chars (`ccxp…` carries the 1184 B KEM key) | ~21× |

### 3.2 Per-operation CPU (ring-4, single core)

| Operation | Classical | PoC PQ (K=L=6, NTT) | Notes |
|---|---:|---:|---|
| Spend sign | ~50 µs | **~3.8 ms** | ~75× slower; lattice sign w/ Fiat-Shamir aborts |
| Spend verify | ~0.13 ms | **~0.9 ms** | ~7× slower; dominates node validation cost |
| KEM encap/decap | n/a (ECDH ~60 µs) | sub-ms (ML-KEM-768) | standardised, fast |

> The NTT rewrite already cut ring-4 verify ~9.5× (6.54 ms → 0.69 ms at the old params); the K=L=6 bump
> brought it back to ~0.9 ms. The **constant-time** rewrite of the modular arithmetic (mainnet gate —
> now **done**, §6) adds +17–18%, keeping verify ~1.1 ms / sign ~2.5 ms — bit-identical, no wire change.

### 3.3 Transaction-size scaling vs. the consensus limit

`PQ tx ≈ 13.4 KB + n·6.14 KB` for ring size *n* (1-in/1-out):

| Ring size *n* | PQ tx size | vs `CRYPTONOTE_MAX_TX_SIZE_LIMIT` (99.4 KB) |
|---:|---:|---|
| 2 (min) | ~25.7 KB | ok |
| 4 | ~37 KB | ok |
| 8 | ~62.6 KB | ok |
| 16 (`PQ_MAX_RING_SIZE`) | **~111.7 KB** | **EXCEEDS the max tx size** |

**Finding:** a single max-ring (n=16) PQ input does not fit inside one transaction under the current
size limit, and even an n=8 multi-input tx blows the block reward zone quickly. The signature is
**linear** in ring size — this is a *deliberate design choice*, not an oversight: we picked a simple,
auditable AOS/LSAG-over-module-lattice construction. **Logarithmic-proof schemes (the MatRiCT family)
were evaluated and ruled out** — they exist only on paper with *no public, production-grade, audited
implementation*, so porting one would mean shipping unaudited research-paper crypto (more audit
surface, not less — the opposite of what a money-critical migration wants). So, until/unless an audited
compact scheme ships (§7), the only realistic levers for the linear-size problem are: **(a) cap PQ ring
size lower (e.g. 8 → ~62 KB fits), and/or (b) raise the tx/block size limits** (with the bandwidth/
storage consequences below). This is the dominant scaling problem and it has no free fix.

### 3.4 Throughput / storage / fee impact (first-order)

- **Blockchain growth:** a PQ-spend-dominated chain stores ~25× the bytes per transaction. At Conceal's
  100 KB reward zone, a block holds only ~2–3 ring-4 PQ spends before the size-penalty curve bites,
  vs. dozens of classical txs. **Effective TPS at constant block size drops ~20–25×** for PQ spends.
- **Bandwidth:** relay + sync bandwidth scales with tx bytes — nodes/wallets move ~25× more data per PQ
  spend; initial block download grows proportionally.
- **Verify CPU:** ~7× per spend, linear in ring size; the `PQ_MAX_RING_SIZE` cap exists precisely to
  bound a single input's verify cost as a CPU-DoS guard.
- **Fees:** Conceal fees are size-coupled (min-fee-per-byte + the block-size-penalty reward curve). A
  ~25× larger tx implies a **~25× higher absolute fee** at equal fee-per-byte — PQ spends are
  materially more expensive to the user. Deposits (ML-DSA, ~3.3 KB/sig) and messages (ML-KEM, ~1–2 KB)
  are far cheaper than ring spends.

---

## 4. What changes from PoC → mainnet, and why

| Area | PoC (testnet) | Mainnet requirement | Why |
|---|---|---|---|
| **Ring-sig trust** | bespoke, **unaudited**, heuristic K=L=6 | parameter-calibrated (lattice estimator) + **professional audit**, or port an audited compact scheme | money + anonymity rest on it; a soundness/parameter error = forgery or de-anonymisation |
| **Ring-sig timing** | NTT-fast but **not constant-time** | constant-time modular arithmetic [in progress] | secret-dependent branches/division leak the key via timing |
| **Ring-sig size** | linear in ring (n·6.1 KB), by design | lower ring cap + tx/block size policy (log-proof schemes ruled out — no audited impl) | linear growth breaks tx/block size + fee economics (§3.3) |
| **Testnet KEM identity** | ONE fixed `PQ_TESTNET_KEM` keypair ("Option B") for all coinbase/scan | per-recipient ML-KEM keys only (already built for wallet↔wallet) | a shared key gives zero recipient privacy; the fixed key is a demo bootstrap |
| **Activation** | `TESTNET_UPGRADE_HEIGHT_V9 = 80`, testnet difficulty pinned | a mainnet `UPGRADE_HEIGHT_*` set far in the future + coordinated fork + voting | consensus change; must not split the live chain |
| **Deposits (ML-DSA)** | tested + agent-reviewed | **human line-by-line review** of interest-minting / reorg money paths | money-critical; standardised primitive but custom integration |
| **Wallet file (v8)** | Argon2id + XChaCha20-Poly1305 + authenticated prefix | shippable as-is (client-side, non-consensus) | already a strict improvement; could ship ahead of consensus changes |
| **Messages** | 0x06 PQ (ML-KEM) + 0x07 authenticated classical | per-recipient ML-KEM key distribution via PQ address | already built; just needs the address path wired into the message UI |
| **Crypto deps** | pre-1.0 RustCrypto `ml-kem`/`ml-dsa`, pinned + Cargo.lock | track to 1.0 / FIPS-validated builds; reproducible build | pre-1.0 crates can change encodings; pinning mitigates, 1.0 removes the risk |

---

## 5. Upgrade vs. don't-upgrade

**Benefits of upgrading (to PQ):**
- Forgery protection of spend authority against a future CRQC.
- **Retroactive-privacy protection** — the HNDL-critical property for a privacy coin (§2); only a PQ
  anonymity layer protects *today's* transactions from *future* de-anonymisation.
- First-mover credibility for a privacy project whose thesis is long-term confidentiality.

**Costs / risks of upgrading:**
- ~25× tx size, ~20–25× lower effective TPS, ~25× fees for PQ spends, ~7× verify CPU (§3).
- Trust shifts onto an **unaudited** bespoke ring sig until audited — a *new* risk that could be worse
  than the quantum risk it mitigates if shipped prematurely.
- Larger attack surface (Rust FFI island, new consensus rules, new wallet format).

**Cost of NOT upgrading:**
- All spend authority and **all historical privacy** become forgeable/de-anonymisable the day a CRQC
  exists — and the HNDL window means the clock is *already running* on privacy.

**Net:** the asymmetry favours *preparing now, activating carefully*. The PoC is exactly that
preparation. The worst outcome is shipping the bespoke ring sig to mainnet **unaudited** to chase a
threat that is likely years out — that trades a future probabilistic risk for a present concrete one.

---

## 6. Remaining gates (in priority order)

1. **Ring-sig constant-time** — ✅ **done for the modular-arithmetic hot paths.** Barrett reduction (no
   `idiv`) for `mulmod`, division-free centered reduce for `cmod`/`pmod`, branchless masked selects for
   the `addq`/`subq` NTT butterflies — no secret-dependent branch or division remains on the reductions
   over the secret `s`/masks `y`/`z`. **Bit-identical** (NTT-equivalence 0 mismatches + exhaustive/random
   equivalence tests + selftests green; wire format unchanged). Measured cost (ring-4): **verify +18%
   (0.95 → 1.12 ms), sign +17% (2.09 → 2.46 ms)**. *Residual:* `sign()`'s Fiat-Shamir-with-aborts
   rejection loop still has a secret-dependent **iteration count** (the `‖z‖∞ ≤ ZBOUND` abort depends on
   the mask norm) — a standard lattice-sig property, wallet-side only (`verify` has no loop). Deferred to
   the audit/constant-time-sampling work; documented in `ringsig-hardening.md`.
2. **Ring-sig parameter calibration** — run a current lattice estimator over the MSIS (forgery) and MLWE
   (key-recovery) instances; replace the heuristic K=L=6 with a justified set.
3. **Ring-sig audit** — professional cryptographic review of the AOS/LSAG-over-module-lattice
   construction *and* the implementation. The hard blocker; external.
4. **Size/economics** — decide ring-size cap + tx/block limits. (Logarithmic-proof schemes that would
   break linear growth are **ruled out** for now — no audited implementation exists, §3.3/§7.)
5. **Human money-path review** — ML-DSA deposit interest/reorg paths; the consensus PQ-input validator.
6. **Per-recipient keys end-to-end** — retire the Option-B fixed testnet KEM key (wallet↔wallet path
   already does this).
7. **Dependency maturity** — RustCrypto PQ crates to 1.0 / FIPS-validated; reproducible builds.

---

## 7. Anything else worth flagging

- **Deposits & messages could ship first.** They use standardised primitives (ML-DSA, ML-KEM), are
  smaller/cheaper than ring spends, and are independently height-gateable — a lower-risk first PQ
  milestone than spends.
- **The wallet file (v8) is a free win.** Argon2id + AEAD + authenticated prefix is a strict, non-
  consensus improvement; it can ship to users ahead of any chain change.
- **Hybrid period.** Mainnet activation should run classical + PQ in parallel (hybrid addresses already
  prototyped: `ccxh`) so users migrate before classical is deprecated, never a hard cutover.
- **The signature backend is swappable — a genuine hedge, but a socket, not a supply.** The PQ ring
  sig sits behind a stable C ABI (`pq_ring_sig.h`: `keygen`/`sign`/`verify`/`nullifier` + dynamic size
  queries; the C++ side never hardcodes sizes). So *any* conforming backend drops in and the daemon
  retests against it — which is exactly why we could re-parameterise and harden our own scheme freely,
  and why a future audited scheme would integrate in days, not months. **Two caveats on "just drop in
  MatRiCT-Au":** (1) *it doesn't exist as code* — MatRiCT/MatRiCT-Au are papers with no public,
  production-grade, audited implementation; the slot makes integration cheap but doesn't conjure a
  backend into being (someone must port the paper — the very unaudited-research-crypto risk we're
  avoiding). (2) *it's a different shape* — MatRiCT is **RingCT** (amount-hiding via commitments +
  range/balance proofs), not a ring *signature*; Conceal has **plaintext amounts** today, so adopting
  it is a whole value-model migration, not a backend swap, and the current signature-shaped ABI
  wouldn't carry it without redesign. The clean drop-in would be a *sublinear linkable ring **signature***
  (Calamari/SMILE/DualRing-style) with a recoverable nullifier — but an **audited** one with those exact
  properties doesn't exist yet either. Swappability is real and worth keeping; it's gated on a
  conforming, audited backend *existing*.
- **The lattice ring sig is the whole risk.** Every other piece is either standardised or client-side.
  Compact **logarithmic**-proof schemes (MatRiCT family) that would also solve the linear-size problem
  (§3.3) are **ruled out today** — none has a public, production-grade, *audited* implementation, and
  porting unaudited research crypto is the opposite of de-risking. **If** an audited compact lattice
  ring/RingCT ever ships, porting it would be strictly preferable to trusting funds to a bespoke linear
  construction (and would fix §3.3) — but that is a *future contingency, not a current option.*
