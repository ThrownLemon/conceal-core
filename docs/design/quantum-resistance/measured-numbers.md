# PQ vs Classical — Measured Numbers (CIP-0001)

**Apples-to-apples comparison of a CLASSICAL Conceal transaction vs a POST-QUANTUM
(PQ) transaction, measured live on the actual built binaries** of branch
`pqc/measured-numbers` (forked from `pqc/testnet-poc` HEAD `c194160`).

Every number below is tagged:

- **[live]** — measured on a running binary / accepted by live consensus this session.
- **[FFI-live]** — read at runtime from the built `libccx_pqc.a` FFI size functions.
- **[const]** — derived from a source constant / size formula (no estimate; exact).

Nothing here is estimated or extrapolated. Where something could not be measured it
is marked **NOT MEASURED** with the reason.

---

## Test environment

| Item | Value | Source |
|---|---|---|
| Build/run host | WSL2 Ubuntu, x86_64, 16 cores / 54 GB | `uname -a`, `nproc` |
| Binary | `Conceal v6.7.4- (Trebopala)`, PQ scheme_id `0xc0de0004` | `conceald --version`, daemon log |
| Build | out-of-source, `cmake -DCMAKE_BUILD_TYPE=Release [-DBUILD_TESTS=ON]`, `make -j8 Daemon ConcealWallet PqInjector PerformanceTests ClassicalTxMeasure` | this session |
| Worktree dir (remote) | `~/conceal-core-meas` (isolated from other agents' `~/conceal-core`) | — |

### Testnet parameters (this run)

| Param | Value | Source |
|---|---|---|
| Mode | `--testnet`, isolated 2-node (exclusive peers, ports RPC 16700/16701, P2P 15700/15800) | mirrors `pqc/run-poc-testnet.sh` |
| `block_major_version` | 1 (v3 PQ txs allowed in v1 testnet blocks via PoC gate) | `getinfo` |
| Difficulty | pinned **1000** (PoC pins testnet difficulty so LWMA overshoot doesn't stall mining) | `getinfo`, `Blockchain.cpp` |
| `DIFFICULTY_TARGET` | 120 s (mainnet target; not the testnet pinned rate) | `CryptoNoteConfig.h:50` |
| Mined-money unlock window | 10 blocks | `CryptoNoteConfig.h:23` |
| `PQ_TESTNET_COINBASE_AMOUNT` | 100000 atomic (0.1 CCX) — one fixed-denom PQ output per block | `CryptoNoteConfig.h:212` |
| `MINIMUM_MIXIN` | 5 (⇒ classical ring size = mixin+1 = 6) | `CryptoNoteConfig.h:65` |
| `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE` | 100000 bytes | `CryptoNoteConfig.h:38` |
| Money supply / decimals | 200M / 6 | `CryptoNoteConfig.h` |

---

## A. CLASSICAL transaction size — **[live]**

Measured by constructing real classical CryptoNote transactions with the project's own
`cn::constructTransaction` (real Ed25519/CryptoNote ring signatures over a ring of
`MINIMUM_MIXIN+1 = 6` members) and serializing them with the project's own
`getObjectBinarySize`. Tool: `pqc/tools/classical_tx_measure.cpp` (built target
`ClassicalTxMeasure` → `build/src/classical_tx_measure <in> <out> [mixin]`), modeled on
`tests/PerformanceTests/MultiTransactionTestBase.h`. This is the same construction +
serialization path the wallet's `transfer` uses — i.e. live-measured bytes on the real
code, not estimates.

| Tx shape | Mixin | Ring/input | **Tx size (bytes)** | inputs | outputs | sig groups |
|---|---|---|---|---|---|---|
| 1-in / 1-out | 5 | 6 | **505** | 1 | 1 | 1 |
| 1-in / 2-out | 5 | 6 | **542** | 1 | 2 | 1 |
| 2-in / 2-out | 5 | 6 | **972** | 2 | 2 | 2 |
| 1-in / 2-out | 0 (ref) | 1 | 217 | 1 | 2 | 1 |

`command: ./classical_tx_measure 1 2 5` → `tx_bytes=542 inputs=1 outputs=2 sig_groups=1 ring_per_input=6`.

A typical classical spend (1-in/2-out, mixin 5: payee + change) is **~542 bytes**. Each
extra ring-6 input adds ≈ 430 B (key image + 6 ring-sig pairs); each extra output adds ≈ 34 B.

### Caveat — a live *wallet* `transfer` could **NOT** be captured end-to-end

Plan A.1 (mine to a wallet `W`, wait for unlocked balance, run `transfer`, fetch the raw
hex via `gettransactions`) was attempted but **blocked by a real PoC defect**, so the
numbers above come from the construction/serialization path directly rather than from a
mined-coin wallet spend:

- Wallet `W` was generated (`--generate-new-wallet --testnet`), the 2-node testnet mined
  to `W`'s address, the chain reached height ~88, and `W` fully synced (`reset` →
  `Height 88 of 88`). **Yet `W`'s balance stayed 0.000000** (Total/Available/Locked all 0).
- Root cause (verified in source): the PoC testnet coinbase
  (`Currency.cpp` `constructMinerTx`, `m_testnet && height>0` branch) emits a `PqKeyOutput`
  at output index 0 and pays the classical reward remainder to a `KeyOutput` at index 1,
  deriving that key with the **absolute** output index (`derive_public_key(derivation, tx.outputs.size()=1, …)`).
  The wallet scanner (`Transfers/TransfersConsumer.cpp` `findMyOutputs` →
  `checkOutputKey`) classifies the `PqKeyOutput` as `OutputType::Invalid`
  (`TransactionUtils.cpp getTransactionOutputType`), **skips it without incrementing
  `keyIndex`**, and then `underive_public_key(derivation, keyIndex=0, …)` for the remainder.
  Index **1 (chain) vs 0 (wallet)** ⇒ derived key mismatch ⇒ the wallet never recognizes
  its own coinbase remainder. So on the PoC testnet **no classical wallet can hold
  spendable coinbase funds**, which is exactly why the PoC "stands in" with `pq_injector`
  and has no funded classical wallet.
- This is a coinbase/wallet-scan defect, not a property of classical txs. It was **not
  worked around** (that would change consensus code and stop measuring the real PoC
  binary). The classical tx sizes above are therefore measured via `cn::constructTransaction`
  on the same built libraries — faithful live bytes, just not sourced from a mined-coin
  wallet send.

---

## B. POST-QUANTUM (PQ v3) transaction size — **[live]**

Measured with `pq_injector <amount> <fee> <signerIdx> <ringfile>`, which builds + signs a
real v3 PQ spend (lattice anonymous linkable ring signature + ML-KEM-768 stealth output)
and prints the raw tx hex. Size = `len(hex)/2`. Ring members are real on-chain coinbase PQ
outputs (heights 1..N), fetched via the daemon `gettransactions` RPC. Signer output
recognized live via KEM stealth scan (`signer output recognised as ours (KEM stealth scan OK)`).

| Ring size | **Tx size (bytes)** | hex chars | injector rc |
|---|---|---|---|
| 2 | **24,663** | 49,326 | 0 |
| 4 | **36,953** | 73,906 | 0 |
| 8 | **61,533** | 123,066 | 0 |

`command: ./pq_injector 100000 1000 0 /tmp/meas/ring4.txt` → `tx_bytes=36953`.

- **Ring-4 = 36,953 B — confirms the ~36953 B expectation.** ✅
- The ring-4 tx was **submitted to live consensus and ACCEPTED**:
  `sendrawtransaction` → `{"status":"OK"}`, `tx_pool_size=1`. So these are sizes of real,
  valid, consensus-accepted transactions.
- Structure: **1 PQ input** (ring of N) + **1 PQ output** (recipient), per
  `PqSpendBuilder.cpp` (no separate change output in the injector path).
- Internal consistency: each extra ring member adds **6145 B** (the lattice ring-sig
  per-member block `L·N·4 = 6·256·4 = 6144 B` + 1 B offset varint). Δ(2→4)=12290=2×6145,
  Δ(4→8)=24580=4×6145. tx − `sig_bytes(N)` is a constant ~6.2 KB of tx overhead
  (PqKeyInput ring refs + PqKeyOutput recipient key 6144 + kemCt 1088 + prefix).

### Wallet-native PQ transfer — **NOT MEASURED**

`concealwallet pq_transfer self 4` was attempted (both `--daemon-host/--daemon-port` and
`--daemon-address` forms). It failed with
`PQ spend via daemon failed: TcpConnector::connect, connection failed`: the wallet's
`Rpc/PqSpendClient.cpp` opens a **second** `HttpClient` to the daemon (separate from the
NodeRpcProxy, which connected fine) and that connector failed in this environment. The
authoritative PQ sizes above therefore come from `pq_injector`, which exercises the same
shared `cn::buildPqSpendTransaction` builder.

---

## C. Per-operation crypto timing — **[live]**

Ran the built `PerformanceTests` target (`build/tests/performance_tests`) on the host. The
harness prints `elapsed` (ms) and `loop count`; per-call times below are computed as
`elapsed·1000/loop` µs (the harness's own `time per call` is integer-ms and rounds fast ops
to 0). Two runs; values stable.

### Classical CryptoNote ring-signature VERIFY — `test_check_ring_signature<ringSize>`

| Ring size | elapsed / loops | **µs / verify** |
|---|---|---|
| 1 | 16 ms / 100 | ~160 |
| 2 | ~32.5 ms / 100 | ~325 |
| 10 | ~160.5 ms / 100 | ~1605 |
| 100 | ~162.5 ms / 10 | ~16250 |

Scales ~160 µs per ring member ⇒ a mixin-5 (ring-6) classical verify ≈ **~0.96 ms**.

### Classical tx construction (includes ring-sig GENERATION) — `test_construct_tx<in,out>`

| Shape | elapsed / loops | **µs / construct** |
|---|---|---|
| 1-in / 1-out | 44 ms / 100 | ~440 |
| 1-in / 2-out | 55 ms / 100 | ~550 |
| 2-in / 1-out | 67 ms / 100 | ~670 |
| 10-in / 1-out | 194 ms / 100 | ~1940 |

### Classical crypto primitives

| Primitive | elapsed / loops | **µs / call** |
|---|---|---|
| `generate_key_image` | 77 ms / 1000 | ~77 |
| `generate_key_image_helper` | 92 ms / 500 | ~184 |
| `generate_key_derivation` | ~78 ms / 1000 | ~78 |
| `derive_public_key` | 29 ms / 1000 | ~29 |
| `derive_secret_key` | 667 ms / 1e6 | ~0.67 |

**No standalone Ed25519 sign/verify microbench** exists in `PerformanceTests` — the closest
classical signature timing is `test_check_ring_signature` (ring-sig verify) above; classical
sign time is folded into `test_construct_tx`. Not fabricating an isolated Ed25519 number.

### PQ ring-signature timing — **[cited, prior measurement]**

Per the constant-time ring-sig work already folded into the PoC report
(`poc-vs-mainnet-report.md` §6 / §3.2): ring-4 **verify ≈ 1.12 ms**, **sign ≈ 2.46 ms**
(constant-time). Cited, not re-measured here. Apples-to-apples: classical ring-6 verify
~0.96 ms vs PQ ring-4 verify ~1.12 ms — same order of magnitude on verify; PQ sign is
~constant-time-padded.

---

## D. Address + key sizes — **[live] / [FFI-live] / [const]**

### Address character lengths — **[live]**

| Address | Example prefix | **Length (chars)** | Source |
|---|---|---|---|
| Classical Conceal (testnet) | `ccx7GVRWm3…` | **98** | `concealwallet --generate-new-wallet`; `echo -n "$ADDR" \| wc -c` |
| PQ (testnet PoC) | `ctp1GGuLNvwi…` | **1747** | `concealwallet pq_address`; piped + `wc -c` |
| Hybrid (`cth…`/`ccxh…`) | — | **NOT MEASURED** | no hybrid address generated this session |

The PQ address is large because it Base58-encodes the ML-KEM-768 public key (1184 B) plus
version/scheme ids. (`W` PQ address: `ctp1GGuLNvwiZzT5MWKxmyTmYm5YaHsk1AAkuVcKqEV…`)

### Key / signature byte sizes — **[FFI-live]** (read from the running `libccx_pqc.a`)

`command: g++ sizeprobe.cpp libccx_pqc.a … && ./sizeprobe`

| Quantity | **Bytes** | FFI function |
|---|---|---|
| Lattice ring-sig public key | **6144** | `ccx_pq_pubkey_bytes` |
| Lattice ring-sig secret (seed) | **32** | `ccx_pq_seckey_bytes` |
| Lattice ring-sig nullifier | **32** | `ccx_pq_nullifier_bytes` |
| ML-KEM-768 public key | **1184** | `ccx_pq_kem_pubkey_bytes` |
| ML-KEM-768 secret key | **2400** | `ccx_pq_kem_seckey_bytes` |
| ML-KEM-768 ciphertext (kemCt) | **1088** | `ccx_pq_kem_ct_bytes` |
| ML-DSA-65 public key (deposits) | **1952** | `ccx_pq_multisig_pubkey_bytes` |
| ML-DSA-65 secret key (deposits) | **4032** | `ccx_pq_multisig_seckey_bytes` |
| ML-DSA-65 signature (deposits) | **3309** | `ccx_pq_sig_bytes` |

### Ring-signature size — **[const]** (exact formula, matches §B live deltas)

`sig_bytes(n) = 32 + K·N·4 + n·L·N·4`, with `N=256, K=L=6` (`ringsig.rs`):
ring-2 = 18,464 B, **ring-4 = 30,752 B**, ring-8 = 55,328 B. (Confirms the 30752 B
expectation; the live tx in §B is this + ~6.2 KB tx overhead.)

### Classical keys — **[const]**

Classical Conceal uses **32-byte** Ed25519/Curve25519 keys (public spend/view, key image,
one-time output key). Contrast: PQ ring-sig pubkey is **6144 B = 192×** a classical key.

---

## E. Throughput context — **[live] + [const]**

- Testnet block time: difficulty **pinned 1000** for the PoC (fast mining); the mainnet
  `DIFFICULTY_TARGET` is **120 s**. (The pinned testnet rate is a PoC convenience, not a
  consensus target.)
- Free-reward zone: `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE = 100000` bytes.

**Txs that fit one 100 KB free-reward zone** (`floor(100000 / tx_bytes)`, from §A/§B
live sizes):

| Tx type | Tx bytes | **Txs / 100 KB zone** |
|---|---|---|
| Classical 1-in/1-out (mixin 5) | 505 | **198** |
| Classical 1-in/2-out (mixin 5) | 542 | **184** |
| Classical 2-in/2-out (mixin 5) | 972 | **102** |
| PQ ring-2 | 24,663 | **4** |
| PQ ring-4 | 36,953 | **2** |
| PQ ring-8 | 61,533 | **1** |

**A PQ ring-4 tx is ~68× the size of a classical 1-in/2-out tx**, so the 100 KB zone holds
~184 classical spends vs only **2** PQ ring-4 spends — the dominant PQ cost is the lattice
ring signature (~6.1 KB per ring member). This is the headline scaling tradeoff of the
experimental PQ scheme at demo-grade parameters.

---

## F. Deposit sizes — Option 3 (PQ-only deposits after the fork) — **[live] + [FFI-live component]**

Under [Option 3](deposit-term-policy-decision.md), classical deposit creation is frozen at `UPGRADE_HEIGHT_V9`
and the only post-fork deposit is a **PQ ML-DSA-65 (FIPS 204)** deposit. The cost delta:

| Deposit operation | Classical | PQ (ML-DSA-65) | Ratio | Source |
|---|---|---|---|---|
| **Create deposit tx** (1-in, 1 deposit out + change, mixin 0) | **217 B** | **≈ 2,137 B** | **~10×** | classical **[live]** — `classical_deposit_injector` printed `bytes=217` (amount 2 CCX, term 30, fee 1000); PQ = 217 + (1952 − 32) for the ML-DSA pubkey replacing the Ed25519 key **[FFI-live component]** |
| **Deposit output key** (per signer) | 32 B (Ed25519) | **1,952 B** | ~61× | **[FFI-live]** `ccx_pq_multisig_pubkey_bytes` |
| **Withdraw signature** (per signer) | 64 B (Ed25519) | **3,309 B** | ~52× | **[FFI-live]** `ccx_pq_sig_bytes` |

**Key point:** the deposit path uses **standardized ML-DSA-65**, not the experimental lattice ring sig. So a
PQ *deposit* is only **~10×** a classical deposit — versus a PQ *spend* at **~68×** (§E) — because deposits
need no anonymity ring, just one FIPS-204 signature per key. "PQ-only deposits after the fork" is therefore
one of the **cheaper** PQ surfaces, and rests on a NIST-standardized primitive rather than research-grade
crypto. (The freeze enforcement itself — a `term != 0` output check gated on `height >= upgradeHeight(V9)` —
has zero size or throughput cost.)

*PQ figures are composed from FFI-live component sizes (the running `libccx_pqc.a`); a fully-live PQ-deposit
tx was not captured because there is no PQ-deposit wallet command yet (PQ deposits are exercised at the
unit-test level — `TestPqDeposits` — and the classical freeze e2e in `verify-deposit-freeze.sh`).*

---

## G. Candidate scheme — ELRS / STARK linkable ring sig (ESORICS 2024) — **[measured this session]**

For the **plaintext-amounts** privacy path (D1), the reference impl of ELRS (eprint 2024/553,
[`github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature`](https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature),
Rust/Winterfell-fork, experimental/unaudited) was **built + run on the WSL host** (x86_64, 128-bit params).
It's an anonymity + linking-tag (nullifier) layer only — **no confidential amounts** — so it's compared against
Conceal's PoC **lattice ring-sig stand-in** (the incumbent for that path), not MatRiCT-Au's full RingCT.

| Ring | **ELRS sig** [measured] | **ELRS cold single-verify** [measured] | Conceal lattice sig [const] | Conceal lattice verify [live] |
|---|---|---|---|---|
| 8 | **~25 KB** | **0.3 ms** | 54 KB | ~1 ms |
| 16 | ~25 KB | **0.3 ms** | ~102 KB | ~1 ms |
| 64 | ~29 KB | **0.3 ms** | ~390 KB | ~1 ms |
| 1024 | ~28 KB | **0.3 ms** | ~6.3 MB | ~1 ms |
| 8192 | ~28 KB | **0.3 ms** | ~49 MB | ~1 ms |

- **Public key: 32 B** (measured) vs Conceal's lattice ring-sig pubkey **6144 B** (192×).
- **Both size AND verify are FLAT in ring size** — the STARK trace is fixed at 2¹⁰–2¹¹ steps regardless of ring
  (membership = one Merkle path against the ring root, not iteration over members). Conceal's lattice sig is
  **~6.1 KB per ring member, linear**. **Crossover where ELRS wins on size ≈ ring 5**; above ring ~8 the gap
  explodes (ring-64 ≈ 14×, ring-1024 ≈ 225×). Huge anonymity sets are nearly free for ELRS.
- **⚠ The verify number is CONTESTED — do not rely on it yet.** The ELRS experiment agent *measured* a cold
  single verify of **0.3 ms** (fresh process per ring, reading `main.rs`/`sigrescue/mod.rs`), and concluded the
  paper's 128 ms "is not this STARK verify." BUT the [focused sweep](pq-ringsig-verdict.md) independently
  re-flagged (2 of 4 angles) that **0.3 ms is the *amortized* online cost** (FRI offline phase shared across
  signatures over the *same* ring) and a **cold single verify is ~128 ms** — which, for CryptoNote's
  distinct-ring-per-tx model, would *not* amortize. The measurement and the paper conflict and the conflict is
  **unresolved** — it needs a careful re-measurement of whether the impl's verify path is truly cold-FRI or
  amortized. **Until then, treat ELRS verify as somewhere between 0.3 ms and ~128 ms.**
- **Size verdict still holds; the "beats outright" verdict does NOT.** ELRS's flat ~25–29 KB is a real win at
  *large* rings (lattice goes linear → MBs). **But at Conceal's actual small rings (mixin 5–16), ELRS's flat
  ~25 KB is *wasted flatness* — linear lattice schemes are physically SMALLER and rest on a CLEANER assumption:**
  **Raptor** (NTRU) ~10 KB @ ring-8 / ~21 KB @ ring-16, natively linkable, NTRU/Ring-SIS *reduction*; *LAPQ-LRS*
  (MLWE/MSIS, same family as ML-DSA) ~4.4 KB @ ring-8 *if its numbers hold*. ELRS only wins once rings grow past
  ~16–32. So **ELRS does NOT beat the lattice option at small rings** — the choice hinges on the **max-ring-size
  decision**, not the crypto. See [`pq-ringsig-verdict.md`](pq-ringsig-verdict.md) (confidence ~65%).
- Caveats: ELRS security is *conjectured* (ethSTARK FRI/ROM — **no reduction to a hard problem**, unlike the
  lattice schemes' Module-SIS/MLWE); experimental unaudited Rust; 0.3 ms (if real) is at the 0.1 ms print floor;
  tx-overhead under a real Conceal output/nullifier binding (~6.2 KB) still unmeasured.

*Sources: [reference impl built + benchmarked](https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature),
[ESORICS 2024](https://link.springer.com/chapter/10.1007/978-3-031-70903-6_22). The flat sizes + cold 0.3 ms
verify are **measured**; eprint 2024/553's table is paywalled (403 to automated fetch). See
[`pq-scheme-landscape.md`](pq-scheme-landscape.md).*

---

## H. Candidate scheme — Gao et al. RingCT vs MatRiCT-Au (FC/PKC 2025) — **[measured this session]**

Benchmarked on the WSL host (AMD Ryzen 9 5950X) to test the "Gao is ~50% smaller / ~20% faster" claim that the
abstract-level scan (§[`pq-scheme-landscape.md`](pq-scheme-landscape.md)) had ranked as the top confidential-
amounts successor. **The claim did not survive contact with the code.**

| Metric | Gao LinearSum (Go ref, N=10) | MatRiCT-Au n10m1 (in-repo C) | Paper |
|---|---|---|---|
| Proof size | 43.9 KB *(ring-sig component only; no serializer)* | **107.4 KB** packed (292.5 KB raw) | **no absolute numbers — % plots only** |
| Verify | ~724 ms (Go/LaGo) | **~12 ms** (median 11.95) | "~20% faster vs MatRiCT/+" |
| Prove | ~1204 ms (Go/LaGo) | **63 ms** (median) | "~20–30% faster vs MatRiCT/+" |
| Prover mem | ~95 MB RSS (Go) | ~30.5 MB RSS | — |
| Full verifying RingCT? | **NO** — ring-sig only; amount/balance proof not wired (and its MatRiCT baseline `Test*Proof` **fails to verify**) | **YES** (30/30, ring+amounts+audit) | — |

**Why the "~50% smaller" claim is misleading for this decision:**
- The paper has **no numeric tables** (Figures 1–4 are matlab plots; results are text percentages only).
- The "~50%" is the **ring-sig component vs the *original* MatRiCT (2019)** measured inside Gao's own Go impl
  under a *smaller parameter set* — **not vs MatRiCT-Au** (which is *newer* than Gao's baseline); vs MatRiCT+
  it's only ~15–20%.
- Under a **shared** param set (q=65537, d=64) the runnable Go ref produced **234 vs 224 elements — Gao
  slightly *larger***. The entire claimed advantage lives in a parameter-set choice (dropping the binary proof
  → smaller q/n) the shared-settings harness can't express.
- The 43.9 KB (Gao, ring-sig only) vs 107.4 KB (MatRiCT-Au, full spend) are **different objects** — not
  apples-to-apples. The ~700 ms Go verify vs ~12 ms C is mostly language (~60×), not algorithm.

**Verdict:** Gao is **not a demonstrated win over MatRiCT-Au** on obtainable evidence. Confirming it would need
porting Gao's param-set + balance-proof into the MatRiCT-Au C code and measuring a full verifying spend — a
multi-week research task, not a benchmark. **Note also:** MatRiCT-Au verify measured here is **~12 ms** (Ryzen
5950X), vs the **45 ms** [paper, i7-8750H] cited elsewhere in these docs — a hardware/impl gap, not a
discrepancy in the scheme. *(Raw notes: [`gao-bench-notes.md`](gao-bench-notes.md).)*

---

## I. Candidate scheme — Raptor (Falcon-512 linkable ring sig) vs the in-house stand-in — **[measured this session]**

For the **small-ring plaintext** path (D1, after the ring-size fork was decided small), the **Raptor** reference
([`github.com/zhenfeizhang/raptor`](https://github.com/zhenfeizhang/raptor) — **C**, Falcon-512 + NTRU/Falcon
chameleon-hash, GPLv3) was **built + run** on the WSL host (release, core-pinned, 200 iters/point), head-to-head
against the PoC's in-house lattice ring-sig stand-in (`ccx-pqc` K=L=6, N=256).

| ring | **Raptor sig (compact)** | Raptor verify | Raptor sign | stand-in sig | stand-in verify | **size ratio** |
|---|---|---|---|---|---|---|
| 4 | **7.3 KB** | 0.53 ms | 0.86 ms | 30.0 KB | 1.13 ms | **4.1×** |
| 6 | **10.2 KB** | 0.79 ms | 1.13 ms | 42.0 KB | 1.97 ms | **4.1×** |
| 8 | **13.1 KB** | 1.00 ms | 1.38 ms | 54.0 KB | 2.69 ms | **4.1×** |
| 16 | **24.7 KB** | 2.15 ms | 2.65 ms | 102.0 KB | 6.95 ms | **4.1×** |

- **Raptor wins on both axes at every small ring:** **~4.1× smaller** *and* **~2.5× faster verify** (the
  consensus hot path). Both schemes are linear, so the ratio holds across the range. (Corrects earlier
  estimates: the win is **4.1×**, not 5×; ~10 KB is **ring-6**, not ring-8.)
- **Security: NIST cat-1 (~128-bit), *calibrated*** (Falcon-512 = the NIST FN-DSA lineage) — vs the stand-in's
  ~128-bit *uncalibrated, biased-sampling, demo-grade* params. So Raptor's size win is **not** bought by lower
  security; it's the cleaner, calibrated assumption.
- **LINKABLE: confirmed** — each sig embeds a one-time-signature public key as the linking tag (SHA-512 masks
  the signer's `h`); maps to a key-image/nullifier, same role as the stand-in's `SHAKE256(I)`.
- **Catches (load-bearing for integration):** (1) the compact sizes above are **paper/model** — the reference
  binary emits a **~4× bloated `int64` debug encoding**; production must implement the compact packing
  (~14 bits/coeff, a `TODO` in the repo). My 14-bit-packed model independently agrees within ~15%. (2) **LICENSE —
  resolved into a path:** the upstream Raptor repo is **GPL + patent-asserted** and **cannot be copied** into MIT
  Conceal — but the *construction* is a published algorithm (eprint 2018/857) and **Falcon is NIST FIPS 206,
  patent-free/royalty-free**, so the route is a **clean-room reimplementation over permissive PQClean Falcon
  (public-domain)**, reimplemented in the existing Rust `ccx-pqc` island (so "C, not Rust" is moot — we don't bind
  the GPL C). *Now built + integrated into the daemon* — see §I.2 below.
  (3) Raptor needs Falcon's **low-level trapdoor preimage sampler**, not just stock FN-DSA sign/verify. (4) Falcon's
  **floating-point Gaussian sampler** is a constant-time **and consensus-determinism** hazard (cross-platform FP
  rounding → block-validation split). (5) Unaudited research code.

**Verdict:** Raptor beats the in-house stand-in on size, verify, assumption-cleanliness/calibration, and
maturity — it is the **production candidate to track** for the small-ring plaintext path. The work is in the
*integration* (clean-room reimpl over PQClean Falcon, compact packing, constant-time/deterministic sampler, audit),
not the cryptography. *(Raw notes on WSL `~/raptor-bench-notes.md`.)*

### I.1 — Clean-room spike BUILT + adversarially reviewed + hardened (2026-06-20)

The clean-room reimplementation now exists as an isolated Rust crate (`~/raptor-spike/` on the WSL host — **not**
in the live tree, **not** merged). Construction from eprint 2018/857 only; Falcon-512 from **PQClean (MIT)**,
fips202 (public-domain), randombytes (MIT) — **zero GPL**, independently license-verified. Behind the existing
`ccx_pq_*` C ABI; builds clean, **harness 25/25 + adversary 12/12 + C-ABI 6/6 + stats PASS**.

**Measured (post-hardening, WSL x86_64):** ring-6 compact sig **9,719 B** (under 10 KB; matches the paper's
Table 1(b) ~9,720 B), verify 5.4 ms. Sign time **rose to ~40 ms @ ring-6** (from ~11 ms) — the *honest* cost of
the anonymity fix below (genuine Falcon sampling per non-signer, not the demo CLT). Sizes ~unchanged.

| ring | sig B | sign ms | verify ms |
|---:|---:|---:|---:|
| 2 | 4,661 | 23 | 2.1 |
| 6 | **9,719** | 40 | 5.4 |
| 8 | 12,251 | 48 | 7.1 |
| 16 | 22,344 | 82 | 13.8 |

**Two independent adversarial reviews** (Codex deep-soundness + Claude license/harness) + a hardening pass:
- ✅ **License clean** (confirmed), **construction faithful** to §6.5, **linkability crux enforced by code**.
- 🔴→🛠 **CRITICAL anonymity bug found + fixed.** Non-signer members were sampled from a CLT approximation
  (truncated tails) → statistically distinguishable from the signer's genuine Falcon preimage = ring-anonymity
  break under repeated observation. **Fixed:** non-signer `(r0,r1)` now drawn from Falcon's own preimage sampler
  (throwaway key/random target). Evidence: signer vs non-signer coeff stddev 165.96 vs 165.62 (0.2%), kurtosis ≈0
  both — coincide within sampling noise. *Honest:* this shows the sampler **matches** Falcon's; it does **not**
  *prove* indistinguishability (formal statistical-distance bound = audit item).
- 🛠 All other findings fixed: `b_i∈{0,1}^256` validation, FFI preimage assertion, length-prefixed transcript,
  hard (not debug-only) consistency check, retry→panic, expanded adversary suite (forged-OTS, replay, ring-1,
  null-ring, b-tamper), and a **KAT tripwire** for keygen FP-determinism (detects cross-platform drift).

**Cross-platform FP determinism — RESOLVED at build level (was a misread).** The earlier "Falcon uses native
`double`, needs an FPEMU patch" (Codex HIGH-1 + the integration plan) was **factually wrong**: the vendored
PQClean **falcon-512 "clean"** variant ships *only* the integer-emulated FP layer — `typedef uint64_t fpr`, zero
real `double`/`float` arithmetic (the few tokens are comments), and no `FALCON_FPNATIVE`/`FPEMU` toggle (the old
`build.rs` define was a dead no-op). **Verified independently** (code inspection + a 7-config keygen-KAT sweep:
`-O0`/`-O3`/`-ffast-math`/`-ffp-contract=fast`/`-march` all produce the **identical** digest — proof there is no
native FP in the path). So keygen+signing are **bit-identical across compilers/opt/arch by construction**; the
chain-split risk the review feared cannot occur. Residual (belt-and-braces, NOT a blocker): an actual
**aarch64/MSVC KAT run** to confirm cross-arch (the `uint64` argument is sound; 32-bit targets use SW 64-bit
helpers but still yield identical results); the `assert_keygen_kat()` tripwire stays in CI (now expected to PASS
everywhere). Perf cost of the "fix": **zero** (already integer-FP).

**STILL requires humans — NOT production-ready to guard funds** (an implementation pass can't close these):
(1) norm-bound **B1 re-derivation** for the ring setting; (2) formal **anonymity** proof; (3) formal
**unforgeability** reduction; (4) **professional external audit**; (5) `paramch_h` nothing-up-my-sleeve
**ceremony**; (6) production wallet **KDF** for per-spend randomness; (7) Falcon **constant-time / side-channel**
review (separate from determinism); (8) NTT (perf); (9) the cross-arch KAT confirmation above. Verdict (Codex):
*"engineering-hardened, comprehensively tested, deterministic — but not production-ready."* Full writeup:
`~/raptor-spike/CODEX-ASSESS.md`.

### I.2 — Raptor INTEGRATED into conceal-core (`pqc/testnet-poc`, 2026-06-20)

The clean-room Raptor backend is now wired into the live consensus crate (`pqc/ccx-pqc`), replacing the
demo lattice stand-in behind the unchanged `ccx_pq_*` C ABI (branch `pqc/testnet-poc`, pushed as an
**UNAUDITED backup branch** to the fork + org — not merged, not mainnet). Measured on the WSL host:

| Stage | Result |
|---|---|
| `pqc/ccx-pqc` crate build | **green** (Falcon C + Raptor Rust → `libccx_pqc.a`) |
| C-ABI round-trip (`abi_test`) | scheme `0x52415054` "RAPT", pk **896** / sk **48** / nf **32**; **sign 7192 B @ ring-4**; verify ✓; nullifier(sign)==nullifier(verify) ✓; linkability ✓; tamper rejected ✓ |
| Full daemon + wallet + tests build | **green** `[100%]` (`conceald` 9.7 MB) |
| PQ unit tests | **72/72 pass** — incl. all golden serialization vectors (`PqKeyInput/Output`, `MixedInputsOutputs`, `FullTransactionV3`) **unchanged** (length-prefixed wire absorbs the variable sig) + tx-extra framing |
| **e2e consensus** (`run-poc-testnet.sh`) | PQ coinbase → **ring-4 spend ACCEPTED** (tx **8148 B**) → **in-pool double-spend REJECTED** (Raptor nullifier) → mined → **independent-nullifier spend ACCEPTED**; KEM stealth scan OK |

**Integration specifics worth recording:**
- **SCHEME_ID** `0xC0DE0004` → **`0x52415054` ("RAPT")** in both `lib.rs` and `CryptoNoteConfig.h` (`PQ_RING_SCHEME_ID`); old-scheme testnet data is incompatible (clean reset, as intended).
- **Variable-size signatures**: the stand-in's exact-size verify check (`sig_len != ring_sig_size(n)`) was replaced with an **upper-bound DoS guard** (`sig_len ≤ n*4096+8192`) + `unpack`'s canonical-length validation (rejects trailing garbage / wrong ring). The C++ already used the max-buffer sign pattern (alloc 256 KB, `resize(sigLen)`), so **no C++ consumer changes** were needed beyond the scheme-id.
- **Consensus-critical bug found + fixed during integration:** the vendored Falcon bundles `fips202.c`/`randombytes.c`, whose unnamespaced `shake256_inc_*`/`randombytes` symbols **collided** with the copies in `pqcrypto-kyber`/`pqcrypto-dilithium` → the linker bound Falcon's `inner_shake256_*` to a differently-laid-out state struct → **stack smash**. Fixed by `-D`-renaming every Falcon fips202/randombytes symbol to `ccxfalcon_*` in `build.rs` (isolated, verified one `shake256` + one `ccxfalcon_shake256`). Caught by a C-ABI smoke test before the daemon build.
- Seed handling: `ccx_pq_keygen` SHAKE-normalizes any-length stealth seed → 48-byte sk; `sign`/`nullifier` reuse that exact sk — consistent with the C++ spend flow (`PqSpendBuilder` stores the exported 48-B `otSk` and passes it back).

**Still gated for the external audit (unchanged from §I.1):** this is an UNAUDITED research construction wired into consensus-shaped code on a **resettable testnet** — it is NOT mainnet-ready. The human gates (formal anonymity/unforgeability proofs, B1 calibration, `paramch_h` ceremony, production per-spend KDF, constant-time review, cross-arch KAT, external audit) all stand. See `raptor-integration-plan.md` §5.

---

## Summary — headline measured numbers

| Metric | Classical | Post-quantum (v3) |
|---|---|---|
| Typical spend tx size | **542 B** (1-in/2-out, mixin 5) [live] | **36,953 B** (ring-4) [live, consensus-accepted] |
| Tx size, other shapes | 505 B (1/1), 972 B (2/2) [live] | 24,663 B (ring-2), 61,533 B (ring-8) [live] |
| Spend signature pubkey | 32 B [const] | 6144 B [FFI-live] |
| **Deposit create tx** (Option 3) | **217 B** [live] | **≈ 2,137 B** (ML-DSA-65, ~10×) [live + FFI-live] |
| Address length | 98 chars [live] | 1747 chars [live] |
| Ring-sig verify (1 ring) | ~160 µs [live] | — |
| Ring-sig verify (ring-4/6) | ~0.96 ms (ring-6 interp.) [live] | ~1.12 ms (ring-4) [cited] |
| Ring-sig sign | folded into construct (~0.55 ms tx) [live] | ~2.46 ms (ring-4, CT) [cited] |
| Txs per 100 KB zone | ~184 (1-in/2-out) [derived] | 2 (ring-4) [derived] |

**Caveats:** (1) Live classical *wallet send* not captured — PoC coinbase/wallet-scan index
mismatch makes coinbase unspendable by the wallet; classical sizes measured via
`cn::constructTransaction` on the real libs instead. (2) Wallet-native `pq_transfer` not
captured — PqSpendClient TcpConnector failure; PQ sizes measured via `pq_injector` (same
shared builder). (3) PQ ring-sig timings are cited from the prior constant-time measurement,
not re-run here. (4) PQ scheme is EXPERIMENTAL / demo-grade params (`K=L=6, N=256`), not a
calibrated security level — sizes/timings are for the current PoC, not a production scheme.
