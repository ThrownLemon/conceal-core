# PQ Ring Signature — Performance / Throughput / Speed Review

Branch: `pqc/testnet-poc`. Scope: the EXPERIMENTAL lattice AOS/LSAG linkable ring
signature in `pqc/ccx-pqc/src/ringsig.rs`, its verify cost in block validation
(`src/CryptoNoteCore/Blockchain.cpp::check_pq_tx_input`), tx/block size, mempool,
mining, and CPU-DoS exposure. All numbers measured on the WSL host
(AMD Ryzen 9 5950X, 16c, Ubuntu x86_64), single-threaded `--release`.

## TL;DR

The lattice ring sig is **structurally fine but ~10× slower to verify and ~80×
larger** than the EC baseline at ring-4, and verify cost is **linear in ring size
N with no upper bound enforced on the PQ path**. The single worst issue is a
**cheap CPU-DoS**: `check_pq_tx_input` (`Blockchain.cpp:2441`) runs full lattice
verification with **no cap on N** (the existing ring-size guard at `Blockchain.cpp:2401`
lives in the EC `check_tx_input` path and does NOT apply to PQ inputs), and the
schoolbook `poly_mul` (N²=65536 i128 mults per multiply) is the bottleneck. The
biggest, safest speedup is an **NTT** (≈100× on `poly_mul`), then caching A/A2,
then a hard N cap + size accounting.

## Measured cost (Ryzen 9 5950X, single thread, real `ringsig.rs`)

Lattice ring sig (`pqc/ccx-pqc/src/ringsig.rs`, params N=256, q=8380417, K=L=4):

| ring N | sig size | sign | verify |
|-------:|---------:|-----:|-------:|
| 1  |   8 224 B |  2.7 ms |  1.8 ms |
| 2  |  12 320 B |  4.4 ms |  3.5 ms |
| 4  |  20 512 B |  8.2 ms |  6.9 ms |
| 8  |  36 896 B | 14.8 ms | 14.0 ms |
| 16 |  69 664 B | 30.1 ms | 29.0 ms |
| 32 | 135 200 B | 63.2 ms | 62.1 ms |

EC baseline (`crypto::check_ring_signature`, same machine, Ed25519):

| ring N | sig size | verify |
|-------:|---------:|-------:|
| 1  |     64 B | 0.18 ms |
| 4  |    256 B | 0.70 ms |
| 16 |  1 024 B | 2.83 ms |
| 32 |  2 048 B | 5.97 ms |

**Ring-4 head-to-head:** verify 6.9 ms vs 0.70 ms (**~10× slower**); size 20 512 B
vs 256 B (**~80× larger**). Both scale linearly in N; the lattice slope is
~1.9 ms/member (verify) vs ~0.18 ms/member for EC. Sign ≈ verify (no rejection
re-rolls observed at these params; the `for attempt in 0..256` abort loop in
`sign()` succeeds on the first attempt in practice).

Sig-size formula (`ringsig.rs:134`): `32 + K·N·4 (tag) + n·L·N·4` = `4128 + n·4096`
bytes. Confirmed: ring-4 = 20 512 B exactly.

## Where the time goes (poly-mult count)

`poly_mul` (`ringsig.rs:40`) is **negacyclic schoolbook**: for each of N=256
output coeffs it sums N=256 i128 products ⇒ **65 536 i128 multiplies per poly
multiply**, plus a `cmod` (`%`) per coeff. That single op is the entire cost
centre.

Per ring member, `verify` (`ringsig.rs:248-259`) does:
`A·z_i` = K·L = 16 muls, `A2·z_i` = 16 muls, `c·t_i` = K = 4 muls,
`c·I` = 4 muls ⇒ **40 `poly_mul`s/member** = ~2.6M i128 mults/member.
Measured ~1.9 ms/member ÷ 40 ≈ **~47 µs per `poly_mul`** — consistent with
65 536 i128 mults + reductions.

Fixed per-verify overhead: `matrix_a()` + `matrix_a2()` (`ringsig.rs:234-235`)
**regenerate both public matrices from SHAKE256 on every verify** —
`gen_matrix` (`ringsig.rs:79`) draws K·L·N = 4 096 `u32` per matrix ⇒ 8 192 SHAKE
draws/verify. Measured small (≈0.4 ms, swamped by the per-member muls because the
intercept of the linear fit is near zero), but it is pure waste: A and A2 are
**compile-time constants** and are re-derived on every sign and every verify.

## Impact on consensus throughput

### 1. Per-tx verify cost in block validation (CRITICAL path)

`check_pq_tx_input` runs inside `checkTransactionInputs` (`Blockchain.cpp:2295`),
i.e. on **every node, for every PQ input, every time a block is validated** (and
again on mempool admission). At ring-4 that is ~6.9 ms of pure CPU per PQ input.

There is a result cache (`Blockchain.cpp:395-425`, the `maxUsedBlock`/`lastFailed`
memo) that skips re-checking an already-validated tx, so a *steady-state* node
that already saw the tx in its pool pays once. But: (a) initial sync / reorg /
alt-chain replays re-run verify from scratch; (b) a tx that is invalid for the
current height still pays full verify before being cached as failed; (c) the memo
keys on block height/id, so it does not protect against a flood of *distinct*
invalid txs (see DoS below).

### 2. CPU-DoS — no ring-size cap on the PQ path (worst bottleneck)

`check_pq_tx_input` accepts **any** `txin.outputIndexes.size()`. The only PQ guard
is `outputIndexes.empty()` (`Blockchain.cpp:2272`). The ring-size lower-bound
check at `Blockchain.cpp:2401` (`Expected: 4`) is in the **EC** `check_tx_input`
and never runs for `PqKeyInput`. Verify cost is linear and unbounded in N:

- `CRYPTONOTE_MAX_TX_SIZE_LIMIT` = 100000 − 600 ≈ **99 400 B** per tx
  (`CryptoNoteConfig.h:95`). One PQ ring sig of N ≈ (99400 − 4128)/4096 ≈ **23
  members** fits in a single max-size tx ⇒ **~44 ms verify for one tx** (1.9 ms ×
  23). A block can hold ~`MAX_BLOCK_SIZE_INITIAL` = 1 MB of such txs ⇒ on the
  order of **~10 PQ txs ≈ ~440 ms of verify for a single block**, single-threaded,
  on every validating node, for a 120 s block target. That is ~0.4% of block time
  for one crafted block, but an attacker spamming the mempool with **distinct**
  invalid max-ring PQ txs (each forcing a full ~44 ms verify before rejection,
  each with a fresh nullifier so the cheap `m_spent_pq_nullifiers` check at
  `Blockchain.cpp:2279` misses) can burn CPU cheaply: ~23 verify-ms per ~99 KB tx,
  far more expensive to verify than to construct/relay. The EC path is naturally
  bounded to ring 4; the PQ path is not.
- **Ordering also matters:** in `check_pq_tx_input` the expensive `ccx_pq_verify`
  (`Blockchain.cpp:2524`) runs *after* ring resolution but the nullifier-spent
  short-circuit (`Blockchain.cpp:2279`) is keyed on the *declared* nullifier,
  which an attacker varies per tx — so the cheap reject doesn't fire and every
  spam tx reaches full verification.

### 3. Transaction size vs network / block

Ring-4 PQ tx ≈ 24.7 KB (POC figure; the ring sig alone is 20.5 KB). vs a normal
CCX tx of a few hundred bytes. Consequences:

- **Block capacity collapses:** at ~24.7 KB/tx the ~100 KB full-reward zone
  (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE`, `CryptoNoteConfig.h:38`) holds only
  ~4 PQ txs before the miner must grow the block (and pay the penalty curve).
  Effective PQ TPS at ring-4 is ~4 tx / 120 s ≈ **0.03 tx/s** at the reward-zone
  boundary.
- **Propagation/bandwidth:** ~80× the bytes of an EC tx per spend; gossip volume
  and `tx_pool` serialization scale accordingly.
- The PQ coinbase output (kemCt) grew the coinbase to ~3.1 KB (POC), eating into
  the 600 B `CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE` assumption — out of scope for
  ring-sig but worth flagging for block-size accounting.

### 4. Mempool memory

Each unconfirmed ring-4 PQ tx is ~24.7 KB resident vs hundreds of bytes for an EC
tx. The in-pool PQ nullifier set is bounded (32 B/entry) and fine; the dominant
memory cost is the raw tx blobs. A mempool sized by *count* rather than *bytes*
would be ~80× heavier under PQ traffic.

### 5. Mining / template impact

Block template assembly calls input validation; large slow-to-verify PQ txs make
template building and the miner's own block-validity self-check more expensive,
and the ~24.7 KB/tx footprint limits how many fee-paying txs fit. Not a
correctness issue, but reduces miner throughput and raises orphan risk if verify
time eats into propagation budget.

## Comparison summary (ring-4)

| metric | EC (Ed25519) | Lattice PQ | ratio |
|---|---|---|---|
| verify | 0.70 ms | 6.9 ms | ~10× |
| sig size | 256 B | 20 512 B | ~80× |
| verify slope | 0.18 ms/member | 1.9 ms/member | ~10× |
| txs / 100 KB reward zone | ~hundreds | ~4 | — |
| ring-size cap enforced | yes (4) | **no** | — |

## Concrete speedups (ranked by impact)

1. **NTT instead of schoolbook `poly_mul`** (biggest win). q=8380417 is the
   Dilithium prime and is NTT-friendly (X²⁵⁶+1, 512th root of unity exists).
   Forward/inverse NTT + pointwise turns each multiply from 65 536 i128 mults
   into ~256·log₂256 ≈ 2 048 ops ⇒ **~50–100× on `poly_mul`**, i.e. ring-4 verify
   from ~6.9 ms toward **~0.1 ms** — at or below the EC baseline. Keep operands in
   NTT domain across `mat_vec` to avoid re-transforming A/A2/t.
2. **Cache A and A2** (`matrix_a()`/`matrix_a2()`, `ringsig.rs:92-93`,
   `234-235`). They are constants; precompute once (ideally pre-transformed into
   NTT domain) instead of re-deriving 8 192 SHAKE draws on every sign/verify.
   Saves the fixed ~0.4 ms/verify and all of sign's matrix gens.
3. **Hard cap N for PQ inputs in `check_pq_tx_input`** (mirror the EC ring policy;
   testnet uses ring-4). Reject `outputIndexes.size() > N_MAX` *before* any
   `poly_mul`. Removes the unbounded-N DoS and makes per-tx verify cost constant.
4. **Account PQ ring sigs in size/fee limits** so a max-size tx can't smuggle a
   23-member ring; tie a minimum fee to verify cost (anti-DoS pricing), and reject
   oversized PQ txs cheaply at deserialization.
5. **Batch verification** across a block's PQ inputs (shared A/A2 in NTT domain;
   batch the SHAKE/`sample_challenge` and the `mat_vec` accumulations). Amortizes
   setup and improves cache locality.
6. **Smaller / calibrated params.** Demo uses 32-bit-padded i32 coeffs
   (`put_poly`, `ringsig.rs:124`) — bit-pack z to ~20 bits and the tag to the real
   coeff range to cut sig size materially. (Security calibration is a separate
   workstream; do not shrink K/L/N for speed without a security argument.)
7. **Constant-time + parallelism.** Per-input verify is independent ⇒ validate a
   block's PQ inputs across threads. (CT is a security requirement, noted in POC,
   not a perf lever per se.)

## Throughput-breaking / DoS flags

- **CPU-DoS (HIGH):** unbounded ring size N on the PQ verify path ⇒ ~44 ms/tx
  worst case, and distinct-nullifier spam bypasses the cheap reject. Cap N + price
  verify before merging to any real network.
- **Schoolbook `poly_mul` (HIGH for throughput):** 65 536 i128 mults/multiply is
  the root cause of both the ~10× verify gap and the DoS amplification; NTT is the
  fix.
- **Wasted matrix regeneration (MEDIUM):** A/A2 re-derived from SHAKE every
  sign/verify.
- **Size/propagation (MEDIUM):** ~80× tx bloat throttles block capacity to ~4
  PQ tx/reward-zone and ~80× gossip/mempool bytes.

All findings are testnet-gated and the code is explicitly labelled
EXPERIMENTAL/DEMO; none of this is a mainnet regression today. The numbers exist
to scope the production hardening (CIP-0001 C1: NTT, params, audit).
