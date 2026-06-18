# PoW / Hashing Hardening Against Grover — Design Blueprint

Scope: the Proof-of-Work and hashing layer of Conceal Core, assessed against a
**Grover-class** quantum adversary (quadratic speedup on unstructured search /
preimage), NOT a Shor-class adversary (which breaks ECDLP and is the subject of
the separate signature/key-image PQC work). This document deliberately stays in
its lane: it covers block PoW, the difficulty target, the nonce search space,
and the structural hashes (block id, tx id, key image, merkle/tree hash). It
does **not** cover ring signatures, stealth addresses, or KEM — those are
Shor-exposed and handled elsewhere (`pqc/`, `docs/specs/quantum-resistance/`).

Bottom line up front: **the symmetric/hash layer needs essentially no consensus
change for Grover.** Every hash that matters is 256-bit, giving a 128-bit
post-Grover security floor, which is the accepted long-term target. The only
items worth any attention are (1) a documentation/parameter note about the
32-bit `nonce` field — which is a non-issue for honest interoperation and
already mitigated in the existing miner — and (2) an optional, cheap,
height-gated widening of the *effective* PoW search input for future-proofing,
recommended **only as a "do nothing now, keep in back pocket"** item. No
emergency action is warranted.

---

## 1. The PoW path as it actually exists (file:line)

### 1.1 Hash selection by fork height

`src/CryptoNoteCore/CryptoNoteFormatUtils.cpp:532` `get_block_longhash()`:

```
if (b.majorVersion >= 8) cn_gpu_hash_v0(...)            // CN-GPU, current PoW (UPGRADE_HEIGHT_V8 = 661300)
else if (b.majorVersion >= 7) cn_conceal_slow_hash_v0   // Cryptonight Conceal
else if (b.majorVersion >= 3) cn_fast_slow_hash_v1      // Cryptonight-Fast
else cn_slow_hash_v0                                     // original CN
```

All four are CryptoNight-family memory-hard functions. The current mainnet PoW
(block major v8, active since height 661300 per `CryptoNoteConfig.h:113`) is
**CN-GPU**. Every variant produces a **256-bit** output.

### 1.2 The PoW output is a 256-bit Keccak/extra-hash digest

CryptoNight finalizes its scratchpad through the Keccak permutation and then
runs the final state through exactly one of four 256-bit "extra" hashes selected
by the low bits of the state:

- `src/crypto/pow_hash/aux_hash.h:33-36` — `blake256_hash`, `skein_hash`,
  `groestl_hash`, `jh_hash` (all 256-bit SHA-3-competition finalists).
- `src/crypto/pow_hash/cn_slow_hash_soft.cpp:414,418,422,559` — `keccakf(...,24)`
  permutation rounds; final state dispatched to one extra hash.

So the value that `check_hash` sees is a full 256-bit digest with no truncation.

### 1.3 The difficulty target check (256-bit, NOT 128-bit)

`src/CryptoNoteCore/Difficulty.cpp:49` `check_hash(const crypto::Hash &hash,
difficulty_type difficulty)`:

This is the standard CryptoNote 256-bit comparison. It treats the 32-byte
`hash` as a little-endian 256-bit integer (four `uint64_t` limbs, indices [0..3])
and accepts the block iff `hash * difficulty` does not overflow 256 bits — i.e.
`hash <= 2^256 / difficulty`. `difficulty_type` is `std::uint64_t`
(`src/CryptoNoteCore/Difficulty.h:17`), but **the target itself is a full
256-bit value**; the 64-bit type only bounds how *small* the target can be made
(max difficulty ~2^64). There is **no 128-bit target anywhere** in the PoW path
— the earlier grep for `128` only hit `mul128` helpers used for reward/interest
math and the difficulty multiply, none of which is a security-relevant target
width.

### 1.4 The mutable PoW search input

`include/CryptoNote.h:78-84` — `BlockHeader { uint8_t majorVersion;
uint8_t minorVersion; uint32_t nonce; uint64_t timestamp; Hash
previousBlockHash; }`.

The hashing blob (`get_block_hashing_blob`,
`CryptoNoteFormatUtils.cpp:496`) = serialized `BlockHeader` ++ `treeRootHash`
(merkle root over coinbase + tx hashes) ++ varint(tx count). The **search**
degrees of freedom a miner varies are:

- `nonce` — `uint32_t` → **2^32** values (`Miner.cpp:375` `b.nonce = nonce;`,
  incremented at `Miner.cpp:397`).
- `timestamp` — `uint64_t`, bounded by consensus time window but still many
  effective bits per template.
- The coinbase extra-nonce (`extra_nonce`, `Miner.cpp:82-88`) and the coinbase
  txn contents, which roll the `treeRootHash` — effectively unbounded extra
  search bits per template.
- `m_starter_nonce = crypto::rand<uint32_t>()` (`Miner.cpp:66`) randomizes the
  starting point each restart.

This is the classic CryptoNote arrangement: the literal 32-bit `nonce` is small,
but the *real* search space is the (nonce × extra_nonce × timestamp × coinbase)
product, which is astronomically larger than 2^32.

---

## 2. Grover threat model applied to each surface

Grover's algorithm gives a quadratic speedup on **unstructured preimage/search**:
finding a preimage of an `n`-bit hash costs ~`2^(n/2)` quantum iterations
instead of `2^n` classical. Crucially:

- Grover does **not** help with **collisions** beyond the classical
  birthday/BHT bounds in any practically relevant way (BHT needs ~`2^(n/3)`
  *and* `2^(n/3)` qubits of QRAM, which is far more expensive than classical
  `2^(n/2)` collision search for n=256; consensus on this is that 256-bit hashes
  remain ~128-bit collision-secure and Grover changes nothing useful here).
- Grover is **highly sequential** — it does not parallelize with the
  `1/sqrt(P)` penalty across `P` machines. Splitting the search across `P`
  quantum machines only yields a `sqrt(P)` speedup, so a quantum mining cartel
  gets far less than the naive `2^(n/2)` headline. This is the single most
  important fact for PoW: Grover is a *terrible* fit for a latency-bound,
  re-targeting, memory-hard PoW.
- CryptoNight is **memory-hard** (multi-MB scratchpad with data-dependent
  random access). Grover requires the entire oracle (one full CryptoNight
  evaluation) to run *in superposition*, which means the multi-MB scratchpad
  must be held in coherent quantum memory and addressed in superposition for
  every iteration. That is wildly beyond any credible quantum hardware horizon
  and inflates the per-iteration constant by orders of magnitude over the clean
  `2^(n/2)` model.

### 2.1 Block PoW (target search) — NO CHANGE NEEDED

A quantum miner using Grover to find a block satisfying the difficulty target
faces, per template, a search whose target is `2^256 / difficulty`. The work to
find one solution is `difficulty` hash evaluations classically; Grover reduces
this to ~`sqrt(difficulty)` *oracle* evaluations — but:

1. Each oracle evaluation is a full memory-hard CN-GPU hash in superposition —
   infeasible for the foreseeable future.
2. The speedup is only `sqrt`, and difficulty **auto-retargets** every block
   (LWMA, `Currency.cpp` `nextDifficulty*`). If a quantum miner is faster, the
   network simply raises difficulty until block time normalizes; the security
   reduces to the *relative* hashrate question, identical to ASIC-vs-CPU today.
   Grover does not let a quantum miner forge blocks below target — it only finds
   valid-target nonces faster, which difficulty retargeting absorbs.
3. There is no "break" here, only a hashrate advantage, and 51%-style economic
   security is unchanged in kind.

**Recommendation: no consensus change.** Widening the 256-bit target is
meaningless (it is already maximal). Difficulty retargeting is the correct and
sufficient defense.

### 2.2 The 32-bit `nonce` field — NO CONSENSUS CHANGE NEEDED

This is the one item that *looks* alarming ("only 2^32 nonce, Grover halves the
exponent to effectively 2^16!") and is the most common misconception, so it is
documented explicitly:

- The `nonce` is **not** the search space; it is one of several mutable fields.
  Once a miner exhausts 2^32 nonces without a hit (which only happens at
  difficulty > ~2^32), it rolls the **extra_nonce** / **coinbase** /
  **timestamp** and gets a fresh 2^32-nonce subspace. The effective search space
  is unbounded. See `Miner.cpp:82-88` (extra_nonce) and the per-template reseed
  at `Miner.cpp:365-366`.
- Grover does not change this. A quantum miner that exhausts the per-template
  search just advances the template exactly as a classical miner does.
- Widening `nonce` from `uint32_t` to `uint64_t` would be a **serialization /
  wire-format consensus change** (it changes `BlockHeader` layout and therefore
  the hashing blob and block id of every block) for **zero security benefit**.

**Recommendation: do NOT widen the nonce.** It would fork the chain
(serialization change, `include/CryptoNote.h:81`, `CryptoNoteFormatUtils.cpp`
hashing blob) for no Grover benefit. The only deliverable here is *documentation*
so future maintainers do not "fix" a non-bug. If a cosmetic change is ever
desired for parity with newer CryptoNote forks, it must be height-gated behind a
new `UPGRADE_HEIGHT_V9` + `BLOCK_MAJOR_VERSION_9` and a versioned
`get_block_hashing_blob`, and even then it buys nothing against Grover.

### 2.3 Structural hashes: block id, tx id, key image, tree/merkle — NO CHANGE NEEDED

These use `cn_fast_hash` = **Keccak-256** (`src/crypto/hash.c:13,23`
`#include "keccak.h"` → `keccak1600`), all producing 256-bit digests:

| Surface | Where | Hash | Grover preimage | Classical collision |
|---|---|---|---|---|
| Block id (`get_block_hash`) | `CryptoNoteFormatUtils.cpp:508` → `getObjectHash` | Keccak-256 | 2^128 | 2^128 |
| Tx id | `getObjectHash` | Keccak-256 | 2^128 | 2^128 |
| Merkle/tree root | `tree_hash` `src/crypto/hash.h:77` | Keccak-256 | 2^128 | 2^128 |
| Key image derivation | `hash_to_scalar`/`hash_to_ec` `crypto.cpp:59,461` | Keccak-256 | 2^128 | 2^128 |

Post-Grover, all of these retain a **128-bit preimage** floor (the accepted NIST
"Category 2/AES-like" long-term level) and a **128-bit collision** floor
(unchanged by Grover; BHT quantum collision is not a practical improvement at
n=256). Nothing here is truncated to 128 bits in storage — the 128-bit numbers
are the *security level*, not a field width.

Two notes:

- **Key image collision/forgery is a Shor problem, not a Grover problem.** The
  key image's unforgeability rests on the discrete-log binding of
  `I = x·H_p(P)` (`crypto.cpp:461` `generate_key_image`), which Shor breaks and
  Grover does not. Hardening the *hash* (Keccak-256) does nothing for that; it is
  correctly out of scope here and owned by the signature-PQC track.
- The merkle **tree_hash** uses Keccak-256 and the CryptoNote tree construction.
  Second-preimage / collision on the tree root would let an attacker swap tx
  sets under a fixed block id — but at 128-bit collision cost post-Grover that is
  not a Grover-driven concern. **No change.**

**Recommendation: no change to any structural hash.** Migrating Keccak-256 → a
wider hash (e.g. 512-bit) would be a sweeping serialization + consensus + wallet
+ P2P break for a threat (sub-128-bit collision) that Grover does not create.

---

## 3. Is the current security margin adequate? (explicit verdict)

**Yes, for Grover.** Summary table:

| Concern | Current width | Post-Grover floor | Adequate? | Action |
|---|---|---|---|---|
| PoW difficulty target | 256-bit target, 64-bit max difficulty | retarget-bounded; sqrt speedup only | **Yes** | None |
| `nonce` search field | 32-bit literal, unbounded effective | N/A (not a security parameter) | **Yes** | Doc only |
| Block id (Keccak) | 256-bit | 128-bit preimage / 128-bit collision | **Yes** | None |
| Tx id (Keccak) | 256-bit | 128-bit / 128-bit | **Yes** | None |
| Tree/merkle root (Keccak) | 256-bit | 128-bit / 128-bit | **Yes** | None |
| Key image hash (Keccak) | 256-bit | 128-bit (hash); DL-binding is Shor's, not Grover's | **Yes (for Grover)** | None |

The codebase is in the comfortable position that **all** money/consensus hashes
are already 256-bit, which is the modern post-quantum-symmetric baseline
(equivalent to the AES-256 / SHA-256 "still fine under Grover" consensus). There
is no 160-bit, no 128-bit, and no truncated hash anywhere in the consensus path
that would need widening.

---

## 4. Recommended changes

### 4.1 Required consensus/config changes: NONE

There is no Grover-driven justification for any change to `CryptoNoteConfig.h`,
`Difficulty.{h,cpp}`, the hash selection in `get_block_longhash`, the
`BlockHeader` layout, or any structural hash. Recommending a height-gated fork
here would be cargo-culting; we explicitly do **not** recommend one.

### 4.2 Documentation-only (recommended, zero consensus risk)

1. Add a comment near `include/CryptoNote.h:81` (`uint32_t nonce;`) and/or
   `Difficulty.cpp:49` (`check_hash`) noting that the effective PoW search space
   is (nonce × extra_nonce × timestamp × coinbase), not 2^32, so the narrow
   `nonce` is **not** a quantum (or classical) weakness and must not be "widened"
   without a height-gated serialization fork.
2. Record in the quantum-resistance spec that the **symmetric/hash layer is
   Grover-adequate and intentionally left unchanged**, so reviewers do not
   conflate it with the Shor-exposed signature work.

### 4.3 Optional, "keep in back pocket" future-proofing (NOT recommended now)

If, in some far-future hard fork, the project wants belt-and-suspenders headroom
purely for optics/marketing ("256→deeper margin"), the *cheapest* and least
disruptive lever — far cheaper than changing the hash or the target — is to add
**extra search-input entropy** via a dedicated header field, height-gated:

- Introduce `BLOCK_MAJOR_VERSION_9` + `UPGRADE_HEIGHT_V9` /
  `TESTNET_UPGRADE_HEIGHT_V9` in `CryptoNoteConfig.h`, and a versioned
  `get_block_hashing_blob` / `get_block_longhash` branch for v9.
- This does **not** change the hash function or the 256-bit target; it only
  enlarges the explicit per-block search field so the literal `nonce` concern
  disappears for good. Even this buys *no* real Grover security (the effective
  search space is already unbounded) — it is cosmetic.
- Cost: full serialization/wire/block-id compatibility break, mandatory
  coordinated fork, checkpoint update, wallet/explorer updates. **Not justified
  by Grover.** Listed only so the option is on record.

Strong recommendation: **do nothing in code now**; ship the documentation note
(4.2) and revisit only if (a) a credibly large-scale, memory-coherent quantum
machine appears, or (b) cryptanalysis weakens Keccak/CryptoNight classically
(which would be a classical emergency, not a Grover one).

---

## 5. Interaction with the PQC PoC branch

The `pqc/testnet-poc` work (PqKey in/out, ML-KEM stealth, lattice ring sig,
nullifiers) is entirely in the **transaction/signature** layer and is **Shor**
defense. It does not touch `get_block_longhash`, `check_hash`, the difficulty
retarget, or any structural hash, and **should not** — the PoW/symmetric layer
is orthogonal and already Grover-adequate. The one place the two tracks touch is
the **key image / nullifier**: the *hash* component is Grover-safe (Keccak-256),
but the *binding* (what stops double-spend forgery) is DL-based today and is
exactly what the PQC nullifier (`pqc/ccx-pqc` `ccx_pq_nullifier`) replaces. That
replacement is correctly scoped to the signature track, not this PoW blueprint.

---

## 6. Verification / test plan (if the doc-only changes are adopted)

Documentation-only changes need no consensus testing. If §4.3 is ever pursued:

- Unit: extend `tests/UnitTests/SerializationKV.cpp` and the block-hashing-blob
  tests to cover the v9 header round-trip and confirm pre-v9 blocks hash
  identically (no retroactive change).
- Core: a chaingen test analogous to `gen_block_invalid_nonce`
  (`tests/CoreTests/BlockValidation.{h,cpp}`) for the v9 boundary at
  `UPGRADE_HEIGHT_V9`.
- Run the existing PoW/difficulty suites on the WSL host
  (`DifficultyTests`, `HashTargetTests`, `HashTests`) to confirm `check_hash`
  semantics are untouched.
- 2-node testnet (`pqc/run-poc-testnet.sh`) across the fork height to confirm
  no split.

For the recommended path (documentation only): the verification is simply a
human review that the comments are accurate; no build/test cycle is required.
