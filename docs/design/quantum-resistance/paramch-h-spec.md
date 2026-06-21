# `paramch_h` — Nothing-Up-My-Sleeve Specification

**Status: Frozen specification for external audit. Mainnet activation requires a ceremony.**

## 1. The parameter

The Raptor ring signature requires a fixed public system parameter `h ∈ R_q` (a random ring element)
used in the verification equation `c_i = r0_i + a_i · r1_i + h · b_i`.

**File:** `pqc/ccx-pqc/src/raptor.rs:53-57`
```rust
pub fn paramch_h() -> [u16; N] {
    fc::hash_to_rq(b"conceal-raptor-paramch-v0", DOM_PARAMCH)
}
```

## 2. Derivation rule (frozen)

```
h = hash_to_rq(input = "conceal-raptor-paramch-v0",
               domain = "RAPTOR-CCX-paramch-h")
```

Where `hash_to_rq` (`raptor_falcon.c:165-179`):
1. Initialize SHAKE256.
2. Absorb the domain string `"RAPTOR-CCX-paramch-h"` (via `strlen`, 22 bytes, no length prefix).
3. Absorb the input `"conceal-raptor-paramch-v0"` (27 bytes).
4. Finalize.
5. Rejection-sample 512 uniform coefficients in `[0, 12289)` by reading 14-bit chunks from the
   SHAKE256 stream, rejecting values ≥ 12289.

## 3. Expected digest (pinned)

The output polynomial `h` is verified byte-identical across all builds by the keygen KAT tripwire
(`raptor::keygen_kat_digest()` matches the pinned constant `KAT_KEYGEN_DIGEST`). The KAT implicitly
pins `h` because `h` is folded into every keygen output.

For explicit verification, the pinned KAT digest is:

```
KAT_KEYGEN_DIGEST = 8f245c82dc7390f3cb4d8955556a45d56af41c83a37fc0388b996b58f295745e
```

(produced from `SHAKE256(modq_encode(a0) || modq_encode(aots))` for `keygen(KAT_SEED_INPUT)`,
where `KAT_SEED_INPUT = "RAPTOR-CCX-KAT-seed-v0"`)

A build that produces a different `h` will fail this KAT.

## 4. Statistical analysis (why the current derivation is functionally NUMS)

Under the SHAKE256 random-oracle model, the probability that a malicious string-chooser can produce
a backdoored `h` is negligible:

| Attack class | Required `h` property | Estimated probability per trial |
|---|---|---|
| Forge without trapdoor | `h ≡ 0` or `h ≡ ±1` or sparse `h` | ~2^-180 (≥256 zero coefficients) |
| Known NTRU trapdoor | `h = g/f` for short `(f,g)` | ~2^-146 (Falcon key density in `R_q`) |
| Anonymity break via `c_i` relation | Non-generic structure in `h` | Negligible under RO |

Even with 2^40 string trials, success probability remains negligible. The deterministic SHAKE
derivation is functionally NUMS-grade **assuming SHAKE256 behaves as a random oracle**.

## 5. Mainnet ceremony requirement

For mainnet activation, one of the following is required:

### Option A: Random beacon (recommended)

```rust
// h = hash_to_rq(SHA256(block_hash_at_pre_announced_height))
pub fn paramch_h_beacon(beacon_block_hash: &[u8; 32]) -> [u16; N] {
    fc::hash_to_rq(beacon_block_hash, c"RAPTOR-CCX-paramch-h-beacon")
}
```

- Pre-announce the beacon height in `CryptoNoteConfig.h` **before** the mainnet launch commit.
- The `h` is unknown to anyone until the beacon block is mined.
- No party can influence the block hash (it depends on all mining up to that height).

### Option B: Multi-party ceremony

1. N contributors each publish a commitment `C_i = SHA256(seed_i || nonce_i)`.
2. After all commitments are published, each reveals `(seed_i, nonce_i)`.
3. Verify `C_i` matches.
4. `h = hash_to_rq(SHAKE256(seed_1 || ... || seed_N))`.
5. Security holds if ≥1 contributor is honest and destroys their seed.

### Option C: Frozen specification (minimum bar)

The derivation rule, expected KAT digest, and change-control policy are published as an external
artifact before mainnet. Any change to the input string or domain requires a new audit. This is
what this document provides.

## 6. Change-control policy

- The input string `"conceal-raptor-paramch-v0"` and domain `"RAPTOR-CCX-paramch-h"` are
  **frozen** for the `0x52415054` ("RAPT") scheme ID.
- Changing `h` requires a scheme-ID bump (new `PQ_RING_SCHEME_ID`) and a height-gated hard fork.
- The KAT tripwire (`assert_keygen_kat()`) catches any accidental drift.
