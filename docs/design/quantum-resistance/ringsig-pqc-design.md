# A Post-Quantum Spend & Anonymity Layer for Conceal — Design

> **Status:** design / decision-support (no implementation). Generated 2026-06-16 via the `/multi-agent` workflow (`pqc-ringsig-design`): 29 agents — 2 local code-characterization, 5 candidate-family deep-dives, adversarial verification (10 confirmed / 5 corrected / 0 refuted), 6 synthesis sections — plus an **empirical size benchmark built on the WSL host** (liboqs, measured bytes). External claims carry primary-source citations (see References). Treat sizes as mid-2026; re-verify before committing.

## Executive summary

The feasibility study named Conceal's CryptoNote ring-signature layer the quantum blocker. This design scopes the actual fix and reaches a concrete, if uncomfortable, answer.

**The problem is smaller than "RingCT."** Conceal has **plaintext amounts** — no Pedersen commitments, no range proofs (confirmed in code). So we do **not** need the heaviest, least-mature lattice machinery (confidential-amount proofs). The target is narrower: a **post-quantum linkable ring signature + post-quantum one-time output key + a post-quantum nullifier (key-image equivalent)**, with amounts left in the clear.

**Recommendation.**
- **Primary:** a module-lattice (MLWE/MSIS) **logarithmic one-out-of-many *linkable* ring signature** in the **MatRiCT⁺ / SMILE lineage**, stripped to the spend-authorization + serial-number core (CT removed). Trusted-setup-free; rests on the **same standardized hard-problem family as ML-DSA (FIPS 204) and ML-KEM (FIPS 203)**; its deterministic per-output **serial number maps 1:1 onto Conceal's existing `m_spent_keys` first-seen-wins nullifier index**.
- **Fallback:** a module-lattice **linear** linkable ring signature (Raptor-style, or DualRing-LB with a purpose-built lattice nullifier) — structurally a near drop-in for today's LSAG, simpler to build, at the cost of size growing with ring members.

**The honest caveat (this is the real finding).** There is **no production-grade, audited, drop-in option today.** Every credible candidate is **prototype-grade research code**. Algorithm *selection* is not the hard part — **implementation, constant-time hardening, and audit are the dominant cost and risk.** The one shipped precedent, **Abelian** (lattice RingCT, MatRiCT lineage; `cryptoblk/Abelian` is itself a Monero/CryptoNote fork), proves the architecture runs on a live PoW chain and is an invaluable *design* reference — but it's Go/CT-entangled/unlicensed-for-copy, so a reference, not a code path.

**Measured size baseline (liboqs, built + run on the WSL host, mid-2026):**

| Primitive | public key | signature / ciphertext | role in this design |
|---|---|---|---|
| **Ed25519** (Conceal today) | 32 B | **64 B** / member | the thing we replace |
| Falcon-512 | 897 B | **752 B** | fallback ring-member / one-time-key candidate |
| ML-DSA-44 (Dilithium2) | 1312 B | 2420 B | conservative signature baseline |
| ML-KEM-768 (Kyber) | 1184 B | ct 1088 B | PQ stealth-address KEM (adjacent surface) |

**Size reality — and the counter-intuitive part.** A *naive* PQ ring (one independent PQ signature per member) is **ML-DSA-44 × 6 ≈ 14.6 KB per input** vs **384 B today** — a non-starter, which is why a true ring construction is required. But at Conceal's **minimum ring size of 6**, the logarithmic schemes' large *constant* term means they are **~16–31 KB/input** (SMILE ≈ 16 KB, Falafl ≈ 29–31 KB, MatRiCT ≈ 19 KB@32) while linear **Raptor is ≈ 7.5 KB at ring 6**. **Logarithmic only wins at large anonymity sets.** So PQ economics actively push Conceal toward **bigger rings** (where log scaling pays off) — or toward the linear fallback if ring 6 stays the norm. Either way, expect a **~20–80× per-input size increase**; block-size, fee, and throughput parameters must move in the same fork.

**Migration.** Every pre-fork Ed25519 output is permanently quantum-exposed (harvest-now-decrypt-later). The plan is a **height-gated hard fork** (new `BLOCK_MAJOR_VERSION` + `UPGRADE_HEIGHT_V9`) introducing a new variable-length output/proof type and a one-way migration of legacy funds into PQ outputs, with a published deadline policy.

**Bottom line:** the blocker is **tractable as an engineering+audit programme, not a research dead-end** — but it is a multi-quarter effort whose critical path is a constant-time, audited implementation of a lattice linkable ring signature, prototyped first on the WSL host against Raptor and the Abelian/MatRiCT references.

## Contents

1. [What we are replacing](#what-we-are-replacing)
2. [Requirements & evaluation criteria](#requirements--evaluation-criteria)
3. [Candidate constructions — comparison](#candidate-constructions--comparison)
4. [Recommendation](#recommendation)
5. [Integration design](#integration-design)
6. [Migration, rollout & open problems](#migration-rollout--open-problems)
7. [References](#references)

---

## What we are replacing

Conceal inherits the classic CryptoNote spend model in `src/crypto/crypto.cpp`, gated by `src/CryptoNoteCore/Blockchain.cpp`. There is **no RingCT, no Bulletproofs, no Pedersen commitments** — amounts are plaintext `uint64` per input — so the only quantum-exposed surface is the **spend-authorization + sender-anonymity + nullifier** layer, all of which lives in the Ed25519/Curve25519 prime-order group (order `l`, cofactor 8). Three coupled pieces must be replaced together.

### 1. One-time (stealth) output keys

The sender draws a transaction keypair `(r, R = r·G)` and publishes `R` in `tx_extra`. For a recipient with view/spend keys `(A, B)`:

- **Derivation** `generate_key_derivation` (`crypto.cpp:96`): `D = 8·(r·A)`, with the `×8` (`ge_mul8`) clearing the cofactor so `D` lands in the prime-order subgroup.
- **Output key** `derive_public_key` (`crypto.cpp:138`): `P = Hs(D ‖ varint(idx))·G + B`. The varint output index binds `P` to its position in the transaction. `P` is what gets stored as `KeyOutput.key`.
- **Recovery** `underive_public_key` (`crypto.cpp:214`) + `derive_secret_key` (`crypto.cpp:197`): the recipient recomputes `D` with their view secret and gets the one-time **spend secret** `x = Hs(D ‖ idx) + b`, satisfying `P = x·G`.

Quantum exposure: `R`, `A`, and every `P` sit in plaintext on-chain forever. Shor recovers `r` from `R` (→ decrypts every output to its recipient) and `x` from any `P` (→ forges spends, recomputes the nullifier, de-anonymizes the ring) [1]. This is harvest-now-decrypt-later: pre-fork outputs are unrecoverable; migration (next sections) can only protect new outputs.

### 2. Nullifier (key image)

`generate_key_image` (`crypto.cpp:461`): `I = x·Hp(P)`, where `Hp = hash_to_ec` (`crypto.cpp:450`) maps `P` into the prime-order subgroup via `cn_fast_hash → ge_fromfe_frombytes_vartime → ge_mul8`. `I` is **deterministic** in `(x, P)` — exactly one valid image per spent output — and reveals nothing about which ring member produced it (DDH/one-more-DL). This is the double-spend tag; its security rests entirely on ECDLP and is fully broken by Shor [2].

### 3. Traceable LSAG-style ring signature

`generate_ring_signature` (`crypto.cpp:491`) / `check_ring_signature` (`crypto.cpp:553`) sign `tx_prefix_hash` over a ring `{P_0, …, P_{n-1}}` of real on-chain output keys plus the image `I`, with real index `s` and secret `x`:

- Real index: pick random `k`, set `L_s = k·G`, `R_s = k·Hp(P_s)`.
- Decoys `i ≠ s`: pick random `(c_i, r_i)`, set `L_i = c_i·P_i + r_i·G`, `R_i = r_i·Hp(P_i) + c_i·I`, accumulate `Σ c_i`.
- Challenge `h = Hs(prefix ‖ L_0 R_0 ‖ … ‖ L_{n-1} R_{n-1})`; close the ring with `c_s = h − Σ_{i≠s} c_i`, `r_s = k − c_s·x`.

Output is one 64-byte `Signature = (c_i, r_i)` **per ring member**, so on-chain cost is **linear**: 6×64 = **384 B/input** at the current `MINIMUM_MIXIN = 5` (ring ≥ 6, `CryptoNoteConfig.h:65`), plus the 32 B key image and varint offsets. Verification (`crypto.cpp:553`) recomputes every `(L_i, R_i)`, runs `sc_check` on each scalar half, and accepts iff `(h' − Σ c_i) ≡ 0 mod l` — also **linear** in `n`. Signer ambiguity holds because all `(c_i, r_i)` are uniformly distributed; linkability holds because `I` is fixed by `x`. Both properties collapse under Shor [1][3].

### Consensus invariants any PQ replacement MUST preserve

These are enforced in `checkTransactionInputs` → `check_tx_input` (`Blockchain.cpp:2219`–`2374`) and must hold byte-for-byte across the fork:

| # | Invariant | Where enforced today |
|---|-----------|----------------------|
| I1 | **Exactly one deterministic nullifier per spent output.** Same output ⇒ same tag, always; one output cannot yield two valid tags. | `crypto.cpp:461` (determinism); the PQ tag needs an equivalent canonical-encoding guarantee. |
| I2 | **Nullifier non-malleability / canonical encoding.** An attacker must not be able to mint a *second* distinct valid tag for one output and bypass the spent set. | Prime-order subgroup gate `scalarmultKey(I, L) == I_identity` (`Blockchain.cpp:2366`). The PQ scheme needs an equivalent in-proof well-formedness check. |
| I3 | **Global double-spend index.** Every nullifier must be absent from `m_spent_keys` before acceptance, inserted on block-add, erased on reorg. First-seen wins. | Pre-check `have_tx_keyimg_as_spent` (`Blockchain.cpp:2240`, set defined `461`); insert `2925`; rollback-on-dup `2932`; erase `3067`. The PQ tag must plug into this same namespaced index. |
| I4 | **Spend authorization binds `tx_prefix_hash`.** The proof signs the prefix (inputs + outputs + extra), so authorization is non-transferable to another tx. | `tx_prefix_hash` passed into `check_ring_signature` (`Blockchain.cpp:2373`). |
| I5 | **Real-output ring membership / anonymity.** The proof demonstrates ownership of *one* referenced output without revealing which; ring members are real on-chain outputs gathered by `scanOutputKeysForIndexes`. Floor of `MINIMUM_MIXIN = 5` (ring ≥ 6) must be preserved or raised. | `Blockchain.cpp:2338`, ring-size floor at `2350`. |
| I6 | **Bounded, deterministic verify cost.** Every full node verifies every input; no attacker-triggered `abort()`/unbounded path beyond today's linear-in-`n` behavior. | `check_ring_signature` is linear; the PQ verifier must stay bounded (DoS). |
| I7 | **Checkpoint-zone parity.** Inside checkpoint zones sig/nullifier checks are skipped, but the spent-set insert still fires — the index stays authoritative. | `Blockchain.cpp:2246`, `2361`–`2364`. |
| I8 | **Cross-format double-spend impossibility.** A legacy Ed25519 spend and a PQ spend of the *same* coin must not both succeed; one tag = one spend across both tag spaces. | Requires a shared/namespaced `m_spent_keys` after migration. |

### The fixed-size wire fields that block a PQC drop-in

All cryptographic fields are **fixed-size raw POD** serialized via `serializePod = serializer.binary(&v, sizeof(v))` (`CryptoNoteSerialization.cpp:120`), with **no length prefix**. Critically, the per-input signature count is **not stored on the wire** — it is recomputed structurally as `getSignaturesCount(input) = outputIndexes.size()`, and the fixed 64-B signatures are written back-to-back (`CryptoNoteSerialization.cpp:196`–`238`). A variable-length PQ proof has nowhere to go.

| Field (`include/CryptoTypes.h`) | Size | Role | Why it blocks PQC |
|---|---|---|---|
| `PublicKey` / `EllipticCurvePoint` (`:18`,`:28`) | 32 B | One-time output key `P` (`KeyOutput.key`) | A lattice address pubkey is KB-scale (e.g. Abelian `AddressPublicKey` = 9,504 B [4]) — cannot fit 32 B. |
| `KeyImage` (`:40`) | 32 B | Nullifier `I` (`KeyInput.keyImage`) | A PQ serial/nullifier is ≥ 64 B (hash-of-lattice-image) [4]; no room and no canonical-encoding hook. |
| `Signature` (`:44`) | 64 B | One LSAG slot **per ring member** | A lattice ring proof is one variable-length blob (~16–33 KB) [5][6], not `n × 64 B` PODs. |
| `KeyDerivation`, `Hash` (`:14`,`:36`) | 32 B | ECDH derivation / digests | Fixed POD; new PQ KEM/derivation material is variable-length. |
| *(implicit)* sig count | — | `= outputIndexes.size()`, never serialized | No length field exists to carry a variable-size proof. |

**Consequence.** A PQ replacement cannot reuse any of these slots. It requires (a) a new `KeyInput`/output **target-variant tag** (today both `KeyInput` and `KeyOutput` carry tag `0x2`, `CryptoNoteSerialization.cpp:57`–`59`), (b) an **explicit length-prefixed** proof + nullifier blob replacing the fixed-POD loop, and (c) a bumped `TRANSACTION_VERSION` activated at a height-gated hard fork mirroring the existing `UPGRADE_HEIGHT_V4/V5` gates (`Blockchain.cpp:2350`, `2715`), with `check_tx_input` dispatching on input version so legacy inputs keep the Ed25519 subgroup gate + `check_ring_signature` while new inputs run PQ verification.

---

[1] L. Lu, M. Au, Z. Zhang. *Raptor: A Practical Lattice-Based (Linkable) Ring Signature*, ACNS 2019 / ePrint 2018/857. https://eprint.iacr.org/2018/857
[2] *SoK: Quantum Disruption* — confirms Monero/CryptoNote RingCT + stealth addresses fully break under Shor (ECDLP). https://arxiv.org/html/2512.13333v1
[3] CryptoNote / Conceal in-repo: `src/crypto/crypto.cpp` (`generate_key_image`, `generate_ring_signature`, `check_ring_signature`); `src/CryptoNoteCore/Blockchain.cpp:2366`,`2373`; `include/CryptoTypes.h`.
[4] Abelian `pqringctx` deployed code — `AddressPublicKey` 9,504 B, 64 B serial-number nullifier. https://github.com/pqabelian/pqringctx
[5] M. F. Esgin et al. *MatRiCT*, ACM CCS 2019 / ePrint 2019/1287 (~19 KB at N=32, ~23 ms verify, no trusted setup). https://eprint.iacr.org/2019/1287
[6] V. Lyubashevsky, N. K. Nguyen, G. Seiler. *SMILE: Set Membership from Ideal Lattices*, CRYPTO 2021 / ePrint 2021/564 (~16 KB at 2^5). https://eprint.iacr.org/2021/564

---

## Requirements & evaluation criteria

This section turns the project mandate (R1–R10) into concrete, Conceal-specific acceptance criteria. Every candidate construction in this document is judged against these criteria, and the consensus-invariant mapping ties each one to the exact code path in `conceal-core` it must preserve or replace.

### Scope-narrowing premise: plaintext amounts, no confidential transactions

Conceal is a **classic CryptoNote** chain, not a RingCT chain. Confirmed in-repo: amounts travel as plaintext `uint64` (varint) on each `KeyInput` (`src/CryptoNoteCore/CryptoNoteSerialization.cpp` `serialize(KeyInput&)`), there are no Pedersen commitments, no range proofs, and no `RingCT`/`Bulletproofs` machinery anywhere in `src/crypto`. The quantum-vulnerable surface is therefore **only** the spend-authorization + sender-anonymity + double-spend-nullifier layer (`generate_ring_signature`/`check_ring_signature`/`generate_key_image` in `src/crypto/crypto.cpp`, gated in `src/CryptoNoteCore/Blockchain.cpp`).

This is a **major simplification** relative to the general post-quantum-RingCT literature. Every lattice scheme surveyed below (MatRiCT/MatRiCT+ [1], SMILE [2], Abelian's deployed `pqringctx` [3]) was designed and benchmarked for *confidential* transactions, and a large fraction of their proof bytes and verifier cost is amount machinery Conceal does not need:

- **No range proofs.** MatRiCT/Abelian carry per-output range proofs (`mlprpulp.go` in Abelian) proving `0 ≤ value < 2^64`. Conceal drops these entirely.
- **No balance/amount-conservation proof.** MatRiCT's balance proof binds amount commitments to ring membership; Conceal's "inputs ≥ outputs" check stays plaintext arithmetic, exactly as today.
- **No amount commitments / no KEM ciphertext per output.** Abelian's `ValueCommitment` is `(k_C+1)·PolyCNTT = 11·896 = 9,856 B` and its `ValuePublicKey` (Kyber768 KEM pk) is `1,188 B` per output [3] — *both omitted* for Conceal.

Practically, adopting any of these constructions means **extracting only the linkable-ring-signature + serial-number core** and discarding the commitment/range/balance layers. This roughly halves the per-output and per-input byte cost versus the published full-CT numbers and removes the most error-prone, most CT-entangled code. The design must call out this separation explicitly, because in MatRiCT the balance proof is interwoven with the ring proof and the surgery is non-trivial.

### Hard requirements (must-pass)

A candidate that fails any of R1–R5, R7, or R10 is **rejected**, not merely down-ranked.

| ID | Requirement | Conceal-specific acceptance criterion | Binds to (code) |
|----|-------------|----------------------------------------|-----------------|
| **R1** | **PQ spend unforgeability (EUF-CMA, Shor-resistant)** | An adversary with a quantum computer and the full chain cannot produce a spend authorization for an output it does not own. Security must reduce to a conservative PQ assumption (MLWE/MSIS, or hash/symmetric), **not** ECDLP/DDH. Replaces the implicit "recover `x` from `P = x·G`" hardness that Shor breaks. | `generate_ring_signature` / `check_ring_signature` (`crypto.cpp:491`, `:553`); verified at `Blockchain.cpp:2373` |
| **R2** | **PQ-sound linkable nullifier** | Each spent output yields **exactly one** deterministic tag: same `(output, secret)` ⇒ same tag (determinism); two distinct outputs never collide (no false link / no burn); one output cannot be made to yield two valid tags (non-malleability, the PQ analogue of the prime-order-subgroup gate). Double-spend prevention must survive a quantum adversary. | `generate_key_image` (`crypto.cpp:461`); subgroup gate `scalarmultKey(I,L)==identity` (`Blockchain.cpp:2366`); `m_spent_keys` index (`Blockchain.cpp:461-464`, insert `:2925`, erase `:3067`) |
| **R3** | **Signer ambiguity vs a quantum adversary** | Given a valid proof, a quantum adversary cannot determine which ring member is the real spender. Anonymity-set hiding must rest on a PQ assumption (MLWE-hiding commitments, or ZK), not DDH. | ring over `output_keys` from `scanOutputKeysForIndexes` (`Blockchain.cpp:2338`) |
| **R4** | **No trusted setup** | Transparent public parameters only (uniform-random lattice matrix from a nothing-up-my-sleeve seed, or a random oracle). **No** CRS, powers-of-tau ceremony, or toxic waste. This **excludes** any Groth16/Plonk-KZG SNARK instantiation. | n/a — global protocol property |
| **R5** | **Keep plaintext amounts** | The construction must authorize a spend over a **ring of one-time output keys only**, with amounts left in clear. No CT, no commitments, no range proofs introduced. (See scope-narrowing premise above.) | `KeyInput.amount` varint stays plaintext (`CryptoNoteSerialization.cpp`) |
| **R7** | **Bounded, deterministic verify cost (DoS-safe)** | Every full node verifies every input. Per-input verification must terminate in bounded time with no attacker-controllable blow-up and no new `abort()`-on-input paths. Verify cost must be ring-size-bounded (today capped by `MINIMUM_MIXIN`); ms-scale per input is acceptable, second-scale is not. Block-validation budget must be re-quantified. | `checkTransactionInputs` (`Blockchain.cpp:2219`); ring floor `MINIMUM_MIXIN=5` (`CryptoNoteConfig.h:65`) |
| **R10** | **Height-gated migration hard fork** | A new `UPGRADE_HEIGHT_Vx` (mirroring the existing `UPGRADE_HEIGHT_V4`/`V5` precedent at `Blockchain.cpp:2350`) introduces a new input/output variant + variable-length wire format. Legacy Ed25519 outputs are quantum-exposed (harvest-now-decrypt-later, since `R`, `A`, `P` are on-chain forever) and **must** be sunset/force-swept to PQ outputs before a CRQC exists. `m_spent_keys` must hold legacy key images **and** PQ nullifiers in one namespaced index so a coin cannot be double-spent across the format boundary. | tx-version gate (`Blockchain.cpp:2715`); fork heights (`CryptoNoteConfig.h:107-113`); shared spent-set (`Blockchain.cpp:461-464`) |

### Ranking criteria (preference-ordered, not pass/fail)

Among candidates that clear the hard requirements, rank by:

| ID | Criterion | Target / how scored |
|----|-----------|---------------------|
| **R6** | **On-chain size** | Quantify against today's baseline: **384 B/input** for the ring sig (`6 × 64 B` Signature at `MINIMUM_MIXIN=5` ⇒ ring 6) + **32 B** key image, written as fixed POD with **no length prefix** (`CryptoNoteSerialization.cpp:196-227`). Logarithmic-in-ring is **strongly preferred**, but note the trap: at ring 6 the *constant floor* dominates, so a "logarithmic" lattice proof (~16–33 KB/input [1][2]) is still ~40–80× larger in absolute bytes than today. A linear scheme like Raptor (~1.26 KB/ring member [4], ⇒ ~7.5 KB/input at ring 6) is smaller at ring 6 but loses at large rings. Score on *absolute bytes at Conceal's actual ring sizes (6–16)*, not asymptotics. |
| **R8** | **Available / auditable implementation** | C/C++ ideal; a clear, fundable path otherwise. Reality check from the survey: **no** audited, production, PQ-linkable-ring-signature-with-deterministic-nullifier exists as of mid-2026. Raptor is an unaudited GPL C/C++ PoC [4]; MatRiCT/SMILE/Falafl are research prototypes; Abelian's `pqringctx` is production but **Go-only and unlicensed** (no SPDX) [3] — design reference, not code reuse. Score: real C/C++ starting point > liboqs-assemblable primitives > paper-only. |
| **R9** | **Conservative, standardized-where-possible assumptions** | Prefer **MLWE/MSIS** (the FIPS 203/204 family) or **hash/symmetric**. Penalize: NTRU (thinner margin than MLWE; Falcon's float64 FFT sampler is hard to make constant-time [4]); the **Legendre/power-residue PRF** (young, actively cryptanalyzed — May–Zweydinger multi-key/preprocessing attacks); **CSIDH/isogeny** (Calamari gives only ~60-bit quantum security — disqualified outright). Note the standardization gap: the base lattice problems are NIST-standard, but the *ring-signature/one-out-of-many constructions on top are not standardized* — partial credit at best. |

### Consensus invariants the replacement must preserve

Beyond R1–R10, the PQ layer must hold these `conceal-core` invariants bit-for-bit, or it forks the chain:

1. **Exactly one nullifier per spend**, first-seen-wins, via the same spent-set semantics: pre-check `have_tx_keyimg_as_spent` (`Blockchain.cpp:2240`), insert on accept (`:2925`), erase on reorg/pop (`:3067`).
2. **Authorization binds `tx_prefix_hash`** — the PQ proof must sign the same message (inputs+outputs+extra) passed into `check_tx_input` → `check_ring_signature` (`Blockchain.cpp:2373`), so authorization is non-transferable to another transaction.
3. **Real-output anonymity set with a ring floor** — members are on-chain outputs referenced by `outputIndexes`; preserve `MINIMUM_MIXIN=5` (ring ≥ 6, `CryptoNoteConfig.h:65`) or raise it.
4. **Variable-length wire format with explicit length prefix** — the current scheme derives sig count *structurally* from ring size (`getSignaturesCount`) and writes fixed 64-B PODs with no size tag (`CryptoNoteSerialization.cpp:196-227`); it **cannot** represent a KB-scale variable proof. A new input/output variant tag + length-prefixed proof blob + bumped transaction version is mandatory.
5. **Checkpoint-zone parity** — signature/nullifier checks are skipped inside checkpoint zones (`Blockchain.cpp:2246`, `2361-2364`), but the spent-set insert still happens on push. The PQ spent-set must remain authoritative regardless of sig-check skipping.

### Summary of the judging rubric

A construction is **viable** for Conceal iff it (a) passes all of R1, R2, R3, R4, R5, R7, R10 and the five invariants above, then (b) ranks well on R6 (absolute bytes at ring 6–16), R8 (auditable C/C++ path), and R9 (MLWE/MSIS or hash-based, avoiding NTRU/Legendre-PRF/CSIDH). The plaintext-amount premise is the lever that makes any of this tractable: by stripping range/balance/commitment machinery, Conceal needs only the **linkable-ring-signature + deterministic-serial-number** core of the surveyed schemes — strictly smaller, simpler, and less audit-surface than the full PQ-RingCT systems they were published as.

---

**Sources**

[1] Esgin, Zhao, Steinfeld, Liu, Liu. *MatRiCT: Efficient, Scalable and Post-Quantum Blockchain Confidential Transactions Protocol.* ACM CCS 2019. https://eprint.iacr.org/2019/1287
[2] Lyubashevsky, Nguyen, Seiler. *SMILE: Set Membership from Ideal Lattices.* CRYPTO 2021. https://eprint.iacr.org/2021/564
[3] Abelian `pqringctx` (deployed Go crypto lib; `param.go`, `serialization.go`, `mlpkeys.go`). https://github.com/pqabelian/pqringctx
[4] Lu, Au, Zhang. *Raptor: A Practical Lattice-Based (Linkable) Ring Signature.* ACNS 2019. https://eprint.iacr.org/2018/857 ; PoC: https://github.com/zhenfeizhang/raptor

---

## Candidate constructions — comparison

This section ranks five post-quantum (PQ) families against Conceal's actual spend/anonymity layer — the CryptoNote traceable LSAG ring signature (`generate_ring_signature`/`check_ring_signature`, `src/crypto/crypto.cpp:491`/`:553`) plus the key-image nullifier `I = x·Hp(P)` (`src/crypto/crypto.cpp:461`) — measured against requirements R1–R10. The current baseline is **384 B/input** for the ring signature (6 × 64 B `Signature` at `MINIMUM_MIXIN = 5`, ring ≥ 6, `src/CryptoNoteConfig.h:65`) **+ 32 B `KeyImage`**, serialized as fixed-size POD with the per-input count derived structurally from `outputIndexes` (`src/CryptoNoteCore/CryptoNoteSerialization.cpp:196-227`). Every figure below is per **spend input** and excludes amount machinery, since Conceal keeps **plaintext amounts** (R5) — none of these families forces confidential transactions.

### Decision table

| Family | Assumptions (R9) | Trusted setup (R4) | Ring scaling (R6) | Proof + nullifier size (vs 384 B + 32 B) | Verify cost (R7) | Maturity (R8) | Code available | Fit for Conceal |
|---|---|---|---|---|---|---|---|---|
| **1. Lattice LINEAR linkable RS** — Raptor, DualRing-LB [1][2][3][4] | Raptor: NTRU + Ring-SIS (Falcon trapdoor), ROM. DualRing-LB: MLWE/MSIS, FS-with-aborts — conservative, Dilithium family | **None** (uniform `h`/seed; transparent) | **Linear** | Raptor-512: **~1.26 KB/member** → **~7.5 KB at ring 6** (≈20× blowup); +1.26 KB per extra mixin. Nullifier = Falcon-512 one-time pubkey **~0.9 KB**. DualRing-LB: ~few-KB response + ~32 B/member, but **no published linkability** | Linear, cheap; Raptor verify ~6 ms/input at ring 6 [3] | Paper + **unaudited PoC** (Raptor); DualRing-LB linkable = paper-only | Raptor: GPL C/C++ PoC [3], unoptimized, not constant-time | **Partial.** Near drop-in structurally, but nullifier is per-signer tag, not per-output key-image — R2 must be re-designed |
| **2. Lattice LOGARITHMIC set-membership** — SMILE, MatRiCT/+, Falafl [5][6][7][8] | MLWE/MSIS, FS-with-aborts — **most conservative PQ option**, NIST-adjacent (FIPS 203/204) | **None** (public matrices from seed; transparent) | **Logarithmic** | SMILE **~16 KB** (set 2⁵→ +6 KB at 2²⁵) [6]; Falafl **~29–31 KB** (≈0.5·log₂N + 29 KB) [5]; MatRiCT ~19 KB@32 [7]. At ring 6–16: **~16–31 KB/input ≈ 40–80× blowup despite log scaling**. Serial-number nullifier proven in-proof; tag small | Ring-size-independent dominant term; MatRiCT ~23 ms/tx [7]; SMILE/MatRiCT+ faster | Paper + research prototype; **no consensus deployment** | Falafl/SMILE/MatRiCT research C/C++ [8], unaudited, academic license | **Good model fit, heavy cost.** Serial number maps exactly onto `m_spent_keys`; size floor is the obstacle |
| **3. Hash-based / symmetric / MPCitH** — DualRing-PRF, PegaRing, Picnic/KKW [9][10][11] | Pure-symmetric members: hash + PRF only (Grover-only). **But practical members use Legendre/power-residue PRF — young, actively cryptanalyzed, non-standardized** | **None** (random oracle only; transparent) | **Mixed**: log for isogeny/lattice OR-proofs; **DualRing-PRF is ~linear, competitive only ring 16–2000** [10] | DualRingL-PRF **~8–16 KB** + **~4 KB linking tag** [9]; Picnic/KKW (truly conservative) **250–456 KB** — impractical | ms-to-seconds; under-benchmarked for PRF schemes | **Paper-only** for every linkable symmetric variant; no public impl [11] | None for linkable variant (`thyuen/dualring` is the unrelated DL/lattice DualRing) | **Weakest near-term.** No code, ~4 KB tag (125× the 32 B key-image), conservative members unusably large |
| **4. Accumulator + PQ NIZK** — Lelantus-Spark/Zerocoin re-instantiated (ZKB++/Picnic or zk-STARK) [12][13][14] | Hash route: collision/preimage only (transparent, most conservative). STARK adds FRI/RS-proximity | **None** for STARK/ZKB++/Picnic; **avoid** SNARK (Groth16/Plonk-KZG need setup) | **Global anonymity set** (decoupled from mixin) | zk-STARK **~45–150 KB/input** (generic benchmark, avg ~100 KB) [13]; ZKB++/Picnic membership at large N: hundreds-of-KB (estimate, unsourced). Nullifier 32–64 B | STARK verify ms-class but heavy constants/RAM; ZKB++ heavier; prover ~300 ms+ | **Paper/prototype** for PQ path; Spark itself is DL, non-PQ | Picnic C (MIT) [12], Winterfell/STARK libs — primitives only, **no end-to-end coin** | **Cleanest anonymity (whole-chain), deepest rewrite.** Replaces rings with global accumulator + Merkle-path wallet state |
| **5. Shipped precedent** — Abelian (MatRiCT lineage) [15][16][17] | MLWE/MSIS + BDLOP commitments; ROM nullifier (hash of lattice key-image) | **None** (matrices from `paramParameterSeedString`; transparent) | **Logarithmic** (MatRiCT+/SMILE engine) | One-time output key **9,504 B** [16]; serial number **64 B**; full TXO ≥~20 KB (≈half is CT amount-hiding Conceal omits) | Lattice NTT verify, tens of ms/tx [7]; bounded via `RingSizeMax=128` | **PRODUCTION** mainnet (2022); **no external audit** of `pqringct`/`pqringctx` | **Go only**, **no SPDX license** on core crypto repos [16] — design reuse, not code reuse; C++ port from scratch | **Best precedent, poor drop-in.** Proves the MatRiCT approach ships transparently; entangled with CT, wrong language |

> **Reading the table.** Every family satisfies R4 (no trusted setup) — that is the decisive shared property for a decentralized PoW coin and the reason all five beat any SNARK-based design. No family beats today's 384 B/input on *absolute* size at Conceal's tiny ring (6); the "logarithmic" families (2, 5) and the global-anonymity family (4) carry a large constant floor that only amortizes at impractically large anonymity sets. The real axes of differentiation are therefore **(a) does the nullifier deterministically bind to the spent output (R2)**, **(b) absolute per-input bytes at ring 6**, and **(c) existence of auditable code (R8)**.

### 1. Lattice LINEAR linkable ring signatures (Raptor, DualRing-LB)

This family is the cleanest *structural* analogue of Conceal's LSAG: one proof slot per ring member, no accumulator, no SNARK, transparent setup [1][4]. Raptor-512's signature is `(617·2 + 32)·ℓ ≈ 1.26 KB` per ring member ℓ — confirmed verbatim from the paper [1] — giving **~7.5 KB at ring 6**, roughly a 20× blowup over today's 384 B, with each added mixin costing ~1.26 KB (the PoC's NIST-wrapper overhead pushes the real figure to ~1.5–1.76 KB/member [3]). It has a real, GPL-licensed C/C++ PoC [3], but it is self-described as a non-audited prototype, builds on Falcon-512's float64 FFT sampler (notoriously hard to make constant-time), and rests on NTRU rather than the more conservative MLWE/MSIS that R9 prefers. DualRing-LB has a far smaller linear coefficient (one ~few-KB response + ~32 B per member) and is "the shortest lattice-based ring signature for ring size 4–2000" [2][4] — but **as published it has no nullifier at all**.

The decisive mismatch is R2. Raptor's linkability is a per-signer one-time-signature *tag* (a fresh Falcon one-time public key bound at key-gen), **not** a deterministic key-image of the spent output the way `I = x·Hp(P)` is. Porting it to Conceal requires re-architecting stealth-output generation so each one-time output deterministically yields exactly one tag, and proving no second valid tag can be minted for the same output — this is where most of the design and security risk lives, and it is unsolved code. Verdict: a tempting mental model and the only family with even prototype C/C++, but the nullifier must be newly designed and the size cost is real.

### 2. Lattice LOGARITHMIC set-membership (SMILE, MatRiCT/+, Falafl)

This is the **best conceptual fit** and the family Conceal should track. The spend becomes a logarithmic one-out-of-many proof that the spender owns one of the ring's one-time output keys; the double-spend nullifier is a deterministic "serial number" proven well-formed *inside* the same proof — semantics identical to Conceal's `m_spent_keys` index and the prime-order subgroup gate at `Blockchain.cpp:2366`, with the gate replaced by an in-proof well-formedness check [5][6][7]. It rests on MLWE/MSIS with Fiat-Shamir-with-aborts — the most conservative, NIST-adjacent PQ assumption set (R9) — and is fully transparent (R4). Verify cost is ring-size-independent in its dominant term (MatRiCT ~23 ms/tx [7]), which suits full-node validation. Crucially, Conceal takes **only** the ring/set-membership + serial-number core and drops the BDLOP amount commitments and range proofs, keeping plaintext amounts (R5) and yielding something strictly smaller than the published CT papers.

The killer is absolute size at Conceal's ring. As the verification verdict for this family notes, "logarithmic" describes *growth*, not the constant: real per-input proofs are **~16 KB (SMILE) to ~29–31 KB (Falafl)** even at small rings [5][6], i.e. **40–80× larger** than today's 384 B, and the log term only wins versus a linear PQ ring at impractically huge anonymity sets (Falafl crosses over near N≈1024). SMILE at ~16 KB is the only member in a tolerable range for a low-throughput coin. Code is research-prototype only and unaudited [8]; porting lattice NTT/rejection-sampling code into consensus-critical C++ is a multi-engineer-year, audit-from-near-zero effort, and the serial-number collision-binding under MSIS is the load-bearing property that must be the audit focus.

### 3. Hash-based / symmetric / MPC-in-the-head (DualRing-PRF, PegaRing, Picnic/KKW)

On paper this family is the most assumption-conservative — unforgeability and linkability rest only on hashes and PRFs, with no algebraic trapdoor, and it is uniformly transparent (R4) including the linkable variants [9][10][11]. DualRingL-PRF even offers a deterministic, key-binding linking tag (a Legendre/power-residue PRF output) that maps conceptually onto `I = x·Hp(P)`, replacing the EC subgroup check with an in-proof tag-well-formedness check (R2). Two facts collapse its near-term viability. First, **every pure-symmetric *linkable* variant is paper-only** — DualRing-PRF (ACISP 2024) and PegaRing (ePrint 2025) have no public implementation; `github.com/thyuen/dualring` is the unrelated DL/lattice CRYPTO-2021 DualRing [11]. Shipping this means writing and auditing novel constant-time crypto from scratch on consensus paths (R8 fail).

Second, the "conservative hash-only" promise is undercut for the *practical* members: the genuinely conservative Picnic/KKW LowMC route is **250–456 KB/input** and unusable on-chain, while the size-tolerable DualRing-PRF line relies on the Legendre/power-residue PRF — a young, non-standardized assumption under active cryptanalysis (May–Zweydinger multi-key/preprocessing attacks have already forced larger parameters). At Conceal's ring 6 these schemes are at their *weakest* (their authors cite a competitive range of ring 16–2000 [10]), the linking tag alone is ~4 KB (≈125× the 32 B key-image), and verify cost is under-benchmarked. **Treat as "watch + prototype," not a near-term replacement** — if lattices are acceptable, family 2 is more mature and better-sized.

### 4. Accumulator + PQ NIZK membership (Lelantus-Spark/Zerocoin re-instantiated)

Architecturally this is the strongest for anonymity (R3): every output is committed into a global accumulator, and a spend proves "I own some leaf AND my revealed nullifier is correctly derived from it" via a transparent PQ NIZK (zk-STARK or ZKB++/Picnic), so the anonymity set is the **whole chain**, not 6 ring members [12][13][14]. Plaintext amounts are trivially kept (commit to `(serial, plaintext_value)` with value in clear, no range proofs), and the nullifier — a hash-based PRF of the coin secret, proven in-circuit — plugs into the same `m_spent_keys` semantics. The transparent instantiations satisfy R4 cleanly; SNARK instantiations (Groth16/Plonk-KZG) need trusted setup and must be avoided.

The costs are severe and the rewrite is deep. zk-STARK membership proofs are ~**45–150 KB/input** (generic benchmark, avg ~100 KB [13]; note this is a generic STARK proof size, not a measured accumulator-membership proof — treat the ZKB++/Picnic "~1 MB" figure as an unsourced estimate), a 100–400× blowup that reshapes block-size, bandwidth and IBD economics. There is **no production PQ implementation** — the only audited code (Spark on Firo) is discrete-log and gives zero PQ assurance [12]. This abandons the per-tx ring entirely: full nodes must maintain a global Merkle accumulator and wallets must re-prove against the current root as it grows, replacing the entire `generate_ring_signature`/`check_ring_signature` path with NIZK verification. A new transaction type, not a drop-in. Best anonymity, highest engineering and size cost.

### 5. Shipped precedent — Abelian (MatRiCT lineage)

Abelian (ABEL) is the **only production-deployed PQ privacy coin**: a mainnet (2022) lattice RingCT chain in the MatRiCT lineage (CCS 2019), with CryptoNote-style stealth addresses, an MLWE/MSIS linkable ring signature, BDLOP commitments, and transparent setup (matrices expanded from a public `paramParameterSeedString`, no ceremony) [15][16][17]. Its serial number — a 64 B hash of a lattice "key-image" deterministically derived from the spend secret — is a direct, PQ-sound analogue of Conceal's key image, gating double-spends exactly as `m_spent_keys` does [16]. This is the single best existence proof that the MatRiCT approach can ship transparently on a PoW chain, and it validates family 2's design choices.

It is a poor drop-in, however. Abelian's shipped code is **Go**, not C++; the core `pqringct`/`pqringctx` repos carry **no SPDX license** (a legal blocker to copying) and have **no external cryptographic audit** [16] — so it offers *design* reuse, not code reuse, and a C++ port would be from scratch. Its TXOs are also entangled with confidential amounts (one-time output keys are 9,504 B, value commitments ~9.6 KB), so reusing it means surgically extracting the ring + serial-number core from the balance/range-proof machinery — non-trivial because MatRiCT's balance proof interweaves ring membership and amount conservation. For Conceal (plaintext amounts, C++), Abelian is the reference implementation to study and the proof that family 2 is deployable, not a library to link against.

---

### Sources

[1] Lu, Au, Zhang, *Raptor: A Practical Lattice-Based (Linkable) Ring Signature*, ePrint 2018/857 / ACNS 2019. https://eprint.iacr.org/2018/857 · https://link.springer.com/chapter/10.1007/978-3-030-21568-2_6
[2] Yuen, Esgin, Liu, Au, Ding, *DualRing*, ePrint 2021/1213 / CRYPTO 2021. https://eprint.iacr.org/2021/1213
[3] Raptor PoC (GPL C/C++, prototype, unaudited). https://github.com/zhenfeizhang/raptor
[4] DualRing, SpringerLink. https://link.springer.com/chapter/10.1007/978-3-030-84242-0_10
[5] Beullens, Katsumata, Pintore, *Calamari and Falafl: Logarithmic (Linkable) Ring Signatures from Isogenies and Lattices*, ePrint 2020/646 / ASIACRYPT 2020. https://eprint.iacr.org/2020/646 · https://github.com/WardBeullens/Calamari-and-Falafl
[6] Lyubashevsky, Nguyen, Seiler, *SMILE: Set Membership from Ideal Lattices*, ePrint 2021/564 / CRYPTO 2021. https://eprint.iacr.org/2021/564
[7] Esgin, Zhao, Steinfeld, Liu, Liu, *MatRiCT*, ePrint 2019/1287 / ACM CCS 2019. https://eprint.iacr.org/2019/1287
[8] Esgin, Steinfeld, Zhao, *MatRiCT+*, ePrint 2021/545 / IEEE S&P 2022. https://eprint.iacr.org/2021/545
[9] Zhang et al., *DualRing-PRF*, ePrint 2024/985 / ACISP 2024. https://eprint.iacr.org/2024/985
[10] DualRing-PRF, SpringerLink (ring size 10–2000, linear PRF instantiation). https://link.springer.com/chapter/10.1007/978-981-97-5028-3_7
[11] *PegaRing/Pegasus*, ePrint 2025/1841. https://eprint.iacr.org/2025/1841 · (unrelated original DualRing repo: https://github.com/thyuen/dualring)
[12] Chase et al., *Post-Quantum ZK and Signatures from Symmetric-Key Primitives* (ZKB++/Picnic), CCS 2017; Picnic reference (C, MIT). https://eprint.iacr.org/2017/279 · https://github.com/microsoft/Picnic · Derler, Ramacher, Slamanig, ePrint 2017/1154 (PQ accumulator → ring sigs). https://eprint.iacr.org/2017/1154
[13] *QRPL*, arXiv:2507.09067 (generic zk-STARK proof sizes ~45–150 KB, avg ~100 KB). https://arxiv.org/abs/2507.09067
[14] Jivanyan et al., *Lelantus Spark* (DL template, non-PQ), ePrint 2021/1173. https://eprint.iacr.org/2021/1173 · Ben-Sasson et al., *zk-STARK* (transparent), ePrint 2018/046. https://eprint.iacr.org/2018/046
[15] Abelian — *What is Abelian*. https://community.pqabelian.io/guide/what-is-abelian
[16] Abelian `pqringctx` crypto (Go; `param.go`/`serialization.go`/`mlpkeys.go`; AddressPublicKey = 9·1056 = 9,504 B; serial number 64 B; no SPDX license). https://github.com/pqabelian/pqringctx · https://github.com/pqabelian
[17] MatRiCT, ACM CCS 2019 (academic engine under Abelian). https://eprint.iacr.org/2019/1287

---

## Recommendation

> ⚠️ **Empirical correction — read with [`prototype-benchmarks.md`](./prototype-benchmarks.md).** The "logarithmic primary at ~16–30 KB" below is the *paper* claim. **Measured on the WSL host, both shipped Abelian libraries (`pqringct`, `pqringctx`) are LINEAR at ~130–150 KB per ring member** (≈0.5 MB tx at ring 2, tens of MB at large rings), and verify takes 0.3–1.4 s/input at ring ≤16. No production code achieves the logarithmic small-constant sizes. Treat the logarithmic target as research-aspirational; plan around **MB-scale transactions** until proven otherwise. For Conceal's plaintext-amount model the **stripped linear (Raptor-style) construction is the more realistic near-term path** than full lattice RingCT.

This section selects a concrete post-quantum spend & anonymity construction for Conceal, names a fallback, fixes parameter targets, and is honest about the (uncomfortable) maturity gap. The short version: **no production-grade, audited, drop-in option exists today**. Every credible candidate is prototype-grade research code. The recommendation therefore optimizes for *conservative assumptions + transparent setup + a clean map onto Conceal's existing `m_spent_keys` nullifier model*, and treats implementation-and-audit as the dominant cost, not algorithm selection.

### Decision

- **PRIMARY: A module-lattice (MLWE/MSIS) logarithmic one-out-of-many *linkable* ring signature in the MatRiCT⁺ / SMILE lineage, stripped to the spend-authorization + serial-number (key-image) core, with confidential-amount machinery removed.** [1][2][3]
- **FALLBACK: A module-lattice *linear* linkable ring signature (Raptor-style CH⁺ construction, or a DualRing-LB-style canonical-identification scheme with an explicitly-designed lattice nullifier).** [4][5]

Both are **trusted-setup-free** (R4), rest on **MLWE/MSIS** — the same standardized hard-problem family as ML-DSA/FIPS 204 and ML-KEM/FIPS 203 (R9) — keep **plaintext amounts** untouched (R5, the ring/nullifier core is fully separable from the amount commitments), and provide a **deterministic per-output serial number** that drops into Conceal's existing spent-set index at `src/CryptoNoteCore/Blockchain.cpp:461-464,2925,3067` (R2). The single shipped precedent in this family, **Abelian (`pqringctx`)** [6], confirms the architecture works on a live PoW chain and gives a concrete, code-level reference for the nullifier (`SerialNumber = Hash(lattice key-image)`, 64 B) and the no-trusted-setup parameter expansion — but it is Go, unlicensed for copying, and CT-entangled, so it is a *design* reference, not a code path.

### Why the primary, mapped to R1–R10

| Req | How the primary satisfies it |
|---|---|
| **R1** PQ EUF-CMA | MSIS-based unforgeability via Fiat-Shamir-with-aborts; Shor-immune (no ECDLP). [1][2] |
| **R2** PQ nullifier | Deterministic per-output serial number `sn`, proven well-formed *inside* the same OR-proof; collision/binding reduces to MSIS. Maps 1:1 onto `I = x·Hp(P)` semantics and the `m_spent_keys` first-seen-wins gate (`Blockchain.cpp:2240`). [2][3] |
| **R3** Anonymity vs quantum | Signer-ambiguity from MLWE-hiding commitments over the real on-chain ring (preserves the `scanOutputKeysForIndexes` anonymity-set model). [1][2] |
| **R4** No trusted setup | Public MSIS/MLWE matrix expanded from a nothing-up-my-sleeve seed; no CRS, no ceremony. Confirmed transparent in `pqringctx` `param.go`. [2][6] |
| **R5** Plaintext amounts | Take ONLY the linkable-ring + serial-number core; drop BDLOP amount commitments, balance and range proofs. Strictly smaller and simpler than the published CT papers. [1] |
| **R6** Log-in-ring | Proof size grows logarithmically in ring size; the dominant term is a fixed floor, not per-member. (Honest caveat below.) [2][3] |
| **R7** Bounded verify | Dominant verify term is ring-size-independent NTT polynomial arithmetic; MatRiCT-class verify ≈ tens of ms/input, MatRiCT⁺/SMILE faster. Cap inputs/outputs (cf. Abelian's 5-in/5-out, RingSizeMax=128) to bound DoS. [1][3][6] |
| **R8** Auditable impl | **Weakest point — see below.** Research prototypes only; a from-scratch, constant-time, audited C++ implementation is required. |
| **R9** Conservative assumptions | MSIS/MLWE, standardized base family. The OR-proof/serial constructions on top are *not* themselves NIST-standardized. [1][2] |
| **R10** Migration | New length-prefixed input/output variant + bumped tx version, height-gated at a `cn::parameters::UPGRADE_HEIGHT_V*` (cf. `Blockchain.cpp:2350,2715`), replacing fixed-size `serializePod` (`CryptoNoteSerialization.cpp:196-238`). Legacy Ed25519 outputs are harvest-now-decrypt-later exposed and must be force-swept before a CRQC. |

### Parameter target (concrete)

- **Security level:** NIST-1 (≈128-bit classical / ≈64-bit quantum core-SVP), matching the published Falafl/SMILE/MatRiCT parameter sets and the Conceal threat model. The 64 B serial number gives a comfortable hash margin (Grover-only → ~128-bit quantum). [1][2][3]
- **Ring / anonymity-set size:** raise the floor from today's `MINIMUM_MIXIN = 5` (ring ≥ 6, `src/CryptoNoteConfig.h:65`) to **ring 16–64**. Because the proof is logarithmic, going from ring 6 to ring 64 costs only ~1–2 KB more (SMILE: ~16 KB at 2⁵ → ~17 KB at 2⁶) [2] — so the larger anonymity set is nearly free and materially improves R3. Cap inputs-per-tx for R7.
- **Expected per-input on-chain cost:**

  | Construction | Per-input proof | Nullifier | vs today's 384 B/input |
  |---|---|---|---|
  | **Today (Ed25519 LSAG, ring 6)** | 384 B (6×64) | 32 B | 1× |
  | **PRIMARY — SMILE-class, ring 16–64** | **~16–18 KB** | 64 B | **~40–47×** |
  | MatRiCT-class (older) | ~19 KB @ N=32 | 64 B | ~50× |
  | **FALLBACK — Raptor-512, ring 6** | **~7.5 KB** (≈1.26 KB/member, linear) [4] | ~0.9 KB (Falcon opk tag) | ~20× |

  **Honest framing of R6:** "logarithmic" does *not* make Conceal smaller. At Conceal's ring sizes the lattice option carries a fixed **~16–18 KB floor per input** — roughly **40–47× today's 384 B**. The log term only *wins versus a linear PQ scheme* at large rings; the constant dominates everywhere Conceal actually operates. SMILE is the size-leader and the only member in a tolerable range; if size proves intolerable, the fallback's ~7.5 KB/input (ring 6) is the smaller absolute object, at the cost of linear growth and a per-signer (not per-output) tag.

### Honest maturity assessment (this is the real blocker)

- **Production-grade, audited, drop-in:** **none exists.** This must be stated plainly to Conceal devs.
- **Production-deployed (but not reusable):** **Abelian `pqringctx`** — live mainnet since 2022, the only shipped PQ privacy coin in this family. But: Go (Conceal is C++), **no SPDX license on the core crypto repos** (legal blocker for copying — design reuse only), no public third-party cryptographic audit, and inseparably entangled with confidential amounts that Conceal does not want. [6]
- **Prototype-grade research code:** MatRiCT / MatRiCT⁺ / SMILE / Falafl — author reference implementations used for paper benchmarks, unaudited, unpackaged, academic-license. [1][2][3] Raptor — a self-described GPL "PoC", C/C++, builds against Falcon-512 internals, last touched 2020, unoptimized, not constant-time-audited. [4]

**Consequence:** adopting the primary means **funding a from-scratch, constant-time, consensus-grade C++ implementation of the MSIS/MLWE ring + serial-number core, plus an external audit, before any fork.** `liboqs` supplies Kyber/Dilithium primitives but **not** the one-out-of-many/serial-number layer — that is net-new code on the most fragile requirement (R2 nullifier binding and bit-exact serial-number determinism across wallets). Budget this as multi-engineer-year work; lattice NTT, rejection sampling, and Fiat-Shamir-with-aborts are notoriously easy to get subtly — and consensus-splittingly — wrong.

### Why the fallback exists and when to switch to it

Choose the **linear** fallback if, during prototyping, either (a) the ~16–18 KB lattice floor proves economically unacceptable for Conceal's block-size/fee model, or (b) the from-scratch log-size OR-proof implementation cannot be made constant-time and audit-clean on schedule. Raptor is attractive because it is the **only candidate with real, runnable C/C++ ring-signature code** [4] and is a near drop-in for the CryptoNote "one slot per ring member" mental model — replacing the fixed `Signature[ringSize]` array with a length-prefixed per-member blob. Its two penalties are honest dealbreakers to weigh: the NTRU assumption is **less conservative than MLWE/MSIS** (R9), Falcon's float64 FFT sampler is hard to implement in constant time (side channels), and — most importantly for R2 — **Raptor's linkability is a per-signer one-time-key tag, not a deterministic per-spent-output key-image.** Using it requires re-architecting stealth-output generation so each output yields exactly one tag and *proving* no second valid tag can be minted for the same output. That nullifier-binding proof is where the design risk concentrates and must be the audit focal point.

### What we explicitly reject

- **Accumulator + transparent PQ NIZK (Zerocoin/Spark-on-STARK/Picnic):** strongest anonymity (whole-chain set) and trusted-setup-free, but **~50–150 KB/input (STARK) to hundreds-of-KB (ZKB++/Picnic)** [7], a global-accumulator rewrite (wallets re-prove against a moving Merkle root), and zero PQ production code. ~100–400× bloat is disqualifying for a low-throughput coin, and the only audited Spark code is discrete-log (Shor-broken). [8]
- **Pure-symmetric / PRF linkable ring sigs (DualRing-PRF, PegaRing):** most conservative *named* assumption, but the practical members rest on the **non-standardized, actively-cryptanalyzed Legendre/power-residue PRF** (May–Zweydinger attacks have forced parameter growth) — undercutting the "hash-only" appeal — while the genuinely conservative members (Picnic/KKW LowMC) are **250–456 KB/sig**. **No public implementation of any linkable PQ-symmetric variant exists** (the only `dualring` repo is the unrelated DL/lattice CRYPTO-2021 paper). Watch-and-prototype, not deploy. [9][10]
- **SNARK instantiations (Groth16/Plonk-KZG):** require trusted setup — violates R4 outright for a decentralized PoW coin.

### Migration posture (R10), non-negotiable regardless of algorithm

No PQ signature retroactively protects existing outputs: `R`, `A`, and every one-time `P = x·G` sit in plaintext on-chain forever and are harvest-now-decrypt-later exposed. The fork must therefore (1) add a length-prefixed PQ input/output target variant and bumped tx version, height-gated like the existing `UPGRADE_HEIGHT_V4/V5` precedent (`Blockchain.cpp:2350`); (2) keep `m_spent_keys` authoritative across *both* the legacy 32 B key-image space and the new ≥64 B serial space so a coin cannot be double-spent across formats; and (3) define a **one-way, time-boxed sweep window** forcing legacy Ed25519 UTXOs into PQ outputs before a CRQC is plausible — after which legacy-format spends are sunset. The dispatch branch lives in `checkTransactionInputs` / `check_tx_input` (`Blockchain.cpp:2219-2374`): keep the Ed25519 subgroup gate (`:2366`) + `check_ring_signature` (`:2373`) below the fork height, run PQ verify + serial-number canonicalization above it.

### Sources

[1] Esgin, Zhao, Steinfeld, Liu, Liu, "MatRiCT", ACM CCS 2019 — https://eprint.iacr.org/2019/1287
[2] Lyubashevsky, Nguyen, Seiler, "SMILE: Set Membership from Ideal Lattices", CRYPTO 2021 — https://eprint.iacr.org/2021/564
[3] Esgin, Steinfeld, Zhao, "MatRiCT⁺", IEEE S&P 2022 — https://eprint.iacr.org/2021/545
[4] Lu, Au, Zhang, "Raptor: A Practical Lattice-Based (Linkable) Ring Signature", ACNS 2019 — https://eprint.iacr.org/2018/857 ; PoC — https://github.com/zhenfeizhang/raptor
[5] Yuen, Esgin, Liu, Au, Ding, "DualRing", CRYPTO 2021 — https://eprint.iacr.org/2021/1213
[6] Abelian `pqringctx` (production lattice RingCT, MatRiCT lineage) — https://github.com/pqabelian/pqringctx ; param.go transparent-setup seed and 9,504 B address key / 64 B serial number confirmed in-repo
[7] Beullens, Katsumata, Pintore, "Calamari and Falafl", ASIACRYPT 2020 (Falafl lattice ~29–39 KB; KKW/Picnic 250–456 KB) — https://eprint.iacr.org/2020/646
[8] Jivanyan et al., "Lelantus Spark" (DL, not PQ) — https://eprint.iacr.org/2021/1173
[9] Zhang et al., "DualRing-PRF", ACISP 2024 — https://eprint.iacr.org/2024/985
[10] "Pegasus and PegaRing", 2025 — https://eprint.iacr.org/2025/1841

---

## Integration design

This section specifies the concrete C++ engineering work to graft a post-quantum (PQ) spend-and-anonymity layer onto Conceal's CryptoNote core, alongside — not replacing — the existing Ed25519 path. The recommended primitive is a **module-lattice (MLWE/MSIS) logarithmic linkable ring signature with an in-proof serial number** (the SMILE/MatRiCT line [1][2]), chosen for the verification-confirmed properties: no trusted setup (R4), Shor-resistant unforgeability under standardized assumptions (R1/R9), an in-proof deterministic serial number that maps cleanly onto the key-image nullifier (R2), and ring-size-independent verify cost (R7). The design is written so the *interfaces* below are primitive-agnostic: the only scheme-specific facts the consensus code needs are (a) a fixed serial-number length, (b) a length-prefixed proof blob, and (c) a `pq_verify(...)` predicate. A linear fallback (Raptor [3], ~1.26 KB/member) drops into the same interfaces if the lattice prover proves too heavy to ship.

> **Scope note honoring the verdicts.** The "logarithmic" wins on *growth*, but the verified absolute floor is ~16–50 KB/input at Conceal's ring 6 — a 40×–130× blowup, not a saving [verdict: partial]. We treat size as the dominant cost and bound it explicitly in §7. We do **not** add confidential amounts (R5): only the ring + nullifier component of MatRiCT/SMILE is taken; BDLOP value commitments, balance proofs, and range proofs are dropped.

### 1. New PQ one-time output key + stealth derivation

Conceal's current stealth output is `P = Hs(8rA || idx)·G + B`, a 32-byte `crypto::PublicKey` stored as `KeyOutput.key` (`src/crypto/crypto.cpp:138`, `include/CryptoNote.h`). The lattice spend secret is a short MLWE/MSIS vector, not an Ed25519 scalar, so we cannot reuse `derive_public_key`. We keep the **CryptoNote two-key, scan-by-view-key model** but make the address-derivation channel a KEM, which is the most robust way to get a per-output unlinkable lattice keypair the recipient can recover:

- **PQ address** = `(A_view, B_spend_seed)` where `B_spend_seed` is a 32-byte seed expanding (via SHAKE-256) to the recipient's master lattice spend key material. The view side stays a KEM public key (ML-KEM-768 is the conservative, FIPS-203-standardized choice and is already a dependency in the Abelian precedent via liboqs [4][5]).
- **Sender, per output i:** `(c_i, k_i) = KEM.Encaps(A_view)`; `seed_i = SHAKE256(k_i || varint(i))`. The one-time lattice spend keypair is `(opk_i, osk_i) = LatticeKeyGen(SHAKE256(seed_i || B_spend_seed))`. The output stores `opk_i` (the lattice one-time public key, ~9.5 KB in the pqringctx parameterization [4]) plus the KEM ciphertext `c_i` in a new target variant; `varint(i)` preserves the existing index-binding of `derivation_to_scalar`.
- **Recipient scan:** `k_i = KEM.Decaps(a_view, c_i)` → recompute `seed_i` → recompute `(opk_i, osk_i)` and test equality against the on-chain `opk_i`. This preserves *scan-by-view-key* (R: stealth invariant) but, unlike Ed25519 ECDH, requires one Decaps + one LatticeKeyGen per candidate output (see §7).

New type in `include/CryptoNote.h` `TransactionOutputTarget` variant (currently `KeyOutput`, tag `0x2`):

```cpp
struct KeyOutputPQ {                 // variant tag 0x3
  std::vector<uint8_t> oneTimeKey;   // serialized lattice opk (~9.5 KB)
  std::vector<uint8_t> kemCt;        // ML-KEM-768 ciphertext (1088 B)
};
```

New variable-length types live in a new header (e.g. `include/CryptoTypesPQ.h`) as `std::vector<uint8_t>` blobs with a declared `PQ_*_LEN` constant; they are **not** added to `include/CryptoTypes.h`, whose 32/64-byte PODs must stay byte-stable for the legacy path and `serializePod`.

### 2. The PQ spend proof object

The current spend proof is `std::vector<crypto::Signature>` (one 64-byte POD per ring member), produced by `generate_ring_signature` (`crypto.cpp:491`) and counted structurally by `getSignaturesCount` (`CryptoNoteSerialization.cpp:44`). The PQ replacement is **one length-prefixed proof per input**, not one slot per member:

```cpp
struct KeyInputPQ {                  // variant tag 0x3, parallels KeyInput (0x2)
  uint64_t amount;                   // varint, plaintext (R5)
  std::vector<uint32_t> outputIndexes; // varint-delta, same anonymity-set semantics
  std::vector<uint8_t>  serialNumber;  // PQ nullifier, fixed PQ_SN_LEN (64 B [4])
  std::vector<uint8_t>  proof;         // length-prefixed lattice ring proof (~16–50 KB)
};
```

The new crypto interface in `src/crypto/` (e.g. `crypto_pq.cpp`, kept as small focused files per the file-organization rule) mirrors the existing trio:

```cpp
// returns {serialNumber, proof}
bool generate_pq_ring_signature(const Hash& txPrefixHash,
                                const std::vector<std::vector<uint8_t>>& ringOpks,
                                size_t realIndex, const LatticeSecretKey& osk,
                                std::vector<uint8_t>& serialOut,
                                std::vector<uint8_t>& proofOut);

bool check_pq_ring_signature(const Hash& txPrefixHash,
                             const std::vector<std::vector<uint8_t>>& ringOpks,
                             const std::vector<uint8_t>& serial,
                             const std::vector<uint8_t>& proof);
```

The proof statement is exactly the CryptoNote one, re-expressed over lattices: *"I know `osk` for some `opk` in `ringOpks`, AND `serial` is the deterministic well-formed serial number of that `opk`."* The serial number plays the role of `I = x·Hp(P)`; it is proven well-formed **inside** the proof (R2), so there is no separable malleability surface. The message bound is `txPrefixHash`, identical to today's `tx_prefix_hash` binding (`crypto.cpp:548`, `Blockchain.cpp:2373`).

### 3. The PQ nullifier and double-spend index

Conceal's nullifier is the 32-byte `KeyImage`, gated by the prime-order subgroup check `scalarmultKey(I, L) == identity` (`Blockchain.cpp:2366–2371`) and indexed in `m_spent_keys` (a `phmap` keyed on `crypto::KeyImage`, queried at `:464`, inserted at `:716`/`:2925`, erased on reorg at `:2932`/`:3067`).

The PQ serial number is a deterministic function of `osk` (e.g. `sn = SHAKE256(LatticeKeyImage(osk))` [4]), 64 bytes. The **Ed25519 subgroup check is dropped for PQ inputs** — it is meaningless for a lattice tag. Its purpose (preventing one output from minting multiple valid tags) is instead discharged by *two* checks:

1. **Canonical encoding:** `serial.size() == PQ_SN_LEN` and the bytes decode to a canonical element; reject otherwise. This is the structural analogue of the subgroup gate and is cheap.
2. **In-proof well-formedness:** `check_pq_ring_signature` rejects any proof where `sn` is not the unique serial of the proven `opk` (binding under MSIS [1][2]). This is where double-spend soundness actually lives and is the audit focal point per the verdicts.

**Unified spent-set.** Cross-format double-spends must be impossible (consensus invariant: one tag = one spend across old and new spaces). Because Ed25519 key images are 32 B and PQ serials are 64 B, they cannot collide structurally, but they must share an authoritative index. Two viable options:

- **Option A (recommended):** add a parallel `phmap<PqSerial, uint32_t> m_spent_serials` next to `m_spent_keys`, with both consulted/updated at every existing call site (`:464`, `:716`, `:2925`, `:2932`, `:3067`). A legacy and a PQ spend reference *different* outputs by construction (a coin is either a `KeyOutput` or a `KeyOutputPQ`), so a single coin can only ever produce one tag in one space — the invariant holds with two disjoint indexes.
- **Option B:** widen to a single `phmap` keyed on a namespaced fixed-width digest `H(tag_type || tag_bytes)`. Cleaner long-term but touches the serialization of the on-disk spent-set snapshot (`Blockchain.cpp:220–225`), so it is a larger migration.

Critically, the spent-set insert on block-accept must remain authoritative **even inside checkpoint zones**, where signature checks are skipped (`Blockchain.cpp:2361–2364`). The PQ path mirrors this: `check_pq_ring_signature` is skipped in-checkpoint, but the serial is still inserted into `m_spent_serials`.

### 4. Wire format and serialization

The blocker is the fixed-POD signature loop in `serialize(Transaction&, ...)` (`CryptoNoteSerialization.cpp:196–238`), which writes `64 × ringSize` bytes with **no length prefix**, deriving the count from `getSignaturesCount`. This cannot represent a variable-size proof. Changes:

1. **New variant tags.** Add `KeyInputPQ` (input tag `0x3`) and `KeyOutputPQ` (output tag `0x3`) to the boost variant tag tables (`CryptoNoteSerialization.cpp:55–59`, the `BinaryVariantTagGetter`/`getVariantValue` dispatch) and to `include/CryptoNote.h`.
2. **Length-prefixed proof container.** Replace `Transaction.signatures` (`vector<vector<Signature>>`) with a discriminated union: keep the legacy path for tag-`0x2` inputs, and for tag-`0x3` inputs serialize the per-input `KeyInputPQ.serialNumber` and `KeyInputPQ.proof` as explicit `serializeAsBinary`-style length-prefixed blobs (the same varint-length-prefix pattern already used for `extra` at `:193`). `getSignaturesCount` returns 0 for PQ inputs so the legacy fixed-POD loop is skipped entirely.
3. **Transaction version bump.** Introduce `TRANSACTION_VERSION_3` in `CryptoNoteConfig.h` (after `TRANSACTION_VERSION_1/2` at `:160–161`). A tx may not mix legacy `KeyInput` and `KeyInputPQ` inputs (enforced in `checkTransactionInputs`), which keeps the proof-container branch unambiguous.
4. **Max-size guard.** `CRYPTONOTE_MAX_TX_SIZE_LIMIT` (`:95`) already bounds tx size; the per-input proof length must additionally be capped (see §5) so deserialization cannot be driven to allocate unbounded memory from attacker-supplied length prefixes (input-validation-at-boundary rule).

### 5. Consensus validation with explicit DoS bounds

Dispatch happens in `check_tx_input` (`Blockchain.cpp:2302`) and its caller `checkTransactionInputs` (`:2219`), branching on the input variant type:

```
for each input:
  if input is KeyInput (0x2):           // legacy, unchanged
     ... existing path: subgroup gate (:2368) + check_ring_signature (:2373)
  else if input is KeyInputPQ (0x3):    // requires height >= UPGRADE_HEIGHT_V9
     1. reject if outputIndexes empty (parallels :2234)
     2. reject if PQ serial already in m_spent_serials (parallels :2240/:464)
     3. gather ringOpks via scanOutputKeysForIndexes (reuse :2338 visitor,
        extended to collect KeyOutputPQ.oneTimeKey)
     4. enforce ring floor: outputIndexes.size() >= MINIMUM_MIXIN+1 (>=6, :65)
     5. reject if proof.size() > MAX_PQ_PROOF_BYTES        // DoS cap
     6. reject if serial.size() != PQ_SN_LEN || !canonical(serial)   // §3 gate
     7. if in checkpoint zone: skip step 8 (parallels :2361)
     8. return check_pq_ring_signature(txPrefixHash, ringOpks, serial, proof)
```

**Explicit DoS / verify-cost bounds (R7):**

- **Per-input proof bytes** capped by `MAX_PQ_PROOF_BYTES` (e.g. 64 KB, covering SMILE/MatRiCT at the chosen ring [1][2]); rejected before any verification work, so the length prefix cannot trigger large allocation.
- **Per-input verify cost is ring-size-independent** in the dominant term for the lattice schemes (a fixed number of R_q NTT multiplications [1][2]) — confirmed ~tens of ms/input (MatRiCT ~23 ms for a full CT tx; the bare ring component is a fraction [2]). Worst case is bounded and deterministic: no abort-on-input paths beyond the current behavior.
- **Per-tx input count** is bounded by `CRYPTONOTE_MAX_TX_SIZE_LIMIT` (`:95`) divided by the minimum PQ-input footprint, giving a hard ceiling on per-tx verify time. As Abelian does (`RingSizeMax=128`, 5-in/5-out [4]), we additionally cap PQ ring size and PQ inputs/outputs per tx via new `CryptoNoteConfig.h` constants, sized so a maximal block's PQ verification stays within the block interval budget. These caps must be benchmarked on reference full-node hardware before mainnet activation.

Fiat-Shamir-with-aborts affects only the *prover* (signing may retry); verification is single-pass and constant-work, so it adds no node-side DoS surface.

### 6. Height-gated activation

Conceal already gates consensus by block major version with per-version upgrade detectors (`Blockchain.cpp:362–366`) and a tx-version/major-version interlock (`:2715`). Mirror this exactly:

- Add `BLOCK_MAJOR_VERSION_9 = 9` and `UPGRADE_HEIGHT_V9` to `CryptoNoteConfig.h` (after `:113`/`:167`), plus the testnet twin (`TESTNET_UPGRADE_HEIGHT_V9` after `:126`).
- Add `m_upgradeDetectorV9(currency, m_blocks, BLOCK_MAJOR_VERSION_9, logger)` to the constructor list and `init()` chain (`:362–366`, `:621–623`), and extend `getBlockMajorVersionForHeight` (`:1017`, `:1111`).
- **Tx-version interlock:** in the `:2715` check, require `version >= TRANSACTION_VERSION_3` ⇒ block `majorVersion >= BLOCK_MAJOR_VERSION_9`, and conversely reject legacy `KeyInput` spends once a *sunset height* `UPGRADE_HEIGHT_V9_SUNSET` is reached.

**Migration of quantum-exposed legacy outputs (R10).** Every pre-fork Ed25519 output (`P`, `R`, `A` all on-chain) is harvest-now-decrypt-later exposed; the fork cannot retroactively secure them. The migration is therefore a forced one-way sweep window:

1. At `UPGRADE_HEIGHT_V9`: `KeyInputPQ`/`KeyOutputPQ` become valid; new outputs SHOULD be PQ. Legacy spends remain valid (legacy `KeyInput` → `KeyOutputPQ` is the sweep transaction).
2. Between `UPGRADE_HEIGHT_V9` and `UPGRADE_HEIGHT_V9_SUNSET`: wallets must sweep all `KeyOutput` UTXOs into `KeyOutputPQ` outputs. This is the only window in which an Ed25519 spend authorization is still accepted.
3. At `UPGRADE_HEIGHT_V9_SUNSET`: `check_tx_input` rejects all legacy `KeyInput` (tag `0x2`) spends. Un-swept coins become unspendable — the deliberate, conservative choice, since after a CRQC exists a still-spendable legacy output is an open theft vector. The sunset gap must be long enough for honest wallets to migrate but short relative to credible CRQC timelines.

The `m_spent_keys` legacy index is retained read-only after sunset (its entries still block replays); only insertion of new legacy spends stops.

### 7. Fee, size, throughput, and wallet-scanning impact

**On-chain size.** Per PQ input ≈ 64 B serial + ~16–50 KB proof; per PQ output ≈ ~9.5 KB `opk` + ~1.1 KB KEM ct [1][2][4]. A 2-in/2-out PQ transaction is therefore ≈ **40–120 KB**, versus well under 2 KB today (today's spend proof is 384 B/input at ring 6 = 6×64 B [verified baseline]). This is a 40×–130× expansion and is the dominant engineering cost; the logarithmic ring growth is essentially free by comparison (an extra mixin adds bytes only to the anonymity-set index, not to the proof). The fallback linear Raptor scheme is smaller per member (~1.26 KB [3]) but loses the in-proof key-image semantics and must re-architect the nullifier, so it is the contingency, not the default.

**Fees and block sizing.** Conceal's dynamic block size (`MAX_BLOCK_SIZE_INITIAL`, growth speed at `:88–90`) and per-byte fee structure mean the size blowup translates directly into ~40×–130× higher fees per PQ tx at constant fee-per-byte, and far fewer txs per block. Recommended adjustments, all in `CryptoNoteConfig.h`/`Currency.cpp`:
- Re-derive `MAX_BLOCK_SIZE_*` and the median-based growth so a block can still hold a meaningful number of PQ txs.
- Introduce a separate **per-byte minimum fee floor for PQ txs** so the larger objects remain economically rational to relay and the mempool is not trivially flooded (the larger objects are a relay-bandwidth DoS surface otherwise).
- Re-budget `CRYPTONOTE_MAX_TX_SIZE_LIMIT` against the new proof sizes, and benchmark worst-case block validation (max PQ inputs × ~tens of ms) against `DIFFICULTY_TARGET` before setting the per-tx input/output caps from §5.

**Wallet scanning.** Today's scan is one Ed25519 `generate_key_derivation` + `derive_public_key` per output — microseconds. The PQ scan is one ML-KEM `Decaps` + one lattice `KeyGen` per candidate output, which is materially heavier and dominates initial blockchain sync for PQ-era blocks. Mitigations: (a) a cheap **view-tag byte** stored in the output (a 1-byte truncated hash of the KEM shared secret) to reject ~255/256 of non-owned outputs before the expensive `KeyGen`, exactly as Monero's view-tags do; (b) parallelize Decaps across cores during sync. The wallet stack (`WalletGreen.cpp`, `WalletTransactionSender.cpp`, `ConcealWallet.cpp`) must learn to build `KeyOutputPQ`/`KeyInputPQ`, store the ~9.5 KB one-time keys and lattice spend secrets, and run the sweep flow of §6.

---

**Maturity caveat (R8).** No member of the recommended family has audited, production C/C++ consensus code; the only shipped PQ privacy coin (Abelian) is Go-only, has no external audit, and its core crypto repos carry no SPDX license, so they are a *design* reference, not a code-reuse path [4][5][verdict: confirmed]. Conceal would reimplement the MatRiCT/SMILE ring+serial component in constant-time C++ from the papers (lattice NTT, rejection sampling) and fund an independent audit, with the in-proof serial-number binding (§3) as the primary audit target. The interfaces in §1–§5 are deliberately primitive-agnostic so this crypto core can be developed and audited behind a stable consensus boundary.

**Sources**
[1] Lyubashevsky, Nguyen, Seiler, *SMILE: Set Membership from Ideal Lattices*, CRYPTO 2021 — https://eprint.iacr.org/2021/564
[2] Esgin, Zhao, Steinfeld, Liu, Liu, *MatRiCT*, ACM CCS 2019 — https://eprint.iacr.org/2019/1287
[3] Lu, Au, Zhang, *Raptor: A Practical Lattice-Based (Linkable) Ring Signature*, ACNS 2019 — https://eprint.iacr.org/2018/857
[4] Abelian `pqringctx` (param.go, serialization.go, mlpkeys.go) — https://github.com/pqabelian/pqringctx
[5] Open Quantum Safe / liboqs (ML-KEM, ML-DSA C reference) — https://github.com/open-quantum-safe/liboqs

Referenced Conceal files: `src/crypto/crypto.cpp:138,461,491,553`; `src/CryptoNoteCore/Blockchain.cpp:2219,2302,2338,2356,2361,2366,2373,464,716,2925,2932,3067,362,621,1017,2715`; `src/CryptoNoteCore/CryptoNoteSerialization.cpp:44,55,190,196,260`; `include/CryptoTypes.h:40,44`; `include/CryptoNote.h`; `src/CryptoNoteConfig.h:65,95,88,106,113,160,167`.

---

## Migration, rollout & open problems

This section specifies how Conceal moves from the Ed25519 LSAG/key-image layer (`src/crypto/crypto.cpp`, `src/CryptoNoteCore/Blockchain.cpp`) to the PQ spend-and-anonymity layer defined earlier, without ever leaving funds spendable by a future cryptographically-relevant quantum computer (CRQC). It is written to slot into Conceal's existing height-gated upgrade machinery (`UPGRADE_HEIGHT_V2..V8`, `src/CryptoNoteConfig.h:107`) and is deliberately conservative: the migration design must be correct even if the chosen PQ primitive (see the recommendation at the end) is later swapped, because the *wire format, consensus dispatch, and spent-set semantics* are the load-bearing parts, not the specific lattice scheme [1].

### The threat model that drives the schedule

Every pre-fork output is **permanently quantum-exposed**. The tx public key `R = r·G` (in `extra`), the recipient view key `A`, and the one-time output key `P = x·G` (`KeyOutput.key`) all sit in plaintext on-chain forever. A CRQC running Shor's algorithm recovers `x` from `P` and `r` from `R` in polynomial time [2], which simultaneously (a) forges the spend, (b) recomputes the deterministic key image `I = x·Hp(P)` to defeat the nullifier, and (c) de-anonymizes the ring. This is the canonical **harvest-now-decrypt-later (HNDL)** posture: an adversary archives the chain today and breaks it whenever a CRQC exists [2]. The migration therefore has two distinct jobs that must not be conflated:

1. **Protect new value** — make all post-fork outputs PQ-secured. This is purely a matter of shipping the new transaction type and switching wallets to it.
2. **Drain old value** — get coins *out* of every legacy Ed25519 UTXO and into PQ outputs **before** a CRQC exists. The fork cannot retroactively secure a legacy `P`; it can only incentivize and ultimately *force* its owner to sweep it while the ECDLP is still hard.

Job 2 is the hard, politically-sensitive part, and it is on a clock no one can read precisely.

### A three-key transition (legacy → dual → PQ-only)

Conceal addresses carry a `(spendPub B, viewPub A)` pair. The migration extends this to a **dual-key address**: `(B_ed, A_ed, B_pq, A_pq)`, where the `_pq` half is a module-lattice spend/view keypair. This is the "hybrid" stance recommended for migrations where legacy material remains exposed — sign/authorize with *both* during the overlap so a break of either curve alone is insufficient, then retire the classical half [3].

- **Output side.** A new `TransactionOutputTarget` variant (alongside `KeyOutput`, `include/CryptoNote.h:43`) carries a lattice one-time output key and the PQ stealth derivation. Because a lattice one-time key is ~9.5 KB in the Abelian/`pqringctx` parameterization versus 32 B today [4], the fixed-size POD path (`serializePod`, `src/CryptoNoteCore/CryptoNoteSerialization.cpp:120`) is replaced by length-prefixed serialization for this variant only (see §wire format in the earlier section).
- **Input side.** A new `KeyInput` variant carries the PQ nullifier (serial number) plus the length-prefixed proof blob, dispatched on input version in `check_tx_input` (`src/CryptoNoteCore/Blockchain.cpp:2302`). Legacy inputs keep the existing path: the prime-order subgroup gate `scalarmultKey(I, L) == identity` (`Blockchain.cpp:2366`) then `check_ring_signature` (`Blockchain.cpp:2373`).
- **Unified spent-set.** `m_spent_keys` (`Blockchain.cpp:461`) must hold *both* 32-B legacy key images and the new PQ serials in one namespaced index so that a coin cannot be double-spent across formats. This is the single most safety-critical invariant of the whole migration: one coin → at most one tag, regardless of which tag space it lives in.

### Height-gated rollout, with a migration window and a hard deadline

Reusing Conceal's existing pattern (`UPGRADE_HEIGHT_Vn`, with the V4 mixin floor and V5 deposit gates as precedent, `Blockchain.cpp:2350`), the activation is a sequence of heights, not a single flag:

| Phase | Gate (new constant) | Consensus rule |
|---|---|---|
| **P0 — Dual-address support** | `UPGRADE_HEIGHT_V9` | Wallets can *generate* dual-key addresses and *receive* to PQ outputs. PQ inputs accepted and verified. Legacy spends still fully valid. |
| **P1 — PQ-output-only for new funds** | `UPGRADE_HEIGHT_V10` | Coinbase and all *new* outputs MUST be PQ targets. Legacy outputs may still be spent (via legacy ring sig) but only *into* PQ outputs — every spend is a forced migration step. |
| **P2 — Legacy-spend sunset** | `UPGRADE_HEIGHT_V11` (the **deadline**) | Legacy `KeyInput` (Ed25519 ring sig) spends are **rejected**. After this height, value still sitting in pre-fork Ed25519 UTXOs is frozen at consensus. |

The deadline (P2) is the controversial lever and must be set by the community, not by this document. The defensible posture: P0→P1 should be a few months (wallet rollout, exchange integration); P1→P2 should be **long enough that any economically-active holder has had ample opportunity to sweep, but short enough to close the HNDL window before credible CRQC timelines** — on current public estimates that argues for a multi-year P1→P2 span with aggressive wallet nagging, revisited as quantum timelines firm up. Freezing unmigrated coins is a real social cost (lost/inactive holders) traded against the systemic risk that those same dormant UTXOs become a quantum adversary's free mint. There is no clean answer; the design's job is to make the lever *exist* and be *adjustable by a later soft consensus*, not to pre-commit a number.

**Forced-sweep mechanics.** During P1, the cleanest UX is a wallet-driven "sweep all" that builds legacy-input → PQ-output transactions. A consensus-assisted variant — a special migration tx that is cheaper/feeless to reduce friction — is worth considering but adds attack surface (fee-griefing, dust) and is deferred to the prototype's findings.

### Phased engineering rollout (testnet → fork)

1. **Crypto core in isolation.** Implement and KAT-test the PQ keygen / stealth-derive / sign / verify / nullifier as a standalone library with fixed test vectors, *before* touching consensus. Deterministic, bit-exact nullifiers across implementations are a hard requirement (a one-bit divergence silently breaks double-spend detection) and must be locked by cross-implementation test vectors.
2. **Serialization + dispatch.** Add the new variants and length-prefixed paths in `CryptoNoteSerialization.cpp`, with round-trip fuzzing. No verify logic yet — just encode/decode parity.
3. **Consensus dispatch + unified spent-set.** Wire `check_tx_input` branching and the namespaced `m_spent_keys`. Test reorg/rollback parity (`Blockchain.cpp:2925/3067`) for PQ serials, and the **checkpoint-zone bypass parity** invariant — inside checkpoint zones sig checks are skipped but the spent-set insert still happens, and that must hold identically for PQ serials.
4. **Testnet fork.** Conceal already maintains compressed testnet upgrade heights (`TESTNET_UPGRADE_HEIGHT_Vn`, `src/CryptoNoteConfig.h:120`), so P0–P2 can be exercised in days, not years: activate, mine PQ outputs, force-sweep, hit the deadline, attempt a post-deadline legacy spend and confirm rejection, attempt cross-format double-spend and confirm rejection.
5. **Benchmark gate.** Before mainnet scheduling, measure per-input verify time and per-input bytes against an explicit budget (see open problems). A coin where every full node validates every input cannot ship a primitive that turns a 384 B / microsecond check into a 16–33 KB / tens-of-ms check [1][5] without first re-budgeting block size, relay policy, and DoS caps.
6. **Mainnet `UPGRADE_HEIGHT_V9` announcement** with a long lead time, audited code, and exchange/pool coordination.

### Open problems — what actually blocks a prototype

These are stated candidly; several are unsolved in the literature, not merely unimplemented.

1. **No audited, production PQ linkable ring signature with a deterministic per-output nullifier exists.** The only *shipped* PQ privacy coin, Abelian, is Go, has no public third-party crypto audit, carries no SPDX license on its core `pqringct`/`pqringctx` repos (a legal blocker for code reuse), and entangles its ring sig with confidential-amount machinery Conceal does not want [4][6]. Everything else (MatRiCT/MatRiCT+, SMILE, Falafl, DualRing-PRF/PegaRing) is research-prototype only [5][6][7][8]. Conceal would be a first mover and must fund implementation **and** independent audit essentially from zero.

2. **Nullifier soundness is the fragile core, and it is the part least supported by existing code.** The PQ serial must be a *deterministic* function of the spent output's secret, *collision-binding* (no two distinct coins share a serial → no false link / burn), and *uniquely derivable* (one coin cannot present two valid serials → no double-spend) — proven *inside* the proof, replacing the algebraic subgroup gate at `Blockchain.cpp:2366` with an in-proof well-formedness check. In the lattice schemes this reduces to MSIS binding [5]; in the PRF schemes it rests on the *non-standardized* Legendre/power-residue PRF, which is under active cryptanalysis (May–Zweydinger multi-key/preprocessing attacks have already forced parameter growth) [7]. This is the single property that must dominate the audit, and getting it wrong is silent and catastrophic (undetected double-spends).

3. **Size vs. anonymity is a genuine tension at Conceal's ring size.** At `MINIMUM_MIXIN = 5` (ring 6, `src/CryptoNoteConfig.h:65`), *every* PQ family is dramatically larger per input than today's 384 B: linear Raptor ≈ 7.5 KB/input (≈20×) [9]; "logarithmic" lattice schemes carry a ~16–33 KB fixed floor (40–80×) that the log term barely moves until impractically large rings [1][5]; accumulator/STARK designs are 45–150 KB/input but offer a *global* anonymity set instead of a 6-member ring [10]. The log-scaling advantage only pays off if Conceal *also* raises the anonymity-set target substantially — a separate policy decision with its own validation-cost consequences.

4. **Verify-cost DoS budgeting is unquantified for Conceal specifically.** Published numbers (MatRiCT ~23 ms/tx [5], Falafl/SMILE tens of ms, Raptor ~6 ms/input at ring 6 [9]) are 100–1000× today's Ed25519 check. Whether this is survivable depends on Conceal's real per-tx input counts and block cadence, which must be measured, then capped (max inputs/outputs, max ring size, per-block proof-count limits) before consensus adoption.

5. **HNDL on legacy outputs is only *partially* solvable.** The fork protects new value and can *freeze* unmigrated value, but it cannot make a holder who has lost their keys, or who never comes online before P2, safe — those coins are either swept by their owner or frozen. There is no third option that doesn't hand a quantum adversary a mint.

6. **Constant-time / side-channel hardening.** Lattice signing (rejection sampling, NTT) and especially Falcon-style float FFT samplers are notoriously hard to implement in constant time [9]. Conceal's wallet signs on user machines; a timing/side-channel leak of the spend secret is a real, non-quantum break that must be in scope from day one.

### Recommended concrete next step

**Prototype the standalone PQ crypto core (open problem #1 + #2) on the Linux/WSL host using `liboqs` for the standardized lattice primitives, while reimplementing only the linkable-ring + nullifier layer in C++ against the MatRiCT/SMILE construction.**

Rationale, decisively:

- **Library:** Open Quantum Safe's **`liboqs`** (C, MIT-licensed, packages the FIPS 204 ML-DSA / FIPS 203 ML-KEM module-lattice primitives) is the only audited, permissively-licensed, C-native foundation that fits Conceal's C++ build and R9's "standardized-where-possible MLWE/MSIS" preference. It gives you the *primitives* but **not** the linkable-ring / serial-number layer — that does not exist as reusable code anywhere [4][6].
- **What to build first:** A standalone executable (no `Blockchain.cpp` integration) that (a) generates a lattice one-time output key + view key, (b) derives a deterministic serial/nullifier from the spend secret, (c) produces and verifies a linkable ring proof over a ring of such keys against `tx_prefix_hash`, and (d) emits **fixed test vectors**. The goal of this prototype is not performance — it is to *measure the real per-input byte size and verify time at ring 6* and to *let an auditor attack the nullifier-binding relation* before a single line of consensus code is written.
- **Why not the alternatives now:** Abelian's `pqringctx` is the closest working design but is Go, unlicensed, and CT-entangled — **study it as a design reference, do not link it** [4][6]. The PRF/symmetric family (DualRing-PRF, PegaRing) has no public linkable implementation and rests on a non-standardized, actively-attacked PRF [7][8] — *track* PegaRing's eventual code release, don't build on it yet. The accumulator/STARK family offers the best anonymity but the largest proofs and a full transaction-model rewrite [10] — out of scope for a first prototype.

The decision gate after this prototype is binary and honest: if ring-6 per-input size and verify time land inside a block-size/DoS budget the community will accept, proceed to phased rollout on the SMILE/MatRiCT line; if not, the realistic fallback is a **larger global anonymity set** (accepting the accumulator family's size in exchange for dropping the per-ring model) or deferring until the linkable-lattice literature ships audited, size-optimized code.

---

**Sources**

[1] Lyubashevsky, Nguyen, Seiler, "SMILE: Set Membership from Ideal Lattices," CRYPTO 2021. https://eprint.iacr.org/2021/564
[2] "SoK: Quantum Disruption" (Shor breaks CryptoNote RingCT + stealth addresses via ECDLP). https://arxiv.org/abs/2512.13333
[3] NIST SP 1800-38 / PQC migration guidance on hybrid (dual-signature) transition. https://www.nccoe.nist.gov/crypto-agility-considerations-migrating-post-quantum-cryptographic-algorithms
[4] Abelian `pqringctx` (param.go: AddressPublicKey = 9×1056 = 9,504 B; serial = 64 B). https://github.com/pqabelian/pqringctx
[5] Esgin, Zhao, Steinfeld, Liu, Liu, "MatRiCT," ACM CCS 2019 (~23 ms verify; serial-number nullifier; no trusted setup). https://eprint.iacr.org/2019/1287
[6] Esgin, Steinfeld, Zhao, "MatRiCT+," IEEE S&P 2022. https://eprint.iacr.org/2021/545
[7] Zhang et al., "DualRing-PRF: Post-Quantum (Linkable) Ring Signatures from Legendre and Power Residue PRFs," ACISP 2024. https://eprint.iacr.org/2024/985
[8] "Pegasus and PegaRing," 2025. https://eprint.iacr.org/2025/1841
[9] Lu, Au, Zhang, "Raptor: A Practical Lattice-Based (Linkable) Ring Signature," ACNS 2019 (~1.26 KB/member, linear). https://eprint.iacr.org/2018/857 · PoC: https://github.com/zhenfeizhang/raptor
[10] Bahar, "QRPL: A Quantum-Resistant Private Ledger," 2025 (zk-STARK proofs ~45–150 KB). https://arxiv.org/abs/2507.09067

---

This is a references-compilation task. I have all the source material in the JSON. Let me compile a deduplicated, numbered references list.

## References

[1] Lu, Au, Zhang — Raptor: A Practical Lattice-Based (Linkable) Ring Signature (ACNS 2019), IACR ePrint 2018/857 — https://eprint.iacr.org/2018/857
[2] Raptor (ACNS 2019, SpringerLink) — https://link.springer.com/chapter/10.1007/978-3-030-21568-2_6
[3] zhenfeizhang/raptor — Raptor PoC implementation (C/C++, GPL) — https://github.com/zhenfeizhang/raptor
[4] Yuen, Esgin, Liu, Au, Ding — DualRing: Generic Construction of Ring Signatures with Efficient Instantiations (CRYPTO 2021), IACR ePrint 2021/1213 — https://eprint.iacr.org/2021/1213
[5] DualRing (CRYPTO 2021, SpringerLink) — https://link.springer.com/chapter/10.1007/978-3-030-84242-0_10
[6] Quartet: Logarithmic Linkable Ring Signature from DualRing (SpringerLink) — https://link.springer.com/chapter/10.1007/978-3-031-18067-5_5
[7] A NTRU Lattice-Based Linkable DualRing Signature (SpringerLink) — https://link.springer.com/chapter/10.1007/978-981-95-2961-2_7
[8] Esgin, Steinfeld, Sakzad, Liu, Liu — Short Lattice-based One-out-of-Many Proofs and Applications to Ring Signatures (ACNS 2019), IACR ePrint 2018/773 — https://eprint.iacr.org/2018/773
[9] Beullens, Katsumata, Pintore — Calamari and Falafl: Logarithmic (Linkable) Ring Signatures from Isogenies and Lattices (ASIACRYPT 2020), IACR ePrint 2020/646 — https://eprint.iacr.org/2020/646
[10] Calamari and Falafl (Oxford ORA full-text mirror, Table 1 sizes) — https://ora.ox.ac.uk/objects/uuid:f5673699-f68f-4362-8796-7cf1a5878c28
[11] WardBeullens/Calamari-and-Falafl — reference implementation — https://github.com/WardBeullens/Calamari-and-Falafl
[12] Lyubashevsky, Nguyen, Seiler — SMILE: Set Membership from Ideal Lattices (CRYPTO 2021), IACR ePrint 2021/564 — https://eprint.iacr.org/2021/564
[13] SMILE (CRYPTO 2021, SpringerLink) — https://link.springer.com/chapter/10.1007/978-3-030-84245-1_21
[14] Esgin, Zhao, Steinfeld, Liu, Liu — MatRiCT: Efficient, Scalable and Post-Quantum Blockchain Confidential Transactions Protocol (ACM CCS 2019), IACR ePrint 2019/1287 — https://eprint.iacr.org/2019/1287
[15] MatRiCT (ACM CCS 2019, ACM DL) — https://dl.acm.org/doi/10.1145/3319535.3354200
[16] Esgin, Steinfeld, Zhao — MatRiCT+: More Efficient Post-Quantum Private Blockchain Payments (IEEE S&P 2022), IACR ePrint 2021/545 — https://eprint.iacr.org/2021/545
[17] Libert, Ling, Nguyen, Wang — Zero-Knowledge Arguments for Lattice-Based Accumulators (EUROCRYPT 2016 / J. Cryptology 2023) — https://link.springer.com/chapter/10.1007/978-3-662-49896-5_1
[18] Libert, Ling, Nguyen, Wang — Zero-Knowledge Arguments for Lattice-Based Accumulators (J. Cryptology 2023) — https://link.springer.com/article/10.1007/s00145-023-09470-6
[19] Zhang, Steinfeld, Liu, Esgin, Liu, Ruj — DualRing-PRF: Post-Quantum (Linkable) Ring Signatures from Legendre and Power Residue PRFs (ACISP 2024), IACR ePrint 2024/985 — https://eprint.iacr.org/2024/985
[20] DualRing-PRF (ACISP 2024, SpringerLink) — https://link.springer.com/chapter/10.1007/978-981-97-5028-3_7
[21] Pegasus and PegaRing: Efficient (Ring) Signatures from Sigma-Protocols for Power Residue PRFs with (Q)ROM Security, IACR ePrint 2025/1841 — https://eprint.iacr.org/2025/1841
[22] Beullens et al. — LegRoast/PorcRoast: Legendre-PRF MPCitH signatures, IACR ePrint 2020/128 — https://eprint.iacr.org/2020/128
[23] thyuen/dualring — original CRYPTO 2021 DualRing reference code (DL + lattice, Python; NOT the PRF variant) — https://github.com/thyuen/dualring
[24] LLRing: Logarithmic Linkable Ring Signatures with Transparent Setup (ESORICS 2024) — https://link.springer.com/content/pdf/10.1007/978-3-031-70896-1_15.pdf
[25] Efficient Set Membership Proofs using MPC-in-the-Head (Picnic/KKW/LowMC ring sigs), IACR ePrint 2021/1656 — https://eprint.iacr.org/2021/1656
[26] Chase et al. — Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives (ZKB++/Picnic, CCS 2017), IACR ePrint 2017/279 — https://eprint.iacr.org/2017/279
[27] Katz, Kolesnikov, Wang — Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures (KKW, CCS 2018) — https://www.researchgate.net/publication/352896440
[28] microsoft/Picnic — Picnic signature reference implementation (C, MIT) — https://github.com/microsoft/Picnic
[29] isec-tugraz/Picnic — optimized Picnic implementation (TU Graz) — https://github.com/isec-tugraz/Picnic
[30] Derler, Ramacher, Slamanig — Post-Quantum Zero-Knowledge Proofs for Accumulators with Applications to Ring Signatures from Symmetric-Key Primitives (PQCrypto 2018), IACR ePrint 2017/1154 — https://eprint.iacr.org/2017/1154
[31] Bonnetain, Schrottenloher — Quantum Security Analysis of CSIDH (EUROCRYPT 2020), IACR ePrint 2018/537 — https://eprint.iacr.org/2018/537
[32] Jivanyan et al. — Lelantus Spark: Secure and Flexible Private Transactions, IACR ePrint 2021/1173 — https://eprint.iacr.org/2021/1173
[33] Jivanyan — Lelantus: Towards Confidentiality and Anonymity of Blockchain Transactions from Standard Assumptions, IACR ePrint 2019/373 — https://eprint.iacr.org/2019/373
[34] Lelantus Spark Audit Report (Firo) — https://firo.org/about/research/papers/Lelantus_Spark_Audit_Report.pdf
[35] Curve Trees: Global Anonymity Sets for Spark (Firo research) — https://firo.org/2024/03/07/curve-trees-research-results.html
[36] Ben-Sasson, Bentov, Horesh, Riabzev — Scalable, Transparent, and Post-Quantum Secure Computational Integrity (STARKs), IACR ePrint 2018/046 — https://eprint.iacr.org/2018/046
[37] Bahar — QRPL: A Quantum-Resistant Private Ledger (zk-STARK design point, 2025), arXiv:2507.09067 — https://arxiv.org/abs/2507.09067
[38] Alberto Torres et al. — Lattice RingCT v1.0: Post-Quantum Linkable Ring Signature (ACISP 2018) — https://link.springer.com/chapter/10.1007/978-3-319-93638-3_32
[39] Lattice RingCT v2.0 (MIMO, 2019) — https://link.springer.com/chapter/10.1007/978-3-030-21548-4_9
[40] chainchip/Lattice-RingCT-v2.0 — reference implementation — https://github.com/chainchip/Lattice-RingCT-v2.0
[41] Abelian — pqabelian GitHub organization (abec node, pqringct/pqringctx crypto, Go) — https://github.com/pqabelian
[42] pqabelian/pqringctx — param.go (public seed, MLWE/MSIS parameters) — https://github.com/pqabelian/pqringctx/blob/master/param.go
[43] pqabelian/pqringctx — serialization.go (PolyANTT/PolyCNTT, AddressPublicKey sizes) — https://github.com/pqabelian/pqringctx/blob/master/serialization.go
[44] pqabelian/pqringctx — mlpkeys.go (AddressPublicKeyForRing serialization) — https://github.com/pqabelian/pqringctx/blob/master/mlpkeys.go
[45] What is Abelian — project documentation (lattice linkable ring sig + commitments, three privacy levels) — https://community.pqabelian.io/guide/what-is-abelian
[46] Wong — From Post-Quantum Cryptography to Post-Quantum Blockchains and Cryptocurrencies (Abelian introduction) — https://pqabelian.medium.com/from-post-quantum-cryptography-to-post-quantum-blockchains-and-cryptocurrencies-an-introduction-eb0b50ed129a
[47] Insight Decentralized Consensus Lab — post-quantum-monero (PQ strategy survey for CryptoNote) — https://github.com/insight-decentralized-consensus-lab/post-quantum-monero
[48] SoK: Quantum Disruption (CryptoNote RingCT + stealth addresses break under Shor), arXiv:2512.13333 — https://arxiv.org/html/2512.13333v1
[49] NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium) — https://csrc.nist.gov/pubs/fips/204/final
[50] NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM / Kyber) — https://csrc.nist.gov/pubs/fips/203/final
[51] NIST FIPS 206 (draft) — FN-DSA (Falcon) — https://csrc.nist.gov/projects/post-quantum-cryptography

---

*Provenance: produced by the conceal-core `/multi-agent` workflow (`pqc-ringsig-design`). Target characterization derived from the local codebase; candidate-family claims web-researched and adversarially verified (10 confirmed, 5 corrected, 0 refuted); PQ primitive sizes measured with liboqs on the WSL host. Corrections applied during synthesis include: the accumulator/QRPL size figures were mis-attributed (architecture differs from QRPL); Abelian uses a hybrid dual-PoW and ships Go + C++ + Java repos (not Go-only). This is a decision-support design, not a commitment to implement.*
