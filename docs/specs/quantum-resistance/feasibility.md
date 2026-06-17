# Post-Quantum Cryptography for Conceal — Feasibility Study

> **Status:** research / feasibility (no implementation). Generated 2026-06-16 via the `/multi-agent` workflow (`pqc-feasibility-conceal`): 34 agents, 5 codebase surface-maps + 6 web-research angles, with an adversarial fact-check pass (10 claims confirmed / 8 corrected / 0 refuted). All external claims carry primary-source citations (see References). Treat sizes/dates as of mid-2026 — re-verify before committing.

## Executive summary

A cryptographically-relevant quantum computer (CRQC) running Shor's algorithm breaks the elliptic-curve discrete-log (ECDLP) that **every** authorization and privacy guarantee in Conceal rests on (Ed25519/Curve25519). The exposure is not partial — ring signatures, key images, stealth-address ECDH, ordinary signatures and payment proofs all fall, enabling **theft, double-spend, forgery, and full retroactive deanonymization** of the existing chain. Keccak / CryptoNight (PoW, hashing) face only Grover — a mild quadratic speedup — and are not the problem.

The feasibility verdict splits sharply by surface:

- **Tractable today (engineering, not research):** ordinary signatures → ML-DSA / Falcon / SLH-DSA; stealth-address ECDH → ML-KEM (Kyber); PoW/hash → widen outputs / retune difficulty for Grover. These are NIST-standardized (FIPS 203/204/205, 2024) with known sizes and reference code.
- **The blocker (research-grade):** the CryptoNote **ring-signature + confidential-transaction (RingCT-style) privacy layer**. Post-quantum lattice ring signatures (MatRiCT / MatRiCT+ / lattice RingCT) exist but produce proofs **orders of magnitude larger** than today's 64-byte signatures and have **little to no production deployment**. The closest precedent is **Abelian (ABEL)**, a lattice-based privacy coin built on this research.
- **Cross-cutting:** Conceal's consensus wire format hard-codes **fixed 32-byte keys / 64-byte signatures** serialized as raw POD, plus an Ed25519 prime-order-subgroup check on key images. PQC objects are kilobytes — so *any* migration is a **consensus-breaking, height-gated hard fork** with new variable-length serialization and new address formats.
- **Urgency:** the **harvest-now-decrypt-later (HNDL)** threat means today's on-chain outputs and encrypted messages are *already* exposed to a future CRQC. This argues for prioritizing the confidentiality / stealth surfaces even though the full ring-signature migration is years out.

### Vulnerable-surface map (overview)

| Surface | Underlying hardness | Quantum threat | Worst-case severity |
|---|---|---|---|
| Ring signatures + key images (spend auth, double-spend nullifier) | Ed25519 ECDLP | **Shor** | **Fatal** — forgery, theft, double-spend, traceability collapse |
| Stealth addresses / view-key ECDH (one-time output keys) | Curve25519 ECDH | **Shor** | **High** — spend-key recovery + full deanonymization |
| Ordinary signatures & payment proofs (multisig, tx proofs) | Ed25519 ECDLP | **Shor** | **High–Med** — authorization bypass, false attribution |
| Encrypted messages / deposits / wallet file | chacha8 (sym) + EC key exchange | mixed (Shor on the EC parts) | **Med** — message/recipient confidentiality |
| PoW + hashing + Merkle (keccak, CryptoNight, tree-hash) | preimage/collision | Grover | **Low** — quadratic only; widen / retune |
| Key & address types + serialization | fixed 32B/64B POD wire format | enabler | **Blocking** — cannot hold kilobyte PQC objects |

## Contents

1. [Threat model & vulnerable-surface map](#threat-model--vulnerable-surface-map)
2. [Option space per cryptographic surface](#option-space-per-cryptographic-surface)
3. [Precedent: what other chains did](#precedent-what-other-chains-did)
4. [Recommended strategy, phased roadmap, risks & open questions](#recommended-strategy-phased-roadmap-risks--open-questions)
5. [References](#references)

---

I have the key file pointers confirmed. Writing the section now.

## Threat model & vulnerable-surface map

This section defines what a cryptographically-relevant quantum computer (CRQC) actually breaks in Conceal, separates the two quantum attack classes (Shor vs Grover), foregrounds the "harvest now, decrypt later" (HNDL) risk that is uniquely severe for a privacy chain, and maps every consensus-relevant Conceal surface to a threat, severity, and concrete consequence with source-file pointers. It closes with an honest CRQC timeline.

### Two adversaries: Shor vs Grover

A CRQC threatens Conceal through two distinct algorithms with radically different impact.

- **Shor's algorithm — fatal, exponential.** Shor solves the elliptic-curve discrete logarithm problem (ECDLP) in polynomial time. *Every* asymmetric primitive in Conceal is built on Ed25519/Curve25519 — ring signatures, key images, the single-key Schnorr/EdDSA signatures, stealth-address ECDH, payment proofs, and address keys. The curve constants are baked into the code (twisted-Edwards `d = -121665/121666` at `src/crypto/crypto-ops-data.c:14`, Montgomery `A = 486662` at `src/crypto/crypto-ops-data.c:843`, group order in `sc_reduce` at `src/crypto/crypto-ops.c:1609`). Because `P = x·G` is the entire security assumption, a Shor-capable adversary recovers the secret scalar `x` from any public point `P`. This single capability simultaneously enables (a) ring-signature forgery, (b) computing the correct key image to spend an output (theft), (c) identifying which ring member truly signed (deanonymization), and (d) recovering wallet spend/view keys from on-chain data. This is the catastrophic, non-recoverable break.

- **Grover's algorithm — mild, quadratic.** Grover gives only a square-root speedup against unstructured search, and this is provably optimal — no quantum algorithm beats it [9]. Against Conceal's Keccak-1600 / CryptoNight hashing (`src/crypto/hash.c:16-23`, `src/crypto/cryptonight.cpp`), a 256-bit digest retains roughly 128-bit preimage security post-Grover, which remains comfortably infeasible; realistic gate/depth overheads of a fault-tolerant hash oracle inflate the true cost well beyond the naive 2^128 query bound [9]. Grover also does **not** meaningfully threaten CryptoNight proof-of-work: Grover parallelizes only as `√(M·t)`, and one credible estimate put a quantum miner at ~1000× slower than a single classical ASIC, with any residual edge absorbed by difficulty adjustment [10]. **Conclusion: Conceal's hashing and PoW layers do not require migration on quantum-security grounds.** The genuine quantum threat is Shor against signatures and key exchange, not the hashing layer.

### Harvest now, decrypt later (HNDL) — the dominant risk for a privacy chain

For a privacy coin, the most severe quantum risk is not theft but **retroactive deanonymization of the entire historical ledger**, and it is already unavoidable in principle. The blockchain is public and permanent: every transaction publishes a 32-byte ephemeral key `R = r·G` in `tx_extra` (`src/CryptoNoteCore/TransactionExtra.cpp:181-197`), and every account view public key `A` is recoverable on-chain. The stealth-address shared secret `D = r·A = a·R` is the root of all unlinkability. A future Shor-capable adversary, working from an archive node, can solve ECDLP on either `R` or `A` to reconstruct `D` for **every output ever created**, then run `underive_public_key` (`src/crypto/crypto.cpp:178`) against every output and address to map outputs to recipients — fully deanonymizing all past transactions. The same applies to encrypted on-chain messages, whose ChaCha8 key is `cn_fast_hash(derivation)` where `derivation = generate_key_derivation(recipient_spend_pubkey, tx_secret)` (`src/CryptoNoteCore/TransactionExtra.cpp:372-426`): recover the ECDH secret via Shor and every message ever posted decrypts.

The implication is decisive and must frame the whole report: **migration protects only outputs created after the fork; it can never un-expose data already on-chain.** Under Mosca's inequality `X + Y > Z` (data shelf-life + migration time vs. years to a CRQC), a privacy chain's historical confidentiality has effectively unbounded `X`, so the harvesting is free and arguably already underway [3]. This is exactly why Monero's own CCS post-quantum research ranks retroactive deanonymization *above* theft as the top-priority quantum risk [3].

### The structural blocker: fixed-size POD serialization

Independent of cryptanalysis, Conceal's wire format physically cannot hold post-quantum objects. Every key/image/signature is a fixed-width raw array in `include/CryptoTypes.h` — `PublicKey`/`SecretKey`/`KeyImage`/`KeyDerivation`/`Hash` are 32 bytes and `Signature` is 64 bytes — serialized byte-for-byte with no length prefix and no algorithm tag (`serializePod → ISerializer::binary(&v, sizeof(v))`, `src/CryptoNoteCore/CryptoNoteSerialization.cpp:120`; `src/Serialization/BinaryOutputStreamSerializer.cpp:84`). The decoder knows each field's size only because `sizeof` is fixed at compile time. Each ring member contributes exactly one 64-byte `Signature` (count == ring size), and consensus enforces an Ed25519 prime-order-subgroup check on the key image (`scalarmultKey(keyImage, L) == I`, `src/CryptoNoteCore/Blockchain.cpp:2366-2371`). NIST PQ objects are kilobytes — ML-DSA-65 signatures are 3,309 B and public keys 1,952 B [1]; ML-KEM-768 ciphertexts are 1,088 B [2] — so they cannot occupy 32/64-byte slots. **Any PQC adoption is therefore a hard-fork wire-format and consensus change, not a drop-in swap**; this is treated in detail in the migration section.

### Vulnerable-surface map

Severity reflects the *quantum* exposure of each surface. "Fatal" = direct theft and/or full deanonymization via Shor; "High" = enables one of those given an adjacent break; "Medium" = a narrower forgery/privacy break; "Low" = Grover-only, no migration needed on quantum grounds.

| # | Surface | Primitive / file pointer | Threat | Severity | Quantum consequence |
|---|---------|--------------------------|--------|----------|---------------------|
| 1 | **Ring signature** (spend authorization) | `generate_ring_signature` / `check_ring_signature`, `src/crypto/crypto.cpp:491`/`553`; sole consensus gate `src/CryptoNoteCore/Blockchain.cpp:2373` | Shor (ECDLP) | **Fatal** | Recover signer's `x` → forge a ring signature for outputs you don't own (theft) **and** identify the true signer in the ring (untraceability collapse / deanonymization). |
| 2 | **Key image** (double-spend nullifier `I = x·Hp(P)`) | `generate_key_image`, `src/crypto/crypto.cpp:461`; spent-key check `src/CryptoNoteCore/Blockchain.cpp:2240`; subgroup gate `Blockchain.cpp:2366-2371` | Shor (ECDLP) | **Fatal** | With `x` recovered, compute the correct key image for any output → spend others' funds; recompute victims' key images from public keys to link outputs to spends. |
| 3 | **Stealth ECDH** (shared secret `D = r·A = a·R`) | `generate_key_derivation`, `src/crypto/crypto.cpp:96`; `derive_secret_key`, `crypto.cpp:197`; `derive_public_key`, `crypto.cpp:138` | Shor (ECDLP) | **Fatal** | Recover `a` (or `r`) → reconstruct `D` for every output → full receiver-side deanonymization, and derive one-time spend secret `x = Hs(D‖idx)+b` → theft. Primary HNDL target. |
| 4 | **tx public key `R` in `tx_extra`** | `addTransactionPublicKeyToExtra`, `src/CryptoNoteCore/TransactionExtra.cpp:193-197` | Shor (ECDLP) | **Fatal** | The permanent on-chain ECDH ephemeral. Inverting `R` retroactively deanonymizes (and enables theft of) every output of that transaction. Already on every historical block. |
| 5 | **Output scanning** (linking oracle) | `underive_public_key`, `src/crypto/crypto.cpp:178`/`214` | Shor (ECDLP) | **High** | With `D` known, test every output against every address → concrete mechanism that maps outputs to owners at chain scale. |
| 6 | **Single-key Schnorr/EdDSA signature** | `generate_signature` / `check_signature`, `src/crypto/crypto.cpp:269`/`293`; multisig path `Blockchain.cpp:2261` | Shor (ECDLP) | **High** | Recover `x` from `P = x·G` → forge arbitrary signatures over any prefix hash (authorization bypass for whatever the signature gates). |
| 7 | **Encrypted on-chain messages** (ECDH → ChaCha8) | key exchange `src/CryptoNoteCore/TransactionExtra.cpp:372-396`; cipher `src/crypto/chacha8.c:44` | Shor (key exchange); Grover (cipher only) | **Fatal** (confidentiality) | Shor on tx/recipient public keys reconstructs the ChaCha8 key → retroactive decryption of every message ever posted (HNDL). ChaCha8 itself is only Grover-relevant and falls with the key, not before it. |
| 8 | **Payment proof** (DLEQ) | `generate_tx_proof` / `check_tx_proof`, `src/crypto/crypto.cpp:314`/`361` | Shor (ECDLP) | **Medium** | Recover tx secret `r` from public `R` → forge payment proofs (false attribution) or derive shared secret to deanonymize recipients. Not a direct theft path. |
| 9 | **Address keys & mnemonic seed** | Base58 `encode_addr`, `src/Common/Base58.cpp:216`; mnemonic→32-byte secret, `src/Mnemonics/Mnemonics.cpp:37-70` | Shor (ECDLP) | **High** | Address publishes both 32-byte Curve25519 public keys; Shor inverts them to steal funds. The 25-word mnemonic merely backs up the same quantum-vulnerable 32-byte scalar. |
| 10 | **Wallet-file encryption** (KDF + cipher) | `generate_chacha8_key = cn_slow_hash_v0(password)`, `src/Wallet/WalletGreen.cpp:583`/`810`; `src/WalletLegacy/WalletLegacySerializer.cpp:96` | Grover only (symmetric) | **Low** (quantum) | No asymmetric step — **not** a Shor target. Real weakness is classical: password-only KDF, no salt, single CryptoNight pass → offline brute force dominates. PQ remediation here means a stronger salted memory-hard KDF, not asymmetric replacement. |
| 11 | **Keccak / CryptoNight hashing & PoW** | `cn_fast_hash`, `src/crypto/hash.c:16-23`; `get_block_longhash`, `src/CryptoNoteCore/CryptoNoteFormatUtils.cpp:513`; `tree_hash`, `src/crypto/tree-hash.c`; `check_hash`, `src/CryptoNoteCore/Difficulty.cpp:49` | Grover only | **Low** | Quadratic-only weakening: ~128-bit residual preimage security on 256-bit digests; PoW unaffected in practice [9][10]. **No quantum-driven migration required.** |
| 12 | **Fixed-size POD wire format** | `serializePod`, `src/CryptoNoteCore/CryptoNoteSerialization.cpp:120`; `src/Serialization/BinaryOutputStreamSerializer.cpp:84`; types in `include/CryptoTypes.h` | n/a (structural) | **High** (blocker) | Not itself quantum-vulnerable, but no length/algorithm field means the format cannot carry variable-size PQ objects. Any PQ migration requires a new tagged/length-prefixed scheme — a hard consensus fork across tx, block, and address parsing. |

Note `DepositIndex` / `InvestmentIndex` (`src/CryptoNoteCore/DepositIndex.cpp`) contain **no cryptography** — they are plain `int64` accumulators; the funds they track are protected by the transaction-layer primitives above, not by anything in those classes.

### Realistic CRQC timeline (stated honestly)

No CRQC capable of breaking 256-bit ECC exists today, and the schemes that would replace Conceal's primitives are largely immature (see later sections). But the planning horizon is short enough to act now:

- The Global Risk Institute / evolutionQ **Quantum Threat Timeline Report 2025** (Mosca & Piani, 26 experts) gives a median CRQC estimate around **2029–2032**, with roughly **34% probability by 2030**, rising past 50% within ~15 years and toward near-certainty by the mid-2040s; the report notes the timeline has *accelerated* relative to prior years [3].
- **NSA CNSA 2.0** mandates PQ signature migration for software/firmware signing — the function most analogous to transaction signing — with preference by 2025 and exclusivity by 2030 [3].
- Honest caveats: these are expert-judgment estimates, not measured engineering milestones, and the exact qubit/error-correction requirements remain contested. The timeline is a probability distribution, not a deadline.

For Conceal specifically, the timeline interacts with HNDL to make the migration *schedule* — not just the end-state design — the dominant risk variable. Theft risk materializes only once a CRQC exists; **deanonymization risk is being incurred continuously today**, because every block published now is permanently harvestable and will be retroactively decryptable the moment Shor becomes feasible. The remainder of this report treats the privacy/deanonymization surface (items 1–5, 7, 9) as the first-priority migration target, consistent with the Monero CCS prioritization [3], while explicitly excluding the Grover-only hashing/PoW layer (items 11) from quantum-driven change.

---

**Sources**
[1] NIST FIPS 204 (ML-DSA), https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf — sizes corrected to final values (ML-DSA-65 sig 3,309 B, pk 1,952 B).
[2] NIST FIPS 203 (ML-KEM), https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
[3] Global Risk Institute Quantum Threat Timeline Report 2025, https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/ ; Mosca's theorem, https://postquantum.com/post-quantum/moscas-theorem/ ; Monero CCS PQ research, https://ccs.getmonero.org/proposals/research-post-quantum-monero.html ; NSA CNSA 2.0, https://www.encryptionconsulting.com/quantum-proof-with-cnsa-2-0/
[9] Grover's algorithm (optimality + oracle overhead), https://en.wikipedia.org/wiki/Grover%27s_algorithm ; https://eprint.iacr.org/2016/992.pdf
[10] Quantum mining analysis (Aggarwal et al. 2017), https://arxiv.org/pdf/1711.04235

---

Confirmed: `PublicKey`/`SecretKey`/`KeyDerivation`/`KeyImage` are 32-byte and `Signature` is 64-byte fixed PODs. Now writing the section.

## Option space per cryptographic surface

This section enumerates the realistic post-quantum (PQ) replacement options for each cryptographic surface in Conceal, with quantified size, performance, and maturity tradeoffs. Conceal's entire authorization and privacy stack is Ed25519/Curve25519 with Keccak as the Fiat-Shamir/hash-to-point primitive, and every key/signature object is a fixed-size POD: `PublicKey`/`SecretKey`/`KeyDerivation`/`KeyImage` are 32 bytes and `Signature` is 64 bytes (`include/CryptoTypes.h`), serialized verbatim with no length prefix or algorithm tag (`serializePod` → `ISerializer::binary(&v, sizeof(v))`, `src/CryptoNoteCore/CryptoNoteSerialization.cpp:120`). The decisive cost across **every** surface is on-chain object size, not CPU: PQ objects are kilobytes where Curve25519 objects are 32–64 bytes, and throughput on a size-limited chain falls roughly inversely with transaction size [1][9].

The surfaces are not equal in difficulty. Three of them (stealth addresses, ordinary signatures, hashing/PoW) have standardized, deployable answers today. The fourth — the **ring signature + confidential-amount privacy layer** — has no production-ready PQ replacement anywhere. It is the hard, research-grade blocker and dominates the feasibility timeline.

### (a) Ring signatures + confidential amounts → lattice ring/RingCT — the research-grade blocker

This is Conceal's privacy core: `generate_ring_signature`/`check_ring_signature` (`src/crypto/crypto.cpp:491`/`:553`), the key-image nullifier `I = x·Hp(P)` (`src/crypto/crypto.cpp:461`), and the consensus gate at `src/CryptoNoteCore/Blockchain.cpp:2373`. Every input emits one 64-byte `Signature` per ring member, plus an Ed25519 subgroup check on the key image (`Blockchain.cpp:2366-2371`). A PQ replacement must reproduce three properties at once — signer-ambiguity (anonymity), linkability (double-spend prevention), and (for Conceal's deposit/investment model) confidential amounts — under lattice or hash assumptions instead of ECDLP.

The most complete lattice RingCT family is the MatRiCT line (Module-SIS / Module-LWE), but every option is academic with **zero production deployment as of mid-2026** [2]:

| Scheme | Venue | Proof / object size | Verify | Input-count scaling | Notes |
|---|---|---|---|---|---|
| MatRiCT [3] | CCS 2019 | (2-in/2-out) proof ~47 KB @ ring 11; coin ~4.48 KB; pubkey ~3.4 KB | ~23 ms | **linear in M** | First implemented PQ RingCT; foundational |
| MatRiCT+ [4] | IEEE S&P 2022 | 2–18× smaller proofs than MatRiCT (still tens of KB absolute) | 3–11× faster than MatRiCT | **O(log M)** | Power-of-two cyclotomic rings |
| SMILE [5] | CRYPTO 2021 | ~30 KB for 2-in/2-out hidden among 2¹⁵ accounts; 4–10× smaller than MatRiCT | — | logarithmic set membership | Ideal-lattice set-membership |
| Raptor | ACNS 2019 | ~1.3 KB **per ring member** (linear) — ring of 1000 ≈ 1.3 MB | — | linear | Signature-only; **no confidential amounts** |
| Falafl / DualRing-LB | ASIACRYPT 2020 / CRYPTO 2021 | logarithmic; e.g. ~9.87 KB @ ring 1024 | — | O(log N) | Signature-only; **no confidential amounts** |

Key honest caveats for Conceal:

- **Size is catastrophic, not merely costly.** Best-in-class lattice RingCT transactions are *tens of KB* (MatRiCT 2→2 ~47 KB; SMILE ~30 KB at a 2¹⁵ anonymity set) versus ~1–3 KB for classical Monero-style RingCT/Bulletproof+ — a ~10–30× on-chain blowup [2]. Conceal's current ring signatures are even smaller (64 bytes × ring size). This compounds the throughput problem (§a does not exist in isolation: the per-input object is what inflates).
- **Compute is not the bottleneck — bytes are.** Verification is fast (~23 ms for MatRiCT) [3]; the blocker is permanent ledger growth and propagation.
- **The two sub-problems split.** Raptor, Falafl, and DualRing solve only the anonymity/ring half and do **not** hide amounts; only the MatRiCT/SMILE/LACT+ family covers both. A full Conceal replacement needs both halves.
- **The field is still churning** (LACT+ 2023, NTRU DualRing variants 2025), and a Dec 2025 SoK concludes PQC is **not a drop-in** for blockchains and forces architectural redesign [6].
- **Monero is not a shortcut.** Monero's FCMP++ (hard fork Q1 2026) replaced ring signatures with classical ECC full-chain membership proofs — it is **not** post-quantum; lattice/hash PQC is roadmap-only (post-Seraphis, 2027+) [2]. The largest privacy chain has explicitly deferred exactly the problem Conceal would be solving.

**Verdict for this surface: no deployable option exists.** Any plan that depends on a production-grade lattice RingCT is, today, a bet on unfinished research.

### (b) Stealth addresses → PQ KEM (ML-KEM / Kyber)

Conceal's stealth scheme is CryptoNote ECDH: `generate_key_derivation` computes `D = 8·r·A` (`src/crypto/crypto.cpp:96`), the tx public key `R` sits in `tx_extra` (`src/CryptoNoteCore/TransactionExtra.cpp:181`), and the one-time output key is `P = H_s(D,idx)·G + B`. This surface has a **sound, standardized PQ answer**: replace the ECDH shared secret with a KEM-derived secret. The sender runs `KEM.Encaps` against the recipient meta-address to produce an on-chain ciphertext ("announcement"); the view-key holder runs `KEM.Decaps` to recover the shared secret `S` and derive the one-time key as in DKSAP [7].

FIPS 203 ML-KEM (final, Aug 2024) [confirmed] sizes drive the tradeoff:

| Parameter set | Enc key (meta-addr) | Ciphertext (announcement) | Shared secret | Blowup vs 32-byte EC key |
|---|---|---|---|---|
| ML-KEM-512 | 800 B | 768 B | 32 B | ct ~24× |
| ML-KEM-768 | 1,184 B | 1,088 B | 32 B | ct ~34× |
| ML-KEM-1024 | 1,568 B | 1,568 B | 32 B | ct ~49× |

Quantified properties [7][8]:

- **Scanning CPU cost goes *down*.** A lattice KEM decapsulation per announcement is cheaper than an EC scalar multiplication. The benchmarked Module-LWE (Kyber) SAP scans ~3× faster than the best classical EC protocol (Curvy) and ~15× faster than DKSAP to compute a recipient address; the bottleneck is the KEM itself, so KEM optimization directly improves scan time. Conceal's view-key model survives unchanged — the view-key holder decapsulates instead of doing ECDH.
- **The decisive cost is object size.** The per-output announcement grows from a 32-byte ephemeral key to a 768–1,568-byte ML-KEM ciphertext (24–49×), and the published meta-address from ~32 B to 800–1,568 B [8]. Because Conceal publishes one tx public key per transaction in `tx_extra` (a fixed 1-tag-byte + 32-byte POD slot, `TransactionExtra.cpp:195-197`), this is a hard-fork wire-format change requiring a new `tx_extra` tag carrying a kilobyte-scale ciphertext. There is no standardized compression for it — this is the open scaling problem, not speed.
- **Anonymity requirement.** Stealth addresses need KEM *key privacy* (ANO-CCA), not merely IND-CCA: the announcement must hide which recipient it was encapsulated to. Kyber/ML-KEM was proven ANO-CCA secure in the QROM (Maram–Xagawa, PKC 2023), which is the formal basis that makes a Kyber-based stealth construction sound [7].
- **No PQ non-interactive Diffie-Hellman drop-in exists.** Isogeny NIKEs (CSIDH) are non-standard, slow, and have contested quantum-security levels, so "one extra KEM ciphertext per output" is the only sound PQ design today [7].
- **Maturity: research prototype.** All published PQ stealth constructions (Mikic et al. lattice SAPs 2025; Pu et al. fuzzy stealth signatures, CCS 2023) are prototypes with no production deployment [7]. The fuzzy-tracking work is the most promising for scaling because it lets recipients outsource scanning to an untrusted server with a tunable false-positive rate.

### (c) Ordinary (single-key) signatures → ML-DSA / Falcon / SLH-DSA

Conceal's non-ring signatures — `generate_signature`/`check_signature` (Schnorr/EdDSA, `src/crypto/crypto.cpp:269`/`:293`) and `generate_tx_proof` (payment-proof DLEQ, `crypto.cpp:355`) — are the most straightforward to migrate because three NIST signature standards are final (Aug 2024). Each Conceal signature is a fixed 64-byte `Signature` POD, so any PQ choice overflows the field and forces a length-prefixed/tagged wire format.

Final-standard options (sizes from FIPS 204/205 [confirmed]):

| Scheme | Status | Signature | Public key | vs 64 B Ed25519 sig | Notes |
|---|---|---|---|---|---|
| ML-DSA-44 (FIPS 204) | Final | 2,420 B | 1,312 B | ~38× | Cat 2 |
| ML-DSA-65 (FIPS 204) | Final | **3,309 B** | 1,952 B | ~52× | Cat 3; common general-purpose choice |
| ML-DSA-87 (FIPS 204) | Final | **4,627 B** | 2,592 B | ~72× | Cat 5; CNSA 2.0 mandate level |
| Falcon-512 (FN-DSA) | **Draft (FIPS 206)** | ~666 B | 897 B | ~10× | Smallest; FP/Gaussian side-channel hazard |
| Falcon-1024 (FN-DSA) | **Draft** | ~1,280 B | 1,793 B | ~20× | — |
| SLH-DSA-128s (FIPS 205) | Final | 7,856 B | 32 B | ~123× | Hash-only; slow signing |
| SLH-DSA-256f (FIPS 205) | Final | 49,856 B | 64 B | ~779× | Conservative anchor only |

> Note: the commonly circulated ML-DSA-65/-87 signature figures of 3,293 B / 4,595 B are the pre-final round-3 Dilithium sizes; the FIPS 204 final values are **3,309 B / 4,627 B** [confirmed against FIPS 204 Table 2].

Recommendations per the verified findings [1][9]:

- **ML-DSA (FIPS 204) is the pragmatic default**: stateless, fast verification, no floating-point/Gaussian side-channel hazards, and the only finalized lattice signature easy to implement constant-time. Cost: ~38–72× larger signatures plus a ~1.3–2.6 KB public key that must also be stored/transmitted (total per-signature overhead ~3.7–7 KB vs ~96 B for Schnorr). FIPS 204 does **not** itself designate a default parameter set; the ML-DSA-65 "default" framing is third-party guidance, while CNSA 2.0 actually mandates ML-DSA-87 [partial-verdict correction].
- **Falcon (FN-DSA) is ~3.6× more compact** (~666–1,280 B) and the best size fit for a chain, but **FIPS 206 is not final** (Initial Public Draft pending as of mid-2026, final expected late 2026/early 2027), and its double-precision FFT Gaussian sampler is a documented side-channel hazard — single-trace power analysis has fully recovered Falcon-512 keys on embedded targets [1]. Treat as standards-risk and implementation-risk. (Algorand ships `falcon_verify` on-chain, demonstrating verification feasibility but predating the standard [1].)
- **SLH-DSA (FIPS 205) is the conservative fallback** (hash-only security, stateless), but 7.8–49.9 KB signatures (~100×+ Ed25519) make it impractical per-transaction; reserve for low-frequency root/checkpoint signing [9].
- **LMS/XMSS (SP 800-208) are unsuitable for wallet signing**: compact and hash-based but **stateful** — one-time-key reuse from a seed-phrase restore, snapshot rollback, or shared key is catastrophic and unrecoverable. NIST forbids any private-key copy/backup, which is incompatible with Conceal's 25-word mnemonic seed model (`src/Mnemonics/Mnemonics.cpp`). Viable only for a single tightly-HSM-controlled infrastructure key [9].

The same options apply to the payment-proof DLEQ (`generate_tx_proof`), which is a lower-severity (medium) surface but rests on the same 64-byte `Signature` slot.

### (d) Hashing & Proof-of-Work → Grover mitigation (little to do)

Conceal's hashing layer is Keccak-f[1600] (`cn_fast_hash`, `src/crypto/hash.c:23`) for tx/block IDs, Merkle `tree_hash`, hash-to-scalar and hash-to-point, plus the CryptoNight slow-hash family for PoW (`src/crypto/cryptonight.cpp`), all producing fixed 32-byte digests (`HASH_SIZE = 32`). The quantum exposure here is **Grover-only and mild** — there is no Shor-style break of a hash function [9].

Quantified facts [9]:

- **Grover gives only a proven-optimal quadratic speedup.** A 256-bit Keccak digest retains ~128-bit preimage security against a quantum adversary; collision resistance (BHT) drops to ~2⁸⁵ but remains infeasible. The query bound understates real cost — a fault-tolerant SHA-256/Keccak oracle adds an estimated ~2³⁸ gate overhead. **No widening is needed.** Doubling to a 512-bit digest is optional over-engineering, not a necessity.
- **PoW is not meaningfully threatened.** Grover parallelizes poorly (advantage scales only as √(M·t)), and per-iteration it is far slower than a classical ASIC — Aggarwal et al. (2017) estimate a quantum miner ~1000× slower than a single Antminer S9. CryptoNight's memory-hardness blunts Grover further. Any residual concern is absorbed by Conceal's difficulty adjustment (`check_hash`, `src/CryptoNoteCore/Difficulty.cpp:49`).
- **The only fatal exposure that *touches* the hashing domain is not a hash problem.** The key-image hash-to-point feeds `cn_fast_hash` (Grover-only, benign), but the surrounding `ge_scalarmult` is ECDLP and falls to Shor — that belongs to surface (a), not here.

**Verdict for this surface: no migration required for quantum resistance.** The 32-byte digest width is a *format-rigidity* concern (it compounds the wire-format problem if a future migration ever wanted wider digests, e.g. `check_hash` casts the digest to four `uint64` words and would silently misparse anything wider), but it carries no standalone quantum risk.

### Summary: difficulty is wildly uneven across surfaces

| Surface | Best PQ option | Object size | Maturity | Difficulty |
|---|---|---|---|---|
| (a) Ring sig + confidential amounts | MatRiCT+/SMILE (lattice RingCT) | ~30–47 KB/tx (10–30× blowup) | **Academic, zero production** | **Research-grade blocker** |
| (b) Stealth addresses | ML-KEM/Kyber KEM | ct 768–1,568 B (24–49× per output) | Prototype, standard exists | Hard but tractable |
| (c) Ordinary signatures | ML-DSA (or Falcon when FIPS 206 finalizes) | 2.4–4.6 KB sig + 1.3–2.6 KB pk | **Finalized standard** | Engineering, not research |
| (d) Hashing / PoW | None needed (Grover mild) | unchanged (32 B) | n/a | Trivial |

Surfaces (c) and (d) are solvable with finalized standards today; (b) has a sound standardized primitive (ML-KEM) but no deployed blockchain precedent and a 24–49× per-output size penalty. Surface (a) — the ring-signature/RingCT privacy layer that defines Conceal as a CryptoNote coin — has **no production-ready replacement anywhere in the world** and is the single feature that determines whether a PQ Conceal is feasible on any near-term timeline.

---

**Sources**

[1] FIPS 204 (ML-DSA) — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf ; FIPS 206/FN-DSA status — https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf ; Falcon sizes — https://falcon-sign.info/ ; Falcon side-channel — https://eprint.iacr.org/2024/1709 , https://arxiv.org/abs/2504.00320
[2] SoK "Quantum Disruption" — https://arxiv.org/abs/2512.13333 ; Monero FCMP++ — https://xgram.io/blog/is-my-monero-quantum-proof
[3] MatRiCT (CCS 2019) — https://eprint.iacr.org/2019/1287
[4] MatRiCT+ (IEEE S&P 2022) — https://eprint.iacr.org/2021/545
[5] SMILE (CRYPTO 2021) — https://eprint.iacr.org/2021/564 , https://research.ibm.com/publications/smile-set-membership-from-ideal-lattices-with-applications-to-ring-signatures-and-confidential-transactions
[6] SoK "Quantum Disruption" (PQC not a drop-in) — https://arxiv.org/html/2512.13333v1
[7] Mikic, Srbakoski & Praska, "Post-Quantum Stealth Address Protocols" — https://arxiv.org/abs/2501.13733 , https://eprint.iacr.org/2025/112.pdf ; Kyber ANO-CCA (Maram–Xagawa, PKC 2023) — https://link.springer.com/chapter/10.1007/978-3-031-31368-4_1 ; Pu et al. PQ Fuzzy Stealth Signatures (CCS 2023) — https://eprint.iacr.org/2023/1148.pdf
[8] FIPS 203 (ML-KEM) — https://csrc.nist.gov/pubs/fips/203/final , https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
[9] FIPS 205 (SLH-DSA) — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf ; SP 800-208 (LMS/XMSS stateful) — https://csrc.nist.gov/pubs/sp/800/208/final ; Grover optimality — https://en.wikipedia.org/wiki/Grover%27s_algorithm , https://eprint.iacr.org/2016/992.pdf ; Grover vs PoW (Aggarwal et al. 2017) — https://arxiv.org/pdf/1711.04235

---

Conceal uses a height-gated block-major-version hard-fork mechanism. I have enough to write the section grounded in the research and the local config.

## Precedent: what other chains did

No production blockchain has solved the problem Conceal faces — a full post-quantum replacement for CryptoNote ring signatures, key images, and stealth-address ECDH. But several projects have shipped or planned *parts* of the migration, and one (Abelian) is a direct post-quantum descendant of the same Monero/CryptoNote codebase Conceal derives from. Their choices map cleanly onto the three axes Conceal must decide: **scheme** (which PQC primitive), **hybrid vs. full** (PQC alongside classical, or PQC-only), and **activation** (hard fork, soft fork, opt-in, or account abstraction). The honest summary up front: real deployments cluster around *ordinary* (non-ring) signatures and *opt-in* scopes; the privacy-preserving core — anonymous, confidential, linkable spends — remains unshipped everywhere.

### Abelian (ABEL) — the closest precedent, and the one to study hardest

Abelian is the single most relevant data point for Conceal because it is a **post-quantum Monero-like built by forking the same CryptoNote lineage**. It forked Monero v0.13 as its codebase and replaced the elliptic-curve cryptography with NIST lattice primitives — CRYSTALS-Dilithium (now ML-DSA, FIPS 204) for signatures and CRYSTALS-Kyber (now ML-KEM, FIPS 203) — plus a **lattice-based linkable ring signature** scheme for sender anonymity and zero-knowledge range proofs for confidential amounts, all resting on the Learning-With-Errors (LWE) assumption [1][2]. It has run on mainnet since 17 April 2022. This is **full PQC by design** (not hybrid) via a **new chain / new address format** rather than an in-place migration of an existing ledger — Abelian launched fresh rather than transitioning live CryptoNote funds.

Two lessons for Conceal stand out:

1. **It is feasible to PQC-ify a CryptoNote privacy stack** — lattice linkable ring signatures + range proofs do cover both halves of the problem (anonymity *and* confidential amounts), which the signature-only academic schemes (Raptor, Falafl, DualRing) do not [3].
2. **But it was done greenfield, not as a migration.** Abelian did not have to solve the unsolved problem — proving ownership of, and safely transitioning, *existing* quantum-vulnerable outputs without exposing classical secrets [4]. Conceal, with a live ledger, does. Abelian therefore demonstrates the *destination* is reachable; it does not demonstrate the *transition path* Conceal needs.

A critical caveat for the report's honesty: Abelian's precise per-transaction on-chain object sizes are **under-documented in primary sources** [1][2]. Given that its building blocks are lattice ring signatures (tens of KB in the comparable MatRiCT/SMILE academic family) plus Dilithium/ML-DSA signatures (~2.4–4.6 KB each [5]), the on-chain blowup versus ECC CryptoNote is the core economic cost — but Conceal should treat any specific Abelian size figure as unverified until its spec is consulted directly.

### QRL — full PQC, but on *ordinary* signatures only

QRL is the longest-running production PQC chain: mainnet since 26 June 2018, securing every transaction with the stateful hash-based **XMSS** scheme — **full PQC, not hybrid** [6]. Two qualifications matter for Conceal. First, XMSS was only NIST-approved (SP 800-208) in October 2020, *after* QRL deployed it, and NIST explicitly scopes stateful hash-based signatures to tightly-controlled, low-volume signing — not general wallet use — because one-time-key reuse (from a restored backup, a snapshot rollback, or concurrent signers) is **catastrophic and unrecoverable** [7]. This makes XMSS/LMS a poor fit for seed-phrase wallets like Conceal's (`src/Mnemonics/Mnemonics.cpp`), which are copied and restored by design. Second, QRL provides **no privacy layer** — it secures plain signatures, not ring signatures or stealth addresses. Its migration *to* stateless SPHINCS+/SLH-DSA (Project Zond) is still on testnet as of mid-2026. Takeaway: QRL proves full-PQC transactional signing is viable for years in production, but says nothing about the anonymity/confidentiality machinery that is Conceal's hard problem.

### Bitcoin (BIP-360 / BIP-361) — the migration-mechanics blueprint, not a scheme

Bitcoin is the most-cited precedent and the most misreported. BIP-360, in its current Draft (v0.11.0), is **Pay-to-Merkle-Root (P2MR)** — it removes the Taproot key-path spend to mitigate long-exposure quantum key recovery and **explicitly does not introduce any PQC signature scheme**; ML-DSA and SLH-DSA are named only as candidates under research, and the proposal is unmerged with no activation mechanism [8]. (The widely-repeated "BIP-360 merged with ML-DSA in 2026" framing is wrong; only a BTQ *testnet* implementation exists [9].) What *is* useful to Conceal is the companion **migration choreography**: a new PQC output type, a **height/version-gated multi-phase hard fork** (ban sends to legacy addresses at ~3 years, invalidate legacy signatures at ~5 years — *freezing* un-migrated vulnerable funds — with an optional ZKP-based recovery path), and an explicit hybrid coexistence window [4]. Conceal already has exactly this gating machinery: `UPGRADE_HEIGHT_V1..V8` and `BLOCK_MAJOR_VERSION_*` in `src/CryptoNoteConfig.h`, validated through `Blockchain.cpp`. A PQC fork would add a `BLOCK_MAJOR_VERSION_9` at a new `UPGRADE_HEIGHT_V9`, exactly as every prior Conceal consensus change (CN-GPU, halving, LWMA) was rolled out — so the *activation* mechanism is the least novel part of Conceal's problem.

### Algorand, Ethereum, Zcash — opt-in scope, hybrid agility, and roadmap

These three illustrate the patterns Conceal will likely choose among for the *parts* it cannot fully solve at once:

- **Algorand** executed the first PQC user transaction on a live public mainnet (3 November 2025) using **Falcon-1024** (FN-DSA) via **account abstraction** — a Falcon key embedded in a logic signature, verified by a new `falcon_verify` AVM opcode — **without any consensus change** [10]. Crucially, this is *opt-in and scoped*: Algorand's own consensus block-proposal and sortition-VRF signatures remain classical Ed25519, and the team labels the Falcon tooling experimental. Lesson: opt-in, no-consensus-change agility ships fastest, but leaves the core protocol quantum-vulnerable.
- **Ethereum** is roadmap-stage: replace consensus BLS with hash-based **leanXMSS** (aggregated through a `leanVM` zkVM, because hash-based validator signatures are ~3,000 B vs. ~96 B for BLS), plus per-account **signature agility** via account-abstraction (EIP-8141). Core PQC infrastructure is targeted ~2029; nothing PQC is on mainnet [11].
- **Zcash** — the most directly comparable privacy chain — is **recoverability-first**: "Orchard Quantum Recoverability" plus Project Tachyon, testing ML-KEM/ML-DSA, full transition targeted ~2027; nothing PQC shipped yet [12].

### Synthesis for Conceal

| Project | Scheme | Hybrid vs. full | Activation | Status (mid-2026) | Covers privacy core? |
|---|---|---|---|---|---|
| **Abelian** | Dilithium/ML-DSA + Kyber/ML-KEM, lattice linkable ring sig | Full | New chain / new address | **Mainnet since 2022** | **Yes** (greenfield) |
| QRL | XMSS (→ SPHINCS+ planned) | Full | New chain | Mainnet since 2018 | No (plain sigs) |
| Bitcoin | P2MR now; ML-DSA/SLH-DSA candidate | Hybrid (planned) | Multi-phase hard fork | Draft / testnet only | N/A (UTXO, no privacy) |
| Algorand | Falcon-1024 | Opt-in alongside classical | Account abstraction, no consensus change | Mainnet (opt-in, experimental) | No |
| Ethereum | leanXMSS + EIP-8141 | Hybrid / agility | Account abstraction + consensus fork | Roadmap (~2029) | N/A |
| Zcash | ML-KEM / ML-DSA + Tachyon | Recoverability-first | Hard fork (planned) | Roadmap (~2027) | Partial (planned) |

Four lessons Conceal should carry forward:

1. **Abelian is the existence proof and the template — but it went greenfield.** A PQC CryptoNote privacy stack works in production, but no one has migrated a *live* CryptoNote ledger to it. Conceal must either follow Abelian's greenfield path (new chain/address type) or solve the still-unsolved live-transition problem [4].
2. **The privacy core is the unshipped frontier.** Every incumbent that "shipped PQC" did so for ordinary signatures or opt-in scopes (QRL, Algorand) and left anonymity/confidentiality classical or deferred (Zcash, Monero's own FCMP++ stayed on Ed25519). Conceal's ring-signature/key-image/stealth-ECDH layer (`src/crypto/crypto.cpp`, `src/CryptoNoteCore/Blockchain.cpp`) is precisely the part nobody has productionized — Abelian's lattice ring signatures being the lone exception, and only greenfield.
3. **Activation is the easy part.** Conceal's existing `UPGRADE_HEIGHT`/`BLOCK_MAJOR_VERSION` gating in `src/CryptoNoteConfig.h` already provides Bitcoin-BIP-361-style phased hard-fork machinery; the new work is the wire format and the transition, not the fork trigger.
4. **Avoid the two known traps.** Stateful hash-based schemes (XMSS/LMS) are a footgun for seed-phrase wallets [7]; and opt-in agility (Algorand-style) ships fast but, applied naively, would leave Conceal's consensus and privacy guarantees quantum-vulnerable — the same gap Algorand still has.

---

**Sources**

[1] https://github.com/CryptoBLK/Abelian
[2] https://medium.com/@abelianfoundation/public-code-release-of-abelian-v1-0a-alpha-source-code-codename-dilithium-5456e1be2191
[3] https://eprint.iacr.org/2018/857 (Raptor); https://eprint.iacr.org/2020/646 (Falafl); https://eprint.iacr.org/2021/1213 (DualRing)
[4] https://arxiv.org/html/2512.13333v1 (SoK "Quantum Disruption"); https://groups.google.com/g/bitcoindev/c/nSAd0UmDSvc (BIP-361)
[5] https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf (FIPS 204, ML-DSA sizes)
[6] https://docs.theqrl.org/what-is-qrl/ ; https://csrc.nist.gov/pubs/sp/800/208/final
[7] https://csrc.nist.gov/pubs/sp/800/208/final ; https://www.wolfssl.com/special-rules-for-lms-and-xmss/
[8] https://raw.githubusercontent.com/bitcoin/bips/master/bip-0360.mediawiki
[9] https://www.prnewswire.com/news-releases/btq-technologies-announces-first-deployment-of-bip-360-on-bitcoin-quantum-testnet-v0-3-0--302718592.html
[10] https://algorand.co/blog/technical-brief-quantum-resistant-transactions-on-algorand-with-falcon-signatures
[11] https://ethereum.org/roadmap/future-proofing/quantum-resistance/ ; https://www.coindesk.com/tech/2026/02/26/vitalik-buterin-unveils-ethereum-roadmap-to-counter-quantum-computing-threat
[12] https://www.coindesk.com/tech/2026/05/08/zcash-to-roll-out-quantum-recoverable-wallets-within-a-month-go-quantum-proof-by-2027

---

The verdicts confirm my key Conceal-specific facts. I have what I need to write the section.

## Recommended strategy, phased roadmap, risks & open questions

This section synthesizes the local surface map and the verified research into an actionable recommendation for the Conceal core team. The guiding constraint is blunt: **the entire transaction-authorization and privacy layer of Conceal reduces to ECDLP on Ed25519/Curve25519, which Shor breaks in polynomial time** — ring signatures (`src/crypto/crypto.cpp:491`), key images (`crypto.cpp:461`), stealth-address ECDH (`crypto.cpp:96`), and single-key signatures (`crypto.cpp:269`) all fall together. Keccak-based hashing and CryptoNight PoW are only Grover-weakened (quadratic), which is **not** an emergency. So the work is overwhelmingly about replacing asymmetric primitives and re-architecting the wire format, not about widening hashes.

A second, equally blunt constraint: **none of the cryptography that would replace Conceal's privacy core exists in production anywhere.** The complete lattice RingCT family (MatRiCT, MatRiCT+, SMILE, LACT+) is academic-only, with no mainnet deployment as of mid-2026 [1]. Even Monero — the reference CryptoNote privacy chain — shipped FCMP++ in Q1 2026 that is still classical Ed25519 and explicitly defers lattice/hash PQC to a post-Seraphis roadmap (2027+) [2]. The honest posture is therefore: **prepare and de-risk now; commit the hard privacy migration only when the research matures.**

### Why "act now" is justified despite the immaturity

Under Mosca's inequality `X + Y > Z` (data shelf-life + migration time vs. time-to-CRQC), a privacy chain is the worst case: every historical block is public and permanent, so `X` is effectively unbounded. Expert median CRQC estimate is ~2029–2032, with ~34% probability of an RSA-2048-class break by 2030 (GRI/evolutionQ Quantum Threat Timeline Report 2025) [3]; NSA CNSA 2.0 wants signing migrated to ML-DSA-87 / ML-KEM-1024, exclusive by 2030 for firmware signing [4]. For Conceal specifically, the highest-priority quantum risk is **retroactive deanonymization**, ranked above theft — exactly as Monero's own CCS research proposal ranks it [2]. The published ephemeral tx public key `R` in `tx_extra` (`src/CryptoNoteCore/TransactionExtra.cpp:193`) plus a recipient's view public key let a Shor-capable adversary recompute the ECDH shared secret for *every output ever created* and link it to its destination. **Migration protects only future outputs — it can never un-expose the existing ledger.** This is harvest-now-decrypt-later, and the harvesting is free for anyone running an archive node [5]. The clock that matters is the one for *future* privacy, and it is already running.

### The structural blocker: fixed-size POD serialization

Before any PQC primitive can land, the wire format must change. Conceal hard-codes every cryptographic object to a fixed Ed25519/Curve25519 size in `include/CryptoTypes.h` — `Hash`, `PublicKey`, `SecretKey`, `KeyDerivation`, `KeyImage` are all `uint8_t data[32]`, and `Signature` is `uint8_t data[64]` (confirmed by direct read). These are serialized as raw POD with **no length prefix and no algorithm tag** via `serializePod` → `binary(&v, sizeof(v))` (`src/CryptoNoteCore/CryptoNoteSerialization.cpp:120`, `src/Serialization/BinaryOutputStreamSerializer.cpp:84`). The decoder knows a field's size *only* because `sizeof` is fixed at compile time. Additional curve-specific consensus invariants are baked in:

- A hardcoded Ed25519 prime-order-subgroup check on key images: `scalarmultKey(keyImage, L) == I` with the literal group order `L` and identity `I` (`Blockchain.cpp:2366-2371`, confirmed by direct read).
- One 64-byte `Signature` per ring member, with count == ring size (`CryptoNoteSerialization.cpp:225`).
- The PoW digest read as exactly four 64-bit little-endian words in `check_hash` (`src/CryptoNoteCore/Difficulty.cpp:49`) — any digest wider than 256 bits silently misparses.
- Base58 addresses assuming `prefix(2) || spendPub(32) || viewPub(32) || checksum(4)` (`src/Common/Base58.cpp:216`), and the 25-word mnemonic encoding *exactly* a 32-byte seed (`src/Mnemonics/Mnemonics.cpp:37`).

PQC objects are kilobytes — ML-DSA-65 signature 3,309 B / public key 1,952 B [6][7], SLH-DSA signatures 7,856–49,856 B [8], ML-KEM-768 ciphertext 1,088 B / encapsulation key 1,184 B [9], and lattice RingCT transactions tens of KB [1]. **None of these fit a 32- or 64-byte slot.** The first, unavoidable, research-independent engineering task is therefore a **new length-prefixed, algorithm-tagged serialization scheme** alongside the legacy POD path. This is a hard consensus fork affecting transaction, block, and address parsing across the entire network and the stored blockchain — but it is feasible *today* and it gates everything else.

### Throughput and size economics (the real cost)

Object size, not CPU, is the decisive cost. Verification of lattice schemes is cheap (~23 ms for MatRiCT; ML-DSA verify is fast and constant-time-friendly; a Kyber-based stealth scan is actually ~3× *faster* than the best classical EC protocol) [1][6][10]. The pain is bytes on chain. Throughput scales roughly inversely with transaction size: the 2025 "Quantum Disruption" SoK shows a worked Algorand example where swapping Ed25519 (64 B) for ML-DSA-44 (2,420 B) grows a 200 B tx to 2,556 B and drops theoretical TPS ~92% [11] (note: the reduction tracks the *transaction*-size ratio, not the raw signature ratio — verified). Conceal is *worse* than a plain UTXO chain because each input already carries a ring signature over multiple members, so swapping each member's primitive multiplies an already-large object [12]. Absorbing the blowup by raising block size degrades consensus convergence: the same SoK cites a 10× block-size increase pushing Bitcoin's fork probability from ~1.9% to ~17.6% via slower propagation [13]. **Block-size, fee, and difficulty/throughput parameters must be revisited at the same fork as any crypto swap — they are not separable.**

### Recommended phased, height-gated hard-fork roadmap

Conceal should mirror the converging industry blueprint (new PQ output type + version/height-gated multi-phase fork + freeze-and-recover for un-migrated funds), as seen in Bitcoin BIP-360/BIP-361 [14], but adapted to CryptoNote's ring structure. Sequencing is deliberately easy-to-hard, deployable-to-research-blocked.

**Phase 0 — Foundations (feasible NOW, no research blocker).**
- Ship the **length-prefixed, algorithm-tagged serialization** v2 format and the height-gated hard-fork machinery. This is the long pole; start here.
- Add **hybrid ordinary (non-ring) signatures** for the Schnorr/EdDSA single-key paths (`crypto.cpp:269`, e.g. multisig inputs) and any future PQ-only outputs: carry both the 64-byte Ed25519 signature **and** an ML-DSA-65 signature (FIPS 204, final standard, no floating-point side-channel hazards, fast verify) [6][7]. Hybrid defends against both a quantum break *and* an undiscovered flaw in the young lattice scheme, at additive size cost [15].
- Optionally widen Keccak/`Hash` margin — but treat this as **over-engineering, not necessity.** 256-bit Keccak retains ~128-bit preimage security under Grover, which is proven-optimal and not beaten [16]; CryptoNight PoW is safe (Grover parallelizes only as a square root and is ~1000× slower than a modern ASIC [17]). Do *not* hold the fork on hash widening. If done at all, it must be co-designed with `check_hash`'s four-64-bit-word assumption (`Difficulty.cpp:49`).
- Deploy a **"quantum canary"**: a deliberately-exposed key/bounty whose spend signals a live CRQC, as an early-warning trigger [2].

**Phase 1 — PQ KEM stealth addresses (feasible NOW with a research prototype; the most defensible early privacy win).**
- Replace the ECDH stealth shared secret with an **ML-KEM (Kyber, FIPS 203) KEM encapsulation** per output, following the benchmarked Mikic et al. Module-LWE Stealth Address Protocol [10]. The sender encapsulates to the recipient meta-address producing a ciphertext (the on-chain announcement); the view-key holder decapsulates to recover the shared secret and derive the one-time key. View-key scanning survives unchanged and is *faster* (~15× vs. DKSAP, ~3× vs. the best classical EC protocol) [10].
- **Critical correctness requirement:** stealth addresses need KEM *anonymity* (ANO-CCA / key privacy), not merely IND-CCA, so an announcement leaks nothing about the recipient. Kyber/ML-KEM was proven ANO-CCA in the QROM by Maram–Xagawa (PKC 2023) — this is the formal basis that makes a Kyber stealth scheme sound; a naive IND-CCA-only KEM would break unlinkability [18].
- **Cost:** the per-output announcement grows from a 32-byte ephemeral key to a 768–1,568 B ML-KEM ciphertext (~24×–49×), and meta-addresses from ~32 B to 800–1,568 B [9]. This requires a **new `tx_extra` tag** carrying a kilobyte-scale encapsulation (the existing 32-byte `TX_EXTRA_TAG_PUBKEY` slot at `TransactionExtra.cpp:193` cannot be reused), and a redesigned address/meta-address format and mnemonic backup. There is **no production-ready PQ non-interactive Diffie-Hellman** drop-in (CSIDH-class isogeny NIKEs are non-standard, slow, and have contested quantum security), so "one extra KEM ciphertext per output" is the only sound path [19].
- The same swap protects **on-chain encrypted messages** (`tx_extra_message`, `TransactionExtra.cpp:390`), whose ChaCha8 key today derives 100% from the same broken Curve25519 ECDH — a fatal Shor exposure that Phase 1 closes for future messages.

**Phase 2 — PQ ring signatures + RingCT (BLOCKED on research; do not commit yet).**
- This is the "hard core" and the genuinely fatal exposure: forging ring signatures, computing key images for outputs you don't own (theft), and collapsing untraceability. The candidate families — MatRiCT, MatRiCT+ (proof size reduced to O(log M) in inputs), SMILE (~30 KB for a 2-in/2-out tx over a 2^15 anonymity set), LACT+ — are **all academic prototypes with zero mainnet deployment**, tens of KB per transaction (~10–30× classical RingCT), and ongoing churn of new schemes [1]. Raptor/Falafl/DualRing cover only the ring-signature half and do **not** hide amounts [1].
- **Recommendation: do not pick a Phase-2 scheme now.** Track the field, fund or follow a reference integration, and gate commitment on the open questions below. The existence proof that a CryptoNote-descended PQC privacy chain is buildable is **Abelian (ABEL)** — a live Monero-v0.13 fork using Dilithium/Kyber and a lattice linkable ring signature since 2022 — but its concrete on-chain sizes are under-documented in primary sources and it should be studied, not blindly copied [20].

**Output migration mechanics (spanning all phases).**
- Use **version/height-gated phases with a sunset**, mirroring BIP-361: at fork height, allow PQ output types; after a multi-year window, **ban sends to legacy quantum-vulnerable output types**; after a longer window, **invalidate legacy spends entirely** (freezing un-migrated funds), with a recovery path for holders who still control their seed [14].
- Distinguish exposure classes when prioritizing: outputs whose curve point is already on-chain are immediately harvestable and must migrate first [5]. Forced mass migration is costly — Bitcoin's estimate is ~76–152 days of cumulative network capacity to re-spend all UTXOs, and CryptoNote's per-input ring cost makes it worse — so phased multi-year deadlines, not an instant cutover, are the realistic mechanism [21].
- **Honest caveat:** securely migrating existing accounts *without exposing classical secrets* is an explicitly **unsolved** open problem (2025 SoK); ZKP-of-ownership approaches exist but are unintegrated with PQ primitives [22]. Treat any migration design as experimental.

### Key risks

1. **Privacy is already forfeit for the past.** No phase recovers the confidentiality of existing outputs/messages. The only lever is the *migration timeline* for future privacy — the dominant risk variable [5].
2. **Committing too early to an immature Phase-2 scheme.** The lattice RingCT field is churning; a premature choice risks shipping a scheme later found weak or superseded, with a consensus fork sunk into it [1].
3. **Size/throughput collapse.** Without coordinated block-size/fee/difficulty changes, PQ objects can drop TPS ~90% and raise orphan rates sharply [11][13].
4. **Standards risk.** Only ML-KEM (203), ML-DSA (204), SLH-DSA (205) are final. Falcon/FN-DSA (FIPS 206) and HQC are still drafts — attractive (Falcon sig ~666–1,280 B [23]) but not yet deployable for standards-conformant work, and Falcon's floating-point Gaussian sampler has demonstrated single-trace side-channel key-recovery [24]. **Prefer ML-DSA and ML-KEM for anything committed now.**
5. **Stateful HBS footguns.** LMS/XMSS are compact but stateful; one-time-key reuse from a seed-phrase restore is catastrophic and unrecoverable, making them unsuitable for general wallet signing — avoid for Conceal user keys [25].
6. **Migration mechanics unsolved.** The freeze-and-recover model is unproven in any production privacy chain [22].

### Open questions to resolve before committing

- **Phase-2 scheme selection:** Which lattice RingCT family (MatRiCT+/SMILE/LACT+/Abelian's construction), at what anonymity-set size, and what is the *measured* per-transaction byte cost on Conceal's actual ring sizes — not paper figures?
- **Block/throughput parameters:** What new max block size, fee schedule, and difficulty retargeting keep fork/orphan rates acceptable at the projected PQ object sizes?
- **Anonymity-set strategy:** Stay with fixed rings, or move toward a full-chain-membership model (as Monero did, but PQ)? These have very different proof-size scaling.
- **Migration without secret exposure:** Is there an acceptable ZKP-of-ownership path to migrate legacy funds, and what are the centralization/UX tradeoffs?
- **Hybrid duration and freeze deadlines:** How long is the classical+PQ coexistence window, and at what heights do legacy-send-ban and legacy-spend-invalidation activate?
- **Hash widening:** Is widening `Hash` past 256 bits worth the format churn given Grover is only quadratic? (Current evidence: no.)
- **Falcon vs. ML-DSA for ordinary signatures:** Wait for FIPS 206 final to gain Falcon's ~3.6× smaller signatures, or ship ML-DSA now and accept the size?

### Decision points for the maintainers

1. **Commit to Phase 0 now** — build the length-prefixed/algorithm-tagged serialization v2 and the height-gated hard-fork framework. This is feasible today and gates everything; nothing else can ship without it.
2. **Approve hybrid ML-DSA-65 for ordinary/non-ring signature paths** as the standardized, side-channel-safe choice; defer Falcon pending FIPS 206 finalization.
3. **Greenlight Phase 1 (ML-KEM stealth addresses + encrypted messages) as a prototype**, accepting the ~24×–49× per-output size cost and requiring the ANO-CCA Kyber variant. This is the earliest *defensible* privacy win.
4. **Do NOT select a Phase-2 ring/RingCT scheme yet** — fund tracking/evaluation against the open questions; treat Abelian as a study target, not a template.
5. **Deploy a quantum canary** and adopt a fixed, frequent hard-fork cadence to enable rapid future rollout.
6. **Mandate that block-size/fee/throughput parameter changes ship in the same fork** as any crypto swap.
7. **Accept and communicate publicly** that historical on-chain privacy cannot be retroactively protected; prioritize the future-output migration timeline accordingly.

---

**Sources:** [1] MatRiCT/MatRiCT+/SMILE/LACT+ family and production status — https://eprint.iacr.org/2019/1287, https://eprint.iacr.org/2021/545, https://eprint.iacr.org/2021/564, https://arxiv.org/abs/2512.13333 . [2] Monero FCMP++ and CCS PQ research proposal — https://ccs.getmonero.org/proposals/research-post-quantum-monero.html, https://xgram.io/blog/is-my-monero-quantum-proof . [3] GRI/evolutionQ Quantum Threat Timeline Report 2025 — https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/ . [4] NSA CNSA 2.0 — https://www.encryptionconsulting.com/quantum-proof-with-cnsa-2-0/ . [5] Harvest-now-decrypt-later / Mosca — https://en.wikipedia.org/wiki/Harvest_now,_decrypt_later, https://postquantum.com/post-quantum/moscas-theorem/ . [6][7] FIPS 204 ML-DSA — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf, https://csrc.nist.gov/pubs/fips/204/final . [8] FIPS 205 SLH-DSA — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf . [9] FIPS 203 ML-KEM — https://csrc.nist.gov/pubs/fips/203/final . [10] PQ stealth address protocols (Mikic et al.) — https://arxiv.org/abs/2501.13733, https://eprint.iacr.org/2025/112.pdf . [11][13] Quantum Disruption SoK (throughput, fork rates) — https://arxiv.org/html/2512.13333v1 . [12] FIPS 204/205 size blowup vs Ed25519 — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf . [14] Bitcoin BIP-360/BIP-361 migration blueprint — https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki, https://groups.google.com/g/bitcoindev/c/nSAd0UmDSvc . [15] Hybrid signatures — https://arxiv.org/html/2512.13333v1 . [16] Grover bound — https://en.wikipedia.org/wiki/Grover%27s_algorithm, https://eprint.iacr.org/2016/992.pdf . [17] Grover vs PoW — https://arxiv.org/pdf/1711.04235 . [18] Kyber ANO-CCA (Maram–Xagawa) — https://link.springer.com/chapter/10.1007/978-3-031-31368-4_1 . [19] No PQ NIKE drop-in — https://csrc.nist.gov/pubs/fips/203/final . [20] Abelian (ABEL) — https://github.com/CryptoBLK/Abelian . [21] UTXO migration cost — https://arxiv.org/html/2512.13333v1 . [22] Transition unsolved (SoK) — https://arxiv.org/html/2512.13333v1 . [23] Falcon sizes/status — https://falcon-sign.info/, https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf . [24] Falcon side-channel — https://eprint.iacr.org/2024/1709, https://arxiv.org/abs/2504.00320 . [25] LMS/XMSS statefulness — https://csrc.nist.gov/pubs/sp/800/208/final .

---

## References

[1] FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf

[2] FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA) — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf

[3] FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA) — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf

[4] NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes (LMS/XMSS) — https://csrc.nist.gov/pubs/sp/800/208/final

[5] FIPS 206 (FN-DSA / Falcon) Status Update — 6th NIST PQC Standardization Conference, R. Perlner, Sep 2025 — https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf

[6] NIST PQC Standardization Project (status page; FN-DSA and HQC drafts) — https://csrc.nist.gov/projects/post-quantum-cryptography

[7] NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption (11 Mar 2025) — https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption

[8] HQC Specification (2025-08-22) — https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf

[9] Federal Register: Announcing Issuance of FIPS 203, 204, and 205 (14 Aug 2024) — https://www.federalregister.gov/documents/2024/08/14/2024-17956/announcing-issuance-of-federal-information-processing-standards-fips-fips-203-module-lattice-based

[10] Esgin, Zhao, Steinfeld, Liu, Liu — MatRiCT: Efficient, Scalable and Post-Quantum Blockchain Confidential Transactions (CCS 2019), IACR ePrint 2019/1287 — https://eprint.iacr.org/2019/1287

[11] Esgin, Steinfeld, Zhao — MatRiCT+: More Efficient Post-Quantum Private Blockchain Payments (IEEE S&P 2022), IACR ePrint 2021/545 — https://eprint.iacr.org/2021/545

[12] Lyubashevsky, Nguyen, Seiler — SMILE: Set Membership from Ideal Lattices with Applications to Ring Signatures and Confidential Transactions (CRYPTO 2021), IACR ePrint 2021/564 — https://eprint.iacr.org/2021/564

[13] Alberto Torres et al. — Lattice RingCT v2.0 (MIMO), IACR ePrint 2019/569 — https://eprint.iacr.org/2019/569

[14] Lu, Au, Zhang — Raptor: A Practical Lattice-Based (Linkable) Ring Signature (ACNS 2019), IACR ePrint 2018/857 — https://eprint.iacr.org/2018/857

[15] Beullens, Katsumata, Pintore — Calamari and Falafl: Logarithmic (Linkable) Ring Signatures (ASIACRYPT 2020), IACR ePrint 2020/646 — https://eprint.iacr.org/2020/646

[16] Yuen, Esgin, Liu, Au, Ding — DualRing: Generic Construction of Ring Signatures (CRYPTO 2021), IACR ePrint 2021/1213 — https://eprint.iacr.org/2021/1213

[17] Mallick, Zeldin, Cenk, Nita-Rotaru — Quantum Disruption: An SoK of How Post-Quantum Attackers Reshape Blockchain Security and Performance, arXiv:2512.13333 — https://arxiv.org/abs/2512.13333

[18] Bitcoin BIP-360: Pay-to-Merkle-Root (P2MR) — https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki

[19] Maram, Xagawa — Post-Quantum Anonymity of Kyber (PKC 2023), IACR ePrint 2022/1696 — https://eprint.iacr.org/2022/1696.pdf

[20] Mikic, Srbakoski, Praska — Post-Quantum Stealth Address Protocols (Jan 2025), IACR ePrint 2025/112 / arXiv:2501.13733 — https://arxiv.org/abs/2501.13733

[21] Mikic et al. — A More Efficient Stealth Address Protocol (Apr 2025), arXiv:2504.06744 — https://arxiv.org/abs/2504.06744

[22] Pu, Thyagarajan, Doettling, Hanzlik — Post-Quantum Fuzzy Stealth Signatures and Applications (ACM CCS 2023), IACR ePrint 2023/1148 — https://eprint.iacr.org/2023/1148.pdf

[23] "Do Not Disturb a Sleeping Falcon": Floating-Point Error Sensitivity of the Falcon Sampler (Eurocrypt 2025), IACR ePrint 2024/1709 — https://eprint.iacr.org/2024/1709

[24] SHIFT SNARE: Single-Trace Power Analysis Key Recovery on Falcon, IACR ePrint 2025/146 / arXiv:2504.00320 — https://eprint.iacr.org/2025/146

[25] Aggarwal, Brennen, Lee, Santha, Tomamichel — Quantum Attacks on Bitcoin, and How to Protect Against Them (2017), arXiv:1711.04235 — https://arxiv.org/pdf/1711.04235

[26] Amy et al. — Estimating the Cost of Generic Quantum Pre-image Attacks on SHA-2 and SHA-3, IACR ePrint 2016/992 — https://eprint.iacr.org/2016/992.pdf

[27] Bennett, Bernstein, Brassard, Vazirani — Strengths and Weaknesses of Quantum Computing (Grover optimality); see also survey arXiv:2202.10982 — https://arxiv.org/pdf/2202.10982

[28] Klarman et al. — bloXroute Labs Whitepaper v1.1 (block propagation / fork analysis), Jan 2019 — https://bloxroute.com/wp-content/uploads/2019/01/whitepaper-V1.1-1.pdf

[29] Decker, Wattenhofer — Information Propagation in the Bitcoin Network (IEEE P2P 2013) — https://tik-db.ee.ethz.ch/file/49318d3f56c1d525aabf7fda78b23fc0/P2P2013_041.pdf

[30] Mosca, Piani et al. — Quantum Threat Timeline Report 2025 (Global Risk Institute / evolutionQ) — https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/

[31] Monero CCS — Research: Post-Quantum Monero — https://ccs.getmonero.org/proposals/research-post-quantum-monero.html

[32] Algorand — Technical Brief: Quantum-Resistant Transactions with Falcon Signatures — https://algorand.co/blog/technical-brief-quantum-resistant-transactions-on-algorand-with-falcon-signatures

[33] Algorand — State Proofs (Falcon-1024) Documentation — https://dev.algorand.co/concepts/protocol/state-proofs/

[34] QRL — The Definitive Guide to Post-Quantum Blockchain Security — https://www.theqrl.org/the-definitive-guide-to-post-quantum-blockchain-security/

[35] QRL — Project Zond — https://www.theqrl.org/project-zond/

[36] Abelian — Source Code Release (Codename Dilithium) — https://github.com/CryptoBLK/Abelian

[37] Nervos CKB — Native Quantum Resistance (SPHINCS+ Lock Script) — https://docs.nervos.org/docs/ckb-features/native-quantum-resistance

[38] Ethereum — Quantum Resistance Roadmap — https://ethereum.org/roadmap/future-proofing/quantum-resistance/

[39] U.S. Federal Reserve — Harvest Now, Decrypt Later: Examining Post-Quantum Cryptography and the Data Privacy Risks for Distributed Ledger Networks — https://www.federalreserve.gov/econres/feds/harvest-now-decrypt-later-examining-post-quantum-cryptography-and-the-data-privacy-risks-for-distributed-ledger-networks.htm

---

*Provenance: produced by the conceal-core `/multi-agent` workflow. Surface map derived from the local codebase; landscape claims web-researched and adversarially verified (10 confirmed, 8 corrected, 0 refuted). This is a decision-support document, not a commitment to implement.*
