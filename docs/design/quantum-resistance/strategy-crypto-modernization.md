# Q2 — Modernize the Crypto Stack (beyond PQ)

**Status:** analysis only — no source edited.
**Scope:** audit the *current* cryptographic primitives in conceal-core as they actually exist in
the code, name better modern alternatives, and rate the migration risk for each. This is the
"clean up the crypto we already have" question, distinct from "add post-quantum" (Q1) and "should we
rewrite in Rust / total redesign" (Q3). PQ is referenced only where the two intersect.

The governing distinction throughout: **non-consensus swaps** (wallet file, message encryption,
local KDF — change them and only *new* artifacts differ; old wallets/peers keep working) vs.
**consensus swaps** (signatures, PoW, the wire/disk serialization, address format — change them and
you fork the chain or break every peer/wallet, so they are hard-fork + audit-gated).

---

## 0. What the code actually uses today (grounded inventory)

| Primitive | Where | What it is | Modern status |
|---|---|---|---|
| **KV binary serialization** | `src/Serialization/KVBinary*`, `BinaryInput/OutputStreamSerializer` | Homemade tag-length-value KV format (CryptoNote "portable storage"), hand-written `serialize()` per struct via `ISerializer` | No schema, no versioned IDL; fine but fragile |
| **chacha8** | `src/crypto/chacha8.{c,h}` | ChaCha **8-round** stream cipher (reduced from standard 20), used for (a) wallet file encryption, (b) legacy 0x04 message field | Non-standard round count; no AEAD/MAC |
| **0x04 encrypted message** | `src/CryptoNoteCore/TransactionExtra.cpp` ~L445–510 | chacha8 keystream over `derivation`-derived key + **4 trailing zero bytes as an "owner check"** | Unauthenticated (malleable); the 4-zero check is *not* a MAC |
| **Wallet-file KDF** | `crypto/chacha8.h:generate_chacha8_key`, `WalletLegacySerializer.cpp`, `WalletSerializationV1.h` | `cn_slow_hash_v0(password)` → 32-byte chacha8 key. **No salt, no iteration count, single pass.** | Weak password KDF; not Argon2/scrypt |
| **Ed25519 / Curve25519** | `src/crypto/crypto.cpp`, `crypto-ops.c`, `ge_*`, `sc_*` | Edwards25519 for one-time keys, ECDH (`generate_key_derivation`), LSAG-style ring signatures, key images | Classically strong; **Shor-broken** under a CRQC |
| **CryptoNight v0 PoW** | `CryptoNoteFormatUtils.cpp:624` `cn_slow_hash_v0`; backends in `src/crypto/pow_hash/` | The **original** CryptoNight (2 MB scratchpad, AES round); v0 variant | ASIC-saturated; superseded everywhere by RandomX |
| **Address checksum** | `src/Common/Base58.cpp` | Base58 + **4-byte `cn_fast_hash` (Keccak) checksum** | Keccak is fine; 4 bytes is a typo-guard, not security |
| **Key derivation (scalars)** | `crypto.cpp` `hash_to_scalar` = Keccak → `sc_reduce32` | Standard CryptoNote scalar derivation | Fine; the `hash_to_ec`/`hash_to_point` is the legacy non-Elligator map (a known minor footgun, not exploited here) |
| **PQ keypair RNG (gap)** | `pqc/ccx-pqc/src/lib.rs:173,183` `kyber768::keypair()` / `dilithium3::keypair()` | Library-internal `OsRng`; **not** derived from a seed | Can't regenerate PQ keys from a wallet mnemonic → backup/HD-wallet gap |

Two of these (the lattice ring sig already swapped to a real construction, and the 0x06 message
field already on ChaCha20-Poly1305 AEAD) are PQ work-in-progress and out of Q2 scope except as
precedent — the 0x06 AEAD swap is exactly the template the legacy items below should follow.

---

## 1. chacha8 + the 4-zero-byte owner-check (the AEAD question)

This is the most clear-cut item and it splits into three independent surfaces. **You already proved
the right answer once** — the new PQ 0x06 message field uses ChaCha20-Poly1305 (`ccx_pq_msg_seal`,
SHAKE256-derived key+nonce, 16-byte Poly1305 tag), and the in-code comment at
`TransactionExtra.cpp:521` explicitly contrasts it with "the legacy 0x04 chacha8 + 4-zero-byte
owner-test (which has no MAC and is left untouched)." The legacy items should follow that template
where they can.

### 1a. Legacy 0x04 message encryption — **REPLACE the construction, but it's already obsoleted, not "fixed in place"**

What's wrong (real, in the code):
- **chacha8** = ChaCha reduced to 8 rounds. Not catastrophically broken, but it is a non-standard,
  reduced-round variant chosen ~2014 for speed; there is no reason to keep it for *new* ciphertext.
- **No authentication.** The construction is keystream-only. The "4 trailing zero bytes, check they
  decrypt to zero" is a *probabilistic owner test* (1-in-2³² that a wrong key passes), **not** a MAC.
  An attacker who can flip ciphertext bytes flips plaintext bytes 1:1 (stream-cipher malleability);
  the zero-check only catches it if a flip lands in the last 4 bytes. On-chain messages are
  immutable once mined, so the practical attack surface is limited, but it is genuinely
  unauthenticated encryption and should not be presented as private+integrity-protected.
- Nonce = `SWAP64LE(index)` (the output index), key = `cn_fast_hash(derivation‖0x80)`. Deterministic
  nonce is acceptable here *only because* the key is unique per (tx, recipient); it's not a
  reusable-nonce bug, but it's brittle.

**Recommendation:** Don't retrofit a MAC onto 0x04. The PQ 0x06 AEAD field already supersedes it
functionally. The clean path:
1. Treat 0x04 as **frozen legacy** — keep decrypt-only support forever (old txs must stay readable);
   stop *emitting* it for new messages.
2. For the classical (non-PQ) path, if you still want a pre-fork message format, introduce a new
   tx-extra tag (e.g. 0x07) that is **ChaCha20-Poly1305 (or XChaCha20-Poly1305) AEAD** with the same
   ECDH-derived key — mirror exactly what `ccx_pq_msg_seal` does, minus the KEM. This is a clean
   reuse of code you already wrote and tested.
3. Long-term, the PQ 0x06 field is the real successor (it fixes both the cipher *and* the
   Shor-broken ECDH).

**Risk: LOW / non-consensus-ish.** Messages are tx-extra payload, not validated by consensus
(nodes don't decrypt them). Emitting a new tag is backward-compatible: old wallets ignore unknown
tags. The only "compatibility" concern is wallet UX (an old wallet can't *read* a new-format
message), which is a normal feature-gating problem, not a fork. **Do this now.**

### 1b. Wallet-file encryption (chacha8 + cn_slow_hash_v0 KDF) — **REPLACE, highest-value easy win**

Two weaknesses stack here, and both are local-only (the wallet file never touches consensus):
- **Cipher:** chacha8, again unauthenticated. A corrupted/truncated wallet file decrypts to garbage
  with no integrity signal beyond downstream parse failure.
- **KDF (the bigger problem):** `generate_chacha8_key` does **one pass of `cn_slow_hash_v0` over the
  raw password, no salt, no iteration/cost parameter.** CryptoNight v0 is memory-hard (~2 MB) so it's
  not *trivially* brute-forced, but: (i) no salt → identical passwords → identical keys, and rainbow
  tables are feasible; (ii) no tunable cost → can't raise the bar as hardware improves; (iii) it's a
  PoW hash repurposed as a password KDF, which is not what it was designed or analyzed for.

**Recommendation:** New wallet-file format version:
- **KDF → Argon2id** (RFC 9106; the modern default for password→key) with a random per-wallet salt
  stored in the header and tunable memory/time cost. scrypt is an acceptable fallback if an Argon2
  dependency is unwelcome, but Argon2id is the right answer in 2026.
- **Cipher → XChaCha20-Poly1305 AEAD** (24-byte random nonce avoids nonce-management entirely; you
  already have a ChaCha20-Poly1305 impl in the Rust module / via the AEAD you adopted). Authenticated
  → tamper/corruption detection for free.
- Bump the wallet serialization version; **keep load-only support for the old chacha8 format** and
  transparently re-encrypt on next save (migrate-on-open). Zero user friction, no data loss.

**Risk: LOW / non-consensus.** Wallet file is purely client-side. The only care needed: a clean
versioned header and an unambiguous migration path so existing wallets open. This is the
**single highest value-to-risk item in the whole audit** — it directly protects user funds at rest
and touches nothing the network sees. **Do this now**, ideally bundled with the deterministic-keygen
fix (§5) since both change the wallet format.

### 1c. The chacha8 primitive itself

Once 1a and 1b move off it, chacha8 survives only as decrypt-only legacy. Leave the file in place
(needed to read old wallets/messages); do not build anything new on it.

---

## 2. Homemade KV binary serialization vs. a schema'd format

`src/Serialization` is a hand-rolled tag-length-value "portable storage" (the CryptoNote/epee
lineage) plus per-struct hand-written `serialize(ISerializer&)`. It is the **single most dangerous
thing to touch** in this whole document, and the recommendation is mostly "don't, but harden."

What it is and why it's risky to change:
- It is simultaneously the **P2P wire format**, the **on-disk blockchain format**, and the
  **wallet/tx-extra format**. The exact byte layout is consensus-observable: the hash of a tx/block
  is computed over the serialized bytes (`get_block_longhash`, `getObjectHash`). **Any change to how
  a consensus object serializes changes its hash → changes block/tx IDs → forks the chain and breaks
  every checkpoint and every stored block.**
- There is **no schema, no IDL, no field-name/wire-compat checking.** Correctness is "the
  hand-written `serialize()` matches on both sides," verified only by it-still-syncs. New fields are
  added by hand (you did exactly this for `PqKeyInput`/`PqKeyOutput`), which is error-prone — a
  mis-ordered field or wrong length is a silent fork.

Modern alternatives and the honest verdict:
- **Protobuf / Cap'n Proto / FlatBuffers / SSZ (Ethereum) / Borsh (Solana/Rust)** give you a schema,
  generated codecs, canonical encoding, and forward/backward-compat rules. For a *greenfield* coin
  any of these (SSZ or Borsh for determinism-critical consensus data) would be the right call.
- **For this chain:** you **cannot swap the consensus serialization without a hard fork and a full
  re-hash of history**, and even then you'd have to bit-for-bit reproduce existing hashes for all
  historical blocks (impossible) or accept that all checkpoints/IDs change (a chain reset, not a
  fork). So a wholesale format swap is effectively "launch a new chain," which belongs to the Q3
  redesign conversation, not Q2 modernization.

**What is worth doing now (non-consensus, high-value):**
1. **A schema-as-documentation + golden-vector test harness.** Write down the canonical byte layout
   of every consensus-serialized struct and add round-trip + fixed-golden-vector tests
   (serialize → known bytes → hash → known hash). This catches the exact class of silent-fork bug the
   hand-written serializers invite, and is *especially* needed because you are actively adding PQ
   fields. **This is the real action item for §2.** Low risk, high payoff.
2. **A canonicalization audit:** confirm there is exactly one valid encoding per object (no
   length-prefix ambiguity, no optional-field ordering slack) — non-canonical encodings are a
   classic malleability/double-relay bug. Document, don't rewrite.
3. **Isolate non-consensus serialization** (RPC JSON responses, config, internal IPC) where you
   *can* freely adopt a schema'd format with no fork. The JSON serializers (`JsonOutput/Input*`) are
   already separate; if any new external API surface is added, use a schema'd format there.

**Risk of touching the consensus codec: CRITICAL (chain fork).** **Risk of the test/schema-doc
harness: LOW and it's protective.** Recommendation: **freeze the consensus codec, add golden-vector
tests around it, never refactor it for aesthetics.**

---

## 3. Ed25519 / Curve25519 — classically fine, Shor-broken

This is the Q1 (PQ) story, included here for completeness of the audit. Curve25519/Ed25519 are
excellent classical primitives (no classical weakness in the way they're used here — one-time keys,
ECDH derivations, LSAG ring signatures, key images). The **only** problem is a
cryptographically-relevant quantum computer: Shor's algorithm breaks the discrete log, which would
let an attacker recover spend keys from public keys and forge signatures / link outputs.

- **Consensus-critical, hard-fork-gated, audit-gated.** The spend signature and key-image are the
  core consensus rule. The PQ branch already replaces them with the experimental lattice anonymous
  linkable ring signature (`ringsig.rs`) and ML-KEM-768 stealth — that *is* the migration. The
  blocker is the maturity of the ring-sig (demo-grade params, not constant-time, unaudited), which is
  the Q1 hard wall, not a Q2 "swap a primitive" task.
- **No Q2 action distinct from Q1.** There is no "better classical curve" worth migrating to
  (P-256/secp256k1 are not improvements; ristretto255 would be a marginal hygiene win but a
  consensus fork for no real benefit). The right move is PQ, height-gated, per the existing
  blueprints. Don't churn the curve layer for its own sake.

**Risk: CRITICAL (consensus, fork, audit).** Already owned by the PQ track.

---

## 4. CryptoNight v0 PoW — the RandomX precedent

The daemon hashes blocks with `cn_slow_hash_v0` (`CryptoNoteFormatUtils.cpp:624`) — the **original**
CryptoNight, v0 variant. Real-world precedent is unambiguous here:

- CryptoNight v0 is **fully ASIC-dominated.** Monero (CryptoNight's origin) went through
  CN v1 → v2 → v4/R specifically to brick ASICs, then **abandoned the whole family for RandomX**
  (Nov 2019) precisely because the tweak-treadmill was unwinnable. v0 is the *oldest, most
  ASIC-friendly* point on that curve. Any ASIC built for early Monero/other CN coins hashes CCX.
- The PQ angle is a **non-issue**: Grover only quadratically speeds up hash preimage search, which
  just halves effective PoW security (a 256-bit hash → 128-bit), and difficulty already absorbs
  hashrate changes. Your own `pow-grover-widening.md` correctly concludes "no change needed." **PoW
  does not need PQ.** The CryptoNight problem is purely a classical ASIC-centralization /
  fair-mining concern.

Modern alternatives:
- **RandomX** (Monero, also used by Wownero, Arweave-adjacent, etc.) — the de-facto standard for
  ASIC-resistant CPU PoW. Battle-tested, audited, with a maintained reference implementation. This is
  the obvious target if PoW modernization is desired.
- Others (ProgPoW = GPU-leaning and effectively dead post-Ethereum-merge; Autolykos/Equihash =
  GPU/memory variants) are not better fits than RandomX for a CPU-fair CryptoNote descendant.

**The hard part — this is a CONSENSUS change:**
- The PoW hash is *the* block-validity rule. Switching to RandomX is a **hard fork** gated behind a
  new `UPGRADE_HEIGHT_V*` + block major version (exactly the mechanism `CryptoNoteConfig.h`
  already uses for V3–V8).
- It is **disruptive to miners** (everyone re-tools; existing CN ASICs become worthless — which is
  the point but also a political event), changes difficulty calibration, needs new
  mining-software/pool support, and RandomX brings a heavy verification cost / large dataset
  (~2+ GB fast mode) that affects node resource profiles.
- It needs its own testing campaign (testnet fork, difficulty retarget tuning — you already saw LWMA
  overshoot stalls on the PQ testnet).

**Risk: HIGH (consensus, hard fork, miner ecosystem).** Worth doing **only if** ASIC centralization
is an actual observed problem for CCX and the community wants it — it is a *policy/economics*
decision, not a security bug. It is independent of PQ and should not be bundled with the PQ fork
(two large consensus changes at once multiplies risk). **Defer unless there's a mining-fairness
mandate; if pursued, RandomX is the answer and it's a standalone height-gated hard fork.**

---

## 5. Deterministic-keygen gap (Kyber/Dilithium RNG keypairs)

Real gap in the current PoC: `kyber768::keypair()` and `dilithium3::keypair()`
(`pqc/ccx-pqc/src/lib.rs:173,183`) use the pqcrypto library's **internal OS RNG**. They are **not**
derived from a seed. By contrast the *classical* CryptoNote keys and the lattice ring-sig seed
(`ccx_pq_keygen` takes a `seed` and does `seed32(seed)`) are deterministic.

Why this matters:
- CryptoNote wallets are **deterministic / mnemonic-restorable** — your whole spend key is recovered
  from a seed phrase. If PQ KEM/signature keys are RNG-generated and *not* seed-derivable, then a
  mnemonic backup **cannot** restore the PQ half of the wallet. You'd have to back up raw PQ secret
  keys separately (large, error-prone) — a serious UX/funds-loss regression for the wallet-v2 work.
- It also blocks any HD-wallet / sub-address derivation for PQ outputs.

The fix (well-defined, not research):
- **FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) both specify deterministic keygen from a seed**
  (ML-KEM: `(d,z)` 64-byte seed; ML-DSA: 32-byte `ξ` seed). The standardized "keygen from seed" /
  "derand" APIs exist precisely for this. The pqcrypto crate's `keypair()` wraps the randomized
  variant; you need the **deterministic/derand keygen** entry point (or a library that exposes it —
  e.g. the RustCrypto `ml-kem`/`ml-dsa` crates expose seed-based keygen). Derive the PQ seed from the
  wallet master seed via a domain-separated SHAKE/HKDF, exactly as `ccx-stealth-otk` already does.
- This makes PQ keys mnemonic-restorable and HD-derivable, closing the gap.

**Risk: LOW-to-MEDIUM, non-consensus *if done right*.** Keygen happens wallet-side; the *public*
keys and on-chain artifacts are unchanged in format, so it is not a consensus fork. The MEDIUM
caveat: it must be done **before** any PQ wallet ships with real funds, because changing the keygen
derivation later would orphan already-created keys. Get the seed-derivation domain separation and the
FIPS-compliant derand path right the first time, with test vectors. **Do this as part of the
wallet-v2 / wallet-file-format work (bundle with §1b).**

---

## 6. Address checksum & scalar key derivation

Minor / mostly-fine items, audited for completeness:
- **Address checksum** (`Base58.cpp`, 4-byte `cn_fast_hash`/Keccak): this is a **typo guard**, not a
  security control — it stops fat-fingered addresses, nothing more. Keccak is fine; 4 bytes is
  conventional. **No change needed.** (It is also consensus-adjacent in the sense that the address
  format is a compatibility surface; don't touch it without a reason.) When the PQ wallet-address-v2
  format lands (PQ keys are large), it'll need its own versioned address prefix + checksum — that's
  new format design, not a fix to the existing one.
- **`hash_to_scalar` = Keccak → `sc_reduce32`:** standard CryptoNote, fine.
- **`hash_to_point` / `hash_to_ec`:** the legacy CryptoNote map-to-curve (not Elligator2). It's a
  known minor wart across the CryptoNote family but is consensus-frozen (key images depend on it) and
  not exploitable as used here. **Do not touch — consensus.**

---

## 7. Prioritized recommendation

**Tier 1 — do now (non-consensus, high value, low risk):**
1. **Wallet-file format v2: Argon2id KDF (salt + tunable cost) + XChaCha20-Poly1305 AEAD**, with
   load-only legacy support and migrate-on-open. (§1b) — *highest value-to-risk item; protects funds
   at rest.*
2. **Deterministic FIPS-203/204 PQ keygen from the wallet seed** (so PQ keys are
   mnemonic-restorable), bundled into the same wallet-format change. (§5) — *must land before any PQ
   wallet holds real funds.*
3. **Golden-vector + round-trip test harness around the consensus serializer**, and a written
   canonical-layout spec — *protective, urgent because PQ fields are actively being added by hand.*
   (§2)
4. **New AEAD message tag (ChaCha20-Poly1305) for classical messages**, freeze 0x04 to decrypt-only.
   Reuses the PQ AEAD code you already wrote/tested. (§1a)

**Tier 2 — policy/community decision, standalone hard fork (do NOT bundle with the PQ fork):**
5. **RandomX PoW** — only if ASIC centralization is an actual problem for CCX and the community wants
   it. Height-gated `UPGRADE_HEIGHT_V*`, its own testnet + difficulty-retune + pool-software
   campaign. (§4)

**Tier 3 — already owned by the PQ track / do not churn:**
6. Ed25519/Curve25519 → PQ: this *is* the Q1 lattice-ring-sig + ML-KEM migration; consensus,
   audit-gated, blocked on ring-sig maturity. No separate Q2 action. (§3)
7. Consensus serializer wholesale swap to a schema'd format: effectively "launch a new chain" —
   belongs to Q3 (total redesign), not Q2. (§2)
8. Address checksum, `hash_to_scalar`, `hash_to_point`: leave alone. (§6)

**The through-line:** every genuinely *easy and safe* modernization here is wallet-side / client-side
(items 1, 2, 4) — and you already built the reference implementation for the cipher half when you
swapped the PQ message field to ChaCha20-Poly1305 AEAD. The genuinely *valuable but hard* items
(PoW, the consensus serializer, the signature layer) are all hard precisely because they're
consensus — they fork the chain, demand audits, and should each be isolated height-gated events, not
combined. Modernize the wallet now; gate everything consensus behind the existing
`UPGRADE_HEIGHT_*` mechanism, one change at a time.
