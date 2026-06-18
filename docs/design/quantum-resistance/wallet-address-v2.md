# PQ Wallet Keys + Address Format v2 — Design Blueprint

Status: **DESIGN / advisory** (no source edited). Targets the working PoC on
`pqc/testnet-poc`. Goal: replace the hardcoded testnet keys + `pq_injector` tool
with a real wallet that derives PQ keys from a mnemonic seed, publishes a PQ
address, scans PQ stealth outputs, and builds/signs a PQ spend natively.

This is consensus- and money-critical. Everything here is **testnet-gated** until
the underlying ring signature is audited (CIP-0001 C1). The address format is the
durable, user-facing surface — get the framing/versioning right now even though
the crypto under it is demo-grade.

---

## 0. Where the PoC stands (the gap this closes)

Grounded in the real branch:

- **PQ key material today is hardcoded.** A single ML-KEM-768 recipient keypair is
  baked into `pqc/include/pq_testnet_kem_keypair.h` (`PQ_TESTNET_KEM_PK` /
  `PQ_TESTNET_KEM_SK`), minted once via `ccx_pq_kem_keypair`. The testnet coinbase
  (`Currency.cpp`) encapsulates to that fixed PK; `pq_injector.cpp` decapsulates with
  that fixed SK. There is **no per-user key, no address, no mnemonic** in the PQ path.
- **The injector is a stand-in wallet.** `pqc/tools/pq_injector.cpp` does the four
  jobs a wallet must do: (1) parse coinbase txs for `PqKeyOutput{key, kemCt}`
  (`parseCoinbasePq`), (2) `ccx_pq_kem_scan(PQ_TESTNET_KEM_SK, kemCt) -> seed`,
  (3) `ccx_pq_keygen(seed) -> (otPk, otSk)` to recover the one-time spend keypair,
  (4) assemble a ring from on-chain keys and `ccx_pq_sign(...)` -> `PqKeyInput`.
- **The crypto ABI already exists** in `pqc/ccx-pqc/src/lib.rs` (C-ABI) and is what
  the wallet will call. Relevant sizes from the real code:
  - `ccx_pq_pubkey_bytes()` = `ringsig::PK_BYTES` = `K*N*4` = `4*256*4` = **4096 B**
    (the lattice ring-sig public key `t`).
  - `ccx_pq_seckey_bytes()` = **32 B** (a seed; the short secret `s` is re-derived).
  - `ccx_pq_nullifier_bytes()` = **32 B**.
  - `ccx_pq_kem_pubkey_bytes()` = **1184 B** (ML-KEM-768 PK),
    `ccx_pq_kem_seckey_bytes()` = **2400 B** (SK),
    `ccx_pq_kem_ct_bytes()` = **1088 B** (`kemCt`).
  - `ccx_pq_scheme_id()` = `0xC0DE_0003`.

These sizes drive the address size (see §2) and storage (§4).

---

## 1. Cryptographic roles a PQ address must carry

A legacy CCX address (`AccountPublicAddress`, `include/CryptoNote.h:91`) is two
32-byte Ed25519 points: **spend** + **view**, Base58 with a 2-byte varint prefix
(`0x7ad4` = `ccx7…`) and a 4-byte `cn_fast_hash` checksum (`Base58.cpp` `encode_addr`).

The PQ analogue needs **three** distinct key roles, because in the PoC two different
primitives do two different jobs:

| Role | Legacy | PQ v2 | Primitive | Pub size |
|------|--------|-------|-----------|----------|
| **Detect/receive** (recipient-unlinkability) | view key | **KEM key** | ML-KEM-768 | 1184 B |
| **Authorise spend** (ownership + ring anonymity + nullifier) | spend key | **ring-sig key** | lattice AOS/LSAG | 4096 B (per-output, derived) |
| **(optional) Hybrid EC** | — | legacy Ed25519 spend+view | Ed25519 | 32+32 B |

Key separation, mirroring the PoC's two primitives:

- The **KEM keypair** is the *long-term account key*. It is the one whose **public**
  part goes in the address (senders encapsulate to it), and whose **secret** part the
  wallet keeps to scan (`ccx_pq_kem_scan`). This is the "view-key-like" role but it is
  also spend-enabling: whoever holds the KEM secret can recover the one-time seed.
- The **ring-sig keypair is NOT a long-term account key.** In the PoC every output has
  a *distinct, one-time* lattice keypair derived from the KEM shared secret
  (`ccx_pq_keygen(seed) -> otPk/otSk`), so the **4096-byte `t` never appears in the
  address** — only on-chain in `PqKeyOutput.key`. This is the crucial size win: the
  address carries the 1184-byte KEM PK, not the 4096-byte ring PK.

> **Design decision (important):** the v2 address carries **only the ML-KEM-768 public
> key** as its PQ component (+ optional legacy EC for hybrid). The ring-sig public key
> is per-output and derived, so it must NOT be embedded. This keeps the address ~1.2 KB
> instead of ~5.3 KB and matches how the PoC actually works.

### 1.1 Hybrid mode (optional, recommended default for migration)

A **hybrid** address additionally carries the legacy Ed25519 spend+view keys so:

- the same address can receive both legacy `KeyOutput` (via Ed25519 stealth) and PQ
  `PqKeyOutput` (via ML-KEM stealth) during the transition;
- funds are protected by EC today and PQ after the fork, with no re-issuing of
  addresses. (Security is `max(EC, PQ)` for confidentiality of *new* outputs.)

Three address kinds, selected by prefix (§2.2):
- **`ccxpq`** — PQ-only (KEM PK [+ ring-sig domain tag]).
- **`ccxh`** — hybrid (legacy spend+view *and* KEM PK).
- (`ccx7…` legacy unchanged.)

---

## 2. Address format v2

### 2.1 Reuse the existing Base58 address machinery

Do **not** invent a new encoder. `tools::base_58::encode_addr/decode_addr`
(`src/Common/Base58.cpp:216-246`) already gives: varint tag prefix + payload +
4-byte `cn_fast_hash` checksum, block-wise Base58. It is payload-length-agnostic, so a
1.2 KB payload encodes fine (it will just produce a long string, ~1.6k Base58 chars —
acceptable for a copy/paste/QR address; see §7 risk on UX).

The only constraints `parseAccountAddressString` adds today
(`CryptoNoteBasicImpl.cpp:73`) are `check_key()` on the two Ed25519 points — those
calls do not apply to the PQ payload, so v2 needs a **separate parse/format path**
keyed on the prefix, not a modification of the legacy one (keep legacy untouched).

### 2.2 New prefixes (consensus-adjacent constant — `CryptoNoteConfig.h`)

Add alongside `CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x7ad4`:

```cpp
// PQ address prefixes — chosen so Base58 human-readable prefix reads "ccxpq"/"ccxh".
// Tune the numeric value the same way 0x7ad4 was tuned to render "ccx7".
const uint64_t CRYPTONOTE_PUBLIC_PQ_ADDRESS_BASE58_PREFIX     = /* tune -> "ccxpq" */;
const uint64_t CRYPTONOTE_PUBLIC_HYBRID_ADDRESS_BASE58_PREFIX = /* tune -> "ccxh"  */;
// Parallel TESTNET_* values (testnet uses a distinct human prefix, e.g. "tccxpq").
```

> The numeric prefix that yields a desired leading string must be **computed**, not
> guessed: write a tiny one-off that brute-forces the varint tag whose Base58 of
> `[tag || zeros]` starts with the target letters (how `0x7ad4`→`ccx7` was found).
> Document the chosen value + the script in this folder.

### 2.3 Payload struct (new serialized type)

Add to `include/CryptoNote.h` (next to `AccountPublicAddress`):

```cpp
struct PqAccountPublicAddress {
  uint8_t  pqVersion;                 // = 2; format/versioning byte inside the payload
  uint8_t  flags;                     // bit0: hybrid, bit1: reserved …
  uint32_t kemSchemeId;               // pin = ccx_pq_kem scheme (ML-KEM-768) for agility
  uint32_t ringSchemeId;              // pin = ccx_pq_scheme_id() (0xC0DE0003) for agility
  std::vector<uint8_t> kemPublicKey;  // 1184 B (ML-KEM-768 PK) — length-validated on parse
  // hybrid only (present iff flags.hybrid):
  crypto::PublicKey legacySpendPublicKey; // 32 B
  crypto::PublicKey legacyViewPublicKey;  // 32 B
};
```

Serialize via the existing `ISerializer` pattern (`serializeAsBinary` for `kemPublicKey`,
exactly like `PqKeyOutput.kemCt` in `CryptoNoteSerialization.cpp:295`). **Validate on
parse**: `kemPublicKey.size() == ccx_pq_kem_pubkey_bytes()`, `kemSchemeId`/`ringSchemeId`
match the daemon's compiled-in values, `pqVersion == 2`. Fail fast (coding-style:
input validation at boundaries). This is the analogue of legacy's `check_key()`.

`pqVersion` + the two `schemeId`s give **crypto-agility**: when the ring sig is
recalibrated for production (CIP C1), bump `ringSchemeId`; old addresses stay parseable
and rejectable with a clear "unsupported scheme" error rather than silent misuse.

### 2.4 New format/parse functions

In `CryptoNoteBasicImpl.{h,cpp}` (new functions, legacy ones untouched):

```cpp
std::string getPqAccountAddressAsStr(uint64_t prefix, const PqAccountPublicAddress&);
bool parsePqAccountAddressString(uint64_t& prefix, PqAccountPublicAddress&, const std::string&);
```

A dispatcher (e.g. in the wallet / RPC layer) peeks the decoded varint tag and routes
to legacy vs PQ vs hybrid parse. **Do not** overload the legacy `AccountPublicAddress`
path — a longer payload there would currently fail `fromBinaryArray`/`check_key`.

---

## 3. Wallet keygen from a mnemonic seed

### 3.1 Today's seed path (legacy, to mirror)

`AccountBase::generate()` (`Account.cpp:29`) does `generate_keys(spendPub, spendSec)`
then `generateViewFromSpend(spendSec, viewSec, viewPub)` where the view key is
**deterministically derived** from the spend secret
(`generate_keys_from_seed`, `crypto.cpp:73`). The CLI 25-word mnemonic
(`Mnemonics::mnemonicToPrivateKey`) encodes the **32-byte spend secret**; the view key
falls out deterministically. So one 256-bit seed reconstructs the whole legacy account.

### 3.2 PQ deterministic derivation (the core new primitive)

Keep the **same UX**: one mnemonic = one 32-byte master seed. Derive *all* PQ material
deterministically from it via domain-separated SHAKE256 (the module already uses
SHAKE/`seed32`). Proposed derivation (to add as a thin Rust ABI on top of existing
`ccx_pq_*` so the C++ wallet stays simple — see §6):

```
master32          = mnemonicToSeed(words)                 // 32 B, reuse CLI 25-word path
kem_seed          = SHAKE256("ccx-pq-kem-acct"  || master32)   // 32 B
ringacct_seed     = SHAKE256("ccx-pq-ring-acct" || master32)   // 32 B (reserved/agility)
legacy_spend_sec  = SHAKE256("ccx-legacy-spend" || master32)   // 32 B (hybrid only)
(KEM_PK, KEM_SK)  = MLKEM768_keygen_deterministic(kem_seed)    // NEW: needs det. keygen
legacy_view       = generateViewFromSpend(legacy_spend_sec)     // existing path
```

> **CRITICAL gap to flag:** the current `ccx_pq_kem_keypair` (lib.rs:181) uses
> `kyber768::keypair()` — **RNG-based, non-deterministic**. Deterministic ML-KEM key
> generation from a seed is **required** for mnemonic recovery and is **not yet
> implemented**. Two options:
> 1. Use a KEM library exposing seed-based keygen (FIPS 203 ML-KEM `KeyGen(d,z)` takes
>    a 64-byte seed → fully deterministic). `pqcrypto-kyber` may not expose this;
>    `ml-kem`/`libcrux-ml-kem`/`fips203` crates do. **Verify the chosen crate exposes
>    `keygen_deterministic(seed)` before committing** (research-first).
> 2. Fallback: store the raw KEM secret in the encrypted wallet file and treat the
>    mnemonic as a *backup of a stored blob*, not a from-seed regenerator — weaker UX
>    (mnemonic alone can't restore), acceptable only as an interim.
>
> Recommend option 1. This is the single biggest new-crypto dependency in this design.

The lattice **ring-sig account** keypair is *not* a long-term key (§1), so no per-account
ring keypair is strictly needed; `ringacct_seed` is reserved for a future "spend
authorisation root" if the design moves away from KEM-derived one-time keys.

### 3.3 Mnemonic encoding of the master seed

Reuse the existing 25-word list/CRC (`src/Mnemonics`). The master 32-byte seed maps to
words exactly as the legacy spend secret does — **no new wordlist, no new checksum**.
The difference is purely *what we derive from it*. This keeps backup/restore identical
for users and means a legacy seed can be *upgraded in place* to a hybrid wallet
(same words, new derived KEM key) — a nice migration property; call it out in UX.

---

## 4. Wallet storage (encrypted container)

### 4.1 What must persist

| Field | Size | Notes |
|-------|------|-------|
| `master32` (or mnemonic) | 32 B | root; everything else derivable |
| KEM secret key | 2400 B | needed every scan; cache to avoid re-keygen per block |
| KEM public key | 1184 B | for address display |
| legacy spend/view (hybrid) | 64 B | existing record |
| per-output recovered one-time `otSk` seeds | 32 B each | cache of spendable PQ outputs |
| ring/kem `schemeId`s | 8 B | agility/version pinning |

### 4.2 Reuse `WalletGreen` container, add a PQ record

The container today stores fixed-size `EncryptedWalletRecord`s (chacha8, IV chain;
`WalletGreen.h:204` `ContainerStoragePrefix`, `encryptKeyPair`). The KEM keypair is
**variable/large (1184+2400 B)** and does not fit the fixed Ed25519 record shape, so:

- **Do not shoehorn** the KEM key into `EncryptedWalletRecord` (it's sized for 32-byte
  keys). Instead add a **versioned PQ side-section** in the wallet cache
  (`WalletSerializationV2`) that holds: `master32`, `kemSchemeId`, `ringSchemeId`,
  encrypted KEM SK/PK blob, and the spendable-PQ-output cache.
- Bump the wallet **container/cache version** so old daemons/wallets reject a PQ wallet
  cleanly and a PQ wallet refuses a legacy-only build with a clear message
  (compatibility surface — call it out).
- Encrypt the PQ section with the **same chacha8 key** derived from the wallet password,
  continuing the existing IV chain (`getNextIv`/`incIv`), so password change/rekey
  (`copyContainerStorageKeys`) re-encrypts it uniformly. No new KDF.

### 4.3 View-only / scan-only PQ wallet

The KEM secret is *both* detect and spend-enabling, so unlike legacy there is no
"view-only that can't spend" variant for PQ unless the design later splits a
detect-only sub-key. For v2: a PQ "tracking" wallet would hold the KEM PK only and can
**recognise** outputs **it cannot recover the one-time seed for** — i.e. it can show
incoming amounts only if we additionally publish a detect tag. **Flag as a limitation**;
legacy view-key semantics do not map 1:1 onto a single KEM key. (A future detect/spend
split would mirror Monero's view/spend; out of scope here.)

---

## 5. Scanning PQ stealth outputs

This replaces `pq_injector`'s parse+scan loop (`pq_injector.cpp:48-117`) with wallet
code, driven off the existing blockchain-sync/`TransfersSynchronizer` path.

For each new block's transactions, for each output of type `PqKeyOutput{key, kemCt}`:

```
1. seed = ccx_pq_kem_scan(myKemSk, kemCt)            // 32 B; cheap, one decapsulation
2. (otPk, otSk) = ccx_pq_keygen(seed)                // re-derive one-time keypair
3. if otPk == output.key:                            // 4096-B compare -> it's ours
      record spendable output { globalIndex, amount, otSk(=seed) }
   else: not ours, skip
```

Notes / correctness:

- **Step 3 is the ownership test** — same as the injector's
  `ccx_pq_kem_scan -> ccx_pq_keygen -> compare key` logic, now per-output during sync.
- **Performance:** one ML-KEM decapsulation per PQ output scanned. Decaps is fast (µs),
  but `ccx_pq_keygen` runs the lattice keygen (poly arithmetic) — measure on the WSL
  host; if hot, gate step 2 behind a cheap pre-filter. A natural pre-filter: publish a
  short **detect tag** `t = SHAKE256("ccx-pq-detect" || ss)[..8]` in the output and
  compare 8 bytes before doing the 4096-byte keygen+compare. (Requires a tiny output
  format addition; optional optimisation, testnet-gated.)
- **Amount + global index** come from the existing output indexing the daemon already
  maintains (`m_pqOutputs[amount]` — see `Blockchain.{h,cpp}`); the wallet needs the
  **global index within `m_pqOutputs[amount]`** to later name ring members in
  `PqKeyInput.outputIndexes`. A testnet `get_pq_outputs` RPC (noted in POC-RESULTS as a
  next step) should expose this so the wallet doesn't re-parse coinbase hex.
- Store recovered spendable outputs in the PQ section (§4); on rescan, re-derive.

---

## 6. Building + signing a PQ spend (replacing `pq_injector`)

The injector's spend path (`pq_injector.cpp:91-160`) becomes a wallet method, e.g.
`WalletGreen::createPqTransaction(...)`. Steps:

```
INPUTS (per output being spent):
1. pick the spendable output (amount A, our otSk seed).
2. choose ring: fetch ringSize-1 decoys of the SAME amount A from m_pqOutputs[A]
   (via get_pq_outputs RPC), + our real member; record their global outputIndexes.
3. ring buffer = concat(member.key)  // each 4096 B, stride = ccx_pq_pubkey_bytes()
4. msg = the tx prefix hash bound to this input (MUST match what the daemon's
   check_pq_tx_input verifies — bind to tx contents to stop replay/malleability).
5. sig: two-call ccx_pq_sign size query then sign (sk = our seed, signer_index = our
   position in the ring).  -> ringSig bytes.
6. nullifier = ccx_pq_nullifier(otSk)  -> 32 B.
7. emit PqKeyInput{ amount:A, outputIndexes:[…], nullifier, ringSig }.

OUTPUTS (paying a PQ/hybrid recipient):
8. parse recipient address -> recipient KEM PK.
9. (ct, seed) = ccx_pq_kem_derive_output(recipientKemPk)   // sender side stealth
10. (otPk, _) = ccx_pq_keygen(seed)
11. emit PqKeyOutput{ key:otPk, kemCt:ct }, amount = denomination.
   (change handled the same way back to our own KEM PK.)

12. set tx.version = 3 (PQ); serialize; submit to mempool.
```

Correctness / consensus alignment (must match the daemon, else the spend is rejected):

- **`msg` binding is the most safety-critical choice.** The injector signs some message;
  the wallet **must** sign exactly the bytes `Blockchain::check_pq_tx_input` recomputes
  and feeds to `ccx_pq_verify` (ring members in the same order, same amount, same
  prefix-hash domain). Mismatch ⇒ silent rejection; a *loose* binding ⇒ malleability.
  **Verify against the real `check_pq_tx_input` before coding** and document the exact
  message construction in the spec.
- **Ring member ordering** must be deterministic and reproduced verbatim by the daemon
  from `outputIndexes` (the daemon resolves keys from `m_pqOutputs`). The wallet sends
  indexes; the daemon rebuilds the ring bytes — so the wallet must order its local ring
  buffer to match index order, and `signer_index` must point at the real member's slot.
- **Unlock window:** `check_pq_tx_input` enforces an unlock/maturity window; the wallet
  must not select outputs that are too recent (mirror the legacy coinbase-maturity
  check). Surface "not yet spendable" rather than building a doomed tx.
- **Fixed denomination (PoC):** the testnet coinbase emits a single fixed amount
  (`PQ_TESTNET_COINBASE_AMOUNT = 100000`). Until variable PQ amounts/change exist, the
  wallet can only spend whole fixed-denomination outputs and must select enough of them;
  change goes to a fresh PQ output of the same denomination (or a legacy `KeyOutput`
  remainder, as the coinbase already does). Document the denomination model as a known
  limitation.

### 6.1 Thin Rust helper ABI (recommended)

To keep C++ free of crypto detail, add (in `pqc/ccx-pqc`) a few **deterministic**
account-level entry points the wallet calls, wrapping existing primitives:

- `ccx_pq_kem_keygen_det(seed32, pk_out, sk_out)` — **the missing deterministic KEM
  keygen (§3.2); blocking dependency.**
- `ccx_pq_account_from_seed(master32, kem_pk_out, kem_sk_out, scheme_ids_out)` —
  one call to derive the whole PQ account.
- (scan/sign/nullifier already exist and are reused unchanged.)

Everything else (`ccx_pq_kem_scan`, `ccx_pq_keygen`, `ccx_pq_sign`,
`ccx_pq_nullifier`, `ccx_pq_kem_derive_output`) is already in `lib.rs` and reused as-is.

---

## 7. Concrete file/step plan

| Step | File(s) | Change |
|------|---------|--------|
| 1 | `pqc/ccx-pqc/src/lib.rs` | Add `ccx_pq_kem_keygen_det` (deterministic ML-KEM keygen) + `ccx_pq_account_from_seed`; verify the KEM crate supports seed-based keygen, swap crate if not. **(blocking)** |
| 2 | `src/CryptoNoteConfig.h` | Add `CRYPTONOTE_PUBLIC_PQ_/HYBRID_ADDRESS_BASE58_PREFIX` (+ `TESTNET_*`); document numeric→string tuning. |
| 3 | `include/CryptoNote.h` | Add `PqAccountPublicAddress` struct. |
| 4 | `src/CryptoNoteCore/CryptoNoteSerialization.{h,cpp}` | `serialize(PqAccountPublicAddress&, …)` mirroring `PqKeyOutput` (serializeAsBinary for KEM PK). |
| 5 | `src/CryptoNoteCore/CryptoNoteBasicImpl.{h,cpp}` | `getPqAccountAddressAsStr` / `parsePqAccountAddressString` (+ length/scheme validation); a prefix dispatcher. Leave legacy fns untouched. |
| 6 | `src/CryptoNoteCore/Account.{h,cpp}` | Extend `AccountBase` (or a new `PqAccountBase`) to hold KEM keypair + scheme ids; `generatePqFromSeed(master32)`. |
| 7 | `src/Mnemonics/*` | No format change; add a helper that returns the 32-byte master seed (already implicit in `mnemonicToPrivateKey`) for PQ derivation. |
| 8 | `src/Wallet/WalletGreen.{h,cpp}` + `WalletSerializationV2.*` | Versioned encrypted PQ section (master32, KEM SK/PK, scheme ids, spendable-PQ-output cache); bump cache version. |
| 9 | `src/Wallet/WalletGreen.cpp` (sync path) | PQ output scanning (§5): per `PqKeyOutput`, `kem_scan→keygen→compare`, record spendable. |
| 10 | `src/Wallet/WalletGreen.cpp` | `createPqTransaction` (§6): ring select, sign, nullifier, build v3 tx; replace `pq_injector`. |
| 11 | `src/Rpc/*` (testnet-gated) | `get_pq_outputs` RPC: list `m_pqOutputs[amount]` entries {globalIndex, key, kemCt, height} for ring selection + scanning. |
| 12 | `src/ConcealWallet/*` | CLI: `pq_address`, `pq_balance`, `pq_transfer`; show hybrid/PQ address. |
| 13 | `pqc/tools/pq_injector.cpp` | Demote to a test fixture / delete once wallet path works. |

Suggested ordering: **1 → 2-5 (address) → 6-8 (keygen+storage) → 11 (RPC) → 9 (scan)
→ 10 (spend) → 12 → 13.** Address + keygen are independent of consensus and safe to
land first.

---

## 8. Risks

1. **Deterministic ML-KEM keygen is unbuilt and load-bearing.** Without it, mnemonic
   recovery of the KEM key is impossible (POC uses RNG `kyber768::keypair()`). Must
   confirm a FIPS-203 seed-keygen path in the chosen crate (`ml-kem`/`libcrux`/`fips203`)
   or the whole "restore from words" UX fails. *Highest risk.*
2. **Address size / UX.** A 1184-byte (PQ) or 1248-byte (hybrid) payload Base58-encodes
   to ~1.6k characters — far longer than a 95-char legacy address. QR codes get dense;
   copy/paste is fine. Consider an integrated-address-style short alias or a versioned
   compression later. Not a blocker; flag for product.
3. **`msg` binding mismatch (consensus).** If the wallet signs a different message than
   `check_pq_tx_input` verifies, every spend is silently rejected; if too loose, txs are
   malleable. Must be derived from the real daemon code, not the injector, and tested
   round-trip.
4. **Single KEM key conflates detect + spend** — no clean legacy-style view-only PQ
   wallet; tracking wallets can't recognise outputs without an extra detect tag. Scope
   limitation, document it.
5. **Wallet file compatibility.** New PQ section + version bump means PQ wallets won't
   open in old builds and vice-versa; rekey/password-change must re-encrypt the PQ
   section through the existing IV chain or funds become unrecoverable. Test
   save→load→rekey→load.
6. **Scheme-agility churn.** Pinning `kemSchemeId`/`ringSchemeId` in the address is
   correct, but when CIP C1 recalibrates the ring sig (new `0xC0DE_xxxx`), all PQ-only
   addresses minted against the old ring scheme are conceptually fine (ring key isn't in
   the address) — but any *outputs/spends* are not; ensure the agility story is
   "address survives, spend rules height-gate." Document.
7. **Consensus blast radius.** New address types touch `CryptoNoteConfig.h`,
   serialization, RPC. Keep strictly testnet-gated; no mainnet prefix until the ring sig
   is audited. The address format itself can stabilise earlier than the crypto (it's
   just an envelope), which is the point of the `pqVersion`/`schemeId` fields.
8. **Performance of per-output scan.** `kem_scan + lattice keygen` per PQ output during
   sync may be heavy on large chains; add the 8-byte detect-tag pre-filter (§5) if WSL
   measurements show it. Measure before optimising.

---

## 9. Test plan

**Rust (`pqc/ccx-pqc`, `cargo test` / selftests):**
- `ccx_pq_kem_keygen_det(seed)` is deterministic: same seed → identical PK/SK across
  calls and processes; different seed → different keys.
- `ccx_pq_account_from_seed` round-trips: derive → `kem_derive_output` → `kem_scan` →
  `keygen` → recovered `otPk` matches (extends existing `ccx_pq_kem_stealth_selftest`).
- master-seed derivation domain-separation: KEM seed ≠ legacy spend seed ≠ ringacct seed.

**C++ unit tests (gtest, `-DBUILD_TESTS=ON`):**
- Address round-trip: `getPqAccountAddressAsStr` → `parsePqAccountAddressString` returns
  the same struct; corrupt 1 char ⇒ checksum/decode fails; wrong prefix ⇒ routed away;
  wrong `kemPublicKey.size()`/`schemeId` ⇒ rejected.
- Hybrid address carries+restores legacy spend/view AND KEM PK; PQ-only omits EC.
- Mnemonic→account: words → master32 → KEM keypair; same words reproduce the same KEM
  PK (recovery). Upgrading a legacy seed yields a stable hybrid address.
- Wallet storage: create PQ wallet → save → load → keys identical → spendable-output
  cache intact; password change re-encrypts PQ section and reloads.

**Integration (WSL 2-node testnet, `pqc/run-poc-testnet.sh`):**
- Mine coinbase PQ outputs to a *wallet-derived* KEM key (replace the hardcoded
  `pq_testnet_kem_keypair.h` with the wallet's address in the coinbase recipient path).
- Wallet **scans** the chain and reports the correct PQ balance (matches what the
  injector found).
- Wallet **builds+signs** a PQ spend via `createPqTransaction`; daemon accepts it
  (parity with `pq_injector`'s accepted ring-of-4 spend).
- Double-spend: second tx reusing the nullifier rejected by mempool + chain
  (re-confirm the PoC's three rejection paths still hold from the wallet).
- Negative: spend an immature output ⇒ wallet refuses / daemon rejects (unlock window).
- **A/B parity test:** for the same coinbase set, wallet-produced `PqKeyInput` bytes are
  consensus-equivalent to injector-produced ones (both accepted) — the regression gate
  for retiring `pq_injector`.

**Measurement (WSL):** time per-output scan (kem_scan + keygen) over N outputs; ring-of-4
spend build time; wallet save/load time with the larger PQ section. Decide whether the
detect-tag pre-filter is needed.

---

## 10. Summary

The wallet v2 design carries the **ML-KEM-768 public key** (not the 4096-byte ring key)
as the PQ component of a new Base58 address, behind new `ccxpq`/`ccxh` prefixes, encoded
with the **existing** `encode_addr` machinery + a `pqVersion`/`schemeId` envelope for
crypto-agility. All PQ key material derives deterministically from the **same 25-word
mnemonic** users already have, stored in a new versioned encrypted section of the
`WalletGreen` container. Scanning and spending reuse the already-working
`ccx_pq_kem_scan / keygen / sign / nullifier` ABI — the four jobs `pq_injector` does
today — moved into the wallet sync + transaction paths. The one genuinely new crypto
dependency is **deterministic ML-KEM keygen** (the PoC's KEM keygen is RNG-based); the
one most safety-critical detail is **matching the daemon's `check_pq_tx_input` message
binding** exactly. Everything stays testnet-gated until the ring signature is audited.
