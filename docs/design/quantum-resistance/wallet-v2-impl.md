# Wallet v2 — Implementation Report

Status: **IN PROGRESS** on the wallet worktree (branched from `pqc/testnet-poc`).
Scope: the two wallet-layer tasks from the wallet-v2 brief —
(1) wallet-file at-rest encryption modernization (Argon2id + XChaCha20-Poly1305), and
(2) the PQ wallet/address-v2 work that retires `pq_injector`.

This file records **what was built, how it is wired, the proofs, and what remains**.

---

## Task 1 — Wallet-file at-rest encryption (Argon2id + XChaCha20-Poly1305) — DONE

### Problem (from `strategy-crypto-modernization.md` §1b, the #1 value-to-risk item)

The WalletGreen container was encrypted with **chacha8** (8-round, *unauthenticated*) keyed by a
**single unsalted pass of `cn_slow_hash_v0`** over the raw password
(`crypto/chacha8.h:generate_chacha8_key`). Weaknesses: no salt (identical passwords → identical
keys, rainbow-table-feasible), no tunable cost, a PoW hash repurposed as a password KDF, and no
integrity (a corrupted/tampered file decrypts to garbage with no signal). All client-side — no
consensus, no fork.

### What was built

**New container format version 7** (`WalletSerializationV2.h`: `SERIALIZATION_VERSION = 7`,
`AEAD_KDF_VERSION = 7`, `MIN_VERSION` stays 6 so v6 wallets still open):

- **KDF → Argon2id** (RFC 9106) with a random 16-byte per-wallet salt and tunable
  memory/time/parallelism cost (default 64 MiB / 3 passes / 1 lane), all stored in a versioned
  `WalletKdfHeader` (`src/Wallet/WalletKdf.h`).
- **Cipher → XChaCha20-Poly1305 AEAD** for the container suffix: a fresh random 24-byte nonce per
  save (XChaCha's 192-bit nonce makes random selection collision-safe) and a 16-byte Poly1305 tag,
  so wrong-password / tamper / truncation are **detected** (open returns nothing, no plaintext leak).

**Crypto source.** Implemented in the existing `ccx-pqc` Rust module (the same audited RustCrypto
family the PQ 0x06 message AEAD already uses), not hand-rolled in C++11:
- `pqc/ccx-pqc/src/walletcrypto.rs` — `argon2id_derive`, `aead_seal`, `aead_open` (+ Rust unit
  tests). Uses crates `argon2 = 0.5` and `chacha20poly1305 = 0.10` (XChaCha20Poly1305).
- `pqc/ccx-pqc/src/lib.rs` — panic-guarded C ABI shims: `ccx_wallet_kdf_argon2id`,
  `ccx_wallet_aead_seal`, `ccx_wallet_aead_open`, size getters, and `ccx_wallet_crypto_selftest`.
- `pqc/include/pq_ring_sig.h` — C declarations for the above.

**Justification for the Rust path (lower risk):** Argon2id and XChaCha20-Poly1305 are non-trivial to
implement correctly; the RustCrypto `argon2`/`chacha20poly1305` crates are vetted and already linked
into the build. The alternative (a C++/Boost Argon2id) would mean hand-integrating an unvetted C
Argon2 and a separate XChaCha20 — strictly more new attack surface for a funds-at-rest primitive.
The brief explicitly allowed either; the Rust helper is the lower-risk option.

**C++ wiring (`src/Wallet/WalletKdf.{h,cpp}`, `src/Wallet/WalletGreen.{h,cpp}`):**
- `WalletKdf` — thin C++ wrapper over the FFI: `makeHeader`, `isValidHeader`, `deriveKey`,
  `aeadSeal`, `aeadOpen`, `randomNonce`. Throws on FFI failure (never proceeds with a half key).
- `WalletGreen`:
  - `m_walletFormatVersion` + `m_kdfHeader` track the open wallet's format.
  - `deriveContainerKey(password, version)` — Argon2id for v7, legacy `cn_slow_hash_v0` for ≤v6.
  - `encryptAndSaveContainerData` / `loadAndDecryptContainerData` now branch on the version: AEAD
    (header || nonce || sealed) for v7, legacy chacha8+IV for ≤v6.
  - `initWithKeys` / `convertAndLoadWalletFile` create **v7** wallets (fresh header, Argon2id key).
  - **Migrate-on-save:** `migrateToAeadFormatIfNeeded()` (called from `save()`) re-keys a loaded v6
    wallet's prefix + spend records onto a fresh Argon2id key and bumps the version to 7 — transparent,
    no data loss (load-only legacy support + migrate-on-open-then-save).
  - `changePassword` migrates-then-rekeys with a **fresh salt**, re-encrypting the whole AEAD suffix
    (so every at-rest secret, including any future PQ section in the container cache, is re-sealed).
  - `exportWallet` migrates first; both encrypted and unencrypted exports are written as v7.

**Backward compatibility.** The on-disk `ContainerStoragePrefix` struct is **unchanged in size**, so
the FileMappedVector open path is untouched. The version byte (offset 0) selects the KDF/cipher; the
KDF header lives at the start of the (always-present) v7 suffix and is read before the key is derived.
v6 wallets load via the legacy path and upgrade to v7 on their next save.

### Tests (`tests/UnitTests/TestWalletKdf.cpp`, runs under `ctest -R UnitTests`)

- Argon2id determinism (same pw+header → same key), salt-sensitivity, password-sensitivity.
- KDF header: `makeHeader` valid + defaults; salt random per call; zero/garbage header rejected;
  `deriveKey` throws on an invalid header.
- AEAD: round-trip; **wrong password fails** (auth, no plaintext); **full-byte tamper sweep** all
  detected; wrong nonce fails; truncation fails; empty-plaintext round-trip.
- Container-level analogue of the wallet's seal/open: **new-format round-trip**, **wrong-password
  fails**, **tamper detected**.
- `ccx_wallet_crypto_selftest()` (the Rust selftest through the C ABI) returns ok=1.
- Rust-side (`cargo test`): `walletcrypto::tests` — determinism+salt, AEAD round-trip+tamper, bogus
  params rejected. (3/3 passing — see proofs below.)

---

## Task 2 — PQ wallet / address v2 (retire pq_injector) — see status at end

### DONE (built + unit-tested)

**(a) PQ address format v2.** New Base58 prefixes carrying the 1184-byte ML-KEM-768 public key (NOT
the 4096-byte ring-sig key — per-output/derived):
- `cn::CRYPTONOTE_PUBLIC_PQ_ADDRESS_BASE58_PREFIX = 0x14fad4` → `ccxp…`
- `cn::CRYPTONOTE_PUBLIC_HYBRID_ADDRESS_BASE58_PREFIX = 0x117ad4` → `ccxh…`
- `cn::TESTNET_PUBLIC_PQ_ADDRESS_BASE58_PREFIX = 0x220bd6` → `ctp…`
- `cn::TESTNET_PUBLIC_HYBRID_ADDRESS_BASE58_PREFIX = 0x164a56` → `cth…`
- `cn::PQ_KEM_PUBLIC_KEY_SIZE = 1184`, `cn::PQ_ADDRESS_VERSION = 2`, `cn::PQ_KEM_SCHEME_ID = 0xC0DE0203`.
Tags brute-forced (replicating `encode_addr`) so the first 4 human chars are stable across the flags
byte, the way `0x7ad4`→`ccx7` was tuned. `PqAccountPublicAddress` struct (`include/CryptoNote.h`) +
canonical `ISerializer` serialization (legacy Ed25519 keys always written, zero when PQ-only — exactly
one valid encoding). `getPqAccountAddressAsStr` / `parsePqAccountAddressString`
(`CryptoNoteBasicImpl.{h,cpp}`) reuse the existing `encode_addr`/`decode_addr` (varint tag + payload +
4-byte cn_fast_hash checksum); parse validates version + both schemeIds + KEM-key length + reserved
flag bits + (hybrid) on-curve legacy keys. Legacy `AccountPublicAddress` path untouched.

**(b) Deterministic PQ key derivation from the mnemonic.** `PqAccount` (`src/Wallet/PqAccount.{h,cpp}`)
derives the KEM seed via domain-separated `cn_fast_hash("ccx-pq-kem-acct" || master32)` and calls
`ccx_pq_kem_keygen_det`. Same master seed → identical KEM keypair (mnemonic-restorable). The KEM seed
is domain-separated from the master seed. **`ccx_pq_kem_keygen_det` / `ccx_pq_multisig_keygen_det` are
declared in `pq_ring_sig.h` and coded against; the ccx-pqc impls are DETERMINISTIC PLACEHOLDERS (SHAKE
expand) — a MERGE DEPENDENCY** flagged for the Rust-crypto agent's real FIPS-203/204 seed keygen with
the same C ABI. Tests assert determinism + sizes + round-trip, never specific bytes.

**(c) Encrypted PQ section in the WalletGreen container.** The PQ account (KEM PK/SK + scheme ids) is
serialized by `WalletGreen::savePqSection`/`loadPqSection` **inside** the AEAD-encrypted v7 container
(appended after the `WalletSerializerV2` stream, guarded by a presence byte). Because it rides inside
the AEAD suffix, it is automatically re-encrypted on `changePassword`/rekey (Task-1 path) — satisfying
"wallet rekey MUST re-encrypt the PQ section". On load, sizes are re-validated against the compiled-in
KEM. Public API: `enablePqAccount(masterSeed)` (migrates to v7, derives + stores), `getPqAddress`,
`getPqHybridAddress`, `hasPqAccount`, `getPqAccountKeys`.

Tests (`tests/UnitTests/TestPqWalletAddress.cpp`): 13 address+keygen cases + 2 PQ-section round-trip
cases — address round-trip / corrupt / wrong-prefix / wrong-size / wrong-scheme / wrong-version /
reserved-flag / stray-legacy-key rejection; hybrid; mnemonic→key reproducibility; domain separation;
seed→address round-trip; PQ-section save/load preserves keys; absent-section round-trip.

### DEFERRED (flagged for follow-up / merge)

1. **Real deterministic KEM/DSA keygen** — the `ccx_pq_*_keygen_det` placeholders must be replaced by
   the Rust-crypto agent's FIPS-203/204 seed keygen, byte-compatible with the daemon's on-chain KEM
   (`pqcrypto-kyber` encap in `ccx_pq_kem_derive_output`). Mixing crates would break daemon interop and
   lose funds — deliberately NOT done unilaterally here.
2. **PQ stealth-output scanning in the wallet sync path** (`ccx_pq_kem_scan → ccx_pq_keygen → compare
   to on-chain key`). Needs the `TransfersSynchronizer` integration + the `get_pq_outputs` RPC; not
   wired yet.
3. **`createPqTransaction` (retire `pq_injector`).** The signed message MUST byte-match
   `Blockchain::getTransactionPqSigningHash` = `getObjectHash(prefix)` with every `PqKeyInput.ringSig`
   cleared (Blockchain.cpp:2536-2557). Verified against the daemon source; the wallet builder + A/B
   parity test (wallet-built `PqKeyInput` ≡ injector-built) require a live testnet and are deferred.
4. **Testnet `get_pq_outputs` RPC** (amount → [{global_index, key, kemCt, height}]) — not added.
5. **CLI `pq_address` / `pq_balance` / `pq_transfer`** in `ConcealWallet` — not added.
6. **Message send-path 0x04 → authenticated 0x07** migration (secondary item) — not done; the
   serializer agent's `tx_extra_authenticated_message` (0x07) + `append_authenticated_message_to_extra`
   exist; wiring `WalletGreen`/`CryptoNoteFormatUtils` to emit 0x07 (0x04 stays read-only) is left as a
   merge wiring item.

---

## MERGE NOTES — shared-core files touched (reconcile against crypto + serializer branches)

| File | What this branch added |
|------|------------------------|
| `pqc/ccx-pqc/src/lib.rs` | `ccx_pq_kem_keygen_det` / `ccx_pq_multisig_keygen_det` (DETERMINISTIC PLACEHOLDERS — delete + bind to the real `detkeygen.rs` impls at merge); the wallet-file `ccx_wallet_*` (Argon2id + XChaCha20-Poly1305) FFI; `mod walletcrypto`. Keep the "PLACEHOLDER / MERGE DEPENDENCY" banner. |
| `pqc/ccx-pqc/src/walletcrypto.rs` | New module: Argon2id + XChaCha20-Poly1305 (Task 1). No conflict expected. |
| `pqc/ccx-pqc/Cargo.toml` | Added `argon2 = "0.5"`. |
| `pqc/include/pq_ring_sig.h` | Declared `ccx_pq_kem_keygen_det` / `ccx_pq_multisig_keygen_det` (delete at merge if the real decls live elsewhere) + the `ccx_wallet_*` block + `ccx_wallet_crypto_selftest`. |
| `src/CryptoNoteConfig.h` | Added (in `namespace cn`, beside `PQ_NULLIFIER_SIZE`): the 4 PQ/hybrid Base58 prefixes (main+testnet), `PQ_KEM_PUBLIC_KEY_SIZE`, `PQ_ADDRESS_VERSION`, `PQ_KEM_SCHEME_ID`. Consensus-adjacent constants — confirm the `PQ_KEM_SCHEME_ID` / prefix values don't collide with the crypto/deposits branches. |
| `include/CryptoNote.h` | Added `PqAccountPublicAddress` struct. |
| `src/CryptoNoteCore/CryptoNoteSerialization.{h,cpp}` | Added `serialize(PqAccountPublicAddress&, …)`. New overload only — no change to existing serializers. |
| `src/CryptoNoteCore/CryptoNoteBasicImpl.{h,cpp}` | Added `getPqAccountAddressAsStr` / `parsePqAccountAddressString` + `#include "CryptoNoteConfig.h"`. Legacy fns untouched. |

Wallet-layer-only files (no cross-branch reconciliation): `src/Wallet/WalletKdf.{h,cpp}`,
`src/Wallet/PqAccount.{h,cpp}`, `src/Wallet/WalletGreen.{h,cpp}`, `src/Wallet/WalletSerializationV2.h`,
`tests/UnitTests/TestWalletKdf.cpp`, `tests/UnitTests/TestPqWalletAddress.cpp`.

---

## Build & proof log

Built on the WSL x86_64 host (`~/conceal-core-wallet`): `cargo test` (walletcrypto 3/3),
`ccx_pqc` + `CryptoNoteCore` + `Wallet` + `UnitTests`. Unit tests: `TestWalletKdf` 17/17,
`TestPqWalletAddress` (PqAddress 9 + PqAccountKeygen 4 + PqWalletSection 2). See the final report for
full `ctest` output and the determinism proof.

---

## Security-review fixes (W1–W11, four-reviewer convergence)

Four independent reviews (Codex, Gemini, GLM, CodeRabbit) ran against this branch. Resolution:

| # | Issue | Status |
|---|-------|--------|
| **W1** | Salt+nonce came from `Randomize::randomBytes` = `std::mt19937` seeded by 32 bits → cross-wallet salt+nonce collision = XChaCha20 nonce reuse. | **FIXED.** New `ccx_wallet_random_bytes` FFI (rand_core `OsRng`); `WalletKdf::makeHeader`/`randomNonce` use it. mt19937 no longer touches any key/salt/nonce. |
| **W2** | v7 load auth failure (wrong password / corruption) was caught → caches cleared → next save overwrote the authenticated ciphertext, destroying keys. Same for `loadPqSection`. | **FIXED.** For version ≥ 7, load failures rethrow (abort load); the PQ-section read no longer swallows (the `endOfStream()` guard still skips the legitimate "no PQ section" case). |
| **W3** | v7 `save()` did `resizeSuffix`+copy into the live mmap with no atomic rename → crash = unrecoverable tag mismatch. | **FIXED.** The plain `save()` v7 path now runs inside `ContainerStorage::atomicUpdate` (temp file → `msync`+`fsync` on flush → rename), republishing prefix+keys+new-suffix as one unit. (`changePassword`/`migrate` already wrote inside `atomicUpdate`.) |
| **W4** | `parsePqAccountAddressString` fed unbounded input to the base58 decoder before any size check. | **FIXED.** Reject `str.empty()` or `str.size() > 2048` before `decode_addr`. |
| **W5** | `readKdfHeader` accepted attacker-supplied `memKib`/`iterations`/`parallelism` unchecked (DoS-on-open or near-free KDF). | **FIXED.** `WalletKdf::isValidHeader` now enforces `[min,max]` on all three (8 MiB–1 GiB, 1–32 iters, 1–16 lanes, `memKib ≥ 8·parallelism`); validated on every parse+derive. |
| **W6** | `changePassword` gated the re-seal on `suffixSize()>0`; a v7 wallet with no suffix would never persist the new KDF salt → brick. | **FIXED.** For version ≥ 7, `changePassword` always writes a sealed suffix (even empty). `migrateToAeadFormatIfNeeded` already did. |
| **W7** | Only `kemSchemeId` was validated; `ringSchemeId` was not (despite the comment). | **FIXED.** Added `PQ_RING_SCHEME_ID = 0xC0DE0003` and validate `adr.ringSchemeId` in parse. |
| **W8** | `WalletKdfHeader` cost fields were native-endian uint32 → platform-endian wallet file. | **FIXED.** Cost fields are now explicit little-endian `uint8_t[4]` with `putLe32`/`getLe32`; on-disk format is endian-independent. |
| **W9** | Old password-derived key not wiped after `changePassword`. | **FIXED.** `secureZero` (volatile store) wipes `m_key` before reassignment. (Best-effort; not mlock-hardened.) |
| **W10** | CR claimed `pq_ring_sig.h` declares `ccx_pq_wallet_crypto_selftest` but Rust exports `ccx_wallet_crypto_selftest`. | **NO-OP (false positive).** Verified: header and Rust both use `ccx_wallet_crypto_selftest`; the names already match. |
| **W11** | The wallet PREFIX (view keys + per-wallet spend records) is still **unauthenticated chacha8** even in v7 — only the suffix container is AEAD. | **DOCUMENTED (deferred, by reviewer's instruction).** See below. |

### W3 residual note (atomicity)

The v7 `save()`, `changePassword`, and `migrateToAeadFormatIfNeeded` paths now all write through
`atomicUpdate` (durable temp-file + rename), so an interrupted write leaves the previous good file
intact. The legacy (≤v6) `save()` path is unchanged (it was never AEAD, so a torn write was already
recoverable by re-sync). No known brick-on-crash remains for v7.

### W11 — known v7 limitation: the container PREFIX is not authenticated

In v7 the **suffix** (the serialized cache + PQ section) is XChaCha20-Poly1305 AEAD, but the
**prefix** — `ContainerStoragePrefix` = `{version, nextIv, encryptedViewKeys}` plus the per-wallet
`EncryptedWalletRecord` spend keys — is still **8-round chacha8 keyed by the Argon2id key, with no
MAC**. Consequence: an attacker with write access to the wallet file can **tamper or roll back the
prefix** (e.g. swap in old/forged encrypted view/spend key records) and it will **not be detected**
by an authentication tag; detection relies only on the downstream `throwIfKeysMissmatch`
(pub/priv consistency) check, which catches random corruption but not a structurally-valid
substitution. The salt/cost header lives in the AEAD suffix and IS authenticated, but the prefix key
material is not.

**Why deferred:** authenticating the prefix means either (a) moving the view/spend key records out of
the fixed-size `EncryptedWalletRecord` mmap prefix into the AEAD suffix (a larger container-format
change + migration), or (b) adding a separate prefix MAC field — both change the on-disk layout that
the `FileMappedVector` open path depends on. Recommended follow-up: in a v8 format, AEAD-wrap the
entire container (prefix + suffix) under the Argon2id key with a single tag, or store an HMAC of the
prefix in the authenticated suffix and verify it on open before trusting any prefix key. Until then,
treat the wallet file as confidential-and-integrity-protected **for the cache** but only
confidential **for the prefix keys** (rollback/tamper of the prefix is undetectable).
