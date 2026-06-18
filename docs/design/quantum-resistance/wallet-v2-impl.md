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

(Filled in as Task 2 lands.)

---

## Build & proof log

(See the final report / ctest output. Rust `cargo test` walletcrypto: 3 passed. C++ build of
`ccx_pqc` + `Wallet` + `UnitTests` on the WSL x86_64 host.)
