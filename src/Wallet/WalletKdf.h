// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Wallet-file at-rest key derivation + AEAD (CIP-0001 Q2 §1b — crypto modernization).
//
// The legacy WalletGreen container derives its chacha8 key from a SINGLE UNSALTED pass of
// cn_slow_hash_v0 over the raw password (crypto/chacha8.h:generate_chacha8_key) and encrypts the
// container with unauthenticated 8-round chacha8. This module replaces BOTH for the new wallet
// format (container version 7):
//   * Argon2id (RFC 9106) for password -> 32-byte key, with a random per-wallet salt and tunable
//     memory/time/parallelism cost stored in a versioned header inside the container prefix; and
//   * XChaCha20-Poly1305 AEAD for the container suffix (24-byte random nonce, 16-byte Poly1305 tag),
//     so a corrupted/tampered/wrong-password container is DETECTED rather than decrypting to garbage.
//
// CLIENT-SIDE ONLY: the wallet file never touches consensus. The crypto comes from the audited
// RustCrypto crates via the ccx-pqc C ABI (ccx_wallet_*), the same module the PQ message AEAD uses.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "crypto/chacha8.h"

namespace cn
{
  // Versioned KDF header stored (fixed-size, packed) inside the wallet container prefix for the
  // Argon2id format. `magic` distinguishes a real header from zero/garbage; `kdfVersion` allows
  // future KDF changes; salt + cost params are everything needed to reproduce the key from the
  // password. 16-byte salt is the RFC 9106 recommendation; the cost params are tunable so the bar
  // can be raised as hardware improves without changing the format.
  // The three Argon2 cost fields are stored as explicit LITTLE-ENDIAN 4-byte arrays (not native
  // uint32) so the wallet file is byte-identical across platforms (the header is written/read by raw
  // copy). Use cost*Value()/setCost*() to access them as host integers.
#pragma pack(push, 1)
  struct WalletKdfHeader
  {
    uint8_t magic[4];        // 'C','K','D','F'
    uint8_t kdfVersion;      // = 1 (Argon2id)
    uint8_t reserved[3];     // padding / future flags (must be zero)
    uint8_t salt[16];        // random per-wallet Argon2 salt (CSPRNG)
    uint8_t memKibLe[4];     // Argon2 memory cost (KiB), little-endian
    uint8_t iterationsLe[4]; // Argon2 time cost (passes), little-endian
    uint8_t parallelismLe[4];// Argon2 lanes, little-endian
  };
#pragma pack(pop)

  static const uint8_t WALLET_KDF_VERSION_ARGON2ID = 1;

  // Default Argon2id cost. 64 MiB / 3 passes / 1 lane is a conservative interactive-login profile
  // (RFC 9106 "second recommended option" is 64 MiB, t=3). Stored per wallet so it can be raised
  // later; older wallets keep whatever cost they were created with until re-saved.
  static const uint32_t WALLET_KDF_DEFAULT_MEM_KIB = 64u * 1024u; // 64 MiB
  static const uint32_t WALLET_KDF_DEFAULT_ITERATIONS = 3u;
  static const uint32_t WALLET_KDF_DEFAULT_PARALLELISM = 1u;

  // Cost-parameter bounds enforced on EVERY header (including ones read from disk) so an
  // attacker-supplied header cannot DoS-on-open (memKib=4 GiB / iterations=2^31) nor near-disable the
  // KDF (memKib=8 / iterations=1). Argon2 also requires memKib >= 8*parallelism.
  static const uint32_t WALLET_KDF_MIN_MEM_KIB = 8u * 1024u;       // 8 MiB floor
  static const uint32_t WALLET_KDF_MAX_MEM_KIB = 1024u * 1024u;    // 1 GiB ceiling
  static const uint32_t WALLET_KDF_MIN_ITERATIONS = 1u;
  static const uint32_t WALLET_KDF_MAX_ITERATIONS = 32u;
  static const uint32_t WALLET_KDF_MIN_PARALLELISM = 1u;
  static const uint32_t WALLET_KDF_MAX_PARALLELISM = 16u;

  class WalletKdf
  {
  public:
    // Little-endian accessors for the cost fields (the on-disk encoding is canonical LE).
    static uint32_t memKib(const WalletKdfHeader &header);
    static uint32_t iterations(const WalletKdfHeader &header);
    static uint32_t parallelism(const WalletKdfHeader &header);

    // True iff `header` carries the Argon2id magic + a supported kdfVersion AND its cost parameters
    // are within the enforced [min,max] bounds (so a corrupt/hostile on-disk header is rejected
    // before it can DoS or weaken the KDF). Used to tell a v7 (Argon2id) container apart from a
    // zero-initialised / legacy prefix and to validate cost params read from disk.
    static bool isValidHeader(const WalletKdfHeader &header);

    // Fill `header` with the magic, version, default cost params and a fresh CSPRNG salt.
    static WalletKdfHeader makeHeader();

    // Derive the 32-byte container key from (password, header). Throws std::runtime_error on any
    // FFI failure (bad params, FFI unavailable) — the wallet must never proceed with a half-derived
    // key. Deterministic in (password, salt, cost) so the same wallet + password always reopens.
    static crypto::chacha8_key deriveKey(const std::string &password, const WalletKdfHeader &header);

    // XChaCha20-Poly1305 nonce length (24) for the container suffix.
    static size_t nonceBytes();
    // Poly1305 tag length (16); sealed length is plaintext + this.
    static size_t tagBytes();

    // Seal `plaintext` under `key` + `nonce`. Returns ciphertext||tag. Throws on FFI failure.
    static std::vector<uint8_t> aeadSeal(const crypto::chacha8_key &key,
                                         const std::vector<uint8_t> &nonce,
                                         const uint8_t *plaintext, size_t plaintextSize);

    // Open a sealed blob. Returns true and fills `plaintext` on a verified tag; returns false on ANY
    // authentication failure (wrong password, tamper, truncation) WITHOUT exposing plaintext.
    static bool aeadOpen(const crypto::chacha8_key &key,
                         const std::vector<uint8_t> &nonce,
                         const uint8_t *sealed, size_t sealedSize,
                         std::vector<uint8_t> &plaintext);

    // Draw a fresh random AEAD nonce (24 bytes).
    static std::vector<uint8_t> randomNonce();

    // Keyed-MAC tag length (32) for the v8 wallet-file prefix authentication.
    static size_t prefixMacBytes();

    // Compute the 32-byte keyed MAC over the container `prefix` bytes under the Argon2id container
    // `key` (v8 wallet-file format, hardening item W11). The MAC key is domain-separated from the
    // AEAD encryption use of `key`, so it is independent of the encryption key. Throws on FFI
    // failure. The caller stores the tag inside the AEAD-sealed suffix and re-verifies it on open;
    // a prefix tamper/rollback (which the suffix AEAD cannot see) is then detected.
    static std::vector<uint8_t> prefixMac(const crypto::chacha8_key &key,
                                          const uint8_t *prefix, size_t prefixSize);
  };
} // namespace cn
