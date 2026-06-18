// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Deterministic PQ wallet account (CIP-0001 wallet-address-v2 §3).
//
// One 25-word mnemonic = one 32-byte master seed (the legacy spend secret). All PQ key material is
// derived DETERMINISTICALLY from it via domain-separated hashing, so the SAME mnemonic always
// reproduces the SAME PQ keys — mnemonic-restorable, exactly like the legacy spend/view keys.
//
// This is the money-critical determinism surface: if the derivation is not reproducible, PQ funds
// are unrecoverable from the seed phrase. The reproducibility is asserted by unit tests.

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "CryptoNote.h"

namespace cn
{
  // A derived PQ account: the long-term ML-KEM keypair (the address-bearing "detect/receive" key)
  // plus the scheme pins. The 4096-byte ring-sig key is per-output/derived and is NOT here.
  struct PqAccountKeys
  {
    std::vector<uint8_t> kemPublicKey;  // ML-KEM-768 PK (PQ_KEM_PUBLIC_KEY_SIZE)
    std::vector<uint8_t> kemSecretKey;  // ML-KEM-768 SK (kept encrypted in the wallet; needed to scan)
    uint32_t kemSchemeId;
    uint32_t ringSchemeId;
  };

  class PqAccount
  {
  public:
    // Derive the 32-byte PQ KEM seed from the 32-byte master seed via a domain-separated hash
    // (cn_fast_hash of "ccx-pq-kem-acct" || master). Deterministic and domain-separated from the
    // legacy spend/view derivation so the KEM seed != the spend seed.
    static crypto::Hash deriveKemSeed(const crypto::SecretKey &masterSeed);

    // Derive the full PQ account (ML-KEM keypair + scheme ids) from the master seed by calling the
    // deterministic keygen FFI. Throws std::runtime_error on FFI failure. Deterministic: same master
    // seed -> identical PqAccountKeys.
    static PqAccountKeys generateFromSeed(const crypto::SecretKey &masterSeed);

    // Build a PQ-only (non-hybrid) public address struct from derived keys.
    static PqAccountPublicAddress toPublicAddress(const PqAccountKeys &keys);

    // Build a hybrid public address struct: PQ KEM key + the legacy Ed25519 spend/view public keys.
    static PqAccountPublicAddress toHybridPublicAddress(const PqAccountKeys &keys,
                                                        const crypto::PublicKey &legacySpend,
                                                        const crypto::PublicKey &legacyView);
  };
} // namespace cn
