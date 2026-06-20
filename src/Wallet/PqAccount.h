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
  //
  // The ML-DSA-65 keypair (dsaPublicKey/dsaSecretKey) is the account-level PQ deposit signing key
  // (CIP-0001 UPGRADE_HEIGHT_V9). Under the v1 single-key design (D1) every PqMultisigOutput deposit
  // this wallet creates names this ONE dsaPublicKey, and a withdrawal is signed by dsaSecretKey. The
  // wallet recognizes its own deposits by matching the on-chain output key against dsaPublicKey (a
  // named-key match, not a stealth scan). Deterministic from the master seed, so it is fully
  // mnemonic-restorable with zero per-deposit state. (Privacy note: deposits to the same wallet share
  // this key and are therefore linkable — acceptable for the testnet PoC; per-deposit indexed keys
  // are deferred to D2.)
  struct PqAccountKeys
  {
    std::vector<uint8_t> kemPublicKey;  // ML-KEM-768 PK (PQ_KEM_PUBLIC_KEY_SIZE)
    std::vector<uint8_t> kemSecretKey;  // ML-KEM-768 SK (kept encrypted in the wallet; needed to scan)
    std::vector<uint8_t> dsaPublicKey;  // ML-DSA-65 PK (ccx_pq_multisig_pubkey_bytes() == 1952)
    std::vector<uint8_t> dsaSecretKey;  // ML-DSA-65 SK (ccx_pq_multisig_seckey_bytes() == 4032; encrypted at rest)
    uint32_t kemSchemeId;
    uint32_t ringSchemeId;
    uint32_t dsaSchemeId;
  };

  class PqAccount
  {
  public:
    // Derive the 32-byte PQ KEM seed from the 32-byte master seed via a domain-separated hash
    // (cn_fast_hash of "ccx-pq-kem-acct" || master). Deterministic and domain-separated from the
    // legacy spend/view derivation so the KEM seed != the spend seed.
    static crypto::Hash deriveKemSeed(const crypto::SecretKey &masterSeed);

    // Derive the 32-byte PQ ML-DSA (deposit-signing) seed from the master seed via a domain-separated
    // hash (cn_fast_hash of "ccx-pq-multisig-acct" || master). A DISTINCT domain tag from the KEM and
    // ring seeds, so the three account seeds are mutually independent (per ccx-pqc detkeygen domain
    // separation). Deterministic: same master seed -> same DSA keypair, hence mnemonic-restorable.
    static crypto::Hash deriveDsaSeed(const crypto::SecretKey &masterSeed);

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
