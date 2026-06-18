// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PqAccount.h"

#include <cstring>
#include <stdexcept>
#include <string>

#include "CryptoNoteConfig.h"

extern "C"
{
#include "pq_ring_sig.h"
}

namespace cn
{
  namespace
  {
    // Domain tag prefixed to the master seed before hashing so each derived seed is independent
    // (the KEM account seed must differ from the legacy spend seed and any future ring-acct seed).
    const char KEM_ACCT_DOMAIN[] = "ccx-pq-kem-acct";
  }

  crypto::Hash PqAccount::deriveKemSeed(const crypto::SecretKey &masterSeed)
  {
    // cn_fast_hash("ccx-pq-kem-acct" || master32) — deterministic, domain-separated.
    std::string buf;
    buf.reserve(sizeof(KEM_ACCT_DOMAIN) - 1 + sizeof(masterSeed.data));
    buf.append(KEM_ACCT_DOMAIN, sizeof(KEM_ACCT_DOMAIN) - 1);
    buf.append(reinterpret_cast<const char *>(masterSeed.data), sizeof(masterSeed.data));
    return crypto::cn_fast_hash(buf.data(), buf.size());
  }

  PqAccountKeys PqAccount::generateFromSeed(const crypto::SecretKey &masterSeed)
  {
    crypto::Hash kemSeed = deriveKemSeed(masterSeed);

    PqAccountKeys keys;
    keys.kemSchemeId = PQ_KEM_SCHEME_ID;
    keys.ringSchemeId = ccx_pq_scheme_id();

    const size_t pkLen = ccx_pq_kem_pubkey_bytes();
    const size_t skLen = ccx_pq_kem_seckey_bytes();
    if (pkLen == 0 || skLen == 0)
    {
      throw std::runtime_error("PqAccount: ccx-pqc reports zero KEM key size");
    }
    keys.kemPublicKey.assign(pkLen, 0);
    keys.kemSecretKey.assign(skLen, 0);

    const int32_t rc = ccx_pq_kem_keygen_det(
        reinterpret_cast<const uint8_t *>(kemSeed.data), sizeof(kemSeed.data),
        keys.kemPublicKey.data(), keys.kemPublicKey.size(),
        keys.kemSecretKey.data(), keys.kemSecretKey.size());
    if (rc != 0)
    {
      throw std::runtime_error("PqAccount: deterministic ML-KEM keygen failed (rc=" + std::to_string(rc) + ")");
    }
    return keys;
  }

  PqAccountPublicAddress PqAccount::toPublicAddress(const PqAccountKeys &keys)
  {
    PqAccountPublicAddress addr;
    addr.pqVersion = PQ_ADDRESS_VERSION;
    addr.flags = 0; // PQ-only
    addr.kemSchemeId = keys.kemSchemeId;
    addr.ringSchemeId = keys.ringSchemeId;
    addr.kemPublicKey = keys.kemPublicKey;
    std::memset(&addr.legacySpendPublicKey, 0, sizeof(addr.legacySpendPublicKey));
    std::memset(&addr.legacyViewPublicKey, 0, sizeof(addr.legacyViewPublicKey));
    return addr;
  }

  PqAccountPublicAddress PqAccount::toHybridPublicAddress(const PqAccountKeys &keys,
                                                          const crypto::PublicKey &legacySpend,
                                                          const crypto::PublicKey &legacyView)
  {
    PqAccountPublicAddress addr;
    addr.pqVersion = PQ_ADDRESS_VERSION;
    addr.flags = 0x01; // hybrid
    addr.kemSchemeId = keys.kemSchemeId;
    addr.ringSchemeId = keys.ringSchemeId;
    addr.kemPublicKey = keys.kemPublicKey;
    addr.legacySpendPublicKey = legacySpend;
    addr.legacyViewPublicKey = legacyView;
    return addr;
  }
} // namespace cn
