// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "CryptoNoteBasicImpl.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteFormatUtils.h"
#include "CryptoNoteTools.h"
#include "CryptoNoteSerialization.h"

#include "Common/Base58.h"
#include "crypto/hash.h"
#include "Common/int-util.h"

#include "pq_testnet_kem_keypair.h" // PQ_TESTNET_KEM_PK (fixed testnet ML-KEM recipient, Option-B bootstrap)

using namespace crypto;
using namespace common;

namespace cn {

  /************************************************************************/
  /* cn helper functions                                          */
  /************************************************************************/
  //-----------------------------------------------------------------------------------------------
  uint64_t getPenalizedAmount(uint64_t amount, size_t medianSize, size_t currentBlockSize) {
    static_assert(sizeof(size_t) >= sizeof(uint32_t), "size_t is too small");
    assert(currentBlockSize <= 2 * medianSize);
    assert(medianSize <= std::numeric_limits<uint32_t>::max());
    assert(currentBlockSize <= std::numeric_limits<uint32_t>::max());

    if (amount == 0) {
      return 0;
    }

    if (currentBlockSize <= medianSize) {
      return amount;
    }

    uint64_t productHi;
    uint64_t productLo = mul128(amount, currentBlockSize * (UINT64_C(2) * medianSize - currentBlockSize), &productHi);

    uint64_t penalizedAmountHi;
    uint64_t penalizedAmountLo;
    div128_32(productHi, productLo, static_cast<uint32_t>(medianSize), &penalizedAmountHi, &penalizedAmountLo);
    div128_32(penalizedAmountHi, penalizedAmountLo, static_cast<uint32_t>(medianSize), &penalizedAmountHi, &penalizedAmountLo);

    assert(0 == penalizedAmountHi);
    assert(penalizedAmountLo < amount);

    return penalizedAmountLo;
  }
  //-----------------------------------------------------------------------
  std::string getAccountAddressAsStr(uint64_t prefix, const AccountPublicAddress& adr) {
    BinaryArray ba;
    bool r = toBinaryArray(adr, ba);
    assert(r);
    return tools::base_58::encode_addr(prefix, common::asString(ba));
  }
  //-----------------------------------------------------------------------
  bool is_coinbase(const Transaction& tx) {
    if(tx.inputs.size() != 1) {
      return false;
    }

    if(tx.inputs[0].type() != typeid(BaseInput)) {
      return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------
  bool parseAccountAddressString(uint64_t& prefix, AccountPublicAddress& adr, const std::string& str) {
    std::string data;

    return
      tools::base_58::decode_addr(str, prefix, data) &&
      fromBinaryArray(adr, asBinaryArray(data)) &&
      // ::serialization::parse_binary(data, adr) &&
      check_key(adr.spendPublicKey) &&
      check_key(adr.viewPublicKey);
  }
  //-----------------------------------------------------------------------
  std::string getPqAccountAddressAsStr(uint64_t prefix, const PqAccountPublicAddress& adr) {
    // Reuse the existing Base58 address machinery (varint tag + payload + 4-byte cn_fast_hash
    // checksum) — do NOT invent a new encoder (wallet-address-v2 §2.1).
    BinaryArray ba;
    bool r = toBinaryArray(adr, ba);
    assert(r);
    return tools::base_58::encode_addr(prefix, common::asString(ba));
  }
  //-----------------------------------------------------------------------
  bool parsePqAccountAddressString(uint64_t& prefix, PqAccountPublicAddress& adr, const std::string& str) {
    // Cap the encoded length BEFORE decoding: decode_addr heap-allocates proportional to the input
    // and runs the full cn_fast_hash checksum, so an attacker could feed a huge string. A valid PQ
    // address payload is ~1.26 KB (version+flags+schemeIds + 1184-byte KEM PK + 64-byte legacy keys +
    // checksum + varint tag) → ~1.75k Base58 chars; reject anything well beyond that up front.
    const size_t MAX_PQ_ADDRESS_STR_LEN = 2048;
    if (str.empty() || str.size() > MAX_PQ_ADDRESS_STR_LEN) {
      return false;
    }
    std::string data;
    if (!tools::base_58::decode_addr(str, prefix, data)) {
      return false; // bad checksum / not Base58 / wrong block sizing
    }
    if (!fromBinaryArray(adr, asBinaryArray(data))) {
      return false; // malformed payload
    }
    // Validate at the boundary (the analogue of legacy check_key()): pin version + scheme ids and the
    // ML-KEM public-key length. Fail fast on anything unexpected so an out-of-spec address is rejected
    // rather than silently misused.
    if (adr.pqVersion != PQ_ADDRESS_VERSION) {
      return false;
    }
    if (adr.kemSchemeId != PQ_KEM_SCHEME_ID) {
      return false; // unsupported KEM scheme (crypto-agility)
    }
    if (adr.ringSchemeId != PQ_RING_SCHEME_ID) {
      return false; // unsupported ring-sig scheme (crypto-agility) — both schemeIds are pinned
    }
    if (adr.kemPublicKey.size() != PQ_KEM_PUBLIC_KEY_SIZE) {
      return false; // wrong ML-KEM-768 public-key length
    }
    // Reserved flag bits must be zero (only bit0 = hybrid is defined).
    if ((adr.flags & ~uint8_t(0x01)) != 0) {
      return false;
    }
    // For a hybrid address the legacy Ed25519 keys must be valid curve points; for PQ-only they must
    // be the canonical zero (the serializer always writes them, zero when not hybrid).
    const bool hybrid = (adr.flags & 0x01) != 0;
    if (hybrid) {
      if (!check_key(adr.legacySpendPublicKey) || !check_key(adr.legacyViewPublicKey)) {
        return false;
      }
    } else {
      if (!(adr.legacySpendPublicKey == NULL_PUBLIC_KEY) || !(adr.legacyViewPublicKey == NULL_PUBLIC_KEY)) {
        return false; // PQ-only address must not carry stray legacy keys
      }
    }
    return true;
  }
  //-----------------------------------------------------------------------
  bool resolveMessageRecipientKemPub(const std::string& recipientAddress, bool testnet,
                                     std::vector<uint8_t>& kemPub) {
    // (a) The recipient address itself carries an ML-KEM public key (PQ-only or hybrid address).
    //     parsePqAccountAddressString already version/scheme/length-validates the payload, so a
    //     successful parse guarantees a well-formed 1184-byte kemPublicKey. Works on any network.
    {
      uint64_t prefix = 0;
      PqAccountPublicAddress pqAddr;
      if (parsePqAccountAddressString(prefix, pqAddr, recipientAddress)) {
        kemPub = pqAddr.kemPublicKey;
        return true;
      }
    }
    // (b) Testnet bootstrap (Option B): the recipient is a legacy address with no published KEM key,
    //     but on testnet we still want permanent messages PQ-encrypted by default, so encapsulate to
    //     the fixed testnet ML-KEM recipient key. (PoC: a single shared testnet identity.)
    if (testnet) {
      kemPub.assign(PQ_TESTNET_KEM_PK, PQ_TESTNET_KEM_PK + sizeof(PQ_TESTNET_KEM_PK));
      return true;
    }
    // (c) Mainnet legacy recipient with no obtainable KEM key: no PQ option. The caller falls back to
    //     the authenticated classical 0x07 field (integrity, but Shor-breakable confidentiality).
    return false;
  }
  //-----------------------------------------------------------------------
  bool operator ==(const cn::Transaction& a, const cn::Transaction& b) {
    return getObjectHash(a) == getObjectHash(b);
  }
  //-----------------------------------------------------------------------
  bool operator ==(const cn::Block& a, const cn::Block& b) {
    return cn::get_block_hash(a) == cn::get_block_hash(b);
  }
}

//--------------------------------------------------------------------------------
bool parse_hash256(const std::string& str_hash, crypto::Hash& hash) {
  return common::podFromHex(str_hash, hash);
}
