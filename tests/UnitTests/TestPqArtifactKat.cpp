// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PQ artifact determinism KAT.
//
// This is the cross-surface fixture M-new-4 asked for: real deterministic ML-KEM/ML-DSA account
// keys are combined with the production C++ serializers for address-v2 and a v4 PQ transaction, plus
// a wallet-section-shaped byte fixture that includes the account DSA material. The digest transcript
// is explicitly label/length-framed so the KAT is independent of host struct layout.

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "Common/StringOutputStream.h"
#include "Common/StringTools.h"
#include "crypto/hash.h"
#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/SerializationOverloads.h"
#include "Wallet/PqAccount.h"

extern "C"
{
#include "pq_ring_sig.h"
}

using namespace cn;

namespace
{
  crypto::SecretKey fixtureMasterSeed()
  {
    crypto::SecretKey seed;
    for (size_t i = 0; i < sizeof(seed.data); ++i)
    {
      seed.data[i] = static_cast<uint8_t>((0x31 + i * 7) & 0xff);
    }
    return seed;
  }

  std::vector<uint8_t> fillVec(size_t len, uint8_t base)
  {
    std::vector<uint8_t> v(len);
    for (size_t i = 0; i < len; ++i)
    {
      v[i] = static_cast<uint8_t>((base + i) & 0xff);
    }
    return v;
  }

  void appendLe32(std::vector<uint8_t> &out, uint32_t value)
  {
    for (int i = 0; i < 4; ++i)
    {
      out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xff));
    }
  }

  void appendLe64(std::vector<uint8_t> &out, uint64_t value)
  {
    for (int i = 0; i < 8; ++i)
    {
      out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xff));
    }
  }

  void appendField(std::vector<uint8_t> &out, const char *label, const std::vector<uint8_t> &bytes)
  {
    const size_t labelLen = std::strlen(label);
    appendLe32(out, static_cast<uint32_t>(labelLen));
    out.insert(out.end(), label, label + labelLen);
    appendLe64(out, static_cast<uint64_t>(bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
  }

  void appendField(std::vector<uint8_t> &out, const char *label, const std::string &text)
  {
    appendField(out, label, std::vector<uint8_t>(text.begin(), text.end()));
  }

  std::vector<uint8_t> serializePqAccountSectionV2(const PqAccountKeys &keys)
  {
    std::string out;
    common::StringOutputStream os(out);
    BinaryOutputStreamSerializer s(os);

    uint8_t sectionVersion = 2;
    uint8_t present = 1;
    uint32_t kemSchemeId = keys.kemSchemeId;
    uint32_t ringSchemeId = keys.ringSchemeId;
    uint32_t dsaSchemeId = keys.dsaSchemeId;
    std::vector<uint8_t> kemPk = keys.kemPublicKey;
    std::vector<uint8_t> kemSk = keys.kemSecretKey;
    std::vector<uint8_t> dsaPk = keys.dsaPublicKey;
    std::vector<uint8_t> dsaSk = keys.dsaSecretKey;

    s(sectionVersion, "pqSectionVersion");
    s(present, "pqPresent");
    s(kemSchemeId, "kemSchemeId");
    s(ringSchemeId, "ringSchemeId");
    s(dsaSchemeId, "dsaSchemeId");
    serializeAsBinary(kemPk, "kemPublicKey", s);
    serializeAsBinary(kemSk, "kemSecretKey", s);
    serializeAsBinary(dsaPk, "dsaPublicKey", s);
    serializeAsBinary(dsaSk, "dsaSecretKey", s);

    return std::vector<uint8_t>(out.begin(), out.end());
  }

  Transaction makeSerializedPqFixtureTransaction(const PqAccountKeys &keys,
                                                 const std::vector<uint8_t> &ringPublicKey,
                                                 const std::vector<uint8_t> &nullifier)
  {
    Transaction tx;
    tx.version = TRANSACTION_VERSION_4;
    tx.unlockTime = 17;

    PqKeyInput spend;
    spend.amount = 123456789;
    spend.outputIndexes = {0, 2};
    spend.nullifier = nullifier;
    spend.ringSig = fillVec(256, 0x90);
    tx.inputs.push_back(spend);

    PqMultisigInput withdraw;
    withdraw.amount = 50000000;
    withdraw.signatureCount = 1;
    withdraw.outputIndex = 3;
    withdraw.term = 30;
    withdraw.signatures.push_back(fillVec(ccx_pq_sig_bytes(), 0xb0));
    tx.inputs.push_back(withdraw);

    PqKeyOutput spendOutput;
    spendOutput.key = ringPublicKey;
    spendOutput.kemCt = fillVec(ccx_pq_kem_ct_bytes(), 0xc0);
    TransactionOutput out1;
    out1.amount = 120000000;
    out1.target = spendOutput;
    tx.outputs.push_back(out1);

    PqMultisigOutput depositOutput;
    depositOutput.dsaSchemeId = keys.dsaSchemeId;
    depositOutput.keys.push_back(keys.dsaPublicKey);
    depositOutput.requiredSignatureCount = 1;
    depositOutput.term = 30;
    TransactionOutput out2;
    out2.amount = 3000000;
    out2.target = depositOutput;
    tx.outputs.push_back(out2);

    tx.extra = fillVec(9, 0xe0);
    return tx;
  }
}

TEST(PqArtifactKat, FullMatrixDigestMatchesReference)
{
  const PqAccountKeys keys = PqAccount::generateFromSeed(fixtureMasterSeed());
  ASSERT_EQ(static_cast<size_t>(1184), keys.kemPublicKey.size());
  ASSERT_EQ(static_cast<size_t>(2400), keys.kemSecretKey.size());
  ASSERT_EQ(static_cast<size_t>(1952), keys.dsaPublicKey.size());
  ASSERT_EQ(static_cast<size_t>(4032), keys.dsaSecretKey.size());
  ASSERT_EQ(PQ_KEM_SCHEME_ID, keys.kemSchemeId);
  ASSERT_EQ(PQ_RING_SCHEME_ID, keys.ringSchemeId);
  ASSERT_EQ(PQ_DSA_SCHEME_ID, keys.dsaSchemeId);

  std::vector<uint8_t> ringSeed = fillVec(48, 0x41);
  std::vector<uint8_t> ringPublicKey(ccx_pq_pubkey_bytes());
  std::vector<uint8_t> ringSecretKey(ccx_pq_seckey_bytes());
  ASSERT_EQ(0, ccx_pq_keygen(ringSeed.data(), ringSeed.size(),
                             ringPublicKey.data(), ringPublicKey.size(),
                             ringSecretKey.data(), ringSecretKey.size()));
  ASSERT_EQ(1, ccx_pq_pubkey_is_canonical(ringPublicKey.data(), ringPublicKey.size()));

  std::vector<uint8_t> nullifier(ccx_pq_nullifier_bytes());
  ASSERT_EQ(0, ccx_pq_nullifier(ringSecretKey.data(), ringSecretKey.size(),
                                ringPublicKey.data(), ringPublicKey.size(),
                                nullifier.data(), nullifier.size()));

  const PqAccountPublicAddress address = PqAccount::toPublicAddress(keys);
  BinaryArray addressBytes;
  ASSERT_TRUE(toBinaryArray(address, addressBytes));
  const std::string testnetAddress =
      getPqAccountAddressAsStr(TESTNET_PUBLIC_PQ_ADDRESS_BASE58_PREFIX, address);
  uint64_t parsedPrefix = 0;
  PqAccountPublicAddress parsedAddress;
  ASSERT_TRUE(parsePqAccountAddressString(parsedPrefix, parsedAddress, testnetAddress));
  ASSERT_EQ(TESTNET_PUBLIC_PQ_ADDRESS_BASE58_PREFIX, parsedPrefix);
  ASSERT_EQ(addressBytes, toBinaryArray(parsedAddress));

  const std::vector<uint8_t> walletSection = serializePqAccountSectionV2(keys);

  const Transaction tx = makeSerializedPqFixtureTransaction(keys, ringPublicKey, nullifier);
  BinaryArray txBytes;
  ASSERT_TRUE(toBinaryArray(tx, txBytes));
  Transaction parsedTx;
  ASSERT_TRUE(fromBinaryArray(parsedTx, txBytes));
  ASSERT_EQ(txBytes, toBinaryArray(parsedTx));

  std::vector<uint8_t> transcript;
  appendField(transcript, "ml-kem-768-public-key", keys.kemPublicKey);
  appendField(transcript, "ml-kem-768-secret-key", keys.kemSecretKey);
  appendField(transcript, "ml-dsa-65-public-key", keys.dsaPublicKey);
  appendField(transcript, "ml-dsa-65-secret-key", keys.dsaSecretKey);
  appendField(transcript, "raptor-public-key", ringPublicKey);
  appendField(transcript, "raptor-secret-key", ringSecretKey);
  appendField(transcript, "raptor-nullifier", nullifier);
  appendField(transcript, "address-v2-binary", addressBytes);
  appendField(transcript, "address-v2-testnet-base58", testnetAddress);
  appendField(transcript, "wallet-pq-section-v2", walletSection);
  appendField(transcript, "serialized-pq-tx-v4", txBytes);

  const crypto::Hash digest = crypto::cn_fast_hash(transcript.data(), transcript.size());
  const std::string actual = common::podToHex(digest);
  std::cout << "PQ_ARTIFACT_KAT_DIGEST=" << actual
            << " TRANSCRIPT_BYTES=" << transcript.size() << std::endl;
  EXPECT_EQ("cad7eea17e1d6bb89898f7faa6d8fb1960b70edcd29e396fcaf8a544e340e441", actual);
}
