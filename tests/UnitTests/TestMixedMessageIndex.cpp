// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// HIGH-2 regression: a transaction that MIXES message tags (0x04 legacy / 0x06 PQ / 0x07 auth) must
// round-trip on the receive path. The builder (CryptoNoteFormatUtils) seals each message with its
// GLOBAL position in the message array (one tx_extra field per message, in order). The legacy per-tag
// getters each restart their index at 0 for their own tag, so in a tx like [0x06@0, 0x07@1] the 0x07
// is sealed at index 1 but a per-tag scan opens it at index 0 -> AEAD auth fails -> the permanent
// on-chain message is silently lost. get_all_messages_from_extra() walks the fields in wire order with
// ONE shared index that advances for every message-tag field, so each field's decrypt index equals its
// encrypt index for every tag combination. These tests pin that behaviour.

#include "gtest/gtest.h"

#include <string>
#include <vector>

#include <boost/utility/value_init.hpp>

#include "crypto/hash.h"
#include "crypto/crypto.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include "pq_ring_sig.h" // ML-KEM keypair for the 0x06 field

using namespace cn;

namespace
{
  struct KemKeyPair
  {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;

    KemKeyPair() : pk(ccx_pq_kem_pubkey_bytes(), 0), sk(ccx_pq_kem_seckey_bytes(), 0)
    {
      EXPECT_EQ(0, ccx_pq_kem_keypair(pk.data(), pk.size(), sk.data(), sk.size()));
    }
  };

  // Sender tx keypair + recipient spend keypair (the classical ECDH halves the 0x04/0x07 fields use).
  struct Parties
  {
    KeyPair txkey;
    AccountPublicAddress recipientPub;
    crypto::SecretKey recipientSpendSec;

    Parties()
    {
      txkey.publicKey = boost::value_initialized<crypto::PublicKey>();
      crypto::generate_keys(txkey.publicKey, txkey.secretKey);
      crypto::generate_keys(recipientPub.spendPublicKey, recipientSpendSec);
      recipientPub.viewPublicKey = boost::value_initialized<crypto::PublicKey>();
    }
  };
}

// [0x06 @ global index 0, 0x07 @ global index 1]: the unified scan decrypts BOTH, in wire order.
TEST(MixedMessageIndex, PqThenAuthUnifiedScanDecryptsBoth)
{
  Parties p;
  KemKeyPair kem;

  std::vector<uint8_t> extra;
  crypto::PublicKey txPub = boost::value_initialized<crypto::PublicKey>();
  ASSERT_TRUE(addTransactionPublicKeyToExtra(extra, txPub));

  // Message 0 -> 0x06 sealed at GLOBAL index 0.
  tx_extra_pq_message pq;
  ASSERT_TRUE(pq.encrypt(0, "pq-first", kem.pk));
  ASSERT_TRUE(append_pq_message_to_extra(extra, pq));

  // Message 1 -> 0x07 sealed at GLOBAL index 1 (the index where the old per-tag scan mis-opened it).
  tx_extra_authenticated_message auth;
  ASSERT_TRUE(auth.encrypt(1, "auth-second", &p.recipientPub, p.txkey));
  ASSERT_TRUE(append_authenticated_message_to_extra(extra, auth));

  std::vector<std::string> all =
      get_all_messages_from_extra(extra, p.txkey.publicKey, &p.recipientSpendSec, &kem.sk);
  ASSERT_EQ(2u, all.size());
  EXPECT_EQ("pq-first", all[0]);
  EXPECT_EQ("auth-second", all[1]); // <- would be LOST under the old per-tag scan

  // Proof of the bug the fix closes: the legacy per-tag getter opens the 0x07 at its own index 0,
  // but it was sealed at global index 1, so AEAD auth fails and it returns nothing.
  std::vector<std::string> perTagAuth =
      get_authenticated_messages_from_extra(extra, p.txkey.publicKey, &p.recipientSpendSec);
  EXPECT_TRUE(perTagAuth.empty());
}

// [0x07 @ 0, 0x06 @ 1]: the reverse ordering also round-trips (shared index follows wire order).
TEST(MixedMessageIndex, AuthThenPqUnifiedScanDecryptsBoth)
{
  Parties p;
  KemKeyPair kem;

  std::vector<uint8_t> extra;
  crypto::PublicKey txPub = boost::value_initialized<crypto::PublicKey>();
  ASSERT_TRUE(addTransactionPublicKeyToExtra(extra, txPub));

  tx_extra_authenticated_message auth;
  ASSERT_TRUE(auth.encrypt(0, "auth-first", &p.recipientPub, p.txkey));
  ASSERT_TRUE(append_authenticated_message_to_extra(extra, auth));

  tx_extra_pq_message pq;
  ASSERT_TRUE(pq.encrypt(1, "pq-second", kem.pk));
  ASSERT_TRUE(append_pq_message_to_extra(extra, pq));

  std::vector<std::string> all =
      get_all_messages_from_extra(extra, p.txkey.publicKey, &p.recipientSpendSec, &kem.sk);
  ASSERT_EQ(2u, all.size());
  EXPECT_EQ("auth-first", all[0]);
  EXPECT_EQ("pq-second", all[1]);
}

// Three tags interleaved [0x04 @ 0, 0x06 @ 1, 0x07 @ 2]: all decode at their global index.
TEST(MixedMessageIndex, LegacyPqAuthAllThreeTagsDecodeAtGlobalIndex)
{
  Parties p;
  KemKeyPair kem;

  std::vector<uint8_t> extra;
  crypto::PublicKey txPub = boost::value_initialized<crypto::PublicKey>();
  ASSERT_TRUE(addTransactionPublicKeyToExtra(extra, txPub));

  // 0x04 to the recipient (ENCRYPTED legacy) at global index 0.
  tx_extra_message legacy;
  ASSERT_TRUE(legacy.encrypt(0, "legacy-zero", &p.recipientPub, p.txkey));
  ASSERT_TRUE(append_message_to_extra(extra, legacy));

  // 0x06 at global index 1.
  tx_extra_pq_message pq;
  ASSERT_TRUE(pq.encrypt(1, "pq-one", kem.pk));
  ASSERT_TRUE(append_pq_message_to_extra(extra, pq));

  // 0x07 at global index 2.
  tx_extra_authenticated_message auth;
  ASSERT_TRUE(auth.encrypt(2, "auth-two", &p.recipientPub, p.txkey));
  ASSERT_TRUE(append_authenticated_message_to_extra(extra, auth));

  std::vector<std::string> all =
      get_all_messages_from_extra(extra, p.txkey.publicKey, &p.recipientSpendSec, &kem.sk);
  ASSERT_EQ(3u, all.size());
  EXPECT_EQ("legacy-zero", all[0]);
  EXPECT_EQ("pq-one", all[1]);
  EXPECT_EQ("auth-two", all[2]);
}

// A null KEM secret skips 0x06 fields but STILL advances the shared index, so a following 0x07 keeps
// its correct global index (mirrors the off-testnet receive path, which has no ML-KEM secret yet).
TEST(MixedMessageIndex, NullKemSecretSkips0x06ButKeepsIndexForFollowingAuth)
{
  Parties p;
  KemKeyPair kem;

  std::vector<uint8_t> extra;
  crypto::PublicKey txPub = boost::value_initialized<crypto::PublicKey>();
  ASSERT_TRUE(addTransactionPublicKeyToExtra(extra, txPub));

  tx_extra_pq_message pq;
  ASSERT_TRUE(pq.encrypt(0, "pq-unreadable", kem.pk));
  ASSERT_TRUE(append_pq_message_to_extra(extra, pq));

  tx_extra_authenticated_message auth;
  ASSERT_TRUE(auth.encrypt(1, "auth-readable", &p.recipientPub, p.txkey));
  ASSERT_TRUE(append_authenticated_message_to_extra(extra, auth));

  // No KEM secret -> 0x06 skipped; 0x07 must still decode at global index 1.
  std::vector<std::string> all =
      get_all_messages_from_extra(extra, p.txkey.publicKey, &p.recipientSpendSec, nullptr);
  ASSERT_EQ(1u, all.size());
  EXPECT_EQ("auth-readable", all[0]);
}

// MEDIUM-3: a plaintext that would seal past the parser's MAX_DATA_SIZE bound is rejected by encrypt()
// BEFORE sealing, for both AEAD fields. The largest sealable plaintext is MAX_DATA_SIZE - AEAD_TAG_SIZE.
TEST(MixedMessageIndex, EncryptRejectsOversizePlaintext)
{
  Parties p;
  KemKeyPair kem;

  const size_t pqMax = TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE - TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE;
  const size_t authMax = TX_EXTRA_AUTH_MESSAGE_MAX_DATA_SIZE - TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE;

  tx_extra_pq_message pqOk;
  EXPECT_TRUE(pqOk.encrypt(0, std::string(pqMax, 'x'), kem.pk));
  EXPECT_EQ(static_cast<size_t>(TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE), pqOk.data.size());
  tx_extra_pq_message pqTooBig;
  EXPECT_FALSE(pqTooBig.encrypt(0, std::string(pqMax + 1, 'x'), kem.pk));

  tx_extra_authenticated_message authOk;
  EXPECT_TRUE(authOk.encrypt(0, std::string(authMax, 'y'), &p.recipientPub, p.txkey));
  EXPECT_EQ(static_cast<size_t>(TX_EXTRA_AUTH_MESSAGE_MAX_DATA_SIZE), authOk.data.size());
  tx_extra_authenticated_message authTooBig;
  EXPECT_FALSE(authTooBig.encrypt(0, std::string(authMax + 1, 'y'), &p.recipientPub, p.txkey));

  // append_*_to_extra rejects an over-bound or under-bound (< AEAD tag) manually built field.
  std::vector<uint8_t> extra;
  tx_extra_pq_message pqOversize;
  pqOversize.kemCt.assign(ccx_pq_kem_ct_bytes(), 0);
  pqOversize.data.assign(TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE + 1, 0);
  EXPECT_FALSE(append_pq_message_to_extra(extra, pqOversize));

  tx_extra_authenticated_message authShort;
  authShort.data.assign(TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE - 1, 0);
  EXPECT_FALSE(append_authenticated_message_to_extra(extra, authShort));
}
