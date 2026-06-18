// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Send -> tx.extra round-trip for the "encrypted messages DEFAULT to post-quantum 0x06" change.
//
// Conceal stores PERMANENT encrypted messages on-chain. The classical authenticated field (0x07,
// tx_extra_authenticated_message) gives integrity but its Curve25519 ECDH key agreement is
// Shor-breakable, so a message recorded today is a harvest-now-decrypt-later target the instant a
// CRQC exists. The post-quantum field (0x06, tx_extra_pq_message, ML-KEM-768 + ChaCha20-Poly1305)
// gives true PQ confidentiality. These tests prove the send path now PREFERS 0x06 whenever a
// recipient KEM pubkey is obtainable, and only falls back to 0x07 (classical) when none is:
//   (a) a PQ recipient address carries a KEM key -> 0x06 (on ANY network, including mainnet);
//   (b) testnet legacy recipient -> 0x06 via the fixed PQ_TESTNET_KEM_PK (Option-B bootstrap);
//   (c) mainnet legacy recipient -> 0x07 classical fallback (no KEM key available);
//   (broadcast/unencrypted) -> legacy 0x04 (no recipient ECDH), unchanged.
// This mirrors TestAuthenticatedMessageSendPath.cpp but for the 0x06-default routing.
//
// tx.extra is opaque to consensus and carried verbatim, so this is an add-only, non-consensus
// routing change — the 0x06/0x07/0x04 wire formats and the serializer are untouched.

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <boost/variant/get.hpp>

#include "crypto/crypto.h"
#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include <Logging/LoggerGroup.h>

#include "pq_ring_sig.h"             // ML-KEM FFI (self-guards extern "C")
#include "pq_testnet_kem_keypair.h" // cn::PQ_TESTNET_KEM_PK / cn::PQ_TESTNET_KEM_SK (testnet KEM keypair)

using namespace cn;

namespace
{
  // Minimal single-input source builder, mirroring TestAuthenticatedMessageSendPath.cpp: a ring of
  // miner txs supplies the decoy/real outputs constructTransaction needs for valid ring signatures.
  // The currency's testnet flag is selectable so we can exercise both the mainnet and testnet paths.
  struct SendPathFixture
  {
    logging::LoggerGroup logger;
    Currency currency;
    AccountBase sender;
    AccountBase recipient;
    std::vector<TransactionSourceEntry> sources;
    AccountKeys senderKeys;

    explicit SendPathFixture(bool testnet)
        : currency(CurrencyBuilder(logger).testnet(testnet).currency())
    {
      recipient.generate();
      buildSources();
    }

    void buildSources()
    {
      const size_t ringSize = 1;
      const size_t realSourceIdx = ringSize / 2;

      std::vector<AccountBase> miners(ringSize);
      std::vector<Transaction> minerTxs(ringSize);
      std::vector<TransactionSourceEntry::OutputEntry> outputEntries;

      for (uint32_t i = 0; i < ringSize; ++i)
      {
        miners[i].generate();
        bool ok = currency.constructMinerTx(0, 0, 0, 2, 0, miners[i].getAccountKeys().address, minerTxs[i]);
        EXPECT_TRUE(ok);
        KeyOutput txOut = boost::get<KeyOutput>(minerTxs[i].outputs[0].target);
        outputEntries.push_back(std::make_pair(i, txOut.key));
      }

      TransactionSourceEntry source;
      source.amount = minerTxs[0].outputs[0].amount;
      source.realTransactionPublicKey = getTransactionPublicKeyFromExtra(minerTxs[realSourceIdx].extra);
      source.realOutputIndexInTransaction = 0;
      source.outputs.swap(outputEntries);
      source.realOutput = realSourceIdx;
      sources.push_back(source);

      sender = miners[realSourceIdx];
      senderKeys = sender.getAccountKeys();
    }

    // Construct a real transaction carrying the given messages and return it (plus the tx public key).
    bool construct(const std::vector<tx_message_entry> &messages, Transaction &tx, crypto::PublicKey &txPub)
    {
      uint64_t fee = 0;
      uint64_t amount = sources[0].amount;
      std::vector<TransactionDestinationEntry> destinations;
      destinations.emplace_back(amount - fee, recipient.getAccountKeys().address);

      crypto::SecretKey txSK;
      if (!constructTransaction(senderKeys, sources, destinations, messages, 0, std::vector<uint8_t>(), tx, 0, logger, txSK))
      {
        return false;
      }
      txPub = getTransactionPublicKeyFromExtra(tx.extra);
      return true;
    }

    static size_t countFields(const Transaction &tx, const std::type_info &type)
    {
      std::vector<TransactionExtraField> fields;
      parseTransactionExtra(tx.extra, fields);
      size_t n = 0;
      for (const auto &f : fields)
      {
        if (f.type() == type)
        {
          ++n;
        }
      }
      return n;
    }
  };

  // The send path packs each TransactionMessage into a tx_message_entry, with the recipient KEM key
  // (when one is obtainable) decided by cn::resolveMessageRecipientKemPub. Build the same entry here
  // so the test exercises the exact routing both wallet send paths use.
  tx_message_entry makeEncryptedEntry(const std::string &msg, const std::string &recipientAddress,
                                      const AccountPublicAddress &addr, bool testnet)
  {
    tx_message_entry e;
    e.message = msg;
    e.encrypt = true;
    e.addr = addr;
    e.pq = false; // tx_message_entry is an aggregate; set pq explicitly (mirrors the real send path)
    std::vector<uint8_t> kemPub;
    if (cn::resolveMessageRecipientKemPub(recipientAddress, testnet, kemPub))
    {
      e.pq = true;
      e.kemPub = std::move(kemPub);
    }
    return e;
  }

  tx_message_entry makeBroadcastEntry(const std::string &msg)
  {
    tx_message_entry e;
    e.message = msg;
    e.encrypt = false;
    e.addr = boost::value_initialized<AccountPublicAddress>();
    e.pq = false;
    return e;
  }

  // Build a real PQ-only address string carrying a freshly-generated ML-KEM keypair; the secret key
  // is returned so the test can prove the recipient decrypts the resulting 0x06 field.
  std::string makePqRecipientAddress(std::vector<uint8_t> &kemSecOut)
  {
    std::vector<uint8_t> pk(ccx_pq_kem_pubkey_bytes(), 0);
    std::vector<uint8_t> sk(ccx_pq_kem_seckey_bytes(), 0);
    EXPECT_EQ(0, ccx_pq_kem_keypair(pk.data(), pk.size(), sk.data(), sk.size()));
    kemSecOut = sk;

    PqAccountPublicAddress addr;
    addr.pqVersion = PQ_ADDRESS_VERSION;
    addr.flags = 0;
    addr.kemSchemeId = PQ_KEM_SCHEME_ID;
    addr.ringSchemeId = PQ_RING_SCHEME_ID;
    addr.kemPublicKey = pk;
    std::memset(&addr.legacySpendPublicKey, 0, sizeof(addr.legacySpendPublicKey));
    std::memset(&addr.legacyViewPublicKey, 0, sizeof(addr.legacyViewPublicKey));
    return getPqAccountAddressAsStr(CRYPTONOTE_PUBLIC_PQ_ADDRESS_BASE58_PREFIX, addr);
  }
}

// (a) An encrypted message to a PQ-capable recipient (its address carries an ML-KEM pubkey) emits a
//     0x06 tx_extra_pq_message and NEITHER a 0x07 NOR a 0x04 field — true PQ confidentiality, even on
//     mainnet — and the recipient's KEM secret decrypts it.
TEST(PqMessageDefaultSendPath, PqRecipientEmits0x06NotClassical)
{
  SendPathFixture f(/*testnet=*/false); // mainnet currency: case (a) does not depend on testnet
  const std::string plaintext = "pq recipient default-pq message";

  std::vector<uint8_t> recipientKemSec;
  const std::string pqAddress = makePqRecipientAddress(recipientKemSec);

  std::vector<tx_message_entry> messages;
  messages.push_back(makeEncryptedEntry(plaintext, pqAddress, f.recipient.getAccountKeys().address,
                                        f.currency.isTestnet()));
  ASSERT_TRUE(messages[0].pq);

  Transaction tx;
  crypto::PublicKey txPub;
  ASSERT_TRUE(f.construct(messages, tx, txPub));

  // 0x06 present; classical 0x07 and legacy 0x04 NOT emitted.
  ASSERT_EQ(1u, SendPathFixture::countFields(tx, typeid(tx_extra_pq_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_authenticated_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_message)));

  // The recipient's ML-KEM secret decrypts the 0x06 message (same getter the receive path uses).
  std::vector<std::string> pqMessages = get_pq_messages_from_extra(tx.extra, recipientKemSec);
  ASSERT_EQ(1u, pqMessages.size());
  ASSERT_EQ(plaintext, pqMessages[0]);
}

// (b) On testnet, an encrypted message to a legacy recipient (no published KEM key) still emits a
//     0x06 field via the fixed testnet bootstrap key, NOT a 0x07/0x04, and PQ_TESTNET_KEM_SK decrypts
//     it — so testnet permanent messages are PQ-encrypted by default.
TEST(PqMessageDefaultSendPath, TestnetLegacyRecipientEmits0x06ViaBootstrapKey)
{
  SendPathFixture f(/*testnet=*/true);
  const std::string plaintext = "testnet default-pq message";

  const std::string legacyAddress =
      f.currency.accountAddressAsString(f.recipient.getAccountKeys().address);

  std::vector<tx_message_entry> messages;
  messages.push_back(makeEncryptedEntry(plaintext, legacyAddress, f.recipient.getAccountKeys().address,
                                        f.currency.isTestnet()));
  ASSERT_TRUE(messages[0].pq);

  Transaction tx;
  crypto::PublicKey txPub;
  ASSERT_TRUE(f.construct(messages, tx, txPub));

  ASSERT_EQ(1u, SendPathFixture::countFields(tx, typeid(tx_extra_pq_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_authenticated_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_message)));

  // The fixed testnet KEM secret decrypts it (this is exactly what TransfersConsumer scans with).
  std::vector<uint8_t> testnetKemSec(PQ_TESTNET_KEM_SK, PQ_TESTNET_KEM_SK + sizeof(PQ_TESTNET_KEM_SK));
  std::vector<std::string> pqMessages = get_pq_messages_from_extra(tx.extra, testnetKemSec);
  ASSERT_EQ(1u, pqMessages.size());
  ASSERT_EQ(plaintext, pqMessages[0]);
}

// (c) On mainnet, an encrypted message to a classical-only (legacy) recipient has no obtainable KEM
//     key, so the send path falls back to the authenticated classical 0x07 field — NOT 0x06, and not
//     the legacy 0x04 — and the recipient's spend secret decrypts it.
TEST(PqMessageDefaultSendPath, MainnetLegacyRecipientEmits0x07NotPq)
{
  SendPathFixture f(/*testnet=*/false);
  const std::string plaintext = "mainnet classical fallback message";

  const std::string legacyAddress =
      f.currency.accountAddressAsString(f.recipient.getAccountKeys().address);

  std::vector<tx_message_entry> messages;
  messages.push_back(makeEncryptedEntry(plaintext, legacyAddress, f.recipient.getAccountKeys().address,
                                        f.currency.isTestnet()));
  ASSERT_FALSE(messages[0].pq); // no KEM key obtainable -> classical path

  Transaction tx;
  crypto::PublicKey txPub;
  ASSERT_TRUE(f.construct(messages, tx, txPub));

  // 0x07 present; the PQ 0x06 and legacy 0x04 are NOT emitted.
  ASSERT_EQ(1u, SendPathFixture::countFields(tx, typeid(tx_extra_authenticated_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_pq_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_message)));

  const crypto::SecretKey &recipientSpendSec = f.recipient.getAccountKeys().spendSecretKey;
  std::vector<std::string> authMessages = get_authenticated_messages_from_extra(tx.extra, txPub, &recipientSpendSec);
  ASSERT_EQ(1u, authMessages.size());
  ASSERT_EQ(plaintext, authMessages[0]);
}

// An UNENCRYPTED (broadcast) message has no recipient, so neither the PQ 0x06 nor the authenticated
// 0x07 field can be produced; it still falls back to the legacy 0x04 plaintext field, unchanged.
TEST(PqMessageDefaultSendPath, BroadcastStillEmits0x04)
{
  SendPathFixture f(/*testnet=*/true); // even on testnet, an unencrypted message is not PQ-sealed
  const std::string plaintext = "broadcast plaintext";

  std::vector<tx_message_entry> messages;
  messages.push_back(makeBroadcastEntry(plaintext));

  Transaction tx;
  crypto::PublicKey txPub;
  ASSERT_TRUE(f.construct(messages, tx, txPub));

  ASSERT_EQ(1u, SendPathFixture::countFields(tx, typeid(tx_extra_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_pq_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_authenticated_message)));

  std::vector<std::string> legacyMessages = get_messages_from_extra(tx.extra, txPub, nullptr);
  ASSERT_EQ(1u, legacyMessages.size());
  ASSERT_EQ(plaintext, legacyMessages[0]);
}
