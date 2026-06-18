// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Send -> tx.extra -> scan round-trip for the authenticated classical message migration.
//
// These tests exercise the real wallet send path (cn::constructTransaction with a tx_message_entry)
// and prove the migration of the encrypted-message field from the legacy unauthenticated 0x04
// (tx_extra_message) to the authenticated 0x07 (tx_extra_authenticated_message, ChaCha20-Poly1305):
//   - an ENCRYPTED message (tx_message_entry::encrypt == true) now emits a 0x07 field and NO 0x04
//     field, and the recipient's spend secret key decrypts it via get_authenticated_messages_from_extra
//     (the same call path TransfersConsumer/WalletGreen/PaymentGate use on receive);
//   - the legacy 0x04 decoder no longer finds anything (0x04 is frozen to decrypt-only for history);
//   - an UNENCRYPTED message (encrypt == false, no recipient ECDH) still falls back to the legacy 0x04
//     plaintext field, the one place 0x04 is still legitimately emitted.
//
// tx-extra is NOT consensus-validated, so this migration is backward-compatible and non-consensus.

#include "gtest/gtest.h"

#include <string>
#include <vector>

#include <boost/variant/get.hpp>

#include "crypto/crypto.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include <Logging/LoggerGroup.h>

using namespace cn;

namespace
{
  // Minimal single-input source builder, mirroring tests/UnitTests/TransactionPool.cpp's
  // TestTransactionGenerator: a ring of miner txs supplies the decoy/real outputs that
  // constructTransaction needs to produce valid ring signatures.
  struct SendPathFixture
  {
    logging::LoggerGroup logger;
    Currency currency;
    AccountBase sender;
    AccountBase recipient;
    std::vector<TransactionSourceEntry> sources;
    AccountKeys senderKeys;

    SendPathFixture() : currency(CurrencyBuilder(logger).currency())
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
      EXPECT_TRUE(parseTransactionExtra(tx.extra, fields));
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

  tx_message_entry makeEncryptedEntry(const std::string &msg, const AccountPublicAddress &addr)
  {
    tx_message_entry e;
    e.message = msg;
    e.encrypt = true;
    e.addr = addr;
    e.pq = false;
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
}

// An encrypted message now emits the authenticated 0x07 field and NOT the legacy 0x04 field, and the
// recipient's spend secret decrypts it through the same getter the receive path uses.
TEST(AuthenticatedMessageSendPath, EncryptedMessageEmits0x07Not0x04AndScans)
{
  SendPathFixture f;
  const std::string plaintext = "authenticated send-path message";

  std::vector<tx_message_entry> messages;
  messages.push_back(makeEncryptedEntry(plaintext, f.recipient.getAccountKeys().address));

  Transaction tx;
  crypto::PublicKey txPub;
  ASSERT_TRUE(f.construct(messages, tx, txPub));

  // The new authenticated field (0x07) is present; the legacy field (0x04) is NOT emitted.
  ASSERT_EQ(1u, SendPathFixture::countFields(tx, typeid(tx_extra_authenticated_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_message)));

  // Receive path: the recipient's spend secret decrypts the 0x07 message (same call the wallet uses).
  const crypto::SecretKey &recipientSpendSec = f.recipient.getAccountKeys().spendSecretKey;
  std::vector<std::string> authMessages = get_authenticated_messages_from_extra(tx.extra, txPub, &recipientSpendSec);
  ASSERT_EQ(1u, authMessages.size());
  ASSERT_EQ(plaintext, authMessages[0]);

  // The legacy 0x04 decoder finds nothing — proof 0x04 is no longer emitted for new messages.
  std::vector<std::string> legacyMessages = get_messages_from_extra(tx.extra, txPub, &recipientSpendSec);
  ASSERT_TRUE(legacyMessages.empty());
}

// A wrong recipient (different spend secret) must not decrypt the authenticated payload.
TEST(AuthenticatedMessageSendPath, WrongRecipientDoesNotDecrypt0x07)
{
  SendPathFixture f;
  std::vector<tx_message_entry> messages;
  messages.push_back(makeEncryptedEntry("only for the recipient", f.recipient.getAccountKeys().address));

  Transaction tx;
  crypto::PublicKey txPub;
  ASSERT_TRUE(f.construct(messages, tx, txPub));

  AccountBase stranger;
  stranger.generate();
  const crypto::SecretKey &strangerSpendSec = stranger.getAccountKeys().spendSecretKey;
  std::vector<std::string> authMessages = get_authenticated_messages_from_extra(tx.extra, txPub, &strangerSpendSec);
  ASSERT_TRUE(authMessages.empty());
}

// The one place 0x04 is still legitimately emitted: an UNENCRYPTED (broadcast) message has no
// recipient ECDH, so it cannot produce the authenticated 0x07 field and falls back to legacy 0x04
// plaintext, preserving historical behaviour. The real wallet send path always sets encrypt == true,
// so this branch is not reached by `transfer -m`.
TEST(AuthenticatedMessageSendPath, UnencryptedMessageStillEmits0x04)
{
  SendPathFixture f;
  const std::string plaintext = "broadcast plaintext";

  std::vector<tx_message_entry> messages;
  messages.push_back(makeBroadcastEntry(plaintext));

  Transaction tx;
  crypto::PublicKey txPub;
  ASSERT_TRUE(f.construct(messages, tx, txPub));

  // Broadcast path keeps the legacy 0x04 field and does NOT emit 0x07.
  ASSERT_EQ(1u, SendPathFixture::countFields(tx, typeid(tx_extra_message)));
  ASSERT_EQ(0u, SendPathFixture::countFields(tx, typeid(tx_extra_authenticated_message)));

  // The legacy 0x04 decoder still reads it as plaintext (recipient secret == nullptr).
  std::vector<std::string> legacyMessages = get_messages_from_extra(tx.extra, txPub, nullptr);
  ASSERT_EQ(1u, legacyMessages.size());
  ASSERT_EQ(plaintext, legacyMessages[0]);
}

// Historical 0x04 messages must STILL decode after the migration (decrypt-only compatibility): an
// encrypted legacy 0x04 field written the old way is still readable by the recipient's spend secret.
TEST(AuthenticatedMessageSendPath, Legacy0x04StillDecodesForHistory)
{
  SendPathFixture f;
  const std::string plaintext = "old encrypted history message";

  // Build a tx public key the same way the sender would, then hand-craft a legacy 0x04 field as the
  // pre-migration code path would have produced it (tx_extra_message::encrypt + append_message_to_extra).
  KeyPair txkey;
  crypto::generate_keys(txkey.publicKey, txkey.secretKey);

  std::vector<uint8_t> extra;
  ASSERT_TRUE(addTransactionPublicKeyToExtra(extra, txkey.publicKey));

  tx_extra_message legacy;
  ASSERT_TRUE(legacy.encrypt(0, plaintext, &f.recipient.getAccountKeys().address, txkey));
  ASSERT_TRUE(append_message_to_extra(extra, legacy));

  // The recipient's spend secret still decrypts the legacy 0x04 field.
  const crypto::SecretKey &recipientSpendSec = f.recipient.getAccountKeys().spendSecretKey;
  std::vector<std::string> legacyMessages = get_messages_from_extra(extra, txkey.publicKey, &recipientSpendSec);
  ASSERT_EQ(1u, legacyMessages.size());
  ASSERT_EQ(plaintext, legacyMessages[0]);
}
