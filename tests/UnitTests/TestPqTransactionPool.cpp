// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include <ctime>

#include <boost/utility/value_init.hpp>

#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/TransactionPool.h"
#include "Logging/ConsoleLogger.h"

using namespace cn;

namespace
{
  class AcceptingValidator : public ITransactionValidator
  {
  public:
    bool checkTransactionInputs(
        const Transaction &, BlockInfo &) override
    {
      return true;
    }

    bool checkTransactionInputs(
        const Transaction &, BlockInfo &, BlockInfo &) override
    {
      return true;
    }

    bool haveSpentKeyImages(const Transaction &) override
    {
      return false;
    }

    bool checkTransactionSize(size_t) override
    {
      return true;
    }
  };

  class FixedTimeProvider : public ITimeProvider
  {
  public:
    time_t now() override
    {
      return 1;
    }
  };

  Transaction pqWithdrawal(uint8_t marker)
  {
    Transaction tx = boost::value_initialized<Transaction>();
    tx.version = TRANSACTION_VERSION_4;
    tx.extra.push_back(marker);

    PqMultisigInput input;
    input.amount = 1000;
    input.signatureCount = 1;
    input.outputIndex = 7;
    input.term = 0;
    input.signatures.push_back(std::vector<uint8_t>(1, marker));
    tx.inputs.push_back(input);
    return tx;
  }
}

TEST(PqTransactionPool, RemovingKeptByBlockWithdrawalPreservesNormalReservation)
{
  logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  AcceptingValidator validator;
  FixedTimeProvider timeProvider;
  tx_memory_pool pool(currency, validator, timeProvider, logger);

  const Transaction normal = pqWithdrawal(0x11);
  const Transaction keptByBlock = pqWithdrawal(0x22);
  const Transaction laterConflict = pqWithdrawal(0x33);

  tx_verification_context normalContext =
      boost::value_initialized<tx_verification_context>();
  ASSERT_TRUE(pool.add_tx(normal, normalContext, false, 0));
  ASSERT_TRUE(normalContext.m_added_to_pool);

  tx_verification_context keptContext =
      boost::value_initialized<tx_verification_context>();
  ASSERT_TRUE(pool.add_tx(keptByBlock, keptContext, true, 0));
  ASSERT_TRUE(keptContext.m_added_to_pool);

  Transaction removed;
  size_t removedSize = 0;
  uint64_t removedFee = 0;
  ASSERT_TRUE(pool.take_tx(
      getObjectHash(keptByBlock), removed, removedSize, removedFee));
  ASSERT_EQ(getObjectHash(keptByBlock), getObjectHash(removed));

  tx_verification_context conflictContext =
      boost::value_initialized<tx_verification_context>();
  EXPECT_FALSE(pool.add_tx(laterConflict, conflictContext, false, 0));
  EXPECT_TRUE(conflictContext.m_verification_failed);
  EXPECT_FALSE(conflictContext.m_added_to_pool);
  EXPECT_FALSE(conflictContext.m_should_be_relayed);
  EXPECT_EQ(1u, pool.get_transactions_count());
}
