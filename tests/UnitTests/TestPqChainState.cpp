// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>

#include "Blockchain/Checkpoints.h"
#include "Common/StringTools.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/PqDepositBuilder.h"
#include "Logging/ConsoleLogger.h"
#include "Wallet/PqAccount.h"
#include "pow/mining/GpuMinerConfig.hpp"
#include "pq_testnet_kem_keypair.h"

using namespace cn;

namespace
{
  crypto::SecretKey seedFromByte(uint8_t value)
  {
    crypto::SecretKey seed;
    std::memset(&seed, value, sizeof(seed));
    return seed;
  }

  std::vector<uint8_t> testnetKemSecret()
  {
    return std::vector<uint8_t>(
        PQ_TESTNET_KEM_SK,
        PQ_TESTNET_KEM_SK + sizeof(PQ_TESTNET_KEM_SK));
  }

  std::vector<uint8_t> testnetKemPublic()
  {
    return std::vector<uint8_t>(
        PQ_TESTNET_KEM_PK,
        PQ_TESTNET_KEM_PK + sizeof(PQ_TESTNET_KEM_PK));
  }

  PqRingMember ringMember(const PqOutputEntry &entry)
  {
    PqRingMember member;
    member.globalIndex = entry.globalIndex;
    member.key = entry.key;
    member.kemCt = entry.kemCt;
    return member;
  }

  bool samePqOutputs(const std::vector<PqOutputEntry> &left,
                     const std::vector<PqOutputEntry> &right)
  {
    if (left.size() != right.size())
    {
      return false;
    }

    for (size_t i = 0; i < left.size(); ++i)
    {
      if (left[i].globalIndex != right[i].globalIndex ||
          left[i].key != right[i].key ||
          left[i].kemCt != right[i].kemCt ||
          left[i].txHash != right[i].txHash ||
          left[i].height != right[i].height ||
          left[i].spendable != right[i].spendable)
      {
        return false;
      }
    }

    return true;
  }

  bool samePqMultisigOutputs(const std::vector<PqMultisigOutputEntry> &left,
                             const std::vector<PqMultisigOutputEntry> &right)
  {
    if (left.size() != right.size())
    {
      return false;
    }

    for (size_t i = 0; i < left.size(); ++i)
    {
      if (left[i].outputIndex != right[i].outputIndex ||
          left[i].keys != right[i].keys ||
          left[i].requiredSignatureCount != right[i].requiredSignatureCount ||
          left[i].term != right[i].term ||
          left[i].txHash != right[i].txHash ||
          left[i].height != right[i].height ||
          left[i].isUsed != right[i].isUsed ||
          left[i].spendable != right[i].spendable)
      {
        return false;
      }
    }

    return true;
  }

  class PqChainState : public ::testing::Test
  {
  protected:
    PqChainState()
        : builder(logger),
          currency(builder.testnet(true)
                       .upgradeHeightV10(1)
                       .depositMinAmount(1000)
                       .depositMinTerm(1)
                       .depositMaxTerm(10)
                       .depositMinTermV3(1)
                       .depositMaxTermV3(10)
                       .depositMaxTermV1(10)
                       .depositHeightV3(0)
                       .depositHeightV4(0)
                       .currency())
    {
    }

    void SetUp() override
    {
      dataDir = boost::filesystem::temp_directory_path() /
                boost::filesystem::unique_path("ccx-pq-chain-state-main-%%%%%%%%");
      forkDataDir = boost::filesystem::temp_directory_path() /
                    boost::filesystem::unique_path("ccx-pq-chain-state-fork-%%%%%%%%");

      boost::system::error_code ec;
      boost::filesystem::create_directories(dataDir, ec);
      ASSERT_FALSE(ec) << ec.message();
      boost::filesystem::create_directories(forkDataDir, ec);
      ASSERT_FALSE(ec) << ec.message();

      miner.generate();
      ASSERT_TRUE(startCoreAt(node, dataDir, false));
    }

    void TearDown() override
    {
      EXPECT_TRUE(stopCoreAt(forkNode));
      EXPECT_TRUE(stopCoreAt(node));

      boost::system::error_code ec;
      boost::filesystem::remove_all(forkDataDir, ec);
      boost::filesystem::remove_all(dataDir, ec);
    }

    bool startCoreAt(std::unique_ptr<core> &target,
                     const boost::filesystem::path &directory,
                     bool loadExisting)
    {
      if (target)
      {
        return false;
      }

      CoreConfig config;
      config.configFolder = directory.string();
      config.configFolderDefaulted = false;
      config.testnet = true;

      MinerConfig minerConfig;
      GpuMinerConfig gpuMinerConfig;
      target.reset(new core(currency, nullptr, logger, false));

      Checkpoints genesisCheckpoint(logger);
      if (!genesisCheckpoint.add_checkpoint(
              0, common::podToHex(get_block_hash(currency.genesisBlock()))))
      {
        target.reset();
        return false;
      }
      target->set_checkpoints(std::move(genesisCheckpoint));

      if (!target->init(config, minerConfig, gpuMinerConfig, -1, loadExisting))
      {
        target.reset();
        return false;
      }
      return true;
    }

    bool stopCoreAt(std::unique_ptr<core> &target)
    {
      if (!target)
      {
        return true;
      }

      const bool stopped = target->deinit();
      target.reset();
      return stopped;
    }

    void startCore(bool loadExisting)
    {
      ASSERT_TRUE(startCoreAt(node, dataDir, loadExisting));
    }

    void stopCore()
    {
      EXPECT_TRUE(stopCoreAt(node));
    }

    bool submitBlock(core &target,
                     const Block &block,
                     bool trustProofOfWork,
                     block_verification_context &bvc)
    {
      if (trustProofOfWork)
      {
        const uint32_t height = get_block_height(block);
        if (!target.addCheckpoint(height, common::podToHex(get_block_hash(block))))
        {
          return false;
        }
      }

      bvc = boost::value_initialized<block_verification_context>();
      return target.handle_incoming_block_blob(
          toBinaryArray(block), bvc, false, false);
    }

    bool mineNextBlock(core &target,
                       Block &block,
                       const crypto::Hash *expectedTransaction = nullptr,
                       bool trustProofOfWork = false,
                       uint64_t forcedTimestamp = 0,
                       const BinaryArray &extraNonce = BinaryArray())
    {
      difficulty_type difficulty = 0;
      uint32_t height = 0;
      if (!target.get_block_template(
              block, miner.getAccountKeys().address, difficulty, height, extraNonce))
      {
        return false;
      }

      if (forcedTimestamp != 0)
      {
        block.timestamp = forcedTimestamp;
      }

      if (expectedTransaction != nullptr &&
          std::find(block.transactionHashes.begin(), block.transactionHashes.end(),
                    *expectedTransaction) == block.transactionHashes.end())
      {
        return false;
      }

      if (!trustProofOfWork)
      {
        crypto::cn_context context;
        while (!Miner::find_nonce_for_given_block(context, block, difficulty))
        {
          ++block.timestamp;
        }
      }

      block_verification_context bvc = boost::value_initialized<block_verification_context>();
      if (!submitBlock(target, block, trustProofOfWork, bvc))
      {
        return false;
      }

      return bvc.m_added_to_main_chain && !bvc.m_verification_failed;
    }

    bool mineNextBlock(const crypto::Hash *expectedTransaction = nullptr,
                       bool trustProofOfWork = false)
    {
      Block ignored;
      return mineNextBlock(*node, ignored, expectedTransaction, trustProofOfWork);
    }

    bool submitTransaction(core &target,
                           const Transaction &tx,
                           bool keptByBlock,
                           tx_verification_context &tvc)
    {
      tvc = boost::value_initialized<tx_verification_context>();
      return target.handle_incoming_tx(toBinaryArray(tx), tvc, keptByBlock);
    }

    bool submitTransaction(const Transaction &tx)
    {
      const size_t oldPoolSize = node->get_pool_transactions_count();
      tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
      const bool handled = submitTransaction(*node, tx, false, tvc);
      return handled && !tvc.m_verification_failed &&
             tvc.m_added_to_pool &&
             node->get_pool_transactions_count() == oldPoolSize + 1;
    }

    bool queryPqOutputs(core &target,
                        uint64_t amount,
                        std::vector<PqOutputEntry> &all)
    {
      all.clear();
      uint32_t startIndex = 0;

      for (;;)
      {
        std::vector<PqOutputEntry> page;
        uint32_t nextIndex = 0;
        bool truncated = false;
        if (!target.getPqOutputs(amount, startIndex, 2, page, nextIndex, truncated))
        {
          return false;
        }

        all.insert(all.end(), page.begin(), page.end());
        if (!truncated)
        {
          return true;
        }
        if (nextIndex <= startIndex)
        {
          return false;
        }
        startIndex = nextIndex;
      }
    }

    bool queryPqOutputs(uint64_t amount, std::vector<PqOutputEntry> &all)
    {
      return queryPqOutputs(*node, amount, all);
    }

    bool queryPqMultisigOutputs(
        core &target,
        uint64_t amount,
        std::vector<PqMultisigOutputEntry> &all)
    {
      all.clear();
      uint32_t startIndex = 0;

      for (;;)
      {
        std::vector<PqMultisigOutputEntry> page;
        uint32_t nextIndex = 0;
        bool truncated = false;
        if (!target.getPqMultisigOutputs(
                amount, startIndex, 1, page, nextIndex, truncated))
        {
          return false;
        }

        all.insert(all.end(), page.begin(), page.end());
        if (!truncated)
        {
          return true;
        }
        if (nextIndex <= startIndex)
        {
          return false;
        }
        startIndex = nextIndex;
      }
    }

    bool queryPqMultisigOutputs(
        uint64_t amount,
        std::vector<PqMultisigOutputEntry> &all)
    {
      return queryPqMultisigOutputs(*node, amount, all);
    }

    logging::ConsoleLogger logger;
    CurrencyBuilder builder;
    Currency currency;
    boost::filesystem::path dataDir;
    boost::filesystem::path forkDataDir;
    AccountBase miner;
    std::unique_ptr<core> node;
    std::unique_ptr<core> forkNode;
  };
}

TEST_F(PqChainState, CompetingForkWithDifferentPqSpendsReorgsAndPersistsState)
{
  ASSERT_TRUE(startCoreAt(forkNode, forkDataDir, false));

  uint64_t commonTimestamp = currency.genesisBlock().timestamp;
  for (size_t i = 0; i < currency.minedMoneyUnlockWindow() + 2; ++i)
  {
    commonTimestamp += currency.difficultyTarget();
    Block block;
    ASSERT_TRUE(mineNextBlock(
        *node, block, nullptr, true, commonTimestamp));

    block_verification_context forkBvc =
        boost::value_initialized<block_verification_context>();
    ASSERT_TRUE(submitBlock(*forkNode, block, true, forkBvc));
    ASSERT_TRUE(forkBvc.m_added_to_main_chain);
    ASSERT_FALSE(forkBvc.m_verification_failed);
  }

  uint32_t commonHeightA = 0;
  uint32_t commonHeightB = 0;
  crypto::Hash commonTipA = NULL_HASH;
  crypto::Hash commonTipB = NULL_HASH;
  node->get_blockchain_top(commonHeightA, commonTipA);
  forkNode->get_blockchain_top(commonHeightB, commonTipB);
  ASSERT_EQ(commonHeightA, commonHeightB);
  ASSERT_EQ(commonTipA, commonTipB);

  std::vector<PqOutputEntry> fundingOutputs;
  ASSERT_TRUE(queryPqOutputs(PQ_TESTNET_COINBASE_AMOUNT, fundingOutputs));
  ASSERT_GE(fundingOutputs.size(), 2u);

  const uint64_t depositAmount = PQ_TESTNET_COINBASE_AMOUNT / 2;
  const uint64_t fee = currency.minimumFee();
  const uint32_t term = 1;

  const PqAccountKeys mainKeys =
      PqAccount::generateFromSeed(seedFromByte(0x41));
  PqDepositRequest mainRequest;
  mainRequest.amount = depositAmount;
  mainRequest.fee = fee;
  mainRequest.term = term;
  mainRequest.inputAmount = PQ_TESTNET_COINBASE_AMOUNT;
  mainRequest.ring.push_back(ringMember(fundingOutputs[0]));
  mainRequest.ring.push_back(ringMember(fundingOutputs[1]));
  mainRequest.signerGlobalIndex = fundingOutputs[0].globalIndex;
  mainRequest.kemSecretKey = testnetKemSecret();
  mainRequest.depositDsaPubKey = mainKeys.dsaPublicKey;
  mainRequest.changeKemPubKey = testnetKemPublic();

  std::string error;
  Transaction mainDepositTx;
  ASSERT_TRUE(buildPqDepositTransaction(mainRequest, mainDepositTx, error))
      << error;
  const crypto::Hash mainDepositHash = getObjectHash(mainDepositTx);
  ASSERT_TRUE(submitTransaction(mainDepositTx));

  uint64_t mainTimestamp = commonTimestamp + currency.difficultyTarget();
  Block mainDepositBlock;
  ASSERT_TRUE(mineNextBlock(
      *node, mainDepositBlock, &mainDepositHash, false, mainTimestamp));

  std::vector<PqMultisigOutputEntry> mainCells;
  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, mainCells));
  ASSERT_EQ(1u, mainCells.size());
  ASSERT_EQ(mainDepositHash, mainCells[0].txHash);
  ASSERT_FALSE(mainCells[0].isUsed);

  while (node->get_current_blockchain_height() - 1 <
         static_cast<uint64_t>(mainCells[0].height) + term)
  {
    mainTimestamp += currency.difficultyTarget();
    Block maturityBlock;
    ASSERT_TRUE(mineNextBlock(
        *node, maturityBlock, nullptr, false, mainTimestamp));
  }

  const uint32_t withdrawalHeight =
      node->get_current_blockchain_height();
  const uint64_t interest =
      currency.calculateInterest(
          depositAmount, term, withdrawalHeight - term);
  const uint64_t payoutAmount = depositAmount + interest;

  PqWithdrawRequest withdrawRequest;
  withdrawRequest.amount = depositAmount;
  withdrawRequest.outputIndex = mainCells[0].outputIndex;
  withdrawRequest.term = term;
  withdrawRequest.requiredSignatureCount = 1;
  withdrawRequest.interest = interest;
  withdrawRequest.signingSecretKeys.push_back(mainKeys.dsaSecretKey);
  withdrawRequest.payoutKemPubKey = testnetKemPublic();

  Transaction mainWithdrawTx;
  ASSERT_TRUE(buildPqWithdrawTransaction(
      withdrawRequest, mainWithdrawTx, error)) << error;
  const crypto::Hash mainWithdrawHash = getObjectHash(mainWithdrawTx);
  ASSERT_TRUE(submitTransaction(mainWithdrawTx));

  mainTimestamp += currency.difficultyTarget();
  Block mainWithdrawBlock;
  ASSERT_TRUE(mineNextBlock(
      *node, mainWithdrawBlock, &mainWithdrawHash, false, mainTimestamp));

  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, mainCells));
  ASSERT_EQ(1u, mainCells.size());
  ASSERT_TRUE(mainCells[0].isUsed);

  std::vector<PqOutputEntry> mainPayouts;
  ASSERT_TRUE(queryPqOutputs(payoutAmount, mainPayouts));
  ASSERT_EQ(1u, mainPayouts.size());

  uint32_t mainTipHeight = 0;
  crypto::Hash mainTipHash = NULL_HASH;
  node->get_blockchain_top(mainTipHeight, mainTipHash);

  const PqAccountKeys forkKeys =
      PqAccount::generateFromSeed(seedFromByte(0x42));
  PqDepositRequest forkRequest = mainRequest;
  forkRequest.depositDsaPubKey = forkKeys.dsaPublicKey;

  Transaction forkDepositTx;
  ASSERT_TRUE(buildPqDepositTransaction(
      forkRequest, forkDepositTx, error)) << error;
  const crypto::Hash forkDepositHash = getObjectHash(forkDepositTx);
  ASSERT_NE(mainDepositHash, forkDepositHash);

  tx_verification_context forkTvc =
      boost::value_initialized<tx_verification_context>();
  ASSERT_TRUE(submitTransaction(*forkNode, forkDepositTx, false, forkTvc));
  ASSERT_FALSE(forkTvc.m_verification_failed);
  ASSERT_TRUE(forkTvc.m_added_to_pool);

  std::vector<Block> forkBlocks;
  uint64_t forkTimestamp = commonTimestamp + currency.difficultyTarget();
  Block forkDepositBlock;
  ASSERT_TRUE(mineNextBlock(
      *forkNode, forkDepositBlock, &forkDepositHash, false, forkTimestamp));
  forkBlocks.push_back(forkDepositBlock);

  while (forkNode->get_current_blockchain_height() <=
         node->get_current_blockchain_height())
  {
    forkTimestamp += currency.difficultyTarget();
    Block forkBlock;
    ASSERT_TRUE(mineNextBlock(
        *forkNode, forkBlock, nullptr, false, forkTimestamp));
    forkBlocks.push_back(forkBlock);
  }

  std::vector<PqOutputEntry> expectedForkFunding;
  std::vector<PqOutputEntry> expectedForkPayouts;
  std::vector<PqMultisigOutputEntry> expectedForkCells;
  ASSERT_TRUE(queryPqOutputs(
      *forkNode, PQ_TESTNET_COINBASE_AMOUNT, expectedForkFunding));
  ASSERT_TRUE(queryPqOutputs(
      *forkNode, payoutAmount, expectedForkPayouts));
  ASSERT_TRUE(queryPqMultisigOutputs(
      *forkNode, depositAmount, expectedForkCells));
  ASSERT_EQ(1u, expectedForkCells.size());
  ASSERT_EQ(forkDepositHash, expectedForkCells[0].txHash);
  ASSERT_FALSE(expectedForkCells[0].isUsed);
  ASSERT_TRUE(expectedForkPayouts.empty());

  tx_verification_context keptTvc =
      boost::value_initialized<tx_verification_context>();
  ASSERT_TRUE(submitTransaction(*node, forkDepositTx, true, keptTvc));
  ASSERT_FALSE(keptTvc.m_verification_failed);
  ASSERT_TRUE(keptTvc.m_added_to_pool);
  ASSERT_TRUE(keptTvc.m_verification_impossible);
  ASSERT_FALSE(keptTvc.m_should_be_relayed);

  for (size_t i = 0; i + 1 < forkBlocks.size(); ++i)
  {
    block_verification_context bvc =
        boost::value_initialized<block_verification_context>();
    ASSERT_TRUE(submitBlock(*node, forkBlocks[i], false, bvc));
    ASSERT_FALSE(bvc.m_verification_failed);
    ASSERT_FALSE(bvc.m_added_to_main_chain);
    ASSERT_FALSE(bvc.m_switched_to_alt_chain);

    uint32_t unchangedHeight = 0;
    crypto::Hash unchangedHash = NULL_HASH;
    node->get_blockchain_top(unchangedHeight, unchangedHash);
    ASSERT_EQ(mainTipHeight, unchangedHeight);
    ASSERT_EQ(mainTipHash, unchangedHash);
  }

  uint32_t forkTipHeight = 0;
  crypto::Hash forkTipHash = NULL_HASH;
  forkNode->get_blockchain_top(forkTipHeight, forkTipHash);

  block_verification_context switchBvc =
      boost::value_initialized<block_verification_context>();
  ASSERT_TRUE(submitBlock(
      *node, forkBlocks.back(), false, switchBvc))
      << "main_tip=" << common::podToHex(mainTipHash)
      << " fork_tip=" << common::podToHex(forkTipHash);
  ASSERT_FALSE(switchBvc.m_verification_failed);
  ASSERT_TRUE(switchBvc.m_added_to_main_chain);
  ASSERT_TRUE(switchBvc.m_switched_to_alt_chain);

  uint32_t switchedHeight = 0;
  crypto::Hash switchedHash = NULL_HASH;
  node->get_blockchain_top(switchedHeight, switchedHash);
  ASSERT_EQ(forkTipHeight, switchedHeight);
  ASSERT_EQ(forkTipHash, switchedHash);

  std::vector<PqMultisigOutputEntry> switchedCells;
  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, switchedCells));
  ASSERT_EQ(1u, switchedCells.size());
  EXPECT_EQ(forkDepositHash, switchedCells[0].txHash);
  EXPECT_EQ(forkKeys.dsaPublicKey, switchedCells[0].keys[0]);
  EXPECT_FALSE(switchedCells[0].isUsed);

  std::vector<PqOutputEntry> switchedFunding;
  std::vector<PqOutputEntry> switchedPayouts;
  ASSERT_TRUE(queryPqOutputs(
      PQ_TESTNET_COINBASE_AMOUNT, switchedFunding));
  ASSERT_TRUE(queryPqOutputs(payoutAmount, switchedPayouts));
  EXPECT_TRUE(samePqOutputs(
      expectedForkFunding, switchedFunding));
  EXPECT_TRUE(samePqOutputs(
      expectedForkPayouts, switchedPayouts));
  EXPECT_TRUE(samePqMultisigOutputs(
      expectedForkCells, switchedCells));

  Block postSwitchTemplate;
  difficulty_type postSwitchDifficulty = 0;
  uint32_t postSwitchHeight = 0;
  ASSERT_TRUE(node->get_block_template(
      postSwitchTemplate,
      miner.getAccountKeys().address,
      postSwitchDifficulty,
      postSwitchHeight,
      BinaryArray()));
  EXPECT_EQ(postSwitchTemplate.transactionHashes.end(),
            std::find(postSwitchTemplate.transactionHashes.begin(),
                      postSwitchTemplate.transactionHashes.end(),
                      mainDepositHash));
  EXPECT_EQ(postSwitchTemplate.transactionHashes.end(),
            std::find(postSwitchTemplate.transactionHashes.begin(),
                      postSwitchTemplate.transactionHashes.end(),
                      mainWithdrawHash));

  tx_verification_context disconnectedDepositTvc =
      boost::value_initialized<tx_verification_context>();
  ASSERT_TRUE(submitTransaction(
      *node, mainDepositTx, false, disconnectedDepositTvc));
  EXPECT_FALSE(disconnectedDepositTvc.m_should_be_relayed);
  EXPECT_FALSE(disconnectedDepositTvc.m_added_to_pool);

  tx_verification_context disconnectedWithdrawTvc =
      boost::value_initialized<tx_verification_context>();
  ASSERT_TRUE(submitTransaction(
      *node, mainWithdrawTx, false, disconnectedWithdrawTvc));
  EXPECT_FALSE(disconnectedWithdrawTvc.m_should_be_relayed);
  EXPECT_FALSE(disconnectedWithdrawTvc.m_added_to_pool);

  const PqAccountKeys thirdKeys =
      PqAccount::generateFromSeed(seedFromByte(0x43));
  PqDepositRequest thirdRequest = mainRequest;
  thirdRequest.depositDsaPubKey = thirdKeys.dsaPublicKey;
  Transaction thirdTx;
  ASSERT_TRUE(buildPqDepositTransaction(
      thirdRequest, thirdTx, error)) << error;
  EXPECT_FALSE(submitTransaction(thirdTx));

  std::vector<PqOutputEntry> fundingBeforeRestart;
  ASSERT_TRUE(queryPqOutputs(
      PQ_TESTNET_COINBASE_AMOUNT, fundingBeforeRestart));
  const std::vector<PqMultisigOutputEntry> cellsBeforeRestart =
      switchedCells;

  ASSERT_TRUE(stopCoreAt(node));
  ASSERT_TRUE(startCoreAt(node, dataDir, true));

  uint32_t restartedHeight = 0;
  crypto::Hash restartedHash = NULL_HASH;
  node->get_blockchain_top(restartedHeight, restartedHash);
  EXPECT_EQ(forkTipHeight, restartedHeight);
  EXPECT_EQ(forkTipHash, restartedHash);

  std::vector<PqOutputEntry> fundingAfterRestart;
  std::vector<PqOutputEntry> payoutAfterRestart;
  std::vector<PqMultisigOutputEntry> cellsAfterRestart;
  ASSERT_TRUE(queryPqOutputs(
      PQ_TESTNET_COINBASE_AMOUNT, fundingAfterRestart));
  ASSERT_TRUE(queryPqOutputs(payoutAmount, payoutAfterRestart));
  ASSERT_TRUE(queryPqMultisigOutputs(
      depositAmount, cellsAfterRestart));

  EXPECT_TRUE(samePqOutputs(
      fundingBeforeRestart, fundingAfterRestart));
  EXPECT_TRUE(samePqMultisigOutputs(
      cellsBeforeRestart, cellsAfterRestart));
  EXPECT_TRUE(payoutAfterRestart.empty());
  EXPECT_FALSE(submitTransaction(thirdTx));
}

TEST_F(PqChainState, FailedAlternativePushRestoresMainPqState)
{
  ASSERT_TRUE(startCoreAt(forkNode, forkDataDir, false));

  uint64_t timestamp = currency.genesisBlock().timestamp;
  for (size_t i = 0; i < currency.minedMoneyUnlockWindow() + 2; ++i)
  {
    timestamp += currency.difficultyTarget();
    Block block;
    ASSERT_TRUE(mineNextBlock(*node, block, nullptr, true, timestamp));

    block_verification_context forkBvc =
        boost::value_initialized<block_verification_context>();
    ASSERT_TRUE(submitBlock(*forkNode, block, true, forkBvc));
    ASSERT_TRUE(forkBvc.m_added_to_main_chain);
    ASSERT_FALSE(forkBvc.m_verification_failed);
  }

  for (size_t i = 0; i < 2; ++i)
  {
    timestamp += currency.difficultyTarget();
    Block mainBlock;
    ASSERT_TRUE(mineNextBlock(
        *node, mainBlock, nullptr, false, timestamp));
  }

  uint32_t mainHeight = 0;
  crypto::Hash mainTip = NULL_HASH;
  node->get_blockchain_top(mainHeight, mainTip);

  std::vector<PqOutputEntry> mainOutputs;
  ASSERT_TRUE(queryPqOutputs(PQ_TESTNET_COINBASE_AMOUNT, mainOutputs));
  ASSERT_EQ(0u, node->get_pool_transactions_count());

  const BinaryArray forkExtraNonce(1, 0x42);
  std::vector<Block> forkBlocks;
  uint64_t forkTimestamp =
      currency.genesisBlock().timestamp +
      (currency.minedMoneyUnlockWindow() + 3) * currency.difficultyTarget();
  for (size_t i = 0; i < 3; ++i)
  {
    Block block;
    ASSERT_TRUE(mineNextBlock(
        *forkNode, block, nullptr, false, forkTimestamp, forkExtraNonce));
    forkBlocks.push_back(block);
    forkTimestamp += currency.difficultyTarget();
  }

  Transaction missingTx = boost::value_initialized<Transaction>();
  missingTx.version = TRANSACTION_VERSION_4;
  missingTx.extra.push_back(0xa5);
  const crypto::Hash missingTxHash = getObjectHash(missingTx);
  forkBlocks[1].transactionHashes.push_back(missingTxHash);

  crypto::cn_context context;
  while (!Miner::find_nonce_for_given_block(
      context, forkBlocks[1], parameters::TESTNET_PQ_POC_DIFFICULTY))
  {
    ++forkBlocks[1].timestamp;
  }

  forkBlocks[2].previousBlockHash = get_block_hash(forkBlocks[1]);
  if (forkBlocks[2].timestamp <= forkBlocks[1].timestamp)
  {
    forkBlocks[2].timestamp =
        forkBlocks[1].timestamp + currency.difficultyTarget();
  }
  while (!Miner::find_nonce_for_given_block(
      context, forkBlocks[2], parameters::TESTNET_PQ_POC_DIFFICULTY))
  {
    ++forkBlocks[2].timestamp;
  }

  for (size_t i = 0; i < 2; ++i)
  {
    block_verification_context bvc =
        boost::value_initialized<block_verification_context>();
    ASSERT_TRUE(submitBlock(*node, forkBlocks[i], false, bvc));
    ASSERT_FALSE(bvc.m_verification_failed);
    ASSERT_FALSE(bvc.m_added_to_main_chain);
  }

  block_verification_context failedSwitch =
      boost::value_initialized<block_verification_context>();
  EXPECT_TRUE(submitBlock(
      *node, forkBlocks[2], false, failedSwitch));
  EXPECT_TRUE(failedSwitch.m_verification_failed);
  EXPECT_FALSE(failedSwitch.m_added_to_main_chain);

  uint32_t restoredHeight = 0;
  crypto::Hash restoredTip = NULL_HASH;
  node->get_blockchain_top(restoredHeight, restoredTip);
  EXPECT_EQ(mainHeight, restoredHeight);
  EXPECT_EQ(mainTip, restoredTip);
  EXPECT_EQ(0u, node->get_pool_transactions_count());

  std::vector<PqOutputEntry> restoredOutputs;
  ASSERT_TRUE(queryPqOutputs(
      PQ_TESTNET_COINBASE_AMOUNT, restoredOutputs));
  EXPECT_TRUE(samePqOutputs(mainOutputs, restoredOutputs));

  stopCore();
  startCore(true);

  uint32_t restartedHeight = 0;
  crypto::Hash restartedTip = NULL_HASH;
  node->get_blockchain_top(restartedHeight, restartedTip);
  EXPECT_EQ(mainHeight, restartedHeight);
  EXPECT_EQ(mainTip, restartedTip);

  std::vector<PqOutputEntry> restartedOutputs;
  ASSERT_TRUE(queryPqOutputs(
      PQ_TESTNET_COINBASE_AMOUNT, restartedOutputs));
  EXPECT_TRUE(samePqOutputs(mainOutputs, restartedOutputs));
}

TEST_F(PqChainState, ConnectDisconnectAndMdbxRebuildPreservePqState)
{
  for (size_t i = 0; i < currency.minedMoneyUnlockWindow() + 2; ++i)
  {
    // These empty setup blocks exist only to mature two PQ coinbase outputs.
    // Trust their exact hashes so the regression remains fast; the deposit and
    // withdrawal blocks are above this checkpoint zone and verify real crypto.
    ASSERT_TRUE(mineNextBlock(nullptr, true));
  }

  std::vector<PqOutputEntry> fundingOutputs;
  ASSERT_TRUE(queryPqOutputs(PQ_TESTNET_COINBASE_AMOUNT, fundingOutputs));
  ASSERT_GE(fundingOutputs.size(), 2u);

  const uint64_t depositAmount = PQ_TESTNET_COINBASE_AMOUNT / 2;
  const uint64_t fee = currency.minimumFee();
  const uint32_t term = 1;
  const uint32_t beforeDepositTop = node->get_current_blockchain_height() - 1;

  const PqAccountKeys depositKeys =
      PqAccount::generateFromSeed(seedFromByte(0x31));
  PqDepositRequest depositRequest;
  depositRequest.amount = depositAmount;
  depositRequest.fee = fee;
  depositRequest.term = term;
  depositRequest.inputAmount = PQ_TESTNET_COINBASE_AMOUNT;
  depositRequest.ring.push_back(ringMember(fundingOutputs[0]));
  depositRequest.ring.push_back(ringMember(fundingOutputs[1]));
  depositRequest.signerGlobalIndex = fundingOutputs[0].globalIndex;
  depositRequest.kemSecretKey = testnetKemSecret();
  depositRequest.depositDsaPubKey = depositKeys.dsaPublicKey;
  depositRequest.changeKemPubKey = testnetKemPublic();

  Transaction depositTx;
  std::string error;
  ASSERT_TRUE(buildPqDepositTransaction(depositRequest, depositTx, error)) << error;
  const crypto::Hash depositHash = getObjectHash(depositTx);
  ASSERT_TRUE(submitTransaction(depositTx));
  ASSERT_TRUE(mineNextBlock(&depositHash));

  std::vector<PqMultisigOutputEntry> depositCells;
  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, depositCells));
  ASSERT_EQ(1u, depositCells.size());
  EXPECT_FALSE(depositCells[0].isUsed);
  EXPECT_EQ(depositKeys.dsaPublicKey, depositCells[0].keys[0]);

  std::vector<PqOutputEntry> fundingAfterDeposit;
  ASSERT_TRUE(queryPqOutputs(PQ_TESTNET_COINBASE_AMOUNT, fundingAfterDeposit));
  ASSERT_EQ(fundingOutputs.size() + 1, fundingAfterDeposit.size());

  ASSERT_TRUE(node->rollback_chain_to(beforeDepositTop));
  std::vector<PqMultisigOutputEntry> cellsAfterDepositRollback;
  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, cellsAfterDepositRollback));
  EXPECT_TRUE(cellsAfterDepositRollback.empty());

  std::vector<PqOutputEntry> fundingAfterDepositRollback;
  ASSERT_TRUE(queryPqOutputs(PQ_TESTNET_COINBASE_AMOUNT, fundingAfterDepositRollback));
  EXPECT_TRUE(samePqOutputs(fundingOutputs, fundingAfterDepositRollback));

  // Re-admission after rollback proves popTransaction removed the funding
  // nullifier from the chain spent set.
  ASSERT_TRUE(submitTransaction(depositTx));
  ASSERT_TRUE(mineNextBlock(&depositHash));
  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, depositCells));
  ASSERT_EQ(1u, depositCells.size());
  EXPECT_FALSE(depositCells[0].isUsed);

  while (node->get_current_blockchain_height() - 1 <
         static_cast<uint64_t>(depositCells[0].height) + term)
  {
    ASSERT_TRUE(mineNextBlock());
  }

  const uint32_t withdrawalHeight = node->get_current_blockchain_height();
  const uint64_t interest =
      currency.calculateInterest(depositAmount, term, withdrawalHeight - term);
  PqWithdrawRequest withdrawRequest;
  withdrawRequest.amount = depositAmount;
  withdrawRequest.outputIndex = depositCells[0].outputIndex;
  withdrawRequest.term = term;
  withdrawRequest.requiredSignatureCount = 1;
  withdrawRequest.interest = interest;
  withdrawRequest.signingSecretKeys.push_back(depositKeys.dsaSecretKey);
  withdrawRequest.payoutKemPubKey = testnetKemPublic();

  Transaction withdrawTx;
  ASSERT_TRUE(buildPqWithdrawTransaction(withdrawRequest, withdrawTx, error)) << error;
  const crypto::Hash withdrawHash = getObjectHash(withdrawTx);
  const uint32_t beforeWithdrawTop = node->get_current_blockchain_height() - 1;
  ASSERT_TRUE(submitTransaction(withdrawTx));
  ASSERT_TRUE(mineNextBlock(&withdrawHash));

  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, depositCells));
  ASSERT_EQ(1u, depositCells.size());
  EXPECT_TRUE(depositCells[0].isUsed);

  const uint64_t payoutAmount = depositAmount + interest;
  std::vector<PqOutputEntry> payoutBeforeRollback;
  ASSERT_TRUE(queryPqOutputs(payoutAmount, payoutBeforeRollback));
  ASSERT_EQ(1u, payoutBeforeRollback.size());

  ASSERT_TRUE(node->rollback_chain_to(beforeWithdrawTop));
  std::vector<PqMultisigOutputEntry> cellsAfterWithdrawRollback;
  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, cellsAfterWithdrawRollback));
  ASSERT_EQ(1u, cellsAfterWithdrawRollback.size());
  EXPECT_FALSE(cellsAfterWithdrawRollback[0].isUsed);

  std::vector<PqOutputEntry> payoutAfterRollback;
  ASSERT_TRUE(queryPqOutputs(payoutAmount, payoutAfterRollback));
  EXPECT_TRUE(payoutAfterRollback.empty());

  ASSERT_TRUE(submitTransaction(withdrawTx));
  ASSERT_TRUE(mineNextBlock(&withdrawHash));
  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, depositCells));
  ASSERT_EQ(1u, depositCells.size());
  EXPECT_TRUE(depositCells[0].isUsed);

  std::vector<PqOutputEntry> fundingBeforeRestart;
  std::vector<PqOutputEntry> changeBeforeRestart;
  std::vector<PqOutputEntry> payoutBeforeRestart;
  ASSERT_TRUE(queryPqOutputs(PQ_TESTNET_COINBASE_AMOUNT, fundingBeforeRestart));
  ASSERT_TRUE(queryPqOutputs(
      PQ_TESTNET_COINBASE_AMOUNT - depositAmount - fee, changeBeforeRestart));
  ASSERT_TRUE(queryPqOutputs(payoutAmount, payoutBeforeRestart));
  const std::vector<PqMultisigOutputEntry> cellsBeforeRestart = depositCells;

  stopCore();
  startCore(true);

  std::vector<PqOutputEntry> fundingAfterRestart;
  std::vector<PqOutputEntry> changeAfterRestart;
  std::vector<PqOutputEntry> payoutAfterRestart;
  std::vector<PqMultisigOutputEntry> cellsAfterRestart;
  ASSERT_TRUE(queryPqOutputs(PQ_TESTNET_COINBASE_AMOUNT, fundingAfterRestart));
  ASSERT_TRUE(queryPqOutputs(
      PQ_TESTNET_COINBASE_AMOUNT - depositAmount - fee, changeAfterRestart));
  ASSERT_TRUE(queryPqOutputs(payoutAmount, payoutAfterRestart));
  ASSERT_TRUE(queryPqMultisigOutputs(depositAmount, cellsAfterRestart));

  EXPECT_TRUE(samePqOutputs(fundingBeforeRestart, fundingAfterRestart));
  EXPECT_TRUE(samePqOutputs(changeBeforeRestart, changeAfterRestart));
  EXPECT_TRUE(samePqOutputs(payoutBeforeRestart, payoutAfterRestart));
  EXPECT_TRUE(samePqMultisigOutputs(cellsBeforeRestart, cellsAfterRestart));

  // This transaction has a different hash but spends the same funding output,
  // so rejection after restart proves rebuildMdbxIndex restored the nullifier.
  const PqAccountKeys conflictingKeys =
      PqAccount::generateFromSeed(seedFromByte(0x32));
  PqDepositRequest conflictingRequest = depositRequest;
  conflictingRequest.depositDsaPubKey = conflictingKeys.dsaPublicKey;
  Transaction conflictingTx;
  ASSERT_TRUE(buildPqDepositTransaction(
      conflictingRequest, conflictingTx, error)) << error;
  EXPECT_NE(depositHash, getObjectHash(conflictingTx));
  EXPECT_FALSE(submitTransaction(conflictingTx));
}
