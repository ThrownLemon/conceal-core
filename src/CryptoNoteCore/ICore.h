// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <list>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

#include <CryptoNote.h>
#include "CryptoNoteCore/Difficulty.h"

#include "CryptoNoteCore/MessageQueue.h"
#include "CryptoNoteCore/BlockchainMessages.h"

namespace cn {

struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request;
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response;
struct NOTIFY_RESPONSE_GET_OBJECTS_request;
struct NOTIFY_REQUEST_GET_OBJECTS_request;

class Currency;
class IBlock;
class ICoreObserver;
struct Block;
struct block_verification_context;
struct BlockFullInfo;
struct BlockShortInfo;
struct core_stat_info;
struct i_cryptonote_protocol;
struct Transaction;
struct MultisignatureInput;
struct KeyInput;
struct TransactionPrefixInfo;
struct tx_verification_context;

// One spendable post-quantum (PqKeyOutput) output, as enumerated for the get_pq_outputs RPC so a
// wallet can assemble a PQ ring (CIP-0001 testnet PoC). Read-only projection of m_pqOutputs[amount].
struct PqOutputEntry {
  uint32_t globalIndex;          // position in m_pqOutputs[amount]
  std::vector<uint8_t> key;      // PqKeyOutput.key (PQ one-time public key)
  std::vector<uint8_t> kemCt;    // PqKeyOutput.kemCt (ML-KEM ciphertext)
  crypto::Hash txHash;           // hash of the containing transaction
  uint32_t height;               // block height of the containing transaction
  bool spendable;                // is_tx_spendtime_unlocked(unlockTime)
};

// One post-quantum DEPOSIT cell (PqMultisigOutput), as enumerated for the get_pq_multisig_outputs RPC
// so a wallet can find its own deposits (named-key match on keys[0]) and resolve the (amount,
// outputIndex, term, height, isUsed) a PQ withdrawal needs (CIP-0001 UPGRADE_HEIGHT_V9, Option 3).
// Read-only projection of m_pqMultisigOutputs[amount]; outputIndex is exactly the PqMultisigInput
// .outputIndex the consensus check resolves against.
struct PqMultisigOutputEntry {
  uint32_t outputIndex;                       // position in m_pqMultisigOutputs[amount] (== PqMultisigInput.outputIndex)
  std::vector<std::vector<uint8_t>> keys;     // PqMultisigOutput.keys (n ML-DSA-65 public keys)
  uint8_t requiredSignatureCount;             // m
  uint32_t term;                              // deposit term (0 = plain multisig; != 0 = deposit)
  crypto::Hash txHash;                        // hash of the containing transaction
  uint32_t height;                            // block height that created the cell
  bool isUsed;                                // already withdrawn (double-spend guard)
  bool spendable;                             // is_tx_spendtime_unlocked(unlockTime)
};

class ICore {
public:
  virtual ~ICore() {}

  virtual const Currency& currency() const = 0;

  virtual bool addObserver(ICoreObserver* observer) = 0;
  virtual bool removeObserver(ICoreObserver* observer) = 0;
  virtual bool saveBlockchain() = 0;

  virtual bool have_block(const crypto::Hash& id) = 0;
  virtual std::vector<crypto::Hash> buildSparseChain() = 0;
  virtual std::vector<crypto::Hash> buildSparseChain(const crypto::Hash& startBlockId) = 0;
  virtual bool get_stat_info(cn::core_stat_info& st_inf) = 0;
  virtual bool on_idle() = 0;
  virtual void pause_mining() = 0;
  virtual void update_block_template_and_resume_mining() = 0;
  virtual bool handle_incoming_block_blob(const cn::BinaryArray& block_blob, cn::block_verification_context& bvc, bool control_miner, bool relay_block) = 0;
  virtual bool handle_incoming_block(const Block& b, block_verification_context& bvc, bool control_miner, bool relay_block) = 0;
  virtual bool handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS_request& arg, NOTIFY_RESPONSE_GET_OBJECTS_request& rsp) = 0; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  virtual void on_synchronized() = 0;
  virtual size_t addChain(const std::vector<const IBlock*>& chain) = 0;

  virtual void get_blockchain_top(uint32_t& height, crypto::Hash& top_id) = 0;
  virtual std::vector<crypto::Hash> findBlockchainSupplement(const std::vector<crypto::Hash>& remoteBlockIds, size_t maxCount,
    uint32_t& totalBlockCount, uint32_t& startBlockIndex) = 0;
  virtual bool get_random_outs_for_amounts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response& res) = 0;
  virtual bool get_tx_outputs_gindexs(const crypto::Hash& tx_id, std::vector<uint32_t>& indexs) = 0;
  virtual bool getOutByMSigGIndex(uint64_t amount, uint64_t gindex, MultisignatureOutput& out) = 0;
  virtual i_cryptonote_protocol* get_protocol() = 0;
  virtual bool handle_incoming_tx(const BinaryArray& tx_blob, tx_verification_context& tvc, bool keeped_by_block) = 0; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  virtual std::vector<Transaction> getPoolTransactions() = 0;
  virtual bool getPoolTransaction(const crypto::Hash &tx_hash, Transaction &transaction) = 0;
  virtual bool getPoolChanges(const crypto::Hash& tailBlockId, const std::vector<crypto::Hash>& knownTxsIds,
                              std::vector<Transaction>& addedTxs, std::vector<crypto::Hash>& deletedTxsIds) = 0;
  virtual bool getPoolChangesLite(const crypto::Hash& tailBlockId, const std::vector<crypto::Hash>& knownTxsIds,
                              std::vector<TransactionPrefixInfo>& addedTxs, std::vector<crypto::Hash>& deletedTxsIds) = 0;
  virtual void getPoolChanges(const std::vector<crypto::Hash>& knownTxsIds, std::vector<Transaction>& addedTxs,
                              std::vector<crypto::Hash>& deletedTxsIds) = 0;
  virtual bool queryBlocks(const std::vector<crypto::Hash>& block_ids, uint64_t timestamp,
    uint32_t& start_height, uint32_t& current_height, uint32_t& full_offset, std::vector<BlockFullInfo>& entries) = 0;
  virtual bool queryBlocksLite(const std::vector<crypto::Hash>& block_ids, uint64_t timestamp,
    uint32_t& start_height, uint32_t& current_height, uint32_t& full_offset, std::vector<BlockShortInfo>& entries) = 0;

  virtual crypto::Hash getBlockIdByHeight(uint32_t height) = 0;
  virtual bool getBlockByHash(const crypto::Hash &h, Block &blk) = 0;
  virtual bool getBlockHeight(const crypto::Hash& blockId, uint32_t& blockHeight) = 0;
  virtual void getTransactions(const std::vector<crypto::Hash>& txs_ids, std::list<Transaction>& txs, std::list<crypto::Hash>& missed_txs, bool checkTxPool = false) = 0;
  virtual bool getTransactionsWithOutputGlobalIndexes(const std::vector<crypto::Hash>& txs_ids, std::list<crypto::Hash>& missed_txs, std::vector<std::pair<Transaction, std::vector<uint32_t>>>& txs) = 0;
  virtual bool getBackwardBlocksSizes(uint32_t fromHeight, std::vector<size_t>& sizes, size_t count) = 0;
  virtual bool getBlockSize(const crypto::Hash& hash, size_t& size) = 0;
  virtual bool getAlreadyGeneratedCoins(const crypto::Hash& hash, uint64_t& generatedCoins) = 0;
  virtual bool getBlockReward(size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint32_t height,
                              uint64_t& reward, int64_t& emissionChange) = 0;
  virtual bool scanOutputkeysForIndices(const KeyInput& txInToKey, std::list<std::pair<crypto::Hash, size_t>>& outputReferences) = 0;
  virtual bool getBlockDifficulty(uint32_t height, difficulty_type& difficulty) = 0;
  virtual bool getBlockTimestamp(uint32_t height, uint64_t &timestamp) = 0;
  virtual bool getBlockContainingTx(const crypto::Hash& txId, crypto::Hash& blockId, uint32_t& blockHeight) = 0;
  virtual bool getMultisigOutputReference(const MultisignatureInput& txInMultisig, std::pair<crypto::Hash, size_t>& outputReference) = 0;
  // Read-only: enumerate spendable PqKeyOutputs indexed under 'amount' (for PQ ring assembly). Paginated
  // by bucket position: emits [startIndex, startIndex + effectiveLimit), effectiveLimit = (limit == 0 ?
  // bucket.size() : limit); nextIndex = one past the last emitted entry; truncated = more entries remain.
  virtual bool getPqOutputs(uint64_t amount, uint32_t startIndex, uint32_t limit, std::vector<PqOutputEntry>& outs, uint32_t& nextIndex, bool& truncated) = 0;
  // Read-only: enumerate PqMultisigOutputs (PQ deposit cells) indexed under 'amount' (so a wallet can
  // find its deposits by named-key match and resolve the withdrawal's (outputIndex, term, isUsed)).
  // Paginated identically to getPqOutputs.
  virtual bool getPqMultisigOutputs(uint64_t amount, uint32_t startIndex, uint32_t limit, std::vector<PqMultisigOutputEntry>& outs, uint32_t& nextIndex, bool& truncated) = 0;
  virtual bool getTransaction(const crypto::Hash &id, Transaction &tx, bool checkTxPool = false) = 0;
  virtual bool getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions) = 0;
  virtual bool getOrphanBlocksByHeight(uint32_t height, std::vector<Block>& blocks) = 0;
  virtual bool getBlocksByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t blocksNumberLimit, std::vector<Block>& blocks, uint32_t& blocksNumberWithinTimestamps) = 0;
  virtual bool getPoolTransactionsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t transactionsNumberLimit, std::vector<Transaction>& transactions, uint64_t& transactionsNumberWithinTimestamps) = 0;
  virtual bool getTransactionsByPaymentId(const crypto::Hash& paymentId, std::vector<Transaction>& transactions) = 0;

  virtual std::unique_ptr<IBlock> getBlock(const crypto::Hash& blocksId) = 0;
  virtual bool handleIncomingTransaction(const Transaction& tx, const crypto::Hash& txHash, size_t blobSize, tx_verification_context& tvc, bool keptByBlock, uint32_t height) = 0;
  virtual std::error_code executeLocked(const std::function<std::error_code()>& func) = 0;

  virtual bool addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) = 0;
  virtual bool removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) = 0;
};

} //namespace cn
