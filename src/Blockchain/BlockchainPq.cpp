// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Post-quantum (CIP-0001 / UPGRADE_HEIGHT_V10) consensus input validation, ported faithfully from the
// monolithic Blockchain.cpp on pqc/testnet-poc into this MDBX fork. Three Blockchain methods:
//   * getTransactionPqSigningHash — the message every PQ signature in a tx signs (prefix with all
//     inline PQ signatures cleared).
//   * check_pq_tx_input          — resolve the ring's one-time keys from m_pqOutputs and verify the
//                                   lattice linkable ring signature (ccx_pq_verify) + nullifier bind.
//   * check_pq_multisig          — gather keys from the m_pqMultisigOutputs deposit cell and verify
//                                   the ML-DSA-65 (ccx_pq_multisig_verify) m-of-n signatures.
// State access is adapted to the fork (blocksAt(...) / transactionByIndex(...) instead of m_blocks[...]);
// the validation semantics are byte-for-byte the source's.

#include "Blockchain.h"

#include "CryptoNoteCore/CryptoNoteFormatUtils.h" // relative_output_offsets_to_absolute
#include "CryptoNoteCore/CryptoNoteTools.h"        // getObjectHash

#include "pq_ring_sig.h" // ccx-pqc FFI

namespace cn
{
  crypto::Hash Blockchain::getTransactionPqSigningHash(const Transaction &tx) const
  {
    // The PQ ring signature signs the tx prefix with every PqKeyInput.ringSig cleared (a signature
    // cannot commit to itself). Everything else in the prefix — amounts, output keys, nullifiers —
    // remains part of the signed message. Injector and validator MUST compute this identically.
    TransactionPrefix prefix = tx; // slice-copy the prefix
    for (auto &in : prefix.inputs)
    {
      if (in.type() == typeid(PqKeyInput))
      {
        boost::get<PqKeyInput>(in).ringSig.clear();
      }
      else if (in.type() == typeid(PqMultisigInput))
      {
        // A PQ multisig (deposit) input carries its m ML-DSA sigs INLINE in the prefix, so — exactly
        // like PqKeyInput.ringSig — they must be cleared before hashing (a signature cannot commit
        // to itself). The signer (injector / wallet) MUST compute this identical hash.
        boost::get<PqMultisigInput>(in).signatures.clear();
      }
    }
    return getObjectHash(prefix);
  }

  bool Blockchain::check_pq_tx_input(const PqKeyInput &txin, const crypto::Hash &pq_signing_hash, uint32_t *pmax_related_block_height)
  {
    std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

    // Nullifier length must equal the scheme's fixed spend-tag size.
    if (txin.nullifier.size() != PQ_NULLIFIER_SIZE)
    {
      logger(logging::INFO, logging::BRIGHT_WHITE) << "PQ input nullifier has wrong length " << txin.nullifier.size();
      return false;
    }

    // Resolve the ring's one-time PQ public keys from m_pqOutputs (mirrors scanOutputKeysForIndexes,
    // but against the PQ output index and extracting PqKeyOutput keys).
    auto it = m_pqOutputs.find(txin.amount);
    if (it == m_pqOutputs.end())
    {
      logger(logging::INFO, logging::BRIGHT_WHITE) << "No PQ outputs indexed for amount " << txin.amount;
      return false;
    }

    // Ring-size bounds: a floor for anonymity, a ceiling to bound the (linear) verify CPU cost so a
    // single oversized PQ input cannot become a cheap CPU-DoS on every validating node.
    if (txin.outputIndexes.size() < PQ_MIN_RING_SIZE || txin.outputIndexes.size() > PQ_MAX_RING_SIZE)
    {
      logger(logging::INFO, logging::BRIGHT_WHITE) << "PQ input ring size " << txin.outputIndexes.size()
                                 << " out of bounds [" << PQ_MIN_RING_SIZE << "," << PQ_MAX_RING_SIZE << "]";
      return false;
    }

    const std::vector<uint32_t> absolute_offsets = relative_output_offsets_to_absolute(txin.outputIndexes);
    const std::vector<std::pair<TransactionIndex, uint16_t>> &amount_outs_vec = it->second;

    // Reject duplicate / non-increasing ring members (a zero relative offset collapses the ring to
    // size 1, silently destroying anonymity).
    for (size_t k = 1; k < absolute_offsets.size(); ++k)
    {
      if (absolute_offsets[k] <= absolute_offsets[k - 1])
      {
        logger(logging::INFO, logging::BRIGHT_WHITE) << "PQ input has duplicate / non-increasing ring offsets";
        return false;
      }
    }

    const size_t pkBytes = ccx_pq_pubkey_bytes();
    if (pkBytes == 0)
    {
      logger(logging::ERROR, logging::BRIGHT_RED) << "ccx-pqc reports zero public-key size";
      return false;
    }

    std::vector<uint8_t> ring;
    ring.reserve(absolute_offsets.size() * pkBytes);

    size_t count = 0;
    for (uint64_t i : absolute_offsets)
    {
      if (i >= amount_outs_vec.size())
      {
        logger(logging::INFO, logging::BRIGHT_WHITE) << "Wrong PQ output index in input: " << i << ", expected maximum " << amount_outs_vec.size() - 1;
        return false;
      }

      const TransactionEntry &te = transactionByIndex(amount_outs_vec[i].first);

      // The referenced output must be spendable (e.g. coinbase outputs respect the unlock window).
      if (!is_tx_spendtime_unlocked(te.tx.unlockTime))
      {
        logger(logging::INFO, logging::BRIGHT_WHITE) << "PQ ring member output is not yet spendable (unlockTime=" << te.tx.unlockTime << ")";
        return false;
      }

      const uint16_t outIdx = amount_outs_vec[i].second;
      if (!(outIdx < te.tx.outputs.size()))
      {
        logger(logging::ERROR, logging::BRIGHT_RED) << "Wrong PQ output index in referenced transaction: " << outIdx;
        return false;
      }

      const TransactionOutputTarget &target = te.tx.outputs[outIdx].target;
      if (target.type() != typeid(PqKeyOutput))
      {
        logger(logging::INFO, logging::BRIGHT_WHITE) << "PQ ring member is not a PqKeyOutput";
        return false;
      }

      const std::vector<uint8_t> &memberKey = boost::get<PqKeyOutput>(target).key;
      if (memberKey.size() != pkBytes)
      {
        logger(logging::INFO, logging::BRIGHT_WHITE) << "PQ ring member key has wrong length " << memberKey.size() << ", expected " << pkBytes;
        return false;
      }
      ring.insert(ring.end(), memberKey.begin(), memberKey.end());

      // Track the MAX referenced block across ALL ring members (not just the last). pmax gates
      // checkpoint-zone sig-skip + reorg; under-reporting it could treat a tx as checkpoint-safe
      // when an earlier ring member sits above the checkpoint. (CodeRabbit)
      ++count;
      if (pmax_related_block_height && *pmax_related_block_height < amount_outs_vec[i].first.block)
      {
        *pmax_related_block_height = amount_outs_vec[i].first.block;
      }
    }

    const size_t ringCount = absolute_offsets.size();

    // Verify the lattice linkable ring signature and recover the spend tag (nullifier).
    std::vector<uint8_t> recoveredNf(PQ_NULLIFIER_SIZE, 0);
    const int32_t rc = ccx_pq_verify(
        reinterpret_cast<const uint8_t *>(&pq_signing_hash), sizeof(pq_signing_hash),
        ring.data(), ringCount, pkBytes,
        txin.ringSig.data(), txin.ringSig.size(),
        recoveredNf.data(), recoveredNf.size());
    if (rc != 0)
    {
      logger(logging::INFO, logging::BRIGHT_WHITE) << "PQ ring signature verification failed (rc=" << rc << ")";
      return false;
    }

    // Bind the claimed nullifier to the signature: the tag recovered from the signature must equal
    // the input's declared nullifier, otherwise an attacker could swap nullifiers to evade the
    // double-spend set while presenting a valid signature.
    if (recoveredNf != txin.nullifier)
    {
      logger(logging::INFO, logging::BRIGHT_WHITE) << "PQ recovered nullifier does not match declared input nullifier";
      return false;
    }

    return true;
  }

  bool Blockchain::check_pq_multisig(const PqMultisigInput &input, const crypto::Hash &transactionHash, const crypto::Hash &transactionPrefixHash)
  {
    std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

    // input.signatures count must equal the declared signatureCount (the sigs live inline, so
    // unlike the Ed25519 path there is no tx.signatures slot whose size to assert against).
    if (input.signatures.size() != input.signatureCount)
    {
      logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input with mismatched inline signature count.";
      return false;
    }

    MultisignatureOutputsContainer::const_iterator amountOutputs = m_pqMultisigOutputs.find(input.amount);
    if (amountOutputs == m_pqMultisigOutputs.end())
    {
      logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input with invalid amount.";
      return false;
    }

    if (input.outputIndex >= amountOutputs->second.size())
    {
      logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input with invalid outputIndex.";
      return false;
    }

    const MultisignatureOutputUsage &outputIndex = amountOutputs->second[input.outputIndex];
    if (outputIndex.isUsed)
    {
      logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains double spending PQ multisignature input.";
      return false;
    }

    const Transaction &outputTransaction = blocksAt(outputIndex.transactionIndex.block).transactions[outputIndex.transactionIndex.transaction].tx;
    if (!is_tx_spendtime_unlocked(outputTransaction.unlockTime))
    {
      logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input which points to a locked transaction.";
      return false;
    }

    // Type guard instead of the Ed25519 path's asserts: a corrupt index must reject, not abort.
    const TransactionOutputTarget &target = outputTransaction.outputs[outputIndex.outputIndex].target;
    if (outputTransaction.outputs[outputIndex.outputIndex].amount != input.amount || target.type() != typeid(PqMultisigOutput))
    {
      logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input pointing to a non-PQ-multisig output.";
      return false;
    }
    const PqMultisigOutput &output = ::boost::get<PqMultisigOutput>(target);

    if (input.signatureCount != output.requiredSignatureCount)
    {
      logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input with invalid signature count.";
      return false;
    }

    // BIND the input's term to the on-chain output's term BEFORE any interest is computed. This is
    // the interest-minting safety guarantee: input_amount_visitor derives interest from input.term,
    // and output.term has already passed validateOutput's term band — so an attacker cannot mint
    // arbitrary interest by declaring a larger term than the deposit actually has.
    if (input.term != output.term)
    {
      logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input with invalid term.";
      return false;
    }

    // DEPOSIT LOCK (ported byte-for-byte): a deposit (term != 0) cannot be spent until its term has
    // fully elapsed since the block that created it. Off-by-one here allows early withdrawal and
    // over-credits interest, so the comparison must match the Ed25519 path exactly.
    if (output.term != 0 &&
        static_cast<uint64_t>(outputIndex.transactionIndex.block) + output.term > getCurrentBlockchainHeight()) // uint64 add: no wrap (CodeRabbit)
    {
      logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input that spends locked deposit output";
      return false;
    }

    const size_t pkBytes = ccx_pq_multisig_pubkey_bytes();
    if (pkBytes == 0)
    {
      logger(logging::ERROR, logging::BRIGHT_RED) << "ccx-pqc reports zero ML-DSA public-key size";
      return false;
    }

    // m-of-n match: the SAME greedy loop as the Ed25519 path (each signature must match a distinct,
    // in-order key), only check_signature -> ccx_pq_multisig_verify over the prefix hash.
    size_t inputSignatureIndex = 0;
    size_t outputKeyIndex = 0;
    while (inputSignatureIndex < input.signatureCount)
    {
      if (outputKeyIndex == output.keys.size())
      {
        logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input with invalid signatures.";
        return false;
      }

      // Exact-length guard at the verify boundary (DoS / malformed-key): the on-chain key was
      // length-checked in check_outs_valid, but re-check here so a corrupt index can never reach
      // the FFI with a wrong-length buffer.
      if (output.keys[outputKeyIndex].size() != pkBytes)
      {
        logger(logging::DEBUGGING) << "Transaction << " << transactionHash << " references PQ multisignature key of wrong length.";
        return false;
      }

      if (ccx_pq_multisig_verify(
              reinterpret_cast<const uint8_t *>(&transactionPrefixHash), sizeof(transactionPrefixHash),
              output.keys[outputKeyIndex].data(), pkBytes,
              input.signatures[inputSignatureIndex].data(), input.signatures[inputSignatureIndex].size()) == 0)
      {
        ++inputSignatureIndex;
      }

      ++outputKeyIndex;
    }

    return true;
  }

  // Read-only enumeration of spendable PqKeyOutput outputs for one amount (for PQ ring assembly).
  // Walks the full m_pqOutputs[amount] index — the global index is the vector position — and projects
  // each PqKeyOutput's key / kemCt plus its containing tx hash, height and spendability. Mirrors the
  // access idioms in check_pq_tx_input; it never mutates state or touches consensus/validation.
  bool Blockchain::getPqOutputs(uint64_t amount, std::vector<PqOutputEntry> &outs)
  {
    std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
    outs.clear();

    auto it = m_pqOutputs.find(amount);
    if (it == m_pqOutputs.end())
    {
      return true; // no PQ outputs indexed for this amount: empty result, not an error
    }

    const std::vector<std::pair<TransactionIndex, uint16_t>> &amount_outs_vec = it->second;
    outs.reserve(amount_outs_vec.size());

    for (size_t i = 0; i < amount_outs_vec.size(); ++i)
    {
      const TransactionIndex &idx = amount_outs_vec[i].first;
      const uint16_t outInTx = amount_outs_vec[i].second;

      const TransactionEntry &te = transactionByIndex(idx);
      if (!(outInTx < te.tx.outputs.size()))
      {
        logger(logging::ERROR, logging::BRIGHT_RED) << "PQ output index out of range in referenced transaction: " << outInTx;
        return false;
      }

      const TransactionOutputTarget &target = te.tx.outputs[outInTx].target;
      if (target.type() != typeid(PqKeyOutput))
      {
        logger(logging::INFO, logging::BRIGHT_WHITE) << "Indexed PQ output is not a PqKeyOutput";
        return false;
      }

      const PqKeyOutput &pqOut = boost::get<PqKeyOutput>(target);

      PqOutputEntry entry;
      entry.globalIndex = static_cast<uint32_t>(i);
      entry.key = pqOut.key;
      entry.kemCt = pqOut.kemCt;
      entry.txHash = getObjectHash(te.tx);
      entry.height = idx.block;
      entry.spendable = is_tx_spendtime_unlocked(te.tx.unlockTime);
      outs.push_back(entry);
    }

    return true;
  }

  // Read-only enumeration of the PQ deposit cells (PqMultisigOutput) under one amount. A faithful twin
  // of getPqOutputs, walking m_pqMultisigOutputs instead of m_pqOutputs and surfacing the deposit
  // metadata a wallet needs to (a) find its own cells by named-key match on keys[0], and (b) build a
  // withdrawal (the outputIndex into this vector is exactly PqMultisigInput.outputIndex, term binds the
  // input, isUsed is the consensus double-spend flag). Mirrors check_pq_multisig's read idioms — this
  // is a read-only RPC path and must never abort the daemon.
  bool Blockchain::getPqMultisigOutputs(uint64_t amount, std::vector<PqMultisigOutputEntry> &outs)
  {
    std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
    outs.clear();

    auto it = m_pqMultisigOutputs.find(amount);
    if (it == m_pqMultisigOutputs.end())
    {
      return true; // no PQ multisig outputs indexed for this amount: empty result, not an error
    }

    const std::vector<MultisignatureOutputUsage> &usages = it->second;
    outs.reserve(usages.size());

    for (size_t i = 0; i < usages.size(); ++i)
    {
      const MultisignatureOutputUsage &usage = usages[i];

      const TransactionEntry &te = transactionByIndex(usage.transactionIndex);
      if (!(usage.outputIndex < te.tx.outputs.size()))
      {
        logger(logging::ERROR, logging::BRIGHT_RED) << "PQ multisig output index out of range in referenced transaction: " << usage.outputIndex;
        return false;
      }

      const TransactionOutputTarget &target = te.tx.outputs[usage.outputIndex].target;
      if (target.type() != typeid(PqMultisigOutput))
      {
        logger(logging::INFO, logging::BRIGHT_WHITE) << "Indexed PQ multisig output is not a PqMultisigOutput";
        return false;
      }

      const PqMultisigOutput &out = boost::get<PqMultisigOutput>(target);

      PqMultisigOutputEntry entry;
      entry.outputIndex = static_cast<uint32_t>(i);
      entry.keys = out.keys;
      entry.requiredSignatureCount = out.requiredSignatureCount;
      entry.term = out.term;
      entry.txHash = getObjectHash(te.tx);
      entry.height = usage.transactionIndex.block;
      entry.isUsed = usage.isUsed;
      entry.spendable = is_tx_spendtime_unlocked(te.tx.unlockTime);
      outs.push_back(entry);
    }

    return true;
  }

} // namespace cn
