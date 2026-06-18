// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "CryptoNoteFormatUtils.h"

#include <set>
#include <Logging/LoggerRef.h>
#include <Common/BinaryArray.hpp>
#include <Common/int-util.h>
#include <Common/Varint.h>
#include "Common/Base58.h"

#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "CryptoNoteSerialization.h"
#include "Account.h"
#include "CryptoNoteBasicImpl.h"
#include "CryptoNoteSerialization.h"
#include "TransactionExtra.h"
#include "pq_ring_sig.h" // ccx-pqc FFI: PQ output key/kemCt length checks (CIP-0001)
#include "CryptoNoteTools.h"
#include "Currency.h"

#include "CryptoNoteConfig.h"

using namespace logging;
using namespace crypto;
using namespace common;

namespace cn {

bool parseAndValidateTransactionFromBinaryArray(const BinaryArray& tx_blob, Transaction& tx, Hash& tx_hash, Hash& tx_prefix_hash) {
  if (!fromBinaryArray(tx, tx_blob)) {
    return false;
  }

  //TODO: validate tx
  cn_fast_hash(tx_blob.data(), tx_blob.size(), tx_hash);
  getObjectHash(*static_cast<TransactionPrefix*>(&tx), tx_prefix_hash);
  return true;
}

bool generate_key_image_helper(const AccountKeys& ack, const PublicKey& tx_public_key, size_t real_output_index, KeyPair& in_ephemeral, KeyImage& ki) {
  KeyDerivation recv_derivation;
  bool r = generate_key_derivation(tx_public_key, ack.viewSecretKey, recv_derivation);

  assert(r && "key image helper: failed to generate_key_derivation");

  if (!r) {
    return false;
  }

  r = derive_public_key(recv_derivation, real_output_index, ack.address.spendPublicKey, in_ephemeral.publicKey);

  assert(r && "key image helper: failed to derive_public_key");

  if (!r) {
    return false;
  }

  derive_secret_key(recv_derivation, real_output_index, ack.spendSecretKey, in_ephemeral.secretKey);
  generate_key_image(in_ephemeral.publicKey, in_ephemeral.secretKey, ki);
  return true;
}

uint64_t power_integral(uint64_t a, uint64_t b) {
  if (b == 0)
    return 1;
  uint64_t total = a;
  for (uint64_t i = 1; i != b; i++)
    total *= a;
  return total;
}

bool constructTransaction(
  const AccountKeys& sender_account_keys,
  const std::vector<TransactionSourceEntry>& sources,
  const std::vector<TransactionDestinationEntry>& destinations,
  const std::vector<tx_message_entry>& messages,
  uint64_t ttl,
  std::vector<uint8_t> extra,
  Transaction& tx,
  uint64_t unlock_time,
  logging::ILogger& log,
  crypto::SecretKey& transactionSK) {
  LoggerRef logger(log, "construct_tx");

  tx.inputs.clear();
  tx.outputs.clear();
  tx.signatures.clear();

  tx.version = TRANSACTION_VERSION_1;
  tx.unlockTime = unlock_time;

  tx.extra = extra;

  struct input_generation_context_data {
    KeyPair in_ephemeral;
  };

  std::vector<input_generation_context_data> in_contexts;
  uint64_t summary_inputs_money = 0;
  //fill inputs
  for (const TransactionSourceEntry& src_entr : sources) {
    if (src_entr.realOutput >= src_entr.outputs.size()) {
      logger(ERROR) << "real_output index (" << src_entr.realOutput << ")bigger than output_keys.size()=" << src_entr.outputs.size();
      return false;
    }
    summary_inputs_money += src_entr.amount;

    //KeyDerivation recv_derivation;
    in_contexts.push_back(input_generation_context_data());
    KeyPair& in_ephemeral = in_contexts.back().in_ephemeral;
    KeyImage img;
    if (!generate_key_image_helper(sender_account_keys, src_entr.realTransactionPublicKey, src_entr.realOutputIndexInTransaction, in_ephemeral, img))
      return false;

    //check that derived key is equal with real output key
    if (!(in_ephemeral.publicKey == src_entr.outputs[src_entr.realOutput].second)) {
      logger(ERROR) << "derived public key mismatch with output public key! " << ENDL << "derived_key:"
        << common::podToHex(in_ephemeral.publicKey) << ENDL << "real output_public_key:"
        << common::podToHex(src_entr.outputs[src_entr.realOutput].second);
      return false;
    }


    //put key image into tx input
    KeyInput input_to_key;
    input_to_key.amount = src_entr.amount;
    input_to_key.keyImage = img;

    //fill outputs array and use relative offsets
    for (const TransactionSourceEntry::OutputEntry& out_entry : src_entr.outputs) {
      input_to_key.outputIndexes.push_back(out_entry.first);
    }

    input_to_key.outputIndexes = absolute_output_offsets_to_relative(input_to_key.outputIndexes);
    tx.inputs.push_back(input_to_key);
  }

  KeyPair txkey;
  if (!generateDeterministicTransactionKeys(getObjectHash(tx.inputs), sender_account_keys.viewSecretKey, txkey))
  {
    logger(ERROR) << "Couldn't generate deterministic transaction keys";
    return false;
  }

  addTransactionPublicKeyToExtra(tx.extra, txkey.publicKey);

  transactionSK = txkey.secretKey;

  // "Shuffle" outs
  std::vector<TransactionDestinationEntry> shuffled_dsts(destinations);
  std::sort(shuffled_dsts.begin(), shuffled_dsts.end(), [](const TransactionDestinationEntry& de1, const TransactionDestinationEntry& de2) { return de1.amount < de2.amount; });

  uint64_t summary_outs_money = 0;
  //fill outputs
  size_t output_index = 0;
  for (const TransactionDestinationEntry& dst_entr : shuffled_dsts) {
    if (!(dst_entr.amount > 0)) {
      logger(ERROR, BRIGHT_RED) << "Destination with wrong amount: " << dst_entr.amount;
      return false;
    }
    KeyDerivation derivation;
    PublicKey out_eph_public_key;
    bool r = generate_key_derivation(dst_entr.addr.viewPublicKey, txkey.secretKey, derivation);

    if (!(r)) {
      logger(ERROR, BRIGHT_RED)
        << "at creation outs: failed to generate_key_derivation("
        << dst_entr.addr.viewPublicKey << ", " << txkey.secretKey << ")";
      return false;
    }

    r = derive_public_key(derivation, output_index,
      dst_entr.addr.spendPublicKey,
      out_eph_public_key);
    if (!(r)) {
      logger(ERROR, BRIGHT_RED)
        << "at creation outs: failed to derive_public_key(" << derivation
        << ", " << output_index << ", " << dst_entr.addr.spendPublicKey
        << ")";
      return false;
    }

    TransactionOutput out;
    out.amount = dst_entr.amount;
    KeyOutput tk;
    tk.key = out_eph_public_key;
    out.target = tk;
    tx.outputs.push_back(out);
    output_index++;
    summary_outs_money += dst_entr.amount;
  }

  //check money
  if (summary_outs_money > summary_inputs_money) {
    logger(ERROR) << "Transaction inputs money (" << summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")";
    return false;
  }

  for (size_t i = 0; i < messages.size(); i++) {
    const tx_message_entry &msg = messages[i];
    if (msg.pq && !msg.kemPub.empty()) {
      // Post-quantum message: emit a tx_extra_pq_message (0x06) keyed by ML-KEM-768. The KEM
      // ciphertext is self-contained, so the legacy 0x04 field is NOT emitted for this message.
      tx_extra_pq_message pqTag;
      if (!pqTag.encrypt(i, msg.message, msg.kemPub)) {
        return false;
      }

      if (!append_pq_message_to_extra(tx.extra, pqTag)) {
        return false;
      }
    } else {
      tx_extra_message tag;
      if (!tag.encrypt(i, msg.message, msg.encrypt ? &msg.addr : NULL, txkey)) {
        return false;
      }

      if (!append_message_to_extra(tx.extra, tag)) {
        return false;
      }
    }
  }

  if (ttl != 0) {
    appendTTLToExtra(tx.extra, ttl);
  }

  //generate ring signatures
  Hash tx_prefix_hash;
  getObjectHash(*static_cast<TransactionPrefix*>(&tx), tx_prefix_hash);

  size_t i = 0;
  for (const TransactionSourceEntry& src_entr : sources) {
    std::vector<const PublicKey*> keys_ptrs;
    for (const TransactionSourceEntry::OutputEntry& o : src_entr.outputs) {
      keys_ptrs.push_back(&o.second);
    }

    tx.signatures.push_back(std::vector<Signature>());
    std::vector<Signature>& sigs = tx.signatures.back();
    sigs.resize(src_entr.outputs.size());
    generate_ring_signature(tx_prefix_hash, boost::get<KeyInput>(tx.inputs[i]).keyImage, keys_ptrs,
      in_contexts[i].in_ephemeral.secretKey, src_entr.realOutput, sigs.data());
    i++;
  }

  return true;
}

bool generateDeterministicTransactionKeys(const crypto::Hash &inputsHash, const crypto::SecretKey &viewSecretKey, KeyPair &generatedKeys)
{
  BinaryArray ba;
  common::append(ba, std::begin(viewSecretKey.data), std::end(viewSecretKey.data));
  common::append(ba, std::begin(inputsHash.data), std::end(inputsHash.data));

  hash_to_scalar(ba.data(), ba.size(), generatedKeys.secretKey);
  return crypto::secret_key_to_public_key(generatedKeys.secretKey, generatedKeys.publicKey);
}

bool generateDeterministicTransactionKeys(const Transaction &tx, const SecretKey &viewSecretKey, KeyPair &generatedKeys)
{
  crypto::Hash inputsHash = getObjectHash(tx.inputs);
  return generateDeterministicTransactionKeys(inputsHash, viewSecretKey, generatedKeys);
}

bool get_inputs_money_amount(const Transaction& tx, uint64_t& money) {
  money = 0;

  for (const auto& in : tx.inputs) {
    uint64_t amount = 0;

    if (in.type() == typeid(KeyInput)) {
      amount = boost::get<KeyInput>(in).amount;
    } else if (in.type() == typeid(MultisignatureInput)) {
      amount = boost::get<MultisignatureInput>(in).amount;
    } else if (in.type() == typeid(PqMultisigInput)) {
      // PQ deposit input (CIP-0001): non-interest principal only, mirroring the MultisignatureInput
      // case. The interest is added separately by the Currency interest path.
      amount = boost::get<PqMultisigInput>(in).amount;
    }

    money += amount;
  }
  return true;
}

uint32_t get_block_height(const Block& b) {
  if (b.baseTransaction.inputs.size() != 1) {
    return 0;
  }
  const auto& in = b.baseTransaction.inputs[0];
  if (in.type() != typeid(BaseInput)) {
    return 0;
  }
  return boost::get<BaseInput>(in).blockIndex;
}

bool check_inputs_types_supported(const TransactionPrefix& tx) {
  for (const auto& in : tx.inputs) {
    const auto& inputType = in.type();
    if (inputType == typeid(MultisignatureInput)) {
      if (tx.version < TRANSACTION_VERSION_2) {
        return false;
      }
    } else if (inputType == typeid(PqKeyInput)) {
      // Post-quantum ring-signature input (CIP-0001), allowed from version 3 on.
      if (tx.version < TRANSACTION_VERSION_3) {
        return false;
      }
    } else if (inputType == typeid(PqMultisigInput)) {
      // Post-quantum deposit (multisig) input (CIP-0001 UPGRADE_HEIGHT_V9), allowed from version 3 on.
      if (tx.version < TRANSACTION_VERSION_3) {
        return false;
      }
    } else if (inputType != typeid(KeyInput)) {
      return false;
    }
  }

  return true;
}

bool check_outs_valid(const TransactionPrefix& tx, std::string* error) {
  for (const TransactionOutput& out : tx.outputs) {
    if (out.target.type() == typeid(KeyOutput)) {
      if (out.amount == 0) {
        if (error) {
          *error = "Zero amount ouput";
        }
        return false;
      }

      if (!check_key(boost::get<KeyOutput>(out.target).key)) {
        if (error) {
          *error = "Output with invalid key";
        }
        return false;
      }
    } else if (out.target.type() == typeid(MultisignatureOutput)) {
      if (tx.version < TRANSACTION_VERSION_2) {
        *error = "Transaction contains multisignature output but its version is less than 2";
        return false;
      }

      const MultisignatureOutput& multisignatureOutput = ::boost::get<MultisignatureOutput>(out.target);
      if (multisignatureOutput.requiredSignatureCount > multisignatureOutput.keys.size()) {
        if (error) {
          *error = "Multisignature output with invalid required signature count";
        }
        return false;
      }
      for (const PublicKey& key : multisignatureOutput.keys) {
        if (!check_key(key)) {
          if (error) {
            *error = "Multisignature output with invalid public key";
          }
          return false;
        }
      }
    } else if (out.target.type() == typeid(PqKeyOutput)) {
      // Post-quantum output (CIP-0001): plaintext amount, fixed-length lattice public key + KEM ct.
      const PqKeyOutput& pqo = boost::get<PqKeyOutput>(out.target);
      if (out.amount == 0) {
        if (error) {
          *error = "Zero amount PQ output";
        }
        return false;
      }
      // Enforce exact lengths so a malformed (wrong-length) key cannot poison m_pqOutputs (the index
      // would bloat and shift global offsets even though the output can never be spent).
      if (pqo.key.size() != ccx_pq_pubkey_bytes()) {
        if (error) {
          *error = "PQ output key has wrong length";
        }
        return false;
      }
      // Reject NON-CANONICALLY-encoded keys at acceptance. A key and key+q are algebraically equal but
      // bytewise different: accepting both would let two outputs share one secret + nullifier (only one
      // ever spendable -> loss of funds) and would make ring members hash differently across nodes (a
      // consensus split). The Rust ring-sig sign/verify also reject non-canonical members, but checking
      // here keeps non-canonical keys out of the chain index entirely.
      if (ccx_pq_pubkey_is_canonical(pqo.key.data(), pqo.key.size()) != 1) {
        if (error) {
          *error = "PQ output key is not canonically encoded";
        }
        return false;
      }
      if (!pqo.kemCt.empty() && pqo.kemCt.size() != ccx_pq_kem_ct_bytes()) {
        if (error) {
          *error = "PQ output kemCt has wrong length";
        }
        return false;
      }
    } else if (out.target.type() == typeid(PqMultisigOutput)) {
      // Post-quantum deposit (multisig) output (CIP-0001 UPGRADE_HEIGHT_V9): n ML-DSA-65 public keys
      // + requiredSignatureCount + term. Bound n, enforce m in [1, n], and enforce exact key lengths
      // at the boundary so a malformed key cannot poison m_pqMultisigOutputs.
      if (tx.version < TRANSACTION_VERSION_3) {
        if (error) {
          *error = "Transaction contains PQ multisignature output but its version is less than 3";
        }
        return false;
      }
      if (out.amount == 0) {
        if (error) {
          *error = "Zero amount PQ multisignature output";
        }
        return false;
      }
      const PqMultisigOutput& pqms = boost::get<PqMultisigOutput>(out.target);
      if (pqms.keys.empty() || pqms.keys.size() > PQ_MULTISIG_MAX_KEYS) {
        if (error) {
          *error = "PQ multisignature output with out-of-bounds key count";
        }
        return false;
      }
      if (pqms.requiredSignatureCount == 0 || pqms.requiredSignatureCount > pqms.keys.size()) {
        if (error) {
          *error = "PQ multisignature output with invalid required signature count";
        }
        return false;
      }
      const size_t pkBytes = ccx_pq_multisig_pubkey_bytes();
      for (const auto& key : pqms.keys) {
        if (key.size() != pkBytes) {
          if (error) {
            *error = "PQ multisignature output key has wrong length";
          }
          return false;
        }
      }
    } else {
      if (error) {
        *error = "Output with invalid type";
      }
      return false;
    }
  }

  return true;
}

bool checkMultisignatureInputsDiff(const TransactionPrefix& tx) {
  std::set<std::pair<uint64_t, uint32_t>> inputsUsage;
  // PQ deposit cells live in a SEPARATE index (m_pqMultisigOutputs), so their (amount, outputIndex)
  // namespace is distinct from the Ed25519 multisig cells — track them separately to catch a tx that
  // spends the same PQ deposit cell twice without falsely colliding with an Ed25519 cell.
  std::set<std::pair<uint64_t, uint32_t>> pqInputsUsage;
  for (const auto& inv : tx.inputs) {
    if (inv.type() == typeid(MultisignatureInput)) {
      const MultisignatureInput& in = ::boost::get<MultisignatureInput>(inv);
      if (!inputsUsage.insert(std::make_pair(in.amount, in.outputIndex)).second) {
        return false;
      }
    } else if (inv.type() == typeid(PqMultisigInput)) {
      const PqMultisigInput& in = ::boost::get<PqMultisigInput>(inv);
      if (!pqInputsUsage.insert(std::make_pair(in.amount, in.outputIndex)).second) {
        return false;
      }
    }
  }
  return true;
}

bool check_money_overflow(const TransactionPrefix &tx) {
  return check_inputs_overflow(tx) && check_outs_overflow(tx);
}

bool check_inputs_overflow(const TransactionPrefix &tx) {
  uint64_t money = 0;

  for (const auto &in : tx.inputs) {
    uint64_t amount = 0;

    if (in.type() == typeid(KeyInput)) {
      amount = boost::get<KeyInput>(in).amount;
    } else if (in.type() == typeid(MultisignatureInput)) {
      amount = boost::get<MultisignatureInput>(in).amount;
      if (boost::get<MultisignatureInput>(in).term != 0) {
        uint64_t hi;
        uint64_t lo = mul128(amount, cn::parameters::DEPOSIT_MAX_TOTAL_RATE, &hi);
        uint64_t maxInterestHi;
        uint64_t maxInterestLo;
        div128_32(hi, lo, 100, &maxInterestHi, &maxInterestLo);
        if (maxInterestHi > 0) {
          return false;
        }

        if (amount > std::numeric_limits<uint64_t>::max() - maxInterestLo) {
          return false;
        }

        amount += maxInterestLo;
      }
    }

    if (money > amount + money)
      return false;

    money += amount;
  }
  return true;
}

bool check_outs_overflow(const TransactionPrefix& tx) {
  uint64_t money = 0;
  for (const auto& o : tx.outputs) {
    if (money > o.amount + money)
      return false;
    money += o.amount;
  }
  return true;
}

uint64_t get_outs_money_amount(const Transaction& tx) {
  uint64_t outputs_amount = 0;
  for (const auto& o : tx.outputs) {
    outputs_amount += o.amount;
  }
  return outputs_amount;
}

std::string short_hash_str(const Hash& h) {
  std::string res = common::podToHex(h);

  if (res.size() == 64) {
    auto erased_pos = res.erase(8, 48);
    res.insert(8, "....");
  }

  return res;
}

bool is_out_to_acc(const AccountKeys& acc, const KeyOutput& out_key, const KeyDerivation& derivation, size_t keyIndex) {
  PublicKey pk;
  derive_public_key(derivation, keyIndex, acc.address.spendPublicKey, pk);
  return pk == out_key.key;
}

bool is_out_to_acc(const AccountKeys& acc, const KeyOutput& out_key, const PublicKey& tx_pub_key, size_t keyIndex) {
  KeyDerivation derivation;
  generate_key_derivation(tx_pub_key, acc.viewSecretKey, derivation);
  return is_out_to_acc(acc, out_key, derivation, keyIndex);
}

bool lookup_acc_outs(const AccountKeys& acc, const Transaction& tx, std::vector<size_t>& outs, uint64_t& money_transfered) {
  PublicKey transactionPublicKey = getTransactionPublicKeyFromExtra(tx.extra);
  if (transactionPublicKey == NULL_PUBLIC_KEY)
    return false;
  return lookup_acc_outs(acc, tx, transactionPublicKey, outs, money_transfered);
}

bool lookup_acc_outs(const AccountKeys& acc, const Transaction& tx, const PublicKey& tx_pub_key, std::vector<size_t>& outs, uint64_t& money_transfered) {
  money_transfered = 0;
  size_t keyIndex = 0;
  size_t outputIndex = 0;

  KeyDerivation derivation;
  generate_key_derivation(tx_pub_key, acc.viewSecretKey, derivation);

  for (const TransactionOutput& o : tx.outputs) {
    assert(o.target.type() == typeid(KeyOutput) || o.target.type() == typeid(MultisignatureOutput));
    if (o.target.type() == typeid(KeyOutput)) {
      if (is_out_to_acc(acc, boost::get<KeyOutput>(o.target), derivation, keyIndex)) {
        outs.push_back(outputIndex);
        money_transfered += o.amount;
      }

      ++keyIndex;
    } else if (o.target.type() == typeid(MultisignatureOutput)) {
      keyIndex += boost::get<MultisignatureOutput>(o.target).keys.size();
    }

    ++outputIndex;
  }
  return true;
}

bool get_block_hashing_blob(const Block& b, BinaryArray& ba) {
  if (!toBinaryArray(static_cast<const BlockHeader&>(b), ba)) {
    return false;
  }

  Hash treeRootHash = get_tx_tree_hash(b);
  ba.insert(ba.end(), treeRootHash.data, treeRootHash.data + 32);
  auto transactionCount = asBinaryArray(tools::get_varint_data(b.transactionHashes.size() + 1));
  ba.insert(ba.end(), transactionCount.begin(), transactionCount.end());
  return true;
}

bool get_block_hash(const Block& b, Hash& res) {
  BinaryArray ba;
  if (!get_block_hashing_blob(b, ba)) {
    return false;
  }

  return getObjectHash(ba, res);
}

Hash get_block_hash(const Block& b) {
  Hash p = NULL_HASH;
  get_block_hash(b, p);
  return p;
}

bool get_aux_block_header_hash(const Block& b, Hash& res) {
  BinaryArray blob;
  if (!get_block_hashing_blob(b, blob)) {
    return false;
  }

  return getObjectHash(blob, res);
}

bool get_block_longhash(cn_context &context, const Block& b, Hash& res) {
  BinaryArray bd;
  if (!get_block_hashing_blob(b, bd)) {
    return false;
  }

  if (b.majorVersion >= 8) {
    cn_gpu_hash_v0(context, bd.data(), bd.size(), res);
  } else if (b.majorVersion >= 7) {
    cn_conceal_slow_hash_v0(context, bd.data(), bd.size(), res);
  } else if (b.majorVersion >= 3) {
    cn_fast_slow_hash_v1(context, bd.data(), bd.size(), res);
  } else {
    cn_slow_hash_v0(context, bd.data(), bd.size(), res);
  }
  

  return true;
}

std::vector<uint32_t> relative_output_offsets_to_absolute(const std::vector<uint32_t>& off) {
  std::vector<uint32_t> res = off;
  for (size_t i = 1; i < res.size(); i++)
    res[i] += res[i - 1];
  return res;
}

std::vector<uint32_t> absolute_output_offsets_to_relative(const std::vector<uint32_t>& off) {
  std::vector<uint32_t> res = off;
  if (!off.size())
    return res;
  std::sort(res.begin(), res.end());//just to be sure, actually it is already should be sorted
  for (size_t i = res.size() - 1; i != 0; i--)
    res[i] -= res[i - 1];

  return res;
}

void get_tx_tree_hash(const std::vector<Hash>& tx_hashes, Hash& h) {
  tree_hash(tx_hashes.data(), tx_hashes.size(), h);
}

Hash get_tx_tree_hash(const std::vector<Hash>& tx_hashes) {
  Hash h = NULL_HASH;
  get_tx_tree_hash(tx_hashes, h);
  return h;
}

Hash get_tx_tree_hash(const Block& b) {
  std::vector<Hash> txs_ids;
  Hash h = NULL_HASH;
  getObjectHash(b.baseTransaction, h);
  txs_ids.push_back(h);
  for (auto& th : b.transactionHashes) {
    txs_ids.push_back(th);
  }
  return get_tx_tree_hash(txs_ids);
}

bool is_valid_decomposed_amount(uint64_t amount) {
  auto it = std::lower_bound(Currency::PRETTY_AMOUNTS.begin(), Currency::PRETTY_AMOUNTS.end(), amount);
  if (it == Currency::PRETTY_AMOUNTS.end() || amount != *it) {
	  return false;
  }
  return true;
}

}
