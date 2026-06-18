// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// pq_injector — testnet PoC tool (CIP-0001).
//
// Builds and signs a version-3 post-quantum transaction that spends a single testnet coinbase
// PQ output (created by Currency::constructMinerTx) and prints the raw transaction as hex. Pipe
// that hex into the daemon's `sendrawtransaction` RPC to exercise the PQ consensus path:
//
//     conceald (testnet) mines  ->  coinbase emits a PqKeyOutput owned by the deterministic
//     testnet PQ keypair (seed = cn::PQ_TESTNET_COINBASE_SEED)  ->  this tool spends it.
//
// No wallet is involved: the spend output is a throwaway PQ key and the ring is the single
// referenced output (the stub ring signature provides no real anonymity — feasibility only).
//
// Usage:
//   pq_injector <amount> [fee] [globalIndex]
//     amount      : atomic amount of the coinbase PQ output to spend (= block reward of the
//                   block that created it; read it from getblockheaderbyheight(.reward)).
//     fee         : atomic fee to leave for the miner (default 1000). Output = amount - fee.
//     globalIndex : index of the output within m_pqOutputs[amount] (default 0 = first such output).

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteConfig.h"
#include "pq_ring_sig.h"

namespace
{
  std::string toHex(const std::vector<uint8_t> &data)
  {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data)
    {
      out.push_back(digits[b >> 4]);
      out.push_back(digits[b & 0x0f]);
    }
    return out;
  }
}

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    std::fprintf(stderr, "usage: %s <amount> [fee] [globalIndex]\n", argv[0]);
    return 2;
  }

  const uint64_t amount = static_cast<uint64_t>(std::strtoull(argv[1], nullptr, 10));
  const uint64_t fee = (argc >= 3) ? static_cast<uint64_t>(std::strtoull(argv[2], nullptr, 10)) : 1000ULL;
  const uint32_t globalIndex = (argc >= 4) ? static_cast<uint32_t>(std::strtoul(argv[3], nullptr, 10)) : 0u;

  if (amount == 0 || fee >= amount)
  {
    std::fprintf(stderr, "error: require amount > 0 and fee < amount (amount=%llu fee=%llu)\n",
                 (unsigned long long)amount, (unsigned long long)fee);
    return 2;
  }

  // Derive the deterministic testnet PQ keypair that owns testnet coinbase PQ outputs.
  const size_t pkBytes = ccx_pq_pubkey_bytes();
  const size_t skBytes = ccx_pq_seckey_bytes();
  const size_t nfBytes = ccx_pq_nullifier_bytes();
  std::vector<uint8_t> pk(pkBytes, 0);
  std::vector<uint8_t> sk(skBytes, 0);
  if (ccx_pq_keygen(cn::PQ_TESTNET_COINBASE_SEED, sizeof(cn::PQ_TESTNET_COINBASE_SEED),
                    pk.data(), pk.size(), sk.data(), sk.size()) != 0)
  {
    std::fprintf(stderr, "error: ccx_pq_keygen failed\n");
    return 1;
  }

  // Spend tag (nullifier) for this key — must match what the daemon recovers from the signature.
  std::vector<uint8_t> nullifier(nfBytes, 0);
  if (ccx_pq_nullifier(sk.data(), sk.size(), pk.data(), pk.size(), nullifier.data(), nullifier.size()) != 0)
  {
    std::fprintf(stderr, "error: ccx_pq_nullifier failed\n");
    return 1;
  }

  // Assemble the PQ input with an empty ring signature: the signed message is the tx prefix with
  // every PqKeyInput.ringSig cleared (matches Blockchain::getTransactionPqSigningHash).
  cn::PqKeyInput in;
  in.amount = amount;
  in.outputIndexes.push_back(globalIndex); // single ring member: relative offset == absolute index
  in.nullifier = nullifier;
  // in.ringSig left empty for now.

  cn::PqKeyOutput out;
  out.key = pk; // throwaway recipient key (reuse the testnet key); kemCt left empty

  cn::TransactionOutput txout;
  txout.amount = amount - fee;
  txout.target = out;

  cn::Transaction tx;
  tx.version = cn::TRANSACTION_VERSION_3;
  tx.unlockTime = 0;
  tx.inputs.push_back(in);
  tx.outputs.push_back(txout);
  // tx.extra and tx.signatures left empty (PQ inputs carry no tx.signatures entry).

  // Hash the prefix with ringSig still empty == the daemon's cleared-ringSig signing hash.
  crypto::Hash signingHash = cn::getObjectHash(static_cast<const cn::TransactionPrefix &>(tx));

  // Sign the linkable ring signature: ring = the single referenced output's public key, signer 0.
  std::vector<uint8_t> sig(256 * 1024, 0);
  size_t sigLen = sig.size();
  int32_t rc = ccx_pq_sign(
      reinterpret_cast<const uint8_t *>(&signingHash), sizeof(signingHash),
      pk.data(), /*ring_count*/ 1, /*member_stride*/ pkBytes,
      sk.data(), sk.size(), /*signer_index*/ 0,
      sig.data(), &sigLen);
  if (rc != 0)
  {
    std::fprintf(stderr, "error: ccx_pq_sign failed (rc=%d)\n", (int)rc);
    return 1;
  }
  sig.resize(sigLen);

  // Attach the signature and emit the final transaction.
  boost::get<cn::PqKeyInput>(tx.inputs[0]).ringSig = sig;

  cn::BinaryArray blob = cn::toBinaryArray(tx);
  std::printf("%s\n", toHex(blob).c_str());
  return 0;
}
