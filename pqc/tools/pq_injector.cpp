// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// pq_injector — testnet PoC tool (CIP-0001).
//
// Builds and signs a version-3 post-quantum transaction that spends ONE testnet coinbase PQ output
// inside a ring of N real on-chain members, and prints the raw transaction as hex. Pipe that hex
// into the daemon's `sendrawtransaction` RPC to exercise the PQ consensus path.
//
// Ring members come from m_pqOutputs[PQ_TESTNET_COINBASE_AMOUNT]. The testnet coinbase emits one
// fixed-denomination PQ output per block (height 1,2,3,...) with a DISTINCT key derived from
// (height,outIndex) via derivePqCoinbaseSeed. So global index g in that bucket == the output mined
// at height g+1, and the injector can re-derive every member's public key (and the signer's secret
// key) deterministically — no RPC, no wallet.
//
// Usage:
//   pq_injector <amount> [fee] [signerIndex] [ringSize]
//     amount      : the PQ output denomination (= PQ_TESTNET_COINBASE_AMOUNT, e.g. 100000).
//     fee         : atomic fee (default 1000). Output = amount - fee.
//     signerIndex : which ring member actually signs, 0..ringSize-1 (default 0). The signer's
//                   output (global index = signerIndex) is the one marked spent by the nullifier.
//     ringSize    : N, the anonymity-set size (default 1). Ring = global indices [0 .. N-1]
//                   (heights 1..N); all must be unlocked (mine past height N + unlock window).

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteConfig.h"
#include "pq_ring_sig.h"
#include "pq_testnet_keys.h"

namespace
{
  std::string toHex(const std::vector<uint8_t> &data)
  {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) { out.push_back(digits[b >> 4]); out.push_back(digits[b & 0x0f]); }
    return out;
  }

  // Derive the (pk, sk) for the PQ coinbase output at global index `gindex` (= height gindex+1).
  bool deriveMember(uint32_t gindex, std::vector<uint8_t> &pk, std::vector<uint8_t> &sk)
  {
    uint8_t seed[32];
    cn::derivePqCoinbaseSeed(cn::PQ_TESTNET_COINBASE_SEED, sizeof(cn::PQ_TESTNET_COINBASE_SEED),
                             static_cast<uint64_t>(gindex) + 1, 0u, seed);
    pk.assign(ccx_pq_pubkey_bytes(), 0);
    sk.assign(ccx_pq_seckey_bytes(), 0);
    return ccx_pq_keygen(seed, sizeof(seed), pk.data(), pk.size(), sk.data(), sk.size()) == 0;
  }
}

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    std::fprintf(stderr, "usage: %s <amount> [fee] [signerIndex] [ringSize]\n", argv[0]);
    return 2;
  }
  const uint64_t amount = static_cast<uint64_t>(std::strtoull(argv[1], nullptr, 10));
  const uint64_t fee = (argc >= 3) ? std::strtoull(argv[2], nullptr, 10) : 1000ULL;
  const uint32_t signerIndex = (argc >= 4) ? static_cast<uint32_t>(std::strtoul(argv[3], nullptr, 10)) : 0u;
  const uint32_t ringSize = (argc >= 5) ? static_cast<uint32_t>(std::strtoul(argv[4], nullptr, 10)) : 1u;

  if (amount == 0 || fee >= amount || ringSize == 0 || signerIndex >= ringSize)
  {
    std::fprintf(stderr, "error: need amount>0, fee<amount, ringSize>=1, signerIndex<ringSize\n");
    return 2;
  }

  const size_t pkBytes = ccx_pq_pubkey_bytes();

  // Ring = global indices [0 .. ringSize-1] (ascending). Build the concatenated pubkey ring and
  // grab the signer's secret key.
  std::vector<uint8_t> ring;
  ring.reserve(static_cast<size_t>(ringSize) * pkBytes);
  std::vector<uint8_t> signerSk, signerPk;
  for (uint32_t i = 0; i < ringSize; ++i)
  {
    std::vector<uint8_t> pk, sk;
    if (!deriveMember(i, pk, sk)) { std::fprintf(stderr, "error: keygen failed for ring member %u\n", i); return 1; }
    ring.insert(ring.end(), pk.begin(), pk.end());
    if (i == signerIndex) { signerPk = pk; signerSk = sk; }
  }

  // Spend tag (nullifier) for the signer's output.
  std::vector<uint8_t> nullifier(ccx_pq_nullifier_bytes(), 0);
  if (ccx_pq_nullifier(signerSk.data(), signerSk.size(), signerPk.data(), signerPk.size(),
                       nullifier.data(), nullifier.size()) != 0)
  {
    std::fprintf(stderr, "error: ccx_pq_nullifier failed\n");
    return 1;
  }

  // Relative (running-delta) encoding of the ascending absolute indices [0..ringSize-1].
  cn::PqKeyInput in;
  in.amount = amount;
  in.outputIndexes.resize(ringSize);
  in.outputIndexes[0] = 0;
  for (uint32_t i = 1; i < ringSize; ++i) in.outputIndexes[i] = 1; // consecutive => deltas of 1
  in.nullifier = nullifier;
  // in.ringSig left empty for the signing-hash computation.

  cn::PqKeyOutput out;
  out.key = signerPk; // throwaway recipient (reuse signer key); kemCt empty

  cn::TransactionOutput txout;
  txout.amount = amount - fee;
  txout.target = out;

  cn::Transaction tx;
  tx.version = cn::TRANSACTION_VERSION_3;
  tx.unlockTime = 0;
  tx.inputs.push_back(in);
  tx.outputs.push_back(txout);

  // Hash the prefix with ringSig empty == the daemon's cleared-ringSig signing hash.
  crypto::Hash signingHash = cn::getObjectHash(static_cast<const cn::TransactionPrefix &>(tx));

  std::vector<uint8_t> sig(256 * 1024, 0);
  size_t sigLen = sig.size();
  int32_t rc = ccx_pq_sign(
      reinterpret_cast<const uint8_t *>(&signingHash), sizeof(signingHash),
      ring.data(), ringSize, pkBytes,
      signerSk.data(), signerSk.size(), signerIndex,
      sig.data(), &sigLen);
  if (rc != 0) { std::fprintf(stderr, "error: ccx_pq_sign failed (rc=%d)\n", (int)rc); return 1; }
  sig.resize(sigLen);

  boost::get<cn::PqKeyInput>(tx.inputs[0]).ringSig = sig;

  cn::BinaryArray blob = cn::toBinaryArray(tx);
  std::printf("%s\n", toHex(blob).c_str());
  return 0;
}
