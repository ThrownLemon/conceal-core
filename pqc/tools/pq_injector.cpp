// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// pq_injector — testnet PoC tool (CIP-0001).
//
// Builds and signs a version-3 post-quantum transaction that spends ONE testnet coinbase PQ output
// (an ML-KEM-768 stealth output) inside a ring of N real on-chain members, and prints the raw
// transaction as hex for `sendrawtransaction`.
//
// The testnet coinbase emits one fixed-denomination PQ output per block (global index g in
// m_pqOutputs[amount] == the output mined at height g+1), whose one-time key is derived from a
// Kyber-768 ciphertext (kemCt) published in the output. The injector cannot re-derive the key from
// height (Kyber encapsulation is randomised), so the demo script fetches each ring member's
// coinbase transaction (existing `gettransactions` RPC) and passes their raw hexes in a file. The
// injector parses each tx for its PqKeyOutput {key, kemCt}, scans the signer's kemCt with the
// testnet KEM secret to recover the spend key, and forms the ring from the on-chain keys.
//
// Usage:
//   pq_injector <amount> <fee> <signerLineIdx> <coinbaseHexFile>
//     coinbaseHexFile : N lines, each the raw hex of the coinbase tx at global indices 0..N-1
//                       (heights 1..N), in ascending order. signerLineIdx selects the signer.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/PqSpendBuilder.h" // shared, verified PQ spend builder
#include "CryptoNoteConfig.h"
#include "Common/StringTools.h"
#include "pq_ring_sig.h"
#include "pq_testnet_kem_keypair.h"

namespace
{
  std::string toHex(const std::vector<uint8_t> &d)
  {
    static const char *h = "0123456789abcdef";
    std::string o; o.reserve(d.size() * 2);
    for (uint8_t b : d) { o.push_back(h[b >> 4]); o.push_back(h[b & 0x0f]); }
    return o;
  }

  // Parse a coinbase tx hex, return its PqKeyOutput {key, kemCt} (assumed at output index 0).
  bool parseCoinbasePq(const std::string &hex, std::vector<uint8_t> &key, std::vector<uint8_t> &kemCt)
  {
    cn::BinaryArray blob;
    if (!common::fromHex(hex, blob)) { std::fprintf(stderr, "error: bad hex\n"); return false; }
    cn::Transaction tx;
    if (!cn::fromBinaryArray(tx, blob)) { std::fprintf(stderr, "error: tx deserialise failed\n"); return false; }
    if (tx.outputs.empty() || tx.outputs[0].target.type() != typeid(cn::PqKeyOutput))
    {
      std::fprintf(stderr, "error: coinbase output 0 is not a PqKeyOutput\n");
      return false;
    }
    const auto &o = boost::get<cn::PqKeyOutput>(tx.outputs[0].target);
    key = o.key; kemCt = o.kemCt;
    return true;
  }
}

int main(int argc, char **argv)
{
  if (argc < 5)
  {
    std::fprintf(stderr, "usage: %s <amount> <fee> <signerLineIdx> <coinbaseHexFile>\n", argv[0]);
    return 2;
  }
  const uint64_t amount = std::strtoull(argv[1], nullptr, 10);
  const uint64_t fee = std::strtoull(argv[2], nullptr, 10);
  const uint32_t signerIdx = static_cast<uint32_t>(std::strtoul(argv[3], nullptr, 10));
  const char *path = argv[4];

  std::vector<std::string> hexes;
  {
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) { if (!line.empty() && line[0] != '#') hexes.push_back(line); }
  }
  const uint32_t ringSize = static_cast<uint32_t>(hexes.size());
  if (amount == 0 || fee >= amount || ringSize == 0 || signerIdx >= ringSize)
  {
    std::fprintf(stderr, "error: need amount>0, fee<amount, non-empty file, signerLineIdx<ringSize(%u)\n", ringSize);
    return 2;
  }

  // Build the ring from the on-chain one-time keys and delegate to the shared, verified PQ spend
  // builder (the same code path concealwallet + walletd use). Global indices are 0..N-1: the demo
  // passes the coinbase PQ outputs mined at heights 1..N in ascending order, so line i == index i.
  cn::PqSpendRequest req;
  req.amount = amount;
  req.fee = fee;
  req.signerGlobalIndex = signerIdx;
  req.kemSecretKey.assign(cn::PQ_TESTNET_KEM_SK, cn::PQ_TESTNET_KEM_SK + sizeof(cn::PQ_TESTNET_KEM_SK));
  req.ring.reserve(ringSize);
  for (uint32_t i = 0; i < ringSize; ++i)
  {
    cn::PqRingMember m;
    m.globalIndex = i;
    if (!parseCoinbasePq(hexes[i], m.key, m.kemCt)) return 1;
    req.ring.push_back(std::move(m));
  }

  cn::Transaction tx;
  std::string err;
  if (!cn::buildPqSpendTransaction(req, tx, err))
  {
    std::fprintf(stderr, "error: %s\n", err.c_str());
    return 1;
  }
  std::fprintf(stderr, "[injector] signer output recognised as ours (KEM stealth scan OK)\n");

  cn::BinaryArray blob = cn::toBinaryArray(tx);
  std::printf("%s\n", toHex(blob).c_str());
  return 0;
}
