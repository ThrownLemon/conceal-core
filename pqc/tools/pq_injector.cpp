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

  const size_t pkBytes = ccx_pq_pubkey_bytes();

  // Build the ring from the on-chain one-time keys; remember the signer's key + kemCt.
  std::vector<uint8_t> ring;
  ring.reserve(static_cast<size_t>(ringSize) * pkBytes);
  std::vector<uint8_t> signerKey, signerKemCt;
  for (uint32_t i = 0; i < ringSize; ++i)
  {
    std::vector<uint8_t> key, kemCt;
    if (!parseCoinbasePq(hexes[i], key, kemCt)) return 1;
    if (key.size() != pkBytes) { std::fprintf(stderr, "error: ring member %u key size %zu\n", i, key.size()); return 1; }
    ring.insert(ring.end(), key.begin(), key.end());
    if (i == signerIdx) { signerKey = key; signerKemCt = kemCt; }
  }

  // Recover the signer's one-time keypair by decapsulating its kemCt with the testnet KEM secret.
  uint8_t otSeed[32];
  if (ccx_pq_kem_scan(cn::PQ_TESTNET_KEM_SK, sizeof(cn::PQ_TESTNET_KEM_SK),
                      signerKemCt.data(), signerKemCt.size(), otSeed, sizeof(otSeed)) != 0)
  {
    std::fprintf(stderr, "error: KEM scan failed\n");
    return 1;
  }
  std::vector<uint8_t> otPk(pkBytes, 0), otSk(ccx_pq_seckey_bytes(), 0);
  if (ccx_pq_keygen(otSeed, sizeof(otSeed), otPk.data(), otPk.size(), otSk.data(), otSk.size()) != 0)
  {
    std::fprintf(stderr, "error: keygen from recovered seed failed\n");
    return 1;
  }
  if (otPk != signerKey)
  {
    std::fprintf(stderr, "error: recovered one-time key does not match the on-chain output (not ours?)\n");
    return 1;
  }
  std::fprintf(stderr, "[injector] signer output recognised as ours (KEM stealth scan OK)\n");

  std::vector<uint8_t> nullifier(ccx_pq_nullifier_bytes(), 0);
  if (ccx_pq_nullifier(otSk.data(), otSk.size(), otPk.data(), otPk.size(),
                       nullifier.data(), nullifier.size()) != 0)
  {
    std::fprintf(stderr, "error: nullifier failed\n");
    return 1;
  }

  cn::PqKeyInput in;
  in.amount = amount;
  in.outputIndexes.resize(ringSize);
  in.outputIndexes[0] = 0;
  for (uint32_t i = 1; i < ringSize; ++i) in.outputIndexes[i] = 1; // consecutive global indices => deltas 1
  in.nullifier = nullifier;

  cn::PqKeyOutput out;
  out.key = otPk; // throwaway recipient; kemCt empty
  cn::TransactionOutput txout;
  txout.amount = amount - fee;
  txout.target = out;

  cn::Transaction tx;
  tx.version = cn::TRANSACTION_VERSION_3;
  tx.unlockTime = 0;
  tx.inputs.push_back(in);
  tx.outputs.push_back(txout);

  crypto::Hash signingHash = cn::getObjectHash(static_cast<const cn::TransactionPrefix &>(tx));

  std::vector<uint8_t> sig(256 * 1024, 0);
  size_t sigLen = sig.size();
  int32_t rc = ccx_pq_sign(
      reinterpret_cast<const uint8_t *>(&signingHash), sizeof(signingHash),
      ring.data(), ringSize, pkBytes,
      otSk.data(), otSk.size(), signerIdx,
      sig.data(), &sigLen);
  if (rc != 0) { std::fprintf(stderr, "error: sign failed (rc=%d)\n", (int)rc); return 1; }
  sig.resize(sigLen);

  boost::get<cn::PqKeyInput>(tx.inputs[0]).ringSig = sig;

  cn::BinaryArray blob = cn::toBinaryArray(tx);
  std::printf("%s\n", toHex(blob).c_str());
  return 0;
}
