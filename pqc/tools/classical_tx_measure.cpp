// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// classical_tx_measure — measurement-only PoC tool (CIP-0001 measured-numbers).
//
// Constructs a REAL classical CryptoNote transaction with the project's own
// cn::constructTransaction (ring signatures over a ring of MINIMUM_MIXIN+1 members)
// and prints the live-serialized size + structure. No consensus/crypto code is
// touched — this links the built CryptoNoteCore library and measures its actual
// serialization, exactly like the daemon would produce. Mirrors the source/ring
// setup used by tests/PerformanceTests/MultiTransactionTestBase.h.
//
// Usage:  classical_tx_measure <in_count> <out_count> [mixin]
//   mixin defaults to cn::parameters::MINIMUM_MIXIN (5). Ring size = mixin + 1.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteConfig.h"
#include "Logging/ConsoleLogger.h"

int main(int argc, char **argv)
{
  using namespace cn;

  if (argc < 3)
  {
    std::fprintf(stderr, "usage: %s <in_count> <out_count> [mixin]\n", argv[0]);
    return 2;
  }
  const size_t inCount = std::strtoull(argv[1], nullptr, 10);
  const size_t outCount = std::strtoull(argv[2], nullptr, 10);
  const size_t mixin = (argc > 3) ? std::strtoull(argv[3], nullptr, 10)
                                  : cn::parameters::MINIMUM_MIXIN;
  const size_t ringSize = mixin + 1; // ring members per input = mixin decoys + 1 real
  if (inCount == 0 || outCount == 0 || ringSize == 0)
  {
    std::fprintf(stderr, "error: in_count>0, out_count>0, ringSize>0 required\n");
    return 2;
  }

  logging::ConsoleLogger logger(logging::ERROR);
  Currency currency = CurrencyBuilder(logger).currency();

  // Build inCount independent sources, each backed by a ring of `ringSize` distinct
  // miner-tx outputs (one of them the real spend). Same construction the perf test uses.
  std::vector<TransactionSourceEntry> sources;
  // A single sender owns the REAL output of every input (constructTransaction signs all real
  // inputs with one keypair); decoy ring members are unrelated random miner outputs.
  AccountBase sender;
  sender.generate();

  uint64_t sourceAmount = 0;
  for (size_t s = 0; s < inCount; ++s)
  {
    std::vector<Transaction> minerTxs(ringSize);
    std::vector<TransactionSourceEntry::OutputEntry> outputEntries;
    const size_t realIdx = ringSize / 2;
    Transaction realMinerTx;

    for (uint32_t i = 0; i < ringSize; ++i)
    {
      // The real ring member pays the sender; the decoys pay throwaway accounts.
      AccountBase owner;
      if (i == realIdx) {
        owner = sender;
      } else {
        owner.generate();
      }
      if (!currency.constructMinerTx(0, 0, 0, 2, 0, owner.getAccountKeys().address, minerTxs[i]))
      {
        std::fprintf(stderr, "error: constructMinerTx failed\n");
        return 1;
      }
      KeyOutput txOut = boost::get<KeyOutput>(minerTxs[i].outputs[0].target);
      // Use a realistic-looking global index (monotone) so varint widths are representative.
      outputEntries.push_back(std::make_pair(static_cast<uint32_t>(s * 1000 + i * 7 + 100000), txOut.key));
    }

    sourceAmount = minerTxs[realIdx].outputs[0].amount;

    TransactionSourceEntry src;
    src.amount = sourceAmount;
    src.realTransactionPublicKey = getTransactionPublicKeyFromExtra(minerTxs[realIdx].extra);
    src.realOutputIndexInTransaction = 0;
    src.outputs = outputEntries;
    src.realOutput = realIdx;
    sources.push_back(src);
  }

  // Total input value; split across outCount destinations to a fresh account.
  // (constructTransaction requires sum(out) + fee == sum(in); fee 0 keeps it exact.)
  uint64_t totalIn = sourceAmount * inCount;
  AccountBase bob;
  bob.generate();
  std::vector<TransactionDestinationEntry> destinations;
  uint64_t per = totalIn / outCount;
  uint64_t acc = 0;
  for (size_t o = 0; o < outCount; ++o)
  {
    uint64_t amt = (o + 1 == outCount) ? (totalIn - acc) : per;
    acc += amt;
    destinations.push_back(TransactionDestinationEntry(amt, bob.getAccountKeys().address));
  }

  Transaction tx;
  crypto::SecretKey txSK;
  bool ok = constructTransaction(sender.getAccountKeys(), sources, destinations,
                                 std::vector<uint8_t>(), tx, 0, logger, txSK);
  if (!ok)
  {
    std::fprintf(stderr, "error: constructTransaction failed (in=%zu out=%zu mixin=%zu)\n",
                 inCount, outCount, mixin);
    return 1;
  }

  size_t bytes = getObjectBinarySize(tx);
  size_t sigGroups = tx.signatures.size();
  size_t sigCount0 = sigGroups ? tx.signatures[0].size() : 0;
  std::printf("in_count=%zu out_count=%zu mixin=%zu ring_size=%zu "
              "tx_bytes=%zu inputs=%zu outputs=%zu sig_groups=%zu ring_per_input=%zu\n",
              inCount, outCount, mixin, ringSize, bytes,
              tx.inputs.size(), tx.outputs.size(), sigGroups, sigCount0);
  return 0;
}
