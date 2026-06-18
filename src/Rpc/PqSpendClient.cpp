// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PqSpendClient.h"

#include <algorithm>

#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteTools.h"  // getObjectHash, toBinaryArray
#include "CryptoNoteCore/PqSpendBuilder.h"   // cn::buildPqSpendTransaction, PqSpendRequest, PqRingMember
#include "CryptoNoteConfig.h"                // PQ_MIN/MAX_RING_SIZE
#include "HttpClient.h"                      // HttpClient, invokeJsonCommand (direct-path)
#include "JsonRpc.h"                          // JsonRpc::invokeJsonRpcCommand
#include "CoreRpcServerCommandsDefinitions.h"

#include "pq_testnet_kem_keypair.h"           // PQ_TESTNET_KEM_SK (testnet KEM secret)

namespace cn
{
  namespace
  {
    // Decode a hex string into a byte vector; returns false on malformed input.
    bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out)
    {
      out.clear();
      return common::fromHex(hex, out);
    }
  }

  bool pqSpendViaDaemon(platform_system::Dispatcher& dispatcher,
                        const std::string& daemonHost,
                        uint16_t daemonPort,
                        uint64_t amount,
                        uint64_t fee,
                        uint32_t ringSize,
                        const std::vector<uint8_t>& recipientKemPubKey,
                        std::string& outTxHashHex,
                        std::string& outStatus,
                        std::string& err)
  {
    outTxHashHex.clear();
    outStatus.clear();
    err.clear();

    // ---- ring-size sanity (also enforced by the builder + consensus) -----------------------------
    if (ringSize < cn::PQ_MIN_RING_SIZE || ringSize > cn::PQ_MAX_RING_SIZE)
    {
      err = "ring size " + std::to_string(ringSize) + " out of bounds [" +
            std::to_string(cn::PQ_MIN_RING_SIZE) + "," + std::to_string(cn::PQ_MAX_RING_SIZE) + "]";
      return false;
    }

    try
    {
      HttpClient httpClient(dispatcher, daemonHost, daemonPort);

      // ---- 1. enumerate PQ outputs for this amount ----------------------------------------------
      COMMAND_RPC_GET_PQ_OUTPUTS::request greq;
      greq.amounts.push_back(amount);
      COMMAND_RPC_GET_PQ_OUTPUTS::response gres;
      cn::JsonRpc::invokeJsonRpcCommand(httpClient, "get_pq_outputs", greq, gres);

      const COMMAND_RPC_GET_PQ_OUTPUTS::outs_for_amount* ofa = nullptr;
      for (const auto& o : gres.outs)
      {
        if (o.amount == amount)
        {
          ofa = &o;
          break;
        }
      }
      if (ofa == nullptr || ofa->outs.empty())
      {
        err = "no PQ outputs for amount " + std::to_string(amount);
        return false;
      }

      // ---- 2. collect spendable entries, sorted by ascending global index -----------------------
      std::vector<COMMAND_RPC_GET_PQ_OUTPUTS::pq_out_entry> spendable;
      spendable.reserve(ofa->outs.size());
      for (const auto& e : ofa->outs)
      {
        if (e.spendable)
        {
          spendable.push_back(e);
        }
      }

      if (spendable.size() < ringSize)
      {
        err = "not enough spendable PQ outputs: have " + std::to_string(spendable.size()) +
              ", need " + std::to_string(ringSize);
        return false;
      }

      std::sort(spendable.begin(), spendable.end(),
                [](const COMMAND_RPC_GET_PQ_OUTPUTS::pq_out_entry& a,
                   const COMMAND_RPC_GET_PQ_OUTPUTS::pq_out_entry& b) {
                  return a.global_index < b.global_index;
                });

      // Signer = the spendable entry with the lowest global index (== spendable[0] after the sort).
      // The ring = the first `ringSize` spendable entries by ascending global index; this always
      // includes the signer, and the indices are distinct (each entry is a distinct output).
      const uint32_t signerGlobalIndex = spendable[0].global_index;

      // ---- 3. build the spend request ------------------------------------------------------------
      cn::PqSpendRequest sreq;
      sreq.amount = amount;
      sreq.fee = fee;
      sreq.signerGlobalIndex = signerGlobalIndex;
      sreq.kemSecretKey.assign(cn::PQ_TESTNET_KEM_SK, cn::PQ_TESTNET_KEM_SK + sizeof(cn::PQ_TESTNET_KEM_SK));
      sreq.recipientKemPubKey = recipientKemPubKey;

      sreq.ring.reserve(ringSize);
      for (uint32_t i = 0; i < ringSize; ++i)
      {
        const COMMAND_RPC_GET_PQ_OUTPUTS::pq_out_entry& e = spendable[i];

        cn::PqRingMember member;
        member.globalIndex = e.global_index;
        if (!hexToBytes(e.key, member.key))
        {
          err = "malformed output key hex at global index " + std::to_string(e.global_index);
          return false;
        }
        if (!e.kem.empty() && !hexToBytes(e.kem, member.kemCt))
        {
          err = "malformed output kem hex at global index " + std::to_string(e.global_index);
          return false;
        }
        sreq.ring.push_back(member);
      }

      // ---- 4. build + sign the transaction (all crypto happens inside the shared builder) --------
      cn::Transaction tx;
      if (!cn::buildPqSpendTransaction(sreq, tx, err))
      {
        return false;
      }

      // ---- 5. relay the signed tx via the direct-path sendrawtransaction command ----------------
      cn::COMMAND_RPC_SEND_RAW_TX::request rreq;
      rreq.tx_as_hex = common::toHex(cn::toBinaryArray(tx));
      cn::COMMAND_RPC_SEND_RAW_TX::response rres;
      cn::invokeJsonCommand(httpClient, "/sendrawtransaction", rreq, rres);

      outStatus = rres.status;
      outTxHashHex = common::podToHex(cn::getObjectHash(tx));
      return true;
    }
    catch (const std::exception& e)
    {
      err = std::string("PQ spend via daemon failed: ") + e.what();
      return false;
    }
  }
}
