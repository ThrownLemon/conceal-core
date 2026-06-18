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
#include "crypto/crypto.h"                    // crypto::rand<T> (CSPRNG; NOT std::mt19937)

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

    // Uniform random index in [0, n) using the project CSPRNG (crypto::rand — the same secure
    // source used by Miner/NetNode/WalletGreen — NOT std::mt19937; the same lesson as the wallet
    // KDF: privacy-relevant randomness must come from a secure source). Rejection-samples to avoid
    // modulo bias; n must be > 0.
    size_t cryptoRandIndex(size_t n)
    {
      const uint64_t limit = UINT64_MAX - (UINT64_MAX % n);
      uint64_t r = 0;
      do
      {
        r = crypto::rand<uint64_t>();
      } while (r >= limit);
      return static_cast<size_t>(r % n);
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

      // FIX A: a non-OK status means the node refused / errored; the response body is then
      // meaningless. Surface it instead of treating an empty/partial result as "no outputs".
      if (gres.status != CORE_RPC_STATUS_OK)
      {
        err = "get_pq_outputs failed: " + gres.status;
        return false;
      }

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

      // ---- 2. collect spendable entries -----------------------------------------------------------
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

      // ---- 3-5. attempt loop: random signer + random decoys, build, relay -------------------------
      //
      // FIX B: the old code always picked signer = lowest global index + ring = the first
      // `ringSize` outputs. Two problems that this loop fixes:
      //   (1) if that output was already spent, every call re-picked it -> permanent failure;
      //   (2) identical ring membership + signer position across spends is trivially linkable on a
      //       privacy coin.
      // Each attempt picks a RANDOM (not-yet-tried) signer and RANDOM ringSize-1 distinct decoys
      // (CSPRNG — crypto::rand, NOT std::mt19937). The builder re-sorts the ring by global index
      // internally, so the entropy is in WHICH outputs are chosen + which one signs. If build or
      // relay fails we fall through to the next attempt with a different signer; the last error is
      // returned once attempts are exhausted.
      const size_t maxAttempts = std::min<size_t>(8, spendable.size());

      // Track which signer slots we have already tried so each attempt uses a fresh one.
      std::vector<bool> signerTried(spendable.size(), false);
      size_t triedCount = 0;

      err = "PQ spend: no attempt succeeded";

      for (size_t attempt = 0; attempt < maxAttempts && triedCount < spendable.size(); ++attempt)
      {
        // Pick a random signer slot we have not tried yet.
        size_t signerSlot = cryptoRandIndex(spendable.size());
        while (signerTried[signerSlot])
        {
          signerSlot = (signerSlot + 1) % spendable.size();
        }
        signerTried[signerSlot] = true;
        ++triedCount;

        // Pick ringSize-1 distinct decoy slots != signerSlot, uniformly at random.
        std::vector<size_t> chosen;
        chosen.reserve(ringSize);
        chosen.push_back(signerSlot);
        std::vector<bool> inRing(spendable.size(), false);
        inRing[signerSlot] = true;
        while (chosen.size() < ringSize)
        {
          size_t slot = cryptoRandIndex(spendable.size());
          if (!inRing[slot])
          {
            inRing[slot] = true;
            chosen.push_back(slot);
          }
        }

        // Assemble the spend request from the chosen slots.
        cn::PqSpendRequest sreq;
        sreq.amount = amount;
        sreq.fee = fee;
        sreq.signerGlobalIndex = spendable[signerSlot].global_index;
        sreq.kemSecretKey.assign(cn::PQ_TESTNET_KEM_SK, cn::PQ_TESTNET_KEM_SK + sizeof(cn::PQ_TESTNET_KEM_SK));
        sreq.recipientKemPubKey = recipientKemPubKey;

        bool malformed = false;
        sreq.ring.reserve(ringSize);
        for (size_t k = 0; k < chosen.size(); ++k)
        {
          const COMMAND_RPC_GET_PQ_OUTPUTS::pq_out_entry& e = spendable[chosen[k]];

          cn::PqRingMember member;
          member.globalIndex = e.global_index;
          if (!hexToBytes(e.key, member.key))
          {
            err = "malformed output key hex at global index " + std::to_string(e.global_index);
            malformed = true;
            break;
          }
          if (!e.kem.empty() && !hexToBytes(e.kem, member.kemCt))
          {
            err = "malformed output kem hex at global index " + std::to_string(e.global_index);
            malformed = true;
            break;
          }
          sreq.ring.push_back(member);
        }
        if (malformed)
        {
          // A malformed on-chain entry is not fixed by retrying with the same signer, but a
          // different ring may avoid it; try the next attempt.
          continue;
        }

        // ---- build + sign the transaction (all crypto happens inside the shared builder) ---------
        cn::Transaction tx;
        if (!cn::buildPqSpendTransaction(sreq, tx, err))
        {
          // Build failed (e.g. signer not ours / already-spent class) — try a different signer.
          continue;
        }

        // ---- relay the signed tx via the direct-path sendrawtransaction command -----------------
        cn::COMMAND_RPC_SEND_RAW_TX::request rreq;
        rreq.tx_as_hex = common::toHex(cn::toBinaryArray(tx));
        cn::COMMAND_RPC_SEND_RAW_TX::response rres;
        cn::invokeJsonCommand(httpClient, "/sendrawtransaction", rreq, rres);

        // FIX A: a rejected relay used to return true (false success). Check the status: only an
        // OK relay is a real success; otherwise record the reason and try the next signer.
        if (rres.status != CORE_RPC_STATUS_OK)
        {
          err = "relay rejected: " + rres.status;
          continue;
        }

        outStatus = rres.status;
        outTxHashHex = common::podToHex(cn::getObjectHash(tx));
        return true;
      }

      // All attempts exhausted; `err` holds the last failure reason.
      return false;
    }
    catch (const std::exception& e)
    {
      err = std::string("PQ spend via daemon failed: ") + e.what();
      return false;
    }
  }
}
