// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PqDepositClient.h"

#include <algorithm>

#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteTools.h"   // getObjectHash, toBinaryArray
#include "CryptoNoteCore/PqDepositBuilder.h"  // buildPqDepositTransaction / buildPqWithdrawTransaction
#include "CryptoNoteConfig.h"                 // PQ_MIN/MAX_RING_SIZE
#include "HttpClient.h"                       // HttpClient, invokeJsonCommand (direct-path)
#include "JsonRpc.h"                          // JsonRpc::invokeJsonRpcCommand
#include "CoreRpcServerCommandsDefinitions.h"
#include "PqEnumClient.h"                      // pqEnumerateAllPages (paged get_pq_outputs)
#include "crypto/crypto.h"                    // crypto::rand<T> (CSPRNG; NOT std::mt19937)
#include "pq_ring_sig.h"                      // ccx_pq_kem_scan / ccx_pq_keygen (signer-ownership scan)

namespace cn
{
  namespace
  {
    bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out)
    {
      out.clear();
      return common::fromHex(hex, out);
    }

    void secure_wipe(void* p, size_t n)
    {
      if (p == nullptr || n == 0)
      {
        return;
      }
      volatile uint8_t* vp = static_cast<volatile uint8_t*>(p);
      while (n-- > 0)
      {
        *vp++ = 0;
      }
    }

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

    // Does a spendable PQ output belong to one of the candidate KEM secrets? Recovers the one-time key
    // the SAME way the builder does (ccx_pq_kem_scan -> ccx_pq_keygen -> compare). Read-only; wipes
    // transient secret material before returning.
    bool entryOwnedByCandidate(const COMMAND_RPC_GET_PQ_OUTPUTS::pq_out_entry& e,
                               const std::vector<std::vector<uint8_t>>& kemSecrets,
                               size_t pkBytes, size_t skBytes, size_t kemSkBytes)
    {
      if (e.kem.empty())
      {
        return false;
      }
      std::vector<uint8_t> kemCt;
      if (!hexToBytes(e.kem, kemCt))
      {
        return false;
      }
      std::vector<uint8_t> outKey;
      if (!hexToBytes(e.key, outKey) || outKey.size() != pkBytes)
      {
        return false;
      }
      for (const auto& kemSk : kemSecrets)
      {
        if (kemSk.size() != kemSkBytes)
        {
          continue;
        }
        uint8_t otSeed[32];
        if (ccx_pq_kem_scan(kemSk.data(), kemSk.size(), kemCt.data(), kemCt.size(),
                            otSeed, sizeof(otSeed)) != 0)
        {
          secure_wipe(otSeed, sizeof(otSeed));
          continue;
        }
        std::vector<uint8_t> otPk(pkBytes, 0), otSk(skBytes, 0);
        const int32_t rc = ccx_pq_keygen(otSeed, sizeof(otSeed), otPk.data(), otPk.size(),
                                         otSk.data(), otSk.size());
        secure_wipe(otSeed, sizeof(otSeed));
        secure_wipe(otSk.data(), otSk.size());
        if (rc == 0 && otPk == outKey)
        {
          return true;
        }
      }
      return false;
    }
  } // namespace

  bool pqDepositViaDaemon(platform_system::Dispatcher& dispatcher,
                          const std::string& daemonHost,
                          uint16_t daemonPort,
                          uint64_t inputAmount,
                          uint64_t amount,
                          uint64_t fee,
                          uint32_t term,
                          uint32_t ringSize,
                          const std::vector<std::vector<uint8_t>>& candidateKemSecretKeys,
                          const std::vector<uint8_t>& depositDsaPubKey,
                          const std::vector<uint8_t>& changeKemPubKey,
                          std::string& outTxHashHex,
                          std::string& outStatus,
                          std::string& err)
  {
    outTxHashHex.clear();
    outStatus.clear();
    err.clear();

    if (ringSize < cn::PQ_MIN_RING_SIZE || ringSize > cn::PQ_MAX_RING_SIZE)
    {
      err = "ring size " + std::to_string(ringSize) + " out of bounds [" +
            std::to_string(cn::PQ_MIN_RING_SIZE) + "," + std::to_string(cn::PQ_MAX_RING_SIZE) + "]";
      return false;
    }
    if (inputAmount < amount || inputAmount - amount < fee)
    {
      err = "funding input " + std::to_string(inputAmount) + " does not cover amount + fee";
      return false;
    }

    std::vector<std::vector<uint8_t>> kemSecrets;
    for (const auto& sk : candidateKemSecretKeys)
    {
      if (!sk.empty())
      {
        kemSecrets.push_back(sk);
      }
    }
    if (kemSecrets.empty())
    {
      err = "no candidate KEM secret keys supplied";
      return false;
    }
    struct KemSecretsWiper
    {
      std::vector<std::vector<uint8_t>>& v;
      ~KemSecretsWiper()
      {
        for (size_t i = 0; i < v.size(); ++i)
        {
          secure_wipe(v[i].data(), v[i].size());
        }
      }
    } kemSecretsWiper{kemSecrets};

    const size_t pkBytes = ccx_pq_pubkey_bytes();
    const size_t skBytes = ccx_pq_seckey_bytes();
    const size_t kemSkBytes = ccx_pq_kem_seckey_bytes();
    if (pkBytes == 0 || skBytes == 0 || kemSkBytes == 0)
    {
      err = "ccx-pqc reports zero key size";
      return false;
    }

    try
    {
      HttpClient httpClient(dispatcher, daemonHost, daemonPort);

      // 1. enumerate spendable PQ outputs for the funding amount (paged so funding outputs past the
      //    node's per-page cap remain reachable; helper enforces the PQ_WALLET_MAX_SCAN_OUTPUTS budget).
      const std::vector<uint64_t> amts(1, inputAmount);
      cn::COMMAND_RPC_GET_PQ_OUTPUTS::response gres;
      bool scanCapped = false;
      if (!pqEnumerateAllPages<cn::COMMAND_RPC_GET_PQ_OUTPUTS>(httpClient, "get_pq_outputs", amts, gres, scanCapped, err))
      {
        return false; // err already set by the helper
      }
      if (scanCapped)
      {
        err = "PQ output set for amount " + std::to_string(inputAmount) + " exceeds the wallet scan budget of " +
              std::to_string(cn::PQ_WALLET_MAX_SCAN_OUTPUTS) + "; aborting.";
        return false;
      }

      // 2. collect the spendable entries for inputAmount and the subset this wallet owns.
      std::vector<COMMAND_RPC_GET_PQ_OUTPUTS::pq_out_entry> spendable;
      for (const auto& ofa : gres.outs)
      {
        if (ofa.amount != inputAmount)
        {
          continue;
        }
        for (const auto& e : ofa.outs)
        {
          if (e.spendable)
          {
            spendable.push_back(e);
          }
        }
      }
      if (spendable.size() < ringSize)
      {
        err = "not enough spendable PQ outputs to form a ring of " + std::to_string(ringSize) +
              " (have " + std::to_string(spendable.size()) + ")";
        return false;
      }

      std::vector<size_t> owned;
      for (size_t i = 0; i < spendable.size(); ++i)
      {
        if (entryOwnedByCandidate(spendable[i], kemSecrets, pkBytes, skBytes, kemSkBytes))
        {
          owned.push_back(i);
        }
      }
      if (owned.empty())
      {
        err = "no spendable PQ output of amount " + std::to_string(inputAmount) + " is owned by this wallet";
        return false;
      }

      // 3. attempt loop: random owned signer + random decoys, build, relay (up to 8 tries).
      const size_t maxAttempts = std::min<size_t>(8, owned.size());
      std::vector<bool> ownedTried(owned.size(), false);
      size_t triedCount = 0;
      err = "PQ deposit: no attempt succeeded";

      for (size_t attempt = 0; attempt < maxAttempts && triedCount < owned.size(); ++attempt)
      {
        size_t ownedPos = cryptoRandIndex(owned.size());
        while (ownedTried[ownedPos])
        {
          ownedPos = (ownedPos + 1) % owned.size();
        }
        ownedTried[ownedPos] = true;
        ++triedCount;
        const size_t signerSlot = owned[ownedPos];

        std::vector<bool> inRing(spendable.size(), false);
        std::vector<size_t> chosen;
        chosen.push_back(signerSlot);
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

        cn::PqDepositRequest dreq;
        dreq.amount = amount;
        dreq.fee = fee;
        dreq.term = term;
        dreq.inputAmount = inputAmount;
        dreq.signerGlobalIndex = spendable[signerSlot].global_index;
        dreq.depositDsaPubKey = depositDsaPubKey;
        dreq.changeKemPubKey = changeKemPubKey;

        bool malformed = false;
        dreq.ring.reserve(ringSize);
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
          dreq.ring.push_back(member);
        }
        if (malformed)
        {
          continue;
        }

        cn::Transaction tx;
        bool built = false;
        for (size_t c = 0; c < kemSecrets.size(); ++c)
        {
          dreq.kemSecretKey = kemSecrets[c];
          const bool ok = cn::buildPqDepositTransaction(dreq, tx, err);
          secure_wipe(dreq.kemSecretKey.data(), dreq.kemSecretKey.size());
          dreq.kemSecretKey.clear();
          if (ok)
          {
            built = true;
            break;
          }
        }
        if (!built)
        {
          continue;
        }

        cn::COMMAND_RPC_SEND_RAW_TX::request rreq;
        rreq.tx_as_hex = common::toHex(cn::toBinaryArray(tx));
        cn::COMMAND_RPC_SEND_RAW_TX::response rres;
        cn::invokeJsonCommand(httpClient, "/sendrawtransaction", rreq, rres);
        if (rres.status != CORE_RPC_STATUS_OK)
        {
          err = "relay rejected: " + rres.status;
          continue;
        }

        outStatus = rres.status;
        outTxHashHex = common::podToHex(cn::getObjectHash(tx));
        return true;
      }

      return false;
    }
    catch (const std::exception& e)
    {
      err = std::string("PQ deposit via daemon failed: ") + e.what();
      return false;
    }
  }

  bool pqWithdrawViaDaemon(platform_system::Dispatcher& dispatcher,
                           const std::string& daemonHost,
                           uint16_t daemonPort,
                           uint64_t amount,
                           uint32_t outputIndex,
                           uint32_t term,
                           uint8_t requiredSignatureCount,
                           uint64_t interest,
                           const std::vector<std::vector<uint8_t>>& signingSecretKeys,
                           const std::vector<uint8_t>& payoutKemPubKey,
                           std::string& outTxHashHex,
                           std::string& outStatus,
                           std::string& err)
  {
    outTxHashHex.clear();
    outStatus.clear();
    err.clear();

    try
    {
      HttpClient httpClient(dispatcher, daemonHost, daemonPort);

      cn::PqWithdrawRequest wreq;
      wreq.amount = amount;
      wreq.outputIndex = outputIndex;
      wreq.term = term;
      wreq.requiredSignatureCount = requiredSignatureCount;
      wreq.interest = interest;
      wreq.signingSecretKeys = signingSecretKeys;
      wreq.payoutKemPubKey = payoutKemPubKey;

      cn::Transaction tx;
      if (!cn::buildPqWithdrawTransaction(wreq, tx, err))
      {
        return false;
      }

      cn::COMMAND_RPC_SEND_RAW_TX::request rreq;
      rreq.tx_as_hex = common::toHex(cn::toBinaryArray(tx));
      cn::COMMAND_RPC_SEND_RAW_TX::response rres;
      cn::invokeJsonCommand(httpClient, "/sendrawtransaction", rreq, rres);
      if (rres.status != CORE_RPC_STATUS_OK)
      {
        err = "relay rejected: " + rres.status;
        return false;
      }

      outStatus = rres.status;
      outTxHashHex = common::podToHex(cn::getObjectHash(tx));
      return true;
    }
    catch (const std::exception& e)
    {
      err = std::string("PQ withdraw via daemon failed: ") + e.what();
      return false;
    }
  }
}
