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
#include "pq_ring_sig.h"                      // ccx_pq_kem_scan / ccx_pq_keygen (signer-ownership scan)

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

    // Best-effort zeroisation of a sensitive buffer the optimiser may not elide (same volatile
    // byte-writer pattern as PqSpendBuilder.cpp's secure_wipe). A plain std::fill on a soon-to-die
    // buffer can be dead-code-eliminated; this cannot.
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

    // Does a spendable entry belong to one of the candidate KEM secrets? Recovers the one-time key
    // the SAME way the builder does — ccx_pq_kem_scan(secret, kemCt) -> 32-byte seed, ccx_pq_keygen
    // (seed) -> one-time pubkey, compare to the on-chain output key — so the answer is exactly "can a
    // candidate actually sign this output". Read-only; no signing. Transient secret material is
    // securely wiped before returning.
    bool entryOwnedByCandidate(const COMMAND_RPC_GET_PQ_OUTPUTS::pq_out_entry& e,
                               const std::vector<std::vector<uint8_t>>& kemSecrets,
                               size_t pkBytes,
                               size_t skBytes,
                               size_t kemSkBytes)
    {
      // An output with no kemCt is a throwaway/injector output — not scannable, never ours.
      if (e.kem.empty())
      {
        return false;
      }
      std::vector<uint8_t> kemCt;
      if (!hexToBytes(e.kem, kemCt))
      {
        return false; // malformed on-chain kem hex — skip
      }
      std::vector<uint8_t> outKey;
      if (!hexToBytes(e.key, outKey) || outKey.size() != pkBytes)
      {
        return false; // malformed / wrong-size on-chain key hex — skip
      }

      for (size_t c = 0; c < kemSecrets.size(); ++c)
      {
        const std::vector<uint8_t>& kemSk = kemSecrets[c];
        if (kemSk.size() != kemSkBytes)
        {
          continue; // wrong-size candidate — never hand a bad length to the FFI
        }
        uint8_t otSeed[32];
        if (ccx_pq_kem_scan(kemSk.data(), kemSk.size(), kemCt.data(), kemCt.size(),
                            otSeed, sizeof(otSeed)) != 0)
        {
          continue; // not ours under this candidate
        }
        std::vector<uint8_t> otPk(pkBytes, 0), otSk(skBytes, 0);
        const int32_t rc = ccx_pq_keygen(otSeed, sizeof(otSeed), otPk.data(), otPk.size(),
                                         otSk.data(), otSk.size());
        // Wipe the recovered secret material immediately; this scan never signs with it.
        secure_wipe(otSeed, sizeof(otSeed));
        secure_wipe(otSk.data(), otSk.size());
        if (rc == 0 && otPk == outKey)
        {
          return true;
        }
      }
      return false;
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
                        const std::vector<std::vector<uint8_t>>& candidateKemSecretKeys,
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

    // ---- candidate KEM secrets: need at least one non-empty key to scan a signer -----------------
    // Filter out empty entries up front so the per-signer loop below never wastes an attempt on one.
    std::vector<std::vector<uint8_t>> kemSecrets;
    kemSecrets.reserve(candidateKemSecretKeys.size());
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

    // FIX (hygiene): kemSecrets holds live copies of the candidate KEM secret keys for the whole
    // function. Wipe every byte on EVERY exit path (all returns + the catch below) with the same
    // non-elidable secure_wipe the builder uses, so the secrets do not outlive this call.
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

      // ---- 2b. restrict signer candidates to OUTPUTS WE ACTUALLY OWN -----------------------------
      //
      // FIX (liveness): the old loop drew the signer at random from ALL spendable outputs and gave
      // up after 8 tries. On a pool with many outputs but few owned, a wallet↔wallet re-spend could
      // exhaust its 8 random draws without ever hitting an owned signer and fail even though an
      // owned, spendable output existed. We now first identify which spendable outputs a candidate
      // KEM secret can sign (same ownership test the builder applies — scan the kemCt, re-derive the
      // one-time key, compare to the on-chain key) and pick the SIGNER only from that owned set, so a
      // spendable owned output always yields a usable signer. Decoys are still drawn from ALL
      // spendable outputs (below) to preserve the anonymity set.
      const size_t pkBytes = ccx_pq_pubkey_bytes();
      const size_t skBytes = ccx_pq_seckey_bytes();
      const size_t kemSkBytes = ccx_pq_kem_seckey_bytes();
      if (pkBytes == 0 || skBytes == 0 || kemSkBytes == 0)
      {
        err = "ccx-pqc reports zero key size (FFI unavailable)";
        return false;
      }

      std::vector<size_t> owned; // indices into `spendable` that a candidate secret can sign
      owned.reserve(spendable.size());
      for (size_t i = 0; i < spendable.size(); ++i)
      {
        if (entryOwnedByCandidate(spendable[i], kemSecrets, pkBytes, skBytes, kemSkBytes))
        {
          owned.push_back(i);
        }
      }
      if (owned.empty())
      {
        err = "no spendable PQ output is owned by any candidate KEM secret";
        return false;
      }

      // ---- 3-5. attempt loop: owned signer + random decoys, build, relay --------------------------
      //
      // FIX B: the old code always picked signer = lowest global index + ring = the first
      // `ringSize` outputs. Two problems that this loop fixes:
      //   (1) if that output was already spent, every call re-picked it -> permanent failure;
      //   (2) identical ring membership + signer position across spends is trivially linkable on a
      //       privacy coin.
      // Each attempt picks a RANDOM (not-yet-tried) signer FROM THE OWNED SET and RANDOM ringSize-1
      // distinct decoys from ALL spendable outputs (CSPRNG — crypto::rand, NOT std::mt19937). The
      // builder re-sorts the ring by global index internally, so the entropy is in WHICH outputs are
      // chosen + which one signs. If build or relay fails we fall through to the next attempt with a
      // different owned signer; the last error is returned once attempts are exhausted.
      const size_t maxAttempts = std::min<size_t>(8, owned.size());

      // Track which OWNED slots we have already tried so each attempt uses a fresh signer.
      std::vector<bool> ownedTried(owned.size(), false);
      size_t triedCount = 0;

      err = "PQ spend: no attempt succeeded";

      for (size_t attempt = 0; attempt < maxAttempts && triedCount < owned.size(); ++attempt)
      {
        // Pick a random owned slot we have not tried yet; map it back to a `spendable` index.
        size_t ownedPos = cryptoRandIndex(owned.size());
        while (ownedTried[ownedPos])
        {
          ownedPos = (ownedPos + 1) % owned.size();
        }
        ownedTried[ownedPos] = true;
        ++triedCount;
        const size_t signerSlot = owned[ownedPos];

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

        // Assemble the spend request from the chosen slots. The ring + signer do not depend on the
        // KEM secret, so build them once; only sreq.kemSecretKey varies across candidates below.
        cn::PqSpendRequest sreq;
        sreq.amount = amount;
        sreq.fee = fee;
        sreq.signerGlobalIndex = spendable[signerSlot].global_index;
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

        // ---- build + sign: try each candidate KEM secret for this signer ------------------------
        // A wrong secret makes the builder's KEM scan fail ("output not ours"), so fall through to
        // the next candidate. The signer output belongs to exactly one of them (the fixed testnet
        // key for coinbase outputs, or the wallet's own seed-derived key for received outputs).
        cn::Transaction tx;
        bool built = false;
        for (size_t c = 0; c < kemSecrets.size(); ++c)
        {
          sreq.kemSecretKey = kemSecrets[c];
          const bool ok = cn::buildPqSpendTransaction(sreq, tx, err);
          // FIX (hygiene): sreq.kemSecretKey holds a live copy of a candidate KEM secret. Wipe it
          // with a non-elidable secure_wipe before the next candidate (or before leaving the loop)
          // so the transient copy does not linger in the request buffer between attempts.
          secure_wipe(sreq.kemSecretKey.data(), sreq.kemSecretKey.size());
          sreq.kemSecretKey.clear();
          if (ok)
          {
            built = true;
            break;
          }
          // else: this candidate did not own the signer (scan failed) — try the next candidate.
        }
        if (!built)
        {
          // No candidate owned this signer (already-spent class / not ours) — try a different signer.
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
