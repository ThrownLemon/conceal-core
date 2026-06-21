// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// PqEnumClient — the ONE shared paging helper for the read-only PQ output-enumeration RPCs
// (get_pq_outputs / get_pq_multisig_outputs). Both commands share an identical request/response
// shape (request{amounts, start_index, limit}; response{outs[], status}; outs_for_amount{amount,
// outs[], truncated, next_index}), so a single template walks either one.
//
// Why this exists: the node caps each amount's bucket at cn::PQ_GET_*_MAX_PER_AMOUNT entries PER
// PAGE (and that cap now bounds the expensive locked walk, not just the response). A wallet/client
// that issued a single request would therefore never see entries past index 999 — its own outputs
// could become permanently invisible (balance/receive/transfer/deposit/withdraw). This helper pages
// through every bucket (start_index = 0, then = next_index) until !truncated, accumulating all
// entries into one response in the SAME shape callers already iterate.
//
// Hard bound: it accumulates at most cn::PQ_WALLET_MAX_SCAN_OUTPUTS entries across ALL pages and
// amounts. If the on-chain set exceeds that, it STOPS and sets scanCapped = true (it never silently
// drops the overflow); callers must surface that the scan was incomplete rather than treating a
// capped result as the full set.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "CryptoNoteConfig.h" // PQ_WALLET_MAX_SCAN_OUTPUTS
#include "HttpClient.h"       // HttpClient
#include "JsonRpc.h"          // JsonRpc::invokeJsonRpcCommand
#include "CoreRpcServerCommandsDefinitions.h" // CORE_RPC_STATUS_OK + the PQ command structs

namespace cn
{
  // Enumerate every page of `method` for each requested amount into `outResponse`.
  //
  // On return true: outResponse.status == CORE_RPC_STATUS_OK and outResponse.outs holds one
  // outs_for_amount per requested amount (in request order), each with its full accumulated `outs`
  // (truncated cleared, next_index = the final bucket position scanned). scanCapped is true iff the
  // PQ_WALLET_MAX_SCAN_OUTPUTS budget was hit and enumeration stopped early — the accumulated set is
  // then a PREFIX of the on-chain set, not the whole thing.
  //
  // On return false: err is set (non-OK node status, or a node that reports truncated without making
  // forward progress). outResponse is left cleared.
  template <typename Command>
  bool pqEnumerateAllPages(HttpClient& httpClient,
                           const std::string& method,
                           const std::vector<uint64_t>& amounts,
                           typename Command::response& outResponse,
                           bool& scanCapped,
                           std::string& err)
  {
    outResponse.outs.clear();
    outResponse.status.clear();
    scanCapped = false;
    err.clear();

    size_t totalAccumulated = 0;
    outResponse.outs.reserve(amounts.size());

    for (uint64_t amount : amounts)
    {
      typename Command::outs_for_amount acc;
      acc.amount = amount;
      acc.truncated = false;
      acc.next_index = 0;

      uint32_t startIndex = 0;
      for (;;)
      {
        typename Command::request req;
        req.amounts.push_back(amount);
        req.start_index = startIndex;
        req.limit = 0; // 0 = the node's per-page cap (cn::PQ_GET_*_MAX_PER_AMOUNT)

        typename Command::response page;
        cn::JsonRpc::invokeJsonRpcCommand(httpClient, method, req, page);

        // A non-OK status means the node refused / errored; the body is then meaningless.
        if (page.status != CORE_RPC_STATUS_OK)
        {
          err = method + " failed: " + page.status;
          outResponse.outs.clear();
          return false;
        }

        // The node returns one outs_for_amount per requested amount; locate ours (it asked for one).
        const typename Command::outs_for_amount* pofa = nullptr;
        for (const auto& o : page.outs)
        {
          if (o.amount == amount)
          {
            pofa = &o;
            break;
          }
        }
        if (pofa == nullptr)
        {
          // No bucket for this amount on this page: nothing to accumulate, nothing to resume.
          break;
        }

        for (const auto& e : pofa->outs)
        {
          if (totalAccumulated >= cn::PQ_WALLET_MAX_SCAN_OUTPUTS)
          {
            scanCapped = true;
            break;
          }
          acc.outs.push_back(e);
          ++totalAccumulated;
        }
        acc.next_index = pofa->next_index;

        if (scanCapped)
        {
          break; // budget hit: stop without claiming completeness
        }
        if (!pofa->truncated)
        {
          break; // whole bucket for this amount has been read
        }
        // Forward-progress guard: a well-behaved node advances next_index past start_index when it
        // truncates. If it does not, paging would loop forever — refuse rather than spin.
        if (pofa->next_index <= startIndex)
        {
          err = method + " reported truncated without advancing (start_index=" +
                std::to_string(startIndex) + ", next_index=" + std::to_string(pofa->next_index) + ")";
          outResponse.outs.clear();
          return false;
        }
        startIndex = pofa->next_index;
      }

      outResponse.outs.push_back(acc);

      if (scanCapped)
      {
        break; // stop requesting further amounts once the total budget is exhausted
      }
    }

    outResponse.status = CORE_RPC_STATUS_OK;
    return true;
  }
}
