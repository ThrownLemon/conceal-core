// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// PqSpendClient — wallet-side helper that builds + relays a post-quantum SPEND through a daemon.
//
// It is the ONE place the concealwallet CLI and the walletd (PaymentGate) RPC service share to
// turn "spend a fixed-denomination PQ output" into a relayed transaction. All it does is talk to
// a daemon over HTTP:
//   1. get_pq_outputs (JSON-RPC) to enumerate spendable PQ outputs for the amount,
//   2. assemble a ring from the spendable entries and hand it to cn::buildPqSpendTransaction
//      (the already-verified shared builder in CryptoNoteCore — all crypto happens there),
//   3. sendrawtransaction to relay the signed tx.
//
// No crypto lives here: the builder does the KEM scan + lattice ring-sign internally and returns
// false if the chosen signer output is not spendable with the supplied KEM secret. The helper
// therefore tries each candidate KEM secret in turn for a chosen signer until one scans.
//
// Testnet only / experimental: the candidate KEM secrets include the hardcoded testnet keypair and
// the lattice ring signature is unaudited. Not for mainnet funds.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <System/Dispatcher.h>

namespace cn
{
  // Build + relay a PQ spend of one `amount`-denominated output via the daemon at host:port.
  //
  // candidateKemSecretKeys: a list of ML-KEM-768 SECRET keys that may own a spendable signer output.
  //   For each chosen signer the helper hands the builder one candidate at a time; a wrong secret
  //   makes the builder's KEM scan fail (output not ours), so the next candidate is tried. This lets
  //   one wallet spend BOTH the fixed-key coinbase outputs (cn::PQ_TESTNET_KEM_SK) AND outputs
  //   received to its own seed-derived PQ address (the wallet's own KEM secret) — pass both. The
  //   list must be non-empty; empty/wrong-size entries are skipped.
  //
  // recipientKemPubKey: ML-KEM-768 public key of the real recipient. The wallet front-ends pass a
  //   real KEM public key (the recipient's, or their own for a self-send) so the spend output is a
  //   real, scannable, re-spendable stealth output. An EMPTY key makes the builder emit a throwaway
  //   output whose one-time secret is discarded (the funds are destroyed) — used only by
  //   pq_injector as the A/B parity oracle, NEVER by the wallet front-ends.
  //
  // The helper randomly selects the signer + decoys via a CSPRNG and retries with a different
  // signer (up to 8 attempts) if a build or relay fails, so an already-spent output no longer
  // permanently wedges the command and successive spends are not trivially linkable.
  //
  // On success: outTxHashHex = getObjectHash(tx) hex, outStatus = the node's relay status, returns
  // true. On any failure: err is set and the function returns false.
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
                        std::string& err);
}
