// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PqDepositClient — wallet-side helper that builds + relays a PQ deposit CREATE / WITHDRAW through a
// daemon (CIP-0001 UPGRADE_HEIGHT_V9, Option 3). The deposit twin of PqSpendClient: the ONE place the
// concealwallet CLI and the walletd RPC service share to turn "lock a PQ deposit" / "withdraw a
// matured PQ deposit" into a relayed transaction. All it does is talk to a daemon over HTTP:
//   CREATE   : get_pq_outputs -> pick a spendable PQ output -> buildPqDepositTransaction -> sendrawtransaction
//   WITHDRAW : get_pq_multisig_outputs -> named-key match the wallet's account DSA pubkey ->
//              buildPqWithdrawTransaction (payout = principal + interest) -> sendrawtransaction
//
// No crypto lives here beyond the named-key match: the builders do the KEM scan + lattice ring-sign /
// ML-DSA-sign internally. Testnet only / experimental. Not for mainnet funds.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <System/Dispatcher.h>

namespace cn
{
  // CREATE: lock `amount` into a PQ deposit cell of `term` blocks, funded by one spendable
  // PqKeyOutput of `inputAmount` denomination found via get_pq_outputs. The deposit names
  // `depositDsaPubKey` (the wallet's account ML-DSA-65 public key). Change is returned to
  // `changeKemPubKey`. `candidateKemSecretKeys` are tried in turn to scan the funding signer.
  // On success: outTxHashHex / outStatus set, returns true. On failure: err set, returns false.
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
                          std::string& err);

  // WITHDRAW: spend the deposit cell at (amount, outputIndex) — resolved via get_pq_multisig_outputs
  // by named-key matching `depositDsaPubKey` against PqMultisigOutput.keys[0] — and pay
  // principal + `interest` to `payoutKemPubKey`. `signingSecretKeys` are the m ML-DSA-65 secret keys
  // (one for the v1 single-key wallet). `outputIndex`/`term` are the on-chain cell's values (the
  // caller resolves them, or passes UINT32_MAX outputIndex to let the helper auto-resolve the first
  // unused, matured, owned cell). Returns true + sets out* on success; false + err otherwise.
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
                           std::string& err);
}
