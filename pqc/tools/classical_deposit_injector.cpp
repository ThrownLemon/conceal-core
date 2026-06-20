// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// classical_deposit_injector — testnet PoC harness tool (CIP-0001 Option-3 freeze demo).
//
// PURPOSE
// -------
// Builds + signs a REAL classical (Ed25519) CryptoNote deposit transaction — i.e. a tx whose
// output is a MultisignatureOutput with term != 0 — and prints it as raw hex for
// `sendrawtransaction`. This is the CREATION-side artifact that the Option-3 freeze
// (CIP-0001 UPGRADE_HEIGHT_V9) targets:
//   * submitted PRE-V9  -> accepted (an ordinary deposit), and later WITHDRAWABLE.
//   * submitted POST-V9 -> rejected by the freeze ("classical deposit creation is frozen ...").
//
// WHY THIS TOOL EXISTS (and is NOT consensus code)
// ------------------------------------------------
// On this testnet PoC branch the per-block coinbase emits a PQ stealth output at index 0 plus a
// classical "remainder" KeyOutput at index 1 (Currency::constructMinerTx, m_testnet branch). The
// standard concealwallet/walletd output scanners (TransfersConsumer::findMyOutputs /
// CryptoNoteFormatUtils::lookup_acc_outs) walk a `keyIndex` counter that does NOT advance over the
// leading PQ output, so they try to underive the index-1 remainder at derivation index 0 and never
// recognise it — a mined wallet shows 0 classical balance. The whole PoC therefore funds wallets
// only through the PQ path. To exercise the CLASSICAL deposit freeze end-to-end we must spend that
// coinbase remainder directly: this tool re-derives the one-time key at the CORRECT derivation index
// (the output's position in the coinbase tx, == 1) via the project's own ITransaction builder
// (cn::createTransaction + generate_key_image_helper), exactly the API WalletGreen::createDeposit
// uses. It links the built CryptoNoteCore library and touches NO consensus/crypto source — it is a
// standalone harness binary, the classical twin of pq_injector.
//
// The spend uses a ring of 1 (mixin 0): there is no consensus minimum-mixin on this branch
// (MINIMUM_MIXIN=5 is a wallet-side policy only), so a mixin-0 deposit is consensus-valid pre-V9.
//
// USAGE
//   classical_deposit_injector <spendSecretHex> <viewSecretHex> <coinbaseTxHex> \
//                              <remainderGlobalIndex> <depositAmount> <term> <fee>
//     spendSecretHex/viewSecretHex : the miner wallet's secret keys (concealwallet `export_keys`).
//     coinbaseTxHex                : raw hex of the coinbase tx that paid the remainder we spend
//                                    (from `gettransactions`); its remainder KeyOutput is at index 1.
//     remainderGlobalIndex         : the global output index of that index-1 KeyOutput
//                                    (from /get_o_indexes.bin for the remainder amount).
//     depositAmount                : atomic units locked into the deposit (>= depositMinAmount).
//     term                         : deposit term in blocks (testnet min 30, multiple of 30).
//     fee                          : tx fee in atomic units.
//   The remainder must cover depositAmount + fee; any leftover is returned to the miner as change.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "Common/StringTools.h"
#include "crypto/crypto.h"

namespace
{
  bool parseHex32(const std::string &hex, void *out32)
  {
    cn::BinaryArray ba;
    if (!common::fromHex(hex, ba) || ba.size() != 32) return false;
    std::memcpy(out32, ba.data(), 32);
    return true;
  }
}

int main(int argc, char **argv)
{
  using namespace cn;

  if (argc < 8)
  {
    std::fprintf(stderr,
      "usage: %s <spendSecretHex> <viewSecretHex> <coinbaseTxHex> <remainderGlobalIndex> "
      "<depositAmount> <term> <fee>\n", argv[0]);
    return 2;
  }

  // --- 1. Reconstruct the miner's AccountKeys from the exported secret keys. ---
  AccountKeys keys;
  if (!parseHex32(argv[1], &keys.spendSecretKey) || !parseHex32(argv[2], &keys.viewSecretKey))
  {
    std::fprintf(stderr, "error: spend/view secret key must be 32-byte hex\n");
    return 2;
  }
  if (!crypto::secret_key_to_public_key(keys.spendSecretKey, keys.address.spendPublicKey) ||
      !crypto::secret_key_to_public_key(keys.viewSecretKey, keys.address.viewPublicKey))
  {
    std::fprintf(stderr, "error: failed to derive public keys from secrets\n");
    return 1;
  }

  const uint32_t remainderGlobalIndex = static_cast<uint32_t>(std::strtoul(argv[4], nullptr, 10));
  const uint64_t depositAmount = std::strtoull(argv[5], nullptr, 10);
  const uint32_t term = static_cast<uint32_t>(std::strtoul(argv[6], nullptr, 10));
  const uint64_t fee = std::strtoull(argv[7], nullptr, 10);

  // --- 2. Parse the coinbase tx and pull out the index-1 classical remainder KeyOutput. ---
  cn::BinaryArray blob;
  if (!common::fromHex(argv[3], blob))
  {
    std::fprintf(stderr, "error: bad coinbase tx hex\n");
    return 2;
  }
  cn::Transaction coinbase;
  if (!cn::fromBinaryArray(coinbase, blob))
  {
    std::fprintf(stderr, "error: coinbase tx deserialise failed\n");
    return 1;
  }
  if (coinbase.outputs.size() < 2 || coinbase.outputs[1].target.type() != typeid(cn::KeyOutput))
  {
    std::fprintf(stderr, "error: coinbase output 1 is not a classical KeyOutput "
                         "(outputs=%zu) — not a testnet PQ-coinbase remainder\n",
                 coinbase.outputs.size());
    return 1;
  }
  const uint64_t remainderAmount = coinbase.outputs[1].amount;
  const crypto::PublicKey remainderKey = boost::get<cn::KeyOutput>(coinbase.outputs[1].target).key;
  const crypto::PublicKey coinbaseTxPubKey = cn::getTransactionPublicKeyFromExtra(coinbase.extra);

  if (remainderAmount < depositAmount + fee)
  {
    std::fprintf(stderr, "error: remainder %llu < depositAmount %llu + fee %llu\n",
                 (unsigned long long)remainderAmount, (unsigned long long)depositAmount,
                 (unsigned long long)fee);
    return 1;
  }

  // --- 3. Build the InputKeyInfo for the remainder, ring of 1 (mixin 0). The CRUCIAL field is
  //        realOutput.outputInTransaction = 1 — the remainder's true position in the coinbase tx,
  //        which is the derivation index the one-time key was generated at. ---
  transaction_types::InputKeyInfo info;
  info.amount = remainderAmount;
  transaction_types::GlobalOutput go;
  go.targetKey = remainderKey;
  go.outputIndex = remainderGlobalIndex;
  info.outputs.push_back(go);
  info.realOutput.transactionPublicKey = coinbaseTxPubKey;
  info.realOutput.transactionIndex = 0;       // single (real) ring member
  info.realOutput.outputInTransaction = 1;    // <-- the fix: remainder is at output index 1

  // --- 4. Assemble the deposit tx with the project's own builder. ---
  std::unique_ptr<ITransaction> tx = createTransaction();
  tx->setUnlockTime(0);

  KeyPair ephKeys;
  tx->addInput(keys, info, ephKeys);

  // The deposit output: a MultisignatureOutput with term != 0 (requiredSignatures = 1), paid back to
  // the miner so the SAME wallet can later `withdraw` it (behavior #2). This is exactly the cell the
  // freeze predicate (transactionContainsClassicalDeposit) matches.
  tx->addOutput(depositAmount, {keys.address}, 1, term);

  // Change back to the miner (ordinary KeyOutput, term 0) so input == output + fee.
  const uint64_t change = remainderAmount - depositAmount - fee;
  if (change > 0)
  {
    tx->addOutput(change, keys.address);
  }

  // Sign the single key input (ring of 1).
  tx->signInputKey(0, info, ephKeys);

  cn::BinaryArray out = tx->getTransactionData();
  std::string hex = common::toHex(out.data(), out.size());
  std::fprintf(stderr, "[classical_deposit_injector] deposit tx built: amount=%llu term=%u fee=%llu "
                       "change=%llu bytes=%zu hash=%s\n",
               (unsigned long long)depositAmount, term, (unsigned long long)fee,
               (unsigned long long)change, out.size(),
               common::podToHex(tx->getTransactionHash()).c_str());
  std::printf("%s\n", hex.c_str());
  return 0;
}
