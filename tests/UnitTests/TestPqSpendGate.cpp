// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Audit F4: unit tests for transactionContainsPqSpend — the predicate that height-gates PQ ring-sig
// spends (PqKeyInput / PqKeyOutput) behind UPGRADE_HEIGHT_V10 on MAINNET. The block-connect gate is
// `!isTestnet() && transactionContainsPqSpend(tx) && height < V10 -> reject` (BlockchainStorage.cpp),
// the symmetric twin of the PQ-deposit gate. This covers the novel "what counts as a PQ spend"
// classification directly; the height/network wrapping is identical structure to the (already-present)
// deposit gate. Mirrors how TestPqDepositTx unit-tests the testable primitive while the full on-chain
// accept/reject is exercised by the Phase-6 e2e.

#include "gtest/gtest.h"

#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"

using namespace cn;

namespace {
TransactionOutput pqOut(const TransactionOutputTarget &tgt) {
  TransactionOutput o;
  o.amount = 1;
  o.target = tgt;
  return o;
}
}

TEST(PqSpendGate, DetectsPqKeyInput) {
  Transaction t;
  t.inputs.push_back(PqKeyInput{});
  EXPECT_TRUE(transactionContainsPqSpend(t));
}

TEST(PqSpendGate, DetectsPqKeyOutput) {
  Transaction t;
  t.outputs.push_back(pqOut(PqKeyOutput{}));
  EXPECT_TRUE(transactionContainsPqSpend(t));
}

TEST(PqSpendGate, IgnoresClassicalKeyInputAndOutput) {
  Transaction t;
  t.inputs.push_back(KeyInput{});
  t.outputs.push_back(pqOut(KeyOutput{}));
  EXPECT_FALSE(transactionContainsPqSpend(t));
}

TEST(PqSpendGate, IgnoresPqMultisigDeposit) {
  // PQ DEPOSIT variants are gated separately (transactionContainsPqMultisig). The spend predicate must
  // NOT classify them as spends, or the deposit gate and the spend gate would overlap/double-fire.
  Transaction tin;
  tin.inputs.push_back(PqMultisigInput{});
  EXPECT_FALSE(transactionContainsPqSpend(tin));
  Transaction tout;
  tout.outputs.push_back(pqOut(PqMultisigOutput{}));
  EXPECT_FALSE(transactionContainsPqSpend(tout));
}

TEST(PqSpendGate, EmptyTransactionIsNotPqSpend) {
  EXPECT_FALSE(transactionContainsPqSpend(Transaction{}));
}

TEST(PqSpendGate, PqKeyOutputAmongClassicalIsDetected) {
  // A mixed tx (classical input, classical + PQ outputs) is still a PQ spend — the gate must fire on
  // either side, so a pre-V10 mainnet tx can't smuggle a PQ output in alongside classical ones.
  Transaction t;
  t.inputs.push_back(KeyInput{});
  t.outputs.push_back(pqOut(KeyOutput{}));
  t.outputs.push_back(pqOut(PqKeyOutput{}));
  EXPECT_TRUE(transactionContainsPqSpend(t));
}

// GLM-verification (Low): a PqKeyOutput in a NON-coinbase pre-v4 tx must be rejected by check_outs_valid
// (the version gate PqKeyInput / PqMultisigOutput already enforce); the coinbase is exempt because it is
// v1 yet legitimately carries the testnet PQ stealth output. The version check fires before the key
// checks, so a dummy key still trips the version reject.
TEST(PqSpendGate, PqKeyOutputRejectedInNonCoinbasePreV4Tx) {
  Transaction t;
  t.version = 1;  // TRANSACTION_VERSION_1, i.e. < TRANSACTION_VERSION_4 (==4)
  t.inputs.push_back(KeyInput{});     // a KeyInput (NOT BaseInput) -> not a coinbase
  t.outputs.push_back(pqOut(PqKeyOutput{}));
  std::string err;
  EXPECT_FALSE(check_outs_valid(t, &err));
}
