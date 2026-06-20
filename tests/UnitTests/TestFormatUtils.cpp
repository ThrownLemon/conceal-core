// Copyright (c) 2012-2017 The Cryptonote developers
// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include <vector>

#include "Common/Util.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "Common/StringTools.h"

#include <Logging/LoggerGroup.h>

#define AUTO_VAL_INIT(n) boost::value_initialized<decltype(n)>()

TEST(parseTransactionExtra, handles_empty_extra)
{
  std::vector<uint8_t> extra;;
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_TRUE(cn::parseTransactionExtra(extra, tx_extra_fields));
  ASSERT_TRUE(tx_extra_fields.empty());
}

TEST(parseTransactionExtra, handles_padding_only_size_1)
{
  const uint8_t extra_arr[] = {0};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_TRUE(cn::parseTransactionExtra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_EQ(typeid(cn::TransactionExtraPadding), tx_extra_fields[0].type());
  ASSERT_EQ(1, boost::get<cn::TransactionExtraPadding>(tx_extra_fields[0]).size);
}

TEST(parseTransactionExtra, handles_padding_only_size_2)
{
  const uint8_t extra_arr[] = {0, 0};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_TRUE(cn::parseTransactionExtra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_EQ(typeid(cn::TransactionExtraPadding), tx_extra_fields[0].type());
  ASSERT_EQ(2, boost::get<cn::TransactionExtraPadding>(tx_extra_fields[0]).size);
}

TEST(parseTransactionExtra, handles_padding_only_max_size)
{
  std::vector<uint8_t> extra(TX_EXTRA_NONCE_MAX_COUNT, 0);
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_TRUE(cn::parseTransactionExtra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_EQ(typeid(cn::TransactionExtraPadding), tx_extra_fields[0].type());
  ASSERT_EQ(TX_EXTRA_NONCE_MAX_COUNT, boost::get<cn::TransactionExtraPadding>(tx_extra_fields[0]).size);
}

TEST(parseTransactionExtra, handles_padding_only_exceed_max_size)
{
  std::vector<uint8_t> extra(TX_EXTRA_NONCE_MAX_COUNT + 1, 0);
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_FALSE(cn::parseTransactionExtra(extra, tx_extra_fields));
}

TEST(parseTransactionExtra, handles_invalid_padding_only)
{
  std::vector<uint8_t> extra(2, 0);
  extra[1] = 42;
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_FALSE(cn::parseTransactionExtra(extra, tx_extra_fields));
}

TEST(parseTransactionExtra, handles_pub_key_only)
{
  const uint8_t extra_arr[] = {1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_TRUE(cn::parseTransactionExtra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_EQ(typeid(cn::TransactionExtraPublicKey), tx_extra_fields[0].type());
}

TEST(parseTransactionExtra, handles_extra_nonce_only)
{
  const uint8_t extra_arr[] = {2, 1, 42};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_TRUE(cn::parseTransactionExtra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_EQ(typeid(cn::TransactionExtraNonce), tx_extra_fields[0].type());
  cn::TransactionExtraNonce extra_nonce = boost::get<cn::TransactionExtraNonce>(tx_extra_fields[0]);
  ASSERT_EQ(1, extra_nonce.nonce.size());
  ASSERT_EQ(42, extra_nonce.nonce[0]);
}

TEST(parseTransactionExtra, handles_pub_key_and_padding)
{
  const uint8_t extra_arr[] = {1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_TRUE(cn::parseTransactionExtra(extra, tx_extra_fields));
  ASSERT_EQ(2, tx_extra_fields.size());
  ASSERT_EQ(typeid(cn::TransactionExtraPublicKey), tx_extra_fields[0].type());
  ASSERT_EQ(typeid(cn::TransactionExtraPadding), tx_extra_fields[1].type());
}

TEST(parse_and_validate_tx_extra, is_valid_tx_extra_parsed)
{
  logging::LoggerGroup logger;
  cn::Currency currency = cn::CurrencyBuilder(logger).currency();
  cn::Transaction tx = AUTO_VAL_INIT(tx);
  cn::AccountBase acc;
  acc.generate();
  cn::BinaryArray b = common::asBinaryArray("dsdsdfsdfsf");
  ASSERT_TRUE(currency.constructMinerTx(0, 0, 10000000000000, 1000, currency.minimumFee(), acc.getAccountKeys().address, tx, b, 1));
  crypto::PublicKey tx_pub_key = cn::getTransactionPublicKeyFromExtra(tx.extra);
  ASSERT_NE(tx_pub_key, cn::NULL_PUBLIC_KEY);
}

// Regression (CIP-0001): the testnet PQ coinbase emits a PqKeyOutput at output index 0 plus a classical
// "remainder" KeyOutput to the miner at index 1. The wallet scanner must underive the remainder at its
// OUTPUT POSITION (1), exactly as construction derives it. A prior key-slot counter advanced only for
// Key/Multisig outputs, so it skipped the leading PQ output and underived the remainder at index 0 ->
// the miner's classical coinbase was invisible to every wallet. This test fails before that fix.
TEST(lookup_acc_outs, finds_testnet_pq_coinbase_remainder)
{
  logging::LoggerGroup logger;
  cn::Currency currency = cn::CurrencyBuilder(logger).testnet(true).currency();
  cn::AccountBase acc;
  acc.generate();
  cn::Transaction tx = AUTO_VAL_INIT(tx);
  cn::BinaryArray b = common::asBinaryArray("pqcb");
  // height > 0 on testnet triggers the PQ-coinbase branch (leading PqKeyOutput + classical remainder).
  ASSERT_TRUE(currency.constructMinerTx(5, 0, 10000000000000, 1000, currency.minimumFee(),
                                        acc.getAccountKeys().address, tx, b, 1));

  // Precondition for the regression to be meaningful: a non-Key output leads the coinbase.
  ASSERT_FALSE(tx.outputs.empty());
  ASSERT_EQ(typeid(cn::PqKeyOutput), tx.outputs[0].target.type());

  // The miner must SEE its classical remainder — the scanner underives at the true output position.
  std::vector<size_t> outs;
  uint64_t money = 0;
  ASSERT_TRUE(cn::lookup_acc_outs(acc.getAccountKeys(), tx, outs, money));
  ASSERT_GT(money, 0u);
  ASSERT_FALSE(outs.empty());
}
TEST(parse_and_validate_tx_extra, fails_on_big_extra_nonce)
{
  logging::LoggerGroup logger;
  cn::Currency currency = cn::CurrencyBuilder(logger).currency();
  cn::Transaction tx = AUTO_VAL_INIT(tx);
  cn::AccountBase acc;
  acc.generate();
  cn::BinaryArray b(TX_EXTRA_NONCE_MAX_COUNT + 1, 0);
  ASSERT_FALSE(currency.constructMinerTx(0, 0, 10000000000000, 1000, currency.minimumFee(), acc.getAccountKeys().address, tx, b, 1));
}
TEST(parse_and_validate_tx_extra, fails_on_wrong_size_in_extra_nonce)
{
  cn::Transaction tx = AUTO_VAL_INIT(tx);
  tx.extra.resize(20, 0);
  tx.extra[0] = TX_EXTRA_NONCE;
  tx.extra[1] = 255;
  std::vector<cn::TransactionExtraField> tx_extra_fields;
  ASSERT_FALSE(cn::parseTransactionExtra(tx.extra, tx_extra_fields));
}
TEST(validate_parse_amount_case, validate_parse_amount)
{
  logging::LoggerGroup logger;
  cn::Currency currency = cn::CurrencyBuilder(logger).numberOfDecimalPlaces(8).currency();
  uint64_t res = 0;
  bool r = currency.parseAmount("0.0001", res);
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 10000);

  r = currency.parseAmount("100.0001", res);
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 10000010000);

  r = currency.parseAmount("000.0000", res);
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 0);

  r = currency.parseAmount("0", res);
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 0);


  r = currency.parseAmount("   100.0001    ", res);
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 10000010000);

  r = currency.parseAmount("   100.0000    ", res);
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 10000000000);

  r = currency.parseAmount("   100. 0000    ", res);
  ASSERT_FALSE(r);

  r = currency.parseAmount("100. 0000", res);
  ASSERT_FALSE(r);

  r = currency.parseAmount("100 . 0000", res);
  ASSERT_FALSE(r);

  r = currency.parseAmount("100.00 00", res);
  ASSERT_FALSE(r);

  r = currency.parseAmount("1 00.00 00", res);
  ASSERT_FALSE(r);
}

// --- Post-quantum (CIP-0001) intra-tx double-spend guards (regression for the adversarial-vet
//     CRITICAL findings: a v4 tx listing the same nullifier / deposit cell twice must be rejected
//     so the money-conservation sum cannot double-count one real spend into output inflation). ---

TEST(checkPqNullifiersDiff, rejects_duplicate_nullifier)
{
  cn::TransactionPrefix tx = AUTO_VAL_INIT(tx);
  cn::PqKeyInput a; a.amount = 100; a.nullifier = {1, 2, 3, 4};
  cn::PqKeyInput b; b.amount = 200; b.nullifier = {1, 2, 3, 4}; // same nullifier as a
  tx.inputs.push_back(a);
  tx.inputs.push_back(b);
  ASSERT_FALSE(cn::checkPqNullifiersDiff(tx));
}

TEST(checkPqNullifiersDiff, accepts_distinct_nullifiers)
{
  cn::TransactionPrefix tx = AUTO_VAL_INIT(tx);
  cn::PqKeyInput a; a.amount = 100; a.nullifier = {1, 2, 3, 4};
  cn::PqKeyInput b; b.amount = 200; b.nullifier = {5, 6, 7, 8};
  tx.inputs.push_back(a);
  tx.inputs.push_back(b);
  ASSERT_TRUE(cn::checkPqNullifiersDiff(tx));
}

TEST(checkPqMultisigInputsDiff, rejects_duplicate_deposit_cell)
{
  cn::TransactionPrefix tx = AUTO_VAL_INIT(tx);
  cn::PqMultisigInput a; a.amount = 100; a.outputIndex = 7;
  cn::PqMultisigInput b; b.amount = 100; b.outputIndex = 7; // same (amount, outputIndex) cell
  tx.inputs.push_back(a);
  tx.inputs.push_back(b);
  ASSERT_FALSE(cn::checkPqMultisigInputsDiff(tx));
}

TEST(checkPqMultisigInputsDiff, accepts_distinct_cells)
{
  cn::TransactionPrefix tx = AUTO_VAL_INIT(tx);
  cn::PqMultisigInput a; a.amount = 100; a.outputIndex = 7;
  cn::PqMultisigInput b; b.amount = 100; b.outputIndex = 8;
  tx.inputs.push_back(a);
  tx.inputs.push_back(b);
  ASSERT_TRUE(cn::checkPqMultisigInputsDiff(tx));
}
