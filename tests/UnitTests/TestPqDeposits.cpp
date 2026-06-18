// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Post-quantum DEPOSITS (ML-DSA-65) unit tests (CIP-0001, UPGRADE_HEIGHT_V9).
//
// Coverage here (deterministic, no live blockchain):
//   * ML-DSA-65 multisig primitive: roundtrip + tamper/wrong-key/wrong-message reject (via FFI).
//   * Serialization round-trip for PqMultisigInput / PqMultisigOutput, and the DoS bound that
//     rejects an oversized key/signature array at the deserialization boundary.
//   * Interest PARITY: a PqMultisigInput credits EXACTLY the same amount + interest as the Ed25519
//     MultisignatureInput for the same amount/term (this is the interest-minting safety outcome).
//   * Output-validation PARITY: validateOutput(PqMultisigOutput) accepts/rejects the same term band
//     and depositMinAmount as the Ed25519 MultisignatureOutput overload.
//
// The chain-level spend/double-spend/reorg/lock behaviours of check_pq_multisig() are a line-for-line
// port of validateInput(MultisignatureInput) / popTransaction (only the primitive is swapped), whose
// Ed25519 originals are exercised by tests/CoreTests/Deposit.cpp. A PQ-aware CoreTests harness is the
// recommended follow-up for full chain coverage (see deposits-mldsa-impl.md).

#include "gtest/gtest.h"

#include <vector>
#include <cstdint>

#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "Logging/ConsoleLogger.h"

#include "pq_ring_sig.h" // ccx-pqc FFI

using namespace common;
using namespace cn;

namespace {

// ---------------------------------------------------------------------------------------------------
// 1. ML-DSA-65 multisig primitive (FFI) — roundtrip + tamper/wrong-key/wrong-message reject.
// ---------------------------------------------------------------------------------------------------

TEST(PqDepositPrimitive, SelftestPasses) {
  // The Rust selftest signs, verifies (roundtrip), and asserts a tampered sig, a wrong key, and a
  // wrong message all reject. ok=1 means every check passed.
  ccx_pq_sizes s = ccx_pq_multisig_selftest();
  EXPECT_EQ(s.ok, 1);
  EXPECT_GT(s.pk, 0u);
  EXPECT_GT(s.ct_or_sig, 0u);
  EXPECT_EQ(s.pk, ccx_pq_multisig_pubkey_bytes());
  EXPECT_EQ(s.ct_or_sig, ccx_pq_sig_bytes());
}

TEST(PqDepositPrimitive, SignVerifyRoundtripAndRejections) {
  const size_t pkBytes = ccx_pq_multisig_pubkey_bytes();
  const size_t skBytes = ccx_pq_multisig_seckey_bytes();
  const size_t sigBytes = ccx_pq_sig_bytes();
  ASSERT_GT(pkBytes, 0u);
  ASSERT_GT(sigBytes, 0u);

  std::vector<uint8_t> pk(pkBytes), sk(skBytes);
  ASSERT_EQ(ccx_pq_multisig_keypair(pk.data(), pk.size(), sk.data(), sk.size()), 0);

  const std::vector<uint8_t> msg = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03};
  std::vector<uint8_t> sig(sigBytes);
  size_t sl = sig.size();
  ASSERT_EQ(ccx_pq_multisig_sign(msg.data(), msg.size(), sk.data(), sk.size(), sig.data(), &sl), 0);
  ASSERT_EQ(sl, sigBytes);

  // roundtrip
  EXPECT_EQ(ccx_pq_multisig_verify(msg.data(), msg.size(), pk.data(), pk.size(), sig.data(), sig.size()), 0);

  // tampered signature -> reject
  std::vector<uint8_t> bad = sig;
  bad[sigBytes / 2] ^= 0xff;
  EXPECT_NE(ccx_pq_multisig_verify(msg.data(), msg.size(), pk.data(), pk.size(), bad.data(), bad.size()), 0);

  // wrong key -> reject
  std::vector<uint8_t> pk2(pkBytes), sk2(skBytes);
  ASSERT_EQ(ccx_pq_multisig_keypair(pk2.data(), pk2.size(), sk2.data(), sk2.size()), 0);
  EXPECT_NE(ccx_pq_multisig_verify(msg.data(), msg.size(), pk2.data(), pk2.size(), sig.data(), sig.size()), 0);

  // wrong message -> reject (covers a sig produced for a different prefix hash)
  std::vector<uint8_t> msg2 = msg;
  msg2[0] ^= 0xff;
  EXPECT_NE(ccx_pq_multisig_verify(msg2.data(), msg2.size(), pk.data(), pk.size(), sig.data(), sig.size()), 0);
}

// ---------------------------------------------------------------------------------------------------
// 2. Serialization round-trip + DoS bound.
// ---------------------------------------------------------------------------------------------------

template <typename T>
static std::string serializeToString(T value) {
  std::stringstream ss;
  StdOutputStream os(ss);
  BinaryOutputStreamSerializer s(os);
  s(value, "v");
  return ss.str();
}

template <typename T>
static T deserializeFromString(const std::string& blob) {
  std::stringstream ss(blob);
  StdInputStream is(ss);
  BinaryInputStreamSerializer s(is);
  T value;
  s(value, "v");
  return value;
}

TEST(PqDepositSerialization, InputRoundtrip) {
  PqMultisigInput in;
  in.amount = 123456789;
  in.signatureCount = 2;
  in.outputIndex = 7;
  in.term = 5460;
  in.signatures.push_back(std::vector<uint8_t>(ccx_pq_sig_bytes(), 0xa1));
  in.signatures.push_back(std::vector<uint8_t>(ccx_pq_sig_bytes(), 0xb2));

  TransactionInput variantIn = in;
  std::string blob = serializeToString(variantIn);
  TransactionInput out = deserializeFromString<TransactionInput>(blob);

  ASSERT_EQ(out.type(), typeid(PqMultisigInput));
  const PqMultisigInput& got = boost::get<PqMultisigInput>(out);
  EXPECT_EQ(got.amount, in.amount);
  EXPECT_EQ(got.signatureCount, in.signatureCount);
  EXPECT_EQ(got.outputIndex, in.outputIndex);
  EXPECT_EQ(got.term, in.term);
  ASSERT_EQ(got.signatures.size(), in.signatures.size());
  EXPECT_EQ(got.signatures[0], in.signatures[0]);
  EXPECT_EQ(got.signatures[1], in.signatures[1]);
}

TEST(PqDepositSerialization, OutputRoundtrip) {
  PqMultisigOutput out;
  out.keys.push_back(std::vector<uint8_t>(ccx_pq_multisig_pubkey_bytes(), 0x11));
  out.keys.push_back(std::vector<uint8_t>(ccx_pq_multisig_pubkey_bytes(), 0x22));
  out.keys.push_back(std::vector<uint8_t>(ccx_pq_multisig_pubkey_bytes(), 0x33));
  out.requiredSignatureCount = 2;
  out.term = 5460;

  TransactionOutputTarget variantOut = out;
  std::string blob = serializeToString(variantOut);
  TransactionOutputTarget back = deserializeFromString<TransactionOutputTarget>(blob);

  ASSERT_EQ(back.type(), typeid(PqMultisigOutput));
  const PqMultisigOutput& got = boost::get<PqMultisigOutput>(back);
  ASSERT_EQ(got.keys.size(), out.keys.size());
  EXPECT_EQ(got.keys[0], out.keys[0]);
  EXPECT_EQ(got.keys[2], out.keys[2]);
  EXPECT_EQ(got.requiredSignatureCount, out.requiredSignatureCount);
  EXPECT_EQ(got.term, out.term);
}

TEST(PqDepositSerialization, OversizedInputArrayRejected) {
  // An attacker-crafted input whose signature array exceeds PQ_MULTISIG_MAX_KEYS must be rejected at
  // the deserialization boundary, BEFORE any large allocation (DoS guard).
  PqMultisigInput in;
  in.amount = 1;
  in.signatureCount = static_cast<uint8_t>(PQ_MULTISIG_MAX_KEYS + 1);
  in.outputIndex = 0;
  in.term = 0;
  for (size_t i = 0; i < PQ_MULTISIG_MAX_KEYS + 1; ++i) {
    in.signatures.push_back(std::vector<uint8_t>(8, 0xcc)); // small blobs; the COUNT is what's bounded
  }
  TransactionInput variantIn = in;
  std::string blob = serializeToString(variantIn);
  EXPECT_THROW(deserializeFromString<TransactionInput>(blob), std::exception);
}

TEST(PqDepositSerialization, OversizedOutputArrayRejected) {
  PqMultisigOutput out;
  for (size_t i = 0; i < PQ_MULTISIG_MAX_KEYS + 1; ++i) {
    out.keys.push_back(std::vector<uint8_t>(8, 0xdd));
  }
  out.requiredSignatureCount = 1;
  out.term = 0;
  TransactionOutputTarget variantOut = out;
  std::string blob = serializeToString(variantOut);
  EXPECT_THROW(deserializeFromString<TransactionOutputTarget>(blob), std::exception);
}

// ---------------------------------------------------------------------------------------------------
// 3 + 4. Interest PARITY and output-validation PARITY with the Ed25519 deposit path.
// ---------------------------------------------------------------------------------------------------

class PqDepositCurrencyTest : public ::testing::Test {
public:
  static const uint64_t fixed_amount = 1000;
  static const uint32_t fixed_term = 400;

  PqDepositCurrencyTest()
      : builder(m_logger),
        fixedCurrency(builder.depositMaxTotalRate(10)
                          .depositMinTotalRateFactor(10)
                          .depositMinTerm(1)
                          .depositMaxTerm(401)
                          .currency()) {}

protected:
  logging::ConsoleLogger m_logger;
  CurrencyBuilder builder;
  Currency fixedCurrency;

  // Same height set the Ed25519 deposit tests use, so the interest curve (multiplier band) is
  // exercised identically.
  const std::vector<uint32_t> heights = {
      0 + fixed_term,
      parameters::END_MULTIPLIER_BLOCK - 1 + fixed_term,
      parameters::END_MULTIPLIER_BLOCK + fixed_term,
      parameters::END_MULTIPLIER_BLOCK + 1 + fixed_term,
      static_cast<uint32_t>(-1)};
};

// The single most important money-safety property: a PQ deposit input credits EXACTLY the same
// principal + interest as the Ed25519 deposit input for the same amount and term. If these ever
// diverge, the PQ path would mint a different (potentially attacker-favourable) amount.
TEST_F(PqDepositCurrencyTest, InputAmountParityWithEd25519) {
  for (auto h : heights) {
    uint64_t ed25519 = fixedCurrency.getTransactionInputAmount(
        MultisignatureInput{fixed_amount, 1, 2, fixed_term}, h);
    PqMultisigInput pqIn;
    pqIn.amount = fixed_amount;
    pqIn.signatureCount = 1;
    pqIn.outputIndex = 2;
    pqIn.term = fixed_term;
    uint64_t pq = fixedCurrency.getTransactionInputAmount(pqIn, h);
    EXPECT_EQ(pq, ed25519);
    // And it equals principal + the deposit interest value directly.
    EXPECT_EQ(pq, fixed_amount + fixedCurrency.calculateInterest(fixed_amount, fixed_term, h - fixed_term));
  }
}

TEST_F(PqDepositCurrencyTest, NonDepositInputIsPrincipalOnly) {
  // term == 0 => plain PQ multisig => no interest, principal only (mirrors the Ed25519 term==0 case).
  for (auto h : heights) {
    PqMultisigInput pqIn;
    pqIn.amount = fixed_amount;
    pqIn.signatureCount = 1;
    pqIn.outputIndex = 0;
    pqIn.term = 0;
    EXPECT_EQ(fixedCurrency.getTransactionInputAmount(pqIn, h), fixed_amount);
  }
}

TEST_F(PqDepositCurrencyTest, TotalTransactionInterestParity) {
  for (auto h : heights) {
    Transaction edTx;
    edTx.inputs.emplace_back(MultisignatureInput{fixed_amount, 1, 2, fixed_term});
    Transaction pqTx;
    PqMultisigInput pqIn;
    pqIn.amount = fixed_amount;
    pqIn.signatureCount = 1;
    pqIn.outputIndex = 2;
    pqIn.term = fixed_term;
    pqTx.inputs.emplace_back(pqIn);

    EXPECT_EQ(fixedCurrency.calculateTotalTransactionInterest(pqTx, h),
              fixedCurrency.calculateTotalTransactionInterest(edTx, h));
  }
}

TEST_F(PqDepositCurrencyTest, ValidateOutputParityTermBand) {
  // height that uses the V3 term band (must be > depositHeightV4 path is not active for fixedCurrency,
  // so the V1 band [depositMinTerm, depositMaxTermV1] applies). We assert PARITY with the Ed25519
  // overload across in-band and out-of-band terms.
  const uint32_t height = 100;
  const std::vector<uint32_t> terms = {0, 1, fixed_term, 400, 401, 402, 5000};
  for (uint32_t term : terms) {
    MultisignatureOutput edOut;
    edOut.requiredSignatureCount = 1;
    edOut.term = term;
    PqMultisigOutput pqOut;
    pqOut.requiredSignatureCount = 1;
    pqOut.term = term;

    bool edValid = fixedCurrency.validateOutput(fixed_amount, edOut, height);
    bool pqValid = fixedCurrency.validateOutput(fixed_amount, pqOut, height);
    EXPECT_EQ(pqValid, edValid) << "term=" << term;
  }
}

TEST_F(PqDepositCurrencyTest, ValidateOutputParityMinAmount) {
  const uint32_t height = 100;
  // A deposit (term != 0) below depositMinAmount must reject for BOTH paths identically.
  const std::vector<uint64_t> amounts = {0, 1, fixed_amount, fixed_amount * 1000};
  for (uint64_t amount : amounts) {
    MultisignatureOutput edOut;
    edOut.requiredSignatureCount = 1;
    edOut.term = fixed_term;
    PqMultisigOutput pqOut;
    pqOut.requiredSignatureCount = 1;
    pqOut.term = fixed_term;

    bool edValid = fixedCurrency.validateOutput(amount, edOut, height);
    bool pqValid = fixedCurrency.validateOutput(amount, pqOut, height);
    EXPECT_EQ(pqValid, edValid) << "amount=" << amount;
  }
}

} // namespace
