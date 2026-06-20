// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PQ deposit CREATE + WITHDRAW transaction-builder tests (CIP-0001 UPGRADE_HEIGHT_V9, Option 3).
//
// Goes beyond TestPqDeposits.cpp (which exercises only the serialization + interest primitives): here
// we build a REAL deposit-creation tx and a REAL withdraw tx through the shared CryptoNoteCore builders
// (buildPqDepositTransaction / buildPqWithdrawTransaction) and assert the money-critical consensus
// contracts the daemon enforces:
//   * the deposit output is a well-formed PqMultisigOutput (key length == 1952, n=m=1, term band) that
//     Currency::validateOutput ACCEPTS — and a wrong key length is rejected;
//   * the withdraw input carries its m ML-DSA-65 signatures INLINE, computed over the SAME signing hash
//     check_pq_multisig verifies against (the prefix with every inline PQ signature/ringSig cleared) —
//     so the inline sig VERIFIES via ccx_pq_multisig_verify (the exact crypto core of check_pq_multisig);
//   * a signature over the WRONG message is REJECTED;
//   * the withdraw binds input.term == output.term (the interest-minting safety guarantee);
//   * interest parity: the wallet's payout == amount + Currency::getInterestForInput (what the daemon
//     credits) — if these diverged the withdraw would fail the v3 conservation check.
//
// check_pq_multisig itself is private and needs the deposit output already on-chain in
// m_pqMultisigOutputs, which a unit test cannot cheaply stand up; we instead reproduce its clearing
// rule + signature primitive here (the parts that can go wrong in the BUILDER), and cover the full
// on-chain accept/reject path in the Phase-6 e2e (verify-deposit-freeze.sh).

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteTools.h"     // getObjectHash
#include "CryptoNoteCore/PqDepositBuilder.h"
#include "CryptoNoteCore/PqSpendBuilder.h"       // PqRingMember
#include "Logging/ConsoleLogger.h"
#include "Wallet/PqAccount.h"

extern "C"
{
#include "pq_ring_sig.h"
}
#include "pq_testnet_kem_keypair.h" // cn::PQ_TESTNET_KEM_PK / cn::PQ_TESTNET_KEM_SK

using namespace cn;

namespace
{
  crypto::SecretKey seedFromByte(uint8_t b)
  {
    crypto::SecretKey s;
    std::memset(&s, b, sizeof(s));
    return s;
  }

  std::vector<uint8_t> testnetKemSk()
  {
    return std::vector<uint8_t>(cn::PQ_TESTNET_KEM_SK, cn::PQ_TESTNET_KEM_SK + sizeof(cn::PQ_TESTNET_KEM_SK));
  }
  std::vector<uint8_t> testnetKemPk()
  {
    return std::vector<uint8_t>(cn::PQ_TESTNET_KEM_PK, cn::PQ_TESTNET_KEM_PK + sizeof(cn::PQ_TESTNET_KEM_PK));
  }

  // Build a real on-chain-shaped PQ ring member (a PqKeyOutput {key, kemCt}) encapsulated to the
  // testnet KEM key, so the builder's KEM-scan recovers a one-time secret that signs the funding ring.
  PqRingMember makeSignerRingMember(uint32_t globalIndex)
  {
    const size_t pkBytes = ccx_pq_pubkey_bytes();
    const size_t skBytes = ccx_pq_seckey_bytes();
    PqRingMember m;
    m.globalIndex = globalIndex;
    std::vector<uint8_t> kemCt(ccx_pq_kem_ct_bytes(), 0);
    uint8_t seed[32];
    EXPECT_EQ(0, ccx_pq_kem_derive_output(cn::PQ_TESTNET_KEM_PK, sizeof(cn::PQ_TESTNET_KEM_PK),
                                          kemCt.data(), kemCt.size(), seed, sizeof(seed)));
    std::vector<uint8_t> pk(pkBytes, 0), sk(skBytes, 0);
    EXPECT_EQ(0, ccx_pq_keygen(seed, sizeof(seed), pk.data(), pk.size(), sk.data(), sk.size()));
    m.key = pk;
    m.kemCt = kemCt;
    return m;
  }

  // A plausible decoy ring member: an independent throwaway one-time key (no kemCt needed for decoys).
  PqRingMember makeDecoyRingMember(uint32_t globalIndex, uint8_t seedByte)
  {
    const size_t pkBytes = ccx_pq_pubkey_bytes();
    const size_t skBytes = ccx_pq_seckey_bytes();
    PqRingMember m;
    m.globalIndex = globalIndex;
    uint8_t seed[32];
    std::memset(seed, seedByte, sizeof(seed));
    std::vector<uint8_t> pk(pkBytes, 0), sk(skBytes, 0);
    EXPECT_EQ(0, ccx_pq_keygen(seed, sizeof(seed), pk.data(), pk.size(), sk.data(), sk.size()));
    m.key = pk;
    return m;
  }

  // Reproduce Blockchain::getTransactionPqSigningHash EXACTLY (the consensus signing message): clear
  // every PqKeyInput.ringSig AND every PqMultisigInput.signatures, then getObjectHash the prefix.
  crypto::Hash pqSigningHash(const Transaction &tx)
  {
    TransactionPrefix prefix = tx;
    for (auto &in : prefix.inputs)
    {
      if (in.type() == typeid(PqKeyInput))
      {
        boost::get<PqKeyInput>(in).ringSig.clear();
      }
      else if (in.type() == typeid(PqMultisigInput))
      {
        boost::get<PqMultisigInput>(in).signatures.clear();
      }
    }
    return getObjectHash(prefix);
  }

  // A fixed-band Currency mirroring TestPqDeposits.cpp so the interest curve is identical.
  class PqDepositTxTest : public ::testing::Test
  {
  public:
    static const uint64_t fixed_input = 100000;
    static const uint64_t fixed_amount = 1000;
    static const uint32_t fixed_term = 400;
    static const uint64_t fee = 1000;

    PqDepositTxTest()
        : builder(m_logger),
          fixedCurrency(builder.depositMaxTotalRate(10)
                            .depositMinTotalRateFactor(10)
                            .depositMinTerm(1)
                            .depositMaxTerm(401)
                            .depositMinAmount(fixed_amount) // small band so the test deposit clears
                            .currency()) {}

  protected:
    logging::ConsoleLogger m_logger;
    CurrencyBuilder builder;
    Currency fixedCurrency;
  };

  const uint64_t PqDepositTxTest::fixed_input;
  const uint64_t PqDepositTxTest::fixed_amount;
  const uint32_t PqDepositTxTest::fixed_term;
  const uint64_t PqDepositTxTest::fee;
}

// ----------------------------------------------------------------------------------------------------
// CREATE
// ----------------------------------------------------------------------------------------------------

TEST_F(PqDepositTxTest, CreateBuildsWellFormedDepositOutput)
{
  PqAccountKeys acct = PqAccount::generateFromSeed(seedFromByte(0x21));

  PqDepositRequest req;
  req.amount = fixed_amount;
  req.fee = fee;
  req.term = fixed_term;
  req.inputAmount = fixed_input;
  req.ring.push_back(makeSignerRingMember(5));
  req.ring.push_back(makeDecoyRingMember(9, 0xAA));
  req.signerGlobalIndex = 5;
  req.kemSecretKey = testnetKemSk();
  req.depositDsaPubKey = acct.dsaPublicKey;
  req.changeKemPubKey = testnetKemPk();

  Transaction tx;
  std::string err;
  ASSERT_TRUE(buildPqDepositTransaction(req, tx, err)) << err;

  ASSERT_EQ(static_cast<uint8_t>(TRANSACTION_VERSION_3), tx.version);
  ASSERT_EQ(1u, tx.inputs.size());
  ASSERT_EQ(typeid(PqKeyInput), tx.inputs[0].type());
  ASSERT_FALSE(boost::get<PqKeyInput>(tx.inputs[0]).ringSig.empty()) << "funding ring must be signed";

  // outputs: [0] deposit cell, [1] change
  ASSERT_EQ(2u, tx.outputs.size());
  ASSERT_EQ(typeid(PqMultisigOutput), tx.outputs[0].target.type());
  const PqMultisigOutput &dep = boost::get<PqMultisigOutput>(tx.outputs[0].target);
  ASSERT_EQ(1u, dep.keys.size());
  ASSERT_EQ(ccx_pq_multisig_pubkey_bytes(), dep.keys[0].size());
  ASSERT_EQ(acct.dsaPublicKey, dep.keys[0]);
  ASSERT_EQ(1, dep.requiredSignatureCount);
  ASSERT_EQ(fixed_term, dep.term);
  ASSERT_EQ(fixed_amount, tx.outputs[0].amount);

  // change == input - amount - fee
  ASSERT_EQ(typeid(PqKeyOutput), tx.outputs[1].target.type());
  ASSERT_EQ(fixed_input - fixed_amount - fee, tx.outputs[1].amount);

  // The daemon's output-acceptance must ACCEPT this deposit cell (term band + depositMinAmount).
  EXPECT_TRUE(fixedCurrency.validateOutput(tx.outputs[0].amount, dep, /*height*/ 100));
}

TEST_F(PqDepositTxTest, CreateRejectsWrongLengthDsaKey)
{
  PqDepositRequest req;
  req.amount = fixed_amount;
  req.fee = fee;
  req.term = fixed_term;
  req.inputAmount = fixed_input;
  req.ring.push_back(makeSignerRingMember(5));
  req.ring.push_back(makeDecoyRingMember(9, 0xAA));
  req.signerGlobalIndex = 5;
  req.kemSecretKey = testnetKemSk();
  req.depositDsaPubKey = std::vector<uint8_t>(100, 0x00); // wrong length (consensus requires 1952)
  req.changeKemPubKey = testnetKemPk();

  Transaction tx;
  std::string err;
  EXPECT_FALSE(buildPqDepositTransaction(req, tx, err));
}

TEST_F(PqDepositTxTest, CreateRejectsInsufficientFunding)
{
  PqAccountKeys acct = PqAccount::generateFromSeed(seedFromByte(0x21));
  PqDepositRequest req;
  req.amount = fixed_input;     // == input, leaves nothing for the fee
  req.fee = fee;
  req.term = fixed_term;
  req.inputAmount = fixed_input;
  req.ring.push_back(makeSignerRingMember(5));
  req.ring.push_back(makeDecoyRingMember(9, 0xAA));
  req.signerGlobalIndex = 5;
  req.kemSecretKey = testnetKemSk();
  req.depositDsaPubKey = acct.dsaPublicKey;
  req.changeKemPubKey = testnetKemPk();

  Transaction tx;
  std::string err;
  EXPECT_FALSE(buildPqDepositTransaction(req, tx, err));
}

// ----------------------------------------------------------------------------------------------------
// WITHDRAW
// ----------------------------------------------------------------------------------------------------

TEST_F(PqDepositTxTest, WithdrawInlineSignatureVerifiesOverSigningHash)
{
  PqAccountKeys acct = PqAccount::generateFromSeed(seedFromByte(0x42));
  const uint32_t height = 100 + fixed_term;
  const uint64_t interest = fixedCurrency.calculateInterest(fixed_amount, fixed_term, height - fixed_term);

  PqWithdrawRequest req;
  req.amount = fixed_amount;
  req.outputIndex = 7;
  req.term = fixed_term;
  req.requiredSignatureCount = 1;
  req.interest = interest;
  req.signingSecretKeys.push_back(acct.dsaSecretKey);
  req.payoutKemPubKey = testnetKemPk();

  Transaction tx;
  std::string err;
  ASSERT_TRUE(buildPqWithdrawTransaction(req, tx, err)) << err;

  ASSERT_EQ(static_cast<uint8_t>(TRANSACTION_VERSION_3), tx.version);
  ASSERT_EQ(1u, tx.inputs.size());
  ASSERT_EQ(typeid(PqMultisigInput), tx.inputs[0].type());
  const PqMultisigInput &in = boost::get<PqMultisigInput>(tx.inputs[0]);
  ASSERT_EQ(fixed_amount, in.amount);
  ASSERT_EQ(7u, in.outputIndex);
  ASSERT_EQ(fixed_term, in.term);
  ASSERT_EQ(1, in.signatureCount);
  ASSERT_EQ(1u, in.signatures.size()) << "the m ML-DSA sigs live INLINE, not in tx.signatures";
  ASSERT_TRUE(tx.signatures.empty()) << "getSignaturesCount(PqMultisigInput) == 0";

  // payout == principal + interest
  ASSERT_EQ(1u, tx.outputs.size());
  ASSERT_EQ(fixed_amount + interest, tx.outputs[0].amount);

  // The single most important property: the inline sig verifies under the account ML-DSA pubkey over
  // the EXACT hash check_pq_multisig verifies against (the prefix with sigs cleared) — i.e. the
  // builder signed the right message.
  const crypto::Hash hash = pqSigningHash(tx);
  ASSERT_EQ(0, ccx_pq_multisig_verify(
                   reinterpret_cast<const uint8_t *>(&hash), sizeof(hash),
                   acct.dsaPublicKey.data(), acct.dsaPublicKey.size(),
                   in.signatures[0].data(), in.signatures[0].size()))
      << "inline ML-DSA signature must verify over getTransactionPqSigningHash";
}

TEST_F(PqDepositTxTest, WithdrawSignatureRejectsWrongMessage)
{
  PqAccountKeys acct = PqAccount::generateFromSeed(seedFromByte(0x42));
  PqWithdrawRequest req;
  req.amount = fixed_amount;
  req.outputIndex = 7;
  req.term = fixed_term;
  req.requiredSignatureCount = 1;
  req.interest = 50;
  req.signingSecretKeys.push_back(acct.dsaSecretKey);
  req.payoutKemPubKey = testnetKemPk();

  Transaction tx;
  std::string err;
  ASSERT_TRUE(buildPqWithdrawTransaction(req, tx, err)) << err;
  const PqMultisigInput &in = boost::get<PqMultisigInput>(tx.inputs[0]);

  // A DIFFERENT message (any hash != the real signing hash) must NOT verify — the sig is bound to the
  // exact prefix. Tamper the payout amount and re-hash; the old signature must fail.
  Transaction tampered = tx;
  tampered.outputs[0].amount += 1;
  const crypto::Hash wrongHash = pqSigningHash(tampered);
  EXPECT_NE(0, ccx_pq_multisig_verify(
                   reinterpret_cast<const uint8_t *>(&wrongHash), sizeof(wrongHash),
                   acct.dsaPublicKey.data(), acct.dsaPublicKey.size(),
                   in.signatures[0].data(), in.signatures[0].size()))
      << "a signature over the wrong message must be rejected";

  // And the wrong public key must reject too.
  PqAccountKeys other = PqAccount::generateFromSeed(seedFromByte(0x43));
  const crypto::Hash hash = pqSigningHash(tx);
  EXPECT_NE(0, ccx_pq_multisig_verify(
                   reinterpret_cast<const uint8_t *>(&hash), sizeof(hash),
                   other.dsaPublicKey.data(), other.dsaPublicKey.size(),
                   in.signatures[0].data(), in.signatures[0].size()))
      << "verification under a different key must fail";
}

TEST_F(PqDepositTxTest, WithdrawTermIsCopiedFromRequest)
{
  // The withdraw builder MUST set input.term from the request (the caller copies it from the tracked
  // on-chain output). check_pq_multisig rejects input.term != output.term, so a builder that dropped
  // the term would always fail consensus. Here we assert the builder faithfully carries it.
  PqAccountKeys acct = PqAccount::generateFromSeed(seedFromByte(0x42));
  for (uint32_t term : {30u, 60u, fixed_term})
  {
    PqWithdrawRequest req;
    req.amount = fixed_amount;
    req.outputIndex = 7;
    req.term = term;
    req.requiredSignatureCount = 1;
    req.interest = 0;
    req.signingSecretKeys.push_back(acct.dsaSecretKey);
    req.payoutKemPubKey = testnetKemPk();
    Transaction tx;
    std::string err;
    ASSERT_TRUE(buildPqWithdrawTransaction(req, tx, err)) << err;
    EXPECT_EQ(term, boost::get<PqMultisigInput>(tx.inputs[0]).term);
  }
}

TEST_F(PqDepositTxTest, WithdrawRejectsWrongKeyCount)
{
  PqAccountKeys acct = PqAccount::generateFromSeed(seedFromByte(0x42));
  PqWithdrawRequest req;
  req.amount = fixed_amount;
  req.outputIndex = 7;
  req.term = fixed_term;
  req.requiredSignatureCount = 2;                // claims 2-of-n ...
  req.signingSecretKeys.push_back(acct.dsaSecretKey); // ... but only 1 key supplied
  req.payoutKemPubKey = testnetKemPk();
  Transaction tx;
  std::string err;
  EXPECT_FALSE(buildPqWithdrawTransaction(req, tx, err));
}

// Interest parity: the wallet's payout (amount + the interest it computes) MUST equal what the daemon
// credits for the deposit input (amount + Currency::getInterestForInput). If these diverge the v3
// conservation check (outputs <= inputs + interest) rejects the withdraw or burns funds.
TEST_F(PqDepositTxTest, WithdrawInterestParityWithDaemon)
{
  const std::vector<uint32_t> heights = {
      0 + fixed_term,
      parameters::END_MULTIPLIER_BLOCK - 1 + fixed_term,
      parameters::END_MULTIPLIER_BLOCK + fixed_term,
      parameters::END_MULTIPLIER_BLOCK + 1 + fixed_term};
  for (uint32_t h : heights)
  {
    // What the wallet would compute for the payout interest:
    const uint64_t walletInterest = fixedCurrency.calculateInterest(fixed_amount, fixed_term, h - fixed_term);
    // What the daemon credits for the PQ deposit input at this height:
    PqMultisigInput in;
    in.amount = fixed_amount;
    in.signatureCount = 1;
    in.outputIndex = 0;
    in.term = fixed_term;
    const uint64_t daemonInputAmount = fixedCurrency.getTransactionInputAmount(in, h);
    EXPECT_EQ(fixed_amount + walletInterest, daemonInputAmount)
        << "wallet payout must equal amount + daemon interest at height " << h;
  }
}
