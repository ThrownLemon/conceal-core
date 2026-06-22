// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SILENT-FORK GUARD for the consensus binary serializer (TASK 1).
//
// The homemade KV binary serializer in CryptoNoteSerialization.cpp is simultaneously the P2P wire
// format, the on-disk blockchain/wallet format, AND consensus-hash-observable (the tx/block hash is
// taken over these exact bytes). Post-quantum input/output variants (PqKeyInput/Output tag 0x4,
// PqMultisigInput/Output tag 0x5) and the tx-extra 0x06 PQ message field were added to it BY HAND.
// Any accidental byte drift in those serialize() functions silently FORKS the chain and invalidates
// every hardcoded checkpoint. This suite pins the format two ways, so a drift FAILS the build:
//
//   1. Round-trip: every input/output variant and full v1/v2/v3 transactions + a block are
//      serialized, parsed back, and RE-serialized; the re-serialized bytes must be byte-identical
//      (toBinaryArray / fromBinaryArray idempotence).
//   2. Golden vectors: a fixed example of each variant is serialized and compared against a
//      hardcoded hex string. A future change to any serialize() body that alters the layout breaks
//      the golden assertion even if round-trip still happens to hold.
//
// The byte layout each vector encodes is documented in
// docs/design/quantum-resistance/serialization-format-spec.md. Do NOT "fix" a failing golden vector
// by editing the expected hex unless the serializer change is a DELIBERATE, height-gated, hard-fork
// consensus change — that is exactly the event this guard exists to surface.

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <boost/utility/value_init.hpp>

#include "crypto/hash.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "Common/StringTools.h"

#include "pq_ring_sig.h" // ccx_pq_kem_ct_bytes() for the 0x06 framing golden

using namespace cn;

namespace
{
  // Deterministic byte filler: byte[i] = (base + i) & 0xff. Gives every vector a distinct,
  // human-recognisable pattern in the golden hex.
  std::vector<uint8_t> fillVec(size_t len, uint8_t base)
  {
    std::vector<uint8_t> v(len);
    for (size_t i = 0; i < len; ++i)
    {
      v[i] = static_cast<uint8_t>((base + i) & 0xff);
    }
    return v;
  }

  template <typename Pod>
  Pod fillPod(uint8_t base)
  {
    Pod p;
    auto *bytes = reinterpret_cast<uint8_t *>(&p);
    for (size_t i = 0; i < sizeof(Pod); ++i)
    {
      bytes[i] = static_cast<uint8_t>((base + i) & 0xff);
    }
    return p;
  }

  std::string toHex(const BinaryArray &ba)
  {
    return common::toHex(ba.data(), ba.size());
  }

  // Serialize an input/output VARIANT (TransactionInput / TransactionOutputTarget) so the leading
  // byte is the variant tag, matching the on-wire encoding for vin/vout elements.
  template <typename Variant>
  BinaryArray variantBytes(const Variant &v)
  {
    return toBinaryArray(v);
  }

  // Round-trip a variant value: serialize -> parse -> re-serialize, assert identical bytes.
  template <typename Variant>
  void expectVariantRoundTrip(const Variant &v)
  {
    BinaryArray first = toBinaryArray(v);
    Variant parsed;
    ASSERT_TRUE(fromBinaryArray(parsed, first));
    BinaryArray second = toBinaryArray(parsed);
    ASSERT_EQ(first, second) << "re-serialization is not byte-identical";
  }

  // --- canonical fixed examples (shared by golden + round-trip tests) ------------------------------

  TransactionInput makeBaseInput()
  {
    BaseInput in;
    in.blockIndex = 0x01020304;
    return in;
  }

  TransactionInput makeKeyInput()
  {
    KeyInput in;
    in.amount = 1000000;
    in.outputIndexes = {1, 2, 3};
    in.keyImage = fillPod<crypto::KeyImage>(0x10);
    return in;
  }

  TransactionInput makeMultisignatureInput()
  {
    MultisignatureInput in;
    in.amount = 2000000;
    in.signatureCount = 2;
    in.outputIndex = 7;
    in.term = 11;
    return in;
  }

  TransactionInput makePqKeyInput()
  {
    PqKeyInput in;
    in.amount = 3000000;
    in.outputIndexes = {4, 5};
    in.nullifier = fillVec(8, 0xA0);
    in.ringSig = fillVec(12, 0xB0);
    return in;
  }

  TransactionInput makePqMultisigInput()
  {
    PqMultisigInput in;
    in.amount = 4000000;
    in.signatureCount = 2;
    in.outputIndex = 9;
    in.term = 13;
    in.signatures = {fillVec(6, 0xC0), fillVec(7, 0xD0)};
    return in;
  }

  TransactionOutputTarget makeKeyOutput()
  {
    KeyOutput out;
    out.key = fillPod<crypto::PublicKey>(0x20);
    return out;
  }

  TransactionOutputTarget makeMultisignatureOutput()
  {
    MultisignatureOutput out;
    out.keys = {fillPod<crypto::PublicKey>(0x30), fillPod<crypto::PublicKey>(0x40)};
    out.requiredSignatureCount = 2;
    out.term = 5;
    return out;
  }

  TransactionOutputTarget makePqKeyOutput()
  {
    PqKeyOutput out;
    out.key = fillVec(10, 0x50);
    out.kemCt = fillVec(14, 0x60);
    return out;
  }

  TransactionOutputTarget makePqMultisigOutput()
  {
    PqMultisigOutput out;
    out.dsaSchemeId = PQ_DSA_SCHEME_ID;
    out.keys = {fillVec(5, 0x70), fillVec(6, 0x80)};
    out.requiredSignatureCount = 3;
    out.term = 17;
    return out;
  }
}

// ================================================================================================
// GOLDEN VECTORS — input variants
// ================================================================================================

TEST(TransactionSerializationGolden, BaseInputGolden)
{
  EXPECT_EQ("ff84868808", toHex(variantBytes(makeBaseInput())));
  expectVariantRoundTrip(makeBaseInput());
}

TEST(TransactionSerializationGolden, KeyInputGolden)
{
  EXPECT_EQ("02c0843d03010203101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            toHex(variantBytes(makeKeyInput())));
  expectVariantRoundTrip(makeKeyInput());
}

TEST(TransactionSerializationGolden, MultisignatureInputGolden)
{
  EXPECT_EQ("0380897a02070b", toHex(variantBytes(makeMultisignatureInput())));
  expectVariantRoundTrip(makeMultisignatureInput());
}

TEST(TransactionSerializationGolden, PqKeyInputGolden)
{
  EXPECT_EQ("08c08db70102040508a0a1a2a3a4a5a6a70cb0b1b2b3b4b5b6b7b8b9babb", // tag 0x08 on the merged tree
            toHex(variantBytes(makePqKeyInput())));
  expectVariantRoundTrip(makePqKeyInput());
}

TEST(TransactionSerializationGolden, PqMultisigInputGolden)
{
  EXPECT_EQ("098092f40102090d0206c0c1c2c3c4c507d0d1d2d3d4d5d6", // tag 0x09 on the merged tree
            toHex(variantBytes(makePqMultisigInput())));
  expectVariantRoundTrip(makePqMultisigInput());
}

// ================================================================================================
// GOLDEN VECTORS — output target variants
// ================================================================================================

TEST(TransactionSerializationGolden, KeyOutputGolden)
{
  EXPECT_EQ("02202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            toHex(variantBytes(makeKeyOutput())));
  expectVariantRoundTrip(makeKeyOutput());
}

TEST(TransactionSerializationGolden, MultisignatureOutputGolden)
{
  EXPECT_EQ("0302303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0205",
            toHex(variantBytes(makeMultisignatureOutput())));
  expectVariantRoundTrip(makeMultisignatureOutput());
}

TEST(TransactionSerializationGolden, PqKeyOutputGolden)
{
  EXPECT_EQ("080a505152535455565758590e606162636465666768696a6b6c6d", // tag 0x08 on the merged tree
            toHex(variantBytes(makePqKeyOutput())));
  expectVariantRoundTrip(makePqKeyOutput());
}

TEST(TransactionSerializationGolden, PqMultisigOutputGolden)
{
  EXPECT_EQ("098484f8860c02057071727374068081828384850311", // tag 0x09 + PQ_DSA_SCHEME_ID
            toHex(variantBytes(makePqMultisigOutput())));
  expectVariantRoundTrip(makePqMultisigOutput());
}

// ================================================================================================
// FULL TRANSACTIONS (v1/v2/v3) and a BLOCK with mixed inputs/outputs
// ================================================================================================

namespace
{
  // Build a transaction prefix shared by the version tests. Mixes a KeyInput with a KeyOutput so the
  // common spend path is covered; the extra carries a tx public key.
  Transaction makeBaseTransaction(uint8_t version)
  {
    Transaction tx;
    tx.version = version;
    tx.unlockTime = 0;

    tx.inputs.push_back(makeKeyInput());

    TransactionOutput o;
    o.amount = 1000000;
    o.target = makeKeyOutput();
    tx.outputs.push_back(o);

    crypto::PublicKey txPub = fillPod<crypto::PublicKey>(0x90);
    addTransactionPublicKeyToExtra(tx.extra, txPub);

    // One KeyInput expects outputIndexes.size() signatures.
    tx.signatures.resize(1);
    tx.signatures[0].push_back(fillPod<crypto::Signature>(0xE0));
    tx.signatures[0].push_back(fillPod<crypto::Signature>(0xF0));
    tx.signatures[0].push_back(fillPod<crypto::Signature>(0x05));
    return tx;
  }
}

TEST(TransactionSerializationGolden, FullTransactionV1RoundTrip)
{
  Transaction tx = makeBaseTransaction(1);
  BinaryArray first = toBinaryArray(tx);
  Transaction parsed;
  ASSERT_TRUE(fromBinaryArray(parsed, first));
  BinaryArray second = toBinaryArray(parsed);
  ASSERT_EQ(first, second);
}

TEST(TransactionSerializationGolden, FullTransactionV2RoundTrip)
{
  Transaction tx = makeBaseTransaction(2);
  BinaryArray first = toBinaryArray(tx);
  Transaction parsed;
  ASSERT_TRUE(fromBinaryArray(parsed, first));
  ASSERT_EQ(first, toBinaryArray(parsed));
}

TEST(TransactionSerializationGolden, FullTransactionV3RoundTrip)
{
  Transaction tx = makeBaseTransaction(3);
  BinaryArray first = toBinaryArray(tx);
  Transaction parsed;
  ASSERT_TRUE(fromBinaryArray(parsed, first));
  ASSERT_EQ(first, toBinaryArray(parsed));
}

namespace
{
  // The full mixed-variant transaction (every input + output variant + framed signatures), built
  // deterministically so it can carry a hardcoded golden vector for the COMPOSITE envelope (version
  // varint, vin/vout counts, per-output amount, extra framing, positional signature framing) — the
  // per-variant goldens above cannot catch a drift in that envelope (review FIX 2).
  Transaction makeMixedTransaction()
  {
    Transaction tx;
    tx.version = 3;
    tx.unlockTime = 42;

    tx.inputs.push_back(makeBaseInput());            // 0 sigs
    tx.inputs.push_back(makeKeyInput());             // 3 sigs (outputIndexes.size())
    tx.inputs.push_back(makeMultisignatureInput());  // 2 sigs (signatureCount)
    tx.inputs.push_back(makePqKeyInput());           // 0 sigs (inline)
    tx.inputs.push_back(makePqMultisigInput());      // 0 sigs (inline)

    std::vector<TransactionOutputTarget> targets;
    targets.push_back(makeKeyOutput());
    targets.push_back(makeMultisignatureOutput());
    targets.push_back(makePqKeyOutput());
    targets.push_back(makePqMultisigOutput());
    for (const auto &target : targets)
    {
      TransactionOutput o;
      o.amount = 7;
      o.target = target;
      tx.outputs.push_back(o);
    }

    // Positional signatures: only KeyInput (3) and MultisignatureInput (2) contribute.
    tx.signatures.resize(tx.inputs.size());
    tx.signatures[1] = {fillPod<crypto::Signature>(0x01), fillPod<crypto::Signature>(0x02),
                        fillPod<crypto::Signature>(0x03)};
    tx.signatures[2] = {fillPod<crypto::Signature>(0x04), fillPod<crypto::Signature>(0x05)};
    return tx;
  }
}

TEST(TransactionSerializationGolden, FullTransactionV3Golden)
{
  // Hardcoded golden for a full v3 Transaction (single KeyInput + KeyOutput, tx-pubkey extra, framed
  // signatures). Pins the composite envelope, not just the variant bodies.
  EXPECT_EQ(
      "03000102c0843d03010203101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
      "01c0843d02202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
      "2101909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
      "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344",
      toHex(toBinaryArray(makeBaseTransaction(3))));
}

TEST(TransactionSerializationGolden, MixedInputsOutputsTransactionRoundTrip)
{
  Transaction tx = makeMixedTransaction();
  BinaryArray first = toBinaryArray(tx);
  Transaction parsed;
  ASSERT_TRUE(fromBinaryArray(parsed, first));
  ASSERT_EQ(first, toBinaryArray(parsed));
}

TEST(TransactionSerializationGolden, MixedInputsOutputsTransactionGolden)
{
  // Hardcoded golden for the mixed-variant transaction — pins the full envelope with all five input
  // tags, all four output tags, and the positional signature framing together (review FIX 2).
  EXPECT_EQ(
      "032a05ff8486880802c0843d03010203101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
      "0380897a02070b08c08db70102040508a0a1a2a3a4a5a6a70cb0b1b2b3b4b5b6b7b8b9babb"
      "098092f40102090d0206c0c1c2c3c4c507d0d1d2d3d4d5d6"
      "040702202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
      "070302303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0205"
      "07080a505152535455565758590e606162636465666768696a6b6c6d"
      "07098484f8860c02057071727374068081828384850311"
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
      "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041"
      "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142"
      "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243"
      "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344",
      toHex(toBinaryArray(makeMixedTransaction())));
}

namespace
{
  // Deterministic block (header + miner tx + tx hashes) shared by the round-trip and golden tests,
  // so the golden pins the block envelope (header varints, the raw-4-byte nonce, the nested miner tx
  // framing, and the tx-hash array count) — review FIX 2.
  Block makeMixedBlock()
  {
    Block block;
    block.majorVersion = BLOCK_MAJOR_VERSION_1;
    block.minorVersion = 0;
    block.nonce = 0x0a0b0c0d;
    block.timestamp = 1500000000;
    block.previousBlockHash = fillPod<crypto::Hash>(0x11);

    // Miner tx: a BaseInput + a KeyOutput (the canonical coinbase shape).
    Transaction miner;
    miner.version = 1;
    miner.unlockTime = 60;
    miner.inputs.push_back(makeBaseInput());
    TransactionOutput o;
    o.amount = 5000000;
    o.target = makeKeyOutput();
    miner.outputs.push_back(o);
    crypto::PublicKey txPub = fillPod<crypto::PublicKey>(0x90);
    addTransactionPublicKeyToExtra(miner.extra, txPub);
    block.baseTransaction = miner;

    block.transactionHashes.push_back(fillPod<crypto::Hash>(0x22));
    block.transactionHashes.push_back(fillPod<crypto::Hash>(0x33));
    return block;
  }
}

TEST(TransactionSerializationGolden, BlockWithMixedBaseTxRoundTrip)
{
  Block block = makeMixedBlock();
  BinaryArray first = toBinaryArray(block);
  Block parsed;
  ASSERT_TRUE(fromBinaryArray(parsed, first));
  ASSERT_EQ(first, toBinaryArray(parsed));
}

TEST(TransactionSerializationGolden, BlockWithMixedBaseTxGolden)
{
  // Hardcoded golden for the block envelope (review FIX 2).
  EXPECT_EQ(
      "010080dea0cb05"
      "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
      "0d0c0b0a"
      "013c01ff8486880801c096b10202202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
      "2101909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
      "0222232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041"
      "333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152",
      toHex(toBinaryArray(makeMixedBlock())));
}

// ================================================================================================
// tx-extra fields: round-trip each type + the no-canonicalisation invariant (hash over RAW bytes)
// ================================================================================================

TEST(TransactionExtraGolden, EachFieldTypeRoundTrips)
{
  std::vector<uint8_t> extra;

  // 0x01 pubkey
  crypto::PublicKey pub = fillPod<crypto::PublicKey>(0x01);
  ASSERT_TRUE(addTransactionPublicKeyToExtra(extra, pub));

  // 0x02 nonce
  std::vector<uint8_t> nonce = fillVec(16, 0x40);
  ASSERT_TRUE(addExtraNonceToTransactionExtra(extra, nonce));

  // 0x03 merge-mining tag
  TransactionExtraMergeMiningTag mm;
  mm.depth = 3;
  mm.merkleRoot = fillPod<crypto::Hash>(0x70);
  ASSERT_TRUE(appendMergeMiningTagToExtra(extra, mm));

  // 0x04 legacy message (plaintext form: recipient == nullptr keeps data == msg || 4 zero bytes)
  tx_extra_message legacy;
  KeyPair dummy = boost::value_initialized<KeyPair>();
  ASSERT_TRUE(legacy.encrypt(0, "legacy", nullptr, dummy));
  ASSERT_TRUE(append_message_to_extra(extra, legacy));

  // 0x05 TTL
  appendTTLToExtra(extra, 999);

  // 0x06 PQ message — built with a FIXED kemCt (exactly ccx_pq_kem_ct_bytes(), so it survives the
  // parser bound) and a fixed sealed-blob `data`, bypassing the random KEM so the field is
  // deterministic. We only exercise the framing/round-trip here, not decryption.
  tx_extra_pq_message pq;
  pq.kemCt = fillVec(ccx_pq_kem_ct_bytes(), 0x11);
  pq.data = std::string(32, '\x55'); // >= 16-byte AEAD tag, <= max
  ASSERT_TRUE(append_pq_message_to_extra(extra, pq));

  // 0x07 authenticated message — fixed sealed-blob `data` (no KEM ct field), deterministic framing.
  tx_extra_authenticated_message auth;
  auth.data = std::string(20, '\x66'); // >= 16-byte AEAD tag, <= max
  ASSERT_TRUE(append_authenticated_message_to_extra(extra, auth));

  // All seven fields parse back in order.
  std::vector<TransactionExtraField> parsed;
  ASSERT_TRUE(parseTransactionExtra(extra, parsed));
  ASSERT_EQ(7u, parsed.size());
  ASSERT_EQ(typeid(TransactionExtraPublicKey), parsed[0].type());
  ASSERT_EQ(typeid(TransactionExtraNonce), parsed[1].type());
  ASSERT_EQ(typeid(TransactionExtraMergeMiningTag), parsed[2].type());
  ASSERT_EQ(typeid(tx_extra_message), parsed[3].type());
  ASSERT_EQ(typeid(TransactionExtraTTL), parsed[4].type());
  ASSERT_EQ(typeid(tx_extra_pq_message), parsed[5].type());
  ASSERT_EQ(typeid(tx_extra_authenticated_message), parsed[6].type());

  // Re-write the parsed fields; every field type (incl. 0x06 and 0x07) reproduces identical bytes.
  std::vector<uint8_t> rewritten;
  ASSERT_TRUE(writeTransactionExtra(rewritten, parsed));
  ASSERT_EQ(extra, rewritten);
}

TEST(TransactionExtraGolden, PqAndAuthMessageFramingGolden)
{
  // Focused, reviewable hardcoded goldens for the 0x06 and 0x07 field FRAMING (tag + length prefixes
  // + payload), built from fixed payloads so a drift in how either field is appended/serialized fails
  // the build (review FIX 2: the previous suite omitted 0x06/0x07 goldens). The 0x06 kemCt is large
  // (ccx_pq_kem_ct_bytes()), so we pin only its framing prefix; 0x07 is small enough to pin whole.

  // 0x07: tag 0x07, varint(len=20), then 20 x 0x66.
  {
    tx_extra_authenticated_message auth;
    auth.data = std::string(20, '\x66');
    std::vector<uint8_t> extra;
    ASSERT_TRUE(append_authenticated_message_to_extra(extra, auth));
    EXPECT_EQ("07146666666666666666666666666666666666666666", toHex(extra));
  }

  // 0x06: tag 0x06, varint(kemLen), kem bytes..., varint(dataLen=32), 32 x 0x55. Pin the leading
  // framing (tag + kem length prefix + first kem byte) which is what a serializer drift would move.
  {
    tx_extra_pq_message pq;
    pq.kemCt = fillVec(ccx_pq_kem_ct_bytes(), 0x11);
    pq.data = std::string(32, '\x55');
    std::vector<uint8_t> extra;
    ASSERT_TRUE(append_pq_message_to_extra(extra, pq));
    std::string hex = toHex(extra);
    // ccx_pq_kem_ct_bytes() == 1088 -> varint(1088) == 0xC0 0x08; first kem byte == 0x11.
    EXPECT_EQ("06c00811", hex.substr(0, 8)) << "0x06 framing prefix drifted";
    // Tail: the 32-byte data is length-prefixed with varint(32) == 0x20 then 32 x 0x55.
    EXPECT_NE(std::string::npos, hex.find("20" + std::string(64, '5'))) << "0x06 data framing drifted";
  }
}

TEST(TransactionExtraGolden, HashIsOverRawExtraBytesNoCanonicalisation)
{
  // The tx hash is computed over the RAW tx.extra byte vector — the parser does NOT canonicalise it.
  // Build an extra whose field ORDER is unusual (TTL before pubkey). Parsing then re-writing would,
  // if any canonicalisation existed, reorder the fields and change the hash. It must not.
  std::vector<uint8_t> extra;
  appendTTLToExtra(extra, 123);
  crypto::PublicKey pub = fillPod<crypto::PublicKey>(0xAA);
  ASSERT_TRUE(addTransactionPublicKeyToExtra(extra, pub));

  Transaction tx;
  tx.version = 1;
  tx.unlockTime = 0;
  tx.inputs.push_back(makeBaseInput());
  TransactionOutput o;
  o.amount = 1;
  o.target = makeKeyOutput();
  tx.outputs.push_back(o);
  tx.extra = extra;

  crypto::Hash h1 = getObjectHash(tx);

  // Parse the extra and write it back — bytes must be unchanged, hence the tx hash unchanged.
  std::vector<TransactionExtraField> parsed;
  ASSERT_TRUE(parseTransactionExtra(tx.extra, parsed));
  std::vector<uint8_t> rewritten;
  ASSERT_TRUE(writeTransactionExtra(rewritten, parsed));
  ASSERT_EQ(tx.extra, rewritten);

  Transaction tx2 = tx;
  tx2.extra = rewritten;
  crypto::Hash h2 = getObjectHash(tx2);
  ASSERT_EQ(0, memcmp(&h1, &h2, sizeof(crypto::Hash)));
}
