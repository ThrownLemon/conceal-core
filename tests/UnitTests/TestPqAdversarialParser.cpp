// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include <cstdint>
#include <string>
#include <vector>

#include "Common/Varint.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionExtra.h"

using namespace cn;

namespace
{
  void appendByte(BinaryArray &out, uint8_t byte)
  {
    out.push_back(byte);
  }

  void appendVarint(BinaryArray &out, uint64_t value)
  {
    const std::string encoded = tools::get_varint_data(value);
    out.insert(out.end(), encoded.begin(), encoded.end());
  }

  void appendBytes(BinaryArray &out, size_t count, uint8_t start)
  {
    out.reserve(out.size() + count);
    for (size_t i = 0; i < count; ++i)
    {
      out.push_back(static_cast<uint8_t>((start + i) & 0xff));
    }
  }

  void appendBinaryBlob(BinaryArray &out, size_t count, uint8_t start)
  {
    appendVarint(out, count);
    appendBytes(out, count, start);
  }

  void appendRepeatedVarint(BinaryArray &out, uint64_t value, size_t count)
  {
    const std::string encoded = tools::get_varint_data(value);
    out.reserve(out.size() + (encoded.size() * count));
    for (size_t i = 0; i < count; ++i)
    {
      out.insert(out.end(), encoded.begin(), encoded.end());
    }
  }

  BinaryArray makePqKeyInputWithOutputIndexCount(size_t outputIndexCount)
  {
    BinaryArray raw;
    appendByte(raw, 0x08); // PqKeyInput variant tag
    appendVarint(raw, 1);  // amount

    appendVarint(raw, outputIndexCount);
    appendRepeatedVarint(raw, 0, outputIndexCount);

    appendBinaryBlob(raw, PQ_NULLIFIER_SIZE, 0xa0);
    appendBinaryBlob(raw, 16, 0xb0);
    return raw;
  }

  BinaryArray makePqKeyInputWithRingSig(size_t ringSigBytes)
  {
    BinaryArray raw;
    appendByte(raw, 0x08); // PqKeyInput variant tag
    appendVarint(raw, 1);  // amount

    appendVarint(raw, 2);  // outputIndexes array length
    appendVarint(raw, 1);
    appendVarint(raw, 2);

    appendBinaryBlob(raw, PQ_NULLIFIER_SIZE, 0xa0);
    appendBinaryBlob(raw, ringSigBytes, 0xb0);
    return raw;
  }

  BinaryArray makePqKeyInputWithNullifier(size_t nullifierBytes)
  {
    BinaryArray raw;
    appendByte(raw, 0x08); // PqKeyInput variant tag
    appendVarint(raw, 1);  // amount

    appendVarint(raw, 2);  // outputIndexes array length
    appendVarint(raw, 1);
    appendVarint(raw, 2);

    appendBinaryBlob(raw, nullifierBytes, 0xa0);
    appendBinaryBlob(raw, 16, 0xb0);
    return raw;
  }

  BinaryArray makePqKeyOutput(size_t keyBytes, size_t kemBytes)
  {
    BinaryArray raw;
    appendByte(raw, 0x08); // PqKeyOutput variant tag
    appendBinaryBlob(raw, keyBytes, 0x50);
    appendBinaryBlob(raw, kemBytes, 0x60);
    return raw;
  }

  BinaryArray makePqMultisigInputWithSignature(size_t signatureBytes)
  {
    BinaryArray raw;
    appendByte(raw, 0x09); // PqMultisigInput variant tag
    appendVarint(raw, 1);  // amount
    appendVarint(raw, 1);  // signatureCount
    appendVarint(raw, 0);  // outputIndex
    appendVarint(raw, 0);  // term

    appendVarint(raw, 1);  // signatures array length
    appendBinaryBlob(raw, signatureBytes, 0x70);
    return raw;
  }

  BinaryArray makePqMultisigOutputWithKey(size_t keyBytes)
  {
    BinaryArray raw;
    appendByte(raw, 0x09); // PqMultisigOutput variant tag
    appendVarint(raw, PQ_DSA_SCHEME_ID);
    appendVarint(raw, 1);  // keys array length
    appendBinaryBlob(raw, keyBytes, 0x80);
    appendVarint(raw, 1);  // requiredSignatureCount
    appendVarint(raw, 0);  // term
    return raw;
  }

  // Build a PqKeyInput whose ringSig length PREFIX declares declaredRingSigBytes but only
  // actualRingSigBytes follow (the blob is truncated — the declared count is never present). A
  // pre-materialization bound rejects this at the prefix; the old post-read cap would have tried to
  // read the full declared blob (which the buffer cannot supply).
  BinaryArray makePqKeyInputWithOverDeclaredTruncatedRingSig(size_t declaredRingSigBytes, size_t actualRingSigBytes)
  {
    BinaryArray raw;
    appendByte(raw, 0x08); // PqKeyInput variant tag
    appendVarint(raw, 1);  // amount

    appendVarint(raw, 2);  // outputIndexes array length
    appendVarint(raw, 1);
    appendVarint(raw, 2);

    appendBinaryBlob(raw, PQ_NULLIFIER_SIZE, 0xa0);
    appendVarint(raw, declaredRingSigBytes);     // hostile over-declared ringSig length prefix
    appendBytes(raw, actualRingSigBytes, 0xb0);  // ...but the blob is truncated to far fewer bytes
    return raw;
  }
}

TEST(PqAdversarialParser, UnknownPqAdjacentVariantTagsReject)
{
  TransactionInput input;
  EXPECT_FALSE(fromBinaryArray(input, BinaryArray{0x0a}));

  TransactionOutputTarget output;
  EXPECT_FALSE(fromBinaryArray(output, BinaryArray{0x0a}));
}

TEST(PqAdversarialParser, PqMultisigArrayCountOverMaxRejects)
{
  BinaryArray raw;
  appendByte(raw, 0x09); // PqMultisigOutput variant tag
  appendVarint(raw, PQ_DSA_SCHEME_ID);
  appendVarint(raw, PQ_MULTISIG_MAX_KEYS + 1);

  TransactionOutputTarget output;
  EXPECT_FALSE(fromBinaryArray(output, raw));
}

TEST(PqAdversarialParser, PqKeyInputRingSigAtOneMiBCapParses)
{
  TransactionInput input;
  EXPECT_TRUE(fromBinaryArray(input, makePqKeyInputWithRingSig(1u << 20)));
}

TEST(PqAdversarialParser, PqKeyInputOversizedRingIndexVectorRejectsAtParseBound)
{
  // M-new-7 fixed: a ring index count beyond PQ_MAX_RING_SIZE is rejected at parse, before the
  // outputIndexes array is materialized.
  TransactionInput input;
  EXPECT_FALSE(fromBinaryArray(input, makePqKeyInputWithOutputIndexCount(1u << 20)));
}

TEST(PqAdversarialParser, PqKeyInputRingSigOverOneMiBCapRejects)
{
  TransactionInput input;
  EXPECT_FALSE(fromBinaryArray(input, makePqKeyInputWithRingSig((1u << 20) + 1)));
}

TEST(PqAdversarialParser, PqKeyInputOversizedNullifierRejectsAtParseBound)
{
  TransactionInput input;
  EXPECT_FALSE(fromBinaryArray(input, makePqKeyInputWithNullifier((1u << 16) + 1)));
}

TEST(PqAdversarialParser, PqKeyOutputOversizedKeyAndKemRejectAtParseBound)
{
  TransactionOutputTarget output;
  EXPECT_FALSE(fromBinaryArray(output, makePqKeyOutput((1u << 16) + 1, (1u << 16) + 1)));
}

TEST(PqAdversarialParser, PqMultisigInputOversizedSignatureRejectsAtParseBound)
{
  // M-new-6 fixed: an oversized multisig inner signature blob is rejected at parse (per-element bound).
  TransactionInput input;
  EXPECT_FALSE(fromBinaryArray(input, makePqMultisigInputWithSignature(1u << 20)));
}

TEST(PqAdversarialParser, PqMultisigOutputOversizedKeyRejectsAtParseBound)
{
  // M-new-6 fixed: an oversized multisig inner key blob is rejected at parse (per-element bound).
  TransactionOutputTarget output;
  EXPECT_FALSE(fromBinaryArray(output, makePqMultisigOutputWithKey(1u << 20)));
}

TEST(PqAdversarialParser, PqMultisigOutputWrongKeyLengthRejectedByCheckOutsValid)
{
  // M-new-8 fixed: a deposit cell whose public key is the wrong length is rejected by check_outs_valid,
  // so malformed PQ multisig outputs can no longer enter validated output state.
  PqMultisigOutput pqout;
  pqout.dsaSchemeId = PQ_DSA_SCHEME_ID;
  pqout.keys.push_back(std::vector<uint8_t>(1, 0x01));
  pqout.requiredSignatureCount = 1;
  pqout.term = 0;

  Transaction tx;
  tx.version = TRANSACTION_VERSION_4;
  TransactionOutput out;
  out.amount = 1000;
  out.target = pqout;
  tx.outputs.push_back(out);

  std::string error;
  EXPECT_FALSE(check_outs_valid(tx, &error));
}

TEST(PqAdversarialParser, PqExtraRejectsTruncatedPqMessageBeforeFollowingField)
{
  BinaryArray extra;
  appendByte(extra, TX_EXTRA_PQ_MESSAGE_TAG);
  appendVarint(extra, 32); // wrong KEM length and no body
  appendByte(extra, TX_EXTRA_AUTH_MESSAGE_TAG);
  appendBinaryBlob(extra, TX_EXTRA_AUTH_MESSAGE_NONCE_SIZE + TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE, 0x55);

  std::vector<TransactionExtraField> fields;
  EXPECT_FALSE(parseTransactionExtra(extra, fields));
  EXPECT_TRUE(fields.empty());
}

TEST(PqAdversarialParser, PqKeyInputOverDeclaredRingSigPrefixRejectedBeforeMaterialization)
{
  // M-new-6 (audit) residual: the ringSig length PREFIX declares (1<<20)+1 bytes but the buffer
  // supplies only 8 — the declared blob is never present. The bounded reader rejects the over-limit
  // length prefix BEFORE allocating/copying, so parsing fails even though the full declared blob is
  // absent (the pre-fix post-read cap would have first tried to read the whole declared size).
  TransactionInput input;
  EXPECT_FALSE(fromBinaryArray(input, makePqKeyInputWithOverDeclaredTruncatedRingSig((1u << 20) + 1, 8)));
}
