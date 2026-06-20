// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the authenticated classical on-chain message field (tx-extra tag 0x07,
// tx_extra_authenticated_message). It keeps the SAME Curve25519 ECDH key agreement as the legacy
// 0x04 message but seals the payload with ChaCha20-Poly1305 AEAD (ccx_pq_msg_seal/open) keyed by the
// ECDH-derived 32-byte seed, so tampering ANY byte is detected — unlike the legacy 0x04 chacha8 +
// 4-zero-byte owner-check, which is malleable. Covers: encrypt/decrypt round-trips across sizes and
// indices, wrong-index and wrong-recipient rejection, full-sweep tamper detection, mixed-extra
// parsing + get_authenticated_messages_from_extra filtering, parser bounds, and the raw-extra hash
// invariant.

#include "gtest/gtest.h"

#include <cstring>
#include <string>
#include <vector>

#include <boost/utility/value_init.hpp>

#include "crypto/hash.h"
#include "crypto/crypto.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include "pq_ring_sig.h" // ccx_pq_kem_ct_bytes() for the 0x06 DoS test

using namespace cn;

namespace
{
  // Append an unsigned LEB128 varint (the on-wire length encoding) to a byte vector. Used to forge a
  // tx-extra field whose declared length prefix is absurdly large without actually carrying that many
  // bytes (review FIX 1 DoS check).
  void appendVarint(std::vector<uint8_t> &out, uint64_t v)
  {
    while (v >= 0x80)
    {
      out.push_back(static_cast<uint8_t>((v & 0x7f) | 0x80));
      v >>= 7;
    }
    out.push_back(static_cast<uint8_t>(v));
  }

  // A sender tx keypair + a recipient account, the two halves of the classical ECDH the 0x07 field
  // (like the legacy 0x04 field) relies on.
  struct Parties
  {
    KeyPair txkey;                     // sender per-tx key
    AccountPublicAddress recipientPub; // recipient public address
    crypto::SecretKey recipientSpendSec;

    Parties()
    {
      txkey.publicKey = boost::value_initialized<crypto::PublicKey>();
      crypto::generate_keys(txkey.publicKey, txkey.secretKey);

      // Recipient spend keypair; the viewPublicKey is irrelevant to 0x07 (it keys off spend).
      crypto::generate_keys(recipientPub.spendPublicKey, recipientSpendSec);
      recipientPub.viewPublicKey = boost::value_initialized<crypto::PublicKey>();
    }
  };

  std::vector<uint8_t> writeAuthExtra(const tx_extra_authenticated_message &m)
  {
    std::vector<uint8_t> extra;
    std::vector<TransactionExtraField> fields;
    fields.push_back(m);
    EXPECT_TRUE(writeTransactionExtra(extra, fields));
    return extra;
  }
}

// --- encrypt/decrypt round-trips ---------------------------------------------------------------

TEST(AuthenticatedMessage, RoundTripVariousSizesAndIndices)
{
  Parties p;

  std::vector<std::string> messages;
  messages.push_back("");                          // empty
  messages.push_back("hi");                         // short
  messages.push_back(std::string(37, 'x'));         // odd length
  messages.push_back(std::string(4096, '\xAB'));    // multi-KB
  messages.push_back(std::string(1, '\0'));         // single NUL

  const size_t indices[] = {0, 1, 5, 123, 65535};

  for (size_t idx : indices)
  {
    for (const std::string &msg : messages)
    {
      tx_extra_authenticated_message field;
      ASSERT_TRUE(field.encrypt(idx, msg, &p.recipientPub, p.txkey));
      // data is the AEAD-sealed blob: plaintext + 16-byte Poly1305 tag.
      ASSERT_EQ(msg.size() + TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE, field.data.size());

      // Round-trip through the production serializer/parser.
      std::vector<uint8_t> extra = writeAuthExtra(field);
      std::vector<TransactionExtraField> parsed;
      ASSERT_TRUE(parseTransactionExtra(extra, parsed));
      ASSERT_EQ(1u, parsed.size());
      ASSERT_EQ(typeid(tx_extra_authenticated_message), parsed[0].type());

      const tx_extra_authenticated_message &back = boost::get<tx_extra_authenticated_message>(parsed[0]);
      std::string out;
      ASSERT_TRUE(back.decrypt(idx, p.txkey.publicKey, &p.recipientSpendSec, out));
      ASSERT_EQ(msg, out);
    }
  }
}

TEST(AuthenticatedMessage, WrongIndexFailsDecrypt)
{
  Parties p;
  tx_extra_authenticated_message field;
  ASSERT_TRUE(field.encrypt(7, "secret payload", &p.recipientPub, p.txkey));

  std::string out;
  // The index is bound into the AEAD key + nonce, so a wrong index fails the Poly1305 tag check.
  ASSERT_FALSE(field.decrypt(8, p.txkey.publicKey, &p.recipientSpendSec, out));
  ASSERT_TRUE(field.decrypt(7, p.txkey.publicKey, &p.recipientSpendSec, out));
  ASSERT_EQ("secret payload", out);
}

// --- wrong recipient ---------------------------------------------------------------------------

TEST(AuthenticatedMessage, WrongRecipientReturnsFalseNoCrash)
{
  Parties intended;
  Parties stranger; // a different recipient spend secret

  tx_extra_authenticated_message field;
  ASSERT_TRUE(field.encrypt(0, "for the right person only", &intended.recipientPub, intended.txkey));

  std::string out;
  // Wrong spend secret -> different ECDH derivation -> different AEAD seed -> Poly1305 tag fails.
  ASSERT_FALSE(field.decrypt(0, intended.txkey.publicKey, &stranger.recipientSpendSec, out));
  ASSERT_TRUE(field.decrypt(0, intended.txkey.publicKey, &intended.recipientSpendSec, out));
  ASSERT_EQ("for the right person only", out);
}

TEST(AuthenticatedMessage, NullRecipientRejected)
{
  Parties p;
  tx_extra_authenticated_message field;
  // Unlike the legacy 0x04 field (which keeps plaintext when recipient == nullptr), 0x07 is an
  // authenticated field with no plaintext fallback: encrypt without a recipient must fail.
  ASSERT_FALSE(field.encrypt(0, "no recipient", nullptr, p.txkey));

  // And decrypt with a null secret must fail rather than crash.
  ASSERT_TRUE(field.encrypt(0, "msg", &p.recipientPub, p.txkey));
  std::string out;
  ASSERT_FALSE(field.decrypt(0, p.txkey.publicKey, nullptr, out));
}

// --- tamper detection --------------------------------------------------------------------------

TEST(AuthenticatedMessage, TamperedAnyByteFailsDecrypt)
{
  Parties p;
  tx_extra_authenticated_message field;
  ASSERT_TRUE(field.encrypt(3, "do not tamper", &p.recipientPub, p.txkey));

  // Real integrity: flipping ANY byte of the AEAD-sealed data (ciphertext bytes OR the trailing
  // 16-byte Poly1305 tag) must make decrypt fail. This is the whole point of 0x07 over the legacy
  // 0x04 chacha8 + 4-zero checksum, where corrupting a plaintext byte was undetected.
  for (size_t i = 0; i < field.data.size(); ++i)
  {
    tx_extra_authenticated_message t = field;
    t.data[i] ^= 0xFF;
    std::string out;
    ASSERT_FALSE(t.decrypt(3, p.txkey.publicKey, &p.recipientSpendSec, out)) << "data byte " << i << " tamper was not detected";
  }

  // Untampered still decrypts.
  std::string out;
  ASSERT_TRUE(field.decrypt(3, p.txkey.publicKey, &p.recipientSpendSec, out));
  ASSERT_EQ("do not tamper", out);
}

// --- mixed extra: pubkey + legacy 0x04 + auth 0x07 + TTL ----------------------------------------

TEST(AuthenticatedMessage, MixedExtraParsesAllAndFiltersAuthOnly)
{
  Parties p;

  std::vector<uint8_t> extra;

  crypto::PublicKey txPub = p.txkey.publicKey;
  ASSERT_TRUE(addTransactionPublicKeyToExtra(extra, txPub));

  // Legacy unencrypted message (recipient == NULL keeps data as plaintext + checksum).
  tx_extra_message legacy;
  KeyPair dummyKey = boost::value_initialized<KeyPair>();
  ASSERT_TRUE(legacy.encrypt(0, "legacy-plain", nullptr, dummyKey));
  ASSERT_TRUE(append_message_to_extra(extra, legacy));

  // Authenticated 0x07 message.
  tx_extra_authenticated_message auth;
  ASSERT_TRUE(auth.encrypt(0, "auth-secret", &p.recipientPub, p.txkey));
  ASSERT_TRUE(append_authenticated_message_to_extra(extra, auth));

  appendTTLToExtra(extra, 1234);

  std::vector<TransactionExtraField> parsed;
  ASSERT_TRUE(parseTransactionExtra(extra, parsed));
  ASSERT_EQ(4u, parsed.size());
  ASSERT_EQ(typeid(TransactionExtraPublicKey), parsed[0].type());
  ASSERT_EQ(typeid(tx_extra_message), parsed[1].type());
  ASSERT_EQ(typeid(tx_extra_authenticated_message), parsed[2].type());
  ASSERT_EQ(typeid(TransactionExtraTTL), parsed[3].type());

  // get_authenticated_messages_from_extra returns only the 0x07 payload.
  std::vector<std::string> authMessages =
      get_authenticated_messages_from_extra(extra, p.txkey.publicKey, &p.recipientSpendSec);
  ASSERT_EQ(1u, authMessages.size());
  ASSERT_EQ("auth-secret", authMessages[0]);

  // get_messages_from_extra returns only the legacy one (and not the 0x07 field).
  std::vector<std::string> legacyMessages = get_messages_from_extra(extra, txPub, nullptr);
  ASSERT_EQ(1u, legacyMessages.size());
  ASSERT_EQ("legacy-plain", legacyMessages[0]);
}

// --- parser bounds -----------------------------------------------------------------------------

TEST(AuthenticatedMessage, OversizeDataRejectedByParser)
{
  Parties p;
  tx_extra_authenticated_message field;
  ASSERT_TRUE(field.encrypt(0, std::string(TX_EXTRA_AUTH_MESSAGE_MAX_DATA_SIZE, 'z'), &p.recipientPub, p.txkey));
  ASSERT_GT(field.data.size(), static_cast<size_t>(TX_EXTRA_AUTH_MESSAGE_MAX_DATA_SIZE));

  std::vector<uint8_t> extra = writeAuthExtra(field);
  std::vector<TransactionExtraField> parsed;
  ASSERT_FALSE(parseTransactionExtra(extra, parsed));
}

TEST(AuthenticatedMessage, ShortSealedDataRejectedByParser)
{
  Parties p;
  tx_extra_authenticated_message field;
  ASSERT_TRUE(field.encrypt(0, "abc", &p.recipientPub, p.txkey));
  // A valid sealed blob is at least the 16-byte Poly1305 tag; truncate below that.
  field.data.resize(TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE - 1);

  std::vector<uint8_t> extra = writeAuthExtra(field);
  std::vector<TransactionExtraField> parsed;
  ASSERT_FALSE(parseTransactionExtra(extra, parsed));
}

// --- raw-extra invariant -----------------------------------------------------------------------

TEST(AuthenticatedMessage, RawExtraBytesAreCanonicalAndHashStable)
{
  Parties p;
  tx_extra_authenticated_message field;
  ASSERT_TRUE(field.encrypt(0, "hash-me", &p.recipientPub, p.txkey));

  std::vector<uint8_t> extra = writeAuthExtra(field);

  // Parsing then re-serializing the same field must reproduce identical bytes, so the tx hash
  // (taken over the raw tx.extra) is unaffected by adding the 0x07 field.
  std::vector<TransactionExtraField> parsed;
  ASSERT_TRUE(parseTransactionExtra(extra, parsed));
  std::vector<uint8_t> rewritten;
  ASSERT_TRUE(writeTransactionExtra(rewritten, parsed));
  ASSERT_EQ(extra, rewritten);

  crypto::Hash h1 = crypto::cn_fast_hash(extra.data(), extra.size());
  crypto::Hash h2 = crypto::cn_fast_hash(rewritten.data(), rewritten.size());
  ASSERT_EQ(0, memcmp(&h1, &h2, sizeof(crypto::Hash)));
}

// --- DoS: huge declared length prefix must be rejected BEFORE allocation (review FIX 1) ---------

TEST(AuthenticatedMessage, HugeLengthPrefixRejectedWithoutAllocation_0x07)
{
  // Forge a 0x07 field whose declared data length is ~4 GiB but which carries only a couple of bytes.
  // The bounded reader must reject this (declared length > field max AND > remaining stream) WITHOUT
  // ever resizing a multi-GB buffer. The whole extra is only a handful of bytes, so if the parser
  // returned cleanly we are safe; a pre-fix parser would try to allocate ~4 GiB here.
  std::vector<uint8_t> extra;
  extra.push_back(TX_EXTRA_AUTH_MESSAGE_TAG);
  appendVarint(extra, 0xFFFFFFFFull); // declared length, far beyond the ~10-byte stream
  extra.push_back(0xAA);              // one stray byte of "payload"

  std::vector<TransactionExtraField> parsed;
  ASSERT_FALSE(parseTransactionExtra(extra, parsed));
}

TEST(AuthenticatedMessage, HugeLengthPrefixRejectedWithoutAllocation_0x06)
{
  // Same DoS shape for the 0x06 PQ message: a huge kemCt length prefix on a tiny stream must be
  // rejected before any allocation. (kemCt is read first, so an oversized kem length trips first.)
  std::vector<uint8_t> extra;
  extra.push_back(TX_EXTRA_PQ_MESSAGE_TAG);
  appendVarint(extra, 0xFFFFFFFFull); // declared kemCt length, far beyond the stream and the kem size
  extra.push_back(0xBB);

  std::vector<TransactionExtraField> parsed;
  ASSERT_FALSE(parseTransactionExtra(extra, parsed));
}

TEST(AuthenticatedMessage, LengthPrefixOverFieldMaxButUnderStreamRejected_0x07)
{
  // Edge case: declared length is within the remaining stream but OVER the field maximum. The bound
  // is min(field max, remaining), so this must still be rejected (and proves the field-max arm of
  // the check, not just the remaining-bytes arm).
  const size_t over = static_cast<size_t>(TX_EXTRA_AUTH_MESSAGE_MAX_DATA_SIZE) + 1;
  std::vector<uint8_t> extra;
  extra.push_back(TX_EXTRA_AUTH_MESSAGE_TAG);
  appendVarint(extra, over);
  extra.resize(extra.size() + over, 0x00); // actually carry that many bytes so only the max-bound trips

  std::vector<TransactionExtraField> parsed;
  ASSERT_FALSE(parseTransactionExtra(extra, parsed));
}

// --- domain separation: 0x04 and 0x07 to the same recipient+index must NOT collide (review FIX 3) -

TEST(AuthenticatedMessage, DomainSeparatedFromLegacy0x04)
{
  Parties p;
  const size_t index = 0;
  const std::string msg = "same plaintext, same recipient, same index";

  // Legacy 0x04 encrypted message (recipient != null engages the chacha8 keystream keyed by the
  // ECDH derivation with magic2 == 0x00).
  tx_extra_message legacy;
  ASSERT_TRUE(legacy.encrypt(index, msg, &p.recipientPub, p.txkey));

  // Authenticated 0x07 message to the SAME recipient + index (magic2 == 0x07).
  tx_extra_authenticated_message auth;
  ASSERT_TRUE(auth.encrypt(index, msg, &p.recipientPub, p.txkey));

  // Because the 0x07 seed is domain-separated (magic2 differs), the sealed/encrypted bytes must
  // differ — the keystreams are derived from different seeds, so no correlation. (They also differ
  // trivially in length thanks to the 16-byte AEAD tag vs the 4-byte legacy checksum, so compare the
  // overlapping prefix too, which would still match if the keystream were shared.)
  ASSERT_NE(legacy.data, auth.data);
  const size_t overlap = std::min(legacy.data.size(), auth.data.size());
  ASSERT_NE(0, memcmp(legacy.data.data(), auth.data.data(), overlap));

  // And 0x07 still round-trips correctly under its own domain.
  std::string out;
  ASSERT_TRUE(auth.decrypt(index, p.txkey.publicKey, &p.recipientSpendSec, out));
  ASSERT_EQ(msg, out);
}
