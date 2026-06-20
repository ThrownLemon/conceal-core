// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the post-quantum encrypted on-chain message field (tx-extra tag 0x06,
// tx_extra_pq_message). The field uses ML-KEM-768 for key agreement and ChaCha20-Poly1305 AEAD for
// confidentiality AND integrity, so tampering ANY byte is detected. Covers: the Rust ML-KEM and
// AEAD selftests, encrypt/decrypt round-trips across message sizes and indices, wrong-recipient
// rejection, mixed-extra parsing and get_pq_messages_from_extra filtering, full-sweep tamper
// detection, oversize/short-length rejection by the parser, and the invariant that the tx hash is
// taken over the raw tx.extra bytes (unchanged by 0x06).
// See docs/design/quantum-resistance/messages-mlkem.md.

#include "gtest/gtest.h"

#include <string>
#include <vector>

#include <boost/utility/value_init.hpp>

#include "crypto/hash.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include "pq_ring_sig.h"

using namespace cn;

namespace
{
  // A fresh ML-KEM-768 keypair for the test (1184-byte pk / 2400-byte sk).
  struct KemKeyPair
  {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;

    KemKeyPair() : pk(ccx_pq_kem_pubkey_bytes(), 0), sk(ccx_pq_kem_seckey_bytes(), 0)
    {
      int rc = ccx_pq_kem_keypair(pk.data(), pk.size(), sk.data(), sk.size());
      EXPECT_EQ(0, rc);
    }
  };

  // Serialize a single PQ message field into a fresh extra byte vector via the production writer.
  std::vector<uint8_t> writePqExtra(const tx_extra_pq_message &m)
  {
    std::vector<uint8_t> extra;
    std::vector<TransactionExtraField> fields;
    fields.push_back(m);
    EXPECT_TRUE(writeTransactionExtra(extra, fields));
    return extra;
  }

  // Append an unsigned LEB128 varint (the on-wire length prefix). Used to FORGE a raw 0x06 field that
  // the production writers (which now enforce MEDIUM-3 bounds) would refuse to emit, so the parser's
  // own bound checks can be exercised independently.
  void appendVarint(std::vector<uint8_t> &out, uint64_t v)
  {
    while (v >= 0x80)
    {
      out.push_back(static_cast<uint8_t>((v & 0x7f) | 0x80));
      v >>= 7;
    }
    out.push_back(static_cast<uint8_t>(v));
  }

  // Forge a raw 0x06 field [tag][varint(kemCtLen)][kemCt][varint(dataLen)][data]; kemCt is the correct
  // ML-KEM ciphertext size so the parser passes the kemCt check and reaches the data-length bound.
  std::vector<uint8_t> forgePqExtra(size_t dataLen)
  {
    std::vector<uint8_t> extra;
    extra.push_back(TX_EXTRA_PQ_MESSAGE_TAG);
    const size_t kemBytes = ccx_pq_kem_ct_bytes();
    appendVarint(extra, kemBytes);
    extra.insert(extra.end(), kemBytes, 0x11);
    appendVarint(extra, dataLen);
    extra.insert(extra.end(), dataLen, 0x22);
    return extra;
  }
}

// --- Rust FFI selftest -------------------------------------------------------------------------

TEST(PqMessage, RustMsgKemSelftestPasses)
{
  ccx_pq_sizes s = ccx_pq_msg_kem_selftest();
  ASSERT_EQ(1, s.ok);
  ASSERT_EQ(ccx_pq_kem_pubkey_bytes(), s.pk);
  ASSERT_EQ(ccx_pq_kem_seckey_bytes(), s.sk);
  ASSERT_EQ(ccx_pq_kem_ct_bytes(), s.ct_or_sig);
}

TEST(PqMessage, RustAeadSelftestPasses)
{
  // seal->open round-trip, full-sweep tamper rejection, wrong-seed and wrong-index rejection.
  ccx_pq_sizes s = ccx_pq_msg_aead_selftest();
  ASSERT_EQ(1, s.ok);
  ASSERT_EQ(static_cast<size_t>(TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE), s.ct_or_sig);
}

// --- encrypt/decrypt round-trips ---------------------------------------------------------------

TEST(PqMessage, RoundTripVariousSizesAndIndices)
{
  KemKeyPair kp;

  std::vector<std::string> messages;
  messages.push_back("");                                  // empty
  messages.push_back("hi");                                // short
  messages.push_back(std::string(37, 'x'));               // odd length
  messages.push_back(std::string(4096, '\xAB'));          // multi-KB
  messages.push_back(std::string(1, '\0'));               // single NUL byte

  const size_t indices[] = {0, 1, 5, 123, 65535};

  for (size_t idx : indices)
  {
    for (const std::string &msg : messages)
    {
      tx_extra_pq_message field;
      ASSERT_TRUE(field.encrypt(idx, msg, kp.pk));
      ASSERT_EQ(ccx_pq_kem_ct_bytes(), field.kemCt.size());
      // data is the AEAD-sealed blob: plaintext + 16-byte Poly1305 tag.
      ASSERT_EQ(msg.size() + TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE, field.data.size());

      // Round-trip through the production serializer/parser.
      std::vector<uint8_t> extra = writePqExtra(field);
      std::vector<TransactionExtraField> parsed;
      ASSERT_TRUE(parseTransactionExtra(extra, parsed));
      ASSERT_EQ(1u, parsed.size());
      ASSERT_EQ(typeid(tx_extra_pq_message), parsed[0].type());

      const tx_extra_pq_message &back = boost::get<tx_extra_pq_message>(parsed[0]);
      std::string out;
      ASSERT_TRUE(back.decrypt(idx, kp.sk, out));
      ASSERT_EQ(msg, out);
    }
  }
}

TEST(PqMessage, WrongIndexFailsDecrypt)
{
  KemKeyPair kp;
  tx_extra_pq_message field;
  ASSERT_TRUE(field.encrypt(7, "secret payload", kp.pk));

  std::string out;
  // The index is bound into the AEAD key + nonce, so a wrong index fails the Poly1305 tag check.
  ASSERT_FALSE(field.decrypt(8, kp.sk, out));
  ASSERT_TRUE(field.decrypt(7, kp.sk, out));
  ASSERT_EQ("secret payload", out);
}

// --- wrong recipient ---------------------------------------------------------------------------

TEST(PqMessage, WrongRecipientReturnsFalseNoCrash)
{
  KemKeyPair sender;   // recipient we encrypt to
  KemKeyPair stranger; // a different recipient

  tx_extra_pq_message field;
  ASSERT_TRUE(field.encrypt(0, "for the right person only", sender.pk));

  std::string out;
  // Wrong KEM secret -> different AEAD seed -> Poly1305 tag fails, no crash, no plaintext exposed.
  ASSERT_FALSE(field.decrypt(0, stranger.sk, out));
  ASSERT_TRUE(field.decrypt(0, sender.sk, out));
  ASSERT_EQ("for the right person only", out);
}

// --- mixed extra: pubkey + legacy 0x04 + pq 0x06 + TTL ------------------------------------------

TEST(PqMessage, MixedExtraParsesAllAndFiltersPqOnly)
{
  KemKeyPair kp;

  // Build [pubkey, legacy 0x04 message, pq 0x06 message, TTL] in one extra blob.
  std::vector<uint8_t> extra;

  crypto::PublicKey txPub = boost::value_initialized<crypto::PublicKey>();
  ASSERT_TRUE(addTransactionPublicKeyToExtra(extra, txPub));

  // Legacy unencrypted message (recipient == NULL keeps data as plaintext + checksum).
  tx_extra_message legacy;
  KeyPair dummyKey = boost::value_initialized<KeyPair>();
  ASSERT_TRUE(legacy.encrypt(0, "legacy-plain", nullptr, dummyKey));
  ASSERT_TRUE(append_message_to_extra(extra, legacy));

  // PQ message.
  tx_extra_pq_message pq;
  ASSERT_TRUE(pq.encrypt(0, "pq-secret", kp.pk));
  ASSERT_TRUE(append_pq_message_to_extra(extra, pq));

  appendTTLToExtra(extra, 1234);

  // All four fields parse.
  std::vector<TransactionExtraField> parsed;
  ASSERT_TRUE(parseTransactionExtra(extra, parsed));
  ASSERT_EQ(4u, parsed.size());
  ASSERT_EQ(typeid(TransactionExtraPublicKey), parsed[0].type());
  ASSERT_EQ(typeid(tx_extra_message), parsed[1].type());
  ASSERT_EQ(typeid(tx_extra_pq_message), parsed[2].type());
  ASSERT_EQ(typeid(TransactionExtraTTL), parsed[3].type());

  // get_pq_messages_from_extra returns only the PQ payload.
  std::vector<std::string> pqMessages = get_pq_messages_from_extra(extra, kp.sk);
  ASSERT_EQ(1u, pqMessages.size());
  ASSERT_EQ("pq-secret", pqMessages[0]);

  // get_messages_from_extra returns only the legacy one (and not the PQ field).
  std::vector<std::string> legacyMessages = get_messages_from_extra(extra, txPub, nullptr);
  ASSERT_EQ(1u, legacyMessages.size());
  ASSERT_EQ("legacy-plain", legacyMessages[0]);
}

// --- tamper detection --------------------------------------------------------------------------

TEST(PqMessage, TamperedAnyByteFailsNoFfiPanic)
{
  KemKeyPair kp;
  tx_extra_pq_message field;
  ASSERT_TRUE(field.encrypt(3, "do not tamper", kp.pk));

  // Real integrity: flipping ANY byte of the AEAD-sealed data (ciphertext bytes OR the trailing
  // 16-byte Poly1305 tag) must make decrypt fail. This is the whole point of the AEAD upgrade over
  // the legacy chacha8 + 4-zero checksum, where corrupting a plaintext byte was undetected.
  for (size_t i = 0; i < field.data.size(); ++i)
  {
    tx_extra_pq_message t = field;
    t.data[i] ^= 0xFF;
    std::string out;
    ASSERT_FALSE(t.decrypt(3, kp.sk, out)) << "data byte " << i << " tamper was not detected";
  }

  // Flipping any KEM-ciphertext byte -> ML-KEM implicit rejection yields a different shared secret
  // -> a different AEAD key -> the Poly1305 tag check fails, no FFI panic.
  {
    tx_extra_pq_message t = field;
    t.kemCt[10] ^= 0xFF;
    std::string out;
    ASSERT_FALSE(t.decrypt(3, kp.sk, out));
  }

  // Untampered still decrypts.
  std::string out;
  ASSERT_TRUE(field.decrypt(3, kp.sk, out));
  ASSERT_EQ("do not tamper", out);
}

// --- parser bounds -----------------------------------------------------------------------------

TEST(PqMessage, OversizeDataRejectedByParser)
{
  // MEDIUM-3: the production writers (encrypt / append_pq_message_to_extra / writeTransactionExtra) now
  // REFUSE to emit a field whose data exceeds the parser bound, so an oversize field can only arrive
  // over the wire from a hostile peer. Forge the raw bytes directly so the parser's bound is exercised.
  std::vector<uint8_t> extra = forgePqExtra(TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE + 1);
  std::vector<TransactionExtraField> parsed;
  // Oversize data must be rejected (parser returns false) without OOM/crash.
  ASSERT_FALSE(parseTransactionExtra(extra, parsed));
}

TEST(PqMessage, WrongKemCtLengthRejectedByParser)
{
  KemKeyPair kp;
  tx_extra_pq_message field;
  ASSERT_TRUE(field.encrypt(0, "abc", kp.pk));
  // Corrupt the kemCt length so it no longer equals ccx_pq_kem_ct_bytes().
  field.kemCt.resize(field.kemCt.size() - 1);

  std::vector<uint8_t> extra = writePqExtra(field);
  std::vector<TransactionExtraField> parsed;
  ASSERT_FALSE(parseTransactionExtra(extra, parsed));
}

TEST(PqMessage, ShortSealedDataRejectedByParser)
{
  // A valid sealed blob is at least the 16-byte Poly1305 tag. Forge a field one byte short of that
  // directly (the production writers now reject it), so the parser's lower-bound check is exercised.
  std::vector<uint8_t> extra = forgePqExtra(TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE - 1);
  std::vector<TransactionExtraField> parsed;
  ASSERT_FALSE(parseTransactionExtra(extra, parsed));
}

// --- raw-extra invariant -----------------------------------------------------------------------

TEST(PqMessage, RawExtraBytesAreCanonicalAndHashStable)
{
  KemKeyPair kp;
  tx_extra_pq_message field;
  ASSERT_TRUE(field.encrypt(0, "hash-me", kp.pk));

  std::vector<uint8_t> extra = writePqExtra(field);

  // The tx hash is taken over the raw tx.extra byte vector. Parsing then re-serializing the same
  // fields must reproduce the identical bytes, so the hash is unaffected by adding the 0x06 field.
  std::vector<TransactionExtraField> parsed;
  ASSERT_TRUE(parseTransactionExtra(extra, parsed));
  std::vector<uint8_t> rewritten;
  ASSERT_TRUE(writeTransactionExtra(rewritten, parsed));
  ASSERT_EQ(extra, rewritten);

  crypto::Hash h1 = crypto::cn_fast_hash(extra.data(), extra.size());
  crypto::Hash h2 = crypto::cn_fast_hash(rewritten.data(), rewritten.size());
  ASSERT_EQ(0, memcmp(&h1, &h2, sizeof(crypto::Hash)));
}
