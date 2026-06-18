// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TransactionExtra.h"
#include "crypto/chacha8.h"
#include "Common/int-util.h"
#include "Common/MemoryInputStream.h"
#include "Common/StreamTools.h"
#include "Common/StringTools.h"
#include "Common/Varint.h"
#include "CryptoNoteTools.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/SerializationOverloads.h"
#include "pq_ring_sig.h" // ccx-pqc FFI: ML-KEM-768 message KEM (tx-extra 0x06)

using namespace crypto;
using namespace common;

namespace cn
{

  namespace
  {
    // Read a length-prefixed (varint len + raw bytes) blob from the extra stream, but BOUND the
    // declared length against both the configured field maximum AND the bytes actually remaining in
    // the stream BEFORE allocating. The generic string/serializeAsBinary readers resize() to the
    // declared length first (capped only at 128 MiB), so a tiny tx with a huge varint length prefix
    // would otherwise force a multi-MB allocation before the read fails (DoS — review FIX 1). This
    // helper rejects such a field early without ever allocating the oversized buffer.
    // Returns false (caller must fail the whole parse) if the declared length is over maxLen or
    // exceeds the remaining stream; the on-wire layout is unchanged — only the rejection is earlier.
    bool readBoundedExtraBlob(common::MemoryInputStream &iss, size_t totalSize, size_t maxLen,
                              std::string &out)
    {
      uint64_t len = 0;
      common::readVarint(iss, len);
      const size_t remaining = totalSize - iss.getPosition();
      if (len > maxLen || len > remaining)
      {
        return false;
      }
      out.resize(static_cast<size_t>(len));
      if (len > 0)
      {
        common::read(iss, &out[0], static_cast<size_t>(len));
      }
      return true;
    }
  }

  bool parseTransactionExtra(const std::vector<uint8_t> &transactionExtra, std::vector<TransactionExtraField> &transactionExtraFields)
  {
    transactionExtraFields.clear();

    if (transactionExtra.empty())
      return true;

    try
    {
      const size_t extraSize = transactionExtra.size();
      MemoryInputStream iss(transactionExtra.data(), extraSize);
      BinaryInputStreamSerializer ar(iss);

      int c = 0;

      while (!iss.endOfStream())
      {
        c = read<uint8_t>(iss);
        switch (c)
        {
        case TX_EXTRA_TAG_PADDING:
        {
          size_t size = 1;
          for (; !iss.endOfStream() && size <= TX_EXTRA_PADDING_MAX_COUNT; ++size)
          {
            if (read<uint8_t>(iss) != 0)
            {
              return false; // all bytes should be zero
            }
          }

          if (size > TX_EXTRA_PADDING_MAX_COUNT)
          {
            return false;
          }

          transactionExtraFields.push_back(TransactionExtraPadding{size});
          break;
        }

        case TX_EXTRA_TAG_PUBKEY:
        {
          TransactionExtraPublicKey extraPk;
          ar(extraPk.publicKey, "public_key");
          transactionExtraFields.push_back(extraPk);
          break;
        }

        case TX_EXTRA_NONCE:
        {
          TransactionExtraNonce extraNonce;
          uint8_t size = read<uint8_t>(iss);
          if (size > 0)
          {
            extraNonce.nonce.resize(size);
            read(iss, extraNonce.nonce.data(), extraNonce.nonce.size());
          }

          transactionExtraFields.push_back(extraNonce);
          break;
        }

        case TX_EXTRA_MERGE_MINING_TAG:
        {
          TransactionExtraMergeMiningTag mmTag;
          ar(mmTag, "mm_tag");
          transactionExtraFields.push_back(mmTag);
          break;
        }

        case TX_EXTRA_MESSAGE_TAG:
        {
          tx_extra_message message;
          ar(message.data, "message");
          transactionExtraFields.push_back(message);
          break;
        }

        case TX_EXTRA_TTL:
        {
          uint8_t size;
          readVarint(iss, size);
          TransactionExtraTTL ttl;
          readVarint(iss, ttl.ttl);
          transactionExtraFields.push_back(ttl);
          break;
        }

        case TX_EXTRA_PQ_MESSAGE_TAG:
        {
          // Read both length-prefixed sub-fields (kemCt, data) with the declared length BOUNDED
          // before allocation (review FIX 1: the generic serializeAsBinary/string readers resize to
          // the declared varint length first, so a huge prefix would force a multi-MB alloc on a
          // tiny tx). The parser has no default case, so an oversize/wrong-length field must be
          // rejected before it can over-read into following fields. data is the AEAD-sealed blob, so
          // it must be at least the 16-byte Poly1305 tag and at most the configured maximum; kemCt is
          // exactly the ML-KEM ciphertext size.
          const size_t kemBytes = ccx_pq_kem_ct_bytes();
          tx_extra_pq_message pqMessage;
          std::string kemBlob;
          if (!readBoundedExtraBlob(iss, extraSize, kemBytes, kemBlob) ||
              kemBlob.size() != kemBytes)
          {
            return false;
          }
          pqMessage.kemCt.assign(kemBlob.begin(), kemBlob.end());
          if (!readBoundedExtraBlob(iss, extraSize, TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE, pqMessage.data) ||
              pqMessage.data.size() < TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE)
          {
            return false;
          }
          transactionExtraFields.push_back(pqMessage);
          break;
        }

        case TX_EXTRA_AUTH_MESSAGE_TAG:
        {
          // Same bounded-before-allocation read as the 0x06 field (review FIX 1). data is the
          // AEAD-sealed blob (>= 16-byte Poly1305 tag, <= configured maximum).
          tx_extra_authenticated_message authMessage;
          if (!readBoundedExtraBlob(iss, extraSize, TX_EXTRA_AUTH_MESSAGE_MAX_DATA_SIZE, authMessage.data) ||
              authMessage.data.size() < TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE)
          {
            return false;
          }
          transactionExtraFields.push_back(authMessage);
          break;
        }
        }
      }
    }
    catch (std::exception &)
    {
      return false;
    }

    return true;
  }

  struct ExtraSerializerVisitor : public boost::static_visitor<bool>
  {
    std::vector<uint8_t> &extra;

    ExtraSerializerVisitor(std::vector<uint8_t> &tx_extra)
        : extra(tx_extra) {}

    bool operator()(const TransactionExtraPadding &t)
    {
      if (t.size > TX_EXTRA_PADDING_MAX_COUNT)
      {
        return false;
      }
      extra.insert(extra.end(), t.size, 0);
      return true;
    }

    bool operator()(const TransactionExtraPublicKey &t)
    {
      return addTransactionPublicKeyToExtra(extra, t.publicKey);
    }

    bool operator()(const TransactionExtraNonce &t)
    {
      return addExtraNonceToTransactionExtra(extra, t.nonce);
    }

    bool operator()(const TransactionExtraMergeMiningTag &t)
    {
      return appendMergeMiningTagToExtra(extra, t);
    }

    bool operator()(const tx_extra_message &t)
    {
      return append_message_to_extra(extra, t);
    }

    bool operator()(const TransactionExtraTTL &t)
    {
      appendTTLToExtra(extra, t.ttl);
      return true;
    }

    bool operator()(const tx_extra_pq_message &t)
    {
      return append_pq_message_to_extra(extra, t);
    }

    bool operator()(const tx_extra_authenticated_message &t)
    {
      return append_authenticated_message_to_extra(extra, t);
    }
  };

  bool writeTransactionExtra(std::vector<uint8_t> &tx_extra, const std::vector<TransactionExtraField> &tx_extra_fields)
  {
    ExtraSerializerVisitor visitor(tx_extra);

    for (const auto &tag : tx_extra_fields)
    {
      if (!boost::apply_visitor(visitor, tag))
      {
        return false;
      }
    }

    return true;
  }

  PublicKey getTransactionPublicKeyFromExtra(const std::vector<uint8_t> &tx_extra)
  {
    std::vector<TransactionExtraField> tx_extra_fields;
    parseTransactionExtra(tx_extra, tx_extra_fields);

    TransactionExtraPublicKey pub_key_field;
    if (!findTransactionExtraFieldByType(tx_extra_fields, pub_key_field))
      return boost::value_initialized<PublicKey>();

    return pub_key_field.publicKey;
  }

  bool addTransactionPublicKeyToExtra(std::vector<uint8_t> &tx_extra, const PublicKey &tx_pub_key)
  {
    tx_extra.resize(tx_extra.size() + 1 + sizeof(PublicKey));
    tx_extra[tx_extra.size() - 1 - sizeof(PublicKey)] = TX_EXTRA_TAG_PUBKEY;
    *reinterpret_cast<PublicKey *>(&tx_extra[tx_extra.size() - sizeof(PublicKey)]) = tx_pub_key;
    return true;
  }

  bool addExtraNonceToTransactionExtra(std::vector<uint8_t> &tx_extra, const BinaryArray &extra_nonce)
  {
    if (extra_nonce.size() > TX_EXTRA_NONCE_MAX_COUNT)
    {
      return false;
    }

    size_t start_pos = tx_extra.size();
    tx_extra.resize(tx_extra.size() + 2 + extra_nonce.size());
    //write tag
    tx_extra[start_pos] = TX_EXTRA_NONCE;
    //write len
    ++start_pos;
    tx_extra[start_pos] = static_cast<uint8_t>(extra_nonce.size());
    //write data
    ++start_pos;
    memcpy(&tx_extra[start_pos], extra_nonce.data(), extra_nonce.size());
    return true;
  }

  bool appendMergeMiningTagToExtra(std::vector<uint8_t> &tx_extra, const TransactionExtraMergeMiningTag &mm_tag)
  {
    BinaryArray blob;
    if (!toBinaryArray(mm_tag, blob))
    {
      return false;
    }

    tx_extra.push_back(TX_EXTRA_MERGE_MINING_TAG);
    std::copy(reinterpret_cast<const uint8_t *>(blob.data()), reinterpret_cast<const uint8_t *>(blob.data() + blob.size()), std::back_inserter(tx_extra));
    return true;
  }

  bool getMergeMiningTagFromExtra(const std::vector<uint8_t> &tx_extra, TransactionExtraMergeMiningTag &mm_tag)
  {
    std::vector<TransactionExtraField> tx_extra_fields;
    parseTransactionExtra(tx_extra, tx_extra_fields);

    return findTransactionExtraFieldByType(tx_extra_fields, mm_tag);
  }

  bool append_message_to_extra(std::vector<uint8_t> &tx_extra, const tx_extra_message &message)
  {
    BinaryArray blob;
    if (!toBinaryArray(message, blob))
    {
      return false;
    }

    tx_extra.reserve(tx_extra.size() + 1 + blob.size());
    tx_extra.push_back(TX_EXTRA_MESSAGE_TAG);
    std::copy(reinterpret_cast<const uint8_t *>(blob.data()), reinterpret_cast<const uint8_t *>(blob.data() + blob.size()), std::back_inserter(tx_extra));

    return true;
  }

  std::vector<std::string> get_messages_from_extra(const std::vector<uint8_t> &extra, const crypto::PublicKey &txkey, const crypto::SecretKey *recepient_secret_key)
  {
    std::vector<TransactionExtraField> tx_extra_fields;
    std::vector<std::string> result;
    if (!parseTransactionExtra(extra, tx_extra_fields))
    {
      return result;
    }
    size_t i = 0;
    for (const auto &f : tx_extra_fields)
    {
      if (f.type() != typeid(tx_extra_message))
      {
        continue;
      }
      std::string res;
      if (boost::get<tx_extra_message>(f).decrypt(i, txkey, recepient_secret_key, res))
      {
        result.push_back(res);
      }
      ++i;
    }
    return result;
  }

  bool append_pq_message_to_extra(std::vector<uint8_t> &tx_extra, const tx_extra_pq_message &message)
  {
    BinaryArray blob;
    if (!toBinaryArray(message, blob))
    {
      return false;
    }

    tx_extra.reserve(tx_extra.size() + 1 + blob.size());
    tx_extra.push_back(TX_EXTRA_PQ_MESSAGE_TAG);
    std::copy(reinterpret_cast<const uint8_t *>(blob.data()), reinterpret_cast<const uint8_t *>(blob.data() + blob.size()), std::back_inserter(tx_extra));

    return true;
  }

  std::vector<std::string> get_pq_messages_from_extra(const std::vector<uint8_t> &extra, const std::vector<uint8_t> &recipientKemSec)
  {
    std::vector<TransactionExtraField> tx_extra_fields;
    std::vector<std::string> result;
    if (!parseTransactionExtra(extra, tx_extra_fields))
    {
      return result;
    }
    size_t i = 0;
    for (const auto &f : tx_extra_fields)
    {
      if (f.type() != typeid(tx_extra_pq_message))
      {
        continue;
      }
      std::string res;
      if (boost::get<tx_extra_pq_message>(f).decrypt(i, recipientKemSec, res))
      {
        result.push_back(res);
      }
      ++i;
    }
    return result;
  }

  bool append_authenticated_message_to_extra(std::vector<uint8_t> &tx_extra, const tx_extra_authenticated_message &message)
  {
    BinaryArray blob;
    if (!toBinaryArray(message, blob))
    {
      return false;
    }

    tx_extra.reserve(tx_extra.size() + 1 + blob.size());
    tx_extra.push_back(TX_EXTRA_AUTH_MESSAGE_TAG);
    std::copy(reinterpret_cast<const uint8_t *>(blob.data()), reinterpret_cast<const uint8_t *>(blob.data() + blob.size()), std::back_inserter(tx_extra));

    return true;
  }

  std::vector<std::string> get_authenticated_messages_from_extra(const std::vector<uint8_t> &extra, const crypto::PublicKey &txkey, const crypto::SecretKey *recipientSecretKey)
  {
    std::vector<TransactionExtraField> tx_extra_fields;
    std::vector<std::string> result;
    if (!parseTransactionExtra(extra, tx_extra_fields))
    {
      return result;
    }
    size_t i = 0;
    for (const auto &f : tx_extra_fields)
    {
      if (f.type() != typeid(tx_extra_authenticated_message))
      {
        continue;
      }
      std::string res;
      if (boost::get<tx_extra_authenticated_message>(f).decrypt(i, txkey, recipientSecretKey, res))
      {
        result.push_back(res);
      }
      ++i;
    }
    return result;
  }

  void appendTTLToExtra(std::vector<uint8_t> &tx_extra, uint64_t ttl)
  {
    std::string ttlData = tools::get_varint_data(ttl);
    std::string extraFieldSize = tools::get_varint_data(ttlData.size());

    tx_extra.reserve(tx_extra.size() + 1 + extraFieldSize.size() + ttlData.size());
    tx_extra.push_back(TX_EXTRA_TTL);
    std::copy(extraFieldSize.begin(), extraFieldSize.end(), std::back_inserter(tx_extra));
    std::copy(ttlData.begin(), ttlData.end(), std::back_inserter(tx_extra));
  }

  void setPaymentIdToTransactionExtraNonce(std::vector<uint8_t> &extra_nonce, const Hash &payment_id)
  {
    extra_nonce.clear();
    extra_nonce.push_back(TX_EXTRA_NONCE_PAYMENT_ID);
    const uint8_t *payment_id_ptr = reinterpret_cast<const uint8_t *>(&payment_id);
    std::copy(payment_id_ptr, payment_id_ptr + sizeof(payment_id), std::back_inserter(extra_nonce));
  }

  bool getPaymentIdFromTransactionExtraNonce(const std::vector<uint8_t> &extra_nonce, Hash &payment_id)
  {
    if (sizeof(Hash) + 1 != extra_nonce.size())
      return false;
    if (TX_EXTRA_NONCE_PAYMENT_ID != extra_nonce[0])
      return false;
    payment_id = *reinterpret_cast<const Hash *>(extra_nonce.data() + 1);
    return true;
  }

  bool parsePaymentId(const std::string &paymentIdString, Hash &paymentId)
  {
    return common::podFromHex(paymentIdString, paymentId);
  }

  bool createTxExtraWithPaymentId(const std::string &paymentIdString, std::vector<uint8_t> &extra)
  {
    Hash paymentIdBin;

    if (!parsePaymentId(paymentIdString, paymentIdBin))
    {
      return false;
    }

    std::vector<uint8_t> extraNonce;
    cn::setPaymentIdToTransactionExtraNonce(extraNonce, paymentIdBin);

    if (!cn::addExtraNonceToTransactionExtra(extra, extraNonce))
    {
      return false;
    }

    return true;
  }

  bool getPaymentIdFromTxExtra(const std::vector<uint8_t> &extra, Hash &paymentId)
  {
    std::vector<TransactionExtraField> tx_extra_fields;
    if (!parseTransactionExtra(extra, tx_extra_fields))
    {
      return false;
    }

    TransactionExtraNonce extra_nonce;
    if (findTransactionExtraFieldByType(tx_extra_fields, extra_nonce))
    {
      if (!getPaymentIdFromTransactionExtraNonce(extra_nonce.nonce, paymentId))
      {
        return false;
      }
    }
    else
    {
      return false;
    }

    return true;
  }

  bool addPaymentIdToExtra(const std::string &paymentId, std::string &extra) {
    std::vector<uint8_t> extraVector;
    if (!createTxExtraWithPaymentId(paymentId, extraVector)) {
      return false;
    }
    std::copy(extraVector.begin(), extraVector.end(), std::back_inserter(extra));
    return true;
  }

#define TX_EXTRA_MESSAGE_CHECKSUM_SIZE 4

#pragma pack(push, 1)
  struct message_key_data
  {
    KeyDerivation derivation;
    uint8_t magic1, magic2;
  };
#pragma pack(pop)
  static_assert(sizeof(message_key_data) == 34, "Invalid structure size");

  bool tx_extra_message::encrypt(size_t index, const std::string &message, const AccountPublicAddress *recipient, const KeyPair &txkey)
  {
    size_t mlen = message.size();
    std::unique_ptr<char[]> buf(new char[mlen + TX_EXTRA_MESSAGE_CHECKSUM_SIZE]);
    memcpy(buf.get(), message.data(), mlen);
    memset(buf.get() + mlen, 0, TX_EXTRA_MESSAGE_CHECKSUM_SIZE);
    mlen += TX_EXTRA_MESSAGE_CHECKSUM_SIZE;
    if (recipient)
    {
      message_key_data key_data;
      if (!generate_key_derivation(recipient->spendPublicKey, txkey.secretKey, key_data.derivation))
      {
        return false;
      }
      key_data.magic1 = 0x80;
      key_data.magic2 = 0;
      Hash h = cn_fast_hash(&key_data, sizeof(message_key_data));
      uint64_t nonce = SWAP64LE(index);
      chacha8(buf.get(), mlen, reinterpret_cast<uint8_t *>(&h), reinterpret_cast<uint8_t *>(&nonce), buf.get());
    }
    data.assign(buf.get(), mlen);
    return true;
  }

  bool tx_extra_message::decrypt(size_t index, const crypto::PublicKey &txkey, const crypto::SecretKey *recepient_secret_key, std::string &message) const
  {
    size_t mlen = data.size();
    if (mlen < TX_EXTRA_MESSAGE_CHECKSUM_SIZE)
    {
      return false;
    }
    const char *buf;
    std::unique_ptr<char[]> ptr;
    if (recepient_secret_key != nullptr)
    {
      ptr.reset(new char[mlen]);
      assert(ptr);
      message_key_data key_data;
      if (!generate_key_derivation(txkey, *recepient_secret_key, key_data.derivation))
      {
        return false;
      }
      key_data.magic1 = 0x80;
      key_data.magic2 = 0;
      Hash h = cn_fast_hash(&key_data, sizeof(message_key_data));
      uint64_t nonce = SWAP64LE(index);
      chacha8(data.data(), mlen, reinterpret_cast<uint8_t *>(&h), reinterpret_cast<uint8_t *>(&nonce), ptr.get());
      buf = ptr.get();
    }
    else
    {
      buf = data.data();
    }
    mlen -= TX_EXTRA_MESSAGE_CHECKSUM_SIZE;
    for (size_t i = 0; i < TX_EXTRA_MESSAGE_CHECKSUM_SIZE; i++)
    {
      if (buf[mlen + i] != 0)
      {
        return false;
      }
    }
    message.assign(buf, mlen);
    return true;
  }

  bool tx_extra_message::serialize(ISerializer &s)
  {
    s(data, "data");
    return true;
  }

  // ML-KEM-768 message field (tx-extra 0x06) ----------------------------------------------------
  // The KEM derives a 32-byte seed (ccx_pq_msg_kem_encap/decap, domain "ccx-msg-kem-v1"); the seed
  // and the per-message index then key a ChaCha20-Poly1305 AEAD (ccx_pq_msg_seal/open, which derive
  // a 32-byte key + 12-byte nonce via SHAKE256 "ccx-msg-aead-v1"). This is REAL authenticated
  // encryption: tampering ANY byte of the sealed ciphertext (incl. the Poly1305 tag) makes open()
  // fail, unlike the legacy 0x04 chacha8 + 4-zero-byte owner-test (which has no MAC and is left
  // untouched). `data` carries the sealed ciphertext (plaintext_len + 16-byte tag).
  bool tx_extra_pq_message::encrypt(size_t index, const std::string &message, const std::vector<uint8_t> &recipientKemPub)
  {
    if (recipientKemPub.size() != ccx_pq_kem_pubkey_bytes())
    {
      return false;
    }

    kemCt.assign(ccx_pq_kem_ct_bytes(), 0);
    uint8_t seed[32];
    if (ccx_pq_msg_kem_encap(recipientKemPub.data(), recipientKemPub.size(),
                             kemCt.data(), kemCt.size(), seed, sizeof(seed)) != 0)
    {
      kemCt.clear();
      return false;
    }

    std::vector<uint8_t> sealed(message.size() + TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE, 0);
    size_t sealedLen = 0;
    int rc = ccx_pq_msg_seal(seed, sizeof(seed), static_cast<uint64_t>(index),
                             reinterpret_cast<const uint8_t *>(message.data()), message.size(),
                             sealed.data(), sealed.size(), &sealedLen);
    if (rc != 0 || sealedLen != sealed.size())
    {
      kemCt.clear();
      return false;
    }

    data.assign(reinterpret_cast<const char *>(sealed.data()), sealedLen);
    return true;
  }

  bool tx_extra_pq_message::decrypt(size_t index, const std::vector<uint8_t> &recipientKemSec, std::string &message) const
  {
    if (data.size() < TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE)
    {
      return false;
    }
    if (kemCt.size() != ccx_pq_kem_ct_bytes() || recipientKemSec.size() != ccx_pq_kem_seckey_bytes())
    {
      return false;
    }

    uint8_t seed[32];
    if (ccx_pq_msg_kem_decap(recipientKemSec.data(), recipientKemSec.size(),
                             kemCt.data(), kemCt.size(), seed, sizeof(seed)) != 0)
    {
      return false;
    }

    std::vector<uint8_t> plain(data.size() - TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE, 0);
    size_t plainLen = 0;
    int rc = ccx_pq_msg_open(seed, sizeof(seed), static_cast<uint64_t>(index),
                             reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                             plain.data(), plain.size(), &plainLen);
    // open() returns non-zero (and writes nothing) on auth failure / wrong recipient.
    if (rc != 0 || plainLen != plain.size())
    {
      return false;
    }

    message.assign(reinterpret_cast<const char *>(plain.data()), plainLen);
    return true;
  }

  bool tx_extra_pq_message::serialize(ISerializer &s)
  {
    serializeAsBinary(kemCt, "kem", s);
    s(data, "data");
    return true;
  }

  // Authenticated classical message field (tx-extra 0x07) -----------------------------------------
  // Key agreement reuses the same Curve25519 ECDH as the legacy 0x04 message (between the tx secret
  // key and the recipient spend public key), BUT the seed is DOMAIN-SEPARATED from 0x04: the
  // message_key_data magic bytes are (0x80, TX_EXTRA_AUTH_MESSAGE_TAG) here vs (0x80, 0x00) for 0x04,
  // so a 0x04 and a 0x07 to the SAME recipient + index can never derive the same seed/keystream
  // (review FIX 3). The symmetric layer is also upgraded: instead of the unauthenticated chacha8 +
  // 4-zero-byte owner-check, the payload is sealed with the existing ChaCha20-Poly1305 AEAD
  // (ccx_pq_msg_seal/open, key+nonce derived from (seed, index)). This is REAL authenticated
  // encryption — tampering ANY byte of the sealed blob (including the 16-byte Poly1305 tag) makes
  // open() fail, and a wrong recipient derives a different seed and also fails. `data` carries the
  // sealed ciphertext (plaintext_len + 16-byte tag). The legacy 0x04 field is frozen to decrypt-only;
  // new authenticated messages use 0x07.
  //
  // Nonce note: the AEAD nonce is bound to (seed, index); seed uniqueness rests on the protocol's
  // existing per-tx-key uniqueness invariant (identical posture to legacy 0x04). Binding the tx
  // prefix hash as AEAD AAD would harden this further but needs an FFI param change — see
  // docs/reviews/tier1/serializer-review-response.md.
  bool tx_extra_authenticated_message::encrypt(size_t index, const std::string &message, const AccountPublicAddress *recipient, const KeyPair &txkey)
  {
    if (recipient == nullptr)
    {
      return false;
    }

    message_key_data key_data;
    if (!generate_key_derivation(recipient->spendPublicKey, txkey.secretKey, key_data.derivation))
    {
      return false;
    }
    key_data.magic1 = 0x80;
    key_data.magic2 = TX_EXTRA_AUTH_MESSAGE_TAG; // domain separation from legacy 0x04 (magic2 == 0)
    Hash seedHash = cn_fast_hash(&key_data, sizeof(message_key_data));

    std::vector<uint8_t> sealed(message.size() + TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE, 0);
    size_t sealedLen = 0;
    int rc = ccx_pq_msg_seal(reinterpret_cast<const uint8_t *>(&seedHash), sizeof(seedHash),
                             static_cast<uint64_t>(index),
                             reinterpret_cast<const uint8_t *>(message.data()), message.size(),
                             sealed.data(), sealed.size(), &sealedLen);
    if (rc != 0 || sealedLen != sealed.size())
    {
      return false;
    }

    data.assign(reinterpret_cast<const char *>(sealed.data()), sealedLen);
    return true;
  }

  bool tx_extra_authenticated_message::decrypt(size_t index, const crypto::PublicKey &txkey, const crypto::SecretKey *recipientSecretKey, std::string &message) const
  {
    if (recipientSecretKey == nullptr)
    {
      return false;
    }
    if (data.size() < TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE)
    {
      return false;
    }

    message_key_data key_data;
    if (!generate_key_derivation(txkey, *recipientSecretKey, key_data.derivation))
    {
      return false;
    }
    key_data.magic1 = 0x80;
    key_data.magic2 = TX_EXTRA_AUTH_MESSAGE_TAG; // domain separation from legacy 0x04 (magic2 == 0)
    Hash seedHash = cn_fast_hash(&key_data, sizeof(message_key_data));

    std::vector<uint8_t> plain(data.size() - TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE, 0);
    size_t plainLen = 0;
    int rc = ccx_pq_msg_open(reinterpret_cast<const uint8_t *>(&seedHash), sizeof(seedHash),
                             static_cast<uint64_t>(index),
                             reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                             plain.data(), plain.size(), &plainLen);
    // open() returns non-zero (and writes nothing) on auth failure / wrong recipient.
    if (rc != 0 || plainLen != plain.size())
    {
      return false;
    }

    message.assign(reinterpret_cast<const char *>(plain.data()), plainLen);
    return true;
  }

  bool tx_extra_authenticated_message::serialize(ISerializer &s)
  {
    s(data, "data");
    return true;
  }

} // namespace cn