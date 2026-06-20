// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <algorithm>
#include <string>
#include <vector>
#include <boost/variant.hpp>

#include <CryptoNote.h>

#define TX_EXTRA_PADDING_MAX_COUNT          255
#define TX_EXTRA_NONCE_MAX_COUNT            255

#define TX_EXTRA_TAG_PADDING                0x00
#define TX_EXTRA_TAG_PUBKEY                 0x01
#define TX_EXTRA_NONCE                      0x02
#define TX_EXTRA_MERGE_MINING_TAG           0x03
#define TX_EXTRA_MESSAGE_TAG                0x04
#define TX_EXTRA_TTL                        0x05
#define TX_EXTRA_PQ_MESSAGE_TAG             0x06
#define TX_EXTRA_AUTH_MESSAGE_TAG           0x07

#define TX_EXTRA_NONCE_PAYMENT_ID           0x00

// ChaCha20-Poly1305 authentication tag length appended to the PQ message ciphertext (data carries
// sealed = plaintext || 16-byte Poly1305 tag).
#define TX_EXTRA_PQ_MESSAGE_AEAD_TAG_SIZE   16
// Upper bound on the sealed ciphertext (data) carried in a PQ message field (defense-in-depth: the
// extra parser has no default case, so an oversize length must be rejected early — see R1/R4). This
// bounds the AEAD-sealed blob, i.e. plaintext length + 16-byte tag.
#define TX_EXTRA_PQ_MESSAGE_MAX_DATA_SIZE   8192

// Authenticated classical message field (tag 0x07): same ChaCha20-Poly1305 AEAD as the 0x06 PQ
// message (16-byte Poly1305 tag, same sealed-blob bound), but the 32-byte AEAD seed is derived from
// a classical Curve25519 ECDH derivation instead of an ML-KEM decapsulation. Bounds mirror the PQ
// field so the same early-reject guard protects the no-default-case parser.
#define TX_EXTRA_AUTH_MESSAGE_AEAD_TAG_SIZE 16
#define TX_EXTRA_AUTH_MESSAGE_MAX_DATA_SIZE 8192

namespace cn {

class ISerializer;

struct TransactionExtraPadding {
  size_t size;
};

struct TransactionExtraPublicKey {
  crypto::PublicKey publicKey;
};

struct TransactionExtraNonce {
  std::vector<uint8_t> nonce;
};

struct TransactionExtraMergeMiningTag {
  size_t depth;
  crypto::Hash merkleRoot;
};

struct tx_extra_message {
  std::string data;

  bool encrypt(std::size_t index, const std::string &message, const AccountPublicAddress* recipient, const KeyPair &txkey);
  bool decrypt(std::size_t index, const crypto::PublicKey &txkey, const crypto::SecretKey *recepient_secret_key, std::string &message) const;

  bool serialize(ISerializer& serializer);
};

struct TransactionExtraTTL {
  uint64_t ttl;
};

// Post-quantum encrypted message (tx-extra tag 0x06). Additive sibling of tx_extra_message: the
// symmetric layer is upgraded to ChaCha20-Poly1305 AEAD, and the 32-byte AEAD seed is derived from
// an ML-KEM-768 shared secret instead of Curve25519 ECDH. The Kyber ciphertext (kemCt, 1088 B) is
// self-contained, so decryption needs only the recipient's KEM secret — no tx public key. See
// docs/design/quantum-resistance/messages-mlkem.md.
struct tx_extra_pq_message {
  std::vector<uint8_t> kemCt;   // ML-KEM-768 ciphertext (1088 B)
  std::string data;             // ChaCha20-Poly1305 sealed blob = plaintext || 16-byte Poly1305 tag

  bool encrypt(std::size_t index, const std::string& message, const std::vector<uint8_t>& recipientKemPub);
  bool decrypt(std::size_t index, const std::vector<uint8_t>& recipientKemSec, std::string& message) const;

  bool serialize(ISerializer& serializer);
};

// Authenticated classical message (tx-extra tag 0x07). Reuses the SAME Curve25519 ECDH key agreement
// as the legacy 0x04 message, but seals the payload with the same ChaCha20-Poly1305 AEAD
// (ccx_pq_msg_seal/open) instead, so tampering ANY byte is detected. No KEM ciphertext is carried:
// like 0x04, the recipient re-derives the seed from the tx public key + their secret. 0x04 is frozen
// to decrypt-only; new authenticated messages use 0x07.
struct tx_extra_authenticated_message {
  std::string data;             // ChaCha20-Poly1305 sealed blob = plaintext || 16-byte Poly1305 tag

  // ECDH seed = cn_fast_hash(generate_key_derivation(recipient->spendPublicKey, txkey.secretKey) || 0x80 || 0x07).
  bool encrypt(std::size_t index, const std::string& message, const AccountPublicAddress* recipient, const KeyPair& txkey);
  bool decrypt(std::size_t index, const crypto::PublicKey& txkey, const crypto::SecretKey* recipientSecretKey, std::string& message) const;

  bool serialize(ISerializer& serializer);
};

// tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
//   varint tag;
//   varint size;
//   varint data[];
typedef boost::variant<TransactionExtraPadding, TransactionExtraPublicKey, TransactionExtraNonce, TransactionExtraMergeMiningTag, tx_extra_message, TransactionExtraTTL, tx_extra_pq_message, tx_extra_authenticated_message> TransactionExtraField;



template<typename T>
bool findTransactionExtraFieldByType(const std::vector<TransactionExtraField>& tx_extra_fields, T& field) {
  auto it = std::find_if(tx_extra_fields.begin(), tx_extra_fields.end(),
    [](const TransactionExtraField& f) { return typeid(T) == f.type(); });

  if (tx_extra_fields.end() == it)
    return false;

  field = boost::get<T>(*it);
  return true;
}

bool parseTransactionExtra(const std::vector<uint8_t>& tx_extra, std::vector<TransactionExtraField>& tx_extra_fields);
bool writeTransactionExtra(std::vector<uint8_t>& tx_extra, const std::vector<TransactionExtraField>& tx_extra_fields);

crypto::PublicKey getTransactionPublicKeyFromExtra(const std::vector<uint8_t>& tx_extra);
bool addTransactionPublicKeyToExtra(std::vector<uint8_t>& tx_extra, const crypto::PublicKey& tx_pub_key);
bool addExtraNonceToTransactionExtra(std::vector<uint8_t>& tx_extra, const BinaryArray& extra_nonce);
void setPaymentIdToTransactionExtraNonce(BinaryArray& extra_nonce, const crypto::Hash& payment_id);
bool getPaymentIdFromTransactionExtraNonce(const BinaryArray& extra_nonce, crypto::Hash& payment_id);
bool appendMergeMiningTagToExtra(std::vector<uint8_t>& tx_extra, const TransactionExtraMergeMiningTag& mm_tag);
bool append_message_to_extra(std::vector<uint8_t>& tx_extra, const tx_extra_message& message);
std::vector<std::string> get_messages_from_extra(const std::vector<uint8_t>& extra, const crypto::PublicKey &txkey, const crypto::SecretKey *recepient_secret_key);
bool append_pq_message_to_extra(std::vector<uint8_t>& tx_extra, const tx_extra_pq_message& message);
std::vector<std::string> get_pq_messages_from_extra(const std::vector<uint8_t>& extra, const std::vector<uint8_t>& recipientKemSec);
bool append_authenticated_message_to_extra(std::vector<uint8_t>& tx_extra, const tx_extra_authenticated_message& message);
std::vector<std::string> get_authenticated_messages_from_extra(const std::vector<uint8_t>& extra, const crypto::PublicKey& txkey, const crypto::SecretKey* recipientSecretKey);
void appendTTLToExtra(std::vector<uint8_t>& tx_extra, uint64_t ttl);
bool getMergeMiningTagFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraMergeMiningTag& mm_tag);

bool createTxExtraWithPaymentId(const std::string& paymentIdString, std::vector<uint8_t>& extra);
//returns false if payment id is not found or parse error
bool getPaymentIdFromTxExtra(const std::vector<uint8_t>& extra, crypto::Hash& paymentId);
bool parsePaymentId(const std::string& paymentIdString, crypto::Hash& paymentId);
bool addPaymentIdToExtra(const std::string &paymentId, std::string &extra);

}
