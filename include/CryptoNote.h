// Copyright (c) 2012-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <vector>
#include <boost/variant.hpp>
#include "CryptoTypes.h"
#include "CryptoNoteCore/NewOutputTypes.h"

namespace cn {

struct BaseInput {
  uint32_t blockIndex;
};

struct KeyInput {
  uint64_t amount;
  std::vector<uint32_t> outputIndexes;
  crypto::KeyImage keyImage;
};

struct MultisignatureInput {
  uint64_t amount;
  uint8_t signatureCount;
  uint32_t outputIndex;
  uint32_t term;
};

struct KeyOutput {
  crypto::PublicKey key;
};

struct MultisignatureOutput {
  std::vector<crypto::PublicKey> keys;
  uint8_t requiredSignatureCount;
  uint32_t term;
};

struct PqKeyInput {
  uint64_t amount;
  std::vector<uint32_t> outputIndexes;
  std::vector<uint8_t> nullifier;   // PQ serial number / key-image equivalent
  std::vector<uint8_t> ringSig;     // PQ linkable ring signature (one proof per input)
};

struct PqKeyOutput {
  std::vector<uint8_t> key;         // PQ one-time public key (variable length)
  std::vector<uint8_t> kemCt;       // ML-KEM ciphertext (stealth shared secret)
};

// Post-quantum deposit cell (CIP-0001 UPGRADE_HEIGHT_V10 on this merged tree). A faithful PQ analogue
// of the legacy Ed25519 MultisignatureInput/Output pair: term/interest/lock/double-spend semantics are
// IDENTICAL; only the signature primitive is swapped to ML-DSA-65 (FIPS 204). The m ML-DSA signatures
// are carried INLINE (not in tx.signatures) — getSignaturesCount(PqMultisigInput) == 0 — because an
// ML-DSA sig (~3.3 KB) cannot live in the fixed-size crypto::Signature (64 B) slots.
struct PqMultisigInput {
  uint64_t amount;
  uint8_t signatureCount;                          // == output.requiredSignatureCount (m)
  uint32_t outputIndex;                            // index into m_pqMultisigOutputs[amount]
  uint32_t term;                                   // bound to output.term (interest + lock)
  std::vector<std::vector<uint8_t>> signatures;    // m ML-DSA-65 detached sigs over the prefix hash
};

struct PqMultisigOutput {
  uint32_t dsaSchemeId = 0;                    // = PQ_DSA_SCHEME_ID; serialized agility pin for deposit verifier
  std::vector<std::vector<uint8_t>> keys;          // n ML-DSA-65 public keys (each ccx_pq_multisig_pubkey_bytes())
  uint8_t requiredSignatureCount;                  // m
  uint32_t term;                                   // 0 = plain PQ multisig; != 0 = deposit
};

typedef boost::variant<BaseInput, KeyInput, MultisignatureInput, PqKeyInput, PqMultisigInput> TransactionInput;

// PQ outputs are appended AFTER the fork's domain outputs so the fork's existing
// boost::variant which() indices stay stable; binary tags are explicit (0x08/0x09).
typedef boost::variant<KeyOutput, MultisignatureOutput,
                       StandardPaymentOutput, MultisigPaymentOutput,
                       DomainRegistrationOutput, DomainDeletionOutput,
                       PqKeyOutput, PqMultisigOutput> TransactionOutputTarget;

struct TransactionOutput {
  uint64_t amount;
  TransactionOutputTarget target;
};

using TransactionInputs = std::vector<TransactionInput>;

struct TransactionPrefix {
  uint8_t version;
  uint64_t unlockTime;
  TransactionInputs inputs;
  std::vector<TransactionOutput> outputs;
  std::vector<uint8_t> extra;
};

struct Transaction : public TransactionPrefix {
  std::vector<std::vector<crypto::Signature>> signatures;
};

struct BlockHeader {
  uint8_t majorVersion;
  uint8_t minorVersion;
  uint32_t nonce;
  uint64_t timestamp;
  crypto::Hash previousBlockHash;
};

struct Block : public BlockHeader {
  Transaction baseTransaction;
  std::vector<crypto::Hash> transactionHashes;
};

struct AccountPublicAddress {
  crypto::PublicKey spendPublicKey;
  crypto::PublicKey viewPublicKey;
};

// Post-quantum wallet address v2 (CIP-0001). Carries an ML-KEM-768 public key + agility-pinned
// scheme ids; hybrid mode also retains the legacy Ed25519 keys.
struct PqAccountPublicAddress {
  uint8_t  pqVersion;                       // = PQ_ADDRESS_VERSION (2)
  uint8_t  flags;                           // bit0: hybrid; other bits reserved (must be 0)
  uint32_t kemSchemeId;                      // pinned ML-KEM scheme id (agility)
  uint32_t ringSchemeId;                     // pinned ring-sig scheme id (agility)
  std::vector<uint8_t> kemPublicKey;         // ML-KEM-768 public key (PQ_KEM_PUBLIC_KEY_SIZE bytes)
  crypto::PublicKey legacySpendPublicKey;    // hybrid only (flags bit0); zero otherwise
  crypto::PublicKey legacyViewPublicKey;     // hybrid only (flags bit0); zero otherwise
};

struct AccountKeys {
  AccountPublicAddress address;
  crypto::SecretKey spendSecretKey;
  crypto::SecretKey viewSecretKey;
};

struct KeyPair {
  crypto::PublicKey publicKey;
  crypto::SecretKey secretKey;
};

using BinaryArray = std::vector<uint8_t>;

}
