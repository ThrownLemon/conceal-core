// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "Common/StringTools.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"


namespace cn {
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  template<class t_array>
  struct array_hasher: std::unary_function<t_array&, size_t>
  {
    size_t operator()(const t_array& val) const
    {
      return boost::hash_range(&val.data[0], &val.data[sizeof(val.data)]);
    }
  };

  /************************************************************************/
  /* cn helper functions                                          */
  /************************************************************************/
  uint64_t getPenalizedAmount(uint64_t amount, size_t medianSize, size_t currentBlockSize);
  std::string getAccountAddressAsStr(uint64_t prefix, const AccountPublicAddress& adr);
  bool parseAccountAddressString(uint64_t& prefix, AccountPublicAddress& adr, const std::string& str);
  std::string getPqAccountAddressAsStr(uint64_t prefix, const PqAccountPublicAddress& adr); // CIP-0001 PQ address v2
  bool parsePqAccountAddressString(uint64_t& prefix, PqAccountPublicAddress& adr, const std::string& str);

  // Resolve the recipient ML-KEM public key for an ENCRYPTED on-chain message so the send path can
  // DEFAULT to the post-quantum 0x06 field (true PQ confidentiality) instead of the classical 0x07
  // (Curve25519 ECDH, Shor-breakable). Conceal's encrypted messages are permanent and on-chain, so a
  // message recorded today is a harvest-now-decrypt-later target the moment a CRQC exists; preferring
  // 0x06 closes that. Resolution order (CIP wallet-address-v2 / messages-mlkem step 4):
  //   (a) the message's recipient address parses as a PQ/hybrid address -> use its kemPublicKey;
  //   (b) else on testnet, use the fixed PQ_TESTNET_KEM_PK (Option-B bootstrap) so testnet permanent
  //       messages are PQ-encrypted by default;
  //   (c) else (mainnet, no PQ key for the recipient) -> return false; the caller falls back to the
  //       authenticated classical 0x07 field.
  // Returns true and fills kemPub for (a)/(b); returns false for (c). Does not throw.
  bool resolveMessageRecipientKemPub(const std::string& recipientAddress, bool testnet,
                                     std::vector<uint8_t>& kemPub);
  bool is_coinbase(const Transaction& tx);

  bool operator ==(const cn::Transaction& a, const cn::Transaction& b);
  bool operator ==(const cn::Block& a, const cn::Block& b);
}

template <class T>
std::ostream &print256(std::ostream &o, const T &v) {
  return o << "<" << common::podToHex(v) << ">";
}

bool parse_hash256(const std::string& str_hash, crypto::Hash& hash);

namespace crypto {
  inline std::ostream &operator <<(std::ostream &o, const crypto::PublicKey &v) { return print256(o, v); }
  inline std::ostream &operator <<(std::ostream &o, const crypto::SecretKey &v) { return print256(o, v); }
  inline std::ostream &operator <<(std::ostream &o, const crypto::KeyDerivation &v) { return print256(o, v); }
  inline std::ostream &operator <<(std::ostream &o, const crypto::KeyImage &v) { return print256(o, v); }
  inline std::ostream &operator <<(std::ostream &o, const crypto::Signature &v) { return print256(o, v); }
  inline std::ostream &operator <<(std::ostream &o, const crypto::Hash &v) { return print256(o, v); }
}
