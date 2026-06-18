// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletKdf.h"

#include <cstring>
#include <stdexcept>

#include "crypto/randomize.h"

extern "C"
{
#include "pq_ring_sig.h"
}

namespace cn
{
  namespace
  {
    const uint8_t WALLET_KDF_MAGIC[4] = {'C', 'K', 'D', 'F'};
  }

  bool WalletKdf::isValidHeader(const WalletKdfHeader &header)
  {
    return std::memcmp(header.magic, WALLET_KDF_MAGIC, sizeof(WALLET_KDF_MAGIC)) == 0 &&
           header.kdfVersion == WALLET_KDF_VERSION_ARGON2ID;
  }

  WalletKdfHeader WalletKdf::makeHeader()
  {
    WalletKdfHeader header;
    std::memset(&header, 0, sizeof(header));
    std::memcpy(header.magic, WALLET_KDF_MAGIC, sizeof(WALLET_KDF_MAGIC));
    header.kdfVersion = WALLET_KDF_VERSION_ARGON2ID;
    Randomize::randomBytes(sizeof(header.salt), header.salt);
    header.memKib = WALLET_KDF_DEFAULT_MEM_KIB;
    header.iterations = WALLET_KDF_DEFAULT_ITERATIONS;
    header.parallelism = WALLET_KDF_DEFAULT_PARALLELISM;
    return header;
  }

  crypto::chacha8_key WalletKdf::deriveKey(const std::string &password, const WalletKdfHeader &header)
  {
    if (!isValidHeader(header))
    {
      throw std::runtime_error("WalletKdf: invalid/unsupported KDF header");
    }

    crypto::chacha8_key key;
    static_assert(sizeof(key.data) == 32, "chacha8_key must be 32 bytes for the wallet AEAD key");

    const int32_t rc = ccx_wallet_kdf_argon2id(
        reinterpret_cast<const uint8_t *>(password.data()), password.size(),
        header.salt, sizeof(header.salt),
        header.memKib, header.iterations, header.parallelism,
        key.data, sizeof(key.data));
    if (rc != 0)
    {
      throw std::runtime_error("WalletKdf: Argon2id key derivation failed (rc=" + std::to_string(rc) + ")");
    }
    return key;
  }

  size_t WalletKdf::nonceBytes()
  {
    return ccx_wallet_nonce_bytes();
  }

  size_t WalletKdf::tagBytes()
  {
    return ccx_wallet_aead_tag_bytes();
  }

  std::vector<uint8_t> WalletKdf::aeadSeal(const crypto::chacha8_key &key,
                                           const std::vector<uint8_t> &nonce,
                                           const uint8_t *plaintext, size_t plaintextSize)
  {
    const size_t tag = tagBytes();
    std::vector<uint8_t> sealed(plaintextSize + tag);
    size_t sealedLen = sealed.size();

    const int32_t rc = ccx_wallet_aead_seal(
        key.data, sizeof(key.data),
        nonce.data(), nonce.size(),
        plaintext, plaintextSize,
        sealed.data(), sealed.size(), &sealedLen);
    if (rc != 0 || sealedLen != sealed.size())
    {
      throw std::runtime_error("WalletKdf: AEAD seal failed (rc=" + std::to_string(rc) + ")");
    }
    return sealed;
  }

  bool WalletKdf::aeadOpen(const crypto::chacha8_key &key,
                           const std::vector<uint8_t> &nonce,
                           const uint8_t *sealed, size_t sealedSize,
                           std::vector<uint8_t> &plaintext)
  {
    const size_t tag = tagBytes();
    if (sealedSize < tag)
    {
      return false;
    }
    plaintext.resize(sealedSize - tag);
    size_t plainLen = plaintext.size();

    const int32_t rc = ccx_wallet_aead_open(
        key.data, sizeof(key.data),
        nonce.data(), nonce.size(),
        sealed, sealedSize,
        plaintext.empty() ? nullptr : plaintext.data(), plaintext.size(), &plainLen);
    if (rc != 0)
    {
      // Authentication failure: do not expose any (unauthenticated) plaintext bytes.
      plaintext.clear();
      return false;
    }
    plaintext.resize(plainLen);
    return true;
  }

  std::vector<uint8_t> WalletKdf::randomNonce()
  {
    return Randomize::randomBytes(nonceBytes());
  }
} // namespace cn
