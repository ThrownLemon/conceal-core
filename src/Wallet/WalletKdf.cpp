// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletKdf.h"

#include <cstring>
#include <stdexcept>

extern "C"
{
#include "pq_ring_sig.h"
}

namespace cn
{
  namespace
  {
    const uint8_t WALLET_KDF_MAGIC[4] = {'C', 'K', 'D', 'F'};

    // Canonical little-endian pack/unpack for the cost fields (endian-independent on-disk format).
    void putLe32(uint8_t out[4], uint32_t v)
    {
      out[0] = static_cast<uint8_t>(v & 0xff);
      out[1] = static_cast<uint8_t>((v >> 8) & 0xff);
      out[2] = static_cast<uint8_t>((v >> 16) & 0xff);
      out[3] = static_cast<uint8_t>((v >> 24) & 0xff);
    }

    uint32_t getLe32(const uint8_t in[4])
    {
      return static_cast<uint32_t>(in[0]) |
             (static_cast<uint32_t>(in[1]) << 8) |
             (static_cast<uint32_t>(in[2]) << 16) |
             (static_cast<uint32_t>(in[3]) << 24);
    }

    // CSPRNG fill via the ccx-pqc OS-entropy FFI. Throws on failure — the wallet must NEVER fall back
    // to a weak RNG for salt/nonce material (that would risk salt+nonce collisions across wallets).
    void csprngBytes(uint8_t *out, size_t len)
    {
      const int32_t rc = ccx_wallet_random_bytes(out, len);
      if (rc != 0)
      {
        throw std::runtime_error("WalletKdf: CSPRNG (ccx_wallet_random_bytes) failed (rc=" + std::to_string(rc) + ")");
      }
    }

    bool costInBounds(uint32_t memKib, uint32_t iterations, uint32_t parallelism)
    {
      if (memKib < WALLET_KDF_MIN_MEM_KIB || memKib > WALLET_KDF_MAX_MEM_KIB)
      {
        return false;
      }
      if (iterations < WALLET_KDF_MIN_ITERATIONS || iterations > WALLET_KDF_MAX_ITERATIONS)
      {
        return false;
      }
      if (parallelism < WALLET_KDF_MIN_PARALLELISM || parallelism > WALLET_KDF_MAX_PARALLELISM)
      {
        return false;
      }
      // Argon2 requires memKib >= 8 * parallelism; our floors already guarantee this, but be explicit.
      if (memKib < 8u * parallelism)
      {
        return false;
      }
      return true;
    }
  }

  uint32_t WalletKdf::memKib(const WalletKdfHeader &header) { return getLe32(header.memKibLe); }
  uint32_t WalletKdf::iterations(const WalletKdfHeader &header) { return getLe32(header.iterationsLe); }
  uint32_t WalletKdf::parallelism(const WalletKdfHeader &header) { return getLe32(header.parallelismLe); }

  bool WalletKdf::isValidHeader(const WalletKdfHeader &header)
  {
    if (std::memcmp(header.magic, WALLET_KDF_MAGIC, sizeof(WALLET_KDF_MAGIC)) != 0 ||
        header.kdfVersion != WALLET_KDF_VERSION_ARGON2ID)
    {
      return false;
    }
    // Reject out-of-range cost params (a hostile/corrupt on-disk header could otherwise DoS-on-open
    // or near-disable the KDF). Validated here so EVERY consumer (parse + derive) is protected.
    return costInBounds(getLe32(header.memKibLe), getLe32(header.iterationsLe), getLe32(header.parallelismLe));
  }

  WalletKdfHeader WalletKdf::makeHeader()
  {
    WalletKdfHeader header;
    std::memset(&header, 0, sizeof(header));
    std::memcpy(header.magic, WALLET_KDF_MAGIC, sizeof(WALLET_KDF_MAGIC));
    header.kdfVersion = WALLET_KDF_VERSION_ARGON2ID;
    csprngBytes(header.salt, sizeof(header.salt)); // CSPRNG salt (NOT mt19937)
    putLe32(header.memKibLe, WALLET_KDF_DEFAULT_MEM_KIB);
    putLe32(header.iterationsLe, WALLET_KDF_DEFAULT_ITERATIONS);
    putLe32(header.parallelismLe, WALLET_KDF_DEFAULT_PARALLELISM);
    return header;
  }

  crypto::chacha8_key WalletKdf::deriveKey(const std::string &password, const WalletKdfHeader &header)
  {
    if (!isValidHeader(header))
    {
      throw std::runtime_error("WalletKdf: invalid/unsupported/out-of-range KDF header");
    }

    crypto::chacha8_key key;
    static_assert(sizeof(key.data) == 32, "chacha8_key must be 32 bytes for the wallet AEAD key");

    const int32_t rc = ccx_wallet_kdf_argon2id(
        reinterpret_cast<const uint8_t *>(password.data()), password.size(),
        header.salt, sizeof(header.salt),
        getLe32(header.memKibLe), getLe32(header.iterationsLe), getLe32(header.parallelismLe),
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
    // CSPRNG nonce (NOT mt19937): with the same password, a repeated XChaCha20 nonce is a
    // catastrophic confidentiality + tag-forgery break, so the nonce MUST be CSPRNG-grade.
    std::vector<uint8_t> nonce(nonceBytes());
    csprngBytes(nonce.data(), nonce.size());
    return nonce;
  }
} // namespace cn
