// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Wallet-file at-rest encryption tests (CIP-0001 Q2 §1b — crypto modernization).
//
// Covers the new wallet KDF/AEAD that replaces the weak legacy wallet protection (an unsalted single
// pass of cn_slow_hash_v0 + unauthenticated 8-round chacha8):
//   * Argon2id KDF: deterministic in (password, salt, cost); salt- and password-sensitive.
//   * XChaCha20-Poly1305 AEAD: seal->open round-trips; wrong password / tamper / wrong nonce all
//     fail to open WITHOUT exposing plaintext (authenticated encryption).
//   * KDF header: makeHeader produces a valid, parseable header; garbage is rejected.
//   * Container-level analogue of the wallet's encrypt/decrypt: a sealed container opens with the
//     right password, fails with the wrong one, and any tamper is detected.
//   * The ccx-pqc wallet-crypto FFI selftest passes.
//
// These run unconditionally (NOT under the skip-listed WalletApi.* fixture), so `ctest -R UnitTests`
// exercises them.

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "crypto/chacha8.h"
#include "Wallet/WalletKdf.h"

extern "C"
{
#include "pq_ring_sig.h"
}

using namespace cn;

namespace
{
  // Cheap Argon2 cost so the test suite stays fast; production wallets use WALLET_KDF_DEFAULT_*.
  WalletKdfHeader cheapHeader(uint8_t saltByte)
  {
    WalletKdfHeader h = WalletKdf::makeHeader();
    std::memset(h.salt, saltByte, sizeof(h.salt));
    h.memKib = 8 * 1024; // 8 MiB
    h.iterations = 1;
    h.parallelism = 1;
    return h;
  }
}

// ---- Argon2id KDF -------------------------------------------------------------------------------

TEST(WalletKdf, argon2idIsDeterministicForSamePasswordAndHeader)
{
  WalletKdfHeader h = cheapHeader(0x11);
  crypto::chacha8_key k1 = WalletKdf::deriveKey("correct horse battery staple", h);
  crypto::chacha8_key k2 = WalletKdf::deriveKey("correct horse battery staple", h);
  ASSERT_EQ(0, std::memcmp(k1.data, k2.data, sizeof(k1.data)));
}

TEST(WalletKdf, argon2idIsSaltSensitive)
{
  WalletKdfHeader hA = cheapHeader(0x11);
  WalletKdfHeader hB = cheapHeader(0x22);
  crypto::chacha8_key kA = WalletKdf::deriveKey("pw", hA);
  crypto::chacha8_key kB = WalletKdf::deriveKey("pw", hB);
  ASSERT_NE(0, std::memcmp(kA.data, kB.data, sizeof(kA.data)));
}

TEST(WalletKdf, argon2idIsPasswordSensitive)
{
  WalletKdfHeader h = cheapHeader(0x33);
  crypto::chacha8_key k1 = WalletKdf::deriveKey("password-one", h);
  crypto::chacha8_key k2 = WalletKdf::deriveKey("password-two", h);
  ASSERT_NE(0, std::memcmp(k1.data, k2.data, sizeof(k1.data)));
}

// ---- KDF header ---------------------------------------------------------------------------------

TEST(WalletKdf, makeHeaderIsValidAndUsesDefaults)
{
  WalletKdfHeader h = WalletKdf::makeHeader();
  ASSERT_TRUE(WalletKdf::isValidHeader(h));
  ASSERT_EQ(WALLET_KDF_VERSION_ARGON2ID, h.kdfVersion);
  ASSERT_EQ(WALLET_KDF_DEFAULT_MEM_KIB, h.memKib);
  ASSERT_EQ(WALLET_KDF_DEFAULT_ITERATIONS, h.iterations);
  ASSERT_EQ(WALLET_KDF_DEFAULT_PARALLELISM, h.parallelism);
}

TEST(WalletKdf, makeHeaderSaltIsRandomPerCall)
{
  WalletKdfHeader a = WalletKdf::makeHeader();
  WalletKdfHeader b = WalletKdf::makeHeader();
  // Two fresh headers must not share a salt (1/2^128 chance otherwise).
  ASSERT_NE(0, std::memcmp(a.salt, b.salt, sizeof(a.salt)));
}

TEST(WalletKdf, zeroHeaderIsRejected)
{
  WalletKdfHeader h;
  std::memset(&h, 0, sizeof(h));
  ASSERT_FALSE(WalletKdf::isValidHeader(h));
}

TEST(WalletKdf, deriveKeyRejectsInvalidHeader)
{
  WalletKdfHeader h;
  std::memset(&h, 0, sizeof(h)); // no magic
  ASSERT_THROW(WalletKdf::deriveKey("pw", h), std::runtime_error);
}

// ---- XChaCha20-Poly1305 AEAD --------------------------------------------------------------------

TEST(WalletKdf, aeadRoundTrips)
{
  WalletKdfHeader h = cheapHeader(0x44);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", h);
  std::vector<uint8_t> nonce = WalletKdf::randomNonce();
  ASSERT_EQ(WalletKdf::nonceBytes(), nonce.size());

  const std::string msg = "the decrypted wallet container plaintext";
  std::vector<uint8_t> sealed = WalletKdf::aeadSeal(key, nonce,
                                                    reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
  ASSERT_EQ(msg.size() + WalletKdf::tagBytes(), sealed.size());

  std::vector<uint8_t> opened;
  ASSERT_TRUE(WalletKdf::aeadOpen(key, nonce, sealed.data(), sealed.size(), opened));
  ASSERT_EQ(msg.size(), opened.size());
  ASSERT_EQ(0, std::memcmp(opened.data(), msg.data(), msg.size()));
}

TEST(WalletKdf, aeadWrongPasswordFails)
{
  WalletKdfHeader h = cheapHeader(0x55);
  crypto::chacha8_key key = WalletKdf::deriveKey("right-password", h);
  crypto::chacha8_key wrong = WalletKdf::deriveKey("wrong-password", h);
  std::vector<uint8_t> nonce = WalletKdf::randomNonce();

  const std::string msg = "secret";
  std::vector<uint8_t> sealed = WalletKdf::aeadSeal(key, nonce,
                                                    reinterpret_cast<const uint8_t *>(msg.data()), msg.size());

  std::vector<uint8_t> opened;
  ASSERT_FALSE(WalletKdf::aeadOpen(wrong, nonce, sealed.data(), sealed.size(), opened));
  ASSERT_TRUE(opened.empty()); // no plaintext exposed on auth failure
}

TEST(WalletKdf, aeadDetectsTamper)
{
  WalletKdfHeader h = cheapHeader(0x66);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", h);
  std::vector<uint8_t> nonce = WalletKdf::randomNonce();

  const std::string msg = "integrity-protected wallet bytes";
  std::vector<uint8_t> sealed = WalletKdf::aeadSeal(key, nonce,
                                                    reinterpret_cast<const uint8_t *>(msg.data()), msg.size());

  // Flip every byte in turn; each tamper must be detected.
  for (size_t i = 0; i < sealed.size(); ++i)
  {
    std::vector<uint8_t> bad = sealed;
    bad[i] ^= 0x01;
    std::vector<uint8_t> opened;
    ASSERT_FALSE(WalletKdf::aeadOpen(key, nonce, bad.data(), bad.size(), opened))
        << "tamper at byte " << i << " was not detected";
    ASSERT_TRUE(opened.empty());
  }
}

TEST(WalletKdf, aeadWrongNonceFails)
{
  WalletKdfHeader h = cheapHeader(0x77);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", h);
  std::vector<uint8_t> nonce = WalletKdf::randomNonce();
  std::vector<uint8_t> wrongNonce = nonce;
  wrongNonce[0] ^= 0xff;

  const std::string msg = "data";
  std::vector<uint8_t> sealed = WalletKdf::aeadSeal(key, nonce,
                                                    reinterpret_cast<const uint8_t *>(msg.data()), msg.size());

  std::vector<uint8_t> opened;
  ASSERT_FALSE(WalletKdf::aeadOpen(key, wrongNonce, sealed.data(), sealed.size(), opened));
}

TEST(WalletKdf, aeadTruncationFails)
{
  WalletKdfHeader h = cheapHeader(0x88);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", h);
  std::vector<uint8_t> nonce = WalletKdf::randomNonce();

  const std::string msg = "0123456789abcdef";
  std::vector<uint8_t> sealed = WalletKdf::aeadSeal(key, nonce,
                                                    reinterpret_cast<const uint8_t *>(msg.data()), msg.size());

  // Drop a byte off the tag/ciphertext.
  std::vector<uint8_t> opened;
  ASSERT_FALSE(WalletKdf::aeadOpen(key, nonce, sealed.data(), sealed.size() - 1, opened));
  // Shorter than the tag length is also rejected.
  ASSERT_FALSE(WalletKdf::aeadOpen(key, nonce, sealed.data(), WalletKdf::tagBytes() - 1, opened));
}

TEST(WalletKdf, emptyPlaintextRoundTrips)
{
  WalletKdfHeader h = cheapHeader(0x99);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", h);
  std::vector<uint8_t> nonce = WalletKdf::randomNonce();

  std::vector<uint8_t> sealed = WalletKdf::aeadSeal(key, nonce, nullptr, 0);
  ASSERT_EQ(WalletKdf::tagBytes(), sealed.size());

  std::vector<uint8_t> opened;
  ASSERT_TRUE(WalletKdf::aeadOpen(key, nonce, sealed.data(), sealed.size(), opened));
  ASSERT_TRUE(opened.empty());
}

// ---- Container-level analogue (mirrors the wallet's encrypt/decrypt of the container suffix) -----

namespace
{
  // Seal a container blob exactly as the wallet does for v7: derive the key from (password, header),
  // draw a fresh nonce, AEAD-seal. Returns header || nonce || sealed.
  std::vector<uint8_t> sealContainer(const std::string &password, const WalletKdfHeader &header,
                                     const std::vector<uint8_t> &plaintext)
  {
    crypto::chacha8_key key = WalletKdf::deriveKey(password, header);
    std::vector<uint8_t> nonce = WalletKdf::randomNonce();
    std::vector<uint8_t> sealed = WalletKdf::aeadSeal(key, nonce, plaintext.data(), plaintext.size());

    std::vector<uint8_t> out;
    out.insert(out.end(), reinterpret_cast<const uint8_t *>(&header),
               reinterpret_cast<const uint8_t *>(&header) + sizeof(header));
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), sealed.begin(), sealed.end());
    return out;
  }

  // Open a container blob with `password`. Returns true + plaintext on success.
  bool openContainer(const std::string &password, const std::vector<uint8_t> &blob,
                     std::vector<uint8_t> &plaintext)
  {
    const size_t nonceLen = WalletKdf::nonceBytes();
    if (blob.size() < sizeof(WalletKdfHeader) + nonceLen)
    {
      return false;
    }
    WalletKdfHeader header;
    std::memcpy(&header, blob.data(), sizeof(header));
    if (!WalletKdf::isValidHeader(header))
    {
      return false;
    }
    std::vector<uint8_t> nonce(blob.begin() + sizeof(header), blob.begin() + sizeof(header) + nonceLen);
    std::vector<uint8_t> sealed(blob.begin() + sizeof(header) + nonceLen, blob.end());
    crypto::chacha8_key key = WalletKdf::deriveKey(password, header);
    return WalletKdf::aeadOpen(key, nonce, sealed.data(), sealed.size(), plaintext);
  }
}

TEST(WalletKdfContainer, newFormatRoundTrip)
{
  WalletKdfHeader header = cheapHeader(0xa1);
  std::vector<uint8_t> plain = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  std::vector<uint8_t> blob = sealContainer("walletpass", header, plain);

  std::vector<uint8_t> out;
  ASSERT_TRUE(openContainer("walletpass", blob, out));
  ASSERT_EQ(plain, out);
}

TEST(WalletKdfContainer, wrongPasswordFailsAuth)
{
  WalletKdfHeader header = cheapHeader(0xa2);
  std::vector<uint8_t> plain = {0xde, 0xad, 0xbe, 0xef};
  std::vector<uint8_t> blob = sealContainer("right", header, plain);

  std::vector<uint8_t> out;
  ASSERT_FALSE(openContainer("wrong", blob, out));
  ASSERT_TRUE(out.empty());
}

TEST(WalletKdfContainer, tamperDetected)
{
  WalletKdfHeader header = cheapHeader(0xa3);
  std::vector<uint8_t> plain(64, 0x5a);
  std::vector<uint8_t> blob = sealContainer("pw", header, plain);

  // Tamper a byte inside the sealed region (after header+nonce) — must fail to open.
  const size_t sealedStart = sizeof(WalletKdfHeader) + WalletKdf::nonceBytes();
  ASSERT_LT(sealedStart, blob.size());
  std::vector<uint8_t> bad = blob;
  bad[sealedStart] ^= 0x80;
  std::vector<uint8_t> out;
  ASSERT_FALSE(openContainer("pw", bad, out));
}

// ---- ccx-pqc wallet-crypto FFI selftest ---------------------------------------------------------

TEST(WalletKdf, ffiSelftestPasses)
{
  ccx_pq_sizes s = ccx_wallet_crypto_selftest();
  ASSERT_EQ(1, s.ok);
  ASSERT_EQ(WalletKdf::nonceBytes(), s.sk);   // selftest reports nonce size in sk
  ASSERT_EQ(WalletKdf::tagBytes(), s.ct_or_sig);
}
