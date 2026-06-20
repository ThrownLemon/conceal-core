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
  // Helper to set the LE cost fields (the struct stores them as little-endian byte arrays).
  void putCost(WalletKdfHeader &h, uint32_t memKib, uint32_t iters, uint32_t par)
  {
    auto le = [](uint8_t out[4], uint32_t v) {
      out[0] = (uint8_t)(v & 0xff); out[1] = (uint8_t)((v >> 8) & 0xff);
      out[2] = (uint8_t)((v >> 16) & 0xff); out[3] = (uint8_t)((v >> 24) & 0xff);
    };
    le(h.memKibLe, memKib); le(h.iterationsLe, iters); le(h.parallelismLe, par);
  }

  // Cheap-but-valid Argon2 cost so the test suite stays fast; production wallets use the larger
  // WALLET_KDF_DEFAULT_*. 8 MiB / 1 / 1 is exactly the enforced floor (still a valid header).
  WalletKdfHeader cheapHeader(uint8_t saltByte)
  {
    WalletKdfHeader h = WalletKdf::makeHeader();
    std::memset(h.salt, saltByte, sizeof(h.salt));
    putCost(h, WALLET_KDF_MIN_MEM_KIB, 1, 1);
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
  ASSERT_EQ(WALLET_KDF_DEFAULT_MEM_KIB, WalletKdf::memKib(h));
  ASSERT_EQ(WALLET_KDF_DEFAULT_ITERATIONS, WalletKdf::iterations(h));
  ASSERT_EQ(WALLET_KDF_DEFAULT_PARALLELISM, WalletKdf::parallelism(h));
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

// W5: out-of-range cost params (from a hostile/corrupt on-disk header) must be rejected.
TEST(WalletKdf, outOfRangeCostParamsRejected)
{
  // Too-low memory (near-free KDF).
  {
    WalletKdfHeader h = WalletKdf::makeHeader();
    putCost(h, WALLET_KDF_MIN_MEM_KIB - 1, 1, 1);
    ASSERT_FALSE(WalletKdf::isValidHeader(h));
    ASSERT_THROW(WalletKdf::deriveKey("pw", h), std::runtime_error);
  }
  // Absurd memory (DoS-on-open).
  {
    WalletKdfHeader h = WalletKdf::makeHeader();
    putCost(h, 4u * 1024u * 1024u /* 4 GiB */, 3, 1);
    ASSERT_FALSE(WalletKdf::isValidHeader(h));
  }
  // Absurd iterations (DoS-on-open).
  {
    WalletKdfHeader h = WalletKdf::makeHeader();
    putCost(h, WALLET_KDF_DEFAULT_MEM_KIB, 0x7fffffffu, 1);
    ASSERT_FALSE(WalletKdf::isValidHeader(h));
  }
  // Zero iterations / zero parallelism.
  {
    WalletKdfHeader h = WalletKdf::makeHeader();
    putCost(h, WALLET_KDF_DEFAULT_MEM_KIB, 0, 1);
    ASSERT_FALSE(WalletKdf::isValidHeader(h));
  }
  // The defaults are in-range and accepted.
  {
    WalletKdfHeader h = WalletKdf::makeHeader();
    ASSERT_TRUE(WalletKdf::isValidHeader(h));
  }
}

// W8: cost fields are stored little-endian on disk (endianness-independent format).
TEST(WalletKdf, costFieldsAreLittleEndian)
{
  WalletKdfHeader h = WalletKdf::makeHeader();
  putCost(h, 0x01020304u, 0x00000003u, 0x00000001u);
  // memKib bytes must be LE: 04 03 02 01
  ASSERT_EQ(0x04, h.memKibLe[0]);
  ASSERT_EQ(0x03, h.memKibLe[1]);
  ASSERT_EQ(0x02, h.memKibLe[2]);
  ASSERT_EQ(0x01, h.memKibLe[3]);
  // Accessor reconstructs the host integer.
  ASSERT_EQ(0x01020304u, WalletKdf::memKib(h));
  ASSERT_EQ(3u, WalletKdf::iterations(h));
  ASSERT_EQ(1u, WalletKdf::parallelism(h));
}

// W1: the salt comes from a CSPRNG, not a 32-bit-seeded mt19937. Two fresh headers must differ in
// salt (this passes for any non-broken RNG, but together with the CSPRNG wiring documents intent).
TEST(WalletKdf, freshHeadersHaveIndependentSalts)
{
  // Draw several; all must be distinct (mt19937 with a 32-bit seed could repeat across processes,
  // but within one process the generator state advances; the real fix is the OsRng wiring).
  WalletKdfHeader a = WalletKdf::makeHeader();
  WalletKdfHeader b = WalletKdf::makeHeader();
  WalletKdfHeader c = WalletKdf::makeHeader();
  ASSERT_NE(0, std::memcmp(a.salt, b.salt, sizeof(a.salt)));
  ASSERT_NE(0, std::memcmp(b.salt, c.salt, sizeof(b.salt)));
  ASSERT_NE(0, std::memcmp(a.salt, c.salt, sizeof(a.salt)));
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

// ---- v8 prefix MAC (hardening item W11) ----------------------------------------------------------
//
// The v8 wallet container authenticates the (chacha8-encrypted-but-unauthenticated) prefix — the
// view/spend key records — with a 32-byte keyed SHAKE256 MAC stored inside the AEAD-sealed suffix.
// These cover the WalletKdf::prefixMac primitive directly.

TEST(WalletKdf, prefixMacIsDeterministicForSameKeyAndPrefix)
{
  WalletKdfHeader h = cheapHeader(0xb1);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", h);
  const std::vector<uint8_t> prefix = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

  std::vector<uint8_t> t1 = WalletKdf::prefixMac(key, prefix.data(), prefix.size());
  std::vector<uint8_t> t2 = WalletKdf::prefixMac(key, prefix.data(), prefix.size());
  ASSERT_EQ(WalletKdf::prefixMacBytes(), t1.size());
  ASSERT_EQ(32u, t1.size());
  ASSERT_EQ(t1, t2);
}

TEST(WalletKdf, prefixMacIsKeySensitive)
{
  WalletKdfHeader hA = cheapHeader(0xb2);
  WalletKdfHeader hB = cheapHeader(0xb3);
  crypto::chacha8_key kA = WalletKdf::deriveKey("pw", hA);
  crypto::chacha8_key kB = WalletKdf::deriveKey("pw", hB);
  const std::vector<uint8_t> prefix(40, 0x5a);

  std::vector<uint8_t> tA = WalletKdf::prefixMac(kA, prefix.data(), prefix.size());
  std::vector<uint8_t> tB = WalletKdf::prefixMac(kB, prefix.data(), prefix.size());
  ASSERT_NE(tA, tB);
}

TEST(WalletKdf, prefixMacDetectsAnyPrefixByteFlip)
{
  WalletKdfHeader h = cheapHeader(0xb4);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", h);
  std::vector<uint8_t> prefix(48);
  for (size_t i = 0; i < prefix.size(); ++i)
  {
    prefix[i] = static_cast<uint8_t>(i * 7 + 1);
  }
  const std::vector<uint8_t> tag = WalletKdf::prefixMac(key, prefix.data(), prefix.size());

  // Flipping any single prefix byte must change the tag (a tampered/rolled-back prefix is detected).
  for (size_t i = 0; i < prefix.size(); ++i)
  {
    std::vector<uint8_t> bad = prefix;
    bad[i] ^= 0x01;
    std::vector<uint8_t> badTag = WalletKdf::prefixMac(key, bad.data(), bad.size());
    ASSERT_NE(tag, badTag) << "prefix tamper at byte " << i << " was not reflected in the MAC";
  }
}

TEST(WalletKdf, prefixMacEmptyPrefixIsStable)
{
  WalletKdfHeader h = cheapHeader(0xb5);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", h);
  std::vector<uint8_t> t1 = WalletKdf::prefixMac(key, nullptr, 0);
  std::vector<uint8_t> t2 = WalletKdf::prefixMac(key, nullptr, 0);
  ASSERT_EQ(32u, t1.size());
  ASSERT_EQ(t1, t2);
}

// ---- v7 -> v8 migrate-on-save (container-analogue) ----------------------------------------------
//
// The wallet's encryptAndSaveContainerData seals, for v8, [32-byte prefix MAC][container data]; v7
// sealed the container data alone (no MAC). Migrate-on-save re-seals a v7 payload as v8 by computing
// the MAC over the live prefix and prepending it. These model that exact re-seal so the migration's
// security property — a post-migration prefix tamper is detected, which the v7 format could not do —
// is covered even though the build constant now always WRITES v8 (so a genuine on-disk v7 file can
// no longer be produced through the public wallet API without raw byte surgery).

namespace
{
  // Seal exactly as the v8 wallet does: plaintext = prefixMac(key, prefix) || containerData.
  std::vector<uint8_t> sealV8(const crypto::chacha8_key &key, const std::vector<uint8_t> &nonce,
                              const std::vector<uint8_t> &prefix, const std::vector<uint8_t> &containerData)
  {
    std::vector<uint8_t> tag = WalletKdf::prefixMac(key, prefix.data(), prefix.size());
    std::vector<uint8_t> plain;
    plain.insert(plain.end(), tag.begin(), tag.end());
    plain.insert(plain.end(), containerData.begin(), containerData.end());
    return WalletKdf::aeadSeal(key, nonce, plain.data(), plain.size());
  }

  // Open + verify exactly as the v8 wallet does: AEAD-open, strip+verify the 32-byte prefix MAC
  // against the live prefix, return the container data. Returns false on any failure.
  bool openV8(const crypto::chacha8_key &key, const std::vector<uint8_t> &nonce,
              const std::vector<uint8_t> &sealed, const std::vector<uint8_t> &livePrefix,
              std::vector<uint8_t> &containerDataOut)
  {
    std::vector<uint8_t> plain;
    if (!WalletKdf::aeadOpen(key, nonce, sealed.data(), sealed.size(), plain))
    {
      return false;
    }
    const size_t macLen = WalletKdf::prefixMacBytes();
    if (plain.size() < macLen)
    {
      return false;
    }
    std::vector<uint8_t> expected = WalletKdf::prefixMac(key, livePrefix.data(), livePrefix.size());
    if (expected.size() != macLen || std::memcmp(plain.data(), expected.data(), macLen) != 0)
    {
      return false; // prefix tamper/rollback
    }
    containerDataOut.assign(plain.begin() + macLen, plain.end());
    return true;
  }
}

TEST(WalletKdfContainer, migrateV7PayloadToV8ThenOpens)
{
  WalletKdfHeader header = cheapHeader(0xc1);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", header);

  // A "v7" payload: just the container data, sealed with no prefix binding.
  const std::vector<uint8_t> containerData = {0x10, 0x20, 0x30, 0x40, 0x50};
  const std::vector<uint8_t> prefix = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

  std::vector<uint8_t> v7nonce = WalletKdf::randomNonce();
  std::vector<uint8_t> v7sealed = WalletKdf::aeadSeal(key, v7nonce, containerData.data(), containerData.size());

  // Migrate: open the v7 payload, then re-seal it as v8 binding the prefix.
  std::vector<uint8_t> recovered;
  ASSERT_TRUE(WalletKdf::aeadOpen(key, v7nonce, v7sealed.data(), v7sealed.size(), recovered));
  ASSERT_EQ(containerData, recovered);

  std::vector<uint8_t> v8nonce = WalletKdf::randomNonce();
  std::vector<uint8_t> v8sealed = sealV8(key, v8nonce, prefix, recovered);

  // The migrated v8 container opens and reproduces the data when the prefix is intact.
  std::vector<uint8_t> out;
  ASSERT_TRUE(openV8(key, v8nonce, v8sealed, prefix, out));
  ASSERT_EQ(containerData, out);
}

TEST(WalletKdfContainer, v8PrefixTamperIsDetectedButV7CannotSee)
{
  WalletKdfHeader header = cheapHeader(0xc2);
  crypto::chacha8_key key = WalletKdf::deriveKey("pw", header);

  const std::vector<uint8_t> containerData(24, 0x5a);
  std::vector<uint8_t> prefix = {1, 2, 3, 4, 5, 6, 7, 8};

  std::vector<uint8_t> nonce = WalletKdf::randomNonce();
  std::vector<uint8_t> sealed = sealV8(key, nonce, prefix, containerData);

  // Intact prefix -> opens.
  std::vector<uint8_t> out;
  ASSERT_TRUE(openV8(key, nonce, sealed, prefix, out));
  ASSERT_EQ(containerData, out);

  // Tamper/rollback the prefix (e.g. a swapped-in forged key record) -> v8 open FAILS.
  std::vector<uint8_t> tamperedPrefix = prefix;
  tamperedPrefix[0] ^= 0x01;
  std::vector<uint8_t> out2;
  ASSERT_FALSE(openV8(key, nonce, sealed, tamperedPrefix, out2));

  // The v7 format (no prefix binding) would NOT see the same change: the suffix AEAD still verifies
  // because the prefix is outside the sealed region. This is exactly the W11 gap v8 closes.
  std::vector<uint8_t> v7nonce = WalletKdf::randomNonce();
  std::vector<uint8_t> v7sealed = WalletKdf::aeadSeal(key, v7nonce, containerData.data(), containerData.size());
  std::vector<uint8_t> v7out;
  ASSERT_TRUE(WalletKdf::aeadOpen(key, v7nonce, v7sealed.data(), v7sealed.size(), v7out));
  ASSERT_EQ(containerData, v7out); // suffix opens regardless of any prefix change
}

// ---- ccx-pqc wallet-crypto FFI selftest ---------------------------------------------------------

TEST(WalletKdf, ffiSelftestPasses)
{
  ccx_pq_sizes s = ccx_wallet_crypto_selftest();
  ASSERT_EQ(1, s.ok);
  ASSERT_EQ(WalletKdf::nonceBytes(), s.sk);   // selftest reports nonce size in sk
  ASSERT_EQ(WalletKdf::tagBytes(), s.ct_or_sig);
}
