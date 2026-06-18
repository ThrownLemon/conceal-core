// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// v8 wallet-container prefix-authentication tests (hardening item W11).
//
// The v7 container made the suffix (the serialized cache + PQ section) XChaCha20-Poly1305 AEAD, but
// left the PREFIX — the chacha8-encrypted view/spend key records held in the FileMappedVector prefix
// + element region — UNauthenticated, so a prefix tamper/rollback was undetectable. v8 stores a
// 32-byte keyed MAC over the prefix bytes inside the AEAD-sealed suffix and verifies it on open.
//
// These tests drive the real WalletGreen save/load/changePassword over a temp file and tamper the
// on-disk prefix directly, so they exercise the production code path end-to-end. They run under a
// dedicated fixture (NOT the skip-listed WalletApi.*), so `ctest -R UnitTests` exercises them.
//
// On-disk FileMappedVector layout (see Common/FileMappedVector.h):
//   [ prefix (prefixSize bytes) ][ capacity:u64 ][ size:u64 ][ records... ][ suffix ]
// The ContainerStoragePrefix begins at file offset 0: byte 0 is the container version, bytes 1..8
// are the prefix "nextIv" counter, then the encrypted view-key record. `nextIv` is NOT a key (it is
// not consulted to decrypt existing records — each record carries its own IV), so flipping a byte in
// it is caught ONLY by the v8 prefix MAC, not by the downstream pub/priv key-consistency check.

#include "gtest/gtest.h"

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>

#include <Logging/ConsoleLogger.h>
#include <System/Dispatcher.h>

#include "CryptoNoteCore/Currency.h"
#include "INodeStubs.h"
#include "TestBlockchainGenerator.h"
#include "Wallet/WalletGreen.h"

using namespace cn;

namespace
{
  // Self-contained WalletGreen harness on a real temp file so we can tamper the on-disk bytes.
  class WalletPrefixMac : public ::testing::Test
  {
  public:
    WalletPrefixMac()
        : currency(CurrencyBuilder(logger).currency()),
          generator(currency),
          node(generator)
    {
    }

    void SetUp() override
    {
      base = (boost::filesystem::temp_directory_path() /
              boost::filesystem::unique_path("ccx-wallet-prefixmac-%%%%-%%%%.wallet"))
                 .string();
    }

    void TearDown() override
    {
      removeFile(base);
      removeFile(base + ".bak");
    }

    static void removeFile(const std::string &path)
    {
      boost::system::error_code ec;
      boost::filesystem::remove(path, ec);
    }

    // Read the whole wallet file into a byte vector.
    static std::vector<uint8_t> readFile(const std::string &path)
    {
      std::ifstream in(path, std::ios::binary);
      return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }

    // XOR a single byte at `offset` in the file (in place).
    static void flipByte(const std::string &path, size_t offset, uint8_t mask = 0x01)
    {
      std::fstream f(path, std::ios::binary | std::ios::in | std::ios::out);
      f.seekg(static_cast<std::streamoff>(offset));
      char b = 0;
      f.read(&b, 1);
      b = static_cast<char>(static_cast<uint8_t>(b) ^ mask);
      f.seekp(static_cast<std::streamoff>(offset));
      f.write(&b, 1);
    }

    platform_system::Dispatcher dispatcher;
    logging::ConsoleLogger logger;
    Currency currency;
    TestBlockchainGenerator generator;
    INodeTrivialRefreshStub node;

    std::string base;
  };

  const uint8_t EXPECTED_V8 = WalletSerializerV2::SERIALIZATION_VERSION; // 8
}

// A freshly-created + saved wallet is written in the v8 (authenticated-prefix) format.
TEST_F(WalletPrefixMac, freshWalletIsV8OnDisk)
{
  {
    WalletGreen w(dispatcher, currency, node, logger);
    w.initialize(base, "pass");
    w.createAddress();
    w.save();
    w.shutdown();
  }

  std::vector<uint8_t> bytes = readFile(base);
  ASSERT_FALSE(bytes.empty());
  ASSERT_EQ(EXPECTED_V8, bytes[0]) << "container version byte (offset 0) must be v8";
}

// v8 round-trip: save then load reproduces the view key + addresses, and the prefix MAC verifies.
TEST_F(WalletPrefixMac, v8RoundTrip)
{
  std::string addr0;
  std::string addr1;
  KeyPair viewKey;
  {
    WalletGreen w(dispatcher, currency, node, logger);
    w.initialize(base, "pass");
    addr0 = w.createAddress();
    addr1 = w.createAddress();
    viewKey = w.getViewKey();
    w.save();
    w.shutdown();
  }

  WalletGreen r(dispatcher, currency, node, logger);
  ASSERT_NO_THROW(r.load(base, "pass"));
  ASSERT_EQ(2u, r.getAddressCount());
  ASSERT_EQ(addr0, r.getAddress(0));
  ASSERT_EQ(addr1, r.getAddress(1));
  ASSERT_EQ(viewKey.publicKey, r.getViewKey().publicKey);
  r.shutdown();
}

// Tampering a single byte of the on-disk prefix `nextIv` (which the downstream key-consistency check
// does NOT cover) must make the load FAIL — the v8 prefix MAC is what catches it.
TEST_F(WalletPrefixMac, prefixNextIvTamperFailsLoad)
{
  {
    WalletGreen w(dispatcher, currency, node, logger);
    w.initialize(base, "pass");
    w.createAddress();
    w.save();
    w.shutdown();
  }

  // Offset 1 is the first byte of the prefix `nextIv` (offset 0 is the version byte). Flipping it
  // changes the MAC'd prefix without touching any key ciphertext or the version selector.
  flipByte(base, 1);

  WalletGreen r(dispatcher, currency, node, logger);
  ASSERT_ANY_THROW(r.load(base, "pass"));
}

// Sweep: flipping ANY byte in the first 8 bytes after the version (the prefix nextIv) is detected.
TEST_F(WalletPrefixMac, prefixTamperSweepDetected)
{
  {
    WalletGreen w(dispatcher, currency, node, logger);
    w.initialize(base, "pass");
    w.createAddress();
    w.save();
    w.shutdown();
  }
  const std::vector<uint8_t> pristine = readFile(base);

  for (size_t off = 1; off <= 8; ++off) // nextIv bytes (skip the version selector at offset 0)
  {
    // restore pristine
    {
      std::ofstream out(base, std::ios::binary | std::ios::trunc);
      out.write(reinterpret_cast<const char *>(pristine.data()), static_cast<std::streamsize>(pristine.size()));
    }
    removeFile(base + ".bak");

    flipByte(base, off);

    WalletGreen r(dispatcher, currency, node, logger);
    ASSERT_ANY_THROW(r.load(base, "pass")) << "prefix tamper at file offset " << off << " was not detected";
  }
}

// The suffix is still AEAD-authenticated in v8: tampering a byte in the (last 16 = Poly1305 tag)
// region of the file must also fail the load (regression guard that v8 did not weaken the suffix).
TEST_F(WalletPrefixMac, suffixTamperStillFailsLoad)
{
  {
    WalletGreen w(dispatcher, currency, node, logger);
    w.initialize(base, "pass");
    w.createAddress();
    w.save();
    w.shutdown();
  }
  std::vector<uint8_t> bytes = readFile(base);
  ASSERT_GT(bytes.size(), 16u);

  flipByte(base, bytes.size() - 1); // last byte lives in the Poly1305 tag of the sealed suffix

  WalletGreen r(dispatcher, currency, node, logger);
  ASSERT_ANY_THROW(r.load(base, "pass"));
}

// changePassword re-seals under a fresh key and re-computes the prefix MAC: the wallet still loads
// with the NEW password (MAC verifies) and the OLD password fails (auth).
TEST_F(WalletPrefixMac, changePasswordPreservesPrefixAuth)
{
  std::string addr0;
  {
    WalletGreen w(dispatcher, currency, node, logger);
    w.initialize(base, "oldpass");
    addr0 = w.createAddress();
    w.save();
    w.changePassword("oldpass", "newpass");
    w.save();
    w.shutdown();
  }

  // Reopen with the new password — the re-stored prefix MAC must verify.
  {
    WalletGreen r(dispatcher, currency, node, logger);
    ASSERT_NO_THROW(r.load(base, "newpass"));
    ASSERT_EQ(1u, r.getAddressCount());
    ASSERT_EQ(addr0, r.getAddress(0));
    r.shutdown();
  }

  // The old password must no longer open the wallet.
  {
    WalletGreen r2(dispatcher, currency, node, logger);
    ASSERT_ANY_THROW(r2.load(base, "oldpass"));
  }

  // After changePassword the file is still v8.
  std::vector<uint8_t> bytes = readFile(base);
  ASSERT_FALSE(bytes.empty());
  ASSERT_EQ(EXPECTED_V8, bytes[0]);

  // And a prefix tamper after the rekey is still detected.
  flipByte(base, 1);
  WalletGreen r3(dispatcher, currency, node, logger);
  ASSERT_ANY_THROW(r3.load(base, "newpass"));
}
