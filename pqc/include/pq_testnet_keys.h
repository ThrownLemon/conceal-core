// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Shared deterministic key-derivation for testnet PQ coinbase outputs (CIP-0001 PoC).
//
// The daemon (Currency::constructMinerTx) emits a per-(height,outIndex) PQ output and stores ONLY
// its public key on-chain; the injector re-derives the SAME keypair to spend it. Both sides MUST
// compute the per-output seed identically — hence this single shared helper.
//
//   perOutputSeed = cn_fast_hash( rootSeed || LE64(height) || LE32(outIndex) )
//
// The 32-byte seed is then fed to ccx_pq_keygen (which internally expands the ML-DSA keypair).
#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include "crypto/hash.h"

namespace cn {

inline void derivePqCoinbaseSeed(const uint8_t *rootSeed, size_t rootLen,
                                 uint64_t height, uint32_t outIndex,
                                 uint8_t out32[32]) {
  std::vector<uint8_t> buf;
  buf.reserve(rootLen + 12);
  buf.insert(buf.end(), rootSeed, rootSeed + rootLen);
  for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>(height >> (8 * i)));
  for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>(outIndex >> (8 * i)));
  crypto::Hash h;
  crypto::cn_fast_hash(buf.data(), buf.size(), h);
  std::memcpy(out32, h.data, 32);
}

} // namespace cn
