// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PqSpendBuilder — shared, front-end-agnostic builder for a version-3 post-quantum SPEND
// transaction (CIP-0001). It reproduces EXACTLY the construction the pq_injector PoC tool proved,
// so the tx it emits is byte-structure-identical to what Blockchain::getTransactionPqSigningHash /
// check_pq_tx_input expect. Lives in CryptoNoteCore so every front-end that links it — the
// concealwallet CLI, the walletd (PaymentGate) RPC service, and the pq_injector tool — can build a
// PQ spend through ONE verified code path instead of duplicating the crypto.
//
// Pure function: no I/O, no globals, no logging. All crypto goes through the ccx-pqc C ABI.
// Testnet only / experimental (the lattice ring signature is unaudited). Not for mainnet funds.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "CryptoNote.h"

namespace cn
{
  // One ring member = an on-chain PQ output addressed by its ABSOLUTE global index in
  // m_pqOutputs[amount]. The SIGNER member must carry its kemCt (used to recover the spend key);
  // decoy members may leave kemCt empty.
  struct PqRingMember
  {
    uint32_t globalIndex = 0;          // absolute index within m_pqOutputs[amount]
    std::vector<uint8_t> key;          // PqKeyOutput.key  (ccx_pq_pubkey_bytes())
    std::vector<uint8_t> kemCt;        // PqKeyOutput.kemCt (signer member only)
  };

  struct PqSpendRequest
  {
    uint64_t amount = 0;               // the (fixed-denomination) input amount being spent
    uint64_t fee = 0;                  // fee; the single output value is amount - fee
    std::vector<PqRingMember> ring;    // ring members INCLUDING the signer (PQ_MIN..MAX_RING_SIZE)
    uint32_t signerGlobalIndex = 0;    // which ring member is ours (must appear in `ring`)
    std::vector<uint8_t> kemSecretKey; // KEM secret able to scan the signer's kemCt
                                       // (testnet: cn::PQ_TESTNET_KEM_SK)
    // Optional real recipient: if non-empty, the builder encapsulates to this ML-KEM-768 public key
    // so the recipient can later scan the output. If empty, it emits a throwaway output (one-time
    // key == the signer's, empty kemCt) — byte-identical to pq_injector, for A/B parity.
    std::vector<uint8_t> recipientKemPubKey;
  };

  // Build + sign a version-3 PQ spend transaction. On success `tx` is fully signed and ready for
  // relay (the same bytes a node will validate). Returns false and sets `err` on any failure.
  //
  // Contract honored (must match consensus byte-for-byte):
  //   * ring is sorted ascending by global index; outputIndexes are the relative deltas of that
  //     sorted order (absolute_output_offsets_to_relative), so relative->absolute on the validator
  //     resolves the SAME members in the SAME order;
  //   * signer_index passed to ccx_pq_sign is the signer's position in the SORTED ring;
  //   * the signing message is getObjectHash(TransactionPrefix) computed while PqKeyInput.ringSig
  //     is still EMPTY (identical to getTransactionPqSigningHash, which clears it);
  //   * the nullifier is bound to the one-time key and equals what ccx_pq_verify recovers.
  bool buildPqSpendTransaction(const PqSpendRequest &req, Transaction &tx, std::string &err);
}
