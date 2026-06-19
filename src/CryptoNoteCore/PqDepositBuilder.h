// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PqDepositBuilder — shared, front-end-agnostic builders for the version-3 post-quantum DEPOSIT
// create + withdraw transactions (CIP-0001 UPGRADE_HEIGHT_V9, Option 3). The twin of PqSpendBuilder:
// it lives in CryptoNoteCore so concealwallet, walletd, and the PoC tools all build a PQ deposit /
// withdrawal through ONE verified code path, byte-structure-identical to what
// Blockchain::getTransactionPqSigningHash / check_pq_multisig / Currency::validateOutput expect.
//
// CREATE  (buildPqDepositTransaction):
//   Spends ONE on-chain PqKeyOutput (the wallet's PQ funds) inside a lattice ring — EXACTLY the input
//   construction PqSpendBuilder proved — and locks `amount` into a PqMultisigOutput{ keys=[dsaPubKey],
//   requiredSignatureCount=1, term } deposit cell. Any remainder (input - amount - fee) is returned to
//   the wallet as a PqKeyOutput change (encapsulated to its KEM key so the scanner re-finds it).
//
// WITHDRAW (buildPqWithdrawTransaction):
//   Spends the deposit cell itself via a PqMultisigInput (no ring, no nullifier — double-spend is
//   caught by the on-chain isUsed flag) and pays principal + daemon interest back to the wallet as a
//   PqKeyOutput. The m ML-DSA-65 detached signatures are computed over the PQ signing hash (the prefix
//   with every inline PQ signature/ringSig cleared) and written INLINE into PqMultisigInput.signatures
//   — never into tx.signatures (getSignaturesCount(PqMultisigInput) == 0). There is NO funding input
//   and NO fee: the deposit principal funds the output, and interest legitimately makes outputs > inputs
//   for a v3 tx (the daemon credits amount + getInterestForInput).
//
// Pure functions: no I/O, no globals, no logging. All crypto goes through the ccx-pqc C ABI.
// Testnet only / experimental (ML-DSA integration unaudited). Not for mainnet funds.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "PqSpendBuilder.h" // PqRingMember

namespace cn
{
  // ---- CREATE -----------------------------------------------------------------------------------
  struct PqDepositRequest
  {
    uint64_t amount = 0;               // atomic units to LOCK into the deposit (>= depositMinAmount)
    uint64_t fee = 0;                  // tx fee; change = inputAmount - amount - fee
    uint32_t term = 0;                 // deposit term in blocks (term band / % depositMinTermV3 enforced by caller+consensus)

    // The funding PQ input: one on-chain PqKeyOutput the wallet owns, spent inside a ring of decoys.
    // Same shape PqSpendBuilder uses: `ring` (sorted internally) INCLUDES the signer, identified by
    // `signerGlobalIndex`; `inputAmount` is the fixed denomination of that PQ output bucket.
    uint64_t inputAmount = 0;          // the PqKeyInput.amount (the funding output's denomination)
    std::vector<PqRingMember> ring;    // ring members INCLUDING the signer (PQ_MIN..MAX_RING_SIZE)
    uint32_t signerGlobalIndex = 0;    // which ring member is ours (must appear in `ring`)
    std::vector<uint8_t> kemSecretKey; // KEM secret able to scan the signer's kemCt (recover spend key)

    // The wallet's account ML-DSA-65 public key — the deposit cell names this key (n=1, m=1).
    std::vector<uint8_t> depositDsaPubKey; // ccx_pq_multisig_pubkey_bytes() == 1952

    // The wallet's KEM public key, so the change PqKeyOutput is encapsulated back to the wallet and the
    // scanner re-finds it. Empty => throwaway change (only valid if there is no change).
    std::vector<uint8_t> changeKemPubKey;
  };

  // Build + sign a version-3 PQ deposit-creation transaction. On success `tx` is fully signed and
  // ready for relay. Returns false and sets `err` on any failure.
  bool buildPqDepositTransaction(const PqDepositRequest &req, Transaction &tx, std::string &err);

  // ---- WITHDRAW ---------------------------------------------------------------------------------
  struct PqWithdrawRequest
  {
    uint64_t amount = 0;               // the deposit principal (PqMultisigOutput.amount == PqMultisigInput.amount)
    uint32_t outputIndex = 0;          // global index of the deposit cell in m_pqMultisigOutputs[amount]
    uint32_t term = 0;                 // MUST equal the on-chain output.term (consensus binds them)
    uint8_t  requiredSignatureCount = 1; // == output.requiredSignatureCount (m)

    uint64_t interest = 0;             // daemon-computed interest credited on withdrawal (payout = amount + interest)

    // The m ML-DSA-65 secret keys that sign the cell, in the SAME order as the on-chain output keys
    // (greedy in-order m-of-n match). For the v1 single-key wallet (D1) this is exactly one key.
    std::vector<std::vector<uint8_t>> signingSecretKeys;

    // The wallet's KEM public key, so the principal+interest PqKeyOutput is encapsulated back to the
    // wallet (the scanner re-finds the withdrawn funds). Empty => throwaway output.
    std::vector<uint8_t> payoutKemPubKey;
  };

  // Build + sign a version-3 PQ deposit-withdrawal transaction. On success `tx` is fully signed and
  // ready for relay (its inline ML-DSA sigs verify under check_pq_multisig over the same signing hash).
  // Returns false and sets `err` on any failure.
  bool buildPqWithdrawTransaction(const PqWithdrawRequest &req, Transaction &tx, std::string &err);
}
