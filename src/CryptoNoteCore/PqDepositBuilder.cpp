// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PqDepositBuilder.h"

#include <algorithm>

#include "CryptoNoteFormatUtils.h" // absolute_output_offsets_to_relative
#include "CryptoNoteTools.h"        // getObjectHash
#include "CryptoNoteConfig.h"       // PQ_MIN/MAX_RING_SIZE, PQ_MULTISIG_MAX_KEYS, TRANSACTION_VERSION_3
#include "pq_ring_sig.h"            // ccx-pqc FFI

namespace cn
{
  namespace
  {
    // Best-effort zeroisation of a sensitive buffer that the optimiser may not elide (matches the
    // PqSpendBuilder helper — kept local to avoid coupling the two translation units).
    void secure_wipe(void *p, size_t n)
    {
      if (p == nullptr || n == 0)
      {
        return;
      }
      volatile uint8_t *vp = static_cast<volatile uint8_t *>(p);
      while (n-- > 0)
      {
        *vp++ = 0;
      }
    }

    // Build a PqKeyOutput either encapsulated to a real recipient (so its scanner re-finds it) or a
    // throwaway (one-time key == fallbackKey, empty kemCt). Returns false + sets err on FFI failure.
    bool makePqKeyOutput(const std::vector<uint8_t> &recipientKemPubKey,
                         const std::vector<uint8_t> &fallbackKey,
                         size_t pkBytes, size_t skBytes,
                         PqKeyOutput &out, std::string &err)
    {
      if (recipientKemPubKey.empty())
      {
        out.key = fallbackKey; // throwaway recipient, empty kemCt
        out.kemCt.clear();
        return true;
      }
      std::vector<uint8_t> kemCt(ccx_pq_kem_ct_bytes(), 0);
      uint8_t rSeed[32];
      if (ccx_pq_kem_derive_output(recipientKemPubKey.data(), recipientKemPubKey.size(),
                                   kemCt.data(), kemCt.size(), rSeed, sizeof(rSeed)) != 0)
      {
        secure_wipe(rSeed, sizeof(rSeed));
        err = "recipient KEM encapsulation failed";
        return false;
      }
      std::vector<uint8_t> rPk(pkBytes, 0), rSk(skBytes, 0);
      if (ccx_pq_keygen(rSeed, sizeof(rSeed), rPk.data(), rPk.size(), rSk.data(), rSk.size()) != 0)
      {
        secure_wipe(rSeed, sizeof(rSeed));
        secure_wipe(rSk.data(), rSk.size());
        err = "recipient one-time keygen failed";
        return false;
      }
      out.key = rPk;
      out.kemCt = kemCt;
      secure_wipe(rSeed, sizeof(rSeed));
      secure_wipe(rSk.data(), rSk.size());
      return true;
    }

    // Recover the signer's one-time PQ keypair from its kemCt + nullifier, and prepare the ring blob +
    // the relative outputIndexes + the signer's position in the sorted ring. Shared by the deposit
    // CREATE path (which spends a PqKeyInput exactly like PqSpendBuilder). On success fills outputs and
    // returns true; on any failure sets err and returns false. Wipes its own sensitive temporaries on
    // the failure paths; on success the caller owns `otSk` and MUST wipe it after signing.
    bool prepareFundingInput(const std::vector<PqRingMember> &reqRing,
                             uint32_t signerGlobalIndex,
                             const std::vector<uint8_t> &kemSecretKey,
                             size_t pkBytes, size_t skBytes,
                             std::vector<uint8_t> &ringBlob,
                             std::vector<uint32_t> &relativeOffsets,
                             std::vector<uint8_t> &nullifier,
                             std::vector<uint8_t> &otPk,
                             std::vector<uint8_t> &otSk,
                             size_t &signerPos,
                             std::string &err)
    {
      if (reqRing.size() < cn::PQ_MIN_RING_SIZE || reqRing.size() > cn::PQ_MAX_RING_SIZE)
      {
        err = "ring size out of bounds [" + std::to_string(cn::PQ_MIN_RING_SIZE) + "," +
              std::to_string(cn::PQ_MAX_RING_SIZE) + "]";
        return false;
      }
      if (kemSecretKey.empty())
      {
        err = "missing KEM secret key";
        return false;
      }

      // Sort ring ascending by global index (consensus resolves members in this order).
      std::vector<PqRingMember> ring = reqRing;
      std::sort(ring.begin(), ring.end(),
                [](const PqRingMember &a, const PqRingMember &b) { return a.globalIndex < b.globalIndex; });
      for (size_t i = 1; i < ring.size(); ++i)
      {
        if (ring[i].globalIndex <= ring[i - 1].globalIndex)
        {
          err = "duplicate / non-increasing ring global indices";
          return false;
        }
      }

      signerPos = ring.size();
      for (size_t i = 0; i < ring.size(); ++i)
      {
        if (ring[i].globalIndex == signerGlobalIndex)
        {
          signerPos = i;
          break;
        }
      }
      if (signerPos == ring.size())
      {
        err = "signer global index not present in ring";
        return false;
      }

      ringBlob.clear();
      ringBlob.reserve(ring.size() * pkBytes);
      for (size_t i = 0; i < ring.size(); ++i)
      {
        if (ring[i].key.size() != pkBytes)
        {
          err = "ring member " + std::to_string(i) + " key has wrong size " +
                std::to_string(ring[i].key.size()) + " (expected " + std::to_string(pkBytes) + ")";
          return false;
        }
        ringBlob.insert(ringBlob.end(), ring[i].key.begin(), ring[i].key.end());
      }

      const PqRingMember &signer = ring[signerPos];
      if (signer.kemCt.empty())
      {
        err = "signer ring member is missing its kemCt (needed to recover the spend key)";
        return false;
      }
      const size_t kemSkBytes = ccx_pq_kem_seckey_bytes();
      if (kemSkBytes == 0 || kemSecretKey.size() != kemSkBytes)
      {
        err = "KEM secret key has wrong size " + std::to_string(kemSecretKey.size()) +
              " (expected " + std::to_string(kemSkBytes) + ")";
        return false;
      }
      uint8_t otSeed[32];
      if (ccx_pq_kem_scan(kemSecretKey.data(), kemSecretKey.size(),
                          signer.kemCt.data(), signer.kemCt.size(), otSeed, sizeof(otSeed)) != 0)
      {
        secure_wipe(otSeed, sizeof(otSeed));
        err = "KEM scan failed (output not ours / wrong KEM secret)";
        return false;
      }
      otPk.assign(pkBytes, 0);
      otSk.assign(skBytes, 0);
      if (ccx_pq_keygen(otSeed, sizeof(otSeed), otPk.data(), otPk.size(), otSk.data(), otSk.size()) != 0)
      {
        secure_wipe(otSeed, sizeof(otSeed));
        secure_wipe(otSk.data(), otSk.size());
        err = "one-time keygen from the recovered seed failed";
        return false;
      }
      if (otPk != signer.key)
      {
        secure_wipe(otSeed, sizeof(otSeed));
        secure_wipe(otSk.data(), otSk.size());
        err = "recovered one-time key does not match the on-chain output (not ours)";
        return false;
      }

      nullifier.assign(ccx_pq_nullifier_bytes(), 0);
      if (ccx_pq_nullifier(otSk.data(), otSk.size(), otPk.data(), otPk.size(),
                           nullifier.data(), nullifier.size()) != 0)
      {
        secure_wipe(otSeed, sizeof(otSeed));
        secure_wipe(otSk.data(), otSk.size());
        err = "nullifier derivation failed";
        return false;
      }

      std::vector<uint32_t> absIdx;
      absIdx.reserve(ring.size());
      for (const auto &m : ring)
      {
        absIdx.push_back(m.globalIndex);
      }
      relativeOffsets = absolute_output_offsets_to_relative(absIdx);

      secure_wipe(otSeed, sizeof(otSeed));
      return true;
    }
  } // namespace

  bool buildPqDepositTransaction(const PqDepositRequest &req, Transaction &tx, std::string &err)
  {
    const size_t pkBytes = ccx_pq_pubkey_bytes();
    const size_t skBytes = ccx_pq_seckey_bytes();
    if (pkBytes == 0 || skBytes == 0)
    {
      err = "ccx-pqc reports zero ring-sig key size";
      return false;
    }
    const size_t dsaPkBytes = ccx_pq_multisig_pubkey_bytes();
    if (dsaPkBytes == 0)
    {
      err = "ccx-pqc reports zero ML-DSA public-key size";
      return false;
    }

    // ---- validate the request --------------------------------------------------------------------
    if (req.amount == 0)
    {
      err = "deposit amount must be > 0";
      return false;
    }
    if (req.term == 0)
    {
      err = "deposit term must be > 0 (a term-0 cell is a plain multisig, not a deposit)";
      return false;
    }
    // input must cover amount + fee; change is the remainder (may be 0).
    if (req.inputAmount < req.amount || req.inputAmount - req.amount < req.fee)
    {
      err = "funding input does not cover amount + fee";
      return false;
    }
    const uint64_t change = req.inputAmount - req.amount - req.fee;
    if (req.depositDsaPubKey.size() != dsaPkBytes)
    {
      err = "deposit ML-DSA public key has wrong size " + std::to_string(req.depositDsaPubKey.size()) +
            " (expected " + std::to_string(dsaPkBytes) + ")";
      return false;
    }
    if (change > 0 && req.changeKemPubKey.empty())
    {
      err = "change present but no change KEM public key to receive it";
      return false;
    }

    // ---- recover the funding input (shared with PqSpendBuilder logic) ----------------------------
    std::vector<uint8_t> ringBlob, nullifier, otPk, otSk;
    std::vector<uint32_t> relativeOffsets;
    size_t signerPos = 0;
    if (!prepareFundingInput(req.ring, req.signerGlobalIndex, req.kemSecretKey, pkBytes, skBytes,
                             ringBlob, relativeOffsets, nullifier, otPk, otSk, signerPos, err))
    {
      return false;
    }

    PqKeyInput in;
    in.amount = req.inputAmount;
    in.outputIndexes = relativeOffsets;
    in.nullifier = nullifier;
    // in.ringSig deliberately empty for the signing-hash computation below.

    // ---- deposit output: a PqMultisigOutput cell naming the wallet's account ML-DSA key (n=m=1) ---
    PqMultisigOutput deposit;
    deposit.keys.push_back(req.depositDsaPubKey);
    deposit.requiredSignatureCount = 1;
    deposit.term = req.term;
    TransactionOutput depositOut;
    depositOut.amount = req.amount;
    depositOut.target = deposit;

    // ---- change output back to the wallet (PqKeyOutput) ------------------------------------------
    std::vector<TransactionOutput> outs;
    outs.push_back(depositOut);
    if (change > 0)
    {
      PqKeyOutput changeOut;
      if (!makePqKeyOutput(req.changeKemPubKey, otPk, pkBytes, skBytes, changeOut, err))
      {
        secure_wipe(otSk.data(), otSk.size());
        return false;
      }
      TransactionOutput co;
      co.amount = change;
      co.target = changeOut;
      outs.push_back(co);
    }

    // ---- assemble the prefix ---------------------------------------------------------------------
    tx = Transaction();
    tx.version = cn::TRANSACTION_VERSION_4; // PQ tx version on the merged tree (fork owns v3)
    tx.unlockTime = 0;
    tx.inputs.clear();
    tx.inputs.push_back(in);
    tx.outputs = outs;
    tx.extra.clear();
    tx.signatures.clear();

    // ---- signing hash = getObjectHash(prefix) while ringSig is still EMPTY (== getTransactionPqSigningHash)
    const crypto::Hash signingHash = getObjectHash(static_cast<const TransactionPrefix &>(tx));

    // ---- sign the funding ring input -------------------------------------------------------------
    std::vector<uint8_t> sig(256 * 1024, 0);
    size_t sigLen = sig.size();
    const int32_t rc = ccx_pq_sign(
        reinterpret_cast<const uint8_t *>(&signingHash), sizeof(signingHash),
        ringBlob.data(), req.ring.size(), pkBytes,
        otSk.data(), otSk.size(), signerPos,
        sig.data(), &sigLen);
    if (rc != 0)
    {
      secure_wipe(otSk.data(), otSk.size());
      err = "ccx_pq_sign failed (rc=" + std::to_string(rc) + ")";
      return false;
    }
    sig.resize(sigLen);
    boost::get<PqKeyInput>(tx.inputs[0]).ringSig = sig;

    secure_wipe(otSk.data(), otSk.size());
    return true;
  }

  bool buildPqWithdrawTransaction(const PqWithdrawRequest &req, Transaction &tx, std::string &err)
  {
    const size_t pkBytes = ccx_pq_pubkey_bytes();
    const size_t skBytes = ccx_pq_seckey_bytes();
    if (pkBytes == 0 || skBytes == 0)
    {
      err = "ccx-pqc reports zero ring-sig key size";
      return false;
    }
    const size_t dsaSkBytes = ccx_pq_multisig_seckey_bytes();
    if (dsaSkBytes == 0)
    {
      err = "ccx-pqc reports zero ML-DSA secret-key size";
      return false;
    }

    // ---- validate the request --------------------------------------------------------------------
    if (req.amount == 0)
    {
      err = "deposit principal must be > 0";
      return false;
    }
    if (req.term == 0)
    {
      err = "withdraw term must be > 0 (a deposit has term != 0)";
      return false;
    }
    if (req.requiredSignatureCount == 0 || req.requiredSignatureCount > cn::PQ_MULTISIG_MAX_KEYS)
    {
      err = "invalid requiredSignatureCount";
      return false;
    }
    if (req.signingSecretKeys.size() != req.requiredSignatureCount)
    {
      err = "expected " + std::to_string(static_cast<unsigned>(req.requiredSignatureCount)) +
            " signing secret key(s), got " + std::to_string(req.signingSecretKeys.size());
      return false;
    }
    for (size_t i = 0; i < req.signingSecretKeys.size(); ++i)
    {
      if (req.signingSecretKeys[i].size() != dsaSkBytes)
      {
        err = "signing secret key " + std::to_string(i) + " has wrong size " +
              std::to_string(req.signingSecretKeys[i].size()) + " (expected " + std::to_string(dsaSkBytes) + ")";
        return false;
      }
    }

    // Payout = principal + daemon-credited interest. The withdraw has NO funding input and NO fee:
    // the deposit cell IS the funds, and interest legitimately makes outputs > inputs for a v3 tx
    // (the daemon credits amount + getInterestForInput; the conservation check allows exactly that).
    const uint64_t payout = req.amount + req.interest;
    if (payout < req.amount)
    {
      err = "payout overflow (amount + interest)";
      return false;
    }

    // ---- the deposit-spend input: PqMultisigInput with signatures EMPTY for the hash ------------
    PqMultisigInput in;
    in.amount = req.amount;
    in.signatureCount = req.requiredSignatureCount;
    in.outputIndex = req.outputIndex;
    in.term = req.term; // MUST equal the on-chain output.term — caller copies it from the tracked cell.
    in.signatures.clear();

    // ---- payout output back to the wallet (PqKeyOutput) ------------------------------------------
    PqKeyOutput payoutOut;
    // For a throwaway payout we have no one-time key handy (no PqKeyInput here), so a real KEM key is
    // required to produce a scannable output; the fallback path needs a non-empty key, so guard it.
    if (req.payoutKemPubKey.empty())
    {
      err = "missing payout KEM public key (the withdrawn funds must be sent to a scannable output)";
      return false;
    }
    if (!makePqKeyOutput(req.payoutKemPubKey, std::vector<uint8_t>(), pkBytes, skBytes, payoutOut, err))
    {
      return false;
    }
    TransactionOutput txout;
    txout.amount = payout;
    txout.target = payoutOut;

    // ---- assemble the prefix ---------------------------------------------------------------------
    tx = Transaction();
    tx.version = cn::TRANSACTION_VERSION_4; // PQ tx version on the merged tree (fork owns v3)
    tx.unlockTime = 0;
    tx.inputs.clear();
    tx.inputs.push_back(in);
    tx.outputs.clear();
    tx.outputs.push_back(txout);
    tx.extra.clear();
    tx.signatures.clear();

    // ---- signing hash = getObjectHash(prefix) while PqMultisigInput.signatures is still EMPTY -----
    // Byte-identical to Blockchain::getTransactionPqSigningHash (which clears every inline PQ
    // signature/ringSig before hashing — a signature cannot commit to itself).
    const crypto::Hash signingHash = getObjectHash(static_cast<const TransactionPrefix &>(tx));

    // ---- sign with each of the m ML-DSA-65 secret keys, IN ORDER ---------------------------------
    // check_pq_multisig does a greedy in-order m-of-n match, so the i-th signature must verify under
    // the i-th output key. The caller supplies signingSecretKeys in the SAME order as output.keys.
    std::vector<std::vector<uint8_t>> sigs;
    sigs.reserve(req.requiredSignatureCount);
    const size_t sigCap = ccx_pq_sig_bytes() + 1024; // detached ML-DSA sig is fixed-size; pad defensively
    for (size_t i = 0; i < req.signingSecretKeys.size(); ++i)
    {
      std::vector<uint8_t> sig(sigCap, 0);
      size_t sigLen = sig.size();
      const int32_t rc = ccx_pq_multisig_sign(
          reinterpret_cast<const uint8_t *>(&signingHash), sizeof(signingHash),
          req.signingSecretKeys[i].data(), req.signingSecretKeys[i].size(),
          sig.data(), &sigLen);
      if (rc != 0)
      {
        err = "ccx_pq_multisig_sign failed for key " + std::to_string(i) + " (rc=" + std::to_string(rc) + ")";
        return false;
      }
      sig.resize(sigLen);
      sigs.push_back(std::move(sig));
    }
    boost::get<PqMultisigInput>(tx.inputs[0]).signatures = std::move(sigs);

    return true;
  }
}
