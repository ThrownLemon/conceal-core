// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PqSpendBuilder.h"

#include <algorithm>

#include "CryptoNoteFormatUtils.h" // absolute_output_offsets_to_relative
#include "CryptoNoteTools.h"        // getObjectHash
#include "CryptoNoteConfig.h"       // PQ_MIN/MAX_RING_SIZE, TRANSACTION_VERSION_3
#include "pq_ring_sig.h"            // ccx-pqc FFI

namespace cn
{
  namespace
  {
    // Best-effort zeroisation of a sensitive buffer that the optimiser may not elide. Uses a
    // volatile byte writer so the stores are not dead-code-eliminated. No external dependency.
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
  }

  bool buildPqSpendTransaction(const PqSpendRequest &req, Transaction &tx, std::string &err)
  {
    const size_t pkBytes = ccx_pq_pubkey_bytes();
    if (pkBytes == 0)
    {
      err = "ccx-pqc reports zero public-key size";
      return false;
    }
    const size_t skBytes = ccx_pq_seckey_bytes();
    if (skBytes == 0)
    {
      err = "ccx-pqc reports zero secret-key size";
      return false;
    }

    // ---- validate the request --------------------------------------------------------------------
    if (req.amount == 0 || req.fee >= req.amount)
    {
      err = "amount must be > 0 and fee < amount";
      return false;
    }
    if (req.ring.size() < cn::PQ_MIN_RING_SIZE || req.ring.size() > cn::PQ_MAX_RING_SIZE)
    {
      err = "ring size out of bounds [" + std::to_string(cn::PQ_MIN_RING_SIZE) + "," +
            std::to_string(cn::PQ_MAX_RING_SIZE) + "]";
      return false;
    }
    if (req.kemSecretKey.empty())
    {
      err = "missing KEM secret key";
      return false;
    }

    // ---- sort ring ascending by global index (consensus resolves members in this order) ----------
    std::vector<PqRingMember> ring = req.ring;
    std::sort(ring.begin(), ring.end(),
              [](const PqRingMember &a, const PqRingMember &b) { return a.globalIndex < b.globalIndex; });

    // Reject duplicate / non-increasing indices (a zero relative offset collapses the ring; the
    // validator rejects this too — fail early with a clear message).
    for (size_t i = 1; i < ring.size(); ++i)
    {
      if (ring[i].globalIndex <= ring[i - 1].globalIndex)
      {
        err = "duplicate / non-increasing ring global indices";
        return false;
      }
    }

    // Locate the signer's position in the SORTED ring (this is the index ccx_pq_sign needs).
    size_t signerPos = ring.size();
    for (size_t i = 0; i < ring.size(); ++i)
    {
      if (ring[i].globalIndex == req.signerGlobalIndex)
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

    // ---- assemble the ring blob (sorted key order) + validate key sizes --------------------------
    std::vector<uint8_t> ringBlob;
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

    // ---- recover the signer's one-time keypair by scanning its kemCt -----------------------------
    const PqRingMember &signer = ring[signerPos];
    if (signer.kemCt.empty())
    {
      err = "signer ring member is missing its kemCt (needed to recover the spend key)";
      return false;
    }
    // Validate the KEM secret length before handing it to the FFI scan (defensive: a wrong-size
    // key is a caller bug, and the C ABI should not be asked to read past the buffer).
    const size_t kemSkBytes = ccx_pq_kem_seckey_bytes();
    if (kemSkBytes == 0 || req.kemSecretKey.size() != kemSkBytes)
    {
      err = "KEM secret key has wrong size " + std::to_string(req.kemSecretKey.size()) +
            " (expected " + std::to_string(kemSkBytes) + ")";
      return false;
    }
    uint8_t otSeed[32];
    if (ccx_pq_kem_scan(req.kemSecretKey.data(), req.kemSecretKey.size(),
                        signer.kemCt.data(), signer.kemCt.size(), otSeed, sizeof(otSeed)) != 0)
    {
      secure_wipe(otSeed, sizeof(otSeed));
      err = "KEM scan failed (output not ours / wrong KEM secret)";
      return false;
    }
    std::vector<uint8_t> otPk(pkBytes, 0), otSk(skBytes, 0);
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

    // ---- nullifier (spend tag) -------------------------------------------------------------------
    std::vector<uint8_t> nullifier(ccx_pq_nullifier_bytes(), 0);
    if (ccx_pq_nullifier(otSk.data(), otSk.size(), otPk.data(), otPk.size(),
                         nullifier.data(), nullifier.size()) != 0)
    {
      secure_wipe(otSeed, sizeof(otSeed));
      secure_wipe(otSk.data(), otSk.size());
      err = "nullifier derivation failed";
      return false;
    }

    // ---- input: relative deltas of the sorted absolute indices (inverse of the validator) --------
    std::vector<uint32_t> absIdx;
    absIdx.reserve(ring.size());
    for (const auto &m : ring)
    {
      absIdx.push_back(m.globalIndex);
    }
    PqKeyInput in;
    in.amount = req.amount;
    in.outputIndexes = absolute_output_offsets_to_relative(absIdx);
    in.nullifier = nullifier;
    // in.ringSig deliberately left empty for the signing-hash computation below.

    // ---- output: real recipient (encapsulate) or throwaway (injector parity) ---------------------
    PqKeyOutput out;
    if (!req.recipientKemPubKey.empty())
    {
      std::vector<uint8_t> kemCt(ccx_pq_kem_ct_bytes(), 0);
      uint8_t rSeed[32];
      if (ccx_pq_kem_derive_output(req.recipientKemPubKey.data(), req.recipientKemPubKey.size(),
                                   kemCt.data(), kemCt.size(), rSeed, sizeof(rSeed)) != 0)
      {
        secure_wipe(rSeed, sizeof(rSeed));
        secure_wipe(otSeed, sizeof(otSeed));
        secure_wipe(otSk.data(), otSk.size());
        err = "recipient KEM encapsulation failed";
        return false;
      }
      std::vector<uint8_t> rPk(pkBytes, 0), rSk(skBytes, 0);
      if (ccx_pq_keygen(rSeed, sizeof(rSeed), rPk.data(), rPk.size(), rSk.data(), rSk.size()) != 0)
      {
        secure_wipe(rSeed, sizeof(rSeed));
        secure_wipe(rSk.data(), rSk.size());
        secure_wipe(otSeed, sizeof(otSeed));
        secure_wipe(otSk.data(), otSk.size());
        err = "recipient one-time keygen failed";
        return false;
      }
      out.key = rPk;
      out.kemCt = kemCt;
      // The recipient's one-time secret (rSk) and seed (rSeed) are not needed past this point — the
      // recipient re-derives them from kemCt with their own KEM secret. Wipe our copies now.
      secure_wipe(rSeed, sizeof(rSeed));
      secure_wipe(rSk.data(), rSk.size());
    }
    else
    {
      out.key = otPk; // throwaway recipient (== signer one-time key), empty kemCt — injector parity
    }

    TransactionOutput txout;
    txout.amount = req.amount - req.fee;
    txout.target = out;

    // ---- assemble the prefix ---------------------------------------------------------------------
    tx = Transaction();
    tx.version = cn::TRANSACTION_VERSION_3;
    tx.unlockTime = 0;
    tx.inputs.clear();
    tx.inputs.push_back(in);
    tx.outputs.clear();
    tx.outputs.push_back(txout);
    tx.extra.clear();
    tx.signatures.clear();

    // ---- signing hash = getObjectHash(prefix) while ringSig is still EMPTY ------------------------
    // Identical to Blockchain::getTransactionPqSigningHash (which clears ringSig before hashing).
    const crypto::Hash signingHash = getObjectHash(static_cast<const TransactionPrefix &>(tx));

    // ---- sign ------------------------------------------------------------------------------------
    std::vector<uint8_t> sig(256 * 1024, 0);
    size_t sigLen = sig.size();
    const int32_t rc = ccx_pq_sign(
        reinterpret_cast<const uint8_t *>(&signingHash), sizeof(signingHash),
        ringBlob.data(), ring.size(), pkBytes,
        otSk.data(), otSk.size(), signerPos,
        sig.data(), &sigLen);
    if (rc != 0)
    {
      secure_wipe(otSeed, sizeof(otSeed));
      secure_wipe(otSk.data(), otSk.size());
      err = "ccx_pq_sign failed (rc=" + std::to_string(rc) + ")";
      return false;
    }
    sig.resize(sigLen);
    boost::get<PqKeyInput>(tx.inputs[0]).ringSig = sig;

    // The signer's one-time secret + seed are no longer needed; wipe before returning.
    secure_wipe(otSeed, sizeof(otSeed));
    secure_wipe(otSk.data(), otSk.size());

    return true;
  }
}
