// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>

#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/NewOutputTypes.h"
#include "pq_ring_sig.h" // ccx-pqc FFI: ccx_pq_pubkey_bytes / _is_canonical / _kem_ct_bytes

namespace cn
{

  class check_tx_outputs_visitor : public boost::static_visitor<bool>
  {
  public:
    check_tx_outputs_visitor(const Transaction &tx, uint32_t height, uint64_t amount,
                             const Currency &currency, std::string &error)
        : m_tx(tx), m_height(height), m_amount(amount),
          m_currency(currency), m_error(error) {}

    bool operator()(const KeyOutput &out) const
    {
      if (m_amount == 0)
      {
        m_error = "zero amount output";
        return false;
      }
      if (!check_key(out.key))
      {
        m_error = "output with invalid key";
        return false;
      }
      return true;
    }

    bool operator()(const MultisignatureOutput &out) const
    {
      if (m_tx.version < TRANSACTION_VERSION_2)
      {
        m_error = "contains multisignature output but has version ";
        m_error += std::to_string(m_tx.version);
        return false;
      }
      if (!m_currency.validateOutput(m_amount, out, m_height))
      {
        m_error = "contains invalid multisignature output";
        return false;
      }
      if (out.requiredSignatureCount > out.keys.size())
      {
        m_error = "contains multisignature with invalid required signature count";
        return false;
      }
      if (std::any_of(out.keys.begin(), out.keys.end(),
                      [](const crypto::PublicKey &key)
                      { return !check_key(key); }))
      {
        m_error = "contains multisignature output with invalid public key";
        return false;
      }
      return true;
    }

    bool operator()(const StandardPaymentOutput &out) const
    {
      if (m_amount == 0)
      {
        m_error = "zero amount standard payment output";
        return false;
      }
      if (!check_key(out.key))
      {
        m_error = "standard payment output with invalid key";
        return false;
      }
      return true;
    }

    bool operator()(const MultisigPaymentOutput &out) const
    {
      if (m_tx.version < TRANSACTION_VERSION_3)
      {
        m_error = "contains multisig payment output but has version ";
        m_error += std::to_string(m_tx.version);
        return false;
      }
      if (out.num_keys > out.keys.size())
      {
        m_error = "multisig payment output with invalid key count";
        return false;
      }
      if (std::any_of(out.keys.begin(), out.keys.end(),
                      [](const crypto::PublicKey &key)
                      { return !check_key(key); }))
      {
        m_error = "multisig payment output with invalid public key";
        return false;
      }
      if (out.isTimeLocked() && out.term == 0)
      {
        m_error = "time-locked multisig payment output with zero term";
        return false;
      }
      return true;
    }

    bool operator()(const DomainRegistrationOutput &out) const
    {
      // Domain registrations are non-spendable outputs.
      // Validate basic structure: domain must be non-empty, tier 1-3.
      if (out.domain.empty())
      {
        m_error = "domain registration with empty domain name";
        return false;
      }
      if (out.tier < 1 || out.tier > 3)
      {
        m_error = "domain registration with invalid tier";
        return false;
      }
      return true;
    }

    bool operator()(const DomainDeletionOutput &out) const
    {
      // Domain deletions are non-spendable outputs.
      // Validate basic structure: domain must be non-empty.
      if (out.domain.empty())
      {
        m_error = "domain deletion with empty domain name";
        return false;
      }
      return true;
    }

    // ---- Post-quantum (CIP-0001) outputs (tags 0x08/0x09) ----
    bool operator()(const PqKeyOutput &out) const
    {
      if (m_amount == 0)
      {
        m_error = "zero amount PQ output";
        return false;
      }
      // Validate the ring-sig public key at the consensus boundary (never trust external bytes).
      // Without this a tx could create a PqKeyOutput with arbitrary `key` bytes: consensus-valid and
      // indexed in m_pqOutputs, but unspendable — an attacker can flood the PQ amount bucket with
      // malformed outputs, shifting global indices and breaking wallet ring assembly (liveness DoS).
      // ccx_pq_pubkey_is_canonical enforces the exact ccx_pq_pubkey_bytes() length + canonical mod-q
      // re-encode equality.
      if (out.key.size() != ccx_pq_pubkey_bytes())
      {
        m_error = "PQ output key wrong size";
        return false;
      }
      if (ccx_pq_pubkey_is_canonical(out.key.data(), out.key.size()) != 1)
      {
        m_error = "PQ output key not canonical";
        return false;
      }
      // kemCt is optional (coinbase / injector outputs carry none and are simply unscannable), but if
      // present it must be the exact KEM-ciphertext length so a malformed one can't be indexed.
      if (!out.kemCt.empty() && out.kemCt.size() != ccx_pq_kem_ct_bytes())
      {
        m_error = "PQ output kemCt wrong size";
        return false;
      }
      return true;
    }

    // PQ deposit output: requires PQ tx version (v4 on this merged tree — fork owns v3), enforces the
    // IDENTICAL term band + depositMinAmount as the Ed25519 MultisignatureOutput path via the Currency.
    bool operator()(const PqMultisigOutput &out) const
    {
      if (m_tx.version < TRANSACTION_VERSION_4)
      {
        m_error = "contains PQ multisignature output but tx version is less than 4";
        return false;
      }
      if (!m_currency.validateOutput(m_amount, out, m_height))
      {
        m_error = "contains invalid PQ multisignature output";
        return false;
      }
      if (out.dsaSchemeId != PQ_DSA_SCHEME_ID)
      {
        m_error = "contains PQ multisignature output with unsupported DSA scheme id";
        return false;
      }
      if (out.requiredSignatureCount == 0 || out.requiredSignatureCount > out.keys.size())
      {
        m_error = "contains PQ multisignature with invalid required signature count";
        return false;
      }
      if (out.keys.size() > PQ_MULTISIG_MAX_KEYS)
      {
        m_error = "contains PQ multisignature output with too many keys";
        return false;
      }
      // M-new-8 (audit): every deposit public key must be the exact ML-DSA pubkey length, mirroring the
      // PqKeyOutput key-length check above. Without it a wrong-length key passes output validation, is
      // indexed as a PQ multisig output, and only fails on spend (ccx_pq_multisig_pubkey_bytes mismatch)
      // — i.e. funds burned into an unspendable cell. check_pq_multisig assumes this earlier check ran.
      for (size_t ki = 0; ki < out.keys.size(); ++ki)
      {
        if (out.keys[ki].size() != ccx_pq_multisig_pubkey_bytes())
        {
          m_error = "contains PQ multisignature output with wrong-length public key";
          return false;
        }
      }
      return true;
    }

  private:
    const Transaction &m_tx;
    uint32_t m_height;
    uint64_t m_amount;
    const Currency &m_currency;
    std::string &m_error;
  };

} // namespace cn
