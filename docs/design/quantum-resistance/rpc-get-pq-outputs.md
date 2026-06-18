# RPC: `get_pq_outputs` — PQ output enumeration

**Status:** testnet PoC (CIP-0001). Branch `pqc/get-pq-outputs-rpc` off `pqc/testnet-poc`.

## Purpose

A read-only JSON-RPC method that enumerates the spendable post-quantum
(`PqKeyOutput`) outputs the daemon has indexed for a given set of amounts, so a
wallet can assemble a PQ ring (the ring members for a `PqKeyInput`).

It is a faithful read-only projection of the in-memory `m_pqOutputs` index
(`Blockchain`), the same index that `check_pq_tx_input` resolves ring members
against. **It changes no consensus, validation, builder, or serialization
logic.** It only walks an existing index and reports it.

## Transport

- JSON-RPC 2.0 method registered in `RpcServer`'s `jsonRpcHandlers` map.
- Registered method name (the string clients call): **`get_pq_outputs`**.
- `allowBusyCore = false` (the index is only meaningful once the core is synced),
  matching the other output-enumeration handlers.

## Request

```json
{ "amounts": [<uint64>, ...] }
```

`amounts` is the list of denominations to enumerate. For each amount the daemon
returns every indexed PQ output (not a random subset), because the wallet needs
the full candidate set to choose ring members and locate its own output's global
index.

## Response

```json
{
  "outs": [
    {
      "amount": <uint64>,
      "outs": [
        {
          "global_index": <uint32>,   // position in m_pqOutputs[amount]
          "key":      "<hex>",        // PqKeyOutput.key  (PQ one-time public key)
          "kem":      "<hex>",        // PqKeyOutput.kemCt (ML-KEM ciphertext)
          "tx_hash":  "<hex>",        // hash of the containing transaction
          "height":   <uint32>,       // block height of that transaction
          "spendable": <bool>         // is_tx_spendtime_unlocked(unlockTime)
        }
      ]
    }
  ],
  "status": "OK"
}
```

- `global_index` is the vector position inside `m_pqOutputs[amount]`; it is the
  absolute offset a `PqKeyInput.outputIndexes` (relative-encoded) ring member
  resolves to. This is the value the wallet uses to reference a ring member.
- `key` / `kem` are hex of the raw `std::vector<uint8_t>` fields, via
  `common::toHex`.
- `tx_hash` is hex of `crypto::Hash` via `common::podToHex`.
- `spendable` reflects only the unlock-time gate; the caller still applies its own
  ring-selection policy. An amount with no indexed PQ outputs yields an empty
  `outs` list (not an error).

## Plumbing

Mirrors the existing `getOutByMSigGIndex` path, top to bottom:

| Layer | Symbol |
|-------|--------|
| Command def | `COMMAND_RPC_GET_PQ_OUTPUTS` (`src/Rpc/CoreRpcServerCommandsDefinitions.h`) |
| Shared POD | `cn::PqOutputEntry` (`src/CryptoNoteCore/ICore.h`) |
| Interface | `ICore::getPqOutputs(uint64_t, std::vector<PqOutputEntry>&)` |
| Core | `core::getPqOutputs` → `m_blockchain.getPqOutputs` |
| Blockchain | `Blockchain::getPqOutputs` — locks `m_blockchain_lock`, walks `m_pqOutputs[amount]`, extracts each `PqKeyOutput` via `transactionByIndex(...).tx.outputs[outInTx].target` |
| RPC handler | `RpcServer::on_get_pq_outputs` — hex-encodes and fills the response |

`PqOutputEntry` carries raw bytes (`std::vector<uint8_t>` key/kemCt,
`crypto::Hash` txHash); hex encoding happens only at the RPC boundary, keeping the
core interface byte-exact.

## Notes / limits

- The index is the PoC in-memory, forward-only `m_pqOutputs` (no reorg rewind of
  the PQ index beyond what the surrounding PoC already does); this RPC inherits
  those PoC properties unchanged.
- Read-only and non-`const` only because it reuses `is_tx_spendtime_unlocked`,
  which is a non-`const` member; it performs no mutation.
- Unbounded by design for the PoC: it returns the full per-amount set. A
  production version would page or cap results.
