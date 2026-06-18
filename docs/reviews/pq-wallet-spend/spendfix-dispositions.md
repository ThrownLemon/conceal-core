# Wallet-native PQ spend — consolidated reviewer-fix dispositions

Branch `pqc/spendfix` (off `pqc/testnet-poc` HEAD `744f331`). All changes here are
**non-consensus robustness fixes**. Three reviewers independently confirmed the
signing-hash / ring-order / nullifier / money-conservation contract in
`PqSpendBuilder` and the validator is byte-correct, so that logic and the
consensus validator are **deliberately untouched**. `pq_injector` (the A/B parity
oracle) is also untouched.

Reviewer inputs consolidated: CodeRabbit (`coderabbit.txt`), Codex (`codex.md`),
Gemini (`gemini.txt`), GLM (`glm.txt`).

## Per-fix disposition

### FIX A — check both RPC statuses (HIGH) — DONE
`src/Rpc/PqSpendClient.cpp`. After `get_pq_outputs` we now reject unless
`gres.status == CORE_RPC_STATUS_OK`. After `/sendrawtransaction` we reject unless
`rres.status == CORE_RPC_STATUS_OK`, setting `err = "relay rejected: " + rres.status`.
Previously a rejected relay returned `true` (false success) — the HIGH finding.

### FIX B — random signer + decoy selection (anonymity + deadlock) — DONE
`src/Rpc/PqSpendClient.cpp`. Replaced the hardcoded `signer = spendable[0]` /
`ring = first ringSize` selection with an attempt loop (up to `min(8, #spendable)`):
each attempt picks a **random** not-yet-tried signer + **random** `ringSize-1`
distinct decoys, builds, relays, and returns on an OK relay; on build/relay failure
it advances to a different signer. Randomness uses the project CSPRNG
(`generate_random_bytes` from `crypto/random.h`, rejection-sampled to avoid modulo
bias) — **not** `std::mt19937` (same lesson as the wallet KDF). Fixes the
permanent-failure-on-already-spent wedge and the trivially-linkable ring/signer
position across spends.

### FIX C — get_pq_outputs DoS + bounds — DONE
- `src/CryptoNoteConfig.h`: added non-consensus RPC caps
  `PQ_GET_OUTPUTS_MAX_AMOUNTS = 64` and `PQ_GET_OUTPUTS_MAX_PER_AMOUNT = 1000`
  (clearly commented as RPC-only, NOT consensus).
- `src/Rpc/RpcServer.cpp` `on_get_pq_outputs`: reject before the locked walk when
  `req.amounts.size() > PQ_GET_OUTPUTS_MAX_AMOUNTS`; cap entries per amount at
  `PQ_GET_OUTPUTS_MAX_PER_AMOUNT` (lowest global indices, which `getPqOutputs`
  already returns first) and set a new `truncated` flag on the response bucket.
- `src/CryptoNoteCore/Blockchain.cpp` `getPqOutputs`: bounds-check the
  `TransactionIndex` (`idx.block < m_blocks.size()` and
  `idx.transaction < m_blocks[idx.block].transactions.size()`) before
  `transactionByIndex(idx)`; on a stale/corrupt entry it logs and `continue`s
  rather than dereferencing blindly. Whole walk stays under `m_blockchain_lock`.
- `src/Rpc/CoreRpcServerCommandsDefinitions.h`: added `bool truncated = false`
  to `outs_for_amount` (backward-compatible KV field).

### FIX D — no silent burn — DONE
`src/ConcealWallet/ConcealWallet.cpp` (`pq_transfer`) and
`src/PaymentGate/WalletService.cpp` (`sendPqTransaction`) now pass
`recipientKemPubKey = cn::PQ_TESTNET_KEM_PK` (from `pq_testnet_kem_keypair.h`), so
the spend output is a real, scannable, re-spendable stealth output to the testnet
identity instead of a throwaway whose one-time secret is discarded (destroyed
funds). `pq_injector`'s empty-recipient throwaway path is unchanged (parity oracle).
CLI help text + inline comments updated to drop "throwaway"; the
`pqSpendViaDaemon` doc comment in `PqSpendClient.h` now states the empty-key path
is injector-only.

### FIX E — builder input guards + secret hygiene — DONE
`src/CryptoNoteCore/PqSpendBuilder.cpp`.
- Guard `skBytes = ccx_pq_seckey_bytes()` for zero and use `skBytes` to size `otSk`
  / `rSk` (was `ccx_pq_seckey_bytes()` inline).
- Validate `req.kemSecretKey.size() == ccx_pq_kem_seckey_bytes()` before
  `ccx_pq_kem_scan` (clear error on mismatch).
- Added a file-local `secure_wipe(void*, size_t)` (volatile byte writer, no new
  dependency) and call it on `otSeed`, `otSk`, `rSeed`, `rSk` before **every**
  return after those buffers hold secrets — both the success path and the
  post-population early-return error paths.

### FIX F — front-end polish — DONE
- `src/ConcealWallet/ConcealWallet.cpp` `pq_balance`: relabelled to
  "unlocked PQ outputs" (the daemon returns unlock-spendable, not unspent-by-you),
  and guarded the `count * amount` product against `uint64` overflow before
  `formatAmount` (prints `(overflow)` instead of wrapping). Handler help text
  aligned ("unlocked" not "spendable").
- `tests/UnitTests/ICoreStub.h` `getPqOutputs` override: now returns `true` with
  `outs` cleared (unknown amount = success + empty, matching Core) instead of
  `false`.

## Explicitly NOT changed (per the contract)
- `PqSpendBuilder` signing-hash / ring-order / nullifier math.
- The consensus PQ-input validator in `Blockchain.cpp` (`check_pq_tx_input`).
- `pq_injector` (the A/B parity oracle, including its empty-recipient throwaway).
