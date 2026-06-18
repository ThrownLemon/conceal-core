# PQ Deposits — ML-DSA-65 Implementation Report (CIP-0001)

Status: **IMPLEMENTED on the worktree branch (testnet-gated, mainnet-sentinel-gated).**
Built + tested on the WSL x86_64 host. Money-critical consensus code — left for human review,
NOT pushed to the fork.

Implements the blueprint `docs/design/quantum-resistance/deposits-mldsa.md` exactly: a dedicated
`PqMultisigInput`/`PqMultisigOutput` variant pair (tag **0x5**, `BLOCK_MAJOR_VERSION_9` /
`UPGRADE_HEIGHT_V9`) that is a faithful PQ analogue of the Ed25519 deposit path — only the signature
primitive is swapped to ML-DSA-65 (FIPS 204, `dilithium3`). Term / interest / lock / double-spend
semantics are byte-identical; the only crypto change is `crypto::check_signature` →
`ccx_pq_multisig_verify`.

---

## 1. What was built

### FFI (`pqc/ccx-pqc/src/lib.rs`, `pqc/include/pq_ring_sig.h`)
New ML-DSA-65 (dilithium3) DETACHED-signature C-ABI, distinct from the experimental lattice ring sig:

| Function | Purpose |
|---|---|
| `ccx_pq_multisig_pubkey_bytes()` | dilithium3 public-key length (deposit key length) |
| `ccx_pq_multisig_seckey_bytes()` | dilithium3 secret-key length |
| `ccx_pq_sig_bytes()` | dilithium3 detached-signature length (deposit sig length) |
| `ccx_pq_multisig_keypair(...)` | RNG keypair (injector / tests; daemon never calls it) |
| `ccx_pq_multisig_sign(msg, sk, ...)` | detached sign over the prefix hash |
| `ccx_pq_multisig_verify(msg, pk, sig)` | detached verify; returns 0 iff valid |
| `ccx_pq_multisig_selftest()` | roundtrip + tamper / wrong-key / wrong-message reject |

Detached signatures keep the sig fixed-size and the message un-embedded — the daemon verifies against
the supplied prefix hash. The dilithium3 primitive is the standardized NIST scheme used as-is (no
ring, no nullifier).

### Types + serialization
- `include/CryptoNote.h`: `PqMultisigInput { amount, signatureCount, outputIndex, term, signatures }`
  and `PqMultisigOutput { keys, requiredSignatureCount, term }`, appended to both variants
  (`TransactionInput`, `TransactionOutputTarget`) — append-only, tag **0x5**.
- `CryptoNoteSerialization.cpp`: tag 0x5 in `BinaryVariantTagGetter` + both `getVariantValue`
  dispatches; `getSignaturesCount(PqMultisigInput) == 0` (inline sigs, like `PqKeyInput`);
  `serialize(PqMultisigInput/Output)` using a bounded `beginArray` helper; block-header version cap
  bumped to `BLOCK_MAJOR_VERSION_9`.

### Config (`CryptoNoteConfig.h`)
- `BLOCK_MAJOR_VERSION_9 = 9`.
- `UPGRADE_HEIGHT_V9 = 5000000` — a far-future **sentinel** well past the last hardcoded checkpoint
  (~2,070,000), so PQ deposits never auto-activate on mainnet and are never auto-trusted in the
  checkpoint zone until audited.
- `TESTNET_UPGRADE_HEIGHT_V9 = 80` — testnet PoC activation (after the existing PoC PQ activation).
- `PQ_MULTISIG_MAX_KEYS = 16` — bounds the attacker-controlled key/sig arrays.
- `Currency` wires `m_upgradeHeightV9` (builder + mainnet/testnet defaults + `upgradeHeight(BLOCK_MAJOR_VERSION_9)`).

### Validation (`Blockchain.{h,cpp}`)
- `check_pq_multisig()` — a line-for-line port of `validateInput(MultisignatureInput)` with the
  primitive swapped (see §2). Wired into the `checkTransactionInputs` switch, gated by checkpoint zone,
  advancing `inputIndex` like `PqKeyInput` (mixed-input alignment).
- `getTransactionPqSigningHash()` extended to also clear inline `PqMultisigInput.signatures` before
  hashing (a signature cannot commit to itself).
- `check_tx_outputs_visitor::operator()(PqMultisigOutput)` — v3 + `validateOutput` + `m in [1,n]`.
- Height gate in `pushBlock` rejects any tx containing a PQ multisig variant below `UPGRADE_HEIGHT_V9`.

### Index, reorg, mempool
- `m_pqMultisigOutputs` (`MultisignatureOutputsContainer`, mirror of `m_multisignatureOutputs`) with
  per-cell `isUsed`. Push / mark / pop / clear-isUsed are symmetric with the Ed25519 path; persisted in
  the on-disk index (`pq_multisig_outputs`) and rebuilt on initial scan (`rebuildCache`).
- Mempool: a dedicated `m_spentPqDeposits` `(amount, outputIndex)` set for in-pool conflict rejection,
  plus `checkMultisignatureInputsDiff` extended to catch intra-tx duplicate deposit cells.

### Interest / amount accounting (`Currency.{h,cpp}`, `CryptoNoteFormatUtils.cpp`, `TransactionUtils.cpp`, `CryptoNoteTools.cpp`)
- `input_amount_visitor::operator()(PqMultisigInput)`, `getInterestForInput(PqMultisigInput)`,
  `calculateTotalTransactionInterest`, `get_inputs_money_amount`, `getTransactionInputAmount` (both the
  Currency visitor and the legacy free helper), `getInputAmount`/`getInputsAmounts` — all dispatch the
  new variant identically to the Ed25519 `MultisignatureInput`, producing byte-identical values.
- `Currency::validateOutput(PqMultisigOutput)` — identical term band + `depositMinAmount` rules.

---

## 2. How each CRITICAL risk is handled

### (1) Interest minting — `input.term` BOUND to `output.term` before interest

`check_pq_multisig` (Blockchain.cpp) — the term bind is the same line as the Ed25519 path, executed
*before* any interest is ever computed:

```cpp
    if (input.signatureCount != output.requiredSignatureCount) { ... return false; }

    // BIND the input's term to the on-chain output's term BEFORE any interest is computed. This is
    // the interest-minting safety guarantee: input_amount_visitor derives interest from input.term,
    // and output.term has already passed validateOutput's term band — so an attacker cannot mint
    // arbitrary interest by declaring a larger term than the deposit actually has.
    if (input.term != output.term)
    {
      logger(DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input with invalid term.";
      return false;
    }
```

Interest is then derived from `input.term` (now == validated `output.term`) by the **same**
`calculateInterest(amount, term, lockHeight)` used by the Ed25519 path:

```cpp
  uint64_t Currency::getInterestForInput(const PqMultisigInput &input, uint32_t height) const
  {
    uint32_t lockHeight = height - input.term;
    if (height == m_blockWithMissingInterest) { lockHeight = height; }
    return calculateInterest(input.amount, input.term, lockHeight);
  }
```

Unit test `PqDepositCurrencyTest.InputAmountParityWithEd25519` asserts the PQ deposit value EQUALS the
Ed25519 deposit value for the same amount/term across the full multiplier-band height set, and
`TotalTransactionInterestParity` asserts the same for `calculateTotalTransactionInterest`.

### (2) Reorg index corruption — symmetric push/pop of `m_pqMultisigOutputs` + `isUsed`

Push (output indexed `isUsed=false`) in `pushTransaction`, mark `isUsed=true` in the separate input
loop, and the **symmetric** unwind in `popTransaction`:

```cpp
      else if (output.target.type() == typeid(PqMultisigOutput))
      {
        // REORG SYMMETRY (CRITICAL): pop the PQ deposit cell from m_pqMultisigOutputs exactly the way
        // the MultisignatureOutput branch above pops m_multisignatureOutputs — same consistency
        // guards, same isUsed check, same LIFO order. An asymmetric pop corrupts the deposit index on
        // a reorg (the PoC hit this class of bug for m_pqOutputs, fixed in commit 4af0ec2).
        auto amountOutputs = m_pqMultisigOutputs.find(output.amount);
        ...
        if (amountOutputs->second.back().isUsed) { ...continue; }
        if (amountOutputs->second.back().transactionIndex.block != transactionIndex.block || ...) { ...continue; }
        if (amountOutputs->second.back().outputIndex != transaction.outputs.size() - 1 - outputIndex) { ...continue; }
        amountOutputs->second.pop_back();
        if (amountOutputs->second.empty()) { m_pqMultisigOutputs.erase(amountOutputs); }
      }
```

and the spent-flag is cleared on the input side of `popTransaction`:

```cpp
      else if (input.type() == typeid(PqMultisigInput))
      {
        // REORG SYMMETRY (CRITICAL): clear the spent flag on the PQ deposit cell exactly the way the
        // MultisignatureInput branch does, so a rolled-back spend frees the cell for re-spend after a
        // reorg. Asymmetry here would wedge a legitimate deposit (cell stuck isUsed=true forever).
        const PqMultisigInput &in = ::boost::get<PqMultisigInput>(input);
        auto &amountOutputs = m_pqMultisigOutputs[in.amount];
        if (!amountOutputs[in.outputIndex].isUsed) { logger(ERROR,...) << "...not marked as used."; }
        amountOutputs[in.outputIndex].isUsed = false;
      }
```

`rebuildCache` repopulates both the deposit cells (output loop) and the `isUsed` flags (input loop),
and the index is persisted (`pq_multisig_outputs`) so a restart keeps spent cells spent.

### (3) Deposit-lock bypass — `block + term > height`, ported byte-for-byte

```cpp
    // DEPOSIT LOCK (ported byte-for-byte): a deposit (term != 0) cannot be spent until its term has
    // fully elapsed since the block that created it. Off-by-one here allows early withdrawal and
    // over-credits interest, so the comparison must match the Ed25519 path exactly.
    if (output.term != 0 && outputIndex.transactionIndex.block + output.term > getCurrentBlockchainHeight())
    {
      logger(DEBUGGING) << "Transaction << " << transactionHash << " contains PQ multisignature input that spends locked deposit output";
      return false;
    }
```

### (4) DoS — bounded length-prefixed arrays + exact lengths

`serialize` bounds the array count to `PQ_MULTISIG_MAX_KEYS` *before* `resize` on the INPUT path:

```cpp
void serializePqMultisigArray(std::vector<std::vector<uint8_t>>& items, cn::ISerializer& s, common::StringView name) {
  size_t n = items.size();
  s.beginArray(n, name);
  if (s.type() == cn::ISerializer::INPUT) {
    if (n > cn::PQ_MULTISIG_MAX_KEYS) { throw serialization_error("PQ multisig array exceeds PQ_MULTISIG_MAX_KEYS"); }
    items.resize(n);
  }
  ...
}
```

`check_outs_valid` re-checks `keys.size() in [1, PQ_MULTISIG_MAX_KEYS]`, `m in [1,n]`, and every key
length `== ccx_pq_multisig_pubkey_bytes()`. `check_pq_multisig` re-checks the key length at the verify
boundary so a corrupt index can never reach the FFI with a wrong-length buffer.

### Coinbase height-gate (review finding — FIXED)
The Codex pre-PR review found a HIGH issue: the per-tx height gate in `pushBlock` only iterates the
non-coinbase `transactions[i]`, so a hand-crafted pre-V9 **coinbase** could mint a `PqMultisigOutput`
deposit cell (spendable after V9). Fixed by also gating `blockData.baseTransaction` before it is pushed:

```cpp
    // HEIGHT GATE (CIP-0001 UPGRADE_HEIGHT_V9) for the COINBASE: the per-tx gate below only covers
    // non-coinbase transactions, so guard the miner tx here too — otherwise a hand-crafted pre-V9
    // coinbase could mint a PqMultisigOutput deposit cell that becomes spendable after V9. ...
    if (transactionContainsPqMultisig(blockData.baseTransaction) &&
        static_cast<uint32_t>(m_blocks.size()) < m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_9))
    {
      ... bvc.m_verification_failed = true; return false;
    }
```
A genuine coinbase never carries one (`constructMinerTx` emits only KeyOutput/PqKeyOutput), so this
only rejects malicious blocks. Codex confirmed interest-minting, reorg symmetry, signing hash,
deposit-lock/double-spend, and DoS bounds are all clean.

### Mixed-input `tx.signatures` alignment
`getSignaturesCount(PqMultisigInput) == 0` (inline sigs), and the switch branch advances `inputIndex`
exactly like `PqKeyInput`, so a mixed `KeyInput + PqMultisigInput` tx reads the correct signature slot.

### Self-reference of inline signatures
The signed message is `getTransactionPqSigningHash(tx)` — the prefix with every inline
`PqMultisigInput.signatures` (and `PqKeyInput.ringSig`) cleared, so a signature never commits to
itself. The signer (injector / future wallet) must compute the identical hash.

---

## 3. Test results

Built on the WSL x86_64 host (Mac arm64 cannot build). Rust lib + CryptoNoteCore + Daemon + UnitTests
all compile clean (only pre-existing deprecation warnings).

`ctest -R UnitTests` (with the repo's baked-in skip filter): **1 test PASSED, 0 failed (66.67 s)**.
Full gtest run: **1007 / 1007 tests pass** (88 suites), including the 11 new PQ deposit tests.

New tests (`tests/UnitTests/TestPqDeposits.cpp`):

| Test | Covers |
|---|---|
| `PqDepositPrimitive.SelftestPasses` | FFI selftest ok=1 (roundtrip + tamper/wrong-key/wrong-msg) |
| `PqDepositPrimitive.SignVerifyRoundtripAndRejections` | direct sign/verify + tamper + wrong-key + wrong-message reject |
| `PqDepositSerialization.InputRoundtrip` | PqMultisigInput binary in→out→in equality |
| `PqDepositSerialization.OutputRoundtrip` | PqMultisigOutput binary in→out→in equality |
| `PqDepositSerialization.OversizedInputArrayRejected` | sig array > PQ_MULTISIG_MAX_KEYS rejected at boundary |
| `PqDepositSerialization.OversizedOutputArrayRejected` | key array > PQ_MULTISIG_MAX_KEYS rejected at boundary |
| `PqDepositCurrencyTest.InputAmountParityWithEd25519` | PQ deposit value == Ed25519 deposit value (amount + interest) |
| `PqDepositCurrencyTest.NonDepositInputIsPrincipalOnly` | term==0 ⇒ principal only |
| `PqDepositCurrencyTest.TotalTransactionInterestParity` | calculateTotalTransactionInterest parity |
| `PqDepositCurrencyTest.ValidateOutputParityTermBand` | term band accept/reject parity with Ed25519 |
| `PqDepositCurrencyTest.ValidateOutputParityMinAmount` | depositMinAmount accept/reject parity |

Rust selftest (`ccx_pq_multisig_selftest`) also runs in isolation (ok=1).

---

## 3a. Pre-PR review outcomes (CodeRabbit + Codex + GLM)

- **CodeRabbit** (`coderabbit review --plain -t all`): **no findings**.
- **Codex** (critical pass on interest/reorg/signing-hash/lock/DoS): one **HIGH** — the coinbase
  height-gate gap (fixed, §2 "Coinbase height-gate"). Explicitly confirmed CLEAN: interest minting,
  reorg index symmetry, signing hash + mixed-input alignment, deposit-lock/double-spend, DoS bounds.
- **GLM** (`openrouter/z-ai/glm-5`): all 5 critical paths **CORRECT** (term binding, reorg symmetry,
  signing-hash self-reference, deposit-lock + double-spend parity, serialization DoS bounds). One
  valid hygiene finding — the block-template builder (`TransactionPool.cpp` `BlockTemplate`) shared the
  `(amount, outputIndex)` keyspace between PQ and Ed25519 deposit cells; **fixed** by giving it a
  separate `m_usedPqDeposits` set (a same-numbered cell in both indexes would otherwise have benignly
  deferred one tx to a later block template — never a consensus error). GLM's two other notes were
  false positives (the `m_spentPqDeposits`/`m_spentOutputs` separation it then calls correct, and a
  misread of the pre-existing Ed25519 `isUsed=false` line as an addition — verified pre-existing in
  the base commit).

> **Build status of the two post-review fixes (coinbase gate + block-template set):** the WSL build
> host became unreachable (Tailscale SSH re-auth required, interactive) after the main build, so these
> two small follow-up edits are **not yet recompiled on the remote**. Both use only already-compiled
> symbols (`transactionContainsPqMultisig`, `upgradeHeight`, a new `std::set` of the existing type).
> Re-run `make -j4 CryptoNoteCore UnitTests` + `ctest -R UnitTests` once the host is reachable to
> confirm. The pre-fix tree (everything except these two edits) built clean and passed 1007/1007.

## 4. Deferred / follow-up (precisely scoped)

- **Chain-level CoreTests for PQ deposits** (spend after lock, reject early withdrawal at `term-1`,
  accept at `term`, double-spend via reused outputIndex, deep reorg across a deposit create+spend leaves
  the index/isUsed clean, pre-gate height reject, version<3 reject). These require a **PQ-aware
  `tests/CoreTests/TransactionBuilder`** (ML-DSA keygen/sign) mirroring `tests/CoreTests/Deposit.cpp`
  (988 lines, Ed25519-specific). The consensus logic for all of these is a line-for-line port of the
  Ed25519 path already covered by `Deposit.cpp` (only the primitive differs), so the unit tests above
  cover the *divergent* surface; the chain-level harness is the recommended next step, matching how the
  PoC deferred ring-sig chain coverage to the end-to-end testnet runner.
- **End-to-end testnet deposit injector** (`pqc/tools/pq_deposit_injector.cpp`): build a v3 tx with a
  `PqMultisigOutput` deposit, mine past `term`, spend with m `ccx_pq_multisig_sign` sigs over the prefix
  hash, observe interest credited. Mirrors `pqc/run-poc-testnet.sh`. Not built here.
- **Wallet integration** (`concealwallet` deposit create/withdraw with ML-DSA keypairs) — follow-up,
  out of the consensus scope (the injector stands in, as in the PoC).
- **Block-explorer RPC** (`BlockchainExplorerDataBuilder`) returns `false` for PQ-multisig txs (the same
  safe behaviour it already has for `PqKeyInput`/`PqKeyOutput`) — full PQ explorer support deferred.
- **Mainnet activation** stays disabled (`UPGRADE_HEIGHT_V9` far-future sentinel) until the ML-DSA
  deposit *integration* (detached-sig handling, constant-time, side channels) is audited (CIP-0001 C1).
  The dilithium3 primitive is production-grade; the integration is unaudited.

---

## 5. Risk note (consensus / money / crypto)

All edits are testnet-gated (height gate + testnet block allowance) and the mainnet height is a
sentinel past the last checkpoint, so this **cannot** affect mainnet consensus until a deliberate,
audited fork lowers `UPGRADE_HEIGHT_V9`. The serialization tag (0x5) is append-only; an old daemon
rejects v3 PQ-multisig txs as an unknown variant tag. Interest and reorg paths are byte-identical ports
of the audited Ed25519 deposit logic with only the signature primitive swapped. Left for human review;
**not** pushed to the fork.
