# PQ Deposits Migration — ML-DSA-65 (Blueprint)

Status: **DESIGN / advisory only.** No source edited. Grounds every claim in the real
`pqc/testnet-poc` branch code (cited `file:line`). Testnet-gated + height-gated throughout.
This is consensus + money + crypto code: a bug forks the chain or mints money.

Scope: migrate Conceal's **on-chain deposits** (term deposits / "banking") to post-quantum.
Today a deposit is an Ed25519 `MultisignatureOutput` (the deposit cell) spent by a
`MultisignatureInput` carrying `term`, with interest paid at spend. Ed25519 is Shor-broken,
so the deposit's spend authorization (the m-of-n signatures over the prefix hash) is the
quantum-vulnerable surface. The deposit *amount + term + interest* accounting is plain integer
math and is **not** crypto — it can stay byte-for-byte identical.

---

## 1. How deposits work today (real code)

### Types (`include/CryptoNote.h:26-41`)
```cpp
struct MultisignatureInput  { uint64_t amount; uint8_t signatureCount; uint32_t outputIndex; uint32_t term; };
struct MultisignatureOutput { std::vector<crypto::PublicKey> keys; uint8_t requiredSignatureCount; uint32_t term; };
```
A deposit is just a `MultisignatureOutput` with `term != 0` (and `amount >= depositMinAmount`).
A plain (non-deposit) multisig has `term == 0`. The variants live in the boost::variant
`TransactionInput` / `TransactionOutputTarget` (`include/CryptoNote.h:55-57`) — the PoC already
appended `PqKeyInput` / `PqKeyOutput` there.

### Serialization (`src/CryptoNoteCore/CryptoNoteSerialization.cpp`)
- Tag bytes: `KeyInput/Output=0x2`, `Multisig=0x3`, `Pq=0x4`
  (`BinaryVariantTagGetter`, lines 59-63; `getVariantValue` dispatch, 78-130).
- `serialize(MultisignatureInput)` 280-285, `serialize(MultisignatureOutput)` 329-333.
- Signatures: `getSignaturesCount` returns `signatureCount` for a multisig input
  (`CryptoNoteSerialization.cpp:48`) — i.e. the m signatures live in `tx.signatures[inputIndex]`.
  PQ inputs return 0 (`:49`) and carry their proof *inline* in the input, advancing no signature slot.

### Validation (`src/CryptoNoteCore/Blockchain.cpp`)
- `checkTransactionInputs` switch (`:2240-2326`): `MultisignatureInput` branch at `:2305` calls
  `validateInput(...)`.
- `validateInput(MultisignatureInput, ...)` (`:3373-3449`) is the heart:
  - resolves the referenced output from `m_multisignatureOutputs[amount][outputIndex]` (`:3376-3391`),
  - rejects if `isUsed` (double-spend, `:3392`),
  - `is_tx_spendtime_unlocked(outputTransaction.unlockTime)` (`:3399`),
  - `input.signatureCount == output.requiredSignatureCount` (`:3409`),
  - **`input.term == output.term`** (`:3417`),
  - **deposit lock**: `output.term != 0 && outputIndex.transactionIndex.block + output.term > getCurrentBlockchainHeight()` → reject (`:3422-3427`) — this enforces the deposit cannot be spent before the term elapses,
  - then the m-of-n loop: each `crypto::check_signature(transactionPrefixHash, output.keys[k], sigs[i])` (`:3429-3447`).
- Output validity: `check_tx_outputs_visitor::operator()(MultisignatureOutput)`
  (`Blockchain.h` around `:470`) → `Currency::validateOutput(amount, output, height)`
  (`Currency.cpp:1364-1389`) enforces term band (`m_depositMinTermV3 / MaxTermV3`, multiple-of-min),
  and `amount >= m_depositMinAmount`.

### Index (chain state)
- `m_multisignatureOutputs` : `parallel_flat_hash_map<uint64_t, vector<MultisignatureOutputUsage>>`
  (`Blockchain.h:273,304`); each `MultisignatureOutputUsage{ transactionIndex, outputIndex, isUsed }`
  (`Blockchain.h:224`).
- Push (output indexed) `Blockchain.cpp:3182-3189`; input marks `isUsed=true` `:3159-3166`.
- Pop/reorg unwinds both (`:3276-3317`, `:3341-3350`).
- Initial scan rebuild on load: `:719-737`.

### Money supply (CRITICAL — this is where interest is minted)
- `input_amount_visitor` (`Currency.h:671-699`): for a `MultisignatureInput` with `term != 0` it
  returns `amount + getInterestForInput(input, height)` (`:687-697`). **This is the only place the
  deposit principal *and accrued interest* are counted as input money.**
- `getInterestForInput` (`Currency.cpp:412-416`) → `calculateInterest(amount, term, lockHeight)`
  (`:251-294`, V2/V3 variants `:298-410`). `lockHeight = height - term`.
- This feeds `getTransactionAllInputsAmount` (`Currency.cpp:451-461`) used by block-money-balance
  checks (`Blockchain.cpp:783`, `Core.cpp:293`) and the mempool (`TransactionPool.cpp:141,490`).
- `calculateTotalTransactionInterest` (`Currency.cpp:424-441`) is summed into the **deposit index /
  emission** (`Blockchain.cpp:741,788,2923,2953`; `pushToDepositIndex`).

**The single most dangerous part of this migration:** any PQ deposit input must reproduce
`amount + interest` accounting *identically*, derived from a `term` that validation has *bound* to
the on-chain deposit output's `term`. If the PQ input's `amount`/`term` are attacker-chosen and not
bound to the output, an attacker mints arbitrary interest.

### Existing PQ machinery the PoC already built (reuse, don't reinvent)
- `PqKeyInput { amount; vector<uint32_t> outputIndexes; vector<uint8_t> nullifier; vector<uint8_t> ringSig; }`
  and `PqKeyOutput { vector<uint8_t> key; vector<uint8_t> kemCt; }` (`include/CryptoNote.h:43-53`).
- `check_pq_tx_input` (`Blockchain.cpp:2441-2540`): ring-resolve from `m_pqOutputs` → `ccx_pq_verify`
  → recover + bind nullifier → unlock-window check.
- `m_pqOutputs` (output index), `m_spent_pq_nullifiers` (double-spend set), reorg-safe push/pop
  (`Blockchain.h:282,286`; `Blockchain.cpp:3128-3191`, `:3241-3340`).
- Mempool PQ nullifier set (`TransactionPool.{h,cpp}`).
- FFI: `ccx_pq_keygen / ccx_pq_sign / ccx_pq_verify / ccx_pq_nullifier / ccx_pq_pubkey_bytes`
  (`pqc/include/pq_ring_sig.h:10-25`); ML-DSA-65 = dilithium3 already linked
  (`pqc/ccx-pqc/src/lib.rs:21`, selftest `ccx_mldsa_selftest` `:156-167`).
- Gates: `TRANSACTION_VERSION_3` (`CryptoNoteConfig.h:162`), `PQ_NULLIFIER_SIZE=32` (`:163`),
  v3-input gate in `check_inputs_types_supported` (`CryptoNoteFormatUtils.cpp:290-300`),
  v3-block allowance in `pushBlock`.

---

## 2. Design decision: NEW `PqMultisig*` variant (do NOT reuse `PqKeyInput`)

**Recommendation: add a dedicated `PqMultisigOutput` / `PqMultisigInput` pair** rather than
overloading `PqKeyInput`/`PqKeyOutput`. Rationale, grounded in the divergence between the two flows:

| Property | `PqKeyInput` (ring spend) | Deposit spend (this work) |
|---|---|---|
| Anonymity | ring-of-N over `m_pqOutputs[amount]`, recovered nullifier | **none** — a deposit is a *known cell* with a fixed key set; multisig deposits are not anonymous today either |
| Signature | experimental lattice AOS/LSAG ring sig (demo-grade, `ringsig.rs`) | **plain ML-DSA-65** m-of-n — production-grade primitive (`dilithium3`), audited NIST FIPS 204 |
| Carries `term` | no | **yes — required for interest + lock** |
| Output target | one-time stealth key (KEM) | n named PQ public keys + `requiredSignatureCount` + `term` |
| Index | `m_pqOutputs[amount]` (offsets) | needs `isUsed` per-cell like `m_multisignatureOutputs` |

Forcing deposits through `PqKeyInput` would (a) drag in the experimental, *unaudited, non-constant-time*
lattice ring sig where deposits need none of its anonymity and (b) lose the `term` field and the
`isUsed`/`requiredSignatureCount` semantics. A `PqMultisig*` variant is the faithful PQ analogue of
the existing multisig path: swap **only** the crypto (Ed25519 `check_signature` → `ccx_pq_*` ML-DSA-65),
keep term/interest/lock byte-identical. This also keeps the deposit path on a *standardized* PQ signature
(FIPS 204) instead of the experimental ring scheme — strictly better for money-critical deposits.

### New types (`include/CryptoNote.h`)
```cpp
struct PqMultisigInput {
  uint64_t amount;
  uint8_t  signatureCount;          // == output.requiredSignatureCount (m)
  uint32_t outputIndex;             // index into m_pqMultisigOutputs[amount]
  uint32_t term;                    // bound to output.term (interest + lock)
  std::vector<std::vector<uint8_t>> signatures;  // m ML-DSA-65 sigs, inline (not in tx.signatures)
};

struct PqMultisigOutput {
  std::vector<std::vector<uint8_t>> keys;  // n ML-DSA-65 public keys (each ccx_pq_pubkey_bytes())
  uint8_t  requiredSignatureCount;         // m
  uint32_t term;                           // 0 = plain PQ multisig; !=0 = deposit
};
```
Add to the variants (`include/CryptoNote.h:55-57`):
```cpp
typedef boost::variant<BaseInput, KeyInput, MultisignatureInput, PqKeyInput, PqMultisigInput> TransactionInput;
typedef boost::variant<KeyOutput, MultisignatureOutput, PqKeyOutput, PqMultisigOutput> TransactionOutputTarget;
```
**Variant-append rule (compatibility):** append at the END. `boost::variant::which()` / the binary tag
are positional. Existing serialized data already uses tags 0x2/0x3/0x4; assign the new pair a **new tag
0x5** in `BinaryVariantTagGetter` (`CryptoNoteSerialization.cpp:59-63`) and `getVariantValue` (`:78-130`).
Never renumber existing tags — that would reinterpret historical blocks.

**Design note (signatures inline vs `tx.signatures`):** carry the m ML-DSA sigs *inside*
`PqMultisigInput.signatures`, exactly as `PqKeyInput` carries its proof inline, and have
`getSignaturesCount` return 0 for `PqMultisigInput` (`CryptoNoteSerialization.cpp:48-49`) so the
`tx.signatures[inputIndex]` slot is **not** advanced (mirror the PoC's PqKeyInput handling at
`Blockchain.cpp:2300-2304` comment). This avoids touching the legacy `tx.signatures` 2-D layout, whose
per-input element count is keyed off `getSignaturesCount`. (Alternative: reuse `tx.signatures` like the
classic multisig — rejected: ML-DSA sigs are ~3.3 KB each and the `vector<vector<Signature>>` element type
is fixed-size `crypto::Signature` (64 B), so they cannot live there without changing that type.)

---

## 3. Serialization (`src/CryptoNoteCore/CryptoNoteSerialization.cpp`)

1. Tag getter — append (`:59-63`):
   ```cpp
   uint8_t operator()(const cn::PqMultisigInput  &) const { return 0x5; }
   uint8_t operator()(const cn::PqMultisigOutput &) const { return 0x5; }
   ```
2. `getVariantValue` input dispatch (`:78-107`) and output dispatch (`:109-130`): add a `case 0x5`
   constructing the new variant and `serializer(v, "value"/"data")`.
3. `getSignaturesCount` visitor (`:48-49`): `size_t operator()(const PqMultisigInput&) const { return 0; }`.
4. New `serialize` bodies (mirror `PqKeyInput` at `:287-292` for the `serializeAsBinary` of byte-vectors,
   and `MultisignatureInput/Output` at `:280-285,329-333` for the scalars):
   ```cpp
   void serialize(PqMultisigInput& in, ISerializer& s) {
     s(in.amount, "amount");
     s(in.signatureCount, "signatures");
     s(in.outputIndex, "outputIndex");
     s(in.term, "term");
     // length-prefixed array of opaque sigs
     size_t n = in.signatures.size();
     s.beginArray(n, "sigs"); in.signatures.resize(n);
     for (auto& sig : in.signatures) serializeAsBinary(sig, "", s);
     s.endArray();
   }
   void serialize(PqMultisigOutput& out, ISerializer& s) {
     size_t n = out.keys.size();
     s.beginArray(n, "keys"); out.keys.resize(n);
     for (auto& k : out.keys) serializeAsBinary(k, "", s);
     s.endArray();
     s(out.requiredSignatureCount, "required_signatures");
     s(out.term, "term");
   }
   ```
   Use the exact `beginArray/endArray` idiom already in `serializeVarintVector` (`:139-153`).
   **Bound array sizes on the INPUT path** (see §6 DoS) before `resize`.
5. Declarations in `CryptoNoteSerialization.h` alongside the existing `serialize(PqKeyInput…)` decls.

---

## 4. `check_pq_multisig` validation (`src/CryptoNoteCore/Blockchain.cpp`)

New `Blockchain::check_pq_multisig(const PqMultisigInput&, const crypto::Hash& prefixHash, uint32_t* pmax)`
— a near line-for-line port of `validateInput(MultisignatureInput,…)` (`:3373-3449`) with the signature
primitive swapped. **Keep term/interest/lock logic identical.**

```cpp
bool Blockchain::check_pq_multisig(const PqMultisigInput& input,
                                   const crypto::Hash& prefixHash, uint32_t* pmax) {
  std::lock_guard lk(m_blockchain_lock);
  auto amountOutputs = m_pqMultisigOutputs.find(input.amount);
  if (amountOutputs == m_pqMultisigOutputs.end()) return false;
  if (input.outputIndex >= amountOutputs->second.size()) return false;
  const auto& usage = amountOutputs->second[input.outputIndex];
  if (usage.isUsed) return false;                                  // double-spend

  const Transaction& outTx = m_blocks[usage.transactionIndex.block]
                               .transactions[usage.transactionIndex.transaction].tx;
  if (!is_tx_spendtime_unlocked(outTx.unlockTime)) return false;

  const auto& target = outTx.outputs[usage.outputIndex].target;
  if (target.type() != typeid(PqMultisigOutput)) return false;     // type guard (PoC adds this vs the asserts)
  const PqMultisigOutput& output = boost::get<PqMultisigOutput>(target);

  if (input.signatureCount != output.requiredSignatureCount) return false;
  if (input.term != output.term) return false;                     // BIND term (interest safety)
  if (output.term != 0 &&
      usage.transactionIndex.block + output.term > getCurrentBlockchainHeight()) return false;  // deposit lock

  // ML-DSA-65 m-of-n: same greedy match loop as Ed25519 (:3429-3447), check_signature -> ccx_pq_verify-style
  const size_t pkBytes = ccx_pq_pubkey_bytes();
  if (pkBytes == 0) return false;
  if (input.signatures.size() != input.signatureCount) return false;
  size_t sIdx = 0, kIdx = 0;
  while (sIdx < input.signatureCount) {
    if (kIdx == output.keys.size()) return false;
    if (output.keys[kIdx].size() != pkBytes) return false;
    if (ccx_pq_multisig_verify(reinterpret_cast<const uint8_t*>(&prefixHash), sizeof(prefixHash),
                               output.keys[kIdx].data(), pkBytes,
                               input.signatures[sIdx].data(), input.signatures[sIdx].size()) == 0) {
      ++sIdx;
    }
    ++kIdx;
  }
  if (pmax && *pmax < usage.transactionIndex.block) *pmax = usage.transactionIndex.block;  // (:3399-ish max_used)
  return true;
}
```

**Crypto detail — no nullifier needed.** Unlike the ring-sig path, a PQ multisig is a *named cell*:
double-spend is caught by the existing `isUsed` flag in `m_pqMultisigOutputs` (exactly like classic
multisig), so there is **no** `m_spent_pq_nullifiers` entry and **no** recovered tag. This is simpler and
keeps the deposit semantics identical. The signed message is `transactionPrefixHash` (same as Ed25519
multisig at `:3438`), not the special PQ-signing hash — there is no ring, so the existing prefix hash works.

**FFI gap:** `ccx_pq_verify` (`pq_ring_sig.h:22`) is the *ring* verifier (walks a ring, recovers a
nullifier). For deposits we want a plain single-key ML-DSA verify. Two options:
- (A) **Add `ccx_pq_multisig_sign/verify`** thin wrappers over `dilithium3::sign/open` in
  `pqc/ccx-pqc/src/lib.rs` (the selftest `ccx_mldsa_selftest` `:156-167` already shows the exact calls)
  + extern decls in `pq_ring_sig.h`. Use *detached* signatures (`dilithium3::detached_sign` /
  `verify_detached_signature`) so the sig is fixed-size (~3293 B) and the message isn't embedded.
  **Recommended.**
- (B) Reuse `ccx_pq_verify` with `ringCount=1` and ignore the recovered nullifier. **Rejected** — couples
  deposits to the experimental ring scheme; option A uses standardized FIPS 204 directly.

Wire it into `checkTransactionInputs` switch (`:2305`-style branch), gated:
```cpp
else if (txin.type() == typeid(PqMultisigInput)) {
  if (!isInCheckpointZone(getCurrentBlockchainHeight())) {
    if (!check_pq_multisig(boost::get<PqMultisigInput>(txin), tx_prefix_hash, pmax_used_block_height))
      return false;
  }
  // inline sigs -> do NOT advance inputIndex (mirror PqKeyInput, :2302-2304)
}
```

---

## 5. Interest / term / money supply — UNCHANGED logic, extended dispatch

These are *integer* paths; only the variant dispatch needs the new type. **No formula changes.**

1. `input_amount_visitor` (`Currency.h:671-699`) — add:
   ```cpp
   uint64_t operator()(const PqMultisigInput& in) const {
     return in.term == 0 ? in.amount
                         : in.amount + m_currency.getInterestForInput(in, m_height);
   }
   ```
   `getInterestForInput` currently takes `MultisignatureInput` (`Currency.cpp:412`). Add an overload (or a
   small struct with `{amount,term}`) so the **same** `calculateInterest(amount, term, lockHeight)` runs.
   Because §4 binds `input.term == output.term` and `output.term` passed `validateOutput`, the interest is
   computed from a consensus-validated term — closing the mint-arbitrary-interest hole.
2. `calculateTotalTransactionInterest` (`Currency.cpp:424-441`) — add a `PqMultisigInput` branch summing
   `getInterestForInput` (so deposit emission / `pushToDepositIndex` stays correct, `Blockchain.cpp:741`).
3. `getTransactionInputAmount` (`Currency.cpp:445`) already routes through the visitor — no change.
4. `get_inputs_money_amount` (`CryptoNoteFormatUtils.cpp:259-273`) — add `PqMultisigInput.amount` (this is
   the *non-interest* sum used by some checks; mirror the `MultisignatureInput` case `:267`).
5. `TransactionUtils.cpp:44 getTransactionInputAmount` and `Transaction.cpp:477` /
   `TransactionPrefixImpl.cpp:143` summations — add the new variant case (amount only).

**Output validity** — extend `Currency::validateOutput` (`Currency.cpp:1364`) to accept a
`PqMultisigOutput` overload enforcing the **identical** term band + `depositMinAmount` rules, and add a
`check_tx_outputs_visitor::operator()(const PqMultisigOutput&)` (`Blockchain.h:436+`) calling it. Also
require `requiredSignatureCount <= keys.size()` and each key length `== ccx_pq_pubkey_bytes()`.

---

## 6. Index, mempool, reorg, DoS

### New chain index `m_pqMultisigOutputs`
Mirror `m_multisignatureOutputs` exactly (`Blockchain.h:273,304`):
```cpp
using PqMultisigOutputsContainer = parallel_flat_hash_map<uint64_t, std::vector<MultisignatureOutputUsage>>;
PqMultisigOutputsContainer m_pqMultisigOutputs;
```
Reuse `MultisignatureOutputUsage{transactionIndex, outputIndex, isUsed}` (`Blockchain.h:224`) unchanged.

- **Push output** (`Blockchain.cpp:3182-3189` pattern): index `PqMultisigOutput` into
  `m_pqMultisigOutputs[amount]` with `isUsed=false`, set `m_global_output_indexes[output]`.
- **Mark spent** (`:3159-3166` pattern): `PqMultisigInput` → `m_pqMultisigOutputs[in.amount][in.outputIndex].isUsed = true`.
- **Pop / reorg** (`:3276-3317` and `:3341-3350`): unwind both the output append and the `isUsed=true` for
  the new type. **This is the reorg-safety surface — must be symmetric with push or a reorg corrupts the
  index.** The PoC already had to fix exactly this class of bug for `m_pqOutputs`
  (`commit 4af0ec2 "make PQ output/nullifier index reorg-safe"`).
- **Initial scan rebuild** (`:719-737`): add `PqMultisigOutput`/`PqMultisigInput` cases so the index is
  reconstructible on load (and the on-disk serialized index `:233` gets a new member; or rebuild from
  blocks — match whatever `m_multisignatureOutputs` does for persistence).

### Mempool (`TransactionPool.cpp`)
Plain multisig has no special pool set (double-spend caught at block time via `isUsed`). But the pool
*does* guard intra-pool conflicts. Add a `(amount, outputIndex)` in-pool used-set for `PqMultisigInput`
analogous to `checkMultisignatureInputsDiff` (`CryptoNoteFormatUtils.cpp:369-382`) extended to the new
type, so two pool txs can't both spend the same deposit cell before mining. Also extend
`getTransactionAllInputsAmount` callers in the pool (`:141,490`) — already covered by §5.1.

### DoS bounds (validate at the serialization boundary — coding-style §"validate at boundaries")
ML-DSA pubkeys (~1952 B) and sigs (~3293 B) are large and the arrays are attacker-controlled. Before any
`resize`/allocation in `serialize(PqMultisig*)` and before verify:
- cap `keys.size()` and `signatures.size()` to a small `PQ_MULTISIG_MAX_KEYS` (e.g. 16) — mirror the
  spirit of the PoC's nullifier-length guard (`Blockchain.cpp:3132-3140`) and `PQ_NULLIFIER_SIZE`.
- require every key length `== ccx_pq_pubkey_bytes()` and every sig length `== ccx_pq_sig_bytes()`
  (add `ccx_pq_sig_bytes()` to the FFI, like `ccx_pq_pubkey_bytes()` at `pq_ring_sig.h:11`).
- reject `requiredSignatureCount == 0` or `> keys.size()`.
These bounds also stop the classic "huge vector length prefix" OOM on deserialization.

---

## 7. Gating: testnet + height + tx-version

Follow the PoC's exact pattern (`CryptoNoteConfig.h`, `check_inputs_types_supported`):

1. **Tx version**: PQ multisig only in `version >= TRANSACTION_VERSION_3` (`CryptoNoteConfig.h:162`).
   Extend `check_inputs_types_supported` (`CryptoNoteFormatUtils.cpp:290-300`) and `check_outs_valid`
   (`:344` block) with `PqMultisigInput/Output` cases requiring v3.
2. **Height gate**: add `UPGRADE_HEIGHT_V9` (mainnet, far future / TBD) and `TESTNET_UPGRADE_HEIGHT_V9`
   in `CryptoNoteConfig.h` (mirror `:113` and `:126`), tied to a new `BLOCK_MAJOR_VERSION_9`. PQ multisig
   outputs/inputs accepted **only at/after** that height. On testnet set it low (e.g. height 80, after the
   existing PoC PQ activation) so the PoC testnet exercises it immediately; on mainnet keep it un-activated
   (sentinel/far-future) until audited. **Never apply retroactively** (CLAUDE.md consensus rule).
3. **Testnet flag**: like the PoC PQ coinbase (`Currency.cpp`, gated on `m_testnet`), keep mainnet emission
   of `PqMultisigOutput` disabled until the height gate is real; validation can be present but the gate
   keeps mainnet from ever seeing one.
4. **Block-version allowance** in `pushBlock`: allow v3 PQ-multisig tx under the new block major version
   (the PoC added a similar allowance for v3 PQ tx in v1 testnet blocks).

Deposit-term constants (`CryptoNoteConfig.h:69-78`, `TESTNET_DEPOSIT_*` `:128-131`) are **reused as-is** —
PQ deposits obey the same term band, min amount, and interest curve. No new term constant.

---

## 8. Wallet (out of scope for consensus, needed for end-to-end)

The PoC used the `pq_injector` tool instead of wallet support; the same applies here. Minimal path to a
live testnet demo without full wallet integration:
- Extend `pqc/tools/pq_injector.cpp` (or a sibling `pq_deposit_injector`) to: ML-DSA-65 keygen
  (`ccx_pq_keygen`), build a v3 tx with a `PqMultisigOutput{keys, requiredSignatureCount, term}` (deposit),
  mine it, then after `term` blocks build a `PqMultisigInput` spending it with m `ccx_pq_multisig_sign`
  signatures over the prefix hash, and observe interest credited.
- A future `concealwallet` integration mirrors `WalletLegacy`'s deposit create/withdraw, swapping the
  Ed25519 multisig keys for ML-DSA keypairs. Flagged as follow-up (CIP-0001), not part of the consensus
  blueprint.

---

## 9. Files to touch (concrete)

| File | Change |
|---|---|
| `include/CryptoNote.h` | add `PqMultisigInput`/`PqMultisigOutput` structs; append to both variants (`:55-57`) |
| `src/CryptoNoteConfig.h` | `UPGRADE_HEIGHT_V9` + `TESTNET_UPGRADE_HEIGHT_V9`, `BLOCK_MAJOR_VERSION_9`, `PQ_MULTISIG_MAX_KEYS` |
| `src/CryptoNoteCore/CryptoNoteSerialization.{h,cpp}` | tag 0x5; `getVariantValue` cases; `getSignaturesCount`=0; `serialize(PqMultisig*)` with bounded arrays |
| `src/CryptoNoteCore/CryptoNoteFormatUtils.cpp` | `check_inputs_types_supported` (`:290`), `check_outs_valid` (`:344`), `get_inputs_money_amount` (`:259`), `checkMultisignatureInputsDiff`-analogue (`:369`) |
| `src/CryptoNoteCore/Blockchain.h` | `PqMultisigOutputsContainer m_pqMultisigOutputs`; `check_pq_multisig` decl; `check_tx_outputs_visitor::operator()(PqMultisigOutput)` |
| `src/CryptoNoteCore/Blockchain.cpp` | `check_pq_multisig` impl; switch branch (`:2305`-style); push/mark/pop/reorg (`:3159,:3182,:3276,:3341`); initial scan (`:719`); height/version gate in `pushBlock`; serialized-index member (`:233`) |
| `src/CryptoNoteCore/Currency.{h,cpp}` | `input_amount_visitor::operator()(PqMultisigInput)` (`Currency.h:671`); `getInterestForInput` overload; `calculateTotalTransactionInterest` branch (`:424`); `validateOutput(PqMultisigOutput)` overload (`:1364`) |
| `src/CryptoNoteCore/TransactionUtils.cpp`, `Transaction.cpp`, `TransactionPrefixImpl.cpp` | input-amount visitor cases (amount only) |
| `src/CryptoNoteCore/TransactionPool.{h,cpp}` | in-pool deposit-cell conflict set for `PqMultisigInput` |
| `pqc/ccx-pqc/src/lib.rs` | `ccx_pq_multisig_sign` / `ccx_pq_multisig_verify` (detached dilithium3) + `ccx_pq_sig_bytes()` |
| `pqc/include/pq_ring_sig.h` | extern decls for the three new FFI functions |
| `pqc/tools/` | deposit injector for end-to-end testnet demo |

---

## 10. Risks (consensus / money / crypto)

1. **Interest minting (CRITICAL).** If `input.term` is not bound to `output.term`, or
   `input_amount_visitor` mis-dispatches, an attacker mints arbitrary interest. Mitigation: §4 binds
   `input.term == output.term` *before* interest is computed; §5 reuses the exact `calculateInterest` path.
   Test: spend with a forged larger `term` → must reject.
2. **Reorg index corruption (CRITICAL).** Asymmetric push/pop of `m_pqMultisigOutputs` (or `isUsed`)
   corrupts the deposit set on a reorg — the PoC already hit this for `m_pqOutputs` (commit 4af0ec2).
   Mitigation: symmetric pop mirroring multisig (`:3276-3350`); test deep reorg across a deposit
   create+spend.
3. **Double-spend via index gap.** Must rely on `isUsed` + in-pool set; missing the pool guard lets two
   mempool txs spend one cell. Test: two pool txs same `(amount,outputIndex)` → second rejected.
4. **Deposit lock bypass.** The `block + term > height` check (`:3422`) must be ported exactly; off-by-one
   lets early withdrawal (and over-credits interest). Test: spend at `term-1` → reject, at `term` → accept.
5. **DoS via oversized arrays.** Unbounded `keys`/`signatures` length prefixes → OOM on deserialize, or
   CPU blowup verifying many large sigs. Mitigation: §6 caps + exact-length checks at the boundary.
6. **Serialization wire/disk compat.** New tag 0x5 must be append-only; mis-numbering reinterprets history.
   The on-disk index serialization (`:233`) must round-trip or be rebuildable. Test: serialize→deserialize
   round-trip; old daemon must reject v3 PQ-multisig (it will: unknown tag → "unsupported type" at
   `:2320`/`check_inputs_types_supported`).
7. **Crypto primitive maturity.** ML-DSA-65 / dilithium3 (`pqcrypto_dilithium`) is a standardized,
   production-oriented primitive (unlike the experimental ring sig) — but the *integration* (detached vs
   attached sigs, message = prefix hash, constant-time, side channels) is unaudited. The PoC's POC-RESULTS
   already flags the whole module "unaudited, not constant-time, demo-only." Mainnet activation must wait
   on audit (CIP-0001 C1). Keep height gate un-activated on mainnet meanwhile.
8. **`tx.signatures` aliasing.** If `getSignaturesCount` is *not* 0 for `PqMultisigInput`, `inputIndex`
   desyncs from `tx.signatures` and a mixed tx (KeyInput + PqMultisigInput) reads the wrong signature slot.
   Test: mixed-input tx validates correctly.
9. **Checkpoint-zone skip.** Validation is skipped inside the checkpoint zone (`isInCheckpointZone`,
   `:2308`) like all inputs — fine for testnet, but the height gate must be far past any checkpoint on
   mainnet so PQ deposits are never auto-trusted.

---

## 11. Test plan

Build/run on WSL x86_64 (`.claude/wsl-build.sh`; `ssh 100.100.90.103`); Rust
`cd ~/conceal-core/pqc/ccx-pqc && cargo build --release`.

**Unit / primitive**
- `ccx_mldsa_selftest` already passes (`lib.rs:156`); add a selftest for the new
  `ccx_pq_multisig_sign/verify` round-trip + tamper-reject + wrong-key-reject.
- Serialization round-trip for `PqMultisigInput/Output` (binary in→out→in equality), including the
  bounded-array rejection of oversized `keys`/`signatures`.

**Consensus (gtest `CoreTests`/`UnitTests`, build `-DBUILD_TESTS=ON`)**
- Output accept: valid `PqMultisigOutput` deposit (term in band, amount ≥ min) accepted; bad term / tiny
  amount / `requiredSignatureCount > keys.size()` rejected (`validateOutput` parity with multisig).
- Spend accept: m-of-n ML-DSA sigs over prefix hash, `term` matching, after lock → accepted; interest
  credited equals `calculateInterest(amount, term, height-term)` (assert against the Ed25519 deposit value
  for the same amount/term — must be identical).
- Spend reject: forged `term`, wrong key, `< requiredSignatureCount` valid sigs, double-spend (reused
  `outputIndex`), early withdrawal (`height < block+term`), wrong tx version (<3), pre-gate height.
- Reorg: create deposit at H, mine spend at H+term, force reorg below H → index and `isUsed` clean; re-mine.

**End-to-end testnet (mirror `pqc/run-poc-testnet.sh`)**
- 2-node testnet; deposit-injector creates a `PqMultisigOutput` deposit, mines past `term`, spends with
  ML-DSA m-of-n, daemon accepts and credits interest; second spend of same cell rejected (pool + chain);
  early-spend rejected. Compare emission/deposit-index to an equivalent Ed25519 deposit.

**Pre-PR**: CodeRabbit + Codex (`codex:rescue`) + GLM (`consult:review`) per `git-workflow.md`, focusing on
the interest-minting path (§5), reorg symmetry (§6), and the FFI length/constant-time handling.
