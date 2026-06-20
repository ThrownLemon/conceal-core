# PQ Testnet PoC — Security & Consensus Review

Branch: `pqc/testnet-poc` vs `master`. Scope: every post-quantum change (PqKeyInput/PqKeyOutput,
`check_pq_tx_input`, nullifier sets, PQ coinbase, mempool, Rust C-ABI). Read-only/advisory.

Reviewer note: this is an explicitly-labelled **demo PoC, testnet-gated, unaudited, not constant-time**.
Many findings below are inherent to "PoC" status. I still rate them at their true consensus/security
severity so the gap to production is unambiguous. The two CRITICALs are real correctness/double-spend
holes that bite even on testnet, not just "production hardening".

---

## CRITICAL

### C1. PQ nullifier set & PQ output index are never persisted and never rebuilt → double-spend after restart
- **Location:** `src/CryptoNoteCore/Blockchain.cpp:230` (storage serializer), `:681` `rebuildCache()`,
  `Blockchain.h:282,286` (`m_spent_pq_nullifiers`, `m_pqOutputs`).
- **Issue:** The blockchain storage serializer persists `m_spent_keys` (`spentkeys.dat`), `m_outputs`,
  `m_multisignatureOutputs`, `m_depositIndex` — but **not** `m_pqOutputs` and **not**
  `m_spent_pq_nullifiers`. Both maps are only ever populated inside `pushTransaction` during live block
  processing. Two consequences on the next daemon start:
  1. **Serialized-load path:** the two maps come up **empty**. `m_spent_pq_nullifiers` empty means every
     previously-spent PQ output's nullifier is forgotten → the same PQ output can be spent again
     (`check_pq_tx_input` at `:2280` finds the nullifier absent) = **double-spend / infinite-mint of PQ
     outputs across a restart.** `m_pqOutputs` empty also means honest PQ spends can no longer resolve
     their ring (`:2454` `m_pqOutputs.find` misses) until/unless re-indexed.
  2. **`rebuildCache()` path** (used on cache corruption / version bump / `-DDB` recovery): the replay loop
     at `:713`–`:739` handles `KeyInput`/`MultisignatureInput` and `KeyOutput`/`MultisignatureOutput` only.
     It has **no `PqKeyInput` branch** (so `m_spent_pq_nullifiers` is never repopulated) and **no
     `PqKeyOutput` branch** (so `m_pqOutputs` is never repopulated). Same double-spend window.
- **Why CRITICAL:** silent loss of the double-spend set is the canonical money-critical failure. Unlike a
  validation bug that rejects, this *accepts* a second spend.
- **Fix:** (a) add `PqKeyInput`/`PqKeyOutput` handling to `rebuildCache()` mirroring `:715`–`:738`; (b)
  persist both maps in the storage serializer (or, simplest and safest for a PoC, force a full
  `rebuildCache()` whenever PQ is active so the maps are always reconstructed by replay). Until then, the
  PoC is only sound for a single uninterrupted daemon lifetime.

### C2. Mixed-input transactions desynchronize the signature index for legacy KeyInputs
- **Location:** `src/CryptoNoteCore/Blockchain.cpp:2240`–`:2310` (`checkTransactionInputs`), interacting with
  `CryptoNoteSerialization.cpp:214`–`:252` (`tx.signatures` is sized one-slot-per-input).
- **Issue:** `tx.signatures[i]` is positional: slot `i` belongs to `inputs[i]` (the PQ slot is an empty
  vector since `getSignaturesCount(PqKeyInput)==0`). But the validator advances `inputIndex` (the index into
  `tx.signatures`) **only** for `KeyInput`/`MultisignatureInput`, **not** for `PqKeyInput`. For a mixed tx
  `[KeyInput, PqKeyInput, KeyInput]`, the second `KeyInput` is validated against `tx.signatures[1]` — the
  empty PQ slot — instead of `tx.signatures[2]`. Result: `check_tx_input` sees a signature-count mismatch.
- **Impact:** as written this *rejects* legitimate mixed txs (a correctness/DoS-of-functionality bug, not an
  acceptance bug), but it proves the `inputIndex`/`signatures` invariant is broken once PQ and legacy inputs
  coexist. Any future change that makes the empty-slot path lenient turns this into an acceptance hole, and
  the mismatch between "signatures are positional per-input" and "inputIndex skips PQ" is a latent footgun.
  The PoC injector only emits PQ-only txs, so this is untested in the demo.
- **Fix:** make the PQ branch advance `inputIndex` too (PQ slot is a real, empty positional slot), or index
  `tx.signatures` by the input loop variable rather than a separate `inputIndex` counter.

---

## HIGH

### H1. Ring signature security parameters are demo-grade — linkability/unforgeability are not real
- **Location:** `pqc/ccx-pqc/src/ringsig.rs:17`–`:25` (N=256, q=8380417, **K=L=4**, biased matrix sampling
  at `:86`), self-attested at `:9`–`:11`.
- **Issue:** The module-SIS instance (K=L=4) is far below any calibrated NIST level, and `gen_matrix`
  uses `read_u32 % Q` (modulo bias) instead of rejection sampling. The double-spend binding (`nf =
  SHAKE256(I)`, `I = A2·s`) is *structurally* sound — the ring closure forces `I = A2·s_signer` for an
  honest single signer (verified by tracing `verify` at `ringsig.rs:246`–`:260`), so a single signer cannot
  swap nullifiers — **but** soundness rests entirely on module-SIS being hard at these parameters, which it
  is not. A solver who can find a short `s'` with `A·s' = t` for some ring member can forge spends and/or
  produce alternate valid tags. Treat the whole scheme as "not yet a security guarantee."
- **Fix:** calibrate to cat-1+, rejection-sample the matrix, constant-time, audit (already documented as
  CIP-0001 C1). Do not advance off testnet until done.

### H2. Expensive PQ verification runs on unconfirmed mempool transactions (CPU DoS)
- **Location:** `Blockchain.cpp:2289`–`:2300` (`check_pq_tx_input` called from `checkTransactionInputs`,
  which `TransactionPool::add_tx` invokes at `TransactionPool.cpp:203` before any PoW), verify cost in
  `ringsig.rs:40` (`poly_mul` is O(N²) schoolbook) × `mat_vec` (K·L) × ring_count.
- **Issue:** `ccx_pq_verify` does `ring_count × (K·L) × N²` 128-bit multiplies per input, on the
  validating thread, for a tx that has paid nothing and proven no work. ring_count is bounded by the number
  of on-chain PQ outputs of that amount (a saving grace), but an attacker can still flood the mempool with
  maximal-ring v3 txs (each ~tens of KB, schoolbook-verified) to burn validator CPU. There is no PQ-specific
  rate limit, fee floor that accounts for verify cost, or ring-size cap independent of the on-chain set.
- **Fix:** cap PQ ring size to a small constant (e.g. ≤ typical mixin), charge a verify-proportional fee,
  and/or defer full PQ verify until the tx is in a candidate block. NTT instead of schoolbook reduces the
  constant but not the DoS shape.

### H3. No minimum ring size / decoy-count enforcement for PQ inputs
- **Location:** `Blockchain.cpp:2272`–`:2275` (only rejects *empty* `outputIndexes`) and `check_pq_tx_input`
  `:2456`+ (accepts `ring_count == 1`).
- **Issue:** Consensus accepts a ring of size 1 (zero anonymity) and does not reject duplicate ring offsets
  (all offsets pointing at the same output → effective ring of 1). The legacy path has mixin policy; PQ has
  none. Not a fund-loss bug, but it silently defeats the entire privacy goal of the feature and lets a
  sender de-anonymize themselves (or be forced to).
- **Fix:** enforce a minimum distinct ring size and reject duplicate absolute offsets within one PQ input.

---

## MEDIUM

### M1. PQ output amount is attacker-chosen and only conserved at the mempool, not in `pushBlock`
- **Location:** money conservation lives in `TransactionPool::add_tx` (`TransactionPool.cpp:141`–`:151`,
  `outputs_amount > inputs_amount`), but `Blockchain::pushBlock` (`:2876`–`:2924`) calls
  `getTransactionFee(tx, height)` (the `uint64_t` overload, `Currency.cpp:527`) and **ignores its result**;
  the `bool` overload returns `false` on overspend (`:514`) but the value-overload swallows it to 0.
- **Issue:** For legacy txs, input amounts are cryptographically fixed (decomposed amounts + ring sig over
  the prefix), so an overspending tx can't be forged. For PQ, `PqKeyInput.amount` is a free field only bound
  to "some on-chain PQ output bucket exists for this amount" (`check_pq_tx_input` `:2454`). The ring sig
  signs the prefix (so the *signer* commits to the amounts), but nothing checks that the claimed input
  `amount` equals the *actual* denomination the spent output carried beyond "the bucket is non-empty". With
  the testnet single fixed denomination (`PQ_TESTNET_COINBASE_AMOUNT`) this is currently safe, but the
  architecture relies on the mempool overspend check that **block-import from peers bypasses**. A malicious
  miner could craft a block whose PQ tx outputs > inputs; `pushBlock` would not reject it on conservation
  grounds (it would only mis-account the fee as 0). Whether this inflates supply depends on
  `validate_miner_transaction` summing fees — an overspend here is *not* caught there.
- **Fix:** add an explicit per-tx `outputs ≤ inputs` check inside `pushBlock`/`checkTransactionInputs` for
  v3 txs (don't rely on the mempool path), and bind the PQ input amount to the resolved ring members'
  output amount (assert all ring members share `txin.amount`, which `m_pqOutputs[amount]` already implies —
  make it explicit and also verify the spending tx's outputs don't exceed it).

### M2. Per-field PQ blob size cap is 128 MB; a single v3 tx can carry ~0.5 GB of PQ blobs
- **Location:** `serializeAsBinary` → `BinaryInputStreamSerializer::operator()(std::string&)`
  (`:98`, 128 MiB cap) applied to `nullifier`, `ringSig`, `key`, `kemCt` (`CryptoNoteSerialization.cpp:291`
  –`:297`); `outputIndexes` via `beginArray` (`:44`, 128 Mi-entries → up to 512 MB).
- **Issue:** `check_pq_tx_input` later rejects wrong-length `nullifier` (`:2440`) and `ringSig`
  (via `ccx_pq_verify`'s `sig_len` check), and `key`/`kemCt` length on spend — but only **after**
  deserialization has already allocated the blobs. A peer can send a v3 tx with 4×128 MB blobs and a 512 MB
  `outputIndexes` and force ~1 GB of allocation + copies before rejection. Pre-existing for other fields,
  but PQ adds four new large attacker-controlled byte vectors with no tight cap.
- **Fix:** validate `nullifier.size()==PQ_NULLIFIER_SIZE`, `key.size()==pkBytes`,
  `kemCt.size()==KEM_CT`, and a sane `ringSig`/ring-size cap at *deserialization* or earliest validation,
  before bulk allocation.

### M3. `check_outs_valid` accepts PqKeyOutput with arbitrary-length / wrong-length key into `m_pqOutputs`
- **Location:** `CryptoNoteFormatUtils.cpp:344`–`:355` (only checks `amount != 0` and `key` non-empty);
  index insert at `Blockchain.cpp:3178`.
- **Issue:** A PqKeyOutput whose `key.size() != pkBytes` (or oversized `kemCt`) passes output validation and
  is inserted into `m_pqOutputs`. It can never be spent (`check_pq_tx_input` rejects wrong-length members at
  `:2496`), but it permanently bloats the index and shifts global indices, and signals that output-side
  length validation is weaker than input-side. On mainnet this is an index-poisoning vector.
- **Fix:** in `check_outs_valid`/`check_tx_outputs_visitor`, require `key.size()==ccx_pq_pubkey_bytes()` and
  `kemCt.size()==ccx_pq_kem_ct_bytes()` (or empty) for PqKeyOutput.

### M4. `getTransactionPqSigningHash` slices the prefix but does not exclude the nullifier/amount from each input
- **Location:** `Blockchain.cpp:2426`–`:2438`.
- **Issue:** The signed message clears only `ringSig` per PQ input, leaving `amount`, `outputIndexes`, and
  `nullifier` in the hash. That's the intended design (sign everything but the sig), and is internally
  consistent with the injector (`pq_injector.cpp:154` hashes the prefix with empty `ringSig`). Flagged only
  to confirm: because `nullifier` is *inside* the signed prefix, a verifier-recovered tag mismatch
  (`:2510`) is the binding, not the hash — which is correct. No action, but note the hash binds the *input*
  amount, so M1's "bind to ring member amount" fix must not change this hash or it desyncs injector/daemon.

---

## LOW

### L1. Release-build `assert`s are the only guard against intra-tx duplicate PQ nullifiers in the mempool
- **Location:** `TransactionPool.cpp:797`–`:806` (`addTransactionInputs`, `assert(r.second)`),
  `:756` (`removeTransactionInputs`, `assert(count)`).
- **Issue:** Two `PqKeyInput`s in one tx sharing a nullifier: `haveSpentInputs` (`:192`) checks the set once
  (empty) and passes; `addTransactionInputs` inserts the first, the second `insert` returns false, but the
  guard is a bare `assert` (compiled out in release) so the tx is still added to the pool. The chain-level
  `pushTransaction` (`:3145`, checked `.second`) catches it at mine time, so no chain corruption — but a
  malformed tx can occupy the pool. Mirrors the legacy multisig pattern, hence LOW.
- **Fix:** promote the assert to a real `if (!r.second) return false;` and track intra-tx nullifier
  uniqueness in `checkTransactionInputs`.

### L2. Testnet difficulty is hard-pinned to 1000, bypassing retarget
- **Location:** `Blockchain.cpp:1018`–`:1024`.
- **Issue:** `getDifficultyForNextBlock` returns a constant 1000 for *all* testnet, not gated behind a PQ
  flag or height. Fine for the PoC, but it's a consensus-affecting shortcut sitting in shared code; if this
  branch ever survives into a non-PoC testnet build it removes difficulty adjustment entirely.
- **Fix:** gate behind a dedicated PoC build flag, not `isTestnet()`.

### L3. Hardcoded testnet KEM secret in-tree
- **Location:** `pqc/include/pq_testnet_kem_keypair.h` (`PQ_TESTNET_KEM_SK`), used by the injector
  (`pq_injector.cpp:108`) and the daemon coinbase (`Currency.cpp` PQ block).
- **Issue:** Anyone with the repo can decapsulate every testnet coinbase `kemCt` and spend the PQ outputs.
  Intended for the demo (the injector *is* the "wallet"), but it must never ship in a mainnet path. The
  `PQ_TESTNET_COINBASE_SEED` comment in `CryptoNoteConfig.h:165` even describes an earlier "single shared
  known key" design — make sure that text doesn't migrate to mainnet config.
- **Fix:** keep strictly testnet-gated; add a build-time assert that these symbols are unreachable when
  `!isTestnet()`.

---

## Rust C-ABI memory-safety assessment (lib.rs / ringsig.rs)

Generally careful. Positives confirmed:
- All FFI entry points null-check pointers and capacity before `from_raw_parts` (e.g. `lib.rs:60`,
  `:77`, `:98`–`:103`, `:125`–`:127`, `:199`–`:205`, `:220`–`:225`).
- `ccx_pq_sign` implements the two-call size-query pattern and rechecks `*sig_len` (`:100`–`:101`).
- `ccx_pq_verify` requires `sig_len == ring_sig_size(ring_count)` (`:127`) before slicing, and
  `ringsig::verify` re-checks `sig.len() == sig_bytes(n)` (`ringsig.rs:233`) before any `get_veck/get_vecl`
  indexing — so the `b[*off..*off+4]` reads (`ringsig.rs:127`) are in-bounds. No panic path found there.
- No `unwrap()` on attacker data; KEM `from_bytes` failures return `-1` rather than panicking.

Concerns:
- **A-1 (LOW):** `split_ring` (`lib.rs:87`–`:90`) reads `ringb[off..off+PK]` with
  `off = i*member_stride`. The caller passes `member_stride = pkBytes` and `ring_count` derived from the
  C++ side; `ringb` is `ring_count*member_stride` long (`:107`,`:130`), so it's consistent. But the bound
  relies on the caller never passing `member_stride < PK` — guarded by `member_stride < PK` checks at
  `:103` and `:126`. OK, but the invariant is implicit; a future caller mismatch would slice OOB and panic
  (Rust panics unwind into C++ = UB across the `extern "C"` boundary, since these are not `catch_unwind`-
  wrapped). Recommend wrapping every `extern "C"` body in `std::panic::catch_unwind` so a panic becomes an
  error code, never UB.
- **A-2 (LOW):** `i_tag` in `verify` is taken from the signature (`ringsig.rs:238`) and returned as the
  nullifier source. This is by design (the tag is bound by the chain closure, see H1), but it means the
  nullifier the daemon stores is *attacker-supplied bytes that merely passed the closure check*. The
  closure soundness (H1) is what makes this safe; at demo parameters it is not safe. No memory issue.
- **A-3 (INFO):** `sample_challenge` (`ringsig.rs:112`–`:121`) loops until TAU coeffs placed; with a
  degenerate XOF this could spin, but SHAKE256 output makes that practically impossible. `sign` bounds
  rejection attempts to 256 (`:169`) and returns `None`. Fine.

---

## Cross-cutting consensus observations

- **PQ vs normal output theft:** A PQ input can only resolve ring members from `m_pqOutputs` (PqKeyOutputs);
  a normal KeyInput resolves from `m_outputs` (KeyOutputs). The two indexes are disjoint by output target
  type (`pushTransaction` `:3172` vs `:3178`). So a PQ tx cannot reference/steal a normal KeyOutput and vice
  versa — **good, the two systems are isolated.**
- **Coinbase manipulation:** `validate_miner_transaction` (`:1458`) sums *all* baseTransaction outputs
  including the PqKeyOutput, so the PQ coinbase split (`Currency.cpp` PQ block) is reward-conserving and
  cannot inflate. `is_coinbase` correctly still requires a single `BaseInput` (`CryptoNoteBasicImpl.cpp:66`),
  so a PQ input can't masquerade as coinbase. **Good.**
- **Reorg symmetry:** `popTransaction` (`Blockchain.cpp:3196`+) now pops PqKeyOutputs LIFO with the same
  consistency checks as KeyOutputs (`:3241`–`:3273`) and erases PQ nullifiers (`:3329`–`:3337`), and
  `pushTransaction`'s rollback lambda (`:3096`) dispatches on input type. The in-memory reorg path looks
  symmetric. **The asymmetry is only with persistence (C1):** a reorg that crosses a restart boundary
  inherits C1's empty-map problem.
- **Version gates:** `check_inputs_types_supported`/`check_outs_valid` correctly require
  `version >= TRANSACTION_VERSION_3` for PQ types, and `serialize(TransactionPrefix)` now allows v3
  (`:201`). The block-version bypass (`pushBlock` `:2888`) is correctly `isTestnet()`-gated.

## Bottom line
The consensus *plumbing* (indexes, reorg pop, type isolation, coinbase accounting, version gates) is
mostly coherent and the FFI is defensively coded. The blocking issues are **C1 (persistence/rebuild gap =
post-restart PQ double-spend)** and **C2 (mixed-tx signature index desync)**, plus the inherent **H1**
(demo-grade crypto). None of C1/C2/M1 are exercised by the single-denomination PoC demo, which is exactly
why they survived. All must be closed before this leaves an ephemeral single-run testnet.
