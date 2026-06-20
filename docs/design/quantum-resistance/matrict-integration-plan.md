# MatRiCT-Au integration — phased plan + adapter design (CIP-0001 C1)

*Concrete blueprint for swapping the bespoke linear ring-sig stand-in for the team's chosen production
scheme, **MatRiCT-Au** (Esgin/Steinfeld/Zhao, PKC 2022; author code at `~/pqc-bench/repo-matrict`). Reads
on top of [`poc-vs-mainnet-report.md`](poc-vs-mainnet-report.md) §10 (the API/data-model facts) and the
scaffold [`~/ccx-pqc-impl`] README (the stub→real-backend plan this realises).*

## 0. The one decision that sets the scope

**MatRiCT-Au is a RingCT confidential-transaction prover, not a bare ring signature.** Adopting it ⇒
Conceal gains **confidential amounts** (it has plaintext amounts today). That is the headline feature
*and* the largest new consensus surface. The plan below assumes **full RingCT** (the reason to pick
MatRiCT-Au at all). A "ring-core-only, keep plaintext amounts" mode is possible but fights the design and
forfeits the benefit — not recommended.

## 1. Target C-ABI (RingCT-shaped) — the new island contract

Today's `pq_ring_sig.h` ABI (`ccx_pq_sign(msgHash, ring, sk, idx) → sig`, `verify → nullifier`) cannot
carry amounts. Introduce a **parallel RingCT ABI** (the existing signature ABI stays for the stand-in /
testnet until cutover). Skeleton:

```c
/* pq_ringct.h — RingCT spend backend (C ABI), MatRiCT-Au behind it. All sizes via the *_bytes() queries
   so the C++ side stays size-agnostic (as it already is for the ring sig). */

/* CRS / public parameters: sampled once from a network-fixed seed, shared by all txs. */
int32_t ccx_rct_setup(const uint8_t *seed, size_t seed_len, ccx_rct_crs **out_crs);
void    ccx_rct_crs_free(ccx_rct_crs *crs);

size_t  ccx_rct_account_bytes(uint32_t ring_size);   /* pk + amount commitment, per member */
size_t  ccx_rct_serial_bytes(void);                  /* the linking tag (= our nullifier) */
size_t  ccx_rct_proof_bytes(uint32_t ring_size, uint32_t n_inputs, uint32_t n_outputs);
size_t  ccx_rct_commitment_bytes(void);              /* one output amount commitment */

/* keygen: spend keypair (sk = short vector r; pk = commitment-style public key). Deterministic from a
   32-byte seed so it stays mnemonic-restorable, like the ML-KEM/ML-DSA keygen. */
int32_t ccx_rct_keygen(const ccx_rct_crs*, const uint8_t seed[32],
                       uint8_t *pk_out, size_t pk_cap, uint8_t *sk_out, size_t sk_cap);

/* serial (nullifier) = H·sk — deterministic, key-derived. */
int32_t ccx_rct_serial(const ccx_rct_crs*, const uint8_t *sk, size_t sk_len,
                       uint8_t *serial_out, size_t serial_cap);

/* SPEND: build + prove. `ring` = ring_size accounts (pk+commitment); `signer_index` = the real spender
   (secret); `in_amounts`/`in_blinds` = the spent inputs; `out_keys`/`out_amounts` = recipients.
   Emits: the proof blob, the per-input serial(s), and the output commitments. `msg_hash` binds the
   Conceal tx-prefix into the Fiat-Shamir transcript (see §3.2). */
int32_t ccx_rct_spend(const ccx_rct_crs*,
                      const uint8_t *msg_hash, size_t msg_hash_len,
                      const uint8_t *ring, uint32_t ring_size, size_t account_stride,
                      uint32_t signer_index,
                      const uint8_t *signer_sk, size_t signer_sk_len,
                      const uint64_t *in_amounts, const uint8_t *in_blinds, uint32_t n_inputs,
                      const uint8_t *out_keys, const uint64_t *out_amounts, uint32_t n_outputs,
                      uint8_t *proof_out, size_t proof_cap, size_t *proof_len_out,
                      uint8_t *serials_out, size_t serials_cap,
                      uint8_t *out_commitments, size_t out_commitments_cap);

/* VERIFY: returns 0 (valid) / negative (invalid). Takes the serials as INPUT (does not recover them) —
   the daemon enforces serial uniqueness against m_spent_pq_nullifiers, exactly as today. */
int32_t ccx_rct_verify(const ccx_rct_crs*,
                       const uint8_t *msg_hash, size_t msg_hash_len,
                       const uint8_t *ring, uint32_t ring_size, size_t account_stride,
                       const uint8_t *proof, size_t proof_len,
                       const uint8_t *serials, uint32_t n_inputs,
                       const uint8_t *out_commitments, uint32_t n_outputs);
```

**Mapping to MatRiCT-Au** (verified API): `ccx_rct_keygen`→`keygen`; `ccx_rct_serial`→`serialgen`
(`s=H·sk`); `ccx_rct_spend`→`spend` (with `mint` for the output commitments, **audit rows = NULL** to
strip accountability); `ccx_rct_verify`→`verify`; `ccx_rct_setup`→`sample_mat_g0/gr/gh/gbig`. The serial
is MatRiCT's `s` lifted out of the proof.

## 2. C++ wrapper responsibilities (the island side)

A `MatRiCTBackend` (Rust or C++ in `pqc/`) that owns what the reference benchmark leaves global:
- **CRS lifetime** — `ccx_rct_setup` once at node start from a network-fixed seed; pass the `crs*` to
  every call (no file-scope statics).
- **Threading** — wrap the (currently non-reentrant) `spend`/`verify` either with per-thread contexts
  (preferred) or a backend mutex (interim). [Milestone in §5.]
- **Ring-size dispatch** — MatRiCT's ring size is compile-time; the wrapper selects the right compiled
  variant (`mrct_n10_* / n50_* / n100_*`) by `ring_size`. [§5.]
- **Serialization** — pack mod-Q coefficients (~31 bits) / QBIG (~57 bits): done in P0-M2, hits **~107 KB**
  (raw `sizeof` ~274–370 KB). This is the floor — **packing alone does NOT reach 58 KB**; that needs
  prover+verifier *proof-compression* (a crypto change — see the P0 note + decision doc D1). This is the wire
  format; it must be canonical + consensus-stable.
- **Nullifier tracking** — none new: the daemon already owns `m_spent_pq_nullifiers`; serial → nullifier.

## 3. Consensus changes (the RingCT value model)

The big new surface — beyond the signature swap:
1. **Outputs carry commitments, not plaintext amounts.** `PqKeyOutput`/the v3 output gains an amount
   commitment; the wallet stores blinds; stealth (ML-KEM) is orthogonal and unchanged.
2. **Balance + range proofs** live in the spend proof (MatRiCT does this internally) — the validator
   calls `ccx_rct_verify`; no separate Bulletproof needed.
3. **Fee handling** — fees become a public/committed value the balance proof accounts for (Monero-style:
   `sum(in) = sum(out) + fee`).
4. **Tx-prefix binding** (§3.2) — extend MatRiCT's Fiat-Shamir `hash()` input to include the Conceal
   tx-prefix hash so the proof binds the whole tx, not just its own body.

## 4. Caps & fusion (raise/redesign)

- **Raise `PQ_MAX_RING_SIZE`** — we lowered it to 8 for the linear stand-in; MatRiCT wants the larger
  rings (10/50/100) its log proof is built for.
- **Raise `CRYPTONOTE_MAX_TX_SIZE_LIMIT`** (~99 KB) — a MatRiCT tx (~58 KB+, multi-in) approaches it.
- **Redesign `FUSION_TX_MAX_SIZE`** (~30 KB) — every PQ scheme blows it; dust consolidation needs a new
  size budget + likely a denomination scheme (PQ output keys are 9–18 KB; many small outputs are costly).

## 5. Phased plan (sequence + gates)

| Phase | Work | Output / gate |
|---|---|---|
| **P0 — library-ize** *(milestones 1+2 done — `~/matrict-lib` on WSL)* | Turn `repo-matrict` into a static lib + clean header; per-ring-size builds + dispatch; thread-safety (PRG/scratch); ARM/AES shim; packed serializer | **M1:** `libmatrict_n{10,50,100}m1.a` + `matrict.h` + dispatcher; correctness 50/50 each. **M2:** canonical range-checked **packed serializer** (`matrict_serialize.{h,c}`) → **107/112/118 KB** (2.7× vs ~292 KB raw raw-sizeof; round-trip byte-exact 30/30). **Full reentrancy** — TLS scratch (`matrict_tls.h`), coarse lock retired, 8-thread 64/64, **TSan 0 races** (API contract: per-call `g_hat`). **aarch64 full run** under qemu (selftest 20/20, serialize 10/10, byte-portable wire). **Size finding:** 107 KB is the **information-theoretic floor** — a measured pass (realized coefficient distributions, 60 runs) shows the responses (73% of the proof) are near-uniform over their norm intervals, so re-encoding wins ~0 KB. The paper's **~58 KB requires commitment (`b`/`c`) high-bit truncation + hint** — a soundness-statement change (verifier-equation rewrite + extractor re-proof + audit), and truncating `b` **conflicts with auditability**. A research-grade sub-project, NOT serialization; the 107 KB packer is the realistic baseline. See decision-doc D1 |
| **P1 — adapter** | Implement `pq_ringct.h` over the lib (keygen/serial/spend/verify, CRS, audit=NULL); unit-test spend→verify + serial==nullifier vs the C++ side | green adapter selftests behind the C ABI |
| **P2 — value model** | v3 output commitments + blinds; wallet commitment bookkeeping; fee-as-committed-value; tx-prefix FS binding; validator calls `ccx_rct_verify` | a RingCT v3 tx builds + validates on a local testnet |
| **P3 — caps/fusion** | Raise `MAX_TX_SIZE` + `PQ_MAX_RING_SIZE`; redesign `FUSION_TX` + denomination | fusion works at PQ sizes |
| **P4 — e2e + perf** | A/B on the 2-node testnet (spend/receive/double-spend); measure real packed sizes + verify-ms vs the 58 KB/45 ms target | numbers match the team bench |
| **P5 — AUDIT (hard gate)** | Professional review of MatRiCT-Au construction + the integration + constant-time; calibrate params | **mainnet activation gate** — do not ship before this |
| **P6 — fork** | New tx version, height-gated activation, hybrid period (`ccxh`), coordinated upgrade | mainnet |

**Dependencies:** P1←P0; P2←P1; P3∥P2; P4←P2,P3; P5←P4; P6←P5. The bespoke linear stand-in remains the
testnet backend through P0–P4 (the swappable slot lets both coexist).

## 6. Open decisions (for the team)

1. **Full RingCT (confidential amounts) — confirm.** It's MatRiCT-Au's reason for existing; assumed yes.
2. **Ring-size policy** — which fixed sizes to compile (10/50/100?) and the dispatch UX, vs investing in
   true runtime-N (a large rewrite of the reference's static arrays).
3. **Accountability/Audit layer** — strip (privacy coin) or keep (regulatory optionality)? Plan assumes
   strip (`t*=NULL`).
4. **ARM/mobile** — is an ARM node a target? (decides P0's AES-shim priority).
5. **Migration of existing classical balances** — hybrid period length; whether old plaintext-amount
   outputs are spendable post-fork or must be swept.

## 7. Effort (honest)

Multi-month. P0 (library-ize) — **milestone 1 landed** (`~/matrict-lib`: 3 namespaced static libs + `matrict.h` +
size dispatcher, correctness preserved; original `repo-matrict` untouched; see its `README.md`). The plan's §1
API mapping is now validated against the real lib (it exposes `sample_mat_g0/gr/gh/gbig`, `keygen`, `mint`,
`serialgen`, `spend`, `verify`, optional `audit`). P0 remainder = packed serializer + full reentrancy (+ aarch64
run). P2 (RingCT value model) = the largest single chunk; P5 (audit) =
external + the schedule driver. The PoC already removed the *integration-plumbing* risk (tx format,
serialization, double-spend set, stealth, wallet send/receive, deposits, messages, constant-time
discipline, the swappable slot) — so this plan is "drop the engine into a proven chassis + go RingCT",
not "build the car".
