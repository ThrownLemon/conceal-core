# ccx-pqc — Conceal PQ crypto module (C-ABI)  [branch: pqc/v2-impl]

The Rust crypto module the C++ daemon links via FFI (CIP-0001 §12, `librustzcash` model).

- `include/pq_ring_sig.h` — the swappable backend C ABI (CIP §5.3).
- `ccx-pqc/` — Rust impl: **real ML-KEM-768** (stealth KEM) + **ML-DSA/Dilithium** (deposit sig);
  the **linkable ring signature is an INSECURE STUB** (correct sizes, `H(pubkey)` nullifier,
  deterministic) so the rest of the integration can be built + tested before the audited
  lattice backend (C1) drops in behind the same ABI.
- `CMakeLists.txt` / `test_pqc.cpp` — build + end-to-end test.

## Build & test
```
cmake -S pqc -B pqc/build && cmake --build pqc/build && ./pqc/build/test_pqc
```
Expected: ML-KEM/ML-DSA roundtrip OK; stub ring-sig keygen→sign→verify→nullifier `ALL=PASS`.

## Status
Decision-independent scaffold DONE. Next (bigger, consensus-adjacent, after team wire-format
sign-off): C++ `PqRingSignature` wrapper, v2 variable-length serialization in `src/Serialization`,
and the validation skeleton in `Blockchain.cpp` against this stub. Real ring-sig crypto = C1 (audit-gated).
