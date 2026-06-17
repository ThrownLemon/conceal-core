# PQ Migration — Code Spike (grounding for CIP-0001)

**Branch:** `pqc/v2-spike` (code; the spec/docs live on `docs/quantum-resistance`). Throwaway grounding, not production.

## What this proves (all built + run on the WSL x86_64 host)
- **FFI seam (CIP §12):** Rust crypto static lib → C ABI → C++ links and runs. `librustzcash`-style.
- **Real PQ primitives through FFI (CIP §5.2/§7):** `rust/` exposes ML-KEM-768 (stealth KEM) + ML-DSA/Dilithium3 (deposit sig) via `cpp/pqc.h`. Measured: ML-KEM-768 pk 1184 / ct 1088 / ss 32 (roundtrip OK); ML-DSA pk 1952 / sig 3331 (verify OK).
- **cargo↔CMake integration:** `CMakeLists.txt` builds the Rust lib via cargo and links the C++ target. Resolves a §13 build-integration unknown.
- **v2 wire format round-trips (CIP §6.2 / wire-format-v2.md):** `cpp/v2ser.cpp` serializes + deserializes the v2 TLV layout (varint + length-prefixed blobs); round-trip OK; real serialized sizes match `wire-size-calc.py` (MatRiCT avg ~50 KB, p90 ~115 KB, fusion ~878 KB; Raptor avg ~38 KB; Falafl fusion ~1.6 MB).

## Build
```
cd rust && cargo build --release           # Rust PQ crypto static lib
cd .. && cmake -S . -B build && cmake --build build && ./build/pqc_test   # FFI via CMake
g++ -std=c++11 -O2 cpp/v2ser.cpp -o v2ser && ./v2ser                      # v2 serialization round-trip
```
Deps: Rust (rustup), gcc, cmake. Crates: `pqcrypto-kyber` (≈ML-KEM-768), `pqcrypto-dilithium` (≈ML-DSA).

## NOT done here (gated / out of scope for a spike)
- **Consensus-validation integration** (the rest of B1) — modifying `conceald`'s `Blockchain` validation is consensus-critical + premature before the scheme/params (§13) are fixed. This spike grounds serialization + FFI + sizes only.
- The real **lattice linkable ring signature** (C1) — needs the audited scheme; here the ring-sig is a sized placeholder blob.
