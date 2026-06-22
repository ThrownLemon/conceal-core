# Cross-Platform PQ KAT Matrix

**Status:** executable M-new-4 coverage is now present for the key material and serializer artifacts
called out in the audit brief. The Rust keygen artifacts are cross-arch verified by the
`pq-determinism` job; the C++ address/wallet-section/transaction artifact digest is enforced by the
normal `UnitTests` jobs.

## Pinned Digests

| Artifact set | Test | Pinned digest | Current local evidence | CI enforcement |
|---|---|---|---|---|
| Raptor/Falcon keygen bytes | `raptor::determinism_kat::keygen_kat_matches_reference` | `8f245c82dc7390f3cb4d8955556a45d56af41c83a37fc0388b996b58f295745e` | WSL x86_64 plus QEMU aarch64, i686, s390x all pass | `pq-determinism` |
| ML-KEM-768 and ML-DSA-65 C-ABI deterministic key bytes, plus the Raptor digest | `detkeygen::determinism_kat::keygen_kat_mlkem_mldsa_artifact_matrix_matches_reference` | `494d647f7fb0892902670ea2daba352d11b8b8c699e60de2fb1301d8c65061f8` | WSL x86_64 plus QEMU aarch64, i686, s390x all pass | `pq-determinism` |
| C++ PQ artifacts: ML-KEM/ML-DSA account keys, Raptor key/nullifier, address-v2 binary bytes, testnet base58 address string, wallet PQ-section v2 bytes, serialized v4 PQ transaction bytes | `PqArtifactKat.FullMatrixDigestMatchesReference` | `cad7eea17e1d6bb89898f7faa6d8fb1960b70edcd29e396fcaf8a544e340e441` | WSL x86_64 `UnitTests` pass | All existing `UnitTests` CI jobs: Windows/MSVC, MinGW, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 22.04 clang, macOS |

## What Each KAT Pins

### Rust keygen/artifact KAT

The `pq-determinism` workflow runs `cargo test --release --target <arch> keygen_kat -- --nocapture`
for:

- `aarch64-unknown-linux-gnu` under `qemu-aarch64-static`
- `i686-unknown-linux-gnu` under `qemu-i386-static`
- `s390x-unknown-linux-gnu` under `qemu-s390x-static`

The `keygen_kat` filter now covers two pinned tests:

1. `keygen_kat_matches_reference`: derives a fixed Raptor/Falcon keypair from
   `"RAPTOR-CCX-KAT-seed-v0"` and checks `SHAKE256_32(modq_encode(a0) || modq_encode(aots))`.
2. `keygen_kat_mlkem_mldsa_artifact_matrix_matches_reference`: derives deterministic
   ML-KEM-768 and ML-DSA-65 keypairs through the exported C ABI, label/length-frames their public and
   secret key bytes together with the Raptor digest, then checks a pinned SHAKE256 digest.

This covers little-endian 64-bit, little-endian 32-bit, and big-endian 64-bit Linux for the
seed-derived PQ key material.

### C++ serializer artifact KAT

`PqArtifactKat.FullMatrixDigestMatchesReference` uses production C++ serializers where they exist:

- `PqAccount::generateFromSeed()` for deterministic ML-KEM/ML-DSA account keys.
- `ccx_pq_keygen()` and `ccx_pq_nullifier()` for deterministic Raptor public/secret/nullifier bytes.
- `toBinaryArray(PqAccountPublicAddress)` for canonical address-v2 binary bytes.
- `getPqAccountAddressAsStr(TESTNET_PUBLIC_PQ_ADDRESS_BASE58_PREFIX, ...)` for the testnet base58
  address string.
- A wallet-section-shaped v2 fixture that includes KEM and DSA scheme IDs plus KEM/DSA key material.
- `toBinaryArray(Transaction)` for a deterministic v4 PQ transaction carrying PQ spend and PQ deposit
  variants.

The transcript is label/length-framed before hashing so the digest is independent of C++ object
memory layout. This test belongs in `UnitTests` because it exercises production C++ serializers, not
only Rust keygen bytes.

## Reproduction

```bash
# Rust native keygen/artifact KATs
cd pqc/ccx-pqc
cargo test --release keygen_kat -- --nocapture

# Rust cross-arch keygen/artifact KATs
CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=qemu-aarch64-static \
QEMU_LD_PREFIX=/usr/aarch64-linux-gnu \
cargo test --release --target aarch64-unknown-linux-gnu keygen_kat -- --nocapture

CC_i686_unknown_linux_gnu=i686-linux-gnu-gcc \
CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=i686-linux-gnu-gcc \
CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_RUNNER=qemu-i386-static \
QEMU_LD_PREFIX=/usr/i686-linux-gnu \
cargo test --release --target i686-unknown-linux-gnu keygen_kat -- --nocapture

CC_s390x_unknown_linux_gnu=s390x-linux-gnu-gcc \
CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER=s390x-linux-gnu-gcc \
CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER=qemu-s390x-static \
QEMU_LD_PREFIX=/usr/s390x-linux-gnu \
cargo test --release --target s390x-unknown-linux-gnu keygen_kat -- --nocapture

# C++ serializer artifact KAT
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --target UnitTests
./build/tests/unit_tests --gtest_filter=PqArtifactKat.FullMatrixDigestMatchesReference --gtest_color=no
```

## Residual Note

The Rust key material KAT is directly cross-arch in `pq-determinism`. The C++ serializer artifact KAT
is enforced by the normal multi-OS/compiler `UnitTests` matrix. If the release process requires the
same C++ serializer artifact on big-endian Linux specifically, add a dedicated cross-compiled C++
`UnitTests` shard; the current job matrix does not run the C++ test binary under s390x QEMU.
