# Cross-Platform Keygen KAT Matrix — 6 Platforms

**Status: Raptor/Falcon keygen KAT COMPLETE across all 6 platforms (byte-identical output).
Full PQ-artifact determinism matrix (ML-KEM, ML-DSA, address-v2 bytes, wallet PQ-section bytes,
serialized PQ tx fixtures) is OPEN/pending — those artifacts are not yet KAT-pinned across arches.**

The Falcon-512 integer-emulated FP keygen is bit-identical across all tested platforms —
confirming cross-platform consensus determinism for the keygen path (no chain-split risk from
keygen divergence). This scope is keygen only; see the OPEN items above for the remaining
PQ artifacts.

## Matrix

| # | Platform | Compiler | Arch | KAT Digest | Match |
|---|----------|----------|------|------------|-------|
| 1 | linux-x86_64 | gcc 13.3 | x86_64 | `8f245c82dc7390f3cb4d8955556a45d56af41c83a37fc0388b996b58f295745e` | ✅ |
| 2 | linux-aarch64 | gcc 13.3 (cross, QEMU) | aarch64 | `8f245c82…f295745e` | ✅ |
| 3 | linux-i686 | gcc 13.3 (cross) | x86 (32-bit) | `8f245c82…f295745e` | ✅ |
| 4 | macos-aarch64 | Apple clang | aarch64 | `8f245c82…f295745e` | ✅ |
| 5 | windows-gnu | gcc (MinGW) | x86_64 | `8f245c82…f295745e` | ✅ |
| 6 | windows-msvc | MSVC `cl` | x86_64 | `8f245c82…f295745e` | ✅ |

**Coverage:** 3 compilers (gcc, MSVC, clang) × 2 architectures (x86_64, aarch64) × 3 OSes
(Linux, macOS, Windows) × 2 word sizes (64-bit, 32-bit).

## Method

Each platform runs `raptor::keygen_kat_digest()` (from `examples/kat_digest.rs`), which:
1. Derives a fixed Falcon keypair from the pinned KAT seed (`"RAPTOR-CCX-KAT-seed-v0"`).
2. Computes `SHAKE256_32(modq_encode(a0) || modq_encode(aots))`.
3. Prints the hex digest and checks it against the pinned constant.

**Platforms 1-3** were run on the WSL build host (Ubuntu 24.04, x86_64). Platform 2 used
`aarch64-linux-gnu-gcc` cross-compilation + `qemu-aarch64-static -L /usr/aarch64-linux-gnu`.
Platform 3 used `i686-linux-gnu-gcc` cross-compilation (native execution on x86_64).

**Platforms 4-6** were verified in the prior session (see `measured-numbers.md` §I.1).

## FFI portability fix applied

`falcon_ffi.rs:35` — changed `domain: *const i8` to `domain: *const core::ffi::c_char`.
The C `char` type is signed (`i8`) on x86_64/aarch64 Linux but unsigned (`u8`) on some ARM
targets. Using `c_char` makes the FFI declaration correct on all platforms without affecting
the x86_64 build (where `c_char == i8`).

## Reproduction

```bash
# Native x86_64
cargo run --release --example kat_digest

# Cross-compile aarch64 (QEMU)
CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
cargo build --target aarch64-unknown-linux-gnu --example kat_digest --release
qemu-aarch64-static -L /usr/aarch64-linux-gnu \
  target/aarch64-unknown-linux-gnu/release/examples/kat_digest

# Cross-compile i686 (32-bit)
CC_i686_unknown_linux_gnu=i686-linux-gnu-gcc \
CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=i686-linux-gnu-gcc \
AR_i686_unknown_linux_gnu=i686-linux-gnu-ar \
cargo build --target i686-unknown-linux-gnu --example kat_digest --release
./target/i686-unknown-linux-gnu/release/examples/kat_digest
```
