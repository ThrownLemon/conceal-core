// build.rs — compile the vendored PQClean Falcon-512 "clean" sources + our C shim into a static lib
// linked into the crate.  All vendored C is MIT (Falcon Project) / public-domain (PQClean fips202,
// randombytes).  See vendor/falcon/LICENSE.falcon and PROGRESS.md provenance.
//
// FLOATING-POINT DETERMINISM (consensus-critical): the PQClean "clean" variant of Falcon ships ONLY
// the emulated, integer-only fpr layer (`typedef uint64_t fpr;`; fpr.c is pure uint64 arithmetic;
// set_fpu_cw() is a no-op stub).  There is NO native-`double` path and NO FALCON_FPNATIVE/FALCON_FPEMU
// conditional here, so Falcon keygen AND signing are bit-exact across compilers, optimisation levels
// and -march (verified by a cross-config keygen-KAT sweep).  The strict-FP flags below are a
// belt-and-braces no-op for the integer-only sources.
//
// SYMBOL NAMESPACING (consensus-critical): this crate ALSO links pqcrypto-kyber / pqcrypto-dilithium,
// which each bundle their own copy of PQClean's `fips202.c` (+ randombytes) exporting the SAME
// unnamespaced symbols (shake256_inc_*, sha3_*, randombytes, …).  Two definitions with potentially
// different `shake256incctx` layouts in one archive => the linker binds Falcon's `inner_shake256_*`
// (which inner.h maps to shake256_inc_*) to the WRONG implementation => state-struct overflow / stack
// smash.  We therefore rename every fips202 public symbol Falcon defines+uses to a `ccxfalcon_`-prefixed
// name via -D, applied to ALL Falcon translation units so definition and call sites stay consistent,
// fully isolating Falcon's hashing (the consensus-critical collision) from the pqcrypto crates'.
// NOTE on `randombytes`: vendor/falcon/randombytes.h carries its OWN `#define randombytes
// PQCLEAN_randombytes`, which (being in-source) wins over our command-line -D, so Falcon's randombytes
// resolves to `PQCLEAN_randombytes` rather than `ccxfalcon_randombytes`.  Verified harmless: `nm` shows
// a single `PQCLEAN_randombytes` def and ZERO undefined `randombytes` refs — Falcon's deterministic
// keygen/sign here are seeded (inner_shake256 over a caller seed) and never call OS randombytes, and
// det-keygen is confirmed bit-exact (KAT sweep).  The -D for randombytes is thus a no-op kept only for
// documentation symmetry.

use std::path::PathBuf;

fn main() {
    let vendor = PathBuf::from("vendor/falcon");

    let falcon_srcs = [
        "codec.c", "common.c", "fft.c", "fpr.c", "keygen.c",
        "rng.c", "sign.c", "vrfy.c",
        // PQClean common deps Falcon's inner.h binds to:
        "fips202.c", "randombytes.c",
    ];

    // Every public symbol Falcon's fips202.h declares + randombytes — renamed to ccxfalcon_* so they
    // never collide with the identical symbols bundled by pqcrypto-kyber/pqcrypto-dilithium.
    let rename_syms = [
        "sha3_256", "sha3_256_inc_absorb", "sha3_256_inc_ctx_clone", "sha3_256_inc_ctx_release",
        "sha3_256_inc_finalize", "sha3_256_inc_init",
        "sha3_384", "sha3_384_inc_absorb", "sha3_384_inc_ctx_clone", "sha3_384_inc_ctx_release",
        "sha3_384_inc_finalize", "sha3_384_inc_init",
        "sha3_512", "sha3_512_inc_absorb", "sha3_512_inc_ctx_clone", "sha3_512_inc_ctx_release",
        "sha3_512_inc_finalize", "sha3_512_inc_init",
        "shake128", "shake128_absorb", "shake128_ctx_clone", "shake128_ctx_release",
        "shake128_inc_absorb", "shake128_inc_ctx_clone", "shake128_inc_ctx_release",
        "shake128_inc_finalize", "shake128_inc_init", "shake128_inc_squeeze", "shake128_squeezeblocks",
        "shake256", "shake256_absorb", "shake256_ctx_clone", "shake256_ctx_release",
        "shake256_inc_absorb", "shake256_inc_ctx_clone", "shake256_inc_ctx_release",
        "shake256_inc_finalize", "shake256_inc_init", "shake256_inc_squeeze", "shake256_squeezeblocks",
        "randombytes",
    ];
    let renames: Vec<(String, String)> = rename_syms
        .iter()
        .map(|s| (s.to_string(), format!("ccxfalcon_{}", s)))
        .collect();

    let mut build = cc::Build::new();
    build
        .include(&vendor)
        .include("csrc")
        // Integer-only fpr (no native double) — see header comment.  Pin strict FP semantics defensively.
        .flag_if_supported("-ffp-contract=off")
        .flag_if_supported("-fno-fast-math")
        .opt_level(3)
        .warnings(false);

    for (from, to) in &renames {
        build.define(from.as_str(), Some(to.as_str()));
    }

    for s in falcon_srcs {
        build.file(vendor.join(s));
    }
    // our clean-room shim
    build.file("csrc/raptor_falcon.c");

    build.compile("raptorfalcon");

    println!("cargo:rerun-if-changed=csrc/raptor_falcon.c");
    println!("cargo:rerun-if-changed=vendor/falcon");
}
