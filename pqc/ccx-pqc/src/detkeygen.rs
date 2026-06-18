//! Deterministic, seed-based FIPS-203 (ML-KEM-768) and FIPS-204 (ML-DSA-65) key generation.
//!
//! WHY THIS EXISTS (funds-loss blocker): `ccx_pq_kem_keypair` / `ccx_pq_multisig_keypair` use
//! pqcrypto's RNG-based `keypair()` (OS entropy), so the keys they produce are NOT derivable from a
//! seed. CryptoNote wallets are mnemonic-restorable — the whole spend key is recovered from a seed
//! phrase. If the PQ half of a wallet is RNG-generated, a mnemonic backup CANNOT restore it: the
//! user would have to back up multi-kilobyte raw PQ secret keys out-of-band, an error-prone
//! funds-loss regression. These two functions close that gap; the existing RNG functions are kept
//! for back-compat (minting the testnet recipient / injector keypairs).
//!
//! HOW: FIPS 203 and FIPS 204 both specify a fully deterministic KeyGen from a short seed (ML-KEM:
//! a 64-byte `d || z`; ML-DSA: a 32-byte `xi`). pqcrypto wraps only the randomized variant, so we
//! use the RustCrypto `ml-kem` / `ml-dsa` crates, which expose the standardized seed-based KeyGen.
//! The caller passes ANY-length seed (the wallet master seed); we domain-separate + SHAKE256-expand
//! it to the exact FIPS seed length, so the same input seed always yields the same keypair, across
//! processes and machines (the determinism property the wallet relies on).
//!
//! COMPATIBILITY (critical): the rest of `lib.rs` does encap/decap (ML-KEM) and sign/verify (ML-DSA)
//! through `pqcrypto`. The keys produced here are exported in the SAME byte encodings pqcrypto uses
//! — the FIPS public key, and the *expanded* secret key (ML-KEM dkEncode 2400 B; ML-DSA skEncode
//! 4032 B) — so a deterministic keypair is a drop-in for the existing pqcrypto code path and the
//! on-chain artifact formats are byte-identical. `ccx_pq_detkeygen_selftest` PROVES this empirically:
//! it encaps/decaps and signs/verifies a deterministic keypair THROUGH the pqcrypto primitives and
//! asserts they round-trip, so a silent cross-library encoding drift can never ship unnoticed.

use crate::{ffi_guard, CcxPqSizes, CCX_SIZES_PANIC};
use sha3::Shake256;
use sha3::digest::{Update, ExtendableOutput, XofReader};

// FIPS byte-encoding sizes for ML-KEM-768 / ML-DSA-65 (must match the pqcrypto-backed constants in
// lib.rs: KEM_PK=1184, KEM_SK=2400, multisig pk=1952, multisig sk=4032).
pub const DET_KEM_PK: usize = 1184;   // FIPS-203 ek (encapsulation/public key)
pub const DET_KEM_SK: usize = 2400;   // FIPS-203 expanded dk (decapsulation/secret key)
pub const DET_DSA_PK: usize = 1952;   // FIPS-204 pkEncode (verifying key)
pub const DET_DSA_SK: usize = 4032;   // FIPS-204 skEncode (expanded signing key)

// Minimum input-seed length (FIX 6). The wallet master seed has >= 256 bits of entropy; reject a
// caller that passes a short/low-entropy seed so PQ keys can never be derived from < 32 bytes.
const MIN_SEED_LEN: usize = 32;

// Network/chain tag bound into the keygen domain (FIX 7) so testnet vs mainnet PQ keys differ and keys
// are chain-bound. MUST be finalized before any wallet ships (the wallet derives keys via these FFIs
// opaquely, so only the resulting address bytes change pre-launch). A future mainnet build is a
// one-line change here (e.g. b"ccx-mainnet"). Stays b"ccx-testnet" while this is testnet-only.
const NETWORK_TAG: &[u8] = b"ccx-testnet";

/// Domain-separated SHAKE256 expansion of an arbitrary-length input seed to exactly `OUT` bytes.
/// Mirrors how `ccx-stealth-otk` already derives sub-secrets, so PQ keygen joins the same HD/mnemonic
/// derivation discipline. The (purpose `domain` + `NETWORK_TAG`) pins both the *purpose* and the
/// *chain*, so the same wallet seed yields independent ML-KEM / ML-DSA keys AND distinct keys per
/// network.
fn expand_seed<const OUT: usize>(domain: &[u8], seed: &[u8]) -> [u8; OUT] {
    let mut x = Shake256::default();
    Update::update(&mut x, domain);
    Update::update(&mut x, NETWORK_TAG);
    Update::update(&mut x, seed);
    let mut out = [0u8; OUT];
    x.finalize_xof().read(&mut out);
    out
}

/// Pure Rust computation of the deterministic ML-KEM-768 keypair from a 64-byte FIPS seed.
/// Returns (pk 1184 B, sk 2400 B expanded), or None on an (unexpected) size mismatch.
#[allow(deprecated)] // to_expanded_bytes is the pqcrypto-compatible encoding we deliberately want
fn mlkem_keypair_from_fips_seed(fips_seed: [u8; 64]) -> Option<(Vec<u8>, Vec<u8>)> {
    use ml_kem::{DecapsulationKey768, KeyExport, ExpandedKeyEncoding};
    let seed = ml_kem::array::Array::<u8, ml_kem::array::typenum::U64>(fips_seed);
    let dk = DecapsulationKey768::from_seed(seed);
    let pk = dk.encapsulation_key().to_bytes();   // FIPS ek encoding (1184 B)
    let sk = dk.to_expanded_bytes();              // FIPS expanded dk encoding (2400 B) == pqcrypto sk
    if pk.len() != DET_KEM_PK || sk.len() != DET_KEM_SK { return None; }
    Some((pk.to_vec(), sk.to_vec()))
}

/// Pure Rust computation of the deterministic ML-DSA-65 keypair from a 32-byte FIPS seed.
/// Returns (pk 1952 B, sk 4032 B expanded), or None on an (unexpected) size mismatch.
#[allow(deprecated)] // to_expanded is the pqcrypto-compatible (FIPS skEncode) encoding we want
fn mldsa_keypair_from_fips_seed(fips_seed: [u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
    use ml_dsa::{MlDsa65, SigningKey, B32};
    use ml_dsa::signature::Keypair;
    let xi: B32 = hybrid_array::Array(fips_seed);
    let ssk = SigningKey::<MlDsa65>::from_seed(&xi);
    let pk = ssk.verifying_key().encode();        // FIPS pkEncode (1952 B)
    let sk = ssk.expanded_key().to_expanded();    // FIPS skEncode expanded (4032 B) == pqcrypto sk
    if pk.len() != DET_DSA_PK || sk.len() != DET_DSA_SK { return None; }
    Some((pk.to_vec(), sk.to_vec()))
}

/// Deterministic ML-KEM-768 keygen (FIPS-203 KeyGen). The input `seed` (the wallet master seed, >= 32
/// bytes) is SHAKE256-expanded — under the keygen domain + network tag — to the 64-byte `d || z` FIPS
/// seed. Writes the 1184-byte FIPS public (encapsulation) key to `pk_out` and the 2400-byte expanded
/// secret (decapsulation) key to `sk_out`, in the encoding pqcrypto's encap/decap path consumes. Same
/// seed -> identical keypair. Returns 0 on success; negative on error (a seed shorter than 32 bytes
/// returns -1; matches `ccx_pq_kem_keypair`'s contract otherwise).
#[no_mangle]
pub extern "C" fn ccx_pq_kem_keygen_det(seed: *const u8, seed_len: usize,
                                        pk_out: *mut u8, pk_cap: usize,
                                        sk_out: *mut u8, sk_cap: usize) -> i32 {
  ffi_guard(-99, || {
    if seed.is_null() || pk_out.is_null() || sk_out.is_null() { return -1; }
    if seed_len < MIN_SEED_LEN { return -1; } // reject low-entropy seeds (FIX 6)
    if pk_cap < DET_KEM_PK || sk_cap < DET_KEM_SK { return -2; }
    let seed_in = unsafe { std::slice::from_raw_parts(seed, seed_len) };
    let fips_seed = expand_seed::<64>(b"ccx-pq-mlkem768-keygen-v1", seed_in);
    let (pk, sk) = match mlkem_keypair_from_fips_seed(fips_seed) { Some(p) => p, None => return -7 };
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, DET_KEM_PK);
        std::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, DET_KEM_SK);
    }
    0
  })
}

/// Deterministic ML-DSA-65 keygen (FIPS-204 KeyGen). The input `seed` (the wallet master seed, >= 32
/// bytes) is SHAKE256-expanded — under the keygen domain + network tag — to the 32-byte `xi` FIPS seed.
/// Writes the 1952-byte FIPS public (verifying) key to `pk_out` and the 4032-byte expanded secret
/// (signing) key to `sk_out`, in the encoding pqcrypto's sign/verify path consumes. Same seed ->
/// identical keypair. Returns 0 on success; a seed shorter than 32 bytes returns -1.
#[no_mangle]
pub extern "C" fn ccx_pq_multisig_keygen_det(seed: *const u8, seed_len: usize,
                                             pk_out: *mut u8, pk_cap: usize,
                                             sk_out: *mut u8, sk_cap: usize) -> i32 {
  ffi_guard(-99, || {
    if seed.is_null() || pk_out.is_null() || sk_out.is_null() { return -1; }
    if seed_len < MIN_SEED_LEN { return -1; } // reject low-entropy seeds (FIX 6)
    if pk_cap < DET_DSA_PK || sk_cap < DET_DSA_SK { return -2; }
    let seed_in = unsafe { std::slice::from_raw_parts(seed, seed_len) };
    let fips_seed = expand_seed::<32>(b"ccx-pq-mldsa65-keygen-v1", seed_in);
    let (pk, sk) = match mldsa_keypair_from_fips_seed(fips_seed) { Some(p) => p, None => return -7 };
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, DET_DSA_PK);
        std::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, DET_DSA_SK);
    }
    0
  })
}

/// Selftest for the deterministic PQ keygen — proves the two properties the wallet relies on:
///   1. DETERMINISM: the same seed twice yields byte-identical (pk, sk) for both ML-KEM and ML-DSA,
///      and two DIFFERENT seeds yield different keypairs.
///   2. pqcrypto INTEROP: a deterministic ML-KEM keypair encaps/decaps to the same shared secret
///      THROUGH pqcrypto (and a stealth-output scan round-trips); a deterministic ML-DSA keypair
///      signs/verifies THROUGH pqcrypto. This guarantees the keys are byte-compatible with the
///      existing on-chain encap/decap and sign/verify paths (no silent cross-library encoding drift).
/// ok=1 means every check passed.
#[no_mangle]
pub extern "C" fn ccx_pq_detkeygen_selftest() -> CcxPqSizes {
  ffi_guard(CCX_SIZES_PANIC, || {
    use pqcrypto_kyber::kyber768;
    use pqcrypto_dilithium::dilithium3;
    use pqcrypto_traits::kem::{PublicKey as KP, SecretKey as KS, SharedSecret as KSS};
    use pqcrypto_traits::sign::{PublicKey as SP, SecretKey as SS, DetachedSignature as SD};

    let fail = CcxPqSizes { pk: 0, sk: 0, ct_or_sig: 0, ss: 0, ok: 0 };

    // ---- ML-KEM-768 determinism ----
    let seed_a = b"ccx wallet master seed A -- 32+ bytes of entropy";
    let seed_b = b"ccx wallet master seed B -- 32+ bytes of entropy"; // differs from A
    let mut k_pk1 = vec![0u8; DET_KEM_PK]; let mut k_sk1 = vec![0u8; DET_KEM_SK];
    let mut k_pk2 = vec![0u8; DET_KEM_PK]; let mut k_sk2 = vec![0u8; DET_KEM_SK];
    let mut k_pk_b = vec![0u8; DET_KEM_PK]; let mut k_sk_b = vec![0u8; DET_KEM_SK];
    if ccx_pq_kem_keygen_det(seed_a.as_ptr(), seed_a.len(), k_pk1.as_mut_ptr(), DET_KEM_PK, k_sk1.as_mut_ptr(), DET_KEM_SK) != 0 { return fail; }
    if ccx_pq_kem_keygen_det(seed_a.as_ptr(), seed_a.len(), k_pk2.as_mut_ptr(), DET_KEM_PK, k_sk2.as_mut_ptr(), DET_KEM_SK) != 0 { return fail; }
    if ccx_pq_kem_keygen_det(seed_b.as_ptr(), seed_b.len(), k_pk_b.as_mut_ptr(), DET_KEM_PK, k_sk_b.as_mut_ptr(), DET_KEM_SK) != 0 { return fail; }
    let kem_deterministic = (k_pk1 == k_pk2) && (k_sk1 == k_sk2);
    let kem_seed_separation = (k_pk1 != k_pk_b) && (k_sk1 != k_sk_b);

    // ---- ML-KEM-768 pqcrypto interop: encap to det-pk, decap with det-sk ----
    let kem_interop = {
        let pk = match <kyber768::PublicKey as KP>::from_bytes(&k_pk1) { Ok(p) => p, Err(_) => return fail };
        let sk = match <kyber768::SecretKey as KS>::from_bytes(&k_sk1) { Ok(s) => s, Err(_) => return fail };
        let (ss_enc, ct) = kyber768::encapsulate(&pk);
        let ss_dec = kyber768::decapsulate(&ct, &sk);
        ss_enc.as_bytes() == ss_dec.as_bytes()
    };

    // ---- ML-KEM-768 stealth-output scan round-trip through the real ABI ----
    // A sender derives a one-time seed by encapsulating to the det public key; the holder of the det
    // secret key must re-derive the SAME seed by scanning. This is the exact wallet receive path.
    let kem_scan_roundtrip = {
        let mut ct = vec![0u8; super::KEM_CT];
        let mut s_send = [0u8; 32];
        let r1 = super::ccx_pq_kem_derive_output(k_pk1.as_ptr(), k_pk1.len(), ct.as_mut_ptr(), ct.len(), s_send.as_mut_ptr(), 32);
        let mut s_recv = [0u8; 32];
        let r2 = super::ccx_pq_kem_scan(k_sk1.as_ptr(), k_sk1.len(), ct.as_ptr(), ct.len(), s_recv.as_mut_ptr(), 32);
        r1 == 0 && r2 == 0 && s_send == s_recv
    };

    // ---- ML-DSA-65 determinism ----
    let mut d_pk1 = vec![0u8; DET_DSA_PK]; let mut d_sk1 = vec![0u8; DET_DSA_SK];
    let mut d_pk2 = vec![0u8; DET_DSA_PK]; let mut d_sk2 = vec![0u8; DET_DSA_SK];
    let mut d_pk_b = vec![0u8; DET_DSA_PK]; let mut d_sk_b = vec![0u8; DET_DSA_SK];
    if ccx_pq_multisig_keygen_det(seed_a.as_ptr(), seed_a.len(), d_pk1.as_mut_ptr(), DET_DSA_PK, d_sk1.as_mut_ptr(), DET_DSA_SK) != 0 { return fail; }
    if ccx_pq_multisig_keygen_det(seed_a.as_ptr(), seed_a.len(), d_pk2.as_mut_ptr(), DET_DSA_PK, d_sk2.as_mut_ptr(), DET_DSA_SK) != 0 { return fail; }
    if ccx_pq_multisig_keygen_det(seed_b.as_ptr(), seed_b.len(), d_pk_b.as_mut_ptr(), DET_DSA_PK, d_sk_b.as_mut_ptr(), DET_DSA_SK) != 0 { return fail; }
    let dsa_deterministic = (d_pk1 == d_pk2) && (d_sk1 == d_sk2);
    let dsa_seed_separation = (d_pk1 != d_pk_b) && (d_sk1 != d_sk_b);

    // ---- ML-DSA-65 pqcrypto interop: sign with det-sk, verify with det-pk ----
    let dsa_interop = {
        let pk = match <dilithium3::PublicKey as SP>::from_bytes(&d_pk1) { Ok(p) => p, Err(_) => return fail };
        let sk = match <dilithium3::SecretKey as SS>::from_bytes(&d_sk1) { Ok(s) => s, Err(_) => return fail };
        let msg = b"ccx-detkeygen interop message";
        let sig = dilithium3::detached_sign(msg, &sk);
        let sigb = sig.as_bytes();
        let det_sig = match <dilithium3::DetachedSignature as SD>::from_bytes(sigb) { Ok(d) => d, Err(_) => return fail };
        dilithium3::verify_detached_signature(&det_sig, msg, &pk).is_ok()
    };

    // Domains must NOT collide: the ML-KEM and ML-DSA seeds derived from the SAME input seed are
    // independent (a leak of one does not reveal the other's seed material).
    let domain_separation = k_sk1[..32] != d_sk1[..32];

    // FIX 6: a low-entropy (< 32-byte) seed must be REJECTED by both det-keygen entry points.
    let short = b"too-short-seed"; // 14 bytes
    let mut tpk = vec![0u8; DET_DSA_SK]; let mut tsk = vec![0u8; DET_DSA_SK];
    let short_kem_rejected = ccx_pq_kem_keygen_det(short.as_ptr(), short.len(), tpk.as_mut_ptr(), DET_KEM_PK, tsk.as_mut_ptr(), DET_KEM_SK) != 0;
    let short_dsa_rejected = ccx_pq_multisig_keygen_det(short.as_ptr(), short.len(), tpk.as_mut_ptr(), DET_DSA_PK, tsk.as_mut_ptr(), DET_DSA_SK) != 0;

    let ok = (kem_deterministic && kem_seed_separation && kem_interop && kem_scan_roundtrip
              && dsa_deterministic && dsa_seed_separation && dsa_interop && domain_separation
              && short_kem_rejected && short_dsa_rejected) as i32;
    CcxPqSizes { pk: DET_KEM_PK, sk: DET_KEM_SK, ct_or_sig: DET_DSA_PK, ss: DET_DSA_SK, ok }
  })
}
