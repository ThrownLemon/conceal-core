//! Conceal PQ crypto module (C ABI).
//!
//! Real post-quantum primitives:
//!   * ML-KEM-768 (Kyber)  — stealth-output KEM + selftest
//!   * ML-DSA-65 (Dilithium-3, FIPS 204) — the LINKABLE-SIGNATURE backend
//!
//! The "ring signature" here is a REAL ML-DSA signature plus a secret-bound link tag
//! (nullifier = SHAKE256(seed)). It is genuinely unforgeable (a valid signature requires a ring
//! member's secret seed) and genuinely linkable for an honest signer (the tag is a deterministic
//! function of the spent output's secret, not of its public key — so it does NOT deanonymise the
//! signer the way the old H(pubkey) stub did).
//!
//! HONEST LIMITATION (demo, unaudited): verification identifies WHICH ring member signed (it tries
//! each member's public key), so this is a real on-chain decoy SET, not yet cryptographic
//! signer-unlinkability. Full ring anonymity + malicious-signer-sound linkability needs a
//! zero-knowledge one-out-of-many proof (lattice Sigma-OR / MPC-in-the-head) — the audit-gated
//! milestone (CIP §5.3 / C1). Not constant-time. Do not use on mainnet.
use sha3::Shake256;
use sha3::digest::{Update, ExtendableOutput, XofReader};
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::kem::{PublicKey as KP, SecretKey as KS, Ciphertext as KC, SharedSecret as KSS};
use pqcrypto_traits::sign::{PublicKey as SP, SecretKey as SS, SignedMessage as SM};
use ml_dsa::{MlDsa65, KeyGen, B32, EncodedVerifyingKey, EncodedSignature, VerifyingKey, Signature};
use ml_dsa::signature::Verifier;

const PK: usize = 1952;          // ML-DSA-65 verifying key bytes
const SK: usize = 32;            // 32-byte master seed (the ML-DSA keypair is expanded on demand)
const SIG: usize = 3309;         // ML-DSA-65 signature bytes
const NF: usize = 32;            // link tag (nullifier)
const SCHEME_ID: u32 = 0xC0DE_0002; // bumped: real ML-DSA backend (0x...0001 was the stub)

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut x = Shake256::default();
    for p in parts { Update::update(&mut x, p); }
    x.finalize_xof().read(out);
}
fn seed32(seed: &[u8]) -> [u8; 32] {
    let mut m = [0u8; 32];
    shake(&[b"ccx-mldsa-seed", seed], &mut m);
    m
}
fn nullifier_of(seed32: &[u8; 32]) -> [u8; NF] {
    let mut nf = [0u8; NF];
    shake(&[b"ccx-pq-nf", seed32], &mut nf);
    nf
}
fn ring_sig_size(_n: usize) -> usize { SIG + NF } // one real ML-DSA sig + the link tag (size is N-independent)

#[no_mangle] pub extern "C" fn ccx_pq_scheme_id() -> u32 { SCHEME_ID }
#[no_mangle] pub extern "C" fn ccx_pq_pubkey_bytes() -> usize { PK }
#[no_mangle] pub extern "C" fn ccx_pq_seckey_bytes() -> usize { SK }
#[no_mangle] pub extern "C" fn ccx_pq_nullifier_bytes() -> usize { NF }

#[no_mangle]
pub extern "C" fn ccx_pq_keygen(seed: *const u8, seed_len: usize,
                                pk_out: *mut u8, pk_cap: usize,
                                sk_out: *mut u8, sk_cap: usize) -> i32 {
    if pk_out.is_null() || sk_out.is_null() { return -1; }
    if pk_cap < PK || sk_cap < SK { return -2; }
    let seed = if seed.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(seed, seed_len) } };
    let master = seed32(seed);
    let xi = B32::try_from(&master[..]).map_err(|_| ()).unwrap();
    let kp = MlDsa65::key_gen_internal(&xi);
    let pk = kp.verifying_key().encode();      // 1952 bytes
    unsafe {
        std::ptr::copy_nonoverlapping(master.as_ptr(), sk_out, SK);   // sk == the 32-byte master seed
        std::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, PK);
    }
    0
}

#[no_mangle]
pub extern "C" fn ccx_pq_nullifier(sk: *const u8, sk_len: usize,
                                   _pk: *const u8, _pk_len: usize,
                                   nf_out: *mut u8, nf_cap: usize) -> i32 {
    if sk.is_null() || nf_out.is_null() { return -1; }
    if nf_cap < NF || sk_len < SK { return -2; }
    let skb = unsafe { std::slice::from_raw_parts(sk, SK) };
    let mut master = [0u8; 32]; master.copy_from_slice(&skb[..SK]);
    let nf = nullifier_of(&master);            // secret-bound: SHAKE256(seed), NOT H(pubkey)
    unsafe { std::ptr::copy_nonoverlapping(nf.as_ptr(), nf_out, NF); }
    0
}

#[no_mangle]
pub extern "C" fn ccx_pq_sign(msg: *const u8, msg_len: usize,
                              ring: *const u8, ring_count: usize, _member_stride: usize,
                              sk: *const u8, sk_len: usize, _signer_index: usize,
                              sig_out: *mut u8, sig_len: *mut usize) -> i32 {
    if sig_len.is_null() { return -1; }
    let need = ring_sig_size(ring_count);
    if sig_out.is_null() { unsafe { *sig_len = need; } return 0; }          // two-call size query
    if unsafe { *sig_len } < need { unsafe { *sig_len = need; } return -2; }
    if msg.is_null() || ring.is_null() || sk.is_null() { return -1; }
    if sk_len < SK { return -1; }
    let msg = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let skb = unsafe { std::slice::from_raw_parts(sk, SK) };
    let mut master = [0u8; 32]; master.copy_from_slice(&skb[..SK]);

    let nf = nullifier_of(&master);
    let mut signed = Vec::with_capacity(msg.len() + NF);
    signed.extend_from_slice(msg);
    signed.extend_from_slice(&nf);             // bind the link tag into the signed transcript

    let xi = match B32::try_from(&master[..]) { Ok(x) => x, Err(_) => return -1 };
    let kp = MlDsa65::key_gen_internal(&xi);
    let sig = match kp.signing_key().sign_deterministic(&signed, &[]) { Ok(s) => s, Err(_) => return -6 };
    let sigb = sig.encode();                   // 3309 bytes
    if sigb.len() != SIG { return -7; }

    let out = unsafe { std::slice::from_raw_parts_mut(sig_out, need) };
    out[..SIG].copy_from_slice(&sigb);
    out[SIG..SIG + NF].copy_from_slice(&nf);
    unsafe { *sig_len = need; }
    0
}

#[no_mangle]
pub extern "C" fn ccx_pq_verify(msg: *const u8, msg_len: usize,
                                ring: *const u8, ring_count: usize, member_stride: usize,
                                sig: *const u8, sig_len: usize, nf_out: *mut u8, nf_cap: usize) -> i32 {
    if msg.is_null() || ring.is_null() || sig.is_null() { return -1; }
    if sig_len != ring_sig_size(ring_count) { return -3; }
    if ring_count == 0 || member_stride < PK { return -1; }
    let msg = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let sigb = unsafe { std::slice::from_raw_parts(sig, sig_len) };
    let ringb = unsafe { std::slice::from_raw_parts(ring, ring_count * member_stride) };

    let nf = &sigb[SIG..SIG + NF];
    let mut signed = Vec::with_capacity(msg.len() + NF);
    signed.extend_from_slice(msg);
    signed.extend_from_slice(nf);

    let enc_sig = match EncodedSignature::<MlDsa65>::try_from(&sigb[..SIG]) { Ok(s) => s, Err(_) => return -3 };
    let signature = match Signature::<MlDsa65>::decode(&enc_sig) { Some(s) => s, None => return -3 };

    // Real verification: accept iff the ML-DSA signature is valid under SOME ring member's key.
    // (Identifying WHICH member is the honest demo limitation — see module docs.)
    for i in 0..ring_count {
        let off = i * member_stride;
        let enc_pk = match EncodedVerifyingKey::<MlDsa65>::try_from(&ringb[off..off + PK]) { Ok(p) => p, Err(_) => continue };
        let vk = VerifyingKey::<MlDsa65>::decode(&enc_pk);
        if vk.verify(&signed, &signature).is_ok() {
            if !nf_out.is_null() {
                if nf_cap < NF { return -2; }
                unsafe { std::ptr::copy_nonoverlapping(nf.as_ptr(), nf_out, NF); }
            }
            return 0;
        }
    }
    -5 // no ring member's key validates the signature
}

#[repr(C)] pub struct CcxPqSizes { pub pk: usize, pub sk: usize, pub ct_or_sig: usize, pub ss: usize, pub ok: i32 }
#[no_mangle]
pub extern "C" fn ccx_mlkem768_selftest() -> CcxPqSizes {
    let (pk, sk) = kyber768::keypair();
    let (ss1, ct) = kyber768::encapsulate(&pk);
    let ss2 = kyber768::decapsulate(&ct, &sk);
    CcxPqSizes { pk: pk.as_bytes().len(), sk: sk.as_bytes().len(), ct_or_sig: ct.as_bytes().len(),
                 ss: ss1.as_bytes().len(), ok: (ss1.as_bytes() == ss2.as_bytes()) as i32 }
}
#[no_mangle]
pub extern "C" fn ccx_mldsa_selftest() -> CcxPqSizes {
    let (pk, sk) = dilithium3::keypair();
    let m = b"ccx deposit";
    let sm = dilithium3::sign(m, &sk);
    let ok = dilithium3::open(&sm, &pk).map(|x| x == m).unwrap_or(false) as i32;
    CcxPqSizes { pk: pk.as_bytes().len(), sk: sk.as_bytes().len(), ct_or_sig: sm.as_bytes().len(), ss: 0, ok }
}

/// Selftest for the real ring-sig backend: keygen -> sign -> verify (ring size 1) + nullifier determinism.
#[no_mangle]
pub extern "C" fn ccx_pq_ringsig_selftest() -> CcxPqSizes {
    let mut pk = vec![0u8; PK];
    let mut sk = vec![0u8; SK];
    let seed = b"ccx-ringsig-selftest";
    if ccx_pq_keygen(seed.as_ptr(), seed.len(), pk.as_mut_ptr(), PK, sk.as_mut_ptr(), SK) != 0 {
        return CcxPqSizes { pk: PK, sk: SK, ct_or_sig: SIG + NF, ss: NF, ok: 0 };
    }
    let msg = b"ccx-ringsig-msg";
    let mut sig = vec![0u8; SIG + NF];
    let mut sl = sig.len();
    let s = ccx_pq_sign(msg.as_ptr(), msg.len(), pk.as_ptr(), 1, PK, sk.as_ptr(), SK, 0, sig.as_mut_ptr(), &mut sl);
    let mut nf = [0u8; NF];
    let v = ccx_pq_verify(msg.as_ptr(), msg.len(), pk.as_ptr(), 1, PK, sig.as_ptr(), sl, nf.as_mut_ptr(), NF);
    let mut nf2 = [0u8; NF];
    ccx_pq_nullifier(sk.as_ptr(), SK, pk.as_ptr(), PK, nf2.as_mut_ptr(), NF);
    let ok = (s == 0 && v == 0 && nf == nf2) as i32;
    CcxPqSizes { pk: PK, sk: SK, ct_or_sig: sl, ss: NF, ok }
}
