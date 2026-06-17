//! Conceal PQ crypto module (C ABI). Real ML-KEM-768 + ML-DSA(Dilithium); the
//! linkable ring signature is an INSECURE STUB (correct sizes, H(pubkey)
//! nullifier, deterministic) pending the audited lattice backend (CIP §5.3 / C1).
use sha3::{Sha3_256, Shake256, Digest};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::kem::{PublicKey as KP, SecretKey as KS, Ciphertext as KC, SharedSecret as KSS};
use pqcrypto_traits::sign::{PublicKey as SP, SecretKey as SS, SignedMessage as SM};

const PK: usize = 1312;     // stub param sizes (real backend overrides)
const SK: usize = 2560;
const NF: usize = 32;
const SCHEME_ID: u32 = 0xC0DE_0001;

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut x = Shake256::default();
    for p in parts { Update::update(&mut x, p); }
    x.finalize_xof().read(out);
}
fn ring_sig_size(n: usize) -> usize {
    let nn = n.max(1) - 1;
    let logn = (usize::BITS - nn.leading_zeros()) as usize; // ceil(log2 n)
    18000 + logn * 1024 + NF
}

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
    let sk = unsafe { std::slice::from_raw_parts_mut(sk_out, SK) };
    shake(&[b"ccx-stub-sk", seed], sk);
    let mut pk = vec![0u8; PK];
    shake(&[b"ccx-stub-pk", sk], &mut pk);
    unsafe { std::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, PK); }
    0
}

#[no_mangle]
pub extern "C" fn ccx_pq_nullifier(_sk: *const u8, _sk_len: usize,
                                   pk: *const u8, pk_len: usize,
                                   nf_out: *mut u8, nf_cap: usize) -> i32 {
    if pk.is_null() || nf_out.is_null() { return -1; }
    if nf_cap < NF { return -2; }
    let pk = unsafe { std::slice::from_raw_parts(pk, pk_len) };
    let nf = Sha3_256::digest(pk);                 // H(pubkey) nullifier
    unsafe { std::ptr::copy_nonoverlapping(nf.as_ptr(), nf_out, NF); }
    0
}

#[no_mangle]
pub extern "C" fn ccx_pq_sign(msg: *const u8, msg_len: usize,
                              ring: *const u8, ring_count: usize, member_stride: usize,
                              sk: *const u8, sk_len: usize, signer_index: usize,
                              sig_out: *mut u8, sig_len: *mut usize) -> i32 {
    if sig_len.is_null() { return -1; }
    let need = ring_sig_size(ring_count);
    if sig_out.is_null() { unsafe { *sig_len = need; } return 0; }   // two-call size query
    if unsafe { *sig_len } < need { unsafe { *sig_len = need; } return -2; }
    if msg.is_null() || ring.is_null() || sk.is_null() { return -1; }
    if signer_index >= ring_count { return -4; }
    let msg = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let ringb = unsafe { std::slice::from_raw_parts(ring, ring_count * member_stride) };
    let skb = unsafe { std::slice::from_raw_parts(sk, sk_len) };
    let sig = unsafe { std::slice::from_raw_parts_mut(sig_out, need) };
    shake(&[b"ccx-stub-sig", msg, ringb, skb, &signer_index.to_le_bytes()], &mut sig[..need - NF]);
    let mut pk = vec![0u8; PK]; shake(&[b"ccx-stub-pk", skb], &mut pk);
    let nf = Sha3_256::digest(&pk);
    sig[need - NF..].copy_from_slice(&nf);
    unsafe { *sig_len = need; }
    0
}

#[no_mangle]
pub extern "C" fn ccx_pq_verify(msg: *const u8, _msg_len: usize,
                                ring: *const u8, ring_count: usize, _member_stride: usize,
                                sig: *const u8, sig_len: usize, nf_out: *mut u8, nf_cap: usize) -> i32 {
    if msg.is_null() || ring.is_null() || sig.is_null() { return -1; }
    if sig_len != ring_sig_size(ring_count) { return -3; }   // STUB: structural only
    if !nf_out.is_null() {
        if nf_cap < NF { return -2; }
        let s = unsafe { std::slice::from_raw_parts(sig, sig_len) };
        unsafe { std::ptr::copy_nonoverlapping(s[sig_len - NF..].as_ptr(), nf_out, NF); }
    }
    0
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
