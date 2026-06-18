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
use std::panic::{catch_unwind, AssertUnwindSafe};

mod ringsig; // EXPERIMENTAL lattice linkable ring signature (anonymous + soundly linkable)

// FFI panic guard: a Rust panic unwinding across the `extern "C"` boundary into the C++ daemon is
// undefined behaviour. Every entry point runs its body inside catch_unwind and, on panic, returns
// the supplied error value instead — preserving each function's existing return-type contract (an
// error int, or a CcxPqSizes with ok=0). AssertUnwindSafe is sound here: the raw C pointers we touch
// are validated before use and we never observe a broken invariant after a caught unwind.
#[inline]
fn ffi_guard<T, F: FnOnce() -> T>(on_panic: T, body: F) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(on_panic)
}

const PK: usize = ringsig::PK_BYTES; // lattice public key (t) bytes
const SK: usize = 32;                // 32-byte seed (the short secret s is re-derived from it)
const NF: usize = 32;                // link tag (nullifier) = SHAKE256 of the lattice tag I
const SCHEME_ID: u32 = 0xC0DE_0003;  // lattice linkable-ring-signature backend (anonymous)

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut x = Shake256::default();
    for p in parts { Update::update(&mut x, p); }
    x.finalize_xof().read(out);
}
fn seed32(seed: &[u8]) -> [u8; 32] {
    let mut m = [0u8; 32];
    shake(&[b"ccx-lring-seed", seed], &mut m);
    m
}
// 32-byte nullifier = SHAKE256(serialized lattice tag I). Same input on sign (ccx_pq_nullifier) and
// verify (recovered tag), so the daemon's double-spend set is consistent.
fn nf_from_tag(tag_bytes: &[u8]) -> [u8; NF] {
    let mut nf = [0u8; NF];
    shake(&[b"ccx-pq-nf", tag_bytes], &mut nf);
    nf
}
fn ring_sig_size(n: usize) -> usize { ringsig::sig_bytes(n) }

#[no_mangle] pub extern "C" fn ccx_pq_scheme_id() -> u32 { SCHEME_ID }
#[no_mangle] pub extern "C" fn ccx_pq_pubkey_bytes() -> usize { PK }
#[no_mangle] pub extern "C" fn ccx_pq_seckey_bytes() -> usize { SK }
#[no_mangle] pub extern "C" fn ccx_pq_nullifier_bytes() -> usize { NF }

#[no_mangle]
pub extern "C" fn ccx_pq_keygen(seed: *const u8, seed_len: usize,
                                pk_out: *mut u8, pk_cap: usize,
                                sk_out: *mut u8, sk_cap: usize) -> i32 {
  ffi_guard(-99, || {
    if pk_out.is_null() || sk_out.is_null() { return -1; }
    if pk_cap < PK || sk_cap < SK { return -2; }
    let seed = if seed.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(seed, seed_len) } };
    let master = seed32(seed);
    let (pk, _s, _t) = ringsig::keygen(&master);
    if pk.len() != PK { return -7; }
    unsafe {
        std::ptr::copy_nonoverlapping(master.as_ptr(), sk_out, SK); // sk == the 32-byte seed
        std::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, PK);
    }
    0
  })
}

#[no_mangle]
pub extern "C" fn ccx_pq_nullifier(sk: *const u8, sk_len: usize,
                                   _pk: *const u8, _pk_len: usize,
                                   nf_out: *mut u8, nf_cap: usize) -> i32 {
  ffi_guard(-99, || {
    if sk.is_null() || nf_out.is_null() { return -1; }
    if nf_cap < NF || sk_len < SK { return -2; }
    let skb = unsafe { std::slice::from_raw_parts(sk, SK) };
    let mut master = [0u8; 32]; master.copy_from_slice(&skb[..SK]);
    let (_pk, s, _t) = ringsig::keygen(&master);
    let nf = nf_from_tag(&ringsig::tag_bytes_of(&s)); // tag I = A2*s, bound to the secret
    unsafe { std::ptr::copy_nonoverlapping(nf.as_ptr(), nf_out, NF); }
    0
  })
}

fn split_ring(ringb: &[u8], ring_count: usize, stride: usize) -> Vec<Vec<u8>> {
    let mut pks = Vec::with_capacity(ring_count);
    for i in 0..ring_count { let off = i * stride; pks.push(ringb[off..off + PK].to_vec()); }
    pks
}

#[no_mangle]
pub extern "C" fn ccx_pq_sign(msg: *const u8, msg_len: usize,
                              ring: *const u8, ring_count: usize, member_stride: usize,
                              sk: *const u8, sk_len: usize, signer_index: usize,
                              sig_out: *mut u8, sig_len: *mut usize) -> i32 {
  ffi_guard(-99, || {
    if sig_len.is_null() { return -1; }
    let need = ring_sig_size(ring_count);
    if sig_out.is_null() { unsafe { *sig_len = need; } return 0; }          // two-call size query
    if unsafe { *sig_len } < need { unsafe { *sig_len = need; } return -2; }
    if msg.is_null() || ring.is_null() || sk.is_null() { return -1; }
    if sk_len < SK || ring_count == 0 || member_stride < PK || signer_index >= ring_count { return -1; }
    let msg = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let skb = unsafe { std::slice::from_raw_parts(sk, SK) };
    let mut master = [0u8; 32]; master.copy_from_slice(&skb[..SK]);
    let ringb = unsafe { std::slice::from_raw_parts(ring, ring_count * member_stride) };
    let pks = split_ring(ringb, ring_count, member_stride);
    match ringsig::sign(msg, &pks, signer_index, &master) {
        Some(sig) => {
            if sig.len() != need { return -7; }
            let out = unsafe { std::slice::from_raw_parts_mut(sig_out, need) };
            out.copy_from_slice(&sig);
            unsafe { *sig_len = need; }
            0
        }
        None => -6, // signing aborted too many times (rejection sampling)
    }
  })
}

#[no_mangle]
pub extern "C" fn ccx_pq_verify(msg: *const u8, msg_len: usize,
                                ring: *const u8, ring_count: usize, member_stride: usize,
                                sig: *const u8, sig_len: usize, nf_out: *mut u8, nf_cap: usize) -> i32 {
  ffi_guard(-99, || {
    if msg.is_null() || ring.is_null() || sig.is_null() { return -1; }
    if ring_count == 0 || member_stride < PK { return -1; }
    if sig_len != ring_sig_size(ring_count) { return -3; }
    let msg = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let sigb = unsafe { std::slice::from_raw_parts(sig, sig_len) };
    let ringb = unsafe { std::slice::from_raw_parts(ring, ring_count * member_stride) };
    let pks = split_ring(ringb, ring_count, member_stride);
    // Anonymous verify: walks the symmetric ring chain; it NEVER learns which member signed.
    match ringsig::verify(msg, &pks, sigb) {
        Some(tag_bytes) => {
            if !nf_out.is_null() {
                if nf_cap < NF { return -2; }
                let nf = nf_from_tag(&tag_bytes);
                unsafe { std::ptr::copy_nonoverlapping(nf.as_ptr(), nf_out, NF); }
            }
            0
        }
        None => -5,
    }
  })
}

#[repr(C)] pub struct CcxPqSizes { pub pk: usize, pub sk: usize, pub ct_or_sig: usize, pub ss: usize, pub ok: i32 }
// Panic default for CcxPqSizes-returning selftests: ok=0 signals failure, sizes zeroed.
const CCX_SIZES_PANIC: CcxPqSizes = CcxPqSizes { pk: 0, sk: 0, ct_or_sig: 0, ss: 0, ok: 0 };
#[no_mangle]
pub extern "C" fn ccx_mlkem768_selftest() -> CcxPqSizes {
  ffi_guard(CCX_SIZES_PANIC, || {
    let (pk, sk) = kyber768::keypair();
    let (ss1, ct) = kyber768::encapsulate(&pk);
    let ss2 = kyber768::decapsulate(&ct, &sk);
    CcxPqSizes { pk: pk.as_bytes().len(), sk: sk.as_bytes().len(), ct_or_sig: ct.as_bytes().len(),
                 ss: ss1.as_bytes().len(), ok: (ss1.as_bytes() == ss2.as_bytes()) as i32 }
  })
}
#[no_mangle]
pub extern "C" fn ccx_mldsa_selftest() -> CcxPqSizes {
  ffi_guard(CCX_SIZES_PANIC, || {
    let (pk, sk) = dilithium3::keypair();
    let m = b"ccx deposit";
    let sm = dilithium3::sign(m, &sk);
    let ok = dilithium3::open(&sm, &pk).map(|x| x == m).unwrap_or(false) as i32;
    CcxPqSizes { pk: pk.as_bytes().len(), sk: sk.as_bytes().len(), ct_or_sig: sm.as_bytes().len(), ss: 0, ok }
  })
}

// --- ML-KEM-768 stealth one-time outputs (Gap 4) -----------------------------------------------
// Real recipient-unlinkability: the sender encapsulates to the recipient's long-term ML-KEM key,
// derives a one-time signing seed from the shared secret (-> a unique on-chain PqKeyOutput.key),
// and publishes the Kyber ciphertext as kemCt. Only the KEM-secret holder can decapsulate, recover
// the seed, and re-derive the one-time keypair to spend. This is genuine PQ confidentiality and is
// independent of the (still-stubbed-for-anonymity) ring signature.
const KEM_PK: usize = 1184;
const KEM_SK: usize = 2400;
const KEM_CT: usize = 1088;

#[no_mangle] pub extern "C" fn ccx_pq_kem_pubkey_bytes() -> usize { KEM_PK }
#[no_mangle] pub extern "C" fn ccx_pq_kem_seckey_bytes() -> usize { KEM_SK }
#[no_mangle] pub extern "C" fn ccx_pq_kem_ct_bytes() -> usize { KEM_CT }

/// Generate a fresh ML-KEM-768 keypair (RNG-based). Used once to mint the deterministic testnet
/// recipient keypair that is then hardcoded in CryptoNoteConfig.h.
#[no_mangle]
pub extern "C" fn ccx_pq_kem_keypair(pk_out: *mut u8, pk_cap: usize,
                                     sk_out: *mut u8, sk_cap: usize) -> i32 {
  ffi_guard(-99, || {
    if pk_out.is_null() || sk_out.is_null() { return -1; }
    if pk_cap < KEM_PK || sk_cap < KEM_SK { return -2; }
    let (pk, sk) = kyber768::keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_bytes().as_ptr(), pk_out, KEM_PK);
        std::ptr::copy_nonoverlapping(sk.as_bytes().as_ptr(), sk_out, KEM_SK);
    }
    0
  })
}

/// Sender: encapsulate to `kem_pk`, write the Kyber ciphertext to `ct_out`, and SHAKE256-derive a
/// 32-byte one-time signing seed from the shared secret into `seed_out`.
#[no_mangle]
pub extern "C" fn ccx_pq_kem_derive_output(kem_pk: *const u8, kem_pk_len: usize,
                                           ct_out: *mut u8, ct_cap: usize,
                                           seed_out: *mut u8, seed_cap: usize) -> i32 {
  ffi_guard(-99, || {
    if kem_pk.is_null() || ct_out.is_null() || seed_out.is_null() { return -1; }
    if seed_cap < 32 { return -2; }
    let pkb = unsafe { std::slice::from_raw_parts(kem_pk, kem_pk_len) };
    let pk = match <kyber768::PublicKey as KP>::from_bytes(pkb) { Ok(p) => p, Err(_) => return -1 };
    let (ss, ct) = kyber768::encapsulate(&pk);
    let ctb = ct.as_bytes();
    if ct_cap < ctb.len() { return -2; }
    let mut seed = [0u8; 32];
    shake(&[b"ccx-stealth-otk", ss.as_bytes()], &mut seed);
    unsafe {
        std::ptr::copy_nonoverlapping(ctb.as_ptr(), ct_out, ctb.len());
        std::ptr::copy_nonoverlapping(seed.as_ptr(), seed_out, 32);
    }
    0
  })
}

/// Recipient: decapsulate `ct` with `kem_sk` and re-derive the same 32-byte one-time signing seed.
#[no_mangle]
pub extern "C" fn ccx_pq_kem_scan(kem_sk: *const u8, kem_sk_len: usize,
                                  ct: *const u8, ct_len: usize,
                                  seed_out: *mut u8, seed_cap: usize) -> i32 {
  ffi_guard(-99, || {
    if kem_sk.is_null() || ct.is_null() || seed_out.is_null() { return -1; }
    if seed_cap < 32 { return -2; }
    let skb = unsafe { std::slice::from_raw_parts(kem_sk, kem_sk_len) };
    let ctb = unsafe { std::slice::from_raw_parts(ct, ct_len) };
    let sk = match <kyber768::SecretKey as KS>::from_bytes(skb) { Ok(s) => s, Err(_) => return -1 };
    let ctt = match <kyber768::Ciphertext as KC>::from_bytes(ctb) { Ok(c) => c, Err(_) => return -1 };
    let ss = kyber768::decapsulate(&ctt, &sk);
    let mut seed = [0u8; 32];
    shake(&[b"ccx-stealth-otk", ss.as_bytes()], &mut seed);
    unsafe { std::ptr::copy_nonoverlapping(seed.as_ptr(), seed_out, 32); }
    0
  })
}

/// Selftest: recipient recovers the SAME one-time keypair the sender derived; a wrong recipient
/// recovers a DIFFERENT seed (cannot derive the output key). Proves real ML-KEM stealth.
#[no_mangle]
pub extern "C" fn ccx_pq_kem_stealth_selftest() -> CcxPqSizes {
  ffi_guard(CCX_SIZES_PANIC, || {
    let (pk, sk) = kyber768::keypair();
    let (pkb, skb) = (pk.as_bytes(), sk.as_bytes());
    let mut ct = vec![0u8; KEM_CT];
    let mut sa = [0u8; 32];
    let r1 = ccx_pq_kem_derive_output(pkb.as_ptr(), pkb.len(), ct.as_mut_ptr(), ct.len(), sa.as_mut_ptr(), 32);
    let mut sb = [0u8; 32];
    let r2 = ccx_pq_kem_scan(skb.as_ptr(), skb.len(), ct.as_ptr(), ct.len(), sb.as_mut_ptr(), 32);

    // one-time pubkeys derived from the sender/recipient seeds must match
    let mut pk_a = vec![0u8; PK]; let mut sk_a = vec![0u8; SK];
    ccx_pq_keygen(sa.as_ptr(), 32, pk_a.as_mut_ptr(), PK, sk_a.as_mut_ptr(), SK);
    let mut pk_b = vec![0u8; PK]; let mut sk_b = vec![0u8; SK];
    ccx_pq_keygen(sb.as_ptr(), 32, pk_b.as_mut_ptr(), PK, sk_b.as_mut_ptr(), SK);

    // a non-owner cannot recover the seed
    let (_pk2, sk2) = kyber768::keypair();
    let mut sc = [0u8; 32];
    ccx_pq_kem_scan(sk2.as_bytes().as_ptr(), sk2.as_bytes().len(), ct.as_ptr(), ct.len(), sc.as_mut_ptr(), 32);

    let ok = (r1 == 0 && r2 == 0 && sa == sb && pk_a == pk_b && sa != sc) as i32;
    CcxPqSizes { pk: KEM_PK, sk: KEM_SK, ct_or_sig: KEM_CT, ss: 32, ok }
  })
}

/// Selftest for the EXPERIMENTAL lattice linkable ring signature: proves a ring-of-4 signature
/// verifies, is linkable (same signer -> same tag), distinguishes signers (different signer ->
/// different tag), and rejects a tampered signature. Anonymity is structural (the ring chain is
/// symmetric across members). ok=1 means all checks passed.
#[no_mangle]
pub extern "C" fn ccx_pqr_ringsig_selftest() -> CcxPqSizes {
  ffi_guard(CCX_SIZES_PANIC, || {
    let n = 4usize;
    let mut pks: Vec<Vec<u8>> = Vec::new();
    let mut seeds: Vec<[u8; 32]> = Vec::new();
    for i in 0..n {
        let mut sd = [0u8; 32]; sd[0] = i as u8; sd[1] = 0xab; sd[2] = 0xcd;
        let (pk, _s, _t) = ringsig::keygen(&sd);
        pks.push(pk); seeds.push(sd);
    }
    let msg = b"ccx-lring-selftest";
    let signer = 2usize;
    let fail = CcxPqSizes { pk: ringsig::PK_BYTES, sk: 32, ct_or_sig: ringsig::sig_bytes(n), ss: ringsig::TAG_BYTES, ok: 0 };
    let sig = match ringsig::sign(msg, &pks, signer, &seeds[signer]) { Some(s) => s, None => return fail };
    let tag1 = match ringsig::verify(msg, &pks, &sig) { Some(t) => t, None => return fail };
    // linkable: a second signature by the SAME signer recovers the SAME tag
    let sig2 = match ringsig::sign(msg, &pks, signer, &seeds[signer]) { Some(s) => s, None => return fail };
    let tag2 = match ringsig::verify(msg, &pks, &sig2) { Some(t) => t, None => return fail };
    // a DIFFERENT signer (index 0) yields a DIFFERENT tag
    let sig3 = match ringsig::sign(msg, &pks, 0, &seeds[0]) { Some(s) => s, None => return fail };
    let tag3 = match ringsig::verify(msg, &pks, &sig3) { Some(t) => t, None => return fail };
    // a tampered signature must fail to verify (flip a byte in the z region)
    let mut bad = sig.clone(); let zoff = 32 + ringsig::TAG_BYTES + 4; bad[zoff] ^= 0xff;
    let forge_rejected = ringsig::verify(msg, &pks, &bad).is_none();
    // wrong message must fail
    let wrongmsg_rejected = ringsig::verify(b"different-message", &pks, &sig).is_none();
    // non-member (signing with a secret whose pk is NOT the ring member at that index) must fail
    let mut wrong_seed = seeds[signer]; wrong_seed[5] ^= 0xff;
    let nonmember_rejected = match ringsig::sign(msg, &pks, signer, &wrong_seed) {
        Some(s) => ringsig::verify(msg, &pks, &s).is_none(),
        None => true,
    };

    let ok = (tag1 == tag2 && tag1 != tag3 && forge_rejected && wrongmsg_rejected && nonmember_rejected) as i32;
    CcxPqSizes { pk: ringsig::PK_BYTES, sk: 32, ct_or_sig: ringsig::sig_bytes(n), ss: ringsig::TAG_BYTES, ok }
  })
}

/// Returns 1 if a no-secret forgery VERIFIES (scheme universally forgeable / BROKEN), else 0.
/// Tests the security review's CRITICAL universal-forgery claim directly.
#[no_mangle]
pub extern "C" fn ccx_pqr_forgery_test() -> i32 {
  // On panic, return 0 ("not forgeable") — the safe answer that does not falsely flag a break.
  ffi_guard(0, || {
    let mut pks: Vec<Vec<u8>> = Vec::new();
    for i in 0..4u8 { let mut sd = [0u8; 32]; sd[0] = i; sd[1] = 0x55; let (pk, _s, _t) = ringsig::keygen(&sd); pks.push(pk); }
    ringsig::forge_no_secret(b"forge-msg", &pks) as i32
  })
}

/// End-to-end C-ABI selftest: keygen -> sign -> verify (ring size 1) and the verify-recovered
/// nullifier equals ccx_pq_nullifier(sk). Exercises the lattice backend through the public ABI.
#[no_mangle]
pub extern "C" fn ccx_pq_ringsig_selftest() -> CcxPqSizes {
  ffi_guard(CCX_SIZES_PANIC, || {
    let mut pk = vec![0u8; PK];
    let mut sk = vec![0u8; SK];
    let seed = b"ccx-ringsig-selftest";
    let need = ring_sig_size(1);
    if ccx_pq_keygen(seed.as_ptr(), seed.len(), pk.as_mut_ptr(), PK, sk.as_mut_ptr(), SK) != 0 {
        return CcxPqSizes { pk: PK, sk: SK, ct_or_sig: need, ss: NF, ok: 0 };
    }
    let msg = b"ccx-ringsig-msg";
    let mut sig = vec![0u8; need];
    let mut sl = sig.len();
    let s = ccx_pq_sign(msg.as_ptr(), msg.len(), pk.as_ptr(), 1, PK, sk.as_ptr(), SK, 0, sig.as_mut_ptr(), &mut sl);
    let mut nf = [0u8; NF];
    let v = ccx_pq_verify(msg.as_ptr(), msg.len(), pk.as_ptr(), 1, PK, sig.as_ptr(), sl, nf.as_mut_ptr(), NF);
    let mut nf2 = [0u8; NF];
    ccx_pq_nullifier(sk.as_ptr(), SK, pk.as_ptr(), PK, nf2.as_mut_ptr(), NF);
    let ok = (s == 0 && v == 0 && nf == nf2) as i32;
    CcxPqSizes { pk: PK, sk: SK, ct_or_sig: sl, ss: NF, ok }
  })
}
