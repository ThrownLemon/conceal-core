#![no_main]
//! Fuzz target: the remaining attacker-reachable FFI entry points the audit brief flagged —
//! ccx_pq_kem_scan (recipient decap), ccx_pq_multisig_verify (deposit-spend validator),
//! ccx_pq_msg_open / ccx_pq_msg_open_v2 (message AEAD). Each is on a path that handles untrusted
//! bytes; every call must reject cleanly (negative code) and NEVER panic across the FFI boundary.
//! All pointers point into the fuzz buffer with len == the real slice len, so any OOB/panic is the
//! crate's, not the harness's.

use ccx_pqc::{ccx_pq_kem_scan, ccx_pq_msg_open, ccx_pq_msg_open_v2, ccx_pq_multisig_verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let n = data.len();
    let (s1, s2) = data.split_at((data[0] as usize) % n);
    let (s3, s4) = data.split_at((data[1] as usize) % n);

    // KEM scan: kem_sk = s1, ct = s2 (malformed sk/ct must return < 0, not panic).
    let mut seed = [0u8; 32];
    let _ = ccx_pq_kem_scan(s1.as_ptr(), s1.len(), s2.as_ptr(), s2.len(), seed.as_mut_ptr(), 32);

    // ML-DSA multisig verify (deposit path): msg = s1, pk = s2, sig = s3.
    let _ = ccx_pq_multisig_verify(s1.as_ptr(), s1.len(), s2.as_ptr(), s2.len(), s3.as_ptr(), s3.len());

    // Message AEAD open paths. seed = first 32 bytes; ct = s4.
    if data.len() >= 32 {
        let mut pt = vec![0u8; s4.len() + 16];
        let mut pl = 0usize;
        let _ = ccx_pq_msg_open(
            data[..32].as_ptr(), 32, data[2] as u64,
            s4.as_ptr(), s4.len(), pt.as_mut_ptr(), pt.len(), &mut pl,
        );
        // v2: nonce = bytes [32..56], aad = s1.
        if data.len() >= 56 {
            let mut pt2 = vec![0u8; s4.len() + 16];
            let mut pl2 = 0usize;
            let _ = ccx_pq_msg_open_v2(
                data[..32].as_ptr(), 32, data[32..56].as_ptr(), 24,
                s1.as_ptr(), s1.len(), s4.as_ptr(), s4.len(),
                pt2.as_mut_ptr(), pt2.len(), &mut pl2,
            );
        }
    }
});
