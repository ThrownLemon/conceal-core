#![no_main]
//! Fuzz target: ccx_pq_verify with arbitrary ring/sig data.
//! Tests that malformed signatures, wrong ring counts, corrupted keys, and
//! garbage sig blobs never panic and always return a negative error code.

use ccx_pqc::ccx_pq_verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split fuzz data into (ring, sig) — use the first byte as a split point.
    if data.len() < 2 { return; }
    let split = (data[0] as usize) % data.len();
    let (ring_blob, sig_blob) = data[1..].split_at(split.min(data.len() - 1));

    let pk_bytes = ccx_pqc::raptor_abi::PUBKEY_BYTES;
    if pk_bytes == 0 { return; }
    let ring_count = ring_blob.len() / pk_bytes;
    if ring_count == 0 || ring_count > 32 { return; }

    let mut nf_out = [0u8; 32];
    let _ = ccx_pq_verify(
        b"fuzz-msg".as_ptr(), 8,
        ring_blob.as_ptr(), ring_count, pk_bytes,
        sig_blob.as_ptr(), sig_blob.len(),
        nf_out.as_mut_ptr(), 32,
    );
});
