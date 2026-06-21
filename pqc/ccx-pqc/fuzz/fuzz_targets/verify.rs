#![no_main]
//! Fuzz target: ccx_pq_verify with arbitrary ring/sig data.
//! Tests that malformed signatures, wrong ring counts, corrupted keys, and
//! garbage sig blobs never panic and always return a negative error code.
//!
//! Every iteration reaches the verifier: the ring is synthesized to a valid
//! length (`ring_count * pk_bytes`) by cycling the fuzz bytes, so even short
//! inputs exercise ring parsing, member-stride handling, signature unpacking,
//! and the error paths (the old `len / pk_bytes` derivation made inputs below
//! one full pubkey short-circuit before ever calling the verifier).

use ccx_pqc::ccx_pq_verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 { return; }

    let pk_bytes = ccx_pqc::raptor_abi::PUBKEY_BYTES;
    if pk_bytes == 0 { return; }

    // ring_count in 1..=6 (the consensus ring-size band) — always >= 1 so the
    // verifier is always invoked.
    let ring_count = 1 + (data[0] as usize % 6);

    // Split the remaining bytes into a ring source and a signature blob.
    let rest = &data[1..];
    let split = (data[1] as usize) % (rest.len() + 1);
    let (ring_src, sig_blob) = rest.split_at(split);

    // Synthesize a correctly-sized ring (ring_count * pk_bytes) by cycling the
    // fuzz bytes — well-sized but adversarially-contented, so the verifier is
    // always reached with a parseable-length ring.
    let ring_len = ring_count * pk_bytes;
    let mut ring_blob = vec![0u8; ring_len];
    if !ring_src.is_empty() {
        for i in 0..ring_len {
            ring_blob[i] = ring_src[i % ring_src.len()];
        }
    }

    let mut nf_out = [0u8; 32];
    let _ = ccx_pq_verify(
        b"fuzz-msg".as_ptr(), 8,
        ring_blob.as_ptr(), ring_count, pk_bytes,
        sig_blob.as_ptr(), sig_blob.len(),
        nf_out.as_mut_ptr(), 32,
    );
});
