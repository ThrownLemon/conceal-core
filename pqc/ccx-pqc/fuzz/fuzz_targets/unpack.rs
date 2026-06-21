#![no_main]
//! Fuzz target: raptor_abi::unpack with arbitrary byte streams.
//! Tests that malformed signatures (truncated, non-canonical, wrong ring count,
//! corrupted varints, garbage comp-encoded polys) never panic across the FFI boundary.

use ccx_pqc::raptor_abi;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try unpacking as a ring of various sizes — must never panic, only return None.
    for ring_count in [1usize, 2, 4, 8, 16] {
        let _ = raptor_abi::unpack(data, ring_count);
    }
});
