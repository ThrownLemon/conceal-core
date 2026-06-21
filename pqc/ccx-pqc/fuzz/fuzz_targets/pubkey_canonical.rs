#![no_main]
//! Fuzz target: pubkey_is_canonical with arbitrary bytes.
//! Tests that the canonical-encoding check never panics on any input.

use ccx_pqc::raptor_abi;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = raptor_abi::pubkey_is_canonical(data);
});
