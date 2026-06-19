//! Raptor compact packing + size/canonicity helpers used by the `ccx_pq_*` ring-sig ABI in lib.rs.
//!
//! Ported from the clean-room spike's `abi.rs`: the spike defined the `extern "C"` wrappers here, but
//! in the integrated crate those live in `lib.rs` (one source of the C ABI), so this module keeps ONLY
//! the codec + the size constants + the helpers lib.rs calls.
//!
//! Encodings:
//!   public key  = modq-encoded a0            (896 bytes, canonical 14-bit packing)
//!   secret key  = 48-byte deterministic seed (wallet-restorable)
//!   nullifier   = 32-byte hash of aots
//!   signature   = compact packing (VARIABLE length): per-member comp-encoded (r0,r1) + 32-byte b,
//!                 then modq aots + comp-encoded ots (s0,s1); canonical varints, no padding.

use crate::falcon_ffi as fc;
use crate::raptor::{Member, OtsSig, Signature};

pub const SCHEME_ID: u32 = 0x52_41_50_54; // "RAPT"
// Raw modq encoding of an n=512 poly at 14 bits/coeff = 512*14/8 = 896 bytes (no header byte; PQClean's
// 897-byte CRYPTO_PUBLICKEYBYTES adds a 1-byte format header which we omit — our scheme id frames it).
pub const PUBKEY_BYTES: usize = 896;
pub const SECKEY_BYTES: usize = 48; // deterministic seed (wallet-restorable)
pub const NULLIFIER_BYTES: usize = crate::raptor::NULLIFIER_BYTES; // 32

/// Safe UPPER BOUND on the compact signature length for a ring of `n` members. Raptor signatures are
/// Golomb-compressed, so the exact length VARIES per signature — this bounds the size-query buffer and
/// gives `ccx_pq_verify` a DoS guard (reject an absurdly large blob before unpack). Each member is two
/// comp-encoded Falcon-512 short polys (each well under 2 KB) + 32 B b; plus aots (896 B) + two comp
/// polys + varints. `n*4096 + 8192` sits comfortably above the measured sizes (ring-16 ≈ 22 KB) and
/// below the 256 KB sign buffer the C++ caller allocates.
pub fn sig_upper_bound(n: usize) -> usize {
    n.saturating_mul(4096).saturating_add(8192)
}

/// Canonical pubkey check: `bytes` must be exactly PUBKEY_BYTES of valid modq encoding (every coeff in
/// [0,q)) AND must re-encode to the identical bytes (rejects non-canonical packings — the consensus
/// requirement so every node hashes a ring member identically). Mirrors the stand-in's
/// `pubkey_is_canonical`, which the daemon's `check_outs_valid` calls at output acceptance.
pub fn pubkey_is_canonical(bytes: &[u8]) -> bool {
    if bytes.len() != PUBKEY_BYTES { return false; }
    let decoded = match fc::modq_decode(bytes) { Some(d) => d, None => return false };
    match fc::modq_encode(&decoded) {
        Some(re) => re.len() == bytes.len() && re.as_slice() == bytes,
        None => false,
    }
}

// ================= compact packing =================
//
// Layout (all integers as canonical LEB128 varints, no padding):
//   varint ring_count
//   for each member:
//     varint len(comp(r0)) || comp(r0)
//     varint len(comp(r1)) || comp(r1)
//     32 bytes b
//   modq(aots)                       [fixed 896 bytes]
//   varint len(comp(s0)) || comp(s0)
//   varint len(comp(s1)) || comp(s1)
//
// comp() is Falcon's native signature compressor (Golomb-style) on each short poly.

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 { byte |= 0x80; }
        out.push(byte);
        if v == 0 { break; }
    }
}
fn get_varint(inp: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64; let mut shift = 0;
    loop {
        if *pos >= inp.len() || shift >= 64 { return None; }
        let byte = inp[*pos]; *pos += 1;
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            // reject overlong (non-canonical) encodings — a multi-byte varint whose terminating group
            // is zero could also be written shorter; canonical wire = no malleable length prefixes.
            if shift > 0 && byte == 0 { return None; }
            break;
        }
        shift += 7;
    }
    Some(v)
}

fn put_blob(out: &mut Vec<u8>, b: &[u8]) {
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}
fn get_blob<'a>(inp: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = get_varint(inp, pos)? as usize;
    if *pos + len > inp.len() { return None; }
    let b = &inp[*pos..*pos + len];
    *pos += len;
    Some(b)
}

pub fn pack(sig: &Signature) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    put_varint(&mut out, sig.members.len() as u64);
    for m in &sig.members {
        let c0 = fc::comp_encode(&m.r0)?;
        let c1 = fc::comp_encode(&m.r1)?;
        put_blob(&mut out, &c0);
        put_blob(&mut out, &c1);
        out.extend_from_slice(&m.b);
    }
    let aots = fc::modq_encode(&sig.aots)?;
    if aots.len() != PUBKEY_BYTES { return None; }
    out.extend_from_slice(&aots);
    let s0 = fc::comp_encode(&sig.ots_sig.s0)?;
    let s1 = fc::comp_encode(&sig.ots_sig.s1)?;
    put_blob(&mut out, &s0);
    put_blob(&mut out, &s1);
    Some(out)
}

pub fn unpack(inp: &[u8], expect_ring: usize) -> Option<Signature> {
    let mut pos = 0usize;
    let count = get_varint(inp, &mut pos)? as usize;
    if count != expect_ring { return None; }
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        let c0 = get_blob(inp, &mut pos)?;
        let r0 = fc::comp_decode(c0)?;
        let c1 = get_blob(inp, &mut pos)?;
        let r1 = fc::comp_decode(c1)?;
        if pos + 32 > inp.len() { return None; }
        let mut b = [0u8; 32];
        b.copy_from_slice(&inp[pos..pos + 32]);
        pos += 32;
        members.push(Member { r0, r1, b });
    }
    if pos + PUBKEY_BYTES > inp.len() { return None; }
    let aots_bytes = &inp[pos..pos + PUBKEY_BYTES];
    let aots = fc::modq_decode(aots_bytes)?;
    // Canonical aots: re-encoding must reproduce the exact bytes (same round-trip check as
    // pubkey_is_canonical). The nullifier binds aots, and the on-chain sig must have a UNIQUE byte
    // encoding — rejecting a non-canonical packing here prevents signature/txid malleability via an
    // alternate aots encoding. (For q<2^14 the 14-bit packing is injective, so this is also a proof.)
    match fc::modq_encode(&aots) {
        Some(re) if re.len() == PUBKEY_BYTES && re.as_slice() == aots_bytes => {}
        _ => return None,
    }
    pos += PUBKEY_BYTES;
    let s0b = get_blob(inp, &mut pos)?;
    let s0 = fc::comp_decode(s0b)?;
    let s1b = get_blob(inp, &mut pos)?;
    let s1 = fc::comp_decode(s1b)?;
    // reject trailing garbage (canonical length) — the variable-size verify's length validator
    if pos != inp.len() { return None; }
    Some(Signature { members, aots, ots_sig: OtsSig { s0, s1 } })
}
