//! EXPERIMENTAL / UNVERIFIED lattice linkable ring signature (CIP-0001 §5.3, demo only).
//!
//! Construction: an AOS/LSAG-style hash-chained ring of Fiat-Shamir-with-aborts (Dilithium-style)
//! Sigma proofs over the module-SIS one-way function t = A*s (s short), with a linking tag
//! I = A2*s bound into every branch's verification. The real branch forces I = A2*s_signer, so the
//! tag is deterministic in the signer's secret (linkable, malicious-signer-sound) while the ring
//! closure hides which member signed (anonymous: all z_i are uniform, the chain is symmetric).
//!
//! THIS IS NOT AUDITED, NOT CONSTANT-TIME, AND THE PARAMETERS ARE DEMO-GRADE (small dimensions,
//! NOT a calibrated security level). It exists to demonstrate that a genuinely anonymous + linkable
//! post-quantum ring signature is structurally possible on this ABI. Do not use on mainnet.
//!
//! Ring polynomial: R_q = Z_q[X]/(X^256 + 1), q = 8380417 (negacyclic schoolbook multiplication).
use sha3::Shake256;
use sha3::digest::{Update, ExtendableOutput, XofReader};

pub const N: usize = 256;          // poly degree
pub const Q: i64 = 8380417;        // modulus (prime, 23-bit)
pub const K: usize = 4;            // # equations (rows of A) — also tag rows
pub const L: usize = 4;            // # secret polys (cols)
pub const ETA: i64 = 2;            // secret coeff bound |s| <= ETA
pub const TAU: usize = 39;         // challenge weight (# of +/-1 coeffs)
pub const GAMMA: i64 = 1 << 17;    // mask bound
pub const BETA: i64 = (TAU as i64) * ETA; // max |c*s|_inf bound => 78
pub const ZBOUND: i64 = GAMMA - BETA;     // accepted |z|_inf range

pub type Poly = [i64; N];
pub type PolyVecL = [Poly; L];
pub type PolyVecK = [Poly; K];

#[inline] fn cmod(a: i64) -> i64 { // centered representative in (-Q/2, Q/2]
    let mut r = a % Q;
    if r > Q / 2 { r -= Q; }
    if r < -Q / 2 { r += Q; }
    r
}
fn poly_zero() -> Poly { [0i64; N] }
fn poly_add(a: &Poly, b: &Poly) -> Poly { let mut r = poly_zero(); for i in 0..N { r[i] = cmod(a[i] + b[i]); } r }
fn poly_sub(a: &Poly, b: &Poly) -> Poly { let mut r = poly_zero(); for i in 0..N { r[i] = cmod(a[i] - b[i]); } r }
fn poly_mul(a: &Poly, b: &Poly) -> Poly { // negacyclic schoolbook: X^N = -1
    let mut t = [0i128; N];
    for i in 0..N {
        if a[i] == 0 { continue; }
        for j in 0..N {
            let p = (a[i] as i128) * (b[j] as i128);
            let k = i + j;
            if k < N { t[k] += p; } else { t[k - N] -= p; }
        }
    }
    let mut r = poly_zero();
    for i in 0..N { r[i] = cmod((t[i] % (Q as i128)) as i64); }
    r
}
fn poly_inf_norm(a: &Poly) -> i64 { let mut m = 0; for &c in a.iter() { let v = if c < 0 { -c } else { c }; if v > m { m = v; } } m }
fn vecl_inf_norm(v: &PolyVecL) -> i64 { let mut m = 0; for p in v.iter() { let n = poly_inf_norm(p); if n > m { m = n; } } m }

// A*z for A: K x L, z: L -> K
fn mat_vec(a: &[[Poly; L]; K], z: &PolyVecL) -> PolyVecK {
    let mut out: PolyVecK = [poly_zero(); K];
    for k in 0..K {
        let mut acc = poly_zero();
        for l in 0..L { acc = poly_add(&acc, &poly_mul(&a[k][l], &z[l])); }
        out[k] = acc;
    }
    out
}
fn veck_add(a: &PolyVecK, b: &PolyVecK) -> PolyVecK { let mut r: PolyVecK = [poly_zero(); K]; for k in 0..K { r[k] = poly_add(&a[k], &b[k]); } r }
fn veck_sub(a: &PolyVecK, b: &PolyVecK) -> PolyVecK { let mut r: PolyVecK = [poly_zero(); K]; for k in 0..K { r[k] = poly_sub(&a[k], &b[k]); } r }
fn veck_scale(c: &Poly, b: &PolyVecK) -> PolyVecK { let mut r: PolyVecK = [poly_zero(); K]; for k in 0..K { r[k] = poly_mul(c, &b[k]); } r }

fn xof(parts: &[&[u8]]) -> impl XofReader {
    let mut x = Shake256::default();
    for p in parts { Update::update(&mut x, p); }
    x.finalize_xof()
}
fn read_u32(r: &mut impl XofReader) -> u32 { let mut b = [0u8; 4]; r.read(&mut b); u32::from_le_bytes(b) }

// Public matrices A (K x L) and A2 (K x L) derived from fixed domain-separated seeds.
fn gen_matrix(domain: &[u8]) -> [[Poly; L]; K] {
    let mut a = [[poly_zero(); L]; K];
    for k in 0..K {
        for l in 0..L {
            let mut r = xof(&[domain, &[k as u8, l as u8]]);
            for i in 0..N {
                // rejection-free: reduce a 32-bit draw mod Q (slight bias, fine for a demo)
                a[k][l][i] = (read_u32(&mut r) as i64) % Q - Q / 2;
            }
        }
    }
    a
}
fn matrix_a() -> [[Poly; L]; K] { gen_matrix(b"ccx-lring-A") }
fn matrix_a2() -> [[Poly; L]; K] { gen_matrix(b"ccx-lring-A2") }

// Secret s in [-ETA,ETA]^(L*N) from seed.
fn sample_secret(seed: &[u8]) -> PolyVecL {
    let mut s: PolyVecL = [poly_zero(); L];
    let mut r = xof(&[b"ccx-lring-s", seed]);
    let span = (2 * ETA + 1) as u32;
    for l in 0..L { for i in 0..N { s[l][i] = (read_u32(&mut r) % span) as i64 - ETA; } }
    s
}
// Mask y in [-GAMMA,GAMMA]^(L*N) from seed+nonce.
fn sample_mask(seed: &[u8], nonce: u32) -> PolyVecL {
    let mut y: PolyVecL = [poly_zero(); L];
    let mut r = xof(&[b"ccx-lring-y", seed, &nonce.to_le_bytes()]);
    let span = (2 * GAMMA + 1) as u32;
    for l in 0..L { for i in 0..N { y[l][i] = (read_u32(&mut r) % span) as i64 - GAMMA; } }
    y
}
// SampleInBall: challenge poly with TAU coeffs in {-1,+1}, rest 0, from a 32-byte seed.
fn sample_challenge(seed: &[u8; 32]) -> Poly {
    let mut c = poly_zero();
    let mut r = xof(&[b"ccx-lring-c", seed]);
    let mut placed = 0;
    while placed < TAU {
        let j = (read_u32(&mut r) as usize) % N;
        if c[j] == 0 { c[j] = if (read_u32(&mut r) & 1) == 0 { 1 } else { -1 }; placed += 1; }
    }
    c
}

// ---- serialization helpers (centered coeffs as i32 LE; demo-simple, not compact) ----
fn put_poly(out: &mut Vec<u8>, p: &Poly) { for &c in p.iter() { out.extend_from_slice(&(c as i32).to_le_bytes()); } }
fn put_vecl(out: &mut Vec<u8>, v: &PolyVecL) { for p in v.iter() { put_poly(out, p); } }
fn put_veck(out: &mut Vec<u8>, v: &PolyVecK) { for p in v.iter() { put_poly(out, p); } }
fn get_poly(b: &[u8], off: &mut usize) -> Poly { let mut p = poly_zero(); for i in 0..N { let mut x = [0u8; 4]; x.copy_from_slice(&b[*off..*off + 4]); p[i] = i32::from_le_bytes(x) as i64; *off += 4; } p }
fn get_vecl(b: &[u8], off: &mut usize) -> PolyVecL { let mut v: PolyVecL = [poly_zero(); L]; for l in 0..L { v[l] = get_poly(b, off); } v }
fn get_veck(b: &[u8], off: &mut usize) -> PolyVecK { let mut v: PolyVecK = [poly_zero(); K]; for k in 0..K { v[k] = get_poly(b, off); } v }

pub const PK_BYTES: usize = K * N * 4;          // t
pub const SK_SEED_BYTES: usize = 32;            // sk = 32-byte seed (s re-derived)
pub const TAG_BYTES: usize = K * N * 4;         // I
pub fn sig_bytes(n: usize) -> usize { 32 /*seed0*/ + TAG_BYTES + n * L * N * 4 }

pub fn keygen(seed32: &[u8; 32]) -> (Vec<u8>, PolyVecL, PolyVecK) {
    let s = sample_secret(seed32);
    let a = matrix_a();
    let t = mat_vec(&a, &s);
    let mut pk = Vec::with_capacity(PK_BYTES);
    put_veck(&mut pk, &t);
    (pk, s, t)
}
pub fn tag(s: &PolyVecL) -> PolyVecK { mat_vec(&matrix_a2(), s) }
/// Serialized link tag I = A2*s (same byte layout the signature/verify use).
pub fn tag_bytes_of(s: &PolyVecL) -> Vec<u8> { let i = tag(s); let mut b = Vec::new(); put_veck(&mut b, &i); b }

fn hash_seed(msg: &[u8], ring: &[u8], i_tag: &[u8], w: &PolyVecK, w2: &PolyVecK, idx: usize) -> [u8; 32] {
    let mut wb = Vec::new(); put_veck(&mut wb, w); put_veck(&mut wb, w2);
    let mut r = xof(&[b"ccx-lring-h", msg, ring, i_tag, &wb, &(idx as u32).to_le_bytes()]);
    let mut out = [0u8; 32]; r.read(&mut out); out
}

/// Sign: ring = concatenated pk bytes (n members), signer at `idx` with secret `s`.
/// Returns the serialized signature, or None if signing aborted too many times.
pub fn sign(msg: &[u8], ring_pks: &[Vec<u8>], idx: usize, sk_seed: &[u8; 32]) -> Option<Vec<u8>> {
    let n = ring_pks.len();
    let a = matrix_a();
    let a2 = matrix_a2();
    let s = sample_secret(sk_seed);
    let i_tag = tag(&s);
    let mut tag_bytes = Vec::new(); put_veck(&mut tag_bytes, &i_tag);
    // ring blob for hashing = all pubkeys concatenated
    let mut ring_blob = Vec::new(); for p in ring_pks { ring_blob.extend_from_slice(p); }
    // decode each member's t
    let mut t_list: Vec<PolyVecK> = Vec::with_capacity(n);
    for p in ring_pks { let mut off = 0; t_list.push(get_veck(p, &mut off)); }

    for attempt in 0..256u32 {
        let mut z: Vec<PolyVecL> = vec![[poly_zero(); L]; n];
        // real branch commit
        let y = sample_mask(sk_seed, attempt);
        let w_j = mat_vec(&a, &y);
        let w2_j = mat_vec(&a2, &y);
        let mut seed = [[0u8; 32]; 1];
        let mut seeds: Vec<[u8; 32]> = vec![[0u8; 32]; n];
        // start chain at idx+1 from the real commit
        let next = (idx + 1) % n;
        seeds[next] = hash_seed(msg, &ring_blob, &tag_bytes, &w_j, &w2_j, next);
        // walk simulated branches idx+1 .. idx-1
        let mut i = next;
        let mut ok = true;
        while i != idx {
            let c = sample_challenge(&seeds[i]);
            // simulate z_i uniform in [-ZBOUND, ZBOUND]
            let zi = sample_mask_bounded(sk_seed, attempt, i as u32);
            z[i] = zi;
            // w_i = A*z_i - c*t_i ; w2_i = A2*z_i - c*I
            let azi = mat_vec(&a, &z[i]);
            let cti = veck_scale(&c, &t_list[i]);
            let w_i = veck_sub(&azi, &cti);
            let a2zi = mat_vec(&a2, &z[i]);
            let cii = veck_scale(&c, &i_tag);
            let w2_i = veck_sub(&a2zi, &cii);
            let nx = (i + 1) % n;
            seeds[nx] = hash_seed(msg, &ring_blob, &tag_bytes, &w_i, &w2_i, nx);
            i = nx;
        }
        // close real branch: c_j from seeds[idx]
        let c_j = sample_challenge(&seeds[idx]);
        // z_j = y + c_j * s  (per secret poly)
        let mut zj: PolyVecL = [poly_zero(); L];
        for l in 0..L { zj[l] = poly_add(&y[l], &poly_mul(&c_j, &s[l])); }
        if vecl_inf_norm(&zj) > ZBOUND { ok = false; }
        if ok {
            z[idx] = zj;
            // signature = seed0 (seeds[0]) + tag + z_0..z_{n-1}
            seed[0] = seeds[0];
            let mut out = Vec::with_capacity(sig_bytes(n));
            out.extend_from_slice(&seeds[0]);
            put_veck(&mut out, &i_tag);
            for zi in &z { put_vecl(&mut out, zi); }
            return Some(out);
        }
        let _ = seed;
    }
    None
}

// A second bounded mask used to simulate z_i (uniform in [-ZBOUND, ZBOUND]).
fn sample_mask_bounded(seed: &[u8], attempt: u32, idx: u32) -> PolyVecL {
    let mut y: PolyVecL = [poly_zero(); L];
    let mut r = xof(&[b"ccx-lring-zsim", seed, &attempt.to_le_bytes(), &idx.to_le_bytes()]);
    let span = (2 * ZBOUND + 1) as u32;
    for l in 0..L { for i in 0..N { y[l][i] = (read_u32(&mut r) % span) as i64 - ZBOUND; } }
    y
}

/// Verify: recompute the ring chain; accept iff it closes (seed_n == seed_0) and all z_i are short.
/// On success, returns the tag I bytes (for the caller to hash into a 32-byte nullifier).
pub fn verify(msg: &[u8], ring_pks: &[Vec<u8>], sig: &[u8]) -> Option<Vec<u8>> {
    let n = ring_pks.len();
    if sig.len() != sig_bytes(n) { return None; }
    let a = matrix_a();
    let a2 = matrix_a2();
    let mut off = 0usize;
    let mut seed0 = [0u8; 32]; seed0.copy_from_slice(&sig[off..off + 32]); off += 32;
    let i_tag = get_veck(sig, &mut off);
    let mut tag_bytes = Vec::new(); put_veck(&mut tag_bytes, &i_tag);
    let mut z: Vec<PolyVecL> = Vec::with_capacity(n);
    for _ in 0..n { z.push(get_vecl(sig, &mut off)); }
    let mut ring_blob = Vec::new(); for p in ring_pks { ring_blob.extend_from_slice(p); }
    let mut t_list: Vec<PolyVecK> = Vec::with_capacity(n);
    for p in ring_pks { let mut o = 0; t_list.push(get_veck(p, &mut o)); }

    // walk the whole ring starting from seed0 at index 0
    let mut seed = seed0;
    for i in 0..n {
        if vecl_inf_norm(&z[i]) > ZBOUND { return None; }
        let c = sample_challenge(&seed);
        let azi = mat_vec(&a, &z[i]);
        let cti = veck_scale(&c, &t_list[i]);
        let w_i = veck_sub(&azi, &cti);
        let a2zi = mat_vec(&a2, &z[i]);
        let cii = veck_scale(&c, &i_tag);
        let w2_i = veck_sub(&a2zi, &cii);
        let nx = (i + 1) % n;
        seed = hash_seed(msg, &ring_blob, &tag_bytes, &w_i, &w2_i, nx);
    }
    if seed == seed0 { Some(tag_bytes) } else { None }
}
