//! EXPERIMENTAL / UNVERIFIED lattice linkable ring signature (CIP-0001 §5.3, demo only).
//!
//! Construction: an AOS/LSAG-style hash-chained ring of Fiat-Shamir-with-aborts (Dilithium-style)
//! Sigma proofs over the module-SIS one-way function t = A*s (s short), with a linking tag
//! I = A2*s bound into every branch's verification. The real branch forces I = A2*s_signer, so the
//! tag is deterministic in the signer's secret (linkable, malicious-signer-sound) while the ring
//! closure hides which member signed (anonymous: all z_i are uniform, the chain is symmetric).
//!
//! THIS IS NOT AUDITED AND THE PARAMETERS ARE DEMO-GRADE (small dimensions, NOT a calibrated security
//! level). It exists to demonstrate that a genuinely anonymous + linkable post-quantum ring signature
//! is structurally possible on this ABI. Do not use on mainnet.
//!
//! CONSTANT-TIME STATUS (mainnet activation gate, see ringsig-hardening.md §5): the modular-arithmetic
//! HOT PATHS are now constant-time. Every reduction the secret key `s`, masks `y`, and responses `z`
//! flow through — `mulmod` (Barrett, no idiv), `cmod`/`pmod` (`reduce_to_0q`, no idiv), and `addq`/`subq`
//! (branchless masked select) — is division-free and branchless, so the NTT butterflies / reductions run
//! in time independent of secret operand values. The rewrite is BIT-IDENTICAL to the old `%`-based code
//! (NTT-vs-schoolbook equivalence == 0, all selftests green). RESIDUAL: the Fiat-Shamir-with-aborts
//! rejection loop in `sign()` still has a secret-dependent ITERATION COUNT (the `‖z‖∞ ≤ ZBOUND` abort
//! decision depends on the mask norm) — a standard, accepted lattice-signature consideration, documented
//! as a residual rather than fully masked; see ringsig-hardening.md §5. Sampling/challenge-handling
//! side-channels remain part of the broader audit gate.
//!
//! Ring polynomial: R_q = Z_q[X]/(X^256 + 1), q = 8380417 (negacyclic schoolbook multiplication).
use sha3::Shake256;
use sha3::digest::{Update, ExtendableOutput, XofReader};

// ============================== PARAMETER SET (HEURISTIC) ======================================
// These are a HEURISTIC module-SIS/LWE parameter set chosen to lift the demo (K=L=4) toward a
// NIST-category-1-ish module rank. They are NOT calibrated by a lattice estimator and are NOT a
// proven security level — a cryptographer MUST run a current estimator (e.g. the APS/"lattice
// estimator" / MATZOV refinements) over both the MSIS forgery instance (the A lattice) and the MLWE
// key-recovery instance (t = A·s, s short) and re-tune before ANY mainnet consideration. See
// docs/design/quantum-resistance/ringsig-hardening.md §Parameters for the rationale and the gate.
//
// Rationale for K=L=6 over the old K=L=4: the unforgeability binding rests on Module-SIS over the
// rank-(K) module; raising K (rows of A and A2) and L (secret cols) increases the SIS/LWE block
// dimension (here 6·256 = 1536 vs the old 1024), which is the dominant lever on lattice-attack cost
// at fixed N,q. K=6 mirrors Dilithium-3's row count (a cat-3 NIST primitive) as a sanity anchor,
// while we deliberately keep the OTHER bounds (η, τ, γ) at the Dilithium-2-ish demo values, so the
// honest claim is "cat-1-ish heuristic", not "matches Dilithium-3". Cost: the public key (K·N·4) and
// the per-member signature share (L·N·4) grow ~50%; a ring-of-4 signature goes 20512 -> 30752 B.
pub const N: usize = 256;          // poly degree (X^N+1, NTT-friendly with q below)
pub const Q: i64 = 8380417;        // modulus (Dilithium prime, 23-bit; supports negacyclic NTT)
pub const K: usize = 6;            // # equations (rows of A) — also tag rows  [HEURISTIC: was 4]
pub const L: usize = 6;            // # secret polys (cols)                    [HEURISTIC: was 4]
pub const ETA: i64 = 2;            // secret coeff bound |s| <= ETA
pub const TAU: usize = 39;         // challenge weight (# of +/-1 coeffs)
pub const GAMMA: i64 = 1 << 17;    // mask bound
pub const BETA: i64 = (TAU as i64) * ETA; // max |c*s|_inf bound => 78
pub const ZBOUND: i64 = GAMMA - BETA;     // accepted |z|_inf range

pub type Poly = [i64; N];
pub type PolyVecL = [Poly; L];
pub type PolyVecK = [Poly; K];

// ============================== CONSTANT-TIME MODULAR ARITHMETIC ===============================
// MAINNET-GATE HARDENING (CIP-0001 §5.3 / docs/design/quantum-resistance/ringsig-hardening.md §5):
// the scheme is testnet-only PARTLY because the modular reductions below used to branch on / divide by
// secret-dependent data (the key `s`, masks `y`, responses `z` all flow through cmod/pmod/mulmod in the
// NTT butterflies). A `%`-by-Q compiles to a hardware `idiv` whose latency is data-dependent, and the
// `if r >= Q`/`if r < 0` folds are secret-dependent branches — both are timing side channels. Every
// reduction here is now BRANCHLESS and division-free (multiply + arithmetic-shift + masked subtract),
// so the running time is independent of the secret operand values. The rewrite is BIT-IDENTICAL to the
// old `%`-based code over every input range these functions see (proven exhaustively against the old
// definitions before integration, and guarded at runtime by `ntt_matches_schoolbook` == 0 and the
// sign/verify selftests): signatures, keys and nullifiers are unchanged and the wire format is the same.
//
// Branchless masked-select idiom used throughout: for a signed i64 `v`, `(v >> 63)` is an arithmetic
// (sign-extending) shift giving the all-ones mask `-1` iff v < 0, else `0`. `Q & mask` is then `Q` iff
// v < 0 else `0`, so `x + (Q & mask)` / `x - (Q & mask)` is a conditional ±Q with NO branch.

// Constant-time fold of a value already in [0, 2Q) to [0, Q): subtract Q iff a >= Q. Bit-identical to
// the old `if a >= Q { a - Q } else { a }` over [0, 2Q). `t = a - Q` is in [-Q, Q); its sign bit selects
// whether to add Q back. (Old name `addq`: the NTT butterfly's plus-side reduction of a sum in [0,2Q).)
#[inline] fn addq(a: i64) -> i64 { let t = a - Q; t + (Q & (t >> 63)) }
// Constant-time fold of a value in (-Q, Q) to [0, Q): add Q iff a < 0. Bit-identical to the old
// `if a < 0 { a + Q } else { a }`. (Old name `subq`: the butterfly's minus-side reduction of a diff.)
#[inline] fn subq(a: i64) -> i64 { a + (Q & (a >> 63)) }

// General constant-time reduction of an ARBITRARY i64 to [0, Q), == the mathematical mod (== the old
// `((a % Q) + Q) % Q`). No `idiv`: estimate floor(a/Q) by a fixed-point reciprocal multiply-shift, then
// correct branchlessly. RECIP = floor(2^RSHIFT / Q); the estimate error is < 1 over the whole i64 range
// (|a|·(2^RSHIFT/Q - RECIP)/2^RSHIFT < |a|/2^RSHIFT <= 2^63/2^84 < 1) plus at most 1 from the two floors,
// so r = a - qf*Q lands in (-2Q, 2Q) and ONE masked ±Q each side suffices — we apply TWO each side as a
// proven-ample constant-count margin (still branchless, no data-dependent loop count).
const RSHIFT: u32 = 84;                       // 2^84 fits the i128 product a*RECIP for |a| up to 2^63
const RECIP: i128 = (1i128 << RSHIFT) / (Q as i128); // ~2^61, computed at compile time (const eval)
#[inline] fn reduce_to_0q(a: i64) -> i64 {
    // floor((a as i128 * RECIP) >> RSHIFT): i128 arithmetic shift floors toward -inf (matches the
    // mathematical floor for negative a, exactly as the multiply-shift derivation requires).
    let qf = ((a as i128 * RECIP) >> RSHIFT) as i64;
    // `wrapping_*` throughout: for inputs near i64::MIN/MAX the intermediate `qf*Q` and `a - qf*Q` can
    // wrap two's-complement, which is EXACT for this reduction (the true `a - qf*Q` lands in (-2Q, 2Q),
    // and its low 64 bits are preserved by wraparound). Using wrapping ops also keeps it panic-free in
    // debug builds. The masked corrections below stay in-range so they need no wrapping. (For the
    // actually-reachable inputs — i32/u32-bounded — nothing wraps; this just makes it total.)
    let mut r = a.wrapping_sub(qf.wrapping_mul(Q));
    // if r >= Q subtract Q (mask = (Q-1-r) sign bit: all-ones iff r > Q-1 iff r >= Q), applied twice.
    r -= Q & ((Q - 1 - r) >> 63);
    r -= Q & ((Q - 1 - r) >> 63);
    // if r < 0 add Q, applied twice.
    r += Q & (r >> 63);
    r += Q & (r >> 63);
    r
}
// Centered representative in [-Q/2, Q/2] (Q odd => Q/2 = (Q-1)/2). Constant-time, division-free and
// branchless. Bit-identical to the old `r = a % Q; if r > Q/2 { r -= Q }; if r < -Q/2 { r += Q }` over
// every input range cmod sees (centered-coeff sums/diffs, intt outputs in [0,Q), and the full i32/u32
// adversarial ranges that `coeff_is_canonical` and the forge helpers feed it). cmod is a canonicalizing
// bijection onto [-Q/2, Q/2], which is what `coeff_is_canonical` (c == cmod(c)) relies on.
#[inline] fn cmod(a: i64) -> i64 {
    let r = reduce_to_0q(a);          // [0, Q)
    // fold the upper half down: subtract Q iff r > Q/2 (mask = (Q/2 - r) sign bit, all-ones iff r > Q/2).
    r - (Q & (((Q / 2) - r) >> 63))
}
// Non-negative representative in [0, Q). Constant-time, division-free, branchless.
#[inline] fn pmod(a: i64) -> i64 { reduce_to_0q(a) }
fn poly_zero() -> Poly { [0i64; N] }
fn poly_add(a: &Poly, b: &Poly) -> Poly { let mut r = poly_zero(); for i in 0..N { r[i] = cmod(a[i] + b[i]); } r }
fn poly_sub(a: &Poly, b: &Poly) -> Poly { let mut r = poly_zero(); for i in 0..N { r[i] = cmod(a[i] - b[i]); } r }

// --- Negacyclic NTT over R_q = Z_q[X]/(X^256+1) -------------------------------------------------
// q=8380417 is the Dilithium prime; ZETA=1753 is a primitive 512th root of unity (ZETA^256 = -1),
// so a length-256 NTT diagonalises negacyclic convolution. This replaces the old O(N^2) schoolbook
// poly_mul with an O(N log N) transform. It is a PURE SPEEDUP: the result is reduced with the SAME
// cmod() to the centered representative, so poly_mul returns byte-identical polynomials to the old
// schoolbook for every input — signatures are unchanged, only faster. (Verified against schoolbook
// over thousands of random vectors before integration.)
const ZETA: i64 = 1753;
// Constant-time modular multiply via BARRETT reduction. CALLED ONLY with both operands in [0, Q)
// (NTT twiddles, pre-transformed residues, n_inv()), so the product p = a*b is in [0, (Q-1)^2] < 2^46.
// The old `(a * b) % Q` used a hardware `idiv` whose latency depends on the operand bytes — a timing
// side channel on the secret-derived residues flowing through the butterflies. Barrett replaces the
// divide with a multiply-by-reciprocal, an arithmetic shift, and TWO branchless masked subtractions:
//   q_est = (p * BARRETT_M) >> BARRETT_K  (the i128 product is exact; q_est is floor(p/Q) or one less)
//   r     = p - q_est*Q                   (in [0, ~2Q))
//   r    -= Q twice, each guarded by a sign-bit mask, landing r in [0, Q).
// BARRETT_M = floor(2^BARRETT_K / Q). With BARRETT_K = 46 (> log2 of the max product) the estimate is
// off by at most 1, so two conditional subtractions are provably enough. Result is BIT-IDENTICAL to
// `(a*b) % Q` for all a,b in [0,Q) (verified exhaustively over edges + tens of millions of pairs);
// `ntt_matches_schoolbook` re-proves end-to-end that the transform output is unchanged.
const BARRETT_K: u32 = 46;
const BARRETT_M: i64 = ((1i128 << BARRETT_K) / (Q as i128)) as i64; // floor(2^46 / Q), ~2^23, const eval
#[inline] fn mulmod(a: i64, b: i64) -> i64 {
    let p = a * b;                                              // exact: a,b in [0,Q) => p < 2^46 < i64::MAX
    let q_est = ((p as i128 * BARRETT_M as i128) >> BARRETT_K) as i64;
    let mut r = p - q_est * Q;                                  // in [0, ~2Q)
    r -= Q & ((Q - 1 - r) >> 63);                               // if r >= Q subtract Q (branchless)
    r -= Q & ((Q - 1 - r) >> 63);                               // estimate off by <= 1 => twice suffices
    r
}
fn powmod(mut b: i64, mut e: i64) -> i64 { let mut r = 1i64; b = pmod(b); while e > 0 { if e & 1 == 1 { r = mulmod(r, b); } b = mulmod(b, b); e >>= 1; } r }
#[inline] fn bitrev8(mut x: usize) -> usize { let mut r = 0; for _ in 0..8 { r = (r << 1) | (x & 1); x >>= 1; } r }

// ZETA^bitrev8(i), the twiddle table the in-place Cooley-Tukey / Gentleman-Sande butterflies index.
fn zeta_table() -> &'static [i64; N] {
    use std::sync::OnceLock;
    static T: OnceLock<[i64; N]> = OnceLock::new();
    T.get_or_init(|| { let mut z = [0i64; N]; for i in 0..N { z[i] = powmod(ZETA, bitrev8(i) as i64); } z })
}
// N^{-1} mod q, applied once at the end of the inverse transform.
fn n_inv() -> i64 { use std::sync::OnceLock; static V: OnceLock<i64> = OnceLock::new(); *V.get_or_init(|| powmod(N as i64, Q - 2)) }

// Forward NTT, in place (operands in [0,Q)). Cooley-Tukey decimation-in-time.
fn ntt(p: &mut [i64; N]) {
    let zt = zeta_table();
    let mut k = 1usize;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            let zeta = zt[k]; k += 1;
            for j in start..start + len {
                let t = mulmod(zeta, p[j + len]);
                p[j + len] = subq(p[j] - t);
                p[j] = addq(p[j] + t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}
// Inverse NTT, in place. Gentleman-Sande, with the final N^{-1} scaling.
fn intt(p: &mut [i64; N]) {
    let zt = zeta_table();
    let mut k = N - 1;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            let zeta = zt[k]; k = k.wrapping_sub(1);
            for j in start..start + len {
                let t = p[j];
                p[j] = addq(t + p[j + len]);
                p[j + len] = mulmod(zeta, subq(p[j + len] - t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    let ni = n_inv();
    for i in 0..N { p[i] = mulmod(ni, pmod(p[i])); }
}
// Forward NTT of a poly into [0,Q) representation (used to pre-transform cached matrices once).
fn poly_to_ntt(a: &Poly) -> [i64; N] { let mut f = [0i64; N]; for i in 0..N { f[i] = pmod(a[i]); } ntt(&mut f); f }
// Pointwise product of two NTT-domain polys, then inverse-transform back to centered coeffs.
fn ntt_pointwise_inv(fa: &[i64; N], fb: &[i64; N]) -> Poly {
    let mut fc = [0i64; N];
    for i in 0..N { fc[i] = mulmod(fa[i], fb[i]); }
    intt(&mut fc);
    let mut r = poly_zero();
    for i in 0..N { r[i] = cmod(fc[i]); }
    r
}
fn poly_mul(a: &Poly, b: &Poly) -> Poly { // negacyclic, via NTT (bit-identical to old schoolbook)
    ntt_pointwise_inv(&poly_to_ntt(a), &poly_to_ntt(b))
}

// Reference O(N^2) negacyclic schoolbook multiply (X^N = -1). RETAINED as the ground-truth oracle for
// the NTT: the NTT poly_mul above is a PURE SPEEDUP claim, so a future twiddle/sign/bitrev regression
// must be caught BEFORE it silently changes signature bytes and bricks stored testnet PQ outputs. The
// equivalence is asserted at runtime by `ntt_matches_schoolbook` (exposed via ccx_pqr_ntt_equiv_test,
// so even the daemon build — which never runs `cargo test` — exercises it).
fn poly_mul_schoolbook(a: &Poly, b: &Poly) -> Poly {
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

/// Asserts the NTT `poly_mul` is BIT-IDENTICAL to `poly_mul_schoolbook` over the scheme's real input
/// distributions plus edge cases. Returns the number of MISMATCHES found (0 == NTT is a pure speedup).
/// `iters` random trials are run with a deterministic SHAKE-seeded PRNG (reproducible). Distributions:
///   * a: z-range masks in [-ZBOUND, ZBOUND]
///   * b: one of {sparse +/-1 challenge (TAU weight), uniform t in [0,q), small +/-2 secret}
/// plus deterministic edge cases (all-zero, all-ones, single-spike, full-negative).
pub fn ntt_matches_schoolbook(iters: u32) -> u32 {
    let mut mism: u32 = 0;
    let check = |a: &Poly, b: &Poly, mism: &mut u32| {
        if poly_mul(a, b) != poly_mul_schoolbook(a, b) { *mism += 1; }
    };

    // --- deterministic edge cases ---
    let zero = poly_zero();
    let mut ones = poly_zero(); for i in 0..N { ones[i] = 1; }
    let mut neg = poly_zero(); for i in 0..N { neg[i] = -ZBOUND; }
    let mut spike = poly_zero(); spike[0] = ZBOUND; spike[N - 1] = -ZBOUND;
    let mut tmax = poly_zero(); for i in 0..N { tmax[i] = cmod((Q - 1) as i64); }
    for a in [&zero, &ones, &neg, &spike, &tmax] {
        for b in [&zero, &ones, &neg, &spike, &tmax] { check(a, b, &mut mism); }
    }

    // --- randomized trials over real distributions ---
    let mut r = xof(&[b"ccx-lring-ntt-equiv-prng"]);
    for t in 0..iters {
        let mut a = poly_zero();
        for i in 0..N { a[i] = read_uniform(&mut r, (2 * ZBOUND + 1) as u32) as i64 - ZBOUND; }
        let mut b = poly_zero();
        match t % 3 {
            0 => { // sparse +/-1 challenge of weight TAU (the real challenge distribution)
                let mut placed = 0;
                while placed < TAU { let j = (read_u32(&mut r) as usize) % N; if b[j] == 0 { b[j] = if read_u32(&mut r) & 1 == 0 { 1 } else { -1 }; placed += 1; } }
            }
            1 => { for i in 0..N { b[i] = cmod(read_uniform(&mut r, Q as u32) as i64); } } // uniform t
            _ => { for i in 0..N { b[i] = read_uniform(&mut r, (2 * ETA + 1) as u32) as i64 - ETA; } } // secret-range
        }
        check(&a, &b, &mut mism);
    }
    mism
}
fn poly_inf_norm(a: &Poly) -> i64 { let mut m = 0; for &c in a.iter() { let v = if c < 0 { -c } else { c }; if v > m { m = v; } } m }
fn vecl_inf_norm(v: &PolyVecL) -> i64 { let mut m = 0; for p in v.iter() { let n = poly_inf_norm(p); if n > m { m = n; } } m }

// A coefficient is CANONICAL iff it equals its own centered residue (i.e. cmod is a no-op). The wire
// format serializes cmod'd values, so any deserialized coeff that is NOT canonical (e.g. I+q smuggled
// in to keep the same algebraic tag while changing the hashed bytes) must be REJECTED. Without this,
// the arithmetic (which reduces mod q) accepts a non-canonical tag while the nullifier
// (= SHAKE256(tag_bytes)) differs — a double-spend linkability break (codex review finding).
#[inline] fn coeff_is_canonical(c: i64) -> bool { c == cmod(c) }
fn veck_is_canonical(v: &PolyVecK) -> bool { v.iter().all(|p| p.iter().all(|&c| coeff_is_canonical(c))) }
fn vecl_is_canonical(v: &PolyVecL) -> bool { v.iter().all(|p| p.iter().all(|&c| coeff_is_canonical(c))) }

/// Decode a ring member's public key `t` from its serialized bytes, validating BOTH:
///   * length (`p.len() >= PK_BYTES`) — a short Vec would make `get_veck` read out of bounds (panic /
///     DoS), and
///   * canonical encoding — a non-canonical `t_i` is algebraically equal mod q but BYTEWISE different,
///     so it lands differently in `ring_blob` and two honest nodes would hash different `seed_{i+1}`
///     from the same on-chain ring → a CONSENSUS SPLIT. (It is also the root of algebraic-key-aliasing
///     loss-of-funds: `t` and `t+q` share one secret/nullifier, so only one is ever spendable.)
/// Returns the decoded `t`, or None if either check fails (the caller aborts sign/verify with None).
fn decode_ring_member(p: &[u8]) -> Option<PolyVecK> {
    if p.len() < PK_BYTES { return None; }
    let mut off = 0usize;
    let t = get_veck(p, &mut off);
    if !veck_is_canonical(&t) { return None; }
    Some(t)
}

/// True iff `pk` is a well-formed public key: exactly `PK_BYTES` long AND every coefficient canonically
/// encoded. The C++ output-acceptance check (`check_outs_valid`) calls this so a non-canonical PQ
/// output key is REJECTED at acceptance — the root fix for algebraic-key-aliasing loss-of-funds (two
/// outputs `t` / `t+q` share one secret + nullifier, so only one is ever spendable) and for the
/// consensus-split risk (a non-canonical ring member hashes differently across nodes).
pub fn pubkey_is_canonical(pk: &[u8]) -> bool {
    if pk.len() != PK_BYTES { return false; }
    let mut off = 0usize;
    let t = get_veck(pk, &mut off);
    veck_is_canonical(&t)
}

// A*z for A: K x L, z: L -> K (kept for completeness / reference; the hot path uses mat_vec_ntt
// against the cached NTT-domain matrices so z is forward-transformed once instead of K*L times).
#[allow(dead_code)]
fn mat_vec(a: &[[Poly; L]; K], z: &PolyVecL) -> PolyVecK {
    let mut out: PolyVecK = [poly_zero(); K];
    for k in 0..K {
        let mut acc = poly_zero();
        for l in 0..L { acc = poly_add(&acc, &poly_mul(&a[k][l], &z[l])); }
        out[k] = acc;
    }
    out
}

// NTT-domain K x L matrix (each entry pre-forward-transformed once and cached).
type NttMatrix = [[[i64; N]; L]; K];
// A*z using a cached NTT-domain matrix: forward-transform each z_l ONCE (L transforms), accumulate
// the K*L pointwise products in NTT domain, then inverse-transform each of the K outputs (K
// transforms). This is mathematically identical to mat_vec (the NTT is a ring isomorphism, the
// pointwise sum equals the transform of the convolution sum), so signatures stay byte-identical —
// it just collapses 2*K*L forward transforms into L.
fn mat_vec_ntt(a_ntt: &NttMatrix, z: &PolyVecL) -> PolyVecK {
    let mut zf: [[i64; N]; L] = [[0i64; N]; L];
    for l in 0..L { zf[l] = poly_to_ntt(&z[l]); }
    mat_apply_ntt(a_ntt, &zf)
}
// Apply a cached NTT-domain matrix to an already-forward-transformed z (avoids re-transforming z).
fn mat_apply_ntt(a_ntt: &NttMatrix, zf: &[[i64; N]; L]) -> PolyVecK {
    let mut out: PolyVecK = [poly_zero(); K];
    for k in 0..K {
        let mut acc = [0i64; N];
        for l in 0..L {
            let m = &a_ntt[k][l];
            for i in 0..N { acc[i] = addq(acc[i] + mulmod(m[i], zf[l][i])); }
        }
        intt(&mut acc);
        for i in 0..N { out[k][i] = cmod(acc[i]); }
    }
    out
}
// Apply BOTH A and A2 to the same z, forward-transforming z only ONCE (the verify/sign inner loop
// always needs A*z AND A2*z together). Returns (A*z, A2*z). Bit-identical to two mat_vec_ntt calls.
fn mat_vec2_ntt(a_ntt: &NttMatrix, a2_ntt: &NttMatrix, z: &PolyVecL) -> (PolyVecK, PolyVecK) {
    let mut zf: [[i64; N]; L] = [[0i64; N]; L];
    for l in 0..L { zf[l] = poly_to_ntt(&z[l]); }
    (mat_apply_ntt(a_ntt, &zf), mat_apply_ntt(a2_ntt, &zf))
}
#[allow(dead_code)]
fn veck_add(a: &PolyVecK, b: &PolyVecK) -> PolyVecK { let mut r: PolyVecK = [poly_zero(); K]; for k in 0..K { r[k] = poly_add(&a[k], &b[k]); } r }
fn veck_sub(a: &PolyVecK, b: &PolyVecK) -> PolyVecK { let mut r: PolyVecK = [poly_zero(); K]; for k in 0..K { r[k] = poly_sub(&a[k], &b[k]); } r }
#[allow(dead_code)]
fn veck_scale(c: &Poly, b: &PolyVecK) -> PolyVecK { let mut r: PolyVecK = [poly_zero(); K]; for k in 0..K { r[k] = poly_mul(c, &b[k]); } r }
// c * b for a pre-transformed b (NTT domain): forward-transform c ONCE, pointwise-multiply against
// each of the K cached b_k, inverse-transform back. Bit-identical to veck_scale(c, b); used in the
// hot loop where b (a ring member's t, or the tag I) is fixed across all branches so it is
// transformed once up front instead of K times per branch.
type NttVecK = [[i64; N]; K];
fn veck_to_ntt(b: &PolyVecK) -> NttVecK { let mut m: NttVecK = [[0i64; N]; K]; for k in 0..K { m[k] = poly_to_ntt(&b[k]); } m }
fn veck_scale_ntt(c: &Poly, b_ntt: &NttVecK) -> PolyVecK {
    let cf = poly_to_ntt(c);
    let mut r: PolyVecK = [poly_zero(); K];
    for k in 0..K { r[k] = ntt_pointwise_inv(&cf, &b_ntt[k]); }
    r
}

fn xof(parts: &[&[u8]]) -> impl XofReader {
    let mut x = Shake256::default();
    for p in parts { Update::update(&mut x, p); }
    x.finalize_xof()
}
fn read_u32(r: &mut impl XofReader) -> u32 { let mut b = [0u8; 4]; r.read(&mut b); u32::from_le_bytes(b) }
// Unbiased uniform in [0, span) via rejection of the top partial block (removes the modulo bias the
// review flagged; real and decoy z then share an identical uniform distribution => anonymity holds).
fn read_uniform(r: &mut impl XofReader, span: u32) -> u32 {
    let limit = (u32::MAX / span) * span;
    loop { let x = read_u32(r); if x < limit { return x % span; } }
}

// Public matrices A (K x L) and A2 (K x L) derived from fixed domain-separated seeds.
fn gen_matrix(domain: &[u8]) -> [[Poly; L]; K] {
    let mut a = [[poly_zero(); L]; K];
    for k in 0..K {
        for l in 0..L {
            let mut r = xof(&[domain, &[k as u8, l as u8]]);
            for i in 0..N {
                a[k][l][i] = cmod(read_uniform(&mut r, Q as u32) as i64);
            }
        }
    }
    a
}
fn matrix_to_ntt(a: &[[Poly; L]; K]) -> NttMatrix {
    let mut m: NttMatrix = [[[0i64; N]; L]; K];
    for k in 0..K { for l in 0..L { m[k][l] = poly_to_ntt(&a[k][l]); } }
    m
}
// A and A2 are FIXED (seed-derived) public parameters, so generate them — and their NTT-domain
// forms — once and reuse. The old code re-ran SHAKE over K*L*N coeffs and re-derived the matrices on
// every sign/verify; caching removes that per-call cost entirely.
fn matrix_a() -> &'static [[Poly; L]; K] {
    use std::sync::OnceLock; static M: OnceLock<[[Poly; L]; K]> = OnceLock::new();
    M.get_or_init(|| gen_matrix(b"ccx-lring-A"))
}
fn matrix_a2() -> &'static [[Poly; L]; K] {
    use std::sync::OnceLock; static M: OnceLock<[[Poly; L]; K]> = OnceLock::new();
    M.get_or_init(|| gen_matrix(b"ccx-lring-A2"))
}
fn matrix_a_ntt() -> &'static NttMatrix {
    use std::sync::OnceLock; static M: OnceLock<NttMatrix> = OnceLock::new();
    M.get_or_init(|| matrix_to_ntt(matrix_a()))
}
fn matrix_a2_ntt() -> &'static NttMatrix {
    use std::sync::OnceLock; static M: OnceLock<NttMatrix> = OnceLock::new();
    M.get_or_init(|| matrix_to_ntt(matrix_a2()))
}

// Secret s in [-ETA,ETA]^(L*N) from seed.
fn sample_secret(seed: &[u8]) -> PolyVecL {
    let mut s: PolyVecL = [poly_zero(); L];
    let mut r = xof(&[b"ccx-lring-s", seed]);
    let span = (2 * ETA + 1) as u32;
    for l in 0..L { for i in 0..N { s[l][i] = read_uniform(&mut r, span) as i64 - ETA; } }
    s
}
// Mask y uniform in [-GAMMA,GAMMA]^(L*N) from a per-signature seed `rho`. `rho` MUST be bound to the
// message+ring (see sign) so the same mask is never reused across two messages — nonce reuse would
// leak the secret via z-z'=(c-c')*s.
fn sample_mask(rho: &[u8], nonce: u32) -> PolyVecL {
    let mut y: PolyVecL = [poly_zero(); L];
    let mut r = xof(&[b"ccx-lring-y", rho, &nonce.to_le_bytes()]);
    let span = (2 * GAMMA + 1) as u32;
    for l in 0..L { for i in 0..N { y[l][i] = read_uniform(&mut r, span) as i64 - GAMMA; } }
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
#[allow(dead_code)] // documents the on-disk sk format (32-byte seed; s is re-derived from it)
pub const SK_SEED_BYTES: usize = 32;            // sk = 32-byte seed (s re-derived)
pub const TAG_BYTES: usize = K * N * 4;         // I
pub fn sig_bytes(n: usize) -> usize { 32 /*seed0*/ + TAG_BYTES + n * L * N * 4 }

pub fn keygen(seed32: &[u8; 32]) -> (Vec<u8>, PolyVecL, PolyVecK) {
    let s = sample_secret(seed32);
    let t = mat_vec_ntt(matrix_a_ntt(), &s);
    let mut pk = Vec::with_capacity(PK_BYTES);
    put_veck(&mut pk, &t);
    (pk, s, t)
}
pub fn tag(s: &PolyVecL) -> PolyVecK { mat_vec_ntt(matrix_a2_ntt(), s) }
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
    let a = matrix_a_ntt();
    let a2 = matrix_a2_ntt();
    let s = sample_secret(sk_seed);
    let i_tag = tag(&s);
    let mut tag_bytes = Vec::new(); put_veck(&mut tag_bytes, &i_tag);
    // ring blob for hashing = all pubkeys concatenated
    let mut ring_blob = Vec::new(); for p in ring_pks { ring_blob.extend_from_slice(p); }
    // decode each member's t (length + canonical-encoding validated) and pre-transform t_i + the tag I
    // to NTT domain once (fixed across attempts and branches) so c*t_i / c*I only forward-transform c
    // in the inner loop. A malformed/non-canonical ring member aborts signing (None).
    let mut t_ntt: Vec<NttVecK> = Vec::with_capacity(n);
    for p in ring_pks { let t = decode_ring_member(p)?; t_ntt.push(veck_to_ntt(&t)); }
    let i_tag_ntt = veck_to_ntt(&i_tag);

    for attempt in 0..256u32 {
        // Per-signature randomness bound to (secret, message, ring, attempt): makes the mask unique
        // per message (no nonce reuse) and the decoys independent of any single input.
        let mut rho = [0u8; 32];
        { let mut rr = xof(&[b"ccx-lring-rho", sk_seed, msg, &ring_blob, &attempt.to_le_bytes()]); rr.read(&mut rho); }
        let mut z: Vec<PolyVecL> = vec![[poly_zero(); L]; n];
        // real branch commit
        let y = sample_mask(&rho, 0);
        let (w_j, w2_j) = mat_vec2_ntt(a, a2, &y);
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
            let zi = sample_mask_bounded(&rho, 0, i as u32);
            z[i] = zi;
            // w_i = A*z_i - c*t_i ; w2_i = A2*z_i - c*I
            let (azi, a2zi) = mat_vec2_ntt(a, a2, &z[i]);
            let cti = veck_scale_ntt(&c, &t_ntt[i]);
            let w_i = veck_sub(&azi, &cti);
            let cii = veck_scale_ntt(&c, &i_tag_ntt);
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
            let mut out = Vec::with_capacity(sig_bytes(n));
            out.extend_from_slice(&seeds[0]);
            put_veck(&mut out, &i_tag);
            for zi in &z { put_vecl(&mut out, zi); }
            return Some(out);
        }
    }
    None
}

// Simulated (decoy) response z_i: UNBIASED uniform in [-ZBOUND, ZBOUND], from a per-signature seed.
// Matches the distribution of an accepted real z_j (uniform on the same range after rejection), so
// the verifier cannot distinguish the real branch from the decoys.
fn sample_mask_bounded(rho: &[u8], attempt: u32, idx: u32) -> PolyVecL {
    let mut y: PolyVecL = [poly_zero(); L];
    let mut r = xof(&[b"ccx-lring-zsim", rho, &attempt.to_le_bytes(), &idx.to_le_bytes()]);
    let span = (2 * ZBOUND + 1) as u32;
    for l in 0..L { for i in 0..N { y[l][i] = read_uniform(&mut r, span) as i64 - ZBOUND; } }
    y
}

/// Verify: recompute the ring chain; accept iff it closes (seed_n == seed_0) and all z_i are short.
/// On success, returns the tag I bytes (for the caller to hash into a 32-byte nullifier).
pub fn verify(msg: &[u8], ring_pks: &[Vec<u8>], sig: &[u8]) -> Option<Vec<u8>> {
    let n = ring_pks.len();
    if n == 0 { return None; } // an empty ring would close trivially (no branch to check)
    if sig.len() != sig_bytes(n) { return None; }
    let a = matrix_a_ntt();
    let a2 = matrix_a2_ntt();
    let mut off = 0usize;
    let mut seed0 = [0u8; 32]; seed0.copy_from_slice(&sig[off..off + 32]); off += 32;
    let i_tag = get_veck(sig, &mut off);
    // The tag I must be CANONICALLY encoded: otherwise a malicious signer could keep the same algebraic
    // tag (mod q) while changing the serialized bytes -> a DIFFERENT nullifier for the SAME output, a
    // double-spend linkability break. Reject any non-canonical tag before it is hashed.
    if !veck_is_canonical(&i_tag) { return None; }
    let mut tag_bytes = Vec::new(); put_veck(&mut tag_bytes, &i_tag);
    let mut z: Vec<PolyVecL> = Vec::with_capacity(n);
    for _ in 0..n {
        let zi = get_vecl(sig, &mut off);
        // Responses must also be canonical (defence in depth; the ZBOUND check below already bounds
        // |z|, and ZBOUND < q/2, so a non-canonical z would also fail the norm test — but be explicit).
        if !vecl_is_canonical(&zi) { return None; }
        z.push(zi);
    }
    // Validate EVERY ring member's length + canonical encoding BEFORE building the hashed ring_blob or
    // decoding t. A short Vec would panic get_veck (DoS); a non-canonical t_i would land differently in
    // ring_blob so honest nodes hash divergent seeds (consensus split). Reject the whole verify on any.
    let mut ring_blob = Vec::new();
    let mut t_ntt: Vec<NttVecK> = Vec::with_capacity(n);
    for p in ring_pks {
        let t = decode_ring_member(p)?;        // length + canonical check
        ring_blob.extend_from_slice(p);
        t_ntt.push(veck_to_ntt(&t));
    }
    let i_tag_ntt = veck_to_ntt(&i_tag);

    // walk the whole ring starting from seed0 at index 0
    let mut seed = seed0;
    for i in 0..n {
        if vecl_inf_norm(&z[i]) > ZBOUND { return None; }
        let c = sample_challenge(&seed);
        let (azi, a2zi) = mat_vec2_ntt(a, a2, &z[i]);
        let cti = veck_scale_ntt(&c, &t_ntt[i]);
        let w_i = veck_sub(&azi, &cti);
        let cii = veck_scale_ntt(&c, &i_tag_ntt);
        let w2_i = veck_sub(&a2zi, &cii);
        let nx = (i + 1) % n;
        seed = hash_seed(msg, &ring_blob, &tag_bytes, &w_i, &w2_i, nx);
    }
    if seed == seed0 { Some(tag_bytes) } else { None }
}

/// Adversarial test of the security review's CRITICAL claim ("simulate all branches with no secret,
/// walk the chain forward, publish seed0 := seed_n -> ring closes for any ring and any I").
/// Returns true iff the forged signature VERIFIES (i.e. the scheme is universally forgeable).
pub fn forge_no_secret(msg: &[u8], ring_pks: &[Vec<u8>]) -> bool {
    let n = ring_pks.len();
    let a = matrix_a_ntt();
    let a2 = matrix_a2_ntt();
    let mut t_list: Vec<PolyVecK> = Vec::with_capacity(n);
    for p in ring_pks { let mut o = 0; t_list.push(get_veck(p, &mut o)); }

    // Forger's free choices: random in-range z_i and an arbitrary tag I (no secret used).
    let mut z: Vec<PolyVecL> = Vec::with_capacity(n);
    for i in 0..n { z.push(sample_mask_bounded(b"forge-z", 7, i as u32)); }
    let mut i_tag: PolyVecK = [poly_zero(); K];
    { let mut r = xof(&[b"forge-I"]); for k in 0..K { for j in 0..N { i_tag[k][j] = cmod(read_u32(&mut r) as i64); } } }
    let mut tag_bytes = Vec::new(); put_veck(&mut tag_bytes, &i_tag);
    let mut ring_blob = Vec::new(); for p in ring_pks { ring_blob.extend_from_slice(p); }

    // Walk the chain forward from an arbitrary start, then publish seed0 := seed_n (the exact attack).
    let mut seed = [0u8; 32];
    for i in 0..n {
        let c = sample_challenge(&seed);
        let w = veck_sub(&mat_vec_ntt(a, &z[i]), &veck_scale(&c, &t_list[i]));
        let w2 = veck_sub(&mat_vec_ntt(a2, &z[i]), &veck_scale(&c, &i_tag));
        let nx = (i + 1) % n;
        seed = hash_seed(msg, &ring_blob, &tag_bytes, &w, &w2, nx);
    }
    let seed0 = seed;

    let mut sig = Vec::new();
    sig.extend_from_slice(&seed0);
    put_veck(&mut sig, &i_tag);
    for zi in &z { put_vecl(&mut sig, zi); }
    verify(msg, ring_pks, &sig).is_some()
}

// ---- Extended adversarial soundness vectors (Task 2a re-verification) --------------------------
// Each helper returns true iff the attack is CORRECTLY REJECTED by verify(). `adversarial_soundness_ok`
// ANDs them all, so a true result means every modelled forgery/malleation failed to verify. These are
// HEURISTIC empirical checks of the AOS/CDS soundness argument (random-oracle unforgeability), NOT a
// proof and NOT a substitute for a professional audit — see docs/design/quantum-resistance/
// ringsig-hardening.md for the soundness reasoning and the remaining audit gate.

// 1) Chosen-tag forgery: take a VALID signature, splice in an attacker-chosen tag I (here: all-zero,
//    the degenerate nullifier a double-spender would want). The tag is hashed into every branch's
//    seed, so swapping it desynchronises the chain -> must reject. Proves the published nullifier is
//    bound to the proof, not free.
fn forge_chosen_tag_rejected(msg: &[u8], ring_pks: &[Vec<u8>], signer: usize, sk_seed: &[u8; 32]) -> bool {
    let sig = match sign(msg, ring_pks, signer, sk_seed) { Some(s) => s, None => return true };
    let mut bad = sig.clone();
    // zero out the TAG region: bytes [32 .. 32+TAG_BYTES)
    for b in bad[32..32 + TAG_BYTES].iter_mut() { *b = 0; }
    verify(msg, ring_pks, &bad).is_none()
}

// 2) Non-member ring forgery: sign with a real, well-formed secret whose public t is NOT one of the
//    ring members, then try to verify against that ring. The real branch's c*t must match a ring
//    member's t for the chain to close; an outsider's t does not -> must reject. (Two variants: a
//    fresh outsider signing "into" the ring, and verifying a valid signature against a DIFFERENT ring.)
fn forge_non_member_rejected(msg: &[u8], ring_pks: &[Vec<u8>]) -> bool {
    // outsider secret, claims to be member `0`
    let outsider_seed = [0x77u8; 32];
    let outsider_ok = match sign(msg, ring_pks, 0, &outsider_seed) {
        Some(s) => verify(msg, ring_pks, &s).is_none(),
        None => true,
    };
    // a valid signature for ring R must NOT verify against a different ring R'
    let mut seeds: Vec<[u8; 32]> = Vec::new();
    let mut ring2: Vec<Vec<u8>> = Vec::new();
    for i in 0..ring_pks.len() { let mut sd = [0u8; 32]; sd[0] = 0x90 ^ i as u8; sd[1] = 0xef; let (pk, _s, _t) = keygen(&sd); ring2.push(pk); seeds.push(sd); }
    let cross_ring_ok = match sign(msg, &ring2, 1, &seeds[1]) {
        Some(s) => verify(msg, ring_pks, &s).is_none(), // verify R' sig against R
        None => true,
    };
    outsider_ok && cross_ring_ok
}

// 3) Malleation: a valid signature must not be maulable into a DIFFERENT accepting signature by
//    tweaking any field. Flip one byte in (a) seed0, (b) a z_i response, (c) the tag, and confirm
//    every mutant is rejected. (Bit-level integrity of the whole serialized signature.)
fn malleation_rejected(msg: &[u8], ring_pks: &[Vec<u8>], signer: usize, sk_seed: &[u8; 32]) -> bool {
    let sig = match sign(msg, ring_pks, signer, sk_seed) { Some(s) => s, None => return true };
    let n = ring_pks.len();
    let probes = [
        0usize,                       // seed0 region
        32 + TAG_BYTES + 4,           // inside z_0
        32 + 4,                       // inside the tag
        sig.len() - 1,                // last z byte
        32 + TAG_BYTES + (n - 1) * L * N * 4 + 8, // inside z_{n-1}
    ];
    for &p in probes.iter() {
        if p >= sig.len() { continue; }
        let mut bad = sig.clone();
        bad[p] ^= 0xff;
        if verify(msg, ring_pks, &bad).is_some() { return false; } // a mutant verified -> malleable
    }
    // also: re-ordering z responses (swap z_0 and z_1) must break the chain
    if n >= 2 {
        let mut bad = sig.clone();
        let z0 = 32 + TAG_BYTES;
        let z1 = 32 + TAG_BYTES + L * N * 4;
        let zlen = L * N * 4;
        let (a_slice, b_slice) = bad[z0..z1 + zlen].split_at_mut(zlen);
        a_slice.swap_with_slice(&mut b_slice[..zlen]);
        if verify(msg, ring_pks, &bad).is_some() { return false; }
    }
    true
}

// 4) Non-canonical malleability (codex review finding): take a VALID signature and offset ONE
//    coefficient by a multiple of q. The algebraic value (mod q) is unchanged, so without a
//    canonical-encoding check the arithmetic would still accept — but the serialized bytes (hence the
//    nullifier, for the tag) differ, letting a malicious signer spend the SAME output twice under two
//    nullifiers. verify() MUST reject every non-canonical encoding. Probes several offsets (+q, -q,
//    +2q) and several positions (tag coeff 0, a mid-tag coeff, z_0 coeff 0, and the last z coeff).
fn forge_noncanonical_tag_rejected(msg: &[u8], ring_pks: &[Vec<u8>], signer: usize, sk_seed: &[u8; 32]) -> bool {
    let sig = match sign(msg, ring_pks, signer, sk_seed) { Some(s) => s, None => return true };
    let n = ring_pks.len();
    // the honest signature must verify and yield a baseline nullifier tag
    let base = match verify(msg, ring_pks, &sig) { Some(t) => t, None => return false };
    if base.is_empty() { return false; }

    // byte offsets of the i32 coefficients we attack
    let tag0 = 32;                                 // tag I, coeff 0
    let tag_mid = (32 + TAG_BYTES / 2) & !3usize;  // tag I, a mid coeff (4-byte aligned)
    let z0 = 32 + TAG_BYTES;                        // z_0, coeff 0
    let z_last = 32 + TAG_BYTES + (n * L * N - 1) * 4; // z_{n-1}, last coeff
    let positions = [tag0, tag_mid, z0, z_last];
    let offsets: [i64; 3] = [Q, -Q, 2 * Q];        // same residue mod q, non-canonical bytes

    for &pos in positions.iter() {
        if pos + 4 > sig.len() { continue; }
        for &delta in offsets.iter() {
            let mut bad = sig.clone();
            let c = i32::from_le_bytes([bad[pos], bad[pos+1], bad[pos+2], bad[pos+3]]) as i64;
            let mutated = (c + delta) as i32; // wraps in i32 but the BYTES are a valid non-canonical i32
            bad[pos..pos+4].copy_from_slice(&mutated.to_le_bytes());
            // only count it as a real attack if the bytes actually changed AND the new coeff is
            // non-canonical (c+delta could land back in range for some edge cases — skip those)
            if bad[pos..pos+4] == sig[pos..pos+4] { continue; }
            if coeff_is_canonical(mutated as i64) { continue; }
            if verify(msg, ring_pks, &bad).is_some() { return false; } // accepted a non-canonical sig!
        }
    }
    true
}

/// Runs every extended adversarial vector against a fresh ring at the given size and returns true iff
/// ALL are correctly rejected and an honest signature still verifies. HEURISTIC, not an audit.
fn adversarial_soundness_ok_for_ring(n: usize) -> bool {
    let mut ring: Vec<Vec<u8>> = Vec::new();
    let mut seeds: Vec<[u8; 32]> = Vec::new();
    for i in 0..n { let mut sd = [0u8; 32]; sd[0] = i as u8; sd[1] = 0x5a; sd[2] = 0xa5; sd[3] = n as u8; let (pk, _s, _t) = keygen(&sd); ring.push(pk); seeds.push(sd); }
    let msg = b"ccx-lring-adversarial";
    let signer = if n > 1 { 1usize } else { 0usize };

    // the existing no-secret universal-forgery attack (review's CRITICAL) must still fail
    let no_secret = !forge_no_secret(msg, &ring);
    let chosen_tag = forge_chosen_tag_rejected(msg, &ring, signer, &seeds[signer]);
    let non_member = forge_non_member_rejected(msg, &ring);
    let malleation = malleation_rejected(msg, &ring, signer, &seeds[signer]);
    let noncanonical = forge_noncanonical_tag_rejected(msg, &ring, signer, &seeds[signer]);
    // a non-canonical RING-MEMBER key must be rejected (consensus-split / key-aliasing root cause):
    // offset member 0's first coeff by +q (same algebraic t, different bytes) -> verify must reject.
    let ring_member_noncanonical = {
        let sig = match sign(msg, &ring, signer, &seeds[signer]) { Some(s) => s, None => return false };
        let mut bad_ring = ring.clone();
        let c0 = i32::from_le_bytes([bad_ring[0][0], bad_ring[0][1], bad_ring[0][2], bad_ring[0][3]]) as i64;
        let m = (c0 + Q) as i32;
        bad_ring[0][0..4].copy_from_slice(&m.to_le_bytes());
        // honest sig verifies against the canonical ring but NOT against the mutated (non-canonical) ring
        verify(msg, &ring, &sig).is_some() && verify(msg, &bad_ring, &sig).is_none()
    };
    // sanity: an HONEST signature still verifies (we are not rejecting everything trivially)
    let honest_ok = match sign(msg, &ring, signer, &seeds[signer]) { Some(s) => verify(msg, &ring, &s).is_some(), None => false };

    no_secret && chosen_tag && non_member && malleation && noncanonical && ring_member_noncanonical && honest_ok
}

/// Runs the adversarial soundness vectors across ring sizes 2, 4, 8 (plus the empty-ring rejection),
/// returning true iff ALL pass. HEURISTIC, not an audit.
pub fn adversarial_soundness_ok() -> bool {
    // empty ring must not verify (a 0-branch chain closes trivially)
    let empty_ring_rejected = verify(b"x", &[], &vec![0u8; sig_bytes(0)]).is_none();
    empty_ring_rejected
        && adversarial_soundness_ok_for_ring(2)
        && adversarial_soundness_ok_for_ring(4)
        && adversarial_soundness_ok_for_ring(8)
}

// ============================== TESTS ==========================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // --- Reference (OLD, division/branch-based) reductions, kept here ONLY as the equivalence oracle.
    // The constant-time rewrite in the module above MUST reproduce these bit-for-bit over every input
    // range the scheme uses, which is the whole bit-identicality claim.
    fn cmod_ref(a: i64) -> i64 { let mut r = a % Q; if r > Q / 2 { r -= Q; } if r < -Q / 2 { r += Q; } r }
    fn pmod_ref(a: i64) -> i64 { let mut r = a % Q; if r < 0 { r += Q; } r }
    fn addq_ref(a: i64) -> i64 { if a >= Q { a - Q } else { a } }
    fn subq_ref(a: i64) -> i64 { if a < 0 { a + Q } else { a } }
    fn mulmod_ref(a: i64, b: i64) -> i64 { (a * b) % Q }

    // small deterministic xorshift PRNG (no rand dependency)
    struct Rng(u64);
    impl Rng { fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x } }

    #[test]
    fn addq_subq_constant_time_bit_identical() {
        // addq is called on sums in [0, 2Q); subq on diffs in (-Q, Q). Cover both ranges exhaustively.
        for a in 0..(2 * Q) { assert_eq!(addq(a), addq_ref(a), "addq({})", a); }
        for a in -(Q - 1)..Q { assert_eq!(subq(a), subq_ref(a), "subq({})", a); }
    }

    #[test]
    fn mulmod_barrett_bit_identical() {
        // mulmod is only ever called with both operands in [0, Q). Edges + random pairs.
        let edges = [0i64, 1, 2, (Q - 1) / 2, (Q - 1) / 2 + 1, Q - 2, Q - 1];
        for &a in edges.iter() { for &b in edges.iter() { assert_eq!(mulmod(a, b), mulmod_ref(a, b), "mulmod({},{})", a, b); } }
        let mut r = Rng(0x9e3779b97f4a7c15);
        for _ in 0..2_000_000u64 {
            let a = (r.next() % Q as u64) as i64;
            let b = (r.next() % Q as u64) as i64;
            assert_eq!(mulmod(a, b), mulmod_ref(a, b), "mulmod({},{})", a, b);
        }
    }

    #[test]
    fn cmod_pmod_constant_time_bit_identical() {
        // cmod/pmod see: centered-coeff sums/diffs in (-Q,Q), intt outputs in [0,Q), and the FULL
        // i32/u32 adversarial ranges (coeff_is_canonical on deserialized i32, forge cmod(read_u32)).
        // Prove bit-identicality densely around 0 and ±multiples of Q, at the i32/u32 edges, and over
        // random i32/u32/i64 — i.e. everywhere the functions can be reached.
        for a in -(5 * Q)..=(5 * Q) {
            assert_eq!(pmod(a), pmod_ref(a), "pmod({})", a);
            assert_eq!(cmod(a), cmod_ref(a), "cmod({})", a);
        }
        let edges: [i64; 20] = [
            i32::MIN as i64, i32::MAX as i64, (i32::MIN as i64) + 1, (i32::MAX as i64) - 1,
            u32::MAX as i64, 0, 1, -1, Q, -Q, Q - 1, -(Q - 1), Q / 2, Q / 2 + 1, -(Q / 2), -(Q / 2) - 1,
            // i64 extremes: NOT reachable by any call site (inputs are i32/u32-bounded), but the
            // reduction is correct over the FULL i64 range (wrapping qf*Q is exact in two's complement),
            // so pin that here too — belt-and-suspenders against any future wider caller.
            i64::MIN, i64::MAX, i64::MIN + 1, i64::MAX - 1,
        ];
        for &a in edges.iter() {
            assert_eq!(pmod(a), pmod_ref(a), "pmod edge {}", a);
            assert_eq!(cmod(a), cmod_ref(a), "cmod edge {}", a);
        }
        let mut r = Rng(0x123456789abcdef0);
        for _ in 0..2_000_000u64 {
            let v = r.next();
            for &a in &[v as i64, (v as u32) as i64, (v as i32) as i64] {
                assert_eq!(pmod(a), pmod_ref(a), "pmod rand {}", a);
                assert_eq!(cmod(a), cmod_ref(a), "cmod rand {}", a);
            }
        }
    }

    // End-to-end bit-identicality of the transform after the constant-time rewrite. Must be 0.
    #[test]
    fn ntt_equivalence_zero_mismatches() {
        assert_eq!(ntt_matches_schoolbook(5000), 0, "NTT must stay bit-identical to schoolbook");
    }

    // Full adversarial soundness suite must still pass after the rewrite.
    #[test]
    fn soundness_still_holds() { assert!(adversarial_soundness_ok()); }

    // Timing harness (Task 4): median sign + verify for a ring of 4. `cargo test -- --nocapture`
    // prints the numbers. This measures the CURRENT (constant-time) build; the BEFORE figure is taken
    // by running this same harness against the pre-rewrite commit (see ringsig-hardening.md §5).
    #[test]
    fn timing_ring4_sign_verify() {
        const RING: usize = 4;
        let mut ring: Vec<Vec<u8>> = Vec::new();
        let mut seeds: Vec<[u8; 32]> = Vec::new();
        for i in 0..RING { let mut sd = [0u8; 32]; sd[0] = i as u8; sd[1] = 0x11; let (pk, _s, _t) = keygen(&sd); ring.push(pk); seeds.push(sd); }
        let msg = b"ccx-lring-timing";
        let signer = 1usize;

        // warm up the OnceLock matrix caches so we time steady-state sign/verify, not first-call setup.
        let warm = sign(msg, &ring, signer, &seeds[signer]).expect("warmup sign");
        assert!(verify(msg, &ring, &warm).is_some());

        let iters = 200u32;
        let mut sign_ns: Vec<u128> = Vec::with_capacity(iters as usize);
        let mut verify_ns: Vec<u128> = Vec::with_capacity(iters as usize);
        for k in 0..iters {
            // vary the message so each sign does fresh work (still ring-of-4)
            let mut m = msg.to_vec(); m.extend_from_slice(&k.to_le_bytes());
            let t0 = Instant::now();
            let sig = sign(&m, &ring, signer, &seeds[signer]).expect("sign");
            sign_ns.push(t0.elapsed().as_nanos());
            let t1 = Instant::now();
            let ok = verify(&m, &ring, &sig).is_some();
            verify_ns.push(t1.elapsed().as_nanos());
            assert!(ok);
        }
        sign_ns.sort_unstable();
        verify_ns.sort_unstable();
        let med = |v: &Vec<u128>| v[v.len() / 2] as f64 / 1.0e6;
        let mean = |v: &Vec<u128>| v.iter().sum::<u128>() as f64 / v.len() as f64 / 1.0e6;
        println!(
            "RING-4 TIMING: sign median={:.3} ms mean={:.3} ms | verify median={:.3} ms mean={:.3} ms | iters={}",
            med(&sign_ns), mean(&sign_ns), med(&verify_ns), mean(&verify_ns), iters
        );
    }
}
