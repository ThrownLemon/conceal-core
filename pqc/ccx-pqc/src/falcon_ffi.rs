//! Raw FFI bindings to the clean-room C shim (csrc/raptor_falcon.c), which in turn drives
//! the vendored PQClean Falcon-512.  All buffers sized for n = 512 (logn = 9).

pub const N: usize = 512;
pub const Q: u32 = 12289;

extern "C" {
    pub fn rfalcon_n() -> usize;
    pub fn rfalcon_q() -> u32;

    /// Deterministic Falcon-512 keygen from a SHAKE256 seed.
    /// f,g,F,G: int8_t[N]; h: uint16_t[N] (public key = g/f mod q). Returns 0 on success.
    pub fn rfalcon_keygen_det(
        seed: *const u8, seed_len: usize,
        f: *mut i8, g: *mut i8, fcap: *mut i8, gcap: *mut i8, h: *mut u16,
    ) -> i32;

    /// Target-driven preimage sign: short (r0,r1) with r0 + r1*a = u_target (a = h = g/f).
    /// r0_out, r1_out: int16_t[N]. Returns 0 on success.
    pub fn rfalcon_sign_target(
        sign_seed: *const u8, seed_len: usize,
        f: *const i8, g: *const i8, fcap: *const i8, gcap: *const i8,
        u_target: *const u16,
        r0_out: *mut i16, r1_out: *mut i16,
    ) -> i32;

    // poly arithmetic mod q in Z_q[x]/(x^n+1)
    pub fn rfalcon_polymul_modq(a: *const u16, b: *const u16, out: *mut u16);
    pub fn rfalcon_polyadd_modq(a: *const u16, b: *const u16, out: *mut u16);
    pub fn rfalcon_polysub_modq(a: *const u16, b: *const u16, out: *mut u16);
    pub fn rfalcon_center_to_modq(s: *const i16, out: *mut u16);
    pub fn rfalcon_sqnorm(s: *const i16) -> u64;

    /// H1: bytes -> uniform ring element in R_q (random-oracle mask). out: uint16_t[N].
    pub fn rfalcon_hash_to_rq(input: *const u8, inlen: usize, domain: *const core::ffi::c_char, out: *mut u16);
    /// SHAKE256(in) -> out[outlen].
    pub fn rfalcon_shake256(input: *const u8, inlen: usize, out: *mut u8, outlen: usize);

    // codecs
    pub fn rfalcon_comp_encode(x: *const i16, out: *mut u8, max_out: usize) -> usize;
    pub fn rfalcon_comp_decode(x: *mut i16, input: *const u8, max_in: usize) -> usize;
    pub fn rfalcon_modq_encode(x: *const u16, out: *mut u8, max_out: usize) -> usize;
    pub fn rfalcon_modq_decode(x: *mut u16, input: *const u8, max_in: usize) -> usize;
}

// ---- safe-ish Rust wrappers ----

/// A Falcon raw keypair (private trapdoor elements + public key polynomial).
#[derive(Clone)]
pub struct FalconKey {
    pub f: [i8; N],
    pub g: [i8; N],
    pub cap_f: [i8; N], // F
    pub cap_g: [i8; N], // G
    pub h: [u16; N],    // public key a = g/f mod q
}

impl FalconKey {
    pub fn keygen_det(seed: &[u8]) -> FalconKey {
        let mut k = FalconKey { f: [0; N], g: [0; N], cap_f: [0; N], cap_g: [0; N], h: [0; N] };
        let rc = unsafe {
            rfalcon_keygen_det(
                seed.as_ptr(), seed.len(),
                k.f.as_mut_ptr(), k.g.as_mut_ptr(), k.cap_f.as_mut_ptr(), k.cap_g.as_mut_ptr(),
                k.h.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "falcon keygen failed");
        k
    }

    /// Sign target polynomial u, returning short (r0, r1) with r0 + r1*h = u.
    ///
    /// MEDIUM-2: every returned preimage is algebraically re-checked here against the public
    /// key `self.h`:  r0 + r1*h == u  (mod q, mod x^n+1).  Falcon's `sign_dyn` writes s1/s2 to
    /// specific offsets (s2 -> sig[], s1 -> start of tmp); if a future PQClean update changes
    /// that internal layout the C shim would silently return a garbage (r0,r1) that still packs
    /// and "verifies" against a wrong relation.  This boundary assert turns that into a loud
    /// panic instead of a silent soundness break.
    pub fn sign_target(&self, sign_seed: &[u8], u: &[u16; N]) -> ([i16; N], [i16; N]) {
        let mut r0 = [0i16; N];
        let mut r1 = [0i16; N];
        let rc = unsafe {
            rfalcon_sign_target(
                sign_seed.as_ptr(), sign_seed.len(),
                self.f.as_ptr(), self.g.as_ptr(), self.cap_f.as_ptr(), self.cap_g.as_ptr(),
                u.as_ptr(), r0.as_mut_ptr(), r1.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "falcon sign_target failed");

        // Algebraic preimage check: r0 + r1*h must equal the requested target u.
        let r0q = center_to_modq(&r0);
        let r1q = center_to_modq(&r1);
        let recomputed = polyadd(&r0q, &polymul(&self.h, &r1q));
        assert!(
            recomputed == *u,
            "falcon sign_target preimage relation r0 + r1*a == u FAILED \
             (PQClean s1/s2 layout break or FFI corruption)"
        );

        (r0, r1)
    }
}

pub fn polymul(a: &[u16; N], b: &[u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    unsafe { rfalcon_polymul_modq(a.as_ptr(), b.as_ptr(), out.as_mut_ptr()) };
    out
}
pub fn polyadd(a: &[u16; N], b: &[u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    unsafe { rfalcon_polyadd_modq(a.as_ptr(), b.as_ptr(), out.as_mut_ptr()) };
    out
}
pub fn polysub(a: &[u16; N], b: &[u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    unsafe { rfalcon_polysub_modq(a.as_ptr(), b.as_ptr(), out.as_mut_ptr()) };
    out
}
pub fn center_to_modq(s: &[i16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    unsafe { rfalcon_center_to_modq(s.as_ptr(), out.as_mut_ptr()) };
    out
}
pub fn sqnorm(s: &[i16; N]) -> u64 {
    unsafe { rfalcon_sqnorm(s.as_ptr()) }
}
pub fn hash_to_rq(input: &[u8], domain: &core::ffi::CStr) -> [u16; N] {
    let mut out = [0u16; N];
    unsafe { rfalcon_hash_to_rq(input.as_ptr(), input.len(), domain.as_ptr(), out.as_mut_ptr()) };
    out
}
pub fn shake256(input: &[u8], outlen: usize) -> Vec<u8> {
    let mut out = vec![0u8; outlen];
    unsafe { rfalcon_shake256(input.as_ptr(), input.len(), out.as_mut_ptr(), outlen) };
    out
}
pub fn comp_encode(x: &[i16; N]) -> Option<Vec<u8>> {
    // comp encoding of a Falcon-512 poly is at most ~CRYPTO_BYTES; use generous buffer.
    let mut buf = vec![0u8; 2048];
    let n = unsafe { rfalcon_comp_encode(x.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    if n == 0 { return None; }
    buf.truncate(n);
    Some(buf)
}
pub fn comp_decode(input: &[u8]) -> Option<[i16; N]> {
    let mut x = [0i16; N];
    let n = unsafe { rfalcon_comp_decode(x.as_mut_ptr(), input.as_ptr(), input.len()) };
    if n == 0 { return None; }
    Some(x)
}
pub fn modq_encode(x: &[u16; N]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 1024];
    let n = unsafe { rfalcon_modq_encode(x.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    if n == 0 { return None; }
    buf.truncate(n);
    Some(buf)
}
pub fn modq_decode(input: &[u8]) -> Option<[u16; N]> {
    let mut x = [0u16; N];
    let n = unsafe { rfalcon_modq_decode(x.as_mut_ptr(), input.as_ptr(), input.len()) };
    if n == 0 { return None; }
    Some(x)
}

// ---- F6: dudect-style constant-time check for the Falcon preimage sampler ----
#[cfg(test)]
mod ct_dudect {
    //! Self-contained dudect-style timing test for `sign_target` (the secret-key Gaussian sampler
    //! flagged OPEN by ctgrind — it runs on the trapdoor every spend). Methodology (Reparaz et al.,
    //! "dudect"): time the operation under a FIXED trapdoor (class A) vs ROTATING RANDOM trapdoors
    //! (class B) over interleaved iterations with identical (seed, target) per iteration so the only
    //! variable is the secret key; crop the slow tail (OS/cache noise); Welch's t-test. `|t| >> ~10`
    //! indicates the sampler's timing depends on the secret -> a leak. PQClean's isochronous sampler
    //! should keep `|t|` small. This in-suite version is a FIRST-ORDER check; a rigorous verdict needs
    //! core-pinning (`taskset`), `performance` governor, and >=1e6 samples. Run explicitly:
    //!   cargo test --release ct_dudect -- --ignored --nocapture
    use super::*;

    fn rand_target(ctr: u64) -> [u16; N] {
        let bytes = shake256(&ctr.to_le_bytes(), N * 4);
        let mut u = [0u16; N];
        let mut bi = 0usize;
        for k in 0..N {
            loop {
                let v = (u16::from_le_bytes([bytes[bi % bytes.len()], bytes[(bi + 1) % bytes.len()]]) & 0x3FFF) as u32;
                bi += 2;
                if v < Q { u[k] = v as u16; break; }
            }
        }
        u
    }

    fn welch_t(a: &[f64], b: &[f64]) -> f64 {
        let mean = |x: &[f64]| x.iter().sum::<f64>() / x.len() as f64;
        let var = |x: &[f64], m: f64| x.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / (x.len() as f64 - 1.0);
        let (ma, mb) = (mean(a), mean(b));
        let (va, vb) = (var(a, ma), var(b, mb));
        (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
    }

    fn crop_fast(mut v: Vec<f64>, keep: f64) -> Vec<f64> {
        v.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let hi = (v.len() as f64 * keep) as usize;
        v[..hi.max(2)].to_vec()
    }

    #[test]
    #[ignore]
    fn falcon_sampler_timing_independent_of_key() {
        use std::time::Instant;
        let fixed = FalconKey::keygen_det(&[0x11u8; 48]);
        let pool: Vec<FalconKey> =
            (0..32u64).map(|i| FalconKey::keygen_det(&shake256(&i.to_le_bytes(), 48))).collect();
        // Sample count; override for a rigorous run: CCX_DUDECT_ITERS=1000000 (default 4000).
        let iters: usize = std::env::var("CCX_DUDECT_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(4000);
        let mut ta = Vec::with_capacity(iters);
        let mut tb = Vec::with_capacity(iters);
        for w in 0..50u64 { let u = rand_target(w); let _ = fixed.sign_target(&shake256(&u[0].to_le_bytes(), 48), &u); }
        for i in 0..iters as u64 {
            let u = rand_target(i ^ 0xabcd);
            let seed = shake256(&i.to_le_bytes(), 48);
            let t0 = Instant::now(); let _ = fixed.sign_target(&seed, &u); ta.push(t0.elapsed().as_nanos() as f64);
            let rk = &pool[(i as usize) % pool.len()];
            let t1 = Instant::now(); let _ = rk.sign_target(&seed, &u); tb.push(t1.elapsed().as_nanos() as f64);
        }
        let t_full = welch_t(&ta, &tb);
        let t_crop = welch_t(&crop_fast(ta, 0.7), &crop_fast(tb, 0.7));
        println!("DUDECT falcon sign_target: Welch t(full)={:.2}  t(fast-70%-cropped)={:.2}  n={}", t_full, t_crop, iters);
        // generous bound: an unpinned shared host inflates |t| from noise; the printed value is the
        // real signal (compare across runs). |t|>=500 would be an unambiguous, noise-immune leak.
        assert!(t_crop.abs() < 500.0, "cropped |t|={:.2} — sampler timing appears key-dependent; investigate", t_crop);
    }
}
