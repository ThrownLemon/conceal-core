//! Linkable Raptor ring signature (eprint 2018/857, §6.5), clean-room implementation.
//!
//! Construction (over Falcon-512, R_q = Z_q[x]/(x^n+1), n=512, q=12289):
//!
//!   System param: h  — a fixed public random polynomial in R_q (paramch / the CH+ hash key).
//!   Per signer (deterministic from a wallet seed):
//!     main keypair (a, f,g,F,G), a = g/f
//!     ots  keypair (aots, ...)            — the linking-tag keypair
//!     public key   a0 = a + H1(aots) mod q
//!     nullifier / linking tag = aots      (one unique tag per signer; binds via a0)
//!
//!   Sign(sk_pi, msg, ring={a0_1..a0_L}, signer_index pi):
//!     ai = a0_i - H1(aots)                 (so a_pi == signer's real main a)
//!     for i != pi:  b_i <- {0,1}^256 ;  (r0_i, r1_i) <- short Gaussian ;  c_i = r0_i + ai*r1_i + h*b_i
//!     for i == pi:  c_pi <- random in R_q
//!     b_pi = H(msg, c_1..c_L) XOR (XOR_{i!=pi} b_i)
//!     u_pi = c_pi - h*b_pi
//!     (r0_pi, r1_pi) = Falcon.sign_target(a_pi; u_pi)   s.t. r0_pi + r1_pi*a_pi = u_pi
//!     ots_sig = Falcon.sign(aots; ({r0_i,r1_i,b_i}, {a0_i}, aots))
//!     sigma = ({r0_i, r1_i, b_i}_{i=1..L}, aots, ots_sig)
//!
//!   Verify: recompute ai, c_i; check XOR relation, short-vector norm bounds, b_i in Db,
//!           and the ots signature over the transcript under aots.
//!   Link(sigma, sigma'): aots == aots'.
//!
//! NOTE: bit-strings b_i are 256-bit values reinterpreted as binary polynomials (bit j ->
//! coefficient j, for j<256, rest 0); combined by XOR; H maps the transcript to {0,1}^256.
//! This keeps every b_i (incl. b_pi) inside Db = {0,1}^256, matching the paper's verify check.

use crate::falcon_ffi as fc;
use crate::falcon_ffi::{FalconKey, N};
use core::ffi::CStr;
use rand::SeedableRng;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;

pub const NULLIFIER_BYTES: usize = 32; // we publish a 32-byte hash of aots as the on-chain tag

// domain separators for the SHAKE-based oracles
const DOM_H1: &CStr = c"RAPTOR-CCX-H1-mask";
const DOM_PARAMCH: &CStr = c"RAPTOR-CCX-paramch-h";
const DOM_KEY_MAIN: &[u8] = b"RAPTOR-CCX-key-main";
const DOM_KEY_OTS: &[u8] = b"RAPTOR-CCX-key-ots";
const DOM_H_TRANSCRIPT: &[u8] = b"RAPTOR-CCX-H-transcript";
const DOM_NULLIFIER: &[u8] = b"RAPTOR-CCX-nullifier";
const DOM_SIGN_RANDOM: &[u8] = b"RAPTOR-CCX-sign-rand";

/// Acceptance bound for short vectors.  Falcon-512 accepts signatures with squared norm
/// (||s1||^2 + ||s2||^2) <= floor(beta^2) where beta^2 = 34034726 for Falcon-512.  Here r0,r1
/// are the two halves; their combined squared norm must be within Falcon's bound.
pub const FALCON512_SQNORM_BOUND: u64 = 34_034_726;

/// The fixed public system parameter h = paramch (a random ring element), derived
/// deterministically from a public domain string so it is identical for all parties.
pub fn paramch_h() -> [u16; N] {
    fc::hash_to_rq(b"conceal-raptor-paramch-v0", DOM_PARAMCH)
}

/// Map a 256-bit value to a binary polynomial in R_q (bit j -> coeff j).
fn bits_to_poly(b: &[u8; 32]) -> [u16; N] {
    let mut p = [0u16; N];
    for j in 0..256 {
        let bit = (b[j / 8] >> (j % 8)) & 1;
        p[j] = bit as u16;
    }
    p
}

/// Explicit Db = {0,1}^256 membership check for a deserialized b_i (CRITICAL-2).
///
/// Today every `[u8;32]` trivially maps into Db (`bits_to_poly` reads exactly 256 bits, all of
/// which are {0,1}), so this is currently always true — BUT verify must not silently *rely* on
/// that `[u8;32]`-typing coincidence.  We check the invariant the construction actually needs —
/// the b_i polynomial has coefficients in {0,1} and degree < 256 — so that if the wire format
/// ever widens b_i (more bytes, a different poly packing) verify still rejects anything outside
/// Db instead of accepting a malformed b that happens to pass the byte-XOR check.
fn b_is_canonical(b: &[u8; 32]) -> bool {
    let p = bits_to_poly(b);
    // coeffs in {0,1}
    for j in 0..N {
        if p[j] > 1 { return false; }
    }
    // support confined to the low 256 positions
    for j in 256..N {
        if p[j] != 0 { return false; }
    }
    // round-trip: the polynomial's bits must reproduce the exact b_i bytes (no aliasing/padding).
    let mut re = [0u8; 32];
    for j in 0..256 {
        if p[j] == 1 { re[j / 8] |= 1 << (j % 8); }
    }
    &re == b
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 { o[i] = a[i] ^ b[i]; }
    o
}

/// A Raptor secret key: both Falcon trapdoors + the ots public key + the mask H1(aots).
#[derive(Clone)]
pub struct RaptorSecretKey {
    pub main: FalconKey,
    pub ots: FalconKey,
    pub mask: [u16; N],   // H1(aots)
    pub a0: [u16; N],     // public key
    pub aots: [u16; N],   // linking-tag public key
}

/// A Raptor public key is the masked hash key a0 (an R_q element).
#[derive(Clone)]
pub struct RaptorPublicKey {
    pub a0: [u16; N],
}

/// Deterministic key generation from a wallet seed.
pub fn keygen(seed: &[u8]) -> (RaptorPublicKey, RaptorSecretKey) {
    // Two independent Falcon keypairs, each seeded by a domain-separated SHAKE of the seed.
    let mut s_main = Vec::from(DOM_KEY_MAIN);
    s_main.extend_from_slice(seed);
    let mut s_ots = Vec::from(DOM_KEY_OTS);
    s_ots.extend_from_slice(seed);
    let main = FalconKey::keygen_det(&fc::shake256(&s_main, 48));
    let ots = FalconKey::keygen_det(&fc::shake256(&s_ots, 48));

    // a0 = a + H1(aots) mod q   (a = main.h, aots = ots.h)
    let aots = ots.h;
    let aots_enc = fc::modq_encode(&aots).expect("encode aots");
    let mask = fc::hash_to_rq(&aots_enc, DOM_H1);
    let a0 = fc::polyadd(&main.h, &mask);

    let sk = RaptorSecretKey { main: main.clone(), ots, mask, a0, aots };
    let pk = RaptorPublicKey { a0 };
    (pk, sk)
}

// ---- keygen-determinism KAT tripwire (HIGH-1) ----
//
// Falcon-512 keygen rejection-samples (f,g) and computes a = g/f using FLOATING-POINT FFT.  The
// rounding in that FP path is not guaranteed bit-identical across compilers / -march / libm, so
// the SAME wallet seed can yield a DIFFERENT (a0, aots) — hence a different nullifier and public
// key — on a different platform.  In a consensus setting that is a chain split / unspendable
// restore.  This KAT does NOT fix that (the real fix is an integer / emulated-FP Falcon keygen,
// a phase-2 consensus blocker); it DETECTS it: if this build's keygen drifts from the pinned
// reference, the tripwire fires loudly instead of silently producing incompatible keys.
//
// The pinned digest was produced on the spike's reference build (WSL x86_64, Ubuntu 24.04,
// rustc + gcc as vendored).  A mismatch means EITHER this platform's Falcon FP keygen differs
// (the hazard we are flagging) OR keygen/encoding was intentionally changed (re-pin then).

/// Domain-tagged fixed KAT seed (not a wallet key).
const KAT_SEED_INPUT: &[u8] = b"RAPTOR-CCX-KAT-seed-v0";

/// SHAKE256_32( modq(a0) || modq(aots) ) for keygen(KAT seed), pinned on the reference build.
const KAT_KEYGEN_DIGEST: [u8; 32] = [
    0x8f, 0x24, 0x5c, 0x82, 0xdc, 0x73, 0x90, 0xf3, 0xcb, 0x4d, 0x89, 0x55, 0x55, 0x6a, 0x45, 0xd5,
    0x6a, 0xf4, 0x1c, 0x83, 0xa3, 0x7f, 0xc0, 0x38, 0x8b, 0x99, 0x6b, 0x58, 0xf2, 0x95, 0x74, 0x5e,
];

/// Recompute the keygen KAT digest for this build.
pub fn keygen_kat_digest() -> [u8; 32] {
    let seed = fc::shake256(KAT_SEED_INPUT, 48);
    let (_pk, sk) = keygen(&seed);
    let mut buf = Vec::new();
    buf.extend_from_slice(&fc::modq_encode(&sk.a0).expect("encode a0"));
    buf.extend_from_slice(&fc::modq_encode(&sk.aots).expect("encode aots"));
    let d = fc::shake256(&buf, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// True iff this build reproduces the pinned keygen KAT (same seed => same a0/aots).
pub fn keygen_kat_ok() -> bool {
    keygen_kat_digest() == KAT_KEYGEN_DIGEST
}

/// Startup/test tripwire: panic if keygen drifts from the pinned reference (HIGH-1).  Call this
/// before any key-dependent operation in a deployment so cross-platform FP divergence is caught
/// at boot rather than after producing incompatible on-chain keys/nullifiers.
pub fn assert_keygen_kat() {
    let got = keygen_kat_digest();
    if got != KAT_KEYGEN_DIGEST {
        let hex = |b: &[u8; 32]| -> String {
            b.iter().map(|x| format!("{:02x}", x)).collect()
        };
        panic!(
            "KEYGEN KAT MISMATCH — Falcon keygen is non-deterministic on this platform.\n  \
             expected: {}\n  got:      {}\n  \
             This build will produce DIFFERENT public keys / nullifiers than the reference \
             (cross-platform Falcon FP-keygen divergence). Do NOT use for consensus. \
             Phase-2 fix: integer/emulated-FP Falcon keygen.",
            hex(&KAT_KEYGEN_DIGEST), hex(&got)
        );
    }
}

/// The on-chain nullifier (linking tag): a 32-byte hash of the ots public key aots.
pub fn nullifier_from_aots(aots: &[u16; N]) -> [u8; 32] {
    let enc = fc::modq_encode(aots).expect("encode aots");
    let mut input = Vec::from(DOM_NULLIFIER);
    input.extend_from_slice(&enc);
    let h = fc::shake256(&input, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

pub fn nullifier(sk: &RaptorSecretKey) -> [u8; 32] {
    nullifier_from_aots(&sk.aots)
}

/// A single ring member's response: short halves (r0,r1) + the 256-bit b.
#[derive(Clone)]
pub struct Member {
    pub r0: [i16; N],
    pub r1: [i16; N],
    pub b: [u8; 32],
}

/// A full Raptor linkable ring signature.
#[derive(Clone)]
pub struct Signature {
    pub members: Vec<Member>,
    pub aots: [u16; N],
    pub ots_sig: OtsSig,
}

/// One-time signature over the transcript = Falcon (r0,r1) preimage under aots for target
/// H1'(transcript).  We reuse Falcon's preimage signing: ots_sig is a short (s0,s1) with
/// s0 + s1*aots = HashToRq(transcript).
#[derive(Clone)]
pub struct OtsSig {
    pub s0: [i16; N],
    pub s1: [i16; N],
}

// ---- transcript hashing ----

/// H : (msg, c_1..c_L) -> {0,1}^256.  Absorb domain || msg || each c_i (modq-encoded).
fn hash_transcript_to_b(msg: &[u8], cs: &[[u16; N]]) -> [u8; 32] {
    let mut input = Vec::from(DOM_H_TRANSCRIPT);
    input.extend_from_slice(&(msg.len() as u64).to_le_bytes());
    input.extend_from_slice(msg);
    for c in cs {
        let e = fc::modq_encode(c).expect("encode c");
        input.extend_from_slice(&e);
    }
    let h = fc::shake256(&input, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

/// HashToRq over the ots transcript ({r0_i,r1_i,b_i}, {a0_i}, aots) -> target in R_q,
/// to be Falcon-preimage-signed under aots.
///
/// Every variable-length region is length-prefixed (MEDIUM-1) so the encoding is
/// boundary-unambiguous: today r0/r1 are fixed [i16; N] and members/ring share L, so a bare
/// concatenation is injective, but prefixing the member count and each (r0,r1,b) field keeps
/// the transcript collision-free if N or the member layout ever changes.  Sign and verify both
/// call this one function, so the encoding stays self-consistent.
fn ots_target(members: &[Member], ring: &[[u16; N]], aots: &[u16; N]) -> [u16; N] {
    fn put_u32(input: &mut Vec<u8>, v: u32) { input.extend_from_slice(&v.to_le_bytes()); }
    fn put_blob(input: &mut Vec<u8>, b: &[u8]) {
        put_u32(input, b.len() as u32);
        input.extend_from_slice(b);
    }
    fn i16s_to_le(arr: &[i16]) -> Vec<u8> {
        let mut v = Vec::with_capacity(arr.len() * 2);
        for &x in arr { v.extend_from_slice(&x.to_le_bytes()); }
        v
    }

    let mut input: Vec<u8> = Vec::new();
    input.extend_from_slice(b"RAPTOR-CCX-ots-transcript");
    put_u32(&mut input, members.len() as u32);
    for m in members {
        // r0,r1 are short ints; serialize as little-endian i16, length-prefixed.
        put_blob(&mut input, &i16s_to_le(&m.r0));
        put_blob(&mut input, &i16s_to_le(&m.r1));
        put_blob(&mut input, &m.b);
    }
    put_u32(&mut input, ring.len() as u32);
    for a0 in ring {
        let e = fc::modq_encode(a0).expect("encode a0");
        put_blob(&mut input, &e);
    }
    put_blob(&mut input, &fc::modq_encode(aots).expect("encode aots"));
    fc::hash_to_rq(&input, c"RAPTOR-CCX-ots-target")
}

// ---- random sampling of a short (r0,r1) for non-signer members ----
//
// Paper draws (r0,r1) <- D_{R,eta}^2 (discrete Gaussian).  For a non-signer member we only
// need (r0,r1) to be VALID short vectors (they are not preimages of anything specific — c_i
// is DEFINED as r0 + ai*r1 + h*b, so it is *computed* from whatever (r0,r1) we draw).
//
// ANONYMITY CRUX (was CRITICAL-1): the signer's genuine (r0_pi,r1_pi) comes out of Falcon's
// trapdoor preimage sampler — a discrete Gaussian over the lattice whose marginal is NOT a
// product of independent per-coordinate Gaussians (it has the lattice's covariance).  A
// per-coordinate CLT/centered-binomial approximation has different tails and no inter-
// coordinate structure, so an adversary holding many on-chain signatures could partition the
// ring by "which member vector looks like a real Falcon preimage" and unmask the signer.
//
// FIX: sample every non-signer (r0,r1) from the SAME distribution Falcon's sampler produces.
// We do exactly what the comment above this block always described: run Falcon's own preimage
// sampler (sign_target) on a uniformly random target u under a FRESH THROWAWAY Falcon key,
// keep the resulting short (r0,r1), and discard the key and u (we never need the relation —
// c_i is recomputed from (r0,r1)).  The output is then statistically the genuine Falcon
// preimage distribution, indistinguishable from the signer's block.  Same reject-retry on the
// norm bound + comp-encodability as Falcon performs internally and as the signer block uses.

/// Draw one non-signer short pair (r0,r1) from Falcon's genuine preimage distribution, using a
/// caller-supplied `throwaway` Falcon trapdoor.
///
/// One throwaway key is created per *signature* (not per member) and shared across all
/// non-signers of that ring: the key is never published and never referenced again, and each
/// call here picks an INDEPENDENT fresh random target `u` and fresh Falcon signing randomness,
/// so the resulting (r0,r1) are independent samples of Falcon's preimage distribution under
/// that lattice.  The lattice differs from the signer's, but Falcon's output distribution
/// (width, tail shape, joint-norm law) is a property of the sampler/parameters, not of which
/// trapdoor instance was used — verified empirically by the `stats` harness.  Reusing one key
/// avoids (L-1) expensive keygens per signature with no effect on the observable distribution.
fn sample_short_pair(throwaway: &FalconKey, rng: &mut ChaCha20Rng) -> ([i16; N], [i16; N]) {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        // Belt-and-braces: Falcon's own internal rejection converges in 1-2 tries, so this
        // cap is only a guard against a broken sampler, never hit in practice.
        if attempt > 256 {
            panic!("non-signer Falcon preimage sampler failed to converge (broken FFI?)");
        }

        // Uniformly random target u in R_q.  We discard u; we only keep the short preimage.
        let mut u = [0u16; N];
        for k in 0..N {
            loop {
                let v = (rng.next_u32() & 0x3FFF) as u16;
                if (v as u32) < fc::Q { u[k] = v; break; }
            }
        }

        // Fresh signing randomness for Falcon's Gaussian sampler each attempt.
        let mut sseed = Vec::from(b"raptor-nonsigner".as_slice());
        sseed.extend_from_slice(&fc::modq_encode(&u).expect("encode u"));
        sseed.extend_from_slice(&attempt.to_le_bytes());
        let mut rbytes = [0u8; 48];
        rng.fill_bytes(&mut rbytes);
        sseed.extend_from_slice(&rbytes);

        let (r0, r1) = throwaway.sign_target(&fc::shake256(&sseed, 48), &u);
        if pair_is_valid(&r0, &r1) {
            return (r0, r1);
        }
    }
}

/// Create the per-signature throwaway Falcon trapdoor used by `sample_short_pair`.
fn new_throwaway_key(rng: &mut ChaCha20Rng) -> FalconKey {
    let mut kseed = [0u8; 48];
    rng.fill_bytes(&mut kseed);
    FalconKey::keygen_det(&kseed)
}

/// A short pair is usable iff its joint norm is within Falcon's acceptance bound AND both
/// halves are encodable by Falcon's compressor (so the signature packs).
fn pair_is_valid(r0: &[i16; N], r1: &[i16; N]) -> bool {
    if fc::sqnorm(r0) + fc::sqnorm(r1) > FALCON512_SQNORM_BOUND { return false; }
    fc::comp_encode(r0).is_some() && fc::comp_encode(r1).is_some()
}

/// Sign `msg` on behalf of `ring` (list of public a0 polynomials), proving knowledge of the
/// secret behind ring[signer_index].  `sign_seed` makes the signature reproducible in tests;
/// in production a wallet would derive it.
pub fn sign(
    msg: &[u8],
    ring: &[[u16; N]],
    sk: &RaptorSecretKey,
    signer_index: usize,
    sign_seed: &[u8],
) -> Result<Signature, &'static str> {
    let l = ring.len();
    if signer_index >= l { return Err("signer_index out of range"); }
    if ring[signer_index] != sk.a0 { return Err("ring[signer_index] != signer public key"); }

    let h = paramch_h();
    let pi = signer_index;

    // deterministic per-signature RNG
    let mut seed = Vec::from(DOM_SIGN_RANDOM);
    seed.extend_from_slice(sign_seed);
    seed.extend_from_slice(msg);
    let seed32 = fc::shake256(&seed, 32);
    let mut rng = ChaCha20Rng::from_seed({
        let mut s = [0u8; 32]; s.copy_from_slice(&seed32); s
    });

    // ai = a0_i - H1(aots)  (mask is the same for all, derived from this signer's aots)
    let mask = &sk.mask;
    let mut ai: Vec<[u16; N]> = Vec::with_capacity(l);
    for a0 in ring {
        ai.push(fc::polysub(a0, mask));
    }

    // c_i and (r0_i, r1_i, b_i) for i != pi
    let mut members: Vec<Option<Member>> = vec![None; l];
    let mut cs: Vec<[u16; N]> = vec![[0u16; N]; l];
    let mut b_acc = [0u8; 32]; // XOR of b_i for i != pi

    // One throwaway Falcon trapdoor for ALL non-signers of this signature: each non-signer
    // (r0,r1) is an independent genuine-Falcon preimage under it (fresh target + randomness),
    // and the key is discarded — never published, never referenced (see sample_short_pair).
    let throwaway = new_throwaway_key(&mut rng);

    for i in 0..l {
        if i == pi { continue; }
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let (r0, r1) = sample_short_pair(&throwaway, &mut rng);
        // c_i = r0 + ai*r1 + h*b
        let r0q = fc::center_to_modq(&r0);
        let r1q = fc::center_to_modq(&r1);
        let bpoly = bits_to_poly(&b);
        let t1 = fc::polymul(&ai[i], &r1q);
        let t2 = fc::polymul(&h, &bpoly);
        let mut c = fc::polyadd(&r0q, &t1);
        c = fc::polyadd(&c, &t2);
        cs[i] = c;
        b_acc = xor32(&b_acc, &b);
        members[i] = Some(Member { r0, r1, b });
    }

    // Signer block: pick c_pi <- R_q, derive b_pi and target u_pi, run the trapdoor preimage.
    // Falcon's preimage of a uniform-random target can occasionally exceed the acceptance
    // bound or fail to comp-encode; re-roll c_pi (fresh randomness) until the pair is valid.
    // This terminates fast (Falcon's own reject rate is small).
    // Hard consistency check (FIX-6): replaces debug_assert_eq! which is stripped in --release.
    // a_pi must equal the signer's real main public key; if this fails the masking relation
    // a0 = a + H1(aots) is inconsistent and the preimage relation would target the wrong key.
    if ai[pi] != sk.main.h {
        return Err("a_pi mismatch — masking inconsistent (ring[pi] != signer a0 or mask corrupt)");
    }
    let mut attempt: u32 = 0;
    let (r0p, r1p, bpi) = loop {
        attempt += 1;
        // FIX-7: panic (not Err) — >64 re-rolls means the Falcon sampler is broken, not a
        // recoverable operational condition.  Callers should not swallow this silently.
        if attempt > 64 {
            panic!("signer preimage failed to converge after 64 attempts (broken Falcon FFI?)");
        }

        // c_pi <- random in R_q
        let mut cpi = [0u16; N];
        for k in 0..N {
            loop {
                let v = (rng.next_u32() & 0x3FFF) as u16;
                if (v as u32) < fc::Q { cpi[k] = v; break; }
            }
        }
        cs[pi] = cpi;

        // b_pi = H(msg, c_1..c_L) XOR b_acc
        let hdig = hash_transcript_to_b(msg, &cs);
        let bpi = xor32(&hdig, &b_acc);

        // u_pi = c_pi - h*b_pi
        let bpoly = bits_to_poly(&bpi);
        let hb = fc::polymul(&h, &bpoly);
        let upi = fc::polysub(&cpi, &hb);

        // (r0_pi, r1_pi) = Falcon.sign_target(a_pi; u_pi) s.t. r0_pi + r1_pi*a_pi = u_pi
        let mut sseed = Vec::from(b"raptor-preimage".as_slice());
        sseed.extend_from_slice(&fc::modq_encode(&upi).unwrap());
        sseed.extend_from_slice(sign_seed);
        sseed.extend_from_slice(&attempt.to_le_bytes());
        let (r0p, r1p) = sk.main.sign_target(&fc::shake256(&sseed, 48), &upi);

        if pair_is_valid(&r0p, &r1p) {
            break (r0p, r1p, bpi);
        }
    };

    members[pi] = Some(Member { r0: r0p, r1: r1p, b: bpi });

    let members: Vec<Member> = members.into_iter().map(|m| m.unwrap()).collect();

    // ots_sig = Falcon.sign(aots; ots_target(transcript))  — preimage under aots.
    // The target is fixed by the transcript, but Falcon draws fresh signing randomness each
    // call; retry the randomness until the preimage is within bound and comp-encodable.
    let tgt = ots_target(&members, ring, &sk.aots);
    let mut o_attempt: u32 = 0;
    let (s0, s1) = loop {
        o_attempt += 1;
        // FIX-7 (OTS): same rationale — panic, not Err.
        if o_attempt > 64 {
            panic!("ots preimage failed to converge after 64 attempts (broken Falcon FFI?)");
        }
        let mut oseed = Vec::from(b"raptor-ots".as_slice());
        oseed.extend_from_slice(sign_seed);
        oseed.extend_from_slice(&fc::modq_encode(&tgt).unwrap());
        oseed.extend_from_slice(&o_attempt.to_le_bytes());
        let (s0, s1) = sk.ots.sign_target(&fc::shake256(&oseed, 48), &tgt);
        if pair_is_valid(&s0, &s1) { break (s0, s1); }
    };

    Ok(Signature { members, aots: sk.aots, ots_sig: OtsSig { s0, s1 } })
}

/// Verify a Raptor signature.  Returns the nullifier on success.
pub fn verify(msg: &[u8], ring: &[[u16; N]], sig: &Signature) -> Result<[u8; 32], &'static str> {
    let l = ring.len();
    if sig.members.len() != l { return Err("member count != ring size"); }

    let h = paramch_h();
    let aots = &sig.aots;
    let aots_enc = fc::modq_encode(aots).ok_or("bad aots")?;
    let mask = fc::hash_to_rq(&aots_enc, DOM_H1);

    // recompute ai and c_i; check norm bounds; accumulate XOR of b_i.
    let mut cs: Vec<[u16; N]> = vec![[0u16; N]; l];
    let mut b_xor = [0u8; 32];
    for i in 0..l {
        let m = &sig.members[i];
        // short-vector norm bound (joint, Falcon-style)
        let sq = fc::sqnorm(&m.r0) + fc::sqnorm(&m.r1);
        if sq > FALCON512_SQNORM_BOUND { return Err("short-vector norm bound exceeded"); }
        // b_i in Db = {0,1}^256 — explicit check (CRITICAL-2), not relying on [u8;32] typing.
        if !b_is_canonical(&m.b) { return Err("b_i not in Db = {0,1}^256"); }
        let ai = fc::polysub(&ring[i], &mask);
        let r0q = fc::center_to_modq(&m.r0);
        let r1q = fc::center_to_modq(&m.r1);
        let bpoly = bits_to_poly(&m.b);
        let t1 = fc::polymul(&ai, &r1q);
        let t2 = fc::polymul(&h, &bpoly);
        let mut c = fc::polyadd(&r0q, &t1);
        c = fc::polyadd(&c, &t2);
        cs[i] = c;
        b_xor = xor32(&b_xor, &m.b);
    }

    // check XOR relation:  XOR_i b_i == H(msg, c_1..c_L)
    let hdig = hash_transcript_to_b(msg, &cs);
    if b_xor != hdig { return Err("ring hash relation failed"); }

    // verify ots signature: s0 + s1*aots == ots_target(transcript), and (s0,s1) short.
    let sq = fc::sqnorm(&sig.ots_sig.s0) + fc::sqnorm(&sig.ots_sig.s1);
    if sq > FALCON512_SQNORM_BOUND { return Err("ots short-vector bound exceeded"); }
    let tgt = ots_target(&sig.members, ring, aots);
    let s0q = fc::center_to_modq(&sig.ots_sig.s0);
    let s1q = fc::center_to_modq(&sig.ots_sig.s1);
    let t = fc::polymul(aots, &s1q);
    let recomputed = fc::polyadd(&s0q, &t);
    if recomputed != tgt { return Err("ots signature relation failed"); }

    Ok(nullifier_from_aots(aots))
}

/// Link two signatures: same signer iff same nullifier.
pub fn link(a: &Signature, b: &Signature) -> bool {
    nullifier_from_aots(&a.aots) == nullifier_from_aots(&b.aots)
}
