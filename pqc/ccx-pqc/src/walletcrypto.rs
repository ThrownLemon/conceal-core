//! Wallet-file at-rest encryption helpers (CIP-0001 Q2 §1b — crypto modernization).
//!
//! Replaces the legacy wallet KDF (a single unsalted pass of `cn_slow_hash_v0` over the raw
//! password) + unauthenticated 8-round chacha8 container cipher with:
//!   * **Argon2id** (RFC 9106) for password -> key derivation, with a random per-wallet salt and
//!     tunable memory/time/parallelism cost stored in the wallet header; and
//!   * **XChaCha20-Poly1305** AEAD for the container (24-byte random nonce — no nonce-management
//!     footgun — plus a 16-byte Poly1305 tag so any tamper/corruption is detected on open).
//!
//! This is CLIENT-SIDE ONLY: the wallet file never touches consensus. The C++ wallet calls these
//! through the C ABI in `lib.rs`; the pure logic lives here so the crypto detail stays out of C++.
//!
//! These primitives come from the audited RustCrypto crates (`argon2`, `chacha20poly1305`), the
//! same family the PQ 0x06 message AEAD already uses — no hand-rolled C password hashing.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// XChaCha20-Poly1305 key length.
pub const KEY_BYTES: usize = 32;
/// XChaCha20-Poly1305 nonce length (the eXtended-nonce variant — 24 bytes, randomly chosen).
pub const NONCE_BYTES: usize = 24;
/// Poly1305 authentication tag length appended by seal().
pub const TAG_BYTES: usize = 16;
/// Prefix-MAC tag length (32) — the keyed SHAKE256 tag authenticating the v8 wallet container prefix.
pub const PREFIX_MAC_BYTES: usize = 32;

/// Domain string for deriving the prefix-MAC subkey from the Argon2id master key. Distinct from the
/// AEAD encryption use of the master key (the master key is fed RAW to XChaCha20-Poly1305), so the
/// MAC subkey is cryptographically independent of the encryption key.
const PREFIX_MAC_KEY_DOMAIN: &[u8] = b"ccx-wallet-prefix-mac-key-v1";
/// Domain string bound into the keyed-MAC sponge itself (KMAC-style domain separation).
const PREFIX_MAC_TAG_DOMAIN: &[u8] = b"ccx-wallet-prefix-mac-v1";

/// Fill `out` with cryptographically-secure random bytes from the OS CSPRNG.
///
/// The wallet's Argon2id salt and the XChaCha20-Poly1305 nonce MUST come from a real CSPRNG: the C++
/// `Randomize` helper is `std::mt19937` seeded from a single 32-bit `random_device()` draw (only 32
/// bits of entropy), so two wallets can collide on the same salt+nonce — and with the same password
/// that is XChaCha20 nonce reuse, a catastrophic confidentiality/forgery break. `OsRng` reads the
/// platform CSPRNG (getrandom/getentropy) and never blocks after early boot.
pub fn fill_random(out: &mut [u8]) {
    OsRng.fill_bytes(out);
}

/// Derive a 32-byte key from `password` + `salt` using Argon2id with the supplied cost parameters.
///
/// `mem_kib` is the memory cost in KiB, `iterations` the time cost (passes), `parallelism` the
/// number of lanes. Returns the 32-byte key on success, or `None` if the parameters are invalid
/// (e.g. below Argon2's minimums) — the caller (lib.rs FFI) maps `None` to an error code so the
/// wallet refuses to derive a key under bogus parameters rather than silently weakening.
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Option<[u8; KEY_BYTES]> {
    // Argon2 requires salt >= 8 bytes; we always store 16, but validate at the boundary.
    if salt.len() < 8 {
        return None;
    }
    let params = Params::new(mem_kib, iterations, parallelism, Some(KEY_BYTES)).ok()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_BYTES];
    argon.hash_password_into(password, salt, &mut key).ok()?;
    Some(key)
}

/// Seal `plaintext` under `key` with a caller-supplied 24-byte `nonce`. Returns
/// `ciphertext || 16-byte Poly1305 tag` (length = `plaintext.len() + 16`), or `None` on failure.
///
/// The nonce MUST be unique per (key) — the caller draws a fresh random 24-byte nonce for every
/// save and stores it in the header. XChaCha20's 192-bit nonce makes random selection collision-
/// safe without a counter.
pub fn aead_seal(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(XNonce::from_slice(nonce), plaintext).ok()
}

/// Open a sealed blob (`ciphertext || tag`) produced by [`aead_seal`] with the same `key`+`nonce`.
/// Returns the recovered plaintext, or `None` if the Poly1305 tag does not verify (wrong password,
/// truncation, or tampering). On failure NOTHING is returned — no unauthenticated plaintext leaks.
pub fn aead_open(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < TAG_BYTES {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(XNonce::from_slice(nonce), sealed).ok()
}

/// Compute the 32-byte keyed MAC over the wallet container `prefix` bytes (v8 wallet-file format,
/// hardening item W11). `master_key` is the 32-byte Argon2id-derived container key.
///
/// Construction (a standard keyed-sponge MAC — NOT a hand-rolled novel scheme):
///   * `mac_key = SHAKE256("ccx-wallet-prefix-mac-key-v1" || master_key)[0..32]` — a subkey
///     domain-separated from the AEAD encryption use of `master_key`, so the MAC key is independent
///     of the encryption key.
///   * `tag = SHAKE256("ccx-wallet-prefix-mac-v1" || mac_key || prefix)[0..32]` — a keyed-prefix
///     SHAKE256 MAC. The sponge (Keccak) construction is immune to length-extension, so a keyed
///     prefix is a sound MAC (unlike Merkle–Damgård SHA-2). Same SHAKE256 KDF family the PQ message
///     AEAD and the deterministic PQ keygen already use.
///
/// The caller stores `tag` INSIDE the AEAD-sealed suffix (so the tag is itself confidential and
/// authenticated) and re-verifies it against the live prefix on open, detecting prefix
/// tamper/rollback that the suffix AEAD alone cannot see.
pub fn prefix_mac(master_key: &[u8; KEY_BYTES], prefix: &[u8]) -> [u8; PREFIX_MAC_BYTES] {
    let mut mac_key = [0u8; KEY_BYTES];
    {
        let mut x = Shake256::default();
        Update::update(&mut x, PREFIX_MAC_KEY_DOMAIN);
        Update::update(&mut x, master_key);
        x.finalize_xof().read(&mut mac_key);
    }

    let mut tag = [0u8; PREFIX_MAC_BYTES];
    {
        let mut x = Shake256::default();
        Update::update(&mut x, PREFIX_MAC_TAG_DOMAIN);
        Update::update(&mut x, &mac_key);
        Update::update(&mut x, prefix);
        x.finalize_xof().read(&mut tag);
    }
    // Wipe the derived MAC subkey before returning — it is sensitive (deriving it again needs the
    // master key, but a lingering copy is needless exposure). Volatile writes + a compiler fence so
    // the dead store cannot be optimised away. (No `zeroize` crate dependency added; this keeps the
    // Cargo manifest/lock unchanged.)
    for b in mac_key.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0u8); }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap params for tests (production uses much larger memory cost).
    const T_MEM: u32 = 8 * 1024; // 8 MiB
    const T_ITERS: u32 = 1;
    const T_PAR: u32 = 1;

    #[test]
    fn argon2id_is_deterministic_and_salt_sensitive() {
        let salt_a = [0x11u8; 16];
        let salt_b = [0x22u8; 16];
        let k1 = argon2id_derive(b"hunter2", &salt_a, T_MEM, T_ITERS, T_PAR).unwrap();
        let k2 = argon2id_derive(b"hunter2", &salt_a, T_MEM, T_ITERS, T_PAR).unwrap();
        let k3 = argon2id_derive(b"hunter2", &salt_b, T_MEM, T_ITERS, T_PAR).unwrap();
        let k4 = argon2id_derive(b"different", &salt_a, T_MEM, T_ITERS, T_PAR).unwrap();
        assert_eq!(k1, k2, "same password+salt must reproduce the key");
        assert_ne!(k1, k3, "different salt must change the key");
        assert_ne!(k1, k4, "different password must change the key");
    }

    #[test]
    fn aead_roundtrip_and_tamper_detection() {
        let salt = [0x33u8; 16];
        let key = argon2id_derive(b"pw", &salt, T_MEM, T_ITERS, T_PAR).unwrap();
        let nonce = [0x44u8; NONCE_BYTES];
        let msg = b"the wallet container plaintext bytes";
        let sealed = aead_seal(&key, &nonce, msg).unwrap();
        assert_eq!(sealed.len(), msg.len() + TAG_BYTES);
        let opened = aead_open(&key, &nonce, &sealed).unwrap();
        assert_eq!(&opened[..], &msg[..]);

        // flip any byte -> open must fail (no plaintext)
        let mut bad = sealed.clone();
        bad[0] ^= 0x01;
        assert!(aead_open(&key, &nonce, &bad).is_none());

        // wrong key (wrong password) -> open must fail
        let wrong = argon2id_derive(b"WRONG", &salt, T_MEM, T_ITERS, T_PAR).unwrap();
        assert!(aead_open(&wrong, &nonce, &sealed).is_none());

        // wrong nonce -> open must fail
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0xff;
        assert!(aead_open(&key, &wrong_nonce, &sealed).is_none());
    }

    #[test]
    fn rejects_bogus_params() {
        // iterations = 0 is invalid for Argon2 -> None (FFI maps to an error).
        assert!(argon2id_derive(b"pw", &[0u8; 16], T_MEM, 0, T_PAR).is_none());
        // salt too short -> None.
        assert!(argon2id_derive(b"pw", &[0u8; 4], T_MEM, T_ITERS, T_PAR).is_none());
    }

    #[test]
    fn prefix_mac_is_deterministic_key_and_message_sensitive() {
        let key_a = [0x11u8; KEY_BYTES];
        let key_b = [0x22u8; KEY_BYTES];
        let prefix = b"container prefix: version || nextIv || encrypted view+spend records";

        let t1 = prefix_mac(&key_a, prefix);
        let t2 = prefix_mac(&key_a, prefix);
        assert_eq!(t1, t2, "same key+prefix must reproduce the tag");
        assert_eq!(t1.len(), PREFIX_MAC_BYTES);

        // different key -> different tag
        let t3 = prefix_mac(&key_b, prefix);
        assert_ne!(t1, t3, "different key must change the tag");

        // flip one prefix byte -> different tag
        let mut tampered = prefix.to_vec();
        tampered[0] ^= 0x01;
        let t4 = prefix_mac(&key_a, &tampered);
        assert_ne!(t1, t4, "tampered prefix must change the tag");

        // empty prefix still yields a tag (defensive — should never happen in practice)
        let _ = prefix_mac(&key_a, &[]);
    }

    #[test]
    fn prefix_mac_subkey_is_independent_of_encryption_use() {
        // The MAC subkey is domain-separated from the raw key used for AEAD encryption, so the tag
        // must differ from a naive SHAKE256 of the raw key over the same message (sanity: the domain
        // separation actually takes effect).
        let key = [0x5au8; KEY_BYTES];
        let prefix = b"abc";
        let tag = prefix_mac(&key, prefix);

        let mut naive = [0u8; PREFIX_MAC_BYTES];
        let mut x = Shake256::default();
        Update::update(&mut x, &key[..]);
        Update::update(&mut x, &prefix[..]);
        x.finalize_xof().read(&mut naive);
        assert_ne!(tag, naive, "domain-separated MAC must not equal a raw keyed hash");
    }
}
