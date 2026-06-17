// CIP-0001 spike: real NIST PQ primitives exposed over the C ABI (CIP §5.2/§7).
// ML-KEM-768 (Kyber) = stealth-address KEM; ML-DSA (Dilithium3) = deposit signature.
// Proves the easy PQ surfaces through the librustzcash-style FFI, with measured sizes.
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::kem::{PublicKey as KPub, SecretKey as KSec, Ciphertext as KCt, SharedSecret as KSs};
use pqcrypto_traits::sign::{PublicKey as SPub, SecretKey as SSec, SignedMessage as SSm};

#[repr(C)]
pub struct PqSizes { pub pk: usize, pub sk: usize, pub ct_or_sig: usize, pub ss: usize, pub ok: i32 }

#[no_mangle]
pub extern "C" fn ccx_mlkem768_selftest() -> PqSizes {
    let (pk, sk) = kyber768::keypair();
    let (ss1, ct) = kyber768::encapsulate(&pk);
    let ss2 = kyber768::decapsulate(&ct, &sk);
    let ok = (ss1.as_bytes() == ss2.as_bytes()) as i32;
    PqSizes { pk: pk.as_bytes().len(), sk: sk.as_bytes().len(),
              ct_or_sig: ct.as_bytes().len(), ss: ss1.as_bytes().len(), ok }
}

#[no_mangle]
pub extern "C" fn ccx_mldsa65_selftest() -> PqSizes {
    let (pk, sk) = dilithium3::keypair();
    let msg = b"conceal pq deposit sig";
    let sm = dilithium3::sign(msg, &sk);
    let ok = dilithium3::open(&sm, &pk).map(|m| m == msg).unwrap_or(false) as i32;
    PqSizes { pk: pk.as_bytes().len(), sk: sk.as_bytes().len(),
              ct_or_sig: sm.as_bytes().len(), ss: 0, ok }
}
