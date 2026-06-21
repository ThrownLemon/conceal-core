//! Cross-platform keygen KAT digest printer. Used for the determinism matrix:
//! cross-compile for each target, run under QEMU (or natively), compare the digest.
//! Expected: 8f245c82dc7390f3cb4d8955556a45d56af41c83a37fc0388b996b58f295745e

fn main() {
    let digest = ccx_pqc::raptor::keygen_kat_digest();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    let ok = ccx_pqc::raptor::keygen_kat_ok();
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    println!("KEYGEN_KAT_DIGEST={}", hex);
    println!("KAT_OK={}", ok);
    println!("PLATFORM={}-{}", os, arch);
    if !ok {
        eprintln!("FAIL: keygen KAT drift detected on {}-{}", os, arch);
        std::process::exit(1);
    }
}
