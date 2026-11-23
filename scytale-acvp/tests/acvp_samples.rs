//! `cargo test -p scytale-acvp --test acvp_samples`: the check
//! against NIST's ACVP sample vectors, kept in this crate, a test per
//! suite, each answering the suite in full under every kernel its
//! vectors test; see `scytale_acvp::vendored`. Test
//! `acvp_samples::sha2_512` alone with `cargo test -p scytale-acvp --
//! --exact acvp_samples::sha2_512`, and name kernels as its lines do
//! in `SCYTALE_KERNELS`.

use std::sync::Mutex;

use scytale_acvp::suite::SUITES;

/// Held for the whole of each suite's check. The set of features in
/// force is process-wide, and each kernel's run puts its own in
/// force, so the tests the harness runs at once must take turns;
/// each one keeps every core busy meanwhile.
static TURN: Mutex<()> = Mutex::new(());

fn check(name: &str, directory: &str) {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    if let Err(e) = scytale_acvp::vendored::check(name, directory) {
        panic!("{e}");
    }
}

const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Compiles only if `directories` names every suite in the registry
/// exactly once: as many as there are suites, each registered, and
/// no two alike. So a suite added without a test fails the build.
const fn every_suite_once(directories: &[&str]) {
    assert!(
        directories.len() == SUITES.len(),
        "a suite has no test, or a test no suite"
    );
    let mut i = 0;
    while i < directories.len() {
        let mut found = false;
        let mut s = 0;
        while s < SUITES.len() {
            found |= same(directories[i], SUITES[s].directory);
            s += 1;
        }
        assert!(found, "a test names a suite that is not registered");
        let mut j = i + 1;
        while j < directories.len() {
            assert!(
                !same(directories[i], directories[j]),
                "two tests name one suite"
            );
            j += 1;
        }
        i += 1;
    }
}

/// A test per suite, named after its vendored directory without the
/// `ACVP-` prefix and without its revision, which is kept only where
/// two directories differ by nothing else.
macro_rules! suites {
    ($($name:ident => $directory:literal,)+) => {
        const _: () = every_suite_once(&[$($directory),+]);

        mod acvp_samples {
            $(
                #[test]
                fn $name() {
                    super::check(stringify!($name), $directory);
                }
            )+
        }
    };
}

suites! {
    aes_cbc => "ACVP-AES-CBC-1.0",
    aes_ccm => "ACVP-AES-CCM-1.0",
    aes_cfb1 => "ACVP-AES-CFB1-1.0",
    aes_cfb128 => "ACVP-AES-CFB128-1.0",
    aes_cfb8 => "ACVP-AES-CFB8-1.0",
    aes_ctr => "ACVP-AES-CTR-1.0",
    aes_ecb => "ACVP-AES-ECB-1.0",
    aes_ff1 => "ACVP-AES-FF1-1.0",
    aes_ff3_1 => "ACVP-AES-FF3-1-1.0",
    aes_gcm => "ACVP-AES-GCM-1.0",
    aes_gcm_siv => "ACVP-AES-GCM-SIV-1.0",
    aes_gmac => "ACVP-AES-GMAC-1.0",
    aes_kw => "ACVP-AES-KW-1.0",
    aes_kwp => "ACVP-AES-KWP-1.0",
    aes_ofb => "ACVP-AES-OFB-1.0",
    aes_xpn => "ACVP-AES-XPN-1.0",
    aes_xts_1_0 => "ACVP-AES-XTS-1.0",
    aes_xts_2_0 => "ACVP-AES-XTS-2.0",
    hmac_sha2_224 => "ACVP-HMAC-SHA2-224-1.0",
    hmac_sha2_256 => "ACVP-HMAC-SHA2-256-1.0",
    hmac_sha2_384 => "ACVP-HMAC-SHA2-384-1.0",
    hmac_sha2_512 => "ACVP-HMAC-SHA2-512-1.0",
    hmac_sha2_512_224 => "ACVP-HMAC-SHA2-512-224-1.0",
    hmac_sha2_512_256 => "ACVP-HMAC-SHA2-512-256-1.0",
    hmac_sha3_224 => "ACVP-HMAC-SHA3-224-1.0",
    hmac_sha3_256 => "ACVP-HMAC-SHA3-256-1.0",
    hmac_sha3_384 => "ACVP-HMAC-SHA3-384-1.0",
    hmac_sha3_512 => "ACVP-HMAC-SHA3-512-1.0",
    hmac_sha_1 => "HMAC-SHA-1-1.0",
    pbkdf => "ACVP-PBKDF-1.0",
    sha2_224 => "ACVP-SHA2-224-1.0",
    sha2_256 => "ACVP-SHA2-256-1.0",
    sha2_384 => "ACVP-SHA2-384-1.0",
    sha2_512 => "ACVP-SHA2-512-1.0",
    sha2_512_224 => "ACVP-SHA2-512-224-1.0",
    sha2_512_256 => "ACVP-SHA2-512-256-1.0",
    sha3_224 => "ACVP-SHA3-224-2.0",
    sha3_256 => "ACVP-SHA3-256-2.0",
    sha3_384 => "ACVP-SHA3-384-2.0",
    sha3_512 => "ACVP-SHA3-512-2.0",
    shake_128 => "ACVP-SHAKE-128-1.0",
    shake_256 => "ACVP-SHAKE-256-1.0",
    cmac_aes => "CMAC-AES-1.0",
    detecdsa_siggen => "DetECDSA-SigGen-FIPS186-5",
    ecdsa_keygen => "ECDSA-KeyGen-FIPS186-5",
    ecdsa_keyver => "ECDSA-KeyVer-FIPS186-5",
    ecdsa_siggen => "ECDSA-SigGen-FIPS186-5",
    ecdsa_sigver => "ECDSA-SigVer-FIPS186-5",
    eddsa_keygen => "EDDSA-KeyGen-1.0",
    eddsa_keyver => "EDDSA-KeyVer-1.0",
    eddsa_siggen => "EDDSA-SigGen-1.0",
    eddsa_sigver => "EDDSA-SigVer-1.0",
    kda_hkdf => "KDA-HKDF-Sp800-56Cr2",
    kda_onestep => "KDA-OneStep-Sp800-56Cr2",
    kda_onestepnocounter => "KDA-OneStepNoCounter-Sp800-56Cr2",
    kdf => "KDF-1.0",
    kdf_kmac => "KDF-KMAC-Sp800-108r1",
    kmac_128 => "KMAC-128-1.0",
    kmac_256 => "KMAC-256-1.0",
    kts_ifc => "KTS-IFC-Sp800-56Br2",
    lms_keygen => "LMS-keyGen-1.0",
    lms_siggen => "LMS-sigGen-SP800-208",
    lms_sigver => "LMS-sigVer-SP800-208",
    lms_keygen_session_788050 => "LMS-keyGen-1.0-session-788050",
    lms_siggen_session_788050 => "LMS-sigGen-SP800-208-session-788050",
    lms_sigver_session_788050 => "LMS-sigVer-SP800-208-session-788050",
    ml_dsa_keygen => "ML-DSA-keyGen-FIPS204",
    ml_dsa_siggen => "ML-DSA-sigGen-FIPS204-tr1",
    ml_dsa_sigver => "ML-DSA-sigVer-FIPS204",
    ml_kem_encapdecap => "ML-KEM-encapDecap-FIPS203-tr1",
    ml_kem_keygen => "ML-KEM-keyGen-FIPS203",
    rsa_keygen => "RSA-KeyGen-FIPS186-5",
    rsa_siggen => "RSA-SigGen-FIPS186-5",
    rsa_sigver_fips186_4 => "RSA-SigVer-FIPS186-4",
    rsa_sigver_fips186_5 => "RSA-SigVer-FIPS186-5",
    rsa_signatureprimitive => "RSA-SignaturePrimitive-2.0",
    rsa_decryptionprimitive => "RSA-decryptionPrimitive-1.0",
    slh_dsa_keygen => "SLH-DSA-keyGen-FIPS205",
    slh_dsa_siggen => "SLH-DSA-sigGen-FIPS205",
    slh_dsa_sigver => "SLH-DSA-sigVer-FIPS205",
    tls_v1_2_kdf => "TLS-v1.2-KDF-RFC7627",
    tuplehash_128 => "TupleHash-128-1.0",
    tuplehash_256 => "TupleHash-256-1.0",
    xecdh_ssc => "XECDH-SSC-RFC7748",
    xecdh_keygen => "XECDH-keyGen-RFC7748",
    cshake_128 => "cSHAKE-128-1.0",
    cshake_256 => "cSHAKE-256-1.0",
    ctrdrbg => "ctrDRBG-1.0",
    hashdrbg_1_0 => "hashDRBG-1.0",
    hashdrbg_sp800_90ar1 => "hashDRBG-SP800-90Ar1",
    hmacdrbg_1_0 => "hmacDRBG-1.0",
    hmacdrbg_sp800_90ar1 => "hmacDRBG-SP800-90Ar1",
    kdf_components_ansix9_63 => "kdf-components-ansix9.63-1.0",
}
