//! Answers a test session from the NIST ACVP server.
//!
//! `scytale-acvp register` downloads a session's vector sets into a
//! directory; this answers them, through the same functions the
//! vendored suites run, and `scytale-acvp submit` sends the answers
//! back. It is a test because the answering code is test code: it
//! lives in this crate so that it can reach every implementation,
//! and the crate's test build is the one with a file system and a
//! JSON parser. It is ignored because it does nothing without a
//! session:
//!
//! ```sh
//! SCYTALE_ACVP_SESSION=target/acvp/12345 \
//!     cargo test --lib acvp::live -- --ignored --nocapture
//! ```
//!
//! Every `<vsId>.prompt.json` in the directory is answered into
//! `<vsId>.response.json`. Where the server also sent its expected
//! answers (`<vsId>.expected.json`, sample sessions), the answers
//! are held to them here and the first disagreement is named, which
//! says more than the server's verdict will.
//!
//! A vector set this crate cannot answer fails the run: the
//! registration advertised it, so one of the two is wrong, and a
//! skip would hide which.

#[allow(unused_imports)]
use std::{
    borrow::ToOwned, eprintln, format, println, string::String, vec, vec::Vec,
};

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::support::acvp::{
    aes_cbc, aes_ccm, aes_cfb1, aes_cfb8, aes_cfb128, aes_ctr, aes_ecb,
    aes_ff1, aes_ff3_1, aes_gcm, aes_gcm_siv, aes_gmac, aes_kw, aes_kwp,
    aes_ofb, aes_xpn, aes_xts, answer_aes, check, cmac_aes, cshake, ctr_drbg,
    ecdsa, eddsa, hmac, kda_hkdf, kmac, kts_ifc, ml_dsa, ml_kem, pbkdf,
    rsa_primitive, rsa_sig, sha, shake, slh_dsa, tls12_kdf, xecdh,
};
use crate::hash::sha3::{Auto, variant};
use crate::hash::{sha1, sha2, sha3};
use crate::mac::kmac::{Kmac128, Kmac256};
use sha::Family;

/// Names the session directory.
const SESSION: &str = "SCYTALE_ACVP_SESSION";

/// The response to `prompt`, by its algorithm, mode and revision,
/// on the implementation this processor picks.
fn answer(prompt: &Value) -> Value {
    let text = |name: &str| prompt[name].as_str().unwrap_or("");
    let (algorithm, mode, revision) =
        (text("algorithm"), text("mode"), text("revision"));
    match (algorithm, mode, revision) {
        ("SHA-1", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha1::Sha1::new)
        }
        ("SHA2-224", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha224::new)
        }
        ("SHA2-256", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha256::new)
        }
        ("SHA2-384", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha384::new)
        }
        ("SHA2-512", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha512::new)
        }
        ("SHA2-512/224", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha512_224::new)
        }
        ("SHA2-512/256", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha512_256::new)
        }
        ("SHA3-224", "", "2.0") => {
            sha::answer(prompt, Family::Sha3, sha3::Sha3_224::new)
        }
        ("SHA3-256", "", "2.0") => {
            sha::answer(prompt, Family::Sha3, sha3::Sha3_256::new)
        }
        ("SHA3-384", "", "2.0") => {
            sha::answer(prompt, Family::Sha3, sha3::Sha3_384::new)
        }
        ("SHA3-512", "", "2.0") => {
            sha::answer(prompt, Family::Sha3, sha3::Sha3_512::new)
        }
        ("SHAKE-128", "", "1.0") => shake::answer(prompt, sha3::Shake128::new),
        ("SHAKE-256", "", "1.0") => shake::answer(prompt, sha3::Shake256::new),
        ("HMAC-SHA-1", "", "1.0") => hmac::answer::<sha1::Sha1>(prompt),
        ("HMAC-SHA2-224", "", "1.0") => hmac::answer::<sha2::Sha224>(prompt),
        ("HMAC-SHA2-256", "", "1.0") => hmac::answer::<sha2::Sha256>(prompt),
        ("HMAC-SHA2-384", "", "1.0") => hmac::answer::<sha2::Sha384>(prompt),
        ("HMAC-SHA2-512", "", "1.0") => hmac::answer::<sha2::Sha512>(prompt),
        ("HMAC-SHA2-512/224", "", "1.0") => {
            hmac::answer::<sha2::Sha512_224>(prompt)
        }
        ("HMAC-SHA2-512/256", "", "1.0") => {
            hmac::answer::<sha2::Sha512_256>(prompt)
        }
        ("HMAC-SHA3-224", "", "1.0") => hmac::answer::<sha3::Sha3_224>(prompt),
        ("HMAC-SHA3-256", "", "1.0") => hmac::answer::<sha3::Sha3_256>(prompt),
        ("HMAC-SHA3-384", "", "1.0") => hmac::answer::<sha3::Sha3_384>(prompt),
        ("HMAC-SHA3-512", "", "1.0") => hmac::answer::<sha3::Sha3_512>(prompt),
        ("CMAC-AES", "", "1.0") => cmac_aes::answer(prompt),
        ("cSHAKE-128", "", "1.0") => {
            cshake::answer(prompt, Auto::<variant::CShake128>::new)
        }
        ("cSHAKE-256", "", "1.0") => {
            cshake::answer(prompt, Auto::<variant::CShake256>::new)
        }
        ("KMAC-128", "", "1.0") => kmac::answer::<Kmac128>(prompt),
        ("KMAC-256", "", "1.0") => kmac::answer::<Kmac256>(prompt),
        ("ctrDRBG", "", "1.0") => ctr_drbg::answer(prompt),
        ("PBKDF", "", "1.0") => pbkdf::answer(prompt),
        ("KDA", "HKDF", "Sp800-56Cr2") => kda_hkdf::answer(prompt),
        ("TLS-v1.2", "KDF", "RFC7627") => tls12_kdf::answer(prompt),
        ("ECDSA" | "DetECDSA", _, "FIPS186-5") => ecdsa::answer(prompt),
        ("EDDSA", _, "1.0") => eddsa::answer(prompt),
        ("XECDH", _, "RFC7748") => xecdh::answer(prompt),
        ("RSA", "sigGen" | "sigVer", "FIPS186-5") => rsa_sig::answer(prompt),
        ("RSA", "sigVer", "FIPS186-4") => rsa_sig::answer(prompt),
        ("RSA", "signaturePrimitive", "2.0") => {
            rsa_primitive::answer_signature(prompt)
        }
        ("RSA", "decryptionPrimitive", "1.0") => {
            rsa_primitive::answer_decryption(prompt)
        }
        ("KTS-IFC", "", "Sp800-56Br2") => kts_ifc::answer(prompt),
        ("ML-KEM", _, "FIPS203" | "FIPS203-tr1") => ml_kem::answer(prompt),
        ("ML-DSA", _, "FIPS204" | "FIPS204-tr1") => ml_dsa::answer(prompt),
        ("SLH-DSA", _, "FIPS205") => slh_dsa::answer(prompt),
        ("ACVP-AES-ECB", "", "1.0") => answer_aes::<aes_ecb::Suite>(prompt),
        ("ACVP-AES-CBC", "", "1.0") => answer_aes::<aes_cbc::Suite>(prompt),
        ("ACVP-AES-CFB1", "", "1.0") => answer_aes::<aes_cfb1::Suite>(prompt),
        ("ACVP-AES-CFB8", "", "1.0") => answer_aes::<aes_cfb8::Suite>(prompt),
        ("ACVP-AES-CFB128", "", "1.0") => {
            answer_aes::<aes_cfb128::Suite>(prompt)
        }
        ("ACVP-AES-OFB", "", "1.0") => answer_aes::<aes_ofb::Suite>(prompt),
        ("ACVP-AES-CTR", "", "1.0") => answer_aes::<aes_ctr::Suite>(prompt),
        ("ACVP-AES-XTS", "", "1.0" | "2.0") => {
            answer_aes::<aes_xts::Suite>(prompt)
        }
        ("ACVP-AES-FF1", "", "1.0") => answer_aes::<aes_ff1::Suite>(prompt),
        ("ACVP-AES-FF3-1", "", "1.0") => answer_aes::<aes_ff3_1::Suite>(prompt),
        ("ACVP-AES-GCM", "", "1.0") => answer_aes::<aes_gcm::Suite>(prompt),
        ("ACVP-AES-GMAC", "", "1.0") => answer_aes::<aes_gmac::Suite>(prompt),
        // The vendored GCM-SIV file predates the revision field.
        ("ACVP-AES-GCM-SIV", "", "" | "1.0") => aes_gcm_siv::answer(prompt),
        ("ACVP-AES-XPN", "", "1.0") => answer_aes::<aes_xpn::Suite>(prompt),
        ("ACVP-AES-CCM", "", "1.0") => answer_aes::<aes_ccm::Suite>(prompt),
        ("ACVP-AES-KW", "", "1.0") => answer_aes::<aes_kw::Suite>(prompt),
        ("ACVP-AES-KWP", "", "1.0") => answer_aes::<aes_kwp::Suite>(prompt),
        _ => panic!(
            "{algorithm}/{mode} {revision}: nothing here answers it, \
             yet scytale-acvp registered it"
        ),
    }
}

/// `<vsId>.prompt.json` files under `dir`, in order.
fn prompts(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".prompt.json"))
        })
        .collect();
    found.sort();
    found
}

fn read(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Answers every vector set of the session named by the
/// environment, and holds the answers to the server's where it sent
/// them.
///
/// With no session named there is nothing to answer, and the test
/// says so and passes: `cargo test-extended` and the jobs that run
/// every ignored test reach it too, and none of them has a session.
#[test]
#[ignore]
fn answer_session() {
    let Ok(dir) = std::env::var(SESSION) else {
        eprintln!("{SESSION} is not set; no session to answer");
        return;
    };
    // Cargo runs a test in its crate's directory; a relative path
    // is meant from the checkout, where scytale-acvp keeps sessions.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let dir = &root.join(dir);
    let prompts = prompts(dir);
    assert!(!prompts.is_empty(), "no prompts in {}", dir.display());
    let mut differ = Vec::new();
    for path in prompts {
        let name = path.file_name().and_then(|n| n.to_str()).expect("name");
        let id = name.trim_end_matches(".prompt.json");
        let prompt = read(&path);
        eprintln!(
            "{id}: {} {}",
            prompt["algorithm"].as_str().unwrap_or("?"),
            prompt["revision"].as_str().unwrap_or("?")
        );
        let response = answer(&prompt);
        let text = serde_json::to_string_pretty(&response).expect("JSON");
        let out = dir.join(format!("{id}.response.json"));
        fs::write(&out, text)
            .unwrap_or_else(|e| panic!("{}: {e}", out.display()));
        let expected = dir.join(format!("{id}.expected.json"));
        if expected.is_file() {
            let expected = read(&expected);
            match check(&expected["testGroups"], &response["testGroups"]) {
                Ok(()) => eprintln!("{id}: as the server expects"),
                Err(why) => {
                    eprintln!("{id}: differs from the server: {why}");
                    differ.push(id.to_owned());
                }
            }
        }
    }
    assert!(
        differ.is_empty(),
        "answers differ from the server's for vector sets {differ:?}"
    );
}
