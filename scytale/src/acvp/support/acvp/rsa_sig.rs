//! RSA sigGen and sigVer under FIPS 186-5, and sigVer under FIPS
//! 186-4 for its 1024-bit groups, a width 186-5 no longer offers.
//!
//! The live server has the implementation draw a key per sigGen
//! group and report its modulus and exponent beside the signatures,
//! which the server then verifies. The vendored sigGen file carries
//! no private key, so its worked answers serve as extra known-good
//! signatures under NIST-chosen keys and exponents, verified like
//! the sigVer files'.
//!
//! Groups whose hash or mask function is a SHAKE are skipped, and
//! never registered: FIPS 186-5 allows XOFs in both roles, and the
//! crate's PSS is defined over fixed-output hashes with MGF1 as the
//! mask. The 186-4 file's ANSI X9.31 groups are skipped too, that
//! encoding not being implemented, as are the SP 800-106 groups of
//! either revision, whose message is randomized before hashing.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use std::collections::BTreeMap;

use super::{check, hex, hex_string, load, response};
use crate::Random;
use crate::hash::sha1::Sha1;
use crate::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use crate::hash::sha2::{Sha512_224, Sha512_256};
use crate::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use crate::random::CtrDrbg;
use crate::sig::rsa::{DigestInfo, PrivateKey, PublicKey};
use serde_json::{Value, json};

/// Runs one case through the right hash, or `None` for a hash the
/// crate does not sign with (the SHAKEs).
macro_rules! dispatch_hash {
    ($alg:expr, $run:ident, $($arg:expr),*) => {
        match $alg {
            "SHA2-224" => Some($run::<Sha224>($($arg),*)),
            "SHA2-256" => Some($run::<Sha256>($($arg),*)),
            "SHA2-384" => Some($run::<Sha384>($($arg),*)),
            "SHA2-512" => Some($run::<Sha512>($($arg),*)),
            "SHA2-512/224" => Some($run::<Sha512_224>($($arg),*)),
            "SHA2-512/256" => Some($run::<Sha512_256>($($arg),*)),
            "SHA3-224" => Some($run::<Sha3_224>($($arg),*)),
            "SHA3-256" => Some($run::<Sha3_256>($($arg),*)),
            "SHA3-384" => Some($run::<Sha3_384>($($arg),*)),
            "SHA3-512" => Some($run::<Sha3_512>($($arg),*)),
            // SHA-1 appears only in the 186-4 file.
            "SHA-1" => Some($run::<Sha1>($($arg),*)),
            "SHAKE-128" | "SHAKE-256" => None,
            other => panic!("unknown hash {other}"),
        }
    };
}

/// Why a group cannot be answered, if it cannot.
fn skip_reason(group: &Value) -> Option<String> {
    // 186-5 names the mask function; 186-4 has only MGF1 and
    // records none, so an absent field is MGF1.
    let mask = group["maskFunction"].as_str().unwrap_or("mgf1");
    if group["sigType"] == "pss" && mask != "mgf1" {
        return Some(format!("the mask function {mask}"));
    }
    if group["sigType"] == "ansx9.31" {
        return Some("ANSI X9.31".into());
    }
    if group["conformance"] == "SP800-106" {
        return Some("SP 800-106 randomized hashing".into());
    }
    let hash = group["hashAlg"].as_str().expect("hashAlg");
    if hash.starts_with("SHAKE") {
        return Some(format!("the hash {hash}"));
    }
    None
}

/// The response to a whole vector set, sigGen or sigVer.
pub fn answer(prompt: &Value) -> Value {
    let mode = prompt["mode"].as_str().expect("mode");
    // One key per modulus serves every group at that width; the
    // server checks each group against the key it reports.
    let mut keys: BTreeMap<u64, PrivateKey> = BTreeMap::new();
    let mut rng = CtrDrbg::from_system().expect("generator");
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            if let Some(why) = skip_reason(group) {
                panic!("tgId {}: {why} is not offered", group["tgId"]);
            }
            let hash = group["hashAlg"].as_str().expect("hashAlg");
            match mode {
                "sigVer" => {
                    let tests = dispatch_hash!(hash, verify_tests, group);
                    json!({"tgId": group["tgId"], "tests": tests})
                }
                "sigGen" => {
                    let bits = group["modulo"].as_u64().expect("modulo");
                    let key = keys.entry(bits).or_insert_with(|| {
                        PrivateKey::generate(&mut rng, bits as usize)
                            .expect("generate")
                    });
                    let tests = dispatch_hash!(hash, sign_tests, key, group);
                    let public = key.public_key();
                    let mut n = vec![0u8; public.modulus_len()];
                    public.modulus_bytes(&mut n).expect("modulus");
                    json!({
                        "tgId": group["tgId"],
                        "n": hex_string(&n),
                        "e": hex_string(trimmed(&public.exponent_bytes())),
                        "tests": tests,
                    })
                }
                other => panic!("unknown mode {other}"),
            }
        })
        .collect();
    response(prompt, groups)
}

/// `bytes` without its leading zeros, as the vectors write numbers.
fn trimmed(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Signs each message of `group` under `key`; PSS with a fresh salt
/// of the group's length.
fn sign_tests<H: DigestInfo + Default>(
    key: &PrivateKey,
    group: &Value,
) -> Vec<Value> {
    let mut rng = CtrDrbg::from_system().expect("generator");
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let message = hex(&t["message"]);
            let sig = match group["sigType"].as_str().expect("sigType") {
                "pkcs1v1.5" => key.sign_pkcs1::<H>(&message),
                "pss" => {
                    let len = group["saltLen"].as_u64().expect("saltLen");
                    let mut salt = vec![0u8; len as usize];
                    rng.fill(&mut salt).expect("salt");
                    key.sign_pss_with_salt::<H>(&message, &salt)
                }
                other => panic!("unknown sigType {other}"),
            }
            .expect("sign");
            json!({"tcId": t["tcId"], "signature": hex_string(sig.as_ref())})
        })
        .collect()
}

/// Verifies each signature of `group` under the group's key.
fn verify_tests<H: DigestInfo + Default>(group: &Value) -> Vec<Value> {
    let n = hex(&group["n"]);
    let key = PublicKey::try_new(&n, &hex(&group["e"])).expect("public key");
    assert_eq!(key.bits() as u64, group["modulo"], "modulus length");
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let message = hex(&t["message"]);
            let sig = hex(&t["signature"]);
            let passed = match group["sigType"].as_str().expect("sigType") {
                "pkcs1v1.5" => key.verify_pkcs1::<H>(&message, &sig).is_ok(),
                "pss" => {
                    let salt = group["saltLen"].as_u64().expect("saltLen");
                    key.verify_pss_with_salt_len::<H>(
                        &message,
                        &sig,
                        salt as usize,
                    )
                    .is_ok()
                }
                other => panic!("unknown sigType {other}"),
            };
            json!({"tcId": t["tcId"], "testPassed": passed})
        })
        .collect()
}

/// Runs the FIPS 186-5 sigVer suite; a no-op without the vendored
/// vectors.
pub fn run_sig_ver() {
    run(
        "RSA-SigVer-FIPS186-5/internalProjection.json",
        "FIPS186-5",
        "sigVer",
        true,
        20,
    );
}

/// Runs the FIPS 186-4 sigVer suite, whose 1024-bit groups are the
/// reason to keep it beside 186-5.
pub fn run_sig_ver_186_4() {
    run(
        "RSA-SigVer-FIPS186-4/internalProjection.json",
        "FIPS186-4",
        "sigVer",
        true,
        144,
    );
}

/// Runs the sigGen file's sample answers as verifications.
pub fn run_sig_gen() {
    run(
        "RSA-SigGen-FIPS186-5/internalProjection.json",
        "FIPS186-5",
        "sigGen",
        false,
        20,
    );
}

/// Verifies every signature of `file`, holding the verdicts to the
/// file's where it has them and expecting acceptance where it does
/// not.
fn run(
    file: &str,
    revision: &str,
    mode: &str,
    has_verdicts: bool,
    least: usize,
) {
    let Some(doc) = load(file, "RSA", revision) else {
        return;
    };
    assert_eq!(doc["mode"], mode);
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if skip_reason(group).is_some() {
            continue;
        }
        let hash = group["hashAlg"].as_str().expect("hashAlg");
        let Some(answered) = dispatch_hash!(hash, verify_tests, group) else {
            continue;
        };
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(&answered) {
            let tag = format!("tgId {} tcId {}", group["tgId"], want["tcId"]);
            if has_verdicts {
                if let Err(why) = check(want, got) {
                    panic!("{tag} {why}");
                }
            } else {
                assert_eq!(got["testPassed"], true, "{tag}");
            }
            if got["testPassed"] == false {
                rejections += 1;
            }
            cases += 1;
        }
    }
    assert!(cases >= least, "only {cases} cases in {file}");
    if has_verdicts {
        assert!(rejections >= 10, "only {rejections} rejections");
    }
}
