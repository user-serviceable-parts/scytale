//! KDA HKDF (SP 800-56Cr2): HKDF as the key-derivation step of a
//! key agreement. The input keying material is the hybrid shared
//! secret `Z || T`, and the info string is built from both parties'
//! identifiers and ephemeral data with the derived length appended,
//! which is the one fixed-info pattern the vendored file uses.
//!
//! The multi-expansion groups extract once and then expand several
//! times, each expansion with its own fixed info and length, which
//! is [`hkdf::extract`] followed by repeated [`hkdf::expand`].

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, rejected, response};
use crate::BlockType;
use crate::hash::Hash;
use crate::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use crate::hash::sha2::{Sha512_224, Sha512_256};
use crate::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use crate::kdf::hkdf;
use serde_json::{Value, json};

/// Dispatches on the group's HMAC hash, which names the whole
/// derivation. Both flows need the same ten arms.
macro_rules! with_hash {
    ($alg:expr, $f:ident($($arg:expr),*)) => {
        match $alg {
            "SHA2-224" => $f::<Sha224>($($arg),*),
            "SHA2-256" => $f::<Sha256>($($arg),*),
            "SHA2-384" => $f::<Sha384>($($arg),*),
            "SHA2-512" => $f::<Sha512>($($arg),*),
            "SHA2-512/224" => $f::<Sha512_224>($($arg),*),
            "SHA2-512/256" => $f::<Sha512_256>($($arg),*),
            "SHA3-224" => $f::<Sha3_224>($($arg),*),
            "SHA3-256" => $f::<Sha3_256>($($arg),*),
            "SHA3-384" => $f::<Sha3_384>($($arg),*),
            "SHA3-512" => $f::<Sha3_512>($($arg),*),
            other => panic!("unknown hash {other}"),
        }
    };
}

/// The response to a whole vector set.
pub fn answer(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| json!({"tgId": group["tgId"], "tests": tests(group)}))
        .collect();
    response(prompt, groups)
}

/// Runs the suite; a no-op without the vendored vectors.
pub fn run() {
    let file = "KDA-HKDF-Sp800-56Cr2/internalProjection.json";
    let Some(doc) = load(file, "KDA", "Sp800-56Cr2") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let answers = tests(group);
        rejections += rejected(&answers);
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(&answers) {
            if let Err(why) = check(want, got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            cases += 1;
        }
    }
    assert!(cases >= 1500, "only {cases} cases");
    assert!(rejections >= 150, "only {rejections} rejections");
}

/// The response to each test of a group: the derived key material
/// for a derivation (AFT), the verdict on supplied material for a
/// validation (VAL).
fn tests(group: &Value) -> Vec<Value> {
    // A group is one flow or the other, named by its configuration;
    // the multi-expansion one has no fixed-info pattern because each
    // expansion carries its own.
    let alg = match group.get("kdfConfiguration") {
        Some(cfg) => {
            assert_eq!(cfg["fixedInfoPattern"], "uPartyInfo||vPartyInfo||l");
            assert_eq!(cfg["fixedInfoEncoding"], "concatenation");
            cfg["hmacAlg"].as_str().expect("hmacAlg")
        }
        None => {
            let cfg = &group["kdfMultiExpansionConfiguration"];
            assert_eq!(cfg["kdfType"], "hkdf");
            cfg["hmacAlg"].as_str().expect("hmacAlg")
        }
    };
    let multi = group.get("kdfConfiguration").is_none();
    let validate = match group["testType"].as_str() {
        Some("AFT") => false,
        Some("VAL") => true,
        other => panic!("unknown testType {other:?}"),
    };
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            if multi {
                let dkms = with_hash!(alg, multi_case(t));
                if validate {
                    let given: Vec<Vec<u8>> = t["dkms"]
                        .as_array()
                        .expect("dkms")
                        .iter()
                        .map(hex)
                        .collect();
                    let passed = dkms == given;
                    return json!({"tcId": t["tcId"], "testPassed": passed});
                }
                let dkms: Vec<String> =
                    dkms.iter().map(|d| hex_string(d)).collect();
                json!({"tcId": t["tcId"], "dkms": dkms})
            } else {
                let dkm = with_hash!(alg, case(t));
                if validate {
                    let passed = dkm == hex(&t["dkm"]);
                    return json!({"tcId": t["tcId"], "testPassed": passed});
                }
                json!({"tcId": t["tcId"], "dkm": hex_string(&dkm)})
            }
        })
        .collect()
}

/// The derived length in bits, which one flow records as a string
/// and the other as a number.
fn bits(v: &Value) -> u32 {
    match v {
        Value::String(s) => s.parse::<u32>().expect("l"),
        v => v.as_u64().expect("l") as u32,
    }
}

/// One extract and several expansions, each with its own fixed info
/// and length. The PRK is computed once, which is the whole point of
/// the flow.
fn multi_case<H: Hash + Clone + BlockType + Default>(
    t: &Value,
) -> Vec<Vec<u8>> {
    let param = &t["kdfMultiExpansionParameter"];
    let salt = hex(&param["salt"]);
    let mut ikm = hex(&param["z"]);
    ikm.extend_from_slice(&hex(&param["t"]));
    let prk = hkdf::extract::<H>(&salt, &ikm);

    param["iterationParameters"]
        .as_array()
        .expect("iterationParameters")
        .iter()
        .map(|iteration| {
            let l_bits = bits(&iteration["l"]);
            let info = hex(&iteration["fixedInfo"]);
            let mut dkm = vec![0u8; l_bits as usize / 8];
            hkdf::expand::<H>(prk.as_ref(), &[&info], &mut dkm)
                .expect("expand");
            dkm
        })
        .collect()
}

/// One derivation.
fn case<H: Hash + Clone + BlockType + Default>(t: &Value) -> Vec<u8> {
    let param = &t["kdfParameter"];
    let salt = hex(&param["salt"]);
    // The hybrid shared secret: the classical part then the
    // auxiliary part, in the order the standard fixes.
    let mut ikm = hex(&param["z"]);
    ikm.extend_from_slice(&hex(&param["t"]));

    let l_bits = bits(&param["l"]);
    let mut info = Vec::new();
    for party in ["fixedInfoPartyU", "fixedInfoPartyV"] {
        let p = &t[party];
        info.extend_from_slice(&hex(&p["partyId"]));
        if !p["ephemeralData"].is_null() {
            info.extend_from_slice(&hex(&p["ephemeralData"]));
        }
    }
    info.extend_from_slice(&l_bits.to_be_bytes());

    let mut dkm = vec![0u8; l_bits as usize / 8];
    hkdf::derive::<H>(&salt, &ikm, &[&info], &mut dkm).expect("derive");
    dkm
}
