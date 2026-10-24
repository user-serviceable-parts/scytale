//! KDA OneStep and OneStepNoCounter Sp800-56Cr2, run through
//! [`one_step`](crate::kdf::one_step), and kdf-components ANSI X9.63
//! 1.0, run through [`x963`](crate::kdf::x963).
//!
//! The one-step files build the fixed info from the auxiliary
//! secret `t`, both parties' identifiers and ephemeral data, and the
//! derived length in bits, which is the one pattern they use. Their
//! validation groups carry deliberately wrong key material, marked by
//! the verdict.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, rejected, response};
use crate::BlockType;
use crate::hash::Hash;
use crate::hash::sha1::Sha1;
use crate::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use crate::hash::sha2::{Sha512_224, Sha512_256};
use crate::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use crate::kdf::{one_step, x963};
use crate::mac::hmac::Hmac;
use serde_json::{Value, json};

/// Calls `$f::<H>` for the hash `$alg` names.
macro_rules! with_hash {
    ($alg:expr, $f:ident($($arg:expr),*)) => {
        match $alg {
            "SHA-1" => $f::<Sha1>($($arg),*),
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

/// The inputs of one derivation.
struct Inputs<'a> {
    salt: &'a [u8],
    z: &'a [u8],
    fixed_info: &'a [u8],
    out: &'a mut [u8],
    counter: bool,
}

/// The response to a OneStep or OneStepNoCounter vector set, which
/// the prompt's mode tells apart.
pub fn answer(prompt: &Value) -> Value {
    let counter = match prompt["mode"].as_str() {
        Some("OneStep") => true,
        Some("OneStepNoCounter") => false,
        other => panic!("unknown mode {other:?}"),
    };
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            json!({"tgId": group["tgId"], "tests": tests(group, counter)})
        })
        .collect();
    response(prompt, groups)
}

/// Runs a one-step file, with the counter or without; a no-op
/// without the vendored vectors.
pub fn run(file: &str, mode: &str) {
    let Some(doc) = load(file, "KDA", "Sp800-56Cr2") else {
        return;
    };
    assert_eq!(doc["mode"], mode);
    let counter = mode == "OneStep";
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let answers = tests(group, counter);
        rejections += rejected(&answers);
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(&answers) {
            if let Err(why) = check(want, got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            cases += 1;
        }
    }
    assert!(cases >= 500, "only {cases} cases in {file}");
    assert!(rejections >= 20, "only {rejections} rejections in {file}");
}

/// The response to each test of a group: the derived key material
/// for a derivation (AFT), the verdict on supplied material for a
/// validation (VAL).
fn tests(group: &Value, counter: bool) -> Vec<Value> {
    let cfg = &group["kdfConfiguration"];
    assert_eq!(cfg["fixedInfoPattern"], "t||uPartyInfo||vPartyInfo||l");
    assert_eq!(cfg["fixedInfoEncoding"], "concatenation");
    let aux = cfg["auxFunction"].as_str().expect("auxFunction");
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
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let param = &t["kdfParameter"];
            let bits = param["l"].as_u64().expect("l") as u32;
            assert_eq!(bits % 8, 0, "{tag}: a length in bits");

            let mut fixed_info = hex(&param["t"]);
            for party in ["fixedInfoPartyU", "fixedInfoPartyV"] {
                let p = &t[party];
                fixed_info.extend_from_slice(&hex(&p["partyId"]));
                if !p["ephemeralData"].is_null() {
                    fixed_info.extend_from_slice(&hex(&p["ephemeralData"]));
                }
            }
            fixed_info.extend_from_slice(&bits.to_be_bytes());

            let salt = if param["salt"].is_null() {
                Vec::new()
            } else {
                hex(&param["salt"])
            };
            let mut out = vec![0u8; bits as usize / 8];
            let inputs = Inputs {
                salt: &salt,
                z: &hex(&param["z"]),
                fixed_info: &fixed_info,
                out: &mut out,
                counter,
            };
            match aux.strip_prefix("HMAC-") {
                Some(alg) => with_hash!(alg, hmac(inputs)),
                None => match aux {
                    "KMAC-128" | "KMAC-256" => kmac(aux, inputs),
                    alg => with_hash!(alg, hash(inputs)),
                },
            }
            if validate {
                let passed = out == hex(&t["dkm"]);
                return json!({"tcId": t["tcId"], "testPassed": passed});
            }
            json!({"tcId": t["tcId"], "dkm": hex_string(&out)})
        })
        .collect()
}

fn hash<H: Hash + Default>(i: Inputs<'_>) {
    let fixed: [&[u8]; 1] = [i.fixed_info];
    if i.counter {
        one_step::hash::<H>(i.z, &fixed, i.out)
    } else {
        one_step::hash_no_counter::<H>(i.z, &fixed, i.out)
    }
    .expect("derive");
}

fn hmac<H: Hash + Clone + BlockType + Default>(i: Inputs<'_>) {
    let fixed: [&[u8]; 1] = [i.fixed_info];
    let mut mac = Hmac::<H>::new(i.salt);
    if i.counter {
        one_step::mac(&mut mac, i.z, &fixed, i.out)
    } else {
        one_step::mac_no_counter(&mut mac, i.z, &fixed, i.out)
    }
    .expect("derive");
}

fn kmac(aux: &str, i: Inputs<'_>) {
    let fixed: [&[u8]; 1] = [i.fixed_info];
    let kdf = match (aux, i.counter) {
        ("KMAC-128", true) => one_step::kmac128,
        ("KMAC-128", false) => one_step::kmac128_no_counter,
        ("KMAC-256", true) => one_step::kmac256,
        ("KMAC-256", false) => one_step::kmac256_no_counter,
        (other, _) => panic!("unknown auxFunction {other}"),
    };
    kdf(i.salt, i.z, &fixed, i.out);
}

/// The response to an ANSI X9.63 vector set.
pub fn answer_x963(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| json!({"tgId": group["tgId"], "tests": x963_tests(group)}))
        .collect();
    response(prompt, groups)
}

/// Runs the ANSI X9.63 file; a no-op without the vendored vectors.
pub fn run_x963() {
    let file = "kdf-components-ansix9.63-1.0/internalProjection.json";
    let Some(doc) = load(file, "kdf-components", "1.0") else {
        return;
    };
    assert_eq!(doc["mode"], "ansix9.63");
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(x963_tests(group)) {
            if let Err(why) = check(want, &got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            cases += 1;
        }
    }
    assert!(cases >= 900, "only {cases} cases");
}

/// The response to each test of an X9.63 group: the key data.
fn x963_tests(group: &Value) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT");
    let alg = group["hashAlg"].as_str().expect("hashAlg");
    let bits = group["keyDataLength"].as_u64().expect("keyDataLength");
    assert_eq!(bits % 8, 0, "tgId {}: a length in bits", group["tgId"]);
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let mut out = vec![0u8; bits as usize / 8];
            with_hash!(alg, x963_case(t, &mut out));
            json!({"tcId": t["tcId"], "keyData": hex_string(&out)})
        })
        .collect()
}

fn x963_case<H: Hash + Default>(t: &Value, out: &mut [u8]) {
    let shared: [&[u8]; 1] = [&hex(&t["sharedInfo"])];
    x963::derive::<H>(&hex(&t["z"]), &shared, out).expect("derive");
}
