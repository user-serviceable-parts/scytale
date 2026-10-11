//! ACVP-PBKDF 1.0. The vendored file exercises HMAC-SHA-224; the
//! driver is generic over the hash and the caller says which groups
//! are its own. The live server sends a group per hash registered,
//! and [`answer`] picks the hash for each.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, response};
use crate::BlockType;
use crate::hash::Hash;
use crate::hash::sha1::Sha1;
use crate::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use crate::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use crate::kdf::pbkdf2::pbkdf2;
use serde_json::{Value, json};

const FILE: &str = "ACVP-PBKDF-1.0/internalProjection.json";

/// The response to a whole vector set, each group on its own hash.
pub fn answer(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            let tests = match group["hmacAlg"].as_str() {
                Some("SHA-1") => tests::<Sha1>(group),
                Some("SHA2-224") => tests::<Sha224>(group),
                Some("SHA2-256") => tests::<Sha256>(group),
                Some("SHA2-384") => tests::<Sha384>(group),
                Some("SHA2-512") => tests::<Sha512>(group),
                Some("SHA2-512/224") => tests::<Sha512_224>(group),
                Some("SHA2-512/256") => tests::<Sha512_256>(group),
                Some("SHA3-224") => tests::<Sha3_224>(group),
                Some("SHA3-256") => tests::<Sha3_256>(group),
                Some("SHA3-384") => tests::<Sha3_384>(group),
                Some("SHA3-512") => tests::<Sha3_512>(group),
                other => panic!("unknown hmacAlg {other:?}"),
            };
            json!({"tgId": group["tgId"], "tests": tests})
        })
        .collect();
    response(prompt, groups)
}

/// Runs the groups whose `hmacAlg` is `hmac_alg` against `H`; a
/// no-op without the vendored vectors.
pub fn run_aft<H: Hash + Clone + BlockType + Default>(hmac_alg: &str) {
    let Some(doc) = load(FILE, "PBKDF", "1.0") else {
        return;
    };
    let mut count = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["hmacAlg"] != hmac_alg {
            continue;
        }
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(tests::<H>(group)) {
            if let Err(why) = check(want, &got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            count += 1;
        }
    }
    assert!(count >= 1, "no {hmac_alg} cases");
}

/// The response to each test of a group: the derived key.
fn tests<H: Hash + Clone + BlockType + Default>(group: &Value) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let password = t["password"].as_str().expect("password");
            let salt = hex(&t["salt"]);
            let iterations =
                t["iterationCount"].as_u64().expect("iterationCount") as u32;
            let bits = t["keyLen"].as_u64().expect("keyLen") as usize;
            let mut key = vec![0u8; bits.div_ceil(8)];
            pbkdf2::<H>(password.as_bytes(), &salt, iterations, &mut key)
                .expect("derive");
            json!({"tcId": t["tcId"], "derivedKey": hex_string(&key)})
        })
        .collect()
}
