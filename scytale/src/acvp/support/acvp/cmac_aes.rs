//! CMAC-AES 1.0, run through [`Cmac`] over any block cipher and the
//! [`Mac`] trait.
//!
//! Generation and verification at every key width, with messages of
//! no bytes, a partial last block and many blocks, and tags of 64, 88
//! and 128 bits. A verification case marked as not passing carries a
//! tag that must be refused.
//!
//! The directions here are `gen` and `ver` rather than encrypt and
//! decrypt, so the suite dispatches its key widths itself rather
//! than through [`answer_aes`](super::answer_aes).

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, key_of, load, rejected, response};
use crate::cipher::BlockCipher;
use crate::cipher::aes::Aes;
use crate::constant_time;
use crate::mac::Mac;
use crate::mac::cmac::Cmac;
use serde_json::{Value, json};

const FILE: &str = "CMAC-AES-1.0/internalProjection.json";

/// The response to a whole vector set, on the cipher this processor
/// picks.
pub fn answer(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            let tests = match group["keyLen"].as_u64() {
                Some(128) => tests::<Aes<16>>(group),
                Some(192) => tests::<Aes<24>>(group),
                Some(256) => tests::<Aes<32>>(group),
                other => panic!("keyLen {other:?}"),
            };
            json!({"tgId": group["tgId"], "tests": tests})
        })
        .collect();
    response(prompt, groups)
}

/// Runs every case at `C`'s key width; a no-op without the vendored
/// vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(doc) = load(FILE, "CMAC-AES", "1.0") else {
        return;
    };
    let bits = 8 * C::zero_key().as_ref().len() as u64;
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["keyLen"].as_u64() != Some(bits) {
            continue;
        }
        let answers = tests::<C>(group);
        rejections += rejected(&answers);
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(&answers) {
            if let Err(why) = check(want, got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            cases += 1;
        }
    }
    // Guard against a truncated or wrong file passing vacuously, and
    // against the rejection cases quietly disappearing. The file has
    // 252 cases a width, 42 or more of them rejections.
    assert!(cases >= 252, "only {cases} cases");
    assert!(rejections >= 42, "only {rejections} rejections");
}

/// The response to each test of a group: the tag for `gen`, the
/// verdict for `ver`.
fn tests<C: BlockCipher<Block = [u8; 16]>>(group: &Value) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
    let generate = match group["direction"].as_str() {
        Some("gen") => true,
        Some("ver") => false,
        other => panic!("unknown direction {other:?}"),
    };
    let mac_len = group["macLen"].as_u64().expect("macLen") as usize / 8;
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let key = key_of::<C>(&hex(&t["key"])).expect("key width");
            let mut mac = Cmac::<C>::new(&key);
            let message = hex(&t["message"]);
            mac.update(&message);
            let tag = mac.finalize();
            if generate {
                return json!({
                    "tcId": t["tcId"],
                    "mac": hex_string(&tag[..mac_len]),
                });
            }
            // A tag cut short is compared as a prefix, in constant
            // time, as a protocol that truncates would check it.
            let given = hex(&t["mac"]);
            let passed = given.len() == mac_len
                && constant_time::equal(&tag[..mac_len], &given);
            // A full tag goes through the trait's check as well;
            // `finalize` left the MAC keyed and ready.
            if mac_len == tag.len() {
                mac.update(&message);
                assert_eq!(mac.verify(&given).is_ok(), passed, "{}", t["tcId"]);
            }
            json!({"tcId": t["tcId"], "testPassed": passed})
        })
        .collect()
}
