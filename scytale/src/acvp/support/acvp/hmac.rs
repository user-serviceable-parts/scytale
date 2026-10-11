//! ACVP-HMAC 1.0, run through [`Hmac`] over the hash and the
//! [`Mac`] trait. One driver serves every variant; the caller names
//! the file.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, response};
use crate::BlockType;
use crate::hash::Hash;
use crate::mac::Mac;
use crate::mac::hmac::Hmac;
use serde_json::{Value, json};

/// The response to a whole vector set.
pub fn answer<H: Hash + Clone + BlockType + Default>(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| json!({"tgId": group["tgId"], "tests": tests::<H>(group)}))
        .collect();
    response(prompt, groups)
}

/// Runs every case against HMAC over `H`; a no-op without the
/// vendored vectors. Tags are compared over `macLen` bits, a prefix
/// of the full tag. The vectors' keys come in every length, so the
/// any-length constructor keys the MAC.
pub fn run_aft<H: Hash + Clone + BlockType + Default>(
    file: &str,
    algorithm: &str,
) {
    let Some(doc) = load(file, algorithm, "1.0") else {
        return;
    };
    let mut count = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(tests::<H>(group)) {
            if let Err(why) = check(want, &got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            count += 1;
        }
    }
    assert!(count >= 500, "only {count} cases");
}

/// The response to each test of a group: the tag, cut to the
/// group's length.
fn tests<H: Hash + Clone + BlockType + Default>(group: &Value) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
    let mac_bytes = group["macLen"].as_u64().expect("macLen") as usize / 8;
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let mut mac = Hmac::<H>::new(&hex(&t["key"]));
            let msg = hex(&t["msg"]);
            mac.update(&msg);
            let tag = mac.finalize();
            let tag = tag.as_ref();
            // A full-length tag must verify too; `finalize` left the
            // MAC keyed and at the start of a message.
            if mac_bytes == tag.len() {
                mac.update(&msg);
                mac.verify(tag).expect("verify");
            }
            json!({"tcId": t["tcId"], "mac": hex_string(&tag[..mac_bytes])})
        })
        .collect()
}
