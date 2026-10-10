//! ACVP-AES-KW 1.0, run through [`Kw`] over any block cipher.
//!
//! The suite covers both cipher directions the standard allows, both
//! wrapping and unwrapping, and a large number of unwrapping cases
//! that are meant to fail, which is what checks that an altered
//! wrapping is refused rather than quietly accepted.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, rejected,
    run_groups,
};
use crate::Error;
use crate::KeyType;
use crate::cipher::BlockCipher;
use crate::cipher::mode::Kw;
use serde_json::{Value, json};

const FILE: &str = "ACVP-AES-KW-1.0/internalProjection.json";

/// The suite, for [`answer_aes`](super::answer_aes).
pub struct Suite;

impl Answers for Suite {
    fn tests<C: BlockCipher<Block = [u8; 16]>>(
        group: &Value,
        encrypt: bool,
    ) -> Vec<Value> {
        tests::<C>(group, encrypt)
    }
}

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("AFT") else {
        return;
    };
    let mut rejections = 0;
    let cases = run_groups(&groups, |group, encrypt| {
        let answers = tests::<C>(group, encrypt);
        rejections += rejected(&answers);
        answers
    });
    // Guard against a truncated or wrong file passing vacuously, and
    // against the rejection cases quietly disappearing.
    assert!(cases >= 1666, "only {cases} AFT cases");
    assert!(rejections >= 33, "only {rejections} had to be rejected");
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-KW", "1.0", test_type)
}

/// Whether a group builds the wrapping on the forward cipher. The
/// standard allows either direction, and the suite exercises both.
pub fn forward(group: &Value) -> bool {
    match group["kwCipher"].as_str() {
        Some("cipher") => true,
        Some("inverse") => false,
        other => panic!("unknown kwCipher {other:?}"),
    }
}

/// The response to each test of a group.
fn tests<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
    let forward = forward(group);
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let key = key_of::<C>(&hex(&t["key"])).expect("key width");
            let kw = if forward {
                Kw::<C>::new(&key)
            } else {
                Kw::<C>::new_inverse(&key)
            };
            if encrypt {
                let plain = hex(&t["pt"]);
                let mut out = vec![0u8; plain.len() + 8];
                let n = kw.wrap(&plain, &mut out).expect("wrap");
                return json!({"tcId": t["tcId"], "ct": hex_string(&out[..n])});
            }
            let wrapped = hex(&t["ct"]);
            let mut out = vec![0u8; wrapped.len()];
            match kw.unwrap(&wrapped, &mut out) {
                Ok(n) => {
                    json!({"tcId": t["tcId"], "pt": hex_string(&out[..n])})
                }
                Err(Error::AuthenticationFailed) => {
                    json!({"tcId": t["tcId"], "testPassed": false})
                }
                Err(e) => panic!("tcId {}: {e}", t["tcId"]),
            }
        })
        .collect()
}
