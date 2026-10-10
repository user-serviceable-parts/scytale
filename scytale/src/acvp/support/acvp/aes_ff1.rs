//! ACVP-AES-FF1 1.0, run through [`Ff1`] over any block cipher.
//!
//! The vectors give messages as text in a stated alphabet. [`Ff1`]
//! works in symbol values, so each character is turned into its
//! position in that alphabet and back again.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::aes_ff3_1::{symbols, text};
use super::{Answers, groups as suite_groups, hex, key_of, run_groups};
use crate::KeyType;
use crate::cipher::BlockCipher;
use crate::cipher::mode::Ff1;
use serde_json::{Value, json};

const FILE: &str = "ACVP-AES-FF1-1.0/internalProjection.json";

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
    let count = run_groups(&groups, tests::<C>);
    assert!(count >= 233, "only {count} AFT cases");
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-FF1", "1.0", test_type)
}

/// The response to each test of a group.
fn tests<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
    let alphabet = group["alphabet"].as_str().expect("alphabet");
    let radix = group["radix"].as_u64().expect("radix") as u32;
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let key = key_of::<C>(&hex(&t["key"])).expect("key width");
            let ff1 = Ff1::<C>::try_new(&key, radix).expect("radix");
            let tweak = hex(&t["tweak"]);
            let message = t[input].as_str().expect("text");
            let mut data = symbols(message, alphabet);
            if encrypt {
                ff1.encrypt(&tweak, &mut data).expect("encrypt");
            } else {
                ff1.decrypt(&tweak, &mut data).expect("decrypt");
            }
            json!({"tcId": t["tcId"], output: text(&data, alphabet)})
        })
        .collect()
}
