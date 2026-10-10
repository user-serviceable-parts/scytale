//! ACVP-AES-OFB 1.0, run through [`Ofb`] over any block cipher.
//!
//! The Monte Carlo test has the same shape as the one for cipher
//! feedback with full-block segments: 1000 blocks through a single
//! continuing state, each input being the IV and then the output one
//! block back.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, run_groups,
};
use crate::KeyType;
use crate::cipher::BlockCipher;
use crate::cipher::mode::Ofb;
use serde_json::{Value, json};

/// The IV as the cipher's block type.
fn block<C: BlockCipher>(bytes: &[u8]) -> C::Block {
    let mut block = C::zero_block();
    block.as_mut().copy_from_slice(bytes);
    block
}

const FILE: &str = "ACVP-AES-OFB-1.0/internalProjection.json";

/// Steps in a Monte Carlo test.
const MCT_STEPS: usize = 100;

/// Segments in one Monte Carlo step.
const MCT_SEGMENTS: usize = 1000;

/// Blocks of history the IV holds: one.
const HISTORY: usize = 1;

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

pub fn run_aft<C: BlockCipher>() {
    let Some(groups) = groups::<C>("AFT") else {
        return;
    };
    let count = run_groups(&groups, tests::<C>);
    assert!(count >= 500, "only {count} AFT cases");
}

pub fn run_mct<C: BlockCipher>() {
    let Some(groups) = groups::<C>("MCT") else {
        return;
    };
    let count = run_groups(&groups, tests::<C>);
    assert!(count >= 2, "only {count} MCT cases");
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-OFB", "1.0", test_type)
}

fn ofb<C: BlockCipher>(key: &[u8]) -> Ofb<C> {
    Ofb::new(&key_of::<C>(key).expect("key width"))
}

/// The response to each test of a group.
fn tests<C: BlockCipher>(group: &Value, encrypt: bool) -> Vec<Value> {
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| match group["testType"].as_str() {
            Some("AFT") => aft::<C>(t, encrypt),
            Some("MCT") => mct::<C>(t, encrypt),
            other => panic!("unknown testType {other:?}"),
        })
        .collect()
}

/// The names of a direction's input and output.
fn names(encrypt: bool) -> (&'static str, &'static str) {
    if encrypt { ("pt", "ct") } else { ("ct", "pt") }
}

fn aft<C: BlockCipher>(t: &Value, encrypt: bool) -> Value {
    let (input, output) = names(encrypt);
    let ofb = ofb::<C>(&hex(&t["key"]));
    let iv = block::<C>(&hex(&t["iv"]));
    let mut data = hex(&t[input]);
    if encrypt {
        ofb.encrypt(&iv, &mut data);
    } else {
        ofb.decrypt(&iv, &mut data);
    }
    json!({"tcId": t["tcId"], output: hex_string(&data)})
}

/// Monte Carlo Test. One step is 1000 segments through a single
/// continuing state; each segment's input is a segment of the IV
/// while the register still holds IV material, and an earlier output
/// after that. Each step reports its key, IV, input and last output.
fn mct<C: BlockCipher>(t: &Value, encrypt: bool) -> Value {
    let (input_name, output_name) = names(encrypt);
    let mut key = hex(&t["key"]);
    let mut iv = hex(&t["iv"]);
    let mut input = hex(&t[input_name]);
    let mut steps = Vec::with_capacity(MCT_STEPS);
    for _ in 0..MCT_STEPS {
        let mut step = json!({
            "key": hex_string(&key),
            "iv": hex_string(&iv),
            input_name: hex_string(&input),
        });
        let ofb = ofb::<C>(&key);
        let mut outputs: Vec<Vec<u8>> = Vec::with_capacity(MCT_SEGMENTS);
        // One state serves both directions: the keystream does not
        // depend on the message.
        let mut segment = input.clone();
        let mut state = ofb.stream(&block::<C>(&iv));
        for j in 0..MCT_SEGMENTS {
            state.update(&mut segment);
            outputs.push(segment.clone());
            segment = next_input(&iv, &outputs, j);
        }

        let last = &outputs[MCT_SEGMENTS - 1];
        step[output_name] = json!(hex_string(last));
        steps.push(step);

        // The tail of the outputs supplies the next key, IV and
        // input. The key takes the last bytes of the stream, which
        // for a 192-bit key is part of one segment and all of the
        // next.
        let size = last.len();
        let segments = key.len().div_ceil(size);
        let recent: Vec<u8> = outputs[MCT_SEGMENTS - segments..].concat();
        let tail = &recent[recent.len() - key.len()..];
        for (k, t) in key.iter_mut().zip(tail) {
            *k ^= t;
        }
        iv = outputs[MCT_SEGMENTS - HISTORY..].concat();
        input = outputs[MCT_SEGMENTS - HISTORY - 1].clone();
    }
    json!({"tcId": t["tcId"], "resultsArray": steps})
}

/// The input for segment `j + 1`: a segment of the IV until the IV
/// has been consumed, then the output `HISTORY` segments back.
fn next_input(iv: &[u8], outputs: &[Vec<u8>], j: usize) -> Vec<u8> {
    if j < HISTORY {
        iv.to_vec()
    } else {
        outputs[j - HISTORY].clone()
    }
}
