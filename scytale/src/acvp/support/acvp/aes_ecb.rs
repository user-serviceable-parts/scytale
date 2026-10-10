//! ACVP-AES-ECB 1.0, run through the [`BlockCipher`] trait.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, cipher_of, groups as suite_groups, hex, hex_string, run_groups,
};
use crate::KeyType;
use crate::cipher::BlockCipher;
use serde_json::{Value, json};

const FILE: &str = "ACVP-AES-ECB-1.0/internalProjection.json";

/// Steps in a Monte Carlo test.
const MCT_STEPS: usize = 100;

/// Iterations of each Monte Carlo step (ACVP AES MCT).
const MCT_ITERATIONS: usize = 1000;

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
    // Guard against a truncated or wrong file passing vacuously.
    assert!(count >= 333, "only {count} AFT cases");
}

/// Runs the Monte Carlo (MCT) groups against `C`; a no-op without the
/// vendored vectors. Slow: 600,000 cipher calls.
pub fn run_mct<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("MCT") else {
        return;
    };
    let count = run_groups(&groups, tests::<C>);
    assert!(count >= 2, "only {count} MCT cases");
}

/// The groups of one test type; `None` without the vectors.
fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-ECB", "1.0", test_type)
}

/// The response to each test of a group.
fn tests<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> Vec<Value> {
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

fn apply<C: BlockCipher<Block = [u8; 16]>>(
    cipher: &C,
    encrypt: bool,
    data: &mut [u8],
) {
    let (blocks, rest) = data.as_chunks_mut::<16>();
    assert!(rest.is_empty(), "whole blocks");
    if encrypt {
        cipher.encrypt(blocks);
    } else {
        cipher.decrypt(blocks);
    }
}

/// The names of a direction's input and output.
fn names(encrypt: bool) -> (&'static str, &'static str) {
    if encrypt { ("pt", "ct") } else { ("ct", "pt") }
}

/// Algorithm Functional Test: one-shot, possibly several blocks.
fn aft<C: BlockCipher<Block = [u8; 16]>>(t: &Value, encrypt: bool) -> Value {
    let (input, output) = names(encrypt);
    let cipher = cipher_of::<C>(&hex(&t["key"])).expect("key width");
    let mut data = hex(&t[input]);
    apply(&cipher, encrypt, &mut data);
    json!({"tcId": t["tcId"], output: hex_string(&data)})
}

/// Monte Carlo Test, per the ACVP AES MCT for ECB: each of 100 steps
/// runs 1000 chained cipher calls, then derives the next key from the
/// last outputs. Each step reports its key and input and the output
/// of its final call.
fn mct<C: BlockCipher<Block = [u8; 16]>>(t: &Value, encrypt: bool) -> Value {
    let (input_name, output_name) = names(encrypt);
    let mut key = hex(&t["key"]);
    let mut data = hex(&t[input_name]);
    let mut steps = Vec::with_capacity(MCT_STEPS);
    for _ in 0..MCT_STEPS {
        let mut step = json!({
            "key": hex_string(&key),
            input_name: hex_string(&data),
        });
        let cipher = cipher_of::<C>(&key).expect("key width");
        let mut previous = data.clone();
        for _ in 0..MCT_ITERATIONS {
            previous.copy_from_slice(&data);
            apply(&cipher, encrypt, &mut data);
        }
        step[output_name] = json!(hex_string(&data));
        steps.push(step);

        // Next key: xor with the last 16, 24 or 32 bytes of the
        // last two outputs, most recent last.
        let mut tail = previous;
        tail.extend_from_slice(&data);
        let tail = &tail[tail.len() - key.len()..];
        for (k, t) in key.iter_mut().zip(tail) {
            *k ^= t;
        }
    }
    json!({"tcId": t["tcId"], "resultsArray": steps})
}
