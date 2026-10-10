//! ACVP-AES-CFB1 1.0, run through [`Cfb1`] over any block cipher.
//!
//! Segments are single bits. The vectors carry each one in the top
//! bit of a byte, which is how the mode reads them too.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, run_groups,
};
use crate::KeyType;
use crate::cipher::BlockCipher;
use crate::cipher::mode::Cfb1;
use serde_json::{Value, json};

/// The IV as the cipher's block type.
fn block<C: BlockCipher>(bytes: &[u8]) -> C::Block {
    let mut block = C::zero_block();
    block.as_mut().copy_from_slice(bytes);
    block
}

const FILE: &str = "ACVP-AES-CFB1-1.0/internalProjection.json";

/// Steps in a Monte Carlo test.
const MCT_STEPS: usize = 100;

/// Segments (bits) in one Monte Carlo step.
const MCT_SEGMENTS: usize = 1000;

/// Segments the IV holds: 128 bits.
const HISTORY: usize = 128;

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
    suite_groups::<C>(FILE, "ACVP-AES-CFB1", "1.0", test_type)
}

fn cfb<C: BlockCipher>(key: &[u8]) -> Cfb1<C> {
    Cfb1::new(&key_of::<C>(key).expect("key width"))
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

/// One message of `payloadLen` bits, one IV.
fn aft<C: BlockCipher>(t: &Value, encrypt: bool) -> Value {
    let (input, output) = names(encrypt);
    let cfb = cfb::<C>(&hex(&t["key"]));
    let iv = block::<C>(&hex(&t["iv"]));
    let bits = t["payloadLen"].as_u64().expect("payloadLen") as usize;
    let mut data = hex(&t[input]);
    if encrypt {
        cfb.encrypt(&iv, &mut data, bits).expect("bits fit");
    } else {
        cfb.decrypt(&iv, &mut data, bits).expect("bits fit");
    }
    json!({"tcId": t["tcId"], output: hex_string(&data)})
}

/// Monte Carlo Test: 1000 single bits through one continuing state
/// per step. Each step reports its key, IV, input bit and last
/// output bit, each bit at the top of a byte.
fn mct<C: BlockCipher>(t: &Value, encrypt: bool) -> Value {
    let (input_name, output_name) = names(encrypt);
    let mut key = hex(&t["key"]);
    let mut iv = hex(&t["iv"]);
    let mut input = top_bit(&hex(&t[input_name]));
    let mut steps = Vec::with_capacity(MCT_STEPS);
    for _ in 0..MCT_STEPS {
        let mut step = json!({
            "key": hex_string(&key),
            "iv": hex_string(&iv),
            input_name: hex_string(&[input << 7]),
        });
        let cfb = cfb::<C>(&key);
        let mut outputs = [0u8; MCT_SEGMENTS];
        let mut segment = [input << 7];
        if encrypt {
            let mut state = cfb.encryptor(&block::<C>(&iv));
            for j in 0..MCT_SEGMENTS {
                state.update(&mut segment, 1).expect("one bit");
                outputs[j] = segment[0] >> 7;
                segment = [next_input(&iv, &outputs, j) << 7];
            }
        } else {
            let mut state = cfb.decryptor(&block::<C>(&iv));
            for j in 0..MCT_SEGMENTS {
                state.update(&mut segment, 1).expect("one bit");
                outputs[j] = segment[0] >> 7;
                segment = [next_input(&iv, &outputs, j) << 7];
            }
        }

        let last = outputs[MCT_SEGMENTS - 1];
        step[output_name] = json!(hex_string(&[last << 7]));
        steps.push(step);

        let bits = 8 * key.len();
        let tail = pack(&outputs[MCT_SEGMENTS - bits..]);
        for (k, t) in key.iter_mut().zip(&tail) {
            *k ^= t;
        }
        iv = pack(&outputs[MCT_SEGMENTS - HISTORY..]);
        input = outputs[MCT_SEGMENTS - HISTORY - 1];
    }
    json!({"tcId": t["tcId"], "resultsArray": steps})
}

/// The input bit for segment `j + 1`: a bit of the IV until the IV
/// has been shifted out, then the output 128 segments back.
fn next_input(iv: &[u8], outputs: &[u8], j: usize) -> u8 {
    if j < HISTORY {
        (iv[j / 8] >> (7 - j % 8)) & 1
    } else {
        outputs[j - HISTORY]
    }
}

/// The single bit a vector carries in the top of its first byte.
fn top_bit(bytes: &[u8]) -> u8 {
    bytes[0] >> 7
}

/// Packs bits, most significant first, into bytes.
fn pack(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| {
            c.iter()
                .enumerate()
                .fold(0u8, |acc, (i, b)| acc | ((b & 1) << (7 - i)))
        })
        .collect()
}
