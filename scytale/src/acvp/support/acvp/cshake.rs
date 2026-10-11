//! cSHAKE 1.0, run through the cSHAKE core over one implementation's
//! sponge: the one-shot test, and the Monte Carlo test whose output
//! length and customization wander.
//!
//! Lengths here are in bits. ACVP keeps the bits of a partial last
//! byte at its top; SHA-3 numbers them from the bottom. Messages are
//! moved down as `sha::Message` already does for SHA-3, and outputs
//! moved up before they are compared.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::sha::{Family, Message};
use super::{check, hex, hex_string, load, response};
use crate::hash::XofReader;
use crate::hash::sha3::SuffixXof;
use crate::hash::sha3::cshake::Core;
use serde_json::{Value, json};

/// Steps in a Monte Carlo test as the server runs it. The vendored
/// file keeps only the first few.
const MCT_STEPS: usize = 100;

/// The response to a whole vector set over the sponge `X`.
pub fn answer<X: SuffixXof>(prompt: &Value, start: fn() -> X) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            let tests: Vec<Value> = group["tests"]
                .as_array()
                .expect("tests")
                .iter()
                .map(|t| match group["testType"].as_str() {
                    Some("AFT") => aft(group, t, start),
                    Some("MCT") => mct(group, t, MCT_STEPS, start),
                    other => panic!("unknown testType {other:?}"),
                })
                .collect();
            json!({"tgId": group["tgId"], "tests": tests})
        })
        .collect();
    response(prompt, groups)
}

/// Runs the one-shot groups against the sponge `X`; a no-op without
/// the vendored vectors.
pub fn run_aft<X: SuffixXof>(file: &str, algorithm: &str, start: fn() -> X) {
    let Some(doc) = load(file, algorithm, "1.0") else {
        return;
    };
    let mut count = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["testType"] != "AFT" {
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            if let Err(why) = check(t, &aft(group, t, start)) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            count += 1;
        }
    }
    assert!(count >= 100, "only {count} cases");
}

/// Runs the Monte Carlo groups against `X`, for as many steps as
/// the file keeps; a no-op without the vendored vectors.
pub fn run_mct<X: SuffixXof>(file: &str, algorithm: &str, start: fn() -> X) {
    let Some(doc) = load(file, algorithm, "1.0") else {
        return;
    };
    let mut count = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["testType"] != "MCT" {
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let steps = t["resultsArray"].as_array().expect("steps").len();
            if let Err(why) = check(t, &mct(group, t, steps, start)) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            count += steps;
        }
    }
    assert!(count >= 3, "only {count} MCT steps");
}

/// A string field's bytes.
fn text(v: &Value) -> Vec<u8> {
    v.as_str().expect("string").as_bytes().to_vec()
}

/// The customization, given as text or, in a hex group, as hex.
fn customization(group: &Value, t: &Value) -> Vec<u8> {
    if group["hexCustomization"].as_bool() == Some(true) {
        hex(&t["customizationHex"])
    } else {
        text(&t["customization"])
    }
}

/// One message, `outLen` bits of output.
fn aft<X: SuffixXof>(group: &Value, t: &Value, start: fn() -> X) -> Value {
    let bits = t["outLen"].as_u64().expect("outLen") as usize;
    let name = text(&t["functionName"]);
    let custom = customization(group, t);
    let out = squeeze(&Message::of(t), &name, &custom, bits, start);
    json!({"tcId": t["tcId"], "md": hex_string(&out), "outLen": bits})
}

/// cSHAKE of `message` under `name` and `custom`, `bits` of output,
/// laid out as ACVP lays out a bit string.
fn squeeze<X: SuffixXof>(
    message: &Message,
    name: &[u8],
    custom: &[u8],
    bits: usize,
    start: fn() -> X,
) -> Vec<u8> {
    let sponge = start();
    let mut xof = Core::with(sponge, name, custom);
    let (whole, tail) = message.split(Family::Sha3);
    xof.update(whole);
    let (last, extra) = tail.unwrap_or((0, 0));
    let mut out = vec![0u8; bits.div_ceil(8)];
    xof.finalize_bits_xof(last, extra)
        .expect("bits")
        .squeeze(&mut out);
    to_top(&mut out, bits);
    out
}

/// Moves the bits of a partial last byte from the bottom, where
/// SHA-3 puts them, to the top, where ACVP does, clearing the rest.
pub fn to_top(out: &mut [u8], bits: usize) {
    let extra = bits % 8;
    if extra != 0 {
        let last = out.last_mut().expect("out");
        *last = (*last & ((1u8 << extra) - 1)) << (8 - extra);
    }
}

/// The ACVP cSHAKE Monte Carlo test: 1000 rounds a step, each
/// hashing the first 128 bits of the last output, with the next
/// output length and customization taken from the last 16 bits of
/// the output and the input. Each step reports its last output and
/// that output's length.
fn mct<X: SuffixXof>(
    group: &Value,
    t: &Value,
    steps: usize,
    start: fn() -> X,
) -> Value {
    let min_bits = group["minOutLen"].as_u64().expect("minOutLen") as usize;
    let max_bits = group["maxOutLen"].as_u64().expect("maxOutLen") as usize;
    let increment =
        group["outLenIncrement"].as_u64().expect("outLenIncrement") as usize;
    let range = max_bits - min_bits + 1;
    // The seed's lengths are strings in this group, and it is
    // always whole bytes, so only the bytes are read.
    let mut output = hex(&t["msg"]);
    let mut out_bits = max_bits;
    let mut custom: Vec<u8> = Vec::new();
    let mut results = Vec::with_capacity(steps);
    for _ in 0..steps {
        // The length of the last output, which is not whole bytes.
        let mut produced = out_bits;
        for _ in 0..1000 {
            let mut inner = output.clone();
            inner.resize(16, 0);
            let message = Message {
                bytes: inner.clone(),
                bits: 128,
            };
            output = squeeze(&message, b"", &custom, out_bits, start);
            produced = out_bits;
            let right = rightmost_16(&output, out_bits);
            out_bits =
                min_bits + (right as usize % range) / increment * increment;
            custom = inner
                .iter()
                .chain(&right.to_be_bytes())
                .map(|byte| byte % 26 + 65)
                .collect();
        }
        results.push(json!({
            "md": hex_string(&output),
            "outLen": produced,
        }));
    }
    json!({"tcId": t["tcId"], "resultsArray": results})
}

/// The last 16 bits of a bit string `bits` long, laid out as ACVP
/// lays it out, read as a number with the first of them most
/// significant.
fn rightmost_16(out: &[u8], bits: usize) -> u16 {
    (bits - 16..bits).fold(0u16, |acc, p| {
        acc << 1 | u16::from(out[p / 8] >> (7 - p % 8) & 1)
    })
}
