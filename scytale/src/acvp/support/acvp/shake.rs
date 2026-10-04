//! ACVP-SHAKE 1.0, run through the [`Xof`] trait: the one-shot
//! test, the variable output test, and a Monte Carlo test whose
//! output length wanders. As in [`sha`](super::sha), each test type
//! has one function that answers a case, and the vendored suites and
//! the live run both go through it.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::sha::{Family, Message, run};
use super::{hex_string, load, response};
use crate::hash::{BitXof, XofReader};
use serde_json::{Value, json};

/// Steps in a Monte Carlo test, each of a thousand squeezes.
const MCT_STEPS: usize = 100;

/// The response to a whole vector set.
pub fn answer<X: BitXof>(prompt: &Value, start: fn() -> X) -> Value {
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
                    Some("AFT" | "VOT") => aft(t, start),
                    Some("MCT") => mct(group, t, start),
                    other => panic!("unknown testType {other:?}"),
                })
                .collect();
            json!({"tgId": group["tgId"], "tests": tests})
        })
        .collect();
    response(prompt, groups)
}

/// Runs the one-shot and variable-output groups against `X`; a no-op
/// without the vendored vectors.
pub fn run_aft<X: BitXof>(file: &str, algorithm: &str, start: fn() -> X) {
    let Some(groups) = groups(file, algorithm, &["AFT", "VOT"]) else {
        return;
    };
    let count = run(&groups, |_, t| aft(t, start));
    assert!(count >= 500, "only {count} cases");
}

/// Runs the Monte Carlo groups against `X`; a no-op without the
/// vendored vectors. Slow: 100,000 SHAKE calls per group.
pub fn run_mct<X: BitXof>(file: &str, algorithm: &str, start: fn() -> X) {
    let Some(groups) = groups(file, algorithm, &["MCT"]) else {
        return;
    };
    let count = run(&groups, |g, t| mct(g, t, start));
    assert!(count >= 1, "only {count} MCT cases");
}

/// The groups of the given test types; `None` without the vectors.
fn groups(file: &str, algorithm: &str, types: &[&str]) -> Option<Vec<Value>> {
    let doc = load(file, algorithm, "1.0")?;
    let selected = doc["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .filter(|g| g["testType"].as_str().is_some_and(|t| types.contains(&t)))
        .cloned()
        .collect();
    Some(selected)
}

impl Message {
    /// Squeezes `out.len()` bytes from the message.
    fn squeeze<X: BitXof>(&self, out: &mut [u8], start: fn() -> X) {
        let mut xof = start();
        let (whole, tail) = self.split(Family::Sha3);
        xof.update(whole);
        let mut reader = match tail {
            None => xof.finalize_xof(),
            Some((last, extra)) => {
                xof.finalize_bits_xof(last, extra).expect("bits")
            }
        };
        reader.squeeze(out);
    }
}

/// One message, `outLen` bits of output. A length that is not whole
/// bytes keeps the last byte's low bits, numbered as FIPS 202
/// numbers them, and the rest zero.
fn aft<X: BitXof>(t: &Value, start: fn() -> X) -> Value {
    let bits = t["outLen"].as_u64().expect("outLen") as usize;
    let mut out = vec![0u8; bits.div_ceil(8)];
    Message::of(t).squeeze(&mut out, start);
    if !bits.is_multiple_of(8) {
        let last = out.last_mut().expect("out");
        *last &= (1u8 << (bits % 8)) - 1;
    }
    json!({"tcId": t["tcId"], "md": hex_string(&out)})
}

/// The SHAKE Monte Carlo test: each of 100 steps squeezes 1000
/// times, feeding the first 16 bytes of each output (zero-padded)
/// into the next, with the output length chosen each time by the
/// last two bytes of the previous output within the group's range.
fn mct<X: BitXof>(group: &Value, t: &Value, start: fn() -> X) -> Value {
    let min_bits = group["minOutLen"].as_u64().expect("minOutLen") as usize;
    let max_bits = group["maxOutLen"].as_u64().expect("maxOutLen") as usize;
    let range = (max_bits - min_bits) / 8 + 1;
    let seed = Message::of(t);
    assert_eq!(seed.bits % 8, 0, "tcId {}: bit seed", t["tcId"]);
    let mut md = seed.bytes.clone();
    let mut out_len = max_bits / 8;
    let mut steps = Vec::with_capacity(MCT_STEPS);
    for _ in 0..MCT_STEPS {
        for _ in 0..1000 {
            let mut msg = md.clone();
            msg.resize(16, 0);
            let message = Message {
                bytes: msg,
                bits: 128,
            };
            let mut out = vec![0u8; out_len];
            message.squeeze(&mut out, start);
            let tail = &out[out.len() - 2..];
            let right = u16::from_be_bytes([tail[0], tail[1]]) as usize;
            out_len = min_bits / 8 + right % range;
            md = out;
        }
        steps.push(json!({"md": hex_string(&md), "outLen": md.len() * 8}));
    }
    json!({"tcId": t["tcId"], "resultsArray": steps})
}
