//! cSHAKE 1.0, through the public cSHAKE functions and the
//! [`BitXof`] trait: the one-shot test, and the Monte Carlo test
//! whose output length and customization wander.
//!
//! Lengths here are in bits. ACVP keeps the bits of a partial last
//! byte at its top; SHA-3 numbers them from the bottom. Messages are
//! moved down as `sha::Message` already does for SHA-3, and outputs
//! moved up before they are answered.

use super::sha::{Family, Message};
use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, int, text, unknown_test_type};
use scytale::Random;
use scytale::hash::sha3::{CShake128, CShake256};
use scytale::hash::{BitXof, XofReader};
use serde_json::{Value, json};

/// The constructor of either width.
type Start<X> = fn(&[u8], &[u8]) -> X;

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    match text(doc, "algorithm")? {
        "cSHAKE-128" => answer_as(doc, CShake128::new),
        "cSHAKE-256" => answer_as(doc, CShake256::new),
        other => Err(Error::new(format!("algorithm {other}"))),
    }
}

fn answer_as<X: BitXof>(doc: &Value, start: Start<X>) -> Result<Value, Error> {
    answer_groups(doc, |group| match text(group, "testType")? {
        "AFT" => answer_tests(group, |t| {
            let bits = int(t, "outLen")? as usize;
            let name = text(t, "functionName")?.as_bytes();
            let custom = customization(group, t)?;
            let out = squeeze(&Message::of(t)?, name, &custom, bits, start)?;
            Ok(json!({ "md": hex_value(&out), "outLen": bits }))
        }),
        "MCT" => {
            let lengths = Lengths::of(group)?;
            let steps = mct_steps(doc);
            answer_tests(group, |t| mct(t, &lengths, steps, start))
        }
        _ => Err(unknown_test_type(group)),
    })
}

/// How many steps a Monte Carlo test answers. The server's cSHAKE
/// and TupleHash tests run 100, but only 3 in a sample vector set,
/// which is what the vendored files are.
pub fn mct_steps(doc: &Value) -> usize {
    if doc["isSample"].as_bool() == Some(true) {
        3
    } else {
        100
    }
}

/// The customization, given as text or, in a hex group, as hex.
pub fn customization(group: &Value, t: &Value) -> Result<Vec<u8>, Error> {
    if group["hexCustomization"].as_bool() == Some(true) {
        hex(t, "customizationHex")
    } else {
        Ok(text(t, "customization")?.as_bytes().to_vec())
    }
}

/// cSHAKE of `message` under `name` and `custom`, `bits` of output,
/// laid out as ACVP lays out a bit string.
fn squeeze<X: BitXof>(
    message: &Message,
    name: &[u8],
    custom: &[u8],
    bits: usize,
    start: Start<X>,
) -> Result<Vec<u8>, Error> {
    let mut xof = start(name, custom);
    let (whole, tail) = message.split(Family::Sha3);
    xof.update(whole);
    let mut reader = match tail {
        None => xof.finalize_xof(),
        Some((last, extra)) => xof.finalize_bits_xof(last, extra)?,
    };
    let mut out = vec![0u8; bits.div_ceil(8)];
    reader.squeeze(&mut out);
    to_top(&mut out, bits);
    Ok(out)
}

/// Moves the bits of a partial last byte from the bottom, where
/// SHA-3 puts them, to the top, where ACVP does, clearing the rest.
pub fn to_top(out: &mut [u8], bits: usize) {
    let extra = bits % 8;
    if let (Some(last), true) = (out.last_mut(), extra != 0) {
        *last = (*last & ((1u8 << extra) - 1)) << (8 - extra);
    }
}

/// A Monte Carlo group's output lengths, in bits.
pub struct Lengths {
    pub min: usize,
    pub max: usize,
    pub increment: usize,
}

impl Lengths {
    pub fn of(group: &Value) -> Result<Self, Error> {
        let lengths = Lengths {
            min: int(group, "minOutLen")? as usize,
            max: int(group, "maxOutLen")? as usize,
            increment: int(group, "outLenIncrement")? as usize,
        };
        // The wander reads the last 16 bits of every output and
        // divides by the increment.
        if lengths.min < 16
            || lengths.max < lengths.min
            || lengths.increment == 0
        {
            return Err(Error::new("output lengths out of range"));
        }
        Ok(lengths)
    }

    /// The next output length, from the last 16 bits of an output.
    pub fn next(&self, right: u16) -> usize {
        let range = self.max - self.min + 1;
        self.min + (right as usize % range) / self.increment * self.increment
    }
}

/// The ACVP cSHAKE Monte Carlo test: 1000 rounds a step, each
/// hashing the first 128 bits of the last output, with the next
/// output length and customization taken from the last 16 bits of
/// the output and the input.
fn mct<X: BitXof>(
    t: &Value,
    lengths: &Lengths,
    steps: usize,
    start: Start<X>,
) -> Result<Value, Error> {
    // The seed's lengths are strings in this group, and it is always
    // whole bytes, so only the bytes are read.
    let mut output = hex(t, "msg")?;
    let mut out_bits = lengths.max;
    let mut custom: Vec<u8> = Vec::new();
    let mut results = Vec::with_capacity(steps);
    for _ in 0..steps {
        let mut last_bits = out_bits;
        for _ in 0..1000 {
            let mut inner = output.clone();
            inner.resize(16, 0);
            let message = Message {
                bytes: inner.clone(),
                bits: 128,
            };
            output = squeeze(&message, b"", &custom, out_bits, start)?;
            last_bits = out_bits;
            let right = rightmost_16(&output, out_bits);
            out_bits = lengths.next(right);
            custom = inner
                .iter()
                .chain(&right.to_be_bytes())
                .map(|byte| byte % 26 + 65)
                .collect();
        }
        results.push(json!({
            "md": hex_value(&output),
            "outLen": last_bits,
        }));
    }
    Ok(json!({ "resultsArray": results }))
}

/// The last 16 bits of a bit string `bits` long, laid out as ACVP
/// lays it out, read as a number with the first of them most
/// significant. The caller keeps `bits` at least 16 and within
/// `out`.
pub fn rightmost_16(out: &[u8], bits: usize) -> u16 {
    (bits - 16..bits).fold(0u16, |acc, p| {
        acc << 1 | u16::from(out[p / 8] >> (7 - p % 8) & 1)
    })
}
