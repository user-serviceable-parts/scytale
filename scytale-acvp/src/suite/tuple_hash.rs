//! TupleHash 1.0, both widths and both forms: the one-shot test, and
//! the Monte Carlo test, whose tuple is cut from the last output and
//! whose output length and customization wander as cSHAKE's do.
//!
//! Every string and output in these files is whole bytes.

use super::cshake::{Lengths, customization, mct_steps, rightmost_16};
use super::{answer_groups, answer_tests};
use crate::support::{
    Error, decode_hex, flag, hex_value, int, list, text, unknown_test_type,
};
use scytale::Random;
use scytale::hash::XofReader;
use scytale::hash::sha3::{TupleHash128, TupleHash256};
use serde_json::{Value, json};

/// The two widths, as the driver drives them.
pub trait Tuple {
    fn start(customization: &[u8]) -> Self;
    fn push(&mut self, element: &[u8]);
    /// TupleHash, or TupleHashXOF if `xof`, filling `out`.
    fn finish(&mut self, xof: bool, out: &mut [u8]);
}

macro_rules! tuple {
    ($ty:ty) => {
        impl Tuple for $ty {
            fn start(customization: &[u8]) -> Self {
                <$ty>::new(customization)
            }

            fn push(&mut self, element: &[u8]) {
                <$ty>::push(self, element)
            }

            fn finish(&mut self, xof: bool, out: &mut [u8]) {
                if xof {
                    self.finalize_xof().squeeze(out)
                } else {
                    self.finalize_to(out)
                }
            }
        }
    };
}

tuple!(TupleHash128);
tuple!(TupleHash256);

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    match text(doc, "algorithm")? {
        "TupleHash-128" => answer_as::<TupleHash128>(doc),
        "TupleHash-256" => answer_as::<TupleHash256>(doc),
        other => Err(Error::new(format!("algorithm {other}"))),
    }
}

fn answer_as<T: Tuple>(doc: &Value) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let xof = flag(group, "xof")?;
        match text(group, "testType")? {
            "AFT" => answer_tests(group, |t| {
                let bits = int(t, "outLen")? as usize;
                let custom = customization(group, t)?;
                let out = hash::<T>(&tuple_of(t)?, &custom, xof, bits)?;
                Ok(json!({ "md": hex_value(&out), "outLen": bits }))
            }),
            "MCT" => {
                let lengths = Lengths::of(group)?;
                let steps = mct_steps(doc);
                answer_tests(group, |t| mct::<T>(t, xof, &lengths, steps))
            }
            _ => Err(unknown_test_type(group)),
        }
    })
}

fn hash<T: Tuple>(
    tuple: &[Vec<u8>],
    custom: &[u8],
    xof: bool,
    bits: usize,
) -> Result<Vec<u8>, Error> {
    if !bits.is_multiple_of(8) {
        return Err(Error::new("an output of part of a byte"));
    }
    let mut h = T::start(custom);
    tuple.iter().for_each(|e| h.push(e));
    let mut out = vec![0u8; bits / 8];
    h.finish(xof, &mut out);
    Ok(out)
}

/// A case's tuple, checking each string is the whole bytes it says.
fn tuple_of(t: &Value) -> Result<Vec<Vec<u8>>, Error> {
    let strings = list(t, "tuple")?;
    let lens = list(t, "len")?;
    if strings.len() != lens.len() {
        return Err(Error::new("tuple and len differ in length"));
    }
    strings
        .iter()
        .zip(lens)
        .map(|(s, len)| {
            let bytes = s
                .as_str()
                .and_then(decode_hex)
                .ok_or_else(|| Error::new("tuple element is not hex"))?;
            let bits = len
                .as_u64()
                .ok_or_else(|| Error::new("len is not a number"))?;
            if 8 * bytes.len() as u64 != bits {
                return Err(Error::new("tuple element does not match len"));
            }
            Ok(bytes)
        })
        .collect()
}

/// The ACVP TupleHash Monte Carlo test, as the server runs it: 1000
/// rounds a step, each hashing one to four strings cut evenly from
/// the first 288 bits of the last output, their count from its first
/// three bits.
fn mct<T: Tuple>(
    t: &Value,
    xof: bool,
    lengths: &Lengths,
    steps: usize,
) -> Result<Value, Error> {
    let mut output = tuple_of(t)?
        .into_iter()
        .next()
        .ok_or_else(|| Error::new("empty tuple"))?;
    let mut out_bits = lengths.max;
    let mut custom: Vec<u8> = Vec::new();
    let mut results = Vec::with_capacity(steps);
    for _ in 0..steps {
        let mut last_bits = out_bits;
        for _ in 0..1000 {
            let mut working = output.clone();
            working.resize(36, 0);
            let size = usize::from(working[0] >> 5) % 4 + 1;
            let tuple: Vec<Vec<u8>> =
                working.chunks(36 / size).map(<[u8]>::to_vec).collect();
            output = hash::<T>(&tuple, &custom, xof, out_bits)?;
            last_bits = out_bits;
            let right = rightmost_16(&output, out_bits);
            out_bits = lengths.next(right);
            custom = tuple[0]
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

#[cfg(test)]
mod tests {
    #[test]
    fn vendored() {
        for name in ["TupleHash-128", "TupleHash-256"] {
            for suite in super::super::find(name) {
                super::super::check(suite);
            }
        }
    }
}
