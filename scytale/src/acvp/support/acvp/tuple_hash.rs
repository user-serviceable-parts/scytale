//! TupleHash 1.0, both widths and both forms: the one-shot test, and
//! the Monte Carlo test, whose tuple is cut from the last output and
//! whose output length and customization wander as cSHAKE's do.
//!
//! Every string and output in these files is whole bytes.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::cshake::{customization, rightmost_16};
use super::{hex, load};
use crate::hash::XofReader;
use crate::hash::sha3::{TupleHash128, TupleHash256};
use serde_json::Value;

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

fn hash<T: Tuple>(
    tuple: &[Vec<u8>],
    custom: &[u8],
    xof: bool,
    bits: usize,
) -> Vec<u8> {
    assert_eq!(bits % 8, 0, "an output of whole bytes");
    let mut h = T::start(custom);
    tuple.iter().for_each(|e| h.push(e));
    let mut out = vec![0u8; bits / 8];
    h.finish(xof, &mut out);
    out
}

/// A case's tuple, checking each string is the whole bytes it says.
fn tuple_of(t: &Value) -> Vec<Vec<u8>> {
    let strings = t["tuple"].as_array().expect("tuple");
    let lens = t["len"].as_array().expect("len");
    assert_eq!(strings.len(), lens.len(), "tcId {}", t["tcId"]);
    strings
        .iter()
        .zip(lens)
        .map(|(s, len)| {
            let bytes = hex(s);
            let bits = len.as_u64().expect("len") as usize;
            assert_eq!(8 * bytes.len(), bits, "tcId {}", t["tcId"]);
            bytes
        })
        .collect()
}

/// Runs both test types against `T`; a no-op without the vendored
/// vectors.
pub fn run<T: Tuple>(file: &str, algorithm: &str) {
    let Some(doc) = load(file, algorithm, "1.0") else {
        return;
    };
    let mut cases = 0;
    let mut steps = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let xof = group["xof"].as_bool().expect("xof");
        if group["testType"] == "MCT" {
            steps += mct::<T>(group, xof);
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let bits = t["outLen"].as_u64().expect("outLen") as usize;
            let custom = customization(group, t);
            let out = hash::<T>(&tuple_of(t), &custom, xof, bits);
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            assert_eq!(out, hex(&t["md"]), "{tag}");
            cases += 1;
        }
    }
    assert!(cases >= 200, "only {cases} cases");
    assert!(steps >= 6, "only {steps} MCT steps");
}

/// The ACVP TupleHash Monte Carlo test, as the server runs it: 1000
/// rounds a step, each hashing one to four strings cut evenly from
/// the first 288 bits of the last output, their count from its first
/// three bits.
fn mct<T: Tuple>(group: &Value, xof: bool) -> usize {
    let min_bits = group["minOutLen"].as_u64().expect("minOutLen") as usize;
    let max_bits = group["maxOutLen"].as_u64().expect("maxOutLen") as usize;
    let increment =
        group["outLenIncrement"].as_u64().expect("outLenIncrement") as usize;
    let range = max_bits - min_bits + 1;
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let mut output = tuple_of(t).swap_remove(0);
        let mut out_bits = max_bits;
        let mut custom: Vec<u8> = Vec::new();
        let steps = t["resultsArray"].as_array().expect("resultsArray");
        for (i, step) in steps.iter().enumerate() {
            for _ in 0..1000 {
                let mut working = output.clone();
                working.resize(36, 0);
                let size = usize::from(working[0] >> 5) % 4 + 1;
                let tuple: Vec<Vec<u8>> =
                    working.chunks(36 / size).map(<[u8]>::to_vec).collect();
                output = hash::<T>(&tuple, &custom, xof, out_bits);
                let right = rightmost_16(&output, out_bits);
                out_bits =
                    min_bits + (right as usize % range) / increment * increment;
                custom = tuple[0]
                    .iter()
                    .chain(&right.to_be_bytes())
                    .map(|byte| byte % 26 + 65)
                    .collect();
            }
            let tag =
                format!("tgId {} tcId {} step {i}", group["tgId"], t["tcId"]);
            assert_eq!(output, hex(&step["md"]), "{tag}");
            count += 1;
        }
    }
    count
}
