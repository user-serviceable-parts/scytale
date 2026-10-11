//! KMAC 1.0, run through the public bit-string calls of
//! [`Kmac128`] and [`Kmac256`]: tags generated (AFT) and checked
//! (MVT), as MACs and as XOFs, under text and hex customizations.
//!
//! Key, message and tag lengths are in bits and rarely whole bytes.
//! The files lay them out as the calls take them: a message's last
//! bits at the top of its byte, which `sha::Message` moves down for
//! SHA-3, and a key's or tag's at the top, which is where the bit
//! calls keep them.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::cshake::to_top;
use super::{check, hex, hex_string, load, rejected, response};
use crate::Error;
use crate::constant_time;
use crate::hash::XofReader;
use crate::mac::kmac::{Kmac128, Kmac256};
use serde_json::{Value, json};

/// What the driver needs of either width.
pub trait Width: Sized {
    fn try_new_bits(key: &[u8], bits: usize, s: &[u8]) -> Result<Self, Error>;
    fn update(&mut self, data: &[u8]);
    fn finalize_bits_to(
        &mut self,
        last: u8,
        bits: u32,
        out: &mut [u8],
        out_bits: usize,
    ) -> Result<(), Error>;
    fn verify_bits(
        &mut self,
        last: u8,
        bits: u32,
        tag: &[u8],
        tag_bits: usize,
    ) -> Result<(), Error>;
    /// KMACXOF, squeezed into `out`.
    fn xof_bits(
        &mut self,
        last: u8,
        bits: u32,
        out: &mut [u8],
    ) -> Result<(), Error>;
}

macro_rules! width {
    ($ty:ty) => {
        impl Width for $ty {
            fn try_new_bits(
                key: &[u8],
                bits: usize,
                s: &[u8],
            ) -> Result<Self, Error> {
                <$ty>::try_new_bits(key, bits, s)
            }
            fn update(&mut self, data: &[u8]) {
                <$ty>::update(self, data)
            }
            fn finalize_bits_to(
                &mut self,
                last: u8,
                bits: u32,
                out: &mut [u8],
                out_bits: usize,
            ) -> Result<(), Error> {
                <$ty>::finalize_bits_to(self, last, bits, out, out_bits)
            }
            fn verify_bits(
                &mut self,
                last: u8,
                bits: u32,
                tag: &[u8],
                tag_bits: usize,
            ) -> Result<(), Error> {
                <$ty>::verify_bits(self, last, bits, tag, tag_bits)
            }
            fn xof_bits(
                &mut self,
                last: u8,
                bits: u32,
                out: &mut [u8],
            ) -> Result<(), Error> {
                self.finalize_bits_xof(last, bits)?.squeeze(out);
                Ok(())
            }
        }
    };
}

width!(Kmac128);
width!(Kmac256);

/// The response to a whole vector set.
pub fn answer<K: Width>(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| json!({"tgId": group["tgId"], "tests": tests::<K>(group)}))
        .collect();
    response(prompt, groups)
}

/// Runs every case against `K`; a no-op without the vendored vectors.
pub fn run_aft<K: Width>(file: &str, algorithm: &str) {
    let Some(doc) = load(file, algorithm, "1.0") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let answers = tests::<K>(group);
        rejections += rejected(&answers);
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(&answers) {
            if let Err(why) = check(want, got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            cases += 1;
        }
    }
    // Guard against a truncated or wrong file passing vacuously, and
    // against the rejection cases quietly disappearing.
    assert!(cases >= 800, "only {cases} cases");
    assert!(rejections >= 190, "only {rejections} rejections");
}

/// The response to each test of a group: the tag for an AFT, the
/// verdict for an MVT.
fn tests<K: Width>(group: &Value) -> Vec<Value> {
    let xof = group["xof"].as_bool().expect("xof");
    let verify = match group["testType"].as_str() {
        Some("AFT") => false,
        Some("MVT") => true,
        other => panic!("unknown testType {other:?}"),
    };
    let hex_custom = group["hexCustomization"].as_bool() == Some(true);
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let name = format!("tcId {}", t["tcId"]);
            let custom = if hex_custom {
                hex(&t["customizationHex"])
            } else {
                t["customization"]
                    .as_str()
                    .expect("text")
                    .as_bytes()
                    .to_vec()
            };
            let key_bits = length(t, "keyLen");
            let mac_bits = length(t, "macLen");
            let key = hex(&t["key"]);
            let msg_bits = length(t, "msgLen");
            let msg = from_top(hex(&t["msg"]), msg_bits);
            let (whole, last, extra) = split(&msg, msg_bits);

            let mut kmac =
                K::try_new_bits(&key, key_bits, &custom).expect("key");
            kmac.update(whole);
            let mut out = vec![0u8; mac_bits.div_ceil(8)];
            if !verify {
                if xof {
                    kmac.xof_bits(last, extra, &mut out).expect("xof");
                    to_top(&mut out, mac_bits);
                } else {
                    kmac.finalize_bits_to(last, extra, &mut out, mac_bits)
                        .expect("mac");
                }
                return json!({"tcId": t["tcId"], "mac": hex_string(&out)});
            }
            let given = hex(&t["mac"]);
            let passed = if given.len() != out.len() {
                false
            } else if xof {
                kmac.xof_bits(last, extra, &mut out).expect("xof");
                to_top(&mut out, mac_bits);
                constant_time::equal(&out, &given)
            } else {
                match kmac.verify_bits(last, extra, &given, mac_bits) {
                    Ok(()) => true,
                    Err(Error::AuthenticationFailed) => false,
                    Err(e) => panic!("{name}: {e}"),
                }
            };
            json!({"tcId": t["tcId"], "testPassed": passed})
        })
        .collect()
}

fn length(t: &Value, field: &str) -> usize {
    t[field].as_u64().expect("length") as usize
}

/// A bit string as ACVP lays it out, with the bits of a partial last
/// byte moved to the bottom where SHA-3 reads them.
fn from_top(mut bytes: Vec<u8>, bits: usize) -> Vec<u8> {
    assert_eq!(bytes.len(), bits.div_ceil(8));
    let extra = bits % 8;
    if let (Some(last), true) = (bytes.last_mut(), extra != 0) {
        *last >>= 8 - extra;
    }
    bytes
}

/// The whole bytes of a message, and its last partial byte and how
/// many bits of it there are.
fn split(msg: &[u8], bits: usize) -> (&[u8], u8, u32) {
    let extra = (bits % 8) as u32;
    match msg.split_last() {
        Some((&last, whole)) if extra != 0 => (whole, last, extra),
        _ => (msg, 0, 0),
    }
}
