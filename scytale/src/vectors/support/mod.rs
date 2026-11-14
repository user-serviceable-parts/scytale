//! Shared test support: vector loading and the Wycheproof, CFRG and
//! BLAKE2 drivers.

#![allow(dead_code)]

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

pub mod blake2;
pub mod cfrg;
pub mod vectors;
pub mod wycheproof;

use serde_json::Value;

/// A hex field of a vector file decoded.
pub fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
