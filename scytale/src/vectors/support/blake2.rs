//! The BLAKE2 reference implementation's known-answer tests for
//! BLAKE2b: messages of 0 to 255 bytes, each hashed unkeyed and under
//! a 64-byte key, with 64-byte digests. The file also holds BLAKE2s
//! and the tree and XOF variants, which the crate does not have.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::hex;
use super::vectors;
use crate::hash::Hash;
use crate::hash::blake2::{Blake2b512, Engine};
use serde_json::Value;

/// Runs every BLAKE2b case; a no-op without the vendored file.
pub fn run() {
    let Some(text) = vectors::load("blake2/blake2-kat.json") else {
        return;
    };
    let doc: Value = serde_json::from_str(&text).expect("valid JSON");
    let (mut plain, mut keyed) = (0, 0);
    for v in doc.as_array().expect("an array of cases") {
        if v["hash"] != "blake2b" {
            continue;
        }
        let (input, key, out) = (hex(&v["in"]), hex(&v["key"]), hex(&v["out"]));
        let mut engine = Engine::new(out.len(), &key);
        engine.update(&input);
        let mut got = vec![0u8; out.len()];
        engine.finalize_into(&mut got);
        assert_eq!(got, out, "key {} in {}", key.len(), input.len());
        if key.is_empty() {
            // The public type too, whole and a byte at a time, which
            // crosses the block boundary at every offset in turn.
            assert_eq!(Blake2b512::digest(&input)[..], out[..]);
            let mut hash = Blake2b512::new();
            for byte in &input {
                hash.update(core::slice::from_ref(byte));
            }
            assert_eq!(hash.finalize()[..], out[..]);
            plain += 1;
        } else {
            keyed += 1;
        }
    }
    assert_eq!((plain, keyed), (256, 256));
}
