//! Wycheproof's AEGIS cases: the valid ones must round-trip, and the
//! invalid ones (modified tags, and the ciphertexts of the version
//! of AEGIS that came before the draft) must be rejected with the
//! buffer wiped.
//!
//! The caller says how the AEAD is made, so that each kernel runs
//! every case in its own right.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::super::hex;
use super::load;
use crate::aead::{Aead, Aegis128L};
use crate::{Error, Key};

/// Runs every AEGIS-128L case through the AEAD `new` makes; a no-op
/// without the vendored vectors.
pub fn aegis128l(new: &dyn Fn(&Key<[u8; 16]>) -> Aegis128L) {
    run("wycheproof/aegis128L_test.json", "AEGIS128L", 367, 112, new);
}

/// Runs every case of `file`, which holds at least `valid` cases
/// that must pass and `invalid` that must not.
fn run<A, const K: usize, const N: usize>(
    file: &str,
    algorithm: &str,
    valid: usize,
    invalid: usize,
    new: &dyn Fn(&Key<[u8; K]>) -> A,
) where
    A: Aead<Key = Key<[u8; K]>, Nonce = [u8; N], Tag = [u8; 16]>,
{
    let Some(doc) = load(file, algorithm) else {
        return;
    };
    let mut passed = 0;
    let mut refused = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        assert_eq!(group["keySize"], 8 * K);
        assert_eq!(group["ivSize"], 8 * N);
        assert_eq!(group["tagSize"], 128);
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let key = Key::try_from(&hex(&t["key"])[..]).expect("key");
            let aead = new(&key);
            let nonce: [u8; N] = hex(&t["iv"]).try_into().expect("nonce");
            let aad = hex(&t["aad"]);
            let msg = hex(&t["msg"]);
            let ct = hex(&t["ct"]);
            let expected: [u8; 16] = hex(&t["tag"]).try_into().expect("tag");
            match t["result"].as_str() {
                Some("valid") => {
                    let mut data = msg.clone();
                    let mut got = [0u8; 16];
                    aead.encrypt(&nonce, &aad, &mut data, &mut got)
                        .expect("encrypt");
                    assert_eq!(data, ct, "{tag} ciphertext");
                    assert_eq!(got, expected, "{tag} tag");
                    aead.decrypt(&nonce, &aad, &mut data, &expected)
                        .expect("decrypt");
                    assert_eq!(data, msg, "{tag} plaintext");
                    passed += 1;
                }
                Some("invalid") => {
                    let mut data = ct.clone();
                    assert_eq!(
                        aead.decrypt(&nonce, &aad, &mut data, &expected),
                        Err(Error::AuthenticationFailed),
                        "{tag}"
                    );
                    assert!(data.iter().all(|&b| b == 0), "{tag} wiped");
                    refused += 1;
                }
                other => panic!("{tag}: unknown result {other:?}"),
            }
        }
    }
    assert!(passed >= valid, "only {passed} valid cases");
    assert!(refused >= invalid, "only {refused} invalid cases");
}
