//! Wycheproof's X448 cases through [`x448`]: twist points, low-order
//! points, non-canonical coordinates and edge-case multiples. The raw
//! function must always match the file, and
//! [`shared_secret`](x448::shared_secret) must refuse exactly the
//! zero outputs. The cases marked invalid are public keys of 57
//! bytes, which the key's array type refuses before any arithmetic.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::super::hex;
use super::load;
use crate::Error;
use crate::kex::x448::{self, KEY_SIZE};

const FILE: &str = "wycheproof/x448_test.json";

/// Runs every case; a no-op without the vendored vectors.
pub fn run() {
    let Some(doc) = load(FILE, "XDH") else {
        return;
    };
    let mut cases = 0;
    let mut zeros = 0;
    let mut too_long = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        assert_eq!(group["curve"], "curve448");
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let private: [u8; KEY_SIZE] =
                hex(&t["private"]).try_into().expect("private");
            let public = hex(&t["public"]);
            match t["result"].as_str() {
                Some("valid") | Some("acceptable") => {}
                Some("invalid") => {
                    let refused: Result<[u8; KEY_SIZE], _> =
                        public.as_slice().try_into();
                    assert!(refused.is_err(), "{tag}: a key was taken");
                    too_long += 1;
                    cases += 1;
                    continue;
                }
                other => panic!("{tag}: unknown result {other:?}"),
            }
            let public: [u8; KEY_SIZE] = public.try_into().expect("public");
            let shared: [u8; KEY_SIZE] =
                hex(&t["shared"]).try_into().expect("shared");

            assert_eq!(x448::x448(&private, &public), shared, "{tag}");
            let checked = x448::shared_secret(&private, &public);
            if shared == [0u8; KEY_SIZE] {
                assert_eq!(
                    checked,
                    Err(Error::InvalidPublicKey),
                    "{tag} accepted a zero secret",
                );
                zeros += 1;
            } else {
                assert_eq!(checked, Ok(shared), "{tag}");
            }
            cases += 1;
        }
    }
    assert!(cases >= 510, "only {cases} cases");
    assert!(zeros >= 11, "only {zeros} zero-secret cases");
    assert!(too_long >= 12, "only {too_long} over-long keys");
}
