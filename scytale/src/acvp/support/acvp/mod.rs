//! Drivers for NIST ACVP vector files, generic over the primitive's
//! trait so any implementation can run them.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

pub mod aes_cbc;
pub mod aes_ccm;
pub mod aes_cfb1;
pub mod aes_cfb128;
pub mod aes_cfb8;
pub mod aes_ctr;
pub mod aes_ecb;
pub mod aes_ff1;
pub mod aes_ff3_1;
pub mod aes_gcm;
pub mod aes_gcm_siv;
pub mod aes_gmac;
pub mod aes_kw;
pub mod aes_kwp;
pub mod aes_ofb;
pub mod aes_xpn;
pub mod aes_xts;
pub mod cmac_aes;
pub mod cshake;
pub mod ctr_drbg;
pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod kda_hkdf;
pub mod kmac;
pub mod kts_ifc;
pub mod ml_dsa;
pub mod ml_kem;
pub mod pbkdf;
pub mod rsa_primitive;
pub mod rsa_sig;
pub mod sha;
pub mod shake;
pub mod slh_dsa;
pub mod xecdh;

use crate::KeyType;
use crate::cipher::BlockCipher;
use serde_json::Value;

pub fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// `bytes` as the vectors write them, upper-case hex.
pub fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// The response to a vector set: its identity and the answered
/// groups, in the shape the server takes.
pub fn response(prompt: &Value, groups: Vec<Value>) -> Value {
    let mut out = serde_json::json!({
        "vsId": prompt["vsId"],
        "algorithm": prompt["algorithm"],
        "revision": prompt["revision"],
        "testGroups": groups,
    });
    if !prompt["mode"].is_null() {
        out["mode"] = prompt["mode"].clone();
    }
    out
}

/// Whether `got` agrees with `expected`: every field of `got` is in
/// `expected` with the same value, hex compared without regard to
/// case, arrays element by element. `expected` may carry more, as
/// the vendored files carry the prompt beside the answer. The error
/// names the first disagreement by its test case and field.
pub fn check(expected: &Value, got: &Value) -> Result<(), String> {
    check_at(expected, got, String::new())
}

fn check_at(expected: &Value, got: &Value, path: String) -> Result<(), String> {
    match (expected, got) {
        (Value::Object(e), Value::Object(g)) => {
            let mut path = path;
            for id in ["tgId", "tcId"] {
                if let Some(n) = g.get(id) {
                    path = format!("{path}{id} {n} ");
                }
            }
            for (key, value) in g {
                let Some(want) = e.get(key) else {
                    return Err(format!("{path}{key}: not expected"));
                };
                check_at(want, value, format!("{path}{key}"))?;
            }
            Ok(())
        }
        (Value::Array(e), Value::Array(g)) => {
            if e.len() != g.len() {
                return Err(format!(
                    "{path}: {} items where {} were expected",
                    g.len(),
                    e.len()
                ));
            }
            for (i, (want, value)) in e.iter().zip(g).enumerate() {
                check_at(want, value, format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        (Value::String(e), Value::String(g)) if e.eq_ignore_ascii_case(g) => {
            Ok(())
        }
        (e, g) if e == g => Ok(()),
        (e, g) => Err(format!("{path}: got {g}, expected {e}")),
    }
}

/// Loads and parses a vector file, checking it is the expected suite;
/// `None` if the vectors are not vendored in this copy.
pub fn load(file: &str, algorithm: &str, revision: &str) -> Option<Value> {
    let json = super::vectors::load(file)?;
    let doc: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(doc["algorithm"], algorithm);
    // Not every suite records a revision.
    if !doc["revision"].is_null() {
        assert_eq!(doc["revision"], revision);
    }
    Some(doc)
}

/// The key of `C` from `bytes`, or `None` if it is another width.
/// Each AES width is its own type, so a driver instantiated at one
/// width skips the cases of the other two.
pub fn key_of<C: KeyType>(bytes: &[u8]) -> Option<C::Key> {
    let mut key = C::zero_key();
    if key.as_ref().len() != bytes.len() {
        return None;
    }
    key.as_mut().copy_from_slice(bytes);
    Some(key)
}

/// `C` keyed from `bytes`, or `None` if the width is another type's.
pub fn cipher_of<C: BlockCipher>(bytes: &[u8]) -> Option<C> {
    key_of::<C>(bytes).map(|key| C::new(&key))
}

/// The groups of one test type in a suite for the key width of `C`,
/// each paired with whether it is the encrypt direction. `None` if
/// the vectors are not vendored in this copy, or define nothing at
/// that width, which the driver treats the same way.
pub fn groups<C: KeyType>(
    file: &str,
    algorithm: &str,
    revision: &str,
    test_type: &str,
) -> Option<Vec<(Value, bool)>> {
    let doc = load(file, algorithm, revision)?;
    let bits = 8 * C::zero_key().as_ref().len() as u64;
    let mut selected = Vec::new();
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["keyLen"].as_u64().is_some_and(|len| len != bits) {
            continue;
        }
        let encrypt = match group["direction"].as_str() {
            Some("encrypt") => true,
            Some("decrypt") => false,
            other => panic!("unknown direction {other:?}"),
        };
        match group["testType"].as_str() {
            Some(t) if t == test_type => {
                selected.push((group.clone(), encrypt))
            }
            Some("AFT") | Some("MCT") => {}
            other => panic!("unknown testType {other:?}"),
        }
    }
    if selected.is_empty() {
        return None;
    }
    Some(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hex_round_trips_in_upper_case() {
        let text = "00FFA5";
        assert_eq!(hex_string(&hex(&json!(text))), text);
    }

    #[test]
    fn check_ignores_case_and_extra_expected_fields() {
        let expected = json!({"tcId": 1, "msg": "AB", "md": "0AFF"});
        let got = json!({"tcId": 1, "md": "0aff"});
        assert_eq!(check(&expected, &got), Ok(()));
    }

    #[test]
    fn check_names_the_first_disagreement() {
        let expected = json!({"tgId": 2, "tests": [
            {"tcId": 5, "md": "00"},
            {"tcId": 6, "md": "01", "resultsArray": [{"md": "0A"}]},
        ]});
        let got = json!({"tgId": 2, "tests": [
            {"tcId": 5, "md": "00"},
            {"tcId": 6, "md": "01", "resultsArray": [{"md": "0B"}]},
        ]});
        let why = check(&expected, &got).expect_err("differs");
        assert!(
            why.starts_with("tgId 2 tests[1]tcId 6 resultsArray[0]"),
            "{why}"
        );
        assert!(why.contains("0B"), "{why}");
        let got = json!({"tgId": 2, "tests": [{"tcId": 5, "md": "00"}]});
        let why = check(&expected, &got).expect_err("short");
        assert!(why.contains("1 items where 2"), "{why}");
        let got = json!({"tgId": 2, "extra": 1});
        let why = check(&expected, &got).expect_err("unexpected");
        assert!(why.contains("extra: not expected"), "{why}");
    }

    #[test]
    fn response_carries_the_identity_and_the_mode_when_there_is_one() {
        let prompt = json!({"vsId": 9, "algorithm": "A", "revision": "r"});
        let r = response(&prompt, vec![]);
        assert_eq!(
            r,
            json!({
                "vsId": 9, "algorithm": "A", "revision": "r", "testGroups": []
            })
        );
        let prompt = json!({"vsId": 9, "algorithm": "A", "mode": "m",
            "revision": "r"});
        assert_eq!(response(&prompt, vec![])["mode"], "m");
    }
}
