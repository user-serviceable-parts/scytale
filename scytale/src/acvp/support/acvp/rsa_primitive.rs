//! The two RSA component suites, which drive the primitives on
//! their own rather than through a scheme.
//!
//! `RSA-SignaturePrimitive` hands over private keys with messages,
//! and is the one place where NIST supplies expected answers under a
//! private exponent, so it is the only external check that a value
//! this crate *produces* with one is the right one. It runs at all
//! three widths in both the plain and the Chinese remainder key
//! forms, and a message at or above the modulus has to be refused.
//!
//! `RSA-decryptionPrimitive` hands over ciphertexts alone. The live
//! server has the implementation draw a key for each and decrypt,
//! reporting the key with the result, or that the ciphertext was at
//! or above the modulus; the server checks the result through the
//! public exponent. The vendored file supplies public keys with
//! each entry's answer and no private exponent, so what it checks is
//! the public direction and the refusal.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, response};
use crate::Error;
use crate::pke::rsa::{PrivateKey as PkePrivateKey, PublicKey as PkePublicKey};
use crate::random::CtrDrbg;
use crate::sig::rsa::PrivateKey;
use serde_json::{Value, json};

/// The modulus the decryption primitive is defined for.
const DECRYPTION_BITS: usize = 2048;

/// The response to a signature primitive vector set.
pub fn answer_signature(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            let tests: Vec<Value> = group["tests"]
                .as_array()
                .expect("tests")
                .iter()
                .map(|t| signature_case(group, t))
                .collect();
            json!({"tgId": group["tgId"], "tests": tests})
        })
        .collect();
    response(prompt, groups)
}

/// One signature-primitive case: the signature, or that the message
/// could not be signed.
fn signature_case(group: &Value, t: &Value) -> Value {
    let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
    let n = hex(&t["n"]);
    let e = hex(&t["e"]);
    let key = match group["keyMode"].as_str().expect("keyMode") {
        "standard" => PrivateKey::try_new(&n, &e, &hex(&t["d"])),
        "crt" => PrivateKey::try_new_crt(
            &n,
            &e,
            &hex(&t["d"]),
            &hex(&t["p"]),
            &hex(&t["q"]),
            &hex(&t["dmp1"]),
            &hex(&t["dmq1"]),
            &hex(&t["iqmp"]),
        ),
        other => panic!("unknown keyMode {other}"),
    }
    .expect("private key");
    assert_eq!(key.bits() as u64, group["modulo"], "{tag} modulus length");

    let message = hex(&t["message"]);
    let len = key.modulus_len();
    let mut signature = vec![0u8; len];
    match key.sign_primitive(&message, &mut signature) {
        Ok(()) => {
            // The public direction must undo it, which also proves
            // the answer is a representative and not a stray value.
            let mut back = vec![0u8; len];
            key.public_key()
                .verify_primitive(&signature, &mut back)
                .expect("verify");
            assert_eq!(back, message, "{tag} round trip");
            json!({"tcId": t["tcId"], "signature": hex_string(&signature)})
        }
        // A representative at or above the modulus, which the
        // primitive is what refuses.
        Err(Error::MessageTooLong) => {
            json!({"tcId": t["tcId"], "testPassed": false})
        }
        Err(e) => panic!("{tag}: {e}"),
    }
}

/// Runs the signature primitive suite; a no-op without the vendored
/// vectors.
pub fn run_signature_primitive() {
    let file = "RSA-SignaturePrimitive-2.0/internalProjection.json";
    let Some(doc) = load(file, "RSA", "2.0") else {
        return;
    };
    assert_eq!(doc["mode"], "signaturePrimitive");
    let mut signed = 0;
    let mut refused = 0;
    let mut crt = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        match group["testType"].as_str() {
            Some("AFT") => {}
            other => panic!("unknown testType {other:?}"),
        }
        let is_crt = group["keyMode"] == "crt";
        for t in group["tests"].as_array().expect("tests") {
            let got = signature_case(group, t);
            if let Err(why) = check(t, &got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            if got["testPassed"] == false {
                // The failing cases carry no signature at all.
                assert!(
                    t["signature"].is_null(),
                    "{} has a signature",
                    t["tcId"]
                );
                refused += 1;
            } else {
                signed += 1;
                if is_crt {
                    crt += 1;
                }
            }
        }
    }
    assert!(signed >= 78, "only {signed} signatures");
    assert!(refused >= 12, "only {refused} refusals");
    // The CRT path is half the point of the suite, so losing it to a
    // change in how the groups are labelled must not pass quietly.
    assert!(crt >= 39, "only {crt} through the primes");
}

/// The response to a decryption primitive vector set: each
/// ciphertext decrypted under a key drawn for it.
pub fn answer_decryption(prompt: &Value) -> Value {
    let mut rng = CtrDrbg::from_system().expect("generator");
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            assert_eq!(group["modulo"], DECRYPTION_BITS, "modulus length");
            let tests: Vec<Value> = group["tests"]
                .as_array()
                .expect("tests")
                .iter()
                .map(|t| {
                    let entries: Vec<Value> = t["resultsArray"]
                        .as_array()
                        .expect("resultsArray")
                        .iter()
                        .map(|r| decryption_entry(&mut rng, r))
                        .collect();
                    json!({"tcId": t["tcId"], "resultsArray": entries})
                })
                .collect();
            json!({"tgId": group["tgId"], "tests": tests})
        })
        .collect();
    response(prompt, groups)
}

/// One entry: a fresh key, and the ciphertext taken through its
/// private exponent, or refused for being at or above the modulus.
fn decryption_entry<R: crate::Random>(rng: &mut R, r: &Value) -> Value {
    let key = PkePrivateKey::generate(rng, DECRYPTION_BITS).expect("generate");
    let public = key.public_key();
    let mut n = vec![0u8; public.modulus_len()];
    public.modulus_bytes(&mut n).expect("modulus");
    let e = public.exponent_bytes();
    let start = e.iter().position(|&b| b != 0).unwrap_or(e.len());
    let mut entry = json!({"n": hex_string(&n), "e": hex_string(&e[start..])});
    let ciphertext = hex(&r["cipherText"]);
    let mut plain = vec![0u8; key.modulus_len()];
    match key.decrypt_primitive(&ciphertext, &mut plain) {
        Ok(()) => entry["plainText"] = json!(hex_string(&plain)),
        Err(Error::DecryptionFailed) => entry["testPassed"] = json!(false),
        Err(e) => panic!("decrypt: {e}"),
    }
    entry
}

/// Runs the decryption primitive suite over the file's public keys;
/// a no-op without the vendored vectors.
pub fn run_decryption_primitive() {
    let file = "RSA-decryptionPrimitive-1.0/internalProjection.json";
    let Some(doc) = load(file, "RSA", "1.0") else {
        return;
    };
    assert_eq!(doc["mode"], "decryptionPrimitive");
    let mut verified = 0;
    let mut refused = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        match group["testType"].as_str() {
            Some("AFT") => {}
            other => panic!("unknown testType {other:?}"),
        }
        assert_eq!(group["modulo"], 2048, "only 2048-bit entries expected");
        for t in group["tests"].as_array().expect("tests") {
            // One case holds many independent entries, each with its
            // own key.
            for (i, r) in t["resultsArray"]
                .as_array()
                .expect("resultsArray")
                .iter()
                .enumerate()
            {
                let tag = format!("tcId {} entry {i}", t["tcId"]);
                let built = PkePublicKey::try_new(&hex(&r["n"]), &hex(&r["e"]));
                let passed = r["testPassed"].as_bool().expect("testPassed");
                // A failing entry can be bad in either of two ways,
                // and the crate refuses them at different points: an
                // even modulus never becomes a key at all, while a
                // ciphertext at or above the modulus is caught by the
                // primitive. Either refusal is the right answer.
                let Ok(key) = built else {
                    assert!(!passed, "{tag} key rejected");
                    refused += 1;
                    continue;
                };
                let len = key.modulus_len();
                assert_eq!(len, 256, "{tag} modulus length");
                if passed {
                    // A representative may be written with a
                    // leading zero byte, so it is right-aligned into
                    // the key's length rather than converted.
                    let bytes = hex(&r["plainText"]);
                    let start = bytes.len().saturating_sub(len);
                    let tail = &bytes[start..];
                    assert!(
                        bytes[..start].iter().all(|b| *b == 0),
                        "{tag} wider than the key"
                    );
                    let mut pt = vec![0u8; len];
                    pt[len - tail.len()..].copy_from_slice(tail);
                    let mut ct = vec![0u8; len];
                    key.encrypt_primitive(&pt, &mut ct).expect("apply");
                    assert_eq!(ct, hex(&r["cipherText"]), "{tag}");
                    verified += 1;
                } else {
                    // No private exponent is given, so the refusal is
                    // checked against the same modulus comparison the
                    // private primitive makes.
                    let ct = hex(&r["cipherText"]);
                    let mut out = vec![0u8; len];
                    assert_eq!(
                        key.encrypt_primitive(&ct, &mut out),
                        Err(Error::MessageTooLong),
                        "{tag}"
                    );
                    refused += 1;
                }
            }
        }
    }
    assert!(verified >= 4, "only {verified} entries verified");
    assert!(refused >= 2, "only {refused} refusals");
}
