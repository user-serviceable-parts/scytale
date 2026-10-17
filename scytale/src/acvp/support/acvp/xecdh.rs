//! XECDH key generation, key verification and shared-secret
//! computation (RFC 7748) for Curve25519; Curve448 is not
//! implemented and never registered.
//!
//! The vendored shared-secret file gives each party's keys, and the
//! secret is checked from both sides. The live server gives only its
//! own public key, and the implementation draws a key per case and
//! reports its public half with the secret, as it does for keyGen.
//!
//! RFC 7748 masks the top bit and accepts any 32-byte string as a
//! public key, so the only key the library can refuse is one of
//! another length, and that is what keyVer here reports. The file
//! for it is not vendored: its failures are all lengths, which the
//! type refuses before any arithmetic, and its one other reason, a
//! set top bit, is a passing case.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, response};
use crate::kex::x25519;
use crate::random::CtrDrbg;
use serde_json::{Value, json};

const CURVE: &str = "Curve25519";

fn secret() -> [u8; 32] {
    let mut rng = CtrDrbg::from_system().expect("generator");
    x25519::PrivateKey::generate(&mut rng)
        .expect("generate")
        .secret_bytes()
}

/// The response to a whole vector set, by its mode.
pub fn answer(prompt: &Value) -> Value {
    let mode = prompt["mode"].as_str().expect("mode");
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            assert_eq!(group["curve"], CURVE, "tgId {}", group["tgId"]);
            let tests: Vec<Value> = group["tests"]
                .as_array()
                .expect("tests")
                .iter()
                .map(|t| match mode {
                    "keyGen" => key_gen(t),
                    "keyVer" => key_ver(t),
                    "SSC" => shared_secret(t, &secret()),
                    other => panic!("unknown mode {other}"),
                })
                .collect();
            json!({"tgId": group["tgId"], "tests": tests})
        })
        .collect();
    response(prompt, groups)
}

fn key_gen(t: &Value) -> Value {
    let secret = secret();
    json!({
        "tcId": t["tcId"],
        "privateKey": hex_string(&secret),
        "publicKey": hex_string(&x25519::public_key(&secret)),
    })
}

fn key_ver(t: &Value) -> Value {
    let usable = hex(&t["publicKey"]).len() == 32;
    json!({"tcId": t["tcId"], "testPassed": usable})
}

/// The shared secret with the server's public key, under `secret`,
/// whose public half is reported beside it.
fn shared_secret(t: &Value, secret: &[u8; 32]) -> Value {
    let server: [u8; 32] = hex(&t["publicServer"]).try_into().expect("key");
    json!({
        "tcId": t["tcId"],
        "publicIut": hex_string(&x25519::public_key(secret)),
        "z": hex_string(&x25519::x25519(secret, &server)),
    })
}

/// Runs the shared-secret suite; a no-op without the vendored
/// vectors. The file gives the implementation's key, so the answer
/// is checked from its side and then from the server's.
pub fn run() {
    let file = "XECDH-SSC-RFC7748/internalProjection.json";
    let Some(doc) = load(file, "XECDH", "RFC7748") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != CURVE {
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let key = |name: &str| -> [u8; 32] {
                hex(&t[name]).try_into().expect("key")
            };
            let answered = shared_secret(t, &key("privateIut"));
            if let Err(why) = check(t, &answered) {
                panic!("{tag} {why}");
            }
            let server =
                x25519::x25519(&key("privateServer"), &key("publicIut"));
            assert_eq!(server, key("z"), "{tag} server side");
            cases += 1;
        }
    }
    assert!(cases >= 20, "only {cases} cases");
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors. The file's keys cannot be drawn again, so each is
/// checked by deriving its public half from its secret.
pub fn run_key_gen() {
    let file = "XECDH-keyGen-RFC7748/internalProjection.json";
    let Some(doc) = load(file, "XECDH", "RFC7748") else {
        return;
    };
    assert_eq!(doc["mode"], "keyGen");
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != CURVE {
            eprintln!(
                "tgId {}: {} not implemented; skipping",
                group["tgId"], group["curve"]
            );
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let secret: [u8; 32] =
                hex(&t["privateKey"]).try_into().expect("privateKey");
            let public: [u8; 32] =
                hex(&t["publicKey"]).try_into().expect("publicKey");
            assert_eq!(x25519::public_key(&secret), public, "{tag}");
            cases += 1;
        }
    }
    assert!(cases >= 10, "only {cases} keyGen cases");
}
