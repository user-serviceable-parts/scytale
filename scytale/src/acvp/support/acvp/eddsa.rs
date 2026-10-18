//! EDDSA keyGen, keyVer, sigGen and sigVer, for the Ed25519 groups:
//! plain Ed25519, and Ed25519ph where a group is marked `preHash`.
//! The pre-hashed cases give the message, which the harness hashes
//! with SHA-512 before handing the digest over. Signing is
//! deterministic, so the vendored sigGen compares exact bytes under
//! the file's keys; the live server has the implementation draw a
//! key per group and verifies against the public half it reports.
//! sigVer and keyVer carry the deliberately damaged cases. Ed448 is
//! not implemented and never registered.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, response};
use crate::Error;
use crate::hash::Hash;
use crate::hash::sha2::Sha512;
use crate::random::CtrDrbg;
use crate::sig::ed25519;
use serde_json::{Value, json};

const CURVE: &str = "ED-25519";

/// A signature over `message` under `context`, by whichever variant
/// the group names. A context on a plain group is Ed25519ctx.
fn sign(
    secret: &[u8; 32],
    prehash: bool,
    context: &[u8],
    message: &[u8],
) -> [u8; 64] {
    if prehash {
        let digest = Sha512::digest(message);
        ed25519::sign_ph_deterministic(secret, context, &digest)
            .expect("sign_ph")
    } else if context.is_empty() {
        ed25519::sign_deterministic(secret, message)
    } else {
        ed25519::sign_ctx_deterministic(secret, context, message)
            .expect("sign_ctx")
    }
}

/// Whether `signature` verifies, by whichever variant the group
/// names.
fn verify(
    public: &[u8; 32],
    prehash: bool,
    context: &[u8],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), Error> {
    if prehash {
        let digest = Sha512::digest(message);
        ed25519::verify_ph(public, context, &digest, signature)
    } else if context.is_empty() {
        ed25519::verify(public, message, signature)
    } else {
        ed25519::verify_ctx(public, context, message, signature)
    }
}

/// The context of a case: absent in the verification files, which
/// means empty.
fn context(t: &Value) -> Vec<u8> {
    if t["context"].is_null() {
        Vec::new()
    } else {
        hex(&t["context"])
    }
}

fn secret() -> [u8; 32] {
    let mut rng = CtrDrbg::from_system().expect("generator");
    ed25519::PrivateKey::generate(&mut rng)
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
            let mut answered = match mode {
                "keyGen" => key_gen_group(group),
                "keyVer" => json!({"tests": key_ver_tests(group)}),
                "sigGen" => {
                    let secret = secret();
                    json!({
                        "q": hex_string(&ed25519::public_key(&secret)),
                        "tests": sign_tests(&secret, group),
                    })
                }
                "sigVer" => json!({"tests": verify_tests(group)}),
                other => panic!("unknown mode {other}"),
            };
            answered["tgId"] = group["tgId"].clone();
            answered
        })
        .collect();
    response(prompt, groups)
}

fn key_gen_group(group: &Value) -> Value {
    let tests: Vec<Value> = group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let secret = secret();
            json!({
                "tcId": t["tcId"],
                "d": hex_string(&secret),
                "q": hex_string(&ed25519::public_key(&secret)),
            })
        })
        .collect();
    json!({"tests": tests})
}

/// The crate has no standalone key check: a public key is validated
/// as part of verifying with it. That is enough here because
/// [`ed25519::verify`] documents the distinction these cases turn on,
/// returning `InvalidPublicKey` when the key is not a point on the
/// curve and `InvalidSignature` for everything else. The signature
/// handed in is therefore a dummy, and the verdict is read from the
/// error alone.
fn key_ver_tests(group: &Value) -> Vec<Value> {
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let usable = <[u8; 32]>::try_from(hex(&t["q"])).is_ok_and(|q| {
                !matches!(
                    ed25519::verify(&q, b"", &[0u8; 64]),
                    Err(Error::InvalidPublicKey)
                )
            });
            json!({"tcId": t["tcId"], "testPassed": usable})
        })
        .collect()
}

/// Signs each message of `group` under `secret`.
fn sign_tests(secret: &[u8; 32], group: &Value) -> Vec<Value> {
    let prehash = group["preHash"].as_bool().expect("preHash");
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let message = hex(&t["message"]);
            let context = context(t);
            if let Some(length) = t["contextLength"].as_u64() {
                assert_eq!(context.len() as u64, length, "{}", t["tcId"]);
            }
            let signature = sign(secret, prehash, &context, &message);
            json!({"tcId": t["tcId"], "signature": hex_string(&signature)})
        })
        .collect()
}

fn verify_tests(group: &Value) -> Vec<Value> {
    let prehash = group["preHash"].as_bool().expect("preHash");
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let public = <[u8; 32]>::try_from(hex(&t["q"])).ok();
            let signature = <[u8; 64]>::try_from(hex(&t["signature"])).ok();
            let accepted = public.zip(signature).is_some_and(|(q, sig)| {
                verify(&q, prehash, &context(t), &hex(&t["message"]), &sig)
                    .is_ok()
            });
            json!({"tcId": t["tcId"], "testPassed": accepted})
        })
        .collect()
}

/// Holds each answered test to the group's, returning the cases and
/// the rejections among them.
fn hold(group: &Value, answered: &[Value]) -> (usize, usize) {
    let expected = group["tests"].as_array().expect("tests");
    assert_eq!(expected.len(), answered.len(), "tgId {}", group["tgId"]);
    let mut rejections = 0;
    for (want, got) in expected.iter().zip(answered) {
        if let Err(why) = check(want, got) {
            panic!("tgId {} {why}: {}", group["tgId"], want["reason"]);
        }
        if got["testPassed"] == false {
            rejections += 1;
        }
    }
    (expected.len(), rejections)
}

/// Runs the generation suite under the file's keys; a no-op without
/// the vendored vectors.
pub fn run_sig_gen() {
    let file = "EDDSA-SigGen-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    let mut cases = 0;
    let mut prehashed = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != CURVE {
            continue;
        }
        let secret: [u8; 32] = hex(&group["d"]).try_into().expect("d");
        let public: [u8; 32] = hex(&group["q"]).try_into().expect("q");
        assert_eq!(ed25519::public_key(&secret), public);
        let answered = sign_tests(&secret, group);
        let (c, _) = hold(group, &answered);
        cases += c;
        if group["preHash"] == true {
            prehashed += c;
        }
    }
    assert!(cases >= 80, "only {cases} sigGen cases");
    assert!(prehashed >= 40, "only {prehashed} Ed25519ph sigGen cases");
}

/// Runs the verification suite; a no-op without the vendored
/// vectors.
pub fn run_sig_ver() {
    let file = "EDDSA-SigVer-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    let (mut cases, mut rejections, mut prehashed) = (0, 0, 0);
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != CURVE {
            continue;
        }
        let (c, r) = hold(group, &verify_tests(group));
        cases += c;
        rejections += r;
        if group["preHash"] == true {
            prehashed += c;
        }
    }
    assert!(cases >= 10, "only {cases} sigVer cases");
    assert!(prehashed >= 5, "only {prehashed} Ed25519ph sigVer cases");
    assert!(rejections >= 1, "no case had to be rejected");
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors. The file's keys cannot be drawn again, so each is
/// checked by deriving its public half from its secret.
pub fn run_key_gen() {
    let file = "EDDSA-KeyGen-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
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
            let secret: [u8; 32] = hex(&t["d"]).try_into().expect("d");
            let public: [u8; 32] = hex(&t["q"]).try_into().expect("q");
            assert_eq!(ed25519::public_key(&secret), public, "{tag}");
            cases += 1;
        }
    }
    assert!(cases >= 3, "only {cases} keyGen cases");
}

/// Runs the key validation suite; a no-op without the vendored
/// vectors.
pub fn run_key_ver() {
    let file = "EDDSA-KeyVer-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    assert_eq!(doc["mode"], "keyVer");
    let (mut cases, mut rejections) = (0, 0);
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != CURVE {
            eprintln!(
                "tgId {}: {} not implemented; skipping",
                group["tgId"], group["curve"]
            );
            continue;
        }
        let (c, r) = hold(group, &key_ver_tests(group));
        cases += c;
        rejections += r;
    }
    assert!(cases >= 4, "only {cases} keyVer cases");
    assert!(rejections >= 2, "only {rejections} rejections");
}
