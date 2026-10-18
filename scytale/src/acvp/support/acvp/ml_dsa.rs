//! ML-DSA keyGen, sigGen and sigVer (FIPS 204), all three parameter
//! sets, for the pure external interface the crate offers: the
//! groups for the internal interface, the pre-hashed variant and an
//! externally supplied `mu` are skipped. Signing runs hedged with the
//! vector's `rnd` supplied through a fixed random source, or
//! deterministically where the group says so, and must reproduce
//! the signature byte for byte; keys come from the seed and from the
//! expanded form alike.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, response};
use crate::Error;
use crate::Random;
use crate::sig::ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use serde_json::{Value, json};

/// A random source that yields fixed bytes.
struct Fixed(Vec<u8>);

impl Random for Fixed {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        assert!(self.0.len() >= out.len(), "vector shorter than the draw");
        let rest = self.0.split_off(out.len());
        out.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

trait Set {
    const NAME: &'static str;
    /// `pk || sk` from the seed.
    fn key_gen(seed: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// A signature from the seed or the expanded key, hedged with
    /// `rnd` when given and deterministic otherwise.
    fn sign(
        seed: Option<&[u8]>,
        sk: &[u8],
        rnd: Option<&[u8]>,
        context: &[u8],
        message: &[u8],
    ) -> Vec<u8>;
    fn verify(pk: &[u8], context: &[u8], message: &[u8], sig: &[u8]) -> bool;
}

macro_rules! set {
    ($name:ident, $module:ident, $acvp:literal) => {
        struct $name;
        impl Set for $name {
            const NAME: &'static str = $acvp;
            fn key_gen(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
                let mut rng = Fixed(seed.to_vec());
                let key =
                    $module::PrivateKey::generate(&mut rng).expect("generate");
                (key.public_key().bytes().to_vec(), key.key_bytes().to_vec())
            }
            fn sign(
                seed: Option<&[u8]>,
                sk: &[u8],
                rnd: Option<&[u8]>,
                context: &[u8],
                message: &[u8],
            ) -> Vec<u8> {
                let key = match seed {
                    Some(seed) => {
                        let seed: [u8; 32] = seed.try_into().expect("seed");
                        $module::PrivateKey::from_seed(&seed)
                    }
                    None => {
                        let sk: [u8; $module::KEY_SIZE] =
                            sk.try_into().expect("sk width");
                        $module::PrivateKey::try_new(&sk).expect("sk")
                    }
                };
                let sig = match rnd {
                    Some(rnd) => key
                        .sign(&mut Fixed(rnd.to_vec()), context, message)
                        .expect("sign"),
                    None => {
                        key.sign_deterministic(context, message).expect("sign")
                    }
                };
                sig.to_vec()
            }
            fn verify(
                pk: &[u8],
                context: &[u8],
                message: &[u8],
                sig: &[u8],
            ) -> bool {
                let Ok(pk) = <[u8; $module::PUBLIC_KEY_SIZE]>::try_from(pk)
                else {
                    return false;
                };
                let Ok(sig) = <[u8; $module::SIGNATURE_SIZE]>::try_from(sig)
                else {
                    return false;
                };
                let key = $module::PublicKey::new(&pk);
                key.verify(context, message, &sig).is_ok()
            }
        }
    };
}

set!(Set44, ml_dsa_44, "ML-DSA-44");
set!(Set65, ml_dsa_65, "ML-DSA-65");
set!(Set87, ml_dsa_87, "ML-DSA-87");

macro_rules! with_set {
    ($set:expr, $f:ident($($arg:expr),*)) => {
        match $set {
            Set44::NAME => $f::<Set44>($($arg),*),
            Set65::NAME => $f::<Set65>($($arg),*),
            Set87::NAME => $f::<Set87>($($arg),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

/// Whether a group is one the pure external interface can run.
fn pure_external(group: &Value) -> bool {
    group["signatureInterface"] == "external"
        && group["preHash"] == "pure"
        && group["externalMu"] != true
}

/// The response to a whole vector set, by its mode. A group the
/// pure external interface cannot run is a registration gone wrong.
pub fn answer(prompt: &Value) -> Value {
    let mode = prompt["mode"].as_str().expect("mode");
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            if mode != "keyGen" && !pure_external(group) {
                panic!(
                    "tgId {}: not the pure external interface",
                    group["tgId"]
                );
            }
            json!({"tgId": group["tgId"], "tests": tests(mode, group)})
        })
        .collect();
    response(prompt, groups)
}

/// The response to each test of a group, by the set's mode.
fn tests(mode: &str, group: &Value) -> Vec<Value> {
    let set = group["parameterSet"].as_str().expect("parameterSet");
    let deterministic = group["deterministic"] == true;
    let seed = group["keyFormat"] == "seed";
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| match mode {
            "keyGen" => with_set!(set, key_gen(t)),
            "sigGen" => {
                let sig = with_set!(set, sig_gen(t, deterministic, seed));
                json!({"tcId": t["tcId"], "signature": hex_string(&sig)})
            }
            "sigVer" => {
                let passed = with_set!(set, sig_ver(t));
                json!({"tcId": t["tcId"], "testPassed": passed})
            }
            other => panic!("unknown mode {other}"),
        })
        .collect()
}

/// Holds each answered test of `group` to the file's. Returns the
/// cases and, of those, the verdicts that were rejections.
fn hold(mode: &str, group: &Value) -> (usize, usize) {
    let expected = group["tests"].as_array().expect("tests");
    let answered = tests(mode, group);
    assert_eq!(expected.len(), answered.len(), "tgId {}", group["tgId"]);
    let mut rejections = 0;
    for (want, got) in expected.iter().zip(&answered) {
        if let Err(why) = check(want, got) {
            panic!("tgId {} {why}: {}", group["tgId"], want["reason"]);
        }
        if got["testPassed"] == false {
            rejections += 1;
        }
    }
    (expected.len(), rejections)
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors.
pub fn run_key_gen() {
    let file = "ML-DSA-keyGen-FIPS204/internalProjection.json";
    let Some(doc) = load(file, "ML-DSA", "FIPS204") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        cases += hold("keyGen", group).0;
    }
    assert!(cases >= 75, "only {cases} keyGen cases");
}

fn key_gen<S: Set>(t: &Value) -> Value {
    let (pk, sk) = S::key_gen(&hex(&t["seed"]));
    json!({"tcId": t["tcId"], "pk": hex_string(&pk), "sk": hex_string(&sk)})
}

/// Runs the signature generation suite; a no-op without the
/// vendored vectors.
pub fn run_sig_gen() {
    let file = "ML-DSA-sigGen-FIPS204-tr1/internalProjection.json";
    let Some(doc) = load(file, "ML-DSA", "FIPS204-tr1") else {
        return;
    };
    let mut cases = 0;
    let mut hedged = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if !pure_external(group) {
            continue;
        }
        let (ran, _) = hold("sigGen", group);
        cases += ran;
        if group["deterministic"] != true {
            hedged += ran;
        }
    }
    assert!(cases >= 180, "only {cases} sigGen cases");
    assert!(hedged >= 90, "only {hedged} hedged cases");
}

fn sig_gen<S: Set>(t: &Value, deterministic: bool, seed: bool) -> Vec<u8> {
    // Only the fields a group uses are present in its cases.
    let rnd = (!deterministic).then(|| hex(&t["rnd"]));
    let seed_bytes = seed.then(|| hex(&t["seed"]));
    let sk = if seed { Vec::new() } else { hex(&t["sk"]) };
    S::sign(
        seed_bytes.as_deref(),
        &sk,
        rnd.as_deref(),
        &hex(&t["context"]),
        &hex(&t["message"]),
    )
}

/// Runs the signature verification suite; a no-op without the
/// vendored vectors.
pub fn run_sig_ver() {
    let file = "ML-DSA-sigVer-FIPS204/internalProjection.json";
    let Some(doc) = load(file, "ML-DSA", "FIPS204") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if !pure_external(group) {
            continue;
        }
        let (ran, refused) = hold("sigVer", group);
        cases += ran;
        rejections += refused;
    }
    assert!(cases >= 45, "only {cases} sigVer cases");
    assert!(rejections >= 20, "only {rejections} rejections");
}

fn sig_ver<S: Set>(t: &Value) -> bool {
    S::verify(
        &hex(&t["pk"]),
        &hex(&t["context"]),
        &hex(&t["message"]),
        &hex(&t["signature"]),
    )
}
