//! ML-KEM keyGen and encapDecap (FIPS 203), all three parameter
//! sets. The vectors fix the randomness, `d || z` for a key and `m`
//! for an encapsulation, so both run through the public API with a
//! random source that hands back exactly those bytes; decapsulation
//! runs from the seed form and the expanded form alike, and its
//! damaged ciphertexts must come out as the implicitly rejected
//! secret the file gives. The live server sends the same inputs, so
//! the answers are the same computations written out.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, response};
use crate::Error;
use crate::Random;
use crate::kem::ml_kem::{ml_kem_512, ml_kem_768, ml_kem_1024};
use serde_json::{Value, json};

/// A random source that yields fixed bytes, so a vector's `d`, `z`
/// or `m` reaches the scheme through the same call a caller makes.
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

/// One parameter set's types, so each suite is written once.
trait Set {
    const NAME: &'static str;
    /// `ek || dk` from the seed `d || z`.
    fn key_gen(seed: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// `c || k` from `ek` and `m`.
    fn encapsulate(ek: &[u8], m: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// `k` from the expanded `dk` and `c`.
    fn decapsulate(dk: &[u8], c: &[u8]) -> Vec<u8>;
    /// `k` from the seed and `c`.
    fn decapsulate_seed(seed: &[u8], c: &[u8]) -> Vec<u8>;
    /// Whether an expanded `dk` passes the key check.
    fn private_ok(dk: &[u8]) -> bool;
    /// Whether an `ek` passes the key check.
    fn public_ok(ek: &[u8]) -> bool;
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
            fn encapsulate(ek: &[u8], m: &[u8]) -> (Vec<u8>, Vec<u8>) {
                let ek: [u8; $module::PUBLIC_KEY_SIZE] =
                    ek.try_into().expect("ek width");
                let key = $module::PublicKey::try_new(&ek).expect("public");
                let mut rng = Fixed(m.to_vec());
                let (c, k) = key.encapsulate(&mut rng).expect("encapsulate");
                (c.to_vec(), k.to_vec())
            }
            fn decapsulate(dk: &[u8], c: &[u8]) -> Vec<u8> {
                let dk: [u8; $module::KEY_SIZE] = dk.try_into().expect("dk");
                let key = $module::PrivateKey::try_new(&dk).expect("private");
                let c: [u8; $module::CIPHERTEXT_SIZE] =
                    c.try_into().expect("c width");
                key.decapsulate(&c).to_vec()
            }
            fn decapsulate_seed(seed: &[u8], c: &[u8]) -> Vec<u8> {
                let seed: [u8; 64] = seed.try_into().expect("seed width");
                let key = $module::PrivateKey::from_seed(&seed);
                let c: [u8; $module::CIPHERTEXT_SIZE] =
                    c.try_into().expect("c width");
                key.decapsulate(&c).to_vec()
            }
            fn private_ok(dk: &[u8]) -> bool {
                <[u8; $module::KEY_SIZE]>::try_from(dk)
                    .is_ok_and(|dk| $module::PrivateKey::try_new(&dk).is_ok())
            }
            fn public_ok(ek: &[u8]) -> bool {
                <[u8; $module::PUBLIC_KEY_SIZE]>::try_from(ek)
                    .is_ok_and(|ek| $module::PublicKey::try_new(&ek).is_ok())
            }
        }
    };
}

set!(Set512, ml_kem_512, "ML-KEM-512");
set!(Set768, ml_kem_768, "ML-KEM-768");
set!(Set1024, ml_kem_1024, "ML-KEM-1024");

/// Runs `$f::<S>($args)` for the group's parameter set.
macro_rules! with_set {
    ($set:expr, $f:ident($($arg:expr),*)) => {
        match $set {
            Set512::NAME => $f::<Set512>($($arg),*),
            Set768::NAME => $f::<Set768>($($arg),*),
            Set1024::NAME => $f::<Set1024>($($arg),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

/// The response to a whole vector set, keyGen or encapDecap.
pub fn answer(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| json!({"tgId": group["tgId"], "tests": tests(group)}))
        .collect();
    response(prompt, groups)
}

/// The response to each test of a group, by the group's function;
/// a keyGen group has none.
fn tests(group: &Value) -> Vec<Value> {
    let set = group["parameterSet"].as_str().expect("parameterSet");
    let function = group["function"].as_str().unwrap_or("keyGen");
    let seed = group["keyFormat"] == "seed";
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| match function {
            "keyGen" => with_set!(set, key_gen(t)),
            "encapsulation" => with_set!(set, encapsulation(t)),
            "decapsulation" => with_set!(set, decapsulation(t, seed)),
            "decapsulationKeyCheck" => {
                let ok = with_set!(set, private_ok(&hex(&t["dk"])));
                json!({"tcId": t["tcId"], "testPassed": ok})
            }
            "encapsulationKeyCheck" => {
                let ok = with_set!(set, public_ok(&hex(&t["ek"])));
                json!({"tcId": t["tcId"], "testPassed": ok})
            }
            other => panic!("unknown function {other}"),
        })
        .collect()
}

fn private_ok<S: Set>(dk: &[u8]) -> bool {
    S::private_ok(dk)
}

fn public_ok<S: Set>(ek: &[u8]) -> bool {
    S::public_ok(ek)
}

/// Holds each answered test of `group` to the file's. Returns the
/// cases and, of those, the verdicts that were rejections.
fn hold(group: &Value) -> (usize, usize) {
    let expected = group["tests"].as_array().expect("tests");
    let answered = tests(group);
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
    let file = "ML-KEM-keyGen-FIPS203/internalProjection.json";
    let Some(doc) = load(file, "ML-KEM", "FIPS203") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        cases += hold(group).0;
    }
    assert!(cases >= 75, "only {cases} keyGen cases");
}

/// Both halves from the case's `d` and `z`.
fn key_gen<S: Set>(t: &Value) -> Value {
    let mut seed = hex(&t["d"]);
    seed.extend(hex(&t["z"]));
    let (ek, dk) = S::key_gen(&seed);
    json!({"tcId": t["tcId"], "ek": hex_string(&ek), "dk": hex_string(&dk)})
}

/// Runs the encapsulation and decapsulation suite; a no-op without
/// the vendored vectors.
pub fn run_encap_decap() {
    let file = "ML-KEM-encapDecap-FIPS203-tr1/internalProjection.json";
    let Some(doc) = load(file, "ML-KEM", "FIPS203-tr1") else {
        return;
    };
    let mut encapsulations = 0;
    let mut decapsulations = 0;
    let mut rejections = 0;
    let mut checks = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let (cases, _) = hold(group);
        match group["function"].as_str().expect("function") {
            "encapsulation" => encapsulations += cases,
            "decapsulation" => {
                decapsulations += cases;
                // A damaged ciphertext is answered with the implicit
                // rejection secret, and the file says which those are.
                rejections += group["tests"]
                    .as_array()
                    .expect("tests")
                    .iter()
                    .filter(|t| {
                        t["reason"]
                            .as_str()
                            .is_some_and(|r| r.contains("modified"))
                    })
                    .count();
            }
            _ => checks += cases,
        }
    }
    assert!(encapsulations >= 75, "only {encapsulations} encapsulations");
    assert!(decapsulations >= 60, "only {decapsulations} decapsulations");
    assert!(rejections >= 20, "only {rejections} implicit rejections");
    assert!(checks >= 30, "only {checks} key checks");
}

/// The ciphertext and secret from `ek` and the case's `m`.
fn encapsulation<S: Set>(t: &Value) -> Value {
    let (c, k) = S::encapsulate(&hex(&t["ek"]), &hex(&t["m"]));
    json!({"tcId": t["tcId"], "c": hex_string(&c), "k": hex_string(&k)})
}

/// The secret from the key, in the group's format, and `c`. The
/// server sends a seed as one `seed`; the vendored file as `d` and
/// `z`.
fn decapsulation<S: Set>(t: &Value, seed: bool) -> Value {
    let c = hex(&t["c"]);
    let k = if seed {
        let seed = if t["seed"].is_null() {
            let mut seed = hex(&t["d"]);
            seed.extend(hex(&t["z"]));
            seed
        } else {
            hex(&t["seed"])
        };
        S::decapsulate_seed(&seed, &c)
    } else {
        S::decapsulate(&hex(&t["dk"]), &c)
    };
    json!({"tcId": t["tcId"], "k": hex_string(&k)})
}
