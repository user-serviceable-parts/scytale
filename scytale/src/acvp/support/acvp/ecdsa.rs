//! ECDSA keyGen, keyVer, sigGen, sigVer and the deterministic
//! sigGen, for the P-256, P-384 and P-521 groups: the P-224 and
//! binary-curve groups are not implemented, and the SHAKE groups are
//! skipped since ECDSA over an XOF is not offered.
//!
//! The deterministic suite is the exact check on signing, since RFC
//! 6979 fixes the nonce. The random-nonce suite in the vendored file
//! can only be verified; the live run answers it with hedged
//! signatures, which the server can only verify too. The live server
//! asks for more than the file can: keyGen has the implementation
//! draw its keys, and both signing modes have it draw a key per
//! group and report the public half, which the server then verifies
//! the signatures against.
//! Both suites also carry SP 800-106 groups, whose message is
//! randomized before hashing; that scheme is not offered, so those
//! groups are skipped and never registered.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, response};
use crate::BlockType;
use crate::Error;
use crate::hash::Hash;
use crate::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use crate::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use crate::random::CtrDrbg;
use crate::sig::ecdsa::{p256, p384, p521};
use serde_json::{Value, json};

/// One curve's key types, so a driver can be written once.
pub trait Curve {
    const NAME: &'static str;
    const WIDTH: usize;
    type Private;
    type Public;
    fn generate() -> Self::Private;
    fn private(d: &[u8]) -> Result<Self::Private, Error>;
    fn secret_of(key: &Self::Private) -> Vec<u8>;
    fn public(sec1: &[u8]) -> Result<Self::Public, Error>;
    fn public_of(key: &Self::Private) -> Vec<u8>;
    /// RFC 6979 when `deterministic`, hedged with fresh noise
    /// otherwise.
    fn sign<H: Hash + Clone + BlockType + Default>(
        key: &Self::Private,
        message: &[u8],
        deterministic: bool,
    ) -> Vec<u8>;
    fn verify<H: Hash + Clone + BlockType + Default>(
        key: &Self::Public,
        message: &[u8],
        sig: &[u8],
    ) -> bool;
}

macro_rules! curve {
    ($name:ident, $module:ident, $acvp:literal, $width:literal) => {
        pub struct $name;
        impl Curve for $name {
            const NAME: &'static str = $acvp;
            const WIDTH: usize = $width;
            type Private = $module::PrivateKey;
            type Public = $module::PublicKey;
            fn generate() -> Self::Private {
                let mut rng = CtrDrbg::from_system().expect("generator");
                $module::PrivateKey::generate(&mut rng).expect("generate")
            }
            fn private(d: &[u8]) -> Result<Self::Private, Error> {
                let d: [u8; $width] = d.try_into().expect("d width");
                $module::PrivateKey::try_new(&d)
            }
            fn secret_of(key: &Self::Private) -> Vec<u8> {
                key.secret_bytes().to_vec()
            }
            fn public(sec1: &[u8]) -> Result<Self::Public, Error> {
                $module::PublicKey::try_from_sec1(sec1)
            }
            fn public_of(key: &Self::Private) -> Vec<u8> {
                key.public_key().sec1_bytes().to_vec()
            }
            fn sign<H: Hash + Clone + BlockType + Default>(
                key: &Self::Private,
                message: &[u8],
                deterministic: bool,
            ) -> Vec<u8> {
                let sig = if deterministic {
                    key.sign_deterministic::<H>(message)
                } else {
                    let mut rng = CtrDrbg::from_system().expect("generator");
                    key.sign::<H, _>(&mut rng, message)
                };
                sig.expect("sign").to_vec()
            }
            fn verify<H: Hash + Clone + BlockType + Default>(
                key: &Self::Public,
                message: &[u8],
                sig: &[u8],
            ) -> bool {
                match <[u8; 2 * $width]>::try_from(sig) {
                    Ok(sig) => key.verify::<H>(message, &sig).is_ok(),
                    Err(_) => false,
                }
            }
        }
    };
}

curve!(P256, p256, "P-256", 32);
curve!(P384, p384, "P-384", 48);
curve!(P521, p521, "P-521", 66);

/// A big-endian value left-padded to `width`, or `None` when it is
/// wider, which a keyVer case may deliberately be.
fn padded(v: &Value, width: usize) -> Option<Vec<u8>> {
    let bytes = hex(v);
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let value = &bytes[start..];
    if value.len() > width {
        return None;
    }
    let mut out = vec![0u8; width - value.len()];
    out.extend_from_slice(value);
    Some(out)
}

/// The uncompressed point from a group's or case's `qx` and `qy`.
fn sec1(v: &Value, width: usize) -> Option<Vec<u8>> {
    let mut out = vec![0x04];
    out.extend(padded(&v["qx"], width)?);
    out.extend(padded(&v["qy"], width)?);
    Some(out)
}

/// The `qx` and `qy` of an uncompressed point, as the response
/// carries them.
fn coordinates(sec1: &[u8], width: usize) -> (String, String) {
    let (x, y) = sec1[1..].split_at(width);
    (hex_string(x), hex_string(y))
}

/// The signature `r || s` from a case.
fn signature(t: &Value, width: usize) -> Option<Vec<u8>> {
    let mut out = padded(&t["r"], width)?;
    out.extend(padded(&t["s"], width)?);
    Some(out)
}

/// Calls `$f::<C, H>($args)` for the group's hash, or skips the
/// group for a hash the scheme does not take here.
macro_rules! with_hash {
    ($hash:expr, $f:ident::<$c:ty>($($arg:expr),*)) => {
        match $hash {
            "SHA2-224" => Some($f::<$c, Sha224>($($arg),*)),
            "SHA2-256" => Some($f::<$c, Sha256>($($arg),*)),
            "SHA2-384" => Some($f::<$c, Sha384>($($arg),*)),
            "SHA2-512" => Some($f::<$c, Sha512>($($arg),*)),
            "SHA2-512/224" => Some($f::<$c, Sha512_224>($($arg),*)),
            "SHA2-512/256" => Some($f::<$c, Sha512_256>($($arg),*)),
            "SHA3-224" => Some($f::<$c, Sha3_224>($($arg),*)),
            "SHA3-256" => Some($f::<$c, Sha3_256>($($arg),*)),
            "SHA3-384" => Some($f::<$c, Sha3_384>($($arg),*)),
            "SHA3-512" => Some($f::<$c, Sha3_512>($($arg),*)),
            "SHAKE-128" | "SHAKE-256" => None,
            other => panic!("unknown hash {other}"),
        }
    };
}

/// Calls `$f::<C>($args)` for the group's curve, or `None` for a
/// curve not implemented.
macro_rules! with_curve {
    ($curve:expr, $f:ident($($arg:expr),*)) => {
        match $curve {
            Some(P256::NAME) => Some($f::<P256>($($arg),*)),
            Some(P384::NAME) => Some($f::<P384>($($arg),*)),
            Some(P521::NAME) => Some($f::<P521>($($arg),*)),
            _ => None,
        }
    };
}

/// The response to a whole vector set, by its mode. A group this
/// crate cannot answer is a registration gone wrong.
pub fn answer(prompt: &Value) -> Value {
    let mode = prompt["mode"].as_str().expect("mode");
    let deterministic = prompt["algorithm"] == "DetECDSA";
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            let curve = group["curve"].as_str();
            let answered = match mode {
                "keyGen" => with_curve!(curve, key_gen_group(group)),
                "keyVer" => with_curve!(curve, key_ver_group(group)),
                "sigGen" => {
                    with_curve!(curve, sig_gen_group(group, deterministic))
                }
                "sigVer" => with_curve!(curve, sig_ver_group(group)),
                other => panic!("unknown mode {other}"),
            };
            match answered.flatten() {
                Some(mut g) => {
                    g["tgId"] = group["tgId"].clone();
                    g
                }
                None => panic!(
                    "tgId {}: {curve:?} with {} is not offered{}",
                    group["tgId"],
                    group["hashAlg"],
                    if deterministic {
                        " (deterministic)"
                    } else {
                        ""
                    }
                ),
            }
        })
        .collect();
    response(prompt, groups)
}

/// Draws a key per case and reports both halves.
fn key_gen_group<C: Curve>(group: &Value) -> Option<Value> {
    let tests: Vec<Value> = group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let key = C::generate();
            let (qx, qy) = coordinates(&C::public_of(&key), C::WIDTH);
            json!({
                "tcId": t["tcId"],
                "d": hex_string(&C::secret_of(&key)),
                "qx": qx,
                "qy": qy,
            })
        })
        .collect();
    Some(json!({"tests": tests}))
}

fn key_ver_group<C: Curve>(group: &Value) -> Option<Value> {
    let tests: Vec<Value> = group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| json!({"tcId": t["tcId"], "testPassed": key_ver::<C>(t)}))
        .collect();
    Some(json!({"tests": tests}))
}

/// Draws the group's key, signs every message with it, and reports
/// the public half beside the signatures. `None` for a hash or a
/// conformance the scheme does not take here.
fn sig_gen_group<C: Curve>(
    group: &Value,
    deterministic: bool,
) -> Option<Value> {
    if group["conformance"] == "SP800-106" || group["componentTest"] == true {
        return None;
    }
    let hash = group["hashAlg"].as_str().expect("hashAlg");
    let key = C::generate();
    let tests = with_hash!(hash, sign_tests::<C>(&key, group, deterministic))?;
    let (qx, qy) = coordinates(&C::public_of(&key), C::WIDTH);
    // The server will verify these against the coordinates reported;
    // do the same here, so a slip in the encoding is caught before
    // anything is sent.
    let mut as_sent = group.clone();
    for t in as_sent["tests"].as_array_mut().expect("tests") {
        t["qx"] = json!(qx);
        t["qy"] = json!(qy);
    }
    for (t, signed) in as_sent["tests"]
        .as_array_mut()
        .expect("tests")
        .iter_mut()
        .zip(&tests)
    {
        t["r"] = signed["r"].clone();
        t["s"] = signed["s"].clone();
    }
    let verified = with_hash!(hash, verify_tests::<C>(&as_sent))?;
    assert!(
        verified.iter().all(|v| v["testPassed"] == true),
        "tgId {}: a fresh signature failed to verify",
        group["tgId"]
    );
    Some(json!({"qx": qx, "qy": qy, "tests": tests}))
}

fn sig_ver_group<C: Curve>(group: &Value) -> Option<Value> {
    if group["conformance"] == "SP800-106" {
        return None;
    }
    let hash = group["hashAlg"].as_str().expect("hashAlg");
    let tests = with_hash!(hash, verify_tests::<C>(group))?;
    Some(json!({"tests": tests}))
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors. The file's keys cannot be drawn again, so each is
/// checked by deriving its public half from its secret.
pub fn run_key_gen() {
    let file = "ECDSA-KeyGen-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "ECDSA", "FIPS186-5") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let curve = group["curve"].as_str();
            if with_curve!(curve, key_gen_check(t, &tag)).is_none() {
                continue;
            }
            cases += 1;
        }
    }
    assert!(cases >= 18, "only {cases} keyGen cases");
}

fn key_gen_check<C: Curve>(t: &Value, tag: &str) {
    let d = padded(&t["d"], C::WIDTH).expect("d");
    let key = C::private(&d).expect("private key");
    assert_eq!(C::public_of(&key), sec1(t, C::WIDTH).expect("q"), "{tag}");
}

/// Runs the key verification suite; a no-op without the vendored
/// vectors.
pub fn run_key_ver() {
    let file = "ECDSA-KeyVer-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "ECDSA", "FIPS186-5") else {
        return;
    };
    let (mut cases, mut rejections) = (0, 0);
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let curve = group["curve"].as_str();
        let Some(Some(answered)) = with_curve!(curve, key_ver_group(group))
        else {
            continue;
        };
        let (c, r) = hold(group, &answered["tests"]);
        cases += c;
        rejections += r;
    }
    assert!(cases >= 9, "only {cases} keyVer cases");
    assert!(rejections >= 4, "only {rejections} rejections");
}

fn key_ver<C: Curve>(t: &Value) -> bool {
    // A coordinate wider than the field cannot be presented at all.
    sec1(t, C::WIDTH).is_some_and(|q| C::public(&q).is_ok())
}

/// Runs the signature verification suite; a no-op without the
/// vendored vectors.
pub fn run_sig_ver() {
    let file = "ECDSA-SigVer-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "ECDSA", "FIPS186-5") else {
        return;
    };
    let (mut cases, mut rejections) = (0, 0);
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let curve = group["curve"].as_str();
        let Some(Some(answered)) = with_curve!(curve, sig_ver_group(group))
        else {
            continue;
        };
        let (c, r) = hold(group, &answered["tests"]);
        cases += c;
        rejections += r;
    }
    assert!(cases >= 105, "only {cases} sigVer cases");
    assert!(rejections >= 40, "only {rejections} rejections");
}

/// Holds each answered test to the group's, returning the cases and
/// the rejections among them.
fn hold(group: &Value, answered: &Value) -> (usize, usize) {
    let expected = group["tests"].as_array().expect("tests");
    let answered = answered.as_array().expect("answers");
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

fn verify_tests<C: Curve, H: Hash + Clone + BlockType + Default>(
    group: &Value,
) -> Vec<Value> {
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let passed = sec1(t, C::WIDTH)
                .and_then(|q| C::public(&q).ok())
                .zip(signature(t, C::WIDTH))
                .is_some_and(|(key, sig)| {
                    C::verify::<H>(&key, &hex(&t["message"]), &sig)
                });
            json!({"tcId": t["tcId"], "testPassed": passed})
        })
        .collect()
}

/// Signs each message of `group` under `key`.
fn sign_tests<C: Curve, H: Hash + Clone + BlockType + Default>(
    key: &C::Private,
    group: &Value,
    deterministic: bool,
) -> Vec<Value> {
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let sig = C::sign::<H>(key, &hex(&t["message"]), deterministic);
            let (r, s) = sig.split_at(C::WIDTH);
            json!({"tcId": t["tcId"], "r": hex_string(r), "s": hex_string(s)})
        })
        .collect()
}

/// Runs the random-nonce generation suite by verifying its
/// answers; a no-op without the vendored vectors.
pub fn run_sig_gen() {
    let file = "ECDSA-SigGen-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "ECDSA", "FIPS186-5") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["conformance"] == "SP800-106" {
            continue;
        }
        let hash = group["hashAlg"].as_str().expect("hashAlg");
        let curve = group["curve"].as_str();
        let ran = with_curve!(curve, sig_gen_verified(group, hash));
        cases += ran.flatten().unwrap_or(0);
    }
    assert!(cases >= 300, "only {cases} sigGen cases");
}

/// One random-nonce group: the key from `d` must give the group's
/// `q`, and each case's signature must verify. Returns the cases.
fn sig_gen_verified<C: Curve>(group: &Value, hash: &str) -> Option<usize> {
    let d = padded(&group["d"], C::WIDTH).expect("d");
    let key = C::private(&d).expect("private key");
    let q = sec1(group, C::WIDTH).expect("q");
    assert_eq!(C::public_of(&key), q, "tgId {}", group["tgId"]);
    // The cases carry no public key of their own: the verifier reads
    // the group's.
    let mut with_key = group.clone();
    for t in with_key["tests"].as_array_mut().expect("tests") {
        t["qx"] = group["qx"].clone();
        t["qy"] = group["qy"].clone();
    }
    let answered = with_hash!(hash, verify_tests::<C>(&with_key))?;
    for got in &answered {
        assert_eq!(got["testPassed"], true, "tgId {} {}", group["tgId"], got);
    }
    Some(answered.len())
}

/// Runs the deterministic generation suite, comparing exact
/// signatures under the file's keys; a no-op without the vendored
/// vectors.
pub fn run_det_sig_gen() {
    let file = "DetECDSA-SigGen-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "DetECDSA", "FIPS186-5") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["conformance"] == "SP800-106" {
            continue;
        }
        let hash = group["hashAlg"].as_str().expect("hashAlg");
        let curve = group["curve"].as_str();
        let ran = with_curve!(curve, det_sig_gen_exact(group, hash));
        cases += ran.flatten().unwrap_or(0);
    }
    assert!(cases >= 330, "only {cases} deterministic sigGen cases");
}

/// One deterministic group under the file's key: the signatures
/// must be the file's, byte for byte.
fn det_sig_gen_exact<C: Curve>(group: &Value, hash: &str) -> Option<usize> {
    let d = padded(&group["d"], C::WIDTH).expect("d");
    let key = C::private(&d).expect("private key");
    assert_eq!(
        C::public_of(&key),
        sec1(group, C::WIDTH).expect("q"),
        "tgId {}",
        group["tgId"]
    );
    let answered = with_hash!(hash, sign_tests::<C>(&key, group, true))?;
    Some(hold(group, &Value::Array(answered)).0)
}
