//! KDF 1.0 and KDF-KMAC Sp800-108r1, run through
//! [`sp800_108`](crate::kdf::sp800_108).
//!
//! KDF 1.0 covers the three modes over HMAC with every SHA-1, SHA-2
//! and SHA-3 hash and over CMAC with AES at every width, with the
//! counter at each width and in each place: before, after and inside
//! the fixed data, the last at a bit position, and before the
//! chaining value or absent for the chaining modes. The CMAC-TDES
//! groups are skipped, and say so: the crate has no Triple DES.
//!
//! The fixed data comes whole, the output length already encoded in
//! it, so an output that is not a whole number of bytes is the bytes
//! it needs with the bits past its end cleared.
//!
//! The server defers the fixed data to the implementation: the
//! vendored file records what its own run chose, and a live session
//! sends none, so [`answer`] draws it afresh and returns it with the
//! key, which is how the server checks the derivation.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, key_of, load, response};
use crate::Random;
use crate::cipher::aes::{Aes128, Aes192, Aes256};
use crate::hash::sha1::Sha1;
use crate::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use crate::hash::sha2::{Sha512_224, Sha512_256};
use crate::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use crate::kdf::sp800_108::{self, Counter};
use crate::mac::Mac;
use crate::mac::cmac::Cmac;
use crate::mac::hmac::Hmac;
use crate::random::CtrDrbg;
use serde_json::{Value, json};

/// Bits of fixed data drawn for a case the server leaves to us.
const FIXED_BITS: usize = 256;

/// The response to a KDF 1.0 vector set.
pub fn answer(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| json!({"tgId": group["tgId"], "tests": tests(group)}))
        .collect();
    response(prompt, groups)
}

/// The response to a KDF-KMAC vector set.
pub fn answer_kmac(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| json!({"tgId": group["tgId"], "tests": kmac_tests(group)}))
        .collect();
    response(prompt, groups)
}

/// Runs KDF 1.0; a no-op without the vendored vectors.
pub fn run() {
    let file = "KDF-1.0/internalProjection.json";
    let Some(doc) = load(file, "KDF", "1.0") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["macMode"] == "CMAC-TDES" {
            eprintln!("tgId {}: no Triple DES; skipping", group["tgId"]);
            continue;
        }
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(tests(group)) {
            if let Err(why) = check(want, &got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            cases += 1;
        }
    }
    // Guard against a truncated or wrong file passing vacuously.
    assert!(cases >= 10_000, "only {cases} cases");
}

/// The response to each test of a group: the key, with the fixed
/// data it was derived under and where the counter broke it.
fn tests(group: &Value) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT");
    let mac = group["macMode"].as_str().expect("macMode");
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let key = hex(&t["keyIn"]);
            match mac {
                "CMAC-AES128" => cmac::<Aes128>(&key, group, t),
                "CMAC-AES192" => cmac::<Aes192>(&key, group, t),
                "CMAC-AES256" => cmac::<Aes256>(&key, group, t),
                "HMAC-SHA-1" => case(&mut Hmac::<Sha1>::new(&key), group, t),
                "HMAC-SHA2-224" => hmac::<Sha224>(&key, group, t),
                "HMAC-SHA2-256" => hmac::<Sha256>(&key, group, t),
                "HMAC-SHA2-384" => hmac::<Sha384>(&key, group, t),
                "HMAC-SHA2-512" => hmac::<Sha512>(&key, group, t),
                "HMAC-SHA2-512/224" => hmac::<Sha512_224>(&key, group, t),
                "HMAC-SHA2-512/256" => hmac::<Sha512_256>(&key, group, t),
                "HMAC-SHA3-224" => hmac::<Sha3_224>(&key, group, t),
                "HMAC-SHA3-256" => hmac::<Sha3_256>(&key, group, t),
                "HMAC-SHA3-384" => hmac::<Sha3_384>(&key, group, t),
                "HMAC-SHA3-512" => hmac::<Sha3_512>(&key, group, t),
                other => panic!("unknown macMode {other}"),
            }
        })
        .collect()
}

fn hmac<H>(key: &[u8], group: &Value, t: &Value) -> Value
where
    H: crate::hash::Hash + Clone + crate::BlockType + Default,
{
    case(&mut Hmac::<H>::new(key), group, t)
}

fn cmac<C>(key: &[u8], group: &Value, t: &Value) -> Value
where
    C: crate::cipher::BlockCipher<Block = [u8; 16]>,
{
    let key = key_of::<Cmac<C>>(key).expect("CMAC key width");
    case(&mut Cmac::<C>::new(&key), group, t)
}

/// The fixed data of a case: the file's where it has one, otherwise
/// fresh random bytes, since the server leaves the choice to us. The
/// break for a counter in the middle is the file's too, or halfway.
fn fixed_data(t: &Value) -> (Vec<u8>, usize) {
    if t["fixedData"].is_null() {
        let mut fixed = vec![0u8; FIXED_BITS / 8];
        let mut rng = CtrDrbg::from_system().expect("generator");
        rng.fill(&mut fixed).expect("random fixed data");
        return (fixed, FIXED_BITS / 2);
    }
    let fixed = hex(&t["fixedData"]);
    let at = t["breakLocation"].as_u64().unwrap_or(0) as usize;
    (fixed, at)
}

/// One derivation: the key, the fixed data and, for a counter in
/// the middle, where it went.
fn case<M: Mac>(prf: &mut M, group: &Value, t: &Value) -> Value {
    let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
    let (fixed, break_at) = fixed_data(t);
    let bits = group["keyOutLength"].as_u64().expect("keyOutLength") as usize;
    let width = group["counterLength"].as_u64().expect("counterLength") as u32;
    let end = 8 * fixed.len();
    let middle = group["counterLocation"] == "middle fixed data";
    let counter = match group["counterLocation"].as_str() {
        Some("none") => Counter::None,
        Some("before iterator") => Counter::BeforeIterator(width),
        Some("before fixed data") => Counter::InFixed { bits: width, at: 0 },
        Some("after fixed data") => Counter::InFixed {
            bits: width,
            at: end,
        },
        Some("middle fixed data") => Counter::InFixed {
            bits: width,
            at: break_at,
        },
        other => panic!("{tag}: unknown counterLocation {other:?}"),
    };

    let mut out = vec![0u8; bits.div_ceil(8)];
    let parts: [&[u8]; 1] = [&fixed];
    match group["kdfMode"].as_str() {
        Some("counter") => {
            let Counter::InFixed { bits, at } = counter else {
                panic!("{tag}: counter mode with {counter:?}");
            };
            sp800_108::counter(prf, bits, at, &parts, &mut out)
        }
        Some("feedback") => {
            let iv = hex(&t["iv"]);
            sp800_108::feedback(prf, &iv, counter, &parts, &mut out)
        }
        Some("double pipeline iteration") => {
            sp800_108::double_pipeline(prf, counter, &parts, &mut out)
        }
        other => panic!("{tag}: unknown kdfMode {other:?}"),
    }
    .unwrap_or_else(|e| panic!("{tag}: {e}"));
    if !bits.is_multiple_of(8)
        && let Some(last) = out.last_mut()
    {
        *last &= 0xffu8 << (8 - bits % 8);
    }
    let mut answer = json!({
        "tcId": t["tcId"],
        "fixedData": hex_string(&fixed),
        "keyOut": hex_string(&out),
    });
    if middle {
        answer["breakLocation"] = json!(break_at);
    }
    answer
}

/// Runs KDF-KMAC; a no-op without the vendored vectors.
pub fn run_kmac() {
    let file = "KDF-KMAC-Sp800-108r1/internalProjection.json";
    let Some(doc) = load(file, "KDF", "Sp800-108r1") else {
        return;
    };
    assert_eq!(doc["mode"], "KMAC");
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let expected = group["tests"].as_array().expect("tests");
        for (want, got) in expected.iter().zip(kmac_tests(group)) {
            if let Err(why) = check(want, &got) {
                panic!("tgId {} {why}", group["tgId"]);
            }
            cases += 1;
        }
    }
    assert!(cases >= 100, "only {cases} cases");
}

/// The response to each test of a KDF-KMAC group: the derived key.
fn kmac_tests(group: &Value) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT");
    let kdf = match group["macMode"].as_str() {
        Some("KMAC-128") => sp800_108::kmac128,
        Some("KMAC-256") => sp800_108::kmac256,
        other => panic!("unknown macMode {other:?}"),
    };
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let bits = t["derivedKeyLength"].as_u64().expect("length");
            assert_eq!(bits % 8, 0, "{tag}: a length in bits");
            let mut out = vec![0u8; bits as usize / 8];
            kdf(
                &hex(&t["keyDerivationKey"]),
                &hex(&t["label"]),
                &hex(&t["context"]),
                &mut out,
            );
            json!({"tcId": t["tcId"], "derivedKey": hex_string(&out)})
        })
        .collect()
}
