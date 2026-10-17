//! KTS-IFC (SP 800-56Br2): RSA-OAEP key transport, which is what
//! [`pke::rsa`](crate::pke::rsa) implements.
//!
//! The live run registers `KTS-OAEP-basic`, transport with no key
//! confirmation, in both roles. As initiator the implementation
//! draws the secret, encrypts it under the server's key and reports
//! the ciphertext with the secret; as responder it decrypts the
//! server's ciphertext under the key the server supplies for it.
//! The mode is without a derivation step, so the transported secret
//! is the keying material itself.
//!
//! Every group in the vendored file is
//! `KTS-OAEP-Party_V-confirmation`, so every one asks for key
//! confirmation over the transported key. The crate does no key
//! confirmation, so `macKey`, `macData` and `tag`, an HMAC-SHA-1 or
//! KMAC-128 tag, are **not checked**. What runs is the OAEP
//! transport alone, which is the part the crate owns, and the file
//! hands over the whole private key of whichever party decrypts, so
//! both roles are checked by decryption. Two groups use SHA-1 for
//! OAEP and two SHA-512.
//!
//! One pattern of associated data is built, which is the OAEP label:
//! `l` as four big-endian bytes, then the initiator's identifier,
//! then the responder's, then the label from the case. The initiator
//! is the server in a responder group and the IUT in an initiator
//! group.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{check, hex, hex_string, load, response};
use crate::Random;
use crate::hash::Hash;
use crate::hash::sha1::Sha1;
use crate::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use crate::pke::rsa::{PrivateKey, PublicKey};
use crate::random::CtrDrbg;
use serde_json::{Value, json};

const FILE: &str = "KTS-IFC-Sp800-56Br2/internalProjection.json";

/// The associated-data patterns this driver knows how to build.
const EMPTY: &str = "";
const PARTY_INFO: &str = "l||uPartyInfo||vPartyInfo||label";

/// Calls `$f::<H>($args)` for the group's OAEP hash.
macro_rules! with_hash {
    ($alg:expr, $f:ident($($arg:expr),*)) => {
        match $alg {
            "SHA-1" => $f::<Sha1>($($arg),*),
            "SHA2-224" => $f::<Sha224>($($arg),*),
            "SHA2-256" => $f::<Sha256>($($arg),*),
            "SHA2-384" => $f::<Sha384>($($arg),*),
            "SHA2-512" => $f::<Sha512>($($arg),*),
            other => panic!("OAEP under {other} is not offered"),
        }
    };
}

/// Why a group cannot run, or `None` if it can.
fn skip_reason(group: &Value) -> Option<String> {
    match group["testType"].as_str() {
        Some("AFT") => {}
        other => panic!("unknown testType {other:?}"),
    }
    if group["kasMode"] != "noKdfKc" && group["kasMode"] != "noKdfNoKc" {
        return Some(format!(
            "{} derives the key rather than transporting it",
            group["kasMode"]
        ));
    }
    let kts = &group["ktsConfiguration"];
    let hash = kts["hashAlg"].as_str().expect("hashAlg");
    if !matches!(
        hash,
        "SHA-1" | "SHA2-224" | "SHA2-256" | "SHA2-384" | "SHA2-512"
    ) {
        return Some(format!("OAEP under {hash}"));
    }
    if group["modulo"] != 2048 {
        return Some(format!("a {}-bit modulus", group["modulo"]));
    }
    let pattern = kts["associatedDataPattern"].as_str().expect("pattern");
    if pattern != EMPTY && pattern != PARTY_INFO {
        return Some(format!("the pattern {pattern}"));
    }
    // An empty pattern makes the encoding moot; a built one must say
    // how its pieces join.
    if pattern == PARTY_INFO && kts["encoding"] != "concatenation" {
        return Some(format!("the encoding {}", kts["encoding"]));
    }
    None
}

/// The OAEP label a group asks for, for one case.
fn label(group: &Value, t: &Value) -> Vec<u8> {
    let kts = &group["ktsConfiguration"];
    if kts["associatedDataPattern"] == EMPTY {
        return Vec::new();
    }
    let l = group["l"].as_u64().expect("l") as u32;
    // The initiator contributes uPartyInfo, so which identifier comes
    // first depends on which side the IUT is.
    let (u, v) = if group["kasRole"] == "responder" {
        (&group["serverId"], &group["iutId"])
    } else {
        (&group["iutId"], &group["serverId"])
    };
    let mut out = Vec::new();
    out.extend_from_slice(&l.to_be_bytes());
    out.extend_from_slice(&hex(u));
    out.extend_from_slice(&hex(v));
    out.extend_from_slice(&hex(&t["ktsParameter"]["label"]));
    out
}

fn decrypt<H: Hash + Default>(
    key: &PrivateKey,
    label: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = [0u8; 256];
    let len = key
        .decrypt_oaep::<H>(label, ciphertext, &mut out)
        .expect("decrypt");
    out[..len].to_vec()
}

fn encrypt<H: Hash + Default>(
    key: &PublicKey,
    label: &[u8],
    secret: &[u8],
) -> Vec<u8> {
    let mut rng = CtrDrbg::from_system().expect("generator");
    key.encrypt_oaep::<H, _>(&mut rng, label, secret)
        .expect("encrypt")
        .as_ref()
        .to_vec()
}

/// The response to a whole vector set.
pub fn answer(prompt: &Value) -> Value {
    let mut rng = CtrDrbg::from_system().expect("generator");
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            if let Some(why) = skip_reason(group) {
                panic!("tgId {}: {why} is not offered", group["tgId"]);
            }
            let hash = group["ktsConfiguration"]["hashAlg"].as_str();
            let hash = hash.expect("hashAlg");
            let bytes = group["l"].as_u64().expect("l") as usize / 8;
            let responder = group["kasRole"] == "responder";
            let tests: Vec<Value> = group["tests"]
                .as_array()
                .expect("tests")
                .iter()
                .map(|t| {
                    let label = label(group, t);
                    if responder {
                        let key = iut_key(t);
                        let ct = hex(&t["serverC"]);
                        let dkm = with_hash!(hash, decrypt(&key, &label, &ct));
                        let dkm = hex_string(&dkm);
                        return json!({"tcId": t["tcId"], "dkm": dkm});
                    }
                    let server = PublicKey::try_new(
                        &hex(&t["serverN"]),
                        &hex(&t["serverE"]),
                    )
                    .expect("server key");
                    let mut secret = vec![0u8; bytes];
                    rng.fill(&mut secret).expect("secret");
                    let ct =
                        with_hash!(hash, encrypt(&server, &label, &secret));
                    json!({
                        "tcId": t["tcId"],
                        "iutC": hex_string(&ct),
                        "dkm": hex_string(&secret),
                    })
                })
                .collect();
            json!({"tgId": group["tgId"], "tests": tests})
        })
        .collect();
    response(prompt, groups)
}

/// The implementation's own key, which the server supplies whole.
fn iut_key(t: &Value) -> PrivateKey {
    let key = PrivateKey::try_new(
        &hex(&t["iutN"]),
        &hex(&t["iutE"]),
        &hex(&t["iutD"]),
    )
    .expect("private key");
    assert_eq!(key.bits(), 2048, "tcId {} modulus length", t["tcId"]);
    key
}

/// Runs the suite; a no-op without the vendored vectors. The file
/// gives every party's private key, so each case is checked by
/// decryption whichever side the implementation is.
pub fn run() {
    let Some(doc) = load(FILE, "KTS-IFC", "Sp800-56Br2") else {
        return;
    };
    let mut plain = 0;
    let mut labelled = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if let Some(why) = skip_reason(group) {
            eprintln!("tgId {}: {why}; skipping", group["tgId"]);
            continue;
        }
        let responder = group["kasRole"] == "responder";
        let hash = group["ktsConfiguration"]["hashAlg"].as_str();
        let hash = hash.expect("hashAlg");
        let bits = group["l"].as_u64().expect("l") as usize;
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            // Every case in this file transports successfully; a
            // future one that does not should be noticed, not scored
            // as a pass.
            assert_eq!(t["testCaseDisposition"], "Success", "{tag}");
            assert_eq!(t["testPassed"], true, "{tag}");

            // The party that decrypts is the one whose private key
            // the case gives in full.
            let (key, c, expected) = if responder {
                (iut_key(t), "serverC", "serverK")
            } else {
                let key = PrivateKey::try_new(
                    &hex(&t["serverN"]),
                    &hex(&t["serverE"]),
                    &hex(&t["serverD"]),
                )
                .expect("server key");
                (key, "iutC", "iutK")
            };
            let label = label(group, t);
            let ct = hex(&t[c]);
            let got = with_hash!(hash, decrypt(&key, &label, &ct));
            assert_eq!(got.len() * 8, bits, "{tag} length");
            assert_eq!(got, hex(&t[expected]), "{tag}");
            // With no derivation step the transported key is the
            // keying material.
            let answered = json!({"tcId": t["tcId"], "dkm": hex_string(&got)});
            if let Err(why) = check(t, &answered) {
                panic!("{tag} {why}");
            }

            if label.is_empty() {
                plain += 1;
            } else {
                labelled += 1;
            }
        }
    }
    // Counted apart so that losing the labelled groups to a skip
    // cannot hide as a pass.
    assert!(plain >= 10, "only {plain} cases without a label");
    assert!(labelled >= 10, "only {labelled} cases with one");
}
