//! Wycheproof's Ed448 verification cases through
//! [`ed448::verify`]: signature malleability, truncated and
//! padded signatures, wrong-length keys, and edge-case points. The
//! valid cases must verify and every other must fail.
//!
//! Each group's key also comes in DER and PEM, which is the external
//! check that the RFC 8410 public key encoding reads and writes.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::super::hex;
use super::load;
use crate::sig::ed448;

const FILE: &str = "wycheproof/ed448_test.json";

/// Runs every case; a no-op without the vendored vectors.
pub fn run() {
    let Some(doc) = load(FILE, "EDDSA") else {
        return;
    };
    let mut valid = 0;
    let mut invalid = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let key = &group["publicKey"];
        assert_eq!(key["curve"], "edwards448");
        let public: [u8; ed448::PUBLIC_KEY_SIZE] =
            hex(&key["pk"]).try_into().expect("pk");
        let der = hex(&group["publicKeyDer"]);
        let pem = group["publicKeyPem"].as_str().expect("publicKeyPem");
        assert_eq!(ed448::public_key_from_der(&der), Ok(public));
        assert_eq!(ed448::public_key_from_pem(pem.as_bytes()), Ok(public));
        assert_eq!(ed448::public_key_der(&public)[..], der[..]);
        assert_eq!(&ed448::public_key_pem(&public)[..], pem.as_bytes());
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let message = hex(&t["msg"]);
            let sig = hex(&t["sig"]);
            let expect_valid = match t["result"].as_str() {
                Some("valid") => true,
                Some("invalid") => false,
                other => panic!("{tag}: unknown result {other:?}"),
            };
            // A signature that is not 114 bytes long is refused by
            // the signature of `verify` itself; the file must agree
            // that every such case is invalid.
            let Ok(sig) = <[u8; ed448::SIGNATURE_SIZE]>::try_from(sig) else {
                assert!(!expect_valid, "{tag} wrong-length but valid");
                invalid += 1;
                continue;
            };
            // Wycheproof signs under the empty context.
            let accepted = ed448::verify(&public, b"", &message, &sig).is_ok();
            assert_eq!(accepted, expect_valid, "{tag}");
            if expect_valid {
                valid += 1;
            } else {
                invalid += 1;
            }
        }
    }
    assert!(valid >= 17, "only {valid} valid cases");
    assert!(invalid >= 70, "only {invalid} invalid cases");
}
