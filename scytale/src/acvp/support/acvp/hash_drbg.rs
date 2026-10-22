//! hashDRBG and hmacDRBG, run through [`HashDrbg`] and [`HmacDrbg`].
//!
//! Both suites come in two revisions, 1.0 and SP800-90Ar1, and both
//! are run: they hold the same shapes of test but ask for different
//! amounts of output, 4096 bits in one and 512 or 768 in the other,
//! so between them a request ends both on and off a digest boundary
//! for every hash.
//!
//! Neither generator has a construction without its derivation
//! function, so every group is the derived shape, with and without
//! prediction resistance; the driver is `ctr_drbg`'s with that branch
//! taken out. Every hash the files name is one the crate has.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{hex, load};
use crate::hash::Hash;
use crate::hash::sha1::Sha1;
use crate::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use crate::hash::sha2::{Sha512_224, Sha512_256};
use crate::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use crate::random::{HashDrbg, HmacDrbg, entropy::External};
use crate::{BlockType, Random};
use serde_json::Value;

/// What the driver needs of either generator.
trait Drbg: Random + Sized {
    fn from_seed(seed: &[u8]) -> Self;
    fn reseed_with(&mut self, entropy: &[u8], additional: &[u8]);
    fn fill_with(&mut self, out: &mut [u8], additional: &[u8]);
}

macro_rules! drbg {
    ($ty:ident, $($bound:tt)+) => {
        impl<H: $($bound)+> Drbg for $ty<H, External> {
            fn from_seed(seed: &[u8]) -> Self {
                $ty::from_seed(seed).expect("instantiate")
            }
            fn reseed_with(&mut self, entropy: &[u8], additional: &[u8]) {
                $ty::reseed_with(self, entropy, additional).expect("reseed");
            }
            fn fill_with(&mut self, out: &mut [u8], additional: &[u8]) {
                $ty::fill_with(self, out, additional).expect("generate");
            }
        }
    };
}

drbg!(HashDrbg, Hash + Default);
drbg!(HmacDrbg, Hash + Clone + BlockType + Default);

/// Runs one group through the generator `$ty` over the group's hash.
macro_rules! dispatch {
    ($ty:ident, $mode:expr, $group:expr) => {
        match $mode {
            "SHA-1" => aft::<$ty<Sha1, External>>($group),
            "SHA2-224" => aft::<$ty<Sha224, External>>($group),
            "SHA2-256" => aft::<$ty<Sha256, External>>($group),
            "SHA2-384" => aft::<$ty<Sha384, External>>($group),
            "SHA2-512" => aft::<$ty<Sha512, External>>($group),
            "SHA2-512/224" => aft::<$ty<Sha512_224, External>>($group),
            "SHA2-512/256" => aft::<$ty<Sha512_256, External>>($group),
            "SHA3-224" => aft::<$ty<Sha3_224, External>>($group),
            "SHA3-256" => aft::<$ty<Sha3_256, External>>($group),
            "SHA3-384" => aft::<$ty<Sha3_384, External>>($group),
            "SHA3-512" => aft::<$ty<Sha3_512, External>>($group),
            other => panic!("unknown hash {other}"),
        }
    };
}

/// Runs a hashDRBG file; a no-op without the vendored vectors.
pub fn run_hash(file: &str, revision: &str) {
    let Some(doc) = load(file, "hashDRBG", revision) else {
        return;
    };
    let mut cases = 0;
    for group in groups(&doc) {
        cases += dispatch!(HashDrbg, mode(group), group);
    }
    assert!(cases >= 300, "only {cases} cases in {file}");
}

/// Runs an hmacDRBG file; a no-op without the vendored vectors.
pub fn run_hmac(file: &str, revision: &str) {
    let Some(doc) = load(file, "hmacDRBG", revision) else {
        return;
    };
    let mut cases = 0;
    for group in groups(&doc) {
        cases += dispatch!(HmacDrbg, mode(group), group);
    }
    assert!(cases >= 300, "only {cases} cases in {file}");
}

/// The groups, each checked to be one this driver understands.
fn groups(doc: &Value) -> impl Iterator<Item = &Value> {
    doc["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .inspect(|group| {
            assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
            assert_eq!(group["derFunc"], false, "tgId {}", group["tgId"]);
        })
}

fn mode(group: &Value) -> &str {
    group["mode"].as_str().expect("mode")
}

/// Returns the cases run.
fn aft<D: Drbg>(group: &Value) -> usize {
    let bits = group["returnedBitsLen"].as_u64().expect("returnedBitsLen");
    let mut cases = 0;
    for t in group["tests"].as_array().expect("tests") {
        let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        // Instantiation takes the entropy, the nonce and the
        // personalization string as one run of material.
        let mut material = hex(&t["entropyInput"]);
        material.extend(hex(&t["nonce"]));
        material.extend(hex(&t["persoString"]));
        let mut rng = D::from_seed(&material);

        let mut out = vec![0u8; bits as usize / 8];
        for other in t["otherInput"].as_array().expect("otherInput") {
            let entropy = hex(&other["entropyInput"]);
            let additional = hex(&other["additionalInput"]);
            match other["intendedUse"].as_str() {
                Some("reSeed") => rng.reseed_with(&entropy, &additional),
                // Prediction resistance is a reseeding from fresh
                // entropy and the additional input, then a request
                // carrying nothing further.
                Some("generate") if !entropy.is_empty() => {
                    rng.reseed_with(&entropy, &additional);
                    rng.fill(&mut out).expect("generate");
                }
                Some("generate") => rng.fill_with(&mut out, &additional),
                other => panic!("{tag}: unknown intendedUse {other:?}"),
            }
        }
        // The bits compared are those of the last request.
        assert_eq!(out, hex(&t["returnedBits"]), "{tag}");
        cases += 1;
    }
    cases
}
