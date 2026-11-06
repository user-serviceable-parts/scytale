//! hashDRBG and hmacDRBG, answered through [`HashDrbg`] and
//! [`HmacDrbg`].
//!
//! Both suites come in two revisions, 1.0 and SP800-90Ar1, and both
//! are answered: they hold the same shapes of test but ask for
//! different amounts of output, 4096 bits in one and 512 or 768 in the
//! other, so between them a request ends both on and off a digest
//! boundary for every hash.
//!
//! Neither generator has a construction without its derivation
//! function, so every group is the derived shape, with and without
//! prediction resistance; the driver is `ctr_drbg`'s with that branch
//! taken out. Every hash the files name is one the crate has.

use super::{answer_groups, answer_tests, skip};
use crate::support::{
    Error, NoEntropy, flag, hex, hex_value, int, list, opt_text, text,
    unknown_test_type,
};
use scytale::hash::Hash;
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::random::{HashDrbg, HmacDrbg};
use scytale::{BlockType, Random};
use serde_json::{Value, json};

/// What the driver needs of either generator.
trait Drbg: Random + Sized {
    fn try_new_seeded(seed: &[u8]) -> Result<Self, scytale::Error>;
    fn reseed_with(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
    ) -> Result<(), scytale::Error>;
    fn fill_with(
        &mut self,
        out: &mut [u8],
        additional: &[u8],
    ) -> Result<(), scytale::Error>;
}

macro_rules! drbg {
    ($ty:ident, $($bound:tt)+) => {
        impl<H: $($bound)+> Drbg for $ty<H, NoEntropy> {
            fn try_new_seeded(seed: &[u8]) -> Result<Self, scytale::Error> {
                $ty::try_new_seeded(seed, NoEntropy)
            }
            fn reseed_with(
                &mut self,
                entropy: &[u8],
                additional: &[u8],
            ) -> Result<(), scytale::Error> {
                $ty::reseed_with(self, entropy, additional)
            }
            fn fill_with(
                &mut self,
                out: &mut [u8],
                additional: &[u8],
            ) -> Result<(), scytale::Error> {
                $ty::fill_with(self, out, additional)
            }
        }
    };
}

drbg!(HashDrbg, Hash + Default);
drbg!(HmacDrbg, Hash + Clone + BlockType + Default);

/// Answers one group through the generator `$ty` over the group's
/// hash.
macro_rules! dispatch {
    ($ty:ident, $group:expr) => {
        match text($group, "mode")? {
            "SHA-1" => aft::<$ty<Sha1, NoEntropy>>($group),
            "SHA2-224" => aft::<$ty<Sha224, NoEntropy>>($group),
            "SHA2-256" => aft::<$ty<Sha256, NoEntropy>>($group),
            "SHA2-384" => aft::<$ty<Sha384, NoEntropy>>($group),
            "SHA2-512" => aft::<$ty<Sha512, NoEntropy>>($group),
            "SHA2-512/224" => aft::<$ty<Sha512_224, NoEntropy>>($group),
            "SHA2-512/256" => aft::<$ty<Sha512_256, NoEntropy>>($group),
            "SHA3-224" => aft::<$ty<Sha3_224, NoEntropy>>($group),
            "SHA3-256" => aft::<$ty<Sha3_256, NoEntropy>>($group),
            "SHA3-384" => aft::<$ty<Sha3_384, NoEntropy>>($group),
            "SHA3-512" => aft::<$ty<Sha3_512, NoEntropy>>($group),
            _ => skip($group, "hash not offered"),
        }
    };
}

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    let hmac = match text(doc, "algorithm")? {
        "hashDRBG" => false,
        "hmacDRBG" => true,
        other => return Err(Error::new(format!("algorithm {other}"))),
    };
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        if flag(group, "derFunc")? {
            return Err(Error::new("derFunc is set"));
        }
        if hmac {
            dispatch!(HmacDrbg, group)
        } else {
            dispatch!(HashDrbg, group)
        }
    })
}

fn aft<D: Drbg>(group: &Value) -> Result<Option<Value>, Error> {
    let bits = int(group, "returnedBitsLen")? as usize;
    answer_tests(group, |t| {
        // Instantiation takes the entropy, the nonce and the
        // personalization string as one run of material.
        let mut material = hex(t, "entropyInput")?;
        material.extend(hex(t, "nonce")?);
        material.extend(hex(t, "persoString")?);
        let mut rng = D::try_new_seeded(&material)?;

        let mut out = vec![0u8; bits / 8];
        for other in list(t, "otherInput")? {
            let entropy = hex(other, "entropyInput")?;
            let additional = hex(other, "additionalInput")?;
            match opt_text(other, "intendedUse") {
                Some("reSeed") => rng.reseed_with(&entropy, &additional)?,
                // Prediction resistance is a reseeding from fresh
                // entropy and the additional input, then a request
                // carrying nothing further.
                Some("generate") if !entropy.is_empty() => {
                    rng.reseed_with(&entropy, &additional)?;
                    rng.fill(&mut out)?;
                }
                Some("generate") => rng.fill_with(&mut out, &additional)?,
                other => {
                    return Err(Error::new(format!("intendedUse {other:?}")));
                }
            }
        }
        // The bits answered are those of the last request.
        Ok(json!({ "returnedBits": hex_value(&out) }))
    })
}
