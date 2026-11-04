//! ACVP-PBKDF 1.0, through [`pbkdf2`] over the hash each group's
//! `hmacAlg` names.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, int, text, unknown_test_type};
use scytale::Random;
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::kdf::pbkdf2::pbkdf2;
use serde_json::{Value, json};

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        let derive = match text(group, "hmacAlg")? {
            "SHA-1" => pbkdf2::<Sha1>,
            "SHA2-224" => pbkdf2::<Sha224>,
            "SHA2-256" => pbkdf2::<Sha256>,
            "SHA2-384" => pbkdf2::<Sha384>,
            "SHA2-512" => pbkdf2::<Sha512>,
            "SHA2-512/224" => pbkdf2::<Sha512_224>,
            "SHA2-512/256" => pbkdf2::<Sha512_256>,
            "SHA3-224" => pbkdf2::<Sha3_224>,
            "SHA3-256" => pbkdf2::<Sha3_256>,
            "SHA3-384" => pbkdf2::<Sha3_384>,
            "SHA3-512" => pbkdf2::<Sha3_512>,
            other => return Err(Error::new(format!("hmacAlg {other}"))),
        };
        answer_tests(group, |t| derived(t, derive))
    })
}

/// [`pbkdf2`] over one hash: password, salt, iterations, key.
type Derive = fn(&[u8], &[u8], u32, &mut [u8]) -> Result<(), scytale::Error>;

fn derived(t: &Value, derive: Derive) -> Result<Value, Error> {
    let password = text(t, "password")?;
    let salt = hex(t, "salt")?;
    let iterations = u32::try_from(int(t, "iterationCount")?)
        .map_err(|_| Error::new("iterationCount out of range"))?;
    let bits = int(t, "keyLen")? as usize;
    if !bits.is_multiple_of(8) {
        return Err(Error::new("keyLen of part of a byte"));
    }
    let mut key = vec![0u8; bits / 8];
    derive(password.as_bytes(), &salt, iterations, &mut key)?;
    Ok(json!({ "derivedKey": hex_value(&key) }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn vendored() {
        for suite in super::super::find("PBKDF") {
            super::super::check(suite);
        }
    }
}
