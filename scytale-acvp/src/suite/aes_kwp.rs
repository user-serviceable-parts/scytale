//! ACVP-AES-KWP 1.0, through [`Kwp`] over any block cipher.
//!
//! The suite covers both cipher directions the standard allows, both
//! wrapping and unwrapping, and a large number of unwrapping cases
//! that are meant to fail, which is what checks that an altered
//! wrapping is refused rather than quietly accepted: those answer
//! `testPassed` false. Padded lengths reach down to a single byte, so
//! the single-block case the standard handles separately is covered
//! too.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, key_of, text, unknown_test_type};
use scytale::Random;
use scytale::cipher::mode::Kwp;
use serde_json::{Value, json};

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let encrypt = match text(group, "direction")? {
            "encrypt" => true,
            "decrypt" => false,
            other => return Err(Error::new(format!("direction {other}"))),
        };
        // The standard lets the wrapping be built on either direction
        // of the cipher, and the suite exercises both.
        let forward = match text(group, "kwCipher")? {
            "cipher" => true,
            "inverse" => false,
            other => return Err(Error::new(format!("kwCipher {other}"))),
        };
        match text(group, "testType")? {
            "AFT" => answer_tests(group, |t| aft(t, encrypt, forward)),
            _ => Err(unknown_test_type(group)),
        }
    })
}

fn aft(t: &Value, encrypt: bool, forward: bool) -> Result<Value, Error> {
    let key = hex(t, "key")?;
    aes_width!(key, C => {
        let key = key_of::<C>(&key)?;
        let kwp = if forward {
            Kwp::<C>::new(&key)
        } else {
            Kwp::<C>::new_inverse(&key)
        };
        if encrypt {
            let plain = hex(t, "pt")?;
            let mut out = vec![0u8; plain.len().next_multiple_of(8) + 8];
            let n = kwp.wrap(&plain, &mut out)?;
            return Ok(json!({ "ct": hex_value(&out[..n]) }));
        }
        let wrapped = hex(t, "ct")?;
        let mut out = vec![0u8; wrapped.len()];
        match kwp.unwrap(&wrapped, &mut out) {
            Ok(n) => Ok(json!({ "pt": hex_value(&out[..n]) })),
            Err(scytale::Error::AuthenticationFailed) => {
                Ok(json!({ "testPassed": false }))
            }
            Err(e) => Err(e.into()),
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn vendored() {
        for suite in super::super::find("ACVP-AES-KWP") {
            super::super::check(suite);
        }
    }
}
