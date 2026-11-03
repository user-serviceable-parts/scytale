//! ACVP-HMAC 1.0 over SHA-1, SHA-2 and SHA-3, through [`Hmac`] and
//! the [`Mac`] trait. One driver serves every variant; the algorithm
//! name chooses the hash.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, int, text, unknown_test_type};
use scytale::BlockType;
use scytale::Random;
use scytale::hash::Hash;
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::mac::Mac;
use scytale::mac::hmac::Hmac;
use serde_json::{Value, json};

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    match text(doc, "algorithm")? {
        "HMAC-SHA-1" => answer_as::<Sha1>(doc),
        "HMAC-SHA2-224" => answer_as::<Sha224>(doc),
        "HMAC-SHA2-256" => answer_as::<Sha256>(doc),
        "HMAC-SHA2-384" => answer_as::<Sha384>(doc),
        "HMAC-SHA2-512" => answer_as::<Sha512>(doc),
        "HMAC-SHA2-512/224" => answer_as::<Sha512_224>(doc),
        "HMAC-SHA2-512/256" => answer_as::<Sha512_256>(doc),
        "HMAC-SHA3-224" => answer_as::<Sha3_224>(doc),
        "HMAC-SHA3-256" => answer_as::<Sha3_256>(doc),
        "HMAC-SHA3-384" => answer_as::<Sha3_384>(doc),
        "HMAC-SHA3-512" => answer_as::<Sha3_512>(doc),
        other => Err(Error::new(format!("algorithm {other}"))),
    }
}

/// Tags are answered over `macLen` bits, a prefix of the full tag.
/// The vectors' keys come in every length, so the any-length
/// constructor keys the MAC.
fn answer_as<H: Hash + Clone + BlockType + Default>(
    doc: &Value,
) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        let mac_bytes = int(group, "macLen")? as usize / 8;
        answer_tests(group, |t| {
            let mut mac = Hmac::<H>::new(&hex(t, "key")?);
            let msg = hex(t, "msg")?;
            mac.update(&msg);
            let tag = mac.finalize();
            let tag = tag.as_ref();
            let truncated = tag
                .get(..mac_bytes)
                .ok_or_else(|| Error::new("macLen longer than the tag"))?;
            // A full-length tag must verify too; `finalize` left the
            // MAC keyed and at the start of a message.
            if mac_bytes == tag.len() {
                mac.update(&msg);
                mac.verify(truncated)?;
            }
            Ok(json!({ "mac": hex_value(truncated) }))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::super::{SUITES, check};

    #[test]
    fn vendored() {
        for suite in SUITES.iter().filter(|s| s.algorithm.starts_with("HMAC-"))
        {
            check(suite);
        }
    }
}
