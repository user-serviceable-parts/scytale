//! RSA sigGen under FIPS 186-5 and sigVer under FIPS 186-5 and FIPS
//! 186-4, through [`sig::rsa`](scytale::sig::rsa).
//!
//! sigGen generates one key per group at the group's width, answers
//! its modulus and exponent, and signs each message with PKCS#1 v1.5
//! or with PSS under a fresh salt of the group's length. The stored
//! answers were made under NIST's own keys, so the offline check
//! verifies the signatures rather than matching them, and runs the
//! file's own signatures through verification as well: worked
//! answers under NIST-chosen keys and exponents.
//!
//! Groups whose hash or mask function is a SHAKE are skipped: FIPS
//! 186-5 allows XOFs in both roles, and the crate's PSS is defined
//! over fixed-output hashes with MGF1 as the mask. So are SP 800-106
//! groups, which sign a randomized transform of the message the
//! crate does not offer.
//!
//! The 186-4 file is worth running beside 186-5 for its 1024-bit
//! groups, a width 186-5 no longer offers. Its ANSI X9.31 groups are
//! skipped, that encoding not being implemented.

use super::{answer_groups, answer_tests, skip};
use crate::support::{
    Error, Rng, field, hex, hex_value, int, opt_text, text, unknown_test_type,
};
use scytale::Random;
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::sig::rsa::{DigestInfo, PrivateKey, PublicKey};
use serde_json::{Value, json};

/// Binds `$H` to the hash named `$alg` for `$body`, or returns an
/// error for a hash the crate does not sign with.
macro_rules! with_hash {
    ($alg:expr, $H:ident => $body:expr) => {
        match $alg {
            "SHA2-224" => {
                type $H = Sha224;
                $body
            }
            "SHA2-256" => {
                type $H = Sha256;
                $body
            }
            "SHA2-384" => {
                type $H = Sha384;
                $body
            }
            "SHA2-512" => {
                type $H = Sha512;
                $body
            }
            "SHA2-512/224" => {
                type $H = Sha512_224;
                $body
            }
            "SHA2-512/256" => {
                type $H = Sha512_256;
                $body
            }
            "SHA3-224" => {
                type $H = Sha3_224;
                $body
            }
            "SHA3-256" => {
                type $H = Sha3_256;
                $body
            }
            "SHA3-384" => {
                type $H = Sha3_384;
                $body
            }
            "SHA3-512" => {
                type $H = Sha3_512;
                $body
            }
            // SHA-1 appears only in the 186-4 file.
            "SHA-1" => {
                type $H = Sha1;
                $body
            }
            other => return Err(Error::new(format!("hash {other}"))),
        }
    };
}

/// The padding a group asks for.
#[derive(Clone, Copy)]
enum Padding {
    Pkcs1,
    Pss(usize),
}

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    let generate = match text(doc, "mode")? {
        "sigGen" => true,
        "sigVer" => false,
        other => return Err(Error::new(format!("mode {other}"))),
    };
    answer_groups(doc, |group| {
        if let Some(why) = skip_reason(group)? {
            return skip(group, why);
        }
        if text(group, "testType")? != "GDT" {
            return Err(unknown_test_type(group));
        }
        let alg = text(group, "hashAlg")?;
        let padding = padding(group)?;
        if generate {
            with_hash!(alg, H => sig_gen::<H>(group, padding, rng))
        } else {
            let key = public_key(group)?;
            answer_tests(group, |t| {
                let message = hex(t, "message")?;
                let sig = hex(t, "signature")?;
                let ok = with_hash!(alg, H => {
                    verify::<H>(&key, padding, &message, &sig)
                });
                Ok(json!({ "testPassed": ok }))
            })
        }
    })
}

/// Why a group cannot run, or `None` if it can.
fn skip_reason(group: &Value) -> Result<Option<&'static str>, Error> {
    let sig_type = text(group, "sigType")?;
    // ANSI X9.31 padding appears only in the 186-4 file and is not
    // implemented.
    if sig_type == "ansx9.31" {
        return Ok(Some("ANSI X9.31 is not implemented"));
    }
    // 186-5 names the mask function; 186-4 has only MGF1 and records
    // none, so an absent field is MGF1.
    let mask = opt_text(group, "maskFunction").unwrap_or("mgf1");
    if sig_type == "pss" && mask != "mgf1" {
        return Ok(Some("PSS masks only with MGF1"));
    }
    if opt_text(group, "conformance") == Some("SP800-106") {
        return Ok(Some("SP 800-106 randomized hashing"));
    }
    if text(group, "hashAlg")?.starts_with("SHAKE") {
        return Ok(Some("RSA signs with fixed-output hashes only"));
    }
    Ok(None)
}

fn padding(group: &Value) -> Result<Padding, Error> {
    match text(group, "sigType")? {
        "pkcs1v1.5" => Ok(Padding::Pkcs1),
        "pss" => Ok(Padding::Pss(int(group, "saltLen")? as usize)),
        other => Err(Error::new(format!("sigType {other}"))),
    }
}

/// The group's key, which must be as wide as the group says.
fn public_key(group: &Value) -> Result<PublicKey, Error> {
    let key = PublicKey::try_new(&hex(group, "n")?, &hex(group, "e")?)?;
    let modulo = int(group, "modulo")?;
    if key.bits() as u64 != modulo {
        return Err(Error::new(format!(
            "a {}-bit modulus in a {modulo}-bit group",
            key.bits()
        )));
    }
    Ok(key)
}

fn verify<H: DigestInfo + Default>(
    key: &PublicKey,
    padding: Padding,
    message: &[u8],
    sig: &[u8],
) -> bool {
    match padding {
        Padding::Pkcs1 => key.verify_pkcs1::<H>(message, sig).is_ok(),
        Padding::Pss(salt) => key
            .verify_pss_with_salt_len::<H>(message, sig, salt)
            .is_ok(),
    }
}

/// Answers a sigGen group under a key generated for it.
fn sig_gen<H: DigestInfo + Default>(
    group: &Value,
    padding: Padding,
    rng: &mut dyn Random,
) -> Result<Option<Value>, Error> {
    let bits = int(group, "modulo")? as usize;
    let key = PrivateKey::generate(&mut Rng(&mut *rng), bits)?;
    let public = key.public_key();
    let mut n = vec![0u8; public.modulus_len()];
    let len = public.modulus_bytes(&mut n)?;
    let e = public.exponent_bytes();
    // NIST writes the exponent without leading zero bytes.
    let start = e.iter().position(|b| *b != 0).unwrap_or(e.len() - 1);
    let answered = answer_tests(group, |t| {
        let message = hex(t, "message")?;
        let sig = match padding {
            Padding::Pkcs1 => key.sign_pkcs1::<H>(&message)?,
            Padding::Pss(salt_len) => {
                let mut salt = vec![0u8; salt_len];
                rng.fill(&mut salt)?;
                key.sign_pss_with_salt::<H>(&message, &salt)?
            }
        };
        Ok(json!({ "signature": hex_value(sig.as_ref()) }))
    })?;
    let Some(mut answered) = answered else {
        return Ok(None);
    };
    if let Some(obj) = answered.as_object_mut() {
        obj.insert("n".into(), hex_value(&n[..len]));
        obj.insert("e".into(), hex_value(&e[start..]));
    }
    Ok(Some(answered))
}

/// Checks an answered sigGen case: its signature must verify under
/// the answered key, and the file's own signature under the file's.
pub fn verify_sig_gen(
    vendored_group: &Value,
    vendored_test: &Value,
    answered_group: &Value,
    answered_test: &Value,
) -> Result<(), Error> {
    let alg = text(vendored_group, "hashAlg")?;
    let padding = padding(vendored_group)?;
    let message = hex(vendored_test, "message")?;
    let n = field(answered_group, "n")?;
    let e = field(answered_group, "e")?;
    let answered_key = public_key(&json!({
        "n": n,
        "e": e,
        "modulo": field(vendored_group, "modulo")?,
    }))?;
    let vendored_key = public_key(vendored_group)?;
    let answered_sig = hex(answered_test, "signature")?;
    let vendored_sig = hex(vendored_test, "signature")?;
    with_hash!(alg, H => {
        if !verify::<H>(&answered_key, padding, &message, &answered_sig) {
            return Err(Error::new("answered signature does not verify"));
        }
        if !verify::<H>(&vendored_key, padding, &message, &vendored_sig) {
            return Err(Error::new("the file's signature does not verify"));
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{SUITES, check};

    #[test]
    fn vendored() {
        for suite in SUITES.iter().filter(|s| {
            s.algorithm == "RSA"
                && matches!(s.mode, Some("sigGen") | Some("sigVer"))
        }) {
            check(suite);
        }
    }
}
