//! RSA keyGen under FIPS 186-5, through
//! [`sig::rsa`](scytale::sig::rsa).
//!
//! The crate generates one kind of key: random probable primes,
//! Miller-Rabin tested, under the public exponent 65537. That is the
//! server's `GDT` group with `randPQ` probable, where the client
//! returns the key it made and the server checks it. The other
//! generation methods, the seeded provable primes and the auxiliary
//! primes of FIPS 186-5 appendix A.1, are constructions the crate
//! does not have, and a group asking for a residue of the primes
//! modulo eight is one it cannot honour; all of those are skipped.
//!
//! NIST's sample file holds no group this driver answers, so the
//! offline check compares nothing: the suite is checked by the test
//! below, which answers a group of its own and verifies the key, and
//! by the live session, where the server judges the keys.

use super::{answer_groups, answer_tests, skip};
use crate::support::{
    Error, Rng, field, hex, hex_value, int, opt_int, opt_text, text,
    unknown_test_type,
};
use scytale::Random;
use scytale::hash::sha2::Sha256;
use scytale::sig::rsa::{PrivateKey, PublicKey};
use serde_json::{Value, json};

/// The one exponent the crate generates under, as NIST writes it.
const FIXED_EXPONENT: &str = "010001";

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    if text(doc, "mode")? != "keyGen" {
        return Err(Error::new(format!("mode {}", doc["mode"])));
    }
    answer_groups(doc, |group| {
        if let Some(why) = skip_reason(group)? {
            return skip(group, why);
        }
        if text(group, "testType")? != "GDT" {
            return Err(unknown_test_type(group));
        }
        let bits = int(group, "modulo")? as usize;
        let crt = opt_text(group, "keyFormat") == Some("crt");
        answer_tests(group, |_| {
            let key = PrivateKey::generate(&mut Rng(&mut *rng), bits)?;
            key_fields(&key, crt)
        })
    })
}

/// Why a group cannot run, or `None` if it can.
fn skip_reason(group: &Value) -> Result<Option<&'static str>, Error> {
    if text(group, "randPQ")? != "probable" {
        return Ok(Some("only random probable primes are generated"));
    }
    if opt_int(group, "pMod8").unwrap_or(0) != 0
        || opt_int(group, "qMod8").unwrap_or(0) != 0
    {
        return Ok(Some("the primes' residues modulo eight are not chosen"));
    }
    // A fixed exponent other than 65537; a random one is the
    // client's to choose.
    if opt_text(group, "pubExp") == Some("fixed")
        && !opt_text(group, "fixedPubExp")
            .is_some_and(|e| e.trim_start_matches('0') == "10001")
    {
        return Ok(Some("the exponent is always 65537"));
    }
    Ok(None)
}

/// The key as the response carries it: the modulus, the exponent,
/// the primes and the private exponent, and under the CRT format the
/// remainder pieces too.
fn key_fields(key: &PrivateKey, crt: bool) -> Result<Value, Error> {
    let public = key.public_key();
    let mut n = vec![0u8; public.modulus_len()];
    let n_len = public.modulus_bytes(&mut n)?;
    let mut d = vec![0u8; key.modulus_len()];
    let d_len = key.d_bytes(&mut d)?;
    let half = key.prime_len();
    let mut p = vec![0u8; half];
    let mut q = vec![0u8; half];
    let mut dp = vec![0u8; half];
    let mut dq = vec![0u8; half];
    let mut qinv = vec![0u8; half];
    key.crt_bytes(&mut p, &mut q, &mut dp, &mut dq, &mut qinv)?;
    let mut out = json!({
        "e": FIXED_EXPONENT,
        "n": hex_value(&n[..n_len]),
        "p": hex_value(&p),
        "q": hex_value(&q),
        "d": hex_value(&d[..d_len]),
    });
    if let Some(obj) = out.as_object_mut().filter(|_| crt) {
        obj.insert("dmp1".into(), hex_value(&dp));
        obj.insert("dmq1".into(), hex_value(&dq));
        obj.insert("iqmp".into(), hex_value(&qinv));
    }
    Ok(out)
}

/// Checks an answered key, and the file's own: each must be a working
/// key of the group's width, its pieces consistent with one another
/// and a signature under it verifying under its public half.
pub fn verify(
    vendored_group: &Value,
    vendored_test: &Value,
    _answered_group: &Value,
    answered_test: &Value,
) -> Result<(), Error> {
    let bits = int(vendored_group, "modulo")? as usize;
    working_key(vendored_test, bits)
        .map_err(|e| Error::new(format!("the file's key: {e}")))?;
    working_key(answered_test, bits)?;
    if text(answered_test, "e")?.trim_start_matches('0') != "10001" {
        return Err(Error::new("exponent is not 65537"));
    }
    Ok(())
}

/// Builds the key from the fields of `test`, which checks the primes
/// against the modulus, then signs and verifies under it.
fn working_key(test: &Value, bits: usize) -> Result<(), Error> {
    let n = hex(test, "n")?;
    let e = hex(test, "e")?;
    let d = hex(test, "d")?;
    let key = if field(test, "dmp1").is_ok() {
        PrivateKey::try_new_crt(
            &n,
            &e,
            &d,
            &hex(test, "p")?,
            &hex(test, "q")?,
            &hex(test, "dmp1")?,
            &hex(test, "dmq1")?,
            &hex(test, "iqmp")?,
        )?
    } else {
        PrivateKey::try_new(&n, &e, &d)?
    };
    if key.bits() != bits {
        return Err(Error::new(format!(
            "a {}-bit key in a {bits}-bit group",
            key.bits()
        )));
    }
    let message = b"RSA keyGen";
    let sig = key.sign_pkcs1::<Sha256>(message)?;
    PublicKey::try_new(&n, &e)?
        .verify_pkcs1::<Sha256>(message, sig.as_ref())
        .map_err(|e| Error::new(format!("signature does not verify: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::{SUITES, check, compare, fixed_rng};

    #[test]
    fn vendored() {
        for suite in SUITES.iter().filter(|s| s.mode == Some("keyGen")) {
            check(suite);
        }
    }

    /// A group of the shape the server sends, answered and verified:
    /// the check the sample file cannot make.
    #[test]
    fn generated_keys_verify() {
        let doc = json!({
            "vsId": 0, "algorithm": "RSA", "mode": "keyGen",
            "revision": "FIPS186-5",
            "testGroups": [{
                "tgId": 1, "testType": "GDT", "randPQ": "probable",
                "modulo": 2048, "keyFormat": "crt", "pubExp": "fixed",
                "fixedPubExp": "010001", "primeTest": "2pow100",
                "pMod8": 0, "qMod8": 0,
                "tests": [{"tcId": 1, "deferred": true}],
            }, {
                "tgId": 2, "testType": "GDT", "randPQ": "probable",
                "modulo": 2048, "keyFormat": "standard", "pubExp": "random",
                "tests": [{"tcId": 2, "deferred": true}],
            }, {
                "tgId": 3, "testType": "GDT", "randPQ": "probable",
                "modulo": 2048, "pMod8": 5, "qMod8": 3,
                "tests": [{"tcId": 3, "deferred": true}],
            }],
        });
        let answered = answer(&doc, &mut fixed_rng()).unwrap();
        let groups = answered["testGroups"].as_array().unwrap();
        assert_eq!(groups.len(), 2, "the residue group is skipped");
        let crt = &groups[0]["tests"][0];
        assert!(crt["dmp1"].is_string() && crt["iqmp"].is_string());
        assert!(groups[1]["tests"][0]["dmp1"].is_null());
        // Verified against itself, as the file's key and the answer.
        let suite = SUITES.iter().find(|s| s.mode == Some("keyGen")).unwrap();
        assert_eq!(compare(suite, &answered, &answered).unwrap(), 2);
    }

    #[test]
    fn a_broken_key_is_caught() {
        let doc = json!({
            "algorithm": "RSA", "mode": "keyGen",
            "testGroups": [{
                "tgId": 1, "testType": "GDT", "randPQ": "probable",
                "modulo": 2048, "tests": [{"tcId": 1}],
            }],
        });
        let good = answer(&doc, &mut fixed_rng()).unwrap();
        let mut bad = good.clone();
        let d = bad["testGroups"][0]["tests"][0]["d"].as_str().unwrap();
        let flipped = format!("{}{}", &d[..d.len() - 1], "0");
        bad["testGroups"][0]["tests"][0]["d"] = json!(flipped);
        let suite = SUITES.iter().find(|s| s.mode == Some("keyGen")).unwrap();
        assert!(compare(suite, &good, &bad).is_err());
    }
}
