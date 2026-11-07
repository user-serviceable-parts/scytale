//! ECDSA keyGen, keyVer, sigGen, sigVer and the deterministic
//! sigGen, for the P-256, P-384 and P-521 groups: the P-224 and
//! binary-curve groups are not implemented, and the SHAKE groups are
//! skipped since ECDSA over an XOF is not offered.
//!
//! A key the file supplies (`d`, per case for keyGen and per group
//! for sigGen) is used; the server's prompt carries none, so one is
//! drawn from the generator instead. The deterministic suite is the
//! exact check on signing, since RFC 6979 fixes the nonce. The
//! random-nonce suite cannot be reproduced, so both are checked
//! offline by [`verify_sig_gen`], which still checks the public key
//! against `d` and the arithmetic against a signature NIST made; the
//! test module compares the deterministic signatures byte for byte.
//! Both suites also carry SP 800-106 groups, whose message is
//! randomized with a value the file supplies before hashing; that
//! scheme is not offered, so those groups are skipped.

use super::{answer_groups, answer_tests, skip};
use crate::support::{
    Error, Rng, hex, hex_value, opt_hex, opt_text, text, unknown_test_type,
};
use scytale::BlockType;
use scytale::Random;
use scytale::hash::Hash;
use scytale::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::sig::ecdsa::{p256, p384, p521};
use serde_json::{Value, json};

/// The hashes a signature here may be made under.
pub trait SigHash: Hash + Clone + BlockType + Default {}
impl<H: Hash + Clone + BlockType + Default> SigHash for H {}

/// One curve's key types, so a driver can be written once.
pub trait Curve {
    const WIDTH: usize;
    type Private;
    type Public;
    fn private(d: &[u8]) -> Result<Self::Private, Error>;
    fn generate(rng: &mut dyn Random) -> Result<Self::Private, Error>;
    fn secret_of(key: &Self::Private) -> Vec<u8>;
    fn public(sec1: &[u8]) -> Result<Self::Public, Error>;
    fn public_of(key: &Self::Private) -> Vec<u8>;
    fn sign<H: SigHash>(
        key: &Self::Private,
        rng: &mut dyn Random,
        message: &[u8],
    ) -> Result<Vec<u8>, Error>;
    fn sign_deterministic<H: SigHash>(
        key: &Self::Private,
        message: &[u8],
    ) -> Result<Vec<u8>, Error>;
    fn verify<H: SigHash>(
        key: &Self::Public,
        message: &[u8],
        sig: &[u8],
    ) -> bool;
}

macro_rules! curve {
    ($name:ident, $module:ident, $width:literal) => {
        pub struct $name;
        impl Curve for $name {
            const WIDTH: usize = $width;
            type Private = $module::PrivateKey;
            type Public = $module::PublicKey;
            fn private(d: &[u8]) -> Result<Self::Private, Error> {
                let d: [u8; $width] = d
                    .try_into()
                    .map_err(|_| Error::new("d is not the curve's width"))?;
                Ok($module::PrivateKey::try_new(&d)?)
            }
            fn generate(rng: &mut dyn Random) -> Result<Self::Private, Error> {
                Ok($module::PrivateKey::generate(&mut Rng(rng))?)
            }
            fn secret_of(key: &Self::Private) -> Vec<u8> {
                key.secret_bytes().to_vec()
            }
            fn public(sec1: &[u8]) -> Result<Self::Public, Error> {
                Ok($module::PublicKey::try_from_sec1(sec1)?)
            }
            fn public_of(key: &Self::Private) -> Vec<u8> {
                key.public_key().sec1_bytes().to_vec()
            }
            fn sign<H: SigHash>(
                key: &Self::Private,
                rng: &mut dyn Random,
                message: &[u8],
            ) -> Result<Vec<u8>, Error> {
                Ok(key.sign::<H, _>(&mut Rng(rng), message)?.to_vec())
            }
            fn sign_deterministic<H: SigHash>(
                key: &Self::Private,
                message: &[u8],
            ) -> Result<Vec<u8>, Error> {
                Ok(key.sign_deterministic::<H>(message)?.to_vec())
            }
            fn verify<H: SigHash>(
                key: &Self::Public,
                message: &[u8],
                sig: &[u8],
            ) -> bool {
                match <[u8; 2 * $width]>::try_from(sig) {
                    Ok(sig) => key.verify::<H>(message, &sig).is_ok(),
                    Err(_) => false,
                }
            }
        }
    };
}

curve!(P256, p256, 32);
curve!(P384, p384, 48);
curve!(P521, p521, 66);

/// Binds `$C` to the group's curve for `$body`, or binds `$why` to
/// the reason it is not offered for `$otherwise`.
macro_rules! with_curve {
    ($group:expr, $C:ident => $body:expr; $why:ident => $otherwise:expr) => {
        match text($group, "curve")? {
            "P-256" => {
                type $C = P256;
                $body
            }
            "P-384" => {
                type $C = P384;
                $body
            }
            "P-521" => {
                type $C = P521;
                $body
            }
            other => {
                let $why: &str = &format!("{other} is not implemented");
                $otherwise
            }
        }
    };
}

/// Binds `$H` to the group's hash for `$body`, or binds `$why` to the
/// reason it is not offered for `$otherwise`.
macro_rules! with_hash {
    ($group:expr, $H:ident => $body:expr; $why:ident => $otherwise:expr) => {
        match text($group, "hashAlg")? {
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
            "SHAKE-128" | "SHAKE-256" => {
                let $why: &str = "ECDSA over an XOF is not offered";
                $otherwise
            }
            other => return Err(Error::new(format!("hashAlg {other}"))),
        }
    };
}

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    let mode = text(doc, "mode")?;
    match (text(doc, "algorithm")?, mode) {
        ("ECDSA", "keyGen") => answer_groups(doc, |group| {
            aft(group)?;
            with_curve!(group, C => key_gen::<C>(group, rng);
                why => skip(group, why))
        }),
        ("ECDSA", "keyVer") => answer_groups(doc, |group| {
            aft(group)?;
            with_curve!(group, C => key_ver::<C>(group);
                why => skip(group, why))
        }),
        ("ECDSA", "sigVer") => answer_groups(doc, |group| {
            aft(group)?;
            with_curve!(group, C => with_hash!(group,
                H => sig_ver::<C, H>(group);
                why => skip(group, why)); why => skip(group, why))
        }),
        (algorithm @ ("ECDSA" | "DetECDSA"), "sigGen") => {
            let exact = algorithm == "DetECDSA";
            answer_groups(doc, |group| {
                aft(group)?;
                if opt_text(group, "conformance") == Some("SP800-106") {
                    return skip(group, "SP 800-106 hashing is not offered");
                }
                with_curve!(group, C => with_hash!(group,
                    H => sig_gen::<C, H>(group, rng, exact);
                    why => skip(group, why)); why => skip(group, why))
            })
        }
        (algorithm, _) => {
            Err(Error::new(format!("algorithm {algorithm} mode {mode}")))
        }
    }
}

/// Every group of these suites is an AFT.
fn aft(group: &Value) -> Result<(), Error> {
    match text(group, "testType")? {
        "AFT" => Ok(()),
        _ => Err(unknown_test_type(group)),
    }
}

/// A big-endian value left-padded to `width`, or `None` when it is
/// wider, which a keyVer case may deliberately be.
fn padded(bytes: &[u8], width: usize) -> Option<Vec<u8>> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let value = &bytes[start..];
    if value.len() > width {
        return None;
    }
    let mut out = vec![0u8; width - value.len()];
    out.extend_from_slice(value);
    Some(out)
}

/// The hex field `name` of `v` padded to `width`.
fn scalar(
    v: &Value,
    name: &str,
    width: usize,
) -> Result<Option<Vec<u8>>, Error> {
    Ok(padded(&hex(v, name)?, width))
}

/// The uncompressed point from a group's or case's `qx` and `qy`.
fn sec1(v: &Value, width: usize) -> Result<Option<Vec<u8>>, Error> {
    let (Some(x), Some(y)) = (scalar(v, "qx", width)?, scalar(v, "qy", width)?)
    else {
        return Ok(None);
    };
    let mut out = vec![0x04];
    out.extend(x);
    out.extend(y);
    Ok(Some(out))
}

/// The signature `r || s` from a case.
fn signature(t: &Value, width: usize) -> Result<Option<Vec<u8>>, Error> {
    let (Some(r), Some(s)) = (scalar(t, "r", width)?, scalar(t, "s", width)?)
    else {
        return Ok(None);
    };
    let mut out = r;
    out.extend(s);
    Ok(Some(out))
}

/// The key the file gives as `d` in `v`, or a fresh one.
fn key<C: Curve>(v: &Value, rng: &mut dyn Random) -> Result<C::Private, Error> {
    match opt_hex(v, "d")? {
        Some(d) => {
            let d = padded(&d, C::WIDTH)
                .ok_or_else(|| Error::new("d is wider than the curve"))?;
            C::private(&d)
        }
        None => C::generate(rng),
    }
}

/// The public key of `key` as the answer's `qx` and `qy`.
fn public_fields<C: Curve>(key: &C::Private) -> (Value, Value) {
    let q = C::public_of(key);
    let (x, y) = q[1..].split_at(C::WIDTH);
    (hex_value(x), hex_value(y))
}

fn key_gen<C: Curve>(
    group: &Value,
    rng: &mut dyn Random,
) -> Result<Option<Value>, Error> {
    answer_tests(group, |t| {
        let key = key::<C>(t, rng)?;
        let (qx, qy) = public_fields::<C>(&key);
        Ok(json!({ "d": hex_value(&C::secret_of(&key)), "qx": qx, "qy": qy }))
    })
}

fn key_ver<C: Curve>(group: &Value) -> Result<Option<Value>, Error> {
    answer_tests(group, |t| {
        // A coordinate wider than the field cannot be presented at all.
        let passed = sec1(t, C::WIDTH)?.is_some_and(|q| C::public(&q).is_ok());
        Ok(json!({ "testPassed": passed }))
    })
}

fn sig_ver<C: Curve, H: SigHash>(
    group: &Value,
) -> Result<Option<Value>, Error> {
    answer_tests(group, |t| {
        let passed = match (sec1(t, C::WIDTH)?, signature(t, C::WIDTH)?) {
            (Some(q), Some(sig)) => match C::public(&q) {
                Ok(key) => C::verify::<H>(&key, &hex(t, "message")?, &sig),
                Err(_) => false,
            },
            _ => false,
        };
        Ok(json!({ "testPassed": passed }))
    })
}

/// One sigGen group under the group's key: deterministic signatures
/// when `exact`, hedged ones from `rng` otherwise.
fn sig_gen<C: Curve, H: SigHash>(
    group: &Value,
    rng: &mut dyn Random,
    exact: bool,
) -> Result<Option<Value>, Error> {
    let key = key::<C>(group, rng)?;
    let answered = answer_tests(group, |t| {
        let message = hex(t, "message")?;
        let sig = if exact {
            C::sign_deterministic::<H>(&key, &message)?
        } else {
            C::sign::<H>(&key, rng, &message)?
        };
        let (r, s) = sig.split_at(C::WIDTH);
        Ok(json!({ "r": hex_value(r), "s": hex_value(s) }))
    })?;
    let Some(mut answered) = answered else {
        return Ok(None);
    };
    let (qx, qy) = public_fields::<C>(&key);
    if let Some(g) = answered.as_object_mut() {
        g.insert("qx".into(), qx);
        g.insert("qy".into(), qy);
    }
    Ok(Some(answered))
}

/// Checks an answered sigGen case against the file: the answered
/// public key must be the file's, which `d` fixes, and both the
/// answered signature and the one NIST made must verify under it.
pub fn verify_sig_gen(
    vendored_group: &Value,
    vendored_test: &Value,
    answered_group: &Value,
    answered_test: &Value,
) -> Result<(), Error> {
    with_curve!(vendored_group, C => with_hash!(vendored_group,
        H => verify_as::<C, H>(
            vendored_group, vendored_test, answered_group, answered_test);
        why => Err(Error::new(why))); why => Err(Error::new(why)))
}

fn verify_as<C: Curve, H: SigHash>(
    vendored_group: &Value,
    vendored_test: &Value,
    answered_group: &Value,
    answered_test: &Value,
) -> Result<(), Error> {
    let q = sec1(answered_group, C::WIDTH)?
        .ok_or_else(|| Error::new("answered q is wider than the curve"))?;
    if sec1(vendored_group, C::WIDTH)?.as_ref() != Some(&q) {
        return Err(Error::new("answered qx, qy differ from the file"));
    }
    let public = C::public(&q)?;
    let message = hex(vendored_test, "message")?;
    for (whose, t) in [("answered", answered_test), ("file's", vendored_test)] {
        let ok = signature(t, C::WIDTH)?
            .is_some_and(|sig| C::verify::<H>(&public, &message, &sig));
        if !ok {
            return Err(Error::new(format!("{whose} r, s do not verify")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{find, fixed_rng};
    use super::*;
    use crate::support::list;

    /// RFC 6979 fixes the nonce, so the deterministic suite's answers
    /// must be the file's to the byte, which the verifying check
    /// alone does not demand.
    #[test]
    fn deterministic_is_exact() {
        let suite = find("DetECDSA")[0];
        let Some(doc) = super::super::vendored(suite) else {
            return;
        };
        let answered = answer(&doc, &mut fixed_rng()).unwrap();
        let mut cases = 0;
        for group in list(&answered, "testGroups").unwrap() {
            let stored = list(&doc, "testGroups")
                .unwrap()
                .iter()
                .find(|g| g["tgId"] == group["tgId"])
                .unwrap();
            for t in list(group, "tests").unwrap() {
                let s = list(stored, "tests")
                    .unwrap()
                    .iter()
                    .find(|s| s["tcId"] == t["tcId"])
                    .unwrap();
                for name in ["r", "s"] {
                    assert_eq!(hex(t, name).unwrap(), hex(s, name).unwrap());
                }
                cases += 1;
            }
        }
        assert!(cases >= suite.minimum);
    }

    /// The server's prompt gives no key, so the driver draws one; what
    /// it answers must hang together.
    #[test]
    fn fresh_keys_are_consistent() {
        let doc = |mode: &str, group: Value| {
            let mut doc =
                json!({ "algorithm": "ECDSA", "testGroups": [group] });
            doc["mode"] = mode.into();
            doc
        };
        let key_gen = doc(
            "keyGen",
            json!({ "tgId": 1, "testType": "AFT", "curve": "P-256",
                    "tests": [{ "tcId": 1 }] }),
        );
        let answered = answer(&key_gen, &mut fixed_rng()).unwrap();
        let t = &answered["testGroups"][0]["tests"][0];
        let key = P256::private(&hex(t, "d").unwrap()).unwrap();
        assert_eq!(sec1(t, 32).unwrap().unwrap(), P256::public_of(&key));

        let sig_gen = doc(
            "sigGen",
            json!({ "tgId": 1, "testType": "AFT", "curve": "P-256",
                    "hashAlg": "SHA2-256",
                    "tests": [{ "tcId": 1, "message": "616263" }] }),
        );
        let answered = answer(&sig_gen, &mut fixed_rng()).unwrap();
        let g = &answered["testGroups"][0];
        let public = P256::public(&sec1(g, 32).unwrap().unwrap()).unwrap();
        let sig = signature(&g["tests"][0], 32).unwrap().unwrap();
        assert!(P256::verify::<Sha256>(&public, b"abc", &sig));
    }

    #[test]
    fn verify_refuses_a_damaged_signature() {
        let suite = find("ECDSA")
            .into_iter()
            .find(|s| s.mode == Some("sigGen"))
            .unwrap();
        let Some(doc) = super::super::vendored(suite) else {
            return;
        };
        let answered = answer(&doc, &mut fixed_rng()).unwrap();
        let group = &list(&answered, "testGroups").unwrap()[0];
        let stored = list(&doc, "testGroups")
            .unwrap()
            .iter()
            .find(|g| g["tgId"] == group["tgId"])
            .unwrap();
        let t = &list(group, "tests").unwrap()[0];
        let s = &list(stored, "tests").unwrap()[0];
        verify_sig_gen(stored, s, group, t).unwrap();
        let mut bad = t.clone();
        let mut r = hex(t, "r").unwrap();
        r[0] ^= 1;
        bad["r"] = hex_value(&r);
        assert!(verify_sig_gen(stored, s, group, &bad).is_err());
    }
}
