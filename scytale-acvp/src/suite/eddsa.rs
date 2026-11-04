//! EDDSA keyGen, keyVer, sigGen and sigVer, for the Ed25519 groups:
//! plain Ed25519, and Ed25519ph where a group is marked `preHash`.
//! Ed448 is not implemented, so its groups are skipped.
//!
//! A secret the file supplies (`d`, per case for keyGen and per group
//! for sigGen) is used; the server's prompt carries none, so one is
//! drawn from the generator instead. The pre-hashed cases give the
//! message, which the driver hashes with SHA-512 before handing the
//! digest over. Signing is deterministic, so sigGen answers are the
//! file's to the byte; sigVer and keyVer carry the deliberately
//! damaged cases. The vendored files have no Ed25519ctx case: every
//! group without pre-hashing has an empty context, which is plain
//! Ed25519, and a context there is refused rather than guessed at.

use super::{answer_groups, answer_tests, skip};
use crate::support::{
    Error, flag, hex, hex_value, opt_hex, opt_int, text, unknown_test_type,
};
use scytale::Random;
use scytale::hash::Hash;
use scytale::hash::sha2::Sha512;
use scytale::sig::ed25519;
use serde_json::{Value, json};

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    let mode = text(doc, "mode")?;
    answer_groups(doc, |group| {
        if text(group, "curve")? != "ED-25519" {
            let curve = text(group, "curve")?;
            return skip(group, &format!("{curve} is not implemented"));
        }
        match (mode, text(group, "testType")?) {
            ("keyGen", "AFT") => key_gen(group, rng),
            ("keyVer", "AFT") => key_ver(group),
            ("sigGen", "AFT" | "BFT") => sig_gen(group, rng),
            ("sigVer", "AFT") => sig_ver(group),
            _ => Err(unknown_test_type(group)),
        }
    })
}

/// A signature over `message` under `context`, by whichever variant
/// the group names.
fn sign(
    secret: &[u8; 32],
    prehash: bool,
    context: &[u8],
    message: &[u8],
) -> Result<[u8; 64], Error> {
    if prehash {
        let digest = Sha512::digest(message);
        Ok(ed25519::sign_ph_deterministic(secret, context, &digest)?)
    } else if context.is_empty() {
        Ok(ed25519::sign_deterministic(secret, message))
    } else {
        Err(Error::new("no Ed25519ctx case is expected"))
    }
}

/// Whether `signature` verifies, by whichever variant the group
/// names.
fn verify(
    public: &[u8; 32],
    prehash: bool,
    context: &[u8],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), Error> {
    if prehash {
        let digest = Sha512::digest(message);
        Ok(ed25519::verify_ph(public, context, &digest, signature)?)
    } else if context.is_empty() {
        Ok(ed25519::verify(public, message, signature)?)
    } else {
        Err(Error::new("no Ed25519ctx case is expected"))
    }
}

/// The secret the file gives as `d` in `v`, or a fresh one.
fn secret(v: &Value, rng: &mut dyn Random) -> Result<[u8; 32], Error> {
    match opt_hex(v, "d")? {
        Some(d) => d.try_into().map_err(|_| Error::new("d is not 32 bytes")),
        None => {
            let mut d = [0u8; 32];
            rng.fill(&mut d)?;
            Ok(d)
        }
    }
}

/// The context of a case: an absent one is the empty context, as the
/// plain groups' prompts and the verification cases leave it out.
fn context(t: &Value) -> Result<Vec<u8>, Error> {
    let context = opt_hex(t, "context")?.unwrap_or_default();
    match opt_int(t, "contextLength") {
        Some(n) if n != context.len() as u64 => Err(Error::new(format!(
            "context of {} bytes, contextLength {n}",
            context.len()
        ))),
        _ => Ok(context),
    }
}

fn key_gen(
    group: &Value,
    rng: &mut dyn Random,
) -> Result<Option<Value>, Error> {
    answer_tests(group, |t| {
        let d = secret(t, rng)?;
        let q = ed25519::public_key(&d);
        Ok(json!({ "d": hex_value(&d), "q": hex_value(&q) }))
    })
}

/// The crate has no standalone key check: a public key is validated
/// as part of verifying with it. That is enough here because
/// [`ed25519::verify`] documents the distinction these cases turn on,
/// returning `InvalidPublicKey` when the key is not a point on the
/// curve and `InvalidSignature` for everything else. The signature
/// handed in is therefore a dummy, and the verdict is read from the
/// error alone.
fn key_ver(group: &Value) -> Result<Option<Value>, Error> {
    answer_tests(group, |t| {
        // A key of another length is not a key at all.
        let passed = match <[u8; 32]>::try_from(hex(t, "q")?) {
            Ok(q) => !matches!(
                ed25519::verify(&q, b"", &[0u8; 64]),
                Err(scytale::Error::InvalidPublicKey)
            ),
            Err(_) => false,
        };
        Ok(json!({ "testPassed": passed }))
    })
}

fn sig_gen(
    group: &Value,
    rng: &mut dyn Random,
) -> Result<Option<Value>, Error> {
    let prehash = flag(group, "preHash")?;
    let d = secret(group, rng)?;
    let q = ed25519::public_key(&d);
    let answered = answer_tests(group, |t| {
        let message = hex(t, "message")?;
        let context = context(t)?;
        let signature = sign(&d, prehash, &context, &message)?;
        // A signature this crate cannot itself verify is a fault worth
        // stopping on before the server sees it.
        verify(&q, prehash, &context, &message, &signature)?;
        Ok(json!({ "signature": hex_value(&signature) }))
    })?;
    let Some(mut answered) = answered else {
        return Ok(None);
    };
    if let Some(g) = answered.as_object_mut() {
        g.insert("q".into(), hex_value(&q));
    }
    Ok(Some(answered))
}

fn sig_ver(group: &Value) -> Result<Option<Value>, Error> {
    let prehash = flag(group, "preHash")?;
    answer_tests(group, |t| {
        let message = hex(t, "message")?;
        let context = context(t)?;
        // A key or signature of another length cannot verify.
        let q = <[u8; 32]>::try_from(hex(t, "q")?);
        let signature = <[u8; 64]>::try_from(hex(t, "signature")?);
        let passed = match (q, signature) {
            (Ok(q), Ok(signature)) => {
                verify(&q, prehash, &context, &message, &signature).is_ok()
            }
            _ => false,
        };
        Ok(json!({ "testPassed": passed }))
    })
}

#[cfg(test)]
mod tests {
    use super::super::fixed_rng;
    use super::*;

    #[test]
    fn vendored() {
        for suite in super::super::find("EDDSA") {
            super::super::check(suite);
        }
    }

    /// The server's prompt gives no secret, so the driver draws one;
    /// what it answers must hang together.
    #[test]
    fn fresh_keys_are_consistent() {
        let doc = |mode: &str, group: Value| {
            let mut doc =
                json!({ "algorithm": "EDDSA", "testGroups": [group] });
            doc["mode"] = mode.into();
            doc
        };
        let key_gen = doc(
            "keyGen",
            json!({ "tgId": 1, "testType": "AFT", "curve": "ED-25519",
                    "tests": [{ "tcId": 1 }] }),
        );
        let answered = answer(&key_gen, &mut fixed_rng()).unwrap();
        let t = &answered["testGroups"][0]["tests"][0];
        let d: [u8; 32] = hex(t, "d").unwrap().try_into().unwrap();
        assert_eq!(hex(t, "q").unwrap(), ed25519::public_key(&d));

        for prehash in [false, true] {
            let sig_gen = doc(
                "sigGen",
                json!({ "tgId": 1, "testType": "AFT", "curve": "ED-25519",
                        "preHash": prehash,
                        "tests": [{ "tcId": 1, "message": "616263" }] }),
            );
            let answered = answer(&sig_gen, &mut fixed_rng()).unwrap();
            let g = &answered["testGroups"][0];
            let q: [u8; 32] = hex(g, "q").unwrap().try_into().unwrap();
            let sig: [u8; 64] = hex(&g["tests"][0], "signature")
                .unwrap()
                .try_into()
                .unwrap();
            verify(&q, prehash, b"", b"abc", &sig).unwrap();
        }
    }
}
