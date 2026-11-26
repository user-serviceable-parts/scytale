//! EDDSA keyGen, keyVer, sigGen and sigVer over both curves:
//! Ed25519, and Ed25519ph where a group is marked `preHash`; Ed448,
//! and Ed448ph likewise.
//!
//! A secret the file supplies (`d`, per case for keyGen and per group
//! for sigGen) is used; the server's prompt carries none, so one is
//! drawn from the generator instead. The pre-hashed cases give the
//! message, which the driver hashes before handing the digest over:
//! SHA-512 for Ed25519ph, 64 bytes of SHAKE256 for Ed448ph. Signing
//! is deterministic, so sigGen answers are the file's to the byte;
//! sigVer and keyVer carry the deliberately damaged cases. The
//! vendored files have no Ed25519ctx case: every Ed25519 group
//! without pre-hashing has an empty context, which is plain Ed25519,
//! and a context there is refused rather than guessed at. Ed448
//! hashes a context into every signature, so its contexts are
//! simply taken.

use super::{answer_groups, answer_tests};
use crate::profile::Profile;
use crate::support::{
    Error, flag, hex, hex_value, opt_hex, opt_int, text, unknown_test_type,
};
use scytale::Context;
use scytale::Random;
use scytale::hash::Hash;
use scytale::hash::sha2::Sha512;
use scytale::sig::{ed448, ed25519};
use serde_json::{Value, json};

/// A signature over a message under a secret, given whether it is
/// pre-hashed and the context: `(d, prehash, context, message)`.
type Sign = fn(Context, &[u8], bool, &[u8], &[u8]) -> Result<Vec<u8>, Error>;

/// Whether a signature verifies under a public key:
/// `(q, prehash, context, message, signature)`.
type Verify =
    fn(Context, &[u8], bool, &[u8], &[u8], &[u8]) -> Result<(), scytale::Error>;

/// One curve's operations over byte slices, with the lengths its
/// keys and signatures take; a slice of another length is refused by
/// the callers before it reaches these.
struct Curve {
    key: usize,
    signature: usize,
    public_key: fn(Context, &[u8]) -> Vec<u8>,
    sign: Sign,
    verify: Verify,
}

const ED25519: Curve = Curve {
    key: ed25519::KEY_SIZE,
    signature: ed25519::SIGNATURE_SIZE,
    public_key: |ctx, d| ed25519::public_key(ctx, &array(d)).to_vec(),
    sign: |ctx, d, prehash, context, message| {
        let d = array(d);
        if prehash {
            let digest = Sha512::digest(ctx, message);
            Ok(ed25519::sign_ph_deterministic(ctx, &d, context, &digest)?
                .to_vec())
        } else if context.is_empty() {
            Ok(ed25519::sign_deterministic(ctx, &d, message).to_vec())
        } else {
            Err(Error::new("no Ed25519ctx case is expected"))
        }
    },
    verify: |ctx, q, prehash, context, message, signature| {
        let (q, signature) = (array(q), array(signature));
        if prehash {
            let digest = Sha512::digest(ctx, message);
            ed25519::verify_ph(ctx, &q, context, &digest, &signature)
        } else if context.is_empty() {
            ed25519::verify(ctx, &q, message, &signature)
        } else {
            // Not a case the files hold; refused as unverifiable.
            Err(scytale::Error::InvalidSignature)
        }
    },
};

const ED448: Curve = Curve {
    key: ed448::KEY_SIZE,
    signature: ed448::SIGNATURE_SIZE,
    public_key: |ctx, d| ed448::public_key(ctx, &array(d)).to_vec(),
    sign: |ctx, d, prehash, context, message| {
        let d = array(d);
        Ok(if prehash {
            let digest = ed448::prehash(ctx, message);
            ed448::sign_ph_deterministic(ctx, &d, context, &digest)?
        } else {
            ed448::sign_deterministic(ctx, &d, context, message)?
        }
        .to_vec())
    },
    verify: |ctx, q, prehash, context, message, signature| {
        let (q, signature) = (array(q), array(signature));
        if prehash {
            let digest = ed448::prehash(ctx, message);
            ed448::verify_ph(ctx, &q, context, &digest, &signature)
        } else {
            ed448::verify(ctx, &q, context, message, &signature)
        }
    },
};

/// A slice the caller has checked is `N` long, as an array.
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

pub fn answer(
    doc: &Value,
    rng: &mut dyn Random,
    profile: &Profile,
) -> Result<Value, Error> {
    let mode = text(doc, "mode")?;
    answer_groups(doc, |group| {
        let curve = match text(group, "curve")? {
            "ED-25519" => &ED25519,
            "ED-448" => &ED448,
            other => {
                return Err(Error::new(format!("no curve named {other}")));
            }
        };
        match (mode, text(group, "testType")?) {
            ("keyGen", "AFT") => key_gen(curve, group, rng, profile),
            ("keyVer", "AFT") => key_ver(curve, group, profile),
            ("sigGen", "AFT" | "BFT") => sig_gen(curve, group, rng, profile),
            ("sigVer", "AFT") => sig_ver(curve, group, profile),
            _ => Err(unknown_test_type(group)),
        }
    })
}

/// The secret the file gives as `d` in `v`, or a fresh one.
fn secret(
    curve: &Curve,
    v: &Value,
    rng: &mut dyn Random,
) -> Result<Vec<u8>, Error> {
    match opt_hex(v, "d")? {
        Some(d) if d.len() == curve.key => Ok(d),
        Some(d) => Err(Error::new(format!("d is {} bytes", d.len()))),
        None => {
            let mut d = vec![0u8; curve.key];
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

/// Every EdDSA function of the crate hashes as it runs, a key's
/// public half included, so each takes the profile's context, as each
/// of the functions below does.
fn key_gen(
    curve: &Curve,
    group: &Value,
    rng: &mut dyn Random,
    profile: &Profile,
) -> Result<Option<Value>, Error> {
    answer_tests(group, |t| {
        let (d, q) = {
            let d = secret(curve, t, rng)?;
            let q = (curve.public_key)(profile.ctx(), &d);
            Ok::<_, Error>((d, q))
        }?;
        Ok(json!({ "d": hex_value(&d), "q": hex_value(&q) }))
    })
}

/// The crate has no standalone key check: a public key is validated
/// as part of verifying with it. That is enough here because both
/// `verify` functions document the distinction these cases turn on,
/// returning `InvalidPublicKey` when the key is not a point on the
/// curve and `InvalidSignature` for everything else. The signature
/// handed in is therefore a dummy, and the verdict is read from the
/// error alone.
fn key_ver(
    curve: &Curve,
    group: &Value,
    profile: &Profile,
) -> Result<Option<Value>, Error> {
    answer_tests(group, |t| {
        let q = hex(t, "q")?;
        let dummy = vec![0; curve.signature];
        // A key of another length is not a key at all.
        let passed = q.len() == curve.key
            && !matches!(
                (curve.verify)(profile.ctx(), &q, false, b"", b"", &dummy),
                Err(scytale::Error::InvalidPublicKey)
            );
        Ok(json!({ "testPassed": passed }))
    })
}

fn sig_gen(
    curve: &Curve,
    group: &Value,
    rng: &mut dyn Random,
    profile: &Profile,
) -> Result<Option<Value>, Error> {
    let prehash = flag(group, "preHash")?;
    let (d, q) = {
        let d = secret(curve, group, rng)?;
        let q = (curve.public_key)(profile.ctx(), &d);
        Ok::<_, Error>((d, q))
    }?;
    let answered = answer_tests(group, |t| {
        let message = hex(t, "message")?;
        let context = context(t)?;
        let signature = {
            let signature =
                (curve.sign)(profile.ctx(), &d, prehash, &context, &message)?;
            // A signature this crate cannot itself verify is a fault
            // worth stopping on before the server sees it.
            (curve.verify)(
                profile.ctx(),
                &q,
                prehash,
                &context,
                &message,
                &signature,
            )?;
            Ok::<_, Error>(signature)
        }?;
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

fn sig_ver(
    curve: &Curve,
    group: &Value,
    profile: &Profile,
) -> Result<Option<Value>, Error> {
    let prehash = flag(group, "preHash")?;
    answer_tests(group, |t| {
        let message = hex(t, "message")?;
        let context = context(t)?;
        let (q, signature) = (hex(t, "q")?, hex(t, "signature")?);
        // A key or signature of another length cannot verify.
        let passed =
            q.len() == curve.key && signature.len() == curve.signature && {
                (curve.verify)(
                    profile.ctx(),
                    &q,
                    prehash,
                    &context,
                    &message,
                    &signature,
                )
                .is_ok()
            };
        Ok(json!({ "testPassed": passed }))
    })
}

#[cfg(test)]
mod tests {
    use super::super::fixed_rng;
    use super::*;

    /// The server's prompt gives no secret, so the driver draws one;
    /// what it answers must hang together, on both curves.
    #[test]
    fn fresh_keys_are_consistent() {
        let ctx = Context::default();
        let doc = |mode: &str, group: Value| {
            let mut doc =
                json!({ "algorithm": "EDDSA", "testGroups": [group] });
            doc["mode"] = mode.into();
            doc
        };
        for (name, curve) in [("ED-25519", &ED25519), ("ED-448", &ED448)] {
            let key_gen = doc(
                "keyGen",
                json!({ "tgId": 1, "testType": "AFT", "curve": name,
                        "tests": [{ "tcId": 1 }] }),
            );
            let answered = answer(
                &key_gen,
                &mut fixed_rng(&Profile::default()).unwrap(),
                &Profile::default(),
            )
            .unwrap();
            let t = &answered["testGroups"][0]["tests"][0];
            let d = hex(t, "d").unwrap();
            assert_eq!(d.len(), curve.key, "{name}");
            assert_eq!(hex(t, "q").unwrap(), (curve.public_key)(ctx, &d));

            for prehash in [false, true] {
                let sig_gen = doc(
                    "sigGen",
                    json!({ "tgId": 1, "testType": "AFT", "curve": name,
                            "preHash": prehash,
                            "tests": [{ "tcId": 1, "message": "616263" }] }),
                );
                let answered = answer(
                    &sig_gen,
                    &mut fixed_rng(&Profile::default()).unwrap(),
                    &Profile::default(),
                )
                .unwrap();
                let g = &answered["testGroups"][0];
                let q = hex(g, "q").unwrap();
                let sig = hex(&g["tests"][0], "signature").unwrap();
                assert_eq!(sig.len(), curve.signature, "{name}");
                (curve.verify)(ctx, &q, prehash, b"", b"abc", &sig).unwrap();
            }
        }
    }

    /// An Ed448 signature under a context verifies under that context
    /// alone, so the contexts the files give are really used.
    #[test]
    fn ed448_contexts_are_taken() {
        let ctx = Context::default();
        let d = [3u8; ed448::KEY_SIZE];
        let q = (ED448.public_key)(ctx, &d);
        let sig = (ED448.sign)(ctx, &d, false, b"ctx", b"m").unwrap();
        (ED448.verify)(ctx, &q, false, b"ctx", b"m", &sig).unwrap();
        assert!((ED448.verify)(ctx, &q, false, b"", b"m", &sig).is_err());
        assert!((ED448.verify)(ctx, &q, true, b"ctx", b"m", &sig).is_err());
    }
}
