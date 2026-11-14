//! SLH-DSA keyGen, sigGen and sigVer (FIPS 205), all twelve
//! parameter sets, for the pure external interface: the groups for
//! the internal interface and the pre-hashed variant are skipped.
//! Key generation runs with the three seeds supplied through a fixed
//! random source, and hedged signing with the prompt's additional
//! randomness the same way, so both reproduce the expected bytes.

use super::{answer_groups, answer_tests, skip};
use crate::support::{Error, flag, hex, hex_value, text};
use scytale::Random;
use scytale::sig::slh_dsa::*;
use serde_json::{Value, json};

/// A random source that yields fixed bytes, so a vector's seeds or
/// additional randomness reach the scheme through the same call a
/// caller makes.
struct Fixed(Vec<u8>);

impl Random for Fixed {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), scytale::Error> {
        if self.0.len() < out.len() {
            return Err(scytale::Error::InvalidLength(self.0.len()));
        }
        let rest = self.0.split_off(out.len());
        out.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

/// `bytes` as an array, or an error naming the field it came from.
fn array<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| {
        Error::new(format!("{name} of {} bytes, not {N}", bytes.len()))
    })
}

trait Set {
    const NAME: &'static str;
    /// `pk || sk` from `SK.seed || SK.prf || PK.seed`.
    fn key_gen(seeds: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;
    /// A signature, hedged with `rnd` when given.
    fn sign(
        sk: &[u8],
        rnd: Option<&[u8]>,
        context: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, Error>;
    fn verify(pk: &[u8], context: &[u8], message: &[u8], sig: &[u8]) -> bool;
}

macro_rules! set {
    ($name:ident, $module:ident, $acvp:literal) => {
        struct $name;
        impl Set for $name {
            const NAME: &'static str = $acvp;
            fn key_gen(seeds: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
                let mut rng = Fixed(seeds.to_vec());
                let key = $module::PrivateKey::generate(&mut rng)?;
                let pk = key.public_key().bytes().to_vec();
                Ok((pk, key.key_bytes().to_vec()))
            }
            fn sign(
                sk: &[u8],
                rnd: Option<&[u8]>,
                context: &[u8],
                message: &[u8],
            ) -> Result<Vec<u8>, Error> {
                let sk = array::<{ $module::KEY_SIZE }>(sk, "sk")?;
                let key = $module::PrivateKey::new(&sk);
                let sig = match rnd {
                    Some(rnd) => {
                        key.sign(&mut Fixed(rnd.to_vec()), context, message)?
                    }
                    None => key.sign_deterministic(context, message)?,
                };
                Ok(sig.to_vec())
            }
            fn verify(
                pk: &[u8],
                context: &[u8],
                message: &[u8],
                sig: &[u8],
            ) -> bool {
                let Ok(pk) = <[u8; $module::PUBLIC_KEY_SIZE]>::try_from(pk)
                else {
                    return false;
                };
                let Ok(sig) = <[u8; $module::SIGNATURE_SIZE]>::try_from(sig)
                else {
                    return false;
                };
                let key = $module::PublicKey::new(&pk);
                key.verify(context, message, &sig).is_ok()
            }
        }
    };
}

set!(Sha2_128s, sha2_128s, "SLH-DSA-SHA2-128s");
set!(Sha2_128f, sha2_128f, "SLH-DSA-SHA2-128f");
set!(Sha2_192s, sha2_192s, "SLH-DSA-SHA2-192s");
set!(Sha2_192f, sha2_192f, "SLH-DSA-SHA2-192f");
set!(Sha2_256s, sha2_256s, "SLH-DSA-SHA2-256s");
set!(Sha2_256f, sha2_256f, "SLH-DSA-SHA2-256f");
set!(Shake128s, shake_128s, "SLH-DSA-SHAKE-128s");
set!(Shake128f, shake_128f, "SLH-DSA-SHAKE-128f");
set!(Shake192s, shake_192s, "SLH-DSA-SHAKE-192s");
set!(Shake192f, shake_192f, "SLH-DSA-SHAKE-192f");
set!(Shake256s, shake_256s, "SLH-DSA-SHAKE-256s");
set!(Shake256f, shake_256f, "SLH-DSA-SHAKE-256f");

/// Whether a group is one the pure external interface can run.
fn pure_external(group: &Value) -> bool {
    group["signatureInterface"] == "external" && group["preHash"] == "pure"
}

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    let mode = text(doc, "mode")?;
    answer_groups(doc, |group| match text(group, "parameterSet")? {
        Sha2_128s::NAME => answer_group::<Sha2_128s>(mode, group),
        Sha2_128f::NAME => answer_group::<Sha2_128f>(mode, group),
        Sha2_192s::NAME => answer_group::<Sha2_192s>(mode, group),
        Sha2_192f::NAME => answer_group::<Sha2_192f>(mode, group),
        Sha2_256s::NAME => answer_group::<Sha2_256s>(mode, group),
        Sha2_256f::NAME => answer_group::<Sha2_256f>(mode, group),
        Shake128s::NAME => answer_group::<Shake128s>(mode, group),
        Shake128f::NAME => answer_group::<Shake128f>(mode, group),
        Shake192s::NAME => answer_group::<Shake192s>(mode, group),
        Shake192f::NAME => answer_group::<Shake192f>(mode, group),
        Shake256s::NAME => answer_group::<Shake256s>(mode, group),
        Shake256f::NAME => answer_group::<Shake256f>(mode, group),
        other => Err(Error::new(format!("parameter set {other}"))),
    })
}

fn answer_group<S: Set>(
    mode: &str,
    group: &Value,
) -> Result<Option<Value>, Error> {
    if mode != "keyGen" && !pure_external(group) {
        return skip(group, "only the pure external interface is offered");
    }
    match mode {
        "keyGen" => answer_tests(group, key_gen::<S>),
        "sigGen" => {
            let deterministic = flag(group, "deterministic")?;
            answer_tests(group, |t| sig_gen::<S>(t, deterministic))
        }
        "sigVer" => answer_tests(group, sig_ver::<S>),
        other => Err(Error::new(format!("mode {other}"))),
    }
}

fn key_gen<S: Set>(t: &Value) -> Result<Value, Error> {
    let mut seeds = hex(t, "skSeed")?;
    seeds.extend(hex(t, "skPrf")?);
    seeds.extend(hex(t, "pkSeed")?);
    let (pk, sk) = S::key_gen(&seeds)?;
    Ok(json!({ "pk": hex_value(&pk), "sk": hex_value(&sk) }))
}

fn sig_gen<S: Set>(t: &Value, deterministic: bool) -> Result<Value, Error> {
    let rnd = if deterministic {
        None
    } else {
        Some(hex(t, "additionalRandomness")?)
    };
    let sig = S::sign(
        &hex(t, "sk")?,
        rnd.as_deref(),
        &hex(t, "context")?,
        &hex(t, "message")?,
    )?;
    Ok(json!({ "signature": hex_value(&sig) }))
}

fn sig_ver<S: Set>(t: &Value) -> Result<Value, Error> {
    let passed = S::verify(
        &hex(t, "pk")?,
        &hex(t, "context")?,
        &hex(t, "message")?,
        &hex(t, "signature")?,
    );
    Ok(json!({ "testPassed": passed }))
}
