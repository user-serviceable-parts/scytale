//! ML-DSA keyGen, sigGen and sigVer (FIPS 204), all three parameter
//! sets, for the pure external interface the crate offers: the
//! groups for the internal interface, the pre-hashed variant and an
//! externally supplied `mu` are skipped. Signing runs hedged with the
//! prompt's `rnd` supplied through a fixed random source, or
//! deterministically where the group says so, and so reproduces the
//! signature byte for byte; keys come from the seed and from the
//! expanded form alike.

use super::{answer_groups, answer_tests, skip};
use crate::support::{Error, flag, hex, hex_value, text};
use scytale::Random;
use scytale::sig::ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use serde_json::{Value, json};

/// A random source that yields fixed bytes, so a vector's seed or
/// `rnd` reaches the scheme through the same call a caller makes.
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
    /// `pk || sk` from the seed.
    fn key_gen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;
    /// A signature from the seed or the expanded key, hedged with
    /// `rnd` when given and deterministic otherwise.
    fn sign(
        seed: Option<&[u8]>,
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
            fn key_gen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
                let mut rng = Fixed(seed.to_vec());
                let key = $module::PrivateKey::generate(&mut rng)?;
                let pk = key.public_key().bytes().to_vec();
                Ok((pk, key.key_bytes().to_vec()))
            }
            fn sign(
                seed: Option<&[u8]>,
                sk: &[u8],
                rnd: Option<&[u8]>,
                context: &[u8],
                message: &[u8],
            ) -> Result<Vec<u8>, Error> {
                let key = match seed {
                    Some(seed) => {
                        let seed = array::<32>(seed, "seed")?;
                        $module::PrivateKey::from_seed(&seed)
                    }
                    None => {
                        let sk = array::<{ $module::KEY_SIZE }>(sk, "sk")?;
                        $module::PrivateKey::try_new(&sk)?
                    }
                };
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

set!(Set44, ml_dsa_44, "ML-DSA-44");
set!(Set65, ml_dsa_65, "ML-DSA-65");
set!(Set87, ml_dsa_87, "ML-DSA-87");

/// Whether a group is one the pure external interface can run.
fn pure_external(group: &Value) -> bool {
    group["signatureInterface"] == "external"
        && group["preHash"] == "pure"
        && group["externalMu"] != true
}

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    let mode = text(doc, "mode")?;
    answer_groups(doc, |group| match text(group, "parameterSet")? {
        Set44::NAME => answer_group::<Set44>(mode, group),
        Set65::NAME => answer_group::<Set65>(mode, group),
        Set87::NAME => answer_group::<Set87>(mode, group),
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
            let seed = text(group, "keyFormat")? == "seed";
            answer_tests(group, |t| sig_gen::<S>(t, deterministic, seed))
        }
        "sigVer" => answer_tests(group, sig_ver::<S>),
        other => Err(Error::new(format!("mode {other}"))),
    }
}

fn key_gen<S: Set>(t: &Value) -> Result<Value, Error> {
    let (pk, sk) = S::key_gen(&hex(t, "seed")?)?;
    Ok(json!({ "pk": hex_value(&pk), "sk": hex_value(&sk) }))
}

fn sig_gen<S: Set>(
    t: &Value,
    deterministic: bool,
    seed: bool,
) -> Result<Value, Error> {
    // Only the fields a group uses are present in its cases.
    let rnd = if deterministic {
        None
    } else {
        Some(hex(t, "rnd")?)
    };
    let seed_bytes = if seed { Some(hex(t, "seed")?) } else { None };
    let sk = if seed { Vec::new() } else { hex(t, "sk")? };
    let sig = S::sign(
        seed_bytes.as_deref(),
        &sk,
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

#[cfg(test)]
mod tests {
    #[test]
    fn vendored() {
        for suite in super::super::find("ML-DSA") {
            super::super::check(suite);
        }
    }
}
