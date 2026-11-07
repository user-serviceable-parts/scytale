//! ML-KEM keyGen and encapDecap (FIPS 203), all three parameter
//! sets. The vectors fix the randomness, `d || z` for a key and `m`
//! for an encapsulation, so both run through the public API with a
//! random source that hands back exactly those bytes; decapsulation
//! runs from the seed form and the expanded form alike, and its
//! damaged ciphertexts must come out as the implicitly rejected
//! secret. The key checks answer whether the library accepts the key.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, text};
use scytale::Random;
use scytale::kem::ml_kem::{ml_kem_512, ml_kem_768, ml_kem_1024};
use serde_json::{Value, json};

/// A random source that yields fixed bytes, so a vector's `d`, `z`
/// or `m` reaches the scheme through the same call a caller makes.
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

/// One parameter set's types, so each suite is written once.
trait Set {
    const NAME: &'static str;
    /// `ek || dk` from the seed `d || z`.
    fn key_gen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;
    /// `c || k` from `ek` and `m`.
    fn encapsulate(ek: &[u8], m: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;
    /// `k` from the expanded `dk` and `c`.
    fn decapsulate(dk: &[u8], c: &[u8]) -> Result<Vec<u8>, Error>;
    /// `k` from the seed and `c`.
    fn decapsulate_seed(seed: &[u8], c: &[u8]) -> Result<Vec<u8>, Error>;
    /// Whether an expanded `dk` passes the key check.
    fn private_ok(dk: &[u8]) -> bool;
    /// Whether an `ek` passes the key check.
    fn public_ok(ek: &[u8]) -> bool;
}

macro_rules! set {
    ($name:ident, $module:ident, $acvp:literal) => {
        struct $name;
        impl Set for $name {
            const NAME: &'static str = $acvp;
            fn key_gen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
                let mut rng = Fixed(seed.to_vec());
                let key = $module::PrivateKey::generate(&mut rng)?;
                let ek = key.public_key().bytes().to_vec();
                Ok((ek, key.key_bytes().to_vec()))
            }
            fn encapsulate(
                ek: &[u8],
                m: &[u8],
            ) -> Result<(Vec<u8>, Vec<u8>), Error> {
                let ek = array::<{ $module::PUBLIC_KEY_SIZE }>(ek, "ek")?;
                let key = $module::PublicKey::try_new(&ek)?;
                let mut rng = Fixed(m.to_vec());
                let (c, k) = key.encapsulate(&mut rng)?;
                Ok((c.to_vec(), k.to_vec()))
            }
            fn decapsulate(dk: &[u8], c: &[u8]) -> Result<Vec<u8>, Error> {
                let dk = array::<{ $module::KEY_SIZE }>(dk, "dk")?;
                let key = $module::PrivateKey::try_new(&dk)?;
                let c = array::<{ $module::CIPHERTEXT_SIZE }>(c, "c")?;
                Ok(key.decapsulate(&c).to_vec())
            }
            fn decapsulate_seed(
                seed: &[u8],
                c: &[u8],
            ) -> Result<Vec<u8>, Error> {
                let seed = array::<64>(seed, "d || z")?;
                let key = $module::PrivateKey::from_seed(&seed);
                let c = array::<{ $module::CIPHERTEXT_SIZE }>(c, "c")?;
                Ok(key.decapsulate(&c).to_vec())
            }
            fn private_ok(dk: &[u8]) -> bool {
                <[u8; $module::KEY_SIZE]>::try_from(dk)
                    .is_ok_and(|dk| $module::PrivateKey::try_new(&dk).is_ok())
            }
            fn public_ok(ek: &[u8]) -> bool {
                <[u8; $module::PUBLIC_KEY_SIZE]>::try_from(ek)
                    .is_ok_and(|ek| $module::PublicKey::try_new(&ek).is_ok())
            }
        }
    };
}

set!(Set512, ml_kem_512, "ML-KEM-512");
set!(Set768, ml_kem_768, "ML-KEM-768");
set!(Set1024, ml_kem_1024, "ML-KEM-1024");

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    let mode = text(doc, "mode")?;
    answer_groups(doc, |group| match text(group, "parameterSet")? {
        Set512::NAME => answer_group::<Set512>(mode, group),
        Set768::NAME => answer_group::<Set768>(mode, group),
        Set1024::NAME => answer_group::<Set1024>(mode, group),
        other => Err(Error::new(format!("parameter set {other}"))),
    })
}

fn answer_group<S: Set>(
    mode: &str,
    group: &Value,
) -> Result<Option<Value>, Error> {
    match mode {
        "keyGen" => answer_tests(group, key_gen::<S>),
        "encapDecap" => match text(group, "function")? {
            "encapsulation" => answer_tests(group, encapsulation::<S>),
            "decapsulation" => {
                let seed = text(group, "keyFormat")? == "seed";
                answer_tests(group, |t| decapsulation::<S>(t, seed))
            }
            "encapsulationKeyCheck" => answer_tests(group, |t| {
                Ok(json!({ "testPassed": S::public_ok(&hex(t, "ek")?) }))
            }),
            "decapsulationKeyCheck" => answer_tests(group, |t| {
                Ok(json!({ "testPassed": S::private_ok(&hex(t, "dk")?) }))
            }),
            other => Err(Error::new(format!("function {other}"))),
        },
        other => Err(Error::new(format!("mode {other}"))),
    }
}

fn seed(t: &Value) -> Result<Vec<u8>, Error> {
    let mut seed = hex(t, "d")?;
    seed.extend(hex(t, "z")?);
    Ok(seed)
}

fn key_gen<S: Set>(t: &Value) -> Result<Value, Error> {
    let (ek, dk) = S::key_gen(&seed(t)?)?;
    Ok(json!({ "ek": hex_value(&ek), "dk": hex_value(&dk) }))
}

fn encapsulation<S: Set>(t: &Value) -> Result<Value, Error> {
    let (c, k) = S::encapsulate(&hex(t, "ek")?, &hex(t, "m")?)?;
    Ok(json!({ "c": hex_value(&c), "k": hex_value(&k) }))
}

fn decapsulation<S: Set>(t: &Value, seeded: bool) -> Result<Value, Error> {
    let c = hex(t, "c")?;
    let k = if seeded {
        S::decapsulate_seed(&seed(t)?, &c)?
    } else {
        S::decapsulate(&hex(t, "dk")?, &c)?
    };
    Ok(json!({ "k": hex_value(&k) }))
}
