//! The implementation walk: every kernel this processor can run,
//! reached through the feature profiles the library's dispatching
//! types publish.
//!
//! The kernels themselves are private to the library. What a type
//! publishes is the feature set each one needs, best first, and an
//! object built with a context of that set takes that row. A context
//! of a type's profile selects that row of it and, for every other
//! type, the best row the same features allow; the empty set selects
//! the portable row of everything. So the union of every profile,
//! plus the detected set with and without [`Feature::Isolated`],
//! reaches every row the processor can run, and a vector set answered
//! under each of them must come out the same.
//!
//! A profile is a [`Profile`], which is a context and nothing more:
//! profiles share nothing, so any number of threads answer under any
//! number of them at once.

use crate::suite::Suite;
use crate::support::{Error, FixedEntropy};
use scytale::aead::{
    Aegis128L, Aegis128X2, Aegis128X4, Aegis256, Aegis256X2, Aegis256X4, Ccm,
    ChaCha20Poly1305, Gcm, GcmSiv, XChaCha20Poly1305, Xpn,
};
use scytale::cipher::aes::{Aes128, Aes192, Aes256};
use scytale::cipher::chacha20::ChaCha20;
use scytale::cipher::mode::{Cbc, Ctr, Xts};
use scytale::features::{self, Dispatcher, Feature, Features};
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use scytale::hash::sha3::{
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
};
use scytale::kex::ecdh;
use scytale::mac::poly1305::Poly1305;
use scytale::random::{CtrDrbg, MIN_SEED};
use scytale::sig::{self, ecdsa};
use scytale::{Context, Random};
use serde_json::Value;

/// The seed every profile's generator starts from, so the answers
/// a run compares drew the same randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seed(pub [u8; MIN_SEED]);

impl Seed {
    /// The seed the offline checks use.
    pub fn fixed() -> Self {
        Seed([0x5c; MIN_SEED])
    }

    /// A seed drawn from the operating system.
    pub fn random() -> Result<Self, Error> {
        let mut seed = Seed([0; MIN_SEED]);
        scytale::random::CtrDrbg::from_system(Context::default())?
            .fill(&mut seed.0)?;
        Ok(seed)
    }

    /// A generator over the seed, built by `profile`. Its own source
    /// is deterministic too, so even a reseed does not part two runs.
    pub fn rng(
        &self,
        profile: &Profile,
    ) -> Result<CtrDrbg<FixedEntropy>, Error> {
        let rng = FixedEntropy::default();
        Ok(CtrDrbg::try_new_seeded(profile.ctx(), &self.0, rng)?)
    }
}

/// One feature profile, as the context the drivers build the
/// library's objects with; the default is the processor's own set, as
/// a program that never names one would build them.
///
/// An object chooses its kernel from its context when it is built,
/// and so does everything it builds as it runs: the GHASH a GCM
/// message starts, the cipher and POLYVAL of a GCM-SIV message, the
/// hashes of a signature, a KDF or a DRBG. So a driver hands the
/// context to the constructors it calls and nothing else.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Profile(Context);

impl Profile {
    /// The profile of `features`, or the error the context gives when
    /// the processor lacks some of them.
    pub fn try_new(features: Features) -> Result<Self, Error> {
        Ok(Profile(Context::try_new(features)?))
    }

    /// The context the objects are built with.
    pub fn ctx(&self) -> Context {
        self.0
    }
}

/// The profiles every dispatching type tells apart, in walking order:
/// the set detected, the same isolated, each type's rows best first,
/// and the empty set.
pub(crate) fn candidates() -> Vec<Features> {
    let mut out = Vec::new();
    let mut push = |f: Features| {
        if !out.contains(&f) {
            out.push(f);
        }
    };
    let current = features::detected();
    push(current);
    push(current.with(Feature::Isolated));
    let lists: &[&[Features]] = &[
        Aes128::profiles(),
        Aes192::profiles(),
        Aes256::profiles(),
        <Cbc<Aes128> as Dispatcher>::profiles(),
        <Ctr<Aes128> as Dispatcher>::profiles(),
        <Xts<Aes128> as Dispatcher>::profiles(),
        <Gcm<Aes128> as Dispatcher>::profiles(),
        GcmSiv::<Aes128>::profiles(),
        <Ccm<Aes128> as Dispatcher>::profiles(),
        <Xpn<Aes128> as Dispatcher>::profiles(),
        Sha1::profiles(),
        Sha224::profiles(),
        Sha256::profiles(),
        Sha384::profiles(),
        Sha512::profiles(),
        Sha512_224::profiles(),
        Sha512_256::profiles(),
        Sha3_224::profiles(),
        Sha3_256::profiles(),
        Sha3_384::profiles(),
        Sha3_512::profiles(),
        Shake128::profiles(),
        Shake256::profiles(),
        ChaCha20::profiles(),
        Poly1305::profiles(),
        ChaCha20Poly1305::profiles(),
        XChaCha20Poly1305::profiles(),
        Aegis128L::profiles(),
        Aegis256::profiles(),
        Aegis128X2::profiles(),
        Aegis128X4::profiles(),
        Aegis256X2::profiles(),
        Aegis256X4::profiles(),
        <ecdh::p256::PrivateKey as Dispatcher>::profiles(),
        <ecdh::p384::PrivateKey as Dispatcher>::profiles(),
        <ecdh::p521::PrivateKey as Dispatcher>::profiles(),
        <ecdsa::p256::PrivateKey as Dispatcher>::profiles(),
        <sig::rsa::PrivateKey as Dispatcher>::profiles(),
    ];
    for list in lists {
        for &profile in *list {
            // Every list ends in the empty set; it goes last.
            if !profile.is_empty() {
                push(profile);
            }
        }
    }
    push(Features::new());
    out
}

/// The profiles this processor can run, and the ones it cannot, each
/// named once.
pub fn walk() -> (Vec<Features>, Vec<Features>) {
    let mut runnable = Vec::new();
    let mut refused = Vec::new();
    for profile in candidates() {
        match Profile::try_new(profile) {
            Ok(_) => runnable.push(profile),
            Err(_) => refused.push(profile),
        }
    }
    (runnable, refused)
}

/// Answers `doc` under each of `profiles` from the same seed and
/// returns the answer, or the first difference as an error with exit
/// status 2 naming both profiles and the case.
pub fn answer_under(
    suite: &Suite,
    doc: &Value,
    seed: &Seed,
    profiles: &[Features],
) -> Result<Value, Error> {
    let mut first: Option<(Features, Value)> = None;
    for &profile in profiles {
        let answered = Profile::try_new(profile).and_then(|profile| {
            let mut rng = seed.rng(&profile)?;
            (suite.answer)(doc, &mut rng, &profile)
        });
        let answered = answered
            .map_err(|e| Error::new(format!("under {profile}: {e}")))?;
        match &first {
            None => first = Some((profile, answered)),
            Some((reference, expected)) => {
                if let Some(detail) = differ(expected, &answered) {
                    return Err(Error::disagreement(format!(
                        "{} {}: {reference} and {profile} disagree at {detail}",
                        suite.algorithm,
                        suite.mode.unwrap_or(""),
                    )));
                }
            }
        }
    }
    first
        .map(|(_, answered)| answered)
        .ok_or_else(|| Error::new("no profile to run"))
}

/// Where two answers to one vector set first differ: the group and
/// case, and the field.
fn differ(a: &Value, b: &Value) -> Option<String> {
    let groups = |v: &Value| v["testGroups"].as_array().cloned();
    let (ga, gb) = (groups(a)?, groups(b)?);
    if ga.len() != gb.len() {
        return Some(format!("group count {} vs {}", ga.len(), gb.len()));
    }
    for (ga, gb) in ga.iter().zip(&gb) {
        let tag = format!("tgId {}", ga["tgId"]);
        if let Some(field) = differing_field(ga, gb, "tests") {
            return Some(format!("{tag} {field}"));
        }
        let (ta, tb) = (ga["tests"].as_array()?, gb["tests"].as_array()?);
        if ta.len() != tb.len() {
            return Some(format!("{tag} case count"));
        }
        for (ta, tb) in ta.iter().zip(tb) {
            if let Some(field) = differing_field(ta, tb, "") {
                return Some(format!("{tag} tcId {} {field}", ta["tcId"]));
            }
        }
    }
    None
}

fn differing_field(a: &Value, b: &Value, except: &str) -> Option<String> {
    let (a, b) = (a.as_object()?, b.as_object()?);
    for (name, value) in a {
        if name == except {
            continue;
        }
        if b.get(name) != Some(value) {
            return Some(name.clone());
        }
    }
    b.keys().find(|k| !a.contains_key(*k)).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn differ_names_the_case_and_field() {
        let a = json!({"testGroups": [{"tgId": 1, "tests": [
            {"tcId": 1, "ct": "AA"}, {"tcId": 2, "ct": "BB"}]}]});
        let mut b = a.clone();
        assert_eq!(differ(&a, &b), None);
        b["testGroups"][0]["tests"][1]["ct"] = json!("BC");
        assert_eq!(differ(&a, &b).as_deref(), Some("tgId 1 tcId 2 ct"));
        b = a.clone();
        b["testGroups"][0]["qx"] = json!("00");
        assert_eq!(differ(&a, &b).as_deref(), Some("tgId 1 qx"));
    }

    #[test]
    fn same_seed_same_bytes() {
        let seed = Seed::fixed();
        let profile = Profile::default();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        seed.rng(&profile).unwrap().fill(&mut x).unwrap();
        seed.rng(&profile).unwrap().fill(&mut y).unwrap();
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 32]);
    }
}
