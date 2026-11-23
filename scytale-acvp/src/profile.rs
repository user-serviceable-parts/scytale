//! The implementation walk: every kernel this processor can run,
//! reached through the feature profiles the library's dispatching
//! types publish.
//!
//! The kernels themselves are private to the library. What a type
//! publishes is the feature set each one needs, best first, and
//! [`features::set`] puts a set in force for everything built
//! afterwards. Setting a type's profile selects that row of it and,
//! for every other type, the best row the same features allow; the
//! empty set selects the portable row of everything. So the union of
//! every profile, plus the detected set with and without
//! [`Feature::Isolated`], reaches every row the processor can run,
//! and a vector set answered under each of them must come out the
//! same.
//!
//! The set in force is the process's, so a profile is put in force
//! only through a [`Builder`], which several threads may share: see
//! there.

use crate::suite::Suite;
use crate::support::{Error, FixedEntropy};
use scytale::Random;
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
use serde_json::Value;
use std::sync::{Condvar, Mutex, PoisonError};

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
        scytale::random::CtrDrbg::from_system()?.fill(&mut seed.0)?;
        Ok(seed)
    }

    /// A generator over the seed, built by `builder`. Its own source
    /// is deterministic too, so even a reseed does not part two runs.
    pub fn rng(
        &self,
        builder: &Builder,
    ) -> Result<CtrDrbg<FixedEntropy>, Error> {
        builder.try_build(|| {
            CtrDrbg::try_new_seeded(&self.0, FixedEntropy::default())
        })
    }
}

/// Where the drivers build the library's objects and run them: under
/// one feature profile, or under the set the processor offers, as a
/// program that never calls [`features::set`] would.
///
/// A type chooses its kernel from the set in force when it is built,
/// and keeps it whatever the set becomes, so a driver builds inside
/// [`build`](Self::build) and runs what it built outside, where
/// builds under another set need not wait for it. Some calls build as
/// they run, though: a GCM message over a cipher with no kernel of
/// GCM's own starts its own GHASH, a GCM-SIV message builds its own
/// cipher and POLYVAL, an ML-KEM key reads its matrix through SHAKE
/// streams chosen then, a signature, a KDF or a DRBG starts hashes or
/// MACs for every call, and the generator rekeys its cipher as it
/// draws. A driver makes such a call inside the builder too, and no
/// more than it.
///
/// The set in force is process-wide, so a builder takes a turn: it
/// waits while builds under another set are running, puts its own in
/// force if it is first, and the last build of a turn puts the set
/// detected back. Builds under the same set share the turn, so the
/// suites with no kernel of their own, whose signatures run for
/// minutes, run side by side, and with them every kernel the
/// processor's whole set selects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Builder(Option<Features>);

/// The set the running builds share, and how many there are.
struct Turn {
    set: Features,
    builds: usize,
}

static TURN: Mutex<Turn> = Mutex::new(Turn {
    set: Features::new(),
    builds: 0,
});

/// Signalled when a turn ends.
static ENDED: Condvar = Condvar::new();

impl Builder {
    /// A builder under `profile`, or the error [`features::set`]
    /// gives when the processor lacks some of it, which is found out
    /// here, once, rather than at every build.
    pub fn try_new(profile: Features) -> Result<Self, Error> {
        let builder = Builder(Some(profile));
        builder.build(|| ())?;
        Ok(builder)
    }

    /// The profile this builder puts in force, or `None` for the set
    /// detected.
    pub fn profile(&self) -> Option<Features> {
        self.0
    }

    /// The set in force while this builder builds.
    pub fn set(&self) -> Features {
        self.0.unwrap_or_else(features::detected)
    }

    /// Runs `build` with this builder's set in force.
    pub fn build<T>(&self, build: impl FnOnce() -> T) -> Result<T, Error> {
        let _turn = self.enter()?;
        Ok(build())
    }

    /// As [`build`](Self::build), for a build that may fail.
    pub fn try_build<T, E>(
        &self,
        build: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, Error>
    where
        Error: From<E>,
    {
        let _turn = self.enter()?;
        Ok(build()?)
    }

    /// Waits until this builder's set is in force or nothing is
    /// building, and joins the turn. A build that starts another
    /// under the same builder joins its own turn, so nesting is safe.
    fn enter(&self) -> Result<Building, Error> {
        let wanted = self.set();
        let mut turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
        while turn.builds > 0 && turn.set != wanted {
            turn = ENDED.wait(turn).unwrap_or_else(PoisonError::into_inner);
        }
        // Between turns the set detected is in force, which is what a
        // builder without a profile wants, so only a profile is set.
        if turn.builds == 0
            && let Some(profile) = self.0
        {
            features::set(profile)?;
        }
        turn.set = wanted;
        turn.builds += 1;
        Ok(Building)
    }
}

/// One build's share of a turn. Dropped however the build ends, so
/// that a panic does not leave the next turn a narrowed set.
struct Building;

impl Drop for Building {
    fn drop(&mut self) {
        let mut turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
        turn.builds -= 1;
        if turn.builds == 0 {
            features::reset();
            ENDED.notify_all();
        }
    }
}

/// The profiles every dispatching type tells apart, in walking order:
/// the set in force, the same isolated, each type's rows best first,
/// and the empty set.
pub(crate) fn candidates() -> Vec<Features> {
    let mut out = Vec::new();
    let mut push = |f: Features| {
        if !out.contains(&f) {
            out.push(f);
        }
    };
    let current = features::get();
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
        match Builder::try_new(profile) {
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
        let answered = Builder::try_new(profile).and_then(|builder| {
            let mut rng = seed.rng(&builder)?;
            (suite.answer)(doc, &mut rng, &builder)
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
        let builder = Builder::default();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        seed.rng(&builder).unwrap().fill(&mut x).unwrap();
        seed.rng(&builder).unwrap().fill(&mut y).unwrap();
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 32]);
    }
}
