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

use crate::suite::Suite;
use crate::support::{Error, FixedEntropy};
use scytale::Random;
use scytale::aead::{Ccm, Gcm, GcmSiv};
use scytale::cipher::aes::{Aes128, Aes192, Aes256};
use scytale::cipher::chacha20::ChaCha20;
use scytale::cipher::mode::{Cbc, Ctr, Xts};
use scytale::features::{self, Dispatcher, Feature, Features};
use scytale::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use scytale::hash::sha3::{
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
};
use scytale::random::{CtrDrbg, MIN_SEED};
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
        scytale::random::CtrDrbg::from_system()?.fill(&mut seed.0)?;
        Ok(seed)
    }

    /// A generator over the seed. Its own source is deterministic
    /// too, so even a reseed does not part two runs.
    pub fn rng(&self) -> Result<CtrDrbg<FixedEntropy>, Error> {
        Ok(CtrDrbg::try_new_seeded(&self.0, FixedEntropy::default())?)
    }
}

/// The profiles every dispatching type tells apart, in walking order:
/// the set in force, the same isolated, each type's rows best first,
/// and the empty set.
fn candidates() -> Vec<Features> {
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
        match features::set(profile) {
            Ok(()) => runnable.push(profile),
            Err(_) => refused.push(profile),
        }
    }
    features::reset();
    (runnable, refused)
}

/// Answers `doc` under each of `profiles` from the same seed and
/// returns the answer, or the first difference as an error with exit
/// status 2 naming both profiles and the case.
///
/// Process-wide: the set in force changes while this runs, and is
/// put back after.
pub fn answer_under(
    suite: &Suite,
    doc: &Value,
    seed: &Seed,
    profiles: &[Features],
) -> Result<Value, Error> {
    let mut first: Option<(Features, Value)> = None;
    for &profile in profiles {
        features::set(profile)?;
        let answered =
            seed.rng().and_then(|mut rng| (suite.answer)(doc, &mut rng));
        features::reset();
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
    use crate::suite::{SUITES, vendored};
    use serde_json::json;

    /// The tests that edit the process-wide set of features in
    /// force. Another test building a cipher while the set changes
    /// under it can see its mode and cipher disagree, so these are
    /// ignored by default and run alone, single-threaded; see
    /// `cargo test-every-profile`.
    mod alone {
        use super::*;

        /// Every symmetric suite answered under every profile this
        /// processor can run but the detected one, each answer compared
        /// with the file: the check that each kernel is right. The
        /// detected profile is what the ordinary run of every suite
        /// answered under, so it is not run again here. Process-wide, so
        /// it runs alone (`cargo test-alone`), and ignored by default for
        /// its length. The large-data groups are left out: each hashes
        /// gigabytes, which checks length handling the one-shot groups
        /// already cover, not the kernel.
        #[test]
        #[ignore]
        fn every_profile() {
            let (profiles, refused) = walk();
            for p in refused {
                eprintln!("profile {p}: not on this processor, skipped");
            }
            assert_eq!(profiles.first(), Some(&features::detected()));
            let profiles = &profiles[1..];
            let symmetric = |s: &&Suite| {
                let a = s.algorithm;
                a.starts_with("ACVP-AES")
                    || a.starts_with("SHA")
                    || a.starts_with("cSHAKE")
                    || a.starts_with("KMAC")
                    || a.starts_with("TupleHash")
                    || a.starts_with("HMAC")
                    || a.starts_with("CMAC")
                    || a.ends_with("DRBG")
                    || a == "PBKDF"
                    || a == "KDF"
            };
            let mut suites = 0;
            for suite in SUITES.iter().filter(symmetric) {
                let Some(mut doc) = vendored(suite) else {
                    continue;
                };
                if let Some(groups) = doc["testGroups"].as_array_mut() {
                    groups.retain(|g| g["testType"] != "LDT");
                }
                let answered =
                    answer_under(suite, &doc, &Seed::fixed(), profiles)
                        .unwrap_or_else(|e| panic!("{}: {e}", suite.directory));
                crate::suite::compare(suite, &doc, &answered)
                    .unwrap_or_else(|e| panic!("{}: {e}", suite.directory));
                suites += 1;
            }
            assert!(suites == 0 || suites >= 50, "only {suites} suites");
        }

        #[test]
        #[ignore]
        fn walk_starts_detected_and_ends_portable() {
            let (runnable, _) = walk();
            let detected = features::detected();
            let portable = Features::new();
            assert_eq!(runnable.first(), Some(&detected));
            // The empty set closes the walk, unless it opened it: a
            // processor with nothing written for it walks the empty set
            // and then the same isolated.
            let last = if detected == portable {
                portable.with(Feature::Isolated)
            } else {
                portable
            };
            assert_eq!(runnable.last(), Some(&last));
            assert_eq!(features::get(), detected);
        }
    }

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
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        seed.rng().unwrap().fill(&mut x).unwrap();
        seed.rng().unwrap().fill(&mut y).unwrap();
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 32]);
    }
}
