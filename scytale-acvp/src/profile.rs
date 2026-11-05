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

/// One piece of the full run: a test group of a suite, or one case of
/// it where the group's cases are minutes apiece.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unit {
    pub suite: usize,
    pub group: usize,
    pub case: Option<usize>,
}

/// Every unit of `docs`, which are the suites' vendored documents in
/// registry order, in a fixed order: a unit per group, except that the
/// large-data groups and SLH-DSA signing give a unit per case.
pub fn units(docs: &[Option<Value>]) -> Vec<Unit> {
    let mut out = Vec::new();
    for (suite, doc) in docs.iter().enumerate() {
        let Some(groups) =
            doc.as_ref().and_then(|d| d["testGroups"].as_array())
        else {
            continue;
        };
        let s = &crate::suite::SUITES[suite];
        let signing = s.algorithm == "SLH-DSA" && s.mode == Some("sigGen");
        for (group, g) in groups.iter().enumerate() {
            let cases = g["tests"].as_array().map_or(0, Vec::len);
            if (g["testType"] == "LDT" || signing) && cases > 0 {
                for case in 0..cases {
                    out.push(Unit {
                        suite,
                        group,
                        case: Some(case),
                    });
                }
            } else {
                out.push(Unit {
                    suite,
                    group,
                    case: None,
                });
            }
        }
    }
    out
}

/// Answers `unit` of `doc` with a fresh fixed generator and compares
/// the answer with `doc`; returns the cases compared.
pub fn answer_unit(
    suite: &Suite,
    doc: &Value,
    unit: &Unit,
) -> Result<usize, Error> {
    let mut group = doc["testGroups"][unit.group].clone();
    if let Some(case) = unit.case {
        let test = group["tests"][case].clone();
        group["tests"] = Value::Array(vec![test]);
    }
    let mut cut = doc.clone();
    cut["testGroups"] = Value::Array(vec![group]);
    let mut rng = crate::suite::fixed_rng();
    let answered = (suite.answer)(&cut, &mut rng)?;
    crate::suite::compare(suite, doc, &answered)
}

/// `SCYTALE_SHARD` parsed: `i/n` gives shard `i` of `n`, one-based;
/// empty is the whole, `1/1`.
pub fn shard(spec: &str) -> Result<(usize, usize), Error> {
    if spec.is_empty() {
        return Ok((1, 1));
    }
    let bad = || Error::new(format!("{spec}: want i/n with 1 <= i <= n"));
    let (i, n) = spec.split_once('/').ok_or_else(bad)?;
    let i: usize = i.parse().map_err(|_| bad())?;
    let n: usize = n.parse().map_err(|_| bad())?;
    if i == 0 || n == 0 || i > n {
        return Err(bad());
    }
    Ok((i, n))
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

        /// Every suite in full, the large-data groups and every
        /// SLH-DSA signature included, under every profile this
        /// processor can run, each answer compared with the file:
        /// the check that each kernel is right, and the figure the
        /// README quotes. Process-wide, so it runs alone (`cargo
        /// test-every-profile`), and ignored by default for its
        /// length.
        ///
        /// The work is cut into units, a test group each, or a single
        /// case of a large-data group or of SLH-DSA signing, since
        /// those cases are minutes apiece. One worker per core takes
        /// the next unit of the profile in force, and the profile
        /// changes only between pools. `SCYTALE_SHARD` as `i/n` takes
        /// every n-th unit across every profile, which is how CI
        /// spreads the run over as many jobs as it needs.
        #[test]
        #[ignore]
        fn every_profile() {
            use std::sync::atomic::{AtomicUsize, Ordering};
            use std::time::{Duration, Instant};

            let (profiles, refused) = walk();
            for p in refused {
                eprintln!("profile {p}: not on this processor, skipped");
            }
            assert_eq!(profiles.first(), Some(&features::detected()));
            let (index, shards) =
                shard(&std::env::var("SCYTALE_SHARD").unwrap_or_default())
                    .unwrap_or_else(|e| panic!("SCYTALE_SHARD: {e}"));

            let docs: Vec<Option<Value>> =
                SUITES.iter().map(vendored).collect();
            let units = units(&docs);
            let mine = |profile: usize, unit: usize| {
                (profile * units.len() + unit) % shards == index - 1
            };

            let mut total = 0;
            let mut ran = 0;
            let mut detected = 0;
            let workers = if cfg!(target_family = "wasm") {
                1
            } else {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            };
            for (p, &profile) in profiles.iter().enumerate() {
                features::set(profile).expect("walk said runnable");
                let next = AtomicUsize::new(0);
                let cases: Vec<AtomicUsize> =
                    SUITES.iter().map(|_| AtomicUsize::new(0)).collect();
                let nanos: Vec<AtomicUsize> =
                    SUITES.iter().map(|_| AtomicUsize::new(0)).collect();
                let work = || {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(unit) = units.get(i) else {
                            break;
                        };
                        if !mine(p, i) {
                            continue;
                        }
                        let started = Instant::now();
                        let suite = &SUITES[unit.suite];
                        let doc = docs[unit.suite].as_ref().expect("unit");
                        let count = answer_unit(suite, doc, unit)
                            .unwrap_or_else(|e| {
                                panic!(
                                    "profile {profile}: {}: {e}",
                                    suite.directory
                                )
                            });
                        cases[unit.suite].fetch_add(count, Ordering::Relaxed);
                        nanos[unit.suite].fetch_add(
                            started.elapsed().as_nanos() as usize,
                            Ordering::Relaxed,
                        );
                    }
                };
                if workers == 1 {
                    work();
                } else {
                    std::thread::scope(|scope| {
                        for _ in 0..workers {
                            scope.spawn(work);
                        }
                    });
                }
                features::reset();
                for (s, suite) in SUITES.iter().enumerate() {
                    let count = cases[s].load(Ordering::Relaxed);
                    let took = Duration::from_nanos(
                        nanos[s].load(Ordering::Relaxed) as u64,
                    );
                    if count > 0 {
                        eprintln!(
                            "profile {profile}: {}: {count} cases in {:.1} s",
                            suite.directory,
                            took.as_secs_f64()
                        );
                    }
                    // The minimum is a whole suite's, so only a whole
                    // run under the detected profile can hold a suite
                    // to it. A shard prints its share instead.
                    if p == 0 && shards == 1 && docs[s].is_some() {
                        assert!(
                            count >= suite.minimum,
                            "{}: only {count} cases, expected at least {}",
                            suite.directory,
                            suite.minimum
                        );
                    }
                    if p == 0 {
                        detected += count;
                    }
                    total += count;
                }
                ran += (0..units.len()).filter(|&i| mine(p, i)).count();
            }
            eprintln!(
                "detected profile: {detected} cases; total: {total} cases \
                 in {ran} of {} units under {} profiles, \
                 shard {index}/{shards}",
                units.len() * profiles.len(),
                profiles.len()
            );
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
    fn shard_parses_i_of_n() {
        assert_eq!(shard("").unwrap(), (1, 1));
        assert_eq!(shard("3/8").unwrap(), (3, 8));
        assert_eq!(shard("8/8").unwrap(), (8, 8));
        for bad in ["0/8", "9/8", "x", "3", "3/", "/8", "3/0"] {
            assert!(shard(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn units_split_large_data_by_case_and_keep_other_groups() {
        // Registry order: a plain suite first; the units name it by
        // index, so the first document stands for whichever suite
        // that is.
        let doc = json!({"testGroups": [
            {"tgId": 1, "testType": "AFT", "tests": [{"tcId": 1}, {"tcId": 2}]},
            {"tgId": 2, "testType": "MCT", "tests": [{"tcId": 3}]},
            {"tgId": 3, "testType": "LDT", "tests": [{"tcId": 4}, {"tcId": 5}]},
        ]});
        let docs = [Some(doc), None];
        let got = units(&docs);
        let unit = |group, case| Unit {
            suite: 0,
            group,
            case,
        };
        assert_eq!(
            got,
            [
                unit(0, None),
                unit(1, None),
                unit(2, Some(0)),
                unit(2, Some(1))
            ]
        );
    }

    #[test]
    fn units_split_slh_dsa_signing_by_case() {
        let signing = SUITES
            .iter()
            .position(|s| s.algorithm == "SLH-DSA" && s.mode == Some("sigGen"))
            .expect("registered");
        let mut docs: Vec<Option<Value>> =
            SUITES.iter().map(|_| None).collect();
        docs[signing] = Some(json!({"testGroups": [
            {"tgId": 1, "testType": "AFT", "tests": [{"tcId": 1}, {"tcId": 2}]},
        ]}));
        let got = units(&docs);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|u| u.suite == signing && u.case.is_some()));
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
