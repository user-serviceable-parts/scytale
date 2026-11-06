//! The check against the vendored vectors: every suite in full, the
//! large-data groups and every SLH-DSA signature included, under
//! every kernel this processor can run, each once.
//!
//! A kernel is reached through the feature profiles the library's
//! types publish: setting a profile puts a feature set in force, and
//! a type takes the first of its profiles the set meets. A suite is
//! built from a few such types, so under a profile its implementation
//! is the tuple of rows those types take, and the suite is answered
//! under a profile only when that tuple is new. SHA-2 on x86-64 thus
//! runs twice, SHA-NI and portable, and not once per profile that
//! happens to differ elsewhere.
//!
//! The work is cut into units, a test group each, or a single case of
//! a large-data group or of SLH-DSA signing, since those cases are
//! minutes apiece under emulation. One worker per core takes the next
//! unit of the profile in force, heaviest first, and the profile
//! changes only between pools. `SCYTALE_SHARD` as `i/n` takes every
//! n-th unit, which is how CI spreads the run over as many jobs as it
//! needs.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use scytale::aead::{Ccm, Gcm, GcmSiv, Xpn};
use scytale::cipher::aes::Aes128;
use scytale::cipher::mode::{Cbc, Ctr, Xts};
use scytale::features::{self, Dispatcher, Feature, Features};
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{Sha256, Sha512};
use scytale::hash::sha3::Sha3_256;
use scytale::sig::{ecdsa, rsa};
use serde_json::Value;

use crate::profile::walk;
use crate::suite::{SUITES, Suite, compare, fixed_rng, vendored};
use crate::support::Error;

/// A public type the suites are built from: its name, for the
/// report, and its published profiles.
pub type Built = (&'static str, fn() -> &'static [Features]);

/// The public types `suite` is built from: the ones whose kernels its
/// answers run through. Naming a type the suite does not use costs a
/// run; missing one hides a kernel.
pub fn built_from(suite: &Suite) -> Result<Vec<Built>, Error> {
    let aes: Built = ("Aes128", Aes128::profiles);
    let sha1: Built = ("Sha1", Sha1::profiles);
    let sha256: Built = ("Sha256", Sha256::profiles);
    let sha512: Built = ("Sha512", Sha512::profiles);
    let sha3: Built = ("Sha3_256", Sha3_256::profiles);
    let hashes = [sha1, sha256, sha512, sha3];
    let curves: [Built; 3] = [
        ("P-256", <ecdsa::p256::PrivateKey as Dispatcher>::profiles),
        ("P-384", <ecdsa::p384::PrivateKey as Dispatcher>::profiles),
        ("P-521", <ecdsa::p521::PrivateKey as Dispatcher>::profiles),
    ];
    let rsa: Built = ("RSA", <rsa::PrivateKey as Dispatcher>::profiles);
    let a = suite.algorithm;
    let types = match a {
        "ACVP-AES-CBC" => {
            vec![aes, ("Cbc", <Cbc<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-CTR" => {
            vec![aes, ("Ctr", <Ctr<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-XTS" => {
            vec![aes, ("Xts", <Xts<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-GCM" | "ACVP-AES-GMAC" => {
            vec![aes, ("Gcm", <Gcm<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-XPN" => {
            vec![aes, ("Xpn", <Xpn<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-GCM-SIV" => {
            vec![aes, ("GcmSiv", <GcmSiv<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-CCM" => {
            vec![aes, ("Ccm", <Ccm<Aes128> as Dispatcher>::profiles)]
        }
        "CMAC-AES" | "ctrDRBG" => vec![aes],
        _ if a.starts_with("ACVP-AES-") => vec![aes],
        "SHA2-224" | "SHA2-256" | "HMAC-SHA2-224" | "HMAC-SHA2-256" => {
            vec![sha256]
        }
        "SHA2-384" | "SHA2-512" | "SHA2-512/224" | "SHA2-512/256"
        | "HMAC-SHA2-384" | "HMAC-SHA2-512" | "HMAC-SHA2-512/224"
        | "HMAC-SHA2-512/256" | "EDDSA" => vec![sha512],
        "HMAC-SHA-1" => vec![sha1],
        "ML-KEM" | "ML-DSA" => vec![sha3],
        _ if a.starts_with("SHA3-")
            || a.starts_with("SHAKE-")
            || a.starts_with("cSHAKE-")
            || a.starts_with("KMAC-")
            || a.starts_with("TupleHash-")
            || a.starts_with("HMAC-SHA3-") =>
        {
            vec![sha3]
        }
        // The one KDF registration covers both the KMAC-based and the
        // HMAC- and CMAC-based functions.
        "KDF" if suite.directory.starts_with("KDF-KMAC") => vec![sha3],
        "KDF" => [&hashes[..], &[aes]].concat(),
        "hashDRBG" | "hmacDRBG" | "PBKDF" | "KDA" | "kdf-components"
        | "TLS-v1.2" => hashes.to_vec(),
        "RSA" | "KTS-IFC" => [&[rsa][..], &hashes].concat(),
        "ECDSA" | "DetECDSA" => [&curves[..], &[sha256, sha512, sha3]].concat(),
        "SLH-DSA" => vec![sha256, sha512, sha3],
        // X25519 and X448 have no kernel to choose.
        "XECDH" => vec![],
        _ => {
            return Err(Error::new(format!(
                "{}: no types known for {a}",
                suite.directory
            )));
        }
    };
    Ok(types)
}

/// The row each of `types` takes under `profile`: the index of the
/// first published profile the set meets, which is how the library
/// chooses. Every list ends with the empty set, so there is always
/// one.
pub fn rows(types: &[Built], profile: Features) -> Vec<usize> {
    types
        .iter()
        .map(|(_, profiles)| {
            profiles()
                .iter()
                .position(|p| p.is_subset(profile))
                .expect("every list ends empty")
        })
        .collect()
}

/// The rows `types` took, each as the type's name and the feature set
/// of its row: what the report says a suite-profile pair ran under.
fn describe(types: &[Built], rows: &[usize]) -> String {
    let taken: Vec<String> = types
        .iter()
        .zip(rows)
        .map(|((name, profiles), &row)| format!("{name} {}", profiles()[row]))
        .collect();
    if taken.is_empty() {
        "no kernel to choose".into()
    } else {
        taken.join(", ")
    }
}

/// One piece of the run: a test group of a suite, or one case of it
/// where the group's cases are minutes apiece.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unit {
    pub suite: usize,
    pub group: usize,
    pub case: Option<usize>,
}

impl Unit {
    /// Whether this is one case cut from a long group.
    fn heavy(&self) -> bool {
        self.case.is_some()
    }
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
        let s = &SUITES[suite];
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
/// the answer with `doc`; returns the cases compared, or `None` for a
/// group the driver skipped.
pub fn answer_unit(
    suite: &Suite,
    doc: &Value,
    unit: &Unit,
) -> Result<Option<usize>, Error> {
    let mut group = doc["testGroups"][unit.group].clone();
    if let Some(case) = unit.case {
        let test = group["tests"][case].clone();
        group["tests"] = Value::Array(vec![test]);
    }
    let mut cut = doc.clone();
    cut["testGroups"] = Value::Array(vec![group]);
    let mut rng = fixed_rng();
    let answered = (suite.answer)(&cut, &mut rng)?;
    if answered["testGroups"].as_array().is_some_and(Vec::is_empty) {
        return Ok(None);
    }
    compare(suite, doc, &answered).map(Some)
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

/// What a run did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// Cases compared, every profile together.
    pub cases: usize,
    /// Cases compared under the detected profile: the count a whole
    /// run of every suite once gives, which the README quotes.
    pub detected: usize,
    /// Units this shard ran, of the units the run has.
    pub units: (usize, usize),
    /// Suite-profile pairs run, of the pairs there would be were every
    /// suite run under every profile.
    pub pairs: (usize, usize),
    pub shard: (usize, usize),
}

/// The run: see the module. Prints what it does to stdout. Fails on
/// any difference from the file, on a suite that answers fewer cases
/// than its minimum when the run is whole, and on a `SCYTALE_SHARD`
/// it cannot read.
///
/// # Panics
///
/// A worker that finds a difference panics with the profile, suite,
/// group and case, which the process reports as it ends.
pub fn run() -> Result<Report, Error> {
    let (index, shards) =
        shard(&std::env::var("SCYTALE_SHARD").unwrap_or_default())
            .map_err(|e| Error::new(format!("SCYTALE_SHARD: {e}")))?;
    let (profiles, refused) = walk();
    for p in &refused {
        println!("profile {p}: not on this processor, skipped");
    }
    let detected = features::detected();
    if profiles.first() != Some(&detected) {
        return Err(Error::new("the walk does not start where it is"));
    }
    // The empty set closes the walk, unless it opened it: a processor
    // with nothing written for it walks the empty set and then the
    // same isolated.
    let last = if detected.is_empty() {
        detected.with(Feature::Isolated)
    } else {
        Features::new()
    };
    if profiles.last() != Some(&last) {
        return Err(Error::new("the walk does not end portable"));
    }

    let docs: Vec<Option<Value>> = SUITES.iter().map(vendored).collect();
    let types: Vec<Vec<Built>> =
        SUITES.iter().map(built_from).collect::<Result<_, _>>()?;
    let all = units(&docs);

    // Which suites run under which profile: each only where the tuple
    // of kernels its types take is new.
    let mut seen: Vec<HashSet<Vec<usize>>> =
        SUITES.iter().map(|_| HashSet::new()).collect();
    let mut work: Vec<(usize, Unit)> = Vec::new();
    let mut pairs = 0;
    let mut possible = 0;
    for (p, &profile) in profiles.iter().enumerate() {
        for (s, suite) in SUITES.iter().enumerate() {
            if docs[s].is_none() {
                continue;
            }
            possible += 1;
            let kernels = rows(&types[s], profile);
            if !seen[s].insert(kernels.clone()) {
                continue;
            }
            pairs += 1;
            println!(
                "profile {profile}: {}: {}",
                suite.directory,
                describe(&types[s], &kernels)
            );
            work.extend(all.iter().filter(|u| u.suite == s).map(|u| (p, *u)));
        }
    }
    // The long units first, so no shard tails on one, and every n-th
    // of the whole to this shard.
    let (heavy, light): (Vec<_>, Vec<_>) =
        work.iter().partition(|(_, u)| u.heavy());
    let work: Vec<(usize, Unit)> = heavy.into_iter().chain(light).collect();
    let mine: Vec<(usize, Unit)> = work
        .iter()
        .enumerate()
        .filter(|(j, _)| j % shards == index - 1)
        .map(|(_, w)| *w)
        .collect();

    // WebAssembly has no threads: spawning one aborts the run.
    let workers = if cfg!(target_family = "wasm") {
        1
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    };
    let mut cases = 0;
    let mut detected_cases = 0;
    for (p, &profile) in profiles.iter().enumerate() {
        let list: Vec<Unit> = mine
            .iter()
            .filter(|(q, _)| *q == p)
            .map(|(_, u)| *u)
            .collect();
        if list.is_empty() {
            continue;
        }
        features::set(profile)?;
        let next = AtomicUsize::new(0);
        let counts: Vec<AtomicUsize> =
            SUITES.iter().map(|_| AtomicUsize::new(0)).collect();
        let skipped: Vec<AtomicUsize> =
            SUITES.iter().map(|_| AtomicUsize::new(0)).collect();
        let nanos: Vec<AtomicU64> =
            SUITES.iter().map(|_| AtomicU64::new(0)).collect();
        let work = || {
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(unit) = list.get(i) else {
                    break;
                };
                let started = Instant::now();
                let suite = &SUITES[unit.suite];
                let doc = docs[unit.suite].as_ref().expect("listed");
                let count = answer_unit(suite, doc, unit).unwrap_or_else(|e| {
                    panic!("profile {profile}: {}: {e}", suite.directory)
                });
                match count {
                    Some(n) => {
                        counts[unit.suite].fetch_add(n, Ordering::Relaxed);
                    }
                    None => {
                        skipped[unit.suite].fetch_add(1, Ordering::Relaxed);
                    }
                }
                nanos[unit.suite].fetch_add(
                    started.elapsed().as_nanos() as u64,
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
            let count = counts[s].load(Ordering::Relaxed);
            let left = skipped[s].load(Ordering::Relaxed);
            if count == 0 && left == 0 {
                continue;
            }
            let took = Duration::from_nanos(nanos[s].load(Ordering::Relaxed));
            let left = if left == 0 {
                String::new()
            } else {
                format!(", {left} groups skipped")
            };
            println!(
                "profile {profile}: {}: {count} cases in {:.1} s{left}",
                suite.directory,
                took.as_secs_f64()
            );
            // The minimum is a whole suite's, so only a whole run
            // under the detected profile can hold a suite to it.
            if p == 0 && shards == 1 && count < suite.minimum {
                return Err(Error::new(format!(
                    "{}: only {count} cases, expected at least {}",
                    suite.directory, suite.minimum
                )));
            }
            if p == 0 {
                detected_cases += count;
            }
            cases += count;
        }
    }
    let report = Report {
        cases,
        detected: detected_cases,
        units: (mine.len(), work.len()),
        pairs: (pairs, possible),
        shard: (index, shards),
    };
    println!(
        "detected profile: {} cases; total: {} cases in {} of {} units, \
         {} of {} suite-profile pairs, shard {}/{}",
        report.detected,
        report.cases,
        report.units.0,
        report.units.1,
        report.pairs.0,
        report.pairs.1,
        report.shard.0,
        report.shard.1
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::candidates;
    use serde_json::json;

    #[test]
    fn every_suite_is_built_from_listed_types() {
        let candidates = candidates();
        for suite in SUITES {
            let types = built_from(suite)
                .unwrap_or_else(|e| panic!("{}: {e}", suite.directory));
            for (_, profiles) in types {
                for p in profiles() {
                    // The walk is built from the same hand list of
                    // types, so a profile it does not reach is a type
                    // the list lacks.
                    assert!(
                        candidates.contains(p),
                        "{}: profile {p} is not walked",
                        suite.directory
                    );
                }
            }
        }
    }

    fn isolated_or_nothing() -> &'static [Features] {
        static P: [Features; 2] =
            [Features::of(&[Feature::Isolated]), Features::new()];
        &P
    }

    fn nothing() -> &'static [Features] {
        static P: [Features; 1] = [Features::new()];
        &P
    }

    #[test]
    fn rows_are_the_first_profile_the_set_meets() {
        let types: [Built; 2] = [("a", isolated_or_nothing), ("b", nothing)];
        let isolated = Features::of(&[Feature::Isolated]);
        assert_eq!(rows(&types, isolated), [0, 0]);
        assert_eq!(rows(&types, Features::new()), [1, 0]);
        assert_eq!(rows(&[], isolated), Vec::<usize>::new());
        assert_eq!(describe(&types, &[1, 0]), "a none, b none");
        assert_eq!(describe(&[], &[]), "no kernel to choose");
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
        // The units name a suite by registry index, so the first
        // document stands for whichever suite is first.
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
        assert!(got[2].heavy() && !got[0].heavy());
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
}
