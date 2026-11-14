//! The check against the vendored vectors: every suite in full, the
//! large-data groups and every SLH-DSA signature included, and every
//! kernel this processor can run answering the vectors that test it,
//! each exactly once.
//!
//! A kernel is reached through the feature profiles the library's
//! types publish: setting a profile puts a feature set in force, and
//! a type takes the first of its profiles the set meets. A vector
//! tests the kernels of one type: a hash suite the hash's, AES-ECB
//! the cipher's, a mode's suite the mode's, an ECDSA group its
//! curve's, the RSA suites RSA's. It is answered under a profile only
//! when that type takes a row there it has not yet taken, so SHA-2 on
//! x86-64 runs twice, SHA-NI and portable. A kernel that has passed
//! its own vectors is taken as good wherever else it is used: ECDSA
//! is not answered again for each hash kernel, and a suite with no
//! kernel of its own, HMAC or LMS or a KDF, is answered once.
//!
//! The work is cut into units, a test group each, or a single case of
//! a large-data group, of SLH-DSA signing or of LMS key generation,
//! since those cases are minutes apiece under emulation. One worker
//! per core takes the next unit of the profile in force, heaviest
//! first, and the profile changes only between pools. `SCYTALE_SHARD`
//! as `i/n` takes the i-th of n shares, equal by expected cost, which
//! is how CI spreads the run over as many jobs as it needs.

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

/// The public types whose kernels `suite`'s vectors test, and so
/// the ones it is answered again for: empty for a suite with no
/// kernel of its own, which is answered once. Naming a type here
/// costs a run under each of its kernels; missing one leaves a
/// kernel untested.
pub fn kernels_tested(suite: &Suite) -> Result<Vec<Built>, Error> {
    let a = suite.algorithm;
    let types: Vec<Built> = match a {
        "ACVP-AES-ECB" => vec![("Aes128", Aes128::profiles)],
        "ACVP-AES-CBC" => {
            vec![("Cbc", <Cbc<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-CTR" => {
            vec![("Ctr", <Ctr<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-XTS" => {
            vec![("Xts", <Xts<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-GCM" | "ACVP-AES-GMAC" => {
            vec![("Gcm", <Gcm<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-XPN" => {
            vec![("Xpn", <Xpn<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-GCM-SIV" => {
            vec![("GcmSiv", <GcmSiv<Aes128> as Dispatcher>::profiles)]
        }
        "ACVP-AES-CCM" => {
            vec![("Ccm", <Ccm<Aes128> as Dispatcher>::profiles)]
        }
        "SHA2-224" | "SHA2-256" => vec![("Sha256", Sha256::profiles)],
        "SHA2-384" | "SHA2-512" | "SHA2-512/224" | "SHA2-512/256" => {
            vec![("Sha512", Sha512::profiles)]
        }
        // SHA-1 has no suite of its own; its HMAC stands in.
        "HMAC-SHA-1" => vec![("Sha1", Sha1::profiles)],
        _ if a.starts_with("SHA3-") || a.starts_with("SHAKE-") => {
            vec![("Sha3_256", Sha3_256::profiles)]
        }
        // A group tests its own curve; see `tested`.
        "ECDSA" | "DetECDSA" => vec![
            ("P-256", <ecdsa::p256::PrivateKey as Dispatcher>::profiles),
            ("P-384", <ecdsa::p384::PrivateKey as Dispatcher>::profiles),
            ("P-521", <ecdsa::p521::PrivateKey as Dispatcher>::profiles),
        ],
        "RSA" | "KTS-IFC" => {
            vec![("RSA", <rsa::PrivateKey as Dispatcher>::profiles)]
        }
        // Built on kernels the suites above test, with none of their
        // own.
        "CMAC-AES" | "ctrDRBG" | "EDDSA" | "ML-KEM" | "ML-DSA" | "KDF"
        | "hashDRBG" | "hmacDRBG" | "PBKDF" | "KDA" | "kdf-components"
        | "TLS-v1.2" | "SLH-DSA" | "LMS" | "XECDH" => vec![],
        _ if a.starts_with("ACVP-AES-")
            || a.starts_with("HMAC-SHA2-")
            || a.starts_with("HMAC-SHA3-")
            || a.starts_with("cSHAKE-")
            || a.starts_with("KMAC-")
            || a.starts_with("TupleHash-") =>
        {
            vec![]
        }
        _ => {
            return Err(Error::new(format!(
                "{}: no types known for {a}",
                suite.directory
            )));
        }
    };
    Ok(types)
}

/// Which of `types`, the suite's from [`kernels_tested`], `group`
/// tests: its curve's for ECDSA, the suite's one type otherwise, and
/// none for a suite without one or a curve the library lacks.
fn tested(types: &[Built], group: &Value) -> Option<usize> {
    match types {
        [] => None,
        [_] => Some(0),
        _ => {
            let curve = group["curve"].as_str()?;
            types.iter().position(|(name, _)| *name == curve)
        }
    }
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

/// The rows of `types` that `fresh` marks, each as the type's name
/// and the feature set of its row: the kernels a suite is answered
/// for under a profile.
fn describe(types: &[Built], rows: &[usize], fresh: &[bool]) -> String {
    let taken: Vec<String> = types
        .iter()
        .zip(rows)
        .zip(fresh)
        .filter(|(_, fresh)| **fresh)
        .map(|(((name, profiles), &row), _)| {
            format!("{name} {}", profiles()[row])
        })
        .collect();
    if taken.is_empty() {
        "no kernel of its own".into()
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
    /// What the unit is expected to cost, in ordinary cases' worth;
    /// see `weight` below. It steers the split over shards and the order
    /// within one, and nothing else, so an estimate off by some
    /// factor costs balance, never coverage.
    pub weight: u64,
}

/// The expected cost of a unit, in the worth of an ordinary case.
/// An ordinary group weighs its cases. A large-data case hashes
/// `fullLength` bits, and one of 2^36 measured as some eight
/// thousand ordinary cases, so a case weighs its bits over 2^23. An
/// SLH-DSA signature is dominated by the WOTS+ public keys of the
/// hypertree, `d` layers of 2^(h/d) leaves each of `len` chains of
/// fifteen hashes, plus the FORS tree, `k` trees of 2^a leaves; ten
/// thousand of those hashes measured as one ordinary case.
///
/// LMS is weighed by [`lms_weight`], where the units are made.
fn weight(group: &Value, case: Option<&Value>, cases: usize) -> u64 {
    let Some(case) = case else {
        return cases as u64;
    };
    if let Some(bits) = case["largeMsg"]["fullLength"].as_u64() {
        return (bits >> 23).max(1);
    }
    let set = group["parameterSet"].as_str().unwrap_or("");
    // FIPS 205 table 2: h, d, len, k, a, for each security level and
    // speed; len is 2n + 3 at w = 16.
    let (h, d, len, k, a): (u32, u64, u64, u64, u32) =
        match set.get(set.len().saturating_sub(4)..) {
            Some("128s") => (63, 7, 35, 14, 12),
            Some("128f") => (66, 22, 35, 33, 6),
            Some("192s") => (63, 7, 51, 17, 14),
            Some("192f") => (66, 22, 51, 33, 8),
            Some("256s") => (64, 8, 67, 22, 14),
            Some("256f") => (68, 17, 67, 35, 9),
            _ => return 120,
        };
    let hashes = d * (1 << (h / d as u32)) * len * 15 + k * (1 << a);
    (hashes / 10_000).max(1)
}

/// The height of an LMS group's tree and the hashes one of its
/// leaves costs: an LM-OTS public key is `p` chains of `2^w - 1`
/// hashes, `p` from RFC 8554 table 1 and SP 800-208 for the hash
/// width `n` and the Winternitz width `w`. `None` for a group whose
/// names are not of that form.
fn lms_leaf(group: &Value) -> Option<(u32, u64)> {
    let h: u32 = group["lmsMode"]
        .as_str()?
        .rsplit_once("_H")?
        .1
        .parse()
        .ok()?;
    let (ots, w) = group["lmOtsMode"].as_str()?.rsplit_once("_W")?;
    let wide = ots.ends_with("_N32");
    let (p, chain): (u64, u64) = match (w, wide) {
        ("1", true) => (265, 1),
        ("2", true) => (133, 3),
        ("4", true) => (67, 15),
        ("8", true) => (34, 255),
        ("1", false) => (200, 1),
        ("2", false) => (101, 3),
        ("4", false) => (51, 15),
        ("8", false) => (26, 255),
        _ => return None,
    };
    (h < 40).then_some((h, p * chain))
}

/// The expected cost of an LMS unit that computes `leaves(h)` leaves
/// of a tree of height `h`, on the scale of [`weight`]: key
/// generation computes all `2^h`, and a signature about `h/2` more.
fn lms_weight(group: &Value, leaves: impl Fn(u32) -> u64) -> Option<u64> {
    let (h, hashes) = lms_leaf(group)?;
    Some((leaves(h) * hashes / 10_000).max(1))
}

/// Every unit of `docs`, which are the suites' vendored documents in
/// registry order, in a fixed order: a unit per group, except that the
/// large-data groups, SLH-DSA signing and LMS key generation give a
/// unit per case. An LMS signing group stays whole, since its cases
/// share the one key the group generates.
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
        let lms = |mode| s.algorithm == "LMS" && s.mode == Some(mode);
        for (group, g) in groups.iter().enumerate() {
            let cases = g["tests"].as_array().map_or(0, Vec::len);
            let tree =
                lms("keyGen").then(|| lms_weight(g, |h| 1 << h)).flatten();
            if let Some(weight) = tree.filter(|_| cases > 0) {
                out.extend((0..cases).map(|case| Unit {
                    suite,
                    group,
                    case: Some(case),
                    weight,
                }));
            } else if (g["testType"] == "LDT" || signing) && cases > 0 {
                for case in 0..cases {
                    out.push(Unit {
                        suite,
                        group,
                        case: Some(case),
                        weight: weight(g, Some(&g["tests"][case]), cases),
                    });
                }
            } else {
                let signed = cases as u64;
                let whole = lms("sigGen")
                    .then(|| {
                        lms_weight(g, |h| {
                            (1 << h) + signed * u64::from(h / 2 + 2)
                        })
                    })
                    .flatten();
                out.push(Unit {
                    suite,
                    group,
                    case: None,
                    weight: whole.unwrap_or_else(|| weight(g, None, cases)),
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

/// The work of a whole run: each unit paired with the index of every
/// profile it is answered under, in walking order, and the count of
/// suite-profile pairs that have any. A unit that tests a type's
/// kernels is answered under each profile where that type takes a
/// row it has not yet taken, so once per kernel; a unit that tests
/// none is answered under the first profile only. `types` is each
/// suite's from [`kernels_tested`]. Prints what each pair is run for.
fn plan(
    profiles: &[Features],
    docs: &[Option<Value>],
    types: &[Vec<Built>],
    all: &[Unit],
) -> (Vec<(usize, Unit)>, usize) {
    let mut seen: Vec<Vec<HashSet<usize>>> = types
        .iter()
        .map(|t| t.iter().map(|_| HashSet::new()).collect())
        .collect();
    let mut work: Vec<(usize, Unit)> = Vec::new();
    let mut pairs = 0;
    for (p, &profile) in profiles.iter().enumerate() {
        for (s, suite) in SUITES.iter().enumerate() {
            let Some(doc) = &docs[s] else {
                continue;
            };
            let taken = rows(&types[s], profile);
            let fresh: Vec<bool> = taken
                .iter()
                .enumerate()
                .map(|(t, &row)| seen[s][t].insert(row))
                .collect();
            let before = work.len();
            for unit in all.iter().filter(|u| u.suite == s) {
                let group = &doc["testGroups"][unit.group];
                let due = match tested(&types[s], group) {
                    Some(t) => fresh[t],
                    None => p == 0,
                };
                if due {
                    work.push((p, *unit));
                }
            }
            if work.len() > before {
                pairs += 1;
                println!(
                    "profile {profile}: {}: {}",
                    suite.directory,
                    describe(&types[s], &taken, &fresh)
                );
            }
        }
    }
    (work, pairs)
}

/// Splits `work` over `shards` and returns shard `index`'s part,
/// heaviest first, with every shard's weight: the heaviest unit left
/// goes to the lightest shard, which keeps the shards within one
/// unit's weight of each other. Deterministic, since every shard
/// computes the split for itself.
fn split(
    work: &[(usize, Unit)],
    shards: usize,
    index: usize,
) -> (Vec<(usize, Unit)>, Vec<u64>) {
    let mut order: Vec<usize> = (0..work.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(work[i].1.weight));
    let mut loads = vec![0u64; shards];
    let mut mine = Vec::new();
    for i in order {
        let lightest = (0..shards)
            .min_by_key(|&s| loads[s])
            .expect("at least one shard");
        loads[lightest] += work[i].1.weight;
        if lightest == index - 1 {
            mine.push(work[i]);
        }
    }
    (mine, loads)
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
    /// Suite-profile pairs with anything to run, of the pairs there
    /// would be were every suite run under every profile.
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
    let types: Vec<Vec<Built>> = SUITES
        .iter()
        .map(kernels_tested)
        .collect::<Result<_, _>>()?;
    let all = units(&docs);
    let possible = profiles.len() * docs.iter().flatten().count();
    let (work, pairs) = plan(&profiles, &docs, &types, &all);
    let (mine, loads) = split(&work, shards, index);
    println!(
        "shard {index}/{shards}: weight {} of {}",
        loads[index - 1],
        loads.iter().sum::<u64>()
    );

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
    fn every_tested_type_is_walked() {
        let candidates = candidates();
        for suite in SUITES {
            let types = kernels_tested(suite)
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
        let both = [true, true];
        assert_eq!(describe(&types, &[1, 0], &both), "a none, b none");
        assert_eq!(describe(&types, &[1, 0], &[false, true]), "b none");
        assert_eq!(describe(&types, &[1, 0], &[false; 2]), NONE);
        assert_eq!(describe(&[], &[], &[]), NONE);
    }

    const NONE: &str = "no kernel of its own";

    /// The registry index of the suite of `algorithm` and `mode`.
    fn suite_of(algorithm: &str, mode: Option<&str>) -> usize {
        SUITES
            .iter()
            .position(|s| s.algorithm == algorithm && s.mode == mode)
            .expect("registered")
    }

    #[test]
    fn a_group_tests_its_curve_and_other_suites_their_one_type() {
        let types = |a, m| kernels_tested(&SUITES[suite_of(a, m)]).unwrap();
        let curves = types("ECDSA", Some("sigGen"));
        let on = |curve: &str| tested(&curves, &json!({"curve": curve}));
        assert_eq!(on("P-256"), Some(0));
        assert_eq!(on("P-384"), Some(1));
        assert_eq!(on("P-521"), Some(2));
        assert_eq!(on("P-224"), None);
        assert_eq!(tested(&curves, &json!({})), None);
        assert_eq!(tested(&types("SHA2-256", None), &json!({})), Some(0));
        assert_eq!(tested(&types("LMS", Some("keyGen")), &json!({})), None);
    }

    #[test]
    fn each_unit_is_planned_once_per_kernel_it_tests() {
        let ecdsa = suite_of("ECDSA", Some("sigGen"));
        let sha = suite_of("SHA2-256", None);
        let lms = suite_of("LMS", Some("sigVer"));
        let mut docs: Vec<Option<Value>> =
            SUITES.iter().map(|_| None).collect();
        let group = |curve: &str| json!({"curve": curve, "tests": [{}]});
        docs[ecdsa] = Some(json!({"testGroups": [
            group("P-256"), group("P-384"), group("P-224"), group("P-521"),
        ]}));
        docs[sha] = Some(json!({"testGroups": [{"tests": [{}, {}]}]}));
        docs[lms] = Some(json!({"testGroups": [{"tests": [{}]}]}));
        let types: Vec<Vec<Built>> =
            SUITES.iter().map(|s| kernels_tested(s).unwrap()).collect();
        let profiles = candidates();
        let all = units(&docs);
        assert_eq!(all.len(), 6);
        let (work, pairs) = plan(&profiles, &docs, &types, &all);
        assert!(pairs >= 3);
        for unit in &all {
            let under: Vec<usize> = work
                .iter()
                .filter(|(_, u)| u == unit)
                .map(|(p, _)| *p)
                .collect();
            let doc = docs[unit.suite].as_ref().unwrap();
            let group = &doc["testGroups"][unit.group];
            let Some(t) = tested(&types[unit.suite], group) else {
                assert_eq!(under, [0], "{unit:?}");
                continue;
            };
            // The rows the type takes where the unit is answered:
            // no row twice, and every row any profile reaches.
            let row = |p: usize| rows(&types[unit.suite], profiles[p])[t];
            let answered: Vec<usize> = under.iter().map(|&p| row(p)).collect();
            let unique: HashSet<usize> = answered.iter().copied().collect();
            assert_eq!(unique.len(), answered.len(), "{unit:?}");
            let reached: HashSet<usize> =
                (0..profiles.len()).map(row).collect();
            assert_eq!(unique, reached, "{unit:?}");
        }
    }

    #[test]
    fn lms_units_weigh_their_trees() {
        let set = |lms: &str, ots: &str, cases: usize| {
            json!({
                "lmsMode": lms,
                "lmOtsMode": ots,
                "tests": vec![json!({}); cases],
            })
        };
        let small = set("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2", 10);
        assert_eq!(lms_leaf(&small), Some((10, 303)));
        let tall = set("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W8", 3);
        assert_eq!(lms_leaf(&tall), Some((15, 34 * 255)));
        assert_eq!(lms_leaf(&json!({"lmsMode": "LMS_SHA256_M24"})), None);

        let mut docs: Vec<Option<Value>> =
            SUITES.iter().map(|_| None).collect();
        let key_gen = suite_of("LMS", Some("keyGen"));
        let sig_gen = suite_of("LMS", Some("sigGen"));
        let sig_ver = suite_of("LMS", Some("sigVer"));
        for s in [key_gen, sig_gen, sig_ver] {
            docs[s] = Some(json!({"testGroups": [small.clone()]}));
        }
        let got = units(&docs);
        let of = |s| got.iter().filter(move |u| u.suite == s);
        // A tree of 1024 leaves of 303 hashes, a case each.
        assert_eq!(of(key_gen).count(), 10);
        assert!(of(key_gen).all(|u| u.case.is_some() && u.weight == 31));
        // The group whole: its tree and ten signatures of 7 leaves.
        let whole: Vec<_> = of(sig_gen).collect();
        assert_eq!(whole.len(), 1);
        assert_eq!((whole[0].case, whole[0].weight), (None, 33));
        // Verifying is an ordinary case.
        let verified: Vec<_> = of(sig_ver).collect();
        assert_eq!((verified[0].case, verified[0].weight), (None, 10));
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
            {"tgId": 3, "testType": "LDT", "tests": [
                {"tcId": 4, "largeMsg": {"fullLength": 1u64 << 23}},
                {"tcId": 5, "largeMsg": {"fullLength": 1u64 << 24}}]},
        ]});
        let docs = [Some(doc), None];
        let got = units(&docs);
        let unit = |group, case, weight| Unit {
            suite: 0,
            group,
            case,
            weight,
        };
        assert_eq!(
            got,
            [
                unit(0, None, 2),
                unit(1, None, 1),
                unit(2, Some(0), 1),
                unit(2, Some(1), 2)
            ]
        );
    }

    #[test]
    fn weights_follow_length_and_parameter_set() {
        let ldt = json!({"largeMsg": {"fullLength": 1u64 << 36}});
        assert_eq!(weight(&json!({}), Some(&ldt), 4), 1 << 13);
        let set = |name| json!({"parameterSet": name});
        let w = |name| weight(&set(name), Some(&json!({})), 7);
        assert!(w("SLH-DSA-SHA2-128s") > 10 * w("SLH-DSA-SHA2-128f"));
        assert!(w("SLH-DSA-SHAKE-192s") > w("SLH-DSA-SHAKE-128s"));
        // 7 * 512 * 35 * 15 + 14 * 4096 hashes.
        assert_eq!(w("SLH-DSA-SHA2-128s"), 193);
        assert_eq!(weight(&json!({}), None, 914), 914);
    }

    #[test]
    fn split_sends_the_heaviest_unit_to_the_lightest_shard() {
        let work: Vec<(usize, Unit)> = [8, 7, 6, 5, 4, 3]
            .into_iter()
            .enumerate()
            .map(|(group, weight)| {
                (
                    0,
                    Unit {
                        suite: 0,
                        group,
                        case: None,
                        weight,
                    },
                )
            })
            .collect();
        let (first, loads) = split(&work, 2, 1);
        let (second, _) = split(&work, 2, 2);
        assert_eq!(loads, [17, 16]);
        let groups = |v: &[(usize, Unit)]| {
            v.iter().map(|(_, u)| u.group).collect::<Vec<_>>()
        };
        assert_eq!(groups(&first), [0, 3, 4]);
        assert_eq!(groups(&second), [1, 2, 5]);
        let (all, loads) = split(&work, 1, 1);
        assert_eq!(all.len(), 6);
        assert_eq!(loads, [33]);
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
