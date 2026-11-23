//! The check against the vendored vectors: every suite in full, the
//! large-data groups and every SLH-DSA signature included, and every
//! kernel this processor can run answering the vectors that test it,
//! each exactly once. Each suite is a test of its own, which `cargo
//! test` runs as the library runs its kernel lists: a line for every
//! kernel, run, not run for the features the processor lacks, or not
//! selected by `SCYTALE_KERNELS`.
//!
//! A kernel is reached through the feature profiles the library's
//! types publish: setting a profile puts a feature set in force, and
//! a type takes the first of its profiles the set meets. A vector
//! tests the kernels of one type: a hash suite the hash's, AES-ECB
//! the cipher's, a mode's suite the mode's, an ECDSA group its
//! curve's, the RSA suites RSA's. It is answered under each profile
//! that type publishes, so SHA-2 on x86-64 runs twice, SHA-NI and
//! portable. A kernel that has passed its own vectors is taken as
//! good wherever else it is used: ECDSA is not answered again for
//! each hash kernel, and a suite with no kernel of its own, HMAC or
//! LMS or a KDF, is answered once, under the features detected.
//!
//! The work is cut into units, a test group each, or a single case of
//! a large-data group, of SLH-DSA signing or of LMS key generation,
//! since those cases are minutes apiece under emulation. A unit is
//! answered under each kernel that tests it, and the units of every
//! kernel of the suite go to one pool: one worker per core takes the
//! next, heaviest first, and answers it through its kernel's
//! [`Builder`], so that kernels and suites run side by side and only
//! wait for one another while something is being built or run under
//! another set; see there.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use scytale::Random;
use scytale::aead::{Ccm, Gcm, GcmSiv, Xpn};
use scytale::cipher::aes::Aes128;
use scytale::cipher::mode::{Cbc, Ctr, Xts};
use scytale::features::{self, Dispatcher, Feature, Features};
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{Sha256, Sha512};
use scytale::hash::sha3::Sha3_256;
use scytale::kem::ml_kem::ml_kem_768;
use scytale::sig::{ecdsa, rsa};
use serde_json::Value;

use crate::profile::Builder;
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
        // CMAC's chaining loops are the CBC kernels' own, chosen by
        // the same rows, and no other suite runs them.
        "ACVP-AES-CBC" | "CMAC-AES" => {
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
        // The matrix is read from SHAKE-128 streams run several
        // together or apart, which no hash suite reaches: the rows
        // are every parameter set's alike.
        "ML-KEM" => {
            vec![("ML-KEM", <ml_kem_768::PrivateKey as Dispatcher>::profiles)]
        }
        // Built on kernels the suites above test, with none of their
        // own.
        "ctrDRBG" | "EDDSA" | "ML-DSA" | "KDF" | "hashDRBG" | "hmacDRBG"
        | "PBKDF" | "KDA" | "kdf-components" | "TLS-v1.2" | "SLH-DSA"
        | "LMS" | "XECDH" => vec![],
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

/// One piece of the run: a test group of a suite, or one case of it
/// where the group's cases are minutes apiece.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unit {
    pub suite: usize,
    pub group: usize,
    pub case: Option<usize>,
    /// What the unit is expected to cost, in ordinary cases' worth;
    /// see `weight` below. It steers the order the workers take the
    /// units in, and nothing else, so an estimate off by some factor
    /// costs time, never coverage.
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

/// Every unit of `doc`, the vendored document of suite `suite` in
/// the registry, in a fixed order: a unit per group, except that the
/// large-data groups, SLH-DSA signing and LMS key generation give a
/// unit per case. An LMS signing group stays whole, since its cases
/// share the one key the group generates.
pub fn units(suite: usize, doc: &Value) -> Vec<Unit> {
    let mut out = Vec::new();
    let Some(groups) = doc["testGroups"].as_array() else {
        return out;
    };
    let s = &SUITES[suite];
    let signing = s.algorithm == "SLH-DSA" && s.mode == Some("sigGen");
    let lms = |mode| s.algorithm == "LMS" && s.mode == Some(mode);
    for (group, g) in groups.iter().enumerate() {
        let cases = g["tests"].as_array().map_or(0, Vec::len);
        let tree = lms("keyGen").then(|| lms_weight(g, |h| 1 << h)).flatten();
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
                    lms_weight(g, |h| (1 << h) + signed * u64::from(h / 2 + 2))
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
    out
}

/// A generator that notes any draw made while its builder's set is
/// not in force. A driver that draws outside the builder has very
/// likely built outside it too, and a build there takes whatever set
/// another thread has put in force; the answers cannot show it, since
/// every kernel answers alike, but a draw can.
struct Watched<R> {
    rng: R,
    set: Features,
    strayed: bool,
}

impl<R: Random> Random for Watched<R> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), scytale::Error> {
        if features::get() != self.set {
            self.strayed = true;
        }
        self.rng.fill(out)
    }
}

/// Answers `unit` of `doc` under `builder` with a fresh fixed
/// generator and compares the answer with `doc`; returns the cases
/// compared, or `None` for a group the driver skipped.
pub fn answer_unit(
    suite: &Suite,
    doc: &Value,
    unit: &Unit,
    builder: &Builder,
) -> Result<Option<usize>, Error> {
    let mut group = doc["testGroups"][unit.group].clone();
    if let Some(case) = unit.case {
        let test = group["tests"][case].clone();
        group["tests"] = Value::Array(vec![test]);
    }
    let mut cut = doc.clone();
    cut["testGroups"] = Value::Array(vec![group]);
    let mut rng = Watched {
        rng: fixed_rng(builder)?,
        set: builder.set(),
        strayed: false,
    };
    let answered = (suite.answer)(&cut, &mut rng, builder)?;
    if rng.strayed {
        return Err(Error::new("drew randomness outside the builder"));
    }
    if answered["testGroups"].as_array().is_some_and(Vec::is_empty) {
        return Ok(None);
    }
    compare(suite, doc, &answered, builder).map(Some)
}

/// The seconds between two lines of progress.
const PROGRESS: u64 = 60;

/// Whether a line of progress is due at `now`, in seconds since the
/// suite began: when [`PROGRESS`] have passed since the last, which
/// `said` holds. One caller of those that ask at once is told yes.
fn progress_due(said: &AtomicU64, now: u64) -> bool {
    let last = said.load(Ordering::Relaxed);
    now >= last + PROGRESS
        && said
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// A kernel's features as its line names them: joined by `+`,
/// without the architecture's prefix; `none` for nothing. The
/// library's kernel tests name theirs the same way.
pub fn short_name(features: Features) -> String {
    if features.is_empty() {
        return "none".into();
    }
    let names: Vec<&str> = features.iter().map(Feature::name).collect();
    names.join("+")
}

/// The kernels `SCYTALE_KERNELS` names, separated by white space, or
/// `None` when it is unset, which selects every kernel.
fn selected() -> Option<Vec<String>> {
    let list = std::env::var("SCYTALE_KERNELS").ok()?;
    Some(list.split_whitespace().map(Into::into).collect())
}

/// The kernels the units `all` of `doc` test, each as the profile
/// that selects it and the indices of the units it answers. `types`
/// is the suite's from [`kernels_tested`]. A profile of a type
/// selects that type's row of it, so each unit is answered once
/// under every profile its type publishes; profiles two types share
/// are one kernel, run once for both. The empty set, last in every
/// list, comes last, and takes the groups no type tests too. A suite
/// with no kernel of its own has one, the features detected.
pub fn kernels(
    types: &[Built],
    doc: &Value,
    all: &[Unit],
) -> Vec<(Features, Vec<usize>)> {
    if types.is_empty() {
        return vec![(features::detected(), (0..all.len()).collect())];
    }
    let mut out: Vec<(Features, Vec<usize>)> = Vec::new();
    for (_, profiles) in types {
        for &profile in profiles() {
            if !profile.is_empty() && out.iter().all(|(p, _)| *p != profile) {
                out.push((profile, Vec::new()));
            }
        }
    }
    out.push((Features::new(), Vec::new()));
    for (i, unit) in all.iter().enumerate() {
        let group = &doc["testGroups"][unit.group];
        let published = tested(types, group).map(|t| (types[t].1)());
        for (profile, list) in &mut out {
            let due = match published {
                Some(published) => published.contains(profile),
                None => profile.is_empty(),
            };
            if due {
                list.push(i);
            }
        }
    }
    out.retain(|(_, list)| !list.is_empty());
    out
}

/// What one unit came to under one kernel: the cases compared, `None`
/// for a group the driver skipped, or what went wrong.
type Outcome = Result<Option<usize>, String>;

/// One unit of `all` to answer under one kernel: their indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Task {
    kernel: usize,
    unit: usize,
}

/// Answers `tasks`, each a unit of `all` under its kernel's builder
/// in `builders`, one worker per core taking the next, heaviest
/// first, and returns each task with its outcome. A panicking driver
/// is one task's failure, not the end of the run. `name` heads the
/// lines of progress.
fn answer_all(
    name: &str,
    suite: &Suite,
    doc: &Value,
    all: &[Unit],
    builders: &[Builder],
    tasks: &[Task],
) -> Vec<(Task, Outcome)> {
    let mut order = tasks.to_vec();
    // Stable, so units of a weight go in kernel order.
    order.sort_by_key(|t| std::cmp::Reverse(all[t.unit].weight));
    // WebAssembly has no threads: spawning one aborts the run.
    let workers = if cfg!(target_family = "wasm") {
        1
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    };
    let next = AtomicUsize::new(0);
    let outcomes = Mutex::new(Vec::with_capacity(order.len()));
    // The table is printed when the suite is done, which under
    // emulation is a long silence; a line a minute says how far it
    // has got.
    let total: u64 = order.iter().map(|t| all[t.unit].weight).sum();
    let began = Instant::now();
    let said = AtomicU64::new(0);
    let finished = AtomicUsize::new(0);
    let weighed = AtomicU64::new(0);
    let work = || {
        while let Some(&task) = order.get(next.fetch_add(1, Ordering::Relaxed))
        {
            let unit = &all[task.unit];
            let builder = &builders[task.kernel];
            let outcome = match catch_unwind(AssertUnwindSafe(|| {
                answer_unit(suite, doc, unit, builder)
            })) {
                Ok(Ok(count)) => Ok(count),
                Ok(Err(e)) => Err(e.message),
                Err(panic) => Err(panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| {
                        panic.downcast_ref::<&str>().map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "panicked".into())),
            };
            let outcome = outcome.map_err(|e| {
                let group = &doc["testGroups"][unit.group];
                let case = unit.case.map_or(String::new(), |c| {
                    format!(" tcId {}", group["tests"][c]["tcId"])
                });
                format!("unit tgId {}{case}: {e}", group["tgId"])
            });
            outcomes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((task, outcome));
            let units = finished.fetch_add(1, Ordering::Relaxed) + 1;
            let weight =
                weighed.fetch_add(unit.weight, Ordering::Relaxed) + unit.weight;
            let now = began.elapsed().as_secs();
            if progress_due(&said, now) {
                println!(
                    "  {name}: {units} of {} units, weight {weight} of \
                     {total}, after {now} s",
                    order.len()
                );
            }
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
    outcomes.into_inner().unwrap_or_else(|e| e.into_inner())
}

/// Checks the suite whose vendored directory is `directory` under
/// each of its kernels, as the test `name`, and prints the cases
/// compared and a line for every kernel: run, not run with the
/// features it lacks, not selected, or failed, with what went wrong
/// on stderr. A suite whose vectors are not in this copy is skipped.
/// Fails if any kernel's run fails, and on a suite that answers fewer
/// cases than its minimum when every unit was answered.
///
/// The kernels run at once, each unit building through its kernel's
/// [`Builder`], so suites may be checked from several threads at
/// once too.
pub fn check(name: &str, directory: &str) -> Result<(), Error> {
    let s = SUITES
        .iter()
        .position(|s| s.directory == directory)
        .ok_or_else(|| Error::new(format!("{directory}: not registered")))?;
    let suite = &SUITES[s];
    let Some(doc) = vendored(suite) else {
        println!("{name}: {directory}: no vectors in this copy, skipped");
        return Ok(());
    };
    let types = kernels_tested(suite)?;
    let all = units(s, &doc);
    let selected = selected();
    let hardware = features::detected();
    let kernels = kernels(&types, &doc, &all);
    // Each kernel's name, and its builder if it is to run or else
    // why not; the processor's refusals are found here, once.
    let mut names = Vec::with_capacity(kernels.len());
    let mut builders = Vec::with_capacity(kernels.len());
    let mut states = Vec::with_capacity(kernels.len());
    let mut tasks = Vec::new();
    for (k, (profile, list)) in kernels.iter().enumerate() {
        // A suite with no kernel of its own runs once, on whatever
        // the processor dispatches to; its name says that, rather
        // than spelling out a set that differs from machine to
        // machine.
        let kernel = if types.is_empty() {
            format!("{name}/default")
        } else {
            format!("{name}/{}", short_name(*profile))
        };
        let missing = profile.without(Feature::Isolated) - hardware;
        let built = if selected.as_ref().is_some_and(|s| !s.contains(&kernel)) {
            Err("not selected".to_string())
        } else if types.is_empty() {
            Ok(Builder::default())
        } else {
            Builder::try_new(*profile)
                .map_err(|_| format!("not run: needs {}", short_name(missing)))
        };
        match built {
            Ok(builder) => {
                tasks.extend(list.iter().map(|&unit| Task { kernel: k, unit }));
                builders.push(builder);
                states.push(None);
            }
            Err(state) => {
                // Holds the kernel's place; no task names it.
                builders.push(Builder::default());
                states.push(Some(state));
            }
        }
        names.push(kernel);
    }
    let mut outcomes = answer_all(name, suite, &doc, &all, &builders, &tasks);
    // In kernel order, so that a unit's cases are counted as the
    // first kernel to answer it found them, whatever order the
    // workers finished in.
    outcomes.sort_by_key(|(t, _)| (t.kernel, t.unit));
    // Each unit's cases, the first time any kernel answers it.
    let mut answered: Vec<Option<usize>> = vec![None; all.len()];
    let mut errors: Vec<Vec<String>> = vec![Vec::new(); kernels.len()];
    for (task, outcome) in outcomes {
        match outcome {
            Ok(count) => {
                answered[task.unit].get_or_insert(count.unwrap_or(0));
            }
            Err(e) => errors[task.kernel].push(e),
        }
    }
    let mut lines = Vec::new();
    let mut failed = Vec::new();
    for ((kernel, state), mut errors) in names.iter().zip(states).zip(errors) {
        let state = state.unwrap_or_else(|| {
            if errors.is_empty() {
                return "run".into();
            }
            errors.sort();
            for e in errors.drain(..) {
                eprintln!("{kernel}: {directory}: {e}");
            }
            failed.push(kernel.clone());
            "FAILED".into()
        });
        lines.push(format!("  {kernel:<40} {state}"));
    }
    let cases: usize = answered.iter().flatten().sum();
    println!("{name}: {directory}, {cases} cases\n{}", lines.join("\n"));
    if !failed.is_empty() {
        return Err(Error::new(format!("failed: {}", failed.join(" "))));
    }
    // The minimum is a whole suite's, so only a run that answered
    // every unit can hold the suite to it.
    if answered.iter().all(Option::is_some) && cases < suite.minimum {
        return Err(Error::new(format!(
            "{directory}: only {cases} cases, expected at least {}",
            suite.minimum
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::candidates;
    use serde_json::json;
    use std::collections::HashSet;

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

    #[test]
    fn short_names_join_the_features() {
        assert_eq!(short_name(Features::new()), "none");
        assert_eq!(short_name(Features::of(&[Feature::Isolated])), "isolated");
    }

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
    fn each_unit_is_answered_once_per_kernel_it_tests() {
        let ecdsa = suite_of("ECDSA", Some("sigGen"));
        let group = |curve: &str| json!({"curve": curve, "tests": [{}]});
        let doc = json!({"testGroups": [
            group("P-256"), group("P-384"), group("P-224"), group("P-521"),
        ]});
        let types = kernels_tested(&SUITES[ecdsa]).unwrap();
        let all = units(ecdsa, &doc);
        assert_eq!(all.len(), 4);
        let got = kernels(&types, &doc, &all);
        assert_eq!(got.last().map(|(p, _)| *p), Some(Features::new()));
        let mut seen = HashSet::new();
        for (profile, _) in &got {
            assert!(seen.insert(*profile), "{profile} twice");
        }
        for (i, unit) in all.iter().enumerate() {
            let group = &doc["testGroups"][unit.group];
            let under: Vec<Features> = got
                .iter()
                .filter(|(_, list)| list.contains(&i))
                .map(|(p, _)| *p)
                .collect();
            // Every profile its curve publishes, once each; a curve
            // the library lacks is answered once, portably.
            match tested(&types, group) {
                Some(t) => assert_eq!(under, (types[t].1)(), "{unit:?}"),
                None => assert_eq!(under, [Features::new()], "{unit:?}"),
            }
        }

        let lms = suite_of("LMS", Some("sigVer"));
        let doc = json!({"testGroups": [{"tests": [{}]}, {"tests": [{}]}]});
        let all = units(lms, &doc);
        let types = kernels_tested(&SUITES[lms]).unwrap();
        assert_eq!(
            kernels(&types, &doc, &all),
            [(features::detected(), vec![0, 1])]
        );
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

        let doc = json!({"testGroups": [small.clone()]});
        let of = |mode| units(suite_of("LMS", Some(mode)), &doc);
        // A tree of 1024 leaves of 303 hashes, a case each.
        let tree = of("keyGen");
        assert_eq!(tree.len(), 10);
        assert!(tree.iter().all(|u| u.case.is_some() && u.weight == 31));
        // The group whole: its tree and ten signatures of 7 leaves.
        let whole = of("sigGen");
        assert_eq!(whole.len(), 1);
        assert_eq!((whole[0].case, whole[0].weight), (None, 33));
        // Verifying is an ordinary case.
        let verified = of("sigVer");
        assert_eq!((verified[0].case, verified[0].weight), (None, 10));
    }

    /// A driver that draws outside its builder fails its unit, which
    /// can be seen only under a profile the processor would not pick
    /// by itself: under the set detected, outside looks like inside.
    #[test]
    fn a_draw_outside_the_builder_fails_the_unit() {
        if features::detected().is_empty() {
            return;
        }
        let suite = |answer| Suite {
            directory: "x",
            algorithm: "x",
            mode: None,
            revision: "1.0",
            answer,
            verify: None,
            minimum: 0,
        };
        let inside = suite(|doc, rng, builder| {
            builder.try_build(|| rng.fill(&mut [0u8; 8]))?;
            Ok(json!({ "testGroups": [], "vsId": doc["vsId"] }))
        });
        let outside = suite(|doc, rng, _| {
            rng.fill(&mut [0u8; 8])?;
            Ok(json!({ "testGroups": [], "vsId": doc["vsId"] }))
        });
        let doc = json!({"testGroups": [{"tgId": 1, "tests": []}]});
        let unit = Unit {
            suite: 0,
            group: 0,
            case: None,
            weight: 1,
        };
        let portable = Builder::try_new(Features::new()).unwrap();
        assert_eq!(answer_unit(&inside, &doc, &unit, &portable), Ok(None));
        let e = answer_unit(&outside, &doc, &unit, &portable).unwrap_err();
        assert_eq!(e.message, "drew randomness outside the builder");
    }

    #[test]
    fn progress_is_due_once_an_interval() {
        let said = AtomicU64::new(0);
        assert!(!progress_due(&said, 0));
        assert!(!progress_due(&said, PROGRESS - 1));
        assert!(progress_due(&said, PROGRESS));
        assert!(!progress_due(&said, PROGRESS + 1));
        assert!(!progress_due(&said, 2 * PROGRESS - 1));
        assert!(progress_due(&said, 2 * PROGRESS + 5));
        assert!(!progress_due(&said, 3 * PROGRESS + 4));
    }

    #[test]
    fn units_split_large_data_by_case_and_keep_other_groups() {
        // The first suite in the registry stands for any ordinary
        // one.
        let doc = json!({"testGroups": [
            {"tgId": 1, "testType": "AFT", "tests": [{"tcId": 1}, {"tcId": 2}]},
            {"tgId": 2, "testType": "MCT", "tests": [{"tcId": 3}]},
            {"tgId": 3, "testType": "LDT", "tests": [
                {"tcId": 4, "largeMsg": {"fullLength": 1u64 << 23}},
                {"tcId": 5, "largeMsg": {"fullLength": 1u64 << 24}}]},
        ]});
        let got = units(0, &doc);
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
    fn units_split_slh_dsa_signing_by_case() {
        let signing = SUITES
            .iter()
            .position(|s| s.algorithm == "SLH-DSA" && s.mode == Some("sigGen"))
            .expect("registered");
        let doc = json!({"testGroups": [
            {"tgId": 1, "testType": "AFT", "tests": [{"tcId": 1}, {"tcId": 2}]},
        ]});
        let got = units(signing, &doc);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|u| u.suite == signing && u.case.is_some()));
    }
}
