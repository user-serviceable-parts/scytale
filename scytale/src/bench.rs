//! Throughput of the primitives, in the manner of `openssl speed`,
//! and the cost of the operations that have no throughput to
//! measure.
//!
//! Everything the library implements is here. A primitive that runs
//! over a buffer is reported at six sizes, from one block to sixteen
//! kilobytes: the small end shows what a call costs before any data
//! moves, the large end the steady state, and the distance between
//! them is what says whether a faster bulk path would need a
//! short-message fallback beside it. A primitive whose cost is the
//! call rather than the data, which is every key operation, both key
//! derivations and the two format-preserving modes, is reported
//! instead as operations a second and the time one takes.
//!
//! Every figure comes in two units. Cycles a byte, or an operation,
//! is what the code costs: it barely moves between runs, between a
//! fast core and a slow one, or as a laptop warms up and its clock
//! falls, so it is the figure to compare across commits. Megabytes
//! a second, or operations a second, is what a caller feels on this
//! machine as it stood. The two are read around the same work, so the
//! document also records the clock rate each cell saw. The cycle
//! counter is the kernel's, through `perf_event_open`; where it
//! cannot be opened, as in a virtual machine or with
//! `kernel.perf_event_paranoid` above 2, the rates stand alone.
//!
//! A figure is the median of thirty-one samples, not a mean over one
//! long run, since an interrupt, a migration, or a neighbour on the
//! other thread of the core only ever slows a sample and never speeds
//! one. The spread of the middle half of the samples is kept with
//! each figure, and a figure whose spread passes five percent of its
//! median is marked `*` in the table: the number is still the best
//! there is, but the run was not quiet. Within a section the cells
//! are sampled in rounds, one sample of every cell and then the next,
//! so that a clock drifting over the minutes lands on every row of
//! the section alike instead of on whichever rows came last.
//!
//! `scripts/bench` pins the run to one CPU, the fastest, so that two
//! runs measure the same core and not wherever the scheduler put each
//! row, and `--save NAME` keeps a pass under a header recording what
//! else the machine was doing: governor, turbo, the other thread of
//! the core, power, load and throttling. `scripts/bench-quiet`, as
//! root, settles those so that the rates repeat as the cycles do.
//!
//! `--json PATH` writes every figure with its spread, the clock, the
//! sample count and what the machine said about itself, and
//! `--compare OLD NEW` sets two such documents side by side: a figure
//! counts as changed only when it moved by more than both spreads
//! together, and the run fails when any figure is worse by that much,
//! so a check before a push has a yes or no.
//!
//! Every implementation gets one section, named for the instructions
//! it runs on, and nothing is measured twice. A mode written out for
//! those instructions is measured as itself; a mode with nothing
//! written for them appears only where the portable construction over
//! that cipher is what runs. The SHA-2, SHA-3 and ChaCha20
//! implementations follow in sections of their own. What chooses
//! inside itself and cannot be named from out here -- SHA-1, the
//! generator, Poly1305 and the AEAD over ChaCha20 -- is under
//! `dispatching`. The operation groups are named for the module they
//! come from: `kdf`, `kex`, `sig`, `sig-pq`, `kem`, `pke` and `fpe`.
//!
//! ```text
//! scripts/bench                    # everything
//! scripts/bench gcm aesni          # rows matching both
//! scripts/bench sha                # the hashes only
//! scripts/bench sig                # signatures, both kinds
//! scripts/bench --seconds 0.25     # a quicker sweep
//! scripts/bench --json out.json    # keep every figure
//! scripts/bench --compare a.json b.json   # what changed, beyond noise
//! scripts/bench --self-test        # check the harness
//! ```
//!
//! # Reading the numbers
//!
//! Counter mode and GMAC are the two halves of GCM measured apart:
//! the keystream without the hash, and the hash without the
//! keystream. If the reciprocal of the GCM rate is close to the sum
//! of their reciprocals, the two halves are running one after the
//! other and a single loop that interleaved them would have the whole
//! of that difference to win. If GCM already beats that sum, the
//! processor is overlapping them on its own.
//!
//! Key wrapping is six passes over its input by construction, so it
//! reads an order of magnitude below the mode rows above it. CFB1 is
//! a block operation per bit, and reads as such.
//!
//! ML-DSA signing repeats until a candidate passes, so its cost
//! depends on the message and not only on the parameter set; a
//! stronger set is not reliably slower. Both key generation figures
//! for RSA and the signature figures for SLH-DSA vary for the same
//! kind of reason.
//!
//! A laptop measured on battery reports about half the rates, evenly
//! across every row, and nearly the same cycles a byte: that is the
//! clock and not the code, and the recorded clock rate says so.
//!
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::hint::black_box;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cpu_time::ThreadTime;
use serde_json::{Value, json};

use crate::Key;
use crate::aead::{Aead, Ccm, ChaCha20Poly1305, Gcm, GcmSiv, Xpn};
use crate::cipher::chacha20;
use crate::cipher::mode::{Cbc, Cfb1, Cfb8, Cfb128, Ctr, Kw, Kwp, Ofb, Xts};
use crate::cipher::mode::{Ff1, Ff3_1};
use crate::cipher::{BlockCipher, aes};
use crate::implementation::Implementation;
#[allow(unused_imports)]
use std::{
    boxed::Box, eprintln, format, print, println, string::String,
    string::ToString, vec, vec::Vec,
};

/// The portable AES implementations at a key width; their paths
/// alone are too long.
type Bitsliced<const K: usize> = aes::portable::bitsliced::Aes<K>;
type Ttable<const K: usize> = aes::portable::ttable::Aes<K>;
use crate::BlockType;
use crate::Error;
use crate::Random;
use crate::hash::sha1::Sha1;
use crate::hash::sha3::TupleHash128;
use crate::hash::{Hash, Xof, XofReader};
use crate::hash::{sha2, sha3};
use crate::kdf::{hkdf, one_step, pbkdf2, sp800_108, tls12, x963};
use crate::kex::{ecdh, x25519};
use crate::mac::Mac;
use crate::mac::cmac::Cmac;
use crate::mac::hmac::Hmac;
use crate::mac::kmac::Kmac128;
use crate::mac::poly1305::Poly1305;
use crate::pke::hpke;
use crate::pke::rsa as oaep;
use crate::random::{CtrDrbg, HashDrbg, HmacDrbg};
use crate::sig::{ecdsa, ed25519, rsa};

/// Buffer sizes reported, the ones `openssl speed` uses.
const SIZES: [usize; 6] = [16, 64, 256, 1024, 8192, 16384];

/// CPU time spent on each cell unless `--seconds` says otherwise.
const DEFAULT_BUDGET: Duration = Duration::from_millis(1000);

/// How long a calibration batch should last. Long enough that the two
/// clock reads around it are lost in the noise, short enough that
/// finding the batch size costs little.
const CALIBRATION: Duration = Duration::from_millis(10);

/// Ceiling on the calibrated batch, so that an operation too quick to
/// reach [`CALIBRATION`] cannot spin the search forever.
const MAX_BATCH: u64 = 1 << 32;

/// Samples a cell is measured in. Odd, so the median is one of them.
const SAMPLES: usize = 31;

/// Spread of the middle half of a cell's samples, as a fraction of the
/// median, past which the cell is marked noisy.
const NOISY: f64 = 0.05;

/// Alignment of every buffer measured: a page, so that where a buffer
/// falls in a cache line and a page is the same on every run.
const PAGE: usize = 4096;

/// One operation, ready to run over a buffer.
///
/// Boxed and called through the vtable, which costs a couple of
/// nanoseconds an iteration. That is invisible at the larger sizes
/// and a few percent at sixteen bytes, and it falls on every row
/// alike, so rows stay comparable with each other.
type Operation<'a> = Box<dyn FnMut(&mut [u8]) + 'a>;

/// A named operation.
type Task<'a> = (&'static str, Operation<'a>);

/// Measures. Ignored by default, since a sweep takes minutes and a
/// test run should not; `scripts/bench` runs it.
///
/// The arguments are in `SCYTALE_BENCH`, since the test harness owns
/// the command line.
#[test]
#[ignore = "measures; run it with scripts/bench"]
fn speed() {
    let arguments = env::var("SCYTALE_BENCH").unwrap_or_default();
    let words = arguments.split_whitespace().map(String::from);
    let options = match Options::parse(words) {
        Ok(Some(options)) => options,
        // `--help`, which has printed itself.
        Ok(None) => return,
        Err(message) => panic!("speed: {message}"),
    };
    if options.self_test {
        assert!(self_test(), "self-test");
        return;
    }
    // Comparing measures nothing, so the profile does not matter.
    if let Some((old, new)) = &options.compare {
        let comparison = match compare_files(old, new) {
            Ok(comparison) => comparison,
            Err(message) => panic!("speed: {message}"),
        };
        print!("{}", comparison.text);
        assert!(
            comparison.worse == 0,
            "{} figures are worse beyond the noise",
            comparison.worse
        );
        return;
    }
    // A build with debug assertions left on is not the release
    // profile that `scripts/bench` uses, so any figure it produced
    // would describe the unoptimised code rather than the shipped
    // code. That is also how `cargo test --benches` arrives here, and
    // a five minute sweep is not what asking for tests means.
    if cfg!(debug_assertions) {
        println!(
            "speed: this build has debug assertions on, so any figure\n\
             would describe unoptimised code. Checking the harness\n\
             instead; `scripts/bench` measures."
        );
        assert!(self_test(), "self-test");
        return;
    }
    let started = unix_seconds();
    let mut run = Run::new(options);
    let ran = report(&mut run);
    let finished = unix_seconds();
    if let Some(path) = &run.options.json {
        let document = document(&run, started, finished);
        if let Err(e) = write_json(path, &document) {
            panic!("speed: {path}: {e}");
        }
    }
    if !ran {
        // Nothing ran. With filters that is a request for rows which
        // do not exist, which `report` has just explained; there is
        // nothing to measure and nothing wrong. With no filters it
        // means the harness itself measured nothing, which is a fault.
        assert!(
            !run.options.filters.is_empty(),
            "no filters, and still nothing measured"
        );
    }
}

/// Seconds since the Unix epoch, for the document's timestamps.
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Writes the document, pretty-printed.
fn write_json(path: &str, document: &Value) -> Result<(), String> {
    let text =
        serde_json::to_string_pretty(document).map_err(|e| e.to_string())?;
    fs::write(path, text + "\n").map_err(|e| e.to_string())
}

/// What the command line asked for.
#[derive(Clone)]
struct Options {
    /// CPU time to spend on each cell.
    budget: Duration,
    /// Words that a row's name must all contain to be run.
    filters: Vec<String>,
    /// Check the harness itself instead of benchmarking.
    self_test: bool,
    /// Where to write the figures as JSON, if anywhere.
    json: Option<String>,
    /// Two documents to compare instead of measuring.
    compare: Option<(String, String)>,
}

impl Options {
    /// Parses arguments, or returns `None` when the work is done
    /// already, as it is for `--help`.
    fn parse(
        args: impl Iterator<Item = String>,
    ) -> Result<Option<Self>, String> {
        let mut options = Options {
            budget: DEFAULT_BUDGET,
            filters: Vec::new(),
            self_test: false,
            json: None,
            compare: None,
        };
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => {
                    print!("{USAGE}");
                    return Ok(None);
                }
                "--self-test" => options.self_test = true,
                "--seconds" => {
                    let value = args
                        .next()
                        .ok_or("--seconds wants a number of seconds")?;
                    let seconds: f64 = value
                        .parse()
                        .map_err(|_| format!("not a number: {value}"))?;
                    if !(seconds.is_finite() && seconds > 0.0) {
                        return Err(format!("not a duration: {value}"));
                    }
                    options.budget = Duration::from_secs_f64(seconds);
                }
                "--json" => {
                    let path = args.next().ok_or("--json wants a path")?;
                    options.json = Some(path);
                }
                "--compare" => {
                    let wants = "--compare wants two JSON paths";
                    let old = args.next().ok_or(wants)?;
                    let new = args.next().ok_or(wants)?;
                    options.compare = Some((old, new));
                }
                // Cargo appends this when it runs a bench target,
                // saying only that this is a benchmark run, which is
                // what the target does anyway.
                "--bench" => {}
                // Cargo appends this one instead when a bench
                // target is reached through `cargo test`.
                "--test" => options.self_test = true,
                other if other.starts_with('-') => {
                    return Err(format!("unknown option: {other}"));
                }
                other => options.filters.push(other.to_ascii_lowercase()),
            }
        }
        Ok(Some(options))
    }

    /// Whether a row belongs in this run. Every filter word must
    /// appear somewhere in the implementation or algorithm name, so
    /// `gcm aesni` narrows to one implementation's GCM rows. A word
    /// may offer alternatives separated by commas, so `ctr,ecb-enc`
    /// keeps rows matching either.
    ///
    /// The two go together: a comparison between rows only means
    /// anything when they were measured in the same run, since the
    /// clock and which core the thread lands on both move between
    /// runs, and a conjunction alone cannot ask for two rows.
    fn wants(&self, implementation: &str, algorithm: &str) -> bool {
        let name = format!("{implementation} {algorithm}");
        self.filters
            .iter()
            .all(|filter| filter.split(',').any(|word| name.contains(word)))
    }
}

const USAGE: &str = "\
usage: scripts/bench [options] [filter...]

  --seconds N   CPU time to spend on each measurement (default 1)
  --json PATH   also write every figure, with its spread, as JSON
  --compare OLD NEW
                compare two such documents instead of measuring;
                fails when a figure is worse beyond the noise
  --self-test   check the harness instead of benchmarking
  --help        this text

A filter is a bare word; a row runs when its implementation and
algorithm names together contain every filter given. Commas inside a
word offer alternatives, so `aesni ctr,ecb-enc` keeps both of those
rows, measured in the one run and so comparable.
";

/// One run: what was asked for, the clocks, and every row measured
/// so far, kept for the JSON document.
struct Run {
    options: Options,
    clock: Clock,
    rows: Vec<Row>,
    /// Whether the heading over the operation groups has been
    /// printed; the first group to run prints it, so a run filtered
    /// down to the throughput rows does not carry a heading over
    /// nothing.
    ops_heading: bool,
}

impl Run {
    fn new(options: Options) -> Self {
        Run {
            options,
            clock: Clock::open(),
            rows: Vec::new(),
            ops_heading: false,
        }
    }
}

/// Runs every implementation the processor supports: measures every
/// section the filters allow, and says whether any row ran.
fn report(run: &mut Run) -> bool {
    println!(
        "Throughput by buffer size in bytes: cycles a byte (cpb) and \
         megabytes a\nsecond (10^6, MB/s). Each figure is the median \
         of {} samples, each over\n{:.3} seconds of CPU time on this \
         thread; `*` marks a figure whose middle half\nof samples \
         spread more than {:.0}% of the median.",
        SAMPLES,
        sample_budget(run.options.budget).as_secs_f64(),
        NOISY * 100.0
    );
    if let Some(reason) = &run.clock.unavailable {
        println!(
            "The cycle counter could not be opened, so only the rates \
             are shown:\n{reason}."
        );
    }

    // One section per implementation, named for the instructions it
    // runs on. A section exists only on the architecture that has
    // them, is skipped when the processor says no, and leaves out any
    // row whose suite has nothing written for those instructions.
    let mut ran = false;
    #[cfg(target_arch = "x86_64")]
    {
        use crate::cipher::aes::x86_64;
        ran |= section::<x86_64::vaes::Aes<16>, x86_64::vaes::Aes<32>>(
            "vaes",
            Implementation::Vaes,
            run,
        );
        ran |= section::<x86_64::aesni::Aes<16>, x86_64::aesni::Aes<32>>(
            "aesni",
            Implementation::Aesni,
            run,
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        use crate::cipher::aes::aarch64;
        ran |= section::<aarch64::armv8::Aes<16>, aarch64::armv8::Aes<32>>(
            "armv8",
            Implementation::Armv8,
            run,
        );
    }
    #[cfg(target_arch = "riscv64")]
    {
        use crate::cipher::aes::riscv64;
        ran |= section::<riscv64::zvkned::Aes<16>, riscv64::zvkned::Aes<32>>(
            "zvkned",
            Implementation::Zvkned,
            run,
        );
        // The scalar cipher has no mode written against it, so its
        // rows are the portable constructions over it.
        ran |= section::<riscv64::zkn::Aes<16>, riscv64::zkn::Aes<32>>(
            "zkn",
            Implementation::Portable,
            run,
        );
    }
    ran |= section::<Bitsliced<16>, Bitsliced<32>>(
        "bitsliced",
        Implementation::Portable,
        run,
    );
    ran |= section::<Ttable<16>, Ttable<32>>(
        "ttable",
        Implementation::Portable,
        run,
    );

    // The hashes, likewise. SHA-224 and SHA-384 cost the same as
    // SHA-256 and SHA-512 and are not measured separately.
    #[cfg(target_arch = "x86_64")]
    {
        ran |= hash_section(
            "shani",
            run,
            sha2::x86_64::Sha256::try_new,
            sha2::portable::Sha512::try_new,
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        ran |= hash_section(
            "armv8",
            run,
            sha2::aarch64::Sha256::try_new,
            sha2::aarch64::Sha512::try_new,
        );
    }
    #[cfg(target_arch = "riscv64")]
    {
        ran |= hash_section(
            "zvknh",
            run,
            sha2::riscv64::zvknh::Sha256::try_new,
            sha2::riscv64::zvknh::Sha512::try_new,
        );
        ran |= hash_section(
            "zknh",
            run,
            sha2::riscv64::zknh::Sha256::try_new,
            sha2::riscv64::zknh::Sha512::try_new,
        );
    }
    ran |= hash_section(
        "portable",
        run,
        sha2::portable::Sha256::try_new,
        sha2::portable::Sha512::try_new,
    );

    // ChaCha20, one section per way of computing the keystream.
    #[cfg(target_arch = "x86_64")]
    {
        ran |= chacha_section::<chacha20::x86_64::ChaCha20>("avx2", run);
    }
    #[cfg(target_arch = "aarch64")]
    {
        ran |= chacha_section::<chacha20::aarch64::ChaCha20>("neon", run);
    }
    #[cfg(target_arch = "riscv64")]
    {
        ran |= chacha_section::<chacha20::riscv64::zvkb::ChaCha20>("zvkb", run);
        ran |= chacha_section::<chacha20::riscv64::zbb::ChaCha20>("zbb", run);
    }
    ran |= chacha_section::<chacha20::portable::ChaCha20>("portable", run);

    // SHA-3: one permutation under every function, so one hardware
    // section, and only AArch64 has the instructions.
    #[cfg(target_arch = "aarch64")]
    {
        ran |= sha3_section(
            "armv8",
            run,
            (
                sha3::aarch64::Sha3_256::try_new,
                sha3::aarch64::Sha3_512::try_new,
                sha3::aarch64::Shake128::try_new,
                sha3::aarch64::Shake256::try_new,
            ),
        );
    }
    ran |= sha3_section(
        "portable",
        run,
        (
            sha3::portable::Sha3_256::try_new,
            sha3::portable::Sha3_512::try_new,
            sha3::portable::Shake128::try_new,
            sha3::portable::Shake256::try_new,
        ),
    );
    ran |= single_section(run);

    ran |= kdf_ops(run);
    ran |= kex_ops(run);
    ran |= sig_ops(run);
    ran |= pq_sig_ops(run);
    ran |= kem_ops(run);
    ran |= pke_ops(run);
    ran |= fpe_ops(run);

    if !ran {
        explain(&run.options.filters);
    }
    ran
}

/// Every row name the harness knows, for saying what a filter could
/// have meant.
///
/// The lists are per family and live beside the code that measures
/// each, so this gathers them rather than being a second copy to keep
/// in step.
fn every_row_name() -> impl Iterator<Item = &'static str> {
    ALGORITHMS
        .iter()
        .chain(HASHES.iter())
        .chain(CHACHA.iter())
        .chain(DISPATCHING.iter())
        .chain(KDF_JOBS.iter())
        .chain(KEX_JOBS.iter())
        .chain(SIG_JOBS.iter())
        .chain(PQ_SIG_JOBS.iter())
        .chain(KEM_JOBS.iter())
        .chain(PKE_JOBS.iter())
        .chain(FPE_JOBS.iter())
        .copied()
}

/// Says what a filter that selected nothing could have meant.
///
/// Nearly always one word is spelt right but asks for a row that does
/// not exist, or two words are each fine and have no row in common --
/// `ctr aes-256`, where counter mode has only a 128-bit row. Showing
/// each word beside the rows it does match makes both visible.
fn explain(filters: &[String]) {
    eprintln!("speed: no row matches every filter word.");
    for filter in filters {
        let matched: Vec<&str> = every_row_name()
            .filter(|name| filter.split(',').any(|word| name.contains(word)))
            .collect();
        if matched.is_empty() {
            eprintln!(
                "  {filter:<16} no row name holds this; \
                 an implementation, perhaps?"
            );
        } else {
            eprintln!("  {filter:<16} {}", matched.join(" "));
        }
    }
    eprintln!(
        "A row runs when its implementation and algorithm names \
         together hold\nevery word given. Commas inside a word offer \
         alternatives; see --help."
    );
}

/// Measures one implementation, returning whether it ran anything.
///
/// An implementation the processor cannot run is left out rather than
/// reported as nothing, and so is one every filter rejected.
/// `name` is the AES implementation the section is headed with, and
/// `implementation` is what the modes in it are built on: the engine
/// written for the same instructions where there is one, and the
/// portable construction over this cipher where there is not. A mode
/// with nothing for either is left out of the section rather than
/// measured twice under two names.
fn section<A, B>(
    name: &str,
    implementation: Implementation,
    run: &mut Run,
) -> bool
where
    A: BlockCipher<Block = [u8; 16], Key = Key<[u8; 16]>>,
    B: BlockCipher<Block = [u8; 16], Key = Key<[u8; 32]>>,
{
    let wanted: Vec<&'static str> = ALGORITHMS
        .iter()
        .copied()
        .filter(|row| run.options.wants(name, row))
        .collect();
    if wanted.is_empty() {
        return false;
    }

    let mut keys = match Keys::<A, B>::try_new(implementation) {
        Ok(keys) => keys,
        // No such instructions here.
        Err(Error::NotSupported) => return false,
        Err(e) => {
            eprintln!("speed: {name}: {e}");
            return false;
        }
    };
    let mut tasks = keys.tasks();
    tasks.retain(|(row, _)| wanted.contains(row));
    if tasks.is_empty() {
        return false;
    }

    throughput_table(run, name, &mut tasks);
    true
}

/// The hash rows: each family, and HMAC over it.
const HASHES: [&str; 4] =
    ["sha-256", "sha-512", "hmac-sha-256", "hmac-sha-512"];

/// Measures one pair of hash implementations, one per family,
/// returning whether it ran anything. A family the processor cannot
/// run is left out, as with the ciphers; on x86-64 the SHA-NI
/// section pairs its SHA-256 with the portable SHA-512, there being
/// no instruction for the latter.
fn hash_section<S256, S512>(
    implementation: &str,
    run: &mut Run,
    start256: fn() -> Result<S256, Error>,
    start512: fn() -> Result<S512, Error>,
) -> bool
where
    S256: Hash<Output = [u8; 32]> + Clone + BlockType,
    S512: Hash<Output = [u8; 64]> + Clone + BlockType,
{
    let wanted: Vec<&'static str> = HASHES
        .iter()
        .copied()
        .filter(|name| run.options.wants(implementation, name))
        .collect();
    if wanted.is_empty() {
        return false;
    }
    let (mut sha256, mut sha512) = match (start256(), start512()) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(Error::NotSupported), _) | (_, Err(Error::NotSupported)) => {
            return false;
        }
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("speed: {implementation}: {e}");
            return false;
        }
    };
    // Keyed from a fresh hash of the same implementation, so the
    // HMAC rows measure the backend this section names.
    let mut hmac256 = Hmac::with(sha256.clone(), &KEY128);
    let mut hmac512 = Hmac::with(sha512.clone(), &KEY128);
    let mut tasks: Vec<Task<'_>> = vec![
        (
            "sha-256",
            Box::new(|d: &mut [u8]| {
                sha256.reset();
                sha256.update(d);
                black_box(sha256.finalize());
            }) as Operation<'_>,
        ),
        (
            "sha-512",
            Box::new(|d: &mut [u8]| {
                sha512.reset();
                sha512.update(d);
                black_box(sha512.finalize());
            }),
        ),
        (
            "hmac-sha-256",
            Box::new(|d: &mut [u8]| {
                hmac256.restart();
                hmac256.append(d);
                black_box(hmac256.tag());
            }),
        ),
        (
            "hmac-sha-512",
            Box::new(|d: &mut [u8]| {
                hmac512.restart();
                hmac512.append(d);
                black_box(hmac512.tag());
            }),
        ),
    ];
    tasks.retain(|(name, _)| wanted.contains(name));

    throughput_table(run, implementation, &mut tasks);
    true
}

/// The SHA-3 rows: two digests and one extendable-output function,
/// the last squeezing 32 bytes.
/// The ChaCha20 row. What is built on it dispatches inside itself,
/// so those rows are in [`DISPATCHING`] instead.
const CHACHA: [&str; 1] = ["chacha20"];

/// What the ChaCha20 rows need of an implementation: the automatic
/// type and the per-backend types have the same methods but no
/// shared trait, since only the bench wants one.
trait StreamCipher: Sized {
    fn try_new(key: &Key<[u8; 32]>) -> Result<Self, Error>;
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error>;
}

impl StreamCipher for chacha20::ChaCha20 {
    fn try_new(key: &Key<[u8; 32]>) -> Result<Self, Error> {
        Ok(chacha20::ChaCha20::new(key))
    }
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        chacha20::ChaCha20::encrypt(self, nonce, counter, data)
    }
}

impl<B: chacha20::Backend> StreamCipher for chacha20::Cipher<B> {
    fn try_new(key: &Key<[u8; 32]>) -> Result<Self, Error> {
        chacha20::Cipher::try_new(key)
    }
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        chacha20::Cipher::encrypt(self, nonce, counter, data)
    }
}

/// Measures one ChaCha20 implementation, with Poly1305 and the AEAD
/// rows when `whole` says so; an implementation the processor cannot
/// run is left out.
fn chacha_section<C: StreamCipher>(
    implementation: &str,
    run: &mut Run,
) -> bool {
    let wanted: Vec<&'static str> = CHACHA
        .iter()
        .copied()
        .filter(|name| run.options.wants(implementation, name))
        .collect();
    if wanted.is_empty() {
        return false;
    }
    let cipher = match C::try_new(&Key::from(KEY256)) {
        Ok(cipher) => cipher,
        Err(Error::NotSupported) => return false,
        Err(e) => {
            eprintln!("speed: {implementation}: {e}");
            return false;
        }
    };
    let mut tasks: Vec<Task<'_>> = vec![(
        "chacha20",
        Box::new(|d: &mut [u8]| {
            let _ = cipher.encrypt(&NONCE, 1, d);
        }) as Operation<'_>,
    )];
    tasks.retain(|(name, _)| wanted.contains(name));

    throughput_table(run, implementation, &mut tasks);
    true
}

const SHA3: [&str; 4] = ["sha3-256", "sha3-512", "shake128", "shake256"];

/// Measures one implementation of SHA-3, returning whether it ran
/// anything; an implementation the processor cannot run is left out.
#[allow(clippy::type_complexity)]
fn sha3_section<D256, D512, X128, X256>(
    implementation: &str,
    run: &mut Run,
    starts: (
        fn() -> Result<D256, Error>,
        fn() -> Result<D512, Error>,
        fn() -> Result<X128, Error>,
        fn() -> Result<X256, Error>,
    ),
) -> bool
where
    D256: Hash<Output = [u8; 32]>,
    D512: Hash<Output = [u8; 64]>,
    X128: Xof,
    X256: Xof,
{
    let wanted: Vec<&'static str> = SHA3
        .iter()
        .copied()
        .filter(|name| run.options.wants(implementation, name))
        .collect();
    if wanted.is_empty() {
        return false;
    }
    let states = (starts.0(), starts.1(), starts.2(), starts.3());
    let (mut d256, mut d512, mut x128, mut x256) = match states {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
        (Err(Error::NotSupported), _, _, _)
        | (_, Err(Error::NotSupported), _, _)
        | (_, _, Err(Error::NotSupported), _)
        | (_, _, _, Err(Error::NotSupported)) => return false,
        (Err(e), _, _, _)
        | (_, Err(e), _, _)
        | (_, _, Err(e), _)
        | (_, _, _, Err(e)) => {
            eprintln!("speed: {implementation}: {e}");
            return false;
        }
    };
    let mut tasks: Vec<Task<'_>> = vec![
        (
            "sha3-256",
            Box::new(|d: &mut [u8]| {
                d256.reset();
                d256.update(d);
                black_box(d256.finalize());
            }) as Operation<'_>,
        ),
        (
            "sha3-512",
            Box::new(|d: &mut [u8]| {
                d512.reset();
                d512.update(d);
                black_box(d512.finalize());
            }),
        ),
        (
            "shake128",
            Box::new(|d: &mut [u8]| {
                x128.reset();
                x128.update(d);
                let mut out = [0u8; 32];
                x128.finalize_xof().squeeze(&mut out);
                black_box(out);
            }),
        ),
        (
            "shake256",
            Box::new(|d: &mut [u8]| {
                x256.reset();
                x256.update(d);
                let mut out = [0u8; 32];
                x256.finalize_xof().squeeze(&mut out);
                black_box(out);
            }),
        ),
    ];
    tasks.retain(|(name, _)| wanted.contains(name));

    throughput_table(run, implementation, &mut tasks);
    true
}

/// The rows whose implementation is settled inside them and cannot
/// be named from out here: SHA-1 picks its own, the generator builds
/// its own cipher or hash, and Poly1305 and the AEAD over ChaCha20 each take
/// the best the processor has without being asked.
const DISPATCHING: [&str; 9] = [
    "sha-1",
    "ctr-drbg",
    "hash-drbg-sha-256",
    "hmac-drbg-sha-256",
    "poly1305",
    "kmac128",
    "tuplehash128",
    "chacha20-poly1305-enc",
    "chacha20-poly1305-dec",
];

/// Measures them, returning whether it ran anything.
fn single_section(run: &mut Run) -> bool {
    let wanted: Vec<&'static str> = DISPATCHING
        .iter()
        .copied()
        .filter(|name| run.options.wants("dispatching", name))
        .collect();
    if wanted.is_empty() {
        return false;
    }
    let mut sha1 = Sha1::new();
    // Seeded rather than drawn, so a run repeats and no entropy
    // source is needed for a measurement.
    let Ok(mut rng) = CtrDrbg::from_seed(&[0x5au8; 64]) else {
        return false;
    };
    let Ok(mut hash_rng) =
        HashDrbg::<sha2::Sha256, _>::from_seed(&[0x5au8; 64])
    else {
        return false;
    };
    let Ok(mut hmac_rng) =
        HmacDrbg::<sha2::Sha256, _>::from_seed(&[0x5au8; 64])
    else {
        return false;
    };
    // Neither of these can fail to build: the key is the right width
    // and the automatic ChaCha20 always exists.
    let mut mac = Poly1305::new(&Key::from(KEY256));
    let aead = ChaCha20Poly1305::new(&Key::from(KEY256));
    let mut kmac = Kmac128::new(&KEY256, b"");
    let mut tuple = TupleHash128::new(b"");
    let mut tuple_out = [0u8; 32];
    let mut tags = [[0u8; 16]; 2];
    let (enc_tag, dec_tag) = tags.split_at_mut(1);
    let mut tasks: Vec<Task<'_>> = vec![
        (
            "sha-1",
            Box::new(|d: &mut [u8]| {
                sha1.reset();
                sha1.update(d);
                black_box(sha1.finalize());
            }) as Operation<'_>,
        ),
        (
            "ctr-drbg",
            Box::new(|d: &mut [u8]| {
                let _ = rng.fill(d);
            }),
        ),
        (
            "hash-drbg-sha-256",
            Box::new(|d: &mut [u8]| {
                let _ = hash_rng.fill(d);
            }),
        ),
        (
            "hmac-drbg-sha-256",
            Box::new(|d: &mut [u8]| {
                let _ = hmac_rng.fill(d);
            }),
        ),
        (
            "poly1305",
            Box::new(|d: &mut [u8]| {
                mac.reset();
                mac.update(d);
                black_box(mac.finalize());
            }),
        ),
        (
            "kmac128",
            Box::new(|d: &mut [u8]| {
                kmac.update(d);
                black_box(Mac::finalize(&mut kmac));
            }),
        ),
        // The buffer as one string, as a message is one for the
        // other hashes.
        (
            "tuplehash128",
            Box::new(|d: &mut [u8]| {
                tuple.push(d);
                tuple.finalize_to(&mut tuple_out);
                black_box(&tuple_out);
            }),
        ),
        (
            "chacha20-poly1305-enc",
            Box::new(|d: &mut [u8]| {
                let _ = aead.encrypt(&NONCE, &[], d, &mut enc_tag[0]);
            }),
        ),
        // The tag never matches after the first round, which costs a
        // comparison and changes nothing else; the streaming form
        // keeps the wipe on a bad tag out of the measurement.
        (
            "chacha20-poly1305-dec",
            Box::new(|d: &mut [u8]| {
                let Ok(mut state) = aead.decryptor(&NONCE) else {
                    return;
                };
                let _ = state.update(d);
                let _ = state.verify(&dec_tag[0]);
            }),
        ),
    ];
    tasks.retain(|(name, _)| wanted.contains(name));

    throughput_table(run, "dispatching", &mut tasks);
    true
}

// Operations whose cost is the call rather than a rate over a
// buffer: everything with a key pair, the two password and key
// derivations, and the format-preserving modes, which work on a
// string of symbols rather than on bytes.

/// One such operation.
type Once<'a> = Box<dyn FnMut() + 'a>;

/// A named one.
type Job<'a> = (&'static str, Once<'a>);

/// The message every signature row signs. Short, because what these
/// rows measure is the key operation and not the hash in front of
/// it.
const MESSAGE: &[u8] = b"scytale benchmark message";

/// PBKDF2 is meant to be slow, and its cost is the iteration count;
/// this is the round number nearest what a login path would use.
const ITERATIONS: u32 = 100_000;

/// The digits a format-preserving row encrypts: a card number's
/// worth, which is what the modes are for.
const DIGITS: usize = 16;

/// FF3-1's tweak is exactly seven bytes.
const FF3_TWEAK: [u8; 7] = [0x3c; 7];

/// A generator seeded rather than drawn, so that every key below is
/// the same one on every run.
fn seeded() -> Result<CtrDrbg<crate::random::entropy::External>, Error> {
    CtrDrbg::from_seed(&[0x5au8; 64])
}

/// Measures one group of operations, returning whether it ran any.
/// The jobs are built by the caller, which has already made the keys
/// they close over. Sampled in rounds across the group, as
/// [`throughput_table`] does.
fn ops_section(run: &mut Run, title: &str, jobs: Vec<Job<'_>>) -> bool {
    let mut jobs: Vec<Job<'_>> = jobs
        .into_iter()
        .filter(|(name, _)| run.options.wants(title, name))
        .collect();
    if jobs.is_empty() {
        return false;
    }
    if !run.ops_heading {
        run.ops_heading = true;
        println!(
            "\nOperations a second, the time one takes, and the cycles \
             it costs."
        );
        println!("{:30}{:>12}{:>10}{:>14}", "", "ops/s", "each", "cycles");
    }
    println!("\n{title}");

    let budget = sample_budget(run.options.budget);
    let clock = &run.clock;
    let mut samples: Vec<Samples> = jobs
        .iter_mut()
        .map(|(_, call)| {
            Samples::calibrated(1.0, budget, &mut |batch| {
                time_calls(clock, batch, call)
            })
        })
        .collect();
    for _ in 0..SAMPLES {
        for ((_, call), samples) in jobs.iter_mut().zip(&mut samples) {
            samples.take(&mut |batch| time_calls(clock, batch, call));
        }
    }
    for ((name, _), samples) in jobs.iter().zip(samples) {
        let cell = samples.cell();
        println!("{}", ops_line(name, cell.as_ref()));
        run.rows.push(Row {
            section: title.to_string(),
            name,
            kind: Kind::Ops,
            cells: vec![(None, cell)],
        });
    }
    true
}

/// Whether any of `names` is wanted, so that a group can be skipped
/// before its keys are made.
fn any_wanted(title: &str, names: &[&str], options: &Options) -> bool {
    names.iter().any(|name| options.wants(title, name))
}

/// One row: the name, how many of the operation run in a second, how
/// long one takes, and the cycles it costs.
fn ops_line(name: &str, cell: Option<&Cell>) -> String {
    let mut line = format!("  {name:28}");
    let Some(cell) = cell else {
        let _ = write!(line, "{:>12}{:>10}{:>14}", "-", "-", "-");
        return line;
    };
    let rate = cell.rate;
    let _ = write!(
        line,
        "{:>11.1}{}{:>10}",
        rate.median,
        mark(rate.noisy()),
        per_call(1.0 / rate.median)
    );
    match cell.cycles {
        Some(cycles) => {
            let _ =
                write!(line, "{:>13.0}{}", cycles.median, mark(cycles.noisy()));
        }
        None => {
            let _ = write!(line, "{:>13} ", "-");
        }
    }
    line
}

/// Runs `batch` calls and reads the clocks around them.
fn time_calls(
    clock: &Clock,
    batch: u64,
    call: &mut Once<'_>,
) -> Option<Reading> {
    let start = clock.read()?;
    for _ in 0..batch {
        call();
    }
    Some(clock.read()?.since(start))
}

/// A duration in the unit that shows it best.
fn per_call(seconds: f64) -> String {
    if seconds >= 1.0 {
        format!("{seconds:.2} s")
    } else if seconds >= 1e-3 {
        format!("{:.2} ms", seconds * 1e3)
    } else {
        format!("{:.2} us", seconds * 1e6)
    }
}

const KDF_JOBS: [&str; 9] = [
    "hkdf-sha-256",
    "hkdf-sha-512",
    "pbkdf2-sha-256",
    "pbkdf2-sha-512",
    "tls12-prf-sha-256",
    "sp800-108-hmac-sha-256",
    "kdf-kmac128",
    "one-step-sha-256",
    "x963-sha-256",
];

/// Key derivation: one derivation of a 32-byte key, which is what a
/// caller asks for. HKDF's cost is two hashes of a short input;
/// PBKDF2's is its iteration count, and nothing else. The TLS 1.2
/// PRF is measured making a master secret, 48 bytes from two randoms.
fn kdf_ops(run: &mut Run) -> bool {
    if !any_wanted("kdf", &KDF_JOBS, &run.options) {
        return false;
    }
    let jobs: Vec<Job<'_>> = vec![
        (
            "hkdf-sha-256",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ = hkdf::derive::<sha2::Sha256>(
                    &KEY128,
                    &KEY256,
                    &[],
                    &mut out,
                );
                black_box(out);
            }) as Once<'_>,
        ),
        (
            "hkdf-sha-512",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ = hkdf::derive::<sha2::Sha512>(
                    &KEY128,
                    &KEY256,
                    &[],
                    &mut out,
                );
                black_box(out);
            }),
        ),
        (
            "pbkdf2-sha-256",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ = pbkdf2::pbkdf2::<sha2::Sha256>(
                    &KEY128, &KEY128, ITERATIONS, &mut out,
                );
                black_box(out);
            }),
        ),
        (
            "pbkdf2-sha-512",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ = pbkdf2::pbkdf2::<sha2::Sha512>(
                    &KEY128, &KEY128, ITERATIONS, &mut out,
                );
                black_box(out);
            }),
        ),
        (
            "tls12-prf-sha-256",
            Box::new(|| {
                let mut out = [0u8; 48];
                tls12::prf::<sha2::Sha256>(
                    &KEY256,
                    b"master secret",
                    &[&KEY256, &KEY256],
                    &mut out,
                );
                black_box(out);
            }),
        ),
        (
            "sp800-108-hmac-sha-256",
            Box::new(|| {
                let mut out = [0u8; 32];
                let mut prf = Hmac::<sha2::Sha256>::new(&KEY256);
                let _ = sp800_108::counter(
                    &mut prf,
                    32,
                    0,
                    &[b"label", &[0], &KEY128, &[0, 0, 1, 0]],
                    &mut out,
                );
                black_box(out);
            }),
        ),
        (
            "kdf-kmac128",
            Box::new(|| {
                let mut out = [0u8; 32];
                sp800_108::kmac128(&KEY256, b"label", &KEY128, &mut out);
                black_box(out);
            }),
        ),
        (
            "one-step-sha-256",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ = one_step::hash::<sha2::Sha256>(
                    &KEY256,
                    &[&KEY128, &[0, 0, 1, 0]],
                    &mut out,
                );
                black_box(out);
            }),
        ),
        (
            "x963-sha-256",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ =
                    x963::derive::<sha2::Sha256>(&KEY256, &[&KEY128], &mut out);
                black_box(out);
            }),
        ),
    ];
    ops_section(run, "kdf", jobs)
}

const KEX_JOBS: [&str; 8] = [
    "x25519-keygen",
    "x25519-agree",
    "ecdh-p256-keygen",
    "ecdh-p256-agree",
    "ecdh-p384-keygen",
    "ecdh-p384-agree",
    "ecdh-p521-keygen",
    "ecdh-p521-agree",
];

/// Key agreement: deriving a public key from a secret, and the
/// shared secret from a peer's.
fn kex_ops(run: &mut Run) -> bool {
    if !any_wanted("kex", &KEX_JOBS, &run.options) {
        return false;
    }
    // A generator each, since two rows draw at once and one
    // borrow of each is all a closure can hold.
    let (Ok(mut build), Ok(mut rng256), Ok(mut rng384), Ok(mut rng521)) =
        (seeded(), seeded(), seeded(), seeded())
    else {
        return false;
    };
    let secret = KEY256;
    let peer = x25519::public_key(&secret);
    let (Ok(p256), Ok(p256_peer), Ok(p384), Ok(p384_peer)) = (
        ecdh::p256::PrivateKey::generate(&mut build),
        ecdh::p256::PrivateKey::generate(&mut build),
        ecdh::p384::PrivateKey::generate(&mut build),
        ecdh::p384::PrivateKey::generate(&mut build),
    ) else {
        return false;
    };
    let (Ok(p521), Ok(p521_peer)) = (
        ecdh::p521::PrivateKey::generate(&mut build),
        ecdh::p521::PrivateKey::generate(&mut build),
    ) else {
        return false;
    };
    let p256_public = p256_peer.public_key();
    let p384_public = p384_peer.public_key();
    let p521_public = p521_peer.public_key();
    let jobs: Vec<Job<'_>> = vec![
        (
            "x25519-keygen",
            Box::new(|| {
                black_box(x25519::public_key(&secret));
            }) as Once<'_>,
        ),
        (
            "x25519-agree",
            Box::new(|| {
                black_box(x25519::shared_secret(&secret, &peer)).ok();
            }),
        ),
        (
            "ecdh-p256-keygen",
            Box::new(|| {
                black_box(ecdh::p256::PrivateKey::generate(&mut rng256)).ok();
            }),
        ),
        (
            "ecdh-p256-agree",
            Box::new(|| {
                black_box(p256.shared_secret(p256_public));
            }),
        ),
        (
            "ecdh-p384-keygen",
            Box::new(|| {
                black_box(ecdh::p384::PrivateKey::generate(&mut rng384)).ok();
            }),
        ),
        (
            "ecdh-p384-agree",
            Box::new(|| {
                black_box(p384.shared_secret(p384_public));
            }),
        ),
        (
            "ecdh-p521-keygen",
            Box::new(|| {
                black_box(ecdh::p521::PrivateKey::generate(&mut rng521)).ok();
            }),
        ),
        (
            "ecdh-p521-agree",
            Box::new(|| {
                black_box(p521.shared_secret(p521_public));
            }),
        ),
    ];
    ops_section(run, "kex", jobs)
}

const SIG_JOBS: [&str; 25] = [
    "ed25519-keygen",
    "ed25519-sign",
    "ed25519-sign-hedged",
    "ed25519-verify",
    "ecdsa-p256-keygen",
    "ecdsa-p256-sign",
    "ecdsa-p256-sign-hedged",
    "ecdsa-p256-verify",
    "ecdsa-p384-keygen",
    "ecdsa-p384-sign",
    "ecdsa-p384-sign-hedged",
    "ecdsa-p384-verify",
    "ecdsa-p521-keygen",
    "ecdsa-p521-sign",
    "ecdsa-p521-sign-hedged",
    "ecdsa-p521-verify",
    "rsa-2048-pkcs1-sign",
    "rsa-2048-pss-sign",
    "rsa-2048-pss-verify",
    "rsa-3072-pkcs1-sign",
    "rsa-3072-pss-sign",
    "rsa-3072-pss-verify",
    "rsa-4096-pkcs1-sign",
    "rsa-4096-pss-sign",
    "rsa-4096-pss-verify",
];

/// The signature schemes with a classical hardness assumption.
/// Signing dominates for RSA and verification for the curves, which
/// is the whole shape of the choice between them. The plain `sign`
/// rows are the deterministic form; the `hedged` rows add the draw
/// from the generator that `sign` makes, which is what a caller pays.
fn sig_ops(run: &mut Run) -> bool {
    if !any_wanted("sig", &SIG_JOBS, &run.options) {
        return false;
    }
    let (Ok(mut build), Ok(mut rng256), Ok(mut rng384), Ok(mut rng521)) =
        (seeded(), seeded(), seeded(), seeded())
    else {
        return false;
    };
    let (Ok(mut hedge25519), Ok(mut hedge256)) = (seeded(), seeded()) else {
        return false;
    };
    let (Ok(mut hedge384), Ok(mut hedge521)) = (seeded(), seeded()) else {
        return false;
    };
    let ed_secret = KEY256;
    let ed_key = ed25519::PrivateKey::new(&Key::from(ed_secret));
    let ed_public = ed_key.public_key().bytes();
    let ed_signature = ed_key.sign_deterministic(MESSAGE);
    let (Ok(p256), Ok(p384), Ok(p521)) = (
        ecdsa::p256::PrivateKey::generate(&mut build),
        ecdsa::p384::PrivateKey::generate(&mut build),
        ecdsa::p521::PrivateKey::generate(&mut build),
    ) else {
        return false;
    };
    let (Ok(sig256), Ok(sig384), Ok(sig521)) = (
        p256.sign_deterministic::<sha2::Sha256>(MESSAGE),
        p384.sign_deterministic::<sha2::Sha384>(MESSAGE),
        p521.sign_deterministic::<sha2::Sha512>(MESSAGE),
    ) else {
        return false;
    };
    // Generated only when one of their rows is wanted: a 4096-bit key
    // takes seconds to find.
    let mut rsa_keys = Vec::new();
    for bits in [2048, 3072, 4096] {
        if !SIG_JOBS.iter().any(|name| {
            name.starts_with(&format!("rsa-{bits}-"))
                && run.options.wants("sig", name)
        }) {
            continue;
        }
        let Ok(key) = rsa::PrivateKey::generate(&mut build, bits) else {
            return false;
        };
        let Ok(signature) =
            key.sign_pss_with_salt::<sha2::Sha256>(MESSAGE, &KEY256)
        else {
            return false;
        };
        rsa_keys.push((bits, key, signature));
    }
    let mut jobs: Vec<Job<'_>> = vec![
        (
            "ed25519-keygen",
            Box::new(|| {
                black_box(ed25519::public_key(&ed_secret));
            }) as Once<'_>,
        ),
        (
            "ed25519-sign",
            Box::new(|| {
                black_box(ed_key.sign_deterministic(MESSAGE));
            }),
        ),
        (
            "ed25519-sign-hedged",
            Box::new(|| {
                black_box(ed_key.sign(&mut hedge25519, MESSAGE)).ok();
            }),
        ),
        (
            "ed25519-verify",
            Box::new(|| {
                black_box(ed25519::verify(&ed_public, MESSAGE, &ed_signature))
                    .ok();
            }),
        ),
        (
            "ecdsa-p256-keygen",
            Box::new(|| {
                black_box(ecdsa::p256::PrivateKey::generate(&mut rng256)).ok();
            }),
        ),
        (
            "ecdsa-p256-sign",
            Box::new(|| {
                black_box(p256.sign_deterministic::<sha2::Sha256>(MESSAGE))
                    .ok();
            }),
        ),
        (
            "ecdsa-p256-sign-hedged",
            Box::new(|| {
                black_box(p256.sign::<sha2::Sha256, _>(&mut hedge256, MESSAGE))
                    .ok();
            }),
        ),
        (
            "ecdsa-p256-verify",
            Box::new(|| {
                black_box(
                    p256.public_key().verify::<sha2::Sha256>(MESSAGE, &sig256),
                )
                .ok();
            }),
        ),
        (
            "ecdsa-p384-keygen",
            Box::new(|| {
                black_box(ecdsa::p384::PrivateKey::generate(&mut rng384)).ok();
            }),
        ),
        (
            "ecdsa-p384-sign",
            Box::new(|| {
                black_box(p384.sign_deterministic::<sha2::Sha384>(MESSAGE))
                    .ok();
            }),
        ),
        (
            "ecdsa-p384-sign-hedged",
            Box::new(|| {
                black_box(p384.sign::<sha2::Sha384, _>(&mut hedge384, MESSAGE))
                    .ok();
            }),
        ),
        (
            "ecdsa-p384-verify",
            Box::new(|| {
                black_box(
                    p384.public_key().verify::<sha2::Sha384>(MESSAGE, &sig384),
                )
                .ok();
            }),
        ),
        (
            "ecdsa-p521-keygen",
            Box::new(|| {
                black_box(ecdsa::p521::PrivateKey::generate(&mut rng521)).ok();
            }),
        ),
        (
            "ecdsa-p521-sign",
            Box::new(|| {
                black_box(p521.sign_deterministic::<sha2::Sha512>(MESSAGE))
                    .ok();
            }),
        ),
        (
            "ecdsa-p521-sign-hedged",
            Box::new(|| {
                black_box(p521.sign::<sha2::Sha512, _>(&mut hedge521, MESSAGE))
                    .ok();
            }),
        ),
        (
            "ecdsa-p521-verify",
            Box::new(|| {
                black_box(
                    p521.public_key().verify::<sha2::Sha512>(MESSAGE, &sig521),
                )
                .ok();
            }),
        ),
    ];
    for (bits, key, signature) in &rsa_keys {
        jobs.extend(rsa_rows(*bits, key, signature.as_ref()));
    }
    ops_section(run, "sig", jobs)
}

/// The three RSA rows at one width, under the names `SIG_JOBS` gives
/// them, which list them in this order.
fn rsa_rows<'a>(
    bits: usize,
    key: &'a rsa::PrivateKey,
    signature: &'a [u8],
) -> Vec<Job<'a>> {
    let prefix = format!("rsa-{bits}-");
    let names: Vec<&'static str> = SIG_JOBS
        .iter()
        .copied()
        .filter(|name| name.starts_with(&prefix))
        .collect();
    let [pkcs1, pss, verify] = names[..] else {
        return Vec::new();
    };
    vec![
        (
            pkcs1,
            Box::new(move || {
                black_box(key.sign_pkcs1::<sha2::Sha256>(MESSAGE)).ok();
            }) as Once<'_>,
        ),
        (
            pss,
            Box::new(move || {
                black_box(
                    key.sign_pss_with_salt::<sha2::Sha256>(MESSAGE, &KEY256),
                )
                .ok();
            }),
        ),
        (
            verify,
            Box::new(move || {
                black_box(
                    key.public_key().verify_pss_with_salt_len::<sha2::Sha256>(
                        MESSAGE,
                        signature,
                        KEY256.len(),
                    ),
                )
                .ok();
            }),
        ),
    ]
}

/// A post-quantum signing key and one signature from it, bound in
/// the caller's scope so that the rows below can share them. Keys
/// are bound before the job list, since the closures borrow them.
macro_rules! pq_sig_key {
    ($key:ident, $signature:ident, $build:expr, $private:ty) => {
        let Ok($key) = <$private>::generate($build) else {
            return false;
        };
        let Ok($signature) = $key.sign_deterministic(&[], MESSAGE) else {
            return false;
        };
    };
}

/// The three rows for one parameter set.
macro_rules! pq_sig_rows {
    ($jobs:expr, $key:ident, $signature:ident, $rng:expr, $private:ty,
     $name:literal) => {
        $jobs.push((
            concat!($name, "-keygen"),
            Box::new(|| {
                black_box(<$private>::generate($rng)).ok();
            }) as Once<'_>,
        ));
        $jobs.push((
            concat!($name, "-sign"),
            Box::new(|| {
                black_box($key.sign_deterministic(&[], MESSAGE)).ok();
            }),
        ));
        $jobs.push((
            concat!($name, "-verify"),
            Box::new(|| {
                black_box($key.public_key().verify(&[], MESSAGE, &$signature))
                    .ok();
            }),
        ));
    };
}

const PQ_SIG_JOBS: [&str; 7] = [
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "slh-dsa-sha2-128s",
    "slh-dsa-sha2-128f",
    "slh-dsa-shake-128s",
    "slh-dsa-shake-128f",
];

/// The post-quantum signature schemes. Signing is measured in its
/// deterministic form, which is the same work as the hedged one
/// without a draw from the generator in the middle of it. SLH-DSA
/// has twelve parameter sets; the four here are the small and the
/// fast end of the 128-bit ones over each hash, SHA-2 and SHAKE, and
/// the rest fall between the pattern they show.
fn pq_sig_ops(run: &mut Run) -> bool {
    if !PQ_SIG_JOBS
        .iter()
        .any(|name| any_wanted("sig-pq", &[name], &run.options))
    {
        return false;
    }
    let (Ok(mut build), Ok(mut r1), Ok(mut r2), Ok(mut r3)) =
        (seeded(), seeded(), seeded(), seeded())
    else {
        return false;
    };
    let (Ok(mut r4), Ok(mut r5), Ok(mut r6), Ok(mut r7)) =
        (seeded(), seeded(), seeded(), seeded())
    else {
        return false;
    };
    pq_sig_key!(
        mldsa44,
        mldsa44_sig,
        &mut build,
        crate::sig::ml_dsa::ml_dsa_44::PrivateKey
    );
    pq_sig_key!(
        mldsa65,
        mldsa65_sig,
        &mut build,
        crate::sig::ml_dsa::ml_dsa_65::PrivateKey
    );
    pq_sig_key!(
        mldsa87,
        mldsa87_sig,
        &mut build,
        crate::sig::ml_dsa::ml_dsa_87::PrivateKey
    );
    pq_sig_key!(
        slh128s,
        slh128s_sig,
        &mut build,
        crate::sig::slh_dsa::sha2_128s::PrivateKey
    );
    pq_sig_key!(
        slh128f,
        slh128f_sig,
        &mut build,
        crate::sig::slh_dsa::sha2_128f::PrivateKey
    );
    pq_sig_key!(
        shake128s,
        shake128s_sig,
        &mut build,
        crate::sig::slh_dsa::shake_128s::PrivateKey
    );
    pq_sig_key!(
        shake128f,
        shake128f_sig,
        &mut build,
        crate::sig::slh_dsa::shake_128f::PrivateKey
    );
    let mut jobs: Vec<Job<'_>> = Vec::new();
    pq_sig_rows!(
        jobs,
        mldsa44,
        mldsa44_sig,
        &mut r1,
        crate::sig::ml_dsa::ml_dsa_44::PrivateKey,
        "ml-dsa-44"
    );
    pq_sig_rows!(
        jobs,
        mldsa65,
        mldsa65_sig,
        &mut r2,
        crate::sig::ml_dsa::ml_dsa_65::PrivateKey,
        "ml-dsa-65"
    );
    pq_sig_rows!(
        jobs,
        mldsa87,
        mldsa87_sig,
        &mut r3,
        crate::sig::ml_dsa::ml_dsa_87::PrivateKey,
        "ml-dsa-87"
    );
    pq_sig_rows!(
        jobs,
        slh128s,
        slh128s_sig,
        &mut r4,
        crate::sig::slh_dsa::sha2_128s::PrivateKey,
        "slh-dsa-sha2-128s"
    );
    pq_sig_rows!(
        jobs,
        slh128f,
        slh128f_sig,
        &mut r5,
        crate::sig::slh_dsa::sha2_128f::PrivateKey,
        "slh-dsa-sha2-128f"
    );
    pq_sig_rows!(
        jobs,
        shake128s,
        shake128s_sig,
        &mut r6,
        crate::sig::slh_dsa::shake_128s::PrivateKey,
        "slh-dsa-shake-128s"
    );
    pq_sig_rows!(
        jobs,
        shake128f,
        shake128f_sig,
        &mut r7,
        crate::sig::slh_dsa::shake_128f::PrivateKey,
        "slh-dsa-shake-128f"
    );
    ops_section(run, "sig-pq", jobs)
}

/// An ML-KEM key and one ciphertext under it, likewise.
macro_rules! kem_key {
    ($key:ident, $ciphertext:ident, $build:expr, $private:ty) => {
        let Ok($key) = <$private>::generate($build) else {
            return false;
        };
        let Ok(($ciphertext, _)) = $key.public_key().encapsulate($build) else {
            return false;
        };
    };
}

/// The three rows for one parameter set.
macro_rules! kem_rows {
    ($jobs:expr, $key:ident, $ciphertext:ident, $keygen:expr, $encap:expr,
     $private:ty, $name:literal) => {
        $jobs.push((
            concat!($name, "-keygen"),
            Box::new(|| {
                black_box(<$private>::generate($keygen)).ok();
            }) as Once<'_>,
        ));
        $jobs.push((
            concat!($name, "-encapsulate"),
            Box::new(|| {
                black_box($key.public_key().encapsulate($encap)).ok();
            }),
        ));
        $jobs.push((
            concat!($name, "-decapsulate"),
            Box::new(|| {
                black_box($key.decapsulate(&$ciphertext));
            }),
        ));
    };
}

const KEM_JOBS: [&str; 3] = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"];

/// Key encapsulation, the three parameter sets.
fn kem_ops(run: &mut Run) -> bool {
    if !KEM_JOBS
        .iter()
        .any(|name| any_wanted("kem", &[name], &run.options))
    {
        return false;
    }
    let (Ok(mut build), Ok(mut k1), Ok(mut e1), Ok(mut k2)) =
        (seeded(), seeded(), seeded(), seeded())
    else {
        return false;
    };
    let (Ok(mut e2), Ok(mut k3), Ok(mut e3)) = (seeded(), seeded(), seeded())
    else {
        return false;
    };
    kem_key!(
        kem512,
        kem512_ct,
        &mut build,
        crate::kem::ml_kem::ml_kem_512::PrivateKey
    );
    kem_key!(
        kem768,
        kem768_ct,
        &mut build,
        crate::kem::ml_kem::ml_kem_768::PrivateKey
    );
    kem_key!(
        kem1024,
        kem1024_ct,
        &mut build,
        crate::kem::ml_kem::ml_kem_1024::PrivateKey
    );
    let mut jobs: Vec<Job<'_>> = Vec::new();
    kem_rows!(
        jobs,
        kem512,
        kem512_ct,
        &mut k1,
        &mut e1,
        crate::kem::ml_kem::ml_kem_512::PrivateKey,
        "ml-kem-512"
    );
    kem_rows!(
        jobs,
        kem768,
        kem768_ct,
        &mut k2,
        &mut e2,
        crate::kem::ml_kem::ml_kem_768::PrivateKey,
        "ml-kem-768"
    );
    kem_rows!(
        jobs,
        kem1024,
        kem1024_ct,
        &mut k3,
        &mut e3,
        crate::kem::ml_kem::ml_kem_1024::PrivateKey,
        "ml-kem-1024"
    );
    ops_section(run, "kem", jobs)
}

const PKE_JOBS: [&str; 4] = [
    "rsa-2048-oaep-encrypt",
    "rsa-2048-oaep-decrypt",
    "hpke-x25519-seal",
    "hpke-x25519-open",
];

/// The HPKE suite measured: X25519, HKDF-SHA256 and AES-128-GCM.
type HpkeContext = hpke::Context<sha2::Sha256, Gcm<aes::Aes128>>;

/// Public-key encryption. The encryption key is a different type
/// from the signing one, since a key does one job. An HPKE row is a
/// whole single-shot message: setting up the context, which is the
/// key agreement and the schedule, then one short message through it.
fn pke_ops(run: &mut Run) -> bool {
    if !any_wanted("pke", &PKE_JOBS, &run.options) {
        return false;
    }
    let (Ok(mut build), Ok(mut rng), Ok(mut ephemeral)) =
        (seeded(), seeded(), seeded())
    else {
        return false;
    };
    let Ok(key) = oaep::PrivateKey::generate(&mut build, 2048) else {
        return false;
    };
    let Ok(recipient) = hpke::x25519::PrivateKey::generate(&mut build) else {
        return false;
    };
    let recipient_public = *recipient.public_key();
    let Ok((enc, mut context)) = recipient_public
        .sender::<sha2::Sha256, Gcm<aes::Aes128>, _>(&mut build, b"bench")
    else {
        return false;
    };
    let mut sealed = MESSAGE.to_vec();
    let mut sealed_tag = [0u8; hpke::TAG_SIZE];
    if context.encrypt(&[], &mut sealed, &mut sealed_tag).is_err() {
        return false;
    }
    let Ok(ciphertext) = key.public_key().encrypt_oaep::<sha2::Sha256, _>(
        &mut build,
        &[],
        MESSAGE,
    ) else {
        return false;
    };
    let jobs: Vec<Job<'_>> = vec![
        (
            "rsa-2048-oaep-encrypt",
            Box::new(|| {
                black_box(key.public_key().encrypt_oaep::<sha2::Sha256, _>(
                    &mut rng,
                    &[],
                    MESSAGE,
                ))
                .ok();
            }) as Once<'_>,
        ),
        (
            "rsa-2048-oaep-decrypt",
            Box::new(|| {
                let mut out = [0u8; 256];
                black_box(key.decrypt_oaep::<sha2::Sha256>(
                    &[],
                    ciphertext.as_ref(),
                    &mut out,
                ))
                .ok();
            }),
        ),
        (
            "hpke-x25519-seal",
            Box::new(|| {
                let sent: Result<(_, HpkeContext), _> =
                    recipient_public.sender(&mut ephemeral, b"bench");
                let Ok((enc, mut context)) = sent else {
                    return;
                };
                let mut data = [0u8; MESSAGE.len()];
                data.copy_from_slice(MESSAGE);
                let mut tag = [0u8; hpke::TAG_SIZE];
                context.encrypt(&[], &mut data, &mut tag).ok();
                black_box((enc, data, tag));
            }),
        ),
        (
            "hpke-x25519-open",
            Box::new(|| {
                let opened: Result<HpkeContext, _> =
                    recipient.recipient(&enc, b"bench");
                let Ok(mut context) = opened else {
                    return;
                };
                let mut data = [0u8; MESSAGE.len()];
                data.copy_from_slice(&sealed);
                context.decrypt(&[], &mut data, &sealed_tag).ok();
                black_box(data);
            }),
        ),
    ];
    ops_section(run, "pke", jobs)
}

const FPE_JOBS: [&str; 2] = ["ff1-radix10", "ff3-1-radix10"];

/// The format-preserving modes, which work on a string of symbols
/// rather than on bytes: sixteen decimal digits, a card number's
/// worth, which is what they exist for.
fn fpe_ops(run: &mut Run) -> bool {
    if !any_wanted("fpe", &FPE_JOBS, &run.options) {
        return false;
    }
    let (Ok(ff1), Ok(ff3)) = (
        Ff1::<aes::Aes<16>>::try_new(&Key::from(KEY128), 10),
        Ff3_1::<aes::Aes<16>>::try_new(&Key::from(KEY128), 10),
    ) else {
        return false;
    };
    let mut digits = [0u16; DIGITS];
    for (i, d) in digits.iter_mut().enumerate() {
        *d = (i % 10) as u16;
    }
    let mut ff1_digits = digits;
    let mut ff3_digits = digits;
    let jobs: Vec<Job<'_>> = vec![
        (
            "ff1-radix10",
            Box::new(move || {
                let _ = ff1.encrypt(&[], &mut ff1_digits);
                black_box(&ff1_digits);
            }) as Once<'_>,
        ),
        (
            "ff3-1-radix10",
            Box::new(move || {
                let _ = ff3.encrypt(&FF3_TWEAK, &mut ff3_digits);
                black_box(&ff3_digits);
            }),
        ),
    ];
    ops_section(run, "fpe", jobs)
}

/// The rows, in the order they are printed. Kept beside the tasks
/// they name so that a filter can be applied before any key is
/// expanded, which is what lets an unsupported implementation be
/// skipped silently.
const ALGORITHMS: [&str; 23] = [
    "aes-128-ecb-enc",
    "aes-128-ecb-dec",
    "aes-256-ecb-enc",
    "aes-128-cbc-enc",
    "aes-128-cbc-dec",
    "aes-128-cfb1-enc",
    "aes-128-cfb8-enc",
    "aes-128-cfb128-enc",
    "aes-128-ofb",
    "aes-128-ctr",
    "aes-256-ctr",
    "aes-128-gmac",
    "aes-128-gcm-enc",
    "aes-128-gcm-dec",
    "aes-256-gcm-enc",
    "aes-128-gcm-siv-enc",
    "aes-128-xpn-enc",
    "aes-128-ccm-enc",
    "aes-128-xts-enc",
    "aes-128-xts-dec",
    "aes-128-kw-wrap",
    "aes-128-kwp-wrap",
    "aes-128-cmac",
];

/// Everything an implementation's rows are built from, held together
/// so that the borrows in [`Keys::tasks`] all have one owner.
struct Keys<
    A: BlockCipher<Block = [u8; 16], Key = Key<[u8; 16]>>,
    B: BlockCipher<Block = [u8; 16], Key = Key<[u8; 32]>>,
> {
    ecb128: A,
    ecb256: B,
    cbc: Option<Cbc<A>>,
    cfb1: Cfb1<A>,
    cfb8: Cfb8<A>,
    cfb128: Cfb128<A>,
    ofb: Ofb<A>,
    ctr: Option<Ctr<A>>,
    ctr256: Option<Ctr<B>>,
    gcm128: Option<Gcm<A>>,
    gcm256: Option<Gcm<B>>,
    siv: Option<GcmSiv<A>>,
    xpn: Option<Xpn<A>>,
    ccm: Option<Ccm<A>>,
    xts: Option<Xts<A>>,
    kw: Kw<A>,
    kwp: Kwp<A>,
    cmac: Cmac<A>,
    /// Room for a wrapped key, one buffer for each of the two rows
    /// that writes one: the largest input and the eight bytes of
    /// check value that go on the end of it.
    wrapped: [Vec<u8>; 2],
    /// A tag buffer for each row that writes one; separate buffers so
    /// the rows borrow disjointly.
    tags: [[u8; 16]; 6],
}

/// Key material. Fixed rather than drawn, so that a run repeats.
const KEY128: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff,
];
const KEY256: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];
/// XTS takes two keys, and they must differ.
const KEY_XTS_DATA: [u8; 16] = KEY128;
const KEY_XTS_TWEAK: [u8; 16] = [0x99; 16];
const NONCE: [u8; 12] = [0xa5; 12];
/// XPN builds its nonce from a salt and a frame number, both of
/// them the width of a short GCM nonce.
const SALT: [u8; 12] = [0x11; 12];
const IV: [u8; 16] = [0x5a; 16];
const TWEAK: [u8; 16] = [0x3c; 16];
/// The tag a decryption is checked against. It will not match after
/// the first iteration, which costs a comparison and changes nothing
/// else: the keystream and the hash are the same work either way, and
/// going through the streaming type rather than `Gcm::decrypt` keeps
/// the wipe on a bad tag out of the measurement.
const CHECKED_TAG: [u8; 16] = [0; 16];

impl<A, B> Keys<A, B>
where
    A: BlockCipher<Block = [u8; 16], Key = Key<[u8; 16]>>,
    B: BlockCipher<Block = [u8; 16], Key = Key<[u8; 32]>>,
{
    /// The keys for one implementation.
    ///
    /// A mode written out for particular instructions is built on
    /// those and no others, so that a row appears under the name of
    /// the code that ran it. Where a mode has nothing written for
    /// them it yields `None`, and its rows are left out of the
    /// section rather than filled in with something else.
    fn try_new(implementation: Implementation) -> Result<Self, Error> {
        let k128 = Key::from(KEY128);
        let k256 = Key::from(KEY256);
        Ok(Keys {
            ecb128: A::new(&k128),
            ecb256: B::new(&k256),
            cbc: Cbc::with_implementation(&k128, implementation),
            cfb1: Cfb1::new(&k128),
            cfb8: Cfb8::new(&k128),
            cfb128: Cfb128::new(&k128),
            ofb: Ofb::new(&k128),
            ctr: Ctr::with_implementation(&k128, implementation),
            ctr256: Ctr::with_implementation(&k256, implementation),
            gcm128: Gcm::with_implementation(&k128, implementation),
            gcm256: Gcm::with_implementation(&k256, implementation),
            siv: GcmSiv::with_implementation(&k128, implementation),
            xpn: Xpn::with_implementation(&k128, implementation),
            ccm: Ccm::with_implementation(&k128, implementation),
            xts: Xts::with_implementation(
                &Key::from(KEY_XTS_DATA),
                &Key::from(KEY_XTS_TWEAK),
                implementation,
            ),
            kw: Kw::new(&k128),
            kwp: Kwp::new(&k128),
            cmac: Cmac::new(&k128),
            wrapped: [
                vec![0u8; SIZES[SIZES.len() - 1] + 8],
                vec![0u8; SIZES[SIZES.len() - 1] + 8],
            ],
            tags: [[0u8; 16]; 6],
        })
    }

    /// One closure per row. Results are discarded: every call here is
    /// given arguments it accepts, and a mode that started failing
    /// would show as an impossible rate rather than pass unnoticed.
    fn tasks(&mut self) -> Vec<Task<'_>> {
        let Keys {
            ecb128,
            ecb256,
            cbc,
            cfb1,
            cfb8,
            cfb128,
            ofb,
            ctr,
            ctr256,
            gcm128,
            gcm256,
            siv,
            xpn,
            ccm,
            xts,
            kw,
            kwp,
            cmac,
            wrapped,
            tags,
        } = self;
        // Split so that each row that writes a tag borrows its own.
        let (gmac_tag, tags) = tags.split_first_mut().expect("six tags");
        let (gcm_tag, tags) = tags.split_first_mut().expect("five tags");
        let (gcm256_tag, tags) = tags.split_first_mut().expect("four tags");
        let (siv_tag, tags) = tags.split_first_mut().expect("three tags");
        let (xpn_tag, tags) = tags.split_first_mut().expect("two tags");
        let (ccm_tag, _) = tags.split_first_mut().expect("one tag");
        let (kw_out, wrapped) = wrapped.split_first_mut().expect("two buffers");
        let (kwp_out, _) = wrapped.split_first_mut().expect("one buffer");
        let mut tasks: Vec<Task<'_>> = Vec::new();
        tasks.push((
            "aes-128-ecb-enc",
            Box::new(|d: &mut [u8]| {
                ecb128.encrypt(blocks_of(d));
            }) as Operation<'_>,
        ));
        tasks.push((
            "aes-128-ecb-dec",
            Box::new(|d: &mut [u8]| {
                ecb128.decrypt(blocks_of(d));
            }),
        ));
        tasks.push((
            "aes-256-ecb-enc",
            Box::new(|d: &mut [u8]| {
                ecb256.encrypt(blocks_of(d));
            }),
        ));
        if let Some(cbc) = cbc {
            tasks.push((
                "aes-128-cbc-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = cbc.encrypt(&IV, d);
                }),
            ));
            tasks.push((
                "aes-128-cbc-dec",
                Box::new(|d: &mut [u8]| {
                    let _ = cbc.decrypt(&IV, d);
                }),
            ));
        }
        // A bit at a time, which is what the mode is for and
        // why it is the slowest row here.
        tasks.push((
            "aes-128-cfb1-enc",
            Box::new(|d: &mut [u8]| {
                let bits = d.len() * 8;
                let _ = cfb1.encrypt(&IV, d, bits);
            }),
        ));
        tasks.push((
            "aes-128-cfb8-enc",
            Box::new(|d: &mut [u8]| {
                cfb8.encrypt(&IV, d);
            }),
        ));
        tasks.push((
            "aes-128-cfb128-enc",
            Box::new(|d: &mut [u8]| {
                let _ = cfb128.encrypt(&IV, d);
            }),
        ));
        tasks.push((
            "aes-128-ofb",
            Box::new(|d: &mut [u8]| {
                ofb.encrypt(&IV, d);
            }),
        ));
        if let Some(ctr) = ctr {
            tasks.push((
                "aes-128-ctr",
                Box::new(|d: &mut [u8]| {
                    ctr.encrypt(&IV, d);
                }),
            ));
        }
        if let Some(ctr256) = ctr256 {
            tasks.push((
                "aes-256-ctr",
                Box::new(|d: &mut [u8]| {
                    ctr256.encrypt(&IV, d);
                }),
            ));
        }
        if let Some(gcm128) = gcm128 {
            // The buffer is the additional data and the message is
            // empty, which is GHASH and nothing else.
            tasks.push((
                "aes-128-gmac",
                Box::new(|d: &mut [u8]| {
                    let _ = gcm128.encrypt(&NONCE, d, &mut [], gmac_tag);
                }),
            ));
            tasks.push((
                "aes-128-gcm-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = gcm128.encrypt(&NONCE, &[], d, gcm_tag);
                }),
            ));
            tasks.push((
                "aes-128-gcm-dec",
                Box::new(|d: &mut [u8]| {
                    let Ok(mut state) = gcm128.decryptor(&NONCE) else {
                        return;
                    };
                    let _ = state.update(d);
                    let _ = state.verify(&CHECKED_TAG);
                }),
            ));
        }
        if let Some(gcm256) = gcm256 {
            tasks.push((
                "aes-256-gcm-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = gcm256.encrypt(&NONCE, &[], d, gcm256_tag);
                }),
            ));
        }
        if let Some(siv) = siv {
            tasks.push((
                "aes-128-gcm-siv-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = siv.encrypt(&NONCE, &[], d, siv_tag);
                }),
            ));
        }
        if let Some(xpn) = xpn {
            tasks.push((
                "aes-128-xpn-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = xpn.encrypt(&SALT, &NONCE, &[], d, xpn_tag);
                }),
            ));
        }
        if let Some(ccm) = ccm {
            tasks.push((
                "aes-128-ccm-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = ccm.encrypt(&NONCE, &[], d, ccm_tag);
                }),
            ));
        }
        if let Some(xts) = xts {
            tasks.push((
                "aes-128-xts-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = xts.encrypt(&TWEAK, d);
                }),
            ));
            tasks.push((
                "aes-128-xts-dec",
                Box::new(|d: &mut [u8]| {
                    let _ = xts.decrypt(&TWEAK, d);
                }),
            ));
        }
        // Wrapping writes eight bytes more than it reads, so
        // these two write into a buffer of their own.
        tasks.push((
            "aes-128-kw-wrap",
            Box::new(|d: &mut [u8]| {
                let _ = kw.wrap(d, &mut kw_out[..d.len() + 8]);
            }),
        ));
        tasks.push((
            "aes-128-kwp-wrap",
            Box::new(|d: &mut [u8]| {
                let _ = kwp.wrap(d, &mut kwp_out[..d.len() + 8]);
            }),
        ));
        tasks.push((
            "aes-128-cmac",
            Box::new(|d: &mut [u8]| {
                cmac.update(d);
                black_box(cmac.finalize());
            }),
        ));
        tasks
    }
}

/// The whole blocks of `data`. Every size the benchmark uses is a
/// multiple of the block, so nothing is ever left over.
fn blocks_of(data: &mut [u8]) -> &mut [[u8; 16]] {
    let (blocks, rest) = data.as_chunks_mut::<16>();
    debug_assert!(rest.is_empty());
    blocks
}

/// The column headings, the buffer sizes. Each sits over the digits
/// below it, which leave their last column to the noise mark.
fn heading() -> String {
    let mut line = format!("{:24}", "");
    for size in SIZES {
        let _ = write!(line, "{size:>8} ");
    }
    line
}

/// Measures every task of one section at every size, prints the
/// table and keeps the rows.
///
/// The cells are calibrated first, then sampled in rounds: one sample
/// of every cell, then another, until each has [`SAMPLES`]. A row
/// measured whole before the next would carry whatever the clock was
/// doing during its own second; spread across the section, the drift
/// lands on every row alike.
fn throughput_table(run: &mut Run, section: &str, tasks: &mut [Task<'_>]) {
    println!("\n{section}");
    println!("{}", heading());

    let budget = sample_budget(run.options.budget);
    let clock = &run.clock;
    let mut grid: Vec<Vec<Option<Measured>>> = tasks
        .iter_mut()
        .map(|(_, operation)| {
            SIZES
                .iter()
                .map(|&size| {
                    Measured::calibrated(clock, size, budget, operation)
                })
                .collect()
        })
        .collect();
    for _ in 0..SAMPLES {
        for ((_, operation), cells) in tasks.iter_mut().zip(&mut grid) {
            for measured in cells.iter_mut().flatten() {
                measured.take(clock, operation);
            }
        }
    }
    for ((name, _), cells) in tasks.iter().zip(grid) {
        let cells: Vec<(Option<usize>, Option<Cell>)> = SIZES
            .iter()
            .zip(cells)
            .map(|(&size, measured)| {
                (Some(size), measured.and_then(|m| m.samples.cell()))
            })
            .collect();
        print!("{}", throughput_lines(name, &cells));
        run.rows.push(Row {
            section: section.to_string(),
            name,
            kind: Kind::Throughput,
            cells,
        });
    }
}

/// One cell under measurement: its buffer and the samples so far.
struct Measured {
    buffer: Buffer,
    samples: Samples,
}

impl Measured {
    /// A cell with its batch found, or `None` where there is no
    /// memory for the buffer.
    fn calibrated(
        clock: &Clock,
        size: usize,
        budget: Duration,
        operation: &mut Operation<'_>,
    ) -> Option<Self> {
        let mut buffer = Buffer::try_new(size)?;
        let samples = Samples::calibrated(size as f64, budget, &mut |batch| {
            time_batch(clock, batch, &mut buffer, operation)
        });
        Some(Measured { buffer, samples })
    }

    /// Takes one sample.
    fn take(&mut self, clock: &Clock, operation: &mut Operation<'_>) {
        let Measured { buffer, samples } = self;
        samples.take(&mut |batch| time_batch(clock, batch, buffer, operation));
    }
}

/// The lines of one row: cycles a byte where the counter is open, and
/// megabytes a second beneath, under the same columns.
fn throughput_lines(
    name: &str,
    cells: &[(Option<usize>, Option<Cell>)],
) -> String {
    let mut text = String::new();
    let cycles: Vec<Option<Summary>> = cells
        .iter()
        .map(|(_, cell)| cell.as_ref().and_then(|cell| cell.cycles))
        .collect();
    let mut label = format!("  {name:20}");
    if cycles.iter().any(Option::is_some) {
        let _ = write!(text, "{label}{:>4}", "cpb");
        for summary in &cycles {
            figure(&mut text, summary.as_ref(), |s| s.median, 2);
        }
        text.push('\n');
        label = format!("  {:20}", "");
    }
    let _ = write!(text, "{label}{:>4}", "MB/s");
    for (_, cell) in cells {
        let rate = cell.as_ref().map(|cell| &cell.rate);
        figure(&mut text, rate, |s| s.median / 1e6, 1);
    }
    text.push('\n');
    text
}

/// One figure of a row, or a dash where the clock refused, which is
/// the same answer at every size, so it is said once per cell rather
/// than by giving up the row.
fn figure(
    text: &mut String,
    summary: Option<&Summary>,
    value: impl Fn(&Summary) -> f64,
    decimals: usize,
) {
    match summary {
        Some(summary) => {
            let _ = write!(
                text,
                "{:>8.*}{}",
                decimals,
                value(summary),
                mark(summary.noisy())
            );
        }
        None => {
            let _ = write!(text, "{:>8} ", "-");
        }
    }
}

/// The noise mark, or the space that holds its column.
fn mark(noisy: bool) -> char {
    if noisy { '*' } else { ' ' }
}

/// Runs `batch` iterations over `buffer` and reads the clocks around
/// them, so their own cost is divided by the batch.
fn time_batch(
    clock: &Clock,
    batch: u64,
    buffer: &mut [u8],
    operation: &mut Operation<'_>,
) -> Option<Reading> {
    let start = clock.read()?;
    for _ in 0..batch {
        // Hides the buffer from the optimiser going in and its
        // contents coming out. Without this a mode whose result is
        // discarded is dead code, and with the release profile's
        // link-time optimisation it would be removed.
        operation(black_box(buffer));
        black_box(&buffer);
    }
    Some(clock.read()?.since(start))
}

/// CPU time one sample runs for: the cell's budget shared among the
/// samples, and never less than a calibration batch, so that a quick
/// sweep still divides the clock's cost by enough work.
fn sample_budget(budget: Duration) -> Duration {
    (budget / SAMPLES as u32).max(CALIBRATION)
}

/// Chooses how many iterations to time at once: the smallest power of
/// two whose run reaches `target`.
///
/// Separated from the clock so it can be checked against a made-up
/// one. An operation too quick to reach the target within
/// [`MAX_BATCH`] stops there rather than doubling forever.
fn calibrate(target: Duration, mut once: impl FnMut(u64) -> Duration) -> u64 {
    let mut batch: u64 = 1;
    while batch < MAX_BATCH {
        if once(batch) >= target {
            break;
        }
        batch *= 2;
    }
    batch
}

/// A cell's samples, gathered one round at a time.
///
/// The batch is chosen first, by doubling until a batch lasts
/// [`CALIBRATION`], which also serves as the warm-up: by the time the
/// first sample starts the buffer is resident and the processor has
/// settled. Each sample then runs batches until it has used its
/// budget and becomes one figure: the units a second it saw, and the
/// cycles a unit where the counter is open.
struct Samples {
    batch: u64,
    /// Units of work an iteration does: the bytes, or one operation.
    units: f64,
    budget: Duration,
    rates: Vec<f64>,
    cycles: Vec<f64>,
    hertz: Vec<f64>,
    /// Whether a clock refused or stood still, which spoils the cell.
    failed: bool,
}

impl Samples {
    fn calibrated(
        units: f64,
        budget: Duration,
        run: &mut dyn FnMut(u64) -> Option<Reading>,
    ) -> Self {
        let batch = calibrate(CALIBRATION, |batch| {
            run(batch).map_or(Duration::from_secs(1), |reading| reading.time)
        });
        Samples {
            batch,
            units,
            budget,
            rates: Vec::with_capacity(SAMPLES),
            cycles: Vec::with_capacity(SAMPLES),
            hertz: Vec::with_capacity(SAMPLES),
            failed: false,
        }
    }

    /// Takes one sample.
    fn take(&mut self, run: &mut dyn FnMut(u64) -> Option<Reading>) {
        if self.failed {
            return;
        }
        let mut iterations: u64 = 0;
        let mut elapsed = Reading {
            time: Duration::ZERO,
            cycles: Some(0),
        };
        while elapsed.time < self.budget {
            // A batch that took no time at all is a clock too coarse
            // to see the work; waiting for it to add up would never
            // end.
            let Some(reading) = run(self.batch).filter(|r| !r.time.is_zero())
            else {
                self.failed = true;
                return;
            };
            elapsed = elapsed.plus(reading);
            iterations = iterations.saturating_add(self.batch);
        }
        let units = iterations as f64 * self.units;
        let seconds = elapsed.time.as_secs_f64();
        self.rates.push(units / seconds);
        if let Some(cycles) = elapsed.cycles {
            self.cycles.push(cycles as f64 / units);
            self.hertz.push(cycles as f64 / seconds);
        }
    }

    /// What the samples say, or `None` where a clock refused or
    /// nothing was sampled.
    fn cell(&self) -> Option<Cell> {
        if self.failed {
            return None;
        }
        let rate = summarize(&self.rates).filter(|rate| rate.median > 0.0)?;
        Some(Cell {
            rate,
            cycles: summarize(&self.cycles),
            ghz: summarize(&self.hertz).map(|hertz| hertz.median / 1e9),
        })
    }
}

/// One measured figure: units a second, cycles a unit where the
/// counter is open, and the clock rate the two together imply.
struct Cell {
    rate: Summary,
    cycles: Option<Summary>,
    ghz: Option<f64>,
}

/// What a set of samples says: the middle one, the extremes, and how
/// far apart the middle half sit as a fraction of the median.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Summary {
    median: f64,
    min: f64,
    max: f64,
    spread: f64,
    samples: usize,
}

impl Summary {
    /// Whether the middle half of the samples disagree by more than
    /// [`NOISY`]. An interrupt or a neighbour on the other thread of
    /// the core only ever slows a sample, so the median holds while
    /// the spread says how often it happened.
    fn noisy(&self) -> bool {
        self.spread > NOISY
    }
}

/// Summarises samples, or `None` where there are none. The quartiles
/// are the samples a quarter and three quarters of the way up, which
/// for [`SAMPLES`] of them is exact enough.
fn summarize(values: &[f64]) -> Option<Summary> {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let median = median(&sorted)?;
    let (low, high) = (sorted[sorted.len() / 4], sorted[sorted.len() * 3 / 4]);
    let spread = if median > 0.0 {
        (high - low) / median
    } else {
        0.0
    };
    Some(Summary {
        median,
        min: sorted[0],
        max: sorted[sorted.len() - 1],
        spread,
        samples: sorted.len(),
    })
}

/// The middle of sorted values: the middle one, or the mean of the
/// middle two.
fn median(sorted: &[f64]) -> Option<f64> {
    let n = sorted.len();
    match n {
        0 => None,
        _ if n % 2 == 1 => Some(sorted[n / 2]),
        _ => Some((sorted[n / 2 - 1] + sorted[n / 2]) / 2.0),
    }
}

/// Both clocks read at one moment: the thread's CPU time, and the
/// cycles its core has run where the counter is open.
#[derive(Clone, Copy, Debug)]
struct Reading {
    time: Duration,
    cycles: Option<u64>,
}

impl Reading {
    /// This reading less an earlier one.
    fn since(self, start: Reading) -> Reading {
        Reading {
            time: self.time.saturating_sub(start.time),
            cycles: match (self.cycles, start.cycles) {
                (Some(now), Some(then)) => Some(now.saturating_sub(then)),
                _ => None,
            },
        }
    }

    /// This reading and another, added.
    fn plus(self, other: Reading) -> Reading {
        Reading {
            time: self.time + other.time,
            cycles: match (self.cycles, other.cycles) {
                (Some(a), Some(b)) => Some(a.saturating_add(b)),
                _ => None,
            },
        }
    }
}

/// The clocks: thread CPU time always, and the processor's cycle
/// counter where it could be opened.
///
/// Cycles a byte barely move with the clock rate, so they are the
/// figure that repeats between runs, between cores of different
/// speeds, and as a laptop warms up. Time a byte is what a caller
/// feels. Reading both around the same batch also says what rate the
/// core was running at, which is where drift shows itself.
struct Clock {
    cycles: Option<cycles::Counter>,
    /// Why there is no counter, for the header.
    unavailable: Option<String>,
}

impl Clock {
    fn open() -> Self {
        match cycles::Counter::try_open() {
            Ok(counter) => Clock {
                cycles: Some(counter),
                unavailable: None,
            },
            Err(reason) => Clock {
                cycles: None,
                unavailable: Some(reason),
            },
        }
    }

    /// Reads both clocks, or `None` where one refused.
    fn read(&self) -> Option<Reading> {
        let time = ThreadTime::try_now().ok()?.as_duration();
        let cycles = match &self.cycles {
            Some(counter) => Some(counter.read()?),
            None => None,
        };
        Some(Reading { time, cycles })
    }
}

/// The cycle counter: `PERF_COUNT_HW_CPU_CYCLES` for this thread
/// alone, user mode only, through `perf_event_open`. It follows the
/// thread from core to core and stops while the thread is off the
/// processor, so it counts the work and not the waiting.
///
/// A hybrid processor has a PMU per kind of core, and an event opened
/// without naming one counts on the first kind alone: a thread on an
/// efficiency core reads zero. So one event is opened per core PMU
/// the kernel lists, each told which PMU it is for, and the count is
/// their sum.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod cycles {
    use std::fs;
    use std::io;
    use std::string::{String, ToString};
    use std::vec::Vec;

    /// The first 64 bytes of the kernel's `perf_event_attr`, which is
    /// `PERF_ATTR_SIZE_VER0` and the layout every kernel accepts when
    /// `size` says so. The fields after it configure sampling, which
    /// a plain counter does not do.
    #[repr(C)]
    struct Attr {
        kind: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_events: u32,
        bp_type: u32,
        config1: u64,
    }

    const PERF_TYPE_HARDWARE: u32 = 0;
    const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
    /// Where a hardware event's `config` names the PMU it is for.
    const PERF_PMU_TYPE_SHIFT: u32 = 32;
    /// `exclude_kernel` and `exclude_hv`: bits 5 and 6 of the flags.
    const EXCLUDE_KERNEL_AND_HV: u64 = (1 << 5) | (1 << 6);
    const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;

    pub struct Counter {
        fds: Vec<libc::c_int>,
    }

    impl Counter {
        /// Opens the counter, or says why the kernel would not.
        /// `perf_event_paranoid` above 2 refuses an unprivileged
        /// process, and a virtual machine usually has no counter to
        /// give.
        pub fn try_open() -> Result<Self, String> {
            let mut pmus = core_pmus();
            // A kernel too old to list its PMUs has one, unnamed.
            if pmus.is_empty() {
                pmus.push(0);
            }
            let fds =
                pmus.into_iter().map(open).collect::<Result<Vec<_>, _>>()?;
            Ok(Counter { fds })
        }

        /// The count so far: the sum over the PMUs.
        pub fn read(&self) -> Option<u64> {
            let mut total: u64 = 0;
            for &fd in &self.fds {
                let mut count: u64 = 0;
                // SAFETY: the buffer is the eight bytes a counter's
                // read delivers.
                let got = unsafe {
                    libc::read(fd, (&raw mut count).cast(), size_of::<u64>())
                };
                if got != size_of::<u64>() as isize {
                    return None;
                }
                total = total.saturating_add(count);
            }
            Some(total)
        }
    }

    impl Drop for Counter {
        fn drop(&mut self) {
            for &fd in &self.fds {
                // SAFETY: the descriptor is ours and closed once.
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }

    /// The types of the PMUs that count on cores, which are the
    /// event sources with a `cpus` file: `cpu` on most machines,
    /// `cpu_core` and `cpu_atom` on a hybrid one, and one per cluster
    /// on an asymmetric Arm.
    fn core_pmus() -> Vec<u64> {
        let Ok(devices) = fs::read_dir("/sys/bus/event_source/devices") else {
            return Vec::new();
        };
        let mut types: Vec<u64> = devices
            .flatten()
            .filter(|device| device.path().join("cpus").is_file())
            .filter_map(|device| {
                let text =
                    fs::read_to_string(device.path().join("type")).ok()?;
                text.trim().parse().ok()
            })
            .collect();
        types.sort_unstable();
        types
    }

    /// Opens the cycle event on one PMU, or on the kernel's default
    /// where `pmu` is zero.
    fn open(pmu: u64) -> Result<libc::c_int, String> {
        const _: () = assert!(size_of::<Attr>() == 64);
        let attr = Attr {
            kind: PERF_TYPE_HARDWARE,
            size: 64,
            config: (pmu << PERF_PMU_TYPE_SHIFT) | PERF_COUNT_HW_CPU_CYCLES,
            sample_period: 0,
            sample_type: 0,
            read_format: 0,
            flags: EXCLUDE_KERNEL_AND_HV,
            wakeup_events: 0,
            bp_type: 0,
            config1: 0,
        };
        // SAFETY: the attributes outlive the call and the kernel
        // reads the `size` bytes it is told about. Process 0 is
        // the calling thread, CPU -1 is any, and there is no
        // group.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &raw const attr,
                0 as libc::pid_t,
                -1 as libc::c_int,
                -1 as libc::c_int,
                PERF_FLAG_FD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(fd as libc::c_int)
    }
}

/// No other operating system has a counter this harness knows how to
/// ask for; the thread clock alone is read there.
#[cfg(not(target_os = "linux"))]
mod cycles {
    use std::string::String;

    pub struct Counter;

    impl Counter {
        pub fn try_open() -> Result<Self, String> {
            Err(String::from("no cycle counter on this operating system"))
        }

        pub fn read(&self) -> Option<u64> {
            None
        }
    }
}

/// A page-aligned buffer, filled so that it is not all zeros.
///
/// Nothing measured here is data-dependent; the pattern only keeps the
/// pages real and the contents recognisable in a debugger. The
/// alignment is so that where a buffer falls in a cache line and a
/// page is the same on every run, rather than whatever the allocator
/// had to hand.
struct Buffer {
    ptr: NonNull<u8>,
    size: usize,
    layout: Layout,
}

#[allow(unsafe_code)]
impl Buffer {
    /// A buffer of `size` bytes, or `None` where there is no memory.
    fn try_new(size: usize) -> Option<Self> {
        let layout = Layout::from_size_align(size.max(1), PAGE).ok()?;
        // SAFETY: the layout has a nonzero size.
        let ptr = NonNull::new(unsafe { alloc_zeroed(layout) })?;
        let mut buffer = Buffer { ptr, size, layout };
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        Some(buffer)
    }
}

#[allow(unsafe_code)]
impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: `size` bytes were allocated at `ptr` and zeroed.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }
}

#[allow(unsafe_code)]
impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `deref`, and this is the only reference.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }
}

#[allow(unsafe_code)]
impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: allocated with this layout, and freed only here.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

/// Which figures a row has: rates over a buffer at each size, or the
/// cost of a call.
#[derive(Clone, Copy)]
enum Kind {
    Throughput,
    Ops,
}

/// One row as measured, kept for the document. A throughput row has a
/// cell per size; an operation row has one cell and no size.
struct Row {
    section: String,
    name: &'static str,
    kind: Kind,
    cells: Vec<(Option<usize>, Option<Cell>)>,
}

/// The run as a JSON document.
///
/// Schema 1: `started` and `finished` are Unix seconds; `clock` says
/// whether the cycle figures exist; `samples` and `sample_seconds`
/// say what each figure is the median of; `commit` is present when
/// `SCYTALE_BENCH_COMMIT` was set; `environment` has whatever the
/// machine would say about itself. Each row's cells carry a summary
/// per figure, with the median, extremes, spread and the noise mark,
/// or `failed` where the clock refused.
fn document(run: &Run, started: u64, finished: u64) -> Value {
    let rows: Vec<Value> = run.rows.iter().map(row_json).collect();
    let mut document = json!({
        "schema": 1,
        "started": started,
        "finished": finished,
        "clock": if run.clock.cycles.is_some() {
            "cycles"
        } else {
            "thread-time"
        },
        "budget_seconds": run.options.budget.as_secs_f64(),
        "sample_seconds": sample_budget(run.options.budget).as_secs_f64(),
        "samples": SAMPLES,
        "environment": environment(),
        "rows": rows,
    });
    if let Ok(commit) = env::var("SCYTALE_BENCH_COMMIT") {
        document["commit"] = Value::String(commit);
    }
    document
}

/// One row of the document.
fn row_json(row: &Row) -> Value {
    let (kind, per_unit, per_second) = match row.kind {
        Kind::Throughput => {
            ("throughput", "cycles_per_byte", "bytes_per_second")
        }
        Kind::Ops => ("ops", "cycles_per_op", "ops_per_second"),
    };
    let cells: Vec<Value> = row
        .cells
        .iter()
        .map(|(size, cell)| {
            let mut object = serde_json::Map::new();
            if let Some(size) = size {
                object.insert("size".into(), json!(size));
            }
            match cell {
                Some(cell) => {
                    if let Some(cycles) = &cell.cycles {
                        object.insert(per_unit.into(), summary_json(cycles));
                    }
                    object.insert(per_second.into(), summary_json(&cell.rate));
                    if let Some(ghz) = cell.ghz {
                        object.insert("ghz".into(), json!(ghz));
                    }
                }
                None => {
                    object.insert("failed".into(), json!(true));
                }
            }
            Value::Object(object)
        })
        .collect();
    json!({
        "section": row.section,
        "name": row.name,
        "kind": kind,
        "cells": cells,
    })
}

/// One figure of the document.
fn summary_json(summary: &Summary) -> Value {
    json!({
        "median": summary.median,
        "min": summary.min,
        "max": summary.max,
        "spread": summary.spread,
        "samples": summary.samples,
        "noisy": summary.noisy(),
    })
}

/// What the machine says about itself, each field present only where
/// it could be read. The governor is the first CPU's this thread may
/// run on, which is the pinned one when `scripts/bench` pinned it.
fn environment() -> Value {
    let mut environment = serde_json::Map::new();
    environment.insert("arch".into(), json!(env::consts::ARCH));
    if let Some(processor) = processor() {
        environment.insert("processor".into(), json!(processor));
    }
    #[cfg(target_os = "linux")]
    {
        let cpus = affinity();
        let first = cpus.first().copied().unwrap_or(0);
        if !cpus.is_empty() {
            environment.insert("cpus".into(), json!(cpus));
        }
        let governor = format!(
            "/sys/devices/system/cpu/cpu{first}/cpufreq/scaling_governor"
        );
        if let Some(governor) = read_trimmed(&governor) {
            environment.insert("governor".into(), json!(governor));
        }
        let no_turbo = "/sys/devices/system/cpu/intel_pstate/no_turbo";
        if let Some(no_turbo) = read_number(no_turbo) {
            environment.insert("no_turbo".into(), json!(no_turbo));
        }
        let paranoid = "/proc/sys/kernel/perf_event_paranoid";
        if let Some(paranoid) = read_number(paranoid) {
            environment.insert("perf_event_paranoid".into(), json!(paranoid));
        }
    }
    Value::Object(environment)
}

/// The processor's name from `/proc/cpuinfo`, under whichever key
/// this architecture's kernel files it. `None` where there is no such
/// file or no such line.
fn processor() -> Option<String> {
    let text = fs::read_to_string("/proc/cpuinfo").ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        ["model name", "uarch", "Model", "Hardware"]
            .contains(&key.trim())
            .then(|| value.trim().to_string())
    })
}

/// A file's contents without surrounding space, or `None` where it
/// cannot be read or says nothing.
#[cfg(target_os = "linux")]
fn read_trimmed(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// A file holding one number.
#[cfg(target_os = "linux")]
fn read_number(path: &str) -> Option<i64> {
    read_trimmed(path)?.parse().ok()
}

/// The CPUs this thread may run on, in order; empty where the kernel
/// would not say.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn affinity() -> Vec<usize> {
    // SAFETY: a zeroed set is a valid empty one, and the call writes
    // within the size it is given.
    let mut set: libc::cpu_set_t = unsafe { core::mem::zeroed() };
    let got = unsafe {
        libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &raw mut set)
    };
    if got != 0 {
        return Vec::new();
    }
    (0..libc::CPU_SETSIZE as usize)
        // SAFETY: the set was filled by the call above.
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .collect()
}

/// What two documents said about the cells they share.
struct Comparison {
    text: String,
    better: usize,
    worse: usize,
    within: usize,
    unmatched: usize,
}

/// Reads two documents and compares them.
fn compare_files(old: &str, new: &str) -> Result<Comparison, String> {
    let read = |path: &str| -> Result<Value, String> {
        let text =
            fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
    };
    Ok(compare(&read(old)?, &read(new)?))
}

/// One figure of a cell, as a document has it, in the unit compared.
struct Figure {
    unit: &'static str,
    median: f64,
    spread: f64,
    lower_is_better: bool,
}

impl Figure {
    /// The cycle figure where both documents counted cycles, since
    /// that is the one that survives a change of clock rate between
    /// the two runs; the rate otherwise.
    fn of(cell: &Value, kind: &str, cycles: bool) -> Option<Figure> {
        let (key, unit, scale, lower_is_better) = match (kind, cycles) {
            ("throughput", true) => ("cycles_per_byte", "cpb", 1.0, true),
            ("throughput", false) => ("bytes_per_second", "MB/s", 1e-6, false),
            ("ops", true) => ("cycles_per_op", "cyc/op", 1.0, true),
            ("ops", false) => ("ops_per_second", "ops/s", 1.0, false),
            _ => return None,
        };
        let summary = cell.get(key)?;
        Some(Figure {
            unit,
            median: summary["median"].as_f64()? * scale,
            spread: summary["spread"].as_f64()?,
            lower_is_better,
        })
    }
}

/// Compares every cell of `new` with the same cell of `old`: same
/// section, row and size. A change counts only when it is larger than
/// the two spreads together, so a figure that moved within its own
/// noise is reported as such and not as a change.
fn compare(old: &Value, new: &Value) -> Comparison {
    let cycles = old["clock"] == "cycles" && new["clock"] == "cycles";
    let empty = Vec::new();
    let rows = |document: &Value| -> Vec<Value> {
        document["rows"].as_array().unwrap_or(&empty).clone()
    };
    let mut before: BTreeMap<(String, String, Option<u64>), Figure> =
        BTreeMap::new();
    for row in rows(old) {
        let kind = row["kind"].as_str().unwrap_or_default();
        for cell in row["cells"].as_array().unwrap_or(&empty) {
            if let Some(figure) = Figure::of(cell, kind, cycles) {
                before.insert(place(&row, cell), figure);
            }
        }
    }

    let mut comparison = Comparison {
        text: format!(
            "Comparing {}: old, new, and the change; `+` is better and \
             `-` worse\nby more than both spreads together.\n",
            if cycles { "cycles" } else { "rates" }
        ),
        better: 0,
        worse: 0,
        within: 0,
        unmatched: 0,
    };
    let mut section = String::new();
    for row in rows(new) {
        let kind = row["kind"].as_str().unwrap_or_default();
        if row["section"] != section {
            section = row["section"].as_str().unwrap_or_default().to_string();
            let _ = writeln!(comparison.text, "\n{section}");
        }
        for cell in row["cells"].as_array().unwrap_or(&empty) {
            let (_, name, size) = place(&row, cell);
            let size = size.map_or(String::new(), |size| size.to_string());
            let _ = write!(comparison.text, "  {name:22}{size:>6}");
            let pair = Figure::of(cell, kind, cycles)
                .and_then(|now| Some((before.get(&place(&row, cell))?, now)));
            let Some((then, now)) = pair else {
                comparison.unmatched += 1;
                let _ = writeln!(comparison.text, "{:>7}{:>11}", "", "-");
                continue;
            };
            let change = (now.median - then.median) / then.median;
            let mark = if change.abs() <= then.spread + now.spread {
                comparison.within += 1;
                ' '
            } else if (change < 0.0) == now.lower_is_better {
                comparison.better += 1;
                '+'
            } else {
                comparison.worse += 1;
                '-'
            };
            let _ = writeln!(
                comparison.text,
                "{:>7}{:>11}{:>11}{:>+8.1}% {mark}",
                now.unit,
                short(then.median),
                short(now.median),
                change * 100.0
            );
        }
    }
    let _ = writeln!(
        comparison.text,
        "\n{} better, {} worse, {} within the noise, {} unmatched.",
        comparison.better,
        comparison.worse,
        comparison.within,
        comparison.unmatched
    );
    comparison
}

/// Where a cell sits: its section, row and size.
fn place(row: &Value, cell: &Value) -> (String, String, Option<u64>) {
    (
        row["section"].as_str().unwrap_or_default().to_string(),
        row["name"].as_str().unwrap_or_default().to_string(),
        cell["size"].as_u64(),
    )
}

/// A figure with the digits that matter at its size.
fn short(value: f64) -> String {
    if value >= 1000.0 {
        format!("{value:.0}")
    } else if value >= 10.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.3}")
    }
}

/// Checks the parts of the harness that have an answer to be right
/// about, and says whether it holds.
fn self_test() -> bool {
    let mut failures = Vec::new();
    let mut check = |name: &str, ok: bool| {
        if !ok {
            failures.push(name.to_string());
        }
    };

    // A fast operation calibrates upwards until a batch is long
    // enough, and a slow one stays at a single iteration.
    let fast = calibrate(Duration::from_millis(10), |batch| {
        Duration::from_nanos(batch)
    });
    check("calibrate reaches the target", fast >= 10_000_000);
    check("calibrate stops at the target", fast <= 20_000_000);
    let slow =
        calibrate(Duration::from_millis(10), |_| Duration::from_millis(50));
    check("calibrate leaves a slow operation alone", slow == 1);
    // One that never gets there stops rather than doubling forever.
    let never = calibrate(Duration::from_secs(1), |_| Duration::ZERO);
    check("calibrate gives up", never == MAX_BATCH);

    // Summaries: the middle sample, and how far the middle half sit.
    check(
        "median of an odd count",
        median(&[1.0, 2.0, 3.0]) == Some(2.0),
    );
    check(
        "median of an even count",
        median(&[1.0, 2.0, 3.0, 4.0]) == Some(2.5),
    );
    check("median of nothing", median(&[]).is_none());
    check("summary of nothing", summarize(&[]).is_none());
    let flat = summarize(&[5.0; SAMPLES]).expect("a flat summary");
    check(
        "a flat set has no spread",
        flat.spread == 0.0 && !flat.noisy(),
    );
    // One to thirty-one, scrambled: the median is 16 and the
    // quartiles 8 and 24, so the spread is the whole median.
    let scrambled: Vec<f64> =
        (1..=31).map(|i| ((i * 7) % 31 + 1) as f64).collect();
    let wide = summarize(&scrambled).expect("a wide summary");
    check(
        "summary sorts first",
        wide.min == 1.0 && wide.max == 31.0 && wide.median == 16.0,
    );
    check(
        "spread is the middle half over the median",
        wide.spread == 1.0,
    );
    check("that much spread is noisy", wide.noisy());
    check("summary counts its samples", wide.samples == SAMPLES);

    // The cell's budget is shared among the samples, down to a floor.
    check(
        "sample budget shares the cell's",
        sample_budget(Duration::from_secs(31)) == Duration::from_secs(1),
    );
    check(
        "sample budget has a floor",
        sample_budget(Duration::from_millis(31)) == CALIBRATION,
    );

    // Samples against a made-up clock: a microsecond and three cycles
    // an iteration, sixteen bytes each.
    let mut fake = |batch: u64| {
        Some(Reading {
            time: Duration::from_micros(batch),
            cycles: Some(batch * 3),
        })
    };
    let mut samples =
        Samples::calibrated(16.0, Duration::from_millis(1), &mut fake);
    for _ in 0..SAMPLES {
        samples.take(&mut fake);
    }
    let cell = samples.cell().expect("a cell");
    check(
        "rate is units a second",
        (cell.rate.median - 16e6).abs() < 1.0,
    );
    check(
        "cycles are a unit's share",
        cell.cycles
            .is_some_and(|c| (c.median - 3.0 / 16.0).abs() < 1e-12),
    );
    check(
        "the clock rate follows",
        cell.ghz.is_some_and(|ghz| (ghz - 3e-3).abs() < 1e-12),
    );
    check("a steady clock is not noisy", !cell.rate.noisy());
    // A clock without a counter gives rates alone.
    let mut plain = |batch: u64| {
        Some(Reading {
            time: Duration::from_micros(batch),
            cycles: None,
        })
    };
    let mut samples = Samples::calibrated(1.0, CALIBRATION, &mut plain);
    samples.take(&mut plain);
    check(
        "no counter, no cycles",
        samples
            .cell()
            .is_some_and(|c| c.cycles.is_none() && c.ghz.is_none()),
    );
    // A clock that refuses, or stands still, spoils the cell and
    // nothing else.
    let mut refuse = |_| None;
    let mut samples = Samples::calibrated(1.0, CALIBRATION, &mut refuse);
    samples.take(&mut refuse);
    check("a refusing clock gives no cell", samples.cell().is_none());
    let mut stopped = |_| {
        Some(Reading {
            time: Duration::ZERO,
            cycles: Some(0),
        })
    };
    let mut samples = Samples::calibrated(1.0, CALIBRATION, &mut stopped);
    samples.take(&mut stopped);
    check("a stopped clock gives no cell", samples.cell().is_none());

    // Readings subtract and add, and lose the count when one side
    // has none.
    let later = Reading {
        time: Duration::from_secs(3),
        cycles: Some(30),
    };
    let earlier = Reading {
        time: Duration::from_secs(1),
        cycles: Some(10),
    };
    let since = later.since(earlier);
    check(
        "readings subtract",
        since.time == Duration::from_secs(2) && since.cycles == Some(20),
    );
    let sum = since.plus(Reading {
        time: Duration::from_secs(1),
        cycles: None,
    });
    check(
        "readings add",
        sum.time == Duration::from_secs(3) && sum.cycles.is_none(),
    );

    // Buffers are page-aligned, the asked size, and not blank.
    let buffer = Buffer::try_new(16384).expect("a buffer");
    check(
        "buffer is page-aligned",
        (buffer.as_ptr() as usize).is_multiple_of(PAGE),
    );
    check("buffer is the asked size", buffer.len() == 16384);
    check("buffer is not blank", buffer.iter().any(|&byte| byte != 0));
    check(
        "an empty buffer is allowed",
        Buffer::try_new(0).is_some_and(|b| b.is_empty()),
    );

    // The clocks run, and the counter counts when it is open.
    let clock = Clock::open();
    match (clock.read(), {
        let mut spin = 0u64;
        for i in 0..1_000_000u64 {
            spin = black_box(spin.wrapping_add(i));
        }
        black_box(spin);
        clock.read()
    }) {
        (Some(start), Some(end)) => {
            let reading = end.since(start);
            check("thread time advances", !reading.time.is_zero());
            if clock.cycles.is_some() {
                check("cycles advance", reading.cycles.is_some_and(|c| c > 0));
            }
        }
        _ => check("the clocks read", false),
    }

    // The document round-trips through text, and says what each
    // figure was.
    let row = Row {
        section: "test".to_string(),
        name: "aes-128-gcm-siv-enc",
        kind: Kind::Throughput,
        cells: vec![
            (
                Some(16),
                Some(Cell {
                    rate: flat,
                    cycles: Some(wide),
                    ghz: Some(4.8),
                }),
            ),
            (Some(64), None),
        ],
    };
    let mut run = Run::new(
        Options::parse(core::iter::empty())
            .ok()
            .flatten()
            .expect("no options parse"),
    );
    run.rows.push(row);
    let text = serde_json::to_string(&document(&run, 1, 2))
        .expect("a document serialises");
    let parsed: Value = serde_json::from_str(&text).expect("and parses");
    check("document has its schema", parsed["schema"] == 1);
    check(
        "document has its times",
        parsed["started"] == 1 && parsed["finished"] == 2,
    );
    check(
        "document knows its clock",
        parsed["clock"]
            == if run.clock.cycles.is_some() {
                "cycles"
            } else {
                "thread-time"
            },
    );
    check(
        "document names the architecture",
        parsed["environment"]["arch"] == env::consts::ARCH,
    );
    let cells = &parsed["rows"][0]["cells"];
    check(
        "document names the row",
        parsed["rows"][0]["name"] == "aes-128-gcm-siv-enc",
    );
    check("document has the size", cells[0]["size"] == 16);
    check(
        "document has the rate",
        cells[0]["bytes_per_second"]["median"] == 5.0,
    );
    check(
        "document has the cycles",
        cells[0]["cycles_per_byte"]["spread"] == 1.0,
    );
    check(
        "document marks the noise",
        cells[0]["cycles_per_byte"]["noisy"] == true,
    );
    check("document has the clock rate", cells[0]["ghz"] == 4.8);
    check("document marks a failed cell", cells[1]["failed"] == true);
    check(
        "document has no cycles for a failed cell",
        cells[1].get("cycles_per_byte").is_none(),
    );

    // The lines fit 80 columns, with the mark on.
    let lines = throughput_lines("aes-128-gcm-siv-enc", &run.rows[0].cells);
    check("a row is two lines", lines.lines().count() == 2);
    check(
        "the lines fit 80 columns",
        lines.lines().all(|line| line.len() <= 80),
    );
    check("the lines carry the mark", lines.contains('*'));
    let ops = ops_line(
        "sp800-108-hmac-sha-256",
        Some(&Cell {
            rate: wide,
            cycles: Some(wide),
            ghz: None,
        }),
    );
    check("an operation line fits 80 columns", ops.len() <= 80);
    check("an operation line carries the mark", ops.contains('*'));
    check(
        "a failed operation line fits",
        ops_line("x", None).len() <= 80,
    );

    check(
        "--json wants a path",
        Options::parse(["--json"].into_iter().map(String::from)).is_err(),
    );
    check(
        "--json takes a path",
        Options::parse(["--json", "out.json"].into_iter().map(String::from))
            .ok()
            .flatten()
            .is_some_and(|o| o.json.as_deref() == Some("out.json")),
    );

    // Filters are conjunctive and case-insensitive.
    let options =
        Options::parse(["GCM", "aesni"].into_iter().map(String::from))
            .ok()
            .flatten()
            .expect("filters parse");
    check(
        "both filters match",
        options.wants("aesni", "aes-128-gcm-enc"),
    );
    check(
        "one filter is not enough",
        !options.wants("vaes", "aes-128-gcm-enc"),
    );
    check(
        "a filter must appear",
        !options.wants("aesni", "aes-128-ctr"),
    );

    // Commas inside a word offer alternatives, so that two rows can
    // be asked for and compared within one run.
    let options =
        Options::parse(["aesni", "ctr,ecb-enc"].into_iter().map(String::from))
            .ok()
            .flatten()
            .expect("filters parse");
    check(
        "the first alternative matches",
        options.wants("aesni", "aes-128-ctr"),
    );
    check(
        "the second alternative matches",
        options.wants("aesni", "aes-128-ecb-enc"),
    );
    check(
        "neither alternative matches",
        !options.wants("aesni", "aes-128-ofb"),
    );
    check(
        "the other words still have to match",
        !options.wants("vaes", "aes-128-ctr"),
    );

    check(
        "--seconds is rejected when it is not a duration",
        Options::parse(["--seconds", "-1"].into_iter().map(String::from))
            .is_err(),
    );

    // Every named row is built, or a filter would silently drop it.
    let mut keys =
        Keys::<Ttable<16>, Ttable<32>>::try_new(Implementation::Portable)
            .expect("t-table keys");
    let built = keys.tasks();
    check(
        "every algorithm has a task",
        built.len() == ALGORITHMS.len(),
    );
    check(
        "the tasks are the algorithms, in order",
        built.iter().map(|(name, _)| *name).eq(ALGORITHMS),
    );

    // The layout has to hold: the checks above are worthless if the
    // table is unreadable.
    check("the heading fits 80 columns", heading().len() <= 80);

    // Comparing two documents: a change counts only past both
    // spreads, and its direction depends on the unit.
    let summary = |median: f64, spread: f64| Summary {
        median,
        min: median,
        max: median,
        spread,
        samples: SAMPLES,
    };
    let cell = |median: f64, spread: f64| {
        Some(Cell {
            rate: summary(1e9 / median, spread),
            cycles: Some(summary(median, spread)),
            ghz: Some(1.0),
        })
    };
    let rows = |cells: Vec<(Option<usize>, Option<Cell>)>| {
        vec![Row {
            section: "aesni".to_string(),
            name: "aes-128-gcm-enc",
            kind: Kind::Throughput,
            cells,
        }]
    };
    let mut old = Run::new(options.clone());
    old.rows = rows(vec![
        (Some(16), cell(10.0, 0.01)),
        (Some(64), cell(10.0, 0.01)),
        (Some(256), cell(10.0, 0.01)),
    ]);
    let mut new = Run::new(options);
    new.rows = rows(vec![
        (Some(16), cell(20.0, 0.01)),
        (Some(64), cell(5.0, 0.01)),
        (Some(256), cell(10.1, 0.01)),
        (Some(1024), cell(10.0, 0.01)),
    ]);
    let (old, new) = (document(&old, 1, 2), document(&new, 3, 4));
    let compared = compare(&old, &new);
    check(
        "compare counts each way",
        (
            compared.better,
            compared.worse,
            compared.within,
            compared.unmatched,
        ) == (1, 1, 1, 1),
    );
    check(
        "compare marks the worse cell",
        compared
            .text
            .lines()
            .any(|l| l.contains("16") && l.ends_with('-')),
    );
    check(
        "compare marks the better cell",
        compared
            .text
            .lines()
            .any(|l| l.contains("64") && l.ends_with('+')),
    );
    check(
        "compare fits 80 columns",
        compared.text.lines().all(|line| line.len() <= 80),
    );
    // Rates are compared where either run lacked the counter, and
    // there more is better.
    let mut plain = old.clone();
    plain["clock"] = json!("thread-time");
    let compared = compare(&plain, &new);
    check(
        "compare falls back to rates",
        compared.text.contains("MB/s") && compared.better == 1,
    );
    check("short keeps the digits that matter", short(0.61) == "0.610");
    check("short drops them at scale", short(12345.6) == "12346");
    check(
        "--compare wants two paths",
        Options::parse(["--compare", "a"].into_iter().map(String::from))
            .is_err(),
    );
    check(
        "--compare takes two paths",
        Options::parse(["--compare", "a", "b"].into_iter().map(String::from))
            .ok()
            .flatten()
            .is_some_and(|o| {
                o.compare == Some(("a".to_string(), "b".to_string()))
            }),
    );

    if failures.is_empty() {
        println!("speed: self-test passed");
        return true;
    }
    for failure in &failures {
        eprintln!("speed: FAILED: {failure}");
    }
    false
}
