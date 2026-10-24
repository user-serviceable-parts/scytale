//! `scytale kdf`: keys from keying material, from a password, from a
//! key-derivation key as SP 800-108 does it, from a shared secret as
//! SP 800-56C and X9.63 do it, or as TLS 1.2 derives them.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use scytale::cipher::aes::{Aes128, Aes192, Aes256};
use scytale::kdf::sp800_108::Counter;
use scytale::kdf::{hkdf, one_step, pbkdf2, sp800_108, tls12, x963};
use scytale::mac::Mac;
use scytale::mac::cmac::Cmac;
use scytale::mac::hmac::Hmac;
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::hash::with_hash;
use crate::io::Format;
use crate::{io, names, value};

#[derive(Subcommand)]
pub enum KdfOp {
    /// Expand already-unguessable material into keys (RFC 5869)
    Hkdf(HkdfArgs),
    /// Turn a password into a key, slowly (RFC 8018)
    Pbkdf2(Pbkdf2Args),
    /// The TLS 1.2 PRF: a secret, a label and a seed (RFC 5246)
    Tls12(Tls12Args),
    /// Keys from a key-derivation key under a MAC (SP 800-108)
    #[command(name = "sp800-108")]
    Sp800_108(Sp800_108Args),
    /// Keys from a key agreement's shared secret (SP 800-56C)
    OneStep(OneStepArgs),
    /// Keys from a shared secret, as ECIES has them (ANSI X9.63)
    X963(X963Args),
}

impl KdfOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            KdfOp::Hkdf(a) => format!("hkdf {}", a.hash),
            KdfOp::Pbkdf2(a) => format!("pbkdf2 {}", a.hash),
            KdfOp::Tls12(a) => format!("tls12 {}", a.hash),
            KdfOp::Sp800_108(a) => format!("sp800-108 {}", a.mac),
            KdfOp::OneStep(a) => format!("one-step {}", a.algorithm),
            KdfOp::X963(a) => format!("x963 {}", a.hash),
        }
    }
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct HkdfArgs {
    /// The hash: sha256, sha512, sha3-256, ... (scytale list kdf)
    pub hash: String,
    /// The input keying material (hex:, file:, fd:, env:)
    #[arg(long)]
    ikm: String,
    /// The salt (str: allowed); none without it
    #[arg(long)]
    salt: Option<String>,
    /// Context, may repeat; concatenated in order
    #[arg(long)]
    info: Vec<String>,
    /// Bytes of output
    #[arg(short, long)]
    length: usize,
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct Pbkdf2Args {
    /// The hash: sha256, sha512, sha3-256, ... (scytale list kdf)
    pub hash: String,
    /// The password (str:, file:, fd:, env:, hex:)
    #[arg(long)]
    password: String,
    /// The salt (str: allowed)
    #[arg(long)]
    salt: String,
    /// Iterations; 600000 is the 2023 OWASP figure for sha256
    #[arg(short, long)]
    iterations: u32,
    /// Bytes of output
    #[arg(short, long)]
    length: usize,
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct Tls12Args {
    /// The cipher suite's hash: sha256, sha384, ... (scytale list kdf)
    pub hash: String,
    /// The secret (hex:, file:, fd:, env:)
    #[arg(long)]
    secret: String,
    /// The label (str: allowed): "master secret", "key expansion", ...
    #[arg(long)]
    label: String,
    /// The seed, may repeat; concatenated in order
    #[arg(long, required = true)]
    seed: Vec<String>,
    /// Bytes of output
    #[arg(short, long)]
    length: usize,
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

/// The SP 800-108 modes over a MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Each block is PRF(fixed input with the counter in it)
    Counter,
    /// Each block is PRF(previous block, counter, fixed input)
    Feedback,
    /// Each block is PRF(A(i), counter, fixed input), A chained
    DoublePipeline,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct Sp800_108Args {
    /// The PRF: hmac-sha256, cmac-aes-128, kmac256, ... (scytale list mac)
    pub mac: String,
    /// The key-derivation key (hex:, file:, fd:, env:)
    #[arg(short, long)]
    key: String,
    /// counter, feedback or double-pipeline; counter without it
    #[arg(long)]
    mode: Option<Mode>,
    /// The fixed input, may repeat; concatenated in order
    #[arg(long)]
    fixed: Vec<String>,
    /// Bits of counter: 8, 16, 24 or 32; 32 without it
    #[arg(long)]
    counter_bits: Option<u32>,
    /// Where the counter goes: bits into the fixed input, 0 without
    /// it; for feedback and double-pipeline also "before" the
    /// chaining value, or "none"
    #[arg(long)]
    counter_at: Option<String>,
    /// The IV, for feedback (hex:, file:, fd:, env:); empty without it
    #[arg(long)]
    iv: Option<String>,
    /// The label, for kmac (str: allowed)
    #[arg(long)]
    label: Option<String>,
    /// The context, for kmac (str: allowed)
    #[arg(long)]
    context: Option<String>,
    /// Bytes of output
    #[arg(short, long)]
    length: usize,
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct OneStepArgs {
    /// The hash, or hmac-* or kmac* (scytale list kdf, scytale list mac)
    pub algorithm: String,
    /// The shared secret Z (hex:, file:, fd:, env:)
    #[arg(long)]
    secret: String,
    /// The salt, for hmac and kmac (str: allowed); the standard's
    /// default, all zeros, without it
    #[arg(long)]
    salt: Option<String>,
    /// Fixed info, may repeat; concatenated in order
    #[arg(long)]
    info: Vec<String>,
    /// Leave out the counter: one block of output at most
    #[arg(long)]
    no_counter: bool,
    /// Bytes of output
    #[arg(short, long)]
    length: usize,
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct X963Args {
    /// The hash: sha256, sha512, sha3-256, ... (scytale list kdf)
    pub hash: String,
    /// The shared secret Z (hex:, file:, fd:, env:)
    #[arg(long)]
    secret: String,
    /// Shared info, may repeat; concatenated in order
    #[arg(long)]
    info: Vec<String>,
    /// Bytes of output
    #[arg(short, long)]
    length: usize,
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: KdfOp) -> Result<()> {
    match op {
        KdfOp::Hkdf(args) => {
            let hash = names::KDF.find(&args.hash)?.name;
            let ikm = value::parse(&args.ikm, "--ikm", false)?;
            let salt = value::text(args.salt.as_deref(), "--salt")?;
            let info = args
                .info
                .iter()
                .map(|i| value::parse(i, "--info", true))
                .collect::<Result<Vec<_>>>()?;
            let info: Vec<&[u8]> = info.iter().map(|i| &i[..]).collect();
            let mut okm = Zeroizing::new(vec![0u8; args.length]);
            with_hash!(hash, H => {
                hkdf::derive::<H>(&salt, &ikm, &info, &mut okm).map_err(|_| {
                    usage!(
                        "--length {}: HKDF over {hash} gives at most {} \
                         bytes",
                        args.length,
                        255 * names::digest_len(hash).unwrap_or(0)
                    )
                })
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &okm, args.format.as_hex(true))
        }
        KdfOp::Pbkdf2(args) => {
            let hash = names::KDF.find(&args.hash)?.name;
            if args.iterations == 0 {
                return Err(usage!(
                    "--iterations 0 would derive nothing; every guess \
                     should cost an attacker what it costs you"
                ));
            }
            let password = value::parse(&args.password, "--password", true)?;
            let salt = value::parse(&args.salt, "--salt", true)?;
            let mut key = Zeroizing::new(vec![0u8; args.length]);
            with_hash!(hash, H => {
                Ok(pbkdf2::pbkdf2::<H>(
                    &password,
                    &salt,
                    args.iterations,
                    &mut key,
                )?)
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &key, args.format.as_hex(true))
        }
        KdfOp::Tls12(args) => {
            let hash = names::KDF.find(&args.hash)?.name;
            let secret = value::parse(&args.secret, "--secret", false)?;
            let label = value::parse(&args.label, "--label", true)?;
            if args.length == 0 {
                return Err(usage!("--length 0 would derive nothing"));
            }
            let seed = args
                .seed
                .iter()
                .map(|s| value::parse(s, "--seed", true))
                .collect::<Result<Vec<_>>>()?;
            let seed: Vec<&[u8]> = seed.iter().map(|s| &s[..]).collect();
            let mut out_bytes = Zeroizing::new(vec![0u8; args.length]);
            with_hash!(hash, H => {
                tls12::prf::<H>(&secret, &label, &seed, &mut out_bytes);
                Ok(())
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &out_bytes, args.format.as_hex(true))
        }
        KdfOp::Sp800_108(args) => {
            let key = sp800_108_derive(&args)?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &key, args.format.as_hex(true))
        }
        KdfOp::OneStep(args) => {
            let key = one_step_derive(&args)?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &key, args.format.as_hex(true))
        }
        KdfOp::X963(args) => {
            let hash = names::KDF.find(&args.hash)?.name;
            let z = value::parse(&args.secret, "--secret", false)?;
            let info = parts(&args.info, "--info")?;
            let info: Vec<&[u8]> = info.iter().map(|i| &i[..]).collect();
            let mut key = Zeroizing::new(vec![0u8; args.length]);
            with_hash!(hash, H => {
                x963::derive::<H>(&z, &info, &mut key).map_err(|_| {
                    usage!(
                        "--length {}: more blocks than a 32-bit counter \
                         numbers",
                        args.length
                    )
                })
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &key, args.format.as_hex(true))
        }
    }
}

/// The values of a repeated option, in order.
fn parts(specs: &[String], option: &str) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    specs
        .iter()
        .map(|s| value::parse(s, option, true))
        .collect()
}

/// `scytale kdf sp800-108`: the counter, feedback and double-pipeline
/// modes over HMAC or CMAC, or KDF-KMAC, which has its own shape with
/// a label and a context in place of the fixed input and no counter
/// to place.
fn sp800_108_derive(args: &Sp800_108Args) -> Result<Zeroizing<Vec<u8>>> {
    let entry = names::MAC.find(&args.mac)?;
    let name = entry.name;
    let mut out = Zeroizing::new(vec![0u8; args.length]);
    if name.starts_with("kmac") {
        if args.mode.is_some()
            || !args.fixed.is_empty()
            || args.counter_bits.is_some()
            || args.counter_at.is_some()
            || args.iv.is_some()
        {
            return Err(usage!(
                "{name} is KDF-KMAC, which takes --label and --context; \
                 the modes, the fixed input and the counter are hmac's \
                 and cmac's"
            ));
        }
        let key = value::checked(&args.key, "--key", entry.key, name)?;
        let label = value::text(args.label.as_deref(), "--label")?;
        let context = value::text(args.context.as_deref(), "--context")?;
        if name == "kmac128" {
            sp800_108::kmac128(&key, &label, &context, &mut out);
        } else {
            sp800_108::kmac256(&key, &label, &context, &mut out);
        }
        return Ok(out);
    }
    if args.label.is_some() || args.context.is_some() {
        return Err(usage!(
            "{name} takes --fixed; --label and --context are KDF-KMAC's"
        ));
    }
    if name == "poly1305" {
        return Err(usage!(
            "poly1305 is keyed once per message, so it is no PRF; hmac-*, \
             cmac-* or kmac*"
        ));
    }
    let mode = args.mode.unwrap_or(Mode::Counter);
    if mode != Mode::Feedback && args.iv.is_some() {
        return Err(usage!(
            "--iv is feedback's; {} mode has none",
            match mode {
                Mode::Counter => "counter",
                _ => "double-pipeline",
            }
        ));
    }
    let fixed = parts(&args.fixed, "--fixed")?;
    let fixed: Vec<&[u8]> = fixed.iter().map(|f| &f[..]).collect();
    let fixed_bits = fixed.iter().map(|f| 8 * f.len()).sum::<usize>();
    let bits = args.counter_bits.unwrap_or(32);
    if !matches!(bits, 8 | 16 | 24 | 32) {
        return Err(usage!("--counter-bits {bits}: 8, 16, 24 or 32"));
    }
    let counter = match args.counter_at.as_deref().unwrap_or("0") {
        "none" if mode == Mode::Counter => {
            return Err(usage!(
                "--counter-at none: counter mode is its counter; feedback \
                 and double-pipeline may go without one"
            ));
        }
        "none" => Counter::None,
        "before" if mode == Mode::Counter => {
            return Err(usage!(
                "--counter-at before: counter mode has no chaining value \
                 to go before; a count of bits into the fixed input"
            ));
        }
        "before" => Counter::BeforeIterator(bits),
        at => {
            let at: usize = at.parse().map_err(|_| {
                usage!(
                    "--counter-at {at}: a count of bits into the fixed \
                     input{}",
                    if mode == Mode::Counter {
                        ""
                    } else {
                        ", or before, or none"
                    }
                )
            })?;
            if at > fixed_bits {
                return Err(usage!(
                    "--counter-at {at}: the fixed input is {fixed_bits} \
                     bits long"
                ));
            }
            Counter::InFixed { bits, at }
        }
    };
    let iv = match &args.iv {
        Some(iv) => value::parse(iv, "--iv", false)?,
        None => Zeroizing::new(Vec::new()),
    };
    let blocks = |tag: usize| args.length.div_ceil(tag) as u64;
    let too_long = |tag: usize| {
        usage!(
            "--length {}: {} blocks of {tag} bytes, and a counter of \
             {bits} bits numbers {}",
            args.length,
            blocks(tag),
            (1u64 << bits) - 1
        )
    };
    macro_rules! derive {
        ($prf:expr) => {{
            let mut prf = $prf;
            modes(&mut prf, mode, counter, &iv, &fixed, &mut out)
                .map_err(|_| too_long(prf_tag_len(&prf)))
        }};
    }
    if let Some(hash) = name.strip_prefix("hmac-") {
        let key = value::checked(&args.key, "--key", entry.key, name)?;
        with_hash!(hash, H => derive!(Hmac::<H>::new(&key)))?;
        return Ok(out);
    }
    match name {
        "cmac-aes-128" => {
            let key = value::key::<Aes128>(&args.key, "--key", name)?;
            derive!(Cmac::<Aes128>::new(&key))?;
        }
        "cmac-aes-192" => {
            let key = value::key::<Aes192>(&args.key, "--key", name)?;
            derive!(Cmac::<Aes192>::new(&key))?;
        }
        "cmac-aes-256" => {
            let key = value::key::<Aes256>(&args.key, "--key", name)?;
            derive!(Cmac::<Aes256>::new(&key))?;
        }
        other => return Err(usage!("no MAC named \"{other}\"")),
    }
    Ok(out)
}

/// The tag length of a MAC, for a message about its blocks.
fn prf_tag_len<M: Mac>(_: &M) -> usize {
    size_of::<M::Tag>()
}

/// One of the three modes over a keyed PRF. The arguments have been
/// checked, so an error left is the output outrunning the counter.
fn modes<M: Mac>(
    prf: &mut M,
    mode: Mode,
    counter: Counter,
    iv: &[u8],
    fixed: &[&[u8]],
    out: &mut [u8],
) -> std::result::Result<(), scytale::Error> {
    match mode {
        Mode::Counter => match counter {
            Counter::InFixed { bits, at } => {
                sp800_108::counter(prf, bits, at, fixed, out)
            }
            // Refused above; the counter mode's counter is always
            // in the fixed input.
            _ => Err(scytale::Error::InvalidLength(0)),
        },
        Mode::Feedback => sp800_108::feedback(prf, iv, counter, fixed, out),
        Mode::DoublePipeline => {
            sp800_108::double_pipeline(prf, counter, fixed, out)
        }
    }
}

/// `scytale kdf one-step`: SP 800-56C's one-step KDF over a hash,
/// over HMAC keyed with a salt, or over KMAC keyed with a salt.
fn one_step_derive(args: &OneStepArgs) -> Result<Zeroizing<Vec<u8>>> {
    let z = value::parse(&args.secret, "--secret", false)?;
    let info = parts(&args.info, "--info")?;
    let info: Vec<&[u8]> = info.iter().map(|i| &i[..]).collect();
    let mut out = Zeroizing::new(vec![0u8; args.length]);
    let keyed = args.algorithm.starts_with("hmac")
        || args.algorithm.starts_with("kmac");
    if !keyed {
        let hash = names::KDF.find(&args.algorithm)?.name;
        if args.salt.is_some() {
            return Err(usage!(
                "{hash} takes no --salt; a salt keys hmac-{hash} or kmac"
            ));
        }
        let digest = names::digest_len(hash).unwrap_or(0);
        return with_hash!(hash, H => {
            if args.no_counter {
                one_step::hash_no_counter::<H>(&z, &info, &mut out)
                    .map_err(|_| one_block(args.length, hash, digest))
            } else {
                one_step::hash::<H>(&z, &info, &mut out)
                    .map_err(|_| too_many_blocks(args.length))
            }
        })
        .map(|()| out);
    }
    let entry = names::MAC.find(&args.algorithm)?;
    let name = entry.name;
    if let Some(hash) = name.strip_prefix("hmac-") {
        let salt = value::text(args.salt.as_deref(), "--salt")?;
        let digest = names::digest_len(hash).unwrap_or(0);
        return with_hash!(hash, H => {
            let mut mac = Hmac::<H>::new(&salt);
            if args.no_counter {
                one_step::mac_no_counter(&mut mac, &z, &info, &mut out)
                    .map_err(|_| one_block(args.length, name, digest))
            } else {
                one_step::mac(&mut mac, &z, &info, &mut out)
                    .map_err(|_| too_many_blocks(args.length))
            }
        })
        .map(|()| out);
    }
    // The standard's default salt is all zeros, 164 bytes for KMAC128
    // and 132 for KMAC256: the rate less four. Unlike HMAC, KMAC does
    // not key the same under an empty string, so the default is spelt
    // out here.
    let default_len = if name == "kmac128" { 164 } else { 132 };
    let salt = match &args.salt {
        Some(salt) => value::parse(salt, "--salt", true)?,
        None => Zeroizing::new(vec![0u8; default_len]),
    };
    match (name, args.no_counter) {
        ("kmac128", false) => one_step::kmac128(&salt, &z, &info, &mut out),
        ("kmac128", true) => {
            one_step::kmac128_no_counter(&salt, &z, &info, &mut out)
        }
        (_, false) => one_step::kmac256(&salt, &z, &info, &mut out),
        (_, true) => one_step::kmac256_no_counter(&salt, &z, &info, &mut out),
    }
    Ok(out)
}

fn one_block(length: usize, name: &str, digest: usize) -> crate::fail::Fail {
    usage!(
        "--length {length}: without the counter {name} gives one block, \
         {digest} bytes, at most"
    )
}

fn too_many_blocks(length: usize) -> crate::fail::Fail {
    usage!("--length {length}: more blocks than a 32-bit counter numbers")
}
