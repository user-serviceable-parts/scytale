//! ACVP-SHA2 1.0 and ACVP-SHA3 2.0, through the [`Hash`] trait. One
//! driver serves every variant of both families; the algorithm name
//! chooses the hash, and the family decides how the last bits of a
//! bit-string message sit in their byte and the Monte Carlo chaining.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, hex, hex_value, int, opt_text, text, unknown_test_type,
};
use scytale::Random;
use scytale::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::hash::{BitHash, Hash};
use serde_json::{Value, json};

/// Which standard a suite belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Sha2,
    Sha3,
}

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    match text(doc, "algorithm")? {
        "SHA2-224" => answer_as::<Sha224>(doc, Family::Sha2),
        "SHA2-256" => answer_as::<Sha256>(doc, Family::Sha2),
        "SHA2-384" => answer_as::<Sha384>(doc, Family::Sha2),
        "SHA2-512" => answer_as::<Sha512>(doc, Family::Sha2),
        "SHA2-512/224" => answer_as::<Sha512_224>(doc, Family::Sha2),
        "SHA2-512/256" => answer_as::<Sha512_256>(doc, Family::Sha2),
        "SHA3-224" => answer_as::<Sha3_224>(doc, Family::Sha3),
        "SHA3-256" => answer_as::<Sha3_256>(doc, Family::Sha3),
        "SHA3-384" => answer_as::<Sha3_384>(doc, Family::Sha3),
        "SHA3-512" => answer_as::<Sha3_512>(doc, Family::Sha3),
        other => Err(Error::new(format!("algorithm {other}"))),
    }
}

fn answer_as<H: BitHash + Default>(
    doc: &Value,
    family: Family,
) -> Result<Value, Error>
where
    H::Output: AsRef<[u8]>,
{
    answer_groups(doc, |group| match text(group, "testType")? {
        "AFT" => answer_tests(group, |t| {
            let digest = Message::of(t)?.digest(H::default(), family);
            Ok(json!({ "md": hex_value(digest.as_ref()) }))
        }),
        "MCT" => {
            let alternate = match opt_text(group, "mctVersion") {
                Some("standard") | None => false,
                Some("alternate") => true,
                Some(other) => {
                    return Err(Error::new(format!("mctVersion {other}")));
                }
            };
            answer_tests(group, |t| mct::<H>(t, family, alternate))
        }
        "LDT" => answer_tests(group, |t| ldt::<H>(t)),
        _ => Err(unknown_test_type(group)),
    })
}

/// A message of the vectors: bytes, and a length in bits, which is
/// not always a whole number of bytes. ACVP keeps any last bits at
/// the top of the last byte. That is where SHA-2 reads them; SHA-3
/// numbers bits from the bottom of a byte, so they are shifted down
/// for it.
pub struct Message {
    pub bytes: Vec<u8>,
    pub bits: usize,
}

impl Message {
    pub fn of(t: &Value) -> Result<Self, Error> {
        let bits = int(t, "len")? as usize;
        let bytes = hex(t, "msg")?;
        if bytes.len() != bits.div_ceil(8) {
            return Err(Error::new("msg does not match len"));
        }
        Ok(Message { bytes, bits })
    }

    /// The whole bytes, and the last byte with its bits placed as
    /// the family reads them, if the length is not a whole number of
    /// bytes.
    pub fn split(&self, family: Family) -> (&[u8], Option<(u8, u32)>) {
        let extra = (self.bits % 8) as u32;
        if extra == 0 {
            return (&self.bytes, None);
        }
        let Some((last, whole)) = self.bytes.split_last() else {
            return (&self.bytes, None);
        };
        let last = match family {
            Family::Sha2 => *last,
            Family::Sha3 => *last >> (8 - extra),
        };
        (whole, Some((last, extra)))
    }

    /// Hashes the message with `hash`, which is consumed.
    fn digest<H: BitHash>(&self, mut hash: H, family: Family) -> H::Output {
        let (whole, tail) = self.split(family);
        hash.update(whole);
        match tail {
            None => hash.finalize(),
            // The count is 1 to 7 by construction.
            Some((last, extra)) => hash
                .finalize_bits(last, extra)
                .unwrap_or_else(|_| hash.finalize()),
        }
    }
}

/// Monte Carlo Test: 100 steps of 1000 chained hashes. SHA-2 hashes
/// the previous three digests each time, in the standard version as
/// they are and in the alternate one cut or padded with zeros to the
/// length of the seed; SHA-3 hashes just the previous digest.
fn mct<H: BitHash + Default>(
    t: &Value,
    family: Family,
    alternate: bool,
) -> Result<Value, Error>
where
    H::Output: AsRef<[u8]>,
{
    let seed = Message::of(t)?;
    if seed.bits % 8 != 0 {
        return Err(Error::new("bit-length seed"));
    }
    let seed = seed.bytes;
    let mut hash = H::default();
    let mut md: Vec<u8> = seed.clone();
    let mut steps = Vec::with_capacity(100);
    for _ in 0..100 {
        md = match family {
            Family::Sha2 => sha2_step(&mut hash, &md, seed.len(), alternate),
            Family::Sha3 => sha3_step(&mut hash, &md),
        };
        steps.push(json!({ "md": hex_value(&md) }));
    }
    Ok(json!({ "resultsArray": steps }))
}

/// One SHA-2 Monte Carlo step.
fn sha2_step<H: Hash>(
    hash: &mut H,
    md: &[u8],
    seed_len: usize,
    alternate: bool,
) -> Vec<u8>
where
    H::Output: AsRef<[u8]>,
{
    let mut a = md.to_vec();
    let mut b = md.to_vec();
    let mut c = md.to_vec();
    for _ in 0..1000 {
        let mut msg = a.clone();
        msg.extend_from_slice(&b);
        msg.extend_from_slice(&c);
        if alternate {
            msg.resize(seed_len, 0);
        }
        hash.reset();
        hash.update(&msg);
        let digest = hash.finalize().as_ref().to_vec();
        a = b;
        b = c;
        c = digest;
    }
    c
}

/// One SHA-3 Monte Carlo step.
fn sha3_step<H: Hash>(hash: &mut H, md: &[u8]) -> Vec<u8>
where
    H::Output: AsRef<[u8]>,
{
    let mut md = md.to_vec();
    for _ in 0..1000 {
        hash.reset();
        hash.update(&md);
        md = hash.finalize().as_ref().to_vec();
    }
    md
}

/// Large Data Test: a short piece repeated to gigabytes, hashed as
/// it is generated.
fn ldt<H: Hash + Default>(t: &Value) -> Result<Value, Error>
where
    H::Output: AsRef<[u8]>,
{
    let large = &t["largeMsg"];
    if large["expansionTechnique"] != "repeating" {
        return Err(Error::new("unknown expansionTechnique"));
    }
    let piece = hex(large, "content")?;
    let piece_bits = int(large, "contentLength")?;
    let full_bits = int(large, "fullLength")?;
    if piece.len() as u64 * 8 != piece_bits || full_bits % piece_bits != 0 {
        return Err(Error::new("largeMsg lengths disagree"));
    }
    let repeats = full_bits / piece_bits;
    // Feed in chunks of many pieces to keep the call count sane.
    let per_chunk = (1 << 20) / piece.len().max(1);
    let chunk: Vec<u8> = piece.repeat(per_chunk);
    let mut hash = H::default();
    let mut left = repeats;
    while left > 0 {
        let n = left.min(per_chunk as u64) as usize;
        hash.update(&chunk[..n * piece.len()]);
        left -= n as u64;
    }
    Ok(json!({ "md": hex_value(hash.finalize().as_ref()) }))
}
