//! KDA HKDF (SP 800-56Cr2): HKDF as the key-derivation step of a
//! key agreement. The input keying material is the hybrid shared
//! secret `Z || T`, and the info string is built from both parties'
//! identifiers and ephemeral data with the derived length appended,
//! which is the one fixed-info pattern the suite is registered for.
//!
//! The multi-expansion groups extract once and then expand several
//! times, each expansion with its own fixed info and length, which
//! is [`hkdf::extract`] followed by repeated [`hkdf::expand`]. The
//! AFT groups answer the key material; the VAL groups carry key
//! material, sometimes deliberately wrong, and answer whether it is
//! what the inputs derive.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, decode_hex, field, hex, hex_value, list, opt_hex, text,
    unknown_test_type,
};
use scytale::hash::Hash;
use scytale::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use scytale::hash::sha2::{Sha512_224, Sha512_256};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::kdf::hkdf;
use scytale::{BlockType, Random};
use serde_json::{Value, json};

/// Dispatches on the group's HMAC hash, which names the whole
/// derivation. Both flows need the same ten arms.
macro_rules! with_hash {
    ($alg:expr, $f:ident($($arg:expr),*)) => {
        match $alg {
            "SHA2-224" => $f::<Sha224>($($arg),*),
            "SHA2-256" => $f::<Sha256>($($arg),*),
            "SHA2-384" => $f::<Sha384>($($arg),*),
            "SHA2-512" => $f::<Sha512>($($arg),*),
            "SHA2-512/224" => $f::<Sha512_224>($($arg),*),
            "SHA2-512/256" => $f::<Sha512_256>($($arg),*),
            "SHA3-224" => $f::<Sha3_224>($($arg),*),
            "SHA3-256" => $f::<Sha3_256>($($arg),*),
            "SHA3-384" => $f::<Sha3_384>($($arg),*),
            "SHA3-512" => $f::<Sha3_512>($($arg),*),
            other => Err(Error::new(format!("hmacAlg {other}"))),
        }
    };
}

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let validate = match text(group, "testType")? {
            "AFT" => false,
            "VAL" => true,
            _ => return Err(unknown_test_type(group)),
        };
        // A group is one flow or the other, named by its
        // configuration; the multi-expansion one has no fixed-info
        // pattern because each expansion carries its own.
        match group.get("kdfConfiguration") {
            Some(cfg) => {
                if text(cfg, "fixedInfoPattern")? != "uPartyInfo||vPartyInfo||l"
                {
                    return Err(Error::new("fixedInfoPattern"));
                }
                if text(cfg, "fixedInfoEncoding")? != "concatenation" {
                    return Err(Error::new("fixedInfoEncoding"));
                }
                let alg = text(cfg, "hmacAlg")?;
                answer_tests(group, |t| {
                    let dkm = with_hash!(alg, single(t))?;
                    Ok(if validate {
                        json!({ "testPassed": dkm == hex(t, "dkm")? })
                    } else {
                        json!({ "dkm": hex_value(&dkm) })
                    })
                })
            }
            None => {
                let cfg = field(group, "kdfMultiExpansionConfiguration")?;
                if text(cfg, "kdfType")? != "hkdf" {
                    return Err(Error::new("kdfType"));
                }
                let alg = text(cfg, "hmacAlg")?;
                answer_tests(group, |t| {
                    let dkms = with_hash!(alg, multi(t))?;
                    if validate {
                        let mut want = Vec::new();
                        for v in list(t, "dkms")? {
                            want.push(
                                v.as_str().and_then(decode_hex).ok_or_else(
                                    || Error::new("dkms entry is not hex"),
                                )?,
                            );
                        }
                        Ok(json!({ "testPassed": dkms == want }))
                    } else {
                        let dkms: Vec<Value> =
                            dkms.iter().map(|d| hex_value(d)).collect();
                        Ok(json!({ "dkms": dkms }))
                    }
                })
            }
        }
    })
}

/// The derived length in bits, which one flow records as a string
/// and the other as a number, as a whole number of bytes.
fn bytes(obj: &Value) -> Result<usize, Error> {
    let bits = match field(obj, "l")? {
        Value::String(s) => s.parse::<u32>().ok(),
        v => v.as_u64().and_then(|n| u32::try_from(n).ok()),
    }
    .ok_or_else(|| Error::new("field l is not a length"))?;
    if !bits.is_multiple_of(8) {
        return Err(Error::new("l is not a whole number of bytes"));
    }
    Ok(bits as usize / 8)
}

/// One extract and several expansions, each with its own fixed info
/// and length. The PRK is computed once, which is the whole point of
/// the flow.
fn multi<H: Hash + Clone + BlockType + Default>(
    t: &Value,
) -> Result<Vec<Vec<u8>>, Error> {
    let param = field(t, "kdfMultiExpansionParameter")?;
    let salt = hex(param, "salt")?;
    let mut ikm = hex(param, "z")?;
    ikm.extend_from_slice(&hex(param, "t")?);
    let prk = hkdf::extract::<H>(&salt, &ikm);

    let mut dkms = Vec::new();
    for iteration in list(param, "iterationParameters")? {
        let info = hex(iteration, "fixedInfo")?;
        let mut dkm = vec![0u8; bytes(iteration)?];
        hkdf::expand::<H>(prk.as_ref(), &[&info], &mut dkm)?;
        dkms.push(dkm);
    }
    Ok(dkms)
}

/// One derivation.
fn single<H: Hash + Clone + BlockType + Default>(
    t: &Value,
) -> Result<Vec<u8>, Error> {
    let param = field(t, "kdfParameter")?;
    let salt = hex(param, "salt")?;
    // The hybrid shared secret: the classical part then the
    // auxiliary part, in the order the standard fixes.
    let mut ikm = hex(param, "z")?;
    ikm.extend_from_slice(&hex(param, "t")?);

    let len = bytes(param)?;
    let mut info = Vec::new();
    for party in ["fixedInfoPartyU", "fixedInfoPartyV"] {
        let p = field(t, party)?;
        info.extend_from_slice(&hex(p, "partyId")?);
        if let Some(e) = opt_hex(p, "ephemeralData")? {
            info.extend_from_slice(&e);
        }
    }
    info.extend_from_slice(&(8 * len as u32).to_be_bytes());

    let mut dkm = vec![0u8; len];
    hkdf::derive::<H>(&salt, &ikm, &[&info], &mut dkm)?;
    Ok(dkm)
}
