//! KDA OneStep and OneStepNoCounter Sp800-56Cr2, through
//! [`one_step`], and kdf-components ANSI X9.63 1.0, through [`x963`].
//!
//! The one-step suites build the fixed info from the auxiliary
//! secret `t`, both parties' identifiers and ephemeral data, and the
//! derived length in bits, which is the one pattern they are
//! registered for. Their AFT groups answer the key material; the VAL
//! groups carry key material, sometimes deliberately wrong, and
//! answer whether it is what the inputs derive.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, field, hex, hex_value, int, opt_hex, text, unknown_test_type,
};
use scytale::hash::Hash;
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use scytale::hash::sha2::{Sha512_224, Sha512_256};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::kdf::{one_step, x963};
use scytale::mac::hmac::Hmac;
use scytale::{BlockType, Random};
use serde_json::{Value, json};

/// Calls `$f::<H>` for the hash `$alg` names.
macro_rules! with_hash {
    ($alg:expr, $f:ident($($arg:expr),*)) => {
        match $alg {
            "SHA-1" => $f::<Sha1>($($arg),*),
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
            other => Err(Error::new(format!("hash {other}"))),
        }
    };
}

/// The inputs of one derivation.
struct Inputs<'a> {
    salt: &'a [u8],
    z: &'a [u8],
    fixed_info: &'a [u8],
    out: &'a mut [u8],
    counter: bool,
}

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    match (text(doc, "algorithm")?, text(doc, "mode")?) {
        ("KDA", "OneStep") => answer_one_step(doc, true),
        ("KDA", "OneStepNoCounter") => answer_one_step(doc, false),
        ("kdf-components", "ansix9.63") => answer_x963(doc),
        (alg, mode) => Err(Error::new(format!("{alg} {mode}"))),
    }
}

fn answer_one_step(doc: &Value, counter: bool) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let validate = match text(group, "testType")? {
            "AFT" => false,
            "VAL" => true,
            _ => return Err(unknown_test_type(group)),
        };
        let cfg = field(group, "kdfConfiguration")?;
        if text(cfg, "fixedInfoPattern")? != "t||uPartyInfo||vPartyInfo||l" {
            return Err(Error::new("fixedInfoPattern"));
        }
        if text(cfg, "fixedInfoEncoding")? != "concatenation" {
            return Err(Error::new("fixedInfoEncoding"));
        }
        let aux = text(cfg, "auxFunction")?;
        answer_tests(group, |t| {
            let dkm = one_step_case(t, aux, counter)?;
            Ok(if validate {
                json!({ "testPassed": dkm == hex(t, "dkm")? })
            } else {
                json!({ "dkm": hex_value(&dkm) })
            })
        })
    })
}

/// One derivation.
fn one_step_case(
    t: &Value,
    aux: &str,
    counter: bool,
) -> Result<Vec<u8>, Error> {
    let param = field(t, "kdfParameter")?;
    let bits = u32::try_from(int(param, "l")?)
        .map_err(|_| Error::new("field l is too large"))?;
    if !bits.is_multiple_of(8) {
        return Err(Error::new("l is not a whole number of bytes"));
    }

    let mut fixed_info = hex(param, "t")?;
    for party in ["fixedInfoPartyU", "fixedInfoPartyV"] {
        let p = field(t, party)?;
        fixed_info.extend_from_slice(&hex(p, "partyId")?);
        if let Some(e) = opt_hex(p, "ephemeralData")? {
            fixed_info.extend_from_slice(&e);
        }
    }
    fixed_info.extend_from_slice(&bits.to_be_bytes());

    // A hash auxiliary function has no salt.
    let salt = opt_hex(param, "salt")?.unwrap_or_default();
    let mut out = vec![0u8; bits as usize / 8];
    let inputs = Inputs {
        salt: &salt,
        z: &hex(param, "z")?,
        fixed_info: &fixed_info,
        out: &mut out,
        counter,
    };
    match aux.strip_prefix("HMAC-") {
        Some(alg) => with_hash!(alg, hmac(inputs)),
        None => match aux {
            "KMAC-128" | "KMAC-256" => kmac(aux, inputs),
            alg => with_hash!(alg, hash(inputs)),
        },
    }?;
    Ok(out)
}

fn hash<H: Hash + Default>(i: Inputs<'_>) -> Result<(), Error> {
    let fixed: [&[u8]; 1] = [i.fixed_info];
    if i.counter {
        one_step::hash::<H>(i.z, &fixed, i.out)
    } else {
        one_step::hash_no_counter::<H>(i.z, &fixed, i.out)
    }?;
    Ok(())
}

fn hmac<H: Hash + Clone + BlockType + Default>(
    i: Inputs<'_>,
) -> Result<(), Error> {
    let fixed: [&[u8]; 1] = [i.fixed_info];
    let mut mac = Hmac::<H>::new(i.salt);
    if i.counter {
        one_step::mac(&mut mac, i.z, &fixed, i.out)
    } else {
        one_step::mac_no_counter(&mut mac, i.z, &fixed, i.out)
    }?;
    Ok(())
}

fn kmac(aux: &str, i: Inputs<'_>) -> Result<(), Error> {
    let fixed: [&[u8]; 1] = [i.fixed_info];
    let kdf = match (aux, i.counter) {
        ("KMAC-128", true) => one_step::kmac128,
        ("KMAC-128", false) => one_step::kmac128_no_counter,
        ("KMAC-256", true) => one_step::kmac256,
        ("KMAC-256", false) => one_step::kmac256_no_counter,
        (other, _) => {
            return Err(Error::new(format!("auxFunction {other}")));
        }
    };
    kdf(i.salt, i.z, &fixed, i.out);
    Ok(())
}

fn answer_x963(doc: &Value) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        let alg = text(group, "hashAlg")?;
        let bits = int(group, "keyDataLength")?;
        if !bits.is_multiple_of(8) {
            return Err(Error::new("keyDataLength is not whole bytes"));
        }
        answer_tests(group, |t| {
            let mut out = vec![0u8; bits as usize / 8];
            with_hash!(alg, x963_case(t, &mut out))?;
            Ok(json!({ "keyData": hex_value(&out) }))
        })
    })
}

fn x963_case<H: Hash + Default>(
    t: &Value,
    out: &mut [u8],
) -> Result<(), Error> {
    let shared: [&[u8]; 1] = [&hex(t, "sharedInfo")?];
    x963::derive::<H>(&hex(t, "z")?, &shared, out)?;
    Ok(())
}
