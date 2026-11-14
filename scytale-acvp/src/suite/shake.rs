//! ACVP-SHAKE 1.0, through the [`BitXof`] trait: the one-shot test,
//! the variable output test, and a Monte Carlo test whose output
//! length wanders.

use super::sha::{Family, Message};
use super::{answer_groups, answer_tests};
use crate::support::{Error, hex_value, int, text, unknown_test_type};
use scytale::Random;
use scytale::hash::sha3::{Shake128, Shake256};
use scytale::hash::{BitXof, XofReader};
use serde_json::{Value, json};

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    match text(doc, "algorithm")? {
        "SHAKE-128" => answer_as::<Shake128>(doc),
        "SHAKE-256" => answer_as::<Shake256>(doc),
        other => Err(Error::new(format!("algorithm {other}"))),
    }
}

fn answer_as<X: BitXof + Default>(doc: &Value) -> Result<Value, Error> {
    answer_groups(doc, |group| match text(group, "testType")? {
        "AFT" | "VOT" => answer_tests(group, |t| {
            let bits = int(t, "outLen")? as usize;
            let mut out = vec![0u8; bits.div_ceil(8)];
            squeeze::<X>(&Message::of(t)?, &mut out)?;
            // A length that is not whole bytes keeps the last byte's
            // low bits, numbered as FIPS 202 numbers them, and the
            // rest zero.
            if let (Some(last), true) =
                (out.last_mut(), !bits.is_multiple_of(8))
            {
                *last &= (1u8 << (bits % 8)) - 1;
            }
            Ok(json!({ "md": hex_value(&out), "outLen": bits }))
        }),
        "MCT" => {
            let min_bits = int(group, "minOutLen")? as usize;
            let max_bits = int(group, "maxOutLen")? as usize;
            if min_bits < 16 || max_bits < min_bits {
                return Err(Error::new("output lengths out of range"));
            }
            answer_tests(group, |t| mct::<X>(t, min_bits, max_bits))
        }
        _ => Err(unknown_test_type(group)),
    })
}

/// Squeezes `out.len()` bytes from `message`.
fn squeeze<X: BitXof + Default>(
    message: &Message,
    out: &mut [u8],
) -> Result<(), Error> {
    let mut xof = X::default();
    let (whole, tail) = message.split(Family::Sha3);
    xof.update(whole);
    let mut reader = match tail {
        None => xof.finalize_xof(),
        Some((last, extra)) => xof.finalize_bits_xof(last, extra)?,
    };
    reader.squeeze(out);
    Ok(())
}

/// The SHAKE Monte Carlo test: each of 100 steps squeezes 1000
/// times, feeding the first 16 bytes of each output (zero-padded)
/// into the next, with the output length chosen each time by the
/// last two bytes of the previous output within the group's range.
fn mct<X: BitXof + Default>(
    t: &Value,
    min_bits: usize,
    max_bits: usize,
) -> Result<Value, Error> {
    let range = (max_bits - min_bits) / 8 + 1;
    let seed = Message::of(t)?;
    if seed.bits % 8 != 0 {
        return Err(Error::new("bit-length seed"));
    }
    let mut md = seed.bytes;
    let mut out_len = max_bits / 8;
    let mut steps = Vec::with_capacity(100);
    for _ in 0..100 {
        for _ in 0..1000 {
            let mut msg = md.clone();
            msg.resize(16, 0);
            let message = Message {
                bytes: msg,
                bits: 128,
            };
            let mut out = vec![0u8; out_len];
            squeeze::<X>(&message, &mut out)?;
            // At least two bytes by the group's minimum.
            let right = usize::from(u16::from_be_bytes([
                out[out.len() - 2],
                out[out.len() - 1],
            ]));
            out_len = min_bits / 8 + right % range;
            md = out;
        }
        steps.push(json!({
            "md": hex_value(&md),
            "outLen": md.len() * 8,
        }));
    }
    Ok(json!({ "resultsArray": steps }))
}
