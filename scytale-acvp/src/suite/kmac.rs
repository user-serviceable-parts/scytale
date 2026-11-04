//! KMAC 1.0, through the public bit-string calls of [`Kmac128`] and
//! [`Kmac256`]: tags generated (AFT) and checked (MVT), as MACs and
//! as XOFs, under text and hex customizations.
//!
//! Key, message and tag lengths are in bits and rarely whole bytes.
//! The files lay them out as the calls take them: a message's last
//! bits at the top of its byte, which `sha::Message` moves down for
//! SHA-3, and a key's or tag's at the top, which is where the bit
//! calls keep them.

use super::cshake::{customization, to_top};
use super::{answer_groups, answer_tests};
use crate::support::{
    Error, flag, hex, hex_value, int, text, unknown_test_type,
};
use scytale::Random;
use scytale::constant_time;
use scytale::hash::XofReader;
use scytale::mac::kmac::{Kmac128, Kmac256};
use serde_json::{Value, json};

/// What the driver needs of either width.
pub trait Width: Sized {
    fn try_new_bits(
        key: &[u8],
        bits: usize,
        s: &[u8],
    ) -> Result<Self, scytale::Error>;
    fn update(&mut self, data: &[u8]);
    fn finalize_bits_to(
        &mut self,
        last: u8,
        bits: u32,
        out: &mut [u8],
        out_bits: usize,
    ) -> Result<(), scytale::Error>;
    fn verify_bits(
        &mut self,
        last: u8,
        bits: u32,
        tag: &[u8],
        tag_bits: usize,
    ) -> Result<(), scytale::Error>;
    /// KMACXOF, squeezed into `out`.
    fn xof_bits(
        &mut self,
        last: u8,
        bits: u32,
        out: &mut [u8],
    ) -> Result<(), scytale::Error>;
}

macro_rules! width {
    ($ty:ty) => {
        impl Width for $ty {
            fn try_new_bits(
                key: &[u8],
                bits: usize,
                s: &[u8],
            ) -> Result<Self, scytale::Error> {
                <$ty>::try_new_bits(key, bits, s)
            }
            fn update(&mut self, data: &[u8]) {
                <$ty>::update(self, data)
            }
            fn finalize_bits_to(
                &mut self,
                last: u8,
                bits: u32,
                out: &mut [u8],
                out_bits: usize,
            ) -> Result<(), scytale::Error> {
                <$ty>::finalize_bits_to(self, last, bits, out, out_bits)
            }
            fn verify_bits(
                &mut self,
                last: u8,
                bits: u32,
                tag: &[u8],
                tag_bits: usize,
            ) -> Result<(), scytale::Error> {
                <$ty>::verify_bits(self, last, bits, tag, tag_bits)
            }
            fn xof_bits(
                &mut self,
                last: u8,
                bits: u32,
                out: &mut [u8],
            ) -> Result<(), scytale::Error> {
                self.finalize_bits_xof(last, bits)?.squeeze(out);
                Ok(())
            }
        }
    };
}

width!(Kmac128);
width!(Kmac256);

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    match text(doc, "algorithm")? {
        "KMAC-128" => answer_as::<Kmac128>(doc),
        "KMAC-256" => answer_as::<Kmac256>(doc),
        other => Err(Error::new(format!("algorithm {other}"))),
    }
}

fn answer_as<K: Width>(doc: &Value) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let xof = flag(group, "xof")?;
        let verify = match text(group, "testType")? {
            "AFT" => false,
            "MVT" => true,
            _ => return Err(unknown_test_type(group)),
        };
        answer_tests(group, |t| {
            let custom = customization(group, t)?;
            let key_bits = length(t, "keyLen")?;
            let mac_bits = length(t, "macLen")?;
            let key = hex(t, "key")?;
            let msg_bits = length(t, "msgLen")?;
            let msg = from_top(hex(t, "msg")?, msg_bits)?;
            let (whole, last, extra) = split(&msg, msg_bits);

            let mut kmac = K::try_new_bits(&key, key_bits, &custom)?;
            kmac.update(whole);
            let mut out = vec![0u8; mac_bits.div_ceil(8)];
            if !verify {
                if xof {
                    kmac.xof_bits(last, extra, &mut out)?;
                    to_top(&mut out, mac_bits);
                } else {
                    kmac.finalize_bits_to(last, extra, &mut out, mac_bits)?;
                }
                return Ok(json!({ "mac": hex_value(&out) }));
            }
            let expected = hex(t, "mac")?;
            let passed = if xof {
                kmac.xof_bits(last, extra, &mut out)?;
                to_top(&mut out, mac_bits);
                constant_time::equal(&out, &expected)
            } else {
                match kmac.verify_bits(last, extra, &expected, mac_bits) {
                    Ok(()) => true,
                    Err(scytale::Error::AuthenticationFailed) => false,
                    Err(e) => return Err(e.into()),
                }
            };
            Ok(json!({ "testPassed": passed }))
        })
    })
}

fn length(t: &Value, field: &str) -> Result<usize, Error> {
    Ok(int(t, field)? as usize)
}

/// A bit string as ACVP lays it out, with the bits of a partial last
/// byte moved to the bottom where SHA-3 reads them.
fn from_top(mut bytes: Vec<u8>, bits: usize) -> Result<Vec<u8>, Error> {
    if bytes.len() != bits.div_ceil(8) {
        return Err(Error::new("msg does not match msgLen"));
    }
    let extra = bits % 8;
    if let (Some(last), true) = (bytes.last_mut(), extra != 0) {
        *last >>= 8 - extra;
    }
    Ok(bytes)
}

/// The whole bytes of a message, and its last partial byte and how
/// many bits of it there are.
fn split(msg: &[u8], bits: usize) -> (&[u8], u8, u32) {
    let extra = (bits % 8) as u32;
    match msg.split_last() {
        Some((&last, whole)) if extra != 0 => (whole, last, extra),
        _ => (msg, 0, 0),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn vendored() {
        for name in ["KMAC-128", "KMAC-256"] {
            for suite in super::super::find(name) {
                super::super::check(suite);
            }
        }
    }
}
