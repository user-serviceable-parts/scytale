//! ACVP-AES-XTS 1.0 and 2.0, through [`Xts`] over any block cipher.
//!
//! Some cases give a payload length that is not a whole number of
//! bytes, as IEEE 1619 allows; those go through the bit-length
//! methods, the rest through the byte ones. 1.0 gives the length per
//! group, 2.0 per test, beside a `dataUnitLen`: the payload is cut
//! into data units of that many bits, each under the next tweak, as
//! IEEE 1619 numbers consecutive units, and the last may be short.
//! The cut need not fall on a byte, so the units are carved out and
//! written back bit by bit.
//!
//! The tweak is taken from `tweakValue` where the test has one: the
//! vendored file carries it even for the groups whose tweak mode is a
//! sequence number. The server's prompt for those gives only
//! `sequenceNumber`, which becomes the tweak as a little-endian
//! integer, as IEEE 1619 numbers its data units.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, hex, hex_value, int, key_of, opt_hex, opt_int, text,
    unknown_test_type,
};
use scytale::Random;
use scytale::cipher::mode::Xts;
use serde_json::{Value, json};

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let encrypt = match text(group, "direction")? {
            "encrypt" => true,
            "decrypt" => false,
            other => return Err(Error::new(format!("direction {other}"))),
        };
        let group_bits = opt_int(group, "payloadLen");
        match text(group, "testType")? {
            "AFT" => answer_tests(group, |t| {
                let bits = match group_bits {
                    Some(bits) => bits,
                    None => int(t, "payloadLen")?,
                } as usize;
                let unit =
                    opt_int(t, "dataUnitLen").map_or(bits, |u| u as usize);
                aft(t, encrypt, bits, unit)
            }),
            _ => Err(unknown_test_type(group)),
        }
    })
}

/// The test's tweak: its `tweakValue`, or else its `sequenceNumber`.
fn tweak(t: &Value) -> Result<[u8; 16], Error> {
    match opt_hex(t, "tweakValue")? {
        Some(value) => <[u8; 16]>::try_from(&value[..])
            .map_err(|_| Error::new("field tweakValue is not one block")),
        None => Ok(u128::from(int(t, "sequenceNumber")?).to_le_bytes()),
    }
}

/// One test: a payload of `bits` bits in units of `unit` bits, neither
/// of which need be whole bytes, in which case ACVP keeps the last
/// byte's spare low bits zero, as the mode does.
fn aft(
    t: &Value,
    encrypt: bool,
    bits: usize,
    unit: usize,
) -> Result<Value, Error> {
    let key = hex(t, "key")?;
    // The key field holds the data key and then the tweak key.
    let (data_key, tweak_key) = key.split_at(key.len() / 2);
    let first = u128::from_le_bytes(tweak(t)?);
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let data = hex(t, input)?;
    if unit == 0 {
        return Err(Error::new("field dataUnitLen is zero"));
    }
    let mut out = vec![0u8; data.len()];
    aes_width!(data_key, C => {
        let xts = Xts::<C>::try_new(
            &key_of::<C>(data_key)?,
            &key_of::<C>(tweak_key)?,
        )?;
        let mut start = 0;
        let mut index = 0u128;
        while start < bits {
            let len = unit.min(bits - start);
            let tweak = first.wrapping_add(index).to_le_bytes();
            let mut piece = take_bits(&data, start, len);
            match (encrypt, len % 8) {
                (true, 0) => xts.encrypt(&tweak, &mut piece)?,
                (false, 0) => xts.decrypt(&tweak, &mut piece)?,
                (true, _) => xts.encrypt_bits(&tweak, &mut piece, len)?,
                (false, _) => xts.decrypt_bits(&tweak, &mut piece, len)?,
            }
            put_bits(&mut out, start, &piece, len);
            start += len;
            index += 1;
        }
    });
    Ok(json!({ output: hex_value(&out) }))
}

/// Bits `start..start + len` of `data`, most significant bit first,
/// as bytes with the spare low bits of the last one zero.
fn take_bits(data: &[u8], start: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len.div_ceil(8)];
    for i in 0..len {
        let bit = (data[(start + i) / 8] >> (7 - (start + i) % 8)) & 1;
        out[i / 8] |= bit << (7 - i % 8);
    }
    out
}

/// Writes the first `len` bits of `piece` into `out` at `start`.
fn put_bits(out: &mut [u8], start: usize, piece: &[u8], len: usize) {
    for i in 0..len {
        let bit = (piece[i / 8] >> (7 - i % 8)) & 1;
        out[(start + i) / 8] |= bit << (7 - (start + i) % 8);
    }
}

#[cfg(test)]
mod tests {
    use super::{put_bits, take_bits};
    use crate::support::list;

    #[test]
    fn bits_are_carved_and_written_back() {
        let data = [0b1011_0010, 0b0111_1100, 0b1000_0001];
        let piece = take_bits(&data, 3, 11);
        assert_eq!(piece, [0b1001_0011, 0b1110_0000]);
        let mut back = [0u8; 3];
        put_bits(&mut back, 3, &piece, 11);
        assert_eq!(back, [0b0001_0010, 0b0111_1100, 0]);
    }

    /// As the server prompts the sequence-number groups: without the
    /// tweak value, which the sequence number must reproduce.
    #[test]
    fn sequence_number_gives_the_tweak() {
        for suite in super::super::find("ACVP-AES-XTS") {
            let Some(doc) = super::super::vendored(suite) else {
                continue;
            };
            let mut seen = 0;
            for group in list(&doc, "testGroups").unwrap() {
                if group["tweakMode"] != "number" {
                    continue;
                }
                for t in list(group, "tests").unwrap() {
                    let mut prompt = t.clone();
                    prompt.as_object_mut().unwrap().remove("tweakValue");
                    assert_eq!(
                        super::tweak(&prompt).unwrap(),
                        super::tweak(t).unwrap()
                    );
                    seen += 1;
                }
            }
            assert!(seen > 0, "no sequence-number groups");
        }
    }
}
