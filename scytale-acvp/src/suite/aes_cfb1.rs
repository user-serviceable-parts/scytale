//! ACVP-AES-CFB1 1.0, through [`Cfb1`].
//!
//! Segments are single bits. The vectors carry each one in the top
//! bit of a byte, which is how the mode reads them too, and the
//! answers carry them the same way.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, hex, hex_value, int, key_of, text, unknown_test_type,
};
use scytale::Random;
use scytale::cipher::mode::Cfb1;
use serde_json::{Value, json};

/// Steps of the Monte Carlo test (ACVP AES MCT).
const MCT_STEPS: usize = 100;

/// Segments (bits) in one Monte Carlo step.
const MCT_SEGMENTS: usize = 1000;

/// Segments the IV holds: 128 bits.
const HISTORY: usize = 128;

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let encrypt = match text(group, "direction")? {
            "encrypt" => true,
            "decrypt" => false,
            other => return Err(Error::new(format!("direction {other}"))),
        };
        match text(group, "testType")? {
            "AFT" => answer_tests(group, |t| aft(t, encrypt)),
            "MCT" => answer_tests(group, |t| mct(t, encrypt)),
            _ => Err(unknown_test_type(group)),
        }
    })
}

/// The IV as a block.
fn block(bytes: &[u8]) -> Result<[u8; 16], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::new(format!("iv of {} bytes", bytes.len())))
}

/// Algorithm Functional Test: `payloadLen` bits, one IV.
fn aft(t: &Value, encrypt: bool) -> Result<Value, Error> {
    let key = hex(t, "key")?;
    let iv = block(&hex(t, "iv")?)?;
    let bits = usize::try_from(int(t, "payloadLen")?)
        .map_err(|_| Error::new("payloadLen too large"))?;
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut data = hex(t, input)?;
    aes_width!(key, C => {
        let cfb = Cfb1::<C>::new(&key_of::<C>(&key)?);
        if encrypt {
            cfb.encrypt(&iv, &mut data, bits)?;
        } else {
            cfb.decrypt(&iv, &mut data, bits)?;
        }
    });
    Ok(json!({ output: hex_value(&data) }))
}

/// Monte Carlo Test: each of 100 steps runs 1000 single bits through
/// one continuing state, then derives the next key, IV and input bit
/// from the outputs.
fn mct(t: &Value, encrypt: bool) -> Result<Value, Error> {
    let (input_name, output_name) =
        if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut key = hex(t, "key")?;
    let mut iv = hex(t, "iv")?;
    let mut input = top_bit(&hex(t, input_name)?, input_name)?;
    let mut steps = Vec::with_capacity(MCT_STEPS);
    for _ in 0..MCT_STEPS {
        let mut step = json!({
            "key": hex_value(&key),
            "iv": hex_value(&iv),
            input_name: hex_value(&[input << 7]),
        });
        let register = block(&iv)?;
        let mut outputs = [0u8; MCT_SEGMENTS];
        let mut segment = [input << 7];
        aes_width!(key, C => {
            let cfb = Cfb1::<C>::new(&key_of::<C>(&key)?);
            if encrypt {
                let mut state = cfb.encryptor(&register);
                for j in 0..MCT_SEGMENTS {
                    state.update(&mut segment, 1)?;
                    outputs[j] = segment[0] >> 7;
                    segment = [next_input(&iv, &outputs, j) << 7];
                }
            } else {
                let mut state = cfb.decryptor(&register);
                for j in 0..MCT_SEGMENTS {
                    state.update(&mut segment, 1)?;
                    outputs[j] = segment[0] >> 7;
                    segment = [next_input(&iv, &outputs, j) << 7];
                }
            }
        });
        let last = outputs[MCT_SEGMENTS - 1];
        step[output_name] = hex_value(&[last << 7]);
        steps.push(step);

        let bits = 8 * key.len();
        let tail = pack(&outputs[MCT_SEGMENTS - bits..]);
        for (k, t) in key.iter_mut().zip(&tail) {
            *k ^= t;
        }
        iv = pack(&outputs[MCT_SEGMENTS - HISTORY..]);
        input = outputs[MCT_SEGMENTS - HISTORY - 1];
    }
    Ok(json!({ "resultsArray": steps }))
}

/// The input bit for segment `j + 1`: a bit of the IV until the IV
/// has been shifted out, then the output 128 segments back.
fn next_input(iv: &[u8], outputs: &[u8], j: usize) -> u8 {
    if j < HISTORY {
        (iv[j / 8] >> (7 - j % 8)) & 1
    } else {
        outputs[j - HISTORY]
    }
}

/// The single bit a vector carries in the top of its first byte.
fn top_bit(bytes: &[u8], name: &str) -> Result<u8, Error> {
    bytes
        .first()
        .map(|b| b >> 7)
        .ok_or_else(|| Error::new(format!("field {name} is empty")))
}

/// Packs bits, most significant first, into bytes.
fn pack(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| {
            c.iter()
                .enumerate()
                .fold(0u8, |acc, (i, b)| acc | ((b & 1) << (7 - i)))
        })
        .collect()
}
