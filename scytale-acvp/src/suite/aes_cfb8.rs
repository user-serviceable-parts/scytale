//! ACVP-AES-CFB8 1.0, through [`Cfb8`].

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, key_of, text, unknown_test_type};
use scytale::Random;
use scytale::cipher::mode::Cfb8;
use serde_json::{Value, json};

/// Steps of the Monte Carlo test (ACVP AES MCT).
const MCT_STEPS: usize = 100;

/// Segments (bytes) in one Monte Carlo step.
const MCT_SEGMENTS: usize = 1000;

/// Segments the IV holds: sixteen bytes.
const HISTORY: usize = 16;

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

/// Algorithm Functional Test: one message, one IV.
fn aft(t: &Value, encrypt: bool) -> Result<Value, Error> {
    let key = hex(t, "key")?;
    let iv = block(&hex(t, "iv")?)?;
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut data = hex(t, input)?;
    aes_width!(key, C => {
        let cfb = Cfb8::<C>::new(&key_of::<C>(&key)?);
        if encrypt {
            cfb.encrypt(&iv, &mut data);
        } else {
            cfb.decrypt(&iv, &mut data);
        }
    });
    Ok(json!({ output: hex_value(&data) }))
}

/// Monte Carlo Test: each of 100 steps runs 1000 single bytes through
/// one continuing state, then derives the next key, IV and input from
/// the outputs.
fn mct(t: &Value, encrypt: bool) -> Result<Value, Error> {
    let (input_name, output_name) =
        if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut key = hex(t, "key")?;
    let mut iv = hex(t, "iv")?;
    let mut input = *hex(t, input_name)?
        .first()
        .ok_or_else(|| Error::new(format!("field {input_name} is empty")))?;
    let mut steps = Vec::with_capacity(MCT_STEPS);
    for _ in 0..MCT_STEPS {
        let mut step = json!({
            "key": hex_value(&key),
            "iv": hex_value(&iv),
            input_name: hex_value(&[input]),
        });
        let register = block(&iv)?;
        let mut outputs = [0u8; MCT_SEGMENTS];
        let mut segment = [input];
        aes_width!(key, C => {
            let cfb = Cfb8::<C>::new(&key_of::<C>(&key)?);
            if encrypt {
                let mut state = cfb.encryptor(&register);
                for j in 0..MCT_SEGMENTS {
                    state.update(&mut segment);
                    outputs[j] = segment[0];
                    segment = [next_input(&iv, &outputs, j)];
                }
            } else {
                let mut state = cfb.decryptor(&register);
                for j in 0..MCT_SEGMENTS {
                    state.update(&mut segment);
                    outputs[j] = segment[0];
                    segment = [next_input(&iv, &outputs, j)];
                }
            }
        });
        step[output_name] = hex_value(&outputs[MCT_SEGMENTS - 1..]);
        steps.push(step);

        let tail = &outputs[MCT_SEGMENTS - key.len()..];
        for (k, t) in key.iter_mut().zip(tail) {
            *k ^= t;
        }
        iv = outputs[MCT_SEGMENTS - HISTORY..].to_vec();
        input = outputs[MCT_SEGMENTS - HISTORY - 1];
    }
    Ok(json!({ "resultsArray": steps }))
}

/// The input byte for segment `j + 1`: a byte of the IV until the IV
/// has been shifted out, then the output sixteen segments back.
fn next_input(iv: &[u8], outputs: &[u8], j: usize) -> u8 {
    if j < HISTORY {
        iv[j]
    } else {
        outputs[j - HISTORY]
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn vendored() {
        for suite in super::super::find("ACVP-AES-CFB8") {
            super::super::check(suite);
        }
    }
}
