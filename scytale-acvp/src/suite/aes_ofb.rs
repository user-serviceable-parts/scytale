//! ACVP-AES-OFB 1.0, through [`Ofb`].
//!
//! The Monte Carlo test has the same shape as the one for cipher
//! feedback with full-block segments: 1000 blocks through a single
//! continuing state, each input being the IV and then the output one
//! block back.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, key_of, text, unknown_test_type};
use scytale::Random;
use scytale::cipher::mode::Ofb;
use serde_json::{Value, json};

/// Steps of the Monte Carlo test (ACVP AES MCT).
const MCT_STEPS: usize = 100;

/// Segments in one Monte Carlo step.
const MCT_SEGMENTS: usize = 1000;

/// Blocks of history the IV holds: one.
const HISTORY: usize = 1;

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
        let ofb = Ofb::<C>::new(&key_of::<C>(&key)?);
        if encrypt {
            ofb.encrypt(&iv, &mut data);
        } else {
            ofb.decrypt(&iv, &mut data);
        }
    });
    Ok(json!({ output: hex_value(&data) }))
}

/// Monte Carlo Test. Each of 100 steps is 1000 segments through a
/// single continuing state; each segment's input is a segment of the
/// IV while the register still holds IV material, and an earlier
/// output after that.
fn mct(t: &Value, encrypt: bool) -> Result<Value, Error> {
    let (input_name, output_name) =
        if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut key = hex(t, "key")?;
    let mut iv = hex(t, "iv")?;
    let mut input = hex(t, input_name)?;
    let mut steps = Vec::with_capacity(MCT_STEPS);
    for _ in 0..MCT_STEPS {
        let mut step = json!({
            "key": hex_value(&key),
            "iv": hex_value(&iv),
            input_name: hex_value(&input),
        });
        let register = block(&iv)?;
        let mut outputs: Vec<Vec<u8>> = Vec::with_capacity(MCT_SEGMENTS);
        let mut segment = input.clone();
        aes_width!(key, C => {
            let ofb = Ofb::<C>::new(&key_of::<C>(&key)?);
            // One state serves both directions: the keystream does
            // not depend on the message.
            let mut state = ofb.stream(&register);
            for j in 0..MCT_SEGMENTS {
                state.update(&mut segment);
                outputs.push(segment.clone());
                segment = next_input(&iv, &outputs, j);
            }
        });
        let last = &outputs[MCT_SEGMENTS - 1];
        step[output_name] = hex_value(last);
        steps.push(step);

        // The tail of the outputs supplies the next key, IV and
        // input. The key takes the last bytes of the stream, which
        // for a 192-bit key is part of one segment and all of the
        // next.
        let size = last.len();
        let segments = key.len().div_ceil(size);
        let recent: Vec<u8> = outputs[MCT_SEGMENTS - segments..].concat();
        let tail = &recent[recent.len() - key.len()..];
        for (k, t) in key.iter_mut().zip(tail) {
            *k ^= t;
        }
        iv = outputs[MCT_SEGMENTS - HISTORY..].concat();
        input = outputs[MCT_SEGMENTS - HISTORY - 1].clone();
    }
    Ok(json!({ "resultsArray": steps }))
}

/// The input for segment `j + 1`: a segment of the IV until the IV
/// has been consumed, then the output `HISTORY` segments back.
fn next_input(iv: &[u8], outputs: &[Vec<u8>], j: usize) -> Vec<u8> {
    if j < HISTORY {
        iv.to_vec()
    } else {
        outputs[j - HISTORY].clone()
    }
}
