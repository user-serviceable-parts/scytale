//! ACVP-AES-ECB 1.0, through the [`BlockCipher`] trait.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, key_of, text, unknown_test_type};
use scytale::Random;
use scytale::cipher::BlockCipher;
use serde_json::{Value, json};

/// Steps of the Monte Carlo test, and iterations of each (ACVP AES
/// MCT).
const MCT_STEPS: usize = 100;
const MCT_ITERATIONS: usize = 1000;

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

fn apply<C: BlockCipher<Block = [u8; 16]>>(
    cipher: &C,
    encrypt: bool,
    data: &mut [u8],
) -> Result<(), Error> {
    let (blocks, rest) = data.as_chunks_mut::<16>();
    if !rest.is_empty() {
        return Err(Error::new("not whole blocks"));
    }
    if encrypt {
        cipher.encrypt(blocks);
    } else {
        cipher.decrypt(blocks);
    }
    Ok(())
}

/// Algorithm Functional Test: one-shot, possibly several blocks.
fn aft(t: &Value, encrypt: bool) -> Result<Value, Error> {
    let key = hex(t, "key")?;
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut data = hex(t, input)?;
    aes_width!(key, C => {
        let cipher = C::new(&key_of::<C>(&key)?);
        apply(&cipher, encrypt, &mut data)?;
    });
    Ok(json!({ output: hex_value(&data) }))
}

/// Monte Carlo Test, per the ACVP AES MCT for ECB: each of 100 steps
/// runs 1000 chained cipher calls, then derives the next key from the
/// last outputs. The answer gives the key and input of each step, and
/// the output of its final call.
fn mct(t: &Value, encrypt: bool) -> Result<Value, Error> {
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut key = hex(t, "key")?;
    let mut data = hex(t, input)?;
    let mut steps = Vec::with_capacity(MCT_STEPS);
    for _ in 0..MCT_STEPS {
        let mut step =
            json!({ "key": hex_value(&key), input: hex_value(&data) });
        let mut previous = data.clone();
        aes_width!(key, C => {
            let cipher = C::new(&key_of::<C>(&key)?);
            for _ in 0..MCT_ITERATIONS {
                previous.copy_from_slice(&data);
                apply(&cipher, encrypt, &mut data)?;
            }
        });
        step[output] = hex_value(&data);
        steps.push(step);

        // Next key: xor with the last 16, 24 or 32 bytes of the last
        // two outputs, most recent last.
        let mut tail = previous;
        tail.extend_from_slice(&data);
        let tail = &tail[tail.len() - key.len()..];
        for (k, t) in key.iter_mut().zip(tail) {
            *k ^= t;
        }
    }
    Ok(json!({ "resultsArray": steps }))
}
