//! ACVP-AES-CBC 1.0, through [`Cbc`].

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, key_of, text, unknown_test_type};
use scytale::Random;
use scytale::cipher::BlockCipher;
use scytale::cipher::mode::Cbc;
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
        let cbc = Cbc::<C>::new(&key_of::<C>(&key)?);
        if encrypt {
            cbc.encrypt(&iv, &mut data)?;
        } else {
            cbc.decrypt(&iv, &mut data)?;
        }
    });
    Ok(json!({ output: hex_value(&data) }))
}

/// Monte Carlo Test. Each of 100 steps runs 1000 single-block
/// operations whose inputs chain into one another, then derives the
/// next key, IV and input from the last two outputs. The answer gives
/// the key, IV and input of each step, and its last output.
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
        let (last, previous) = aes_width!(key, C => {
            let cbc = Cbc::<C>::new(&key_of::<C>(&key)?);
            if encrypt {
                step_encrypt(&cbc, &iv, &input)?
            } else {
                step_decrypt(&cbc, &iv, &input)?
            }
        });
        step[output_name] = hex_value(&last);
        steps.push(step);

        // Next key: xor with the tail of the last two outputs.
        let mut tail = previous.clone();
        tail.extend_from_slice(&last);
        let tail = &tail[tail.len() - key.len()..];
        for (k, t) in key.iter_mut().zip(tail) {
            *k ^= t;
        }
        iv = last;
        input = previous;
    }
    Ok(json!({ "resultsArray": steps }))
}

/// One encryption step. Each iteration encrypts one block, and the
/// next input is the chaining value this one used: the IV to begin
/// with, then the ciphertext before last. Returns the last two
/// ciphertext blocks.
fn step_encrypt<C: BlockCipher<Block = [u8; 16]>>(
    cbc: &Cbc<C>,
    iv: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut chain = iv.to_vec();
    let mut input = pt.to_vec();
    let mut previous = vec![0u8; iv.len()];
    let mut output = vec![0u8; iv.len()];
    for _ in 0..MCT_ITERATIONS {
        previous.copy_from_slice(&output);
        output.copy_from_slice(&input);
        cbc.encrypt(&block(&chain)?, &mut output)?;
        input.copy_from_slice(&chain);
        chain.copy_from_slice(&output);
    }
    Ok((output, previous))
}

/// One decryption step, which is the encryption step with plaintext
/// and ciphertext exchanged: the chaining value is the previous
/// ciphertext, and the next ciphertext is the plaintext before last.
/// Returns the last two plaintext blocks.
fn step_decrypt<C: BlockCipher<Block = [u8; 16]>>(
    cbc: &Cbc<C>,
    iv: &[u8],
    ct: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut chain = iv.to_vec();
    let mut input = ct.to_vec();
    let mut previous = vec![0u8; iv.len()];
    let mut output = vec![0u8; iv.len()];
    for j in 0..MCT_ITERATIONS {
        previous.copy_from_slice(&output);
        output.copy_from_slice(&input);
        cbc.decrypt(&block(&chain)?, &mut output)?;
        let next = if j == 0 {
            iv.to_vec()
        } else {
            previous.clone()
        };
        chain.copy_from_slice(&input);
        input = next;
    }
    Ok((output, previous))
}

#[cfg(test)]
mod tests {
    #[test]
    fn vendored() {
        for suite in super::super::find("ACVP-AES-CBC") {
            super::super::check(suite);
        }
    }
}
