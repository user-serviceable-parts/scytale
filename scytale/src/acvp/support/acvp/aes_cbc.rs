//! ACVP-AES-CBC 1.0, run through [`Cbc`] over any block cipher.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, run_groups,
};
use crate::KeyType;
use crate::cipher::BlockCipher;
use crate::cipher::mode::Cbc;
use crate::cipher::mode::cbc;
use crate::implementation::Implementation;
use serde_json::{Value, json};

/// The IV as the cipher's block type.
fn block<C: BlockCipher<Block = [u8; 16]>>(bytes: &[u8]) -> C::Block {
    let mut block = C::zero_block();
    block.as_mut().copy_from_slice(bytes);
    block
}

const FILE: &str = "ACVP-AES-CBC-1.0/internalProjection.json";

/// Steps in a Monte Carlo test.
const MCT_STEPS: usize = 100;

/// Iterations of each Monte Carlo step (ACVP AES MCT).
const MCT_ITERATIONS: usize = 1000;

/// The suite, for [`answer_aes`](super::answer_aes): the mode on
/// the implementation this processor picks.
pub struct Suite;

impl Answers for Suite {
    fn tests<C: BlockCipher<Block = [u8; 16]>>(
        group: &Value,
        encrypt: bool,
    ) -> Vec<Value> {
        tests::<C>(group, encrypt, None)
    }
}

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
/// Runs them against every implementation this processor has, not
/// only the one the mode would pick: which that is depends on the
/// machine, so anything else leaves whichever the machine did not
/// choose unvalidated.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("AFT") else {
        return;
    };
    let (count, engines) = every_implementation::<C>(&groups);
    assert!(engines >= 1, "no implementation to test");
    // Guard against a truncated or wrong file passing vacuously.
    assert!(count >= 500, "only {count} AFT cases");
}

/// Runs the Monte Carlo (MCT) groups against `C`; a no-op without the
/// vendored vectors. Slow: 600,000 cipher calls.
pub fn run_mct<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("MCT") else {
        return;
    };
    let (count, _) = every_implementation::<C>(&groups);
    assert!(count >= 2, "only {count} MCT cases");
}

/// Runs `groups` on each implementation the processor has; the
/// cases run and the implementations tried.
fn every_implementation<C: BlockCipher<Block = [u8; 16]>>(
    groups: &[(Value, bool)],
) -> (usize, usize) {
    let mut count = 0;
    let mut engines = 0;
    for &implementation in cbc::CHOICES {
        if Cbc::<C>::with_implementation(&C::zero_key(), implementation)
            .is_none()
        {
            continue;
        }
        engines += 1;
        count += run_groups(groups, |group, encrypt| {
            tests::<C>(group, encrypt, Some(implementation))
        });
    }
    (count, engines)
}

/// The groups of one test type; `None` without the vectors.
fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-CBC", "1.0", test_type)
}

/// The mode under `key`, on `implementation` or on the one the
/// processor picks.
fn cbc<C: BlockCipher<Block = [u8; 16]>>(
    key: &[u8],
    implementation: Option<Implementation>,
) -> Cbc<C> {
    let key = key_of::<C>(key).expect("key width");
    match implementation {
        None => Cbc::new(&key),
        Some(i) => Cbc::with_implementation(&key, i).expect("implementation"),
    }
}

/// The response to each test of a group.
fn tests<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
    implementation: Option<Implementation>,
) -> Vec<Value> {
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| match group["testType"].as_str() {
            Some("AFT") => aft::<C>(t, encrypt, implementation),
            Some("MCT") => mct::<C>(t, encrypt, implementation),
            other => panic!("unknown testType {other:?}"),
        })
        .collect()
}

/// The names of a direction's input and output.
fn names(encrypt: bool) -> (&'static str, &'static str) {
    if encrypt { ("pt", "ct") } else { ("ct", "pt") }
}

/// Algorithm Functional Test: one message, one IV.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    t: &Value,
    encrypt: bool,
    implementation: Option<Implementation>,
) -> Value {
    let (input, output) = names(encrypt);
    let cbc = cbc::<C>(&hex(&t["key"]), implementation);
    let iv = block::<C>(&hex(&t["iv"]));
    let mut data = hex(&t[input]);
    if encrypt {
        cbc.encrypt(&iv, &mut data).expect("whole blocks");
    } else {
        cbc.decrypt(&iv, &mut data).expect("whole blocks");
    }
    json!({"tcId": t["tcId"], output: hex_string(&data)})
}

/// Monte Carlo Test. Each of 100 steps runs 1000 single-block
/// operations whose inputs chain into one another, then derives the
/// next key, IV and input from the last two outputs. Each step
/// reports its key, IV, input and last output.
fn mct<C: BlockCipher<Block = [u8; 16]>>(
    t: &Value,
    encrypt: bool,
    implementation: Option<Implementation>,
) -> Value {
    let (input_name, output_name) = names(encrypt);
    let mut key = hex(&t["key"]);
    let mut iv = hex(&t["iv"]);
    let mut input = hex(&t[input_name]);
    let mut steps = Vec::with_capacity(MCT_STEPS);
    for _ in 0..MCT_STEPS {
        let mut step = json!({
            "key": hex_string(&key),
            "iv": hex_string(&iv),
            input_name: hex_string(&input),
        });
        let cbc = cbc::<C>(&key, implementation);
        let (last, previous) = if encrypt {
            step_encrypt(&cbc, &iv, &input)
        } else {
            step_decrypt(&cbc, &iv, &input)
        };
        step[output_name] = json!(hex_string(&last));
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
    json!({"tcId": t["tcId"], "resultsArray": steps})
}

/// One encryption step. Each iteration encrypts one block, and the
/// next input is the chaining value this one used: the IV to begin
/// with, then the ciphertext before last. Returns the last two
/// ciphertext blocks.
fn step_encrypt<C: BlockCipher<Block = [u8; 16]>>(
    cbc: &Cbc<C>,
    iv: &[u8],
    pt: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut chain = iv.to_vec();
    let mut input = pt.to_vec();
    let mut previous = vec![0u8; iv.len()];
    let mut output = vec![0u8; iv.len()];
    for _ in 0..MCT_ITERATIONS {
        previous.copy_from_slice(&output);
        output.copy_from_slice(&input);
        cbc.encrypt(&block::<C>(&chain), &mut output)
            .expect("one block");
        input.copy_from_slice(&chain);
        chain.copy_from_slice(&output);
    }
    (output, previous)
}

/// One decryption step, which is the encryption step with plaintext
/// and ciphertext exchanged: the chaining value is the previous
/// ciphertext, and the next ciphertext is the plaintext before last.
/// Returns the last two plaintext blocks.
fn step_decrypt<C: BlockCipher<Block = [u8; 16]>>(
    cbc: &Cbc<C>,
    iv: &[u8],
    ct: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut chain = iv.to_vec();
    let mut input = ct.to_vec();
    let mut previous = vec![0u8; iv.len()];
    let mut output = vec![0u8; iv.len()];
    for j in 0..MCT_ITERATIONS {
        previous.copy_from_slice(&output);
        output.copy_from_slice(&input);
        cbc.decrypt(&block::<C>(&chain), &mut output)
            .expect("one block");
        let next = if j == 0 {
            iv.to_vec()
        } else {
            previous.clone()
        };
        chain.copy_from_slice(&input);
        input = next;
    }
    (output, previous)
}
