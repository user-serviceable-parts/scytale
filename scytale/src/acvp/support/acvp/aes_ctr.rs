//! ACVP-AES-CTR 1.0, run through [`Ctr`] over any block cipher.
//!
//! This suite has no Monte Carlo tests, only one-shot ones, but they
//! are more searching than the other suites': the payload length is
//! given in bits and is usually not a whole number of bytes.
//!
//! Counter mode is defined for any number of bits, the final
//! keystream block simply being cut short. [`Ctr`] works in whole
//! bytes, which is what callers want, so a length that is not a
//! multiple of eight is answered over its significant bits only: the
//! bits past the end are ours to leave as we like, and the vectors
//! record them as zero, so that is what is sent.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, run_groups,
};
use crate::KeyType;
use crate::cipher::BlockCipher;
use crate::cipher::mode::Ctr;
use crate::cipher::mode::ctr;
use crate::implementation::Implementation;
use serde_json::{Value, json};

/// The IV as the cipher's block type.
fn block<C: BlockCipher<Block = [u8; 16]>>(bytes: &[u8]) -> C::Block {
    let mut block = C::zero_block();
    block.as_mut().copy_from_slice(bytes);
    block
}

const FILE: &str = "ACVP-AES-CTR-1.0/internalProjection.json";

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
    let mut count = 0;
    let mut engines = 0;
    for &implementation in ctr::CHOICES {
        if Ctr::<C>::with_implementation(&C::zero_key(), implementation)
            .is_none()
        {
            continue;
        }
        engines += 1;
        count += run_groups(&groups, |group, encrypt| {
            tests::<C>(group, encrypt, Some(implementation))
        });
    }
    assert!(engines >= 1, "no implementation to test");
    // Guard against a truncated or wrong file passing vacuously.
    assert!(count >= 33, "only {count} AFT cases");
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-CTR", "1.0", test_type)
}

/// Zeroes every bit past `bits`.
fn truncate(data: &mut [u8], bits: usize) {
    for i in bits..8 * data.len() {
        data[i / 8] &= !(1 << (7 - i % 8));
    }
}

/// The response to each test of a group.
fn tests<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
    implementation: Option<Implementation>,
) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| aft::<C>(t, encrypt, implementation))
        .collect()
}

fn aft<C: BlockCipher<Block = [u8; 16]>>(
    t: &Value,
    encrypt: bool,
    implementation: Option<Implementation>,
) -> Value {
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let key = key_of::<C>(&hex(&t["key"])).expect("key width");
    let ctr = match implementation {
        None => Ctr::<C>::new(&key),
        Some(i) => Ctr::with_implementation(&key, i).expect("implementation"),
    };
    let counter = block::<C>(&hex(&t["iv"]));
    let mut data = hex(&t[input]);
    if encrypt {
        ctr.encrypt(&counter, &mut data);
    } else {
        ctr.decrypt(&counter, &mut data);
    }
    // Only the most significant payloadLen bits are the answer.
    if let Some(bits) = t["payloadLen"].as_u64() {
        truncate(&mut data, bits as usize);
    }
    json!({"tcId": t["tcId"], output: hex_string(&data)})
}
