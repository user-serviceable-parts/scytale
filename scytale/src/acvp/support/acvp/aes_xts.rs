//! ACVP-AES-XTS, run through [`Xts`] over any block cipher: the
//! vendored 1.0 file, and 2.0 from the live server, which moves the
//! payload length from the group to the case and is otherwise the
//! same.
//!
//! Some groups give a data unit length that is not a whole number of
//! bytes, as IEEE 1619 allows; those go through the bit-length
//! methods, the rest through the byte ones.
//!
//! The tweak is `tweakValue` when the group's tweak mode is `hex`,
//! and the little-endian encoding of `sequenceNumber`, as IEEE 1619
//! defines it, when the mode is `number`. The 1.0 file carries both
//! for every case, which checks the encoding.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, run_groups,
};
use crate::KeyType;
use crate::cipher::BlockCipher;
use crate::cipher::mode::Xts;
use crate::cipher::mode::xts;
use crate::implementation::Implementation;
use serde_json::{Value, json};

const FILE: &str = "ACVP-AES-XTS-1.0/internalProjection.json";

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
    let mut cases = 0;
    let mut engines = 0;
    for &implementation in xts::CHOICES {
        let (data, tweak) = (C::zero_key(), one_key::<C>());
        if Xts::<C>::with_implementation(&data, &tweak, implementation)
            .is_none()
        {
            continue;
        }
        engines += 1;
        cases += run_groups(&groups, |group, encrypt| {
            tests::<C>(group, encrypt, Some(implementation))
        });
    }
    assert!(engines >= 1, "no implementation to test");
    assert!(cases >= 133, "only {cases} AFT cases");
}

/// A key that differs from the zero one, which XTS needs: the two it
/// takes may not be equal.
fn one_key<C: KeyType>() -> C::Key {
    let mut key = C::zero_key();
    key.as_mut()[0] = 1;
    key
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-XTS", "1.0", test_type)
}

/// The response to each test of a group.
fn tests<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
    implementation: Option<Implementation>,
) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
    let by_number = match group["tweakMode"].as_str() {
        Some("hex") => false,
        Some("number") => true,
        other => panic!("unknown tweakMode {other:?}"),
    };
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| {
            // 1.0 states the length once per group, 2.0 per case.
            let bits = t["payloadLen"]
                .as_u64()
                .or(group["payloadLen"].as_u64())
                .expect("payloadLen") as usize;
            aft::<C>(t, encrypt, bits, by_number, implementation)
        })
        .collect()
}

/// The tweak of a case.
fn tweak(t: &Value, by_number: bool) -> [u8; 16] {
    if by_number {
        let n = t["sequenceNumber"].as_u64().expect("sequenceNumber");
        u128::from(n).to_le_bytes()
    } else {
        hex(&t["tweakValue"]).try_into().expect("tweak")
    }
}

/// One case; a unit of `bits` bits, which may not be whole bytes,
/// in which case ACVP keeps the last byte's spare low bits zero, as
/// the mode does.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    t: &Value,
    encrypt: bool,
    bits: usize,
    by_number: bool,
    implementation: Option<Implementation>,
) -> Value {
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let key = hex(&t["key"]);
    let (data_key, tweak_key) = key.split_at(key.len() / 2);
    let data_key = key_of::<C>(data_key).expect("key width");
    let tweak_key = key_of::<C>(tweak_key).expect("key width");
    let xts = match implementation {
        None => Xts::<C>::try_new(&data_key, &tweak_key).expect("keys"),
        Some(i) => Xts::with_implementation(&data_key, &tweak_key, i)
            .expect("implementation"),
    };
    let tweak = tweak(t, by_number);
    let mut data = hex(&t[input]);
    match (encrypt, bits % 8) {
        (true, 0) => xts.encrypt(&tweak, &mut data).expect("encrypt"),
        (false, 0) => xts.decrypt(&tweak, &mut data).expect("decrypt"),
        (true, _) => xts
            .encrypt_bits(&tweak, &mut data, bits)
            .expect("encrypt bits"),
        (false, _) => xts
            .decrypt_bits(&tweak, &mut data, bits)
            .expect("decrypt bits"),
    }
    json!({"tcId": t["tcId"], output: hex_string(&data)})
}
