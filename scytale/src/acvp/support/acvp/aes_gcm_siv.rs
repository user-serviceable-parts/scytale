//! ACVP-AES-GCM-SIV, run through [`GcmSiv`] over any block cipher.
//!
//! This suite records the ciphertext with its tag appended, rather
//! than as separate fields, and includes thirteen decryption cases
//! whose tags must be rejected.
//!
//! RFC 8452 defines the mode for 128- and 256-bit keys only, which
//! the type system enforces, so the live run dispatches those two
//! widths itself rather than through [`answer_aes`].
//!
//! [`answer_aes`]: super::answer_aes

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    encrypts, groups as suite_groups, hex, hex_string, key_of, rejected,
    response, run_groups,
};
use crate::Error;
use crate::KeyType;
use crate::aead::{Aead, GcmSiv, SivKey, gcm_siv};
use crate::cipher::BlockCipher;
use crate::cipher::aes::Aes;
use crate::implementation::Implementation;
use serde_json::{Value, json};

const FILE: &str = "ACVP-AES-GCM-SIV-1.0/internalProjection.json";

/// The tag length the standard fixes.
const TAG: usize = 16;

/// The response to a whole vector set, on the implementation this
/// processor picks.
pub fn answer(prompt: &Value) -> Value {
    let groups = prompt["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| {
            let encrypt = encrypts(group);
            let tests = match group["keyLen"].as_u64() {
                Some(128) => tests::<Aes<16>>(group, encrypt, None),
                Some(256) => tests::<Aes<32>>(group, encrypt, None),
                other => panic!("keyLen {other:?}"),
            };
            json!({"tgId": group["tgId"], "tests": tests})
        })
        .collect();
    response(prompt, groups)
}

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
/// Runs them against every implementation this processor has, not
/// only the one the mode would pick: which that is depends on the
/// machine, so anything else leaves whichever the machine did not
/// choose unvalidated.
pub fn run_aft<C: BlockCipher<Block = [u8; 16], Key: SivKey>>() {
    let Some(groups) = groups::<C>("AFT") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    let mut engines = 0;
    for &implementation in gcm_siv::CHOICES {
        if GcmSiv::<C>::with_implementation(&C::zero_key(), implementation)
            .is_none()
        {
            continue;
        }
        engines += 1;
        cases += run_groups(&groups, |group, encrypt| {
            let answers = tests::<C>(group, encrypt, Some(implementation));
            rejections += rejected(&answers);
            answers
        });
    }
    assert!(engines >= 1, "no implementation to test");
    assert!(cases >= 33, "only {cases} AFT cases");
    assert!(
        rejections >= 1,
        "only {rejections} cases had to be rejected"
    );
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-GCM-SIV", "1.0", test_type)
}

/// The response to each test of a group.
fn tests<C: BlockCipher<Block = [u8; 16], Key: SivKey>>(
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

/// One case. The ciphertext carries its tag on the end, both ways.
fn aft<C: BlockCipher<Block = [u8; 16], Key: SivKey>>(
    t: &Value,
    encrypt: bool,
    implementation: Option<Implementation>,
) -> Value {
    let key = key_of::<C>(&hex(&t["key"])).expect("key width");
    let siv = match implementation {
        None => GcmSiv::<C>::new(&key),
        Some(i) => {
            GcmSiv::with_implementation(&key, i).expect("implementation")
        }
    };
    let nonce: [u8; 12] = hex(&t["iv"]).try_into().expect("nonce");
    let aad = hex(&t["aad"]);

    if encrypt {
        let mut data = hex(&t["pt"]);
        let mut tag = [0u8; TAG];
        siv.encrypt(&nonce, &aad, &mut data, &mut tag)
            .expect("encrypt");
        data.extend_from_slice(&tag);
        return json!({"tcId": t["tcId"], "ct": hex_string(&data)});
    }
    let sealed = hex(&t["ct"]);
    let (cipher, tag) = sealed.split_at(sealed.len() - TAG);
    let tag: &[u8; TAG] = tag.try_into().expect("tag");
    let mut data = cipher.to_vec();
    match siv.decrypt(&nonce, &aad, &mut data, tag) {
        Ok(()) => json!({"tcId": t["tcId"], "pt": hex_string(&data)}),
        Err(Error::AuthenticationFailed) => {
            json!({"tcId": t["tcId"], "testPassed": false})
        }
        Err(e) => panic!("tcId {}: {e}", t["tcId"]),
    }
}
