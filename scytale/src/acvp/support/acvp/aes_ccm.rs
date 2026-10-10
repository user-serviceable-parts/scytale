//! ACVP-AES-CCM 1.0, run through [`Ccm`] over any block cipher.
//!
//! Every nonce length from 7 to 13 bytes and every tag length from 4
//! to 16, payloads up to 32 bytes, additional data up to 8,192, and
//! decryption cases that are *meant* to fail. The ciphertext carries
//! the tag on its end, both in the file and in an answer.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, rejected,
    run_groups,
};
use crate::Error;
use crate::KeyType;
use crate::aead::{Ccm, ccm};
use crate::cipher::BlockCipher;
use crate::implementation::Implementation;
use serde_json::{Value, json};

const FILE: &str = "ACVP-AES-CCM-1.0/internalProjection.json";

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

/// Runs the one-shot (AFT) groups against `C`, through every
/// implementation this processor has; a no-op without the vendored
/// vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("AFT") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    let mut engines = 0;
    for &implementation in ccm::CHOICES {
        if Ccm::<C>::with_implementation(&C::zero_key(), implementation)
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
    // Guard against a truncated or wrong file passing vacuously, and
    // against the rejection cases quietly disappearing. The file has
    // 2,770 cases a width, 457 or more of them rejections.
    assert!(cases >= 2770 * engines, "only {cases} AFT cases");
    assert!(
        rejections >= 450 * engines,
        "only {rejections} cases had to be rejected"
    );
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-CCM", "1.0", test_type)
}

/// The response to each test of a group.
fn tests<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
    implementation: Option<Implementation>,
) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
    let tag_len = group["tagLen"].as_u64().expect("tagLen") as usize / 8;
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| aft::<C>(t, encrypt, tag_len, implementation))
        .collect()
}

/// One case: the sealed ciphertext, or the plaintext, or a
/// rejection.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    t: &Value,
    encrypt: bool,
    tag_len: usize,
    implementation: Option<Implementation>,
) -> Value {
    let key = key_of::<C>(&hex(&t["key"])).expect("key width");
    let ccm = match implementation {
        None => Ccm::<C>::new(&key),
        Some(i) => Ccm::with_implementation(&key, i).expect("implementation"),
    };
    let nonce = hex(&t["iv"]);
    let aad = hex(&t["aad"]);

    if encrypt {
        let mut data = hex(&t["pt"]);
        let mut tag = vec![0u8; tag_len];
        ccm.encrypt(&nonce, &aad, &mut data, &mut tag)
            .expect("encrypt");
        data.extend_from_slice(&tag);
        return json!({"tcId": t["tcId"], "ct": hex_string(&data)});
    }
    let sealed = hex(&t["ct"]);
    let (ct, tag) = sealed.split_at(sealed.len() - tag_len);
    let mut data = ct.to_vec();
    match ccm.decrypt(&nonce, &aad, &mut data, tag) {
        Ok(()) => json!({"tcId": t["tcId"], "pt": hex_string(&data)}),
        Err(Error::AuthenticationFailed) => {
            assert!(data.iter().all(|&b| b == 0), "tcId {} wipe", t["tcId"]);
            json!({"tcId": t["tcId"], "testPassed": false})
        }
        Err(e) => panic!("tcId {}: {e}", t["tcId"]),
    }
}
