//! ACVP-AES-GCM 1.0, run through [`Gcm`] over any block cipher.
//!
//! This suite is smaller than the others but reaches further: tags
//! of 32 and 128 bits, empty and non-empty additional data and
//! message, and decryption cases that are *meant* to fail, which
//! check that a bad tag is rejected rather than quietly accepted,
//! and nonces of 96 bits and otherwise.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, rejected,
    run_groups,
};
use crate::Error;
use crate::KeyType;
use crate::aead::gcm;
use crate::aead::{Aead, Gcm};
use crate::cipher::BlockCipher;
use crate::implementation::Implementation;
use serde_json::{Value, json};

const FILE: &str = "ACVP-AES-GCM-1.0/internalProjection.json";

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
    let mut rejections = 0;
    let mut engines = 0;
    for &implementation in gcm::CHOICES {
        if Gcm::<C>::with_implementation(&C::zero_key(), implementation)
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
    // against the rejection cases quietly disappearing.
    assert!(cases >= 20, "only {cases} AFT cases");
    assert!(
        rejections >= 1,
        "only {rejections} cases had to be rejected"
    );
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-GCM", "1.0", test_type)
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

/// One case. Encryption answers the ciphertext and the tag cut to
/// the group's length; decryption the plaintext, or that the tag was
/// rejected.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    t: &Value,
    encrypt: bool,
    tag_len: usize,
    implementation: Option<Implementation>,
) -> Value {
    let key = key_of::<C>(&hex(&t["key"])).expect("key width");
    let gcm = match implementation {
        None => Gcm::<C>::new(&key),
        Some(i) => Gcm::with_implementation(&key, i).expect("implementation"),
    };
    let nonce = hex(&t["iv"]);
    let aad = hex(&t["aad"]);

    if encrypt {
        let mut data = hex(&t["pt"]);
        let mut tag = [0u8; 16];
        // The suite runs several nonce lengths. The one-shot takes
        // the standard twelve bytes; the rest go through the
        // incremental form, which accepts any length.
        match <&[u8; 12]>::try_from(&nonce[..]) {
            Ok(nonce) => gcm
                .encrypt(nonce, &aad, &mut data, &mut tag)
                .expect("encrypt"),
            Err(_) => {
                let mut state = gcm.encryptor(&nonce).expect("encryptor");
                state.aad(&aad).expect("aad");
                state.update(&mut data).expect("update");
                tag = state.finalize();
            }
        }
        return json!({
            "tcId": t["tcId"],
            "ct": hex_string(&data),
            "tag": hex_string(&tag[..tag_len]),
        });
    }

    // The one-shot takes full tags only, so the shorter ones go
    // through the streaming form, which is where a protocol would
    // check them.
    let mut data = hex(&t["ct"]);
    let given = hex(&t["tag"]);
    let short_nonce = <&[u8; 12]>::try_from(&nonce[..]).ok();
    let result = if let (16, Some(nonce)) = (tag_len, short_nonce) {
        let full: [u8; 16] = given.try_into().expect("tag");
        gcm.decrypt(nonce, &aad, &mut data, &full)
    } else {
        let mut state = gcm.decryptor(&nonce).expect("decryptor");
        state.aad(&aad).expect("aad");
        state.update(&mut data).expect("update");
        state.verify_truncated(&given)
    };
    match result {
        Ok(()) => json!({"tcId": t["tcId"], "pt": hex_string(&data)}),
        Err(Error::AuthenticationFailed) => {
            json!({"tcId": t["tcId"], "testPassed": false})
        }
        Err(e) => panic!("tcId {}: {e}", t["tcId"]),
    }
}
