//! ACVP-AES-XPN 1.0, run through [`Xpn`] over any block cipher.
//!
//! The vectors give the session salt and the frame identifier
//! separately, which is how the mode takes them. Twelve of the
//! decryption cases carry a tag that must be rejected.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, rejected,
    run_groups,
};
use crate::Error;
use crate::KeyType;
use crate::aead::Xpn;
use crate::cipher::BlockCipher;
use serde_json::{Value, json};

const FILE: &str = "ACVP-AES-XPN-1.0/internalProjection.json";

/// The suite, for [`answer_aes`](super::answer_aes).
pub struct Suite;

impl Answers for Suite {
    fn tests<C: BlockCipher<Block = [u8; 16]>>(
        group: &Value,
        encrypt: bool,
    ) -> Vec<Value> {
        tests::<C>(group, encrypt)
    }
}

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("AFT") else {
        return;
    };
    let mut rejections = 0;
    let cases = run_groups(&groups, |group, encrypt| {
        let answers = tests::<C>(group, encrypt);
        rejections += rejected(&answers);
        answers
    });
    assert!(cases >= 33, "only {cases} AFT cases");
    assert!(
        rejections >= 1,
        "only {rejections} cases had to be rejected"
    );
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-XPN", "1.0", test_type)
}

/// The response to each test of a group.
fn tests<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> Vec<Value> {
    assert_eq!(group["testType"], "AFT", "tgId {}", group["tgId"]);
    let tag_len = group["tagLen"].as_u64().expect("tagLen") as usize / 8;
    group["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .map(|t| aft::<C>(t, encrypt, tag_len))
        .collect()
}

/// One case: ciphertext and tag, or plaintext, or a rejection.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    t: &Value,
    encrypt: bool,
    tag_len: usize,
) -> Value {
    let key = key_of::<C>(&hex(&t["key"])).expect("key width");
    let xpn = Xpn::<C>::new(&key);
    let salt: [u8; 12] = hex(&t["salt"]).try_into().expect("salt");
    let frame: [u8; 12] = hex(&t["iv"]).try_into().expect("iv");
    let aad = hex(&t["aad"]);

    if encrypt {
        let mut data = hex(&t["pt"]);
        let mut tag = [0u8; 16];
        xpn.encrypt(&salt, &frame, &aad, &mut data, &mut tag)
            .expect("encrypt");
        return json!({
            "tcId": t["tcId"],
            "ct": hex_string(&data),
            "tag": hex_string(&tag[..tag_len]),
        });
    }
    let mut data = hex(&t["ct"]);
    let given = hex(&t["tag"]);
    let result = if tag_len == 16 {
        let full: [u8; 16] = given.try_into().expect("tag");
        xpn.decrypt(&salt, &frame, &aad, &mut data, &full)
    } else {
        xpn.decrypt_truncated(&salt, &frame, &aad, &mut data, &given)
    };
    match result {
        Ok(()) => json!({"tcId": t["tcId"], "pt": hex_string(&data)}),
        Err(Error::AuthenticationFailed) => {
            json!({"tcId": t["tcId"], "testPassed": false})
        }
        Err(e) => panic!("tcId {}: {e}", t["tcId"]),
    }
}
