//! ACVP-AES-GMAC 1.0: GCM with no plaintext, which is how the crate
//! provides GMAC. The suite's value is its verdicts: tags over
//! additional data only, at 128 and truncated 32 bits, under 96-bit
//! and longer nonces, with cases that must be rejected.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{
    Answers, groups as suite_groups, hex, hex_string, key_of, rejected,
    run_groups,
};
use crate::Error;
use crate::aead::{Aead, Gcm};
use crate::cipher::BlockCipher;
use serde_json::{Value, json};

const FILE: &str = "ACVP-AES-GMAC-1.0/internalProjection.json";

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

/// Runs the suite against `C`; a no-op without the vendored
/// vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = suite_groups::<C>(FILE, "ACVP-AES-GMAC", "1.0", "AFT")
    else {
        return;
    };
    let mut rejections = 0;
    let cases = run_groups(&groups, |group, encrypt| {
        let answers = tests::<C>(group, encrypt);
        rejections += rejected(&answers);
        answers
    });
    assert!(cases >= 8, "only {cases} cases");
    assert!(rejections >= 1, "only {rejections} rejections");
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

/// One case: the tag over the additional data, or whether a given
/// tag holds.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    t: &Value,
    encrypt: bool,
    tag_len: usize,
) -> Value {
    let key = key_of::<C>(&hex(&t["key"])).expect("key width");
    let gcm = Gcm::<C>::new(&key);
    let nonce = hex(&t["iv"]);
    let aad = hex(&t["aad"]);
    assert!(hex(&t["pt"]).is_empty() && hex(&t["ct"]).is_empty());
    if encrypt {
        // As in the GCM suite: the one-shot takes the standard
        // nonce, the incremental form takes the rest.
        let mut tag = [0u8; 16];
        match <&[u8; 12]>::try_from(&nonce[..]) {
            Ok(nonce) => gcm
                .encrypt(nonce, &aad, &mut [], &mut tag)
                .expect("encrypt"),
            Err(_) => {
                let mut state = gcm.encryptor(&nonce).expect("encryptor");
                state.aad(&aad).expect("aad");
                tag = state.finalize();
            }
        }
        return json!({"tcId": t["tcId"], "tag": hex_string(&tag[..tag_len])});
    }
    let mut state = gcm.decryptor(&nonce).expect("decryptor");
    state.aad(&aad).expect("aad");
    match state.verify_truncated(&hex(&t["tag"])) {
        Ok(()) => json!({"tcId": t["tcId"], "testPassed": true}),
        Err(Error::AuthenticationFailed) => {
            json!({"tcId": t["tcId"], "testPassed": false})
        }
        Err(e) => panic!("tcId {}: {e}", t["tcId"]),
    }
}
