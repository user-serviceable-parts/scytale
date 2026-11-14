//! ACVP-AES-GMAC 1.0: GCM with no plaintext, which is how the crate
//! provides GMAC. The suite's value is its verdicts: tags over
//! additional data only, at 128 and truncated 32 bits, under 96-bit
//! and longer nonces, with cases that must be rejected.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, hex, hex_value, int, key_of, text, unknown_test_type,
};
use scytale::Random;
use scytale::aead::{Aead, Gcm};
use scytale::cipher::BlockCipher;
use serde_json::{Value, json};

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let encrypt = match text(group, "direction")? {
            "encrypt" => true,
            "decrypt" => false,
            other => return Err(Error::new(format!("direction {other}"))),
        };
        let tag_len = int(group, "tagLen")? as usize / 8;
        match text(group, "testType")? {
            "AFT" => answer_tests(group, |t| {
                let key = hex(t, "key")?;
                aes_width!(key, C => {
                    let gcm = Gcm::<C>::new(&key_of::<C>(&key)?);
                    aft(&gcm, t, encrypt, tag_len)
                })
            }),
            _ => Err(unknown_test_type(group)),
        }
    })
}

fn aft<C: BlockCipher<Block = [u8; 16]>>(
    gcm: &Gcm<C>,
    t: &Value,
    encrypt: bool,
    tag_len: usize,
) -> Result<Value, Error> {
    let nonce = hex(t, "iv")?;
    let aad = hex(t, "aad")?;
    if encrypt {
        // As in the GCM suite: the one-shot takes the standard
        // nonce, the incremental form takes the rest.
        let mut tag = [0u8; 16];
        match <&[u8; 12]>::try_from(&nonce[..]) {
            Ok(nonce) => gcm.encrypt(nonce, &aad, &mut [], &mut tag)?,
            Err(_) => {
                let mut state = gcm.encryptor(&nonce)?;
                state.aad(&aad)?;
                tag = state.finalize();
            }
        }
        let tag = tag
            .get(..tag_len)
            .ok_or_else(|| Error::new(format!("tagLen {tag_len} bytes")))?;
        return Ok(json!({ "tag": hex_value(tag) }));
    }
    let tag = hex(t, "tag")?;
    let mut state = gcm.decryptor(&nonce)?;
    state.aad(&aad)?;
    match state.verify_truncated(&tag) {
        Ok(()) => Ok(json!({ "testPassed": true })),
        Err(scytale::Error::AuthenticationFailed) => {
            Ok(json!({ "testPassed": false }))
        }
        Err(e) => Err(e.into()),
    }
}
