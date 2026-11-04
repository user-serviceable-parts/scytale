//! ACVP-AES-GCM 1.0, through [`Gcm`] over any block cipher.
//!
//! This suite is smaller than the others but reaches further: tags
//! of 32 and 128 bits, empty and non-empty additional data and
//! message, decryption cases that are meant to fail, which check that
//! a bad tag is rejected rather than quietly accepted, and nonces of
//! 96 bits and otherwise.

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
        let mut data = hex(t, "pt")?;
        let mut tag = [0u8; 16];
        // The suite runs several nonce lengths. The one-shot takes
        // the standard twelve bytes; the rest go through the
        // incremental form, which accepts any length.
        match <&[u8; 12]>::try_from(&nonce[..]) {
            Ok(nonce) => gcm.encrypt(nonce, &aad, &mut data, &mut tag)?,
            Err(_) => {
                let mut state = gcm.encryptor(&nonce)?;
                state.aad(&aad)?;
                state.update(&mut data)?;
                tag = state.finalize();
            }
        }
        return Ok(json!({
            "ct": hex_value(&data),
            "tag": hex_value(&tag[..tag_len]),
        }));
    }
    // The one-shot takes full tags only, so the shorter ones go
    // through the streaming form, which is where a protocol would
    // check them.
    let mut data = hex(t, "ct")?;
    let tag = hex(t, "tag")?;
    let short_nonce = <&[u8; 12]>::try_from(&nonce[..]).ok();
    let result = match (<[u8; 16]>::try_from(&tag[..]), short_nonce) {
        (Ok(full), Some(nonce)) => gcm.decrypt(nonce, &aad, &mut data, &full),
        _ => {
            let mut state = gcm.decryptor(&nonce)?;
            state.aad(&aad)?;
            state.update(&mut data)?;
            state.verify_truncated(&tag)
        }
    };
    match result {
        Ok(()) => Ok(json!({ "pt": hex_value(&data) })),
        Err(scytale::Error::AuthenticationFailed) => {
            Ok(json!({ "testPassed": false }))
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn vendored() {
        for suite in super::super::find("ACVP-AES-GCM") {
            super::super::check(suite);
        }
    }
}
