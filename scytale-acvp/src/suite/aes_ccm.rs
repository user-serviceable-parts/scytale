//! ACVP-AES-CCM 1.0, through [`Ccm`] over any block cipher.
//!
//! Every nonce length from 7 to 13 bytes and every tag length from 4
//! to 16, payloads up to 32 bytes, additional data up to 8,192, and
//! decryption cases that are *meant* to fail. The ciphertext carries
//! the tag on its end, both in the prompt and in the answer.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, hex, hex_value, int, key_of, text, unknown_test_type,
};
use scytale::Random;
use scytale::aead::Ccm;
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
                    let ccm = Ccm::<C>::new(&key_of::<C>(&key)?);
                    aft(&ccm, t, encrypt, tag_len)
                })
            }),
            _ => Err(unknown_test_type(group)),
        }
    })
}

fn aft<C: BlockCipher<Block = [u8; 16]>>(
    ccm: &Ccm<C>,
    t: &Value,
    encrypt: bool,
    tag_len: usize,
) -> Result<Value, Error> {
    let nonce = hex(t, "iv")?;
    let aad = hex(t, "aad")?;
    if encrypt {
        let mut data = hex(t, "pt")?;
        let mut tag = vec![0u8; tag_len];
        ccm.encrypt(&nonce, &aad, &mut data, &mut tag)?;
        data.extend_from_slice(&tag);
        return Ok(json!({ "ct": hex_value(&data) }));
    }
    let sealed = hex(t, "ct")?;
    let split = sealed
        .len()
        .checked_sub(tag_len)
        .ok_or_else(|| Error::new("ct shorter than its tag"))?;
    let (ct, tag) = sealed.split_at(split);
    let mut data = ct.to_vec();
    match ccm.decrypt(&nonce, &aad, &mut data, tag) {
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
        for suite in super::super::find("ACVP-AES-CCM") {
            super::super::check(suite);
        }
    }
}
