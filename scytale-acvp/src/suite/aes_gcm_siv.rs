//! ACVP-AES-GCM-SIV, through [`GcmSiv`] over AES-128 and AES-256.
//!
//! This suite carries the ciphertext with its tag appended, rather
//! than as separate fields, and includes decryption cases whose tags
//! must be rejected.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, key_of, text, unknown_test_type};
use scytale::Random;
use scytale::aead::{Aead, GcmSiv, SivKey};
use scytale::cipher::BlockCipher;
use scytale::cipher::aes::{Aes128, Aes256};
use serde_json::{Value, json};

/// The tag length the standard fixes.
const TAG: usize = 16;

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let encrypt = match text(group, "direction")? {
            "encrypt" => true,
            "decrypt" => false,
            other => return Err(Error::new(format!("direction {other}"))),
        };
        match text(group, "testType")? {
            // Not `aes_width!`: GCM-SIV is not defined over AES-192.
            "AFT" => answer_tests(group, |t| {
                let key = hex(t, "key")?;
                match key.len() {
                    16 => aft::<Aes128>(&key, t, encrypt),
                    32 => aft::<Aes256>(&key, t, encrypt),
                    n => Err(Error::new(format!("key of {n} bytes"))),
                }
            }),
            _ => Err(unknown_test_type(group)),
        }
    })
}

fn aft<C: BlockCipher<Block = [u8; 16], Key: SivKey>>(
    key: &[u8],
    t: &Value,
    encrypt: bool,
) -> Result<Value, Error> {
    let siv = GcmSiv::<C>::new(&key_of::<C>(key)?);
    let nonce: [u8; 12] = hex(t, "iv")?
        .try_into()
        .map_err(|_| Error::new("iv is not 12 bytes"))?;
    let aad = hex(t, "aad")?;
    if encrypt {
        let mut data = hex(t, "pt")?;
        let mut tag = [0u8; TAG];
        siv.encrypt(&nonce, &aad, &mut data, &mut tag)?;
        data.extend_from_slice(&tag);
        return Ok(json!({ "ct": hex_value(&data) }));
    }
    let sealed = hex(t, "ct")?;
    let split = sealed
        .len()
        .checked_sub(TAG)
        .ok_or_else(|| Error::new("ct shorter than its tag"))?;
    let (ct, tag) = sealed.split_at(split);
    let tag: &[u8; TAG] = tag
        .try_into()
        .map_err(|_| Error::new("tag is not 16 bytes"))?;
    let mut data = ct.to_vec();
    match siv.decrypt(&nonce, &aad, &mut data, tag) {
        Ok(()) => Ok(json!({ "pt": hex_value(&data) })),
        Err(scytale::Error::AuthenticationFailed) => {
            Ok(json!({ "testPassed": false }))
        }
        Err(e) => Err(e.into()),
    }
}
