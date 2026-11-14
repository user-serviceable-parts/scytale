//! ACVP-AES-XPN 1.0, through [`Xpn`] over any block cipher.
//!
//! The vectors give the session salt and the frame identifier
//! separately, which is how the mode takes them. Some of the
//! decryption cases carry a tag that must be rejected.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, hex, hex_value, int, key_of, text, unknown_test_type,
};
use scytale::Random;
use scytale::aead::Xpn;
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
                    let xpn = Xpn::<C>::new(&key_of::<C>(&key)?);
                    aft(&xpn, t, encrypt, tag_len)
                })
            }),
            _ => Err(unknown_test_type(group)),
        }
    })
}

fn twelve(t: &Value, name: &str) -> Result<[u8; 12], Error> {
    hex(t, name)?
        .try_into()
        .map_err(|_| Error::new(format!("{name} is not 12 bytes")))
}

fn aft<C: BlockCipher<Block = [u8; 16]>>(
    xpn: &Xpn<C>,
    t: &Value,
    encrypt: bool,
    tag_len: usize,
) -> Result<Value, Error> {
    let salt = twelve(t, "salt")?;
    let frame = twelve(t, "iv")?;
    let aad = hex(t, "aad")?;
    if encrypt {
        let mut data = hex(t, "pt")?;
        let mut tag = [0u8; 16];
        xpn.encrypt(&salt, &frame, &aad, &mut data, &mut tag)?;
        let tag = tag
            .get(..tag_len)
            .ok_or_else(|| Error::new(format!("tagLen {tag_len} bytes")))?;
        return Ok(json!({
            "ct": hex_value(&data),
            "tag": hex_value(tag),
        }));
    }
    let mut data = hex(t, "ct")?;
    let tag = hex(t, "tag")?;
    let result = match <[u8; 16]>::try_from(&tag[..]) {
        Ok(full) => xpn.decrypt(&salt, &frame, &aad, &mut data, &full),
        Err(_) => xpn.decrypt_truncated(&salt, &frame, &aad, &mut data, &tag),
    };
    match result {
        Ok(()) => Ok(json!({ "pt": hex_value(&data) })),
        Err(scytale::Error::AuthenticationFailed) => {
            Ok(json!({ "testPassed": false }))
        }
        Err(e) => Err(e.into()),
    }
}
