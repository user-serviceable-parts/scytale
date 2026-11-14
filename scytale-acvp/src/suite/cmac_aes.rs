//! CMAC-AES 1.0, through [`Cmac`] over any block cipher and the
//! [`Mac`] trait.
//!
//! Generation and verification at every key width, with messages of
//! no bytes, a partial last block and many blocks, and tags of 64, 88
//! and 128 bits. A verification case marked as not passing carries a
//! tag that must be refused.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, hex, hex_value, int, key_of, text, unknown_test_type,
};
use scytale::Random;
use scytale::cipher::BlockCipher;
use scytale::constant_time;
use scytale::mac::Mac;
use scytale::mac::cmac::Cmac;
use serde_json::{Value, json};

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let generate = match text(group, "direction")? {
            "gen" => true,
            "ver" => false,
            other => return Err(Error::new(format!("direction {other}"))),
        };
        let mac_len = int(group, "macLen")? as usize / 8;
        match text(group, "testType")? {
            "AFT" => answer_tests(group, |t| {
                let key = hex(t, "key")?;
                aes_width!(key, C => {
                    let mac = Cmac::<C>::new(&key_of::<C>(&key)?);
                    aft(mac, t, generate, mac_len)
                })
            }),
            _ => Err(unknown_test_type(group)),
        }
    })
}

fn aft<C: BlockCipher<Block = [u8; 16]>>(
    mut mac: Cmac<C>,
    t: &Value,
    generate: bool,
    mac_len: usize,
) -> Result<Value, Error> {
    let message = hex(t, "message")?;
    mac.update(&message);
    let tag = mac.finalize();
    let prefix = tag
        .get(..mac_len)
        .ok_or_else(|| Error::new(format!("macLen {mac_len} bytes")))?;
    if generate {
        return Ok(json!({ "mac": hex_value(prefix) }));
    }
    let expected = hex(t, "mac")?;
    if expected.len() != mac_len {
        return Err(Error::new("mac is not macLen long"));
    }
    // A tag cut short is compared as a prefix, in constant time, as a
    // protocol that truncates would check it.
    let passed = constant_time::equal(prefix, &expected);
    // A full tag goes through the trait's check as well; `finalize`
    // left the MAC keyed and ready. The two must agree.
    if mac_len == tag.len() {
        mac.update(&message);
        if mac.verify(&expected).is_ok() != passed {
            return Err(Error::new("verify disagrees with the comparison"));
        }
    }
    Ok(json!({ "testPassed": passed }))
}
