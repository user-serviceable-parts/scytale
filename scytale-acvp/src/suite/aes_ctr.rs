//! ACVP-AES-CTR 1.0, through [`Ctr`] over any block cipher.
//!
//! This suite has no Monte Carlo tests, only one-shot ones, but they
//! are more searching than the other suites': the payload length is
//! given in bits and is usually not a whole number of bytes.
//!
//! Counter mode is defined for any number of bits, the final
//! keystream block simply being cut short. [`Ctr`] works in whole
//! bytes, which is what callers want, so a length that is not a
//! multiple of eight is answered over its significant bits only: the
//! bits past the end are ours to leave as we like, and the vectors
//! record them as zero.
//!
//! The registration has the counter generated internally, so the
//! server's encrypt prompt gives no IV and the answer must carry the
//! one used. The vendored file records it; with it the answer
//! matches the file, and without it one is drawn from the generator:
//! a random nonce and IV with the block counter at one, as RFC 3686
//! lays the counter block out and the server checks.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, hex, hex_value, int, key_of, opt_hex, text, unknown_test_type,
};
use scytale::Random;
use scytale::cipher::mode::Ctr;
use serde_json::{Value, json};

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let encrypt = match text(group, "direction")? {
            "encrypt" => true,
            "decrypt" => false,
            other => return Err(Error::new(format!("direction {other}"))),
        };
        match text(group, "testType")? {
            "AFT" => answer_tests(group, |t| aft(t, encrypt, rng)),
            _ => Err(unknown_test_type(group)),
        }
    })
}

/// Zeroes every bit past `bits`, the part the vector does not
/// specify.
fn truncate(data: &mut [u8], bits: usize) {
    for i in bits..8 * data.len() {
        data[i / 8] &= !(1 << (7 - i % 8));
    }
}

fn aft(t: &Value, encrypt: bool, rng: &mut dyn Random) -> Result<Value, Error> {
    let key = hex(t, "key")?;
    let bits = int(t, "payloadLen")? as usize;
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut data = hex(t, input)?;
    let counter = match opt_hex(t, "iv")? {
        Some(iv) => iv,
        None if encrypt => {
            let mut iv = vec![0u8; 16];
            rng.fill(&mut iv[..12])?;
            iv[15] = 1;
            iv
        }
        None => return Err(Error::new("missing field iv")),
    };
    let block = <[u8; 16]>::try_from(&counter[..])
        .map_err(|_| Error::new("field iv is not one block"))?;
    aes_width!(key, C => {
        let ctr = Ctr::<C>::new(&key_of::<C>(&key)?);
        if encrypt {
            ctr.encrypt(&block, &mut data);
        } else {
            ctr.decrypt(&block, &mut data);
        }
    });
    truncate(&mut data, bits);
    let mut answer = json!({ output: hex_value(&data) });
    if encrypt {
        answer["iv"] = hex_value(&counter);
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::super::{find, fixed_rng};
    use crate::support::{hex, list};
    use serde_json::json;

    /// As the server prompts, with no IV for encryption: the answer
    /// must carry an IV under which its ciphertext decrypts.
    #[test]
    fn encrypt_draws_an_iv() {
        let mut rng = fixed_rng();
        for suite in find("ACVP-AES-CTR") {
            let Some(doc) = super::super::vendored(suite) else {
                continue;
            };
            for group in list(&doc, "testGroups").unwrap() {
                if group["direction"] != "encrypt" {
                    continue;
                }
                for t in list(group, "tests").unwrap() {
                    let mut prompt = t.clone();
                    prompt.as_object_mut().unwrap().remove("iv");
                    let a = super::aft(&prompt, true, &mut rng).unwrap();
                    let iv = hex(&a, "iv").unwrap();
                    assert_eq!(iv.len(), 16);
                    assert_eq!(iv[12..], [0, 0, 0, 1], "RFC 3686 counter");
                    let back = json!({
                        "key": t["key"],
                        "payloadLen": t["payloadLen"],
                        "iv": a["iv"],
                        "ct": a["ct"],
                    });
                    let p = super::aft(&back, false, &mut rng).unwrap();
                    assert_eq!(hex(&p, "pt").unwrap(), hex(t, "pt").unwrap());
                }
            }
        }
    }
}
