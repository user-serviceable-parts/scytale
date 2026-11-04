//! ACVP-AES-FF3-1 1.0, through [`Ff3_1`] over any block cipher.
//!
//! The vectors give messages as text in a stated alphabet, and the
//! answers are text in it too. [`Ff3_1`] works in symbol values, so
//! each character is turned into its position in that alphabet and
//! back again.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, int, key_of, text, unknown_test_type};
use scytale::Random;
use scytale::cipher::mode::Ff3_1;
use serde_json::{Value, json};

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        let encrypt = match text(group, "direction")? {
            "encrypt" => true,
            "decrypt" => false,
            other => return Err(Error::new(format!("direction {other}"))),
        };
        let alphabet: Vec<char> = text(group, "alphabet")?.chars().collect();
        let radix = u32::try_from(int(group, "radix")?)
            .map_err(|_| Error::new("field radix is too large"))?;
        match text(group, "testType")? {
            "AFT" => answer_tests(group, |t| aft(t, encrypt, &alphabet, radix)),
            _ => Err(unknown_test_type(group)),
        }
    })
}

/// Turns text into symbol values, by position in the alphabet.
fn symbols(text: &str, alphabet: &[char]) -> Result<Vec<u16>, Error> {
    text.chars()
        .map(|c| {
            alphabet
                .iter()
                .position(|&a| a == c)
                .and_then(|i| u16::try_from(i).ok())
                .ok_or_else(|| {
                    Error::new(format!("{c:?} is not in the alphabet"))
                })
        })
        .collect()
}

/// Turns symbol values back into text.
fn spell(values: &[u16], alphabet: &[char]) -> Result<String, Error> {
    values
        .iter()
        .map(|&v| {
            alphabet.get(usize::from(v)).ok_or_else(|| {
                Error::new(format!("symbol {v} past the alphabet"))
            })
        })
        .collect()
}

fn aft(
    t: &Value,
    encrypt: bool,
    alphabet: &[char],
    radix: u32,
) -> Result<Value, Error> {
    let key = hex(t, "key")?;
    let tweak = <[u8; 7]>::try_from(hex(t, "tweak")?)
        .map_err(|_| Error::new("field tweak is not 7 bytes"))?;
    let (input, output) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut data = symbols(text(t, input)?, alphabet)?;
    aes_width!(key, C => {
        let ff3 = Ff3_1::<C>::try_new(&key_of::<C>(&key)?, radix)?;
        if encrypt {
            ff3.encrypt(&tweak, &mut data)?;
        } else {
            ff3.decrypt(&tweak, &mut data)?;
        }
    });
    Ok(json!({ output: spell(&data, alphabet)? }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn vendored() {
        for suite in super::super::find("ACVP-AES-FF3-1") {
            super::super::check(suite);
        }
    }
}
