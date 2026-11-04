//! KDF 1.0 and KDF-KMAC Sp800-108r1, through [`sp800_108`].
//!
//! KDF 1.0 covers the three modes over HMAC with every SHA-1, SHA-2
//! and SHA-3 hash and over CMAC with AES at every width, with the
//! counter at each width and in each place: before, after and inside
//! the fixed data, the last at a bit position, and before the
//! chaining value or absent for the chaining modes. The CMAC-TDES
//! groups are skipped, and say so: the library has no Triple DES.
//!
//! The server gives only the key; the fixed data, and where the
//! counter breaks it, are the client's to choose and are answered
//! alongside the output. The vendored file records the ones NIST's
//! own run chose, so they are used when present to make the output
//! comparable. The output length is already encoded in the fixed
//! data where it matters, so an output that is not a whole number of
//! bytes is the bytes it needs with the bits past its end cleared.

use super::{answer_groups, answer_tests, skip};
use crate::support::{
    Error, hex, hex_value, int, key_of, opt_hex, opt_int, text,
    unknown_test_type,
};
use scytale::cipher::BlockCipher;
use scytale::cipher::aes::{Aes128, Aes192, Aes256};
use scytale::hash::Hash;
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use scytale::hash::sha2::{Sha512_224, Sha512_256};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::kdf::sp800_108::{self, Counter};
use scytale::mac::Mac;
use scytale::mac::cmac::Cmac;
use scytale::mac::hmac::Hmac;
use scytale::{BlockType, Random};
use serde_json::{Value, json};

/// The fixed data a live run makes up, in bytes: long enough that a
/// middle break has room on both sides.
const FIXED_DATA_LEN: usize = 32;

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    match doc.get("mode").and_then(Value::as_str) {
        None => answer_kdf(doc, rng),
        Some("KMAC") => answer_kmac(doc),
        Some(other) => Err(Error::new(format!("mode {other}"))),
    }
}

fn answer_kdf(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        let mac = text(group, "macMode")?;
        if mac == "CMAC-TDES" {
            return skip(group, "no Triple DES");
        }
        answer_tests(group, |t| {
            let key = hex(t, "keyIn")?;
            match mac {
                "CMAC-AES128" => cmac::<Aes128>(&key, group, t, rng),
                "CMAC-AES192" => cmac::<Aes192>(&key, group, t, rng),
                "CMAC-AES256" => cmac::<Aes256>(&key, group, t, rng),
                "HMAC-SHA-1" => hmac::<Sha1>(&key, group, t, rng),
                "HMAC-SHA2-224" => hmac::<Sha224>(&key, group, t, rng),
                "HMAC-SHA2-256" => hmac::<Sha256>(&key, group, t, rng),
                "HMAC-SHA2-384" => hmac::<Sha384>(&key, group, t, rng),
                "HMAC-SHA2-512" => hmac::<Sha512>(&key, group, t, rng),
                "HMAC-SHA2-512/224" => hmac::<Sha512_224>(&key, group, t, rng),
                "HMAC-SHA2-512/256" => hmac::<Sha512_256>(&key, group, t, rng),
                "HMAC-SHA3-224" => hmac::<Sha3_224>(&key, group, t, rng),
                "HMAC-SHA3-256" => hmac::<Sha3_256>(&key, group, t, rng),
                "HMAC-SHA3-384" => hmac::<Sha3_384>(&key, group, t, rng),
                "HMAC-SHA3-512" => hmac::<Sha3_512>(&key, group, t, rng),
                other => Err(Error::new(format!("macMode {other}"))),
            }
        })
    })
}

fn hmac<H>(
    key: &[u8],
    group: &Value,
    t: &Value,
    rng: &mut dyn Random,
) -> Result<Value, Error>
where
    H: Hash + Clone + BlockType + Default,
{
    case(&mut Hmac::<H>::new(key), group, t, rng)
}

fn cmac<C>(
    key: &[u8],
    group: &Value,
    t: &Value,
    rng: &mut dyn Random,
) -> Result<Value, Error>
where
    C: BlockCipher<Block = [u8; 16]>,
{
    let key = key_of::<Cmac<C>>(key)?;
    case(&mut Cmac::<C>::new(&key), group, t, rng)
}

/// One derivation: the output, the fixed data, and for a counter in
/// the middle of the fixed data, where it went.
fn case<M: Mac>(
    prf: &mut M,
    group: &Value,
    t: &Value,
    rng: &mut dyn Random,
) -> Result<Value, Error> {
    let fixed = match opt_hex(t, "fixedData")? {
        Some(fixed) => fixed,
        None => {
            let mut fixed = vec![0u8; FIXED_DATA_LEN];
            rng.fill(&mut fixed)?;
            fixed
        }
    };
    let bits = int(group, "keyOutLength")? as usize;
    // A chaining mode with no counter has no width to give, and the
    // server gives none; the vendored file writes one anyway.
    let width = match opt_int(group, "counterLength") {
        Some(width) => u32::try_from(width)
            .map_err(|_| Error::new("field counterLength is too large"))?,
        None => 0,
    };
    let end = 8 * fixed.len();
    let mut break_location = None;
    let counter = match text(group, "counterLocation")? {
        "none" => Counter::None,
        "before iterator" => Counter::BeforeIterator(width),
        "before fixed data" => Counter::InFixed { bits: width, at: 0 },
        "after fixed data" => Counter::InFixed {
            bits: width,
            at: end,
        },
        "middle fixed data" => {
            let at = opt_int(t, "breakLocation").unwrap_or(end as u64 / 2);
            break_location = Some(at);
            Counter::InFixed {
                bits: width,
                at: at as usize,
            }
        }
        other => return Err(Error::new(format!("counterLocation {other}"))),
    };

    let mut out = vec![0u8; bits.div_ceil(8)];
    let parts: [&[u8]; 1] = [&fixed];
    match text(group, "kdfMode")? {
        "counter" => {
            let Counter::InFixed { bits, at } = counter else {
                return Err(Error::new("counter mode with no counter"));
            };
            sp800_108::counter(prf, bits, at, &parts, &mut out)
        }
        "feedback" => {
            let iv = hex(t, "iv")?;
            sp800_108::feedback(prf, &iv, counter, &parts, &mut out)
        }
        "double pipeline iteration" => {
            sp800_108::double_pipeline(prf, counter, &parts, &mut out)
        }
        other => return Err(Error::new(format!("kdfMode {other}"))),
    }?;
    if !bits.is_multiple_of(8)
        && let Some(last) = out.last_mut()
    {
        *last &= 0xffu8 << (8 - bits % 8);
    }
    let mut answer = json!({
        "keyOut": hex_value(&out),
        "fixedData": hex_value(&fixed),
    });
    if let (Some(at), Some(obj)) = (break_location, answer.as_object_mut()) {
        obj.insert("breakLocation".into(), json!(at));
    }
    Ok(answer)
}

fn answer_kmac(doc: &Value) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        let kdf = match text(group, "macMode")? {
            "KMAC-128" => sp800_108::kmac128,
            "KMAC-256" => sp800_108::kmac256,
            other => return Err(Error::new(format!("macMode {other}"))),
        };
        answer_tests(group, |t| {
            let bits = int(t, "derivedKeyLength")?;
            if !bits.is_multiple_of(8) {
                return Err(Error::new("derivedKeyLength is not whole bytes"));
            }
            let mut out = vec![0u8; bits as usize / 8];
            kdf(
                &hex(t, "keyDerivationKey")?,
                &hex(t, "label")?,
                &hex(t, "context")?,
                &mut out,
            );
            Ok(json!({ "derivedKey": hex_value(&out) }))
        })
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    /// A live prompt gives only the key: the made-up fixed data and
    /// break must be answered, and must be what the output came from.
    #[test]
    fn live_prompt_answers_its_fixed_data() {
        let mut doc = json!({
            "algorithm": "KDF",
            "testGroups": [{
                "tgId": 1, "testType": "AFT", "kdfMode": "counter",
                "macMode": "HMAC-SHA2-256", "keyOutLength": 100,
                "counterLength": 16, "counterLocation": "middle fixed data",
                "tests": [{"tcId": 1, "keyIn": "000102030405060708090A0B"}]
            }]
        });
        let mut rng = super::super::fixed_rng();
        let live = super::answer(&doc, &mut rng).unwrap();
        let answered = &live["testGroups"][0]["tests"][0];
        assert_eq!(answered["fixedData"].as_str().unwrap().len(), 64);
        assert_eq!(answered["breakLocation"], 128);

        let test = &mut doc["testGroups"][0]["tests"][0];
        test["fixedData"] = answered["fixedData"].clone();
        test["breakLocation"] = json!(128);
        let mut rng = super::super::fixed_rng();
        let again = super::answer(&doc, &mut rng).unwrap();
        assert_eq!(again["testGroups"][0]["tests"][0], *answered);
    }

    /// The server leaves the counter's width out of a group that has
    /// no counter.
    #[test]
    fn no_counter_needs_no_width() {
        let doc = json!({
            "algorithm": "KDF",
            "testGroups": [{
                "tgId": 1, "testType": "AFT", "kdfMode": "feedback",
                "macMode": "CMAC-AES128", "keyOutLength": 8,
                "counterLocation": "none", "zeroLengthIv": true,
                "tests": [{
                    "tcId": 1, "iv": "",
                    "keyIn": "0715AA8C18FAA0A45586080BA19A7857",
                }]
            }]
        });
        let mut rng = super::super::fixed_rng();
        let answered = super::answer(&doc, &mut rng).unwrap();
        let key = &answered["testGroups"][0]["tests"][0]["keyOut"];
        assert_eq!(key.as_str().unwrap().len(), 2);
    }

    #[test]
    fn vendored() {
        for name in ["KDF-1.0", "KDF-KMAC-Sp800-108r1"] {
            for suite in super::super::find(name) {
                super::super::check(suite);
            }
        }
    }
}
