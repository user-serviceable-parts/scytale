//! TLS v1.2 KDF (RFC 7627): the extended master secret from the
//! premaster secret and the session hash, then the key block from
//! it and the two randoms, under the cipher suite's hash. The suite
//! is the extended form only; the RFC 5246 form is the same function
//! with another label and seed.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, int, text, unknown_test_type};
use scytale::hash::Hash;
use scytale::hash::sha2::{Sha256, Sha384, Sha512};
use scytale::kdf::tls12;
use scytale::{BlockType, Random};
use serde_json::{Value, json};

/// The master secret's length, which TLS fixes.
const MASTER_SECRET_LEN: usize = 48;

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        if let Some(v) = group.get("tlsVersion").and_then(Value::as_str)
            && v != "v1.2_ems"
        {
            return Err(Error::new(format!("tlsVersion {v}")));
        }
        let key_block_len = int(group, "keyBlockLength")? as usize / 8;
        let alg = text(group, "hashAlg")?;
        answer_tests(group, |t| match alg {
            "SHA2-256" => case::<Sha256>(t, key_block_len),
            "SHA2-384" => case::<Sha384>(t, key_block_len),
            "SHA2-512" => case::<Sha512>(t, key_block_len),
            other => Err(Error::new(format!("hashAlg {other}"))),
        })
    })
}

fn case<H: Hash + Clone + BlockType + Default>(
    t: &Value,
    key_block_len: usize,
) -> Result<Value, Error> {
    let premaster = hex(t, "preMasterSecret")?;
    let session_hash = hex(t, "sessionHash")?;
    let mut master = vec![0u8; MASTER_SECRET_LEN];
    tls12::prf::<H>(
        &premaster,
        b"extended master secret",
        &[&session_hash],
        &mut master,
    );

    let server_random = hex(t, "serverRandom")?;
    let client_random = hex(t, "clientRandom")?;
    let mut key_block = vec![0u8; key_block_len];
    tls12::prf::<H>(
        &master,
        b"key expansion",
        &[&server_random, &client_random],
        &mut key_block,
    );
    Ok(json!({
        "masterSecret": hex_value(&master),
        "keyBlock": hex_value(&key_block),
    }))
}
