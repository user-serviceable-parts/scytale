//! LMS keyGen (revision 1.0), sigGen and sigVer (revision SP800-208),
//! single trees under every set SP 800-208 defines. Key generation
//! grows the tree from the vector's `seed` and `i` by RFC 8554
//! appendix A, which is the derivation the suite specifies, and so
//! reproduces the expected public key. Signing uses a key of the
//! group's sets generated here, as the protocol has it: the response
//! carries the public key with the group, and the offline check
//! verifies each signature under it rather than comparing bytes,
//! since the vendored signatures were made with NIST's own key.

use super::{answer_groups, answer_tests};
use crate::support::{Error, Rng, hex, hex_value, text};
use scytale::Random;
use scytale::sig::lms::{Lmots, Lms, PrivateKey, PublicKey};
use serde_json::{Value, json};

/// The group's two sets.
fn sets(group: &Value) -> Result<(Lms, Lmots), Error> {
    let lms = Lms::from_name(text(group, "lmsMode")?)
        .map_err(|_| Error::new(format!("lmsMode {}", group["lmsMode"])))?;
    let ots = Lmots::from_name(text(group, "lmOtsMode")?)
        .map_err(|_| Error::new(format!("lmOtsMode {}", group["lmOtsMode"])))?;
    Ok((lms, ots))
}

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    let mode = text(doc, "mode")?;
    answer_groups(doc, |group| {
        let (lms, ots) = sets(group)?;
        match mode {
            "keyGen" => answer_tests(group, |t| key_gen(lms, ots, t)),
            "sigGen" => {
                let mut key = PrivateKey::generate(&mut Rng(rng), lms, ots)?;
                let public = key.public_key().clone();
                let answered =
                    answer_tests(group, |t| sig_gen(&mut key, rng, t))?;
                Ok(answered.map(|mut answered| {
                    let key = hex_value(&public.bytes()[..public.len()]);
                    answered["publicKey"] = key;
                    answered
                }))
            }
            "sigVer" => {
                let public = PublicKey::new(&hex(group, "publicKey")?)?;
                answer_tests(group, |t| sig_ver(&public, t))
            }
            other => Err(Error::new(format!("mode {other}"))),
        }
    })
}

fn key_gen(lms: Lms, ots: Lmots, t: &Value) -> Result<Value, Error> {
    let i = hex(t, "i")?;
    let i: [u8; 16] = i
        .as_slice()
        .try_into()
        .map_err(|_| Error::new(format!("i of {} bytes", i.len())))?;
    let key = PrivateKey::from_seed(lms, ots, &i, &hex(t, "seed")?)?;
    let public = key.public_key();
    Ok(json!({ "publicKey": hex_value(&public.bytes()[..public.len()]) }))
}

fn sig_gen(
    key: &mut PrivateKey,
    rng: &mut dyn Random,
    t: &Value,
) -> Result<Value, Error> {
    let mut signature = vec![0u8; key.signature_len()];
    let n = key.sign(&mut Rng(rng), &hex(t, "message")?, &mut signature)?;
    Ok(json!({ "signature": hex_value(&signature[..n]) }))
}

fn sig_ver(public: &PublicKey, t: &Value) -> Result<Value, Error> {
    let passed = public
        .verify(&hex(t, "message")?, &hex(t, "signature")?)
        .is_ok();
    Ok(json!({ "testPassed": passed }))
}

/// Checks a sigGen answer: the answered signature verifies under the
/// answered group's public key, and the file's under the file's.
pub fn verify_sig_gen(
    vendored_group: &Value,
    vendored_test: &Value,
    answered_group: &Value,
    answered_test: &Value,
) -> Result<(), Error> {
    let message = hex(vendored_test, "message")?;
    for (whose, group, t) in [
        ("answered", answered_group, answered_test),
        ("file's", vendored_group, vendored_test),
    ] {
        let public = PublicKey::new(&hex(group, "publicKey")?)
            .map_err(|e| Error::new(format!("{whose} publicKey: {e}")))?;
        public
            .verify(&message, &hex(t, "signature")?)
            .map_err(|_| {
                Error::new(format!("{whose} signature does not verify"))
            })?;
    }
    Ok(())
}
