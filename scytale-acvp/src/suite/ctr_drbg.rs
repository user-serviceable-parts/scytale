//! ctrDRBG 1.0, answered through [`CtrDrbg`].
//!
//! The generator is not generic over a block cipher the way the modes
//! are: it is AES-256 and nothing else. The AES underneath is the
//! dispatching one, so whichever implementation this processor uses is
//! the one being answered for.
//!
//! # What is answered
//!
//! The suite covers four shapes of the mechanism for each key size,
//! and all four are answered for AES-256:
//!
//! - **With the derivation function**, which is
//!   [`CtrDrbg::try_new_seeded`] and every reseeding from it.
//! - **Without it**, which is [`CtrDrbg::try_new_full_entropy`]: the
//!   seed goes straight in, the personalization and every later input
//!   padded and XORed over it.
//! - **With prediction resistance**, where every request is preceded
//!   by a reseeding from fresh entropy and the additional input:
//!   [`CtrDrbg::reseed_with`] followed by a plain request.
//! - **Without it**, where one reseeding is followed by requests
//!   carrying additional input of their own: [`CtrDrbg::fill_with`].
//!
//! Between them that is the whole of the mechanism's arithmetic: both
//! ways of making a seed, instantiation, reseeding, generation with
//! and without additional input, and the state update after every
//! request. The other key sizes and TDES are skipped, and say so,
//! since the library offers only AES-256.

use super::{answer_groups, answer_tests, skip};
use crate::support::{
    Error, NoEntropy, flag, hex, hex_value, int, list, opt_text, text,
    unknown_test_type,
};
use scytale::Random;
use scytale::random::{CtrDrbg, MIN_SEED};
use serde_json::{Value, json};

pub fn answer(doc: &Value, _rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        if text(group, "mode")? != "AES-256" {
            return skip(group, "not AES-256");
        }
        let bits = int(group, "returnedBitsLen")? as usize;
        let derivation = flag(group, "derFunc")?;
        answer_tests(group, |t| aft(t, bits, derivation))
    })
}

fn aft(t: &Value, bits: usize, derivation: bool) -> Result<Value, Error> {
    // The source is never drawn on: every reseeding is handed its
    // entropy by the vectors.
    let mut rng = if derivation {
        // Instantiation takes the entropy, the nonce and the
        // personalization string as one run of material, which is
        // what the derivation function is handed.
        let mut material = hex(t, "entropyInput")?;
        material.extend(hex(t, "nonce")?);
        material.extend(hex(t, "persoString")?);
        CtrDrbg::try_new_seeded(&material, NoEntropy)?
    } else {
        // Without it the entropy is the seed itself, no nonce, and
        // the personalization is applied over it.
        let entropy: [u8; MIN_SEED] = hex(t, "entropyInput")?
            .try_into()
            .map_err(|_| Error::new("entropyInput is not a seed"))?;
        CtrDrbg::try_new_full_entropy(
            &entropy,
            &hex(t, "persoString")?,
            NoEntropy,
        )?
    };

    let mut out = vec![0u8; bits / 8];
    for other in list(t, "otherInput")? {
        let entropy = hex(other, "entropyInput")?;
        let additional = hex(other, "additionalInput")?;
        match opt_text(other, "intendedUse") {
            Some("reSeed") => rng.reseed_with(&entropy, &additional)?,
            // Prediction resistance is a reseeding from fresh entropy
            // and the additional input, then a request carrying
            // nothing further.
            Some("generate") if !entropy.is_empty() => {
                rng.reseed_with(&entropy, &additional)?;
                rng.fill(&mut out)?;
            }
            Some("generate") => rng.fill_with(&mut out, &additional)?,
            other => {
                return Err(Error::new(format!("intendedUse {other:?}")));
            }
        }
    }
    // The bits answered are those of the last request.
    Ok(json!({ "returnedBits": hex_value(&out) }))
}
