//! The one-time password the ACVP servers take as the login
//! password: RFC 6238 over HMAC-SHA-256, eight digits, thirty-second
//! steps from the Unix epoch, the seed as NIST hands it out, base64.

use crate::support::Error;
use scytale::codec::base64;
use scytale::hash::sha2::Sha256;
use scytale::mac::hmac::Hmac;
use std::time::{SystemTime, UNIX_EPOCH};

const STEP_SECONDS: u64 = 30;
const DIGITS: u32 = 8;

/// The code for `now`, in seconds since the epoch, under the
/// base64 `seed`.
pub fn code_at(seed: &str, now: u64) -> Result<String, Error> {
    let mut key = vec![0u8; seed.len()];
    let n = base64::decode(seed.trim().as_bytes(), &mut key)
        .map_err(|_| Error::new("TOTP seed is not base64"))?;
    let counter = (now / STEP_SECONDS).to_be_bytes();
    let mac = Hmac::<Sha256>::mac(&key[..n], &counter);
    // Dynamic truncation (RFC 4226): the low nibble of the last byte
    // picks four bytes, read big-endian with the top bit cleared.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let window = &mac[offset..offset + 4];
    let value =
        u32::from_be_bytes([window[0], window[1], window[2], window[3]])
            & 0x7fff_ffff;
    let code = value % 10u32.pow(DIGITS);
    Ok(format!("{code:0width$}", width = DIGITS as usize))
}

/// The code for this moment.
pub fn code(seed: &str) -> Result<String, Error> {
    code_at(seed, now()?)
}

/// Seconds until the next code: the rest of this window, plus one so
/// the clock has surely moved on.
pub fn seconds_left() -> Result<u64, Error> {
    Ok(STEP_SECONDS - now()? % STEP_SECONDS + 1)
}

fn now() -> Result<u64, Error> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new("clock before the epoch"))?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-256 column: the seed is the ASCII
    /// digits 1 to 0 repeated to 32 bytes, base64 here.
    #[test]
    fn rfc_6238_vectors() {
        let seed = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        for (now, expected) in [
            (59, "46119246"),
            (1_111_111_109, "68084774"),
            (1_111_111_111, "67062674"),
            (1_234_567_890, "91819424"),
            (2_000_000_000, "90698825"),
            (20_000_000_000, "77737706"),
        ] {
            assert_eq!(code_at(seed, now).unwrap(), expected, "at {now}");
        }
    }

    #[test]
    fn bad_seed_is_an_error() {
        assert!(code_at("not base64!", 0).is_err());
    }

    #[test]
    fn seconds_left_is_within_a_window() {
        let left = seconds_left().unwrap();
        assert!((1..=STEP_SECONDS + 1).contains(&left));
    }
}
