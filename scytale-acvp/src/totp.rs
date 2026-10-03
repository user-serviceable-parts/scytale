//! The one-time password the server asks for at login: RFC 6238
//! as NIST configures it, HMAC-SHA-256, eight digits, a thirty
//! second step from the Unix epoch. The seed arrives from NIST as
//! base64.

use std::time::{SystemTime, UNIX_EPOCH};

use scytale::codec::base64;
use scytale::hash::sha2::Sha256;
use scytale::mac::hmac::Hmac;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Result;

/// Seconds per time step.
const STEP: u64 = 30;

/// Digits in a password, leading zeros kept.
const DIGITS: usize = 8;

/// A TOTP seed, wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Totp {
    seed: Vec<u8>,
}

impl Totp {
    /// The seed as NIST ships it, base64 with no line breaks.
    pub fn from_base64(text: &str) -> Result<Self> {
        let text = text.trim();
        let mut seed = vec![0u8; text.len() / 4 * 3 + 3];
        let len = base64::decode(text.as_bytes(), &mut seed)
            .map_err(|_| "the TOTP seed is not base64")?;
        seed.truncate(len);
        Ok(Totp { seed })
    }

    /// The password for the step containing `unix_seconds`.
    pub fn password_at(&self, unix_seconds: u64) -> String {
        let counter = (unix_seconds / STEP).to_be_bytes();
        let tag = Hmac::<Sha256>::mac(&self.seed, &counter);
        // Dynamic truncation, RFC 4226 section 5.3: the low nibble
        // of the last byte picks four bytes, whose top bit is
        // dropped.
        let offset = usize::from(tag[tag.len() - 1] & 0x0f);
        let word = u32::from_be_bytes([
            tag[offset] & 0x7f,
            tag[offset + 1],
            tag[offset + 2],
            tag[offset + 3],
        ]);
        let code = word % 10u32.pow(DIGITS as u32);
        format!("{code:0DIGITS$}")
    }

    /// The password for now.
    pub fn password(&self) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "the clock is before 1970")?;
        Ok(self.password_at(now.as_secs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, the HMAC-SHA-256 rows; the seed there is
    /// the ASCII digits repeated to 32 bytes.
    fn seed() -> Totp {
        Totp {
            seed: b"12345678901234567890123456789012".to_vec(),
        }
    }

    #[test]
    fn rfc_6238_vectors() {
        let totp = seed();
        for (time, code) in [
            (59, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ] {
            assert_eq!(totp.password_at(time), code, "T={time}");
        }
    }

    #[test]
    fn keeps_leading_zeros() {
        // Found by search: a step whose code is below 10^7.
        let totp = seed();
        let found = (0..100_000u64)
            .map(|step| totp.password_at(step * STEP))
            .find(|code| code.starts_with('0'))
            .expect("some code starts with zero");
        assert_eq!(found.len(), DIGITS);
    }

    #[test]
    fn decodes_the_base64_seed() {
        let text = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=\n";
        let totp = Totp::from_base64(text).expect("base64");
        assert_eq!(totp.seed, seed().seed);
        assert_eq!(totp.password_at(59), "46119246");
    }

    #[test]
    fn rejects_a_seed_that_is_not_base64() {
        assert!(Totp::from_base64("not base64!").is_err());
    }
}
