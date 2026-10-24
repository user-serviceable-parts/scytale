//! The one-step key derivation of NIST SP 800-56C r2, section 4: the
//! KDF for a key agreement's shared secret `Z`.
//!
//! Block `i` is `H(i || Z || FixedInfo)`, the counter 32 bits and
//! starting from one, where `H` is a hash, HMAC keyed with a salt, or
//! KMAC keyed with a salt. `FixedInfo` names the key being derived,
//! typically the parties' identities and the length; its layout is
//! the protocol's, so it is taken here as a list of parts already
//! encoded.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::one_step;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let z = [0x5a; 32];
//! let mut key = [0u8; 32];
//! let fixed_info: [&[u8]; 3] = [b"alice", b"bob", &256u32.to_be_bytes()];
//! one_step::hash::<Sha256>(&z, &fixed_info, &mut key)?;
//! # Ok(())
//! # }
//! ```
//!
//! The `_no_counter` forms are the variant without the counter,
//! which yields one block at most: a hash's digest or an HMAC's tag,
//! or for KMAC whatever length is asked for.
//!
//! For HKDF, the standard's two-step alternative, see
//! [`hkdf`](super::hkdf).

use zeroize::Zeroize;

use crate::Error;
use crate::hash::Hash;
use crate::mac::Mac;
use crate::mac::kmac::{Kmac128, Kmac256};

/// The customization string the standard gives KMAC here.
const KMAC_CUSTOMIZATION: &[u8] = b"KDF";

/// Fills `out` with `H(i || Z || FixedInfo)` for `i` from one.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `out` needs more than 2^32 - 1 blocks.
pub fn hash<H: Hash + Default>(
    z: &[u8],
    fixed_info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    check::<H::Output>(out)?;
    let mut hash = H::default();
    for (i, chunk) in out.chunks_mut(size_of::<H::Output>()).enumerate() {
        hash.update(&(i as u32 + 1).to_be_bytes());
        hash.update(z);
        fixed_info.iter().for_each(|part| hash.update(part));
        emit(hash.finalize(), chunk);
    }
    Ok(())
}

/// Fills `out` with `H(Z || FixedInfo)`, the variant without a
/// counter.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `out` is longer than a digest.
pub fn hash_no_counter<H: Hash + Default>(
    z: &[u8],
    fixed_info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() > size_of::<H::Output>() {
        return Err(Error::InvalidLength(out.len()));
    }
    let mut hash = H::default();
    hash.update(z);
    fixed_info.iter().for_each(|part| hash.update(part));
    emit(hash.finalize(), out);
    Ok(())
}

/// Fills `out` with `MAC(i || Z || FixedInfo)` for `i` from one,
/// where `mac` is HMAC keyed with the salt.
///
/// The standard names HMAC; any [`Mac`] is taken so that the hash
/// under it is the caller's choice. `mac` is reset first, and left at
/// the start of a message.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `out` needs more than 2^32 - 1 blocks.
pub fn mac<M: Mac>(
    mac: &mut M,
    z: &[u8],
    fixed_info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    check::<M::Tag>(out)?;
    mac.reset();
    for (i, chunk) in out.chunks_mut(size_of::<M::Tag>()).enumerate() {
        mac.update(&(i as u32 + 1).to_be_bytes());
        mac.update(z);
        fixed_info.iter().for_each(|part| mac.update(part));
        emit(mac.finalize(), chunk);
    }
    Ok(())
}

/// Fills `out` with `MAC(Z || FixedInfo)`, the variant without a
/// counter.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `out` is longer than a tag.
pub fn mac_no_counter<M: Mac>(
    mac: &mut M,
    z: &[u8],
    fixed_info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() > size_of::<M::Tag>() {
        return Err(Error::InvalidLength(out.len()));
    }
    mac.reset();
    mac.update(z);
    fixed_info.iter().for_each(|part| mac.update(part));
    emit(mac.finalize(), out);
    Ok(())
}

/// Fills `out` with `KMAC128(salt, 1 || Z || FixedInfo, L, "KDF")`.
///
/// KMAC gives any length in one call, so the counter is always one.
pub fn kmac128(salt: &[u8], z: &[u8], fixed_info: &[&[u8]], out: &mut [u8]) {
    let mut mac = Kmac128::new(salt, KMAC_CUSTOMIZATION);
    mac.update(&1u32.to_be_bytes());
    mac.update(z);
    fixed_info.iter().for_each(|part| mac.update(part));
    mac.finalize_to(out);
}

/// Fills `out` with `KMAC256(salt, 1 || Z || FixedInfo, L, "KDF")`.
pub fn kmac256(salt: &[u8], z: &[u8], fixed_info: &[&[u8]], out: &mut [u8]) {
    let mut mac = Kmac256::new(salt, KMAC_CUSTOMIZATION);
    mac.update(&1u32.to_be_bytes());
    mac.update(z);
    fixed_info.iter().for_each(|part| mac.update(part));
    mac.finalize_to(out);
}

/// Fills `out` with `KMAC128(salt, Z || FixedInfo, L, "KDF")`, the
/// variant without a counter.
pub fn kmac128_no_counter(
    salt: &[u8],
    z: &[u8],
    fixed_info: &[&[u8]],
    out: &mut [u8],
) {
    let mut mac = Kmac128::new(salt, KMAC_CUSTOMIZATION);
    mac.update(z);
    fixed_info.iter().for_each(|part| mac.update(part));
    mac.finalize_to(out);
}

/// Fills `out` with `KMAC256(salt, Z || FixedInfo, L, "KDF")`, the
/// variant without a counter.
pub fn kmac256_no_counter(
    salt: &[u8],
    z: &[u8],
    fixed_info: &[&[u8]],
    out: &mut [u8],
) {
    let mut mac = Kmac256::new(salt, KMAC_CUSTOMIZATION);
    mac.update(z);
    fixed_info.iter().for_each(|part| mac.update(part));
    mac.finalize_to(out);
}

/// Checks that a 32-bit counter can number the blocks of `out`.
fn check<T>(out: &[u8]) -> Result<(), Error> {
    let blocks = out.len().div_ceil(size_of::<T>()) as u64;
    if blocks > u64::from(u32::MAX) {
        return Err(Error::InvalidLength(out.len()));
    }
    Ok(())
}

/// Copies as much of a block as `chunk` takes, and wipes the block.
fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(mut block: T, chunk: &mut [u8]) {
    chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
    block.as_mut().zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::Sha256;
    use crate::mac::hmac::HmacSha256;

    /// The hash form is the standard's definition written out, block
    /// by block, and the fixed info in parts is one input.
    #[test]
    fn hash_is_the_definition() {
        let mut out = [0u8; 50];
        hash::<Sha256>(b"secret", &[b"fix", b"ed"], &mut out).expect("kdf");
        for (i, block) in out.chunks(32).enumerate() {
            let mut h = Sha256::default();
            h.update(&(i as u32 + 1).to_be_bytes());
            h.update(b"secretfixed");
            assert_eq!(block, &h.finalize()[..block.len()]);
        }
    }

    /// The HMAC form is the same over HMAC under the salt.
    #[test]
    fn mac_is_the_definition() {
        let mut out = [0u8; 40];
        mac(&mut HmacSha256::new(b"salt"), b"z", &[b"info"], &mut out)
            .expect("kdf");
        let mut want = HmacSha256::new(b"salt");
        want.update(&[0, 0, 0, 1]);
        want.update(b"zinfo");
        assert_eq!(out[..32], want.finalize());
    }

    /// Without the counter there is one block, and asking for more
    /// is refused.
    #[test]
    fn no_counter_is_one_block() {
        let mut out = [0u8; 32];
        hash_no_counter::<Sha256>(b"z", &[b"info"], &mut out).expect("kdf");
        assert_eq!(out, Sha256::digest(b"zinfo"));
        let mut long = [0u8; 33];
        assert_eq!(
            hash_no_counter::<Sha256>(b"z", &[], &mut long),
            Err(Error::InvalidLength(33))
        );
        assert_eq!(
            mac_no_counter(&mut HmacSha256::new(b"s"), b"z", &[], &mut long),
            Err(Error::InvalidLength(33))
        );
    }

    /// The KMAC forms put the counter in, or leave it out, under the
    /// customization the standard fixes.
    #[test]
    fn kmac_is_the_definition() {
        let mut out = [0u8; 48];
        kmac128(b"salt", b"z", &[b"info"], &mut out);
        let mut want = [0u8; 48];
        let mut m = Kmac128::new(b"salt", b"KDF");
        m.update(b"\x00\x00\x00\x01zinfo");
        m.finalize_to(&mut want);
        assert_eq!(out, want);
        kmac128_no_counter(b"salt", b"z", &[b"info"], &mut out);
        m.update(b"zinfo");
        m.finalize_to(&mut want);
        assert_eq!(out, want);
        kmac256_no_counter(b"salt", b"z", &[b"info"], &mut want);
        assert_ne!(out, want);
        kmac256(b"salt", b"z", &[b"info"], &mut out);
        assert_ne!(out, want);
    }
}
