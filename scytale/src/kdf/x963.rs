//! The ANSI X9.63 KDF, the one SEC 1 gives ECIES: block `i` is
//! `H(Z || i || SharedInfo)`, the counter 32 bits and starting from
//! one.
//!
//! It is SP 800-56C's one-step hash KDF with the counter after the
//! secret instead of before it. Prefer [`one_step`](super::one_step)
//! for a new design; this is here for the protocols that name it.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::x963;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let z = [0x5a; 32];
//! let mut key = [0u8; 32];
//! x963::derive::<Sha256>(&z, &[b"shared info"], &mut key)?;
//! # Ok(())
//! # }
//! ```

use zeroize::Zeroize;

use crate::Error;
use crate::hash::Hash;

/// Fills `out` with `H(Z || i || SharedInfo)` for `i` from one.
/// `shared_info` is a list of parts, joined in the order given.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `out` needs more than 2^32 - 1 blocks.
pub fn derive<H: Hash + Default>(
    z: &[u8],
    shared_info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    let blocks = out.len().div_ceil(size_of::<H::Output>()) as u64;
    if blocks > u64::from(u32::MAX) {
        return Err(Error::InvalidLength(out.len()));
    }
    let mut hash = H::default();
    for (i, chunk) in out.chunks_mut(size_of::<H::Output>()).enumerate() {
        hash.update(z);
        hash.update(&(i as u32 + 1).to_be_bytes());
        shared_info.iter().for_each(|part| hash.update(part));
        let mut block = hash.finalize();
        chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
        block.as_mut().zeroize();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::Sha256;

    /// The counter goes after the secret, and the shared info in
    /// parts is one input.
    #[test]
    fn derive_is_the_definition() {
        let mut out = [0u8; 40];
        derive::<Sha256>(b"z", &[b"sha", b"red"], &mut out).expect("kdf");
        for (i, block) in out.chunks(32).enumerate() {
            let mut h = Sha256::default();
            h.update(b"z");
            h.update(&(i as u32 + 1).to_be_bytes());
            h.update(b"shared");
            assert_eq!(block, &h.finalize()[..block.len()]);
        }
    }

    /// It is not the one-step KDF, whose counter comes first.
    #[test]
    fn it_is_not_one_step() {
        let mut ours = [0u8; 32];
        let mut theirs = [0u8; 32];
        derive::<Sha256>(b"z", &[b"info"], &mut ours).expect("kdf");
        super::super::one_step::hash::<Sha256>(b"z", &[b"info"], &mut theirs)
            .expect("kdf");
        assert_ne!(ours, theirs);
    }
}
