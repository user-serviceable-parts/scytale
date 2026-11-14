//! XChaCha20 (draft-irtf-cfrg-xchacha): ChaCha20 with a 192-bit
//! nonce.
//!
//! ChaCha20's nonce is 96 bits, which is too few to draw at random:
//! after 2^32 messages a repeat is more likely than not, and one
//! repeat gives away every message that shares it. XChaCha20 takes a
//! 192-bit nonce instead. The first 128 bits and the key go through
//! [`hchacha20`] to make a key for this message alone, and the last
//! 64 bits, behind four zero bytes, are the ChaCha20 nonce under that
//! key. The keystream is then ChaCha20's, from whichever kernel the
//! processor has; the extension costs one extra block a message.
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::xchacha20::XChaCha20;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let cipher = XChaCha20::new(&Key::from([0x42u8; 32]));
//! let nonce = [0u8; 24];
//! let mut message = *b"attack at dawn";
//! cipher.encrypt(&nonce, 0, &mut message)?;
//! cipher.decrypt(&nonce, 0, &mut message)?;
//! assert_eq!(&message, b"attack at dawn");
//! # Ok(())
//! # }
//! ```
//!
//! # Using it safely
//!
//! - A nonce may be drawn at random: 192 bits do not repeat in any
//!   number of messages a key will see. Counting them, with
//!   [`Nonces`](crate::cipher::Nonces), is still fine.
//! - **This authenticates nothing.** Use
//!   [`XChaCha20Poly1305`](crate::aead::XChaCha20Poly1305), which is
//!   this cipher under a MAC, unless a protocol supplies its own
//!   authentication.
//! - The counter is 32 bits, so one nonce carries at most 256 GiB;
//!   [`Error::MessageTooLong`] is returned rather than wrapping.

use core::fmt;

use zeroize::ZeroizeOnDrop;

use super::chacha20::{
    self, ChaCha20, HNONCE_SIZE, KEY_SIZE, OwnedAutoStream, hchacha20,
};
use crate::{Error, Key, KeyType};

/// The nonce length, in bytes.
pub const NONCE_SIZE: usize = 24;

/// XChaCha20 under one key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct XChaCha20 {
    key: Key<[u8; KEY_SIZE]>,
}

impl KeyType for XChaCha20 {
    type Key = Key<[u8; KEY_SIZE]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

impl XChaCha20 {
    /// Takes the key.
    pub fn new(key: &Key<[u8; KEY_SIZE]>) -> Self {
        XChaCha20 { key: key.clone() }
    }

    /// The ChaCha20 for one message, and its nonce: the key from
    /// HChaCha20 over the first sixteen bytes of `nonce`, and the
    /// last eight behind four zero bytes.
    pub(crate) fn message(
        &self,
        nonce: &[u8; NONCE_SIZE],
    ) -> (ChaCha20, [u8; chacha20::NONCE_SIZE]) {
        let mut head = [0u8; HNONCE_SIZE];
        head.copy_from_slice(&nonce[..HNONCE_SIZE]);
        let subkey = hchacha20(&self.key, &head);
        let mut short = [0u8; chacha20::NONCE_SIZE];
        short[4..].copy_from_slice(&nonce[HNONCE_SIZE..]);
        (ChaCha20::new(&subkey), short)
    }

    /// Encrypts `data` in place, its first byte at the start of
    /// block `counter`.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        let (cipher, short) = self.message(nonce);
        cipher.encrypt(&short, counter, data)
    }

    /// Decrypts `data` in place; the same operation as
    /// [`encrypt`](Self::encrypt).
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.encrypt(nonce, counter, data)
    }

    /// Starts a message that arrives in pieces.
    pub fn stream(&self, nonce: &[u8; NONCE_SIZE], counter: u32) -> Stream {
        let (cipher, short) = self.message(nonce);
        Stream(cipher.into_stream(&short, counter))
    }
}

impl fmt::Debug for XChaCha20 {
    /// Deliberately omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XChaCha20").finish_non_exhaustive()
    }
}

/// A message in progress under [`XChaCha20`]. It holds the key for
/// this message, so it does not borrow the cipher.
pub struct Stream(OwnedAutoStream);

impl Stream {
    /// Encrypts or decrypts the next piece of the message in place.
    ///
    /// Returns [`Error::MessageTooLong`] if the piece would take the
    /// block counter past 2^32, leaving `data` untouched.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.0.update(data)
    }
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> std::vec::Vec<u8> {
        let s: std::string::String =
            s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// draft-irtf-cfrg-xchacha-03 appendix A.3.2.
    const KEY: &str =
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const NONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555658";
    const PLAIN: &str = "
        5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973
        20616c736f206b6e6f776e2061732074686520417369617469632077696c6420
        646f672c2072656420646f672c20616e642077686973746c696e6720646f672e
        2049742069732061626f7574207468652073697a65206f662061204765726d61
        6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061
        206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c
        757369766520616e6420736b696c6c6564206a756d70657220697320636c6173
        736966696564207769746820776f6c7665732c20636f796f7465732c206a6163
        6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963
        2066616d696c792043616e696461652e";
    const KEYSTREAM_0: &str = "
        1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9a
        adec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d
        29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4
        cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25
        5e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe46221
        5cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf60
        7cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd
        241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290f
        a0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00
        b3df507ca8c924f7017b7e712d15a2eb";
    const CIPHER_0: &str = "
        4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9
        8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d
        4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da
        ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744
        3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240
        7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c
        09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae
        577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c
        cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663
        93b93111c1a55dd7421a10184974c7c5";
    const CIPHER_1: &str = "
        7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87
        ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05
        3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f
        7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201
        12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc
        047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63
        d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73
        c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4
        d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683
        8a9c71f70b5b5907a66f7ea49aadc409";

    fn cipher() -> XChaCha20 {
        let key: [u8; 32] = hex(KEY).try_into().unwrap();
        XChaCha20::new(&Key::from(key))
    }

    fn nonce() -> [u8; 24] {
        hex(NONCE).try_into().unwrap()
    }

    #[test]
    fn draft_counter_zero() {
        let mut data = hex(PLAIN);
        let plain = data.clone();
        cipher().encrypt(&nonce(), 0, &mut data).unwrap();
        assert_eq!(data, hex(CIPHER_0));
        cipher().decrypt(&nonce(), 0, &mut data).unwrap();
        assert_eq!(data, plain);
        // The keystream itself.
        let mut zeros = std::vec![0u8; plain.len()];
        cipher().encrypt(&nonce(), 0, &mut zeros).unwrap();
        assert_eq!(zeros, hex(KEYSTREAM_0));
    }

    /// Counter 1 over the same message: the draft's ciphertext, and
    /// a keystream that is counter 0's from its second block on.
    #[test]
    fn draft_counter_one() {
        let mut data = hex(PLAIN);
        cipher().encrypt(&nonce(), 1, &mut data).unwrap();
        assert_eq!(data, hex(CIPHER_1));
        let mut zeros = std::vec![0u8; data.len()];
        cipher().encrypt(&nonce(), 1, &mut zeros).unwrap();
        let shifted = &hex(KEYSTREAM_0)[64..];
        assert_eq!(zeros[..shifted.len()], shifted[..]);
    }

    #[test]
    fn pieces_match_whole() {
        let data: [u8; 517] = core::array::from_fn(|i| (i * 31) as u8);
        let mut whole = data;
        cipher().encrypt(&nonce(), 5, &mut whole).unwrap();
        for chunk in [1, 3, 63, 64, 65, 100, 517] {
            let mut pieces = data;
            let mut stream = cipher().stream(&nonce(), 5);
            for piece in pieces.chunks_mut(chunk) {
                stream.update(piece).unwrap();
            }
            assert_eq!(pieces[..], whole[..], "chunk {chunk}");
        }
    }

    /// Every bit of the nonce matters: the first sixteen bytes
    /// through the subkey, the last eight through ChaCha20's nonce.
    #[test]
    fn every_nonce_byte_changes_the_keystream() {
        let mut base = [0u8; 64];
        cipher().encrypt(&nonce(), 0, &mut base).unwrap();
        for i in 0..24 {
            let mut n = nonce();
            n[i] ^= 0x80;
            let mut other = [0u8; 64];
            cipher().encrypt(&n, 0, &mut other).unwrap();
            assert_ne!(base, other, "byte {i}");
        }
    }

    #[test]
    fn refuses_to_wrap_the_counter() {
        let mut data = [0u8; 129];
        assert_eq!(
            cipher().encrypt(&nonce(), u32::MAX - 1, &mut data),
            Err(Error::MessageTooLong)
        );
        assert_eq!(data, [0u8; 129]);
    }

    #[test]
    fn wipes_and_hides_the_key() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<XChaCha20>();
        let text = std::format!("{:?}", cipher());
        assert!(!text.contains("80"), "{text}");
    }
}
