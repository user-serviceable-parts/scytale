//! XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha): ChaCha20-Poly1305
//! with a 192-bit nonce.
//!
//! The construction is [`ChaCha20Poly1305`](super::ChaCha20Poly1305)
//! exactly, under a key and a 96-bit nonce made for the message:
//! HChaCha20 over the key and the first 128 bits of the nonce gives
//! the key, and the last 64 bits behind four zero bytes give the
//! nonce. What that buys is a
//! nonce wide enough to draw at random. ChaCha20-Poly1305's 96 bits
//! repeat, more likely than not, somewhere in 2^32 random nonces,
//! and one repeat gives away the Poly1305 key; 192 bits do not
//! repeat in any number of messages a key will see.
//!
//! ```
//! use scytale::Key;
//! use scytale::aead::{Aead, XChaCha20Poly1305};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let aead = XChaCha20Poly1305::new(&Key::from([0x42u8; 32]));
//! let nonce = [7u8; 24];
//! let header = b"to: bob";
//! let mut message = *b"attack at dawn";
//! let mut tag = [0u8; 16];
//! aead.encrypt(&nonce, header, &mut message, &mut tag)?;
//! aead.decrypt(&nonce, header, &mut message, &tag)?;
//! assert_eq!(&message, b"attack at dawn");
//! # Ok(())
//! # }
//! ```
//!
//! # Using it safely
//!
//! - A nonce may be drawn from a [`Random`](crate::Random) source
//!   for every message, which is the point of the construction.
//!   Counting them works too. It must still never be chosen twice on
//!   purpose: a repeat fails exactly as it does for
//!   ChaCha20-Poly1305.
//! - Do not use a decrypted message before the tag has been checked.
//!   The one-shot [`decrypt`](XChaCha20Poly1305::decrypt) checks
//!   first and wipes the buffer on failure; the incremental form
//!   cannot, see [`Decryptor`].
//! - A message is at most 256 GiB, the reach of ChaCha20's counter;
//!   [`Error::MessageTooLong`] is returned rather than wrapping.
//!
//! # Compared with ChaCha20-Poly1305
//!
//! One extra block of ChaCha20 a message, and otherwise the same
//! speed, strength and kernels. Where nonces are counted there is no
//! reason to prefer it; where they are drawn, or where many writers
//! share a key without a counter between them, it is the one that
//! is safe. It is not an IETF standard: the draft expired, and the
//! construction lives on as libsodium's and as what the IETF's
//! AEAD registry calls `AEAD_XCHACHA20_POLY1305`.

use core::fmt;

use zeroize::ZeroizeOnDrop;

use super::Aead;
use super::chacha20_poly1305::{Core, TAG};
use crate::cipher::chacha20::{KEY_SIZE, OwnedAutoStream};
use crate::cipher::xchacha20::{NONCE_SIZE, XChaCha20};
use crate::features::{self, Dispatcher, Features};
use crate::{Error, Key, KeyType};

/// XChaCha20-Poly1305 under one key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct XChaCha20Poly1305 {
    cipher: XChaCha20,
}

impl XChaCha20Poly1305 {
    /// The feature profiles this construction tells apart, best
    /// first: ChaCha20-Poly1305's, since the message runs through
    /// that construction; see [`Dispatcher`].
    pub fn profiles() -> &'static [Features] {
        super::ChaCha20Poly1305::profiles()
    }
}

impl features::sealed::Sealed for XChaCha20Poly1305 {}

impl Dispatcher for XChaCha20Poly1305 {
    fn profiles() -> &'static [Features] {
        XChaCha20Poly1305::profiles()
    }
}

impl KeyType for XChaCha20Poly1305 {
    type Key = Key<[u8; KEY_SIZE]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

impl Aead for XChaCha20Poly1305 {
    type Nonce = [u8; NONCE_SIZE];
    type Tag = [u8; TAG];

    fn new(key: &Self::Key) -> Self {
        // The inherent constructor, which takes precedence here.
        XChaCha20Poly1305::new(key)
    }

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    ) -> Result<(), Error> {
        let mut state = self.encryptor(nonce)?;
        state.aad(aad)?;
        state.update(data)?;
        *tag = state.finalize();
        Ok(())
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), Error> {
        let mut state = self.decryptor(nonce)?;
        state.aad(aad)?;
        state.update(data)?;
        match state.verify(tag) {
            Ok(()) => Ok(()),
            Err(e) => {
                data.fill(0);
                Err(e)
            }
        }
    }
}

impl XChaCha20Poly1305 {
    /// Takes the key.
    pub fn new(key: &Key<[u8; KEY_SIZE]>) -> Self {
        XChaCha20Poly1305 {
            cipher: XChaCha20::new(key),
        }
    }

    /// The ChaCha20-Poly1305 state for one message.
    fn core(
        &self,
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Core<OwnedAutoStream>, Error> {
        let (cipher, short) = self.cipher.message(nonce);
        Core::owned(cipher, &short)
    }

    /// Starts encrypting a message that arrives in pieces.
    pub fn encryptor(
        &self,
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Encryptor, Error> {
        Ok(Encryptor {
            core: self.core(nonce)?,
        })
    }

    /// Starts decrypting a message that arrives in pieces.
    pub fn decryptor(
        &self,
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Decryptor, Error> {
        Ok(Decryptor {
            core: self.core(nonce)?,
        })
    }
}

impl fmt::Debug for XChaCha20Poly1305 {
    /// Deliberately omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XChaCha20Poly1305").finish_non_exhaustive()
    }
}

/// Encryption of a message that arrives in pieces.
///
/// Additional data first, then the message, then the tag; the
/// ciphertext is in place as each piece is given. It holds the key
/// for this message, so it does not borrow the construction.
pub struct Encryptor {
    core: Core<OwnedAutoStream>,
}

impl Encryptor {
    /// Authenticates `data` without encrypting it. All of it must
    /// come before any of the message, or
    /// [`Error::OutOfOrder`] is returned.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Encrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.encrypt(data)
    }

    /// Finishes, returning the tag.
    pub fn finalize(self) -> [u8; TAG] {
        self.core.tag()
    }
}

/// Decryption of a message that arrives in pieces.
///
/// **The pieces this hands back are not yet authenticated.** Nothing
/// can vouch for any of the message until [`verify`](Self::verify)
/// has passed, so a caller must hold every piece back from use until
/// then, or use the one-shot
/// [`decrypt`](XChaCha20Poly1305::decrypt), which does that itself.
pub struct Decryptor {
    core: Core<OwnedAutoStream>,
}

impl Decryptor {
    /// Authenticates `data`. All of it must come before any of the
    /// message, or [`Error::OutOfOrder`] is returned.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Decrypts the next piece of the message in place. The result
    /// is not authenticated until [`verify`](Self::verify) passes.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.decrypt(data)
    }

    /// Checks `tag` against the message, in constant time.
    pub fn verify(self, tag: &[u8; TAG]) -> Result<(), Error> {
        self.core.verify(tag)
    }
}

impl fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("message_bytes", &self.core.message_bytes)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Decryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryptor")
            .field("message_bytes", &self.core.message_bytes)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::ChaCha20Poly1305;
    use crate::cipher::chacha20::hchacha20;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), 2 * N);
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    /// draft-irtf-cfrg-xchacha-03 appendix A.3.1.
    const KEY: &str =
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const NONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
    const AAD: &str = "50515253c0c1c2c3c4c5c6c7";
    const PLAIN: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would \
        be it.";
    const POLY_KEY: &str =
        "7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5";
    const CIPHER: &str = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbe\
        d2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96\
        b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b238\
        3565d3fff921f9664c97637da9768812f615c68b13b52e";
    const TAG_HEX: &str = "c0875924c1c7987947deafd8780acf49";

    fn aead() -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::from(hex::<32>(KEY)))
    }

    #[test]
    fn draft_vector() {
        let aead = aead();
        let nonce = hex::<24>(NONCE);
        let aad = hex::<12>(AAD);
        let mut data = *PLAIN;
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, &aad, &mut data, &mut tag).unwrap();
        assert_eq!(data, hex::<114>(CIPHER));
        assert_eq!(tag, hex::<16>(TAG_HEX));
        aead.decrypt(&nonce, &aad, &mut data, &tag).unwrap();
        assert_eq!(&data, PLAIN);
    }

    /// The draft also prints the Poly1305 key: block zero under the
    /// subkey and the short nonce.
    #[test]
    fn draft_poly1305_key() {
        let key = Key::from(hex::<32>(KEY));
        let nonce = hex::<24>(NONCE);
        let subkey = hchacha20(&key, nonce[..16].try_into().unwrap());
        let mut short = [0u8; 12];
        short[4..].copy_from_slice(&nonce[16..]);
        let block = crate::cipher::chacha20::ChaCha20::new(&subkey)
            .keystream_block(&short, 0);
        assert_eq!(block[..32], hex::<32>(POLY_KEY));
    }

    /// The construction is ChaCha20-Poly1305 under the derived key
    /// and nonce, byte for byte.
    #[test]
    fn is_chacha20_poly1305_under_the_subkey() {
        let key = Key::from(hex::<32>(KEY));
        let nonce = hex::<24>(NONCE);
        let subkey = hchacha20(&key, nonce[..16].try_into().unwrap());
        let mut short = [0u8; 12];
        short[4..].copy_from_slice(&nonce[16..]);
        let mut a = *PLAIN;
        let mut b = *PLAIN;
        let mut tag_a = [0u8; 16];
        let mut tag_b = [0u8; 16];
        aead().encrypt(&nonce, b"hdr", &mut a, &mut tag_a).unwrap();
        ChaCha20Poly1305::new(&subkey)
            .encrypt(&short, b"hdr", &mut b, &mut tag_b)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(tag_a, tag_b);
    }

    #[test]
    fn rejects_and_wipes() {
        let aead = aead();
        let nonce = hex::<24>(NONCE);
        let aad = hex::<12>(AAD);
        let mut data = *PLAIN;
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, &aad, &mut data, &mut tag).unwrap();
        let sealed = data;

        let mut wrong = tag;
        wrong[0] ^= 1;
        assert_eq!(
            aead.decrypt(&nonce, &aad, &mut data, &wrong).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(data, [0u8; 114]);

        data = sealed;
        assert_eq!(
            aead.decrypt(&nonce, b"other", &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(data, [0u8; 114]);

        data = sealed;
        let mut other = nonce;
        other[0] ^= 1;
        assert_eq!(
            aead.decrypt(&other, &aad, &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
        data = sealed;
        other = nonce;
        other[23] ^= 1;
        assert_eq!(
            aead.decrypt(&other, &aad, &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn pieces_match_whole() {
        let aead = aead();
        let nonce = hex::<24>(NONCE);
        let aad = hex::<12>(AAD);
        let mut whole = *PLAIN;
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, &aad, &mut whole, &mut tag).unwrap();
        for chunk in [1, 7, 16, 63, 64, 65, 114] {
            let mut data = *PLAIN;
            let mut e = aead.encryptor(&nonce).unwrap();
            e.aad(&aad[..5]).unwrap();
            e.aad(&aad[5..]).unwrap();
            for piece in data.chunks_mut(chunk) {
                e.update(piece).unwrap();
            }
            assert_eq!(data, whole, "chunk {chunk}");
            assert_eq!(e.finalize(), tag, "chunk {chunk}");

            let mut d = aead.decryptor(&nonce).unwrap();
            d.aad(&aad).unwrap();
            for piece in data.chunks_mut(chunk) {
                d.update(piece).unwrap();
            }
            d.verify(&tag).unwrap();
            assert_eq!(&data, PLAIN, "chunk {chunk}");
        }
    }

    /// The streaming forms outlive the construction they came from.
    #[test]
    fn streams_do_not_borrow() {
        let nonce = hex::<24>(NONCE);
        let mut e = aead().encryptor(&nonce).unwrap();
        let mut data = *b"hello";
        e.update(&mut data).unwrap();
        let tag = e.finalize();
        let mut d = aead().decryptor(&nonce).unwrap();
        d.update(&mut data).unwrap();
        d.verify(&tag).unwrap();
        assert_eq!(&data, b"hello");
    }

    #[test]
    fn aad_after_message_is_out_of_order() {
        let mut e = aead().encryptor(&[0u8; 24]).unwrap();
        e.update(&mut [0u8; 3]).unwrap();
        assert_eq!(e.aad(b"late"), Err(Error::OutOfOrder));
    }

    #[test]
    fn empty_message_and_aad() {
        let aead = aead();
        let mut tag = [0u8; 16];
        aead.encrypt(&[0u8; 24], &[], &mut [], &mut tag).unwrap();
        aead.decrypt(&[0u8; 24], &[], &mut [], &tag).unwrap();
        let mut wrong = tag;
        wrong[15] ^= 1;
        assert_eq!(
            aead.decrypt(&[0u8; 24], &[], &mut [], &wrong),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn wipes_and_hides_the_key() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<XChaCha20Poly1305>();
        let text = std::format!("{:?}", aead());
        assert!(!text.contains("80"), "{text}");
    }
}
