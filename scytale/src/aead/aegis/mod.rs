//! AEGIS (draft-irtf-cfrg-aegis-aead): authenticated encryption built
//! straight on the AES round.
//!
//! AEGIS is not a mode of AES. It keeps a state of several AES blocks
//! and stirs it with one round of the cipher for every block of
//! input: a block's ciphertext is the block xored with a combination
//! of the state, and the tag is what is left of the state once the
//! lengths have been stirred in. There is no key schedule and no
//! separate hash, so with AES instructions it costs a fraction of a
//! full encryption for each block, and nothing in it multiplies.
//!
//! [`Aegis128L`] takes a 128-bit key and a 128-bit nonce, and two
//! blocks of input to each stir of its eight; it is the faster.
//! [`Aegis256`] takes a 256-bit key and a 256-bit nonce, wide enough
//! to draw at random, and one block to each stir of its six.
//!
//! ```
//! use scytale::Key;
//! use scytale::aead::{Aead, Aegis128L};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let aead = Aegis128L::new(&Key::from([0x42u8; 16]));
//! let nonce = [7u8; 16];
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
//! - **Never reuse a nonce with the same key.** A repeat gives away
//!   the state, and with it everything the key protects. Count
//!   nonces, with [`Nonces`](crate::cipher::Nonces) or otherwise.
//! - Do not use a decrypted message before the tag has been checked.
//!   The one-shot [`decrypt`](crate::aead::Aead::decrypt) checks
//!   first and wipes the buffer on failure; the incremental form
//!   cannot, see [`Decryptor`].
//! - The tag is 128 bits. The draft also defines a 256-bit tag, which
//!   this does not produce.
//! - A message, and its additional data, are each at most 2^61 - 1
//!   bytes; [`Error::MessageTooLong`] is returned beyond that.
//!
//! # Compared with GCM
//!
//! The same job. Where the processor has AES instructions this is
//! the faster, since a block costs a few rounds rather than a whole
//! encryption and a multiplication. Without them it runs the
//! constant-time bitsliced round, as AES itself does here. GCM is the
//! one every protocol speaks; AEGIS is for both ends being yours.

#[cfg(target_arch = "aarch64")]
mod aarch64;
pub(crate) mod aegis128l;
pub(crate) mod aegis256;
mod portable;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use core::fmt;
use core::marker::PhantomData;

use zeroize::{Zeroize, ZeroizeOnDrop};

pub use aegis128l::Aegis128L;
pub use aegis256::Aegis256;

use crate::Error;
use crate::cipher::aes::{BLOCK_SIZE, Kernel};

/// What the scalar kernels need: the AES encryption instructions
/// alone, since nothing in AEGIS runs the cipher backwards.
#[cfg(target_arch = "riscv64")]
const ZKNE: crate::features::Features =
    crate::features::riscv(&[crate::features::riscv64::Feature::Zkne]);

/// The tag length, in bytes.
const TAG: usize = 16;

/// The most bytes any variant takes in at a time: AEGIS-128L's two
/// blocks.
const MAX_RATE: usize = 2 * BLOCK_SIZE;

/// The longest message, and the longest additional data, in bytes:
/// the draft's P_MAX and A_MAX, set by a length that goes into the
/// tag as a 64-bit count of bits.
const MAX_BYTES: u64 = (1 << 61) - 1;

/// The state, as the blocks the draft names S0 on. A variant with
/// fewer than eight leaves the rest zero.
type State = [[u8; BLOCK_SIZE]; 8];

/// The constants the state starts from: the Fibonacci numbers modulo
/// 256, in two halves.
const C0: [u8; BLOCK_SIZE] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59,
    0x90, 0xe9, 0x79, 0x62,
];
const C1: [u8; BLOCK_SIZE] = [
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42,
    0x73, 0xb5, 0x28, 0xdd,
];

/// `a ^ b`.
fn xor(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

/// `a & b`.
fn and(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    core::array::from_fn(|i| a[i] & b[i])
}

/// The two lengths, in bits, as the block `Finalize` stirs in.
fn lengths(aad_bits: u64, message_bits: u64) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    let (aad, message) = block.split_at_mut(8);
    aad.copy_from_slice(&aad_bits.to_le_bytes());
    message.copy_from_slice(&message_bits.to_le_bytes());
    block
}

mod sealed {
    use super::{Kernel, MAX_RATE, State, TAG};
    use crate::KeyType;
    use crate::traits::ByteArray;

    /// The kernel a key was taken for, as [`Variant`] may name it.
    /// The trait is public in name, so that the incremental types
    /// can be bounded by it, and the kernels' own names are not
    /// public at all.
    #[derive(Clone, Copy)]
    pub struct Chosen(pub(in super::super) Kernel);

    /// What tells one member of the family from another: the widths,
    /// and the handful of functions the draft defines for each. The
    /// rest, cutting a message that arrives in pieces into blocks, is
    /// the same for all of them and is written once over this.
    ///
    /// The three that take a kernel work on whole blocks of
    /// [`RATE`](Variant::RATE) bytes and are the only ones written
    /// more than once.
    pub trait Variant: KeyType {
        /// The nonce.
        type Nonce: ByteArray;

        /// Bytes taken in by one update of the state.
        const RATE: usize;

        /// The draft's `Init`.
        fn init(kernel: Chosen, key: &Self::Key, nonce: &Self::Nonce) -> State;

        /// The draft's `Absorb`, over each block of `blocks`.
        fn absorb(kernel: Chosen, state: &mut State, blocks: &[u8]);

        /// The draft's `Enc`, over each block of `data` in place.
        fn encrypt(kernel: Chosen, state: &mut State, data: &mut [u8]);

        /// The draft's `Dec`, over each block of `data` in place.
        fn decrypt(kernel: Chosen, state: &mut State, data: &mut [u8]);

        /// What `Enc` would xor into the next block: the first
        /// [`RATE`](Variant::RATE) bytes are the keystream, which
        /// depends on the state alone, so a block that arrives in
        /// pieces can be encrypted as it comes.
        fn keystream(state: &State) -> [u8; MAX_RATE];

        /// The draft's `Finalize`, for lengths in bits.
        fn tag(
            kernel: Chosen,
            state: &mut State,
            aad_bits: u64,
            message_bits: u64,
        ) -> [u8; TAG];
    }
}

use sealed::{Chosen, Variant};

/// One message in progress: the state, and the block that is still
/// arriving.
struct Core<A: Variant> {
    state: State,
    /// The plaintext, or the additional data, of the block in
    /// progress. The state is updated with it once it is whole, or
    /// zero padded at the end.
    buffer: [u8; MAX_RATE],
    filled: usize,
    aad_bytes: u64,
    message_bytes: u64,
    /// Whether any of the message has been seen, after which no more
    /// additional data may be.
    started: bool,
    kernel: Chosen,
    variant: PhantomData<A>,
}

impl<A: Variant> Core<A> {
    fn new(kernel: Chosen, key: &A::Key, nonce: &A::Nonce) -> Self {
        Core {
            state: A::init(kernel, key, nonce),
            buffer: [0; MAX_RATE],
            filled: 0,
            aad_bytes: 0,
            message_bytes: 0,
            started: false,
            kernel,
            variant: PhantomData,
        }
    }

    /// `count` and `more` together, where that is a length the tag
    /// can carry.
    fn extended(count: u64, more: usize) -> Result<u64, Error> {
        u64::try_from(more)
            .ok()
            .and_then(|more| count.checked_add(more))
            .filter(|total| *total <= MAX_BYTES)
            .ok_or(Error::MessageTooLong)
    }

    fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.started {
            return Err(Error::OutOfOrder);
        }
        self.aad_bytes = Self::extended(self.aad_bytes, data.len())?;

        let room = (A::RATE - self.filled) % A::RATE;
        let (head, data) = data.split_at(room.min(data.len()));
        self.buffer[self.filled..self.filled + head.len()]
            .copy_from_slice(head);
        self.filled += head.len();
        if self.filled == A::RATE {
            self.flush();
        }

        let (blocks, tail) = data.split_at(data.len() - data.len() % A::RATE);
        A::absorb(self.kernel, &mut self.state, blocks);
        // Empty unless the buffer was, since a head that did not fill
        // the block took all there was.
        self.buffer[self.filled..self.filled + tail.len()]
            .copy_from_slice(tail);
        self.filled += tail.len();
        Ok(())
    }

    /// Updates the state with the block in progress, zero padded,
    /// if there is any of one.
    fn flush(&mut self) {
        if self.filled != 0 {
            self.buffer[self.filled..].fill(0);
            A::absorb(self.kernel, &mut self.state, &self.buffer[..A::RATE]);
            self.filled = 0;
        }
    }

    /// Ends the additional data, before the first piece of message.
    fn start(&mut self) {
        if !self.started {
            self.started = true;
            self.flush();
        }
    }

    /// Encrypts or decrypts the next piece in place.
    fn message(&mut self, data: &mut [u8], decrypt: bool) -> Result<(), Error> {
        self.start();
        self.message_bytes = Self::extended(self.message_bytes, data.len())?;

        let room = (A::RATE - self.filled) % A::RATE;
        let (head, data) = data.split_at_mut(room.min(data.len()));
        self.piece(head, decrypt);

        let whole = data.len() - data.len() % A::RATE;
        let (blocks, tail) = data.split_at_mut(whole);
        if decrypt {
            A::decrypt(self.kernel, &mut self.state, blocks);
        } else {
            A::encrypt(self.kernel, &mut self.state, blocks);
        }
        self.piece(tail, decrypt);
        Ok(())
    }

    /// Less than a block, continuing the one in progress: xors the
    /// keystream in, and keeps the plaintext for the update the block
    /// is owed once it is whole.
    ///
    /// This is the draft's `DecPartial` too. What that pads with
    /// zeros and updates the state with is the plaintext, not the
    /// ciphertext xored with a whole block of keystream, and the
    /// buffer holds exactly that.
    fn piece(&mut self, piece: &mut [u8], decrypt: bool) {
        if piece.is_empty() {
            return;
        }
        let mut keystream = A::keystream(&self.state);
        let at = self.filled;
        let kept = &mut self.buffer[at..at + piece.len()];
        for ((byte, kept), z) in
            piece.iter_mut().zip(kept).zip(&keystream[at..])
        {
            let out = *byte ^ z;
            *kept = if decrypt { out } else { *byte };
            *byte = out;
        }
        keystream.zeroize();
        self.filled += piece.len();
        if self.filled == A::RATE {
            self.flush();
        }
    }

    fn tag(mut self) -> [u8; TAG] {
        self.start();
        self.flush();
        // Neither count can overflow: both are below 2^61.
        A::tag(
            self.kernel,
            &mut self.state,
            8 * self.aad_bytes,
            8 * self.message_bytes,
        )
    }

    /// Checks `tag` against the message, in constant time.
    fn verify(self, tag: &[u8; TAG]) -> Result<(), Error> {
        let expected = self.tag();
        if crate::constant_time::equal(&expected, tag) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

impl<A: Variant> Drop for Core<A> {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
    }
}

impl<A: Variant> ZeroizeOnDrop for Core<A> {}

/// Encryption of a message that arrives in pieces, under `A`:
/// [`Aegis128L`] or [`Aegis256`].
///
/// Additional data first, then the message, then the tag; the
/// ciphertext is in place as each piece is given.
pub struct Encryptor<A: Variant> {
    core: Core<A>,
}

impl<A: Variant> Encryptor<A> {
    fn new(kernel: Chosen, key: &A::Key, nonce: &A::Nonce) -> Self {
        Encryptor {
            core: Core::new(kernel, key, nonce),
        }
    }

    /// Authenticates `data` without encrypting it. All of it must
    /// come before any of the message, or
    /// [`Error::OutOfOrder`] is returned.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Encrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.message(data, false)
    }

    /// Finishes, returning the tag.
    pub fn finalize(self) -> [u8; TAG] {
        self.core.tag()
    }
}

/// Decryption of a message that arrives in pieces, under `A`:
/// [`Aegis128L`] or [`Aegis256`].
///
/// **The pieces this hands back are not yet authenticated.** Nothing
/// can vouch for any of the message until [`verify`](Self::verify)
/// has passed, so a caller must hold every piece back from use until
/// then, or use the one-shot [`decrypt`](crate::aead::Aead::decrypt),
/// which does that itself.
pub struct Decryptor<A: Variant> {
    core: Core<A>,
}

impl<A: Variant> Decryptor<A> {
    fn new(kernel: Chosen, key: &A::Key, nonce: &A::Nonce) -> Self {
        Decryptor {
            core: Core::new(kernel, key, nonce),
        }
    }

    /// Authenticates `data`. All of it must come before any of the
    /// message, or [`Error::OutOfOrder`] is returned.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Decrypts the next piece of the message in place. The result
    /// is not authenticated until [`verify`](Self::verify) passes.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.message(data, true)
    }

    /// Checks `tag` against the message, in constant time.
    pub fn verify(self, tag: &[u8; TAG]) -> Result<(), Error> {
        self.core.verify(tag)
    }
}

impl<A: Variant> fmt::Debug for Encryptor<A> {
    /// Deliberately omits the state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("message_bytes", &self.core.message_bytes)
            .finish_non_exhaustive()
    }
}

impl<A: Variant> fmt::Debug for Decryptor<A> {
    /// Deliberately omits the state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryptor")
            .field("message_bytes", &self.core.message_bytes)
            .finish_non_exhaustive()
    }
}

/// What the one-shot calls of every variant do, over the pieces.
fn seal<A: Variant>(
    mut state: Encryptor<A>,
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; TAG], Error> {
    state.aad(aad)?;
    state.update(data)?;
    Ok(state.finalize())
}

/// As [`seal`], the other way; the buffer is wiped where the tag does
/// not check.
fn open<A: Variant>(
    mut state: Decryptor<A>,
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG],
) -> Result<(), Error> {
    state.aad(aad)?;
    state.update(data)?;
    state.verify(tag).inspect_err(|_| data.fill(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The draft's appendix A.1, through both portable rounds.
    #[test]
    fn aes_round() {
        use crate::cipher::aes::portable::{bitsliced, ttable};

        let input: [u8; 16] = core::array::from_fn(|i| i as u8);
        let rk: [u8; 16] = core::array::from_fn(|i| 0x10 + i as u8);
        let expected = [
            0x7a, 0x7b, 0x4e, 0x56, 0x38, 0x78, 0x25, 0x46, 0xa8, 0xc0, 0x47,
            0x7a, 0x3b, 0x81, 0x3f, 0x43,
        ];
        assert_eq!(ttable::round(&input, &rk), expected);

        let mut planes = bitsliced::pack(&input);
        bitsliced::round(&mut planes);
        let mut out = [0u8; 16];
        bitsliced::unpack(&planes, &mut out);
        assert_eq!(xor(&out, &rk), expected);
    }

    #[test]
    fn lengths_the_tag_cannot_carry_are_refused() {
        type Core = super::Core<Aegis128L>;
        assert_eq!(Core::extended(0, 5), Ok(5));
        assert_eq!(Core::extended(MAX_BYTES - 5, 5), Ok(MAX_BYTES));
        let too_long = Err(Error::MessageTooLong);
        assert_eq!(Core::extended(MAX_BYTES - 4, 5), too_long);
        assert_eq!(Core::extended(u64::MAX, 1), too_long);
    }
}
