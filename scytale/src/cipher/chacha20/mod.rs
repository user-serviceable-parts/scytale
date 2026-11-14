//! ChaCha20 (RFC 8439): a stream cipher.
//!
//! ChaCha20 turns a 256-bit key, a 96-bit nonce and a 32-bit block
//! counter into a keystream, sixty-four bytes a block, and a message
//! is xored with it. There is no block cipher underneath: the block
//! function is twenty rounds of additions, rotations and xors on
//! sixteen 32-bit words, which run at full speed on any processor
//! without special instructions and never touch memory in a way
//! that depends on the key.
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::chacha20::ChaCha20;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let cipher = ChaCha20::new(&Key::from([0x42u8; 32]));
//! let nonce = [0u8; 12];
//! let mut message = *b"attack at dawn";
//! cipher.encrypt(&nonce, 1, &mut message)?;
//! cipher.decrypt(&nonce, 1, &mut message)?;
//! assert_eq!(&message, b"attack at dawn");
//! # Ok(())
//! # }
//! ```
//!
//! # Using it safely
//!
//! - **Never reuse a nonce with the same key.** Two messages under
//!   the same key and nonce are xored with the same keystream, and
//!   the xor of the two messages falls straight out. Count nonces:
//!   96 bits are too few to draw at random. Where they must be
//!   drawn, [`xchacha20`](crate::cipher::xchacha20) widens the nonce
//!   to 192 bits through [`hchacha20`].
//! - **This authenticates nothing.** Anyone can flip bits of the
//!   ciphertext and flip the same bits of the message. Use
//!   [`ChaCha20Poly1305`](crate::aead::ChaCha20Poly1305),
//!   which is this cipher under a MAC, unless a protocol supplies
//!   its own authentication.
//! - The counter is 32 bits, so one nonce carries at most 256 GiB;
//!   [`Error::MessageTooLong`] is returned rather than wrapping.
//!   RFC 8439 starts the counter at one when a Poly1305 key has been
//!   taken from block zero; on its own the cipher accepts any start.
//!
//! # Speed
//!
//! Every block is independent, so the processor's vector unit can
//! compute several at once: eight with AVX2 on x86-64, four with
//! NEON on AArch64, and as many as the registers hold with the
//! RISC-V vector extension and Zvkb's rotates. Where RISC-V has no
//! vector unit, Zbb's scalar rotate is still worth a version of its
//! own, because a third of the cipher's work is rotating. Each is
//! reachable by name in the module for its architecture;
//! [`ChaCha20`] picks the best the processor has. The portable code
//! works four blocks at a time in a form the compiler vectorises
//! where it can.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
pub mod portable;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_arch = "riscv64")]
use crate::features::riscv64::Feature as R;
#[cfg(target_arch = "x86_64")]
use crate::features::x86_64::Feature as X;
use crate::features::{self, Dispatcher, Features};
use crate::{Error, Key, KeyType};

/// The key length, in bytes.
pub const KEY_SIZE: usize = 32;

/// The nonce length, in bytes.
///
/// It must never repeat under one key, which is a stronger
/// requirement than being unpredictable:
/// [`Nonces`](crate::cipher::Nonces) counts them so that it cannot.
pub const NONCE_SIZE: usize = 12;

/// Bytes of keystream per block.
pub const BLOCK_SIZE: usize = 64;

/// The nonce length of [`hchacha20`], in bytes.
pub const HNONCE_SIZE: usize = 16;

/// The first four words of every state: "expand 32-byte k".
pub(crate) const CONSTANTS: [u32; 4] =
    [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// Keeps the backend trait to this crate's own implementations.
mod sealed {
    pub trait Sealed {}
}
pub(crate) use sealed::Sealed;

/// A keystream generator. Sealed.
///
/// A value of the type is the proof that this processor can run it:
/// [`probe`](Backend::probe) is the only way to make one, the
/// hardware ones have no public constructor, and the cipher holds the
/// value it was given. So the generator is a safe call, and the one
/// `unsafe` block in a hardware module is where the value is minted.
pub trait Backend: Sealed + Copy {
    /// The generator, where this processor can run it. Asked once.
    fn probe() -> Option<Self>;

    /// Whether this processor can run it.
    fn supported() -> bool {
        Self::probe().is_some()
    }

    /// Xors the keystream for consecutive blocks from `counter` into
    /// `data`, whose length is a whole number of blocks.
    fn xor(
        self,
        key: &[u32; 8],
        nonce: &[u32; 3],
        counter: u32,
        data: &mut [u8],
    );
}

/// The key as the words the block function takes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Words([u32; 8]);

impl Words {
    fn new(key: &[u8; KEY_SIZE]) -> Self {
        let mut words = [0u32; 8];
        for (w, bytes) in words.iter_mut().zip(key.chunks_exact(4)) {
            *w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        Words(words)
    }
}

impl<B: Backend> KeyType for Cipher<B> {
    type Key = Key<[u8; KEY_SIZE]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

/// The nonce as words.
fn nonce_words<const N: usize>(nonce: &[u8]) -> [u32; N] {
    let mut words = [0u32; N];
    for (w, bytes) in words.iter_mut().zip(nonce.chunks_exact(4)) {
        *w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    words
}

/// HChaCha20 (draft-irtf-cfrg-xchacha): a key from a key and a
/// 128-bit nonce.
///
/// The ChaCha20 rounds run over the key with the nonce in the place
/// of the counter and the nonce, and the first and last rows of the
/// result are the new key; the input is not added back, so the rows
/// are not keystream and give nothing of the input away. It is the
/// first half of [`XChaCha20`](crate::cipher::xchacha20::XChaCha20),
/// which takes the second half of a 192-bit nonce through plain
/// ChaCha20 under the key this returns; on its own it is a
/// one-block, constant-time way to derive a subkey per nonce.
///
/// Portable code on every processor: one block a message is not
/// worth a hardware kernel.
pub fn hchacha20(
    key: &Key<[u8; KEY_SIZE]>,
    nonce: &[u8; HNONCE_SIZE],
) -> Key<[u8; KEY_SIZE]> {
    let words = Words::new(key.array());
    let mut out = portable::hchacha20(&words.0, &nonce_words(nonce));
    let mut key = Key::zeroed();
    for (bytes, w) in key.as_mut().chunks_exact_mut(4).zip(out) {
        bytes.copy_from_slice(&w.to_le_bytes());
    }
    out.zeroize();
    key
}

/// ChaCha20 over the keystream generator `B`. The type for callers
/// is [`ChaCha20`], which picks `B`; the per-architecture modules
/// name the others.
pub struct Cipher<B: Backend> {
    key: Words,
    /// The generator, which is the proof the processor can run it.
    backend: B,
}

impl<B: Backend> Cipher<B> {
    /// Takes the key.
    ///
    /// [`Error::NotSupported`] where this processor cannot run `B`.
    pub fn try_new(key: &Key<[u8; KEY_SIZE]>) -> Result<Self, Error> {
        B::probe()
            .map(|backend| Self::with(backend, key))
            .ok_or(Error::NotSupported)
    }

    /// Takes `key` under `backend`, which the caller got from the
    /// probe.
    pub(crate) fn with(backend: B, key: &Key<[u8; KEY_SIZE]>) -> Self {
        Cipher {
            key: Words::new(key.array()),
            backend,
        }
    }

    /// Encrypts `data` in place, its first byte at the start of
    /// block `counter`.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.stream(nonce, counter).update(data)
    }

    /// Decrypts `data` in place, its first byte at the start of
    /// block `counter`.
    ///
    /// This is the same operation as [`encrypt`](Self::encrypt): the
    /// keystream does not depend on the message. Both names exist so
    /// that calling code reads the way it means.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.stream(nonce, counter).update(data)
    }

    /// Starts a message that arrives in pieces.
    pub fn stream(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> Stream<'_, B> {
        Stream {
            cipher: self,
            position: Position::new(nonce, counter),
        }
    }

    /// Starts a message that arrives in pieces, taking the cipher
    /// with it: for a key that serves this one message, as under
    /// [`XChaCha20`](crate::cipher::xchacha20::XChaCha20).
    pub fn into_stream(
        self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> OwnedStream<B> {
        OwnedStream {
            position: Position::new(nonce, counter),
            cipher: self,
        }
    }

    /// One block of keystream, as the AEAD takes its Poly1305 key.
    pub(crate) fn keystream_block(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        self.backend
            .xor(&self.key.0, &nonce_words(nonce), counter, &mut block);
        block
    }
}

impl<B: Backend> Clone for Cipher<B> {
    fn clone(&self) -> Self {
        Cipher {
            key: self.key.clone(),
            backend: self.backend,
        }
    }
}

// The key wipes itself; this only says so.
impl<B: Backend> ZeroizeOnDrop for Cipher<B> {}

impl<B: Backend> fmt::Debug for Cipher<B> {
    /// Deliberately omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChaCha20").finish_non_exhaustive()
    }
}

/// Where a message is up to: the nonce, the block the next fresh
/// keystream comes from, and any of the current block not yet used.
struct Position {
    nonce: [u32; 3],
    /// Wider than the counter so that using the last block is
    /// recorded rather than wrapped round.
    counter: u64,
    keystream: [u8; BLOCK_SIZE],
    used: usize,
}

impl Position {
    fn new(nonce: &[u8; NONCE_SIZE], counter: u32) -> Self {
        Position {
            nonce: nonce_words(nonce),
            counter: u64::from(counter),
            keystream: [0; BLOCK_SIZE],
            used: BLOCK_SIZE,
        }
    }

    /// Encrypts or decrypts the next piece of the message in place
    /// under `cipher`, or [`Error::MessageTooLong`] if the piece would
    /// take the block counter past 2^32, leaving `data` untouched.
    fn update<B: Backend>(
        &mut self,
        cipher: &Cipher<B>,
        mut data: &mut [u8],
    ) -> Result<(), Error> {
        let fresh = data.len().saturating_sub(BLOCK_SIZE - self.used);
        let blocks = fresh.div_ceil(BLOCK_SIZE) as u64;
        if self.counter + blocks > 1 << 32 {
            return Err(Error::MessageTooLong);
        }

        // What is left of the current block first.
        if self.used < BLOCK_SIZE {
            let take = (BLOCK_SIZE - self.used).min(data.len());
            let (now, rest) = data.split_at_mut(take);
            for (d, k) in now.iter_mut().zip(&self.keystream[self.used..]) {
                *d ^= k;
            }
            self.used += take;
            data = rest;
        }

        // Whole blocks straight through the backend.
        let whole = data.len() - data.len() % BLOCK_SIZE;
        let (now, rest) = data.split_at_mut(whole);
        if !now.is_empty() {
            cipher.backend.xor(
                &cipher.key.0,
                &self.nonce,
                self.counter as u32,
                now,
            );
            self.counter += (whole / BLOCK_SIZE) as u64;
        }

        // A last partial block, keeping the rest of its keystream.
        if !rest.is_empty() {
            self.keystream = [0; BLOCK_SIZE];
            cipher.backend.xor(
                &cipher.key.0,
                &self.nonce,
                self.counter as u32,
                &mut self.keystream,
            );
            self.counter += 1;
            for (d, k) in rest.iter_mut().zip(&self.keystream) {
                *d ^= k;
            }
            self.used = rest.len();
        }
        Ok(())
    }
}

impl Drop for Position {
    /// The keystream is as secret as the key.
    fn drop(&mut self) {
        self.keystream.zeroize();
        self.nonce.zeroize();
        self.counter.zeroize();
        self.used.zeroize();
    }
}

impl ZeroizeOnDrop for Position {}

impl fmt::Debug for Position {
    /// Deliberately omits the keystream.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

/// A message in progress under a borrowed cipher.
pub struct Stream<'a, B: Backend> {
    cipher: &'a Cipher<B>,
    position: Position,
}

impl<B: Backend> Stream<'_, B> {
    /// Encrypts or decrypts the next piece of the message in place.
    ///
    /// Returns [`Error::MessageTooLong`] if the piece would take the
    /// block counter past 2^32, leaving `data` untouched.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.position.update(self.cipher, data)
    }
}

// Both parts wipe themselves; this only says so.
impl<B: Backend> ZeroizeOnDrop for Stream<'_, B> {}

impl<B: Backend> fmt::Debug for Stream<'_, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.position.fmt(f)
    }
}

/// A message in progress under a cipher of its own; see
/// [`Cipher::into_stream`].
pub struct OwnedStream<B: Backend> {
    cipher: Cipher<B>,
    position: Position,
}

impl<B: Backend> OwnedStream<B> {
    /// Encrypts or decrypts the next piece of the message in place.
    ///
    /// Returns [`Error::MessageTooLong`] if the piece would take the
    /// block counter past 2^32, leaving `data` untouched.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.position.update(&self.cipher, data)
    }
}

// Both parts wipe themselves; this only says so.
impl<B: Backend> ZeroizeOnDrop for OwnedStream<B> {}

impl<B: Backend> fmt::Debug for OwnedStream<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.position.fmt(f)
    }
}

/// Which kernel a [`ChaCha20`] is running on.
///
/// Which can be chosen is what [`ChaCha20::profiles`] publishes, by
/// needs rather than by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Kernel {
    /// AVX2 on x86-64, eight blocks at a time.
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// NEON on AArch64, which every such processor has.
    #[cfg(target_arch = "aarch64")]
    Neon,
    /// RISC-V vector rotates, Zvkb or Zvbb.
    #[cfg(target_arch = "riscv64")]
    Zvkb,
    /// RISC-V scalar rotates, Zbb or Zbkb.
    #[cfg(target_arch = "riscv64")]
    Zbb,
    /// Plain Rust, on any processor. Never chosen on AArch64, where
    /// NEON needs nothing either and comes first; the fallback arm
    /// there is named after it all the same.
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    Portable,
}

/// AVX2 with the operating system saving the upper register halves.
#[cfg(target_arch = "x86_64")]
pub(crate) const AVX2: Features = features::x86(&[X::Avx, X::Avx2]);
/// The vector rotate `vror.vi`, from Zvkb (which Zvbb includes), on
/// registers of a block or more.
#[cfg(target_arch = "riscv64")]
pub(crate) const ZVKB: Features = features::riscv(&[R::V, R::Zvkb]);
/// The scalar rotate, which Zbb has.
#[cfg(target_arch = "riscv64")]
pub(crate) const ZBB: Features = features::riscv(&[R::Zbb]);
/// The same rotate, which Zbkb has as well; a processor with the
/// scalar cryptography and not Zbb takes this row.
#[cfg(target_arch = "riscv64")]
pub(crate) const ZBKB: Features = features::riscv(&[R::Zbkb]);

/// The kernels, best first, each with what it needs; the first whose
/// needs are in force is the one a new cipher gets. One kernel may
/// appear twice, under two sets that each suffice. Every AArch64
/// processor has NEON, so there the list ends with it and the
/// portable code is never reached: two rows needing nothing would
/// leave the second unreachable by any edit to the features.
pub(crate) const KERNELS: &[(Kernel, Features)] = &[
    #[cfg(target_arch = "x86_64")]
    (Kernel::Avx2, AVX2),
    #[cfg(target_arch = "aarch64")]
    (Kernel::Neon, Features::new()),
    #[cfg(target_arch = "riscv64")]
    (Kernel::Zvkb, ZVKB),
    #[cfg(target_arch = "riscv64")]
    (Kernel::Zbb, ZBB),
    #[cfg(target_arch = "riscv64")]
    (Kernel::Zbb, ZBKB),
    #[cfg(not(target_arch = "aarch64"))]
    (Kernel::Portable, Features::new()),
];

/// What the list publishes: the needs, without the names.
pub(crate) const PROFILES: [Features; KERNELS.len()] =
    features::profiles_of(KERNELS);

/// Applies a method to whichever implementation is in use.
macro_rules! dispatch {
    ($value:expr, $inner:ident, $x:ident => $body:expr) => {
        match $value {
            #[cfg(target_arch = "x86_64")]
            $inner::Avx2($x) => $body,
            #[cfg(target_arch = "aarch64")]
            $inner::Neon($x) => $body,
            #[cfg(target_arch = "riscv64")]
            $inner::Zvkb($x) => $body,
            #[cfg(target_arch = "riscv64")]
            $inner::Zbb($x) => $body,
            $inner::Portable($x) => $body,
        }
    };
}

/// ChaCha20 using the best implementation the features in force
/// allow; see [`crate::features`].
///
/// The choice is made when the key is taken, and each call then
/// dispatches with a single predictable branch.
#[derive(Clone)]
pub struct ChaCha20(Inner);

#[derive(Clone)]
enum Inner {
    #[cfg(target_arch = "x86_64")]
    Avx2(Cipher<x86_64::Avx2>),
    #[cfg(target_arch = "aarch64")]
    Neon(Cipher<aarch64::Neon>),
    #[cfg(target_arch = "riscv64")]
    Zvkb(Cipher<riscv64::Zvkb>),
    #[cfg(target_arch = "riscv64")]
    Zbb(Cipher<riscv64::Zbb>),
    Portable(Cipher<portable::Portable>),
}

/// A message in progress under a borrowed [`ChaCha20`].
pub struct AutoStream<'a>(InnerStream<'a>);

enum InnerStream<'a> {
    #[cfg(target_arch = "x86_64")]
    Avx2(Stream<'a, x86_64::Avx2>),
    #[cfg(target_arch = "aarch64")]
    Neon(Stream<'a, aarch64::Neon>),
    #[cfg(target_arch = "riscv64")]
    Zvkb(Stream<'a, riscv64::Zvkb>),
    #[cfg(target_arch = "riscv64")]
    Zbb(Stream<'a, riscv64::Zbb>),
    Portable(Stream<'a, portable::Portable>),
}

/// A message in progress under a [`ChaCha20`] of its own; see
/// [`ChaCha20::into_stream`].
pub struct OwnedAutoStream(InnerOwned);

enum InnerOwned {
    #[cfg(target_arch = "x86_64")]
    Avx2(OwnedStream<x86_64::Avx2>),
    #[cfg(target_arch = "aarch64")]
    Neon(OwnedStream<aarch64::Neon>),
    #[cfg(target_arch = "riscv64")]
    Zvkb(OwnedStream<riscv64::Zvkb>),
    #[cfg(target_arch = "riscv64")]
    Zbb(OwnedStream<riscv64::Zbb>),
    Portable(OwnedStream<portable::Portable>),
}

impl ChaCha20 {
    /// Takes the key, with the best implementation the features in
    /// force allow. The last kernel in the list needs nothing, so
    /// this cannot fail.
    pub fn new(key: &Key<[u8; KEY_SIZE]>) -> Self {
        // The list chose the arm, so the backend's own probe
        // answers yes unless the features changed between the two
        // reads; the portable fallback in each arm is right if they
        // did.
        let portable =
            || Inner::Portable(Cipher::with(portable::Portable, key));
        let inner = match features::select(KERNELS) {
            #[cfg(target_arch = "x86_64")]
            Some(Kernel::Avx2) => match x86_64::Avx2::probe() {
                Some(b) => Inner::Avx2(Cipher::with(b, key)),
                None => portable(),
            },
            #[cfg(target_arch = "aarch64")]
            Some(Kernel::Neon) => match aarch64::Neon::probe() {
                Some(b) => Inner::Neon(Cipher::with(b, key)),
                None => portable(),
            },
            #[cfg(target_arch = "riscv64")]
            Some(Kernel::Zvkb) => match riscv64::Zvkb::probe() {
                Some(b) => Inner::Zvkb(Cipher::with(b, key)),
                None => portable(),
            },
            #[cfg(target_arch = "riscv64")]
            Some(Kernel::Zbb) => match riscv64::Zbb::probe() {
                Some(b) => Inner::Zbb(Cipher::with(b, key)),
                None => portable(),
            },
            _ => portable(),
        };
        ChaCha20(inner)
    }

    /// The kernels this cipher chooses among, with their needs.
    #[cfg(test)]
    pub(crate) fn kernels() -> &'static [(Kernel, Features)] {
        KERNELS
    }

    /// Takes the key under `kernel` alone, or `None` where the set in
    /// force does not allow it. The vector suites and the cross-checks
    /// reach each kernel this way, through the same type that
    /// dispatches to it.
    #[cfg(test)]
    pub(crate) fn with_kernel(
        key: &Key<[u8; KEY_SIZE]>,
        kernel: Kernel,
    ) -> Option<Self> {
        if !features::available(KERNELS, kernel) {
            return None;
        }
        let inner = match kernel {
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx2 => {
                Inner::Avx2(Cipher::with(x86_64::Avx2::probe()?, key))
            }
            #[cfg(target_arch = "aarch64")]
            Kernel::Neon => {
                Inner::Neon(Cipher::with(aarch64::Neon::probe()?, key))
            }
            #[cfg(target_arch = "riscv64")]
            Kernel::Zvkb => {
                Inner::Zvkb(Cipher::with(riscv64::Zvkb::probe()?, key))
            }
            #[cfg(target_arch = "riscv64")]
            Kernel::Zbb => {
                Inner::Zbb(Cipher::with(riscv64::Zbb::probe()?, key))
            }
            Kernel::Portable => {
                Inner::Portable(Cipher::with(portable::Portable, key))
            }
        };
        Some(ChaCha20(inner))
    }

    /// Which kernel this cipher is running on.
    #[cfg(test)]
    pub(crate) fn kernel(&self) -> Kernel {
        match &self.0 {
            #[cfg(target_arch = "x86_64")]
            Inner::Avx2(_) => Kernel::Avx2,
            #[cfg(target_arch = "aarch64")]
            Inner::Neon(_) => Kernel::Neon,
            #[cfg(target_arch = "riscv64")]
            Inner::Zvkb(_) => Kernel::Zvkb,
            #[cfg(target_arch = "riscv64")]
            Inner::Zbb(_) => Kernel::Zbb,
            Inner::Portable(_) => Kernel::Portable,
        }
    }

    /// The feature profiles this cipher tells apart, best first; see
    /// [`Dispatcher`].
    pub fn profiles() -> &'static [Features] {
        &PROFILES
    }

    /// Encrypts `data` in place, its first byte at the start of
    /// block `counter`.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        dispatch!(&self.0, Inner, c => c.encrypt(nonce, counter, data))
    }

    /// Decrypts `data` in place; the same operation as
    /// [`encrypt`](Self::encrypt).
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        dispatch!(&self.0, Inner, c => c.decrypt(nonce, counter, data))
    }

    /// Starts a message that arrives in pieces.
    pub fn stream(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> AutoStream<'_> {
        AutoStream(match &self.0 {
            #[cfg(target_arch = "x86_64")]
            Inner::Avx2(c) => InnerStream::Avx2(c.stream(nonce, counter)),
            #[cfg(target_arch = "aarch64")]
            Inner::Neon(c) => InnerStream::Neon(c.stream(nonce, counter)),
            #[cfg(target_arch = "riscv64")]
            Inner::Zvkb(c) => InnerStream::Zvkb(c.stream(nonce, counter)),
            #[cfg(target_arch = "riscv64")]
            Inner::Zbb(c) => InnerStream::Zbb(c.stream(nonce, counter)),
            Inner::Portable(c) => {
                InnerStream::Portable(c.stream(nonce, counter))
            }
        })
    }

    /// Starts a message that arrives in pieces, taking the cipher
    /// with it: for a key that serves this one message, as under
    /// [`XChaCha20`](crate::cipher::xchacha20::XChaCha20).
    pub fn into_stream(
        self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> OwnedAutoStream {
        OwnedAutoStream(match self.0 {
            #[cfg(target_arch = "x86_64")]
            Inner::Avx2(c) => InnerOwned::Avx2(c.into_stream(nonce, counter)),
            #[cfg(target_arch = "aarch64")]
            Inner::Neon(c) => InnerOwned::Neon(c.into_stream(nonce, counter)),
            #[cfg(target_arch = "riscv64")]
            Inner::Zvkb(c) => InnerOwned::Zvkb(c.into_stream(nonce, counter)),
            #[cfg(target_arch = "riscv64")]
            Inner::Zbb(c) => InnerOwned::Zbb(c.into_stream(nonce, counter)),
            Inner::Portable(c) => {
                InnerOwned::Portable(c.into_stream(nonce, counter))
            }
        })
    }

    /// One block of keystream, as the AEAD takes its Poly1305 key.
    pub(crate) fn keystream_block(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> [u8; BLOCK_SIZE] {
        dispatch!(&self.0, Inner, c => c.keystream_block(nonce, counter))
    }
}

impl AutoStream<'_> {
    /// Encrypts or decrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        dispatch!(&mut self.0, InnerStream, s => s.update(data))
    }
}

impl OwnedAutoStream {
    /// Encrypts or decrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        dispatch!(&mut self.0, InnerOwned, s => s.update(data))
    }
}

impl features::sealed::Sealed for ChaCha20 {}

impl Dispatcher for ChaCha20 {
    fn profiles() -> &'static [Features] {
        ChaCha20::profiles()
    }
}

impl fmt::Debug for ChaCha20 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dispatch!(&self.0, Inner, c => c.fmt(f))
    }
}

impl fmt::Debug for AutoStream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dispatch!(&self.0, InnerStream, s => s.fmt(f))
    }
}

impl fmt::Debug for OwnedAutoStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dispatch!(&self.0, InnerOwned, s => s.fmt(f))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::format;

    use super::*;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), 2 * N);
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    /// RFC 8439 section 2.4.2: the sunscreen message.
    pub(crate) const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    const NONCE: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    const PLAIN: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would \
        be it.";
    const CIPHER: &str = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a\
        27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c\
        359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7\
        7937365af90bbf74a35be6b40b8eedf2785e42874d";

    /// Checks one implementation against the RFC's worked examples.
    pub(crate) fn check_known_answers<B: Backend>() {
        let cipher = Cipher::<B>::try_new(&Key::from(KEY)).unwrap();
        let mut data = *PLAIN;
        cipher.encrypt(&NONCE, 1, &mut data).unwrap();
        assert_eq!(data, hex::<114>(CIPHER));
        cipher.decrypt(&NONCE, 1, &mut data).unwrap();
        assert_eq!(&data, PLAIN);

        // Section 2.3.2: the block function on its own.
        let cipher = Cipher::<B>::try_new(&Key::from(KEY)).unwrap();
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let block = cipher.keystream_block(&nonce, 1);
        assert_eq!(block[..16], hex::<16>("10f1e7e4d13b5915500fdd1fa32071c4"));
        assert_eq!(block[48..], hex::<16>("b5129cd1de164eb9cbd083e8a2503c4e"));

        // Section 2.6.2: the Poly1305 key generation block.
        let key = hex::<32>(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e\
             9f",
        );
        let cipher = Cipher::<B>::try_new(&Key::from(key)).unwrap();
        let nonce = hex::<12>("000000000001020304050607");
        assert_eq!(
            cipher.keystream_block(&nonce, 0)[..32],
            hex::<32>(
                "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1\
                 a646"
            )
        );
    }

    /// Checks one implementation against the portable one over many
    /// lengths, counters and chunkings.
    #[cfg_attr(
        not(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "x86_64"
        )),
        allow(dead_code)
    )]
    #[test]
    fn known_answers() {
        let cipher = ChaCha20::new(&Key::from(KEY));
        let mut data = *PLAIN;
        cipher.encrypt(&NONCE, 1, &mut data).unwrap();
        assert_eq!(data, hex::<114>(CIPHER));
    }

    /// Every kernel this processor can build agrees with the portable
    /// code across lengths, counters and chunkings. The portable code
    /// is reached directly: on AArch64 it is not a row, since every
    /// processor there has NEON. The kernels this processor cannot
    /// build are reported rather than passed over in silence; the
    /// inventory audits those skips.
    #[test]
    fn every_kernel_agrees_with_the_portable_code() {
        let key = Key::from(KEY);
        let reference = Cipher::with(portable::Portable, &key);
        let data: [u8; 1100] = core::array::from_fn(|i| (i * 13 + 7) as u8);
        for &(kernel, _) in KERNELS {
            let Some(cipher) = ChaCha20::with_kernel(&key, kernel) else {
                std::eprintln!("{kernel:?} not available; skipping");
                continue;
            };
            for len in [
                0usize, 1, 63, 64, 65, 127, 128, 255, 256, 257, 511, 512, 513,
                1024, 1100,
            ] {
                for counter in [0u32, 1, 7, u32::MAX - 20] {
                    let tag = format!("{kernel:?} len {len} counter {counter}");
                    let mut want = data;
                    let mut got = data;
                    let want_result =
                        reference.encrypt(&NONCE, counter, &mut want[..len]);
                    let got_result =
                        cipher.encrypt(&NONCE, counter, &mut got[..len]);
                    assert_eq!(want_result, got_result, "{tag}");
                    assert_eq!(want[..len], got[..len], "{tag}");
                    // The same message in pieces.
                    let mut pieces = data;
                    let mut stream = cipher.stream(&NONCE, counter);
                    let mut ok = Ok(());
                    for chunk in pieces[..len].chunks_mut(37) {
                        ok = ok.and(stream.update(chunk));
                    }
                    assert_eq!(ok, got_result, "{tag} pieces");
                    if ok.is_ok() {
                        assert_eq!(pieces[..len], want[..len], "{tag} pieces");
                    }
                }
            }
        }
    }

    #[test]
    fn pieces_match_whole() {
        let cipher = ChaCha20::new(&Key::from(KEY));
        let data: [u8; 517] = core::array::from_fn(|i| (i * 31) as u8);
        let mut whole = data;
        cipher.encrypt(&NONCE, 5, &mut whole).unwrap();
        for chunk in [1, 3, 63, 64, 65, 100, 517] {
            let mut pieces = data;
            let mut stream = cipher.stream(&NONCE, 5);
            for piece in pieces.chunks_mut(chunk) {
                stream.update(piece).unwrap();
            }
            assert_eq!(pieces[..], whole[..], "chunk {chunk}");

            // And the stream that owns its cipher is the same stream.
            let mut owned = data;
            let mut stream = cipher.clone().into_stream(&NONCE, 5);
            for piece in owned.chunks_mut(chunk) {
                stream.update(piece).unwrap();
            }
            assert_eq!(owned[..], whole[..], "owned, chunk {chunk}");
        }
    }

    /// draft-irtf-cfrg-xchacha-03 section 2.2.1.
    #[test]
    fn hchacha20_known_answer() {
        let nonce = hex::<16>("000000090000004a0000000031415927");
        let subkey = hchacha20(&Key::from(KEY), &nonce);
        assert_eq!(
            *subkey.array(),
            hex::<32>(
                "82413b4227b27bfed30e42508a877d73\
                 a0f9e4d58a74a853c12ec41326d3ecdc"
            )
        );
    }

    /// The subkey is the first and last rows of the rounds without
    /// the input added back, so it cannot be read off any keystream
    /// block under the same key.
    #[test]
    fn hchacha20_is_not_keystream() {
        let key = Key::from(KEY);
        let nonce = hex::<16>("000000090000004a0000000031415927");
        let subkey = hchacha20(&key, &nonce);
        let cipher = ChaCha20::new(&key);
        let block = cipher.keystream_block(&[0u8; 12], 0);
        assert_ne!(&subkey.array()[..], &block[..32]);
        assert_ne!(&subkey.array()[..], &block[32..]);
        // Any change to the nonce changes every word of the result.
        let mut other = nonce;
        other[15] ^= 1;
        let changed = hchacha20(&key, &other);
        for (a, b) in subkey
            .array()
            .chunks_exact(4)
            .zip(changed.array().chunks_exact(4))
        {
            assert_ne!(a, b);
        }
    }

    #[test]
    fn refuses_to_wrap_the_counter() {
        let cipher = ChaCha20::new(&Key::from(KEY));
        let mut data = [0u8; 129];
        // Two blocks and a byte from the last block: the third block
        // does not exist.
        assert_eq!(
            cipher.encrypt(&NONCE, u32::MAX - 1, &mut data),
            Err(Error::MessageTooLong)
        );
        assert_eq!(data, [0u8; 129]);
        // Exactly the last two blocks is fine.
        assert_eq!(
            cipher.encrypt(&NONCE, u32::MAX - 1, &mut data[..128]),
            Ok(())
        );
        // And a stream that has consumed the last block cannot go on.
        let mut stream = cipher.stream(&NONCE, u32::MAX);
        assert_eq!(stream.update(&mut data[..10]), Ok(()));
        assert_eq!(stream.update(&mut data[..54]), Ok(()));
        assert_eq!(stream.update(&mut data[..1]), Err(Error::MessageTooLong));
    }

    #[test]
    fn every_implementation_zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Cipher<portable::Portable>>();
        wipes::<Stream<'static, portable::Portable>>();
        wipes::<OwnedStream<portable::Portable>>();
        #[cfg(target_arch = "x86_64")]
        wipes::<Cipher<x86_64::Avx2>>();
        #[cfg(target_arch = "aarch64")]
        wipes::<Cipher<aarch64::Neon>>();
        #[cfg(target_arch = "riscv64")]
        wipes::<Cipher<riscv64::Zvkb>>();
        #[cfg(target_arch = "riscv64")]
        wipes::<Cipher<riscv64::Zbb>>();
    }

    #[test]
    fn picks_the_first_kernel_whose_needs_are_met() {
        let cipher = ChaCha20::new(&Key::from([0u8; 32]));
        features::dispatches(KERNELS, ChaCha20::profiles(), cipher.kernel());
    }

    #[test]
    fn debug_omits_the_key() {
        struct Buffer([u8; 128], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let cipher = ChaCha20::new(&Key::from([0x5au8; 32]));
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{cipher:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("5a"), "{text}");
    }
}
