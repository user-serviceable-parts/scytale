//! AES (FIPS 197) block cipher.
//!
//! The key width is the type: [`Aes128`], [`Aes192`] and [`Aes256`],
//! each taking a key of exactly its width. Each runs the best
//! implementation the processor supports, chosen when the key is
//! expanded: hardware instructions where there are any, otherwise
//! constant-time portable code. Which one that is is not a choice a
//! caller makes, and the implementations are not names a caller can
//! reach; security comes before speed, so the faster table-driven
//! code, whose memory access pattern depends on the key, is never
//! chosen.
//!
//! The expanded key is wiped on drop.
//!
//! ```
//! use scytale::Context;
//! use scytale::Key;
//! use scytale::cipher::BlockCipher;
//! use scytale::cipher::aes::Aes128;
//! let ctx = Context::default();
//!
//! let aes = Aes128::new(ctx, &Key::from([0u8; 16]));
//! let mut blocks = [[0u8; 16]; 4];
//! aes.encrypt(&mut blocks);
//! aes.decrypt(&mut blocks);
//! assert_eq!(blocks, [[0u8; 16]; 4]);
//! ```

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;
pub(crate) mod portable;
#[cfg(target_arch = "riscv64")]
pub(crate) mod riscv64;
#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

use core::fmt;

use crate::cipher::BlockCipher;
use crate::features::{self, Dispatcher, Features};
use crate::{BlockType, Context, Key, KeyType};

/// AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// Words in the longest key schedule (AES-256: 15 round keys).
pub(crate) const MAX_WORDS: usize = 60;

/// Key size, which fixes the number of rounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeySize {
    Aes128,
    Aes192,
    Aes256,
}

impl KeySize {
    /// The size of a `key`.
    ///
    /// Every caller has a key whose width the type system has
    /// already fixed to 16, 24 or 32.
    pub(crate) fn for_key(key: &[u8]) -> Self {
        match key.len() {
            16 => KeySize::Aes128,
            24 => KeySize::Aes192,
            32 => KeySize::Aes256,
            n => unreachable!("AES key of {n} bytes"),
        }
    }

    pub(crate) fn rounds(self) -> usize {
        match self {
            KeySize::Aes128 => 10,
            KeySize::Aes192 => 12,
            KeySize::Aes256 => 14,
        }
    }
}

/// Key expansion (FIPS 197 section 5.2), shared by every
/// implementation; each supplies its own `SubWord`.
///
/// Words are the little-endian view of four consecutive key bytes,
/// the order in which the hardware instructions see the state. On
/// such a word `RotWord` is a rotate right by 8 and the round constant
/// goes in the low byte. Unused words at the end stay zero.
pub(crate) fn expand_words(
    key: &[u8],
    size: KeySize,
    sub_word: impl Fn(u32) -> u32,
) -> [u32; MAX_WORDS] {
    let nk = key.len() / 4;
    let words = 4 * (size.rounds() + 1);

    let mut w = [0u32; MAX_WORDS];
    for (w, k) in w.iter_mut().zip(key.chunks_exact(4)) {
        *w = u32::from_le_bytes([k[0], k[1], k[2], k[3]]);
    }
    let mut rcon: u32 = 1;
    for i in nk..words {
        let mut t = w[i - 1];
        if i % nk == 0 {
            t = sub_word(t.rotate_right(8)) ^ rcon;
            // Multiply by x in GF(2^8).
            rcon = (rcon << 1) ^ if rcon & 0x80 != 0 { 0x11b } else { 0 };
        } else if nk > 6 && i % nk == 4 {
            t = sub_word(t);
        }
        w[i] = w[i - nk] ^ t;
    }
    w
}

/// Which kernel an AES key is expanded for.
///
/// Which can be chosen is what [`Aes128::profiles`] and its siblings
/// publish, by needs rather than by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Kernel {
    /// VAES on x86-64, two blocks to a register.
    #[cfg(target_arch = "x86_64")]
    Vaes,
    /// AES-NI on x86-64.
    #[cfg(target_arch = "x86_64")]
    AesNi,
    /// The ARMv8 cryptography extension.
    #[cfg(target_arch = "aarch64")]
    Armv8,
    /// RISC-V vector AES, Zvkned.
    #[cfg(target_arch = "riscv64")]
    Zvkned,
    /// RISC-V scalar AES, Zkne and Zknd.
    #[cfg(target_arch = "riscv64")]
    Zkn,
    /// Plain Rust over lookup tables, which leak through cache
    /// timing: chosen only where [`Feature::Isolated`] is in force.
    Tables,
    /// Plain Rust, bitsliced, constant time, on any processor.
    Bitsliced,
}

features::kernels! {
    enum Kernel;

    /// The kernels, best first; the first whose needs are in force is
    /// the one a new key gets. The hardware comes first, fastest
    /// first; then the table-driven code, which only
    /// [`Feature::Isolated`] admits; then the constant-time portable
    /// code, which needs nothing.
    ///
    /// AES-NI's key expansion shuffles with `pshufb` (SSSE3); its
    /// loops are the legacy SSE encodings, so it needs no AVX. VAES
    /// runs two blocks to a 256-bit register (AVX2, with AVX for the
    /// operating system keeping those registers) and finishes its
    /// tails with the AES-NI loops.
    pub(crate) const KERNELS for aes tested by tests::kernel = [
        #[cfg(target_arch = "x86_64")]
        Vaes => (x86_64: Aes, Ssse3, Avx, Avx2, Vaes),
        #[cfg(target_arch = "x86_64")]
        AesNi => (x86_64: Aes, Ssse3),
        #[cfg(target_arch = "aarch64")]
        Armv8 => (aarch64: Aes),
        #[cfg(target_arch = "riscv64")]
        Zvkned => (riscv64: V, Zvkned),
        #[cfg(target_arch = "riscv64")]
        Zkn => (riscv64: Zkne, Zknd),
        Tables => (isolated),
        Bitsliced => (),
    ];

    /// AEGIS-128L's kernels, named as AES's are since each is built
    /// on that kernel's round. Only the encryption round is used, so
    /// the scalar RISC-V kernel needs Zkne alone.
    pub(crate) const AEGIS128L for aegis128l
        tested by crate::aead::aegis::aegis128l::tests::kernel = [
        #[cfg(target_arch = "x86_64")]
        AesNi => (x86_64: Aes, Ssse3),
        #[cfg(target_arch = "aarch64")]
        Armv8 => (aarch64: Aes),
        #[cfg(target_arch = "riscv64")]
        Zvkned => (riscv64: V, Zvkned),
        #[cfg(target_arch = "riscv64")]
        Zkn => (riscv64: Zkne),
        Tables => (isolated),
        Bitsliced => (),
    ];

    /// AEGIS-256's kernels, as AEGIS-128L's.
    pub(crate) const AEGIS256 for aegis256
        tested by crate::aead::aegis::aegis256::tests::kernel = [
        #[cfg(target_arch = "x86_64")]
        AesNi => (x86_64: Aes, Ssse3),
        #[cfg(target_arch = "aarch64")]
        Armv8 => (aarch64: Aes),
        #[cfg(target_arch = "riscv64")]
        Zvkned => (riscv64: V, Zvkned),
        #[cfg(target_arch = "riscv64")]
        Zkn => (riscv64: Zkne),
        Tables => (isolated),
        Bitsliced => (),
    ];

    /// AEGIS-128X's kernels: AEGIS-128L's, and VAES on x86-64, whose
    /// lanes are its own.
    pub(crate) const AEGIS128X for aegis128x
        tested by crate::aead::aegis::aegis128x::tests::kernel = [
        #[cfg(target_arch = "x86_64")]
        Vaes => (x86_64: Aes, Ssse3, Avx, Avx2, Vaes),
        #[cfg(target_arch = "x86_64")]
        AesNi => (x86_64: Aes, Ssse3),
        #[cfg(target_arch = "aarch64")]
        Armv8 => (aarch64: Aes),
        #[cfg(target_arch = "riscv64")]
        Zvkned => (riscv64: V, Zvkned),
        #[cfg(target_arch = "riscv64")]
        Zkn => (riscv64: Zkne),
        Tables => (isolated),
        Bitsliced => (),
    ];

    /// AEGIS-256X's kernels, as AEGIS-128X's.
    pub(crate) const AEGIS256X for aegis256x
        tested by crate::aead::aegis::aegis256x::tests::kernel = [
        #[cfg(target_arch = "x86_64")]
        Vaes => (x86_64: Aes, Ssse3, Avx, Avx2, Vaes),
        #[cfg(target_arch = "x86_64")]
        AesNi => (x86_64: Aes, Ssse3),
        #[cfg(target_arch = "aarch64")]
        Armv8 => (aarch64: Aes),
        #[cfg(target_arch = "riscv64")]
        Zvkned => (riscv64: V, Zvkned),
        #[cfg(target_arch = "riscv64")]
        Zkn => (riscv64: Zkne),
        Tables => (isolated),
        Bitsliced => (),
    ];
}

/// What the list publishes: the needs, without the names.
const PROFILES: [Features; KERNELS.len()] = features::profiles_of(KERNELS);

/// AES over the best implementation its context allows, at
/// a key width of `K` bytes.
///
/// The public types are the three widths: [`Aes128`], [`Aes192`] and
/// [`Aes256`]. This one is generic so that the crate's own code, and
/// the tests, can be written once for all three.
///
/// The choice is made when the key is expanded, and each call then
/// dispatches with a single predictable branch.
#[derive(Clone)]
pub(crate) struct Aes<const K: usize>(Inner<K>);

// Each variant is that implementation's key schedule; the bitsliced
// one is twice the size of the others and there is no heap to box it.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum Inner<const K: usize> {
    #[cfg(target_arch = "x86_64")]
    Vaes(x86_64::vaes::Aes<K>),
    #[cfg(target_arch = "x86_64")]
    AesNi(x86_64::aesni::Aes<K>),
    #[cfg(target_arch = "aarch64")]
    Armv8(aarch64::armv8::Aes<K>),
    #[cfg(target_arch = "riscv64")]
    Zvkned(riscv64::zvkned::Aes<K>),
    #[cfg(target_arch = "riscv64")]
    Zkn(riscv64::zkn::Aes<K>),
    Tables(portable::ttable::Aes<K>),
    Bitsliced(portable::bitsliced::Aes<K>),
}

/// Applies a method to whichever implementation is in use.
macro_rules! dispatch {
    ($self:expr, $aes:ident => $body:expr) => {
        match &$self.0 {
            #[cfg(target_arch = "x86_64")]
            Inner::Vaes($aes) => $body,
            #[cfg(target_arch = "x86_64")]
            Inner::AesNi($aes) => $body,
            #[cfg(target_arch = "aarch64")]
            Inner::Armv8($aes) => $body,
            #[cfg(target_arch = "riscv64")]
            Inner::Zvkned($aes) => $body,
            #[cfg(target_arch = "riscv64")]
            Inner::Zkn($aes) => $body,
            Inner::Tables($aes) => $body,
            Inner::Bitsliced($aes) => $body,
        }
    };
}

impl<const K: usize> fmt::Debug for Aes<K> {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

impl<const K: usize> Aes<K> {
    /// Expands `key` with the best implementation `ctx` allows.
    ///
    /// A width other than 16, 24 or 32 is refused when the type is
    /// instantiated, at compile time.
    pub(crate) fn new(ctx: Context, key: &[u8; K]) -> Self {
        const {
            assert!(
                K == 16 || K == 24 || K == 32,
                "AES keys are 16, 24 or 32 bytes"
            )
        };
        let inner = {
            let built = match features::choose(ctx, KERNELS) {
                #[cfg(target_arch = "x86_64")]
                Some(c) if c.kernel() == Kernel::Vaes => {
                    x86_64::vaes::Aes::new(key, c).map(Inner::Vaes)
                }
                #[cfg(target_arch = "x86_64")]
                Some(c) if c.kernel() == Kernel::AesNi => {
                    x86_64::aesni::Aes::new(key, c).map(Inner::AesNi)
                }
                #[cfg(target_arch = "aarch64")]
                Some(c) if c.kernel() == Kernel::Armv8 => {
                    aarch64::armv8::Aes::new(key, c).map(Inner::Armv8)
                }
                #[cfg(target_arch = "riscv64")]
                Some(c) if c.kernel() == Kernel::Zvkned => {
                    riscv64::zvkned::Aes::new(key, c).map(Inner::Zvkned)
                }
                #[cfg(target_arch = "riscv64")]
                Some(c) if c.kernel() == Kernel::Zkn => {
                    riscv64::zkn::Aes::new(key, c).map(Inner::Zkn)
                }
                Some(c) if c.kernel() == Kernel::Tables => {
                    Some(Inner::Tables(portable::ttable::Aes::new(key)))
                }
                _ => None,
            };
            built.unwrap_or_else(|| {
                Inner::Bitsliced(portable::bitsliced::Aes::new(key))
            })
        };
        Aes(inner)
    }

    /// Which kernel this key was expanded for.
    #[cfg(test)]
    pub(crate) fn kernel(&self) -> Kernel {
        match &self.0 {
            #[cfg(target_arch = "x86_64")]
            Inner::Vaes(_) => Kernel::Vaes,
            #[cfg(target_arch = "x86_64")]
            Inner::AesNi(_) => Kernel::AesNi,
            #[cfg(target_arch = "aarch64")]
            Inner::Armv8(_) => Kernel::Armv8,
            #[cfg(target_arch = "riscv64")]
            Inner::Zvkned(_) => Kernel::Zvkned,
            #[cfg(target_arch = "riscv64")]
            Inner::Zkn(_) => Kernel::Zkn,
            Inner::Tables(_) => Kernel::Tables,
            Inner::Bitsliced(_) => Kernel::Bitsliced,
        }
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub(crate) fn rounds(&self) -> usize {
        dispatch!(self, aes => aes.rounds())
    }

    /// Encrypts every block in place, independently (ECB).
    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        dispatch!(self, aes => aes.encrypt_blocks(blocks))
    }

    /// Decrypts every block in place, independently (ECB).
    pub(crate) fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        dispatch!(self, aes => aes.decrypt_blocks(blocks))
    }
}

/// The expanded key as the AES instructions want it, where the
/// implementation the processor chose is one of theirs, and `None`
/// for the portable ones, whose key schedules are nothing those
/// instructions could read.
#[cfg(target_arch = "aarch64")]
impl<const K: usize> aarch64::Keyed for Aes<K> {
    fn schedule(&self) -> Option<aarch64::Schedule<'_>> {
        match &self.0 {
            Inner::Armv8(aes) => aes.schedule(),
            _ => None,
        }
    }

    fn decryption(&self) -> Option<aarch64::Schedule<'_>> {
        match &self.0 {
            Inner::Armv8(aes) => aes.decryption(),
            _ => None,
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl<const K: usize> x86_64::Keyed for Aes<K> {
    fn schedule(&self) -> Option<x86_64::Schedule<'_>> {
        match &self.0 {
            Inner::Vaes(aes) => aes.schedule(),
            Inner::AesNi(aes) => aes.schedule(),
            _ => None,
        }
    }

    fn decryption(&self) -> Option<x86_64::Schedule<'_>> {
        match &self.0 {
            Inner::Vaes(aes) => aes.decryption(),
            Inner::AesNi(aes) => aes.decryption(),
            _ => None,
        }
    }
}

#[cfg(target_arch = "riscv64")]
impl<const K: usize> riscv64::Keyed for Aes<K> {
    fn schedule(&self) -> Option<riscv64::Schedule<'_>> {
        match &self.0 {
            Inner::Zvkned(aes) => aes.schedule(),
            _ => None,
        }
    }
}

impl<const K: usize> BlockType for Aes<K> {
    type Block = [u8; BLOCK_SIZE];

    fn zero_block() -> Self::Block {
        [0; BLOCK_SIZE]
    }
}

impl<const K: usize> KeyType for Aes<K> {
    type Key = Key<[u8; K]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

impl<const K: usize> BlockCipher for Aes<K> {
    fn new(ctx: Context, key: &Self::Key) -> Self {
        Aes::new(ctx, key.array())
    }

    fn encrypt(&self, blocks: &mut [Self::Block]) {
        Aes::encrypt_blocks(self, blocks)
    }

    fn decrypt(&self, blocks: &mut [Self::Block]) {
        Aes::decrypt_blocks(self, blocks)
    }
}

/// Defines one of the three public widths over [`Aes`].
macro_rules! width {
    ($(#[$doc:meta])* $name:ident, $k:literal) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name(Aes<$k>);

        impl $name {
            /// Expands `key` with the best implementation `ctx`
            /// allows; see [`crate::features`].
            pub fn new(ctx: Context, key: &Key<[u8; $k]>) -> Self {
                $name(Aes::new(ctx, key.array()))
            }

            /// The feature profiles this cipher tells apart, best
            /// first; see [`Dispatcher`].
            pub fn profiles() -> &'static [Features] {
                &PROFILES
            }

            /// Number of rounds the key width fixes.
            pub fn rounds(&self) -> usize {
                self.0.rounds()
            }

            /// Encrypts every block in place, independently (ECB).
            pub fn encrypt(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
                self.0.encrypt_blocks(blocks)
            }

            /// Decrypts every block in place, independently (ECB).
            pub fn decrypt(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
                self.0.decrypt_blocks(blocks)
            }
        }

        impl fmt::Debug for $name {
            /// Deliberately omits the key material.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("rounds", &self.rounds())
                    .finish()
            }
        }

        impl features::sealed::Sealed for $name {}

        impl Dispatcher for $name {
            fn profiles() -> &'static [Features] {
                $name::profiles()
            }
        }

        /// The expanded key; see the implementation over [`Aes`].
        #[cfg(target_arch = "aarch64")]
        impl aarch64::Keyed for $name {
            fn schedule(&self) -> Option<aarch64::Schedule<'_>> {
                aarch64::Keyed::schedule(&self.0)
            }

            fn decryption(&self) -> Option<aarch64::Schedule<'_>> {
                aarch64::Keyed::decryption(&self.0)
            }
        }

        /// The expanded key; see the implementation over [`Aes`].
        #[cfg(target_arch = "riscv64")]
        impl riscv64::Keyed for $name {
            fn schedule(&self) -> Option<riscv64::Schedule<'_>> {
                riscv64::Keyed::schedule(&self.0)
            }
        }

        /// The expanded key; see the implementation over [`Aes`].
        #[cfg(target_arch = "x86_64")]
        impl x86_64::Keyed for $name {
            fn schedule(&self) -> Option<x86_64::Schedule<'_>> {
                x86_64::Keyed::schedule(&self.0)
            }

            fn decryption(&self) -> Option<x86_64::Schedule<'_>> {
                x86_64::Keyed::decryption(&self.0)
            }
        }

        impl BlockType for $name {
            type Block = [u8; BLOCK_SIZE];

            fn zero_block() -> Self::Block {
                [0; BLOCK_SIZE]
            }
        }

        impl KeyType for $name {
            type Key = Key<[u8; $k]>;

            fn zero_key() -> Self::Key {
                Key::zeroed()
            }
        }

        impl BlockCipher for $name {
            fn new(ctx: Context, key: &Self::Key) -> Self {
                $name::new(ctx, key)
            }

            fn encrypt(&self, blocks: &mut [Self::Block]) {
                $name::encrypt(self, blocks)
            }

            fn decrypt(&self, blocks: &mut [Self::Block]) {
                $name::decrypt(self, blocks)
            }
        }
    };
}

width!(
    /// AES with a 128-bit key.
    Aes128,
    16
);
width!(
    /// AES with a 192-bit key.
    Aes192,
    24
);
width!(
    /// AES with a 256-bit key.
    Aes256,
    32
);

#[cfg(test)]
mod tests {

    use super::*;
    use zeroize::ZeroizeOnDrop;

    /// Compiles only if every implementation wipes its key on drop.
    #[test]
    fn every_implementation_zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<portable::ttable::Aes<16>>();
        wipes::<portable::bitsliced::Aes<16>>();
        #[cfg(target_arch = "x86_64")]
        {
            wipes::<x86_64::aesni::Aes<16>>();
            wipes::<x86_64::vaes::Aes<16>>();
        }
        #[cfg(target_arch = "aarch64")]
        wipes::<aarch64::armv8::Aes<16>>();
        #[cfg(target_arch = "riscv64")]
        {
            wipes::<riscv64::zkn::Aes<16>>();
            wipes::<riscv64::zvkned::Aes<16>>();
        }
    }

    #[test]
    fn expansion_matches_fips197_appendix_a() {
        use portable::ttable::tables::SBOX;
        let sub = |w: u32| {
            u32::from_le_bytes(w.to_le_bytes().map(|b| SBOX[b as usize]))
        };
        // FIPS 197 A.1: last round key of the AES-128 example.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let w = expand_words(&key, KeySize::Aes128, sub);
        let mut last = [0u8; 16];
        for (c, word) in last.chunks_exact_mut(4).zip(&w[40..44]) {
            c.copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            last,
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f,
                0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6
            ]
        );
        assert_eq!(w[44..], [0; 16], "unused words stay zero");
    }

    #[test]
    fn picks_the_first_kernel_whose_needs_are_met() {
        let built = {
            let built = Aes::<16>::new(Context::default(), &[0; 16]).kernel();
            features::dispatches(KERNELS, Aes128::profiles(), built);
            built
        };
        assert_eq!(Aes256::profiles(), Aes128::profiles());
        assert_eq!(KERNELS.last(), Some(&(Kernel::Bitsliced, Features::new())));
        // Tables are never detected, so never chosen unasked.
        assert_ne!(built, Kernel::Tables);
    }

    /// AES at every key width under one kernel, built through the
    /// public types: the FIPS 197 examples, and agreement with the
    /// portable code both directions, a block at a time and in bulk,
    /// at every tail width the widest loop has, with and without full
    /// groups before it.
    pub(crate) fn kernel(under: &features::Under) {
        // The round counts, on the kernel the row chooses.
        assert_eq!(Aes::<16>::new(under.ctx(), &[0; 16]).rounds(), 10);
        assert_eq!(Aes::<24>::new(under.ctx(), &[0; 24]).rounds(), 12);
        assert_eq!(Aes::<32>::new(under.ctx(), &[0; 32]).rounds(), 14);
        let chosen = features::choose(under.ctx(), KERNELS).expect("listed");
        #[cfg(target_arch = "x86_64")]
        x86_64::schedule_is_standard(chosen);
        #[cfg(target_arch = "aarch64")]
        aarch64::armv8::schedule_is_standard(chosen);
        let _ = chosen;
        fips197(under);
        agrees::<Aes128, 16>(under);
        agrees::<Aes192, 24>(under);
        agrees::<Aes256, 32>(under);
    }

    /// FIPS 197 appendix C, at each width.
    fn fips197(under: &features::Under) {
        let plain: [u8; 16] = core::array::from_fn(|i| (i * 0x11) as u8);
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let cases: [(&[u8], [u8; 16]); 3] = [
            (
                &key[..16],
                [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd,
                    0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
                ],
            ),
            (
                &key[..24],
                [
                    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf,
                    0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
                ],
            ),
            (
                &key[..32],
                [
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc,
                    0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
                ],
            ),
        ];
        for (key, want) in cases {
            let mut block = [plain];
            match key.len() {
                16 => run::<Aes128, 16>(under, key, &mut block),
                24 => run::<Aes192, 24>(under, key, &mut block),
                _ => run::<Aes256, 32>(under, key, &mut block),
            }
            assert_eq!(block[0], want, "AES-{}", key.len() * 8);
        }

        fn run<C, const K: usize>(
            under: &features::Under,
            key: &[u8],
            blocks: &mut [[u8; 16]],
        ) where
            C: BlockCipher<Block = [u8; BLOCK_SIZE], Key = Key<[u8; K]>>,
        {
            let key = Key::from(<[u8; K]>::try_from(key).expect("width"));
            let aes = C::new(under.ctx(), &key);
            aes.encrypt(blocks);
            let mut back = blocks.to_vec();
            aes.decrypt(&mut back);
            assert_eq!(back[0], core::array::from_fn(|i| (i * 0x11) as u8));
        }
    }

    /// One width under one kernel against the bitsliced code.
    fn agrees<C, const K: usize>(under: &features::Under)
    where
        C: BlockCipher<Block = [u8; BLOCK_SIZE], Key = Key<[u8; K]>>,
    {
        // Past the widest loop's group, so its tails are all here.
        const MAX: usize = 41;
        let key = Key::from(core::array::from_fn(|i| (i * 37 + K) as u8));
        let aes = C::new(under.ctx(), &key);
        let reference = { C::new(Context::portable(), &key) };
        let mut data = [[0u8; BLOCK_SIZE]; MAX];
        for (i, b) in data.as_flattened_mut().iter_mut().enumerate() {
            *b = (i * 13 + K) as u8;
        }
        for nblocks in 0..=MAX {
            let mut got = data;
            let mut want = data;
            reference.encrypt(&mut want[..nblocks]);
            aes.encrypt(&mut got[..nblocks]);
            assert_eq!(got, want, "encrypt {K} {nblocks}");
            aes.decrypt(&mut got[..nblocks]);
            assert_eq!(got, data, "decrypt {K} {nblocks}");
        }
    }

    /// The three public widths are the same cipher as the generic one
    /// they wrap, both ways round and over a run of blocks.
    ///
    /// The vector suites validate each kernel through the generic
    /// type; these wrappers sit above all of that and are covered
    /// here.
    #[test]
    fn widths_match() {
        fn same<W, const K: usize>(wrapped: W, key: [u8; K])
        where
            W: BlockCipher<Block = [u8; BLOCK_SIZE], Key = Key<[u8; K]>>,
        {
            let generic = Aes::<K>::new(Context::default(), &key);
            // Enough blocks to pass through a group loop and leave a
            // tail, which is where the two could differ.
            let mut mine = [[0u8; BLOCK_SIZE]; 19];
            for (i, x) in mine.as_flattened_mut().iter_mut().enumerate() {
                *x = (i * 7) as u8;
            }
            let plain = mine;
            let mut theirs = mine;

            wrapped.encrypt(&mut mine);
            generic.encrypt_blocks(&mut theirs);
            assert_eq!(mine, theirs, "encrypting under a {K} byte key");
            assert_ne!(mine, plain, "encrypting changed nothing");

            wrapped.decrypt(&mut mine);
            generic.decrypt_blocks(&mut theirs);
            assert_eq!(mine, theirs, "decrypting under a {K} byte key");
            assert_eq!(mine, plain, "decrypting did not undo encrypting");
        }

        same(
            Aes128::new(Context::default(), &Key::from([9u8; 16])),
            [9u8; 16],
        );
        same(
            Aes192::new(Context::default(), &Key::from([9u8; 24])),
            [9u8; 24],
        );
        same(
            Aes256::new(Context::default(), &Key::from([9u8; 32])),
            [9u8; 32],
        );

        assert_eq!(
            Aes128::new(Context::default(), &Key::from([0u8; 16])).rounds(),
            10
        );
        assert_eq!(
            Aes192::new(Context::default(), &Key::from([0u8; 24])).rounds(),
            12
        );
        assert_eq!(
            Aes256::new(Context::default(), &Key::from([0u8; 32])).rounds(),
            14
        );
    }
}
