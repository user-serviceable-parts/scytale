//! SHA-3 (FIPS 202): SHA3-224, SHA3-256, SHA3-384 and SHA3-512, the
//! extendable-output functions SHAKE128 and SHAKE256, their
//! customizable forms cSHAKE128 and cSHAKE256 (SP 800-185), and
//! TupleHash128 and TupleHash256, which hash a sequence of strings.
//!
//! One function underneath, really: the Keccak-f\[1600\] permutation
//! used as a sponge. The six differ in how much of the 1600-bit
//! state the message goes into at a time, the rate, and in the bits
//! that end the message. The digests give a fixed output; the SHAKE
//! functions give as much as is asked for, through [`Xof`]. The types
//! here pick the best kernel the features in force allow (see
//! [`crate::features`]); the kernels are not names a caller can
//! reach, only the feature profiles that tell them apart.
//!
//! ```
//! use scytale::hash::sha3::{Sha3_256, Shake128};
//! use scytale::hash::{Hash, Xof, XofReader};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let digest = Sha3_256::digest(b"abc");
//! assert_eq!(digest[..4], [0x3a, 0x98, 0x5d, 0xa7]);
//!
//! let mut shake = Shake128::new();
//! shake.update(b"abc");
//! let mut reader = shake.finalize_xof();
//! let mut out = [0u8; 64];
//! reader.squeeze(&mut out[..32]);
//! reader.squeeze(&mut out[32..]);
//! assert_eq!(out[..4], [0x58, 0x81, 0x09, 0x2d]);
//! # Ok(())
//! # }
//! ```
//!
//! # Choosing
//!
//! SHA-3 is not a replacement for SHA-2, which is unbroken; it is a
//! different design, for protocols that name it and for anyone who
//! wants a hash that cannot be length-extended: a SHA-3 digest gives
//! away nothing about the state that made it. SHAKE is the choice
//! where the output length is the caller's to decide, and is what
//! the newer standards build key derivation on. cSHAKE is SHAKE with
//! a label absorbed first, for outputs that must not coincide across
//! purposes; KMAC, in [`mac::kmac`](crate::mac::kmac), is built on it.
//! SHA3-256 and SHAKE128 are the usual picks; the larger digests cost
//! more per byte because less of each permutation is message.
//! TupleHash, [`TupleHash128`], is for hashing several strings where
//! the boundaries between them must count.
//!
//! # ParallelHash
//!
//! SP 800-185's ParallelHash is deliberately absent. The standard
//! counts its blocks as `ceil((len(X)/8) / B)` over the reals, so a
//! message's last few bits after a full block make a block of their
//! own; NIST's validation vectors divide in integers and drop those
//! bits unhashed. The two disagree on 73 of the 400 one-shot vectors,
//! and the question is open with NIST as ACVP-Server issue 440. Until
//! it is settled, an implementation of either reading would fail the
//! other, so there is none.
//!
//! # Bit strings
//!
//! Like SHA-2, defined over bit strings, with the last few bits
//! taken by [`BitHash::finalize_bits`] and
//! [`BitXof::finalize_bits_xof`]. FIPS 202 numbers bits from the
//! least significant end of a byte, and so do these.
//!
//! # Speed
//!
//! The permutation is the whole cost, and a message advances the
//! state one permutation per rate of bytes. AArch64 processors with
//! the SHA3 extension have instructions for the permutation's steps,
//! and are two to three times the portable speed. Nothing else has
//! such instructions. x86-64 runs the portable permutation compiled
//! a second time for BMI1 and BMI2, about a fifth faster, and RISC-V
//! does the same for Zbb, which has the same two instructions; either
//! is a little slower than SHA-256 with no hardware and much slower
//! than SHA-256 with it.

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;
pub(crate) mod cshake;
pub(crate) mod engine;
pub(crate) mod portable;
#[cfg(target_arch = "riscv64")]
mod riscv64;
mod tuple_hash;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use core::fmt;

use engine::{DigestVariant, Reader, Sponge, XofVariant};

#[cfg(target_arch = "aarch64")]
use crate::features::aarch64::Feature as A;
use crate::features::{self, Dispatcher, Features};
use crate::hash::{BitHash, BitXof, Hash, Xof, XofReader};
use crate::{BlockType, Error};

/// The six functions, as markers the sponge is generic over.
pub(crate) mod variant {
    use super::engine::{DigestVariant, Sealed, Variant, XofVariant};

    /// Defines a marker with its rate and suffix.
    macro_rules! variant {
        ($(#[$doc:meta])* $name:ident, $rate:literal, $suffix:literal) => {
            $(#[$doc])*
            #[derive(Clone, Copy, Debug)]
            pub struct $name;

            impl Sealed for $name {}

            impl Variant for $name {
                type Block = [u8; $rate];
                const SUFFIX: u8 = $suffix;

                fn zero_block() -> Self::Block {
                    [0; $rate]
                }
            }
        };
    }

    variant!(/** SHA3-224. */ Sha3_224, 144, 0x06);
    variant!(/** SHA3-256. */ Sha3_256, 136, 0x06);
    variant!(/** SHA3-384. */ Sha3_384, 104, 0x06);
    variant!(/** SHA3-512. */ Sha3_512, 72, 0x06);
    variant!(/** SHAKE128. */ Shake128, 168, 0x1f);
    variant!(/** SHAKE256. */ Shake256, 136, 0x1f);
    variant!(/** cSHAKE128. */ CShake128, 168, 0x04);
    variant!(/** cSHAKE256. */ CShake256, 136, 0x04);

    impl DigestVariant for Sha3_224 {
        type Output = [u8; 28];

        fn zero_output() -> Self::Output {
            [0; 28]
        }
    }
    impl DigestVariant for Sha3_256 {
        type Output = [u8; 32];

        fn zero_output() -> Self::Output {
            [0; 32]
        }
    }
    impl DigestVariant for Sha3_384 {
        type Output = [u8; 48];

        fn zero_output() -> Self::Output {
            [0; 48]
        }
    }
    impl DigestVariant for Sha3_512 {
        type Output = [u8; 64];

        fn zero_output() -> Self::Output {
            [0; 64]
        }
    }
    impl XofVariant for Shake128 {}
    impl XofVariant for Shake256 {}
    impl XofVariant for CShake128 {}
    impl XofVariant for CShake256 {}
}

/// Which permutation a SHA-3 function is running on.
///
/// Which can be chosen is what [`Sha3_256::profiles`] and its
/// siblings publish, by needs rather than by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Kernel {
    /// The ARMv8.2 SHA-3 instructions.
    #[cfg(target_arch = "aarch64")]
    Armv8,
    /// The portable permutation compiled for BMI1 and BMI2.
    #[cfg(target_arch = "x86_64")]
    Bmi,
    /// The portable permutation compiled for Zbb.
    #[cfg(target_arch = "riscv64")]
    Zbb,
    /// Plain Rust, on any processor.
    Portable,
}

/// The ARMv8.2 SHA-3 instructions.
#[cfg(target_arch = "aarch64")]
pub(crate) const ARMV8: Features = features::arm(&[A::Sha3]);

/// The kernels, best first, each with what it needs; the first whose
/// needs are in force is the one a new function gets.
pub(crate) const KERNELS: &[(Kernel, Features)] = &[
    #[cfg(target_arch = "aarch64")]
    (Kernel::Armv8, ARMV8),
    #[cfg(target_arch = "x86_64")]
    (Kernel::Bmi, x86_64::BMI),
    #[cfg(target_arch = "riscv64")]
    (Kernel::Zbb, riscv64::ZBB),
    (Kernel::Portable, Features::new()),
];

/// What the list publishes: the needs, without the names.
const PROFILES: [Features; KERNELS.len()] = features::profiles_of(KERNELS);

/// Applies a method to whichever implementation is in use.
macro_rules! dispatch {
    ($value:expr, $inner:ident, $x:ident => $body:expr) => {
        match $value {
            #[cfg(target_arch = "aarch64")]
            $inner::Armv8($x) => $body,
            #[cfg(target_arch = "x86_64")]
            $inner::Bmi($x) => $body,
            #[cfg(target_arch = "riscv64")]
            $inner::Zbb($x) => $body,
            $inner::Portable($x) => $body,
        }
    };
}

/// A SHA-3 function using the best implementation the features in
/// force allow; see [`Sha3_256`] and [`Shake128`].
#[derive(Clone)]
pub(crate) struct Auto<V: engine::Variant>(Inner<V>);

#[derive(Clone)]
enum Inner<V: engine::Variant> {
    #[cfg(target_arch = "aarch64")]
    Armv8(Sponge<aarch64::Armv8, V>),
    #[cfg(target_arch = "x86_64")]
    Bmi(Sponge<x86_64::Bmi, V>),
    #[cfg(target_arch = "riscv64")]
    Zbb(Sponge<riscv64::Zbb, V>),
    Portable(Sponge<portable::Keccak, V>),
}

impl<V: engine::Variant> Auto<V> {
    /// Starts a function with the best implementation the features
    /// in force allow.
    pub fn new() -> Self {
        // The list chose the kernel, so its probe answers unless the
        // features changed between the two reads; portable is right
        // if they did.
        let inner = features::select(KERNELS)
            .and_then(Self::with)
            .unwrap_or(Inner::Portable(Sponge::with(portable::Keccak)));
        Auto(inner)
    }

    /// The sponge on `kernel`, or `None` where its probe says no.
    fn with(kernel: Kernel) -> Option<Inner<V>> {
        Some(match kernel {
            #[cfg(target_arch = "aarch64")]
            Kernel::Armv8 => {
                let p = <aarch64::Armv8 as engine::Permutation>::probe()?;
                Inner::Armv8(Sponge::with(p))
            }
            #[cfg(target_arch = "x86_64")]
            Kernel::Bmi => {
                let p = <x86_64::Bmi as engine::Permutation>::probe()?;
                Inner::Bmi(Sponge::with(p))
            }
            #[cfg(target_arch = "riscv64")]
            Kernel::Zbb => {
                let p = <riscv64::Zbb as engine::Permutation>::probe()?;
                Inner::Zbb(Sponge::with(p))
            }
            Kernel::Portable => Inner::Portable(Sponge::with(portable::Keccak)),
        })
    }

    /// Which kernel this function is running on.
    #[cfg(test)]
    pub(crate) fn kernel(&self) -> Kernel {
        match &self.0 {
            #[cfg(target_arch = "aarch64")]
            Inner::Armv8(_) => Kernel::Armv8,
            #[cfg(target_arch = "x86_64")]
            Inner::Bmi(_) => Kernel::Bmi,
            #[cfg(target_arch = "riscv64")]
            Inner::Zbb(_) => Kernel::Zbb,
            Inner::Portable(_) => Kernel::Portable,
        }
    }

    /// The kernels this family chooses among, with their needs.
    #[cfg(test)]
    pub(crate) fn kernels() -> &'static [(Kernel, Features)] {
        KERNELS
    }

    /// Starts a function on `kernel` alone, or `None` where the set
    /// in force does not allow it. The vector suites and the cross-checks
    /// reach each kernel this way, through the same type that
    /// dispatches to it.
    #[cfg(test)]
    pub(crate) fn with_kernel(kernel: Kernel) -> Option<Self> {
        if !features::available(KERNELS, kernel) {
            return None;
        }
        Self::with(kernel).map(Auto)
    }
}

impl<V: engine::Variant> Default for Auto<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: engine::Variant> fmt::Debug for Auto<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dispatch!(&self.0, Inner, s => s.fmt(f))
    }
}

impl<V: engine::Variant> BlockType for Auto<V> {
    type Block = V::Block;

    fn zero_block() -> Self::Block {
        V::zero_block()
    }
}

impl<V: DigestVariant> Hash for Auto<V> {
    type Output = V::Output;

    fn reset(&mut self) {
        dispatch!(&mut self.0, Inner, s => Hash::reset(s))
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        dispatch!(&mut self.0, Inner, s => Hash::update(s, data))
    }

    fn finalize(&mut self) -> Self::Output {
        dispatch!(&mut self.0, Inner, s => s.finalize())
    }
}

impl<V: DigestVariant> BitHash for Auto<V> {
    fn finalize_bits(
        &mut self,
        last: u8,
        bits: u32,
    ) -> Result<Self::Output, Error> {
        dispatch!(&mut self.0, Inner, s => s.finalize_bits(last, bits))
    }
}

/// The output of a SHAKE function from [`Auto`].
#[derive(Clone, Debug)]
pub(crate) struct AutoReader<V: XofVariant>(InnerReader<V>);

#[derive(Clone, Debug)]
enum InnerReader<V: XofVariant> {
    #[cfg(target_arch = "aarch64")]
    Armv8(Reader<aarch64::Armv8, V>),
    #[cfg(target_arch = "x86_64")]
    Bmi(Reader<x86_64::Bmi, V>),
    #[cfg(target_arch = "riscv64")]
    Zbb(Reader<riscv64::Zbb, V>),
    Portable(Reader<portable::Keccak, V>),
}

/// Ends the message of whichever sponge `$value` holds and wraps the
/// reader in the same arm.
macro_rules! finalize {
    ($value:expr, $s:ident => $body:expr) => {
        match $value {
            #[cfg(target_arch = "aarch64")]
            Inner::Armv8($s) => InnerReader::Armv8($body),
            #[cfg(target_arch = "x86_64")]
            Inner::Bmi($s) => InnerReader::Bmi($body),
            #[cfg(target_arch = "riscv64")]
            Inner::Zbb($s) => InnerReader::Zbb($body),
            Inner::Portable($s) => InnerReader::Portable($body),
        }
    };
}

impl<V: XofVariant> XofReader for AutoReader<V> {
    fn squeeze(&mut self, out: &mut [u8]) {
        dispatch!(&mut self.0, InnerReader, r => r.squeeze(out))
    }
}

impl<V: XofVariant> Xof for Auto<V> {
    type Reader = AutoReader<V>;

    fn reset(&mut self) {
        dispatch!(&mut self.0, Inner, s => Xof::reset(s))
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        dispatch!(&mut self.0, Inner, s => Xof::update(s, data))
    }

    fn finalize_xof(&mut self) -> Self::Reader {
        AutoReader(finalize!(&mut self.0, s => s.finalize_xof()))
    }
}

/// A sponge whose domain bits are chosen when it is finalized, which
/// is what cSHAKE and KMAC are built over. Implemented for the
/// dispatching type and for each implementation, so the vector suites
/// can drive every one.
pub(crate) trait SuffixXof: BitXof + BlockType + Clone {
    /// Ends the message with `suffix` and the padding.
    fn finalize_suffix_xof(&mut self, suffix: u8) -> Self::Reader;

    /// Ends the message with the first `bits` bits of `last`, one to
    /// seven, then `suffix` and the padding.
    fn finalize_bits_suffix_xof(
        &mut self,
        suffix: u8,
        last: u8,
        bits: u32,
    ) -> Result<Self::Reader, Error>;
}

impl<V: XofVariant> SuffixXof for Auto<V> {
    fn finalize_suffix_xof(&mut self, suffix: u8) -> Self::Reader {
        AutoReader(finalize!(&mut self.0, s => s.finalize_suffix_xof(suffix)))
    }

    fn finalize_bits_suffix_xof(
        &mut self,
        suffix: u8,
        last: u8,
        bits: u32,
    ) -> Result<Self::Reader, Error> {
        Ok(AutoReader(finalize!(&mut self.0, s => {
            s.finalize_bits_suffix_xof(suffix, last, bits)?
        })))
    }
}

impl<P: engine::Permutation, V: XofVariant> SuffixXof for Sponge<P, V> {
    fn finalize_suffix_xof(&mut self, suffix: u8) -> Self::Reader {
        Sponge::finalize_suffix_xof(self, suffix)
    }

    fn finalize_bits_suffix_xof(
        &mut self,
        suffix: u8,
        last: u8,
        bits: u32,
    ) -> Result<Self::Reader, Error> {
        Sponge::finalize_bits_suffix_xof(self, suffix, last, bits)
    }
}

impl<V: XofVariant> BitXof for Auto<V> {
    fn finalize_bits_xof(
        &mut self,
        last: u8,
        bits: u32,
    ) -> Result<Self::Reader, Error> {
        Ok(AutoReader(finalize!(&mut self.0, s => {
            s.finalize_bits_xof(last, bits)?
        })))
    }
}

pub use cshake::{CShake128, CShake128Reader, CShake256, CShake256Reader};
pub use tuple_hash::{
    TupleHash128, TupleHash128Reader, TupleHash256, TupleHash256Reader,
};

#[cfg(test)]
pub(crate) mod tests {

    use super::*;
    use zeroize::ZeroizeOnDrop;

    fn hex(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    /// The NIST example values for the empty message and "abc"; the
    /// SHAKE ones are the first 32 and 64 bytes.
    struct Example {
        message: &'static [u8],
        sha3_224: &'static str,
        sha3_256: &'static str,
        sha3_384: &'static str,
        sha3_512: &'static str,
        shake128: &'static str,
        shake256: &'static str,
    }

    const EXAMPLES: [Example; 2] = [
        Example {
            message: b"",
            sha3_224: "\
                6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
            sha3_256: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b\
                80f8434a",
            sha3_384: "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bb\
                ee983a2ac3713831264adb47fb6bd1e058d5f004",
            sha3_512: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1\
                475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e3\
                01758586281dcd26",
            shake128: "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eac\
                fa66ef26",
            shake256: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c2764\
                6ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab486\
                40292eacb3b7c4be",
        },
        Example {
            message: b"abc",
            sha3_224: "\
                e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
            sha3_256: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe245\
                11431532",
            sha3_384: "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0\
                e49be4b298d88cea927ac7f539f1edf228376d25",
            sha3_512: "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d02\
                40d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a5\
                6592f8274eec53f0",
            shake128: "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351\
                940f2cc8",
            shake256: "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37\
                e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4f\
                eb06bd8801e751e4",
        },
    ];

    fn squeeze<X: Xof>(
        message: &[u8],
        n: usize,
        start: impl Fn() -> X,
    ) -> [u8; 64] {
        let mut x = start();
        x.update(message);
        let mut out = [0u8; 64];
        x.finalize_xof().squeeze(&mut out[..n]);
        out
    }

    /// Checks the six functions of one implementation against the
    /// NIST examples.
    #[allow(clippy::type_complexity)]
    pub(crate) fn check_known_answers<A, B, C, D, E, F>(
        starts: (fn() -> A, fn() -> B, fn() -> C, fn() -> D),
        xofs: (fn() -> E, fn() -> F),
    ) where
        A: Hash<Output = [u8; 28]>,
        B: Hash<Output = [u8; 32]>,
        C: Hash<Output = [u8; 48]>,
        D: Hash<Output = [u8; 64]>,
        E: Xof,
        F: Xof,
    {
        for e in &EXAMPLES {
            let mut a = starts.0();
            a.update(e.message);
            assert_eq!(a.finalize(), hex(e.sha3_224)[..28]);
            let mut b = starts.1();
            b.update(e.message);
            assert_eq!(b.finalize(), hex(e.sha3_256)[..32]);
            let mut c = starts.2();
            c.update(e.message);
            assert_eq!(c.finalize(), hex(e.sha3_384)[..48]);
            let mut d = starts.3();
            d.update(e.message);
            assert_eq!(d.finalize(), hex(e.sha3_512)[..64]);
            assert_eq!(
                squeeze(e.message, 32, xofs.0)[..32],
                hex(e.shake128)[..32]
            );
            assert_eq!(squeeze(e.message, 64, xofs.1), hex(e.shake256));
        }
    }

    /// Checks one kernel against the portable one over every length
    /// up to a few blocks, fed in every way, digest and XOF.
    fn check_matches_portable<H, P, X, Y>(
        start: impl Fn() -> H,
        portable: impl Fn() -> P,
        xof: impl Fn() -> X,
        portable_xof: impl Fn() -> Y,
    ) where
        H: Hash,
        P: Hash<Output = H::Output>,
        H::Output: PartialEq + core::fmt::Debug,
        X: Xof,
        Y: Xof,
    {
        let data: [u8; 400] = core::array::from_fn(|i| (i * 7 + i / 3) as u8);
        for len in 0..data.len() {
            let message = &data[..len];
            let mut reference = portable();
            reference.update(message);
            let expected = reference.finalize();
            let mut once = start();
            once.update(message);
            assert_eq!(once.finalize(), expected, "len {len}");
            for split in (0..len).step_by(17) {
                let mut hash = start();
                hash.update(&message[..split]);
                hash.update(&message[split..]);
                assert_eq!(hash.finalize(), expected, "len {len} at {split}");
            }
            assert_eq!(
                squeeze(message, 64, &xof),
                squeeze(message, 64, &portable_xof),
                "xof len {len}"
            );
        }
    }

    #[test]
    fn known_answers() {
        check_known_answers(
            (Sha3_224::new, Sha3_256::new, Sha3_384::new, Sha3_512::new),
            (Shake128::new, Shake256::new),
        );
    }

    /// Every kernel this processor can build agrees with the portable
    /// code, for each digest and each XOF. The kernels this processor
    /// cannot build are reported rather than passed over in silence;
    /// the inventory audits those skips.
    #[test]
    fn every_kernel_agrees_with_the_portable_code() {
        fn check<H, X>(
            kernel: Kernel,
            digest: fn(Kernel) -> Option<H>,
            xof: fn(Kernel) -> Option<X>,
        ) where
            H: Hash,
            H::Output: PartialEq + core::fmt::Debug,
            X: Xof,
        {
            check_matches_portable(
                || digest(kernel).expect("available"),
                || digest(Kernel::Portable).expect("portable"),
                || xof(kernel).expect("available"),
                || xof(Kernel::Portable).expect("portable"),
            );
        }
        for &(kernel, _) in KERNELS {
            if Sha3_256::with_kernel(kernel).is_none() {
                std::eprintln!("{kernel:?} not available; skipping");
                continue;
            }
            check(kernel, Sha3_224::with_kernel, Shake128::with_kernel);
            check(kernel, Sha3_256::with_kernel, Shake256::with_kernel);
            check(kernel, Sha3_384::with_kernel, Shake128::with_kernel);
            check(kernel, Sha3_512::with_kernel, Shake256::with_kernel);
        }
    }

    /// Two bit-string cases from the NIST ACVP SHA3-256 vectors: 22
    /// bits (two bytes and six bits) and 13 bits (one byte and five).
    /// ACVP left-aligns the last bits in their byte; FIPS 202, and
    /// this API, number bits from the least significant end, so they
    /// are shifted down before being passed.
    #[test]
    fn bit_strings() {
        let mut hash = Sha3_256::new();
        hash.update(&[0xf1, 0x3d]);
        assert_eq!(
            hash.finalize_bits(0x64 >> 2, 6).unwrap(),
            hex(
                "f561e056b721fcd859ba37efc08431ccf70fde1cf9f13dc95385daa6a082\
                 55f6"
            )[..32]
        );
        let mut hash = Sha3_256::new();
        hash.update(&[0x26]);
        assert_eq!(
            hash.finalize_bits(0x58 >> 3, 5).unwrap(),
            hex(
                "e2976b7527ff3d52a3c3fb6a6df4e56d1876427f6304a0a7a194582920481\
                 de0"
            )[..32]
        );
        // Bits beyond the count are ignored.
        let a = Sha3_256::new().finalize_bits(0x1f, 5).unwrap();
        let b = Sha3_256::new().finalize_bits(0xff, 5).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn bit_count_is_checked() {
        for bits in [0, 8, 9] {
            assert_eq!(
                Sha3_256::new().finalize_bits(0, bits),
                Err(Error::InvalidBitCount(bits))
            );
            assert!(Shake128::new().finalize_bits_xof(0, bits).is_err());
        }
    }

    #[test]
    fn squeezing_in_pieces_is_the_same_stream() {
        let whole = squeeze(b"abc", 64, Shake128::new);
        let mut x = Shake128::new();
        x.update(b"abc");
        let mut reader = x.finalize_xof();
        let mut out = [0u8; 64];
        reader.squeeze(&mut out[..1]);
        reader.squeeze(&mut out[1..3]);
        reader.squeeze(&mut out[3..40]);
        reader.squeeze(&mut out[40..]);
        assert_eq!(out, whole);
        // Well past one rate of output, against a fresh reader.
        let mut long = [0u8; 500];
        let mut again = [0u8; 500];
        let mut x = Shake128::new();
        x.update(b"abc");
        x.finalize_xof().squeeze(&mut long);
        let mut x = Shake128::new();
        x.update(b"abc");
        let mut reader = x.finalize_xof();
        reader.squeeze(&mut again[..167]);
        reader.squeeze(&mut again[167..169]);
        reader.squeeze(&mut again[169..]);
        assert_eq!(long[..], again[..]);
    }

    #[test]
    fn splitting_does_not_matter() {
        let data: [u8; 617] = core::array::from_fn(|i| (i * 31) as u8);
        let expected = Sha3_512::digest(&data);
        for chunk in [1, 3, 7, 71, 72, 73, 144, 200] {
            let mut hash = Sha3_512::new();
            for piece in data.chunks(chunk) {
                hash.update(piece);
            }
            assert_eq!(hash.finalize(), expected, "chunk {chunk}");
        }
    }

    #[test]
    fn reset_and_clone() {
        let mut hash = Sha3_224::new();
        hash.update(b"not this");
        hash.reset();
        hash.update(b"ab");
        let mut fork = hash.clone();
        hash.update(b"c");
        assert_eq!(hash.finalize(), Sha3_224::digest(b"abc"));
        assert_eq!(fork.finalize(), Sha3_224::digest(b"ab"));
    }

    #[test]
    fn every_implementation_zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<portable::Sha3_256>();
        wipes::<portable::Shake128>();
        wipes::<<portable::Shake128 as Xof>::Reader>();
        #[cfg(target_arch = "aarch64")]
        {
            wipes::<aarch64::Sha3_256>();
            wipes::<aarch64::Shake128>();
        }
    }

    #[test]
    fn picks_the_first_kernel_whose_needs_are_met() {
        let hash = Auto::<variant::Sha3_256>::new();
        features::dispatches(KERNELS, Sha3_256::profiles(), hash.kernel());
        let xof = Auto::<variant::Shake128>::new();
        features::dispatches(KERNELS, Shake128::profiles(), xof.kernel());
    }

    #[test]
    fn debug_omits_the_message() {
        struct Buffer([u8; 128], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let mut hash = Sha3_256::new();
        hash.update(b"secret");
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{hash:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("secret"));
        assert!(text.contains("used: 6"));
    }
}

/// Defines one of the four public digests over the sponge.
macro_rules! digest {
    ($(#[$doc:meta])* $name:ident, $variant:ident, $rate:literal,
     $out:literal) => {
        $(#[$doc])*
        #[derive(Clone, Default)]
        pub struct $name(Auto<variant::$variant>);

        impl $name {
            /// Starts a hash with the best implementation the
            /// features in force allow; see [`crate::features`].
            pub fn new() -> Self {
                $name(Auto::new())
            }

            /// The feature profiles this hash tells apart, best
            /// first; see [`Dispatcher`].
            pub fn profiles() -> &'static [Features] {
                &PROFILES
            }

            /// The kernels this hash chooses among, with their needs.
            #[cfg(test)]
            pub(crate) fn kernels() -> &'static [(Kernel, Features)] {
                KERNELS
            }

            /// Starts a hash on `kernel` alone, or `None` where the
            /// set in force does not allow it.
            #[cfg(test)]
            pub(crate) fn with_kernel(kernel: Kernel) -> Option<Self> {
                Auto::with_kernel(kernel).map($name)
            }
        }

        impl features::sealed::Sealed for $name {}

        impl Dispatcher for $name {
            fn profiles() -> &'static [Features] {
                $name::profiles()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl BlockType for $name {
            type Block = [u8; $rate];

            fn zero_block() -> Self::Block {
                [0; $rate]
            }
        }

        impl Hash for $name {
            type Output = [u8; $out];

            fn reset(&mut self) {
                Hash::reset(&mut self.0)
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                Hash::update(&mut self.0, data)
            }

            fn finalize(&mut self) -> Self::Output {
                self.0.finalize()
            }
        }

        impl BitHash for $name {
            fn finalize_bits(
                &mut self,
                last: u8,
                bits: u32,
            ) -> Result<Self::Output, Error> {
                self.0.finalize_bits(last, bits)
            }
        }
    };
}

/// Defines one of the two public SHAKE functions and its reader.
macro_rules! shake {
    ($(#[$doc:meta])* $name:ident, $reader:ident, $variant:ident,
     $rate:literal) => {
        $(#[$doc])*
        #[derive(Clone, Default)]
        pub struct $name(Auto<variant::$variant>);

        #[doc = concat!("The output stream of [`", stringify!($name), "`].")]
        #[derive(Clone, Debug)]
        pub struct $reader(AutoReader<variant::$variant>);

        impl $name {
            /// Starts a function with the best implementation the
            /// features in force allow; see [`crate::features`].
            pub fn new() -> Self {
                $name(Auto::new())
            }

            /// The feature profiles this function tells apart, best
            /// first; see [`Dispatcher`].
            pub fn profiles() -> &'static [Features] {
                &PROFILES
            }

            /// The kernels this function chooses among, with their
            /// needs.
            #[cfg(test)]
            pub(crate) fn kernels() -> &'static [(Kernel, Features)] {
                KERNELS
            }

            /// Starts a function on `kernel` alone, or `None` where
            /// the set in force does not allow it.
            #[cfg(test)]
            pub(crate) fn with_kernel(kernel: Kernel) -> Option<Self> {
                Auto::with_kernel(kernel).map($name)
            }
        }

        impl features::sealed::Sealed for $name {}

        impl Dispatcher for $name {
            fn profiles() -> &'static [Features] {
                $name::profiles()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl BlockType for $name {
            type Block = [u8; $rate];

            fn zero_block() -> Self::Block {
                [0; $rate]
            }
        }

        impl XofReader for $reader {
            fn squeeze(&mut self, out: &mut [u8]) {
                self.0.squeeze(out)
            }
        }

        impl Xof for $name {
            type Reader = $reader;

            fn reset(&mut self) {
                Xof::reset(&mut self.0)
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                Xof::update(&mut self.0, data)
            }

            fn finalize_xof(&mut self) -> Self::Reader {
                $reader(self.0.finalize_xof())
            }
        }

        impl BitXof for $name {
            fn finalize_bits_xof(
                &mut self,
                last: u8,
                bits: u32,
            ) -> Result<Self::Reader, Error> {
                Ok($reader(self.0.finalize_bits_xof(last, bits)?))
            }
        }
    };
}

digest!(
    /// SHA3-224.
    Sha3_224,
    Sha3_224,
    144,
    28
);
digest!(
    /// SHA3-256.
    Sha3_256,
    Sha3_256,
    136,
    32
);
digest!(
    /// SHA3-384.
    Sha3_384,
    Sha3_384,
    104,
    48
);
digest!(
    /// SHA3-512.
    Sha3_512,
    Sha3_512,
    72,
    64
);
shake!(
    /// SHAKE128, output of any length at the 128-bit security level.
    Shake128,
    Shake128Reader,
    Shake128,
    168
);
shake!(
    /// SHAKE256, output of any length at the 256-bit security level.
    Shake256,
    Shake256Reader,
    Shake256,
    136
);
