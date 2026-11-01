//! What the processor has, and what the program lets the library use.
//!
//! Every primitive with more than one implementation chooses between
//! them at construction, from a fixed ranking: the first engine whose
//! requirements are met wins. What meets them is a set of
//! [`Features`], and this module owns that set.
//!
//! [`detected`] is what the processor reports, asked once. It is the
//! default, and the reference set: the set in force, [`get`], may
//! hold any of its members and nothing else from this architecture,
//! so no edit can select an engine the processor cannot run. [`set`]
//! replaces the set in force; [`reset`] goes back to the hardware.
//!
//! Removing a feature selects the engine below the one it unlocked,
//! which is how a program chooses an implementation: not by naming
//! one, but by saying what it may not use. A *virtual feature* is one
//! no processor reports and only the program grants.
//! [`Feature::Isolated`] is the first: no adversary shares this
//! processor's caches, so the table-driven AES, which leaks through
//! them, may be chosen above the bitsliced one. Two engines with the
//! same hardware requirements are told apart by a virtual feature,
//! never by position alone.
//!
//! The per-architecture enums exist on every target, so a program
//! for three architectures names all of their features in one place
//! without a `cfg`, and the documentation shows every name whatever
//! machine rendered it. [`set`] is strict about this architecture and
//! inert about the others: a feature of this one that the processor
//! lacks is an error, a feature of another is never required by
//! anything here and is kept without effect.
//!
//! ```
//! use scytale::features::{self, Feature, Features, aarch64, x86_64};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut f = features::get();
//! // AES-NI rather than VAES; a no-op on any other architecture.
//! f.remove(x86_64::Feature::Vaes.into());
//! // A board with no AES instructions and nothing untrusted on it.
//! if !f.contains(aarch64::Feature::Aes.into()) {
//!     f.insert(Feature::Isolated);
//! }
//! features::set(f)?;
//! # features::reset();
//! # Ok(())
//! # }
//! ```
//!
//! The set in force is global to the process and may be changed at
//! any time; the latest `set` wins. A value constructed earlier keeps
//! the engine it was built with, and says which through its
//! `engine()` method. Code sharing the address space is trusted, so
//! there is no fuse.
//!
//! # Asking once
//!
//! Asking the processor is not cheap: `cpuid` serialises the
//! pipeline, and the RISC-V answer is a system call. Neither can
//! change while the program runs, so [`detected`] asks once and keeps
//! the answer in an atomic. Nothing locks: two threads arriving
//! together both ask and both store the same word, which is worth
//! more than a lock, since it means the question can be put from code
//! with no allocator and no threads at all. Reading the set in force
//! is then one relaxed load, cheap enough for a mode that expands a
//! key for every message.

use core::fmt;
use core::str::FromStr;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::Error;

/// A processor feature of some architecture, or a virtual one.
///
/// Each architecture's features are in its own module, so that the
/// same name on two architectures (`aes` on x86-64 and on AArch64)
/// is two values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Feature {
    /// An x86-64 feature.
    X86_64(x86_64::Feature),
    /// An AArch64 feature.
    Aarch64(aarch64::Feature),
    /// A RISC-V feature.
    Riscv64(riscv64::Feature),
    /// Virtual: no adversary shares this processor's caches, so an
    /// implementation that leaks through cache timing may be chosen.
    /// No processor reports it; only the program grants it.
    Isolated,
}

/// Where in a [`Features`] word each architecture's bits start, and
/// where the virtual ones do. Bit 63 is kept out of every range: the
/// atomics below use it to mean "has been written".
const X86_64_BITS: u8 = 0;
const AARCH64_BITS: u8 = 16;
const RISCV64_BITS: u8 = 24;
const VIRTUAL_BITS: u8 = 56;
const WRITTEN: u64 = 1 << 63;

impl Feature {
    /// The bit this feature occupies in a [`Features`] word.
    const fn bit(self) -> u8 {
        match self {
            Feature::X86_64(f) => X86_64_BITS + f as u8,
            Feature::Aarch64(f) => AARCH64_BITS + f as u8,
            Feature::Riscv64(f) => RISCV64_BITS + f as u8,
            Feature::Isolated => VIRTUAL_BITS,
        }
    }

    /// The feature at `bit`, if one is.
    fn from_bit(bit: u8) -> Option<Feature> {
        if bit == VIRTUAL_BITS {
            return Some(Feature::Isolated);
        }
        let in_range = |start: u8, all: &[Feature]| {
            let i = usize::from(bit.checked_sub(start)?);
            all.get(i).copied()
        };
        if bit >= RISCV64_BITS {
            in_range(RISCV64_BITS, &riscv64::Feature::ALL_WRAPPED)
        } else if bit >= AARCH64_BITS {
            in_range(AARCH64_BITS, &aarch64::Feature::ALL_WRAPPED)
        } else {
            in_range(X86_64_BITS, &x86_64::Feature::ALL_WRAPPED)
        }
    }

    /// The name, as [`Display`](fmt::Display) prints it and
    /// [`FromStr`] reads it: the architecture's own spelling in lower
    /// case, `sse4.1` and `zvknha` included.
    pub fn name(self) -> &'static str {
        match self {
            Feature::X86_64(f) => f.name(),
            Feature::Aarch64(f) => f.name(),
            Feature::Riscv64(f) => f.name(),
            Feature::Isolated => "isolated",
        }
    }

    /// Whether this is a feature of the architecture the program is
    /// running on, which is the only kind [`set`] checks against the
    /// hardware.
    fn is_native(self) -> bool {
        match self {
            Feature::X86_64(_) => cfg!(target_arch = "x86_64"),
            Feature::Aarch64(_) => cfg!(target_arch = "aarch64"),
            Feature::Riscv64(_) => cfg!(target_arch = "riscv64"),
            Feature::Isolated => false,
        }
    }
}

impl From<x86_64::Feature> for Feature {
    fn from(f: x86_64::Feature) -> Self {
        Feature::X86_64(f)
    }
}

impl From<aarch64::Feature> for Feature {
    fn from(f: aarch64::Feature) -> Self {
        Feature::Aarch64(f)
    }
}

impl From<riscv64::Feature> for Feature {
    fn from(f: riscv64::Feature) -> Self {
        Feature::Riscv64(f)
    }
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A bare name is this architecture's feature of that name, or a
/// virtual one. Another architecture's features are named with their
/// prefix, through [`Features`]'s parser.
impl FromStr for Feature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if s == "isolated" {
            return Ok(Feature::Isolated);
        }
        #[cfg(target_arch = "x86_64")]
        let native = x86_64::Feature::by_name(s).map(Feature::X86_64);
        #[cfg(target_arch = "aarch64")]
        let native = aarch64::Feature::by_name(s).map(Feature::Aarch64);
        #[cfg(target_arch = "riscv64")]
        let native = riscv64::Feature::by_name(s).map(Feature::Riscv64);
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )))]
        let native: Option<Feature> = None;
        native.ok_or(Error::InvalidEncoding)
    }
}

/// Defines one architecture's features: the enum, its names, and
/// the list of all of them in bit order.
macro_rules! architecture {
    ($(#[$doc:meta])* $module:ident, $prefix:literal,
     [$( $(#[$vdoc:meta])* $variant:ident = $name:literal ),* $(,)?]) => {
        $(#[$doc])*
        pub mod $module {
            /// A feature of this architecture. The discriminant is
            /// its bit within the architecture's range.
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
            #[non_exhaustive]
            #[repr(u8)]
            pub enum Feature {
                $( $(#[$vdoc])* $variant, )*
            }

            impl Feature {
                /// Every feature, in bit order.
                pub const ALL: &'static [Feature] = &[
                    $( Feature::$variant, )*
                ];

                /// The architecture's name, as it prefixes a group
                /// in a [`Features`](super::Features) string.
                pub const ARCHITECTURE: &'static str = $prefix;

                /// The name, in the architecture's own spelling.
                pub const fn name(self) -> &'static str {
                    match self {
                        $( Feature::$variant => $name, )*
                    }
                }

                /// The feature called `name`, if there is one.
                pub fn by_name(name: &str) -> Option<Feature> {
                    Self::ALL.iter().copied().find(|f| f.name() == name)
                }
            }

            impl core::fmt::Display for Feature {
                fn fmt(
                    &self,
                    f: &mut core::fmt::Formatter<'_>,
                ) -> core::fmt::Result {
                    f.write_str(self.name())
                }
            }
        }
    };
}

architecture!(
    /// The x86-64 features the library's implementations need.
    ///
    /// `avx`, and everything that is encoded with it, is detected
    /// only where the operating system has enabled the wider register
    /// state (XCR0 bits 1 and 2), since the instructions fault
    /// otherwise.
    x86_64, "x86_64",
    [
        /// AES-NI (CPUID leaf 1, ECX bit 25).
        Aes = "aes",
        /// SSSE3, for `pshufb` (leaf 1, ECX bit 9).
        Ssse3 = "ssse3",
        /// SSE4.1, for inserting and blending words (leaf 1, ECX
        /// bit 19).
        Sse41 = "sse4.1",
        /// AVX with the operating system saving its state (leaf 1,
        /// ECX bits 27 and 28, then XCR0 bits 1 and 2).
        Avx = "avx",
        /// AVX2 (leaf 7, EBX bit 5), with AVX usable.
        Avx2 = "avx2",
        /// VAES (leaf 7, ECX bit 9), with AVX usable.
        Vaes = "vaes",
        /// PCLMULQDQ (leaf 1, ECX bit 1).
        Pclmulqdq = "pclmulqdq",
        /// VPCLMULQDQ (leaf 7, ECX bit 10), with AVX usable.
        Vpclmulqdq = "vpclmulqdq",
        /// The SHA extensions (leaf 7, EBX bit 29).
        Sha = "sha",
        /// ADX, the two-carry-chain adds (leaf 7, EBX bit 19).
        Adx = "adx",
        /// BMI1 (leaf 7, EBX bit 3).
        Bmi1 = "bmi1",
        /// BMI2, for `mulx` and the shifts (leaf 7, EBX bit 8).
        Bmi2 = "bmi2",
    ]
);

architecture!(
    /// The AArch64 features the library's implementations need, each
    /// a field of `ID_AA64ISAR0_EL1`. A feature named at build time
    /// with `-C target-feature` counts as present.
    aarch64, "aarch64",
    [
        /// The AES instructions (AES field, 1 or more).
        Aes = "aes",
        /// The 64-bit polynomial multiply (AES field, 2 or more).
        Pmull = "pmull",
        /// The SHA-1 instructions (SHA1 field).
        Sha1 = "sha1",
        /// The SHA-256 instructions (SHA2 field, 1 or more).
        Sha2 = "sha2",
        /// The SHA-512 instructions (SHA2 field, 2 or more).
        Sha512 = "sha512",
        /// The SHA-3 instructions (SHA3 field).
        Sha3 = "sha3",
    ]
);

architecture!(
    /// The RISC-V extensions the library's implementations need, as
    /// Linux `hwprobe` reports them. An extension named at build time
    /// with `-C target-feature` counts as present. `v` is detected
    /// only where the vector registers are at least 128 bits wide,
    /// which every vector loop here needs.
    riscv64, "riscv64",
    [
        /// The vector extension, with registers of 128 bits or more.
        V = "v",
        /// Zbb, basic bit manipulation: the rotates among them.
        Zbb = "zbb",
        /// Zbc, the scalar carry-less multiply.
        Zbc = "zbc",
        /// Zbkb, bit manipulation for cryptography: the same rotates
        /// as Zbb, with the byte reverse and packs.
        Zbkb = "zbkb",
        /// Zbkc, the carry-less multiply for cryptography.
        Zbkc = "zbkc",
        /// Zkne, scalar AES encryption.
        Zkne = "zkne",
        /// Zknd, scalar AES decryption.
        Zknd = "zknd",
        /// Zknh, the scalar SHA-2 sigma functions.
        Zknh = "zknh",
        /// Zvbb, vector basic bit manipulation.
        Zvbb = "zvbb",
        /// Zvbc, the vector carry-less multiply.
        Zvbc = "zvbc",
        /// Zvkb, the subset of Zvbb the vector cryptography pulls in;
        /// detected where either is reported, since Zvbb has every
        /// instruction of it.
        Zvkb = "zvkb",
        /// Zvkg, the vector GHASH multiply.
        Zvkg = "zvkg",
        /// Zvkned, vector AES.
        Zvkned = "zvkned",
        /// Zvknha, vector SHA-256; detected where either it or Zvknhb
        /// is reported, since Zvknhb has every instruction of it.
        Zvknha = "zvknha",
        /// Zvknhb, vector SHA-256 and SHA-512.
        Zvknhb = "zvknhb",
    ]
);

/// A set of [`Feature`]s.
///
/// A plain value: `Copy`, with the set operations, and a string form
/// that names each architecture's group with its prefix, the virtual
/// features bare, and the empty set `portable`:
///
/// ```
/// use scytale::features::{Feature, Features, x86_64::Feature as X};
///
/// let f: Features = [X::Aes.into(), X::Sha.into(), Feature::Isolated]
///     .into_iter()
///     .collect();
/// assert_eq!(f.to_string(), "x86_64/aes+sha isolated");
/// assert_eq!(f.to_string().parse::<Features>(), Ok(f));
/// assert_eq!(Features::new().to_string(), "portable");
/// ```
///
/// Reading one back accepts that form, and also bare names, which
/// are this architecture's features: `aes sha` on x86-64 is the
/// first two above.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Features(u64);

impl Features {
    /// The empty set.
    pub const fn new() -> Self {
        Features(0)
    }

    /// The set of exactly these features.
    pub const fn of(features: &[Feature]) -> Self {
        let mut set = Features(0);
        let mut i = 0;
        while i < features.len() {
            set = set.with(features[i]);
            i += 1;
        }
        set
    }

    /// This set with `feature` added.
    pub const fn with(self, feature: Feature) -> Self {
        Features(self.0 | 1 << feature.bit())
    }

    /// This set and `other` together.
    pub const fn union(self, other: Features) -> Self {
        Features(self.0 | other.0)
    }

    /// This set with `feature` removed.
    pub const fn without(self, feature: Feature) -> Self {
        Features(self.0 & !(1 << feature.bit()))
    }

    /// Adds `feature`.
    pub fn insert(&mut self, feature: Feature) {
        *self = self.with(feature);
    }

    /// Removes `feature`.
    pub fn remove(&mut self, feature: Feature) {
        *self = self.without(feature);
    }

    /// Whether `feature` is in the set.
    pub const fn contains(self, feature: Feature) -> bool {
        self.0 & 1 << feature.bit() != 0
    }

    /// Whether every member of this set is in `of`.
    pub const fn is_subset(self, of: Features) -> bool {
        self.0 & !of.0 == 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The members, in bit order: each architecture's features in
    /// its own order, then the virtual ones.
    pub fn iter(self) -> impl Iterator<Item = Feature> {
        (0..64u8)
            .filter(move |&bit| self.0 & 1 << bit != 0)
            .filter_map(Feature::from_bit)
    }

    /// The members of this architecture, which are what the
    /// processor can be asked about.
    fn native(self) -> Features {
        self.iter().filter(|f| f.is_native()).collect()
    }
}

impl fmt::Debug for Features {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Features({self})")
    }
}

impl core::ops::BitOr for Features {
    type Output = Features;

    fn bitor(self, rhs: Features) -> Features {
        Features(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Features {
    type Output = Features;

    fn bitand(self, rhs: Features) -> Features {
        Features(self.0 & rhs.0)
    }
}

impl core::ops::Sub for Features {
    type Output = Features;

    fn sub(self, rhs: Features) -> Features {
        Features(self.0 & !rhs.0)
    }
}

impl FromIterator<Feature> for Features {
    fn from_iter<I: IntoIterator<Item = Feature>>(iter: I) -> Self {
        iter.into_iter().fold(Features::new(), Features::with)
    }
}

impl Extend<Feature> for Features {
    fn extend<I: IntoIterator<Item = Feature>>(&mut self, iter: I) {
        for f in iter {
            self.insert(f);
        }
    }
}

impl fmt::Display for Features {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("portable");
        }
        let mut first = true;
        let mut space = |f: &mut fmt::Formatter<'_>| {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            Ok(())
        };
        let groups: [(&str, &[Feature]); 3] = [
            (x86_64::Feature::ARCHITECTURE, &x86_64::Feature::ALL_WRAPPED),
            (
                aarch64::Feature::ARCHITECTURE,
                &aarch64::Feature::ALL_WRAPPED,
            ),
            (
                riscv64::Feature::ARCHITECTURE,
                &riscv64::Feature::ALL_WRAPPED,
            ),
        ];
        for (prefix, all) in groups {
            let mut members = all.iter().filter(|&&m| self.contains(m));
            if let Some(m) = members.next() {
                space(f)?;
                write!(f, "{prefix}/{m}")?;
                for m in members {
                    write!(f, "+{m}")?;
                }
            }
        }
        if self.contains(Feature::Isolated) {
            space(f)?;
            f.write_str("isolated")?;
        }
        Ok(())
    }
}

/// Reads the [`Display`](fmt::Display) form back, and bare names as
/// [`Feature`] reads them. Tokens are separated by whitespace;
/// `portable` names no feature.
impl FromStr for Features {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let mut set = Features::new();
        for token in s.split_whitespace() {
            if token == "portable" {
                continue;
            }
            match token.split_once('/') {
                Some((prefix, names)) => {
                    for name in names.split('+') {
                        set.insert(prefixed(prefix, name)?);
                    }
                }
                None => set.insert(token.parse()?),
            }
        }
        Ok(set)
    }
}

/// The feature `name` of the architecture `prefix` names.
fn prefixed(prefix: &str, name: &str) -> Result<Feature, Error> {
    let found = match prefix {
        "x86_64" => x86_64::Feature::by_name(name).map(Feature::X86_64),
        "aarch64" => aarch64::Feature::by_name(name).map(Feature::Aarch64),
        "riscv64" => riscv64::Feature::by_name(name).map(Feature::Riscv64),
        _ => None,
    };
    found.ok_or(Error::InvalidEncoding)
}

/// Each architecture's features wrapped as [`Feature`], for the
/// printer to walk in order.
macro_rules! wrapped {
    ($module:ident, $wrap:ident) => {
        impl $module::Feature {
            /// The variant of [`Feature`] that holds this.
            const fn wrap(self) -> Feature {
                Feature::$wrap(self)
            }

            /// [`ALL`](Self::ALL), each wrapped as a [`Feature`].
            const ALL_WRAPPED: [Feature; $module::Feature::ALL.len()] = {
                let mut out = [Feature::Isolated; $module::Feature::ALL.len()];
                let mut i = 0;
                while i < out.len() {
                    out[i] = $module::Feature::ALL[i].wrap();
                    i += 1;
                }
                out
            };
        }
    };
}

wrapped!(x86_64, X86_64);
wrapped!(aarch64, Aarch64);
wrapped!(riscv64, Riscv64);

/// Every feature of this architecture: the ones the processor can be
/// asked about.
#[cfg(test)]
pub(crate) fn native_all() -> Features {
    #[cfg(target_arch = "x86_64")]
    return Features::of(&x86_64::Feature::ALL_WRAPPED);
    #[cfg(target_arch = "aarch64")]
    return Features::of(&aarch64::Feature::ALL_WRAPPED);
    #[cfg(target_arch = "riscv64")]
    return Features::of(&riscv64::Feature::ALL_WRAPPED);
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    Features::new()
}

/// What the processor reported, with [`WRITTEN`] once it has been
/// asked; see the module documentation for why the race is harmless.
static DETECTED: AtomicU64 = AtomicU64::new(0);

/// The set in force, with [`WRITTEN`] once [`set`] has been called.
/// Zero means [`detected`] is in force, so a program that never calls
/// `set` pays one load and a branch.
static IN_FORCE: AtomicU64 = AtomicU64::new(0);

/// What the processor reports, asked once.
///
/// This is the default set in force and the reference every call to
/// [`set`] is checked against. On an architecture with no
/// implementations written for it, the empty set.
pub fn detected() -> Features {
    let kept = DETECTED.load(Ordering::Relaxed);
    if kept & WRITTEN != 0 {
        return Features(kept & !WRITTEN);
    }
    let found = crate::arch::detected();
    DETECTED.store(found.0 | WRITTEN, Ordering::Relaxed);
    found
}

/// The set in force: what [`set`] last stored, or [`detected`] if
/// nothing has been stored.
pub fn get() -> Features {
    let kept = IN_FORCE.load(Ordering::Relaxed);
    if kept & WRITTEN != 0 {
        Features(kept & !WRITTEN)
    } else {
        detected()
    }
}

/// Makes `features` the set in force.
///
/// The set may hold any member of [`detected`] and any virtual
/// feature; a feature of this architecture that the processor lacks
/// is refused with [`Error::UnsupportedFeature`] naming it, and the
/// set in force is unchanged. Features of other architectures are
/// kept and have no effect, so a program for several architectures
/// can build one set for all of them.
///
/// Takes effect for every value constructed afterwards; values built
/// earlier keep their engines.
pub fn set(features: Features) -> Result<(), Error> {
    let hardware = detected();
    if let Some(missing) =
        features.native().iter().find(|&f| !hardware.contains(f))
    {
        return Err(Error::UnsupportedFeature(missing));
    }
    IN_FORCE.store(features.0 | WRITTEN, Ordering::Relaxed);
    Ok(())
}

/// Puts [`detected`] back in force.
pub fn reset() {
    IN_FORCE.store(0, Ordering::Relaxed);
}

/// Whether everything in `required` is in force. What every
/// implementation asks before it is chosen.
pub(crate) fn has(required: Features) -> bool {
    required.is_subset(get())
}

/// The set of these x86-64 features, for writing a requirement down.
#[cfg(target_arch = "x86_64")]
pub(crate) const fn x86(features: &[x86_64::Feature]) -> Features {
    let mut set = Features::new();
    let mut i = 0;
    while i < features.len() {
        set = set.with(Feature::X86_64(features[i]));
        i += 1;
    }
    set
}

/// The set of these AArch64 features, for writing a requirement
/// down.
#[cfg(target_arch = "aarch64")]
pub(crate) const fn arm(features: &[aarch64::Feature]) -> Features {
    let mut set = Features::new();
    let mut i = 0;
    while i < features.len() {
        set = set.with(Feature::Aarch64(features[i]));
        i += 1;
    }
    set
}

/// The set of these RISC-V features, for writing a requirement down.
#[cfg(target_arch = "riscv64")]
pub(crate) const fn riscv(features: &[riscv64::Feature]) -> Features {
    let mut set = Features::new();
    let mut i = 0;
    while i < features.len() {
        set = set.with(Feature::Riscv64(features[i]));
        i += 1;
    }
    set
}

/// The first engine in `ranking` whose requirements are in force.
/// Every ranking ends with an engine that requires nothing, so there
/// is always one; `None` only for an empty list.
pub(crate) fn select<E: Copy>(ranking: &[(E, Features)]) -> Option<E> {
    ranking
        .iter()
        .find(|(_, required)| has(*required))
        .map(|(engine, _)| *engine)
}

/// Whether `ranking` tells its rows apart: no two require the same
/// set, so that each is reachable by editing the set in force. Every
/// family's test asks this of its own ranking.
#[cfg(test)]
pub(crate) fn rows_are_distinct<E>(ranking: &[(E, Features)]) -> bool {
    ranking.iter().enumerate().all(|(i, (_, required))| {
        ranking[i + 1..].iter().all(|(_, other)| other != required)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;
    use std::vec::Vec;

    #[test]
    fn set_algebra() {
        let a = Feature::X86_64(x86_64::Feature::Aes);
        let s = Feature::Aarch64(aarch64::Feature::Sha2);
        let mut f = Features::new();
        assert!(f.is_empty());
        f.insert(a);
        f.insert(s);
        assert!(f.contains(a) && f.contains(s));
        assert!(!f.contains(Feature::Isolated));
        assert!(Features::of(&[a]).is_subset(f));
        assert!(!f.is_subset(Features::of(&[a])));
        assert_eq!(f - Features::of(&[a]), Features::of(&[s]));
        assert_eq!(f & Features::of(&[a]), Features::of(&[a]));
        assert_eq!(Features::of(&[a]) | Features::of(&[s]), f);
        f.remove(a);
        assert_eq!(f, Features::of(&[s]));
        assert_eq!(f.iter().collect::<Vec<_>>(), [s]);
    }

    #[test]
    fn every_feature_has_its_own_bit() {
        let all = x86_64::Feature::ALL_WRAPPED
            .iter()
            .chain(&aarch64::Feature::ALL_WRAPPED)
            .chain(&riscv64::Feature::ALL_WRAPPED)
            .chain(&[Feature::Isolated])
            .copied()
            .collect::<Vec<_>>();
        for (i, &a) in all.iter().enumerate() {
            assert!(a.bit() < 63, "{a:?} collides with the marker");
            assert_eq!(Feature::from_bit(a.bit()), Some(a));
            for &b in &all[i + 1..] {
                assert_ne!(a.bit(), b.bit(), "{a:?} and {b:?}");
            }
        }
        assert_eq!(Features::of(&all).iter().collect::<Vec<_>>(), all);
    }

    #[test]
    fn names_round_trip() {
        let all = x86_64::Feature::ALL_WRAPPED
            .iter()
            .chain(&aarch64::Feature::ALL_WRAPPED)
            .chain(&riscv64::Feature::ALL_WRAPPED)
            .chain(&[Feature::Isolated]);
        for &f in all {
            let one = Features::of(&[f]);
            assert_eq!(one.to_string().parse::<Features>(), Ok(one), "{f}");
        }
        let everything = Features::of(&x86_64::Feature::ALL_WRAPPED)
            | Features::of(&aarch64::Feature::ALL_WRAPPED)
            | Features::of(&riscv64::Feature::ALL_WRAPPED)
            | Features::of(&[Feature::Isolated]);
        let text = everything.to_string();
        assert_eq!(text.parse::<Features>(), Ok(everything));
        assert!(text.starts_with("x86_64/aes+ssse3+sse4.1"));
        assert!(text.ends_with(" isolated"));
    }

    #[test]
    fn the_empty_set_is_portable() {
        assert_eq!(Features::new().to_string(), "portable");
        assert_eq!("portable".parse::<Features>(), Ok(Features::new()));
        assert_eq!("".parse::<Features>(), Ok(Features::new()));
    }

    #[test]
    fn bare_names_are_this_architecture() {
        let native = native_all();
        for f in native.iter() {
            assert_eq!(f.name().parse::<Feature>(), Ok(f));
            assert_eq!(f.name().parse::<Features>(), Ok(Features::of(&[f])));
        }
        assert_eq!("isolated".parse::<Feature>(), Ok(Feature::Isolated));
        let x86 = cfg!(target_arch = "x86_64");
        assert_eq!("sse4.1".parse::<Feature>().is_ok(), x86);
        assert!("nonsense".parse::<Feature>().is_err());
        assert!("mips/aes".parse::<Features>().is_err());
        assert!("x86_64/nonsense".parse::<Features>().is_err());
    }

    #[test]
    fn detected_is_asked_once_and_native() {
        let first = detected();
        assert_eq!(detected(), first);
        assert_ne!(DETECTED.load(Ordering::Relaxed) & WRITTEN, 0);
        assert!(first.is_subset(native_all()));
        assert!(!first.contains(Feature::Isolated));
    }

    #[test]
    fn select_walks_the_ranking() {
        let ranking = [
            ("isolated", Features::of(&[Feature::Isolated])),
            ("portable", Features::new()),
        ];
        assert!(rows_are_distinct(&ranking));
        assert_eq!(select::<&str>(&[]), None);
        // Isolated is never detected, so the walk passes it.
        assert_eq!(select(&ranking), Some("portable"));
        assert!(!rows_are_distinct(&[
            ("a", Features::new()),
            ("b", Features::new()),
        ]));
    }
}
