//! What the processor has, and what the program lets the library use.
//!
//! A primitive with more than one kernel, one routine for each
//! instruction set it has been written for, chooses between them at
//! construction from a fixed list, best first: the first kernel whose
//! requirements are met wins. What meets them is a set of
//! [`Features`], and this module owns that set.
//!
//! [`detected`] is what the processor reports, asked once. Every
//! object is created with a [`Context`], which carries the set it may
//! choose from: [`Context::default`] is the processor's, and
//! [`Context::try_new`] takes a set of the program's own, which may
//! hold any member of [`detected`] and nothing else from this
//! architecture, so no context can select a kernel the processor
//! cannot run. An object that creates others as it runs, a MAC its
//! hash or a signature scheme its hashes, gives them its own context.
//!
//! Removing a feature selects the kernel below the one it unlocked,
//! which is how a program chooses an implementation: not by naming
//! one, but by saying what it may not use. A *virtual feature* is one
//! no processor reports and only the program grants.
//! [`Feature::Isolated`] is the first: no adversary shares this
//! processor's caches, so the table-driven AES, which leaks through
//! them, may be chosen above the bitsliced one. Two kernels with the
//! same hardware requirements are told apart by a virtual feature,
//! never by position alone.
//!
//! The kernels themselves are not named. What a type tells the
//! program is its [`profiles`](Dispatcher::profiles): the feature
//! sets it tells apart, each the least a processor must offer for
//! one choice. A program that wants every choice exercised makes a
//! context of each profile in turn; one that wants to know what a
//! machine will run finds the first profile its context meets.
//!
//! The per-architecture enums exist on every target, so a program
//! for three architectures names all of their features in one place
//! without a `cfg`, and the documentation shows every name whatever
//! machine rendered it. [`Context::try_new`] is strict about this
//! architecture and inert about the others: a feature of this one
//! that the processor lacks is an error, a feature of another is
//! never required by anything here and is kept without effect.
//!
//! ```
//! use scytale::Context;
//! use scytale::cipher::aes::Aes128;
//! use scytale::features::{self, Feature, aarch64, x86_64};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut f = features::detected();
//! // AES-NI rather than VAES; a no-op on any other architecture.
//! f.remove(x86_64::Feature::Vaes.into());
//! // A board with no AES instructions and nothing untrusted on it.
//! if !f.contains(aarch64::Feature::Aes.into()) {
//!     f.insert(Feature::Isolated);
//! }
//! let ctx = Context::try_new(f)?;
//! let aes = Aes128::new(ctx, &[0u8; 16].into());
//! # let _ = aes;
//! # Ok(())
//! # }
//! ```
//!
//! A context is a value: two in one program are independent, and
//! nothing is shared or locked. An object keeps the kernel it was
//! built with for its whole life.
//!
//! # Asking once
//!
//! Asking the processor is not cheap: `cpuid` serialises the
//! pipeline, and the RISC-V answer is a system call. Neither can
//! change while the program runs, so [`detected`] asks once and keeps
//! the answer in an atomic. Nothing locks: two threads arriving
//! together both ask and both store the same word, which is worth
//! more than a lock, since it means the question can be put from code
//! with no allocator and no threads at all. A default context is then
//! one relaxed load.

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
    /// running on, which is the only kind [`Context::try_new`] checks
    /// against the hardware.
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
    x86_64,
    "x86_64",
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
    aarch64,
    "aarch64",
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
    riscv64,
    "riscv64",
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
/// features bare, and the empty set `none`:
///
/// ```
/// use scytale::features::{Feature, Features, x86_64::Feature as X};
///
/// let f: Features = [X::Aes.into(), X::Sha.into(), Feature::Isolated]
///     .into_iter()
///     .collect();
/// assert_eq!(f.to_string(), "x86_64/aes+sha isolated");
/// assert_eq!(f.to_string().parse::<Features>(), Ok(f));
/// assert_eq!(Features::new().to_string(), "none");
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
            return f.write_str("none");
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
/// [`Feature`] reads them. Tokens are separated by whitespace; `none`
/// names no feature.
impl FromStr for Features {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let mut set = Features::new();
        for token in s.split_whitespace() {
            if token == "none" {
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

/// What the processor reports, asked once.
///
/// This is the set of [`Context::default`] and the reference every
/// [`Context::try_new`] is checked against. On an architecture with no
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

/// The features an object may use, given to it when it is created.
///
/// Every object that chooses a kernel takes a context at creation
/// and chooses from its set, once; an object that creates others as
/// it runs gives them its own context, so everything it does follows
/// the set it was created with. Two contexts in one program are
/// wholly independent: nothing is shared, and nothing need be locked.
///
/// A context holds only features the processor has, so a kernel
/// chosen from one can always run. [`Context::default`] is the set
/// [`detected`]; [`Context::try_new`] takes a set of the program's
/// own, such as one with [`Feature::Isolated`] added or a feature
/// taken away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context(Features);

impl Context {
    /// A context allowing `features`.
    ///
    /// The set may hold any member of [`detected`] and any virtual
    /// feature; a feature of this architecture that the processor
    /// lacks is refused with [`Error::UnsupportedFeature`] naming it.
    /// Features of other architectures are kept and have no effect,
    /// so a program for several architectures can build one set for
    /// all of them.
    pub fn try_new(features: Features) -> Result<Self, Error> {
        let hardware = detected();
        if let Some(missing) =
            features.native().iter().find(|&f| !hardware.contains(f))
        {
            return Err(Error::UnsupportedFeature(missing));
        }
        Ok(Self(features))
    }

    /// The features this context allows.
    pub fn features(self) -> Features {
        self.0
    }

    /// The context that allows nothing, so that every object takes
    /// its portable kernel: the reference the tests compare against.
    #[cfg(test)]
    pub(crate) fn portable() -> Self {
        Self(Features::new())
    }

    /// Whether everything in `required` is allowed. Private: a kernel
    /// is chosen by [`choose`] from its list, so that every hardware
    /// branch in the crate is a row some list publishes and a kernel
    /// test runs.
    fn has(self, required: Features) -> bool {
        required.is_subset(self.0)
    }
}

impl Default for Context {
    /// The features the processor has.
    fn default() -> Self {
        Self(detected())
    }
}

/// A kernel the list chose: proof that its row's features were in
/// the context it was chosen from, and so that the processor has
/// them, since a context never holds a feature the processor lacks.
/// Only [`choose`] makes one, so a kernel's constructor that takes
/// one needs to ask nothing of the processor: it checks only that the
/// choice is its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Chosen<K>(K);

impl<K: Copy> Chosen<K> {
    /// Which kernel was chosen.
    pub(crate) fn kernel(self) -> K {
        self.0
    }
}

/// As [`select`], with the answer as the proof a kernel's constructor
/// takes.
pub(crate) fn choose<K: Copy>(
    ctx: Context,
    kernels: &[(K, Features)],
) -> Option<Chosen<K>> {
    select(ctx, kernels).map(Chosen)
}

/// The first kernel in `kernels` whose requirements `ctx` allows.
/// Every family's list ends with a kernel that requires nothing, so
/// there is always one; `None` only for an empty list.
pub(crate) fn select<K: Copy>(
    ctx: Context,
    kernels: &[(K, Features)],
) -> Option<K> {
    kernels
        .iter()
        .find(|(_, required)| ctx.has(*required))
        .map(|(kernel, _)| *kernel)
}

/// The set of features one kernel needs, written out: nothing,
/// `isolated`, or one architecture's features by their variant names,
/// as `x86_64: Avx2, Bmi2`. Every architecture's form compiles
/// everywhere, so a row's `cfg` alone decides where it exists.
macro_rules! needs {
    () => {
        $crate::features::Features::new()
    };
    (isolated) => {
        $crate::features::Features::of(&[$crate::features::Feature::Isolated])
    };
    (x86_64: $($f:ident),+ $(,)?) => {
        $crate::features::Features::of(&[$(
            $crate::features::Feature::X86_64(
                $crate::features::x86_64::Feature::$f,
            )
        ),+])
    };
    (aarch64: $($f:ident),+ $(,)?) => {
        $crate::features::Features::of(&[$(
            $crate::features::Feature::Aarch64(
                $crate::features::aarch64::Feature::$f,
            )
        ),+])
    };
    (riscv64: $($f:ident),+ $(,)?) => {
        $crate::features::Features::of(&[$(
            $crate::features::Feature::Riscv64(
                $crate::features::riscv64::Feature::$f,
            )
        ),+])
    };
}
pub(crate) use needs;

/// Declares the kernel lists of one kernel enum, the one place a
/// kernel and the features it needs are written down.
///
/// Each list is a type's kernels, best first, each with exactly the
/// features its code uses. From the same rows this makes:
///
/// - the list itself, which construction searches and
///   [`Dispatcher::profiles`] publishes;
/// - a compile-time check of each list, [`check_list`];
/// - a `match` over the enum that compiles only if every kernel is in
///   some list, so a kernel cannot be written and never dispatched;
/// - in the test build, a test per list, `kernels::<alg>`, that runs
///   the named suite once under every kernel, so a listed kernel
///   cannot go untested.
///
/// ```text
/// kernels! {
///     enum Kernel;
///     pub(crate) const KERNELS for sha512 tested by tests::suite = [
///         #[cfg(target_arch = "x86_64")]
///         Avx2 => (x86_64: Avx2, Bmi1, Bmi2),
///         Portable => (),
///     ];
/// }
/// ```
macro_rules! kernels {
    (
        enum $kernel:ident;
        $(
            $(#[$doc:meta])*
            $vis:vis const $list:ident for $alg:ident
                tested by $suite:path = [
                $(
                    $(#[$attr:meta])*
                    $variant:ident => ($($needs:tt)*)
                ),+ $(,)?
            ];
        )+
    ) => {
        $(
            $(#[$doc])*
            $vis const $list: &[($kernel, $crate::features::Features)] = &[
                $(
                    $(#[$attr])*
                    (
                        $kernel::$variant,
                        $crate::features::needs!($($needs)*),
                    ),
                )+
            ];
            const _: () = $crate::features::check_list($list);
        )+

        /// Compiles only if every kernel is in some list above.
        #[allow(dead_code, unreachable_patterns)]
        const fn every_kernel_is_listed(kernel: $kernel) {
            match kernel {
                $($(
                    $(#[$attr])*
                    $kernel::$variant => {}
                )+)+
            }
        }

        /// One test per list: its suite under every kernel.
        #[cfg(test)]
        mod kernels {
            #[allow(unused_imports)]
            use super::*;
            $(
                #[test]
                fn $alg() {
                    $crate::features::each_kernel(
                        stringify!($alg),
                        $list,
                        $suite,
                    );
                }
            )+
        }
    };
}
pub(crate) use kernels;

/// What every kernel list must be, checked when the list is compiled:
/// not empty; the last row needs nothing, so the search always ends;
/// no row needs all that a row above it needs, since the row above
/// would then always win and this one could never be chosen; and a
/// row that needs `isolated` sits directly above the last, so the
/// leaky tables are chosen only over the portable code.
pub(crate) const fn check_list<K>(rows: &[(K, Features)]) {
    assert!(!rows.is_empty(), "a kernel list is empty");
    let n = rows.len();
    assert!(
        rows[n - 1].1.is_empty(),
        "the last kernel must need nothing"
    );
    let isolated = Features::of(&[Feature::Isolated]);
    let mut i = 0;
    while i < n {
        let mut j = i + 1;
        while j < n {
            assert!(
                !rows[i].1.is_subset(rows[j].1),
                "a kernel needs all that one above it needs: unreachable"
            );
            j += 1;
        }
        assert!(
            !isolated.is_subset(rows[i].1) || i + 2 == n,
            "an isolated kernel must sit directly above the last"
        );
        i += 1;
    }
}

/// A kernel's needs as its test names them: the features, joined by
/// `+`, without the architecture's prefix; `none` for nothing.
#[cfg(test)]
pub(crate) fn short_name(needs: Features) -> std::string::String {
    if needs.is_empty() {
        return "none".into();
    }
    let names: std::vec::Vec<&str> = needs.iter().map(Feature::name).collect();
    names.join("+")
}

/// The features `kernel`'s row of `rows` needs, for a test that asks
/// what a processor with some set of extensions would be offered.
#[cfg(test)]
// Only the RISC-V tests ask, so far.
#[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
pub(crate) fn needs_of<K: PartialEq>(
    rows: &[(K, Features)],
    kernel: K,
) -> Features {
    rows.iter()
        .find(|(k, _)| *k == kernel)
        .map(|(_, needs)| *needs)
        .expect("the kernel is listed")
}

/// Where a kernel test builds its objects: with exactly one kernel's
/// features in their context, through the public API.
#[cfg(test)]
pub(crate) struct Under(Context);

#[cfg(test)]
impl Under {
    /// The context with this kernel's features and no others.
    pub(crate) fn ctx(&self) -> Context {
        self.0
    }
}

/// The kernels `SCYTALE_KERNELS` names, separated by white space, or
/// `None` when it is unset, which selects every kernel.
#[cfg(test)]
fn selected() -> Option<std::vec::Vec<std::string::String>> {
    let list = std::env::var("SCYTALE_KERNELS").ok()?;
    Some(list.split_whitespace().map(Into::into).collect())
}

/// Runs `suite` once under each kernel of `rows` that is selected and
/// that this processor can run, and prints a line for every kernel:
/// run, not run with the features it lacks, or not selected. A
/// kernel named twice, under two sets that each suffice, runs under
/// the first the processor has. Fails if any kernel's suite fails.
#[cfg(test)]
pub(crate) fn each_kernel<K: Copy + PartialEq>(
    alg: &str,
    rows: &[(K, Features)],
    suite: fn(&Under),
) {
    use std::string::String;
    use std::vec::Vec;

    let selected = selected();
    let hardware = detected();
    let mut ran: Vec<K> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    for &(kernel, needs) in rows {
        if ran.contains(&kernel) {
            continue;
        }
        let name = std::format!("{alg}/{}", short_name(needs));
        let missing = needs.native() - hardware;
        let state = if selected.as_ref().is_some_and(|s| !s.contains(&name)) {
            "not selected".into()
        } else if !missing.is_empty() {
            std::format!("not run: needs {}", short_name(missing))
        } else {
            ran.push(kernel);
            // The processor has every feature the row needs, checked
            // just above, so the context is always allowed.
            let under = Under(Context(needs));
            match std::panic::catch_unwind(|| suite(&under)) {
                Ok(()) => "run".into(),
                Err(_) => {
                    failed.push(name.clone());
                    "FAILED".into()
                }
            }
        };
        lines.push(std::format!("  {name:<40} {state}"));
    }
    std::println!("{alg}\n{}", lines.join("\n"));
    assert!(failed.is_empty(), "failed: {}", failed.join(" "));
}

/// The requirements alone, in order: what a family publishes as its
/// profiles. `N` is the length of `kernels`, checked when the constant
/// is evaluated.
pub(crate) const fn profiles_of<K, const N: usize>(
    kernels: &[(K, Features)],
) -> [Features; N] {
    assert!(kernels.len() == N, "profiles_of: wrong length");
    let mut profiles = [Features::new(); N];
    let mut i = 0;
    while i < N {
        profiles[i] = kernels[i].1;
        i += 1;
    }
    profiles
}

/// How many rows [`combined`] yields for `a` and `b`.
pub(crate) const fn combined_len(a: &[Features], b: &[Features]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < a.len() {
        let mut j = 0;
        while j < b.len() {
            if !union_before(a, b, i, j) {
                n += 1;
            }
            j += 1;
        }
        i += 1;
    }
    n
}

/// The profiles of a type whose kernel is two choices made apart, as
/// GCM's cipher loop and its multiply: the union of every pair, in
/// order, each once. `N` is what [`combined_len`] gives.
pub(crate) const fn combined<const N: usize>(
    a: &[Features],
    b: &[Features],
) -> [Features; N] {
    let mut out = [Features::new(); N];
    let mut n = 0;
    let mut i = 0;
    while i < a.len() {
        let mut j = 0;
        while j < b.len() {
            if !union_before(a, b, i, j) {
                out[n] = a[i].union(b[j]);
                n += 1;
            }
            j += 1;
        }
        i += 1;
    }
    assert!(n == N, "combined: wrong length");
    out
}

/// Whether the union of `a[i]` and `b[j]` is also the union of an
/// earlier pair.
const fn union_before(
    a: &[Features],
    b: &[Features],
    i: usize,
    j: usize,
) -> bool {
    let u = a[i].union(b[j]);
    let mut p = 0;
    while p <= i {
        let mut q = 0;
        let last = if p == i { j } else { b.len() };
        while q < last {
            if a[p].union(b[q]).0 == u.0 {
                return true;
            }
            q += 1;
        }
        p += 1;
    }
    false
}

/// Whether every row of `kernels` can be chosen: no row's requirements
/// include a higher row's, since the higher one would then be taken
/// whenever the lower one could be. Setting exactly a row's
/// requirements selects that row, which is what a program running
/// every kernel relies on. Every family's test asks this of its own
/// list.
#[cfg(test)]
pub(crate) fn rows_are_reachable<K>(kernels: &[(K, Features)]) -> bool {
    kernels.iter().enumerate().all(|(i, (_, higher))| {
        kernels[i + 1..]
            .iter()
            .all(|(_, lower)| !higher.is_subset(*lower))
    })
}

/// What every dispatching type's test asserts of its list: each row
/// can be chosen and the last needs nothing, so the search always
/// ends; the published profiles are the rows' needs in order; and the
/// kernel a value took under the default context, `built`, is the
/// first row the processor meets, which is what [`select`] says too.
#[cfg(test)]
pub(crate) fn dispatches<K: Copy + PartialEq + core::fmt::Debug>(
    kernels: &[(K, Features)],
    profiles: &[Features],
    built: K,
) {
    assert!(rows_are_reachable(kernels), "{kernels:?}");
    let last = kernels.last().map(|(_, needs)| *needs);
    assert_eq!(last, Some(Features::new()), "the search must always end");
    let needs: std::vec::Vec<Features> =
        kernels.iter().map(|(_, needs)| *needs).collect();
    assert_eq!(profiles, needs);
    dispatches_to(kernels, built);
}

/// As [`dispatches`], for a type whose profiles are its rows joined
/// with `other`, the rows of a second kernel chosen apart.
#[cfg(test)]
pub(crate) fn dispatches_combined<K: Copy + PartialEq + core::fmt::Debug>(
    kernels: &[(K, Features)],
    other: &[Features],
    profiles: &[Features],
    built: K,
) {
    assert!(rows_are_reachable(kernels), "{kernels:?}");
    let last = kernels.last().map(|(_, needs)| *needs);
    assert_eq!(last, Some(Features::new()), "the search must always end");
    let mut joined = std::vec::Vec::new();
    for (_, needs) in kernels {
        for &o in other {
            let u = needs.union(o);
            if !joined.contains(&u) {
                joined.push(u);
            }
        }
    }
    assert_eq!(profiles, joined);
    dispatches_to(kernels, built);
}

/// A value built under the default context takes the first row the
/// processor meets.
#[cfg(test)]
fn dispatches_to<K: Copy + PartialEq + core::fmt::Debug>(
    kernels: &[(K, Features)],
    built: K,
) {
    let ctx = Context::default();
    let expected = kernels
        .iter()
        .find(|(_, needs)| needs.is_subset(ctx.features()))
        .map(|(kernel, _)| *kernel);
    assert_eq!(select(ctx, kernels), expected);
    assert_eq!(Some(built), expected, "with {}", ctx.features());
}

/// A type that chooses a kernel from its context's features.
///
/// Sealed: only the crate's own dispatching types have kernels to
/// choose among. The kernels are not named; what a type publishes is
/// the feature set each one needs.
pub trait Dispatcher: sealed::Sealed {
    /// The feature profiles this type tells apart, best first. Each
    /// is the least a processor must offer for one choice; a new
    /// value takes the first whose profile its context meets, and the
    /// last needs nothing, so there is always one.
    fn profiles() -> &'static [Features];
}

pub(crate) mod sealed {
    pub trait Sealed {}
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
    fn the_empty_set_is_none() {
        assert_eq!(Features::new().to_string(), "none");
        assert_eq!("none".parse::<Features>(), Ok(Features::new()));
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
    fn select_walks_the_list() {
        let isolated = Features::of(&[Feature::Isolated]);
        let kernels = [("isolated", isolated), ("none", Features::new())];
        assert!(rows_are_reachable(&kernels));
        assert_eq!(select::<&str>(Context::default(), &[]), None);
        // Isolated is never detected, so the walk passes it.
        assert_eq!(select(crate::Context::default(), &kernels), Some("none"));
        let profiles: [Features; 2] = profiles_of(&kernels);
        assert_eq!(profiles, [isolated, Features::new()]);
    }

    #[test]
    fn a_row_below_one_it_includes_is_unreachable() {
        let a = Features::of(&[Feature::X86_64(x86_64::Feature::Aes)]);
        let b = a | Features::of(&[Feature::X86_64(x86_64::Feature::Sha)]);
        // Two rows needing the same thing: the second never wins.
        assert!(!rows_are_reachable(&[("a", a), ("b", a)]));
        // A row needing more than the one above it: never wins either.
        assert!(!rows_are_reachable(&[("a", a), ("b", b)]));
        // More demanding rows first is the shape that works.
        let none = Features::new();
        assert!(rows_are_reachable(&[("b", b), ("a", a), ("", none)]));
    }

    /// Dispatch itself: what each context's set selects.
    mod dispatch {
        use super::*;
        use crate::Key;
        use crate::aead::{Ccm, Gcm, GcmSiv, ccm, gcm, gcm_siv};
        use crate::cipher::aes::{self, Aes, Aes128};
        use crate::cipher::chacha20::ChaCha20;
        use crate::cipher::mode::{Cbc, Ctr, Xts, cbc, ctr, xts};
        use crate::hash::{sha2, sha3};

        /// Removing what the chosen kernel needs selects the kernel
        /// below, for every row of a family's list the processor can
        /// reach; and a context of exactly a row's needs selects that
        /// row.
        fn walk<K: Copy + PartialEq + core::fmt::Debug>(
            kernels: &[(K, Features)],
            built: &dyn Fn(Context) -> K,
        ) {
            let hardware = detected();
            let reachable: Vec<&(K, Features)> = kernels
                .iter()
                .filter(|(_, needs)| needs.is_subset(hardware))
                .collect();
            let mut allowed = hardware;
            for (i, (kernel, needs)) in reachable.iter().enumerate() {
                let ctx = Context::try_new(allowed).unwrap();
                assert_eq!(built(ctx), *kernel, "with {allowed}");
                allowed = allowed - *needs;
                for (_, lower) in &reachable[i + 1..] {
                    allowed = allowed | *lower;
                }
            }
            // Virtual features are granted, not detected, so every
            // row is reachable by its own profile.
            for (kernel, needs) in kernels {
                if needs.native().is_subset(hardware) {
                    let ctx = Context::try_new(*needs).unwrap();
                    assert_eq!(built(ctx), *kernel, "exactly {needs}");
                }
            }
        }

        #[test]
        fn removing_a_feature_selects_the_kernel_below() {
            let key = [0u8; 16];
            let chacha_key = crate::Key::from([0u8; 32]);
            walk(aes::KERNELS, &|ctx| Aes::<16>::new(ctx, &key).kernel());
            walk(sha2::KERNELS32, &|ctx| {
                sha2::Auto32::<sha2::variant::Sha256>::new(ctx).kernel()
            });
            walk(sha2::KERNELS64, &|ctx| {
                sha2::Auto64::<sha2::variant::Sha512>::new(ctx).kernel()
            });
            walk(sha3::KERNELS, &|ctx| {
                sha3::Auto::<sha3::variant::Sha3_256>::new(ctx).kernel()
            });
            walk(crate::cipher::chacha20::KERNELS, &|ctx| {
                ChaCha20::new(ctx, &chacha_key).kernel()
            });
            // The modes, over a cipher whose schedule their
            // instructions can read, so every row is in play.
            let aes = Key::from([0u8; 16]);
            let tweak = Key::from([1u8; 16]);
            walk(cbc::KERNELS, &|ctx| Cbc::<Aes128>::new(ctx, &aes).kernel());
            walk(ctr::KERNELS, &|ctx| Ctr::<Aes128>::new(ctx, &aes).kernel());
            walk(xts::KERNELS, &|ctx| {
                Xts::<Aes128>::try_new(ctx, &aes, &tweak)
                    .expect("distinct keys")
                    .kernel()
            });
            walk(gcm::KERNELS, &|ctx| Gcm::<Aes128>::new(ctx, &aes).kernel());
            walk(gcm_siv::KERNELS, &|ctx| {
                GcmSiv::<Aes128>::new(ctx, &aes).kernel()
            });
            walk(ccm::KERNELS, &|ctx| Ccm::<Aes128>::new(ctx, &aes).kernel());
        }

        #[test]
        fn isolated_admits_the_tables_below_the_hardware() {
            let key = [0u8; 16];
            let aes = |f: Features| {
                Aes::<16>::new(Context::try_new(f).unwrap(), &key).kernel()
            };
            // Alone, it unlocks the table-driven code over the
            // bitsliced.
            assert_eq!(
                aes(Features::of(&[Feature::Isolated])),
                aes::Kernel::Tables
            );
            // Beside the hardware, the hardware still wins.
            let mut f = detected();
            f.insert(Feature::Isolated);
            let ctx = Context::try_new(f).unwrap();
            assert_eq!(aes(f), select(ctx, aes::KERNELS).unwrap());
            // And without it, the tables are never chosen.
            assert_eq!(aes(Features::new()), aes::Kernel::Bitsliced);
        }

        /// Two contexts in one program are independent: a value keeps
        /// the kernel its own chose, whatever another chooses after.
        #[test]
        fn a_value_keeps_the_kernel_it_was_built_with() {
            let key = [0u8; 16];
            let built = Aes::<16>::new(Context::default(), &key);
            let kernel = built.kernel();
            let portable = Aes::<16>::new(Context::portable(), &key);
            assert_eq!(portable.kernel(), aes::Kernel::Bitsliced);
            assert_eq!(built.kernel(), kernel);
        }

        /// A context refuses a feature the processor lacks, and takes
        /// any virtual one.
        #[test]
        fn a_context_holds_only_what_the_processor_has() {
            let missing = native_all() - detected();
            if let Some(f) = missing.iter().next() {
                assert_eq!(
                    Context::try_new(Features::of(&[f])),
                    Err(Error::UnsupportedFeature(f))
                );
            }
            let isolated = Features::of(&[Feature::Isolated]);
            assert_eq!(
                Context::try_new(isolated).map(Context::features),
                Ok(isolated)
            );
            assert_eq!(Context::default().features(), detected());
        }
    }
}
