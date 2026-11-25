//! Arithmetic the primitives need beyond what the integer types give.
//!
//! [`natural`] is a bounded non-negative integer, which the
//! format-preserving modes use to move between a string of symbols
//! and the number it stands for. [`fe25519`] is the field under
//! Curve25519, shared by X25519 and Ed25519, and [`fe448`] the field
//! under Curve448. [`uint`] is an unsigned
//! integer of any fixed width, and [`montgomery`] the multiplication
//! and exponentiation modulo an odd number built on it, which is the
//! arithmetic under the prime curves. [`limbs`] is the same
//! arithmetic over a length known only at run time, which is the
//! arithmetic under RSA. [`rsa`] is the key machinery itself,
//! shared by the RSA signature and encryption schemes, and [`ec`]
//! the same for the NIST prime curves, shared by ECDH and ECDSA.
//!
//! # Kinds
//!
//! The big-number arithmetic has instructions written out for some
//! processors: the carry-chain products of [`limbs`] and
//! [`montgomery`], and the vector table read of [`ec`]. Which of them
//! a key runs is chosen once, when the key is made, and kept with it
//! as a [`Choice`]. The arithmetic is compiled once for each choice:
//! it takes an [`Arith`], a value of no size whose type says what
//! was chosen, so that every test of it inside the arithmetic is a
//! constant and folds away. [`with_arith`] and [`ec::with_engine`]
//! turn the kept choice into that type, with one branch on it.

pub(crate) mod ec;
pub(crate) mod fe25519;
pub(crate) mod fe448;
pub(crate) mod limbs;
pub(crate) mod montgomery;
pub(crate) mod natural;
pub(crate) mod rsa;
pub(crate) mod uint;

/// What an operation's arithmetic may use: the proofs the lists
/// handed out when its key was made, or none. Each kind answers the
/// same way every time, by its type alone, so the compiler keeps
/// only the code its answers reach.
pub(crate) trait Arith: Copy {
    /// The carry-chain products, where the list chose them.
    #[cfg(target_arch = "x86_64")]
    fn adx(self) -> Option<limbs::x86_64::Adx>;

    /// The vector table read, where the list chose it.
    #[cfg(target_arch = "x86_64")]
    fn avx2(self) -> Option<ec::x86_64::Avx2>;
}

/// Nothing written out: the arithmetic as plain Rust.
#[derive(Clone, Copy)]
pub(crate) struct Portable;

impl Arith for Portable {
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn adx(self) -> Option<limbs::x86_64::Adx> {
        None
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn avx2(self) -> Option<ec::x86_64::Avx2> {
        None
    }
}

/// The carry-chain products alone.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
pub(crate) struct WithAdx(pub(crate) limbs::x86_64::Adx);

#[cfg(target_arch = "x86_64")]
impl Arith for WithAdx {
    #[inline(always)]
    fn adx(self) -> Option<limbs::x86_64::Adx> {
        Some(self.0)
    }

    #[inline(always)]
    fn avx2(self) -> Option<ec::x86_64::Avx2> {
        None
    }
}

/// The vector table read alone.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
pub(crate) struct WithAvx2(pub(crate) ec::x86_64::Avx2);

#[cfg(target_arch = "x86_64")]
impl Arith for WithAvx2 {
    #[inline(always)]
    fn adx(self) -> Option<limbs::x86_64::Adx> {
        None
    }

    #[inline(always)]
    fn avx2(self) -> Option<ec::x86_64::Avx2> {
        Some(self.0)
    }
}

/// Both.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
pub(crate) struct WithBoth(
    pub(crate) limbs::x86_64::Adx,
    pub(crate) ec::x86_64::Avx2,
);

#[cfg(target_arch = "x86_64")]
impl Arith for WithBoth {
    #[inline(always)]
    fn adx(self) -> Option<limbs::x86_64::Adx> {
        Some(self.0)
    }

    #[inline(always)]
    fn avx2(self) -> Option<ec::x86_64::Avx2> {
        Some(self.1)
    }
}

/// The kinds of arithmetic a key may run, as the lists chose them
/// when it was made. Each kind written out holds the proof its list
/// handed out, so a key that has one may use it without asking
/// again.
#[derive(Clone, Copy)]
pub(crate) enum Choice {
    /// Nothing written out.
    Portable,
    /// The carry-chain products alone.
    #[cfg(target_arch = "x86_64")]
    Adx(limbs::x86_64::Adx),
    /// The vector table read alone.
    #[cfg(target_arch = "x86_64")]
    Avx2(ec::x86_64::Avx2),
    /// Both.
    #[cfg(target_arch = "x86_64")]
    Both(limbs::x86_64::Adx, ec::x86_64::Avx2),
}

impl Choice {
    /// What the big-number list [`limbs::KERNELS`] chooses under
    /// `ctx`: for a key whose arithmetic reads no table.
    pub(crate) fn bignum(ctx: crate::Context) -> Self {
        Self::of(crate::features::choose(ctx, limbs::KERNELS), None)
    }

    /// The kind the two lists' answers make together.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn of(
        adx: Option<crate::features::Chosen<limbs::Kernel>>,
        avx2: Option<crate::features::Chosen<ec::Kernel>>,
    ) -> Self {
        let adx = adx.and_then(limbs::x86_64::Adx::of);
        let avx2 = avx2.and_then(ec::x86_64::Avx2::of);
        match (adx, avx2) {
            (Some(x), Some(v)) => Choice::Both(x, v),
            (Some(x), None) => Choice::Adx(x),
            (None, Some(v)) => Choice::Avx2(v),
            (None, None) => Choice::Portable,
        }
    }

    /// Elsewhere every answer makes the one kind there is.
    #[cfg(not(target_arch = "x86_64"))]
    pub(crate) fn of(
        _: Option<crate::features::Chosen<limbs::Kernel>>,
        _: Option<crate::features::Chosen<ec::Kernel>>,
    ) -> Self {
        Choice::Portable
    }

    /// The carry-chain products, where the choice has them.
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    pub(crate) fn adx(self) -> Option<limbs::x86_64::Adx> {
        match self {
            Choice::Adx(x) | Choice::Both(x, _) => Some(x),
            Choice::Portable | Choice::Avx2(_) => None,
        }
    }
}

/// Runs `$body` with `$a` bound to the [`Arith`] a key's kept
/// [`Choice`] names, as `with_arith!(choice, a => ...)`; the body is
/// compiled once for each kind. Only the products matter here, so a
/// choice with the table read too runs as the products alone.
#[cfg(target_arch = "x86_64")]
macro_rules! with_arith {
    ($choice:expr, $a:ident => $body:expr) => {
        match ($choice).adx() {
            Some(adx) => {
                let $a = $crate::math::WithAdx(adx);
                $body
            }
            None => {
                let $a = $crate::math::Portable;
                $body
            }
        }
    };
}

/// Elsewhere there is nothing written out to run.
#[cfg(not(target_arch = "x86_64"))]
macro_rules! with_arith {
    ($choice:expr, $a:ident => $body:expr) => {{
        let _: $crate::math::Choice = $choice;
        let $a = $crate::math::Portable;
        $body
    }};
}

pub(crate) use with_arith;
