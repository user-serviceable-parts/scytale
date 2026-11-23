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
//! an operation runs is chosen once, when it starts, and the
//! arithmetic is then compiled once for each choice: it takes an
//! [`Arith`], a value of no size whose type says what was chosen, so
//! that every test of it inside the arithmetic is a constant and
//! folds away. [`with_arith`] and [`ec::with_engine`] make the
//! choice.

pub(crate) mod ec;
pub(crate) mod fe25519;
pub(crate) mod fe448;
pub(crate) mod limbs;
pub(crate) mod montgomery;
pub(crate) mod natural;
pub(crate) mod rsa;
pub(crate) mod uint;

/// What an operation's arithmetic may use: the proofs the lists
/// handed out when it started, or none. Each kind answers the same
/// way every time, by its type alone, so the compiler keeps only the
/// code its answers reach.
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

/// Runs `$body` with `$a` bound to the [`Arith`] the big-number list
/// [`limbs::KERNELS`] chooses, which it asks once, here; the body is
/// compiled once for each kind. Given a choice already made, as
/// `with_arith!(chosen, a => ...)`, it takes that one instead.
#[cfg(target_arch = "x86_64")]
macro_rules! with_arith {
    ($a:ident => $body:expr) => {
        $crate::math::with_arith!(
            $crate::features::choose($crate::math::limbs::KERNELS),
            $a => $body
        )
    };
    ($chosen:expr, $a:ident => $body:expr) => {
        match ($chosen).and_then($crate::math::limbs::x86_64::Adx::of) {
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

/// Elsewhere there is nothing written out to choose.
#[cfg(not(target_arch = "x86_64"))]
macro_rules! with_arith {
    ($a:ident => $body:expr) => {{
        let $a = $crate::math::Portable;
        $body
    }};
    ($chosen:expr, $a:ident => $body:expr) => {{
        let _ = $chosen;
        let $a = $crate::math::Portable;
        $body
    }};
}

pub(crate) use with_arith;
