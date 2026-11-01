//! Keccak-f\[1600\] compiled for Zbb on RISC-V.
//!
//! There are no instructions for Keccak on this architecture. What
//! there is are `andn`, which is chi's `!b & c` in one instruction
//! where the baseline needs two, and `rori`, a rotation where the
//! baseline needs a shift, a shift and an or. Those are the two
//! things the permutation is made of: twenty-four rounds of twenty-five
//! lanes, each rotated and each taking a chi.
//!
//! This is the same arrangement as [`x86_64`](super::x86_64), where
//! the same two instructions under other names measured about a fifth
//! faster than the baseline build. The permutation itself is the
//! portable source and nothing else.

#![allow(unsafe_code)]

use super::engine::{LANES, Permutation};
use super::portable::keccak_f1600;
use crate::features::{self, Features, riscv64::Feature};

/// The permutation compiled for Zbb. No public constructor: a value
/// exists only by way of `probe`.
#[derive(Clone, Copy)]
pub struct Zbb(());

impl super::engine::Sealed for Zbb {}

impl Permutation for Zbb {
    fn probe() -> Option<Self> {
        features::allows(super::KERNELS, super::Kernel::Zbb).then_some(Zbb(()))
    }

    fn permute(self, state: &mut [u64; LANES]) {
        // SAFETY: `self` was minted by `probe`, which confirmed the
        // extension.
        unsafe { permute_zbb(state) }
    }
}

/// The portable permutation, inlined here and compiled for the
/// extension.
///
/// # Safety
/// Requires Zbb.
#[target_feature(enable = "zbb")]
unsafe fn permute_zbb(state: &mut [u64; LANES]) {
    keccak_f1600(state);
}

/// What the Zbb row needs.
pub(crate) const ZBB: Features = features::riscv(&[Feature::Zbb]);

#[cfg(test)]
mod tests {
    use super::*;

    /// The build for the extension permutes as the baseline one
    /// does, from the zero state and from states reached by
    /// permuting it.
    #[test]
    fn matches_the_baseline_build() {
        let Some(zbb) = Zbb::probe() else {
            std::eprintln!("Zbb not available; skipping");
            return;
        };
        let mut expected = [0u64; LANES];
        for round in 0..4 {
            for (i, lane) in expected.iter_mut().enumerate() {
                *lane ^= (i as u64 + 1)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_mul(round);
            }
            let mut actual = expected;
            keccak_f1600(&mut expected);
            zbb.permute(&mut actual);
            assert_eq!(actual, expected, "round {round}");
        }
    }
}
