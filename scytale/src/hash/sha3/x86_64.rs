//! Keccak-f\[1600\] compiled for BMI1 and BMI2 on x86-64.
//!
//! There are no instructions for Keccak on this architecture. What
//! there is are `andn`, which is chi's `!b & c` in one instruction
//! where the baseline needs three, and `rorx`, a rotation that leaves
//! its source alone and so needs no copy first. The portable
//! permutation, compiled with both allowed, measured about a fifth
//! faster than the baseline build of the same source, so this is that
//! source and nothing else.

#![allow(unsafe_code)]

use super::engine::LANES;
use super::portable::keccak_f1600;
use crate::features::{self, Features, x86_64::Feature as F};

/// Applies the permutation where the processor has BMI1 and BMI2,
/// returning whether it did.
pub(crate) fn permute(state: &mut [u64; LANES]) -> bool {
    if !has_bmi() {
        return false;
    }
    // SAFETY: the instructions were just confirmed.
    unsafe { permute_bmi(state) };
    true
}

/// The portable permutation, inlined here and compiled for the two
/// instruction sets.
///
/// # Safety
/// Requires BMI1 and BMI2.
#[target_feature(enable = "bmi1,bmi2")]
unsafe fn permute_bmi(state: &mut [u64; LANES]) {
    keccak_f1600(state);
}

/// Whether the processor reports BMI1 and BMI2 (CPUID leaf 7, EBX
/// bits 3 and 8).
fn has_bmi() -> bool {
    features::has(BMI)
}

/// What [`has_bmi`] asks for.
const BMI: Features = features::x86(&[F::Bmi1, F::Bmi2]);

#[cfg(test)]
mod tests {
    use super::*;

    /// The build for the instruction sets permutes as the baseline
    /// one does, from the zero state and from states reached by
    /// permuting it.
    #[test]
    fn matches_the_baseline_build() {
        let mut expected = [0u64; LANES];
        for round in 0..4 {
            for (i, lane) in expected.iter_mut().enumerate() {
                *lane ^= (i as u64 + 1)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_mul(round);
            }
            let mut actual = expected;
            keccak_f1600(&mut expected);
            if !permute(&mut actual) {
                return;
            }
            assert_eq!(actual, expected, "round {round}");
        }
    }
}
