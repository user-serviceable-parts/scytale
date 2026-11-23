//! Keccak-f\[1600\] with the ARMv8.2 SHA3 instructions.
//!
//! The extension adds four instructions that are the steps of a
//! round: `eor3` for the column parities of theta, `rax1` for the
//! rotate-and-xor that finishes it, `xar` for the rotation of rho
//! combined with the xor of theta, and `bcax` for chi. With the
//! twenty-five lanes held in v0 to v24 a round is straight-line code
//! and the state never touches memory between rounds. The upper half
//! of each register carries junk that costs nothing and is never
//! stored.

#![allow(unsafe_code)]

#[cfg(test)]
use super::engine::Sponge;
use super::engine::{LANES, Permutation};
use super::portable::ROUND_CONSTANTS;
#[cfg(test)]
use super::variant;
use crate::align::At32;
use crate::features::Chosen;

/// SHA3-256 with the SHA3 instructions.
#[cfg(test)]
pub type Sha3_256 = Sponge<Armv8, variant::Sha3_256>;
/// SHAKE128 with the SHA3 instructions.
#[cfg(test)]
pub type Shake128 = Sponge<Armv8, variant::Shake128>;

/// The permutation via the SHA3 instructions. No public constructor:
/// a value exists only by way of `of`.
#[derive(Clone, Copy)]
pub struct Armv8(());

impl super::engine::Sealed for Armv8 {}

impl Permutation for Armv8 {
    fn of(chosen: Chosen<super::Kernel>) -> Option<Self> {
        (chosen.kernel() == super::Kernel::Armv8).then_some(Armv8(()))
    }

    fn permute(self, state: &mut [u64; LANES]) {
        // SAFETY: `self` was minted by `of`, which confirmed the
        // instructions.
        unsafe { keccak_f1600(state.as_mut_ptr()) }
    }
}

/// The twenty-four rounds, on lanes already in v0 to v24.
///
/// Every instruction here works on a whole register, so the same
/// rounds serve one state in the lower halves and two states, one in
/// each half; only what loads and stores the lanes knows which.
#[rustfmt::skip]
macro_rules! rounds {
    () => {
        concat!(
            "2:\n",
            "eor3 v25.16b, v0.16b, v5.16b, v10.16b\n",
            "eor3 v25.16b, v25.16b, v15.16b, v20.16b\n",
            "eor3 v26.16b, v1.16b, v6.16b, v11.16b\n",
            "eor3 v26.16b, v26.16b, v16.16b, v21.16b\n",
            "eor3 v27.16b, v2.16b, v7.16b, v12.16b\n",
            "eor3 v27.16b, v27.16b, v17.16b, v22.16b\n",
            "eor3 v28.16b, v3.16b, v8.16b, v13.16b\n",
            "eor3 v28.16b, v28.16b, v18.16b, v23.16b\n",
            "eor3 v29.16b, v4.16b, v9.16b, v14.16b\n",
            "eor3 v29.16b, v29.16b, v19.16b, v24.16b\n",
            "rax1 v30.2d, v29.2d, v26.2d\n",
            "rax1 v31.2d, v25.2d, v27.2d\n",
            "rax1 v26.2d, v26.2d, v28.2d\n",
            "rax1 v27.2d, v27.2d, v29.2d\n",
            "rax1 v28.2d, v28.2d, v25.2d\n",
            "eor v0.16b, v0.16b, v30.16b\n",
            "mov v25.16b, v1.16b\n",
            "xar v1.2d, v6.2d, v31.2d, #20\n",
            "xar v6.2d, v9.2d, v28.2d, #44\n",
            "xar v9.2d, v22.2d, v26.2d, #3\n",
            "xar v22.2d, v14.2d, v28.2d, #25\n",
            "xar v14.2d, v20.2d, v30.2d, #46\n",
            "xar v20.2d, v2.2d, v26.2d, #2\n",
            "xar v2.2d, v12.2d, v26.2d, #21\n",
            "xar v12.2d, v13.2d, v27.2d, #39\n",
            "xar v13.2d, v19.2d, v28.2d, #56\n",
            "xar v19.2d, v23.2d, v27.2d, #8\n",
            "xar v23.2d, v15.2d, v30.2d, #23\n",
            "xar v15.2d, v4.2d, v28.2d, #37\n",
            "xar v4.2d, v24.2d, v28.2d, #50\n",
            "xar v24.2d, v21.2d, v31.2d, #62\n",
            "xar v21.2d, v8.2d, v27.2d, #9\n",
            "xar v8.2d, v16.2d, v31.2d, #19\n",
            "xar v16.2d, v5.2d, v30.2d, #28\n",
            "xar v5.2d, v3.2d, v27.2d, #36\n",
            "xar v3.2d, v18.2d, v27.2d, #43\n",
            "xar v18.2d, v17.2d, v26.2d, #49\n",
            "xar v17.2d, v11.2d, v31.2d, #54\n",
            "xar v11.2d, v7.2d, v26.2d, #58\n",
            "xar v7.2d, v10.2d, v30.2d, #61\n",
            "xar v10.2d, v25.2d, v31.2d, #63\n",
            "mov v25.16b, v0.16b\n",
            "mov v29.16b, v1.16b\n",
            "bcax v0.16b, v0.16b, v2.16b, v1.16b\n",
            "bcax v1.16b, v1.16b, v3.16b, v2.16b\n",
            "bcax v2.16b, v2.16b, v4.16b, v3.16b\n",
            "bcax v3.16b, v3.16b, v25.16b, v4.16b\n",
            "bcax v4.16b, v4.16b, v29.16b, v25.16b\n",
            "mov v25.16b, v5.16b\n",
            "mov v29.16b, v6.16b\n",
            "bcax v5.16b, v5.16b, v7.16b, v6.16b\n",
            "bcax v6.16b, v6.16b, v8.16b, v7.16b\n",
            "bcax v7.16b, v7.16b, v9.16b, v8.16b\n",
            "bcax v8.16b, v8.16b, v25.16b, v9.16b\n",
            "bcax v9.16b, v9.16b, v29.16b, v25.16b\n",
            "mov v25.16b, v10.16b\n",
            "mov v29.16b, v11.16b\n",
            "bcax v10.16b, v10.16b, v12.16b, v11.16b\n",
            "bcax v11.16b, v11.16b, v13.16b, v12.16b\n",
            "bcax v12.16b, v12.16b, v14.16b, v13.16b\n",
            "bcax v13.16b, v13.16b, v25.16b, v14.16b\n",
            "bcax v14.16b, v14.16b, v29.16b, v25.16b\n",
            "mov v25.16b, v15.16b\n",
            "mov v29.16b, v16.16b\n",
            "bcax v15.16b, v15.16b, v17.16b, v16.16b\n",
            "bcax v16.16b, v16.16b, v18.16b, v17.16b\n",
            "bcax v17.16b, v17.16b, v19.16b, v18.16b\n",
            "bcax v18.16b, v18.16b, v25.16b, v19.16b\n",
            "bcax v19.16b, v19.16b, v29.16b, v25.16b\n",
            "mov v25.16b, v20.16b\n",
            "mov v29.16b, v21.16b\n",
            "bcax v20.16b, v20.16b, v22.16b, v21.16b\n",
            "bcax v21.16b, v21.16b, v23.16b, v22.16b\n",
            "bcax v22.16b, v22.16b, v24.16b, v23.16b\n",
            "bcax v23.16b, v23.16b, v25.16b, v24.16b\n",
            "bcax v24.16b, v24.16b, v29.16b, v25.16b\n",
            "ld1r {{v29.2d}}, [{rc}], #8\n",
            "eor v0.16b, v0.16b, v29.16b\n",
            "subs {n}, {n}, #1\n",
            "b.ne 2b\n",
        )
    };
}

/// Applies Keccak-f\[1600\] to the twenty-five lanes at `state`.
///
/// Lane `x + 5y` lives in `v(x + 5y)`. Theta leaves the five column
/// xors D[x] in v30, v31, v26, v27 and v28; rho and pi then follow
/// the single 24-lane cycle of pi backwards, each lane taking its
/// predecessor xored with its D and rotated, with v25 holding the
/// lane the cycle starts from. Chi keeps a row's first two lanes in
/// v25 and v29 while the row is overwritten.
///
/// # Safety
/// Requires the SHA3 instructions; `state` must point at 25 lanes.
#[target_feature(enable = "sha3")]
#[rustfmt::skip]
unsafe fn keccak_f1600(state: *mut u64) {
    unsafe {
        core::arch::asm!(
            "ld1 {{v0.1d, v1.1d, v2.1d, v3.1d}}, [{p}], #32",
            "ld1 {{v4.1d, v5.1d, v6.1d, v7.1d}}, [{p}], #32",
            "ld1 {{v8.1d, v9.1d, v10.1d, v11.1d}}, [{p}], #32",
            "ld1 {{v12.1d, v13.1d, v14.1d, v15.1d}}, [{p}], #32",
            "ld1 {{v16.1d, v17.1d, v18.1d, v19.1d}}, [{p}], #32",
            "ld1 {{v20.1d, v21.1d, v22.1d, v23.1d}}, [{p}], #32",
            "ld1 {{v24.1d}}, [{p}]",
            rounds!(),
            "st1 {{v0.1d, v1.1d, v2.1d, v3.1d}}, [{q}], #32",
            "st1 {{v4.1d, v5.1d, v6.1d, v7.1d}}, [{q}], #32",
            "st1 {{v8.1d, v9.1d, v10.1d, v11.1d}}, [{q}], #32",
            "st1 {{v12.1d, v13.1d, v14.1d, v15.1d}}, [{q}], #32",
            "st1 {{v16.1d, v17.1d, v18.1d, v19.1d}}, [{q}], #32",
            "st1 {{v20.1d, v21.1d, v22.1d, v23.1d}}, [{q}], #32",
            "st1 {{v24.1d}}, [{q}]",
            p = inout(reg) state => _,
            q = inout(reg) state => _,
            rc = inout(reg) ROUND_CONSTANTS.as_ptr() => _,
            n = inout(reg) ROUND_CONSTANTS.len() => _,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
            out("v16") _,
            out("v17") _,
            out("v18") _,
            out("v19") _,
            out("v20") _,
            out("v21") _,
            out("v22") _,
            out("v23") _,
            out("v24") _,
            out("v25") _,
            out("v26") _,
            out("v27") _,
            out("v28") _,
            out("v29") _,
            out("v30") _,
            out("v31") _,
            options(nostack),
        );
    }
}

/// Applies Keccak-f\[1600\] to two states at once, lane by lane:
/// each of the twenty-five lanes at `state` is a pair, the first
/// state's and then the second's, and a register holds the pair.
///
/// The rounds are the ones above, which were always done to both
/// halves of every register; here the upper half is a state too.
///
/// # Safety
/// Requires the SHA3 instructions; `state` must point at 25 pairs of
/// lanes.
#[target_feature(enable = "sha3")]
#[rustfmt::skip]
unsafe fn keccak_f1600_x2(state: *mut u64) {
    unsafe {
        core::arch::asm!(
            "ld1 {{v0.2d, v1.2d, v2.2d, v3.2d}}, [{p}], #64",
            "ld1 {{v4.2d, v5.2d, v6.2d, v7.2d}}, [{p}], #64",
            "ld1 {{v8.2d, v9.2d, v10.2d, v11.2d}}, [{p}], #64",
            "ld1 {{v12.2d, v13.2d, v14.2d, v15.2d}}, [{p}], #64",
            "ld1 {{v16.2d, v17.2d, v18.2d, v19.2d}}, [{p}], #64",
            "ld1 {{v20.2d, v21.2d, v22.2d, v23.2d}}, [{p}], #64",
            "ld1 {{v24.2d}}, [{p}]",
            rounds!(),
            "st1 {{v0.2d, v1.2d, v2.2d, v3.2d}}, [{q}], #64",
            "st1 {{v4.2d, v5.2d, v6.2d, v7.2d}}, [{q}], #64",
            "st1 {{v8.2d, v9.2d, v10.2d, v11.2d}}, [{q}], #64",
            "st1 {{v12.2d, v13.2d, v14.2d, v15.2d}}, [{q}], #64",
            "st1 {{v16.2d, v17.2d, v18.2d, v19.2d}}, [{q}], #64",
            "st1 {{v20.2d, v21.2d, v22.2d, v23.2d}}, [{q}], #64",
            "st1 {{v24.2d}}, [{q}]",
            p = inout(reg) state => _,
            q = inout(reg) state => _,
            rc = inout(reg) ROUND_CONSTANTS.as_ptr() => _,
            n = inout(reg) ROUND_CONSTANTS.len() => _,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
            out("v16") _,
            out("v17") _,
            out("v18") _,
            out("v19") _,
            out("v20") _,
            out("v21") _,
            out("v22") _,
            out("v23") _,
            out("v24") _,
            out("v25") _,
            out("v26") _,
            out("v27") _,
            out("v28") _,
            out("v29") _,
            out("v30") _,
            out("v31") _,
            options(nostack),
        );
    }
}

/// Two states side by side, lane by lane: `state[i][s]` is lane `i`
/// of state `s`.
pub(crate) type Two = At32<[[u64; 2]; LANES]>;

/// The two-state permutation. No public constructor: a value exists
/// only by way of `of`.
#[derive(Clone, Copy)]
pub(crate) struct Pair(());

impl Pair {
    /// The permutation, where the two-state list chose it.
    pub(crate) fn of(chosen: Chosen<super::together::Kernel>) -> Option<Self> {
        (chosen.kernel() == super::together::Kernel::Armv8).then_some(Pair(()))
    }

    /// Applies the permutation to each of the two states.
    pub(crate) fn permute(self, state: &mut Two) {
        // SAFETY: `self` was minted by `of`, which confirmed the
        // instructions, and `state` is 25 pairs of lanes.
        unsafe { keccak_f1600_x2(state.0.as_mut_ptr().cast()) }
    }
}
