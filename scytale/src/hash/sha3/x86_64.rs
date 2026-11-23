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

use crate::features::Chosen;
use zeroize::Zeroize;

use super::engine::{LANES, Permutation};
use super::portable::{ROUND_CONSTANTS, keccak_f1600};
use crate::align::At32;

/// The permutation compiled for BMI1 and BMI2. No public constructor:
/// a value exists only by way of `of`.
#[derive(Clone, Copy)]
pub struct Bmi(());

impl super::engine::Sealed for Bmi {}

impl Permutation for Bmi {
    fn of(chosen: Chosen<super::Kernel>) -> Option<Self> {
        (chosen.kernel() == super::Kernel::Bmi).then_some(Bmi(()))
    }

    fn permute(self, state: &mut [u64; LANES]) {
        // SAFETY: `self` was minted by `of`, which confirmed the
        // instructions.
        unsafe { permute_bmi(state) }
    }
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

/// Four states at once, lane by lane: `state[i][s]` is lane `i` of
/// state `s`, so one 256-bit register holds the same lane of all
/// four and a round is the scalar round with every operation done
/// four times over.
pub(crate) type Four = At32<[[u64; 4]; LANES]>;

/// The round constants, each four times over, one to a state.
static ROUND_CONSTANTS4: At32<[[u64; 4]; 24]> = {
    let mut out = [[0u64; 4]; 24];
    let mut round = 0;
    while round < 24 {
        out[round] = [ROUND_CONSTANTS[round]; 4];
        round += 1;
    }
    At32(out)
};

/// Keccak-f\[1600\] on four states.
///
/// Twenty-five lanes do not fit sixteen registers, so the states
/// stay in memory: a round reads from one copy and writes the other,
/// and the two change places each round. Within a round the five
/// lanes of the row being made are in registers, and each lane is
/// read once and written once.
///
/// The column parities theta begins with never leave registers:
/// each lane chi makes is added to its column's as it is stored. Read
/// back from memory instead, the next round could not begin until
/// the last row of this one had been stored and reloaded, and the
/// processor, with a round and a half of instructions in view at
/// most, had nothing else to run while it waited.
///
/// There is no 64-bit rotate at this width; each is two shifts and
/// an or.
///
/// # Safety
/// Requires AVX2.
unsafe fn permute4(state: &mut Four) {
    let mut other: Four = At32([[0; 4]; LANES]);
    unsafe {
        core::arch::asm!(
            // The column parities of the state as it arrives.
            "vmovdqa ymm0, [{a} + 0]",
            "vpxor ymm0, ymm0, [{a} + 160]",
            "vpxor ymm0, ymm0, [{a} + 320]",
            "vpxor ymm0, ymm0, [{a} + 480]",
            "vpxor ymm0, ymm0, [{a} + 640]",
            "vmovdqa ymm1, [{a} + 32]",
            "vpxor ymm1, ymm1, [{a} + 192]",
            "vpxor ymm1, ymm1, [{a} + 352]",
            "vpxor ymm1, ymm1, [{a} + 512]",
            "vpxor ymm1, ymm1, [{a} + 672]",
            "vmovdqa ymm2, [{a} + 64]",
            "vpxor ymm2, ymm2, [{a} + 224]",
            "vpxor ymm2, ymm2, [{a} + 384]",
            "vpxor ymm2, ymm2, [{a} + 544]",
            "vpxor ymm2, ymm2, [{a} + 704]",
            "vmovdqa ymm3, [{a} + 96]",
            "vpxor ymm3, ymm3, [{a} + 256]",
            "vpxor ymm3, ymm3, [{a} + 416]",
            "vpxor ymm3, ymm3, [{a} + 576]",
            "vpxor ymm3, ymm3, [{a} + 736]",
            "vmovdqa ymm4, [{a} + 128]",
            "vpxor ymm4, ymm4, [{a} + 288]",
            "vpxor ymm4, ymm4, [{a} + 448]",
            "vpxor ymm4, ymm4, [{a} + 608]",
            "vpxor ymm4, ymm4, [{a} + 768]",
            "2:",
            // Theta: for each column, the parity to its left with the
            // one to its right rotated by one.
            "vpaddq ymm10, ymm1, ymm1",
            "vpsrlq ymm11, ymm1, 63",
            "vpor ymm10, ymm10, ymm11",
            "vpxor ymm5, ymm10, ymm4",
            "vpaddq ymm10, ymm2, ymm2",
            "vpsrlq ymm11, ymm2, 63",
            "vpor ymm10, ymm10, ymm11",
            "vpxor ymm6, ymm10, ymm0",
            "vpaddq ymm10, ymm3, ymm3",
            "vpsrlq ymm11, ymm3, 63",
            "vpor ymm10, ymm10, ymm11",
            "vpxor ymm7, ymm10, ymm1",
            "vpaddq ymm10, ymm4, ymm4",
            "vpsrlq ymm11, ymm4, 63",
            "vpor ymm10, ymm10, ymm11",
            "vpxor ymm8, ymm10, ymm2",
            "vpaddq ymm10, ymm0, ymm0",
            "vpsrlq ymm11, ymm0, 63",
            "vpor ymm10, ymm10, ymm11",
            "vpxor ymm9, ymm10, ymm3",
            // Row 0: rho and pi bring five lanes in, chi sends them
            // out, and each joins the parity of its column.
            "vpxor ymm10, ymm5, [{a} + 0]",
            "vpxor ymm11, ymm6, [{a} + 192]",
            "vpsllq ymm15, ymm11, 44",
            "vpsrlq ymm11, ymm11, 20",
            "vpor ymm11, ymm11, ymm15",
            "vpxor ymm12, ymm7, [{a} + 384]",
            "vpsllq ymm15, ymm12, 43",
            "vpsrlq ymm12, ymm12, 21",
            "vpor ymm12, ymm12, ymm15",
            "vpxor ymm13, ymm8, [{a} + 576]",
            "vpsllq ymm15, ymm13, 21",
            "vpsrlq ymm13, ymm13, 43",
            "vpor ymm13, ymm13, ymm15",
            "vpxor ymm14, ymm9, [{a} + 768]",
            "vpsllq ymm15, ymm14, 14",
            "vpsrlq ymm14, ymm14, 50",
            "vpor ymm14, ymm14, ymm15",
            "vpandn ymm0, ymm11, ymm12",
            "vpxor ymm0, ymm0, ymm10",
            // Iota.
            "vpxor ymm0, ymm0, [{rc}]",
            "vmovdqa [{e} + 0], ymm0",
            "vpandn ymm1, ymm12, ymm13",
            "vpxor ymm1, ymm1, ymm11",
            "vmovdqa [{e} + 32], ymm1",
            "vpandn ymm2, ymm13, ymm14",
            "vpxor ymm2, ymm2, ymm12",
            "vmovdqa [{e} + 64], ymm2",
            "vpandn ymm3, ymm14, ymm10",
            "vpxor ymm3, ymm3, ymm13",
            "vmovdqa [{e} + 96], ymm3",
            "vpandn ymm4, ymm10, ymm11",
            "vpxor ymm4, ymm4, ymm14",
            "vmovdqa [{e} + 128], ymm4",
            // Row 1: rho and pi bring five lanes in, chi sends them
            // out, and each joins the parity of its column.
            "vpxor ymm10, ymm8, [{a} + 96]",
            "vpsllq ymm15, ymm10, 28",
            "vpsrlq ymm10, ymm10, 36",
            "vpor ymm10, ymm10, ymm15",
            "vpxor ymm11, ymm9, [{a} + 288]",
            "vpsllq ymm15, ymm11, 20",
            "vpsrlq ymm11, ymm11, 44",
            "vpor ymm11, ymm11, ymm15",
            "vpxor ymm12, ymm5, [{a} + 320]",
            "vpsllq ymm15, ymm12, 3",
            "vpsrlq ymm12, ymm12, 61",
            "vpor ymm12, ymm12, ymm15",
            "vpxor ymm13, ymm6, [{a} + 512]",
            "vpsllq ymm15, ymm13, 45",
            "vpsrlq ymm13, ymm13, 19",
            "vpor ymm13, ymm13, ymm15",
            "vpxor ymm14, ymm7, [{a} + 704]",
            "vpsllq ymm15, ymm14, 61",
            "vpsrlq ymm14, ymm14, 3",
            "vpor ymm14, ymm14, ymm15",
            "vpandn ymm15, ymm11, ymm12",
            "vpxor ymm15, ymm15, ymm10",
            "vmovdqa [{e} + 160], ymm15",
            "vpxor ymm0, ymm0, ymm15",
            "vpandn ymm15, ymm12, ymm13",
            "vpxor ymm15, ymm15, ymm11",
            "vmovdqa [{e} + 192], ymm15",
            "vpxor ymm1, ymm1, ymm15",
            "vpandn ymm15, ymm13, ymm14",
            "vpxor ymm15, ymm15, ymm12",
            "vmovdqa [{e} + 224], ymm15",
            "vpxor ymm2, ymm2, ymm15",
            "vpandn ymm15, ymm14, ymm10",
            "vpxor ymm15, ymm15, ymm13",
            "vmovdqa [{e} + 256], ymm15",
            "vpxor ymm3, ymm3, ymm15",
            "vpandn ymm15, ymm10, ymm11",
            "vpxor ymm15, ymm15, ymm14",
            "vmovdqa [{e} + 288], ymm15",
            "vpxor ymm4, ymm4, ymm15",
            // Row 2: rho and pi bring five lanes in, chi sends them
            // out, and each joins the parity of its column.
            "vpxor ymm10, ymm6, [{a} + 32]",
            "vpsllq ymm15, ymm10, 1",
            "vpsrlq ymm10, ymm10, 63",
            "vpor ymm10, ymm10, ymm15",
            "vpxor ymm11, ymm7, [{a} + 224]",
            "vpsllq ymm15, ymm11, 6",
            "vpsrlq ymm11, ymm11, 58",
            "vpor ymm11, ymm11, ymm15",
            "vpxor ymm12, ymm8, [{a} + 416]",
            "vpsllq ymm15, ymm12, 25",
            "vpsrlq ymm12, ymm12, 39",
            "vpor ymm12, ymm12, ymm15",
            "vpxor ymm13, ymm9, [{a} + 608]",
            "vpsllq ymm15, ymm13, 8",
            "vpsrlq ymm13, ymm13, 56",
            "vpor ymm13, ymm13, ymm15",
            "vpxor ymm14, ymm5, [{a} + 640]",
            "vpsllq ymm15, ymm14, 18",
            "vpsrlq ymm14, ymm14, 46",
            "vpor ymm14, ymm14, ymm15",
            "vpandn ymm15, ymm11, ymm12",
            "vpxor ymm15, ymm15, ymm10",
            "vmovdqa [{e} + 320], ymm15",
            "vpxor ymm0, ymm0, ymm15",
            "vpandn ymm15, ymm12, ymm13",
            "vpxor ymm15, ymm15, ymm11",
            "vmovdqa [{e} + 352], ymm15",
            "vpxor ymm1, ymm1, ymm15",
            "vpandn ymm15, ymm13, ymm14",
            "vpxor ymm15, ymm15, ymm12",
            "vmovdqa [{e} + 384], ymm15",
            "vpxor ymm2, ymm2, ymm15",
            "vpandn ymm15, ymm14, ymm10",
            "vpxor ymm15, ymm15, ymm13",
            "vmovdqa [{e} + 416], ymm15",
            "vpxor ymm3, ymm3, ymm15",
            "vpandn ymm15, ymm10, ymm11",
            "vpxor ymm15, ymm15, ymm14",
            "vmovdqa [{e} + 448], ymm15",
            "vpxor ymm4, ymm4, ymm15",
            // Row 3: rho and pi bring five lanes in, chi sends them
            // out, and each joins the parity of its column.
            "vpxor ymm10, ymm9, [{a} + 128]",
            "vpsllq ymm15, ymm10, 27",
            "vpsrlq ymm10, ymm10, 37",
            "vpor ymm10, ymm10, ymm15",
            "vpxor ymm11, ymm5, [{a} + 160]",
            "vpsllq ymm15, ymm11, 36",
            "vpsrlq ymm11, ymm11, 28",
            "vpor ymm11, ymm11, ymm15",
            "vpxor ymm12, ymm6, [{a} + 352]",
            "vpsllq ymm15, ymm12, 10",
            "vpsrlq ymm12, ymm12, 54",
            "vpor ymm12, ymm12, ymm15",
            "vpxor ymm13, ymm7, [{a} + 544]",
            "vpsllq ymm15, ymm13, 15",
            "vpsrlq ymm13, ymm13, 49",
            "vpor ymm13, ymm13, ymm15",
            "vpxor ymm14, ymm8, [{a} + 736]",
            "vpsllq ymm15, ymm14, 56",
            "vpsrlq ymm14, ymm14, 8",
            "vpor ymm14, ymm14, ymm15",
            "vpandn ymm15, ymm11, ymm12",
            "vpxor ymm15, ymm15, ymm10",
            "vmovdqa [{e} + 480], ymm15",
            "vpxor ymm0, ymm0, ymm15",
            "vpandn ymm15, ymm12, ymm13",
            "vpxor ymm15, ymm15, ymm11",
            "vmovdqa [{e} + 512], ymm15",
            "vpxor ymm1, ymm1, ymm15",
            "vpandn ymm15, ymm13, ymm14",
            "vpxor ymm15, ymm15, ymm12",
            "vmovdqa [{e} + 544], ymm15",
            "vpxor ymm2, ymm2, ymm15",
            "vpandn ymm15, ymm14, ymm10",
            "vpxor ymm15, ymm15, ymm13",
            "vmovdqa [{e} + 576], ymm15",
            "vpxor ymm3, ymm3, ymm15",
            "vpandn ymm15, ymm10, ymm11",
            "vpxor ymm15, ymm15, ymm14",
            "vmovdqa [{e} + 608], ymm15",
            "vpxor ymm4, ymm4, ymm15",
            // Row 4: rho and pi bring five lanes in, chi sends them
            // out, and each joins the parity of its column.
            "vpxor ymm10, ymm7, [{a} + 64]",
            "vpsllq ymm15, ymm10, 62",
            "vpsrlq ymm10, ymm10, 2",
            "vpor ymm10, ymm10, ymm15",
            "vpxor ymm11, ymm8, [{a} + 256]",
            "vpsllq ymm15, ymm11, 55",
            "vpsrlq ymm11, ymm11, 9",
            "vpor ymm11, ymm11, ymm15",
            "vpxor ymm12, ymm9, [{a} + 448]",
            "vpsllq ymm15, ymm12, 39",
            "vpsrlq ymm12, ymm12, 25",
            "vpor ymm12, ymm12, ymm15",
            "vpxor ymm13, ymm5, [{a} + 480]",
            "vpsllq ymm15, ymm13, 41",
            "vpsrlq ymm13, ymm13, 23",
            "vpor ymm13, ymm13, ymm15",
            "vpxor ymm14, ymm6, [{a} + 672]",
            "vpsllq ymm15, ymm14, 2",
            "vpsrlq ymm14, ymm14, 62",
            "vpor ymm14, ymm14, ymm15",
            "vpandn ymm15, ymm11, ymm12",
            "vpxor ymm15, ymm15, ymm10",
            "vmovdqa [{e} + 640], ymm15",
            "vpxor ymm0, ymm0, ymm15",
            "vpandn ymm15, ymm12, ymm13",
            "vpxor ymm15, ymm15, ymm11",
            "vmovdqa [{e} + 672], ymm15",
            "vpxor ymm1, ymm1, ymm15",
            "vpandn ymm15, ymm13, ymm14",
            "vpxor ymm15, ymm15, ymm12",
            "vmovdqa [{e} + 704], ymm15",
            "vpxor ymm2, ymm2, ymm15",
            "vpandn ymm15, ymm14, ymm10",
            "vpxor ymm15, ymm15, ymm13",
            "vmovdqa [{e} + 736], ymm15",
            "vpxor ymm3, ymm3, ymm15",
            "vpandn ymm15, ymm10, ymm11",
            "vpxor ymm15, ymm15, ymm14",
            "vmovdqa [{e} + 768], ymm15",
            "vpxor ymm4, ymm4, ymm15",
            // The copy just written is the next round's source. An
            // even number of rounds leaves the result where it began.
            "xchg {a}, {e}",
            "add {rc}, 32",
            "dec {n}",
            "jnz 2b",
            // Leaving the upper halves dirty would slow down whatever
            // plain SSE code runs next.
            "vzeroupper",
            a = inout(reg) state.0.as_mut_ptr() => _,
            e = inout(reg) other.0.as_mut_ptr() => _,
            rc = inout(reg) ROUND_CONSTANTS4.0.as_ptr() => _,
            n = inout(reg) ROUND_CONSTANTS4.0.len() => _,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
            out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
            options(nostack),
        );
    }
    // The round before last, of whatever was being hashed.
    other.0.zeroize();
}

/// The four-state permutation. No public constructor: a value exists
/// only by way of `of`.
#[derive(Clone, Copy)]
pub(crate) struct Avx2(());

impl Avx2 {
    /// The permutation, where the four-state list chose it.
    pub(crate) fn of(chosen: Chosen<super::together::Kernel>) -> Option<Self> {
        (chosen.kernel() == super::together::Kernel::Avx2).then_some(Avx2(()))
    }

    /// Applies the permutation to each of the four states.
    pub(crate) fn permute(self, state: &mut Four) {
        // SAFETY: `self` was minted by `of`, which confirmed the
        // instructions.
        unsafe { permute4(state) }
    }
}
