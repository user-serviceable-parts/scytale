//! SHA-256 with the SHA-NI instructions, and SHA-512 with AVX2, on
//! x86-64.
//!
//! `sha256rnds2` does two rounds on a pair of registers holding the
//! state as `ABEF` and `CDGH`, and `sha256msg1` and `sha256msg2`
//! between them do the message schedule four words at a time. The
//! whole compression is written out here, sixty-four rounds unrolled,
//! because the register rotation between four-round groups is fixed
//! and a loop would spend its time moving registers around.
//!
//! SHA-512 has no such instructions before the SHA512 extension. What
//! AVX2 offers is the message schedule four 64-bit words at a time;
//! the rounds stay scalar, one long dependency chain, with `rorx` for
//! the rotations and `andn` for the choice.

#![allow(unsafe_code)]

use zeroize::Zeroize;

use crate::features;

use super::engine::{Compress32, Compress64};
#[cfg(test)]
use super::engine::{Engine32, Engine64};
use super::portable::{K256, K512};
#[cfg(test)]
use super::variant;
use crate::align::{At16, At32};

// Named for the vector suites, which drive each engine in turn; the
// dispatching types reach it directly.
/// SHA-224 with SHA-NI.
#[cfg(test)]
pub type Sha224 = Engine32<ShaNi, variant::Sha224>;
/// SHA-256 with SHA-NI.
#[cfg(test)]
pub type Sha256 = Engine32<ShaNi, variant::Sha256>;
/// SHA-384 with AVX2.
#[cfg(test)]
pub type Sha384 = Engine64<Avx2, variant::Sha384>;
/// SHA-512 with AVX2.
#[cfg(test)]
pub type Sha512 = Engine64<Avx2, variant::Sha512>;

/// Whether the processor reports SHA-NI (CPUID leaf 7, EBX bit 29).
/// Every such processor also has the SSSE3 and SSE4.1 shuffles the
/// code uses.
pub(crate) fn has_sha() -> bool {
    features::allows(super::KERNELS32, super::Kernel::ShaNi)
}

/// The compression function via SHA-NI.
// No public constructor: a value exists only by way of `probe`.
#[derive(Clone, Copy)]
pub struct ShaNi(());

impl super::engine::Sealed for ShaNi {}

impl Compress32 for ShaNi {
    fn probe() -> Option<Self> {
        has_sha().then_some(ShaNi(()))
    }

    fn compress(self, state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        // SAFETY: `self` was minted by `probe`, which confirmed the
        // instructions.
        unsafe {
            if !blocks.is_empty() {
                compress(state, blocks.as_ptr().cast(), blocks.len());
            }
        }
    }
}

static BYTE_SWAP: At16<[u8; 16]> =
    At16([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]);

/// Four rounds from constant byte offset `$i`: adds the constants to
/// the four message words in `$m0`, runs two `sha256rnds2` on them,
/// and advances the schedule. `$m0` through `$m3` are the last
/// sixteen words, oldest first.
// Kept as written: one instruction per line.
#[rustfmt::skip]
macro_rules! rounds4 {
    ($i:literal, $m0:literal, $m1:literal, $m2:literal, $m3:literal) => {
        concat!(
            "movdqu xmm0, [{k} + ", $i, "]\n",
            "paddd xmm0, ", $m0, "\n",
            "sha256rnds2 xmm2, xmm1\n",
            "pshufd xmm0, xmm0, 0x0e\n",
            "sha256rnds2 xmm1, xmm2\n",
            rounds4!(@schedule $i, $m0, $m1, $m2, $m3),
        )
    };
    // Words 16 to 63 are made from the previous sixteen; each group
    // finishes the words the group after next will need.
    (@schedule $i:literal, $m0:literal, $m1:literal, $m2:literal,
     $m3:literal) => {
        concat!(
            rounds4!(@msg2 $i, $m0, $m1, $m3),
            rounds4!(@msg1 $i, $m0, $m3),
        )
    };
    (@msg2 $i:literal, $m0:literal, $m1:literal, $m3:literal) => {
        concat!(
            "movdqa xmm7, ", $m0, "\n",
            "palignr xmm7, ", $m3, ", 4\n",
            "paddd ", $m1, ", xmm7\n",
            "sha256msg2 ", $m1, ", ", $m0, "\n",
        )
    };
    (@msg1 $i:literal, $m0:literal, $m3:literal) => {
        concat!("sha256msg1 ", $m3, ", ", $m0, "\n")
    };
}

/// Loads four message words from byte offset `$i`, big-endian.
// Kept as written: one instruction per line.
#[rustfmt::skip]
macro_rules! load4 {
    ($i:literal, $m:literal) => {
        concat!(
            "movdqu ", $m, ", [{data} + ", $i, "]\n",
            "pshufb ", $m, ", xmm8\n",
        )
    };
}

/// Folds `count` blocks at `data` into `state`.
///
/// # Safety
/// Requires SHA-NI, SSSE3 and SSE4.1; `data` must point at `count`
/// whole blocks.
unsafe fn compress(state: &mut [u32; 8], data: *const u8, count: usize) {
    unsafe {
        // State words a..h in memory become ABEF in xmm1 and CDGH in
        // xmm2, the layout the instructions want, and are put back at
        // the end.
        core::arch::asm!(
            "movdqu xmm1, [{state}]",
            "movdqu xmm2, [{state} + 16]",
            "movdqa xmm8, [{swap}]",
            "pshufd xmm1, xmm1, 0xb1",
            "pshufd xmm2, xmm2, 0x1b",
            "movdqa xmm7, xmm1",
            "palignr xmm1, xmm2, 8",
            "pblendw xmm2, xmm7, 0xf0",

            "2:",
            "movdqa xmm9, xmm1",
            "movdqa xmm10, xmm2",

            // Rounds 0 to 15: load, then round, then start the schedule.
            load4!(0, "xmm3"),
            "movdqu xmm0, [{k}]",
            "paddd xmm0, xmm3",
            "sha256rnds2 xmm2, xmm1",
            "pshufd xmm0, xmm0, 0x0e",
            "sha256rnds2 xmm1, xmm2",

            load4!(16, "xmm4"),
            "movdqu xmm0, [{k} + 16]",
            "paddd xmm0, xmm4",
            "sha256rnds2 xmm2, xmm1",
            "pshufd xmm0, xmm0, 0x0e",
            "sha256rnds2 xmm1, xmm2",
            "sha256msg1 xmm3, xmm4",

            load4!(32, "xmm5"),
            "movdqu xmm0, [{k} + 32]",
            "paddd xmm0, xmm5",
            "sha256rnds2 xmm2, xmm1",
            "pshufd xmm0, xmm0, 0x0e",
            "sha256rnds2 xmm1, xmm2",
            "sha256msg1 xmm4, xmm5",

            load4!(48, "xmm6"),
            rounds4!(48, "xmm6", "xmm3", "xmm4", "xmm5"),
            // Rounds 16 to 51: full schedule.
            rounds4!(64, "xmm3", "xmm4", "xmm5", "xmm6"),
            rounds4!(80, "xmm4", "xmm5", "xmm6", "xmm3"),
            rounds4!(96, "xmm5", "xmm6", "xmm3", "xmm4"),
            rounds4!(112, "xmm6", "xmm3", "xmm4", "xmm5"),
            rounds4!(128, "xmm3", "xmm4", "xmm5", "xmm6"),
            rounds4!(144, "xmm4", "xmm5", "xmm6", "xmm3"),
            rounds4!(160, "xmm5", "xmm6", "xmm3", "xmm4"),
            rounds4!(176, "xmm6", "xmm3", "xmm4", "xmm5"),
            rounds4!(192, "xmm3", "xmm4", "xmm5", "xmm6"),
            // Rounds 52 to 59: msg2 only, the last words to finish.
            "movdqu xmm0, [{k} + 208]",
            "paddd xmm0, xmm4",
            "sha256rnds2 xmm2, xmm1",
            "pshufd xmm0, xmm0, 0x0e",
            "sha256rnds2 xmm1, xmm2",
            "movdqa xmm7, xmm4",
            "palignr xmm7, xmm3, 4",
            "paddd xmm5, xmm7",
            "sha256msg2 xmm5, xmm4",

            "movdqu xmm0, [{k} + 224]",
            "paddd xmm0, xmm5",
            "sha256rnds2 xmm2, xmm1",
            "pshufd xmm0, xmm0, 0x0e",
            "sha256rnds2 xmm1, xmm2",
            "movdqa xmm7, xmm5",
            "palignr xmm7, xmm4, 4",
            "paddd xmm6, xmm7",
            "sha256msg2 xmm6, xmm5",

            // Rounds 60 to 63.
            "movdqu xmm0, [{k} + 240]",
            "paddd xmm0, xmm6",
            "sha256rnds2 xmm2, xmm1",
            "pshufd xmm0, xmm0, 0x0e",
            "sha256rnds2 xmm1, xmm2",

            "paddd xmm1, xmm9",
            "paddd xmm2, xmm10",
            "add {data}, 64",
            "dec {count}",
            "jnz 2b",

            "pshufd xmm1, xmm1, 0x1b",
            "pshufd xmm2, xmm2, 0xb1",
            "movdqa xmm7, xmm1",
            "pblendw xmm1, xmm2, 0xf0",
            "palignr xmm2, xmm7, 8",
            "movdqu [{state}], xmm1",
            "movdqu [{state} + 16], xmm2",
            state = in(reg) state.as_mut_ptr(),
            k = in(reg) K256.as_ptr(),
            swap = in(reg) BYTE_SWAP.0.as_ptr(),
            data = inout(reg) data => _,
            count = inout(reg) count => _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _,
            options(nostack),
        );
    }
}

/// Whether the features in force allow the AVX2 SHA-512 kernel.
pub(crate) fn has_avx2() -> bool {
    features::allows(super::KERNELS64, super::Kernel::Avx2)
}

/// The SHA-512 compression function with an AVX2 message schedule.
// No public constructor: a value exists only by way of `probe`.
#[derive(Clone, Copy)]
pub struct Avx2(());

impl super::engine::Sealed for Avx2 {}

impl Compress64 for Avx2 {
    fn probe() -> Option<Self> {
        has_avx2().then_some(Avx2(()))
    }

    fn compress(self, state: &mut [u64; 8], blocks: &[[u8; 128]]) {
        if blocks.is_empty() {
            return;
        }
        // SAFETY: `self` was minted by `probe`, which confirmed the
        // instructions.
        unsafe { compress512(state, blocks.as_ptr().cast(), blocks.len()) }
    }
}

/// Reverses the bytes of each 64-bit word, in both 128-bit lanes.
static SWAP64: At32<[u8; 32]> = At32([
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, //
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
]);

/// Everything the SHA-512 loop keeps in memory, behind one register:
/// the scalar rounds want every general register they can get, and
/// this leaves them ten.
#[repr(C, align(32))]
struct Frame {
    /// The schedule words of the block, each with its round constant
    /// already added.
    wk: [u64; 80],
    state: [u64; 8],
    data: *const u8,
    count: usize,
}

/// Four schedule words, `W[t..t+4]`, from the sixteen before them in
/// `$x0` (oldest) to `$x3`, written over `$x0`; then the same words
/// plus their round constants, stored at byte offset `$off` of the
/// frame. `ymm4` to `ymm7` are scratch. It comes in four parts, one
/// to follow each of four rounds, so that the vector work runs on
/// the ports the scalar rounds leave idle rather than ahead of them.
// Kept as written: one instruction per line.
#[rustfmt::skip]
macro_rules! schedule4 {
    (1, $x0:literal, $x1:literal, $x2:literal, $x3:literal) => {
        concat!(
            // W[t-15] to W[t-12], and W[t-7] to W[t-4]: each four
            // straddle two registers, and `vpalignr` works within
            // 128-bit lanes, so the lanes are lined up first.
            "vperm2i128 ymm4, ", $x0, ", ", $x1, ", 0x21\n",
            "vpalignr ymm4, ymm4, ", $x0, ", 8\n",
            "vperm2i128 ymm5, ", $x2, ", ", $x3, ", 0x21\n",
            "vpalignr ymm5, ymm5, ", $x2, ", 8\n",
            "vpaddq ymm5, ymm5, ", $x0, "\n",
            // sigma0: rotations by 1 and 8, a shift by 7. A rotation
            // is two shifts whose bits do not meet, so all five are
            // simply XORed.
            "vpsrlq ymm6, ymm4, 1\n",
            "vpsllq ymm7, ymm4, 63\n",
            "vpxor ymm6, ymm6, ymm7\n",
        )
    };
    (2, $x0:literal, $x1:literal, $x2:literal, $x3:literal) => {
        concat!(
            "vpsrlq ymm7, ymm4, 8\n",
            "vpxor ymm6, ymm6, ymm7\n",
            "vpsllq ymm7, ymm4, 56\n",
            "vpxor ymm6, ymm6, ymm7\n",
            "vpsrlq ymm7, ymm4, 7\n",
            "vpxor ymm6, ymm6, ymm7\n",
            "vpaddq ymm5, ymm5, ymm6\n",
        )
    };
    (3, $x0:literal, $x1:literal, $x2:literal, $x3:literal) => {
        concat!(
            // sigma1 needs W[t-2] and W[t-1], which finishes the first
            // two words; the second two need those, so the low half
            // is done first, the high half left zero.
            "vperm2i128 ymm4, ", $x3, ", ", $x3, ", 0x81\n",
            schedule4!(@sigma1),
            "vpaddq ymm5, ymm5, ymm6\n",
        )
    };
    (4, $off:literal, $x0:literal) => {
        concat!(
            "vperm2i128 ymm4, ymm5, ymm5, 0x08\n",
            schedule4!(@sigma1),
            "vpaddq ", $x0, ", ymm5, ymm6\n",
            "vpaddq ymm7, ", $x0, ", [rip + {k} + ", $off, "]\n",
            "vmovdqa [{w} + ", $off, "], ymm7\n",
        )
    };
    // sigma1 of ymm4 into ymm6: rotations by 19 and 61, a shift by 6.
    (@sigma1) => {
        concat!(
            "vpsrlq ymm6, ymm4, 19\n",
            "vpsllq ymm7, ymm4, 45\n",
            "vpxor ymm6, ymm6, ymm7\n",
            "vpsrlq ymm7, ymm4, 61\n",
            "vpxor ymm6, ymm6, ymm7\n",
            "vpsllq ymm7, ymm4, 3\n",
            "vpxor ymm6, ymm6, ymm7\n",
            "vpsrlq ymm7, ymm4, 6\n",
            "vpxor ymm6, ymm6, ymm7\n",
        )
    };
}

/// One round, on the word at byte offset `$off` of the frame. The
/// registers are named for the state words they hold; the caller
/// rotates the names, so no value moves. `h` becomes the new `a` and
/// `d` the new `e`.
// Kept as written: one instruction per line.
#[rustfmt::skip]
macro_rules! round {
    ($a:literal, $b:literal, $c:literal, $d:literal, $e:literal,
     $f:literal, $g:literal, $h:literal, $off:expr) => {
        concat!(
            "add ", $h, ", [{w} + ", $off, "]\n",
            // Sigma1(e).
            "rorx {t1}, ", $e, ", 41\n",
            "rorx {t2}, ", $e, ", 18\n",
            "xor {t1}, {t2}\n",
            "rorx {t2}, ", $e, ", 14\n",
            "xor {t1}, {t2}\n",
            "add ", $h, ", {t1}\n",
            // Ch(e, f, g): the two halves share no bits, so they add.
            "andn {t1}, ", $e, ", ", $g, "\n",
            "add ", $h, ", {t1}\n",
            "mov {t2}, ", $f, "\n",
            "and {t2}, ", $e, "\n",
            "add ", $h, ", {t2}\n",
            "add ", $d, ", ", $h, "\n",
            // Sigma0(a).
            "rorx {t1}, ", $a, ", 39\n",
            "rorx {t2}, ", $a, ", 34\n",
            "xor {t1}, {t2}\n",
            "rorx {t2}, ", $a, ", 28\n",
            "xor {t1}, {t2}\n",
            "add ", $h, ", {t1}\n",
            // Maj(a, b, c) as (a & b) + (c & (a ^ b)), whose halves
            // also share no bits.
            "mov {t1}, ", $a, "\n",
            "xor {t1}, ", $b, "\n",
            "and {t1}, ", $c, "\n",
            "add ", $h, ", {t1}\n",
            "mov {t2}, ", $a, "\n",
            "and {t2}, ", $b, "\n",
            "add ", $h, ", {t2}\n",
        )
    };
}

/// Eight rounds from byte offset `$off`, after which the names are
/// back where they started. Given two more offsets and the schedule
/// registers, oldest first, it also computes the eight words due
/// sixteen rounds on, four into `$x0` then four into `$x1`, which
/// leaves the registers to be named from `$x2` next time.
// Kept as written: one round per line.
#[rustfmt::skip]
macro_rules! rounds8 {
    ($off:literal) => {
        concat!(
            round!("{a}", "{b}", "{c}", "{d}", "{e}", "{f}", "{g}", "{h}",
                concat!($off, " + 0")),
            round!("{h}", "{a}", "{b}", "{c}", "{d}", "{e}", "{f}", "{g}",
                concat!($off, " + 8")),
            round!("{g}", "{h}", "{a}", "{b}", "{c}", "{d}", "{e}", "{f}",
                concat!($off, " + 16")),
            round!("{f}", "{g}", "{h}", "{a}", "{b}", "{c}", "{d}", "{e}",
                concat!($off, " + 24")),
            round!("{e}", "{f}", "{g}", "{h}", "{a}", "{b}", "{c}", "{d}",
                concat!($off, " + 32")),
            round!("{d}", "{e}", "{f}", "{g}", "{h}", "{a}", "{b}", "{c}",
                concat!($off, " + 40")),
            round!("{c}", "{d}", "{e}", "{f}", "{g}", "{h}", "{a}", "{b}",
                concat!($off, " + 48")),
            round!("{b}", "{c}", "{d}", "{e}", "{f}", "{g}", "{h}", "{a}",
                concat!($off, " + 56")),
        )
    };
    ($off:literal, $s0:literal, $s1:literal,
     $x0:literal, $x1:literal, $x2:literal, $x3:literal) => {
        concat!(
            round!("{a}", "{b}", "{c}", "{d}", "{e}", "{f}", "{g}", "{h}",
                concat!($off, " + 0")),
            schedule4!(1, $x0, $x1, $x2, $x3),
            round!("{h}", "{a}", "{b}", "{c}", "{d}", "{e}", "{f}", "{g}",
                concat!($off, " + 8")),
            schedule4!(2, $x0, $x1, $x2, $x3),
            round!("{g}", "{h}", "{a}", "{b}", "{c}", "{d}", "{e}", "{f}",
                concat!($off, " + 16")),
            schedule4!(3, $x0, $x1, $x2, $x3),
            round!("{f}", "{g}", "{h}", "{a}", "{b}", "{c}", "{d}", "{e}",
                concat!($off, " + 24")),
            schedule4!(4, $s0, $x0),
            round!("{e}", "{f}", "{g}", "{h}", "{a}", "{b}", "{c}", "{d}",
                concat!($off, " + 32")),
            schedule4!(1, $x1, $x2, $x3, $x0),
            round!("{d}", "{e}", "{f}", "{g}", "{h}", "{a}", "{b}", "{c}",
                concat!($off, " + 40")),
            schedule4!(2, $x1, $x2, $x3, $x0),
            round!("{c}", "{d}", "{e}", "{f}", "{g}", "{h}", "{a}", "{b}",
                concat!($off, " + 48")),
            schedule4!(3, $x1, $x2, $x3, $x0),
            round!("{b}", "{c}", "{d}", "{e}", "{f}", "{g}", "{h}", "{a}",
                concat!($off, " + 56")),
            schedule4!(4, $s1, $x1),
        )
    };
}

/// Folds `count` blocks at `data` into `state`.
///
/// # Safety
/// Requires AVX2, BMI1 and BMI2; `data` must point at `count` whole
/// blocks, and `count` must not be zero.
unsafe fn compress512(state: &mut [u64; 8], data: *const u8, count: usize) {
    let mut frame = Frame {
        wk: [0; 80],
        state: *state,
        data,
        count,
    };
    unsafe {
        core::arch::asm!(
            "mov {a}, [{w} + {st}]",
            "mov {b}, [{w} + {st} + 8]",
            "mov {c}, [{w} + {st} + 16]",
            "mov {d}, [{w} + {st} + 24]",
            "mov {e}, [{w} + {st} + 32]",
            "mov {f}, [{w} + {st} + 40]",
            "mov {g}, [{w} + {st} + 48]",
            "mov {h}, [{w} + {st} + 56]",
            "vmovdqa ymm8, [rip + {swap}]",

            "2:",
            // The first sixteen words, into the frame; the rest are
            // made among the rounds, each sixteen rounds before it is
            // needed.
            "mov {t1}, [{w} + {dp}]",
            "vmovdqu ymm0, [{t1}]",
            "vmovdqu ymm1, [{t1} + 32]",
            "vmovdqu ymm2, [{t1} + 64]",
            "vmovdqu ymm3, [{t1} + 96]",
            "add {t1}, 128",
            "mov [{w} + {dp}], {t1}",
            "vpshufb ymm0, ymm0, ymm8",
            "vpshufb ymm1, ymm1, ymm8",
            "vpshufb ymm2, ymm2, ymm8",
            "vpshufb ymm3, ymm3, ymm8",
            "vpaddq ymm4, ymm0, [rip + {k}]",
            "vmovdqa [{w}], ymm4",
            "vpaddq ymm4, ymm1, [rip + {k} + 32]",
            "vmovdqa [{w} + 32], ymm4",
            "vpaddq ymm4, ymm2, [rip + {k} + 64]",
            "vmovdqa [{w} + 64], ymm4",
            "vpaddq ymm4, ymm3, [rip + {k} + 96]",
            "vmovdqa [{w} + 96], ymm4",
            rounds8!("0", "128", "160", "ymm0", "ymm1", "ymm2", "ymm3"),
            rounds8!("64", "192", "224", "ymm2", "ymm3", "ymm0", "ymm1"),
            rounds8!("128", "256", "288", "ymm0", "ymm1", "ymm2", "ymm3"),
            rounds8!("192", "320", "352", "ymm2", "ymm3", "ymm0", "ymm1"),
            rounds8!("256", "384", "416", "ymm0", "ymm1", "ymm2", "ymm3"),
            rounds8!("320", "448", "480", "ymm2", "ymm3", "ymm0", "ymm1"),
            rounds8!("384", "512", "544", "ymm0", "ymm1", "ymm2", "ymm3"),
            rounds8!("448", "576", "608", "ymm2", "ymm3", "ymm0", "ymm1"),
            rounds8!("512"),
            rounds8!("576"),

            "add {a}, [{w} + {st}]",
            "mov [{w} + {st}], {a}",
            "add {b}, [{w} + {st} + 8]",
            "mov [{w} + {st} + 8], {b}",
            "add {c}, [{w} + {st} + 16]",
            "mov [{w} + {st} + 16], {c}",
            "add {d}, [{w} + {st} + 24]",
            "mov [{w} + {st} + 24], {d}",
            "add {e}, [{w} + {st} + 32]",
            "mov [{w} + {st} + 32], {e}",
            "add {f}, [{w} + {st} + 40]",
            "mov [{w} + {st} + 40], {f}",
            "add {g}, [{w} + {st} + 48]",
            "mov [{w} + {st} + 48], {g}",
            "add {h}, [{w} + {st} + 56]",
            "mov [{w} + {st} + 56], {h}",
            "dec qword ptr [{w} + {n}]",
            "jnz 2b",
            // Leaving the upper halves dirty would slow down whatever
            // plain SSE code runs next.
            "vzeroupper",
            w = in(reg) &raw mut frame,
            st = const core::mem::offset_of!(Frame, state),
            dp = const core::mem::offset_of!(Frame, data),
            n = const core::mem::offset_of!(Frame, count),
            k = sym K512,
            swap = sym SWAP64,
            a = out(reg) _, b = out(reg) _, c = out(reg) _, d = out(reg) _,
            e = out(reg) _, f = out(reg) _, g = out(reg) _, h = out(reg) _,
            t1 = out(reg) _, t2 = out(reg) _,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _,
            options(nostack),
        );
    }
    *state = frame.state;
    // The schedule is the message, and the state is the hash so far.
    frame.wk.zeroize();
    frame.state.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::hash::sha2::portable;
    use crate::hash::sha2::tests::check_known_answers;

    #[test]
    fn known_answers() {
        if !has_sha() {
            return;
        }
        type Sha384 = portable::Sha384;
        type Sha512 = portable::Sha512;
        check_known_answers(
            || Sha224::try_new().expect("supported"),
            || Sha256::try_new().expect("supported"),
            || Sha384::try_new().expect("supported"),
            || Sha512::try_new().expect("supported"),
        );
    }

    #[test]
    fn probe_agrees_with_constructor() {
        assert_eq!(Sha256::try_new().is_ok(), has_sha());
        if !has_sha() {
            assert_eq!(Sha256::try_new().err(), Some(Error::NotSupported));
        }
    }

    #[test]
    fn avx2_known_answers() {
        if !has_avx2() {
            return;
        }
        type Sha224 = portable::Sha224;
        type Sha256 = portable::Sha256;
        check_known_answers(
            || Sha224::try_new().expect("supported"),
            || Sha256::try_new().expect("supported"),
            || Sha384::try_new().expect("supported"),
            || Sha512::try_new().expect("supported"),
        );
    }

    #[test]
    fn avx2_probe_agrees_with_constructor() {
        assert_eq!(Sha512::try_new().is_ok(), has_avx2());
        if !has_avx2() {
            assert_eq!(Sha512::try_new().err(), Some(Error::NotSupported));
        }
    }

    /// Every block count from one to nine through one call, against
    /// the portable code, so that the loop, and the state it carries
    /// from block to block, are tested and not only a single block.
    #[test]
    fn avx2_matches_portable_over_many_blocks() {
        if !has_avx2() {
            return;
        }
        let mut blocks = [[0u8; 128]; 9];
        for (i, b) in blocks.iter_mut().flatten().enumerate() {
            *b = (i as u8).wrapping_mul(167).wrapping_add(13);
        }
        use crate::hash::sha2::engine::Variant64;
        let avx2 = Avx2::probe().expect("supported");
        for n in 1..=blocks.len() {
            let mut ours = variant::Sha512::IV;
            let mut theirs = ours;
            avx2.compress(&mut ours, &blocks[..n]);
            Compress64::compress(portable::Compress, &mut theirs, &blocks[..n]);
            assert_eq!(ours, theirs, "{n} blocks");
        }
    }
}
