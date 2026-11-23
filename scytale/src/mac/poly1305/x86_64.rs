//! Poly1305 over four message blocks at a time, for processors with
//! AVX2.
//!
//! # Why four at once
//!
//! The definition is a chain: each block is added to the running value
//! and the sum multiplied by `r`, so a block cannot start until the
//! one before it has finished. Nothing about that is parallel.
//!
//! It becomes parallel the way GHASH does, by writing the polynomial
//! out. A message of `4K` blocks has
//!
//! ```text
//! P = sum over i of m_i r^(4K+1-i)
//! ```
//!
//! and splitting the blocks by their position within each group of
//! four gives four chains, each stepping by `r^4` and none waiting on
//! another:
//!
//! ```text
//! P = A_0 r^4 + A_1 r^3 + A_2 r^2 + A_3 r
//! where A_j = sum over k of m_(4k+j) (r^4)^(K-1-k)
//! ```
//!
//! The four chains are the four lanes of a 256-bit register, so the
//! loop below does one multiplication by `r^4` for every four blocks.
//!
//! # The limbs
//!
//! Five limbs of 26 bits, rather than the three of 44 the portable
//! code uses: `vpmuludq` multiplies the low 32 bits of each 64-bit
//! lane, so 26 is as wide as a limb can be and still leave room for
//! a product and the sum of five of them.
//!
//! # Between calls
//!
//! The four chains stay in their lanes from one call to the next, and
//! become one value only when the message ends. Turning them into the
//! portable code's three limbs and back on every call cost more than
//! the multiply itself for a short run, and nothing needs them as one
//! value before the end.
//!
//! # What is left to the caller
//!
//! The key's powers and the last carries. Each happens once for a
//! message rather than once for a group, so neither is worth the
//! assembly, and the arithmetic that is easiest to get wrong stays
//! where it can be read. The weights at the end are in the assembly
//! after all: done as four scalar products they were two thirds of
//! the cost of a 64-byte message.

#![allow(unsafe_code)]

use super::Kernel;
use crate::features::Chosen;
use zeroize::Zeroize;

/// Bytes in a block.
const BLOCK: usize = 16;

/// Blocks the loop takes at once: the lanes of a 256-bit register.
pub(super) const LANES: usize = 4;

/// Bytes in one group.
pub(super) const SPAN: usize = LANES * BLOCK;

/// A limb's worth of ones.
const MASK: u64 = (1 << 26) - 1;

/// Limbs in a value: 130 bits at 26 bits each.
const LIMBS: usize = 5;

/// The tables the loop reads, laid out as it wants them and aligned
/// so that a load of one is a single operation.
///
/// The first five are the limbs of `r^4`, each in every lane; then
/// the upper four of them times five, which is what a limb carried
/// past the top of the field is worth; then the limb mask; then the
/// bit that sits above a whole block.
#[repr(align(32))]
#[derive(Clone)]
struct Tables([[u64; LANES]; 11]);

/// Everything worked out from the key, once.
#[derive(Clone)]
pub(super) struct Powers {
    tables: Tables,
    /// The weight each lane's chain is multiplied by at the end,
    /// laid out as `tables` is but a different value in each lane:
    /// `r^4`, `r^3`, `r^2` and `r`, in the order the loads below
    /// leave the lanes. The last two of the eleven rows are unused.
    weights: Tables,
}

// Every word here is worked out from `r`, and the last weight is `r`
// itself: the one-time key. Not `Copy`, so that there is one of these
// to wipe and not a copy left on the frame of whatever was handed
// one; the loop reaches it by reference.
impl Drop for Powers {
    fn drop(&mut self) {
        self.tables.0.zeroize();
        self.weights.0.zeroize();
    }
}

/// Multiplies two values in the field, with the limbs carried far
/// enough that another multiplication cannot overflow.
///
/// Plain integer arithmetic: this runs a handful of times for a key
/// and never in the loop.
fn multiply(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> [u64; LIMBS] {
    let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
    // A limb carried past the top is worth five of the bottom, since
    // the field is the integers modulo 2^130 - 5.
    let five = |x: u64| 5 * x;
    let mut d = [0u128; LIMBS];
    for (k, d) in d.iter_mut().enumerate() {
        for (i, &a) in a.iter().enumerate() {
            let j = (k + LIMBS - i) % LIMBS;
            let term = if i + j == k { b[j] } else { five(b[j]) };
            *d += wide(a, term);
        }
    }
    carry(d)
}

/// Brings a row of products down to five limbs of 26 bits.
fn carry(d: [u128; LIMBS]) -> [u64; LIMBS] {
    let mut out = [0u64; LIMBS];
    let mut c = 0u128;
    for (out, d) in out.iter_mut().zip(d) {
        let v = d + c;
        *out = (v as u64) & MASK;
        c = v >> 26;
    }
    // What came off the top re-enters at the bottom, five times over.
    out[0] += 5 * (c as u64);
    let c = out[0] >> 26;
    out[0] &= MASK;
    out[1] += c;
    out
}

impl Powers {
    /// The powers of `r`, which arrives as the three limbs the
    /// portable code clamped it into.
    pub(super) fn new(r: &[u64; 3]) -> Self {
        let r = &from_thirds(r);
        let r2 = multiply(r, r);
        let r3 = multiply(&r2, r);
        let r4 = multiply(&r2, &r2);

        let mut tables = Tables([[0u64; LANES]; 11]);
        for (k, &limb) in r4.iter().enumerate() {
            tables.0[k] = [limb; LANES];
        }
        for (k, &limb) in r4[1..].iter().enumerate() {
            tables.0[5 + k] = [5 * limb; LANES];
        }
        tables.0[9] = [MASK; LANES];
        tables.0[10] = [1 << 24; LANES];

        // The loads in the loop leave the group's blocks in the lane
        // order 0, 2, 1, 3, so the weights take that order too.
        let lanes = [&r4, &r2, &r3, r];
        let mut weights = Tables([[0u64; LANES]; 11]);
        for k in 0..LIMBS {
            weights.0[k] = core::array::from_fn(|lane| lanes[lane][k]);
        }
        for k in 1..LIMBS {
            weights.0[4 + k] = core::array::from_fn(|lane| 5 * lanes[lane][k]);
        }
        Powers { tables, weights }
    }
}

/// Five limbs in each lane, aligned as the tables are.
#[repr(align(32))]
#[derive(Clone)]
struct Limbs([[u64; LANES]; LIMBS]);

/// The four chains of a message under way.
#[derive(Clone)]
pub(super) struct Lanes {
    limbs: Limbs,
    /// Whether a group has gone in since the message began. Until one
    /// has, the limbs hold nothing of this message, and the loop
    /// starts from registers it clears rather than from memory: zeros
    /// written here and read straight back as whole registers stall
    /// the load for longer than the rest of a group takes.
    started: bool,
}

impl Lanes {
    pub(super) fn new() -> Self {
        Lanes {
            limbs: Limbs([[0; LANES]; LIMBS]),
            started: false,
        }
    }

    /// Whether any of the message is in the chains.
    pub(super) fn started(&self) -> bool {
        self.started
    }

    /// Forgets the message, wiping what it left.
    pub(super) fn clear(&mut self) {
        if self.started {
            self.limbs.0.zeroize();
            self.started = false;
        }
    }
}

// A function of the key and the message, like the running value.
impl Drop for Lanes {
    fn drop(&mut self) {
        self.limbs.0.zeroize();
    }
}

/// The proof the kernel list chose the vector loop. No public
/// constructor: a value exists only by way of [`Avx2::of`].
#[derive(Clone, Copy, Debug)]
pub(super) struct Avx2(());

impl Avx2 {
    /// The vector loop, where the list chose it.
    pub(super) fn of(chosen: Chosen<Kernel>) -> Option<Self> {
        (chosen.kernel() == Kernel::Avx2).then_some(Avx2(()))
    }
}

/// Runs `data`, a whole number of groups, through the four chains.
///
/// `data` must be at least one group; the caller splits it so, and
/// this is a debug check on that rather than a branch on every call.
pub(super) fn bulk(_: Avx2, lanes: &mut Lanes, powers: &Powers, data: &[u8]) {
    debug_assert!(!data.is_empty() && data.len().is_multiple_of(SPAN));
    // SAFETY: the `Avx2` passed is the proof the list chose this
    // kernel, so the processor has its instructions; `lanes` is the
    // five limbs the loop expects, the tables are the ones built
    // beside them, and `data` is whole groups.
    unsafe {
        multiply_groups(
            lanes.limbs.0.as_mut_ptr().cast::<u64>(),
            usize::from(lanes.started),
            powers.tables.0.as_ptr().cast::<u64>(),
            data.as_ptr(),
            data.len() / SPAN,
        );
    }
    lanes.started = true;
}

/// The four chains as one value: the running value of the message so
/// far, as the three limbs of 44, 44 and 42 bits the portable code
/// keeps, so that it can take the last blocks on from here.
///
/// The chains must have started; a message with nothing in them has
/// nothing to collapse.
pub(super) fn collapse(lanes: &Lanes, powers: &Powers) -> [u64; 3] {
    debug_assert!(lanes.started);
    let mut sums = [0u64; LIMBS];
    // SAFETY: as for `bulk`, with the weights built beside the tables
    // and `sums` room for five limbs.
    unsafe {
        weigh(
            lanes.limbs.0.as_ptr().cast::<u64>(),
            powers.weights.0.as_ptr().cast::<u64>(),
            sums.as_mut_ptr(),
        );
    }
    into_thirds(&reduce(sums))
}

/// Carries five limbs down to 26 bits each, all the way.
///
/// `into_thirds` joins the limbs with OR, which is right only when no
/// limb has a bit above its 26: a single pass of carries can leave
/// one limb at exactly `2^26`, when the fold from the top tips the
/// bottom over and that carry lands on a limb already full. Three
/// passes cannot: the second leaves a carry of at most one from the
/// top, and the third can only fold that into a bottom limb it has
/// just emptied.
fn reduce(mut limbs: [u64; LIMBS]) -> [u64; LIMBS] {
    for _ in 0..3 {
        let mut c = 0;
        for limb in limbs.iter_mut() {
            let v = *limb + c;
            *limb = v & MASK;
            c = v >> 26;
        }
        limbs[0] += 5 * c;
    }
    limbs
}

/// The five limbs of a value kept as three.
fn from_thirds(h: &[u64; 3]) -> [u64; LIMBS] {
    let w0 = h[0] | (h[1] << 44);
    let w1 = (h[1] >> 20) | (h[2] << 24);
    let w2 = h[2] >> 40;
    [
        w0 & MASK,
        (w0 >> 26) & MASK,
        ((w0 >> 52) | (w1 << 12)) & MASK,
        (w1 >> 14) & MASK,
        ((w1 >> 40) | (w2 << 24)) & MASK,
    ]
}

/// The other way round.
fn into_thirds(limbs: &[u64; LIMBS]) -> [u64; 3] {
    let w0 = limbs[0] | (limbs[1] << 26) | (limbs[2] << 52);
    let w1 = (limbs[2] >> 12) | (limbs[3] << 14) | (limbs[4] << 40);
    let w2 = limbs[4] >> 24;
    [
        w0 & ((1 << 44) - 1),
        ((w0 >> 44) | (w1 << 20)) & ((1 << 44) - 1),
        ((w1 >> 24) | (w2 << 40)) & ((1 << 42) - 1),
    ]
}

/// One term of the product: limb `$k` of the result takes limb `$i`
/// of the running value times the table entry `$t`.
macro_rules! term {
    ($k:literal, $i:literal, $t:literal) => {
        term!("r", $k, $i, $t)
    };
    ($base:literal, $k:literal, $i:literal, $t:literal) => {
        concat!(
            "vpmuludq ymm15, ymm",
            $i,
            ", [{",
            $base,
            "} + ",
            $t,
            "*32]\n",
            "vpaddq ymm",
            $k,
            ", ymm",
            $k,
            ", ymm15\n",
        )
    };
}

/// The first term of a limb, which starts it rather than adding to it.
macro_rules! first {
    ($k:literal, $i:literal, $t:literal) => {
        first!("r", $k, $i, $t)
    };
    ($base:literal, $k:literal, $i:literal, $t:literal) => {
        concat!(
            "vpmuludq ymm",
            $k,
            ", ymm",
            $i,
            ", [{",
            $base,
            "} + ",
            $t,
            "*32]\n"
        )
    };
}

/// The four lanes of `ymm$k` added together, stored as limb `$k - 5`
/// of the result.
macro_rules! fold {
    ($k:literal, $at:literal) => {
        concat!(
            "vextracti128 xmm15, ymm",
            $k,
            ", 1\n",
            "vpaddq xmm",
            $k,
            ", xmm",
            $k,
            ", xmm15\n",
            "vpshufd xmm15, xmm",
            $k,
            ", 0x4e\n",
            "vpaddq xmm",
            $k,
            ", xmm",
            $k,
            ", xmm15\n",
            "vmovq [{out} + ",
            $at,
            "], xmm",
            $k,
            "\n",
        )
    };
}

/// One limb's carry into the next.
macro_rules! step {
    ($from:literal, $to:literal, $into:literal) => {
        concat!(
            "vpsrlq ymm15, ymm",
            $from,
            ", 26\n",
            "vpand ymm",
            $into,
            ", ymm",
            $from,
            ", [{r} + 9*32]\n",
            "vpaddq ymm",
            $to,
            ", ymm",
            $to,
            ", ymm15\n",
        )
    };
}

/// Runs `groups` groups of four blocks through the four chains held
/// at `a`, and leaves them there. When `started` is zero the chains
/// begin at zero and what is at `a` is not read.
///
/// # Safety
/// Requires AVX2. `a` must point at five lanes-wide limbs of the
/// chains, aligned to 32 bytes, `r` at the tables, and `data` at
/// `groups * 64` bytes. `groups` must not be zero.
unsafe fn multiply_groups(
    a: *mut u64,
    started: usize,
    r: *const u64,
    data: *const u8,
    groups: usize,
) {
    unsafe {
        core::arch::asm!(
            "test {started}, {started}",
            "jz 3f",
            "vmovdqa ymm0, [{a} + 0*32]",
            "vmovdqa ymm1, [{a} + 1*32]",
            "vmovdqa ymm2, [{a} + 2*32]",
            "vmovdqa ymm3, [{a} + 3*32]",
            "vmovdqa ymm4, [{a} + 4*32]",
            "jmp 2f",
            "3:",
            "vpxor xmm0, xmm0, xmm0",
            "vpxor xmm1, xmm1, xmm1",
            "vpxor xmm2, xmm2, xmm2",
            "vpxor xmm3, xmm3, xmm3",
            "vpxor xmm4, xmm4, xmm4",

            "2:",
            // Four blocks. The unpacks put the four low words of the
            // blocks in one register and the four high words in
            // another, which leaves the lanes in the order 0, 2, 1, 3;
            // the weights at the end are in that order to match.
            "vmovdqu ymm5, [{data}]",
            "vmovdqu ymm6, [{data} + 32]",
            "vpunpcklqdq ymm7, ymm5, ymm6",
            "vpunpckhqdq ymm8, ymm5, ymm6",

            // Their five limbs, kept aside until after the multiply:
            // the running value is multiplied first and the blocks
            // added to the product, which is what the definition's
            // chain comes to when it is written out.
            "vpand ymm10, ymm7, [{r} + 9*32]",
            "vpsrlq ymm11, ymm7, 26",
            "vpand ymm11, ymm11, [{r} + 9*32]",
            "vpsrlq ymm12, ymm7, 52",
            "vpsllq ymm13, ymm8, 12",
            "vpor ymm12, ymm12, ymm13",
            "vpand ymm12, ymm12, [{r} + 9*32]",
            "vpsrlq ymm13, ymm8, 14",
            "vpand ymm13, ymm13, [{r} + 9*32]",
            "vpsrlq ymm14, ymm8, 40",
            // The bit that sits above a whole block.
            "vpor ymm14, ymm14, [{r} + 10*32]",

            // Multiply by r^4. Limbs that would pass the top of the
            // field come back at the bottom five times over, which is
            // what the second half of the table holds.
            first!(5, 0, 0),
            term!(5, 1, 8),
            term!(5, 2, 7),
            term!(5, 3, 6),
            term!(5, 4, 5),
            first!(6, 0, 1),
            term!(6, 1, 0),
            term!(6, 2, 8),
            term!(6, 3, 7),
            term!(6, 4, 6),
            first!(7, 0, 2),
            term!(7, 1, 1),
            term!(7, 2, 0),
            term!(7, 3, 8),
            term!(7, 4, 7),
            first!(8, 0, 3),
            term!(8, 1, 2),
            term!(8, 2, 1),
            term!(8, 3, 0),
            term!(8, 4, 8),
            first!(9, 0, 4),
            term!(9, 1, 3),
            term!(9, 2, 2),
            term!(9, 3, 1),
            term!(9, 4, 0),

            // Back down to 26 bits a limb.
            step!(5, 6, 0),
            step!(6, 7, 1),
            step!(7, 8, 2),
            step!(8, 9, 3),
            "vpsrlq ymm15, ymm9, 26",
            "vpand ymm4, ymm9, [{r} + 9*32]",
            // Five times what came off the top.
            "vpsllq ymm5, ymm15, 2",
            "vpaddq ymm15, ymm15, ymm5",
            "vpaddq ymm0, ymm0, ymm15",
            "vpsrlq ymm15, ymm0, 26",
            "vpand ymm0, ymm0, [{r} + 9*32]",
            "vpaddq ymm1, ymm1, ymm15",

            // And the blocks join the product.
            "vpaddq ymm0, ymm0, ymm10",
            "vpaddq ymm1, ymm1, ymm11",
            "vpaddq ymm2, ymm2, ymm12",
            "vpaddq ymm3, ymm3, ymm13",
            "vpaddq ymm4, ymm4, ymm14",

            "add {data}, 64",
            "dec {groups}",
            "jnz 2b",

            "vmovdqa [{a} + 0*32], ymm0",
            "vmovdqa [{a} + 1*32], ymm1",
            "vmovdqa [{a} + 2*32], ymm2",
            "vmovdqa [{a} + 3*32], ymm3",
            "vmovdqa [{a} + 4*32], ymm4",
            // Leaving the upper halves dirty would slow down whatever
            // plain SSE code runs next.
            "vzeroupper",
            a = in(reg) a,
            started = in(reg) started,
            r = in(reg) r,
            data = inout(reg) data => _,
            groups = inout(reg) groups => _,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
            out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
            options(nostack),
        );
    }
}

/// Weighs each of the four chains at `a` by its place and adds the
/// lanes together into `out`, as five limbs not yet carried.
///
/// # Safety
/// Requires AVX2. `a` must point at five lanes-wide limbs of the
/// chains, aligned to 32 bytes, `w` at the weights, and `out` at room
/// for five limbs.
unsafe fn weigh(a: *const u64, w: *const u64, out: *mut u64) {
    unsafe {
        core::arch::asm!(
            "vmovdqa ymm0, [{a} + 0*32]",
            "vmovdqa ymm1, [{a} + 1*32]",
            "vmovdqa ymm2, [{a} + 2*32]",
            "vmovdqa ymm3, [{a} + 3*32]",
            "vmovdqa ymm4, [{a} + 4*32]",
            // Each lane times its weight, the same product as the
            // loop's with a different multiplier in every lane. The
            // limbs are below 2^28 and the weights' below 2^29, so a
            // term is below 2^57, a limb of five terms below 2^60,
            // and the four lanes of one below 2^62: no carry is needed
            // before the lanes are added.
            first!("w", 5, 0, 0),
            term!("w", 5, 1, 8),
            term!("w", 5, 2, 7),
            term!("w", 5, 3, 6),
            term!("w", 5, 4, 5),
            first!("w", 6, 0, 1),
            term!("w", 6, 1, 0),
            term!("w", 6, 2, 8),
            term!("w", 6, 3, 7),
            term!("w", 6, 4, 6),
            first!("w", 7, 0, 2),
            term!("w", 7, 1, 1),
            term!("w", 7, 2, 0),
            term!("w", 7, 3, 8),
            term!("w", 7, 4, 7),
            first!("w", 8, 0, 3),
            term!("w", 8, 1, 2),
            term!("w", 8, 2, 1),
            term!("w", 8, 3, 0),
            term!("w", 8, 4, 8),
            first!("w", 9, 0, 4),
            term!("w", 9, 1, 3),
            term!("w", 9, 2, 2),
            term!("w", 9, 3, 1),
            term!("w", 9, 4, 0),
            fold!(5, "0"),
            fold!(6, "8"),
            fold!(7, "16"),
            fold!(8, "24"),
            fold!(9, "32"),
            "vzeroupper",
            a = in(reg) a,
            w = in(reg) w,
            out = in(reg) out,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
            out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
            options(nostack),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The case one pass of carries gets wrong: the fold from the top
    /// tips the bottom limb over, and its carry lands on a full limb.
    /// The value is `2^52 - 1 + 2^130`, which is `2^52 + 4` in the
    /// field.
    #[test]
    fn reduce_carries_all_the_way() {
        let full = MASK;
        let got = reduce([full, full, 0, 0, 1 << 26]);
        assert_eq!(got, [4, 0, 1, 0, 0]);
    }

    /// Limbs as large as the vector code can hand over come back
    /// within 26 bits, so that `into_thirds` may join them with OR.
    #[test]
    fn reduce_leaves_every_limb_within_its_bits() {
        for top in [0, 1, u64::MAX >> 2] {
            let got = reduce([u64::MAX >> 2, top, top, u64::MAX >> 3, top]);
            assert!(got.iter().all(|&limb| limb <= MASK), "{got:?}");
        }
    }
}
