//! GHASH multiplication on RISC-V.
//!
//! Three different extensions can do this work, and a processor may
//! have any one of them without the others, so there is a backend for
//! each and the choice is made once, the first time a hash starts.
//!
//! * [`zvkg`] has `vgmul`, which performs the whole field
//!   multiplication, reduction included, in one instruction. It is
//!   the fastest and the first choice.
//! * [`zvbc`] has a vector carry-less multiply, which is the
//!   primitive x86 and ARM build this out of. Eight blocks are
//!   multiplied at once, one to a lane.
//! * [`zbc`] has the same primitive on the general registers, for a
//!   processor with no vector unit. Every processor with the scalar
//!   AES instructions has it, because Zkn pulls in Zbkc.
//!
//! The three are not alternatives a vendor picks between at whim:
//! `Zvkng` is `Zvkn` plus Zvkg, `Zvknc` is `Zvkn` plus Zvbc, and
//! `Zkn` includes Zbkc, so each of these is the only carry-less
//! multiply some real configuration has.
//!
//! # What is shared
//!
//! Both carry-less backends end the same way, and [`finish`] is that
//! ending: it corrects Karatsuba's middle product, folds it into the
//! outer thirds of the 256-bit result, and reduces. Only the multiply
//! itself differs, so each passes its own in.

#![allow(unsafe_code)]

#[cfg(test)]
use super::KERNELS;
use super::Kernel;
use crate::features::Chosen;

mod zbc;
mod zvbc;
pub(crate) mod zvkg;

/// The field polynomial `x^128 + x^7 + x^2 + x + 1` without its
/// leading term, written in GHASH's reversed bit order.
const POLYNOMIAL: u64 = 0xc200_0000_0000_0000;

/// The best multiply the extensions in `ext` offer, on a processor
/// whose vector registers are `bytes` wide.
#[cfg(test)]
fn best_of(ext: u64, bytes: usize) -> Option<Kernel> {
    let found = crate::arch::riscv64::detected_from(ext, bytes);
    KERNELS
        .iter()
        .find(|(_, needs)| needs.is_subset(found))
        .map(|(c, _)| *c)
}

/// The processor's carry-less multiply, whichever of the three it
/// is. A value exists only by way of [`probe`], so holding one is
/// holding the proof that the instructions are there, and the calls
/// on it are safe; which backend answers is carried in the value, so
/// there is no arm for "none".
#[derive(Clone, Copy)]
pub(crate) struct Multiply(Hw);

/// The three multiplies, which a [`Multiply`] names. Apart from
/// [`Kernel`] so that the portable row has no arm here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hw {
    Zvkg,
    Zvbc,
    Zbc,
}

impl Multiply {
    /// The multiply, where the kernel list chose one.
    pub(crate) fn of(chosen: Chosen<Kernel>) -> Option<Self> {
        match chosen.kernel() {
            Kernel::Zvkg => Some(Multiply(Hw::Zvkg)),
            Kernel::Zvbc => Some(Multiply(Hw::Zvbc)),
            Kernel::Zbc => Some(Multiply(Hw::Zbc)),
            Kernel::Portable => None,
        }
    }

    /// How many blocks the group multiply takes at once.
    pub(crate) fn group(self) -> usize {
        match self.0 {
            Hw::Zvkg => zvkg::GROUP,
            Hw::Zvbc => zvbc::GROUP,
            Hw::Zbc => zbc::GROUP,
        }
    }

    /// Prepares the subkey for [`Multiply::multiply`].
    pub(crate) fn prepare(self, h: &[u64; 2]) -> [u64; 2] {
        match self.0 {
            Hw::Zvkg => zvkg::prepare(h),
            Hw::Zvbc => zvbc::prepare(h),
            Hw::Zbc => zbc::prepare(h),
        }
    }

    /// Multiplies `value` by the prepared subkey `h`, in place.
    pub(crate) fn multiply(self, value: &mut [u64; 2], h: &[u64; 2]) {
        // SAFETY: `self` was minted by `of`, from the list's choice of
        // a row whose features were in force.
        unsafe {
            match self.0 {
                Hw::Zvkg => zvkg::multiply(value, h),
                Hw::Zvbc => zvbc::multiply(value, h),
                Hw::Zbc => zbc::multiply(value, h),
            }
        }
    }

    /// Multiplies in the whole of `blocks`, which is
    /// [`group`](Multiply::group) blocks, leaving the running hash in
    /// `value`. `powers` holds the prepared powers of the subkey, `H`
    /// first.
    pub(crate) fn multiply_group(
        self,
        value: &mut [u64; 2],
        powers: &[[u64; 2]; super::MAX_GROUP],
        blocks: &[u8],
    ) {
        // Two of the three loops walk exactly their own group from
        // the pointer, so a shorter slice reads past the end. The
        // check is here rather than a `debug_assert` inside the
        // unsafe functions, which a release build removes.
        assert_eq!(blocks.len(), self.group() * super::BLOCK);
        // SAFETY: as for `multiply`, and the length was just checked.
        unsafe {
            match self.0 {
                Hw::Zvkg => zvkg::multiply_group(value, powers, blocks),
                Hw::Zvbc => zvbc::multiply_group(value, powers, blocks),
                Hw::Zbc => zbc::multiply_group(value, powers, blocks),
            }
        }
    }
}

/// Finishes a field multiplication from its three Karatsuba pieces,
/// given a carry-less multiply. The scalar backend uses this; the
/// vector one has no scalar multiply to give and reduces inside its
/// own block instead.
///
/// `lo`, `m` and `hi` are the products of the operands' low halves,
/// of their halves added together, and of their high halves, each
/// least significant word first. `m` is the raw product, not yet
/// corrected; since every piece is a sum over however many blocks
/// went into it, and the correction is linear, it can be applied once
/// here rather than once a block.
///
/// The result is the field product in register order, least
/// significant word first.
fn finish(
    lo: [u64; 2],
    m: [u64; 2],
    hi: [u64; 2],
    wide: impl Fn(u64, u64) -> [u64; 2],
) -> [u64; 2] {
    // Karatsuba's middle term is the sum of the two cross products,
    // which this recovers from the product of the sums.
    let mid = [m[0] ^ lo[0] ^ hi[0], m[1] ^ lo[1] ^ hi[1]];
    // It belongs half in each end of the 256-bit result.
    let lo = [lo[0], lo[1] ^ mid[0]];
    let hi = [hi[0] ^ mid[1], hi[1]];

    // Fold the low half down in two steps. Each multiplication by
    // the polynomial moves one word's worth of excess up, and
    // exchanging the halves in between lets the same step do both.
    let p = wide(POLYNOMIAL, lo[0]);
    let s = [lo[1] ^ p[0], lo[0] ^ p[1]];
    let q = wide(POLYNOMIAL, s[0]);
    [hi[0] ^ s[1] ^ q[0], hi[1] ^ s[0] ^ q[1]]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which backend each kind of real processor is given. The choice
    /// is a function of the extension bit set, so this is the whole of
    /// the dispatch rather than a sample of it, and it covers
    /// combinations no emulator offers.
    #[test]
    fn the_choice_follows_the_extensions() {
        use crate::arch::riscv64::profile;

        // The vector profiles that carry a multiply, and the ones
        // that carry none.
        assert_eq!(best_of(profile::ZVKNG, 16), Some(Kernel::Zvkg));
        assert_eq!(best_of(profile::ZVKNC, 16), Some(Kernel::Zvbc));
        assert_eq!(best_of(profile::ZVKN, 16), Some(Kernel::Portable));
        assert_eq!(best_of(profile::RVA23, 16), Some(Kernel::Portable));

        // Zkn has no vector unit and Zbkc with it, which is the whole
        // reason the scalar backend exists.
        assert_eq!(best_of(profile::ZKN, 0), Some(Kernel::Zbc));

        // Zvkg wins wherever it is, whatever else is there.
        assert_eq!(
            best_of(profile::ZVKNG | profile::ZVKNC | profile::ZKN, 16),
            Some(Kernel::Zvkg)
        );
        // The scalar multiply is taken over nothing, even beside a
        // vector unit that cannot help.
        assert_eq!(
            best_of(profile::RVA23 | profile::ZKN, 16),
            Some(Kernel::Zbc)
        );

        // Registers too narrow for a 128-bit element group put the
        // vector backends out, and a vector profile has nothing else.
        assert_eq!(best_of(profile::ZVKNG, 8), Some(Kernel::Portable));
        assert_eq!(best_of(profile::ZVKNC, 8), Some(Kernel::Portable));
        // A processor with none of it has nothing.
        assert_eq!(best_of(0, 0), Some(Kernel::Portable));
    }
}
