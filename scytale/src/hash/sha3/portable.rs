//! Keccak-f\[1600\] in plain Rust, for any processor.
//!
//! Twenty-four rounds of the five steps FIPS 202 names, theta, rho,
//! pi, chi and iota, on the 5 by 5 array of 64-bit lanes. The lane
//! rotations are by constants and there are no lookup tables, so the
//! time taken depends on nothing but the length of the message.

// Only the trait impl is unsafe, and it calls safe code.
#[cfg(test)]
use super::engine::Sponge;
use super::engine::{LANES, Permutation};
#[cfg(test)]
use super::variant;
use crate::features::Chosen;

/// SHA3-256, portably.
#[cfg(test)]
pub type Sha3_256 = Sponge<Keccak, variant::Sha3_256>;
/// SHAKE128, portably.
#[cfg(test)]
pub type Shake128 = Sponge<Keccak, variant::Shake128>;

/// The round constants, one per round, for iota.
pub(crate) static ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// The rho rotation of each lane, indexed as the state is, x + 5y.
const ROTATIONS: [u32; LANES] = [
    0, 1, 62, 28, 27, //
    36, 44, 6, 55, 20, //
    3, 10, 43, 25, 39, //
    41, 45, 15, 21, 8, //
    18, 2, 61, 56, 14,
];

/// Applies Keccak-f\[1600\] to `a`.
///
/// Inlined always, so that the x86-64 build for BMI compiles it
/// afresh with those instructions allowed.
#[inline(always)]
pub(crate) fn keccak_f1600(a: &mut [u64; LANES]) {
    for &rc in &ROUND_CONSTANTS {
        // Theta: each lane takes the parity of two columns.
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }

        // Rho and pi: rotate each lane and move it to (y, 2x + 3y).
        let mut b = [0u64; LANES];
        for x in 0..5 {
            for y in 0..5 {
                let to = y + 5 * ((2 * x + 3 * y) % 5);
                b[to] = a[x + 5 * y].rotate_left(ROTATIONS[x + 5 * y]);
            }
        }

        // Chi: each lane takes the two after it in its row.
        for y in 0..5 {
            let row = &b[5 * y..5 * y + 5];
            for x in 0..5 {
                a[x + 5 * y] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }

        // Iota.
        a[0] ^= rc;
    }
}

/// The permutation in plain Rust.
#[derive(Clone, Copy)]
pub struct Keccak;

impl super::engine::Sealed for Keccak {}

impl Permutation for Keccak {
    fn of(_: Chosen<super::Kernel>) -> Option<Self> {
        Some(Keccak)
    }

    fn permute(self, state: &mut [u64; LANES]) {
        keccak_f1600(state)
    }
}
