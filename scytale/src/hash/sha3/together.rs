//! SHAKE128 over several short messages at once.
//!
//! One sponge cannot be hurried: each permutation waits for the one
//! before it. Sponges that have nothing to do with each other can
//! share every instruction, a lane of each to a part of a wide
//! register: four to a 256-bit register with AVX2, at little more
//! than two would cost apart, and two to a 128-bit one with the
//! ARMv8.2 SHA3 instructions, which were being done to both halves
//! of the register all along.
//!
//! What asks for this is a matrix whose every entry is its own
//! SHAKE128 stream over a seed and two indices, as ML-KEM's is: the
//! messages are a few bytes, shorter than a block, and the output is
//! wanted a block at a time until enough of it has been kept. So
//! that is all this does. A message of a block or more, or output
//! taken in other pieces, goes through [`Shake128`](super::Shake128)
//! as ever, and so does everything where no row below but the last
//! is in force.

use crate::features::{self, Features};

/// How the streams are run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Kernel {
    /// Four together, a lane of each in a 256-bit register.
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// Two together, a lane of each in a 128-bit register, on the
    /// ARMv8.2 SHA3 instructions.
    #[cfg(target_arch = "aarch64")]
    Armv8,
    /// One after another, on whatever permutation one stream gets.
    Apart,
}

features::kernels! {
    enum Kernel;

    /// The kernels, best first. Four states in 256-bit registers need
    /// AVX2 and the operating system keeping them (AVX); two in
    /// 128-bit registers need the ARMv8.2 SHA-3 instructions.
    pub(crate) const KERNELS for shake128_together
        tested by crate::kem::ml_kem::tests::together = [
        #[cfg(target_arch = "x86_64")]
        Avx2 => (x86_64: Avx, Avx2),
        #[cfg(target_arch = "aarch64")]
        Armv8 => (aarch64: Sha3),
        Apart => (),
    ];
}

/// What the list publishes: the needs, without the names.
pub(crate) const PROFILES: [Features; KERNELS.len()] =
    features::profiles_of(KERNELS);

/// SHAKE128's rate: the bytes of output a permutation yields.
pub(crate) const RATE: usize = 168;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) use wide::{Shake128Together, WIDTH};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod wide {
    use zeroize::Zeroize;

    use super::super::engine::LANES;
    use super::RATE;
    use crate::align::At32;
    use crate::features::Chosen;

    #[cfg(target_arch = "aarch64")]
    use super::super::aarch64::Pair as Permutation;
    #[cfg(target_arch = "x86_64")]
    use super::super::x86_64::Avx2 as Permutation;

    /// How many streams this architecture's kernel runs together.
    #[cfg(target_arch = "x86_64")]
    pub(crate) const WIDTH: usize = 4;
    /// How many streams this architecture's kernel runs together.
    #[cfg(target_arch = "aarch64")]
    pub(crate) const WIDTH: usize = 2;

    /// [`WIDTH`] SHAKE128 streams, each over its own message, squeezed
    /// a block of each at a time.
    pub(crate) struct Shake128Together {
        /// `state[i][s]` is lane `i` of stream `s`.
        state: At32<[[u64; WIDTH]; LANES]>,
        /// The permutation, which is the proof the processor can
        /// run it.
        permutation: Permutation,
        /// Whether the block the state now holds has been read, so
        /// that the next read permutes first and the last block
        /// wanted is not followed by a permutation nobody reads.
        read: bool,
    }

    impl Shake128Together {
        /// The streams over `messages`, or `None` where the list
        /// chose to run them apart.
        pub(crate) fn new<const M: usize>(
            messages: [&[u8; M]; WIDTH],
            chosen: Chosen<super::Kernel>,
        ) -> Option<Self> {
            // Shorter than a block, so the padding ends the first
            // block and there is exactly one to absorb.
            const { assert!(M < RATE) };
            let permutation = Permutation::of(chosen)?;
            let mut state = At32([[0; WIDTH]; LANES]);
            for (s, message) in messages.iter().enumerate() {
                let mut block = [0u8; RATE];
                block[..M].copy_from_slice(*message);
                // The four bits that say SHAKE with the first
                // padding bit after them, and the last padding bit.
                block[M] ^= 0x1f;
                block[RATE - 1] ^= 0x80;
                let (lanes, _) = block.as_chunks::<8>();
                for (i, lane) in lanes.iter().enumerate() {
                    state.0[i][s] = u64::from_le_bytes(*lane);
                }
                block.zeroize();
            }
            permutation.permute(&mut state);
            Some(Shake128Together {
                state,
                permutation,
                read: false,
            })
        }

        /// The next block of each stream.
        pub(crate) fn squeeze(&mut self, out: &mut [[u8; RATE]; WIDTH]) {
            if self.read {
                self.permutation.permute(&mut self.state);
            }
            self.read = true;
            for (s, block) in out.iter_mut().enumerate() {
                let (lanes, _) = block.as_chunks_mut::<8>();
                for (i, lane) in lanes.iter_mut().enumerate() {
                    *lane = self.state.0[i][s].to_le_bytes();
                }
            }
        }
    }

    impl Drop for Shake128Together {
        fn drop(&mut self) {
            self.state.0.zeroize();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    use crate::features::Chosen;

    /// Each row can be chosen, the last needs nothing, and the
    /// streams are run together exactly when the first row the set
    /// in force meets says so.
    #[test]
    fn dispatches_by_the_list() {
        features::build_alone(|| {
            let chosen = features::choose(KERNELS).expect("listed");
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            let built = match Shake128Together::new([&[0u8; 1]; WIDTH], chosen)
            {
                Some(_) => KERNELS[0].0,
                None => Kernel::Apart,
            };
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            let built = chosen.kernel();
            features::dispatches(KERNELS, &PROFILES, built);
        });
    }

    /// The streams together are the streams apart: over messages
    /// that differ, so that a lane in the wrong stream shows, at the
    /// shortest and longest lengths there are and the one ML-KEM
    /// uses, and for more blocks than a matrix entry ever takes.
    ///
    /// Run by the kernel's meta test, under the kernel's own choice.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) fn together_agrees_with_apart(chosen: Chosen<Kernel>) {
        use super::super::Shake128;
        use crate::hash::{Xof, XofReader};

        fn check<const M: usize>(chosen: Chosen<Kernel>) {
            let messages: [[u8; M]; WIDTH] = core::array::from_fn(|s| {
                core::array::from_fn(|i| (i * 7 + s * 59 + M) as u8)
            });
            // The row that runs them apart has nothing to compare.
            let Some(mut wide) =
                Shake128Together::new(messages.each_ref(), chosen)
            else {
                return;
            };
            let mut readers = messages.each_ref().map(|message| {
                let mut xof = Shake128::new();
                xof.update(message);
                xof.finalize_xof()
            });
            for block in 0..6 {
                let mut together = [[0u8; RATE]; WIDTH];
                wide.squeeze(&mut together);
                for (s, reader) in readers.iter_mut().enumerate() {
                    let mut apart = [0u8; RATE];
                    reader.squeeze(&mut apart);
                    assert_eq!(together[s], apart, "{M} {block} {s}");
                }
            }
        }
        check::<0>(chosen);
        check::<1>(chosen);
        check::<34>(chosen);
        check::<166>(chosen);
        check::<167>(chosen);
    }
}
