//! SHAKE128 over four short messages at once.
//!
//! One sponge cannot be hurried: each permutation waits for the one
//! before it. Four sponges that have nothing to do with each other
//! can share every instruction, a lane of each to a quarter of a
//! wide register, and where the processor has such registers the
//! four cost little more than two would apart.
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

/// How the four streams are run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Kernel {
    /// Together, a lane of each in a 256-bit register.
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// One after another, on whatever permutation one stream gets.
    Apart,
}

/// The kernels, best first, each with what it needs.
pub(crate) const KERNELS: &[(Kernel, Features)] = &[
    #[cfg(target_arch = "x86_64")]
    (Kernel::Avx2, super::x86_64::AVX2),
    (Kernel::Apart, Features::new()),
];

/// What the list publishes: the needs, without the names.
pub(crate) const PROFILES: [Features; KERNELS.len()] =
    features::profiles_of(KERNELS);

/// SHAKE128's rate: the bytes of output a permutation yields.
pub(crate) const RATE: usize = 168;

#[cfg(target_arch = "x86_64")]
pub(crate) use together::Shake128x4;

#[cfg(target_arch = "x86_64")]
mod together {
    use zeroize::Zeroize;

    use super::super::engine::LANES;
    use super::super::x86_64::{Avx2, Four};
    use super::RATE;
    use crate::align::At32;

    /// Four SHAKE128 streams, each over its own message, squeezed a
    /// block of each at a time.
    pub(crate) struct Shake128x4 {
        state: Four,
        /// The permutation, which is the proof the processor can
        /// run it.
        avx2: Avx2,
        /// Whether the block the state now holds has been read, so
        /// that the next read permutes first and the last block
        /// wanted is not followed by a permutation nobody reads.
        read: bool,
    }

    impl Shake128x4 {
        /// The four streams over `messages`, or `None` where the
        /// features in force have no kernel that runs them
        /// together.
        pub(crate) fn new<const M: usize>(
            messages: [&[u8; M]; 4],
        ) -> Option<Self> {
            // Shorter than a block, so the padding ends the first
            // block and there is exactly one to absorb.
            const { assert!(M < RATE) };
            let avx2 = Avx2::probe()?;
            let mut state: Four = At32([[0; 4]; LANES]);
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
            avx2.permute(&mut state);
            Some(Shake128x4 {
                state,
                avx2,
                read: false,
            })
        }

        /// The next block of each stream.
        pub(crate) fn squeeze(&mut self, out: &mut [[u8; RATE]; 4]) {
            if self.read {
                self.avx2.permute(&mut self.state);
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

    impl Drop for Shake128x4 {
        fn drop(&mut self) {
            self.state.0.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each row can be chosen, the last needs nothing, and the
    /// streams are run together exactly when the first row the set
    /// in force meets says so.
    #[test]
    fn dispatches_by_the_list() {
        #[cfg(target_arch = "x86_64")]
        let built = match Shake128x4::new([&[0u8; 1]; 4]) {
            Some(_) => Kernel::Avx2,
            None => Kernel::Apart,
        };
        #[cfg(not(target_arch = "x86_64"))]
        let built = Kernel::Apart;
        features::dispatches(KERNELS, &PROFILES, built);
    }

    /// Four streams together are the four apart: over messages that
    /// differ, so that a lane in the wrong stream shows, at the
    /// shortest and longest lengths there are and the one ML-KEM
    /// uses, and for more blocks than a matrix entry ever takes.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn together_agrees_with_apart() {
        use super::super::Shake128;
        use crate::hash::{Xof, XofReader};

        fn check<const M: usize>() {
            let messages: [[u8; M]; 4] = core::array::from_fn(|s| {
                core::array::from_fn(|i| (i * 7 + s * 59 + M) as u8)
            });
            let Some(mut four) = Shake128x4::new(messages.each_ref()) else {
                std::eprintln!("no kernel runs four together; skipping");
                return;
            };
            let mut readers = messages.each_ref().map(|message| {
                let mut xof = Shake128::new();
                xof.update(message);
                xof.finalize_xof()
            });
            for block in 0..6 {
                let mut together = [[0u8; RATE]; 4];
                four.squeeze(&mut together);
                for (s, reader) in readers.iter_mut().enumerate() {
                    let mut apart = [0u8; RATE];
                    reader.squeeze(&mut apart);
                    assert_eq!(together[s], apart, "{M} {block} {s}");
                }
            }
        }
        check::<0>();
        check::<1>();
        check::<34>();
        check::<166>();
        check::<167>();
    }
}
