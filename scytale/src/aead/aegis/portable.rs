//! AEGIS in plain Rust, for any target: for each variant, one kernel
//! over each of the two portable AES rounds.
//!
//! The bitsliced ones are constant time and are what a processor
//! without AES instructions gets. The table-driven ones are faster
//! and leak through cache timing exactly as the table-driven AES
//! does, so they are chosen only where
//! [`Isolated`](crate::features::Feature::Isolated) is in force.

/// AEGIS-128L over the bitsliced round.
///
/// The bitsliced code works on four blocks at once, and an update of
/// this state is eight rounds that do not depend on each other, so
/// one update is two groups of four with no lane left idle. The state
/// stays in bit planes for the whole of a call: only the message goes
/// in and out of them.
pub(super) mod bitsliced128l {
    use super::super::State;
    use crate::cipher::aes::portable::bitsliced::{
        State as Planes, pack, round, unpack,
    };

    /// Bytes to a block of input.
    const RATE: usize = 32;

    /// The bits of lane 0 in every plane. A lane is one block of the
    /// four, and lane `n` is these shifted left by `n`.
    const LANE: u64 = 0x1111_1111_1111_1111;

    /// The state in bit planes: S0 to S3 in the lanes of `low`, in
    /// order, and S4 to S7 in those of `high`.
    struct Sliced {
        low: Planes,
        high: Planes,
    }

    impl Sliced {
        fn load(state: &State) -> Self {
            let (low, high) = state.as_flattened().split_at(64);
            Sliced {
                low: pack(low),
                high: pack(high),
            }
        }

        fn store(&self, state: &mut State) {
            let (low, high) = state.as_flattened_mut().split_at_mut(64);
            unpack(&self.low, low);
            unpack(&self.high, high);
        }

        /// The draft's `Update`, for `message` holding M0 in lane 0
        /// and M1 in lane 1.
        ///
        /// Every block goes through the round and is xored into its
        /// successor, so the rounds' input is the state moved up one
        /// lane, S7 coming round into the lane S0 left.
        #[inline(always)]
        fn update(&mut self, message: &Planes) {
            let mut x = [0u64; 8];
            let mut y = [0u64; 8];
            for i in 0..8 {
                x[i] =
                    ((self.low[i] << 1) & !LANE) | ((self.high[i] >> 3) & LANE);
                y[i] =
                    ((self.high[i] << 1) & !LANE) | ((self.low[i] >> 3) & LANE);
            }
            round(&mut x);
            round(&mut y);
            for i in 0..8 {
                self.low[i] ^= x[i] ^ (message[i] & LANE);
                self.high[i] ^= y[i] ^ ((message[i] >> 1) & LANE);
            }
        }

        /// The keystream for the next block: z0 in lane 0 and z1 in
        /// lane 1, as a packed block of input lies.
        #[inline(always)]
        fn keystream(&self) -> Planes {
            core::array::from_fn(|i| {
                let lane = |planes: u64, n: u32| (planes >> n) & LANE;
                let (low, high) = (self.low[i], self.high[i]);
                let z0 = lane(low, 1)
                    ^ lane(high, 2)
                    ^ (lane(low, 2) & lane(low, 3));
                let z1 = lane(low, 2)
                    ^ lane(high, 1)
                    ^ (lane(high, 2) & lane(high, 3));
                z0 | (z1 << 1)
            })
        }
    }

    pub(in super::super) fn absorb(state: &mut State, blocks: &[u8]) {
        let mut sliced = Sliced::load(state);
        for block in blocks.chunks_exact(RATE) {
            sliced.update(&pack(block));
        }
        sliced.store(state);
    }

    pub(in super::super) fn encrypt(state: &mut State, data: &mut [u8]) {
        let mut sliced = Sliced::load(state);
        for block in data.chunks_exact_mut(RATE) {
            let message = pack(block);
            let keystream = sliced.keystream();
            let out: Planes =
                core::array::from_fn(|i| message[i] ^ keystream[i]);
            unpack(&out, block);
            sliced.update(&message);
        }
        sliced.store(state);
    }

    pub(in super::super) fn decrypt(state: &mut State, data: &mut [u8]) {
        let mut sliced = Sliced::load(state);
        for block in data.chunks_exact_mut(RATE) {
            let sealed = pack(block);
            let keystream = sliced.keystream();
            let message: Planes =
                core::array::from_fn(|i| sealed[i] ^ keystream[i]);
            unpack(&message, block);
            sliced.update(&message);
        }
        sliced.store(state);
    }
}

/// AEGIS-128L over the table-driven round, which leaks through cache
/// timing; see [`ttable`](crate::cipher::aes::portable::ttable).
pub(super) mod tables128l {
    use super::super::State;
    use super::super::aegis128l::keystream;
    use crate::cipher::aes::BLOCK_SIZE;
    use crate::cipher::aes::portable::ttable::round;

    /// Bytes to a block of input.
    const RATE: usize = 32;

    /// The draft's `Update`.
    fn update(state: &mut State, block: &[u8]) {
        let (m0, m1) = block.split_at(BLOCK_SIZE);
        let old = *state;
        for (i, next) in state.iter_mut().enumerate() {
            let mut key = old[i];
            let message = match i {
                0 => m0,
                4 => m1,
                _ => &[],
            };
            for (k, m) in key.iter_mut().zip(message) {
                *k ^= m;
            }
            *next = round(&old[(i + 7) % 8], &key);
        }
    }

    pub(in super::super) fn absorb(state: &mut State, blocks: &[u8]) {
        for block in blocks.chunks_exact(RATE) {
            update(state, block);
        }
    }

    pub(in super::super) fn encrypt(state: &mut State, data: &mut [u8]) {
        for block in data.chunks_exact_mut(RATE) {
            let z = keystream(state);
            let mut message = [0u8; RATE];
            message.copy_from_slice(block);
            for (byte, z) in block.iter_mut().zip(z) {
                *byte ^= z;
            }
            update(state, &message);
        }
    }

    pub(in super::super) fn decrypt(state: &mut State, data: &mut [u8]) {
        for block in data.chunks_exact_mut(RATE) {
            let z = keystream(state);
            for (byte, z) in block.iter_mut().zip(z) {
                *byte ^= z;
            }
            update(state, block);
        }
    }
}

/// AEGIS-256 over the bitsliced round.
///
/// An update is six rounds, so the second group of four runs with
/// two lanes idle; and since each update needs the one before it,
/// there is nothing to fill them with.
pub(super) mod bitsliced256 {
    use super::super::State;
    use crate::cipher::aes::portable::bitsliced::{
        State as Planes, pack, round, unpack,
    };

    /// Bytes to a block of input.
    const RATE: usize = 16;

    /// The bits of lane 0 in every plane; see
    /// [`bitsliced128l`](super::bitsliced128l).
    const LANE: u64 = 0x1111_1111_1111_1111;

    /// The state in bit planes: S0 to S3 in the lanes of `low`, in
    /// order, and S4 and S5 in the first two of `high`, whose other
    /// two are kept zero.
    struct Sliced {
        low: Planes,
        high: Planes,
    }

    impl Sliced {
        fn load(state: &State) -> Self {
            let (low, high) = state.as_flattened().split_at(64);
            Sliced {
                low: pack(low),
                high: pack(&high[..32]),
            }
        }

        fn store(&self, state: &mut State) {
            let (low, high) = state.as_flattened_mut().split_at_mut(64);
            unpack(&self.low, low);
            unpack(&self.high, &mut high[..32]);
        }

        /// The draft's `Update`, for `message` holding M in lane 0.
        ///
        /// As for AEGIS-128L, the rounds' input is the state moved
        /// up one lane, S5 coming round into the lane S0 left. The
        /// idle lanes go through the round too and come out as
        /// something, which is masked off.
        #[inline(always)]
        fn update(&mut self, message: &Planes) {
            let mut x = [0u64; 8];
            let mut y = [0u64; 8];
            for i in 0..8 {
                x[i] =
                    ((self.low[i] << 1) & !LANE) | ((self.high[i] >> 1) & LANE);
                y[i] = ((self.high[i] << 1) & (LANE << 1))
                    | ((self.low[i] >> 3) & LANE);
            }
            round(&mut x);
            round(&mut y);
            for i in 0..8 {
                self.low[i] ^= x[i] ^ (message[i] & LANE);
                self.high[i] ^= y[i] & (LANE | (LANE << 1));
            }
        }

        /// The keystream for the next block, in lane 0.
        #[inline(always)]
        fn keystream(&self) -> Planes {
            core::array::from_fn(|i| {
                let lane = |planes: u64, n: u32| (planes >> n) & LANE;
                let (low, high) = (self.low[i], self.high[i]);
                lane(low, 1)
                    ^ lane(high, 0)
                    ^ lane(high, 1)
                    ^ (lane(low, 2) & lane(low, 3))
            })
        }
    }

    pub(in super::super) fn absorb(state: &mut State, blocks: &[u8]) {
        let mut sliced = Sliced::load(state);
        for block in blocks.chunks_exact(RATE) {
            sliced.update(&pack(block));
        }
        sliced.store(state);
    }

    pub(in super::super) fn encrypt(state: &mut State, data: &mut [u8]) {
        let mut sliced = Sliced::load(state);
        for block in data.chunks_exact_mut(RATE) {
            let message = pack(block);
            let keystream = sliced.keystream();
            let out: Planes =
                core::array::from_fn(|i| message[i] ^ keystream[i]);
            unpack(&out, block);
            sliced.update(&message);
        }
        sliced.store(state);
    }

    pub(in super::super) fn decrypt(state: &mut State, data: &mut [u8]) {
        let mut sliced = Sliced::load(state);
        for block in data.chunks_exact_mut(RATE) {
            let sealed = pack(block);
            let keystream = sliced.keystream();
            let message: Planes =
                core::array::from_fn(|i| sealed[i] ^ keystream[i]);
            unpack(&message, block);
            sliced.update(&message);
        }
        sliced.store(state);
    }
}

/// AEGIS-256 over the table-driven round, which leaks through cache
/// timing; see [`ttable`](crate::cipher::aes::portable::ttable).
pub(super) mod tables256 {
    use super::super::State;
    use super::super::aegis256::keystream;
    use crate::cipher::aes::portable::ttable::round;

    /// Bytes to a block of input.
    const RATE: usize = 16;

    /// The draft's `Update`.
    fn update(state: &mut State, block: &[u8]) {
        let old = *state;
        for (i, next) in state[..6].iter_mut().enumerate() {
            let mut key = old[i];
            if i == 0 {
                for (k, m) in key.iter_mut().zip(block) {
                    *k ^= m;
                }
            }
            *next = round(&old[(i + 5) % 6], &key);
        }
    }

    pub(in super::super) fn absorb(state: &mut State, blocks: &[u8]) {
        for block in blocks.chunks_exact(RATE) {
            update(state, block);
        }
    }

    pub(in super::super) fn encrypt(state: &mut State, data: &mut [u8]) {
        for block in data.chunks_exact_mut(RATE) {
            let z = keystream(state);
            let mut message = [0u8; RATE];
            message.copy_from_slice(block);
            for (byte, z) in block.iter_mut().zip(z) {
                *byte ^= z;
            }
            update(state, &message);
        }
    }

    pub(in super::super) fn decrypt(state: &mut State, data: &mut [u8]) {
        for block in data.chunks_exact_mut(RATE) {
            let z = keystream(state);
            for (byte, z) in block.iter_mut().zip(z) {
                *byte ^= z;
            }
            update(state, block);
        }
    }
}
