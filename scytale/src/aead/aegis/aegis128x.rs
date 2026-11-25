//! AEGIS-128X2 and AEGIS-128X4: two or four states of AEGIS-128L side by
//! side, each started with a mark of its own, taking a block of
//! input between them.
//!
//! These are not AEGIS-128L made faster: the ciphertext and the
//! tag are other ones, and both ends have to have agreed on the
//! variant. What they are for is a processor whose registers hold
//! more than one block, where the states go through their rounds
//! together and each wait buys two blocks of message, or four.
//!
//! Each state is a lane. A block of input is two halves, each holding
//! a block of the cipher for every lane in turn, so a register as
//! wide as the lanes it holds takes its share of a block in one load.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::aegis128l;
use super::sealed::{Chosen, Variant};
use super::{Decryptor, Encryptor, Lane, State, TAG, lengths, open, seal, xor};
use crate::aead::Aead;
use crate::cipher::aes::{BLOCK_SIZE, Kernel};
use crate::features::{self, Dispatcher, Features};
use crate::{Context, Error, Key, KeyType};

#[cfg(target_arch = "x86_64")]
use super::x86_64;

/// The key length, in bytes.
const KEY_SIZE: usize = 16;

/// The nonce length, in bytes.
const NONCE_SIZE: usize = 16;

/// The kernels, best first; see [`crate::cipher::aes::AEGIS128X`].
pub(crate) const KERNELS: &[(Kernel, Features)] = crate::cipher::aes::AEGIS128X;

/// What the list publishes: the needs, without the names.
const PROFILES: [Features; KERNELS.len()] = features::profiles_of(KERNELS);

/// AEGIS-128X under one key, with `D` states side by side: two or
/// four, as [`Aegis128X2`] and [`Aegis128X4`].
///
/// See the [module](super) for what it is and how to use it safely.
#[derive(Clone)]
pub struct Aegis128X<const D: usize> {
    key: Key<[u8; KEY_SIZE]>,
    kernel: Kernel,
}

/// AEGIS-128X2: two states side by side.
pub type Aegis128X2 = Aegis128X<2>;

/// AEGIS-128X4: four states side by side.
pub type Aegis128X4 = Aegis128X<4>;

impl<const D: usize> Aegis128X<D> {
    /// Takes the key.
    pub fn new(ctx: Context, key: &Key<[u8; KEY_SIZE]>) -> Self {
        const { assert!(D == 2 || D == 4, "two lanes or four") };
        Aegis128X {
            key: key.clone(),
            kernel: features::select(ctx, KERNELS).unwrap_or(Kernel::Bitsliced),
        }
    }

    /// The feature profiles this construction tells apart, best
    /// first; see [`Dispatcher`].
    pub fn profiles() -> &'static [Features] {
        &PROFILES
    }

    /// Takes the key for `kernel` alone, trusting the caller: the
    /// meta tests pass only the kernel the list chose under the
    /// row's features, which the processor has.
    #[cfg(test)]
    pub(crate) fn with_kernel(
        key: &Key<[u8; KEY_SIZE]>,
        kernel: Kernel,
    ) -> Option<Self> {
        Some(Aegis128X {
            key: key.clone(),
            kernel,
        })
    }

    /// Which kernel this key was taken for.
    #[cfg(test)]
    pub(crate) fn kernel(&self) -> Kernel {
        self.kernel
    }
}

impl<const D: usize> ZeroizeOnDrop for Aegis128X<D> {}

impl<const D: usize> fmt::Debug for Aegis128X<D> {
    /// Deliberately omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aegis128X")
            .field("lanes", &D)
            .finish_non_exhaustive()
    }
}

impl<const D: usize> features::sealed::Sealed for Aegis128X<D> {}

impl<const D: usize> Dispatcher for Aegis128X<D> {
    fn profiles() -> &'static [Features] {
        Aegis128X::<D>::profiles()
    }
}

impl<const D: usize> KeyType for Aegis128X<D> {
    type Key = Key<[u8; KEY_SIZE]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

/// The mark that tells lane `lane` of `lanes` from the others: the
/// lane's number and the highest there is, a byte each, and zeros.
fn mark(lane: usize, lanes: usize) -> [u8; BLOCK_SIZE] {
    let mut mark = [0u8; BLOCK_SIZE];
    // Neither is ever more than three.
    mark[0] = lane as u8;
    mark[1] = (lanes - 1) as u8;
    mark
}

/// A lane's mark into the two blocks of its state at `blocks`.
fn context(state: &mut State, blocks: [usize; 2], lane: usize, lanes: usize) {
    let mark = mark(lane, lanes);
    for block in blocks {
        state[block] = xor(&state[block], &mark);
    }
}

/// The draft's `Init`: every lane starts as AEGIS-128L does and is
/// then stirred as it is, with the lane's mark going in before each
/// update, so that no two lanes are ever in the same state.
fn init<const D: usize>(
    kernel: Chosen,
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> [State; D] {
    let mut block = [0u8; 2 * BLOCK_SIZE];
    let (m0, m1) = block.split_at_mut(BLOCK_SIZE);
    m0.copy_from_slice(nonce);
    m1.copy_from_slice(key);
    let mut lanes = [aegis128l::start(key, nonce); D];
    // Ten updates with the nonce and the key, the lane's mark going
    // into the fourth and eighth blocks before each.
    #[cfg(target_arch = "x86_64")]
    if kernel.0 == Kernel::Vaes {
        for (i, pair) in pairs(&mut lanes) {
            let marks = [mark(i, D), mark(i + 1, D)];
            x86_64::vaes::init128(pair, &block, &marks);
        }
        block.zeroize();
        return lanes;
    }
    for (i, lane) in lanes.iter_mut().enumerate() {
        for _ in 0..10 {
            context(lane, [3, 7], i, D);
            aegis128l::stir(kernel, lane, &block, 1);
        }
    }
    block.zeroize();
    lanes
}

/// Where lane `i` of `lanes` lies in a block of input.
fn lane(i: usize, lanes: &[State]) -> Lane {
    Lane {
        offset: BLOCK_SIZE * i,
        width: 2 * BLOCK_SIZE * lanes.len(),
    }
}

/// The draft's `Absorb`, over each block of `blocks`: every lane
/// takes its share, two lanes at a time where the kernel holds two.
fn absorb(kernel: Chosen, lanes: &mut [State], blocks: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    if kernel.0 == Kernel::Vaes {
        let first = lane(0, lanes);
        for (i, pair) in pairs(lanes) {
            let at = Lane {
                offset: BLOCK_SIZE * i,
                width: first.width,
            };
            x86_64::vaes::absorb128(pair, blocks, at);
        }
        return;
    }
    for i in 0..lanes.len() {
        let at = lane(i, lanes);
        aegis128l::absorb_lane(kernel, &mut lanes[i], blocks, at);
    }
}

/// The draft's `Enc`, over each block of `data` in place.
fn encrypt(kernel: Chosen, lanes: &mut [State], data: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if kernel.0 == Kernel::Vaes {
        let first = lane(0, lanes);
        for (i, pair) in pairs(lanes) {
            let at = Lane {
                offset: BLOCK_SIZE * i,
                width: first.width,
            };
            x86_64::vaes::encrypt128(pair, data, at);
        }
        return;
    }
    for i in 0..lanes.len() {
        let at = lane(i, lanes);
        aegis128l::encrypt_lane(kernel, &mut lanes[i], data, at);
    }
}

/// The draft's `Dec`, over each block of `data` in place.
fn decrypt(kernel: Chosen, lanes: &mut [State], data: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if kernel.0 == Kernel::Vaes {
        let first = lane(0, lanes);
        for (i, pair) in pairs(lanes) {
            let at = Lane {
                offset: BLOCK_SIZE * i,
                width: first.width,
            };
            x86_64::vaes::decrypt128(pair, data, at);
        }
        return;
    }
    for i in 0..lanes.len() {
        let at = lane(i, lanes);
        aegis128l::decrypt_lane(kernel, &mut lanes[i], data, at);
    }
}

/// The keystream for the next block, into `out`: each lane's, laid
/// out as a block of input is.
fn keystream(lanes: &[State], out: &mut [u8]) {
    let (z0, z1) = out.split_at_mut(BLOCK_SIZE * lanes.len());
    let pieces = z0
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(z1.chunks_exact_mut(BLOCK_SIZE));
    for (lane, (z0, z1)) in lanes.iter().zip(pieces) {
        let mut z = aegis128l::keystream(lane);
        let (first, second) = z.split_at(BLOCK_SIZE);
        z0.copy_from_slice(first);
        z1.copy_from_slice(second);
        z.zeroize();
    }
}

/// The draft's `Finalize`: every lane finishes as AEGIS-128L does,
/// and the tag is all of theirs xored together.
fn tag(
    kernel: Chosen,
    lanes: &mut [State],
    aad_bits: u64,
    message_bits: u64,
) -> [u8; TAG] {
    let lengths = lengths(aad_bits, message_bits);
    #[cfg(target_arch = "x86_64")]
    if kernel.0 == Kernel::Vaes {
        for (_, pair) in pairs(lanes) {
            x86_64::vaes::finish128(pair, &lengths);
        }
        return lanes
            .iter()
            .fold([0; TAG], |tag, lane| xor(&tag, &aegis128l::fold(lane)));
    }
    lanes.iter_mut().fold([0; TAG], |tag, lane| {
        xor(&tag, &aegis128l::finish(kernel, lane, &lengths))
    })
}

/// The lanes two at a time, each pair with the number of its first,
/// for the kernel that holds two.
#[cfg(target_arch = "x86_64")]
fn pairs(
    lanes: &mut [State],
) -> impl Iterator<Item = (usize, &mut [State; 2])> {
    let (pairs, _) = lanes.as_chunks_mut::<2>();
    pairs.iter_mut().enumerate().map(|(i, pair)| (2 * i, pair))
}

/// What needs the number of lanes as a number: the width of a block
/// is a multiple of it, and an array's length cannot yet be worked
/// out from a parameter.
macro_rules! degree {
    ($lanes:literal, $rate:literal) => {
        impl Aegis128X<$lanes> {
            /// Starts encrypting a message that arrives in pieces.
            pub fn encryptor(
                &self,
                nonce: &[u8; NONCE_SIZE],
            ) -> Encryptor<Self> {
                Encryptor::new(Chosen(self.kernel), &self.key, nonce)
            }

            /// Starts decrypting a message that arrives in pieces.
            pub fn decryptor(
                &self,
                nonce: &[u8; NONCE_SIZE],
            ) -> Decryptor<Self> {
                Decryptor::new(Chosen(self.kernel), &self.key, nonce)
            }
        }

        impl Aead for Aegis128X<$lanes> {
            type Nonce = [u8; NONCE_SIZE];
            type Tag = [u8; TAG];

            fn new(ctx: Context, key: &Self::Key) -> Self {
                // The inherent constructor, which takes precedence
                // here.
                Aegis128X::new(ctx, key)
            }

            fn encrypt(
                &self,
                nonce: &Self::Nonce,
                aad: &[u8],
                data: &mut [u8],
                tag: &mut Self::Tag,
            ) -> Result<(), Error> {
                *tag = seal(self.encryptor(nonce), aad, data)?;
                Ok(())
            }

            fn decrypt(
                &self,
                nonce: &Self::Nonce,
                aad: &[u8],
                data: &mut [u8],
                tag: &Self::Tag,
            ) -> Result<(), Error> {
                open(self.decryptor(nonce), aad, data, tag)
            }
        }

        impl Variant for Aegis128X<$lanes> {
            type Nonce = [u8; NONCE_SIZE];
            type State = [State; $lanes];
            type Block = [u8; $rate];

            const RATE: usize = $rate;

            fn init(
                kernel: Chosen,
                key: &Self::Key,
                nonce: &Self::Nonce,
            ) -> Self::State {
                init(kernel, key.array(), nonce)
            }

            fn absorb(kernel: Chosen, state: &mut Self::State, blocks: &[u8]) {
                absorb(kernel, state, blocks)
            }

            fn encrypt(
                kernel: Chosen,
                state: &mut Self::State,
                data: &mut [u8],
            ) {
                encrypt(kernel, state, data)
            }

            fn decrypt(
                kernel: Chosen,
                state: &mut Self::State,
                data: &mut [u8],
            ) {
                decrypt(kernel, state, data)
            }

            fn keystream(state: &Self::State) -> Self::Block {
                let mut out = [0u8; $rate];
                keystream(state, &mut out);
                out
            }

            fn tag(
                kernel: Chosen,
                state: &mut Self::State,
                aad_bits: u64,
                message_bits: u64,
            ) -> [u8; TAG] {
                tag(kernel, state, aad_bits, message_bits)
            }
        }
    };
}

degree!(2, 64);
degree!(4, 128);

#[cfg(test)]
pub(crate) mod tests {
    use std::vec::Vec;

    use super::super::Aegis128L;
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }

    fn block(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }

    /// This variant under one kernel: the draft's vectors and the
    /// rest below, each against the portable kernel. The kernel the
    /// list chooses under the row's features is the one they build
    /// on, through the test constructor that trusts its caller.
    pub(crate) fn kernel(under: &features::Under) {
        let chosen = features::select(under.ctx(), KERNELS).expect("listed");
        UNDER.set(Some(chosen));
        initial_state_of_two();
        initial_state_of_four();
        draft_vectors_of_two();
        draft_vectors_of_four();
        kernels_and_pieces_agree_for_two();
        kernels_and_pieces_agree_for_four();
        UNDER.set(None);
    }

    std::thread_local! {
        /// The kernel the meta test has this thread checking.
        static UNDER: core::cell::Cell<Option<Kernel>> =
            const { core::cell::Cell::new(None) };
    }

    /// The portable kernel, as the reference, then the kernel under
    /// test where it is another.
    fn kernels() -> impl Iterator<Item = Kernel> {
        let under = UNDER.get().filter(|k| *k != Kernel::Bitsliced);
        core::iter::once(Kernel::Bitsliced).chain(under)
    }

    /// The key and nonce of every vector in the draft's appendix
    /// for these variants.
    const KEY: &str = "000102030405060708090a0b0c0d0e0f";
    const NONCE: &str = "101112131415161718191a1b1c1d1e1f";

    fn key() -> Key<[u8; KEY_SIZE]> {
        Key::from(<[u8; KEY_SIZE]>::try_from(hex(KEY)).unwrap())
    }

    fn nonce() -> [u8; NONCE_SIZE] {
        hex(NONCE).try_into().unwrap()
    }

    #[test]
    fn dispatches() {
        {
            let two =
                Aegis128X2::new(crate::Context::default(), &Key::zeroed());
            features::dispatches(KERNELS, Aegis128X2::profiles(), two.kernel());
            let four =
                Aegis128X4::new(crate::Context::default(), &Key::zeroed());
            features::dispatches(
                KERNELS,
                Aegis128X4::profiles(),
                four.kernel(),
            );
        };
    }

    /// The state after `Init`, a lane to a row, against what the
    /// draft lists a block at a time.
    fn initial_state<const D: usize>(expected: [[&str; 8]; D]) {
        for kernel in kernels() {
            let lanes: [State; D] =
                init(Chosen(kernel), key().array(), &nonce());
            for (lane, expected) in lanes.iter().zip(expected) {
                let expected = expected.map(block);
                assert_eq!(lane[..8], expected, "{kernel:?}");
            }
        }
    }

    /// The draft's appendix A.4.1.
    fn initial_state_of_two() {
        initial_state([
            [
                "a4fc1ad9a72942fb88bd2cabbba6509a",
                "380f435cf801763b1f0c2a2f7212052d",
                "6ee1de433ea877fa33bc0782abff2dcb",
                "85f94b0d4263bfa86fdf45a603d8b6ac",
                "09bd69ad3730174bcd2ce9a27cd1357e",
                "fcdeb0cf0a87bf442fc82383ddb0f6d6",
                "571c207988659e2cdfbdaae77f4f37e3",
                "ca549badf8faa58222412478598651cf",
            ],
            [
                "80a40e392fc71084209b6c3319bdc6cc",
                "73796607b59b1b650ee91c152af1f18a",
                "b9fab2ab496e16d1facaffd5453cbf14",
                "90356c8cadbaa2c969001da02e3feca0",
                "e610b45125796a4fcf1708cef5c4f718",
                "61ad32a4694d6f3cca313a2d3f4687aa",
                "32e6094e217573bf91fb28c145a3efa8",
                "3407279a54ce76d2e2e8a90ec5d108eb",
            ],
        ]);
    }

    /// The draft's appendix A.5.1.
    fn initial_state_of_four() {
        initial_state([
            [
                "924eb07635003a37e6c6575ba8ce1929",
                "1a1f60c4fab64e5471dc72edfcf6fe6b",
                "7bb50c534f6ec4780530ff1cce8a16e8",
                "af339fd2d50ee45fc47665c647cf6586",
                "9f93737d699ba05c11e94f2b201bef5e",
                "7a5aca78d636c05bbc702b2980196ab6",
                "e46f4cf71a95ac45b6f0823e3aba1a86",
                "85075f0080e9d618e7eb40f57c32d9f7",
            ],
            [
                "c8b6a5d91475445e936d48e794be0ce2",
                "c1e525ebea2d6375a9edd045dce96381",
                "7b08d57557da0b5ef7b5f7d98b0ba189",
                "d0669b39d140f0e118a4a511efe2f95a",
                "61caf387cf7cfd3f8300ac7680ccfd76",
                "915d868408495d07eb527789f282c575",
                "8c4ecef682fc44a8eba911b3fc7d99f9",
                "d2ab2b320c6e93b155a3787cb83e5281",
            ],
            [
                "fcd37d050e24084befe3bbb219d64760",
                "97a3e25abd228a44d4a14a6d3fe9185c",
                "6bfcac34ddb68404821a4d665303cb0f",
                "7a94330f35c194fadda2a87e42cdeccc",
                "5825a671ecef03b7a9c98a601ae32115",
                "d0947bfbc1d3309cdffc9be1503aea62",
                "a4fb61e2c928a2ca760b8772f2ea5f2e",
                "0b3af0250ae36831a1b072e499929bcb",
            ],
            [
                "2e9f58cfb893a8800220242c373a8b18",
                "c2d4cf7f4287a98744645674265d4ca8",
                "d95626f6dfad1aed7467622c38529932",
                "233b640d1f4d56e2757e72c1a9d8ecb1",
                "87a1fe4d558161a8f4c38731f3223032",
                "8834ea57a15b9fbdc0245464a4b8cbef",
                "3d34ea89da73caa3016c280500a155a3",
                "5cce4d00329d69f1aae36aa541347512",
            ],
        ]);
    }

    /// One vector: additional data, message, ciphertext and 128-bit
    /// tag, both ways, and then spoiled three ways, each of which
    /// must be refused with the buffer wiped.
    fn vector<A>(
        with: impl Fn(Kernel) -> A,
        [aad, message, sealed, tag]: [&str; 4],
    ) where
        A: Aead<Nonce = [u8; NONCE_SIZE], Tag = [u8; TAG]>,
    {
        let (aad, message, sealed) = (hex(aad), hex(message), hex(sealed));
        let tag = block(tag);
        for kernel in kernels() {
            let aead = with(kernel);
            let mut data = message.clone();
            let mut got = [0u8; 16];
            aead.encrypt(&nonce(), &aad, &mut data, &mut got).unwrap();
            assert_eq!(data, sealed, "{kernel:?}");
            assert_eq!(got, tag, "{kernel:?}");
            aead.decrypt(&nonce(), &aad, &mut data, &tag).unwrap();
            assert_eq!(data, message, "{kernel:?}");

            let refused = Err(Error::AuthenticationFailed);
            let mut wrong = tag;
            wrong[15] ^= 1;
            let mut data = sealed.clone();
            let result = aead.decrypt(&nonce(), &aad, &mut data, &wrong);
            assert_eq!(result, refused, "{kernel:?}");
            assert!(data.iter().all(|b| *b == 0), "{kernel:?}");

            let mut data = sealed.clone();
            let result = aead.decrypt(&nonce(), b"other", &mut data, &tag);
            assert_eq!(result, refused, "{kernel:?}");

            if let Some(last) = sealed.len().checked_sub(1) {
                let mut data = sealed.clone();
                data[last] ^= 0x80;
                let result = aead.decrypt(&nonce(), &aad, &mut data, &tag);
                assert_eq!(result, refused, "{kernel:?}");
            }
        }
    }

    const AAD: &str = "0102030401020304";
    const MESSAGE: &str = "\
        04050607040506070405060704050607\
        04050607040506070405060704050607\
        04050607040506070405060704050607\
        04050607040506070405060704050607\
        04050607040506070405060704050607\
        04050607040506070405060704050607\
        04050607040506070405060704050607\
        0405060704050607";

    /// The draft's appendix A.4.2 and A.4.3.
    fn draft_vectors_of_two() {
        let with = |kernel| Aegis128X2::with_kernel(&key(), kernel).unwrap();
        vector(with, ["", "", "", "63117dc57756e402819a82e13eca8379"]);
        vector(
            with,
            [
                AAD,
                MESSAGE,
                "5795544301997f93621b278809d6331b\
                 3bfa6f18e90db12c4aa35965b5e98c5f\
                 c6fb4e54bcb6111842c20637252eff74\
                 7cb3a8f85b37de80919a589fe0f24872\
                 bc926360696739e05520647e390989e1\
                 eb5fd42f99678a0276a498f8c454761c\
                 9d6aacb647ad56be62b29c22cd4b5761\
                 b38f43d5a5ee062f",
                "1aebc200804f405cab637f2adebb6d77",
            ],
        );
    }

    /// The draft's appendix A.5.2 and A.5.3.
    fn draft_vectors_of_four() {
        let with = |kernel| Aegis128X4::with_kernel(&key(), kernel).unwrap();
        vector(with, ["", "", "", "5bef762d0947c00455b97bb3af30dfa3"]);
        vector(
            with,
            [
                AAD,
                MESSAGE,
                "e836118562f4479c9d35c17356a83311\
                 4c21f9aa39e4dda5e5c87f4152a00fce\
                 9a7c38f832eafe8b1c12f8a7cf12a81a\
                 1ad8a9c24ba9dedfbdaa586ffea67ddc\
                 801ea97d9ab4a872f42d0e352e2713da\
                 cd609f9442c17517c5a29daf3e2a3fac\
                 4ff6b1380c4e46df7b086af6ce6bc1ed\
                 594b8dd64aed2a7e",
                "0e56ab94e2e85db80f9d54010caabfb4",
            ],
        );
    }

    /// A message of every length to several blocks, with additional
    /// data of every length likewise, sealed whole and then again in
    /// pieces of every size: every kernel must agree with the first,
    /// and the pieces with the whole. The draft has one message of
    /// any length for each variant, so this is what holds the
    /// kernels to each other everywhere else.
    fn kernels_and_pieces_agree<A, E, D>(
        with: impl Fn(Kernel) -> A,
        encryptor: impl Fn(&A) -> Encryptor<E>,
        decryptor: impl Fn(&A) -> Decryptor<D>,
    ) where
        A: Aead<Nonce = [u8; NONCE_SIZE], Tag = [u8; TAG]>,
        E: Variant,
        D: Variant,
    {
        let bytes: [u8; 700] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let mut reference: Vec<(Vec<u8>, [u8; 16])> = Vec::new();
        for (k, kernel) in kernels().enumerate() {
            let aead = with(kernel);
            for length in 0..=bytes.len() {
                let message = &bytes[..length];
                let aad = &bytes[..(length * 3) % 271];
                let mut whole = message.to_vec();
                let mut tag = [0u8; 16];
                aead.encrypt(&nonce(), aad, &mut whole, &mut tag).unwrap();
                if k == 0 {
                    reference.push((whole.clone(), tag));
                }
                assert_eq!(
                    reference[length],
                    (whole.clone(), tag),
                    "{kernel:?} length {length}"
                );

                let size = 1 + length % 97;
                let mut data = message.to_vec();
                let mut e = encryptor(&aead);
                for piece in aad.chunks(size) {
                    e.aad(piece).unwrap();
                }
                for piece in data.chunks_mut(size) {
                    e.update(piece).unwrap();
                }
                assert_eq!(data, whole, "{kernel:?} {length} by {size}");
                assert_eq!(e.finalize(), tag, "{kernel:?} {length} by {size}");

                let mut d = decryptor(&aead);
                for piece in aad.chunks(size) {
                    d.aad(piece).unwrap();
                }
                for piece in data.chunks_mut(size) {
                    d.update(piece).unwrap();
                }
                d.verify(&tag).unwrap();
                assert_eq!(data, message, "{kernel:?} {length} by {size}");
            }
        }
    }

    fn kernels_and_pieces_agree_for_two() {
        kernels_and_pieces_agree(
            |kernel| Aegis128X2::with_kernel(&key(), kernel).unwrap(),
            |aead| aead.encryptor(&nonce()),
            |aead| aead.decryptor(&nonce()),
        );
    }

    fn kernels_and_pieces_agree_for_four() {
        kernels_and_pieces_agree(
            |kernel| Aegis128X4::with_kernel(&key(), kernel).unwrap(),
            |aead| aead.encryptor(&nonce()),
            |aead| aead.decryptor(&nonce()),
        );
    }

    /// The lanes are told apart: the two variants, and AEGIS-128L
    /// itself, give three different answers for one key, nonce and
    /// message.
    #[test]
    fn the_variants_differ() {
        let mut tags = [[0u8; 16]; 3];
        let [base, two, four] = &mut tags;
        Aegis128L::new(crate::Context::default(), &key())
            .encrypt(&nonce(), b"", &mut [], base)
            .unwrap();
        Aegis128X2::new(crate::Context::default(), &key())
            .encrypt(&nonce(), b"", &mut [], two)
            .unwrap();
        Aegis128X4::new(crate::Context::default(), &key())
            .encrypt(&nonce(), b"", &mut [], four)
            .unwrap();
        assert_ne!(tags[0], tags[1]);
        assert_ne!(tags[0], tags[2]);
        assert_ne!(tags[1], tags[2]);
    }

    #[test]
    fn aad_after_message_is_out_of_order() {
        let aead = Aegis128X2::new(crate::Context::default(), &Key::zeroed());
        let mut e = aead.encryptor(&nonce());
        e.update(&mut [0u8; 3]).unwrap();
        assert_eq!(e.aad(b"late"), Err(Error::OutOfOrder));
        let aead = Aegis128X4::new(crate::Context::default(), &Key::zeroed());
        let mut d = aead.decryptor(&nonce());
        d.update(&mut []).unwrap();
        assert_eq!(d.aad(b"late"), Err(Error::OutOfOrder));
    }

    #[test]
    fn wipes_and_hides_the_key() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Aegis128X2>();
        wipes::<Aegis128X4>();
        let aead = Aegis128X4::new(
            crate::Context::default(),
            &Key::from([0x5au8; KEY_SIZE]),
        );
        let text = std::format!("{aead:?}");
        assert!(!text.contains("5a"), "{text}");
        let text = std::format!("{:?}", aead.encryptor(&[0x5au8; NONCE_SIZE]));
        assert!(!text.contains("5a"), "{text}");
    }
}
