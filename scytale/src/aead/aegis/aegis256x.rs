//! AEGIS-256X2 and AEGIS-256X4: two or four states of AEGIS-256 side by
//! side, each started with a mark of its own, taking a block of
//! input between them.
//!
//! These are not AEGIS-256 made faster: the ciphertext and the
//! tag are other ones, and both ends have to have agreed on the
//! variant. What they are for is a processor whose registers hold
//! more than one block, where the states go through their rounds
//! together and each wait buys two blocks of message, or four.
//!
//! Each state is a lane. A block of input is a block of the cipher
//! for every lane in turn, so a register as wide as the lanes it
//! holds takes its share of a block in one load.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::aegis256::{self, Aegis256};
use super::sealed::{Chosen, Variant};
use super::{Decryptor, Encryptor, Lane, State, TAG, lengths, open, seal, xor};
use crate::aead::Aead;
use crate::cipher::aes::{BLOCK_SIZE, Kernel};
use crate::features::{self, Dispatcher, Features};
use crate::{Error, Key, KeyType};

#[cfg(target_arch = "x86_64")]
use super::x86_64;

/// The key length, in bytes.
const KEY_SIZE: usize = 32;

/// The nonce length, in bytes.
const NONCE_SIZE: usize = 32;

/// The kernels, best first; see [`crate::cipher::aes::AEGIS256X`].
pub(crate) const KERNELS: &[(Kernel, Features)] = crate::cipher::aes::AEGIS256X;

/// What the list publishes: the needs, without the names.
const PROFILES: [Features; KERNELS.len()] = features::profiles_of(KERNELS);

/// AEGIS-256X under one key, with `D` states side by side: two or
/// four, as [`Aegis256X2`] and [`Aegis256X4`].
///
/// See the [module](super) for what it is and how to use it safely.
#[derive(Clone)]
pub struct Aegis256X<const D: usize> {
    key: Key<[u8; KEY_SIZE]>,
    kernel: Kernel,
}

/// AEGIS-256X2: two states side by side.
pub type Aegis256X2 = Aegis256X<2>;

/// AEGIS-256X4: four states side by side.
pub type Aegis256X4 = Aegis256X<4>;

impl<const D: usize> Aegis256X<D> {
    /// Takes the key.
    pub fn new(key: &Key<[u8; KEY_SIZE]>) -> Self {
        const { assert!(D == 2 || D == 4, "two lanes or four") };
        Aegis256X {
            key: key.clone(),
            kernel: features::select(KERNELS).unwrap_or(Kernel::Bitsliced),
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
        Some(Aegis256X {
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

impl<const D: usize> ZeroizeOnDrop for Aegis256X<D> {}

impl<const D: usize> fmt::Debug for Aegis256X<D> {
    /// Deliberately omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aegis256X")
            .field("lanes", &D)
            .finish_non_exhaustive()
    }
}

impl<const D: usize> features::sealed::Sealed for Aegis256X<D> {}

impl<const D: usize> Dispatcher for Aegis256X<D> {
    fn profiles() -> &'static [Features] {
        Aegis256X::<D>::profiles()
    }
}

impl<const D: usize> KeyType for Aegis256X<D> {
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

/// The draft's `Init`: every lane starts as AEGIS-256 does and is
/// then stirred as it is, with the lane's mark going in before each
/// update, so that no two lanes are ever in the same state.
fn init<const D: usize>(
    kernel: Chosen,
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> [State; D] {
    let (start, mut inputs) = aegis256::start(key, nonce);
    let mut lanes = [start; D];
    // The four blocks four times over, the lane's mark going into
    // the fourth and sixth blocks before each update.
    #[cfg(target_arch = "x86_64")]
    if kernel.0 == Kernel::Vaes {
        for (i, pair) in pairs(&mut lanes) {
            let marks = [mark(i, D), mark(i + 1, D)];
            x86_64::vaes::init256(pair, &inputs, &marks);
        }
        inputs.zeroize();
        return lanes;
    }
    for (i, lane) in lanes.iter_mut().enumerate() {
        for _ in 0..4 {
            for input in &inputs {
                context(lane, [3, 5], i, D);
                <Aegis256 as Variant>::absorb(kernel, lane, input);
            }
        }
    }
    inputs.zeroize();
    lanes
}

/// Where lane `i` of `lanes` lies in a block of input.
fn lane(i: usize, lanes: &[State]) -> Lane {
    Lane {
        offset: BLOCK_SIZE * i,
        width: BLOCK_SIZE * lanes.len(),
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
            x86_64::vaes::absorb256(pair, blocks, at);
        }
        return;
    }
    for i in 0..lanes.len() {
        let at = lane(i, lanes);
        aegis256::absorb_lane(kernel, &mut lanes[i], blocks, at);
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
            x86_64::vaes::encrypt256(pair, data, at);
        }
        return;
    }
    for i in 0..lanes.len() {
        let at = lane(i, lanes);
        aegis256::encrypt_lane(kernel, &mut lanes[i], data, at);
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
            x86_64::vaes::decrypt256(pair, data, at);
        }
        return;
    }
    for i in 0..lanes.len() {
        let at = lane(i, lanes);
        aegis256::decrypt_lane(kernel, &mut lanes[i], data, at);
    }
}

/// The keystream for the next block, into `out`: each lane's, laid
/// out as a block of input is.
fn keystream(lanes: &[State], out: &mut [u8]) {
    for (lane, z) in lanes.iter().zip(out.chunks_exact_mut(BLOCK_SIZE)) {
        z.copy_from_slice(&aegis256::keystream(lane));
    }
}

/// The draft's `Finalize`: every lane finishes as AEGIS-256 does,
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
            x86_64::vaes::finish256(pair, &lengths);
        }
        return lanes
            .iter()
            .fold([0; TAG], |tag, lane| xor(&tag, &aegis256::fold(lane)));
    }
    lanes.iter_mut().fold([0; TAG], |tag, lane| {
        xor(&tag, &aegis256::finish(kernel, lane, &lengths))
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
        impl Aegis256X<$lanes> {
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

        impl Aead for Aegis256X<$lanes> {
            type Nonce = [u8; NONCE_SIZE];
            type Tag = [u8; TAG];

            fn new(key: &Self::Key) -> Self {
                // The inherent constructor, which takes precedence
                // here.
                Aegis256X::new(key)
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

        impl Variant for Aegis256X<$lanes> {
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

degree!(2, 32);
degree!(4, 64);

#[cfg(test)]
pub(crate) mod tests {
    use std::vec::Vec;

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

    /// Each kernel this processor can run under the set in force,
    /// the virtual features granted.
    /// This variant under one kernel: the draft's vectors and the
    /// rest below, each against the portable kernel. The kernel the
    /// list chooses under the row's features is the one they build
    /// on, through the test constructor that trusts its caller.
    pub(crate) fn kernel(under: &features::Under) {
        let chosen = under.build(|| features::select(KERNELS)).expect("listed");
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
    const KEY: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const NONCE: &str =
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

    fn key() -> Key<[u8; KEY_SIZE]> {
        Key::from(<[u8; KEY_SIZE]>::try_from(hex(KEY)).unwrap())
    }

    fn nonce() -> [u8; NONCE_SIZE] {
        hex(NONCE).try_into().unwrap()
    }

    #[test]
    fn dispatches() {
        features::build_alone(|| {
            let two = Aegis256X2::new(&Key::zeroed());
            features::dispatches(KERNELS, Aegis256X2::profiles(), two.kernel());
            let four = Aegis256X4::new(&Key::zeroed());
            features::dispatches(
                KERNELS,
                Aegis256X4::profiles(),
                four.kernel(),
            );
        });
    }

    /// The state after `Init`, a lane to a row, against what the
    /// draft lists a block at a time.
    fn initial_state<const D: usize>(expected: [[&str; 6]; D]) {
        for kernel in kernels() {
            let lanes: [State; D] =
                init(Chosen(kernel), key().array(), &nonce());
            for (lane, expected) in lanes.iter().zip(expected) {
                let expected = expected.map(block);
                assert_eq!(lane[..6], expected, "{kernel:?}");
            }
        }
    }

    /// The draft's appendix A.6.1.
    fn initial_state_of_two() {
        initial_state([
            [
                "eca2bf4538442e8712d4972595744039",
                "3e536a998799408a97f3479a6f779d48",
                "cf8c63d6f2b4563cdd9231107c85950e",
                "d7e0707e6bfbbad913bc94b6993a9fa0",
                "a373cf6d537dd66bc0ef0f2f9285359f",
                "9f76560dcae1efacabdcce446ae283bc",
            ],
            [
                "201405efa9264f07911db58101903087",
                "0d79a7d822a5d215f78c3bf2feb33ae1",
                "78d17ed7d8d563ff11bd202c76864839",
                "097e4b1bff40d4c19cb29dfd125d62f2",
                "c0d0ae0c48f9df3faaf0e7be7768c326",
                "bd52a6b9c8f976a26ec1409df19e8bfe",
            ],
        ]);
    }

    /// The draft's appendix A.7.1.
    fn initial_state_of_four() {
        initial_state([
            [
                "482a86e8436cd2361063a4b2702769b9",
                "e705e8866267717d96092e58e78b574c",
                "e1aa6af5d9e31dde8d94a48a0810fa89",
                "37f06808410c8f3954525ae44584d3be",
                "d1c9eb37fecbc5ada7b351fa4f501f32",
                "4f6110c2ef0c3c687e90c1e5532ddf8e",
            ],
            [
                "d95a2be81c9245b22996f68eea0122f9",
                "d1dd412142df9806cc267af2fe1d830e",
                "63555cdf0d98f18fb75b029ad80786c0",
                "8fcc23bca2fe2209f93d34e2da35b33d",
                "0b9b803283c1538628b507c8f6432434",
                "031bd85d99f64684d23728a0453c72a1",
            ],
            [
                "0c2a3b348b1a5e256c6751377318c41e",
                "30e7dfd3c9941b8394e95bdf5bac99d9",
                "a3ee0e4a3429a9539e4fcec385475608",
                "33156347df89eaa69ab11096362daccf",
                "bfb8b6d4f87cce28825c7e92f54b8728",
                "10bc7ec34d4119b5bdeb6c7dfc458247",
            ],
            [
                "f64436a21653fe7cf2e0829a177db383",
                "9f27186f8a4fab86820689822c3c74d2",
                "28ea527d31ef61df498dc107fe02df99",
                "bbe58d9dbe8c5b0469be5a87086db5d4",
                "8917bb5b09c32f900c6a5a1d63c46264",
                "591ece530aeaa5c9867220156f5c25e3",
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

    /// The draft's appendix A.6.2 and A.6.3.
    fn draft_vectors_of_two() {
        let with = |kernel| Aegis256X2::with_kernel(&key(), kernel).unwrap();
        vector(with, ["", "", "", "62cdbab084c83dacdb945bb446f049c8"]);
        vector(
            with,
            [
                AAD,
                MESSAGE,
                "72120c2ea8236180d67859001f472907\
                 7b7064c414384fe3a7b52f1571f4f8a7\
                 d0f01e18db4f3bc0adb150702e5d147a\
                 8d36522132761b994c1bd395589e2ccf\
                 0790dfe2a3d12d61cd666b2859827739\
                 db4037dd3124c78424459376f6cac08e\
                 1a7223a2a43e398ce6385cd654a19f48\
                 1cba3b8f25910b42",
                "635d391828520bf1512763f0c8f5cdbd",
            ],
        );
    }

    /// The draft's appendix A.7.2 and A.7.3.
    fn draft_vectors_of_four() {
        let with = |kernel| Aegis256X4::with_kernel(&key(), kernel).unwrap();
        vector(with, ["", "", "", "3b7fee6cee7bf17888ad11ed2397beb4"]);
        vector(
            with,
            [
                AAD,
                MESSAGE,
                "bfc2085b7e8017da99b0b6d646ae4d01\
                 f4ba8f2e7dfca1d759ae48a135139b9a\
                 aac6b4f5db810d426be1fdaff4e14541\
                 53a34b11da78ed7e418ee2ee9853042e\
                 95536aecbb694cea1b16a478eb0d4d1b\
                 f6509b1ce652a45af58e0e46ffccfa2d\
                 0426e702391d2ff5813808b81748a490\
                 dd656465fed61f09",
                "b63b611b13975e2f3dc3cb6c2397bfcd",
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
            |kernel| Aegis256X2::with_kernel(&key(), kernel).unwrap(),
            |aead| aead.encryptor(&nonce()),
            |aead| aead.decryptor(&nonce()),
        );
    }

    fn kernels_and_pieces_agree_for_four() {
        kernels_and_pieces_agree(
            |kernel| Aegis256X4::with_kernel(&key(), kernel).unwrap(),
            |aead| aead.encryptor(&nonce()),
            |aead| aead.decryptor(&nonce()),
        );
    }

    /// The lanes are told apart: the two variants, and AEGIS-256
    /// itself, give three different answers for one key, nonce and
    /// message.
    #[test]
    fn the_variants_differ() {
        let mut tags = [[0u8; 16]; 3];
        let [base, two, four] = &mut tags;
        Aegis256::new(&key())
            .encrypt(&nonce(), b"", &mut [], base)
            .unwrap();
        Aegis256X2::new(&key())
            .encrypt(&nonce(), b"", &mut [], two)
            .unwrap();
        Aegis256X4::new(&key())
            .encrypt(&nonce(), b"", &mut [], four)
            .unwrap();
        assert_ne!(tags[0], tags[1]);
        assert_ne!(tags[0], tags[2]);
        assert_ne!(tags[1], tags[2]);
    }

    #[test]
    fn aad_after_message_is_out_of_order() {
        let aead = Aegis256X2::new(&Key::zeroed());
        let mut e = aead.encryptor(&nonce());
        e.update(&mut [0u8; 3]).unwrap();
        assert_eq!(e.aad(b"late"), Err(Error::OutOfOrder));
        let aead = Aegis256X4::new(&Key::zeroed());
        let mut d = aead.decryptor(&nonce());
        d.update(&mut []).unwrap();
        assert_eq!(d.aad(b"late"), Err(Error::OutOfOrder));
    }

    #[test]
    fn wipes_and_hides_the_key() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Aegis256X2>();
        wipes::<Aegis256X4>();
        let aead = Aegis256X4::new(&Key::from([0x5au8; KEY_SIZE]));
        let text = std::format!("{aead:?}");
        assert!(!text.contains("5a"), "{text}");
        let text = std::format!("{:?}", aead.encryptor(&[0x5au8; NONCE_SIZE]));
        assert!(!text.contains("5a"), "{text}");
    }
}
