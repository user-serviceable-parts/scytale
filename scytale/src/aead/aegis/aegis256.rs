//! AEGIS-256: a 256-bit key and nonce, a state of six blocks, and one
//! block of input to an update.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::sealed::{Chosen, Variant};
use super::{
    C0, C1, Decryptor, Encryptor, MAX_RATE, State, TAG, and, lengths, open,
    portable, seal, xor,
};
use crate::aead::Aead;
use crate::cipher::aes::{BLOCK_SIZE, ISOLATED, Kernel};
use crate::features::{self, Dispatcher, Features};
use crate::{Error, Key, KeyType};

/// The key length, in bytes.
const KEY_SIZE: usize = 32;

/// The nonce length, in bytes.
const NONCE_SIZE: usize = 32;

/// The kernels, best first, each with what it needs. They are named
/// as the AES kernels are, since each is built on that kernel's
/// round; the table-driven one leaks as its cipher does and is
/// admitted the same way.
pub(crate) const KERNELS: &[(Kernel, Features)] = &[
    (Kernel::Tables, ISOLATED),
    (Kernel::Bitsliced, Features::new()),
];

/// What the list publishes: the needs, without the names.
const PROFILES: [Features; KERNELS.len()] = features::profiles_of(KERNELS);

/// AEGIS-256 under one key.
///
/// See the [module](super) for what it is and how to use it safely.
#[derive(Clone)]
pub struct Aegis256 {
    key: Key<[u8; KEY_SIZE]>,
    kernel: Kernel,
}

impl Aegis256 {
    /// Takes the key.
    pub fn new(key: &Key<[u8; KEY_SIZE]>) -> Self {
        Aegis256 {
            key: key.clone(),
            kernel: features::select(KERNELS).unwrap_or(Kernel::Bitsliced),
        }
    }

    /// The feature profiles this construction tells apart, best
    /// first; see [`Dispatcher`].
    pub fn profiles() -> &'static [Features] {
        &PROFILES
    }

    /// Starts encrypting a message that arrives in pieces.
    pub fn encryptor(&self, nonce: &[u8; NONCE_SIZE]) -> Encryptor<Self> {
        Encryptor::new(Chosen(self.kernel), &self.key, nonce)
    }

    /// Starts decrypting a message that arrives in pieces.
    pub fn decryptor(&self, nonce: &[u8; NONCE_SIZE]) -> Decryptor<Self> {
        Decryptor::new(Chosen(self.kernel), &self.key, nonce)
    }

    /// Takes the key for `kernel` alone, or `None` where the set in
    /// force does not allow it.
    #[cfg(test)]
    pub(crate) fn with_kernel(
        key: &Key<[u8; KEY_SIZE]>,
        kernel: Kernel,
    ) -> Option<Self> {
        features::available(KERNELS, kernel).then(|| Aegis256 {
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

impl ZeroizeOnDrop for Aegis256 {}

impl fmt::Debug for Aegis256 {
    /// Deliberately omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aegis256").finish_non_exhaustive()
    }
}

impl features::sealed::Sealed for Aegis256 {}

impl Dispatcher for Aegis256 {
    fn profiles() -> &'static [Features] {
        Aegis256::profiles()
    }
}

impl KeyType for Aegis256 {
    type Key = Key<[u8; KEY_SIZE]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

impl Aead for Aegis256 {
    type Nonce = [u8; NONCE_SIZE];
    type Tag = [u8; TAG];

    fn new(key: &Self::Key) -> Self {
        // The inherent constructor, which takes precedence here.
        Aegis256::new(key)
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

/// The keystream for the next block, and zeros after it.
pub(super) fn keystream(s: &State) -> [u8; MAX_RATE] {
    let z = xor(&xor(&xor(&s[1], &s[4]), &s[5]), &and(&s[2], &s[3]));
    let mut out = [0u8; MAX_RATE];
    out[..BLOCK_SIZE].copy_from_slice(&z);
    out
}

/// The two halves of a key or a nonce.
fn halves(bytes: &[u8; 32]) -> ([u8; BLOCK_SIZE], [u8; BLOCK_SIZE]) {
    let mut low = [0u8; BLOCK_SIZE];
    let mut high = [0u8; BLOCK_SIZE];
    let (a, b) = bytes.split_at(BLOCK_SIZE);
    low.copy_from_slice(a);
    high.copy_from_slice(b);
    (low, high)
}

impl Variant for Aegis256 {
    type Nonce = [u8; NONCE_SIZE];

    const RATE: usize = BLOCK_SIZE;

    fn init(kernel: Chosen, key: &Self::Key, nonce: &Self::Nonce) -> State {
        let (mut k0, mut k1) = halves(key.array());
        let (n0, n1) = halves(nonce);
        let mut state = [
            xor(&k0, &n0),
            xor(&k1, &n1),
            C1,
            C0,
            xor(&k0, &C0),
            xor(&k1, &C1),
            [0; BLOCK_SIZE],
            [0; BLOCK_SIZE],
        ];
        // Four times over: the two halves of the key, then each with
        // its half of the nonce.
        let mut blocks = [0u8; 4 * 4 * BLOCK_SIZE];
        for four in blocks.chunks_exact_mut(4 * BLOCK_SIZE) {
            let inputs = [k0, k1, state[0], state[1]];
            four.copy_from_slice(inputs.as_flattened());
        }
        k0.zeroize();
        k1.zeroize();
        // The first two blocks of the state are among the inputs,
        // and the updates change them, so they were copied first.
        Self::absorb(kernel, &mut state, &blocks);
        blocks.zeroize();
        state
    }

    fn absorb(kernel: Chosen, state: &mut State, blocks: &[u8]) {
        match kernel.0 {
            Kernel::Tables => portable::tables256::absorb(state, blocks),
            _ => portable::bitsliced256::absorb(state, blocks),
        }
    }

    fn encrypt(kernel: Chosen, state: &mut State, data: &mut [u8]) {
        match kernel.0 {
            Kernel::Tables => portable::tables256::encrypt(state, data),
            _ => portable::bitsliced256::encrypt(state, data),
        }
    }

    fn decrypt(kernel: Chosen, state: &mut State, data: &mut [u8]) {
        match kernel.0 {
            Kernel::Tables => portable::tables256::decrypt(state, data),
            _ => portable::bitsliced256::decrypt(state, data),
        }
    }

    fn keystream(state: &State) -> [u8; MAX_RATE] {
        keystream(state)
    }

    fn tag(
        kernel: Chosen,
        state: &mut State,
        aad_bits: u64,
        message_bits: u64,
    ) -> [u8; TAG] {
        let mut t = xor(&state[3], &lengths(aad_bits, message_bits));
        // Seven updates with that block.
        let mut blocks = [0u8; 7 * BLOCK_SIZE];
        for block in blocks.chunks_exact_mut(BLOCK_SIZE) {
            block.copy_from_slice(&t);
        }
        Self::absorb(kernel, state, &blocks);
        blocks.zeroize();
        t.zeroize();
        state[1..6].iter().fold(state[0], |tag, s| xor(&tag, s))
    }
}

#[cfg(test)]
mod tests {
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

    fn wide(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    /// Each kernel this processor can run under the set in force,
    /// the virtual features granted.
    fn kernels() -> impl Iterator<Item = Kernel> {
        KERNELS
            .iter()
            .map(|(kernel, _)| *kernel)
            .filter(|kernel| features::available(KERNELS, *kernel))
    }

    fn aead(key: &str, kernel: Kernel) -> Aegis256 {
        Aegis256::with_kernel(&Key::from(wide(key)), kernel).unwrap()
    }

    #[test]
    fn dispatches() {
        let aead = Aegis256::new(&Key::zeroed());
        features::dispatches(KERNELS, Aegis256::profiles(), aead.kernel());
    }

    /// The draft's appendix A.3.1.
    #[test]
    fn update() {
        let before = [
            "1fa1207ed76c86f2c4bb40e8b395b43e",
            "b44c375e6c1e1978db64bcd12e9e332f",
            "0dab84bfa9f0226432ff630f233d4e5b",
            "d7ef65c9b93e8ee60c75161407b066e7",
            "a760bb3da073fbd92bdc24734b1f56fb",
            "a828a18d6a964497ac6e7e53c5f55c73",
        ];
        let message = hex("b165617ed04ab738afb2612c6d18a1ec");
        let after = [
            "e6bc643bae82dfa3d991b1b323839dcd",
            "648578232ba0f2f0a3677f617dc052c3",
            "ea788e0e572044a46059212dd007a789",
            "2f1498ae19b80da13fba698f088a8590",
            "a54c2ee95e8c2a2c3dae2ec743ae6b86",
            "a3240fceb68e32d5d114df1b5363ab67",
        ];
        let state = |blocks: [&str; 6]| -> State {
            core::array::from_fn(|i| {
                blocks.get(i).map_or([0; 16], |s| block(s))
            })
        };
        for kernel in kernels() {
            let mut got = state(before);
            Aegis256::absorb(Chosen(kernel), &mut got, &message);
            // The two blocks this variant does not use stay zero.
            assert_eq!(got, state(after), "{kernel:?}");
        }
    }

    const KEY: &str = "10010000000000000000000000000000\
                       00000000000000000000000000000000";
    const NONCE: &str = "10000200000000000000000000000000\
                         00000000000000000000000000000000";

    /// The draft's appendix A.3.2 to A.3.6: additional data, message,
    /// ciphertext and 128-bit tag, under [`KEY`] and [`NONCE`].
    const VALID: &[[&str; 4]] = &[
        [
            "",
            "00000000000000000000000000000000",
            "754fc3d8c973246dcc6d741412a4b236",
            "3fe91994768b332ed7f570a19ec5896e",
        ],
        ["", "", "", "e3def978a0f054afd1e761d7553afba3"],
        [
            "0001020304050607",
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f",
            "f373079ed84b2709faee373584585d60\
             accd191db310ef5d8b11833df9dec711",
            "8d86f91ee606e9ff26a01b64ccbdd91d",
        ],
        [
            "0001020304050607",
            "000102030405060708090a0b0c0d",
            "f373079ed84b2709faee37358458",
            "c60b9c2d33ceb058f96e6dd03c215652",
        ],
        [
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             20212223242526272829",
            "101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             3031323334353637",
            "57754a7d09963e7c787583a2e7b859bb\
             24fa1e04d49fd550b2511a358e3bca25\
             2a9b1b8b30cc4a67",
            "ab8a7d53fd0e98d727accca94925e128",
        ],
    ];

    #[test]
    fn draft_vectors() {
        for kernel in kernels() {
            let aead = aead(KEY, kernel);
            let nonce = wide(NONCE);
            for (i, [aad, message, sealed, tag]) in VALID.iter().enumerate() {
                let (aad, message) = (hex(aad), hex(message));
                let mut data = message.clone();
                let mut got = [0u8; 16];
                aead.encrypt(&nonce, &aad, &mut data, &mut got).unwrap();
                assert_eq!(data, hex(sealed), "{kernel:?} vector {}", i + 1);
                assert_eq!(got, block(tag), "{kernel:?} vector {}", i + 1);
                aead.decrypt(&nonce, &aad, &mut data, &got).unwrap();
                assert_eq!(data, message, "{kernel:?} vector {}", i + 1);
            }
        }
    }

    /// The draft's appendix A.3.7 to A.3.10, each of which must fail:
    /// key and nonce exchanged, then a wrong ciphertext, wrong
    /// additional data and a wrong tag.
    #[test]
    fn draft_vectors_that_must_fail() {
        const AAD: &str = "0001020304050607";
        const SEALED: &str = "f373079ed84b2709faee37358458";
        const TAG: &str = "c60b9c2d33ceb058f96e6dd03c215652";
        let cases = [
            (NONCE, KEY, AAD, SEALED, TAG),
            (KEY, NONCE, AAD, "f373079ed84b2709faee37358459", TAG),
            (KEY, NONCE, "0001020304050608", SEALED, TAG),
            (KEY, NONCE, AAD, SEALED, "c60b9c2d33ceb058f96e6dd03c215653"),
        ];
        for kernel in kernels() {
            for (i, (key, nonce, aad, sealed, tag)) in cases.iter().enumerate()
            {
                let mut data = hex(sealed);
                let result = aead(key, kernel).decrypt(
                    &wide(nonce),
                    &hex(aad),
                    &mut data,
                    &block(tag),
                );
                assert_eq!(
                    result,
                    Err(Error::AuthenticationFailed),
                    "{kernel:?} vector {}",
                    i + 6
                );
                assert_eq!(data, [0u8; 14], "{kernel:?} vector {}", i + 6);
            }
        }
    }

    /// A message of every length to a little over eight blocks, with
    /// additional data of every length likewise, sealed whole and
    /// then again in pieces of every size: every kernel must agree
    /// with the first, and the pieces with the whole.
    #[test]
    fn kernels_and_pieces_agree() {
        let key = "000102030405060708090a0b0c0d0e0f\
                   101112131415161718191a1b1c1d1e1f";
        let nonce = [0x5au8; 32];
        let bytes: [u8; 140] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let mut reference: Vec<(Vec<u8>, [u8; 16])> = Vec::new();
        for (k, kernel) in kernels().enumerate() {
            let aead = aead(key, kernel);
            for length in 0..=bytes.len() {
                let message = &bytes[..length];
                let aad = &bytes[..(length * 3) % 71];
                let mut whole = message.to_vec();
                let mut tag = [0u8; 16];
                aead.encrypt(&nonce, aad, &mut whole, &mut tag).unwrap();
                if k == 0 {
                    reference.push((whole.clone(), tag));
                }
                assert_eq!(
                    reference[length],
                    (whole.clone(), tag),
                    "{kernel:?} length {length}"
                );

                let size = 1 + length % 37;
                let mut data = message.to_vec();
                let mut e = aead.encryptor(&nonce);
                for piece in aad.chunks(size) {
                    e.aad(piece).unwrap();
                }
                for piece in data.chunks_mut(size) {
                    e.update(piece).unwrap();
                }
                assert_eq!(data, whole, "{kernel:?} {length} by {size}");
                assert_eq!(e.finalize(), tag, "{kernel:?} {length} by {size}");

                let mut d = aead.decryptor(&nonce);
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

    #[test]
    fn aad_after_message_is_out_of_order() {
        let aead = Aegis256::new(&Key::zeroed());
        let mut e = aead.encryptor(&[0u8; 32]);
        e.update(&mut [0u8; 3]).unwrap();
        assert_eq!(e.aad(b"late"), Err(Error::OutOfOrder));
        let mut d = aead.decryptor(&[0u8; 32]);
        d.update(&mut []).unwrap();
        assert_eq!(d.aad(b"late"), Err(Error::OutOfOrder));
    }

    #[test]
    fn wipes_and_hides_the_key() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Aegis256>();
        let aead = Aegis256::new(&Key::from([0x5au8; 32]));
        let text = std::format!("{aead:?}");
        assert!(!text.contains("5a"), "{text}");
        let text = std::format!("{:?}", aead.decryptor(&[0x5au8; 32]));
        assert!(!text.contains("5a"), "{text}");
    }
}
