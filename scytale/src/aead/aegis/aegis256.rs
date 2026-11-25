//! AEGIS-256: a 256-bit key and nonce, a state of six blocks, and one
//! block of input to an update.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::sealed::{Chosen, Variant};
use super::{
    C0, C1, Decryptor, Encryptor, Lane, State, TAG, and, gathered,
    gathered_mut, lengths, open, portable, seal, xor,
};
use crate::aead::Aead;
use crate::cipher::aes::{BLOCK_SIZE, Kernel};
use crate::features::{self, Dispatcher, Features};
use crate::{Context, Error, Key, KeyType};

#[cfg(target_arch = "aarch64")]
use super::aarch64;
#[cfg(target_arch = "riscv64")]
use super::riscv64;
#[cfg(target_arch = "x86_64")]
use super::x86_64;

/// The key length, in bytes.
const KEY_SIZE: usize = 32;

/// The nonce length, in bytes.
const NONCE_SIZE: usize = 32;

/// The kernels, best first; see [`crate::cipher::aes::AEGIS256`].
pub(crate) const KERNELS: &[(Kernel, Features)] = crate::cipher::aes::AEGIS256;

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
    pub fn new(ctx: Context, key: &Key<[u8; KEY_SIZE]>) -> Self {
        Aegis256 {
            key: key.clone(),
            kernel: features::select(ctx, KERNELS).unwrap_or(Kernel::Bitsliced),
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

    /// Takes the key for `kernel` alone, trusting the caller: the
    /// meta tests pass only the kernel the list chose under the
    /// row's features, which the processor has.
    #[cfg(test)]
    pub(crate) fn with_kernel(
        key: &Key<[u8; KEY_SIZE]>,
        kernel: Kernel,
    ) -> Option<Self> {
        Some(Aegis256 {
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

    fn new(ctx: Context, key: &Self::Key) -> Self {
        // The inherent constructor, which takes precedence here.
        Aegis256::new(ctx, key)
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

/// The keystream for the next block.
pub(super) fn keystream(s: &State) -> [u8; BLOCK_SIZE] {
    xor(&xor(&xor(&s[1], &s[4]), &s[5]), &and(&s[2], &s[3]))
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

/// `Absorb`, of the one block `block`, `times` over: what `Init` and
/// `Finalize` are made of. A kernel does this without the block
/// being written out that many times, which would be a secret that
/// many times as long to wipe.
pub(super) fn stir(
    kernel: Chosen,
    state: &mut State,
    block: &[u8; BLOCK_SIZE],
    times: usize,
) {
    match kernel.0 {
        #[cfg(target_arch = "x86_64")]
        Kernel::AesNi | Kernel::Vaes => x86_64::stir256(state, block, times),
        #[cfg(target_arch = "aarch64")]
        Kernel::Armv8 => aarch64::stir256(state, block, times),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zvkned => riscv64::zvkned::stir256(state, block, times),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zkn => riscv64::zkn::stir256(state, block, times),
        Kernel::Tables => portable::tables256::stir(state, block, times),
        _ => portable::bitsliced256::stir(state, block, times),
    }
}

/// The state `Init` starts from, and the four blocks it then takes
/// in, four times over: the two halves of the key, then each with
/// its half of the nonce. Those last two are the first two blocks
/// of the state as it starts.
pub(super) fn start(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> (State, [[u8; BLOCK_SIZE]; 4]) {
    let (mut k0, mut k1) = halves(key);
    let (n0, n1) = halves(nonce);
    let state = [
        xor(&k0, &n0),
        xor(&k1, &n1),
        C1,
        C0,
        xor(&k0, &C0),
        xor(&k1, &C1),
        [0; BLOCK_SIZE],
        [0; BLOCK_SIZE],
    ];
    let inputs = [k0, k1, state[0], state[1]];
    k0.zeroize();
    k1.zeroize();
    (state, inputs)
}

/// `Finalize` from the lengths on: the seven updates and the fold
/// that is the 128-bit tag. `lengths` is the block of them.
pub(super) fn finish(
    kernel: Chosen,
    state: &mut State,
    lengths: &[u8; BLOCK_SIZE],
) -> [u8; TAG] {
    let mut t = xor(&state[3], lengths);
    // Seven updates with that block.
    stir(kernel, state, &t, 7);
    t.zeroize();
    fold(state)
}

/// The 128-bit tag of a state that has had `Finalize`'s updates.
pub(super) fn fold(state: &State) -> [u8; TAG] {
    state[1..6].iter().fold(state[0], |tag, s| xor(&tag, s))
}

/// `Absorb`, for one lane of a parallel variant: this state takes
/// its share of each block of `data`.
pub(super) fn absorb_lane(
    kernel: Chosen,
    state: &mut State,
    data: &[u8],
    lane: Lane,
) {
    match kernel.0 {
        #[cfg(target_arch = "x86_64")]
        Kernel::AesNi | Kernel::Vaes => {
            x86_64::absorb256_lane(state, data, lane)
        }
        #[cfg(target_arch = "aarch64")]
        Kernel::Armv8 => aarch64::absorb256_lane(state, data, lane),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zvkned => riscv64::zvkned::absorb256_lane(state, data, lane),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zkn => riscv64::zkn::absorb256_lane(state, data, lane),
        _ => gathered(data, lane.width, [lane.offset], |blocks| {
            <Aegis256 as Variant>::absorb(kernel, state, blocks)
        }),
    }
}

/// `Enc`, for one lane of a parallel variant.
pub(super) fn encrypt_lane(
    kernel: Chosen,
    state: &mut State,
    data: &mut [u8],
    lane: Lane,
) {
    match kernel.0 {
        #[cfg(target_arch = "x86_64")]
        Kernel::AesNi | Kernel::Vaes => {
            x86_64::encrypt256_lane(state, data, lane)
        }
        #[cfg(target_arch = "aarch64")]
        Kernel::Armv8 => aarch64::encrypt256_lane(state, data, lane),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zvkned => riscv64::zvkned::encrypt256_lane(state, data, lane),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zkn => riscv64::zkn::encrypt256_lane(state, data, lane),
        _ => gathered_mut(data, lane.width, [lane.offset], |blocks| {
            <Aegis256 as Variant>::encrypt(kernel, state, blocks)
        }),
    }
}

/// `Dec`, for one lane of a parallel variant.
pub(super) fn decrypt_lane(
    kernel: Chosen,
    state: &mut State,
    data: &mut [u8],
    lane: Lane,
) {
    match kernel.0 {
        #[cfg(target_arch = "x86_64")]
        Kernel::AesNi | Kernel::Vaes => {
            x86_64::decrypt256_lane(state, data, lane)
        }
        #[cfg(target_arch = "aarch64")]
        Kernel::Armv8 => aarch64::decrypt256_lane(state, data, lane),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zvkned => riscv64::zvkned::decrypt256_lane(state, data, lane),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zkn => riscv64::zkn::decrypt256_lane(state, data, lane),
        _ => gathered_mut(data, lane.width, [lane.offset], |blocks| {
            <Aegis256 as Variant>::decrypt(kernel, state, blocks)
        }),
    }
}

impl Variant for Aegis256 {
    type Nonce = [u8; NONCE_SIZE];
    type State = State;
    type Block = [u8; BLOCK_SIZE];

    const RATE: usize = BLOCK_SIZE;

    fn init(kernel: Chosen, key: &Self::Key, nonce: &Self::Nonce) -> State {
        let (mut state, mut inputs) = start(key.array(), nonce);
        for _ in 0..4 {
            Self::absorb(kernel, &mut state, inputs.as_flattened());
        }
        inputs.zeroize();
        state
    }

    fn absorb(kernel: Chosen, state: &mut State, blocks: &[u8]) {
        match kernel.0 {
            #[cfg(target_arch = "x86_64")]
            Kernel::AesNi | Kernel::Vaes => x86_64::absorb256(state, blocks),
            #[cfg(target_arch = "aarch64")]
            Kernel::Armv8 => aarch64::absorb256(state, blocks),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zvkned => riscv64::zvkned::absorb256(state, blocks),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zkn => riscv64::zkn::absorb256(state, blocks),
            Kernel::Tables => portable::tables256::absorb(state, blocks),
            _ => portable::bitsliced256::absorb(state, blocks),
        }
    }

    fn encrypt(kernel: Chosen, state: &mut State, data: &mut [u8]) {
        match kernel.0 {
            #[cfg(target_arch = "x86_64")]
            Kernel::AesNi | Kernel::Vaes => x86_64::encrypt256(state, data),
            #[cfg(target_arch = "aarch64")]
            Kernel::Armv8 => aarch64::encrypt256(state, data),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zvkned => riscv64::zvkned::encrypt256(state, data),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zkn => riscv64::zkn::encrypt256(state, data),
            Kernel::Tables => portable::tables256::encrypt(state, data),
            _ => portable::bitsliced256::encrypt(state, data),
        }
    }

    fn decrypt(kernel: Chosen, state: &mut State, data: &mut [u8]) {
        match kernel.0 {
            #[cfg(target_arch = "x86_64")]
            Kernel::AesNi | Kernel::Vaes => x86_64::decrypt256(state, data),
            #[cfg(target_arch = "aarch64")]
            Kernel::Armv8 => aarch64::decrypt256(state, data),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zvkned => riscv64::zvkned::decrypt256(state, data),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zkn => riscv64::zkn::decrypt256(state, data),
            Kernel::Tables => portable::tables256::decrypt(state, data),
            _ => portable::bitsliced256::decrypt(state, data),
        }
    }

    fn keystream(state: &State) -> [u8; BLOCK_SIZE] {
        keystream(state)
    }

    fn tag(
        kernel: Chosen,
        state: &mut State,
        aad_bits: u64,
        message_bits: u64,
    ) -> [u8; TAG] {
        finish(kernel, state, &lengths(aad_bits, message_bits))
    }
}

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

    fn wide(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    /// This variant under one kernel: the draft's vectors and the
    /// rest below, each against the portable kernel. The kernel the
    /// list chooses under the row's features is the one they build
    /// on, through the test constructor that trusts its caller.
    pub(crate) fn kernel(under: &features::Under) {
        let chosen = features::select(under.ctx(), KERNELS).expect("listed");
        UNDER.set(Some(chosen));
        update();
        draft_vectors();
        draft_vectors_that_must_fail();
        kernels_and_pieces_agree();
        crate::vectors::support::wycheproof::aegis::aegis256(&|key| {
            Aegis256::new(under.ctx(), key)
        });
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

    fn aead(key: &str, kernel: Kernel) -> Aegis256 {
        Aegis256::with_kernel(&Key::from(wide(key)), kernel).unwrap()
    }

    #[test]
    fn dispatches() {
        {
            let aead = Aegis256::new(crate::Context::default(), &Key::zeroed());
            features::dispatches(KERNELS, Aegis256::profiles(), aead.kernel());
        };
    }

    /// The draft's appendix A.3.1.
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

    /// A message of every length to a little over twenty blocks, with
    /// additional data of every length likewise, sealed whole and
    /// then again in pieces of every size: every kernel must agree
    /// with the first, and the pieces with the whole.
    fn kernels_and_pieces_agree() {
        let key = "000102030405060708090a0b0c0d0e0f\
                   101112131415161718191a1b1c1d1e1f";
        let nonce = [0x5au8; 32];
        let bytes: [u8; 330] = core::array::from_fn(|i| (i * 7 + 3) as u8);
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
        let aead = Aegis256::new(crate::Context::default(), &Key::zeroed());
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
        let aead =
            Aegis256::new(crate::Context::default(), &Key::from([0x5au8; 32]));
        let text = std::format!("{aead:?}");
        assert!(!text.contains("5a"), "{text}");
        let text = std::format!("{:?}", aead.decryptor(&[0x5au8; 32]));
        assert!(!text.contains("5a"), "{text}");
    }
}
