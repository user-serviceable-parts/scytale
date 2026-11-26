//! AEGIS-128L: a 128-bit key and nonce, a state of eight blocks, and
//! two blocks of input to an update.

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
const KEY_SIZE: usize = 16;

/// The nonce length, in bytes.
const NONCE_SIZE: usize = 16;

/// The kernels, best first; see [`crate::cipher::aes::AEGIS128L`].
pub(crate) const KERNELS: &[(Kernel, Features)] = crate::cipher::aes::AEGIS128L;

/// What the list publishes: the needs, without the names.
const PROFILES: [Features; KERNELS.len()] = features::profiles_of(KERNELS);

/// AEGIS-128L under one key.
///
/// See the [module](super) for what it is and how to use it safely.
#[derive(Clone)]
pub struct Aegis128L {
    key: Key<[u8; KEY_SIZE]>,
    kernel: Kernel,
}

impl Aegis128L {
    /// Takes the key.
    pub fn new(ctx: Context, key: &Key<[u8; KEY_SIZE]>) -> Self {
        Aegis128L {
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
        Some(Aegis128L {
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

impl ZeroizeOnDrop for Aegis128L {}

impl fmt::Debug for Aegis128L {
    /// Deliberately omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aegis128L").finish_non_exhaustive()
    }
}

impl features::sealed::Sealed for Aegis128L {}

impl Dispatcher for Aegis128L {
    fn profiles() -> &'static [Features] {
        Aegis128L::profiles()
    }
}

impl KeyType for Aegis128L {
    type Key = Key<[u8; KEY_SIZE]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

impl Aead for Aegis128L {
    type Nonce = [u8; NONCE_SIZE];
    type Tag = [u8; TAG];

    fn new(ctx: Context, key: &Self::Key) -> Self {
        // The inherent constructor, which takes precedence here.
        Aegis128L::new(ctx, key)
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

/// The keystream for the next block: z0 then z1.
pub(super) fn keystream(s: &State) -> [u8; 2 * BLOCK_SIZE] {
    let z0 = xor(&xor(&s[1], &s[6]), &and(&s[2], &s[3]));
    let z1 = xor(&xor(&s[2], &s[5]), &and(&s[6], &s[7]));
    let mut z = [0u8; 2 * BLOCK_SIZE];
    z[..BLOCK_SIZE].copy_from_slice(&z0);
    z[BLOCK_SIZE..].copy_from_slice(&z1);
    z
}

/// `Absorb`, of the one block `block`, `times` over: what `Init` and
/// `Finalize` are made of. A kernel does this without the block
/// being written out that many times, which would be a secret that
/// many times as long to wipe.
pub(super) fn stir(
    kernel: Chosen,
    state: &mut State,
    block: &[u8; 2 * BLOCK_SIZE],
    times: usize,
) {
    match kernel.0 {
        // The parallel variants stir a lane at a time, whichever
        // kernel takes their input two lanes at a time.
        #[cfg(target_arch = "x86_64")]
        Kernel::AesNi | Kernel::Vaes => x86_64::stir128l(state, block, times),
        #[cfg(target_arch = "aarch64")]
        Kernel::Armv8 => aarch64::stir128l(state, block, times),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zvkned => riscv64::zvkned::stir128l(state, block, times),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zkn => riscv64::zkn::stir128l(state, block, times),
        Kernel::Tables => portable::tables128l::stir(state, block, times),
        _ => portable::bitsliced128l::stir(state, block, times),
    }
}

/// The state `Init` starts from, before the key and nonce are
/// stirred in.
pub(super) fn start(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> State {
    [
        xor(key, nonce),
        C1,
        C0,
        C1,
        xor(key, nonce),
        xor(key, &C0),
        xor(key, &C1),
        xor(key, &C0),
    ]
}

/// `Finalize` from the lengths on: the seven updates and the fold
/// that is the 128-bit tag. `lengths` is the block of them.
pub(super) fn finish(
    kernel: Chosen,
    state: &mut State,
    lengths: &[u8; BLOCK_SIZE],
) -> [u8; TAG] {
    let mut t = xor(&state[2], lengths);
    // Seven updates with that block in both halves.
    let mut block = [0u8; 2 * BLOCK_SIZE];
    let (m0, m1) = block.split_at_mut(BLOCK_SIZE);
    m0.copy_from_slice(&t);
    m1.copy_from_slice(&t);
    stir(kernel, state, &block, 7);
    block.zeroize();
    t.zeroize();
    fold(state)
}

/// The 128-bit tag of a state that has had `Finalize`'s updates.
pub(super) fn fold(state: &State) -> [u8; TAG] {
    state[1..7].iter().fold(state[0], |tag, s| xor(&tag, s))
}

/// Where a lane's two pieces lie in a block of a parallel variant's
/// input.
fn pieces(lane: Lane) -> [usize; 2] {
    [lane.offset, lane.offset + lane.width / 2]
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
            x86_64::absorb128l_lane(state, data, lane)
        }
        #[cfg(target_arch = "aarch64")]
        Kernel::Armv8 => aarch64::absorb128l_lane(state, data, lane),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zvkned => riscv64::zvkned::absorb128l_lane(state, data, lane),
        _ => gathered(data, lane.width, pieces(lane), |blocks| {
            <Aegis128L as Variant>::absorb(kernel, state, blocks)
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
            x86_64::encrypt128l_lane(state, data, lane)
        }
        #[cfg(target_arch = "aarch64")]
        Kernel::Armv8 => aarch64::encrypt128l_lane(state, data, lane),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zvkned => riscv64::zvkned::encrypt128l_lane(state, data, lane),
        _ => gathered_mut(data, lane.width, pieces(lane), |blocks| {
            <Aegis128L as Variant>::encrypt(kernel, state, blocks)
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
            x86_64::decrypt128l_lane(state, data, lane)
        }
        #[cfg(target_arch = "aarch64")]
        Kernel::Armv8 => aarch64::decrypt128l_lane(state, data, lane),
        #[cfg(target_arch = "riscv64")]
        Kernel::Zvkned => riscv64::zvkned::decrypt128l_lane(state, data, lane),
        _ => gathered_mut(data, lane.width, pieces(lane), |blocks| {
            <Aegis128L as Variant>::decrypt(kernel, state, blocks)
        }),
    }
}

impl Variant for Aegis128L {
    type Nonce = [u8; NONCE_SIZE];
    type State = State;
    type Block = [u8; 2 * BLOCK_SIZE];

    const RATE: usize = 2 * BLOCK_SIZE;

    fn init(kernel: Chosen, key: &Self::Key, nonce: &Self::Nonce) -> State {
        let key = key.array();
        let mut state = start(key, nonce);
        // Ten updates with the nonce and the key.
        let mut block = [0u8; 2 * BLOCK_SIZE];
        let (m0, m1) = block.split_at_mut(BLOCK_SIZE);
        m0.copy_from_slice(nonce);
        m1.copy_from_slice(key);
        stir(kernel, &mut state, &block, 10);
        block.zeroize();
        state
    }

    fn absorb(kernel: Chosen, state: &mut State, blocks: &[u8]) {
        match kernel.0 {
            #[cfg(target_arch = "x86_64")]
            Kernel::AesNi => x86_64::absorb128l(state, blocks),
            #[cfg(target_arch = "aarch64")]
            Kernel::Armv8 => aarch64::absorb128l(state, blocks),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zvkned => riscv64::zvkned::absorb128l(state, blocks),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zkn => riscv64::zkn::absorb128l(state, blocks),
            Kernel::Tables => portable::tables128l::absorb(state, blocks),
            _ => portable::bitsliced128l::absorb(state, blocks),
        }
    }

    fn encrypt(kernel: Chosen, state: &mut State, data: &mut [u8]) {
        match kernel.0 {
            #[cfg(target_arch = "x86_64")]
            Kernel::AesNi => x86_64::encrypt128l(state, data),
            #[cfg(target_arch = "aarch64")]
            Kernel::Armv8 => aarch64::encrypt128l(state, data),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zvkned => riscv64::zvkned::encrypt128l(state, data),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zkn => riscv64::zkn::encrypt128l(state, data),
            Kernel::Tables => portable::tables128l::encrypt(state, data),
            _ => portable::bitsliced128l::encrypt(state, data),
        }
    }

    fn decrypt(kernel: Chosen, state: &mut State, data: &mut [u8]) {
        match kernel.0 {
            #[cfg(target_arch = "x86_64")]
            Kernel::AesNi => x86_64::decrypt128l(state, data),
            #[cfg(target_arch = "aarch64")]
            Kernel::Armv8 => aarch64::decrypt128l(state, data),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zvkned => riscv64::zvkned::decrypt128l(state, data),
            #[cfg(target_arch = "riscv64")]
            Kernel::Zkn => riscv64::zkn::decrypt128l(state, data),
            Kernel::Tables => portable::tables128l::decrypt(state, data),
            _ => portable::bitsliced128l::decrypt(state, data),
        }
    }

    fn keystream(state: &State) -> [u8; 2 * BLOCK_SIZE] {
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
        crate::vectors::support::wycheproof::aegis::aegis128l(&|key| {
            Aegis128L::new(under.ctx(), key)
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

    fn aead(key: &str, kernel: Kernel) -> Aegis128L {
        Aegis128L::with_kernel(&Key::from(block(key)), kernel).unwrap()
    }

    #[test]
    fn dispatches() {
        {
            let aead = Aegis128L::new(Context::default(), &Key::zeroed());
            features::dispatches(KERNELS, Aegis128L::profiles(), aead.kernel());
        };
    }

    /// The draft's appendix A.2.1.
    fn update() {
        let before = [
            "9b7e60b24cc873ea894ecc07911049a3",
            "330be08f35300faa2ebf9a7b0d274658",
            "7bbd5bd2b049f7b9b515cf26fbe7756c",
            "c35a00f55ea86c3886ec5e928f87db18",
            "9ebccafce87cab446396c4334592c91f",
            "58d83e31f256371e60fc6bb257114601",
            "1639b56ea322c88568a176585bc915de",
            "640818ffb57dc0fbc2e72ae93457e39a",
        ];
        let message = hex(concat!(
            "033e6975b94816879e42917650955aa0",
            "fcc1968a46b7e97861bd6e89af6aa55f",
        ));
        let after = [
            "596ab773e4433ca0127c73f60536769d",
            "790394041a3d26ab697bde865014652d",
            "38cf49e4b65248acd533041b64dd0611",
            "16d8e58748f437bfff1797f780337cee",
            "9689ecdf08228c74d7e3360cca53d0a5",
            "a21746bb193a569e331e1aa985d0d729",
            "09d714e6fcf9177a8ed1cde7e3d259a6",
            "61279ba73167f0ab76f0a11bf203bdff",
        ];
        for kernel in kernels() {
            let mut state: State = before.map(block);
            Aegis128L::absorb(Chosen(kernel), &mut state, &message);
            assert_eq!(state, after.map(block), "{kernel:?}");
        }
    }

    const KEY: &str = "10010000000000000000000000000000";
    const NONCE: &str = "10000200000000000000000000000000";

    /// The draft's appendix A.2.2 to A.2.6: additional data, message,
    /// ciphertext and 128-bit tag, under [`KEY`] and [`NONCE`].
    const VALID: &[[&str; 4]] = &[
        [
            "",
            "00000000000000000000000000000000",
            "c1c0e58bd913006feba00f4b3cc3594e",
            "abe0ece80c24868a226a35d16bdae37a",
        ],
        ["", "", "", "c2b879a67def9d74e6c14f708bbcc9b4"],
        [
            "0001020304050607",
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f",
            "79d94593d8c2119d7e8fd9b8fc77845c\
             5c077a05b2528b6ac54b563aed8efe84",
            "cc6f3372f6aa1bb82388d695c3962d9a",
        ],
        [
            "0001020304050607",
            "000102030405060708090a0b0c0d",
            "79d94593d8c2119d7e8fd9b8fc77",
            "5c04b3dba849b2701effbe32c7f0fab7",
        ],
        [
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             20212223242526272829",
            "101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             3031323334353637",
            "b31052ad1cca4e291abcf2df3502e6bd\
             b1bfd6db36798be3607b1f94d34478aa\
             7ede7f7a990fec10",
            "7542a745733014f9474417b337399507",
        ],
    ];

    fn draft_vectors() {
        for kernel in kernels() {
            let aead = aead(KEY, kernel);
            let nonce = block(NONCE);
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

    /// The draft's appendix A.2.7 to A.2.10, each of which must fail:
    /// key and nonce exchanged, then a wrong ciphertext, wrong
    /// additional data and a wrong tag.
    fn draft_vectors_that_must_fail() {
        const AAD: &str = "0001020304050607";
        const SEALED: &str = "79d94593d8c2119d7e8fd9b8fc77";
        const TAG: &str = "5c04b3dba849b2701effbe32c7f0fab7";
        let cases = [
            (NONCE, KEY, AAD, SEALED, TAG),
            (KEY, NONCE, AAD, "79d94593d8c2119d7e8fd9b8fc78", TAG),
            (KEY, NONCE, "0001020304050608", SEALED, TAG),
            (KEY, NONCE, AAD, SEALED, "6c04b3dba849b2701effbe32c7f0fab8"),
        ];
        for kernel in kernels() {
            for (i, (key, nonce, aad, sealed, tag)) in cases.iter().enumerate()
            {
                let mut data = hex(sealed);
                let result = aead(key, kernel).decrypt(
                    &block(nonce),
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

    /// A message of every length to a little over ten blocks, with
    /// additional data of every length likewise, sealed whole and
    /// then again in pieces of every size: every kernel must agree
    /// with the first, and the pieces with the whole.
    fn kernels_and_pieces_agree() {
        let key = "000102030405060708090a0b0c0d0e0f";
        let nonce = [0x5au8; 16];
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
        let aead = Aegis128L::new(Context::default(), &Key::zeroed());
        let mut e = aead.encryptor(&[0u8; 16]);
        e.update(&mut [0u8; 3]).unwrap();
        assert_eq!(e.aad(b"late"), Err(Error::OutOfOrder));
        let mut d = aead.decryptor(&[0u8; 16]);
        d.update(&mut []).unwrap();
        assert_eq!(d.aad(b"late"), Err(Error::OutOfOrder));
    }

    #[test]
    fn wipes_and_hides_the_key() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Aegis128L>();
        wipes::<Key<[u8; KEY_SIZE]>>();
        let aead = Aegis128L::new(Context::default(), &Key::from([0x5au8; 16]));
        let text = std::format!("{aead:?}");
        assert!(!text.contains("5a"), "{text}");
        let text = std::format!("{:?}", aead.encryptor(&[0x5au8; 16]));
        assert!(!text.contains("5a"), "{text}");
    }
}
