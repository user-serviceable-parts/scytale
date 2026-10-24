//! Hash_DRBG (SP 800-90A section 10.1.1).

use core::fmt;
use core::marker::PhantomData;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::entropy;
use super::{Entropy, MAX_REQUEST, MIN_SEED, OVERSAMPLE, RESEED_INTERVAL};
use crate::hash::Hash;
use crate::{ByteArray, Error, Random};

/// The longest seed the standard defines, in bytes: 888 bits, for
/// the hashes with a digest longer than 256 bits.
const MAX_SEEDLEN: usize = 111;

/// The seed length SP 800-90A gives `H`, in bytes: 440 bits for a
/// digest of up to 256, 888 for anything longer. The table names
/// the hashes, but that is the rule it follows.
const fn seedlen<H: Hash>() -> usize {
    if size_of::<H::Output>() <= 32 {
        55
    } else {
        MAX_SEEDLEN
    }
}

/// A generator in the shape SP 800-90A calls Hash_DRBG, over the hash
/// `H`, seeded from `S`.
///
/// Everything [`CtrDrbg`](super::CtrDrbg) says about holding one
/// holds here: see the [module documentation](super) for the rule
/// across `fork` and virtual machine snapshots. This one needs only a
/// hash. Where there is a choice, [`HmacDrbg`](super::HmacDrbg) has
/// the simpler security argument; this one is here for the
/// deployments that call for it by name.
///
/// Deliberately not `Clone`, for the reason `CtrDrbg` is not.
#[derive(ZeroizeOnDrop)]
pub struct HashDrbg<H: Hash + Default, S: Entropy = entropy::System> {
    #[zeroize(skip)]
    source: S,
    /// The value and the constant that are the generator's whole
    /// secret, each the first `seedlen::<H>()` bytes of its array.
    v: [u8; MAX_SEEDLEN],
    c: [u8; MAX_SEEDLEN],
    /// Requests made since the last seeding, counted from one as
    /// SP 800-90A counts it.
    #[zeroize(skip)]
    counter: u64,
    #[zeroize(skip)]
    hash: PhantomData<H>,
}

impl<H: Hash + Default, S: Entropy> HashDrbg<H, S> {
    const SEEDLEN: usize = seedlen::<H>();

    /// A generator seeded from `source`, which is kept for every
    /// later reseeding.
    ///
    /// # Fork and snapshots
    ///
    /// A copy of this process holds a copy of this generator, and
    /// both will hand out the same bytes. Call
    /// [`reseed`](HashDrbg::reseed) in the copy before it is used, or
    /// build a fresh one there. See
    /// [the rule](super#fork-snapshots-and-clones-the-rule).
    ///
    /// # Errors
    ///
    /// Whatever the source refuses with.
    pub fn try_new(mut source: S) -> Result<Self, Error> {
        let mut raw = [0u8; MIN_SEED * OVERSAMPLE];
        let drawn = source.fill(&mut raw);
        let built = drawn.and_then(|()| Self::instantiate(&raw, source));
        raw.zeroize();
        built
    }

    /// Reseeds from the generator's own source: the call
    /// [the rule](super#fork-snapshots-and-clones-the-rule) asks for
    /// in a copy of the process. Made automatically once
    /// [`RESEED_INTERVAL`] requests have been made.
    ///
    /// # Errors
    ///
    /// Whatever the source refuses with. The generator is left
    /// exactly as it was.
    pub fn reseed(&mut self) -> Result<(), Error> {
        let mut raw = [0u8; MIN_SEED * OVERSAMPLE];
        let drawn = self.source.fill(&mut raw);
        let done = drawn.and_then(|()| self.reseed_from(&raw));
        raw.zeroize();
        done
    }

    /// Mixes `entropy` into the generator and starts the count again.
    /// The new material is combined with what is there, never
    /// substituted for it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSeedLength`] if `entropy` is shorter than
    /// [`MIN_SEED`]. The generator is left exactly as it was.
    pub fn reseed_from(&mut self, entropy: &[u8]) -> Result<(), Error> {
        self.reseed_with(entropy, &[])
    }

    /// [`reseed_from`](HashDrbg::reseed_from), with additional input
    /// mixed in alongside the entropy. The input is not credited as
    /// entropy.
    ///
    /// # Errors
    ///
    /// As `reseed_from`.
    pub fn reseed_with(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
    ) -> Result<(), Error> {
        if entropy.len() < MIN_SEED {
            return Err(Error::InvalidSeedLength(entropy.len()));
        }
        let n = Self::SEEDLEN;
        let mut seed = [0u8; MAX_SEEDLEN];
        derive::<H>(
            &[&[0x01], &self.v[..n], entropy, additional],
            &mut seed[..n],
        );
        self.set_seed(&seed);
        seed.zeroize();
        self.counter = 1;
        Ok(())
    }

    /// Fills `out` with random bytes, with additional input mixed
    /// into the state before they are made. With nothing in it this
    /// is exactly [`fill`](Random::fill).
    ///
    /// # Errors
    ///
    /// [`Error::RequestTooLarge`] for more than [`MAX_REQUEST`]
    /// bytes, and whatever the source refuses with when a reseeding
    /// is due. A refused request leaves the generator as it was.
    pub fn fill_with(
        &mut self,
        out: &mut [u8],
        additional: &[u8],
    ) -> Result<(), Error> {
        if out.len() > MAX_REQUEST {
            return Err(Error::RequestTooLarge(out.len()));
        }
        if self.counter > RESEED_INTERVAL {
            self.reseed()?;
        }
        let n = Self::SEEDLEN;
        let mut hash = H::default();
        if !additional.is_empty() {
            hash.update(&[0x02]);
            hash.update(&self.v[..n]);
            hash.update(additional);
            let mut w = hash.finalize();
            add(&mut self.v[..n], w.as_ref());
            w.zeroize();
        }

        // Hashgen: the output is the hashes of V, V + 1, V + 2 ...,
        // counted on a copy so that V itself moves only below.
        let mut data = [0u8; MAX_SEEDLEN];
        data[..n].copy_from_slice(&self.v[..n]);
        let (whole, tail) = H::Output::split_mut(out);
        for block in whole {
            hash.update(&data[..n]);
            *block = hash.finalize();
            add(&mut data[..n], &[1]);
        }
        if !tail.is_empty() {
            hash.update(&data[..n]);
            let mut last = hash.finalize();
            tail.copy_from_slice(&last.as_ref()[..tail.len()]);
            last.zeroize();
        }
        data.zeroize();

        // V = V + Hash(0x03 || V) + C + reseed_counter: the step that
        // moves the generator past what was just handed out.
        hash.update(&[0x03]);
        hash.update(&self.v[..n]);
        let mut h = hash.finalize();
        add(&mut self.v[..n], h.as_ref());
        h.zeroize();
        let c = self.c;
        add(&mut self.v[..n], &c[..n]);
        add(&mut self.v[..n], &self.counter.to_be_bytes());
        self.counter += 1;
        Ok(())
    }

    /// Builds a generator from material that has already been
    /// gathered: the entropy, nonce and personalization as one run.
    fn instantiate(material: &[u8], source: S) -> Result<Self, Error> {
        if material.len() < MIN_SEED {
            return Err(Error::InvalidSeedLength(material.len()));
        }
        let mut rng = HashDrbg {
            source,
            v: [0u8; MAX_SEEDLEN],
            c: [0u8; MAX_SEEDLEN],
            counter: 1,
            hash: PhantomData,
        };
        let mut seed = [0u8; MAX_SEEDLEN];
        derive::<H>(&[material], &mut seed[..Self::SEEDLEN]);
        rng.set_seed(&seed);
        seed.zeroize();
        Ok(rng)
    }

    /// V becomes the seed, and C is derived from it.
    fn set_seed(&mut self, seed: &[u8; MAX_SEEDLEN]) {
        let n = Self::SEEDLEN;
        self.v = *seed;
        derive::<H>(&[&[0x00], &self.v[..n]], &mut self.c[..n]);
    }
}

impl<H: Hash + Default> HashDrbg<H, entropy::System> {
    /// A generator seeded from this machine's own source, as
    /// [`CtrDrbg::from_system`](super::CtrDrbg::from_system) is.
    ///
    /// # Fork and snapshots
    ///
    /// Call [`reseed`](HashDrbg::reseed) in a copy of the process
    /// before it is used. See
    /// [the rule](super#fork-snapshots-and-clones-the-rule).
    ///
    /// # Errors
    ///
    /// As `CtrDrbg::from_system`.
    pub fn from_system() -> Result<Self, Error> {
        Self::try_new(entropy::System::try_new()?)
    }
}

/// The generator the vector suites and the unit tests are built on,
/// seeded from bytes the test holds. Not public, for the reasons
/// `CtrDrbg`'s is not.
#[cfg(test)]
impl<H: Hash + Default> HashDrbg<H, entropy::External> {
    /// A generator seeded from `seed`, the entropy, nonce and
    /// personalization as one run, at least [`MIN_SEED`] bytes.
    pub(crate) fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        Self::instantiate(seed, entropy::External)
    }
}

impl<H: Hash + Default, S: Entropy> Random for HashDrbg<H, S> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.fill_with(out, &[])
    }
}

impl<H: Hash + Default, S: Entropy> fmt::Debug for HashDrbg<H, S> {
    /// Deliberately omits the state, which is key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashDrbg")
            .field("requests_since_seeding", &(self.counter - 1))
            .finish()
    }
}

/// Hash_df: hashes the concatenation of `parts` out to the length of
/// `out`, a digest at a time, each under its own counter.
fn derive<H: Hash + Default>(parts: &[&[u8]], out: &mut [u8]) {
    // The length goes in as a 32-bit count of bits; a seed is at
    // most 888 of them.
    let bits = (8 * out.len() as u32).to_be_bytes();
    let mut hash = H::default();
    for (i, chunk) in out.chunks_mut(size_of::<H::Output>()).enumerate() {
        hash.update(&[(i + 1) as u8]);
        hash.update(&bits);
        for part in parts {
            hash.update(part);
        }
        let mut digest = hash.finalize();
        chunk.copy_from_slice(&digest.as_ref()[..chunk.len()]);
        digest.zeroize();
    }
}

/// Adds `x` into `v`, both big-endian, modulo 2 to the length of
/// `v`. The carry is carried through every byte whatever its value,
/// so the time does not depend on the numbers.
fn add(v: &mut [u8], x: &[u8]) {
    let mut carry = 0u16;
    let mut x = x.iter().rev();
    for byte in v.iter_mut().rev() {
        let sum = u16::from(*byte) + u16::from(*x.next().unwrap_or(&0)) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha1::Sha1;
    use crate::hash::sha2::{Sha256, Sha384, Sha512};
    use crate::hash::sha3::Sha3_512;
    use std::format;

    type Drbg = HashDrbg<Sha256, entropy::External>;

    fn seed() -> [u8; MIN_SEED] {
        let mut seed = [0u8; MIN_SEED];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        seed
    }

    /// The seed lengths are SP 800-90A's table.
    #[test]
    fn seed_lengths_are_the_standards() {
        assert_eq!(seedlen::<Sha1>(), 55);
        assert_eq!(seedlen::<Sha256>(), 55);
        assert_eq!(seedlen::<Sha384>(), 111);
        assert_eq!(seedlen::<Sha512>(), 111);
        assert_eq!(seedlen::<Sha3_512>(), 111);
    }

    /// Addition carries through every byte and wraps at the top; a
    /// shorter addend lines up with the low end.
    #[test]
    fn addition_carries_and_wraps() {
        let mut v = [0x00, 0xff, 0xff];
        add(&mut v, &[1]);
        assert_eq!(v, [0x01, 0x00, 0x00]);
        let mut v = [0xff, 0xff, 0xfe];
        add(&mut v, &[0x00, 0x03]);
        assert_eq!(v, [0x00, 0x00, 0x01]);
        let mut v = [0x12, 0x34];
        add(&mut v, &[0x01, 0x01, 0x01]);
        assert_eq!(v, [0x13, 0x35], "the addend's excess is dropped");
    }

    /// Hash_df in parts is Hash_df of the parts joined, and runs
    /// past one digest.
    #[test]
    fn the_derivation_function_joins_its_parts() {
        let whole = [0x44u8; 70];
        let mut joined = [0u8; 55];
        let mut split = [0u8; 55];
        derive::<Sha256>(&[&whole], &mut joined);
        derive::<Sha256>(&[&whole[..17], &whole[17..], &[]], &mut split);
        assert_eq!(joined, split);
        assert_ne!(joined[..32], joined[32..]);
    }

    /// The same seed must give the same stream, or the ACVP vectors
    /// could not check anything; successive requests must differ.
    #[test]
    fn one_seed_gives_one_stream_that_moves_on() {
        let mut first = Drbg::from_seed(&seed()).expect("seed");
        let mut second = Drbg::from_seed(&seed()).expect("seed");
        let mut a = [0u8; 50];
        let mut b = [0u8; 50];
        first.fill(&mut a).expect("fill");
        second.fill(&mut b).expect("fill");
        assert_eq!(a, b);
        first.fill(&mut b).expect("fill");
        assert_ne!(a, b);
    }

    /// Guard bytes either side catch a length slip, at lengths either
    /// side of a whole digest.
    #[test]
    fn requests_stay_inside_the_buffer() {
        let mut rng = HashDrbg::<Sha512, _>::from_seed(&seed()).expect("seed");
        const PAD: usize = 32;
        let mut buf = [0xaau8; PAD + 200 + PAD];
        for len in [0, 1, 63, 64, 65, 128, 200] {
            buf.fill(0xaa);
            rng.fill(&mut buf[PAD..PAD + len]).expect("fill");
            assert!(buf[..PAD].iter().all(|&b| b == 0xaa), "{len}: before");
            assert!(buf[PAD + len..].iter().all(|&b| b == 0xaa), "{len}");
        }
    }

    /// Too little entropy is refused, at construction and reseeding,
    /// and a refused reseeding changes nothing.
    #[test]
    fn a_short_seed_is_refused() {
        let short = [0x5au8; MIN_SEED - 1];
        assert_eq!(
            Drbg::from_seed(&short).err(),
            Some(Error::InvalidSeedLength(MIN_SEED - 1))
        );
        let mut rng = Drbg::from_seed(&seed()).expect("seed");
        let mut untouched = Drbg::from_seed(&seed()).expect("seed");
        assert_eq!(
            rng.reseed_from(&short).err(),
            Some(Error::InvalidSeedLength(MIN_SEED - 1))
        );
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill(&mut a).expect("fill");
        untouched.fill(&mut b).expect("fill");
        assert_eq!(a, b);
    }

    /// Reseeding must change the stream and count from the start.
    #[test]
    fn reseeding_moves_the_generator_on() {
        let mut rng = Drbg::from_seed(&seed()).expect("seed");
        let mut untouched = Drbg::from_seed(&seed()).expect("seed");
        rng.fill(&mut [0u8; 8]).expect("fill");
        untouched.fill(&mut [0u8; 8]).expect("fill");
        rng.reseed_from(&[0x11u8; MIN_SEED]).expect("reseed");
        assert_eq!(rng.counter, 1);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill(&mut a).expect("fill");
        untouched.fill(&mut b).expect("fill");
        assert_ne!(a, b);
    }

    /// A request larger than the standard allows is refused, and the
    /// largest allowed one is not.
    #[test]
    fn an_oversized_request_is_refused() {
        let mut rng = Drbg::from_seed(&seed()).expect("seed");
        let mut buf = [0u8; MAX_REQUEST + 1];
        assert_eq!(
            rng.fill(&mut buf).err(),
            Some(Error::RequestTooLarge(MAX_REQUEST + 1))
        );
        rng.fill(&mut buf[..MAX_REQUEST]).expect("largest allowed");
    }

    /// At the reseed interval a generator with no source must stop,
    /// and start again once fed.
    #[test]
    fn running_out_stops_a_generator_until_it_is_fed() {
        let mut rng = Drbg::from_seed(&seed()).expect("seed");
        rng.counter = RESEED_INTERVAL + 1;
        let mut buf = [0u8; 16];
        assert_eq!(rng.fill(&mut buf).err(), Some(Error::ReseedRequired));
        rng.reseed_from(&[0x22u8; MIN_SEED]).expect("reseed");
        rng.fill(&mut buf).expect("fill after reseeding");
    }

    /// A generator with a source of its own reseeds itself.
    #[test]
    fn a_generator_with_a_source_reseeds_itself() {
        let Ok(mut rng) = HashDrbg::<Sha256>::from_system() else {
            return;
        };
        rng.counter = RESEED_INTERVAL + 1;
        rng.fill(&mut [0u8; 16]).expect("fill");
        assert_eq!(rng.counter, 2, "reseeded and then counted one request");
    }

    /// Empty additional input is the plain request; any other input
    /// changes the output and repeats from the same state.
    #[test]
    fn additional_input_binds_the_request() {
        let mut plain = Drbg::from_seed(&seed()).expect("seed");
        let mut empty = Drbg::from_seed(&seed()).expect("seed");
        let mut first = Drbg::from_seed(&seed()).expect("seed");
        let mut again = Drbg::from_seed(&seed()).expect("seed");
        let [mut a, mut b, mut c, mut d] = [[0u8; 32]; 4];
        plain.fill(&mut a).expect("fill");
        empty.fill_with(&mut b, &[]).expect("fill_with");
        first.fill_with(&mut c, b"request 1").expect("fill_with");
        again.fill_with(&mut d, b"request 1").expect("fill_with");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(c, d);
        assert_eq!(first.counter, 2);
    }

    /// Reseeding with additional input is reseeding from the two
    /// joined: Hash_df sees one run either way.
    #[test]
    fn reseed_with_is_reseed_from_the_concatenation() {
        let mut split = Drbg::from_seed(&seed()).expect("seed");
        let mut joined = Drbg::from_seed(&seed()).expect("seed");
        let mut both = [0u8; MIN_SEED + 20];
        both[..MIN_SEED].fill(0x66);
        both[MIN_SEED..].fill(0x77);
        split
            .reseed_with(&both[..MIN_SEED], &both[MIN_SEED..])
            .expect("reseed");
        joined.reseed_from(&both).expect("reseed");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        split.fill(&mut a).expect("fill");
        joined.fill(&mut b).expect("fill");
        assert_eq!(a, b);
    }

    /// The state must not survive the object, and must not be shown.
    #[test]
    fn the_state_is_wiped_and_not_shown() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Drbg>();
        let rng = Drbg::from_seed(&seed()).expect("seed");
        assert_eq!(
            format!("{rng:?}"),
            "HashDrbg { requests_since_seeding: 0 }"
        );
    }
}
