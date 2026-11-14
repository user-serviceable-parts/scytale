//! X448 (RFC 7748): Diffie-Hellman over Curve448.
//!
//! The same construction as [`x25519`](super::x25519) over a larger
//! curve: each party multiplies the base point by a secret scalar to
//! make a public key, then multiplies the other's public key by the
//! same scalar, and the u-coordinate both arrive at is the shared
//! secret. Curve448 is the conservative choice of the two, at about
//! 224 bits of security against 128, for a protocol that names it;
//! X25519 is the one to reach for otherwise.
//!
//! The shared secret is a curve point, not a uniform string: feed it
//! to [`hkdf`](crate::kdf::hkdf) to make keys, never use it as one.
//!
//! Keys are 56 bytes each way. [`PrivateKey`] and [`PublicKey`] are
//! the pair to reach for: the secret is held in a [`Key`], so it is
//! wiped when it goes out of scope, and each carries the RFC 8410
//! encodings the rest of the world stores keys in. The free functions
//! below take the bare bytes, for code that already has them.
//!
//! ```
//! use scytale::Key;
//! use scytale::kex::x448::PrivateKey;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let alice = PrivateKey::new(&Key::from([0x11u8; 56]));
//! let bob = PrivateKey::new(&Key::from([0x22u8; 56]));
//!
//! let ours = alice.shared_secret(bob.public_key())?;
//! let theirs = bob.shared_secret(alice.public_key())?;
//! assert_eq!(ours, theirs);
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! The shared secret is a Montgomery ladder: the same field
//! operations in the same order for every scalar, with the working
//! values exchanged by a masked swap rather than a branch. A public
//! key is the Ed448 base point's comb instead, whose table is read
//! whole and chosen from by a mask, then mapped to Curve448.
//!
//! # Low-order public keys
//!
//! A few points on the curve generate tiny subgroups, and a peer who
//! sends one forces the shared secret to zero, a value anyone can
//! compute. [`shared_secret`] refuses them, which is the check RFC
//! 7748 section 6.2 asks for. The raw [`x448`] function performs no
//! such check, because the protocols that need the unchecked
//! function say so explicitly.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::der;
use crate::math::fe448::Fe;
use crate::{Key, Random};

/// The length of a secret key, a public key, and the shared secret.
pub const KEY_SIZE: usize = 56;

/// The u-coordinate of the base point: 5. The public key is taken on
/// the Edwards curve instead, and the tests check the two agree.
#[cfg(test)]
const BASE_POINT: [u8; KEY_SIZE] = {
    let mut u = [0u8; KEY_SIZE];
    u[0] = 5;
    u
};

/// The public key belonging to `secret`.
///
/// Any 56 bytes are a valid secret key; take them from
/// [`random`](crate::random). The bits that clamping fixes are fixed
/// here, so unclamped and clamped forms of a secret name the same
/// public key.
pub fn public_key(secret: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    // The same multiple as `x448(secret, &BASE_POINT)`, taken on the
    // Edwards form of the curve, where the base point has a table.
    let mut k = clamp(secret);
    let public = crate::sig::ed448::montgomery_base(&k);
    k.zeroize();
    public
}

/// The scalar as RFC 7748 decodes it. Clamping clears the two
/// cofactor bits, so the multiple lands in the prime-order subgroup,
/// and sets the top bit, so every scalar takes the same ladder length.
fn clamp(secret: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    let mut k = *secret;
    k[0] &= 252;
    k[55] |= 128;
    k
}

/// The secret shared between `secret` and a peer's `public` key.
///
/// Fails with [`Error::InvalidPublicKey`] when `public` is a
/// low-order point, whose shared secret anyone can compute.
pub fn shared_secret(
    secret: &[u8; KEY_SIZE],
    public: &[u8; KEY_SIZE],
) -> Result<[u8; KEY_SIZE], Error> {
    let mut shared = x448(secret, public);
    // All low-order points, and only those, land on zero. The check
    // runs over every byte whatever their values.
    let mut acc = 0u8;
    for byte in shared {
        acc |= byte;
    }
    if acc == 0 {
        shared.zeroize();
        return Err(Error::InvalidPublicKey);
    }
    Ok(shared)
}

/// The X448 function of RFC 7748 section 5: the scalar `k` times the
/// point whose u-coordinate is `u`.
///
/// [`public_key`] and [`shared_secret`] are this function applied to
/// the base point and to a peer's key; reach for this form only when
/// a protocol asks for it by name.
pub fn x448(k: &[u8; KEY_SIZE], u: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    let mut k = clamp(k);

    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;

    // One ladder step per scalar bit, high to low, swapping only
    // when this bit differs from the last, which `swap` tracks.
    let mut swap = 0u64;
    for t in (0..448).rev() {
        let bit = u64::from((k[t >> 3] >> (t & 7)) & 1);
        swap ^= bit;
        Fe::cswap(swap, &mut x2, &mut x3);
        Fe::cswap(swap, &mut z2, &mut z3);
        swap = bit;

        // The combined double-and-add of RFC 7748 section 5, with
        // a24 = (156326 - 2) / 4.
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(39081)));
    }
    Fe::cswap(swap, &mut x2, &mut x3);
    Fe::cswap(swap, &mut z2, &mut z3);

    let out = x2.mul(&z2.invert()).to_bytes();

    // The named intermediates hold functions of the secret. `Fe` is
    // `Copy`, so the compiler may have spilled other copies; wiping
    // these is the best that can be done without owning the frame.
    k.zeroize();
    x2.zeroize();
    z2.zeroize();
    x3.zeroize();
    z3.zeroize();
    out
}

/// The length of a secret key's DER encoding, a PKCS#8
/// `PrivateKeyInfo` (RFC 8410 section 7).
pub const DER_SIZE: usize = der::curve_secret_der_len(KEY_SIZE);

/// The length of a public key's DER encoding, a
/// `SubjectPublicKeyInfo` (RFC 8410 section 4).
pub const PUBLIC_KEY_DER_SIZE: usize = der::curve_public_der_len(KEY_SIZE);

/// The length of a secret key's PEM encoding, a `PRIVATE KEY` block.
pub const PEM_SIZE: usize = der::curve_secret_pem_len(KEY_SIZE);

/// The length of a public key's PEM encoding, a `PUBLIC KEY` block.
pub const PUBLIC_KEY_PEM_SIZE: usize = der::curve_public_pem_len(KEY_SIZE);

/// A secret key from its DER PKCS#8 `PrivateKeyInfo`, the form under
/// `PRIVATE KEY` in a PEM file, which RFC 8410 fixes for X448: the
/// 56 bytes in an OCTET STRING of their own inside the one PKCS#8
/// provides. A version 1 structure that also carries the public key
/// is read, and refused as [`Error::InconsistentKey`] when that key
/// is not the secret's. A structure under another identifier, the
/// other curve's included, or under `id-X448` with the NULL
/// parameters RFC 8410 forbids, is [`Error::WrongAlgorithm`];
/// anything else wrong with the bytes is [`Error::InvalidEncoding`].
pub fn secret_from_der(der: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    let found = der::curve_secret_from_der(&der::X448, der)?;
    checked(found.secret, found.public)
}

/// The secret a structure carried, once the public key it may
/// have carried beside it is checked to be the secret's own: a pair
/// that disagrees has been corrupted, and neither half is returned.
fn checked(
    mut secret: [u8; KEY_SIZE],
    carried: Option<[u8; KEY_SIZE]>,
) -> Result<[u8; KEY_SIZE], Error> {
    if let Some(carried) = carried
        && carried != public_key(&secret)
    {
        secret.zeroize();
        return Err(Error::InconsistentKey);
    }
    Ok(secret)
}

/// The secret key's DER encoding, a version 0 `PrivateKeyInfo`. The
/// output is a secret, to be wiped when done.
pub fn secret_der(secret: &[u8; KEY_SIZE]) -> [u8; DER_SIZE] {
    der::curve_secret_der(&der::X448, secret)
}

/// A public key from its DER `SubjectPublicKeyInfo`, the form under
/// `PUBLIC KEY`. The bytes are not checked to be a point here, any
/// more than the argument type of the functions that take them
/// checks; those refuse one that is not.
pub fn public_key_from_der(der: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    der::curve_public_from_der(&der::X448, der)
}

/// The public key's DER encoding.
pub fn public_key_der(public: &[u8; KEY_SIZE]) -> [u8; PUBLIC_KEY_DER_SIZE] {
    der::curve_public_der(&der::X448, public)
}

/// A secret key from a `PRIVATE KEY` PEM block (RFC 7468) around
/// [`secret_der`]'s bytes. Whitespace and line ends are read
/// leniently; anything else that is not exactly one well-formed
/// block, an encrypted key included, is [`Error::InvalidEncoding`].
pub fn secret_from_pem(pem: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    let found = der::curve_secret_from_pem(&der::X448, pem)?;
    let (secret, carried) = (found.secret, found.public);
    checked(secret, carried)
}

/// The secret key as a `PRIVATE KEY` PEM block: ASCII with LF line
/// ends, always [`PEM_SIZE`] bytes. A secret, to be wiped when done.
pub fn secret_pem(secret: &[u8; KEY_SIZE]) -> [u8; PEM_SIZE] {
    der::curve_secret_pem(&der::X448, secret)
}

/// A public key from a `PUBLIC KEY` PEM block, read as
/// [`secret_from_pem`] reads its block.
pub fn public_key_from_pem(pem: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    der::curve_public_from_pem(&der::X448, pem)
}

/// The public key as a `PUBLIC KEY` PEM block, always
/// [`PUBLIC_KEY_PEM_SIZE`] bytes.
pub fn public_key_pem(public: &[u8; KEY_SIZE]) -> [u8; PUBLIC_KEY_PEM_SIZE] {
    der::curve_public_pem(&der::X448, public)
}

/// The length of a key pair's DER encoding, a version 1
/// `PrivateKeyInfo` carrying the public key beside the secret.
pub const PAIR_DER_SIZE: usize = der::curve_pair_der_len(KEY_SIZE);

/// The length of a key pair's PEM encoding, a `PRIVATE KEY` block.
pub const PAIR_PEM_SIZE: usize = der::curve_pair_pem_len(KEY_SIZE);

/// One side's secret key, and the public key that goes with it.
///
/// The secret is held in a [`Key`], so it is wiped when the key goes
/// out of scope; the free functions above take the bare bytes for
/// code that has them already.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    secret: Key<[u8; KEY_SIZE]>,
    #[zeroize(skip)]
    public: PublicKey,
}

/// The other side's public key: a u-coordinate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; KEY_SIZE],
}

impl fmt::Debug for PrivateKey {
    /// Deliberately omits the secret; the public key is not one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey").finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// A key drawn from `rng`. Any 56 bytes are a secret key.
    pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
        let mut secret = Key::zeroed();
        rng.fill(secret.as_mut())?;
        Ok(Self::new(&secret))
    }

    /// The key `secret` is.
    pub fn new(secret: &Key<[u8; KEY_SIZE]>) -> Self {
        let public = PublicKey {
            bytes: public_key(secret.array()),
        };
        PrivateKey {
            secret: secret.clone(),
            public,
        }
    }

    /// The secret, to store or to hand to code that wants the bytes.
    pub fn secret_bytes(&self) -> [u8; KEY_SIZE] {
        *self.secret.array()
    }

    /// The public key, derived when this key was built.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The secret shared with `public`, as [`shared_secret`]
    /// computes it and with the same refusal of a low-order point.
    pub fn shared_secret(
        &self,
        public: &PublicKey,
    ) -> Result<[u8; KEY_SIZE], Error> {
        shared_secret(self.secret.array(), &public.bytes)
    }

    /// A key from its DER `PrivateKeyInfo`, of either version; a
    /// version 1 structure's public key is checked against the
    /// secret's own, as [`secret_from_der`] describes.
    pub fn try_from_der(bytes: &[u8]) -> Result<Self, Error> {
        let mut secret = Key::from(secret_from_der(bytes)?);
        let key = Self::new(&secret);
        secret.zeroize();
        Ok(key)
    }

    /// The key pair as a version 1 `PrivateKeyInfo`, which carries
    /// the public key beside the secret. The output is a secret, to
    /// be wiped when done.
    ///
    /// [`secret_der`] writes the version 0 form, which is what
    /// OpenSSL emits; this one is what readers that require the
    /// public key accept.
    pub fn der_bytes(&self) -> [u8; PAIR_DER_SIZE] {
        der::curve_pair_der(&der::X448, self.secret.array(), &self.public.bytes)
    }

    /// A key from a `PRIVATE KEY` PEM block, read as
    /// [`secret_from_pem`] reads one.
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        let mut secret = Key::from(secret_from_pem(pem)?);
        let key = Self::new(&secret);
        secret.zeroize();
        Ok(key)
    }

    /// The key pair as a `PRIVATE KEY` PEM block around
    /// [`der_bytes`](Self::der_bytes). A secret, to be wiped when
    /// done.
    pub fn pem_bytes(&self) -> [u8; PAIR_PEM_SIZE] {
        der::curve_pair_pem(&der::X448, self.secret.array(), &self.public.bytes)
    }
}

impl PublicKey {
    /// The key those bytes are. Every 56 bytes name a u-coordinate;
    /// the ones that are useless are refused where they are used, by
    /// [`PrivateKey::shared_secret`].
    pub fn new(bytes: &[u8; KEY_SIZE]) -> Self {
        PublicKey { bytes: *bytes }
    }

    /// The u-coordinate.
    pub fn bytes(&self) -> [u8; KEY_SIZE] {
        self.bytes
    }

    /// A key from its DER `SubjectPublicKeyInfo`.
    pub fn try_from_der(bytes: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            bytes: public_key_from_der(bytes)?,
        })
    }

    /// The key's `SubjectPublicKeyInfo`.
    pub fn der_bytes(&self) -> [u8; PUBLIC_KEY_DER_SIZE] {
        public_key_der(&self.bytes)
    }

    /// A key from a `PUBLIC KEY` PEM block.
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            bytes: public_key_from_pem(pem)?,
        })
    }

    /// The key as a `PUBLIC KEY` PEM block.
    pub fn pem_bytes(&self) -> [u8; PUBLIC_KEY_PEM_SIZE] {
        public_key_pem(&self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::{CtrDrbg, MIN_SEED};

    /// Decodes the RFC's lowercase hex into bytes.
    fn unhex(hex: &str) -> [u8; KEY_SIZE] {
        let mut bytes = [0u8; KEY_SIZE];
        assert_eq!(hex.len(), 2 * KEY_SIZE);
        for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        bytes
    }

    /// The public key from the Edwards table is the ladder's, for
    /// secrets whose clamped bits vary, for ones that reduce past the
    /// group order, and for the one clamped secret that is four times
    /// the order, whose multiple is the identity.
    #[test]
    fn public_key_matches_the_ladder() {
        let mut secrets = [[0u8; KEY_SIZE]; 7];
        secrets[1] = [0xff; KEY_SIZE];
        for (i, secret) in secrets.iter_mut().enumerate().skip(2) {
            for (j, byte) in secret.iter_mut().enumerate() {
                *byte = (i * 37 + j * 11) as u8;
            }
        }
        // 4L, little-endian: the order times four, clamped as it is.
        let l = [
            0x2378c292ab5844f3u64,
            0x216cc2728dc58f55,
            0xc44edb49aed63690,
            0xffffffff7cca23e9,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x3fffffffffffffff,
        ];
        let mut four_l = [0u8; KEY_SIZE];
        let mut carry = 0u64;
        for (i, limb) in l.iter().enumerate() {
            let shifted = (limb << 2) | carry;
            carry = limb >> 62;
            four_l[8 * i..8 * i + 8].copy_from_slice(&shifted.to_le_bytes());
        }
        secrets[6] = four_l;
        for secret in &secrets {
            assert_eq!(public_key(secret), x448(secret, &BASE_POINT));
        }
        assert_eq!(public_key(&four_l), [0u8; KEY_SIZE]);
    }

    /// The key types are the free functions with the secret held in
    /// something that wipes itself, so they must agree at every step,
    /// and the pair encoding must read back as what it wrote.
    #[test]
    fn key_types_match_the_functions() {
        let alice = PrivateKey::new(&Key::from([0x11u8; KEY_SIZE]));
        let bob = PrivateKey::new(&Key::from([0x22u8; KEY_SIZE]));
        assert_eq!(alice.public_key().bytes(), public_key(&[0x11; KEY_SIZE]));

        let one = alice.shared_secret(bob.public_key()).expect("shared");
        let two = bob.shared_secret(alice.public_key()).expect("shared");
        assert_eq!(one, two);
        assert_eq!(
            one,
            shared_secret(&[0x11; KEY_SIZE], &public_key(&[0x22; KEY_SIZE]))
                .unwrap()
        );
        assert_eq!(
            alice.shared_secret(&PublicKey::new(&[0u8; KEY_SIZE])),
            Err(Error::InvalidPublicKey)
        );

        let der = alice.der_bytes();
        let read = PrivateKey::try_from_der(&der).expect("der");
        assert_eq!(read.secret_bytes(), alice.secret_bytes());
        assert_eq!(read.public_key(), alice.public_key());
        let pem = alice.pem_bytes();
        assert_eq!(
            PrivateKey::try_from_pem(&pem).unwrap().secret_bytes(),
            alice.secret_bytes()
        );
        let short = secret_der(&alice.secret_bytes());
        assert!(short.len() < der.len());
        assert_eq!(
            PrivateKey::try_from_der(&short).unwrap().public_key(),
            alice.public_key()
        );

        let public = *alice.public_key();
        assert_eq!(
            PublicKey::try_from_der(&public.der_bytes()).unwrap(),
            public
        );
        assert_eq!(
            PublicKey::try_from_pem(&public.pem_bytes()).unwrap(),
            public
        );
    }

    /// A drawn key takes its whole secret from the source.
    #[test]
    fn generate_draws_the_secret() {
        let mut rng = CtrDrbg::from_seed(&[0x77u8; MIN_SEED]).expect("seed");
        let one = PrivateKey::generate(&mut rng).expect("one");
        let two = PrivateKey::generate(&mut rng).expect("two");
        assert_ne!(one.secret_bytes(), two.secret_bytes());
        assert_ne!(one.public_key(), two.public_key());
    }

    /// RFC 7748 section 5.2, both one-shot vectors.
    #[test]
    fn rfc7748_function_vectors() {
        let k = unhex(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
             700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        );
        let u = unhex(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
             814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        );
        let out = unhex(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
             e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
        );
        assert_eq!(x448(&k, &u), out);

        let k = unhex(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5\
             38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
        );
        let u = unhex(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b\
             165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
        );
        let out = unhex(
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7\
             ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
        );
        assert_eq!(x448(&k, &u), out);
    }

    /// RFC 7748 section 5.2: the function iterated, each output
    /// becoming the next scalar and the old scalar the next point.
    /// One check after the first call, one after a thousand; the
    /// million-call value is in the RFC but takes minutes.
    #[test]
    fn rfc7748_iterated() {
        let mut k = BASE_POINT;
        let mut u = BASE_POINT;
        for i in 1..=1000 {
            let out = x448(&k, &u);
            u = k;
            k = out;
            if i == 1 {
                let one = unhex(
                    "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a\
                     4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
                );
                assert_eq!(k, one);
            }
        }
        let thousand = unhex(
            "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4\
             af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38",
        );
        assert_eq!(k, thousand);
    }

    /// RFC 7748 section 6.2: the worked Diffie-Hellman exchange.
    #[test]
    fn rfc7748_diffie_hellman() {
        let alice_secret = unhex(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
             d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let bob_secret = unhex(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
             6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        );
        let alice_public = unhex(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
             22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
        );
        let bob_public = unhex(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
             27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        );
        assert_eq!(public_key(&alice_secret), alice_public);
        assert_eq!(public_key(&bob_secret), bob_public);

        let shared = unhex(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
             b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
        );
        assert_eq!(shared_secret(&alice_secret, &bob_public), Ok(shared));
        assert_eq!(shared_secret(&bob_secret, &alice_public), Ok(shared));
    }

    /// Low-order points force a zero shared secret, and are refused:
    /// zero, one and p - 1, and p, which is zero spelled another way.
    #[test]
    fn refuses_low_order_public_keys() {
        let secret = [0x5au8; KEY_SIZE];
        let zero = [0u8; KEY_SIZE];
        let mut one = [0u8; KEY_SIZE];
        one[0] = 1;
        let mut p = [0xffu8; KEY_SIZE];
        p[28] = 0xfe;
        let mut minus_one = p;
        minus_one[0] = 0xfe;
        for low in [zero, one, minus_one, p] {
            assert_eq!(
                shared_secret(&secret, &low),
                Err(Error::InvalidPublicKey),
            );
        }
    }

    /// A non-canonical coordinate, the prime plus two, reads the same
    /// as its reduced form, as RFC 7748 asks.
    #[test]
    fn reduces_non_canonical_u() {
        let k = [0x33u8; KEY_SIZE];
        let mut canonical = [0u8; KEY_SIZE];
        canonical[0] = 2;
        // p + 2 = 2^448 - 2^224 + 1: all ones from bit 224 up, and
        // a one at the bottom.
        let mut wrapped = [0u8; KEY_SIZE];
        wrapped[0] = 1;
        wrapped[28..].fill(0xff);
        assert_eq!(x448(&k, &wrapped), x448(&k, &canonical));
    }

    /// Clamping happens inside, so a pre-clamped secret and its raw
    /// form name the same public key.
    #[test]
    fn clamps_the_scalar() {
        let raw = [0x7fu8; KEY_SIZE];
        let mut clamped = raw;
        clamped[0] &= 252;
        clamped[55] |= 128;
        assert_eq!(public_key(&raw), public_key(&clamped));
    }

    /// What OpenSSL 3.5 writes for a fresh key, from
    /// `openssl genpkey -algorithm X448` and `openssl pkey`, with and
    /// without `-pubout`, in DER and PEM.
    #[test]
    fn openssl_encodings() {
        let secret = unhex(
            "7495d80006186efe88910b7cdb430fd7a8395364a7976ff6a345e00e\
             349fc397ce5784d3fd3d45089a62e1b62448b6f1cd2f67f49d4e69bf",
        );
        let public = unhex(
            "14a42dbf5b049979352f1de7410aa06814857a88647010a68fd771e8\
             ae6adc2cebe9d822f06cde5b3c3a52e54c5626ea1781ec9b5c9e22cf",
        );
        let mut secret_der_bytes = [0u8; DER_SIZE];
        secret_der_bytes[..16].copy_from_slice(&[
            0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x6f, 0x04, 0x3a, 0x04, 0x38,
        ]);
        secret_der_bytes[16..].copy_from_slice(&secret);
        let mut public_der_bytes = [0u8; PUBLIC_KEY_DER_SIZE];
        public_der_bytes[..12].copy_from_slice(&[
            0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x39,
            0x00,
        ]);
        public_der_bytes[12..].copy_from_slice(&public);
        let secret_pem_text = b"-----BEGIN PRIVATE KEY-----\n\
            MEYCAQAwBQYDK2VvBDoEOHSV2AAGGG7+iJELfNtDD9eoOVNkp5dv9qNF4A40n8OX\n\
            zleE0/09RQiaYuG2JEi28c0vZ/SdTmm/\n\
            -----END PRIVATE KEY-----\n";
        let public_pem_text = b"-----BEGIN PUBLIC KEY-----\n\
            MEIwBQYDK2VvAzkAFKQtv1sEmXk1Lx3nQQqgaBSFeohkcBCmj9dx6K5q3Czr6dgi\n\
            8GzeWzw6UuVMVibqF4Hsm1yeIs8=\n\
            -----END PUBLIC KEY-----\n";

        assert_eq!(public_key(&secret), public);
        assert_eq!(secret_from_der(&secret_der_bytes), Ok(secret));
        assert_eq!(public_key_from_der(&public_der_bytes), Ok(public));
        assert_eq!(secret_der(&secret), secret_der_bytes);
        assert_eq!(public_key_der(&public), public_der_bytes);
        assert_eq!(secret_from_pem(secret_pem_text), Ok(secret));
        assert_eq!(public_key_from_pem(public_pem_text), Ok(public));
        assert_eq!(secret_pem(&secret)[..], secret_pem_text[..]);
        assert_eq!(public_key_pem(&public)[..], public_pem_text[..]);

        // An X25519 structure is not an X448 key, even padded out.
        let mut e = secret_der_bytes;
        e[11] = 0x6e;
        assert_eq!(secret_from_der(&e), Err(Error::WrongAlgorithm));
        let mut e = public_der_bytes;
        e[8] = 0x6e;
        assert_eq!(public_key_from_der(&e), Err(Error::WrongAlgorithm));

        // A version 1 structure carrying the public key reads when
        // the pair agrees and is refused when it does not.
        let mut v1 = [0u8; PAIR_DER_SIZE];
        v1[..17].copy_from_slice(&[
            0x30, 0x81, 0x81, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b,
            0x65, 0x6f, 0x04, 0x3a, 0x04, 0x38,
        ]);
        v1[17..73].copy_from_slice(&secret);
        v1[73..76].copy_from_slice(&[0x81, 0x39, 0x00]);
        v1[76..].copy_from_slice(&public);
        assert_eq!(secret_from_der(&v1), Ok(secret));
        assert_eq!(PrivateKey::try_from_der(&v1).unwrap().der_bytes(), v1);
        v1[PAIR_DER_SIZE - 1] ^= 1;
        assert_eq!(secret_from_der(&v1), Err(Error::InconsistentKey));
    }
}
