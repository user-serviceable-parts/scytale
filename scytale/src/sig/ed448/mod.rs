//! Ed448 (RFC 8032): signatures over the edwards448 curve.
//!
//! The signer's secret is 57 bytes; SHAKE256 expands it into a scalar
//! and a prefix. A signature commits to the message twice over: `R`
//! is a point derived from the prefix and the message, and `S` binds
//! the secret scalar to a hash of `R`, the public key and the
//! message. Verification checks the one equation `SB = R + kA`.
//!
//! The construction is Ed25519's over a larger curve, at about 224
//! bits of security against 128, for the protocols that name it;
//! [`ed25519`](super::ed25519) is the one to reach for otherwise.
//! Unlike Ed25519 there is no variant without a context: every
//! signature hashes one in, the empty string where the caller gives
//! none, so [`sign`] takes it alongside the message. Ed448ph,
//! [`sign_ph`], signs a 64-byte SHAKE256 digest the caller has made,
//! so a message too large to hold can be hashed as it arrives. The
//! two never accept each other's signatures.
//!
//! RFC 8032 makes signing deterministic, and [`sign`] hedges it as
//! Ed25519's does: 32 random bytes are hashed into the prefix first,
//! so no two signatures share the computation that a fault or a
//! power trace would attack, and a weak random source leaves the
//! nonce as good as the RFC's. [`sign_deterministic`] and its kin
//! are RFC 8032 exactly, for test vectors and the protocols that need
//! the same signature twice.
//!
//! Keys are 57 bytes each way and signatures 114. [`PrivateKey`] and
//! [`PublicKey`] are the pair to reach for: the secret is held in a
//! [`Key`], so it is wiped when it goes out of scope, and each
//! carries the RFC 8410 encodings the rest of the world stores keys
//! in. The free functions below take the bare bytes.
//!
//! ```
//! use scytale::Key;
//! use scytale::random::CtrDrbg;
//! use scytale::sig::ed448::PrivateKey;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let key = PrivateKey::new(&Key::from([0x42u8; 57]));
//! let signature = key.sign(&mut rng, b"", b"the message")?;
//! key.public_key().verify(b"", b"the message", &signature)?;
//! assert!(key.public_key().verify(b"", b"another", &signature).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! Signing performs the same sequence of field and scalar operations
//! whatever the secret. Multiplying the base point reads a table of
//! its multiples, and the read scans every entry, choosing by a mask,
//! so the secret digit that selects one never becomes an index or a
//! branch. Verification handles only public data, so it takes the
//! faster path whose work depends on the scalars.
//!
//! # What verification accepts
//!
//! The checks are the ones RFC 8032 requires: the public key must
//! decode (a coordinate at or above the field prime does not, and
//! neither does a zero x with its sign bit set), and `S` must be
//! below the group order, which is what stops an accepted signature
//! from being malleated into a second one. The equation is checked
//! without the cofactor, as for Ed25519.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::der;
use crate::hash::sha3::Shake256;
use crate::hash::{Xof, XofReader};
use crate::math::fe448::Fe;
use crate::math::montgomery::Montgomery;
use crate::math::uint::Uint;
use crate::{Error, Key, Pkcs8Form, Random};

mod base;

/// The length of a secret key: the seed SHAKE256 expands.
pub const KEY_SIZE: usize = 57;

/// The length of a public key: a compressed point.
pub const PUBLIC_KEY_SIZE: usize = 57;

/// The length of a signature: `R` and then `S`.
pub const SIGNATURE_SIZE: usize = 114;

/// The longest context string either variant takes.
pub const CONTEXT_MAX: usize = 255;

/// The length of the SHAKE256 digest Ed448ph signs.
pub const PREHASH_SIZE: usize = 64;

/// The length of the hashes inside a signature: twice a scalar.
const WIDE: usize = 114;

/// SHAKE256 of the parts, in order, to `out`.
fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut xof = Shake256::new();
    for part in parts {
        xof.update(part);
    }
    xof.finalize_xof().squeeze(out);
}

/// The public key belonging to `secret`.
///
/// Any 57 bytes are a valid secret key; take them from
/// [`random`](crate::random).
pub fn public_key(secret: &[u8; KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    let mut h = expand(secret);
    let mut a = secret_scalar(&h);
    let public = Point::mul_base(&a).compress();
    h.zeroize();
    a.zeroize();
    public
}

/// The 32 random bytes that hedge one signature's nonce.
fn noise<R: Random>(rng: &mut R) -> Result<[u8; 32], Error> {
    let mut z = [0u8; 32];
    rng.fill(&mut z)?;
    Ok(z)
}

/// Signs `message` under `context` with `secret`, the nonce hedged
/// by 32 bytes from `rng`: see the module's notes.
///
/// The context is up to [`CONTEXT_MAX`] bytes and may be empty; a
/// longer one is [`Error::InvalidLength`].
pub fn sign<R: Random>(
    secret: &[u8; KEY_SIZE],
    rng: &mut R,
    context: &[u8],
    message: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let head = dom4(PURE, context)?;
    let mut z = noise(rng)?;
    let signature = sign_with(
        secret,
        &public_key(secret),
        &[&head, context],
        message,
        Some(&z),
    );
    z.zeroize();
    Ok(signature)
}

/// Signs `message` under `context` as RFC 8032 does, the same key,
/// context and message always giving the same signature. For test
/// vectors and repeatable output; [`sign`] otherwise.
pub fn sign_deterministic(
    secret: &[u8; KEY_SIZE],
    context: &[u8],
    message: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let head = dom4(PURE, context)?;
    Ok(sign_with(
        secret,
        &public_key(secret),
        &[&head, context],
        message,
        None,
    ))
}

/// Checks that `signature` signs `message` under `context` and
/// `public`.
///
/// [`Error::InvalidPublicKey`] when the key does not name a point on
/// the curve; [`Error::InvalidLength`] for a context over
/// [`CONTEXT_MAX`]; [`Error::InvalidSignature`] for everything else,
/// which deliberately says no more than that.
pub fn verify(
    public: &[u8; PUBLIC_KEY_SIZE],
    context: &[u8],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), Error> {
    let head = dom4(PURE, context)?;
    verify_with(public, &[&head, context], message, signature)
}

/// The prehash Ed448ph signs: the first 64 bytes of SHAKE256 of the
/// message, which can be fed to SHAKE256 in as many pieces as it
/// arrives in.
pub fn prehash(message: &[u8]) -> [u8; PREHASH_SIZE] {
    let mut out = [0u8; PREHASH_SIZE];
    shake(&[message], &mut out);
    out
}

/// Signs the SHAKE256 digest `prehash` under `context` with `secret`,
/// by Ed448ph, the nonce hedged by 32 bytes from `rng`. The context
/// is refused as [`sign`] refuses it.
pub fn sign_ph<R: Random>(
    secret: &[u8; KEY_SIZE],
    rng: &mut R,
    context: &[u8],
    prehash: &[u8; PREHASH_SIZE],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let head = dom4(PH, context)?;
    let mut z = noise(rng)?;
    let signature = sign_with(
        secret,
        &public_key(secret),
        &[&head, context],
        prehash,
        Some(&z),
    );
    z.zeroize();
    Ok(signature)
}

/// Ed448ph as RFC 8032 does it, deterministically.
pub fn sign_ph_deterministic(
    secret: &[u8; KEY_SIZE],
    context: &[u8],
    prehash: &[u8; PREHASH_SIZE],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let head = dom4(PH, context)?;
    Ok(sign_with(
        secret,
        &public_key(secret),
        &[&head, context],
        prehash,
        None,
    ))
}

/// Checks that `signature` signs the SHAKE256 digest `prehash` under
/// `context` and `public`, by Ed448ph; the errors are [`verify`]'s.
pub fn verify_ph(
    public: &[u8; PUBLIC_KEY_SIZE],
    context: &[u8],
    prehash: &[u8; PREHASH_SIZE],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), Error> {
    let head = dom4(PH, context)?;
    verify_with(public, &[&head, context], prehash, signature)
}

/// The phflag of plain Ed448.
const PURE: u8 = 0;

/// The phflag of Ed448ph.
const PH: u8 = 1;

/// The fixed part of RFC 8032's `dom4(phflag, context)`: the name,
/// the flag and the context's length. The context follows it into
/// both hashes, which is what keeps a signature under one variant or
/// context from verifying under another.
fn dom4(flag: u8, context: &[u8]) -> Result<[u8; 10], Error> {
    if context.len() > CONTEXT_MAX {
        return Err(Error::InvalidLength(context.len()));
    }
    let mut head = [0u8; 10];
    head[..8].copy_from_slice(b"SigEd448");
    head[8] = flag;
    head[9] = context.len() as u8;
    Ok(head)
}

/// SHAKE256 of the secret, 114 bytes: the scalar's half, then the
/// prefix.
fn expand(secret: &[u8; KEY_SIZE]) -> [u8; WIDE] {
    let mut h = [0u8; WIDE];
    shake(&[secret], &mut h);
    h
}

/// Signs `message` with `secret`, whose public key `public` must be,
/// with `dom` hashed ahead of both hashes. With `noise`, the nonce is
/// hedged as the module's notes say.
fn sign_with(
    secret: &[u8; KEY_SIZE],
    public: &[u8; PUBLIC_KEY_SIZE],
    dom: &[&[u8]],
    message: &[u8],
    noise: Option<&[u8; 32]>,
) -> [u8; SIGNATURE_SIZE] {
    let mut h = expand(secret);
    let mut a = secret_scalar(&h);

    // The prefix, or hedged, the first 57 bytes of
    // SHAKE256(prefix || Z): the secret meets the random bytes
    // before anything public.
    let mut prefix = [0u8; KEY_SIZE];
    match noise {
        Some(z) => shake(&[&h[KEY_SIZE..], z], &mut prefix),
        None => prefix.copy_from_slice(&h[KEY_SIZE..]),
    }

    // The nonce: a hash of the prefix and the message, so it is
    // unique per message whatever the random source does.
    let mut wide = [0u8; WIDE];
    let mut parts = [&[][..]; 5];
    parts[..dom.len()].copy_from_slice(dom);
    parts[dom.len()] = &prefix;
    parts[dom.len() + 1] = message;
    shake(&parts[..dom.len() + 2], &mut wide);
    prefix.zeroize();
    let mut r = Scalar::from_wide(&wide);
    let big_r = Point::mul_base(&r).compress();

    // The challenge binds R, the public key and the message.
    let k = challenge(dom, &big_r, public, message);

    let mut s = k.mul_add(&a, &r);
    let mut signature = [0u8; SIGNATURE_SIZE];
    signature[..KEY_SIZE].copy_from_slice(&big_r);
    signature[KEY_SIZE..].copy_from_slice(&s.to_bytes());

    h.zeroize();
    a.zeroize();
    wide.zeroize();
    r.zeroize();
    s.zeroize();
    signature
}

/// Verification under either variant, `dom` as [`sign_with`] takes
/// it.
fn verify_with(
    public: &[u8; PUBLIC_KEY_SIZE],
    dom: &[&[u8]],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), Error> {
    let a = Point::decompress(public).ok_or(Error::InvalidPublicKey)?;

    let mut s_bytes = [0u8; KEY_SIZE];
    s_bytes.copy_from_slice(&signature[KEY_SIZE..]);
    // S at or above the group order is the malleable form of another
    // signature, and RFC 8032 says to refuse it.
    let s = Scalar::below_order(&s_bytes).ok_or(Error::InvalidSignature)?;

    let mut big_r = [0u8; KEY_SIZE];
    big_r.copy_from_slice(&signature[..KEY_SIZE]);
    let k = challenge(dom, &big_r, public, message);

    // SB = R + kA, checked as R = SB - kA so R need never be
    // decompressed: its bytes are compared directly, and only the
    // canonical encoding of a point can match.
    if a.neg().mul_add_base_vartime(&k, &s).compress() == big_r {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// `k = SHAKE256(dom || R || A || M, 114)`, reduced into the group.
fn challenge(
    dom: &[&[u8]],
    big_r: &[u8; KEY_SIZE],
    public: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8],
) -> Scalar {
    let mut parts = [&[][..]; 5];
    parts[..dom.len()].copy_from_slice(dom);
    parts[dom.len()] = big_r;
    parts[dom.len() + 1] = public;
    parts[dom.len() + 2] = message;
    let mut wide = [0u8; WIDE];
    shake(&parts[..dom.len() + 3], &mut wide);
    Scalar::from_wide(&wide)
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
/// `PRIVATE KEY` in a PEM file, which RFC 8410 fixes for Ed448: the
/// 57 bytes in an OCTET STRING of their own inside the one PKCS#8
/// provides. A version 1 structure that also carries the public key
/// is read, and refused as [`Error::InconsistentKey`] when that key
/// is not the secret's. A structure under another identifier, or
/// under `id-Ed448` with the NULL parameters RFC 8410 forbids, is
/// [`Error::WrongAlgorithm`]; anything else wrong with the bytes is
/// [`Error::InvalidEncoding`].
pub fn secret_from_der(der: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    secret_from_der_with_form(der).map(|(secret, _)| secret)
}

/// As [`secret_from_der`], and also which form the structure took.
pub fn secret_from_der_with_form(
    der: &[u8],
) -> Result<([u8; KEY_SIZE], Pkcs8Form), Error> {
    let found = der::curve_secret_from_der(&der::ED448, der)?;
    let form = Pkcs8Form {
        v1: found.v1,
        public_key: found.public.is_some(),
    };
    Ok((checked(found.secret, found.public)?, form))
}

/// The secret a structure carried, once the public key it may have
/// carried beside it is checked to be the secret's own.
fn checked(
    mut secret: [u8; KEY_SIZE],
    carried: Option<[u8; PUBLIC_KEY_SIZE]>,
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
    der::curve_secret_der(&der::ED448, secret)
}

/// A public key from its DER `SubjectPublicKeyInfo`. The bytes are
/// not checked to be a point here; the functions that use them
/// refuse one that is not.
pub fn public_key_from_der(der: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE], Error> {
    der::curve_public_from_der(&der::ED448, der)
}

/// The public key's DER encoding.
pub fn public_key_der(
    public: &[u8; PUBLIC_KEY_SIZE],
) -> [u8; PUBLIC_KEY_DER_SIZE] {
    der::curve_public_der(&der::ED448, public)
}

/// A secret key from a `PRIVATE KEY` PEM block (RFC 7468) around
/// [`secret_der`]'s bytes, read as [`secret_from_der`] reads them.
pub fn secret_from_pem(pem: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    let found = der::curve_secret_from_pem(&der::ED448, pem)?;
    checked(found.secret, found.public)
}

/// The secret key as a `PRIVATE KEY` PEM block, always [`PEM_SIZE`]
/// bytes. A secret, to be wiped when done.
pub fn secret_pem(secret: &[u8; KEY_SIZE]) -> [u8; PEM_SIZE] {
    der::curve_secret_pem(&der::ED448, secret)
}

/// A public key from a `PUBLIC KEY` PEM block.
pub fn public_key_from_pem(pem: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE], Error> {
    der::curve_public_from_pem(&der::ED448, pem)
}

/// The public key as a `PUBLIC KEY` PEM block, always
/// [`PUBLIC_KEY_PEM_SIZE`] bytes.
pub fn public_key_pem(
    public: &[u8; PUBLIC_KEY_SIZE],
) -> [u8; PUBLIC_KEY_PEM_SIZE] {
    der::curve_public_pem(&der::ED448, public)
}

/// The length of a key pair's DER encoding, a version 1
/// `PrivateKeyInfo` carrying the public key beside the seed.
pub const PAIR_DER_SIZE: usize = der::curve_pair_der_len(KEY_SIZE);

/// The length of a key pair's PEM encoding, a `PRIVATE KEY` block.
pub const PAIR_PEM_SIZE: usize = der::curve_pair_pem_len(KEY_SIZE);

/// A signing key, and the public key that goes with it.
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

/// A verifying key: a point in its compressed form.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
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
    /// A key drawn from `rng`: 57 bytes from the source, since any
    /// 57 bytes are a secret key, and the public key they give.
    pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
        let mut secret = Key::zeroed();
        rng.fill(secret.as_mut())?;
        Ok(Self::new(&secret))
    }

    /// The key `secret` is the seed of; every 57 bytes are one.
    pub fn new(secret: &Key<[u8; KEY_SIZE]>) -> Self {
        let public = PublicKey {
            bytes: public_key(secret.array()),
        };
        PrivateKey {
            secret: secret.clone(),
            public,
        }
    }

    /// The seed, to store or to hand to code that wants the bytes.
    pub fn secret_bytes(&self) -> [u8; KEY_SIZE] {
        *self.secret.array()
    }

    /// The public key, derived when this key was built.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Signs `message` under `context`, hedged, as [`sign`] does.
    pub fn sign<R: Random>(
        &self,
        rng: &mut R,
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let head = dom4(PURE, context)?;
        self.hedged(rng, &[&head, context], message)
    }

    /// Signs `message` under `context` as RFC 8032 does, as
    /// [`sign_deterministic`] does.
    pub fn sign_deterministic(
        &self,
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let head = dom4(PURE, context)?;
        Ok(self.sign_dom(&[&head, context], message, None))
    }

    /// Signs the SHAKE256 digest `prehash` under `context`, by
    /// Ed448ph, hedged, as [`sign_ph`] does.
    pub fn sign_ph<R: Random>(
        &self,
        rng: &mut R,
        context: &[u8],
        prehash: &[u8; PREHASH_SIZE],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let head = dom4(PH, context)?;
        self.hedged(rng, &[&head, context], prehash)
    }

    /// Ed448ph deterministically, as [`sign_ph_deterministic`] does.
    pub fn sign_ph_deterministic(
        &self,
        context: &[u8],
        prehash: &[u8; PREHASH_SIZE],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let head = dom4(PH, context)?;
        Ok(self.sign_dom(&[&head, context], prehash, None))
    }

    /// One signature under `dom`, hedged by bytes from `rng`.
    fn hedged<R: Random>(
        &self,
        rng: &mut R,
        dom: &[&[u8]],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let mut z = noise(rng)?;
        let signature = self.sign_dom(dom, message, Some(&z));
        z.zeroize();
        Ok(signature)
    }

    /// One signature under `dom`, hedged by `noise` if there is any.
    fn sign_dom(
        &self,
        dom: &[&[u8]],
        message: &[u8],
        noise: Option<&[u8; 32]>,
    ) -> [u8; SIGNATURE_SIZE] {
        sign_with(self.secret.array(), &self.public.bytes, dom, message, noise)
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
    /// the public key beside the seed. The output is a secret, to be
    /// wiped when done; [`secret_der`] writes the version 0 form,
    /// which is what OpenSSL emits.
    pub fn der_bytes(&self) -> [u8; PAIR_DER_SIZE] {
        der::curve_pair_der(
            &der::ED448,
            self.secret.array(),
            &self.public.bytes,
        )
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
        der::curve_pair_pem(
            &der::ED448,
            self.secret.array(),
            &self.public.bytes,
        )
    }
}

impl PublicKey {
    /// The key those bytes are, unchecked: they are checked where
    /// they are used, as [`verify`] describes.
    pub fn new(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey { bytes: *bytes }
    }

    /// The compressed point.
    pub fn bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
    }

    /// Checks that `signature` signs `message` under `context` and
    /// this key, as [`verify`] does.
    pub fn verify(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<(), Error> {
        verify(&self.bytes, context, message, signature)
    }

    /// Checks that `signature` signs the SHAKE256 digest `prehash`
    /// under `context` and this key, by Ed448ph, as [`verify_ph`]
    /// does.
    pub fn verify_ph(
        &self,
        context: &[u8],
        prehash: &[u8; PREHASH_SIZE],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<(), Error> {
        verify_ph(&self.bytes, context, prehash, signature)
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

/// The u-coordinate of `k` times X448's base point, with `k` already
/// clamped: the comb over the Ed448 base table, then RFC 7748
/// section 4.2's 4-isogeny `u = y^2 / x^2` to Curve448, which takes
/// Ed448's base point to X448's.
///
/// Reducing `k` modulo the group order changes nothing, since the
/// base point has that order. A multiple that is the identity, for
/// the one clamped `k` that is a multiple of the order, has x = 0,
/// and the inverse of zero is zero, so the answer is zero as the
/// ladder's is.
pub(crate) fn montgomery_base(k: &[u8; 56]) -> [u8; 56] {
    let mut scalar = Scalar::reduce(k);
    let mut point = Point::mul_base(&scalar);
    let u = point.y.square().mul(&point.x.square().invert()).to_bytes();
    scalar.zeroize();
    point.zeroize();
    u
}

/// The secret scalar: the low 57 bytes of the expanded secret,
/// clamped as RFC 8032 section 5.2.5 requires, reduced into the
/// group, which changes nothing the curve can see.
fn secret_scalar(h: &[u8; WIDE]) -> Scalar {
    let mut bytes = [0u8; 56];
    bytes.copy_from_slice(&h[..56]);
    bytes[0] &= 0xfc;
    bytes[55] |= 0x80;
    // Byte 56 is cleared by the clamping, so the 56 here are all.
    let scalar = Scalar::reduce(&bytes);
    bytes.zeroize();
    scalar
}

/// The curve constant d, -39081, as its multiplier: every use is a
/// product by d, which is the negation of a product by 39081.
const MINUS_D: u32 = 39081;

/// The blocks the comb cuts a scalar into.
const COMB: usize = 6;

/// The bits in a block: enough that six of them cover the 446 bits
/// of a reduced scalar.
const BLOCK: usize = 446usize.div_ceil(COMB);

/// The digit positions a reduced scalar can need: 446 bits, and a
/// digit or two past them for the carry of the signed form.
const DIGITS: usize = 456;

/// An affine point as the mixed addition reads it: `x`, `y` and
/// `d x y`, each fully reduced.
#[derive(Clone, Copy)]
struct Affine {
    x: Fe,
    y: Fe,
    dxy: Fe,
}

impl Affine {
    /// The neutral element, (0, 1).
    const IDENTITY: Affine = Affine {
        x: Fe::ZERO,
        y: Fe::ONE,
        dxy: Fe::ZERO,
    };

    /// Replaces `self` with `other` when `condition` is one, by a
    /// mask rather than a branch.
    fn cmov(&mut self, other: &Affine, condition: u64) {
        self.x.cmov(&other.x, condition);
        self.y.cmov(&other.y, condition);
        self.dxy.cmov(&other.dxy, condition);
    }

    /// `-P` is `(-x, y)`.
    fn neg(&self) -> Affine {
        Affine {
            x: self.x.neg(),
            y: self.y,
            dxy: self.dxy.neg(),
        }
    }
}

/// The digit width for the public key's scalar in verification,
/// whose odd multiples are built per signature: eight of them.
const A_WIDTH: u32 = 5;

/// The digit width for the base point's scalar, whose odd multiples
/// are the 32 in [`base::ODD`].
const B_WIDTH: u32 = 7;

/// `scalar` in width-`width` non-adjacent form: digits that are zero
/// or odd, below `2^(width - 1)` in magnitude, with at least
/// `width - 1` zeros between any two nonzero ones, whose sum of
/// `digit[i] * 2^i` is the scalar. Branches on the scalar, so for
/// public ones only.
fn naf(scalar: &Scalar, width: u32) -> [i8; DIGITS] {
    debug_assert!((2..=8).contains(&width));
    let mut words = [0u64; 8];
    words[..7].copy_from_slice(&scalar.0.0);
    let span = 1u64 << width;
    let mask = span - 1;

    let mut digits = [0i8; DIGITS];
    let mut carry = 0u64;
    let mut pos = 0usize;
    while pos < DIGITS {
        let (word, bit) = (pos / 64, pos % 64);
        // The window can straddle a word; the eighth word is zero and
        // stands for the bits past the scalar.
        let mut window = words[word] >> bit;
        if bit > 0 && word + 1 < words.len() {
            window |= words[word + 1] << (64 - bit);
        }
        let value = carry + (window & mask);
        // An even value has a zero bottom bit, carry included: no
        // digit here, and the carry moves up with the position.
        if value & 1 == 0 {
            pos += 1;
            continue;
        }
        // Past half the span the digit goes negative, and what it
        // borrowed from the next window is the carry.
        if value < span / 2 {
            carry = 0;
            digits[pos] = value as i8;
        } else {
            carry = 1;
            digits[pos] = (value as i64 - span as i64) as i8;
        }
        pos += width as usize;
    }
    // Reduced scalars are below 2^446, so nothing carries out.
    debug_assert_eq!(carry, 0);
    digits
}

/// A point in extended coordinates: x = X/Z, y = Y/Z, T = XY/Z.
///
/// The extra T coordinate is what lets one addition formula serve
/// every case, doubling included, with no exceptional inputs: on
/// edwards448, with a = 1 and d not a square, the formula is
/// complete.
#[derive(Clone, Copy, Zeroize)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    /// The neutral element: (0, 1).
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// The unified addition of Hisil, Wong, Carter and Dawson for
    /// a = 1 (add-2008-hwcd): correct for any pair of inputs,
    /// doubling included.
    fn add(&self, other: &Point) -> Point {
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        // d T1 T2, kept as its negation.
        let c = self.t.mul(&other.t).mul_small(MINUS_D);
        let d = self.z.mul(&other.z);
        let e = self
            .x
            .add(&self.y)
            .mul(&other.x.add(&other.y))
            .sub(&a)
            .sub(&b);
        Point::finish(e, d.add(&c), d.sub(&c), b.sub(&a))
    }

    /// The doubling of the same authors for a = 1 (dbl-2008-hwcd),
    /// which saves the multiplication by d.
    fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = a.add(&b);
        Point::finish(e, g.sub(&c), g, a.sub(&b))
    }

    /// The formulas' common last step from E, F, G and H.
    fn finish(e: Fe, f: Fe, g: Fe, h: Fe) -> Point {
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// `-P` is `(-x, y)`.
    fn neg(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// The addition with an affine point, whose Z is one and whose
    /// `d x y` is ready-made.
    fn add_affine(&self, other: &Affine) -> Point {
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = self.t.mul(&other.dxy);
        let e = self
            .x
            .add(&self.y)
            .mul(&other.x.add(&other.y))
            .sub(&a)
            .sub(&b);
        Point::finish(e, self.z.sub(&c), self.z.add(&c), b.sub(&a))
    }

    /// `scalar` times the base point, by the comb over [`base::BASE`]:
    /// each step doubles once and adds the entry that the step's bit
    /// of every block selects. The scalar is secret, so the read
    /// scans every entry and chooses by a mask.
    fn mul_base(scalar: &Scalar) -> Point {
        let mut bytes = scalar.to_bytes();
        let mut acc = Point::IDENTITY;
        for t in (0..BLOCK).rev() {
            acc = acc.double();
            // Bit `t` of every block, gathered least block first. The
            // last block runs past the 446 bits a reduced scalar has,
            // and those bits are zero.
            let mut digit = 0u64;
            for i in 0..COMB {
                let bit = i * BLOCK + t;
                if bit < 8 * KEY_SIZE {
                    digit |= u64::from((bytes[bit >> 3] >> (bit & 7)) & 1) << i;
                }
            }
            // Entry `j` holds the digit `j + 1`, so a zero digit
            // matches nothing and leaves the identity.
            let mut chosen = Affine::IDENTITY;
            for (j, entry) in base::BASE.iter().enumerate() {
                let index = j as u64 + 1;
                let matches = ((index ^ digit).wrapping_sub(1)) >> 63;
                chosen.cmov(entry, matches);
            }
            acc = acc.add_affine(&chosen);
        }
        bytes.zeroize();
        acc
    }

    /// `a` times `self` plus `b` times the base point, in one pass
    /// that shares the doublings: each scalar is written in signed
    /// odd digits, five bits wide for `self`, whose odd multiples are
    /// built here, and seven for the base point, whose are in
    /// [`base::ODD`]. For public scalars only.
    fn mul_add_base_vartime(&self, a: &Scalar, b: &Scalar) -> Point {
        let a_digits = naf(a, A_WIDTH);
        let b_digits = naf(b, B_WIDTH);

        // self, 3 self, 5 self, ..., 15 self.
        let twice = self.double();
        let mut odd = [*self; 8];
        for i in 1..odd.len() {
            odd[i] = odd[i - 1].add(&twice);
        }

        let mut acc = Point::IDENTITY;
        let Some(top) =
            (0..DIGITS).rposition(|i| a_digits[i] | b_digits[i] != 0)
        else {
            return acc;
        };
        for i in (0..=top).rev() {
            acc = acc.double();
            // Digit `d` is odd, and `|d| / 2` indexes its multiple.
            let d = a_digits[i];
            let entry = usize::from(d.unsigned_abs() / 2);
            if d > 0 {
                acc = acc.add(&odd[entry]);
            } else if d < 0 {
                acc = acc.add(&odd[entry].neg());
            }
            let d = b_digits[i];
            let entry = usize::from(d.unsigned_abs() / 2);
            if d > 0 {
                acc = acc.add_affine(&base::ODD[entry]);
            } else if d < 0 {
                acc = acc.add_affine(&base::ODD[entry].neg());
            }
        }
        acc
    }

    /// The 57-byte encoding: y, then a byte holding the sign of x in
    /// its top bit.
    fn compress(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut out = [0u8; PUBLIC_KEY_SIZE];
        out[..56].copy_from_slice(&y.to_bytes());
        out[56] = x.is_negative() << 7;
        out
    }

    /// The point `bytes` encode, by RFC 8032 section 5.2.3, or `None`
    /// where they encode none: a y at or above the prime, low bits
    /// set in the last byte, an x whose square is not a square, or a
    /// zero x with its sign bit set. Public data only, so the checks
    /// may branch.
    fn decompress(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Option<Point> {
        if bytes[56] & 0x7f != 0 {
            return None;
        }
        let mut y_bytes = [0u8; 56];
        y_bytes.copy_from_slice(&bytes[..56]);
        let y = Fe::from_bytes(&y_bytes);
        if y.to_bytes() != y_bytes {
            return None;
        }
        // x^2 = u / v, u = y^2 - 1, v = d y^2 - 1; the root is
        // u^3 v (u^5 v^3)^((p - 3) / 4).
        let y2 = y.square();
        let u = y2.sub(&Fe::ONE);
        let v = y2.mul_small(MINUS_D).neg().sub(&Fe::ONE);
        let u2 = u.square();
        let u3 = u2.mul(&u);
        let v3 = v.square().mul(&v);
        let mut x = u3.mul(&v).mul(&u3.mul(&u2).mul(&v3).pow_p34());
        if !v.mul(&x.square()).equals(&u) {
            return None;
        }
        let sign = bytes[56] >> 7;
        if x.equals(&Fe::ZERO) && sign == 1 {
            return None;
        }
        if x.is_negative() != sign {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }
}

/// The group order L = 2^446 - 13818066809895115352007386748515426
/// 880336692474882178609894547503885, least significant limb first.
const L: Uint<7> = Uint([
    0x2378c292ab5844f3,
    0x216cc2728dc58f55,
    0xc44edb49aed63690,
    0xffffffff7cca23e9,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x3fffffffffffffff,
]);

/// Arithmetic modulo the group order.
static ORDER: Montgomery<7> = Montgomery::known(L);

/// An integer modulo the group order, fully reduced.
#[derive(Clone, Copy)]
struct Scalar(Uint<7>);

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Little-endian bytes, at most 56 of them, as an integer.
fn from_le(bytes: &[u8]) -> Uint<7> {
    let mut be = [0u8; 56];
    for (b, &x) in be.iter_mut().rev().zip(bytes) {
        *b = x;
    }
    let value = Uint::from_be_bytes(&be);
    be.zeroize();
    value
}

impl Scalar {
    /// Any 448-bit integer, reduced: the product by one in plain form
    /// is a full reduction, whatever the input's size.
    fn reduce(bytes: &[u8; 56]) -> Scalar {
        Scalar(ORDER.mulmod(&from_le(bytes), &Uint::one()))
    }

    /// A 114-byte hash, little-endian, reduced: Horner's rule over
    /// pieces of 448 bits, each reduced as it comes in, and the
    /// running value scaled by 2^448 mod L between them.
    fn from_wide(bytes: &[u8; WIDE]) -> Scalar {
        let one = Uint::one();
        let radix = ORDER.to_mont(&one);
        let piece = |range: core::ops::Range<usize>| {
            ORDER.mulmod(&from_le(&bytes[range]), &one)
        };
        let mut acc = piece(112..114);
        for range in [56..112, 0..56] {
            acc = ORDER.mulmod(&acc, &radix).add_mod(&piece(range), &L);
        }
        Scalar(acc)
    }

    /// The value of the 57 bytes of a signature's `S`, if they are
    /// below the group order; `None` for one that is not, which
    /// RFC 8032 refuses.
    fn below_order(bytes: &[u8; KEY_SIZE]) -> Option<Scalar> {
        let value = from_le(&bytes[..56]);
        (bytes[56] == 0 && value.less_than(&L) == 1).then_some(Scalar(value))
    }

    /// The 57-byte little-endian encoding; the top byte is always
    /// zero, the order being under 2^446.
    fn to_bytes(self) -> [u8; KEY_SIZE] {
        let mut be = [0u8; 56];
        self.0.to_be_bytes(&mut be);
        let mut out = [0u8; KEY_SIZE];
        for (o, &b) in out.iter_mut().zip(be.iter().rev()) {
            *o = b;
        }
        be.zeroize();
        out
    }

    /// `self * a + b`.
    fn mul_add(&self, a: &Scalar, b: &Scalar) -> Scalar {
        Scalar(ORDER.mulmod(&self.0, &a.0).add_mod(&b.0, &L))
    }
}

#[cfg(test)]
mod tests;
