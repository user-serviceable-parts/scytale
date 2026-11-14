//! LMS and HSS (RFC 8554, SP 800-208): stateful hash-based signatures
//! for firmware signing.
//!
//! An LMS key is a Merkle tree of one-time keys. Each signature spends
//! one leaf, so a key signs a fixed number of messages and the signer
//! must remember which leaves are gone: a leaf used twice gives away
//! enough to forge. That is the price for being the scheme CNSA 2.0
//! names for software and firmware, with signatures a quarter the size
//! of SLH-DSA's and verification that fits a boot ROM. For anything
//! without that requirement, [`slh_dsa`](crate::sig::slh_dsa) is the
//! same security without the state; see [State](#state).
//!
//! HSS stacks trees: the top tree signs the roots of the trees under
//! it, so a key gets more signatures than one tree's leaves without
//! the whole 2^h cost at key generation. An HSS key with one level is
//! a single LMS tree, and the HSS forms are what RFC 9708 puts in
//! certificates, so [`hss`] is the module to use; [`PrivateKey`] and
//! [`PublicKey`] here are the single tree under it, which the ACVP
//! vectors exercise directly.
//!
//! ```
//! use scytale::random::CtrDrbg;
//! use scytale::sig::lms::hss::PrivateKey;
//! use scytale::sig::lms::{Lmots, Lms};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let sets = [(Lms::Sha256M32H5, Lmots::Sha256N32W8); 2];
//! let mut key = PrivateKey::<2>::generate(&mut rng, &sets)?;
//! assert_eq!(key.remaining(), 32 * 32);
//!
//! let mut signature = [0u8; scytale::sig::lms::hss::signature_max(2)];
//! let n = key.sign(&mut rng, b"firmware 1.2", &mut signature)?;
//! assert_eq!(key.remaining(), 32 * 32 - 1);
//!
//! let public = key.public_key();
//! public.verify(b"firmware 1.2", &signature[..n])?;
//! assert!(public.verify(b"firmware 1.3", &signature[..n]).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # Parameter sets
//!
//! A tree is named by an LMS set, [`Lms`], which fixes the hash and
//! the height h (5 to 25, so 32 to 33 million leaves), and an LM-OTS
//! set, [`Lmots`], which fixes the Winternitz width w (1, 2, 4 or 8)
//! and so the trade between signature size and hashing: w = 8 gives
//! the smallest signature and the most hashing, 255 hashes a chain.
//! SP 800-208 defines four hashes, SHA-256, SHA-256/192, SHAKE256/256
//! and SHAKE256/192, and the two sets of a tree, and every tree of an
//! HSS key, must share one. The IANA typecodes are the discriminants.
//!
//! | Set                              | Signature | Hashes to verify |
//! |----------------------------------|-----------|------------------|
//! | LMS_SHA256_M32_H10, N32_W8       |     1 452 |           ~4 500 |
//! | LMS_SHA256_M32_H10, N32_W4       |     2 508 |           ~1 000 |
//! | LMS_SHA256_M32_H10, N32_W1       |     8 844 |             ~300 |
//! | HSS of two of the first          |     2 964 |           ~9 000 |
//!
//! Key generation hashes every leaf: at w = 8 a leaf is about 8 700
//! hashes, so an H10 tree is about nine million, an H15 three hundred
//! million, and H20 and H25 are hours and days of work. The HSS
//! layering is the answer: two H10 trees give a million signatures for
//! twice the H10 cost, the lower tree regenerated when it is spent.
//!
//! # State
//!
//! A private key here carries the Merkle traversal state of each tree
//! (the BDS algorithm of Buchmann, Dahmen and Schneider), so a
//! signature costs about h/2 leaf computations rather than 2^h, and
//! each signature advances the key. The key the caller holds after
//! [`sign`](hss::PrivateKey::sign) is a different key from the one
//! before it, and the one before it must never sign again. So:
//!
//! - persist the advanced key before releasing the signature, and if
//!   persisting fails, discard the signature;
//! - never copy a private key: two copies sign the same leaf twice;
//! - never restore a private key from a backup made before signatures
//!   were issued.
//!
//! The library cannot enforce any of that; it is the caller's whole
//! job. SP 800-208 section 8 discusses it at length. The encodings
//! here are the library's own: PKCS#8 under the RFC 9708 algorithm
//! identifier with a private layout, documented at
//! [`hss::PrivateKey::der_bytes`], since no standard defines one.

use zeroize::Zeroize;

use crate::constant_time;
use crate::hash::sha2::Sha256;
use crate::hash::sha3::Shake256;
use crate::hash::{Hash, Xof, XofReader};
use crate::{Error, Random};

pub mod hss;
mod ots;
mod tree;

/// The widest node or hash output: SHA-256's.
const N_MAX: usize = 32;

/// The tallest tree.
const H_MAX: usize = 25;

/// The length of the key identifier `I`.
pub const I_SIZE: usize = 16;

/// A node, hash or seed: `n` bytes used, the rest zero.
type Node = [u8; N_MAX];

/// The longest LMS public key, `u32str(type) || u32str(otstype) || I
/// || T[1]`, at n = 32.
pub const PUBLIC_KEY_MAX: usize = 24 + N_MAX;

/// The longest LMS signature of any set: H25 with W1.
pub const SIGNATURE_MAX: usize =
    Lms::Sha256M32H25.signature_len(Lmots::Sha256N32W1);

/// The hash a parameter set is built on (SP 800-208 section 2.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// SHA-256, 32-byte nodes; RFC 8554's own sets.
    Sha256,
    /// SHA-256/192: SHA-256 cut to its first 24 bytes.
    Sha256_192,
    /// SHAKE256 with 32 bytes of output.
    Shake256,
    /// SHAKE256 with 24 bytes of output.
    Shake256_192,
}

impl Family {
    /// The output length, `n` or `m` in the RFC.
    pub const fn n(self) -> usize {
        match self {
            Family::Sha256 | Family::Shake256 => 32,
            Family::Sha256_192 | Family::Shake256_192 => 24,
        }
    }
}

/// An LM-OTS parameter set (RFC 8554 table 1, SP 800-208 tables 3,
/// 5 and 7). The discriminant is the IANA typecode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum Lmots {
    Sha256N32W1 = 1,
    Sha256N32W2 = 2,
    Sha256N32W4 = 3,
    Sha256N32W8 = 4,
    Sha256N24W1 = 5,
    Sha256N24W2 = 6,
    Sha256N24W4 = 7,
    Sha256N24W8 = 8,
    ShakeN32W1 = 9,
    ShakeN32W2 = 10,
    ShakeN32W4 = 11,
    ShakeN32W8 = 12,
    ShakeN24W1 = 13,
    ShakeN24W2 = 14,
    ShakeN24W4 = 15,
    ShakeN24W8 = 16,
}

impl Lmots {
    /// Every set, in typecode order.
    pub const ALL: [Lmots; 16] = [
        Lmots::Sha256N32W1,
        Lmots::Sha256N32W2,
        Lmots::Sha256N32W4,
        Lmots::Sha256N32W8,
        Lmots::Sha256N24W1,
        Lmots::Sha256N24W2,
        Lmots::Sha256N24W4,
        Lmots::Sha256N24W8,
        Lmots::ShakeN32W1,
        Lmots::ShakeN32W2,
        Lmots::ShakeN32W4,
        Lmots::ShakeN32W8,
        Lmots::ShakeN24W1,
        Lmots::ShakeN24W2,
        Lmots::ShakeN24W4,
        Lmots::ShakeN24W8,
    ];

    /// The set with this IANA typecode, or [`Error::WrongAlgorithm`]
    /// for a typecode that names none.
    pub const fn from_typecode(typecode: u32) -> Result<Self, Error> {
        if typecode == 0 || typecode > Self::ALL.len() as u32 {
            return Err(Error::WrongAlgorithm);
        }
        Ok(Self::ALL[typecode as usize - 1])
    }

    /// The IANA typecode.
    pub const fn typecode(self) -> u32 {
        self as u32
    }

    /// The set's name as RFC 8554 and SP 800-208 write it,
    /// `LMOTS_SHA256_N32_W1`.
    pub const fn name(self) -> &'static str {
        match self {
            Lmots::Sha256N32W1 => "LMOTS_SHA256_N32_W1",
            Lmots::Sha256N32W2 => "LMOTS_SHA256_N32_W2",
            Lmots::Sha256N32W4 => "LMOTS_SHA256_N32_W4",
            Lmots::Sha256N32W8 => "LMOTS_SHA256_N32_W8",
            Lmots::Sha256N24W1 => "LMOTS_SHA256_N24_W1",
            Lmots::Sha256N24W2 => "LMOTS_SHA256_N24_W2",
            Lmots::Sha256N24W4 => "LMOTS_SHA256_N24_W4",
            Lmots::Sha256N24W8 => "LMOTS_SHA256_N24_W8",
            Lmots::ShakeN32W1 => "LMOTS_SHAKE_N32_W1",
            Lmots::ShakeN32W2 => "LMOTS_SHAKE_N32_W2",
            Lmots::ShakeN32W4 => "LMOTS_SHAKE_N32_W4",
            Lmots::ShakeN32W8 => "LMOTS_SHAKE_N32_W8",
            Lmots::ShakeN24W1 => "LMOTS_SHAKE_N24_W1",
            Lmots::ShakeN24W2 => "LMOTS_SHAKE_N24_W2",
            Lmots::ShakeN24W4 => "LMOTS_SHAKE_N24_W4",
            Lmots::ShakeN24W8 => "LMOTS_SHAKE_N24_W8",
        }
    }

    /// The set with this [`name`](Self::name), or
    /// [`Error::WrongAlgorithm`].
    pub fn from_name(name: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|set| set.name() == name)
            .ok_or(Error::WrongAlgorithm)
    }

    /// The hash.
    pub const fn family(self) -> Family {
        match (self as u32 - 1) / 4 {
            0 => Family::Sha256,
            1 => Family::Sha256_192,
            2 => Family::Shake256,
            _ => Family::Shake256_192,
        }
    }

    /// The hash length `n`.
    pub const fn n(self) -> usize {
        self.family().n()
    }

    /// The Winternitz width `w`, in bits.
    pub const fn w(self) -> u32 {
        1 << ((self as u32 - 1) % 4)
    }

    /// The number of chains `p` (RFC 8554 appendix B).
    pub const fn p(self) -> usize {
        match (self.n(), self.w()) {
            (32, 1) => 265,
            (32, 2) => 133,
            (32, 4) => 67,
            (32, _) => 34,
            (_, 1) => 200,
            (_, 2) => 101,
            (_, 4) => 51,
            _ => 26,
        }
    }

    /// The checksum shift `ls` (RFC 8554 appendix B).
    const fn ls(self) -> u32 {
        match (self.n(), self.w()) {
            (32, 1) => 7,
            (_, 1) => 8,
            (_, 2) => 6,
            (_, 4) => 4,
            _ => 0,
        }
    }

    /// The length of a one-time signature, `4 + n(p + 1)`.
    pub const fn signature_len(self) -> usize {
        4 + self.n() * (self.p() + 1)
    }
}

/// An LMS parameter set (RFC 8554 table 2, SP 800-208 tables 4, 6
/// and 8). The discriminant is the IANA typecode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum Lms {
    Sha256M32H5 = 5,
    Sha256M32H10 = 6,
    Sha256M32H15 = 7,
    Sha256M32H20 = 8,
    Sha256M32H25 = 9,
    Sha256M24H5 = 10,
    Sha256M24H10 = 11,
    Sha256M24H15 = 12,
    Sha256M24H20 = 13,
    Sha256M24H25 = 14,
    ShakeM32H5 = 15,
    ShakeM32H10 = 16,
    ShakeM32H15 = 17,
    ShakeM32H20 = 18,
    ShakeM32H25 = 19,
    ShakeM24H5 = 20,
    ShakeM24H10 = 21,
    ShakeM24H15 = 22,
    ShakeM24H20 = 23,
    ShakeM24H25 = 24,
}

impl Lms {
    /// Every set, in typecode order.
    pub const ALL: [Lms; 20] = [
        Lms::Sha256M32H5,
        Lms::Sha256M32H10,
        Lms::Sha256M32H15,
        Lms::Sha256M32H20,
        Lms::Sha256M32H25,
        Lms::Sha256M24H5,
        Lms::Sha256M24H10,
        Lms::Sha256M24H15,
        Lms::Sha256M24H20,
        Lms::Sha256M24H25,
        Lms::ShakeM32H5,
        Lms::ShakeM32H10,
        Lms::ShakeM32H15,
        Lms::ShakeM32H20,
        Lms::ShakeM32H25,
        Lms::ShakeM24H5,
        Lms::ShakeM24H10,
        Lms::ShakeM24H15,
        Lms::ShakeM24H20,
        Lms::ShakeM24H25,
    ];

    /// The set with this IANA typecode, or [`Error::WrongAlgorithm`]
    /// for a typecode that names none.
    pub const fn from_typecode(typecode: u32) -> Result<Self, Error> {
        if typecode < 5 || typecode > 4 + Self::ALL.len() as u32 {
            return Err(Error::WrongAlgorithm);
        }
        Ok(Self::ALL[typecode as usize - 5])
    }

    /// The IANA typecode.
    pub const fn typecode(self) -> u32 {
        self as u32
    }

    /// The set's name as RFC 8554 and SP 800-208 write it,
    /// `LMS_SHA256_M32_H5`.
    pub const fn name(self) -> &'static str {
        match self {
            Lms::Sha256M32H5 => "LMS_SHA256_M32_H5",
            Lms::Sha256M32H10 => "LMS_SHA256_M32_H10",
            Lms::Sha256M32H15 => "LMS_SHA256_M32_H15",
            Lms::Sha256M32H20 => "LMS_SHA256_M32_H20",
            Lms::Sha256M32H25 => "LMS_SHA256_M32_H25",
            Lms::Sha256M24H5 => "LMS_SHA256_M24_H5",
            Lms::Sha256M24H10 => "LMS_SHA256_M24_H10",
            Lms::Sha256M24H15 => "LMS_SHA256_M24_H15",
            Lms::Sha256M24H20 => "LMS_SHA256_M24_H20",
            Lms::Sha256M24H25 => "LMS_SHA256_M24_H25",
            Lms::ShakeM32H5 => "LMS_SHAKE_M32_H5",
            Lms::ShakeM32H10 => "LMS_SHAKE_M32_H10",
            Lms::ShakeM32H15 => "LMS_SHAKE_M32_H15",
            Lms::ShakeM32H20 => "LMS_SHAKE_M32_H20",
            Lms::ShakeM32H25 => "LMS_SHAKE_M32_H25",
            Lms::ShakeM24H5 => "LMS_SHAKE_M24_H5",
            Lms::ShakeM24H10 => "LMS_SHAKE_M24_H10",
            Lms::ShakeM24H15 => "LMS_SHAKE_M24_H15",
            Lms::ShakeM24H20 => "LMS_SHAKE_M24_H20",
            Lms::ShakeM24H25 => "LMS_SHAKE_M24_H25",
        }
    }

    /// The set with this [`name`](Self::name), or
    /// [`Error::WrongAlgorithm`].
    pub fn from_name(name: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|set| set.name() == name)
            .ok_or(Error::WrongAlgorithm)
    }

    /// The hash.
    pub const fn family(self) -> Family {
        match (self as u32 - 5) / 5 {
            0 => Family::Sha256,
            1 => Family::Sha256_192,
            2 => Family::Shake256,
            _ => Family::Shake256_192,
        }
    }

    /// The node length `m`.
    pub const fn m(self) -> usize {
        self.family().n()
    }

    /// The tree height `h`: the tree has `2^h` leaves.
    pub const fn h(self) -> u32 {
        5 * (1 + (self as u32 - 5) % 5)
    }

    /// The number of signatures a tree of this set can make, `2^h`.
    pub const fn leaves(self) -> u64 {
        1 << self.h()
    }

    /// The length of a public key, `24 + m`.
    pub const fn public_key_len(self) -> usize {
        24 + self.m()
    }

    /// The length of a signature under this set and `ots`: `4 +
    /// ots.signature_len() + 4 + h m`.
    pub const fn signature_len(self, ots: Lmots) -> usize {
        8 + ots.signature_len() + self.h() as usize * self.m()
    }
}

/// Checks that a tree's two sets are built on one hash, as SP 800-208
/// section 4 requires; the hash in the typecodes is what makes the
/// pair unambiguous on the wire.
const fn check_pair(lms: Lms, ots: Lmots) -> Result<(), Error> {
    // `Family` has no const `PartialEq`; compare through the
    // discriminant.
    if lms.family() as u32 != ots.family() as u32 {
        return Err(Error::WrongAlgorithm);
    }
    Ok(())
}

/// The hash of a parameter set, `H`, as one state reused for message
/// after message.
pub(crate) struct Hasher {
    engine: Engine,
    n: usize,
}

enum Engine {
    Sha256(Sha256),
    Shake256(Shake256),
}

impl Hasher {
    fn new(family: Family) -> Self {
        let engine = match family {
            Family::Sha256 | Family::Sha256_192 => {
                Engine::Sha256(Sha256::new())
            }
            Family::Shake256 | Family::Shake256_192 => {
                Engine::Shake256(Shake256::new())
            }
        };
        Hasher {
            engine,
            n: family.n(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match &mut self.engine {
            Engine::Sha256(h) => h.update(data),
            Engine::Shake256(h) => h.update(data),
        }
    }

    /// The `n`-byte digest, zero-padded; the state is then fresh.
    fn finish(&mut self) -> Node {
        let mut out = [0u8; N_MAX];
        match &mut self.engine {
            Engine::Sha256(h) => {
                let digest = h.finalize();
                out[..self.n].copy_from_slice(&digest[..self.n]);
            }
            Engine::Shake256(h) => {
                h.finalize_xof().squeeze(&mut out[..self.n]);
            }
        }
        out
    }

    /// The digest of `parts` concatenated.
    fn digest(&mut self, parts: &[&[u8]]) -> Node {
        for part in parts {
            self.update(part);
        }
        self.finish()
    }
}

/// An LMS public key: one tree's root with the sets and identifier
/// that name it.
#[derive(Clone)]
pub struct PublicKey {
    lms: Lms,
    ots: Lmots,
    i: [u8; I_SIZE],
    root: Node,
}

impl PublicKey {
    /// A key from its RFC 8554 bytes, `u32str(type) || u32str(otstype)
    /// || I || T[1]`. A typecode that names no set, or two sets on
    /// different hashes, is [`Error::WrongAlgorithm`]; the wrong length
    /// for the sets is [`Error::InvalidEncoding`].
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        let (lms, ots, rest) = Self::parse_sets(bytes)?;
        if rest.len() != I_SIZE + lms.m() {
            return Err(Error::InvalidEncoding);
        }
        let mut i = [0u8; I_SIZE];
        i.copy_from_slice(&rest[..I_SIZE]);
        let mut root = [0u8; N_MAX];
        root[..lms.m()].copy_from_slice(&rest[I_SIZE..]);
        Ok(PublicKey { lms, ots, i, root })
    }

    /// The two typecodes at the front of a key or signature, and what
    /// follows them.
    fn parse_sets(bytes: &[u8]) -> Result<(Lms, Lmots, &[u8]), Error> {
        if bytes.len() < 8 {
            return Err(Error::InvalidEncoding);
        }
        let lms = Lms::from_typecode(u32_at(bytes, 0))?;
        let ots = Lmots::from_typecode(u32_at(bytes, 4))?;
        check_pair(lms, ots)?;
        Ok((lms, ots, &bytes[8..]))
    }

    /// The key's bytes, `u32str(type) || u32str(otstype) || I ||
    /// T[1]`.
    pub fn bytes(&self) -> [u8; PUBLIC_KEY_MAX] {
        let mut out = [0u8; PUBLIC_KEY_MAX];
        out[..4].copy_from_slice(&self.lms.typecode().to_be_bytes());
        out[4..8].copy_from_slice(&self.ots.typecode().to_be_bytes());
        out[8..8 + I_SIZE].copy_from_slice(&self.i);
        out[8 + I_SIZE..].copy_from_slice(&self.root);
        out
    }

    /// The length of [`bytes`](Self::bytes) that is the key: the rest
    /// is zero.
    pub fn len(&self) -> usize {
        self.lms.public_key_len()
    }

    /// Whether the key has no bytes, which it never has; here because
    /// [`len`](Self::len) is.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The LMS set.
    pub fn lms(&self) -> Lms {
        self.lms
    }

    /// The LM-OTS set.
    pub fn lmots(&self) -> Lmots {
        self.ots
    }

    /// The length of a signature under this key.
    pub fn signature_len(&self) -> usize {
        self.lms.signature_len(self.ots)
    }

    /// Checks that `signature` signs `message` under this key (RFC
    /// 8554 algorithm 6). [`Error::InvalidSignature`] for anything
    /// that does not, which deliberately says no more: a signature of
    /// the wrong length or sets is as invalid as a wrong one.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        self.verify_parts(&[message], signature)
    }

    /// [`verify`](Self::verify) over `message` in pieces, so a
    /// signed public key need not be copied to be hashed.
    fn verify_parts(
        &self,
        message: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), Error> {
        let candidate = self.root_candidate(message, signature)?;
        let m = self.lms.m();
        if constant_time::equal(&candidate[..m], &self.root[..m]) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Algorithm 6b: the root the signature would hang from.
    fn root_candidate(
        &self,
        message: &[&[u8]],
        signature: &[u8],
    ) -> Result<Node, Error> {
        let (lms, ots, n, h) = (self.lms, self.ots, self.ots.n(), self.lms.h());
        if signature.len() != lms.signature_len(ots) {
            return Err(Error::InvalidSignature);
        }
        let q = u32_at(signature, 0);
        if u64::from(q) >= lms.leaves() {
            return Err(Error::InvalidSignature);
        }
        let ots_sig = &signature[4..4 + ots.signature_len()];
        if u32_at(ots_sig, 0) != ots.typecode() {
            return Err(Error::InvalidSignature);
        }
        let rest = &signature[4 + ots.signature_len()..];
        if u32_at(rest, 0) != lms.typecode() {
            return Err(Error::InvalidSignature);
        }
        let path = &rest[4..];
        let mut hasher = Hasher::new(lms.family());
        let kc = ots::Ots::new(ots, &mut hasher, &self.i, q)
            .candidate(ots_sig, message);
        let mut node_num = (1u32 << h) + q;
        let mut tmp = tree::leaf_hash(&mut hasher, &self.i, node_num, &kc[..n]);
        for sibling in path.chunks_exact(n) {
            let (left, right) = if node_num & 1 == 1 {
                (sibling, &tmp[..n])
            } else {
                (&tmp[..n], sibling)
            };
            node_num /= 2;
            tmp = tree::node_hash(&mut hasher, &self.i, node_num, left, right);
        }
        Ok(tmp)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.lms == other.lms
            && self.ots == other.ots
            && self.i == other.i
            && self.root == other.root
    }
}

impl Eq for PublicKey {}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey")
            .field("lms", &self.lms)
            .field("lmots", &self.ots)
            .finish_non_exhaustive()
    }
}

/// An LMS signing key: one tree, its seed, and where it is up to.
/// Wiped on drop.
///
/// Every signature advances the key; see [State](self#state). A tree
/// on its own is what SP 800-208 calls an LMS instance; keys for use
/// are [`hss::PrivateKey`], which this is one level of.
pub struct PrivateKey {
    public: PublicKey,
    seed: Node,
    q: u32,
    state: tree::Bds,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.state.zeroize();
    }
}

impl PrivateKey {
    /// A fresh tree under `lms` and `ots`, with a random identifier
    /// and seed (SP 800-208 section 6.1), its root computed over all
    /// `2^h` leaves. Two sets on different hashes are
    /// [`Error::WrongAlgorithm`].
    pub fn generate<R: Random>(
        rng: &mut R,
        lms: Lms,
        ots: Lmots,
    ) -> Result<Self, Error> {
        check_pair(lms, ots)?;
        let mut i = [0u8; I_SIZE];
        rng.fill(&mut i)?;
        let mut seed = [0u8; N_MAX];
        rng.fill(&mut seed[..lms.m()])?;
        let key = Self::grow(lms, ots, &i, &seed);
        seed.zeroize();
        Ok(key)
    }

    /// The tree `lms` and `ots` grow from the identifier `i` and the
    /// `n`-byte `seed` by RFC 8554 appendix A, which is how the ACVP
    /// vectors specify key generation; the same cost as
    /// [`generate`](Self::generate). A seed of another length is
    /// [`Error::InvalidSeedLength`], and two sets on different hashes
    /// [`Error::WrongAlgorithm`].
    pub fn from_seed(
        lms: Lms,
        ots: Lmots,
        i: &[u8; I_SIZE],
        seed: &[u8],
    ) -> Result<Self, Error> {
        check_pair(lms, ots)?;
        if seed.len() != lms.m() {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        let mut node = [0u8; N_MAX];
        node[..seed.len()].copy_from_slice(seed);
        let key = Self::grow(lms, ots, i, &node);
        node.zeroize();
        Ok(key)
    }

    /// [`from_seed`](Self::from_seed) with the pair checked and the
    /// seed padded.
    fn grow(lms: Lms, ots: Lmots, i: &[u8; I_SIZE], seed: &Node) -> Self {
        let mut state = tree::Bds::blank();
        let root = {
            let mut tree = tree::Tree::new(lms, ots, i, seed);
            state.init(&mut tree)
        };
        PrivateKey {
            public: PublicKey {
                lms,
                ots,
                i: *i,
                root,
            },
            seed: *seed,
            q: 0,
            state,
        }
    }

    /// The public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The LMS set.
    pub fn lms(&self) -> Lms {
        self.public.lms
    }

    /// The LM-OTS set.
    pub fn lmots(&self) -> Lmots {
        self.public.ots
    }

    /// The length of a signature.
    pub fn signature_len(&self) -> usize {
        self.public.signature_len()
    }

    /// How many signatures the tree has left.
    pub fn remaining(&self) -> u64 {
        self.public.lms.leaves() - u64::from(self.q)
    }

    /// Signs `message` with the next leaf, writing the RFC 8554
    /// signature into the front of `out` and returning its length,
    /// then advances the key. `out` shorter than
    /// [`signature_len`](Self::signature_len) is
    /// [`Error::OutputTooSmall`], and an exhausted tree
    /// [`Error::SequenceExhausted`]; neither touches the key.
    pub fn sign<R: Random>(
        &mut self,
        rng: &mut R,
        message: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.sign_parts(rng, &[message], out)
    }

    /// [`sign`](Self::sign) over `message` in pieces.
    pub(crate) fn sign_parts<R: Random>(
        &mut self,
        rng: &mut R,
        message: &[&[u8]],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let (lms, ots) = (self.public.lms, self.public.ots);
        let len = lms.signature_len(ots);
        if out.len() < len {
            return Err(Error::OutputTooSmall(len));
        }
        if self.remaining() == 0 {
            return Err(Error::SequenceExhausted);
        }
        let out = &mut out[..len];
        let (n, h) = (ots.n(), lms.h() as usize);
        let q = self.q;
        // The randomizer C (SP 800-208 section 6.1 wants it random).
        let mut c = [0u8; N_MAX];
        rng.fill(&mut c[..n])?;
        out[..4].copy_from_slice(&q.to_be_bytes());
        let (ots_out, rest) = out[4..].split_at_mut(ots.signature_len());
        {
            let mut hasher = Hasher::new(lms.family());
            ots::Ots::new(ots, &mut hasher, &self.public.i, q)
                .sign(&self.seed, &c, message, ots_out);
        }
        c.zeroize();
        rest[..4].copy_from_slice(&lms.typecode().to_be_bytes());
        for (dst, node) in rest[4..].chunks_exact_mut(n).zip(self.state.auth(h))
        {
            dst.copy_from_slice(&node[..n]);
        }
        // The key is spent on this leaf from here, whatever the
        // caller does with the signature.
        self.q = q + 1;
        if self.remaining() > 0 {
            let mut tree =
                tree::Tree::new(lms, ots, &self.public.i, &self.seed);
            self.state.advance(&mut tree, q);
        }
        Ok(len)
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("lms", &self.public.lms)
            .field("lmots", &self.public.ots)
            .field("q", &self.q)
            .finish_non_exhaustive()
    }
}

/// The longest encoding of a tree by [`PrivateKey::write`].
const PRIVATE_ENCODED_MAX: usize =
    8 + I_SIZE + N_MAX + 4 + N_MAX + tree::Bds::encoded_len(H_MAX, N_MAX);

impl PrivateKey {
    /// A key with nothing in it, a slot for a decoder to fill.
    pub(crate) fn blank() -> Self {
        PrivateKey {
            public: PublicKey {
                lms: Lms::Sha256M32H5,
                ots: Lmots::Sha256N32W8,
                i: [0u8; I_SIZE],
                root: [0u8; N_MAX],
            },
            seed: [0u8; N_MAX],
            q: 0,
            state: tree::Bds::blank(),
        }
    }

    /// The length of [`write`](Self::write).
    fn encoded_len(lms: Lms) -> usize {
        let (h, n) = (lms.h() as usize, lms.m());
        8 + I_SIZE + n + 4 + n + tree::Bds::encoded_len(h, n)
    }

    /// Writes the key through `put`: the two typecodes, `I`, the
    /// seed, `q`, the root, then the traversal state.
    pub(crate) fn write(&self, put: &mut impl FnMut(&[u8])) {
        let (lms, ots) = (self.public.lms, self.public.ots);
        let (h, n) = (lms.h() as usize, lms.m());
        put(&lms.typecode().to_be_bytes());
        put(&ots.typecode().to_be_bytes());
        put(&self.public.i);
        put(&self.seed[..n]);
        put(&self.q.to_be_bytes());
        put(&self.public.root[..n]);
        self.state.write(h, n, put);
    }

    /// A key from the front of `bytes`, as [`write`](Self::write)
    /// wrote it, and how many bytes it took.
    pub(crate) fn read(bytes: &[u8]) -> Result<(Self, usize), Error> {
        let (lms, ots, _) = PublicKey::parse_sets(bytes)?;
        let len = Self::encoded_len(lms);
        if bytes.len() < len {
            return Err(Error::InvalidEncoding);
        }
        let (h, n) = (lms.h() as usize, lms.m());
        let mut at = 8;
        let mut take = |len: usize| {
            let piece = &bytes[at..at + len];
            at += len;
            piece
        };
        let mut key = Self::blank();
        key.public.lms = lms;
        key.public.ots = ots;
        key.public.i.copy_from_slice(take(I_SIZE));
        key.seed[..n].copy_from_slice(take(n));
        key.q = u32_at(take(4), 0);
        if u64::from(key.q) > lms.leaves() {
            return Err(Error::InvalidEncoding);
        }
        key.public.root[..n].copy_from_slice(take(n));
        let state = take(tree::Bds::encoded_len(h, n));
        key.state =
            tree::Bds::read(h, n, state).ok_or(Error::InvalidEncoding)?;
        Ok((key, len))
    }
}

impl PublicKey {
    /// A key from its DER `SubjectPublicKeyInfo`: the HSS form with
    /// one level, as RFC 9708 writes a single tree, read as
    /// [`hss::PublicKey::try_from_der`] reads it. More levels than
    /// one is [`Error::WrongAlgorithm`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        let key = hss::PublicKey::try_from_der(der)?;
        if key.levels() != 1 {
            return Err(Error::WrongAlgorithm);
        }
        Ok(key.top().clone())
    }

    /// Writes the key as a `SubjectPublicKeyInfo`, the HSS form with
    /// one level, into the front of `out`, returning the length.
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.as_hss().der_bytes(out)
    }

    /// A key from a `PUBLIC KEY` PEM block around the DER above.
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        let key = hss::PublicKey::try_from_pem(pem)?;
        if key.levels() != 1 {
            return Err(Error::WrongAlgorithm);
        }
        Ok(key.top().clone())
    }

    /// Writes the key as a `PUBLIC KEY` PEM block into the front of
    /// `out`, returning the length.
    pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.as_hss().pem_bytes(out)
    }

    /// The key as a one-level HSS key.
    pub fn as_hss(&self) -> hss::PublicKey {
        hss::PublicKey::single(self.clone())
    }
}

/// A big-endian `u32` at `offset`, which the caller has bounds-checked.
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(word)
}

#[cfg(test)]
mod rfc8554;
#[cfg(test)]
mod tests;
