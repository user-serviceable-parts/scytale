//! HSS: LMS trees stacked (RFC 8554 section 6), the form keys take
//! in certificates (RFC 9708).
//!
//! The top tree signs the root of the tree below it, that one the
//! root below it, and the bottom tree signs messages. A signature
//! carries the whole chain, each lower public key with the signature
//! over it, so the verifier needs only the top public key. When a
//! lower tree is spent, its parent signs a fresh one; when every tree
//! is spent, the key is finished. The level count `L` is a type
//! parameter, so a key's memory is fixed by its type; a one-level key
//! is a single LMS tree in the HSS wire format.

use zeroize::Zeroize;

use super::{
    I_SIZE, Lmots, Lms, N_MAX, PUBLIC_KEY_MAX as LMS_PUBLIC_KEY_MAX,
    SIGNATURE_MAX as LMS_SIGNATURE_MAX, check_pair, u32_at,
};
use crate::{Error, Random};

/// The most levels a key may have (SP 800-208 section 4).
pub const LEVELS_MAX: usize = 8;

/// The longest public key, `u32str(L) || lms_public_key` at n = 32.
pub const PUBLIC_KEY_MAX: usize = 4 + LMS_PUBLIC_KEY_MAX;

/// The longest signature a key of `levels` levels can make: every
/// level's signature and every lower level's public key at their
/// largest.
pub const fn signature_max(levels: usize) -> usize {
    4 + levels * LMS_SIGNATURE_MAX + (levels - 1) * LMS_PUBLIC_KEY_MAX
}

/// The longest DER encoding of a private key of `levels` levels; see
/// [`PrivateKey::der_bytes`].
pub const fn der_max(levels: usize) -> usize {
    let level = super::PRIVATE_ENCODED_MAX + LMS_SIGNATURE_MAX;
    let inner = 2 + levels * level;
    crate::der::pkcs8_len(OID.len(), crate::der::tlv_len(inner))
}

/// The longest PEM encoding of a private key of `levels` levels.
pub const fn pem_max(levels: usize) -> usize {
    crate::codec::pem::encoded_len(PRIVATE_LABEL, der_max(levels))
}

/// The length of a public key's DER encoding, a
/// `SubjectPublicKeyInfo`; the most it can be.
pub const PUBLIC_KEY_DER_MAX: usize =
    crate::der::spki_len(OID.len(), PUBLIC_KEY_MAX);

/// The length of a public key's PEM encoding, a `PUBLIC KEY` block;
/// the most it can be.
pub const PUBLIC_KEY_PEM_MAX: usize =
    crate::codec::pem::encoded_len(PUBLIC_LABEL, PUBLIC_KEY_DER_MAX);

const OID: [u8; 11] = crate::der::HSS_LMS_HASHSIG;
const PRIVATE_LABEL: &str = "PRIVATE KEY";
const PUBLIC_LABEL: &str = "PUBLIC KEY";

/// The first byte of the private key layout; see
/// [`PrivateKey::der_bytes`].
const LAYOUT_VERSION: u8 = 1;

/// An HSS public key: the level count and the top tree's key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    levels: usize,
    top: super::PublicKey,
}

impl PublicKey {
    /// A key from its RFC 8554 bytes, `u32str(L) || lms_public_key`.
    /// A level count outside 1 to 8, or a set that names no
    /// parameters, is [`Error::WrongAlgorithm`]; the wrong length is
    /// [`Error::InvalidEncoding`].
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::InvalidEncoding);
        }
        let levels = u32_at(bytes, 0) as usize;
        if levels == 0 || levels > LEVELS_MAX {
            return Err(Error::WrongAlgorithm);
        }
        let top = super::PublicKey::new(&bytes[4..])?;
        Ok(PublicKey { levels, top })
    }

    /// A one-level key: the tree alone.
    pub(super) fn single(top: super::PublicKey) -> Self {
        PublicKey { levels: 1, top }
    }

    /// The key's bytes, `u32str(L) || lms_public_key`, in the first
    /// [`len`](Self::len) of the array.
    pub fn bytes(&self) -> [u8; PUBLIC_KEY_MAX] {
        let mut out = [0u8; PUBLIC_KEY_MAX];
        out[..4].copy_from_slice(&(self.levels as u32).to_be_bytes());
        out[4..].copy_from_slice(&self.top.bytes());
        out
    }

    /// The length of the key's bytes.
    pub fn len(&self) -> usize {
        4 + self.top.len()
    }

    /// Whether the key has no bytes, which it never has; here because
    /// [`len`](Self::len) is.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The number of levels.
    pub fn levels(&self) -> usize {
        self.levels
    }

    /// The top tree's key.
    pub fn top(&self) -> &super::PublicKey {
        &self.top
    }

    /// Checks that `signature` signs `message` under this key (RFC
    /// 8554 section 6.3): each level's public key under the one
    /// above, then the message under the lowest.
    /// [`Error::InvalidSignature`] for anything that does not, which
    /// deliberately says no more.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        if signature.len() < 4 {
            return Err(Error::InvalidSignature);
        }
        let signed = u32_at(signature, 0) as usize;
        if signed + 1 != self.levels {
            return Err(Error::InvalidSignature);
        }
        let family = self.top.lms.family();
        let mut key = self.top.clone();
        let mut rest = &signature[4..];
        for _ in 0..signed {
            let len = key.signature_len();
            if rest.len() < len + 8 {
                return Err(Error::InvalidSignature);
            }
            let (sig, after) = rest.split_at(len);
            let lower_len = Lms::from_typecode(u32_at(after, 0))
                .map_err(|_| Error::InvalidSignature)?
                .public_key_len();
            if after.len() < lower_len {
                return Err(Error::InvalidSignature);
            }
            let (lower_bytes, after) = after.split_at(lower_len);
            let lower = super::PublicKey::new(lower_bytes)
                .map_err(|_| Error::InvalidSignature)?;
            if lower.lms.family() != family {
                return Err(Error::InvalidSignature);
            }
            key.verify(lower_bytes, sig)?;
            key = lower;
            rest = after;
        }
        key.verify(message, rest)
    }

    /// A key from its DER `SubjectPublicKeyInfo`, the form under
    /// `PUBLIC KEY` in a PEM file: the RFC 8554 bytes as the key
    /// under id-alg-hss-lms-hashsig (RFC 9708). Another algorithm is
    /// [`Error::WrongAlgorithm`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        let (algorithm, key) = crate::der::read_spki(der)?;
        if algorithm.oid != OID || !algorithm.params.is_empty() {
            return Err(Error::WrongAlgorithm);
        }
        Self::new(key)
    }

    /// Writes the key as a `SubjectPublicKeyInfo` into the front of
    /// `out`, returning the length.
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        let bytes = self.bytes();
        let bytes = &bytes[..self.len()];
        crate::der::write_spki(out, &OID, false, |w| w.raw(bytes))
    }

    /// A key from a `PUBLIC KEY` PEM block (RFC 7468) around the DER
    /// above; whitespace and line ends are read leniently, and
    /// anything else that is not exactly one well-formed block is
    /// [`Error::InvalidEncoding`].
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        let mut der = [0u8; PUBLIC_KEY_DER_MAX];
        let labels = [PUBLIC_LABEL];
        let (_, n) = crate::codec::pem::decode_one_of(&labels, pem, &mut der)?;
        Self::try_from_der(&der[..n])
    }

    /// Writes the key as a `PUBLIC KEY` PEM block, ASCII with LF line
    /// ends, into the front of `out`, returning the length.
    pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut der = [0u8; PUBLIC_KEY_DER_MAX];
        let n = self.der_bytes(&mut der)?;
        crate::codec::pem::encode(PUBLIC_LABEL, &der[..n], out)
    }
}

/// A signature a tree made over the public key of the tree below it,
/// kept for every signature until that tree is spent (SP 800-208
/// section 8.1: a root is signed once, not once a message).
#[derive(Clone)]
struct Signed {
    bytes: [u8; LMS_SIGNATURE_MAX],
}

const UNSIGNED: Signed = Signed {
    bytes: [0u8; LMS_SIGNATURE_MAX],
};

/// An HSS signing key of `L` levels, 1 to 8; wiped on drop.
///
/// Every signature advances the key, and spending a lower tree costs
/// its parent a leaf and the caller a tree's key generation; see
/// [State](super#state) for what the caller must do with it.
pub struct PrivateKey<const L: usize> {
    trees: [super::PrivateKey; L],
    /// `signed[j]` is tree `j`'s signature over tree `j + 1`'s public
    /// key; the last is unused.
    signed: [Signed; L],
}

impl<const L: usize> PrivateKey<L> {
    const LEVELS_OK: () = assert!(L >= 1 && L <= LEVELS_MAX, "1 to 8 levels");

    /// A fresh key with the trees of `sets`, top first, every one
    /// generated and the lower roots signed; `2^h` leaves of work for
    /// each level. Sets on different hashes, within a level or
    /// between levels, are [`Error::WrongAlgorithm`].
    pub fn generate<R: Random>(
        rng: &mut R,
        sets: &[(Lms, Lmots); L],
    ) -> Result<Self, Error> {
        let () = Self::LEVELS_OK;
        let family = sets[0].0.family();
        for &(lms, ots) in sets {
            check_pair(lms, ots)?;
            if lms.family() != family {
                return Err(Error::WrongAlgorithm);
            }
        }
        let mut ids = [[0u8; I_SIZE]; L];
        let mut seeds = [[0u8; N_MAX]; L];
        let mut filled = Ok(());
        for (id, seed) in ids.iter_mut().zip(seeds.iter_mut()) {
            filled = filled
                .and_then(|()| rng.fill(id))
                .and_then(|()| rng.fill(&mut seed[..family.n()]));
        }
        let key = filled.map(|()| PrivateKey {
            trees: core::array::from_fn(|j| {
                super::PrivateKey::grow(
                    sets[j].0, sets[j].1, &ids[j], &seeds[j],
                )
            }),
            signed: [UNSIGNED; L],
        });
        seeds.zeroize();
        let mut key = key?;
        for j in 0..L - 1 {
            key.sign_lower(rng, j)?;
        }
        Ok(key)
    }

    /// Tree `j` signs tree `j + 1`'s public key.
    fn sign_lower<R: Random>(
        &mut self,
        rng: &mut R,
        j: usize,
    ) -> Result<(), Error> {
        let lower = self.trees[j + 1].public_key().bytes();
        let lower = &lower[..self.trees[j + 1].public_key().len()];
        let signed = &mut self.signed[j].bytes;
        self.trees[j].sign_parts(rng, &[lower], signed)?;
        Ok(())
    }

    /// The public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            levels: L,
            top: self.trees[0].public_key().clone(),
        }
    }

    /// The sets of each level, top first.
    pub fn sets(&self) -> [(Lms, Lmots); L] {
        core::array::from_fn(|j| (self.trees[j].lms(), self.trees[j].lmots()))
    }

    /// The length of a signature, fixed by the sets.
    pub fn signature_len(&self) -> usize {
        let mut len = 4;
        for (j, tree) in self.trees.iter().enumerate() {
            len += tree.signature_len();
            if j > 0 {
                len += tree.public_key().len();
            }
        }
        len
    }

    /// How many signatures the key has left: the bottom tree's, then
    /// a whole fresh bottom tree for every leaf left above it, and so
    /// on up. Saturates at `u64::MAX`, which eight tall trees pass.
    pub fn remaining(&self) -> u64 {
        let mut total = 0u64;
        let mut below = 1u64;
        for tree in self.trees.iter().rev() {
            total =
                total.saturating_add(tree.remaining().saturating_mul(below));
            below = below.saturating_mul(tree.lms().leaves());
        }
        total
    }

    /// Signs `message` (RFC 8554 section 6.2), writing the signature
    /// into the front of `out` and returning its length, then
    /// advances the key. A spent lower tree is replaced first, which
    /// costs its key generation and a leaf of the tree above. `out`
    /// shorter than [`signature_len`](Self::signature_len) is
    /// [`Error::OutputTooSmall`], and a key with nothing left
    /// [`Error::SequenceExhausted`]; neither touches the key.
    pub fn sign<R: Random>(
        &mut self,
        rng: &mut R,
        message: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let len = self.signature_len();
        if out.len() < len {
            return Err(Error::OutputTooSmall(len));
        }
        if self.remaining() == 0 {
            return Err(Error::SequenceExhausted);
        }
        // The deepest level with a leaf left; everything below it is
        // spent and grows again from there.
        let mut d = L - 1;
        while self.trees[d].remaining() == 0 {
            d -= 1;
        }
        for j in d + 1..L {
            let (lms, ots) = (self.trees[j].lms(), self.trees[j].lmots());
            self.trees[j] = super::PrivateKey::generate(rng, lms, ots)?;
            self.sign_lower(rng, j - 1)?;
        }
        let out = &mut out[..len];
        out[..4].copy_from_slice(&((L - 1) as u32).to_be_bytes());
        let mut at = 4;
        for j in 0..L - 1 {
            let sig_len = self.trees[j].signature_len();
            out[at..at + sig_len]
                .copy_from_slice(&self.signed[j].bytes[..sig_len]);
            at += sig_len;
            let lower = self.trees[j + 1].public_key();
            let lower_len = lower.len();
            out[at..at + lower_len]
                .copy_from_slice(&lower.bytes()[..lower_len]);
            at += lower_len;
        }
        self.trees[L - 1].sign(rng, message, &mut out[at..])?;
        Ok(len)
    }

    /// A key from its DER PKCS#8 `PrivateKeyInfo`, the form under
    /// `PRIVATE KEY` in a PEM file, written as
    /// [`der_bytes`](Self::der_bytes) writes it. Another algorithm,
    /// or another number of levels than `L`, is
    /// [`Error::WrongAlgorithm`]; anything else wrong with the bytes
    /// [`Error::InvalidEncoding`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        let () = Self::LEVELS_OK;
        let info = crate::der::read_pkcs8(der)?;
        let algorithm = &info.algorithm;
        if algorithm.oid != OID || !algorithm.params.is_empty() {
            return Err(Error::WrongAlgorithm);
        }
        let mut inner = crate::der::Reader::new(info.private_key);
        let bytes = inner.octet_string()?;
        inner.end()?;
        if bytes.len() < 2 || bytes[0] != LAYOUT_VERSION {
            return Err(Error::InvalidEncoding);
        }
        if usize::from(bytes[1]) != L {
            return Err(Error::WrongAlgorithm);
        }
        let mut rest = &bytes[2..];
        let mut key = PrivateKey {
            trees: core::array::from_fn(|_| super::PrivateKey::blank()),
            signed: [UNSIGNED; L],
        };
        let mut family = None;
        for j in 0..L {
            let (tree, used) = super::PrivateKey::read(rest)?;
            rest = &rest[used..];
            let this = tree.lms().family();
            if *family.get_or_insert(this) != this {
                return Err(Error::InvalidEncoding);
            }
            if j < L - 1 {
                let len = tree.signature_len();
                if rest.len() < len {
                    return Err(Error::InvalidEncoding);
                }
                key.signed[j].bytes[..len].copy_from_slice(&rest[..len]);
                rest = &rest[len..];
            }
            key.trees[j] = tree;
        }
        if !rest.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        Ok(key)
    }

    /// Writes the key as a version 0 `PrivateKeyInfo` under
    /// id-alg-hss-lms-hashsig into the front of `out`, returning the
    /// length. A secret, to be wiped.
    ///
    /// No standard defines a private key encoding for HSS, so the
    /// privateKey OCTET STRING here holds the library's own layout,
    /// which carries the traversal state so that loading a key costs
    /// nothing: a version byte (1), the level count, then for each
    /// level from the top the LMS and LM-OTS typecodes as `u32str`,
    /// `I`, the seed, the next leaf `q` as `u32str`, the root, the
    /// BDS state, and for every level but the last the signature over
    /// the next level's public key.
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        crate::der::write_pkcs8(out, &OID, false, |w| {
            w.octet_string_of(|w| {
                w.raw(&[LAYOUT_VERSION, L as u8]);
                for (j, tree) in self.trees.iter().enumerate() {
                    tree.write(&mut |bytes| w.raw(bytes));
                    if j < L - 1 {
                        w.raw(&self.signed[j].bytes[..tree.signature_len()]);
                    }
                }
            })
        })
    }

    /// A key from a `PRIVATE KEY` PEM block (RFC 7468) around the DER
    /// above, read as [`PublicKey::try_from_pem`] reads its own.
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        let mut der = [0u8; der_max(LEVELS_MAX)];
        let labels = [PRIVATE_LABEL];
        let result = crate::codec::pem::decode_one_of(&labels, pem, &mut der)
            .and_then(|(_, n)| Self::try_from_der(&der[..n]));
        der.zeroize();
        result
    }

    /// Writes the key as a `PRIVATE KEY` PEM block, ASCII with LF line
    /// ends, into the front of `out`, returning the length. A secret,
    /// to be wiped.
    pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut der = [0u8; der_max(LEVELS_MAX)];
        let result = self.der_bytes(&mut der).and_then(|n| {
            crate::codec::pem::encode(PRIVATE_LABEL, &der[..n], out)
        });
        der.zeroize();
        result
    }
}

impl<const L: usize> core::fmt::Debug for PrivateKey<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("trees", &self.trees)
            .finish_non_exhaustive()
    }
}

/// The number of levels of the private key `der` encodes, for a
/// reader that must pick the type before decoding; the algorithm is
/// checked and nothing else.
pub fn levels(der: &[u8]) -> Result<usize, Error> {
    let info = crate::der::read_pkcs8(der)?;
    if info.algorithm.oid != OID || !info.algorithm.params.is_empty() {
        return Err(Error::WrongAlgorithm);
    }
    let mut inner = crate::der::Reader::new(info.private_key);
    let bytes = inner.octet_string()?;
    inner.end()?;
    match bytes {
        [LAYOUT_VERSION, levels, ..]
            if (1..=LEVELS_MAX as u8).contains(levels) =>
        {
            Ok(usize::from(*levels))
        }
        _ => Err(Error::InvalidEncoding),
    }
}

/// [`levels`] through a `PRIVATE KEY` PEM block.
pub fn levels_from_pem(pem: &[u8]) -> Result<usize, Error> {
    let mut der = [0u8; der_max(LEVELS_MAX)];
    let labels = [PRIVATE_LABEL];
    let result = crate::codec::pem::decode_one_of(&labels, pem, &mut der)
        .and_then(|(_, n)| levels(&der[..n]));
    der.zeroize();
    result
}
