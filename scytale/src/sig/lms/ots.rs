//! LM-OTS, the one-time signature under each leaf (RFC 8554 section
//! 4).
//!
//! A one-time key is `p` chains of `2^w - 1` hashes each. The message
//! digest and its checksum are read as `p` digits of `w` bits, and the
//! signature is each chain advanced by its digit; the verifier runs
//! every chain to its end and hashes the ends together, which gives
//! the public key only if every digit was honest, the checksum
//! stopping anyone from moving a digit up.

use zeroize::Zeroize;

use super::{Hasher, I_SIZE, Lmots, N_MAX, Node};

/// Ends the hash that makes a public key from the chain ends.
const D_PBLC: [u8; 2] = [0x80, 0x80];
/// Ends the hash that makes the digest a signature is over.
const D_MESG: [u8; 2] = [0x81, 0x81];
/// Marks the hash that derives a chain's start from the seed
/// (appendix A).
const D_PRIVATE: u8 = 0xff;

/// The most digits a set has, with room for `Q || Cksm(Q)`.
const DIGEST_MAX: usize = N_MAX + 2;

/// `coef(S, i, w)`: the `i`-th `w`-bit digit of `S`, most significant
/// bits first.
fn coef(s: &[u8], i: usize, w: u32) -> u32 {
    let w = w as usize;
    let byte = s[i * w / 8];
    let shift = 8 - w - (i * w) % 8;
    (u32::from(byte) >> shift) & ((1 << w) - 1)
}

/// `Cksm(Q)` (algorithm 2), shifted into the digits the signature
/// uses.
fn checksum(ots: Lmots, q: &[u8]) -> u16 {
    let (n, w) = (ots.n(), ots.w());
    let top = (1 << w) - 1;
    let mut sum = 0u32;
    for i in 0..n * 8 / w as usize {
        sum += top - coef(q, i, w);
    }
    (sum << ots.ls()) as u16
}

/// One leaf's one-time key: the set, the hash, and the identifiers
/// `I` and `q` that every hash of it starts with.
pub(super) struct Ots<'a> {
    ots: Lmots,
    hasher: &'a mut Hasher,
    i: &'a [u8; I_SIZE],
    q: u32,
}

impl<'a> Ots<'a> {
    pub(super) fn new(
        ots: Lmots,
        hasher: &'a mut Hasher,
        i: &'a [u8; I_SIZE],
        q: u32,
    ) -> Self {
        Ots { ots, hasher, i, q }
    }

    /// Runs chain `chain` from `tmp` for the steps `from..to`.
    fn advance(&mut self, chain: usize, from: u32, to: u32, tmp: &mut Node) {
        let n = self.ots.n();
        let chain = (chain as u16).to_be_bytes();
        let q = self.q.to_be_bytes();
        for j in from..to {
            self.hasher.update(self.i);
            self.hasher.update(&q);
            self.hasher.update(&chain);
            self.hasher.update(&[j as u8]);
            self.hasher.update(&tmp[..n]);
            *tmp = self.hasher.finish();
        }
    }

    /// `x_q[chain]`, the start of a chain (appendix A).
    fn element(&mut self, chain: usize, seed: &Node) -> Node {
        self.hasher.digest(&[
            self.i,
            &self.q.to_be_bytes(),
            &(chain as u16).to_be_bytes(),
            &[D_PRIVATE],
            &seed[..self.ots.n()],
        ])
    }

    /// A hash begun as `K` is, over `I || u32str(q) || D_PBLC`, for
    /// the chain ends to follow.
    fn ends(&self) -> Hasher {
        let mut ends = Hasher::new(self.ots.family());
        ends.update(self.i);
        ends.update(&self.q.to_be_bytes());
        ends.update(&D_PBLC);
        ends
    }

    /// `Q || Cksm(Q)`: the digest of `message` under `C`, and its
    /// checksum, as the `p` digits are read from it.
    fn digits(&mut self, c: &[u8], message: &[&[u8]]) -> [u8; DIGEST_MAX] {
        let n = self.ots.n();
        self.hasher.update(self.i);
        self.hasher.update(&self.q.to_be_bytes());
        self.hasher.update(&D_MESG);
        self.hasher.update(c);
        for part in message {
            self.hasher.update(part);
        }
        let digest = self.hasher.finish();
        let mut out = [0u8; DIGEST_MAX];
        out[..n].copy_from_slice(&digest[..n]);
        let cksm = checksum(self.ots, &digest[..n]);
        out[n..n + 2].copy_from_slice(&cksm.to_be_bytes());
        out
    }

    /// The public key `K` (algorithm 1): every chain run to its end,
    /// the ends hashed together.
    pub(super) fn public_key(&mut self, seed: &Node) -> Node {
        let (n, w) = (self.ots.n(), self.ots.w());
        let mut ends = self.ends();
        for chain in 0..self.ots.p() {
            let mut tmp = self.element(chain, seed);
            self.advance(chain, 0, (1 << w) - 1, &mut tmp);
            ends.update(&tmp[..n]);
        }
        ends.finish()
    }

    /// Signs `message` (algorithm 3), writing `u32str(type) || C ||
    /// y[0] || ... || y[p-1]` into `out`, which is exactly
    /// [`Lmots::signature_len`] long.
    pub(super) fn sign(
        &mut self,
        seed: &Node,
        c: &Node,
        message: &[&[u8]],
        out: &mut [u8],
    ) {
        let (n, w) = (self.ots.n(), self.ots.w());
        debug_assert_eq!(out.len(), self.ots.signature_len());
        out[..4].copy_from_slice(&self.ots.typecode().to_be_bytes());
        out[4..4 + n].copy_from_slice(&c[..n]);
        let digits = self.digits(&c[..n], message);
        for (chain, y) in out[4 + n..].chunks_exact_mut(n).enumerate() {
            let a = coef(&digits, chain, w);
            let mut tmp = self.element(chain, seed);
            self.advance(chain, 0, a, &mut tmp);
            y.copy_from_slice(&tmp[..n]);
            tmp.zeroize();
        }
    }

    /// The public key `signature` would be a signature of `message`
    /// under (algorithm 4b). `signature` is exactly
    /// [`Lmots::signature_len`] long, its typecode already checked.
    pub(super) fn candidate(
        &mut self,
        signature: &[u8],
        message: &[&[u8]],
    ) -> Node {
        let (n, w) = (self.ots.n(), self.ots.w());
        debug_assert_eq!(signature.len(), self.ots.signature_len());
        let c = &signature[4..4 + n];
        let digits = self.digits(c, message);
        let mut ends = self.ends();
        for (chain, y) in signature[4 + n..].chunks_exact(n).enumerate() {
            let a = coef(&digits, chain, w);
            let mut tmp = [0u8; N_MAX];
            tmp[..n].copy_from_slice(y);
            self.advance(chain, a, (1 << w) - 1, &mut tmp);
            ends.update(&tmp[..n]);
        }
        ends.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coef_reads_digits_most_significant_first() {
        let s = [0x12u8, 0x34];
        assert_eq!(coef(&s, 0, 4), 1);
        assert_eq!(coef(&s, 1, 4), 2);
        assert_eq!(coef(&s, 3, 4), 4);
        assert_eq!(coef(&s, 0, 8), 0x12);
        assert_eq!(coef(&s, 3, 1), 1);
        assert_eq!(coef(&s, 4, 2), 0);
        assert_eq!(coef(&s, 5, 2), 3);
        assert_eq!(coef(&s, 6, 2), 1);
        assert_eq!(coef(&s, 7, 2), 0);
    }

    /// Appendix B's derivation of `p` and `ls` against the tables.
    #[test]
    fn p_and_ls_follow_appendix_b() {
        for ots in Lmots::ALL {
            let (n, w) = (ots.n() as u32, ots.w());
            let u = (8 * n).div_ceil(w);
            let v = (((1 << w) - 1) * u).ilog2() + 1;
            let v = v.div_ceil(w);
            assert_eq!(ots.p() as u32, u + v, "{ots:?}");
            assert_eq!(ots.ls(), 16 - v * w, "{ots:?}");
        }
    }

    #[test]
    fn checksum_of_all_top_digits_is_zero() {
        let q = [0xffu8; 32];
        for ots in Lmots::ALL {
            assert_eq!(checksum(ots, &q[..ots.n()]), 0);
        }
        // All-zero digits: every digit contributes 2^w - 1.
        let q = [0u8; 32];
        let ots = Lmots::Sha256N32W8;
        assert_eq!(checksum(ots, &q), 32 * 255);
        let ots = Lmots::Sha256N32W1;
        assert_eq!(checksum(ots, &q), 256 << 7);
    }
}
