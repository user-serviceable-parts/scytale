//! Arithmetic in the field of 2^448 - 2^224 - 1 elements.
//!
//! The field under Curve448, and so under X448 key agreement. Every
//! operation is a fixed sequence of limb arithmetic: no branch, index
//! or table lookup depends on a value, so a secret in the field stays
//! out of timing and the cache.
//!
//! The prime's shape is what makes the reduction cheap. With 2^448
//! congruent to 2^224 + 1, and 2^224 falling on a limb boundary, a
//! product limb past the top folds back onto two lower limbs as it
//! stands, with no multiplication by a constant.

use zeroize::Zeroize;

/// A 56-bit limb's worth of ones.
const MASK56: u64 = (1 << 56) - 1;

/// An element of the field, as eight limbs of 56 bits, least
/// significant first.
///
/// Every operation returns limbs below 2^56 + 2^9. The products
/// accept limbs to 2^57: a product of two is then below 2^114, eight
/// of those to a column and the folds of the high columns onto the
/// low leave every sum below 2^120, well inside a `u128`.
#[derive(Clone, Copy, Zeroize)]
pub(crate) struct Fe(pub(crate) [u64; 8]);

/// The prime, limb by limb: all ones, but for the 2^224 bit.
const P: [u64; 8] = [
    MASK56,
    MASK56,
    MASK56,
    MASK56,
    MASK56 - 1,
    MASK56,
    MASK56,
    MASK56,
];

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 8]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0]);

    /// Reads 56 little-endian bytes. Every value up to 2^448 - 1 is
    /// taken, as RFC 7748 asks, and reduced by the arithmetic that
    /// follows.
    pub(crate) fn from_bytes(bytes: &[u8; 56]) -> Fe {
        let mut limbs = [0u64; 8];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(7)) {
            let mut word = [0u8; 8];
            word[..7].copy_from_slice(chunk);
            *limb = u64::from_le_bytes(word);
        }
        Fe(limbs)
    }

    /// Writes the canonical form: fully reduced, little-endian.
    pub(crate) fn to_bytes(self) -> [u8; 56] {
        // Three passes bring every limb below 2^56 and the value
        // below 2^448: each leaves at most a carry of one into limbs
        // zero and four, and the third has none to leave.
        let mut t = self.0;
        for _ in 0..3 {
            t = Fe::carry(t).0;
        }
        // Below 2^448 but perhaps not below the prime: subtract it,
        // and keep the difference unless that borrowed.
        let mut diff = [0u64; 8];
        let mut borrow = 0u64;
        for i in 0..8 {
            let d = t[i].wrapping_sub(P[i]).wrapping_sub(borrow);
            borrow = d >> 63;
            diff[i] = d & MASK56;
        }
        let keep = borrow.wrapping_neg();
        for (t, d) in t.iter_mut().zip(diff) {
            *t = (*t & keep) | (d & !keep);
        }

        let mut out = [0u8; 56];
        for (chunk, limb) in out.chunks_exact_mut(7).zip(t) {
            chunk.copy_from_slice(&limb.to_le_bytes()[..7]);
        }
        t.zeroize();
        diff.zeroize();
        out
    }

    /// One carry pass, folding the carry out of the top limb onto
    /// limbs zero and four. Limbs come back below 2^56, but for those
    /// two, which may pass it by the carry.
    fn carry(mut t: [u64; 8]) -> Fe {
        for i in 0..7 {
            t[i + 1] += t[i] >> 56;
            t[i] &= MASK56;
        }
        let top = t[7] >> 56;
        t[7] &= MASK56;
        t[0] += top;
        t[4] += top;
        Fe(t)
    }

    /// `self + other`, carried, so that sums can be chained without
    /// tracking how far each limb has grown.
    pub(crate) fn add(&self, other: &Fe) -> Fe {
        let mut sum = [0u64; 8];
        for (s, (a, b)) in sum.iter_mut().zip(self.0.iter().zip(other.0)) {
            *s = a + b;
        }
        Fe::carry(sum)
    }

    /// `self - other`, computed as `self + 2p - other` so no limb
    /// underflows: twice the prime's limbs are 2^57 - 2 or 2^57 - 4,
    /// above any limb an operation here returns.
    pub(crate) fn sub(&self, other: &Fe) -> Fe {
        let mut diff = [0u64; 8];
        for i in 0..8 {
            diff[i] = self.0[i] + 2 * P[i] - other.0[i];
        }
        Fe::carry(diff)
    }

    /// `-self`, as `0 - self`.
    pub(crate) fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    pub(crate) fn mul(&self, other: &Fe) -> Fe {
        let (a, b) = (self.0, other.0);
        let mut t = [0u128; 15];
        for i in 0..8 {
            for j in 0..8 {
                t[i + j] += u128::from(a[i]) * u128::from(b[j]);
            }
        }
        Fe::reduce(t)
    }

    pub(crate) fn square(&self) -> Fe {
        let a = self.0;
        // Every cross term appears twice: 36 products do the work of
        // 64. The doubling goes on one factor, below 2^58.
        let mut t = [0u128; 15];
        for i in 0..8 {
            t[2 * i] += u128::from(a[i]) * u128::from(a[i]);
            let d = 2 * a[i];
            for j in i + 1..8 {
                t[i + j] += u128::from(d) * u128::from(a[j]);
            }
        }
        Fe::reduce(t)
    }

    /// Multiplication by a small constant, such as the curve
    /// coefficient 39081.
    pub(crate) fn mul_small(&self, n: u32) -> Fe {
        let mut t = [0u128; 15];
        for (t, limb) in t.iter_mut().zip(self.0) {
            *t = u128::from(limb) * u128::from(n);
        }
        Fe::reduce(t)
    }

    /// Reduces a product's fifteen columns to eight limbs.
    ///
    /// Column k at or past eight weighs 2^(56k) = 2^(56(k - 8)) *
    /// 2^448, which is congruent to 2^(56(k - 8)) + 2^(56(k - 4)):
    /// the column adds onto columns k - 8 and k - 4. Working from the
    /// top down, a column that lands at or past eight is folded again
    /// in its turn.
    fn reduce(mut t: [u128; 15]) -> Fe {
        for k in (8..15).rev() {
            let c = t[k];
            t[k - 4] += c;
            t[k - 8] += c;
        }
        let mask = u128::from(MASK56);
        for i in 0..7 {
            t[i + 1] += t[i] >> 56;
            t[i] &= mask;
        }
        let top = t[7] >> 56;
        t[7] &= mask;
        t[0] += top;
        t[4] += top;
        // The top carry is below 2^66, so one more step from each of
        // the two limbs it landed on brings them under 2^56 and the
        // limbs above them under 2^57.
        t[1] += t[0] >> 56;
        t[0] &= mask;
        t[5] += t[4] >> 56;
        t[4] &= mask;
        let mut limbs = [0u64; 8];
        for (limb, wide) in limbs.iter_mut().zip(t) {
            *limb = wide as u64;
        }
        t.zeroize();
        Fe(limbs)
    }

    /// `self` squared `k` times.
    fn pow2k(&self, k: u32) -> Fe {
        let mut x = *self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// The powers 2^222 - 1 and 2^223 - 1 of `self`, from which the
    /// inverse is built: its exponent is a run of ones with a short
    /// tail.
    fn pow_runs(&self) -> (Fe, Fe) {
        // Each name is the length of the run of one bits in the
        // exponent built so far.
        let x2 = self.square().mul(self);
        let x3 = x2.square().mul(self);
        let x6 = x3.pow2k(3).mul(&x3);
        let x12 = x6.pow2k(6).mul(&x6);
        let x24 = x12.pow2k(12).mul(&x12);
        let x48 = x24.pow2k(24).mul(&x24);
        let x96 = x48.pow2k(48).mul(&x48);
        let x192 = x96.pow2k(96).mul(&x96);
        let x216 = x192.pow2k(24).mul(&x24);
        let x222 = x216.pow2k(6).mul(&x6);
        let x223 = x222.square().mul(self);
        (x222, x223)
    }

    /// The multiplicative inverse, as the power p - 2. A fixed
    /// exponent, so a fixed sequence of operations, whatever the
    /// value.
    pub(crate) fn invert(&self) -> Fe {
        // p - 2 = (2^223 - 1) 2^225 + (2^222 - 1) 4 + 1.
        let (x222, x223) = self.pow_runs();
        x223.pow2k(225).mul(&x222.pow2k(2)).mul(self)
    }

    /// The power (p - 3) / 4 = (2^223 - 1) 2^223 + (2^222 - 1), from
    /// which square roots are built: p is 3 mod 4, so for a square
    /// `a`, `a^((p + 1) / 4)` is a root, and this is that power over
    /// `a`, which lets a root of a quotient be taken in one pass.
    pub(crate) fn pow_p34(&self) -> Fe {
        let (x222, x223) = self.pow_runs();
        x223.pow2k(223).mul(&x222)
    }

    /// Whether the canonical form is odd, which RFC 8032 uses as the
    /// sign of a coordinate.
    pub(crate) fn is_negative(&self) -> u8 {
        self.to_bytes()[0] & 1
    }

    /// Equality on values, not on representations.
    pub(crate) fn equals(&self, other: &Fe) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    /// Replaces `self` with `other` when `condition` is one, with a
    /// mask rather than a branch.
    pub(crate) fn cmov(&mut self, other: &Fe, condition: u64) {
        debug_assert!(condition <= 1);
        let mask = condition.wrapping_neg();
        for (a, b) in self.0.iter_mut().zip(other.0) {
            *a ^= (*a ^ b) & mask;
        }
    }

    /// Exchanges `a` and `b` when `condition` is one, by arithmetic
    /// on a mask rather than a branch.
    pub(crate) fn cswap(condition: u64, a: &mut Fe, b: &mut Fe) {
        debug_assert!(condition <= 1);
        let mask = condition.wrapping_neg();
        for (a, b) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let x = (*a ^ *b) & mask;
            *a ^= x;
            *b ^= x;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prime's encoding: all ones but bit 224.
    fn prime_bytes() -> [u8; 56] {
        let mut p = [0xffu8; 56];
        p[28] = 0xfe;
        p
    }

    fn equals(a: &Fe, b: &Fe) -> bool {
        a.to_bytes() == b.to_bytes()
    }

    #[test]
    fn round_trips_and_reduces() {
        // p reads back as zero.
        let p = prime_bytes();
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0u8; 56]);
        // p + 1 = 2^448 - 2^224, all ones from bit 224 up, as one.
        let mut p1 = [0u8; 56];
        p1[28..].fill(0xff);
        assert_eq!(Fe::from_bytes(&p1).to_bytes(), Fe::ONE.to_bytes());
        // 2^448 - 1, the most 56 bytes hold, is p + 2^224.
        let mut top = [0u8; 56];
        top[28] = 1;
        assert_eq!(Fe::from_bytes(&[0xff; 56]).to_bytes(), top);
        // A value below p comes back as it went in.
        let mut x = [0u8; 56];
        for (i, b) in x.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(Fe::from_bytes(&x).to_bytes(), x);
    }

    /// The squaring agrees with the product of an element with
    /// itself, on reduced elements and on limbs at the bound the type
    /// allows.
    #[test]
    fn square_is_mul_by_self() {
        let mut x = Fe::from_bytes(&[0x5a; 56]);
        let y = Fe::from_bytes(&[0xc3; 56]);
        for _ in 0..50 {
            assert_eq!(x.square().to_bytes(), x.mul(&x).to_bytes());
            x = x.mul(&y).add(&Fe::ONE);
        }
        let grown = Fe([(1 << 57) - 1; 8]);
        assert_eq!(grown.square().to_bytes(), grown.mul(&grown).to_bytes());
        // And the product at that bound against one computed from
        // the reduced form, so the folds are checked, not only
        // compared with themselves.
        let reduced = Fe::from_bytes(&grown.to_bytes());
        assert!(equals(&grown.mul(&y), &reduced.mul(&y)));
    }

    /// Multiplication distributes over addition, which a slip in the
    /// fold of one column would break.
    #[test]
    fn mul_distributes() {
        let a = Fe::from_bytes(&[0x17; 56]);
        let b = Fe::from_bytes(&[0xe9; 56]);
        let c = Fe::from_bytes(&prime_bytes()).sub(&Fe::from_bytes(&[3; 56]));
        assert!(equals(&a.mul(&b.add(&c)), &a.mul(&b).add(&a.mul(&c))));
        assert!(equals(
            &a.mul_small(39081),
            &a.mul(&Fe([39081, 0, 0, 0, 0, 0, 0, 0]))
        ));
    }

    #[test]
    fn inverse_multiplies_to_one() {
        for seed in [1u8, 7, 0xfe] {
            let x = Fe::from_bytes(&[seed; 56]);
            assert!(equals(&x.mul(&x.invert()), &Fe::ONE));
        }
        // -1 is its own inverse.
        let m1 = Fe::ZERO.sub(&Fe::ONE);
        assert!(equals(&m1.invert(), &m1));
    }

    #[test]
    fn subtraction_wraps() {
        let x = Fe::from_bytes(&[42u8; 56]);
        assert_eq!(x.add(&Fe::ZERO.sub(&x)).to_bytes(), [0u8; 56]);
        assert_eq!(Fe::ZERO.sub(&Fe::ZERO).to_bytes(), [0u8; 56]);
        // -1 is p - 1.
        let mut pm1 = prime_bytes();
        pm1[0] = 0xfe;
        assert_eq!(Fe::ZERO.sub(&Fe::ONE).to_bytes(), pm1);
    }

    /// The power (p - 3) / 4 gives square roots: for a square `a`,
    /// `a * a^((p - 3) / 4)` squares back to `a`.
    #[test]
    fn pow_p34_gives_roots() {
        for seed in [3u8, 0x5c, 0xe1] {
            let r = Fe::from_bytes(&[seed; 56]);
            let a = r.square();
            let root = a.mul(&a.pow_p34());
            assert!(root.square().equals(&a));
            assert!(root.equals(&r) || root.equals(&r.neg()));
        }
        // -1 is not a square, p being 3 mod 4, and the root test
        // says so.
        let m1 = Fe::ONE.neg();
        assert!(!m1.mul(&m1.pow_p34()).square().equals(&m1));
    }

    #[test]
    fn negation_and_sign() {
        let x = Fe::from_bytes(&[42u8; 56]);
        assert_eq!(x.add(&x.neg()).to_bytes(), [0u8; 56]);
        assert_eq!(x.is_negative() ^ x.neg().is_negative(), 1);
        assert_eq!(Fe::ZERO.neg().is_negative(), 0);
    }

    #[test]
    fn cmov_moves_only_on_one() {
        let a = Fe::from_bytes(&[1u8; 56]);
        let b = Fe::from_bytes(&[2u8; 56]);
        let mut x = a;
        x.cmov(&b, 0);
        assert!(x.equals(&a));
        x.cmov(&b, 1);
        assert!(x.equals(&b));
    }

    #[test]
    fn cswap_swaps_only_on_one() {
        let a = Fe::from_bytes(&[1u8; 56]);
        let b = Fe::from_bytes(&[2u8; 56]);
        let (mut x, mut y) = (a, b);
        Fe::cswap(0, &mut x, &mut y);
        assert!(equals(&x, &a) && equals(&y, &b));
        Fe::cswap(1, &mut x, &mut y);
        assert!(equals(&x, &b) && equals(&y, &a));
    }
}
