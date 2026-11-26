//! Poly1305 (RFC 8439 section 2.5): a one-time authenticator.
//!
//! The message is read as coefficients of a polynomial, evaluated
//! at a secret point `r` modulo the prime `2^130 - 5`, and the
//! result is masked with a second secret `s`. The bound on forgery
//! is information-theoretic: it does not rest on any problem being
//! hard, only on `r` and `s` being uniform and unknown.
//!
//! # One key, one message
//!
//! That bound holds for a single message. Two tags under the same
//! key give away `r` through a little algebra, and every later tag
//! can then be forged. So a Poly1305 key is never reused, which is
//! why it is nearly always derived afresh per message from a stream
//! cipher, as ChaCha20-Poly1305 does; reach it that way unless a
//! protocol says otherwise. [`reset`](Mac::reset) exists for that
//! caller, not for a second message, and neither does the keyed
//! state that [`finalize`](Mac::finalize) leaves behind: a second
//! message under the same key is a misuse the type does not prevent.
//!
//! # Constant time
//!
//! The arithmetic is plain multiplication and addition on limbs,
//! with no branch or table lookup that depends on the key or the
//! message; the final reduction chooses with a mask.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Mac;
use crate::features::{self, Dispatcher, Features};
use crate::{Context, Key, KeyType};

/// The key length in bytes: `r` then `s`.
pub const KEY_SIZE: usize = 32;

/// The block, and tag, length in bytes.
const BLOCK: usize = 16;

/// The most a message can leave waiting between calls: one group of
/// the vector loop, which takes nothing smaller.
const BUFFER: usize = 4 * BLOCK;

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

/// A 44-bit limb's worth of ones.
const MASK44: u64 = (1 << 44) - 1;

/// A 42-bit limb's worth: the top limb holds 130 - 88 bits.
const MASK42: u64 = (1 << 42) - 1;

/// Poly1305 under a one-time key.
///
/// The accumulator and `r` are kept as three limbs of 44, 44 and 42
/// bits, so that a product of two fits a 128-bit word with room for
/// the sums of three, and reduction modulo `2^130 - 5` is a
/// multiplication by five folded into the limb arithmetic.
pub struct Poly1305 {
    /// `r`, clamped as the standard requires.
    r: [u64; 3],
    /// `r[1]` and `r[2]` times twenty: `2^132 = 4 * 2^130 = 20`
    /// modulo the prime, which is what a limb carried past the top
    /// is worth.
    r20: [u64; 2],
    /// `s`, as the two little-endian words it is added as.
    s: [u64; 2],
    /// The running polynomial value.
    h: [u64; 3],
    /// Bytes waiting for the rest of their block, or of their group
    /// when the vector loop is taking the message.
    buffer: [u8; BUFFER],
    used: usize,
    /// How far into `buffer` this message has written: what a reset
    /// has to wipe. A message whose pieces are whole groups writes
    /// none of it, and a wipe of all of it, a byte at a time, cost
    /// more than one of those groups takes.
    dirty: usize,
    /// The vector loop, where the list chose it when this was built:
    /// settled once, here, rather than on the way past for every run
    /// of blocks.
    #[cfg(target_arch = "x86_64")]
    fast: Option<x86_64::Avx2>,
    /// The powers of `r` that loop wants, worked out the first time a
    /// run long enough to use them arrives. A short message never
    /// pays for them.
    #[cfg(target_arch = "x86_64")]
    powers: Option<x86_64::Powers>,
    /// The vector loop's four chains, from its first group until the
    /// message ends, when they become `h`. Until then nothing else
    /// touches `h`: every block goes through them, the last ones
    /// waiting in `buffer`.
    #[cfg(target_arch = "x86_64")]
    lanes: x86_64::Lanes,
}

impl Poly1305 {
    /// Starts an authenticator under `key`: `r` then `s`.
    ///
    /// The key is for this message and no other; see the warnings
    /// above.
    // Only x86-64 has a kernel to choose.
    #[cfg_attr(not(target_arch = "x86_64"), allow(unused_variables))]
    pub fn new(ctx: Context, key: &Key<[u8; KEY_SIZE]>) -> Self {
        let key = key.array();
        let word = |at: usize| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&key[at..at + 8]);
            u64::from_le_bytes(bytes)
        };
        // Clamping clears the top four bits of every four-byte word
        // of `r` and the low two bits of all but the first, so that
        // the limb products cannot carry too far.
        let t0 = word(0) & 0x0ffffffc0fffffff;
        let t1 = word(8) & 0x0ffffffc0ffffffc;
        let r = [
            t0 & MASK44,
            ((t0 >> 44) | (t1 << 20)) & MASK44,
            (t1 >> 24) & MASK42,
        ];
        Poly1305 {
            r,
            r20: [r[1] * 20, r[2] * 20],
            s: [word(16), word(24)],
            h: [0; 3],
            buffer: [0; BUFFER],
            used: 0,
            dirty: 0,
            #[cfg(target_arch = "x86_64")]
            fast: features::choose(ctx, KERNELS).and_then(x86_64::Avx2::of),
            #[cfg(target_arch = "x86_64")]
            powers: None,
            #[cfg(target_arch = "x86_64")]
            lanes: x86_64::Lanes::new(),
        }
    }

    /// What `update` hands on at once: a group for the vector loop,
    /// a block for the chain.
    fn unit(&self) -> usize {
        #[cfg(target_arch = "x86_64")]
        if self.fast.is_some() {
            return x86_64::SPAN;
        }
        BLOCK
    }

    /// Takes `data`, a whole number of units, into the message.
    fn run(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // The powers of `r` are left until a group arrives, and are
        // borrowed where they lie, field by field, so that no copy of
        // them is made for the `Drop` to miss.
        #[cfg(target_arch = "x86_64")]
        if let Some(avx2) = self.fast {
            let r = &self.r;
            let powers =
                self.powers.get_or_insert_with(|| x86_64::Powers::new(r));
            x86_64::bulk(avx2, &mut self.lanes, powers, data);
            return;
        }
        let (blocks, _) = data.as_chunks::<BLOCK>();
        for block in blocks {
            self.absorb(block, 1);
        }
    }

    /// Adds one block, with `high` as the bit above its top byte,
    /// and multiplies by `r`.
    ///
    /// The bit is `2^128` for a whole block. A final short block has
    /// its one written as a byte in the buffer instead, and passes
    /// zero here.
    fn absorb(&mut self, block: &[u8; BLOCK], high: u64) {
        Self::chain(&mut self.h, &self.r, &self.r20, block, high);
    }

    /// `absorb` on the fields it uses, so that a block can be read
    /// where it lies in the buffer rather than copied out of it first.
    fn chain(
        h: &mut [u64; 3],
        r: &[u64; 3],
        r20: &[u64; 2],
        block: &[u8; BLOCK],
        high: u64,
    ) {
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&block[..8]);
        hi.copy_from_slice(&block[8..]);
        let t0 = u64::from_le_bytes(lo);
        let t1 = u64::from_le_bytes(hi);
        let [mut h0, mut h1, mut h2] = *h;
        h0 += t0 & MASK44;
        h1 += ((t0 >> 44) | (t1 << 20)) & MASK44;
        h2 += ((t1 >> 24) & MASK42) | (high << 40);

        let [r0, r1, r2] = *r;
        let [s1, s2] = *r20;
        let wide = |a: u64, b: u64| u128::from(a) * u128::from(b);
        // Schoolbook product, with the limbs that pass 2^132 wrapped
        // round through the twenty-fold values.
        let d0 = wide(h0, r0) + wide(h1, s2) + wide(h2, s1);
        let d1 = wide(h0, r1) + wide(h1, r0) + wide(h2, s2);
        let d2 = wide(h0, r2) + wide(h1, r1) + wide(h2, r0);

        // Partial carry: enough to keep every limb small for the
        // next block, without a full reduction.
        let c = (d0 >> 44) as u64;
        h0 = (d0 as u64) & MASK44;
        let d1 = d1 + u128::from(c);
        let c = (d1 >> 44) as u64;
        h1 = (d1 as u64) & MASK44;
        let d2 = d2 + u128::from(c);
        let c = (d2 >> 42) as u64;
        h2 = (d2 as u64) & MASK42;
        h0 += c * 5;
        let c = h0 >> 44;
        h0 &= MASK44;
        h1 += c;
        *h = [h0, h1, h2];
    }

    /// Fully reduces the accumulator, adds `s`, and returns the tag.
    fn tag(&self) -> [u8; BLOCK] {
        let [mut h0, mut h1, mut h2] = self.h;
        // Carry through twice, so that only the top limb can be at
        // most one above the prime.
        for _ in 0..2 {
            let c = h1 >> 44;
            h1 &= MASK44;
            h2 += c;
            let c = h2 >> 42;
            h2 &= MASK42;
            h0 += c * 5;
            let c = h0 >> 44;
            h0 &= MASK44;
            h1 += c;
        }

        // Compute h - p and keep it if there was no borrow, choosing
        // with a mask rather than a branch.
        let mut g0 = h0 + 5;
        let c = g0 >> 44;
        g0 &= MASK44;
        let mut g1 = h1 + c;
        let c = g1 >> 44;
        g1 &= MASK44;
        let g2 = h2.wrapping_add(c).wrapping_sub(1 << 42);
        let keep = (g2 >> 63).wrapping_sub(1);
        h0 = (h0 & !keep) | (g0 & keep);
        h1 = (h1 & !keep) | (g1 & keep);
        h2 = (h2 & !keep) | (g2 & keep);

        // The low 128 bits as two words, plus s, dropping the carry.
        let lo = h0 | (h1 << 44);
        let hi = (h1 >> 20) | (h2 << 24);
        let (lo, carry) = lo.overflowing_add(self.s[0]);
        let hi = hi.wrapping_add(self.s[1]).wrapping_add(u64::from(carry));
        let mut tag = [0u8; BLOCK];
        tag[..8].copy_from_slice(&lo.to_le_bytes());
        tag[8..].copy_from_slice(&hi.to_le_bytes());
        tag
    }
}

/// Which loop the bulk of a message runs through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    /// Four blocks at once in the vector registers.
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// Plain Rust, a block at a time, on any processor.
    Portable,
}

features::kernels! {
    enum Kernel;

    /// The kernels, best first: AVX2, with the operating system
    /// keeping the wider registers (AVX), then the chain a block at a
    /// time.
    pub(crate) const KERNELS for poly1305 tested by tests::kernel = [
        #[cfg(target_arch = "x86_64")]
        Avx2 => (x86_64: Avx, Avx2),
        Portable => (),
    ];
}

/// What the type publishes: the rows' needs.
pub(crate) const PROFILES: [Features; KERNELS.len()] =
    features::profiles_of(KERNELS);

impl Poly1305 {
    /// The feature profiles this authenticator tells apart, best
    /// first; see [`Dispatcher`].
    pub fn profiles() -> &'static [Features] {
        &PROFILES
    }
}

impl features::sealed::Sealed for Poly1305 {}

impl Dispatcher for Poly1305 {
    fn profiles() -> &'static [Features] {
        Poly1305::profiles()
    }
}

impl KeyType for Poly1305 {
    type Key = Key<[u8; KEY_SIZE]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

impl Mac for Poly1305 {
    type Tag = [u8; BLOCK];

    fn new(ctx: Context, key: &Self::Key) -> Self {
        Poly1305::new(ctx, key)
    }

    fn reset(&mut self) {
        self.h = [0; 3];
        self.buffer[..self.dirty].zeroize();
        self.used = 0;
        self.dirty = 0;
        #[cfg(target_arch = "x86_64")]
        self.lanes.clear();
    }

    fn update(&mut self, mut data: &[u8]) {
        let unit = self.unit();
        if self.used > 0 {
            let take = (unit - self.used).min(data.len());
            self.buffer[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            self.dirty = self.dirty.max(self.used);
            data = &data[take..];
            if self.used < unit {
                return;
            }
            let buffer = self.buffer;
            self.run(&buffer[..unit]);
            self.used = 0;
        }
        let (whole, rest) = data.split_at(data.len() - data.len() % unit);
        self.run(whole);
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
        self.dirty = self.dirty.max(self.used);
    }

    fn finalize(&mut self) -> Self::Tag {
        // A message shorter than a group never started the chains,
        // and is the chain's alone.
        #[cfg(target_arch = "x86_64")]
        if self.lanes.started()
            && let Some(powers) = &self.powers
        {
            self.h = x86_64::collapse(&self.lanes, powers);
        }
        let (blocks, rest) = self.buffer[..self.used].as_chunks::<BLOCK>();
        for block in blocks {
            Self::chain(&mut self.h, &self.r, &self.r20, block, 1);
        }
        if !rest.is_empty() {
            // The one that marks the end goes just past the message;
            // the standard's 2^128 for a whole block is the same rule.
            let mut block = [0u8; BLOCK];
            block[..rest.len()].copy_from_slice(rest);
            block[rest.len()] = 1;
            self.absorb(&block, 0);
        }
        let tag = self.tag();
        self.reset();
        tag
    }
}

impl Clone for Poly1305 {
    fn clone(&self) -> Self {
        Poly1305 {
            r: self.r,
            r20: self.r20,
            s: self.s,
            h: self.h,
            buffer: self.buffer,
            used: self.used,
            dirty: self.dirty,
            #[cfg(target_arch = "x86_64")]
            fast: self.fast,
            #[cfg(target_arch = "x86_64")]
            powers: self.powers.clone(),
            #[cfg(target_arch = "x86_64")]
            lanes: self.lanes.clone(),
        }
    }
}

impl Drop for Poly1305 {
    /// Every field is the key, or a function of it and the message.
    fn drop(&mut self) {
        self.r.zeroize();
        self.r20.zeroize();
        self.s.zeroize();
        self.h.zeroize();
        self.buffer.zeroize();
        self.used.zeroize();
    }
}

impl ZeroizeOnDrop for Poly1305 {}

impl fmt::Debug for Poly1305 {
    /// Deliberately omits everything but how far the message has got.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Poly1305")
            .field("buffered", &self.used)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::Error;

    /// Decodes hex into a fixed buffer, returning the used prefix.
    fn hex(s: &str) -> ([u8; 512], usize) {
        let mut out = [0u8; 512];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        (out, s.len() / 2)
    }

    /// The tag under the kernel this processor dispatches to.
    fn plain_tag(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        let mut mac =
            Poly1305::new(crate::Context::default(), &Key::from(*key));
        mac.update(message);
        mac.finalize()
    }

    fn tag_of(
        under: &features::Under,
        key: &[u8; 32],
        message: &[u8],
    ) -> [u8; 16] {
        let mut mac = { Poly1305::new(under.ctx(), &Key::from(*key)) };
        mac.update(message);
        mac.finalize()
    }

    fn check(
        under: &features::Under,
        key: &str,
        message: &[u8],
        expected: &str,
    ) {
        let (k, _) = hex(key);
        let (t, _) = hex(expected);
        assert_eq!(
            tag_of(under, k[..32].try_into().unwrap(), message),
            t[..16]
        );
    }

    /// Poly1305 under one kernel, built through the public type: the
    /// RFC 8439 examples, and the vector loop against the chain a
    /// block at a time.
    pub(crate) fn kernel(under: &features::Under) {
        rfc8439_example(under);
        rfc8439_a3_ordinary(under);
        rfc8439_a3_edge_cases(under);
        four_at_once_agrees_with_one(under);
    }

    /// RFC 8439 section 2.5.2.
    /// The loop that takes four blocks at once must agree with the
    /// chain taken a block at a time, at every length around its group
    /// boundary and with the pieces landing anywhere.
    ///
    /// On a processor without the instructions both sides of this are
    /// the same code, and the test still says the lengths are right.
    fn four_at_once_agrees_with_one(under: &features::Under) {
        const MAX: usize = 17 * BLOCK + 7;
        let mut data = [0u8; MAX];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        agrees(under, &[0x2bu8; KEY_SIZE], &data);
        // Every bit set, in the key and the message: the limbs as
        // large as they come, which is what the bounds in the vector
        // code are about.
        agrees(under, &[0xffu8; KEY_SIZE], &[0xffu8; MAX]);
    }

    fn agrees(under: &features::Under, key: &[u8; KEY_SIZE], data: &[u8]) {
        let key = *key;
        for len in 0..data.len() {
            let want = one_at_a_time(under, &key, &data[..len]);

            let mut p = { Poly1305::new(under.ctx(), &Key::from(key)) };
            p.update(&data[..len]);
            assert_eq!(p.finalize(), want, "{len} bytes");

            // Pieces, so a run starts and ends part way along and the
            // part block is carried between calls.
            for piece in [1, 16, 17, 64, 65] {
                let mut p = { Poly1305::new(under.ctx(), &Key::from(key)) };
                for part in data[..len].chunks(piece) {
                    p.update(part);
                }
                assert_eq!(p.finalize(), want, "{len} bytes in {piece}");
            }
        }
    }

    /// The tag with every block put through the chain on its own,
    /// which no bulk path touches.
    fn one_at_a_time(
        under: &features::Under,
        key: &[u8; KEY_SIZE],
        message: &[u8],
    ) -> [u8; BLOCK] {
        let mut p = { Poly1305::new(under.ctx(), &Key::from(*key)) };
        let (blocks, rest) = message.as_chunks::<BLOCK>();
        for block in blocks {
            p.absorb(block, 1);
        }
        if !rest.is_empty() {
            let mut block = [0u8; BLOCK];
            block[..rest.len()].copy_from_slice(rest);
            block[rest.len()] = 1;
            p.absorb(&block, 0);
        }
        p.tag()
    }

    fn rfc8439_example(under: &features::Under) {
        check(
            under,
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f5\
             1b",
            b"Cryptographic Forum Research Group",
            "a8061dc1305136c6c22b8baf0c0127a9",
        );
    }

    /// The text of RFC 8439 appendix A.3, tests 2 and 3.
    const IETF: &str = "\
         416e79207375626d697373696f6e20746f20746865204945544620696e74656e\
         6465642062792074686520436f6e7472696275746f7220666f72207075626c69\
         636174696f6e20617320616c6c206f722070617274206f6620616e2049455446\
         20496e7465726e65742d4472616674206f722052464320616e6420616e792073\
         746174656d656e74206d6164652077697468696e2074686520636f6e74657874\
         206f6620616e204945544620616374697669747920697320636f6e7369646572\
         656420616e20224945544620436f6e747269627574696f6e222e205375636820\
         73746174656d656e747320696e636c756465206f72616c2073746174656d656e\
         747320696e20494554462073657373696f6e732c2061732077656c6c20617320\
         7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361\
         74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c\
         207768696368206172652061646472657373656420746f";

    /// A 32-byte key from `r` and `s` given as 16-byte arrays.
    fn key(r: [u8; 16], s: [u8; 16]) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&r);
        key[16..].copy_from_slice(&s);
        key
    }

    /// Sixteen bytes: `first`, then `rest` repeated.
    fn block(first: u8, rest: u8) -> [u8; 16] {
        let mut b = [rest; 16];
        b[0] = first;
        b
    }

    /// RFC 8439 appendix A.3, tests 1 to 4.
    fn rfc8439_a3_ordinary(under: &features::Under) {
        assert_eq!(tag_of(under, &[0u8; 32], &[0u8; 64]), [0u8; 16]);
        let (text, n) = hex(IETF);
        let text = &text[..n];
        assert_eq!(n, 375);
        let (s, _) = hex("36e5f6b5c5e06070f0efca96227a863e");
        let s: [u8; 16] = s[..16].try_into().unwrap();
        // r = 0: the tag is s, whatever the message.
        assert_eq!(tag_of(under, &key([0; 16], s), text), s);
        // s = 0.
        let (expected, _) = hex("f3477e7cd95417af89a6b8794c310cf0");
        assert_eq!(tag_of(under, &key(s, [0; 16]), text), expected[..16]);
        check(
            under,
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075\
             c0",
            b"'Twas brillig, and the slithy toves\nDid gyre and gimble in \
              the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths \
              outgrabe.",
            "4541669a7eaaee61e708dc7cbcc5eb62",
        );
    }

    /// RFC 8439 appendix A.3, tests 5 to 11: values chosen to make
    /// the accumulator overflow, borrow, and need every reduction.
    /// The tags were also recomputed from the standard's definition
    /// with big integers, which agreed.
    fn rfc8439_a3_edge_cases(under: &features::Under) {
        let r1 = block(1, 0);
        let r2 = block(2, 0);
        let ones = [0xff; 16];
        let zero = [0; 16];

        // 5: r = 2, s = 0, message of ones: the product wraps past
        // 2^130 and reduces to three.
        assert_eq!(tag_of(under, &key(r2, zero), &ones), block(3, 0));
        // 6: r = 2, s all ones, message 2: the final addition wraps.
        assert_eq!(tag_of(under, &key(r2, ones), &r2), block(3, 0));
        // 7: r = 1, carries through every limb.
        let mut m = [0u8; 48];
        m[..16].copy_from_slice(&ones);
        m[16..32].copy_from_slice(&block(0xf0, 0xff));
        m[32..].copy_from_slice(&block(0x11, 0));
        assert_eq!(tag_of(under, &key(r1, zero), &m), block(5, 0));
        // 8: r = 1, a borrow.
        m[16..32].copy_from_slice(&block(0xfb, 0xff));
        m[17] = 0xfe;
        m[32..].copy_from_slice(&block(1, 0));
        assert_eq!(tag_of(under, &key(r1, zero), &m), block(0, 0xff));
        // 9: r = 2, the accumulator lands just under the prime.
        assert_eq!(
            tag_of(under, &key(r2, zero), &block(0xfd, 0xff)),
            block(0xfa, 0xff)
        );
        // 10 and 11: r with a bit in its second word, and messages
        // built to cancel.
        let mut r = block(1, 0);
        r[8] = 4;
        let (m, n) = hex(
            "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000\
             0000000000000000000000000000000000010000000000000000000000000000\
             00",
        );
        assert_eq!(n, 64);
        let mut expected = block(0x14, 0);
        expected[8] = 0x55;
        assert_eq!(tag_of(under, &key(r, zero), &m[..64]), expected);
        assert_eq!(tag_of(under, &key(r, zero), &m[..48]), block(0x13, 0));
    }

    #[test]
    fn pieces_make_the_same_tag() {
        let (key, _) = hex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f5\
             1b",
        );
        let key: &[u8; 32] = key[..32].try_into().unwrap();
        let message: [u8; 101] = core::array::from_fn(|i| (i * 13) as u8);
        let expected = plain_tag(key, &message);
        for chunk in [1, 3, 15, 16, 17, 40] {
            let mut mac =
                Poly1305::new(crate::Context::default(), &Key::from(*key));
            for piece in message.chunks(chunk) {
                mac.update(piece);
            }
            assert_eq!(mac.finalize(), expected, "chunk {chunk}");
        }
        let mut mac =
            Poly1305::new(crate::Context::default(), &Key::from(*key));
        mac.update(b"not this");
        mac.reset();
        mac.update(&message);
        assert_eq!(mac.finalize(), expected);
    }

    /// A reset forgets a message the vector loop had already started
    /// on, chains and buffer both, and so does a finalize.
    #[test]
    fn reset_forgets_the_chains() {
        let key = [0x3cu8; KEY_SIZE];
        let message: [u8; 101] = core::array::from_fn(|i| (i * 5) as u8);
        let expected = plain_tag(&key, &message);
        let mut mac = Poly1305::new(crate::Context::default(), &Key::from(key));
        mac.update(&[0xa5; 3 * BUFFER + 9]);
        mac.reset();
        mac.update(&message);
        assert_eq!(mac.finalize(), expected);
        mac.update(&message);
        assert_eq!(mac.finalize(), expected);
    }

    #[test]
    fn verify_accepts_and_rejects() {
        let key = [7u8; 32];
        let tag = plain_tag(&key, b"message");
        let mut mac = Poly1305::new(crate::Context::default(), &Key::from(key));
        mac.update(b"message");
        assert_eq!(mac.clone().verify(&tag), Ok(()));
        let mut wrong = tag;
        wrong[0] ^= 1;
        assert_eq!(
            mac.clone().verify(&wrong),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(mac.verify(&tag[..15]), Err(Error::AuthenticationFailed));
    }

    #[test]
    fn debug_omits_the_key() {
        struct Buffer([u8; 128], usize);
        impl fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let key = [0x5a; 32];
        let mut mac = Poly1305::new(crate::Context::default(), &Key::from(key));
        mac.update(b"abc");
        let mut buffer = Buffer([0; 128], 0);
        fmt::write(&mut buffer, format_args!("{mac:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("5a") && !text.contains("90"));
        assert!(text.contains("buffered: 3"));
    }

    #[test]
    fn zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Poly1305>();
    }
}
