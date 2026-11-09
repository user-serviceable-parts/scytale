//! BLAKE2b (RFC 7693).
//!
//! A hash of 1 to 64 bytes over 64-bit words, built from ChaCha's
//! quarter-round and HAIFA's counter and final flag rather than
//! Merkle-Damgard padding, so it cannot be length extended. On a
//! 64-bit processor without SHA instructions it is faster than any
//! SHA-2 or SHA-3 function. Argon2 is built on it.
//!
//! ```
//! use scytale::hash::Hash;
//! use scytale::hash::blake2::{Blake2b256, Blake2b512};
//!
//! let digest = Blake2b512::digest(b"abc");
//! assert_eq!(digest[..4], [0xba, 0x80, 0xa5, 0x3f]);
//!
//! let mut hash = Blake2b256::new();
//! hash.update(b"a");
//! hash.update(b"bc");
//! assert_eq!(hash.finalize().len(), 32);
//! ```
//!
//! The two widths are the ones RFC 7693 assigns identifiers and the
//! protocols that name BLAKE2b use. A digest of another length is not
//! a truncation of these: the length is hashed into the result. The
//! RFC's keyed mode is not offered; HMAC over either type works,
//! since both say their block through [`BlockType`].
//!
//! There is one implementation, written out over `u64`, so nothing
//! here dispatches.

use crate::BlockType;
use crate::hash::Hash;
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The block, in bytes.
const BLOCK: usize = 128;

/// The initialisation vector: SHA-512's, as the RFC specifies.
const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// The message schedule of each of the twelve rounds; the last two
/// repeat the first two.
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// The mixing function G of RFC 7693 section 3.1.
#[inline(always)]
#[allow(clippy::many_single_char_names)]
fn g(
    v: &mut [u64; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: u64,
    y: u64,
) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The compression function F: `t` is the count of bytes hashed so
/// far, this block's included, and `last` the final block flag.
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (word, bytes) in m.iter_mut().zip(block.chunks_exact(8)) {
        let mut le = [0u8; 8];
        le.copy_from_slice(bytes);
        *word = u64::from_le_bytes(le);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    // The counter's two halves; the truncations are the split.
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (i, word) in h.iter_mut().enumerate() {
        *word ^= v[i] ^ v[i + 8];
    }
    // Both are functions of the message.
    m.zeroize();
    v.zeroize();
}

/// A BLAKE2b computation in progress, at any output length and with
/// an optional key: what Argon2's variable-length hash needs, and
/// what RFC 7693's own test exercises.
#[derive(Clone)]
pub(crate) struct Engine {
    h: [u64; 8],
    /// Bytes compressed so far.
    t: u128,
    buf: [u8; BLOCK],
    /// Bytes of `buf` that are message. A full buffer is held back
    /// until more arrives, since the last block is compressed
    /// differently and only the next update shows this was not it.
    used: usize,
    out_len: usize,
}

impl Engine {
    /// Starts a hash of `out_len` bytes, 1 to 64, under `key`, of at
    /// most 64 bytes and empty for the unkeyed hash. The callers are
    /// the crate's own and pass constants or checked lengths.
    pub(crate) fn new(out_len: usize, key: &[u8]) -> Self {
        debug_assert!((1..=64).contains(&out_len), "{out_len}");
        debug_assert!(key.len() <= 64, "{}", key.len());
        let mut h = IV;
        // The parameter block's first word: digest length, key
        // length, fanout 1 and depth 1; the rest are zero.
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ out_len as u64;
        let mut engine = Engine {
            h,
            t: 0,
            buf: [0; BLOCK],
            used: 0,
            out_len,
        };
        if !key.is_empty() {
            // The key padded to a block is the first block.
            engine.buf[..key.len()].copy_from_slice(key);
            engine.used = BLOCK;
        }
        engine
    }

    /// Appends `data` to the message.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.used == BLOCK {
                self.t += BLOCK as u128;
                compress(&mut self.h, &self.buf, self.t, false);
                self.used = 0;
            }
            let take = (BLOCK - self.used).min(data.len());
            self.buf[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
        }
    }

    /// Ends the message and writes the digest, of the length given to
    /// [`Engine::new`], to `out`, which is that long. The state is
    /// spent; start another to hash again.
    pub(crate) fn finalize_into(&mut self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.out_len);
        self.t += self.used as u128;
        self.buf[self.used..].fill(0);
        compress(&mut self.h, &self.buf, self.t, true);
        for (bytes, word) in out.chunks_mut(8).zip(self.h.iter()) {
            bytes.copy_from_slice(&word.to_le_bytes()[..bytes.len()]);
        }
    }
}

impl Drop for Engine {
    /// The buffer holds message, and the state is a function of it.
    fn drop(&mut self) {
        self.h.zeroize();
        self.buf.zeroize();
        self.t.zeroize();
        self.used.zeroize();
    }
}

impl ZeroizeOnDrop for Engine {}

impl fmt::Debug for Engine {
    /// Deliberately omits the state and buffer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("out_len", &self.out_len)
            .finish_non_exhaustive()
    }
}

/// Defines one of the public digests over the engine.
macro_rules! digest {
    ($(#[$doc:meta])* $name:ident, $out:literal) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name(Engine);

        impl $name {
            /// Starts a hash.
            pub fn new() -> Self {
                $name(Engine::new($out, &[]))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            /// Deliberately omits the state and buffer.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ZeroizeOnDrop for $name {}

        impl BlockType for $name {
            type Block = [u8; BLOCK];

            fn zero_block() -> Self::Block {
                [0; BLOCK]
            }
        }

        impl Hash for $name {
            type Output = [u8; $out];

            fn reset(&mut self) {
                *self = Self::new();
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.0.update(data)
            }

            fn finalize(&mut self) -> Self::Output {
                let mut out = [0; $out];
                self.0.finalize_into(&mut out);
                self.reset();
                out
            }
        }
    };
}

digest!(
    /// BLAKE2b-256: BLAKE2b with a 32-byte digest.
    Blake2b256,
    32
);
digest!(
    /// BLAKE2b-512: BLAKE2b with a 64-byte digest.
    Blake2b512,
    64
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::Mac;
    use crate::mac::hmac::Hmac;

    /// The engine at `out_len` under `key`, in one call.
    fn engine(out_len: usize, key: &[u8], data: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        let mut e = Engine::new(out_len, key);
        e.update(data);
        e.finalize_into(&mut out[..out_len]);
        out
    }

    /// RFC 7693 appendix A.
    #[test]
    fn rfc7693_abc() {
        let expected = [
            0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d, 0x6a, 0x27, 0x97,
            0xb6, 0x9f, 0x12, 0xf6, 0xe9, 0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a,
            0xc4, 0xb7, 0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1, 0x7d,
            0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d, 0xc2, 0x52, 0xd5, 0xde,
            0x45, 0x33, 0xcc, 0x95, 0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92,
            0x5a, 0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
        ];
        assert_eq!(Blake2b512::digest(b"abc"), expected);
    }

    /// RFC 7693 appendix E's deterministic input.
    fn selftest_seq(out: &mut [u8], seed: u32) {
        let mut a = 0xdead_4badu32.wrapping_mul(seed);
        let mut b = 1u32;
        for byte in out {
            let t = a.wrapping_add(b);
            a = b;
            b = t;
            *byte = (t >> 24) as u8;
        }
    }

    /// RFC 7693 appendix E: four digest lengths, six message lengths
    /// across the block boundary, keyed and unkeyed, each digest
    /// hashed into a 32-byte grand hash.
    #[test]
    fn rfc7693_selftest() {
        let expected = [
            0xc2, 0x3a, 0x78, 0x00, 0xd9, 0x81, 0x23, 0xbd, 0x10, 0xf5, 0x06,
            0xc6, 0x1e, 0x29, 0xda, 0x56, 0x03, 0xd7, 0x63, 0xb8, 0xbb, 0xad,
            0x2e, 0x73, 0x7f, 0x5e, 0x76, 0x5a, 0x7b, 0xcc, 0xd4, 0x75,
        ];
        let mut grand = Blake2b256::new();
        let mut input = [0u8; 1024];
        let mut key = [0u8; 64];
        for out_len in [20usize, 32, 48, 64] {
            for in_len in [0usize, 3, 128, 129, 255, 1024] {
                selftest_seq(&mut input[..in_len], in_len as u32);
                let md = engine(out_len, &[], &input[..in_len]);
                grand.update(&md[..out_len]);
                selftest_seq(&mut key[..out_len], out_len as u32);
                let md = engine(out_len, &key[..out_len], &input[..in_len]);
                grand.update(&md[..out_len]);
            }
        }
        assert_eq!(grand.finalize(), expected);
    }

    /// The public types are the engine at their widths, in one call
    /// or a byte at a time.
    #[test]
    fn the_types_are_the_engine_at_their_widths() {
        let mut input = [0u8; 300];
        selftest_seq(&mut input, 7);
        for len in [0usize, 1, 127, 128, 129, 256, 300] {
            let data = &input[..len];
            assert_eq!(
                Blake2b256::digest(data)[..],
                engine(32, &[], data)[..32]
            );
            assert_eq!(Blake2b512::digest(data), engine(64, &[], data));
            let mut hash = Blake2b512::new();
            for byte in data {
                hash.update(core::slice::from_ref(byte));
            }
            assert_eq!(hash.finalize(), Blake2b512::digest(data));
        }
    }

    /// `finalize` leaves a new hash behind.
    #[test]
    fn finalize_resets() {
        let mut hash = Blake2b512::new();
        hash.update(b"something else");
        let _ = hash.finalize();
        hash.update(b"abc");
        assert_eq!(hash.finalize(), Blake2b512::digest(b"abc"));
    }

    /// HMAC takes the 128-byte block from `BlockType`: checked against
    /// the definition written out.
    #[test]
    fn hmac_uses_the_128_byte_block() {
        let key = [0x0bu8; 20];
        let message = b"Hi There";
        let mut padded = [0u8; BLOCK];
        padded[..key.len()].copy_from_slice(&key);
        let mut inner = Blake2b512::new();
        inner.update(&padded.map(|b| b ^ 0x36));
        inner.update(message);
        let mut outer = Blake2b512::new();
        outer.update(&padded.map(|b| b ^ 0x5c));
        outer.update(&inner.finalize());
        let mut mac = Hmac::<Blake2b512>::new(&key);
        mac.update(message);
        assert_eq!(mac.finalize(), outer.finalize());
    }

    #[test]
    fn every_type_zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Engine>();
        wipes::<Blake2b256>();
        wipes::<Blake2b512>();
    }
}
