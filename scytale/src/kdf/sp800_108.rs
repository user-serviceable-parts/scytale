//! The key-based KDFs of NIST SP 800-108r1: counter, feedback and
//! double-pipeline modes over any MAC, and KDF-KMAC.
//!
//! Each mode runs a pseudorandom function, keyed with the
//! key-derivation key, over a counter and the *fixed input*: whatever
//! names the key being derived. The standard leaves the layout of the
//! fixed input to the protocol, typically a label, a zero byte, a
//! context and the output length in bits, so it is taken here as a
//! list of parts already encoded, as [`hkdf::expand`] takes its info.
//!
//! ```
//! use scytale::kdf::sp800_108;
//! use scytale::mac::hmac::HmacSha256;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut prf = HmacSha256::new(&[0x4b; 32]);
//! let mut key = [0u8; 32];
//! let length = (8 * key.len() as u32).to_be_bytes();
//! let fixed: [&[u8]; 4] = [b"encryption", &[0], b"session 7", &length];
//! sp800_108::counter(&mut prf, 32, 0, &fixed, &mut key)?;
//! # Ok(())
//! # }
//! ```
//!
//! The pseudorandom function is any [`Mac`], handed over already
//! keyed: HMAC under a key of any length from
//! [`Hmac::new`](crate::mac::hmac::Hmac::new), or CMAC under a key of
//! its cipher's width. KMAC takes its key and output length itself,
//! so it has its own functions, [`kmac128`] and [`kmac256`].
//!
//! # The counter
//!
//! The counter is the block number, from one, big-endian in 8, 16, 24
//! or 32 bits. SP 800-108r1 lets a protocol put it anywhere in the
//! fixed input, and even a position that is not a whole byte is
//! allowed, so its place is a count of bits from the start of the
//! fixed input: zero for before it, its whole length for after. A
//! counter must be wide enough to number every block asked for, and
//! a request that would overflow it is refused.
//!
//! [`hkdf::expand`]: super::hkdf::expand

use zeroize::Zeroize;

use crate::Error;
use crate::mac::Mac;
use crate::mac::kmac::{Kmac128, Kmac256};

/// Where the feedback and double-pipeline modes put their counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    /// No counter at all.
    None,
    /// A counter `bits` wide, ahead of the chaining value.
    BeforeIterator(u32),
    /// A counter `bits` wide, `at` bits into the fixed input, as
    /// [`counter`] places its own.
    InFixed {
        /// The width, 8, 16, 24 or 32.
        bits: u32,
        /// The position in the fixed input, in bits.
        at: usize,
    },
}

/// Counter mode: block `i` is `PRF(fixed input with [i] at `at`
/// bits)`.
///
/// `prf` must be keyed with the key-derivation key; it is reset
/// first, and left at the start of a message.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `bits` is not 8, 16, 24 or 32, if `at`
/// is past the end of the fixed input, or if `out` needs more blocks
/// than the counter can number.
pub fn counter<M: Mac>(
    prf: &mut M,
    bits: u32,
    at: usize,
    fixed: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    check_counter::<M>(bits, out)?;
    check_place(at, fixed)?;
    prf.reset();
    for (i, chunk) in out.chunks_mut(size_of::<M::Tag>()).enumerate() {
        let (count, n) = encode(i + 1, bits);
        absorb_fixed(prf, fixed, at, &count[..n]);
        emit(prf.finalize(), chunk);
    }
    Ok(())
}

/// Feedback mode: block `i` is `PRF(K(i-1) || fixed input)` with the
/// counter where `counter` puts it, and `K(0)` is `iv`, which may be
/// empty.
///
/// `prf` must be keyed with the key-derivation key; it is reset
/// first, and left at the start of a message.
///
/// # Errors
///
/// As [`counter`], for whatever counter there is.
pub fn feedback<M: Mac>(
    prf: &mut M,
    iv: &[u8],
    counter: Counter,
    fixed: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    check::<M>(counter, fixed, out)?;
    prf.reset();
    let mut previous: Option<M::Tag> = None;
    for (i, chunk) in out.chunks_mut(size_of::<M::Tag>()).enumerate() {
        let chaining = previous.as_ref().map_or(iv, |k| k.as_ref());
        absorb(prf, chaining, counter, i + 1, fixed);
        let k = prf.finalize();
        chunk.copy_from_slice(&k.as_ref()[..chunk.len()]);
        if let Some(mut old) = previous.replace(k) {
            old.as_mut().zeroize();
        }
    }
    if let Some(mut last) = previous {
        last.as_mut().zeroize();
    }
    Ok(())
}

/// Double-pipeline mode: `A(0)` is the fixed input, `A(i)` is
/// `PRF(A(i-1))`, and block `i` is `PRF(A(i) || fixed input)` with
/// the counter where `counter` puts it.
///
/// `prf` must be keyed with the key-derivation key; it is reset
/// first, and left at the start of a message.
///
/// # Errors
///
/// As [`counter`], for whatever counter there is.
pub fn double_pipeline<M: Mac>(
    prf: &mut M,
    counter: Counter,
    fixed: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    check::<M>(counter, fixed, out)?;
    prf.reset();
    let mut a: Option<M::Tag> = None;
    for (i, chunk) in out.chunks_mut(size_of::<M::Tag>()).enumerate() {
        match &a {
            None => fixed.iter().for_each(|part| prf.update(part)),
            Some(a) => prf.update(a.as_ref()),
        }
        let next = prf.finalize();
        if let Some(mut old) = a.replace(next) {
            old.as_mut().zeroize();
        }
        let chaining = a.as_ref().map_or(&[][..], |a| a.as_ref());
        absorb(prf, chaining, counter, i + 1, fixed);
        emit(prf.finalize(), chunk);
    }
    if let Some(mut last) = a {
        last.as_mut().zeroize();
    }
    Ok(())
}

/// KDF-KMAC with KMAC128 (SP 800-108r1 section 4.4): fills `out`
/// with `KMAC128(key, context, 8 * out.len(), label)`.
///
/// There is no counter or fixed-input layout to choose: the label is
/// KMAC's customization string and the output length is absorbed by
/// KMAC itself.
pub fn kmac128(key: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut mac = Kmac128::new(key, label);
    mac.update(context);
    mac.finalize_to(out);
}

/// KDF-KMAC with KMAC256, as [`kmac128`].
pub fn kmac256(key: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut mac = Kmac256::new(key, label);
    mac.update(context);
    mac.finalize_to(out);
}

/// Checks a counter and the output it must number.
fn check_counter<M: Mac>(bits: u32, out: &[u8]) -> Result<(), Error> {
    if !matches!(bits, 8 | 16 | 24 | 32) {
        return Err(Error::InvalidLength(bits as usize));
    }
    let blocks = out.len().div_ceil(size_of::<M::Tag>()) as u64;
    if blocks > (1u64 << bits) - 1 {
        return Err(Error::InvalidLength(out.len()));
    }
    Ok(())
}

/// Checks that a position in bits lies within the fixed input.
fn check_place(at: usize, fixed: &[&[u8]]) -> Result<(), Error> {
    let total: usize = fixed.iter().map(|p| p.len()).sum();
    if at > 8 * total {
        return Err(Error::InvalidLength(at));
    }
    Ok(())
}

/// Checks a chaining mode's counter, whatever it is.
fn check<M: Mac>(
    counter: Counter,
    fixed: &[&[u8]],
    out: &[u8],
) -> Result<(), Error> {
    match counter {
        Counter::None => Ok(()),
        Counter::BeforeIterator(bits) => check_counter::<M>(bits, out),
        Counter::InFixed { bits, at } => {
            check_counter::<M>(bits, out)?;
            check_place(at, fixed)
        }
    }
}

/// `i` big-endian in `bits` bits; returns the buffer and how much of
/// it is used.
fn encode(i: usize, bits: u32) -> ([u8; 4], usize) {
    let n = bits as usize / 8;
    let mut out = [0u8; 4];
    out[..n].copy_from_slice(&(i as u32).to_be_bytes()[4 - n..]);
    (out, n)
}

/// Copies as much of a block as `chunk` takes, and wipes the block.
fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(mut block: T, chunk: &mut [u8]) {
    chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
    block.as_mut().zeroize();
}

/// One block's input to a chaining mode: the chaining value and the
/// fixed input, with the counter for block `i` where `counter` says.
fn absorb<M: Mac>(
    prf: &mut M,
    chaining: &[u8],
    counter: Counter,
    i: usize,
    fixed: &[&[u8]],
) {
    match counter {
        Counter::None => {
            prf.update(chaining);
            fixed.iter().for_each(|part| prf.update(part));
        }
        Counter::BeforeIterator(bits) => {
            let (count, n) = encode(i, bits);
            prf.update(&count[..n]);
            prf.update(chaining);
            fixed.iter().for_each(|part| prf.update(part));
        }
        Counter::InFixed { bits, at } => {
            let (count, n) = encode(i, bits);
            prf.update(chaining);
            absorb_fixed(prf, fixed, at, &count[..n]);
        }
    }
}

/// The fixed input with `counter` inserted `at` bits into it, which
/// the caller has checked is within it.
///
/// A position on a byte boundary is a matter of where to cut the
/// parts. One inside a byte shifts everything after it by the same
/// number of bits, which goes through [`Bits`]; the counter is whole
/// bytes, so the input still ends on a byte boundary.
fn absorb_fixed<M: Mac>(
    prf: &mut M,
    fixed: &[&[u8]],
    at: usize,
    counter: &[u8],
) {
    let whole = at / 8;
    let shift = (at % 8) as u32;
    let mut taken = 0;
    let mut inserted = false;
    let mut bits = Bits::new();
    for part in fixed {
        let mut part: &[u8] = part;
        if !inserted {
            let n = (whole - taken).min(part.len());
            prf.update(&part[..n]);
            taken += n;
            part = &part[n..];
            if taken < whole {
                continue;
            }
            if shift == 0 {
                prf.update(counter);
            } else {
                // The byte the position falls in: its high bits, then
                // the counter, then its low bits.
                let Some((&byte, rest)) = part.split_first() else {
                    continue;
                };
                bits.push(prf, byte >> (8 - shift), shift);
                for &c in counter {
                    bits.push(prf, c, 8);
                }
                bits.push(prf, byte, 8 - shift);
                part = rest;
            }
            inserted = true;
        }
        if shift == 0 {
            prf.update(part);
        } else {
            for &byte in part {
                bits.push(prf, byte, 8);
            }
        }
    }
    // Only an empty fixed input, or a position at its very end with
    // nothing after, gets here without the counter in.
    if !inserted {
        prf.update(counter);
    }
    bits.flush(prf);
}

/// Bits written a few at a time and handed on as bytes, for fixed
/// input that the counter's position has shifted off byte
/// boundaries.
struct Bits {
    acc: u16,
    pending: u32,
    buf: [u8; 32],
    len: usize,
}

impl Bits {
    fn new() -> Self {
        Bits {
            acc: 0,
            pending: 0,
            buf: [0u8; 32],
            len: 0,
        }
    }

    /// Appends the low `n` bits of `value`, most significant first.
    fn push<M: Mac>(&mut self, prf: &mut M, value: u8, n: u32) {
        let mask = ((1u16 << n) - 1) as u8;
        self.acc = (self.acc << n) | u16::from(value & mask);
        self.pending += n;
        if self.pending >= 8 {
            self.pending -= 8;
            self.buf[self.len] = (self.acc >> self.pending) as u8;
            self.len += 1;
            self.acc &= (1 << self.pending) - 1;
            if self.len == self.buf.len() {
                self.flush(prf);
            }
        }
    }

    /// Hands on every whole byte written so far.
    fn flush<M: Mac>(&mut self, prf: &mut M) {
        prf.update(&self.buf[..self.len]);
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::Aes128;
    use crate::mac::cmac::Cmac;
    use crate::mac::hmac::HmacSha256;
    use crate::{Key, KeyType};

    fn prf() -> HmacSha256 {
        HmacSha256::new(&[0x4b; 32])
    }

    /// The fixed input in parts derives what it derives in one piece,
    /// wherever the counter is and however the parts are cut.
    #[test]
    fn parts_are_one_input() {
        let whole = [0x3cu8; 20];
        for at in [0, 8, 13, 80, 159, 160] {
            let mut one = [0u8; 70];
            let mut many = [0u8; 70];
            counter(&mut prf(), 16, at, &[&whole], &mut one).expect("one");
            let parts: [&[u8]; 4] =
                [&whole[..1], &[], &whole[1..11], &whole[11..]];
            counter(&mut prf(), 16, at, &parts, &mut many).expect("many");
            assert_eq!(one, many, "at {at}");
        }
    }

    /// Counter mode with the counter at the start is the standard's
    /// definition written out: HMAC of [i] || fixed, block by block.
    #[test]
    fn counter_mode_is_the_definition() {
        let fixed = b"label\x00context\x00\x00\x02\x00";
        let mut out = [0u8; 64];
        counter(&mut prf(), 32, 0, &[fixed], &mut out).expect("derive");
        for (i, block) in out.chunks(32).enumerate() {
            let mut mac = prf();
            mac.update(&(i as u32 + 1).to_be_bytes());
            mac.update(fixed);
            assert_eq!(block, mac.finalize(), "block {}", i + 1);
        }
    }

    /// A counter inside a byte splits that byte around it: the
    /// input is the same bits as the definition lays them out.
    #[test]
    fn a_counter_inside_a_byte_shifts_what_follows() {
        let fixed = [0b1011_0110u8, 0xff];
        let mut out = [0u8; 32];
        counter(&mut prf(), 8, 3, &[&fixed], &mut out).expect("derive");
        // 101 then 00000001 then 10110 then 11111111.
        let mut mac = prf();
        mac.update(&[0b1010_0000, 0b0011_0110, 0xff]);
        assert_eq!(out, mac.finalize());
    }

    /// Feedback mode chains each block into the next, starting from
    /// the IV, and every placement of the counter is a different
    /// derivation.
    #[test]
    fn feedback_chains_from_the_iv() {
        let fixed: [&[u8]; 1] = [b"fixed"];
        let iv = [7u8; 16];
        let mut out = [0u8; 64];
        feedback(&mut prf(), &iv, Counter::None, &fixed, &mut out)
            .expect("derive");
        let mut mac = prf();
        mac.update(&iv);
        mac.update(fixed[0]);
        let k1 = mac.finalize();
        mac.update(&k1);
        mac.update(fixed[0]);
        let k2 = mac.finalize();
        assert_eq!(out[..32], k1);
        assert_eq!(out[32..], k2);

        let placements = [
            Counter::BeforeIterator(8),
            Counter::InFixed { bits: 8, at: 0 },
            Counter::InFixed { bits: 8, at: 40 },
        ];
        for counter in placements {
            let mut other = [0u8; 64];
            feedback(&mut prf(), &iv, counter, &fixed, &mut other)
                .expect("derive");
            assert_ne!(out, other, "{counter:?}");
        }
    }

    /// Double-pipeline mode runs the first pipeline over the fixed
    /// input and feeds each value to the second.
    #[test]
    fn double_pipeline_is_the_definition() {
        let fixed: [&[u8]; 1] = [b"fixed"];
        let mut out = [0u8; 64];
        double_pipeline(&mut prf(), Counter::None, &fixed, &mut out)
            .expect("derive");
        let mut mac = prf();
        mac.update(fixed[0]);
        let a1 = mac.finalize();
        mac.update(&a1);
        let a2 = mac.finalize();
        for (a, block) in [a1, a2].iter().zip(out.chunks(32)) {
            mac.update(a);
            mac.update(fixed[0]);
            assert_eq!(block, mac.finalize());
        }
    }

    /// Bad widths, positions past the end and overflowing counters
    /// are refused before anything is written.
    #[test]
    fn refuses_what_the_standard_does_not_define() {
        let fixed: [&[u8]; 1] = [&[1, 2]];
        let mut out = [0xaau8; 40];
        assert_eq!(
            counter(&mut prf(), 12, 0, &fixed, &mut out),
            Err(Error::InvalidLength(12))
        );
        assert_eq!(
            counter(&mut prf(), 8, 17, &fixed, &mut out),
            Err(Error::InvalidLength(17))
        );
        // An 8-bit counter numbers 255 blocks of 32 bytes.
        let mut long = [0u8; 255 * 32 + 1];
        assert_eq!(
            counter(&mut prf(), 8, 0, &fixed, &mut long),
            Err(Error::InvalidLength(long.len()))
        );
        counter(&mut prf(), 8, 0, &fixed, &mut long[..255 * 32])
            .expect("the largest an 8-bit counter allows");
        assert_eq!(
            feedback(
                &mut prf(),
                &[],
                Counter::InFixed { bits: 8, at: 17 },
                &fixed,
                &mut out
            ),
            Err(Error::InvalidLength(17))
        );
        assert!(out.iter().all(|&b| b == 0xaa));
    }

    /// CMAC is as good a PRF as HMAC here: any keyed MAC will do.
    #[test]
    fn any_mac_is_a_prf() {
        let mut cmac = Cmac::<Aes128>::new(&Key::from([9u8; 16]));
        let mut out = [0u8; 40];
        counter(&mut cmac, 8, 0, &[b"x"], &mut out).expect("derive");
        let mut again = Cmac::<Aes128>::new(&Cmac::<Aes128>::zero_key());
        let mut other = [0u8; 40];
        counter(&mut again, 8, 0, &[b"x"], &mut other).expect("derive");
        assert_ne!(out, other);
    }

    /// KDF-KMAC is KMAC with the label as customization and the
    /// context as message.
    #[test]
    fn kmac_is_kmac() {
        let mut out = [0u8; 40];
        kmac128(b"key material", b"label", b"context", &mut out);
        let mut mac = Kmac128::new(b"key material", b"label");
        mac.update(b"context");
        let mut want = [0u8; 40];
        mac.finalize_to(&mut want);
        assert_eq!(out, want);
        kmac256(b"key material", b"label", b"context", &mut want);
        assert_ne!(out, want);
    }
}
