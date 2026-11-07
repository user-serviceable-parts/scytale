//! Argon2id (RFC 9106): a key from a password, at a cost in memory.
//!
//! Each guess at a password costs whoever makes it a fixed amount of
//! memory, filled and refilled in an order that depends on what was
//! written, so special hardware cannot trade the memory for speed as
//! it can with PBKDF2. Argon2id is the variant RFC 9106 recommends:
//! its first half pass is addressed independently of the password,
//! which denies a cache-timing observer anything on the first pass,
//! and the rest depends on the data, which makes trading memory for
//! time expensive.
//!
//! ```
//! use scytale::kdf::argon2::{self, Block, Params};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // The costs and the salt are stored beside the tag; the salt
//! // differs for every password.
//! let params = Params { passes: 3, memory_kib: 64, lanes: 1 };
//! let salt = [0x1f; 16];
//! // The memory is the caller's: the crate has no allocator. With
//! // std, `vec![Block::ZERO; n]`; on bare metal, a static array.
//! let mut work = [Block::ZERO; 64];
//! let mut tag = [0u8; 32];
//! let password = b"correct horse battery staple";
//! argon2::argon2id(password, &salt, &[], &[], params, &mut work, &mut tag)?;
//! argon2::verify(password, &salt, &[], &[], params, &mut work, &tag)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Choosing the costs
//!
//! RFC 9106 section 4 recommends 2 GiB of memory and one pass where
//! that can be afforded, and otherwise 64 MiB and three passes.
//! Memory is the defence: choose as much as the machine can give each
//! login, then the passes that bring the time to what the login can
//! bear. Lanes are computed one after another here, since a crate
//! with no operating system has no threads, so more than one lane
//! adds time and no security; use one unless the tag must match an
//! implementation that used more.
//!
//! # The secret and the associated data
//!
//! Both are optional in the RFC and empty means unused: they are
//! hashed with their lengths, so an empty one and an absent one are
//! the same input. The secret is a key held apart from the stored
//! tags, so that a stolen table cannot be attacked without it; the
//! associated data binds a tag to its context, a user's identifier
//! say, so that it does not verify when copied to another.
//!
//! # Resources
//!
//! The memory is handed in, so verifying a tag whose costs were read
//! from storage cannot be made to use more than the caller gave:
//! costs that ask for more fail with [`Error::InvalidLength`]. The
//! blocks used are zeroed before return, since they are a function
//! of the password.

use crate::Error;
use crate::constant_time;
use crate::hash::blake2::Engine;
use core::fmt;
use zeroize::Zeroize;

/// The version this implements, 0x13; RFC 9106 defines no other.
const VERSION: u32 = 0x13;

/// The 64-bit words of a block.
const WORDS: usize = 128;

/// The slices a pass is cut into; lanes synchronise only between
/// them.
const SLICES: usize = 4;

/// The type `y` of RFC 9106: hashed into the tag, and choosing the
/// addressing. Argon2d and Argon2i are not offered; the tests run
/// their vectors through the core, since Argon2id is made of the two.
#[cfg(test)]
const ARGON2D: u32 = 0;
const ARGON2I: u32 = 1;
const ARGON2ID: u32 = 2;

/// One 1 KiB unit of Argon2's working memory; RFC 9106 fixes the
/// size. Not a hash's block: nothing to do with
/// [`BlockType`](crate::BlockType). The contents are private, and
/// the type is aligned to 64 bytes so that every block of a slice of
/// them is.
#[derive(Clone)]
#[repr(align(64))]
pub struct Block([u64; WORDS]);

impl Block {
    /// A zeroed block, to fill a buffer from; `const` so that a
    /// static array can be.
    pub const ZERO: Block = Block([0; WORDS]);
}

impl Default for Block {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for Block {
    /// Deliberately omits the contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Block")
    }
}

/// The costs: stored beside a tag, since verifying needs them, and
/// tuned together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// t, the passes over the memory: at least one.
    pub passes: u32,
    /// m, the memory in KiB, which is in blocks: at least eight a
    /// lane. Used rounded down to a multiple of four a lane.
    pub memory_kib: u32,
    /// p, the lanes: 1 to 2^24 - 1.
    pub lanes: u32,
}

/// Fills `tag` from `password` and `salt`, with the optional
/// `secret` and associated `data` (empty for none), at the costs in
/// `params`, using the first `params.memory_kib` blocks of `work`.
///
/// Returns [`Error::InvalidIterations`] for no passes, and
/// [`Error::InvalidLength`] for a salt under 8 bytes, a tag under 4,
/// lanes outside 1 to 2^24 - 1, memory under 8 blocks a lane, `work`
/// shorter than the memory asked for, or an input longer than
/// 2^32 - 1 bytes.
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    data: &[u8],
    params: Params,
    work: &mut [Block],
    tag: &mut [u8],
) -> Result<(), Error> {
    let inputs = Inputs {
        password,
        salt,
        secret,
        data,
    };
    let tag_len = len32(tag.len())?;
    let mut at = 0;
    let mut emit = |piece: &[u8]| {
        tag[at..at + piece.len()].copy_from_slice(piece);
        at += piece.len();
    };
    hash(
        ARGON2ID, &inputs, params, tag_len, work, &mut emit, in_order,
    )
}

/// Whether `tag` is what [`argon2id`] derives from the same inputs,
/// for a stored verifier: the tag is compared as it is produced, so
/// no buffer its length is needed, and the comparison takes the same
/// time wherever it differs.
///
/// Returns [`Error::AuthenticationFailed`] on a mismatch, and the
/// errors [`argon2id`] returns for the same inputs.
pub fn verify(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    data: &[u8],
    params: Params,
    work: &mut [Block],
    tag: &[u8],
) -> Result<(), Error> {
    let inputs = Inputs {
        password,
        salt,
        secret,
        data,
    };
    let tag_len = len32(tag.len())?;
    let mut at = 0;
    let mut same = true;
    let mut emit = |piece: &[u8]| {
        // Every piece is compared whatever the earlier ones said.
        same &= constant_time::equal(piece, &tag[at..at + piece.len()]);
        at += piece.len();
    };
    hash(
        ARGON2ID, &inputs, params, tag_len, work, &mut emit, in_order,
    )?;
    if same {
        Ok(())
    } else {
        Err(Error::AuthenticationFailed)
    }
}

/// The variable-length inputs, which RFC 9106 calls P, S, K and X.
struct Inputs<'a> {
    password: &'a [u8],
    salt: &'a [u8],
    secret: &'a [u8],
    data: &'a [u8],
}

/// `n` as the RFC's 32-bit length.
fn len32(n: usize) -> Result<u32, Error> {
    u32::try_from(n).map_err(|_| Error::InvalidLength(n))
}

/// What every segment of a run shares.
struct Instance {
    y: u32,
    passes: u32,
    lanes: usize,
    /// Blocks a segment; a lane is four of them.
    segment: usize,
}

impl Instance {
    /// q, the blocks of a lane.
    fn lane_len(&self) -> usize {
        SLICES * self.segment
    }
}

/// The memory outside the slice being filled, which the segments of
/// that slice share for reading.
///
/// The blocks are stored slice by slice, each slice lane by lane,
/// rather than as the RFC's lanes of columns: then the slice being
/// filled is one run of the buffer, cut into one segment a lane, and
/// the borrow checker sees the segments' writes as disjoint from one
/// another and from everything they read. That is what lets them be
/// filled at once with no unsafe code.
struct View<'a> {
    before: &'a [Block],
    after: &'a [Block],
    slice: usize,
}

/// One segment, a (pass, slice, lane): the unit of work that can run
/// beside the other lanes' segments of the same slice, since none of
/// them reads another. A run hands every segment of a slice to its
/// driver, which must fill them all, in any order or at once, before
/// it returns; the next slice reads what they wrote.
pub(crate) struct Segment<'a> {
    instance: &'a Instance,
    view: &'a View<'a>,
    blocks: &'a mut [Block],
    pass: u32,
    lane: usize,
}

/// The driver that fills a slice's segments one after another, lane
/// order: all a crate without threads can do.
fn in_order(segments: &mut dyn Iterator<Item = Segment<'_>>) {
    for mut segment in segments {
        segment.fill();
    }
}

/// Argon2 of type `y`: validates, fills the memory pass by pass and
/// slice by slice through `drive`, and hands the tag to `emit` in
/// order, in pieces.
fn hash<D>(
    y: u32,
    inputs: &Inputs<'_>,
    params: Params,
    tag_len: u32,
    work: &mut [Block],
    emit: &mut dyn FnMut(&[u8]),
    mut drive: D,
) -> Result<(), Error>
where
    D: FnMut(&mut dyn Iterator<Item = Segment<'_>>),
{
    let Params {
        passes,
        memory_kib,
        lanes,
    } = params;
    if passes == 0 {
        return Err(Error::InvalidIterations);
    }
    if lanes == 0 || lanes > 0x00ff_ffff {
        return Err(Error::InvalidLength(lanes as usize));
    }
    if u64::from(memory_kib) < 8 * u64::from(lanes) {
        return Err(Error::InvalidLength(memory_kib as usize));
    }
    let memory = usize::try_from(memory_kib)
        .map_err(|_| Error::InvalidLength(memory_kib as usize))?;
    if work.len() < memory {
        return Err(Error::InvalidLength(work.len()));
    }
    if inputs.salt.len() < 8 {
        return Err(Error::InvalidLength(inputs.salt.len()));
    }
    if tag_len < 4 {
        return Err(Error::InvalidLength(tag_len as usize));
    }
    let parts = [inputs.password, inputs.salt, inputs.secret, inputs.data];
    for part in parts {
        len32(part.len())?;
    }

    let lanes = lanes as usize;
    let instance = Instance {
        y,
        passes,
        lanes,
        segment: memory / (SLICES * lanes),
    };
    // m', the blocks used: m rounded down to four a lane.
    let used = SLICES * lanes * instance.segment;
    let work = &mut work[..used];

    // H_0, of every parameter and input.
    let mut h0 = [0u8; 64];
    let mut engine = Engine::new(64, &[]);
    for word in [params.lanes, tag_len, memory_kib, passes, VERSION, y] {
        engine.update(&word.to_le_bytes());
    }
    for part in parts {
        engine.update(&(part.len() as u32).to_le_bytes());
        engine.update(part);
    }
    engine.finalize_into(&mut h0);

    // The first two blocks of every lane, from H_0; they are columns
    // 0 and 1, so in slice 0.
    let mut bytes = [0u8; 1024];
    for lane in 0..lanes {
        for column in 0..2u32 {
            let index = (lane as u32).to_le_bytes();
            let mut at = 0;
            h_prime(1024, &[&h0, &column.to_le_bytes(), &index], &mut |p| {
                bytes[at..at + p.len()].copy_from_slice(p);
                at += p.len();
            });
            let block = &mut work[lane * instance.segment + column as usize];
            for (word, le) in block.0.iter_mut().zip(bytes.chunks_exact(8)) {
                let mut b = [0u8; 8];
                b.copy_from_slice(le);
                *word = u64::from_le_bytes(b);
            }
        }
    }

    let run = lanes * instance.segment;
    for pass in 0..passes {
        for slice in 0..SLICES {
            let (before, rest) = work.split_at_mut(slice * run);
            let (current, after) = rest.split_at_mut(run);
            let view = View {
                before,
                after,
                slice,
            };
            let mut segments = current
                .chunks_mut(instance.segment)
                .enumerate()
                .map(|(lane, blocks)| Segment {
                    instance: &instance,
                    view: &view,
                    blocks,
                    pass,
                    lane,
                });
            drive(&mut segments);
        }
    }

    // C, the last column folded together, is the tag's only input.
    let mut last = [0u64; WORDS];
    for lane in 0..lanes {
        let block =
            &work[(3 * lanes + lane) * instance.segment + instance.segment - 1];
        for (c, w) in last.iter_mut().zip(block.0.iter()) {
            *c ^= w;
        }
    }
    for (le, word) in bytes.chunks_exact_mut(8).zip(last.iter()) {
        le.copy_from_slice(&word.to_le_bytes());
    }
    h_prime(tag_len, &[&bytes], emit);

    for block in work.iter_mut() {
        block.0.zeroize();
    }
    h0.zeroize();
    bytes.zeroize();
    last.zeroize();
    Ok(())
}

/// H' of RFC 9106 section 3.3, the hash of any length `len` (at
/// least 1) over `parts` concatenated, handed to `emit` in order in
/// pieces of at most 64 bytes.
fn h_prime(len: u32, parts: &[&[u8]], emit: &mut dyn FnMut(&[u8])) {
    let mut v = [0u8; 64];
    if len <= 64 {
        let n = len as usize;
        let mut engine = Engine::new(n, &[]);
        engine.update(&len.to_le_bytes());
        for part in parts {
            engine.update(part);
        }
        engine.finalize_into(&mut v[..n]);
        emit(&v[..n]);
        v.zeroize();
        return;
    }
    // r whole 64-byte hashes, of which the first half of each is
    // output, then one of the length left.
    let r = len.div_ceil(32) - 2;
    let mut engine = Engine::new(64, &[]);
    engine.update(&len.to_le_bytes());
    for part in parts {
        engine.update(part);
    }
    engine.finalize_into(&mut v);
    emit(&v[..32]);
    for _ in 1..r {
        let mut engine = Engine::new(64, &[]);
        engine.update(&v);
        engine.finalize_into(&mut v);
        emit(&v[..32]);
    }
    let rest = (len - 32 * r) as usize;
    let mut engine = Engine::new(rest, &[]);
    engine.update(&v);
    let mut out = [0u8; 64];
    engine.finalize_into(&mut out[..rest]);
    emit(&out[..rest]);
    v.zeroize();
    out.zeroize();
}

impl Segment<'_> {
    /// The block at (`lane`, `column`): from this segment if it is in
    /// the slice being filled, which for any lane but this one the
    /// reference set never asks for, and otherwise from the view.
    fn block(&self, lane: usize, column: usize) -> &Block {
        let i = self.instance;
        let (slice, offset) = (column / i.segment, column % i.segment);
        let view = self.view;
        if slice == view.slice {
            debug_assert_eq!(lane, self.lane);
            &self.blocks[offset]
        } else if slice < view.slice {
            &view.before[(slice * i.lanes + lane) * i.segment + offset]
        } else {
            let after = slice - view.slice - 1;
            &view.after[(after * i.lanes + lane) * i.segment + offset]
        }
    }

    /// z, the column of the reference block for the block at `index`
    /// in this segment, from J_1 (RFC 9106 section 3.4.2).
    fn reference(&self, index: usize, same_lane: bool, j1: u32) -> usize {
        let i = self.instance;
        let (segment, slice) = (i.segment, self.view.slice);
        // |W|: the blocks finished in the last three segments, and
        // in this lane those of this segment but the one before.
        let area = if self.pass == 0 {
            if slice == 0 || same_lane {
                slice * segment + index - 1
            } else {
                slice * segment - usize::from(index == 0)
            }
        } else if same_lane {
            i.lane_len() - segment + index - 1
        } else {
            i.lane_len() - segment - usize::from(index == 0)
        };
        let x = (u64::from(j1) * u64::from(j1)) >> 32;
        let y = (area as u64 * x) >> 32;
        let relative = area as u64 - 1 - y;
        // W starts after this segment, at the oldest block still in
        // it, except on the first pass.
        let start = if self.pass != 0 && slice != SLICES - 1 {
            (slice + 1) * segment
        } else {
            0
        };
        ((start as u64 + relative) % i.lane_len() as u64) as usize
    }

    /// Fills the segment's blocks (RFC 9106 section 3.2, steps 5 and
    /// 6), XORing into the old contents on later passes as version
    /// 0x13 does.
    pub(crate) fn fill(&mut self) {
        let i = self.instance;
        let slice = self.view.slice;
        let independent =
            i.y == ARGON2I || (i.y == ARGON2ID && self.pass == 0 && slice < 2);
        let mut input = Block::ZERO;
        let mut addresses = Block::ZERO;
        if independent {
            let fields = [
                u64::from(self.pass),
                self.lane as u64,
                slice as u64,
                (SLICES * i.lanes * i.segment) as u64,
                u64::from(i.passes),
                u64::from(i.y),
            ];
            input.0[..6].copy_from_slice(&fields);
        }
        // Columns 0 and 1 came from H_0.
        let start = if self.pass == 0 && slice == 0 { 2 } else { 0 };
        if independent && start != 0 {
            next_addresses(&mut input, &mut addresses);
        }
        let mut next = Block::ZERO;
        for index in start..i.segment {
            let column = slice * i.segment + index;
            let previous = if column == 0 {
                i.lane_len() - 1
            } else {
                column - 1
            };
            let random = if independent {
                if index % WORDS == 0 {
                    next_addresses(&mut input, &mut addresses);
                }
                addresses.0[index % WORDS]
            } else {
                self.block(self.lane, previous).0[0]
            };
            // J_2 picks the lane, except in the first slice of the
            // first pass, which has only this lane to take from.
            let lane = if self.pass == 0 && slice == 0 {
                self.lane
            } else {
                ((random >> 32) % i.lanes as u64) as usize
            };
            let z = self.reference(index, lane == self.lane, random as u32);
            compress(
                self.block(self.lane, previous),
                self.block(lane, z),
                &mut next,
            );
            let block = &mut self.blocks[index];
            if self.pass == 0 {
                block.0 = next.0;
            } else {
                for (b, n) in block.0.iter_mut().zip(next.0.iter()) {
                    *b ^= n;
                }
            }
        }
        next.0.zeroize();
    }
}

/// The next block of Argon2i's addresses: the counter in `input`
/// stepped, then G applied twice from zero (RFC 9106 section
/// 3.4.1.2).
fn next_addresses(input: &mut Block, addresses: &mut Block) {
    input.0[6] += 1;
    let mut once = Block::ZERO;
    compress(&Block::ZERO, input, &mut once);
    compress(&Block::ZERO, &once, addresses);
}

/// The compression function G of RFC 9106 section 3.5: `out` is
/// G(`x`, `y`).
fn compress(x: &Block, y: &Block, out: &mut Block) {
    let mut r = [0u64; WORDS];
    for (r, (x, y)) in r.iter_mut().zip(x.0.iter().zip(y.0.iter())) {
        *r = x ^ y;
    }
    let mut q = r;
    // P on each row of eight 16-byte registers, then on each column.
    for row in 0..8 {
        permute(&mut q, |k| 16 * row + k);
    }
    for column in 0..8 {
        permute(&mut q, |k| 2 * column + 16 * (k / 2) + k % 2);
    }
    for (o, (q, r)) in out.0.iter_mut().zip(q.iter().zip(r.iter())) {
        *o = q ^ r;
    }
    r.zeroize();
    q.zeroize();
}

/// The permutation P of RFC 9106 section 3.6 on the sixteen words of
/// `q` that `at` names, v_0 to v_15 in order.
fn permute(q: &mut [u64; WORDS], at: impl Fn(usize) -> usize) {
    let mut v = [0u64; 16];
    for (k, v) in v.iter_mut().enumerate() {
        *v = q[at(k)];
    }
    gb(&mut v, 0, 4, 8, 12);
    gb(&mut v, 1, 5, 9, 13);
    gb(&mut v, 2, 6, 10, 14);
    gb(&mut v, 3, 7, 11, 15);
    gb(&mut v, 0, 5, 10, 15);
    gb(&mut v, 1, 6, 11, 12);
    gb(&mut v, 2, 7, 8, 13);
    gb(&mut v, 3, 4, 9, 14);
    for (k, v) in v.iter().enumerate() {
        q[at(k)] = *v;
    }
    v.zeroize();
}

/// BLAKE2b's G with each addition carrying the product of the low
/// halves, as RFC 9106 figure 19 gives it.
#[inline(always)]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    let mix = |x: u64, y: u64| {
        let product = u64::from(x as u32) * u64::from(y as u32);
        x.wrapping_add(y).wrapping_add(product.wrapping_mul(2))
    };
    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::{vec, vec::Vec};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The tag of `y` over `inputs`, through `drive`, with exactly the
    /// memory asked for.
    fn tag<D>(
        y: u32,
        inputs: &Inputs<'_>,
        params: Params,
        len: usize,
        drive: D,
    ) -> Vec<u8>
    where
        D: FnMut(&mut dyn Iterator<Item = Segment<'_>>),
    {
        let mut work = vec![Block::ZERO; params.memory_kib as usize];
        let mut out = Vec::new();
        let mut emit = |p: &[u8]| out.extend_from_slice(p);
        hash(y, inputs, params, len as u32, &mut work, &mut emit, drive)
            .unwrap();
        out
    }

    /// The segments of each slice filled last lane first.
    fn reversed(segments: &mut dyn Iterator<Item = Segment<'_>>) {
        let mut all: Vec<_> = segments.collect();
        for segment in all.iter_mut().rev() {
            segment.fill();
        }
    }

    /// The segments of each slice filled at once, a thread each.
    #[cfg(not(target_family = "wasm"))]
    fn threaded(segments: &mut dyn Iterator<Item = Segment<'_>>) {
        std::thread::scope(|scope| {
            for mut segment in segments {
                scope.spawn(move || segment.fill());
            }
        });
    }

    /// The tag through every driver there is, which must agree: the
    /// lanes of a slice are independent, whatever order they run in
    /// and whether they run at once.
    fn every_driver(
        y: u32,
        inputs: &Inputs<'_>,
        params: Params,
        len: usize,
    ) -> Vec<u8> {
        let first = tag(y, inputs, params, len, in_order);
        assert_eq!(tag(y, inputs, params, len, reversed), first);
        #[cfg(not(target_family = "wasm"))]
        assert_eq!(tag(y, inputs, params, len, threaded), first);
        first
    }

    /// RFC 9106 section 5: the three types, four lanes, with a secret
    /// and associated data.
    #[test]
    fn rfc9106() {
        let inputs = Inputs {
            password: &[1; 32],
            salt: &[2; 16],
            secret: &[3; 8],
            data: &[4; 12],
        };
        let params = Params {
            passes: 3,
            memory_kib: 32,
            lanes: 4,
        };
        for (y, expected) in [
            (
                ARGON2D,
                concat!(
                    "512b391b6f1162975371d30919734294",
                    "f868e3be3984f3c1a13a4db9fabe4acb"
                ),
            ),
            (
                ARGON2I,
                concat!(
                    "c814d9d1dc7f37aa13f0d77f2494bda1",
                    "c8de6b016dd388d29952a4c4672b6ce8"
                ),
            ),
            (
                ARGON2ID,
                concat!(
                    "0d640df58d78766c08c037a34a8b53c9",
                    "d01ef0452d75b65eb52520e96b01e659"
                ),
            ),
        ] {
            assert_eq!(
                every_driver(y, &inputs, params, 32),
                hex(expected),
                "y {y}"
            );
        }
        // And through the public functions.
        let mut work = vec![Block::ZERO; 32];
        let mut out = [0u8; 32];
        argon2id(
            &[1; 32], &[2; 16], &[3; 8], &[4; 12], params, &mut work, &mut out,
        )
        .unwrap();
        assert_eq!(
            out[..],
            hex(concat!(
                "0d640df58d78766c08c037a34a8b53c9",
                "d01ef0452d75b65eb52520e96b01e659"
            ))[..]
        );
        verify(
            &[1; 32], &[2; 16], &[3; 8], &[4; 12], params, &mut work, &out,
        )
        .unwrap();
    }

    /// The reference implementation's version 0x13 cases, phc-winner-
    /// argon2 `src/test.c`: (t, log2 m, p, password, salt, tag).
    type Case = (u32, u32, u32, &'static str, &'static str, &'static str);

    fn reference(y: u32, cases: &[Case]) {
        for &(passes, log_m, lanes, password, salt, expected) in cases {
            let inputs = Inputs {
                password: password.as_bytes(),
                salt: salt.as_bytes(),
                secret: &[],
                data: &[],
            };
            let params = Params {
                passes,
                memory_kib: 1 << log_m,
                lanes,
            };
            // One lane is one segment a slice, so every driver does
            // the same work; the others only for more.
            let got = if lanes > 1 {
                every_driver(y, &inputs, params, 32)
            } else {
                tag(y, &inputs, params, 32, in_order)
            };
            assert_eq!(
                got,
                hex(expected),
                "t {passes} m 2^{log_m} p {lanes} {password} {salt}"
            );
        }
    }

    /// One test a type, so the large cases run one at a time and a
    /// 32-bit address space holds them.
    #[test]
    fn reference_argon2id() {
        reference(
            ARGON2ID,
            &[
                (
                    2,
                    16,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "09316115d5cf24ed5a15a31a3ba326e5",
                        "cf32edc24702987c02b6566f61913cf7"
                    ),
                ),
                (
                    2,
                    18,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "78fe1ec91fb3aa5657d72e710854e4c3",
                        "d9b9198c742f9616c2f085bed95b2e8c"
                    ),
                ),
                (
                    2,
                    8,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "9dfeb910e80bad0311fee20f9c0e2b12",
                        "c17987b4cac90c2ef54d5b3021c68bfe"
                    ),
                ),
                (
                    2,
                    8,
                    2,
                    "password",
                    "somesalt",
                    concat!(
                        "6d093c501fd5999645e0ea3bf620d7b8",
                        "be7fd2db59c20d9fff9539da2bf57037"
                    ),
                ),
                (
                    1,
                    16,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "f6a5adc1ba723dddef9b5ac1d464e180",
                        "fcd9dffc9d1cbf76cca2fed795d9ca98"
                    ),
                ),
                (
                    4,
                    16,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "9025d48e68ef7395cca9079da4c4ec3a",
                        "ffb3c8911fe4f86d1a2520856f63172c"
                    ),
                ),
                (
                    2,
                    16,
                    1,
                    "differentpassword",
                    "somesalt",
                    concat!(
                        "0b84d652cf6b0c4beaef0dfe278ba6a8",
                        "0df6696281d7e0d2891b817d8c458fde"
                    ),
                ),
                (
                    2,
                    16,
                    1,
                    "password",
                    "diffsalt",
                    concat!(
                        "bdf32b05ccc42eb15d58fd19b1f856b1",
                        "13da1e9a5874fdcc544308565aa8141c"
                    ),
                ),
            ],
        );
    }

    /// Argon2i is half of Argon2id's addressing; its cases include the
    /// one the reference keeps behind TEST_LARGE_RAM, 1 GiB.
    #[test]
    fn reference_argon2i() {
        reference(
            ARGON2I,
            &[
                (
                    2,
                    16,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "c1628832147d9720c5bd1cfd61367078",
                        "729f6dfb6f8fea9ff98158e0d7816ed0"
                    ),
                ),
                (
                    2,
                    20,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "d1587aca0922c3b5d6a83edab31bee3c",
                        "4ebaef342ed6127a55d19b2351ad1f41"
                    ),
                ),
                (
                    2,
                    18,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "296dbae80b807cdceaad44ae741b506f",
                        "14db0959267b183b118f9b24229bc7cb"
                    ),
                ),
                (
                    2,
                    8,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "89e9029f4637b295beb027056a7336c4",
                        "14fadd43f6b208645281cb214a56452f"
                    ),
                ),
                (
                    2,
                    8,
                    2,
                    "password",
                    "somesalt",
                    concat!(
                        "4ff5ce2769a1d7f4c8a491df09d41a9f",
                        "be90e5eb02155a13e4c01e20cd4eab61"
                    ),
                ),
                (
                    1,
                    16,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "d168075c4d985e13ebeae560cf8b94c3",
                        "b5d8a16c51916b6f4ac2da3ac11bbecf"
                    ),
                ),
                (
                    4,
                    16,
                    1,
                    "password",
                    "somesalt",
                    concat!(
                        "aaa953d58af3706ce3df1aefd4a64a84",
                        "e31d7f54175231f1285259f88174ce5b"
                    ),
                ),
                (
                    2,
                    16,
                    1,
                    "differentpassword",
                    "somesalt",
                    concat!(
                        "14ae8da01afea8700c2358dcef7c5358",
                        "d9021282bd88663a4562f59fb74d22ee"
                    ),
                ),
                (
                    2,
                    16,
                    1,
                    "password",
                    "diffsalt",
                    concat!(
                        "b0357cccfbef91f3860b0dba447b2348",
                        "cbefecadaf990abfe9cc40726c521271"
                    ),
                ),
            ],
        );
    }

    const P: Params = Params {
        passes: 1,
        memory_kib: 8,
        lanes: 1,
    };

    fn run(
        salt: &[u8],
        params: Params,
        work: &mut [Block],
        tag: &mut [u8],
    ) -> Result<(), Error> {
        argon2id(b"password", salt, &[], &[], params, work, tag)
    }

    #[test]
    fn bad_inputs_are_refused() {
        let mut work = vec![Block::ZERO; 64];
        let mut tag = [0u8; 32];
        let salt = [0u8; 8];
        assert_eq!(
            run(&salt, Params { passes: 0, ..P }, &mut work, &mut tag),
            Err(Error::InvalidIterations)
        );
        assert_eq!(
            run(&salt, Params { lanes: 0, ..P }, &mut work, &mut tag),
            Err(Error::InvalidLength(0))
        );
        assert_eq!(
            run(
                &salt,
                Params {
                    lanes: 1 << 24,
                    memory_kib: u32::MAX,
                    ..P
                },
                &mut work,
                &mut tag
            ),
            Err(Error::InvalidLength(1 << 24))
        );
        assert_eq!(
            run(&salt, Params { memory_kib: 7, ..P }, &mut work, &mut tag),
            Err(Error::InvalidLength(7))
        );
        assert_eq!(
            run(
                &salt,
                Params {
                    memory_kib: 15,
                    lanes: 2,
                    ..P
                },
                &mut work,
                &mut tag
            ),
            Err(Error::InvalidLength(15))
        );
        assert_eq!(
            run(
                &salt,
                Params {
                    memory_kib: 65,
                    ..P
                },
                &mut work,
                &mut tag
            ),
            Err(Error::InvalidLength(64))
        );
        assert_eq!(
            run(&salt[..7], P, &mut work, &mut tag),
            Err(Error::InvalidLength(7))
        );
        assert_eq!(
            run(&salt, P, &mut work, &mut tag[..3]),
            Err(Error::InvalidLength(3))
        );
        // The smallest of each is accepted.
        run(&salt, P, &mut work[..8], &mut tag[..4]).unwrap();
    }

    #[test]
    fn verify_accepts_its_own_tag_and_nothing_else() {
        let mut work = vec![Block::ZERO; 16];
        let params = Params {
            passes: 2,
            memory_kib: 16,
            lanes: 2,
        };
        let salt = [9u8; 16];
        // 1024 bytes takes H' through its long form; 4 is the
        // shortest tag allowed.
        for len in [4usize, 32, 64, 65, 1024] {
            let mut tag = vec![0u8; len];
            argon2id(b"pw", &salt, b"k", b"x", params, &mut work, &mut tag)
                .unwrap();
            verify(b"pw", &salt, b"k", b"x", params, &mut work, &tag).unwrap();
            for wrong in [0, len - 1] {
                let mut bad = tag.clone();
                bad[wrong] ^= 1;
                assert_eq!(
                    verify(b"pw", &salt, b"k", b"x", params, &mut work, &bad),
                    Err(Error::AuthenticationFailed)
                );
            }
            // Each input reaches the tag.
            for (p, k, x) in [
                (&b"pX"[..], &b"k"[..], &b"x"[..]),
                (b"pw", b"", b"x"),
                (b"pw", b"k", b""),
            ] {
                assert_eq!(
                    verify(p, &salt, k, x, params, &mut work, &tag),
                    Err(Error::AuthenticationFailed)
                );
            }
        }
    }

    /// m is used rounded down to four blocks a lane, the blocks past
    /// that are never touched, and those used are zeroed after.
    #[test]
    fn memory_is_rounded_down_used_and_wiped() {
        let marked = {
            let mut b = Block::ZERO;
            b.0.fill(0x5a5a_5a5a_5a5a_5a5a);
            b
        };
        let params = Params {
            passes: 1,
            memory_kib: 35,
            lanes: 4,
        };
        let mut work = vec![marked.clone(); 40];
        let mut tag = [0u8; 32];
        run(&[1; 8], params, &mut work, &mut tag).unwrap();
        assert!(work[..32].iter().all(|b| b.0 == [0; WORDS]));
        assert!(work[32..].iter().all(|b| b.0 == marked.0));
        // The same tag whatever was in the buffer beforehand.
        let mut fresh = vec![Block::ZERO; 35];
        let mut again = [0u8; 32];
        run(&[1; 8], params, &mut fresh, &mut again).unwrap();
        assert_eq!(tag, again);
    }

    #[test]
    fn a_block_is_a_kibibyte_on_a_cache_line() {
        assert_eq!(size_of::<Block>(), 1024);
        assert_eq!(align_of::<Block>(), 64);
        let work = [Block::ZERO, Block::ZERO];
        assert_eq!(work.as_ptr() as usize % 64, 0);
        assert_eq!(&work[1] as *const Block as usize % 64, 0);
    }
}
