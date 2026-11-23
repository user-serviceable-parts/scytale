//! AES using the ARMv8 cryptography extension, with the round loops
//! in hand-written assembly.
//!
//! `aese` does AddRoundKey, SubBytes and ShiftRows in one instruction
//! and `aesmc` does MixColumns; `aesd` and `aesimc` are the inverses.
//! The multi-block methods feed eight blocks through each round
//! together so the pipelined AES unit stays busy; a tail of fewer
//! blocks goes through one pass of exactly its width.
//!
//! The S-box lives in hardware, so this implementation does not leak
//! key material through cache timing.
//!
//! # Availability
//!
//! There is no user-space CPUID on aarch64. [`Aes::new`] accepts
//! when the crate was compiled with the `aes` target feature, or, on
//! Linux, when the kernel's emulated `ID_AA64ISAR0_EL1` register
//! reports the instructions. Otherwise it returns
//! [`Error::NotSupported`].
//!

#![allow(unsafe_code)]

use core::arch::aarch64::{
    uint32x4_t, vaeseq_u8, vaesimcq_u8, vcombine_u32, vdup_n_u32,
    vdupq_laneq_u32, vdupq_n_u8, vdupq_n_u32, veorq_u32, vextq_u8,
    vget_low_u32, vld1_u32, vld1q_u8, vld1q_u32, vreinterpretq_u8_u32,
    vreinterpretq_u32_u8, vshlq_n_u32, vsriq_n_u32, vst1_u32, vst1q_u8,
    vst1q_u32,
};
use core::fmt;

use crate::cipher::aes::{BLOCK_SIZE, KeySize, MAX_WORDS};
use crate::features::Chosen;
use zeroize::ZeroizeOnDrop;

/// An AES cipher with an expanded key, using the ARMv8 instructions.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::new`]; the key is wiped on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes<const K: usize> {
    /// Round keys as words in memory order; the loops load them
    /// straight from memory.
    enc: [u32; MAX_WORDS],
    dec: [u32; MAX_WORDS],
    #[zeroize(skip)]
    size: KeySize,
}

impl<const K: usize> fmt::Debug for Aes<K> {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

impl<const K: usize> Aes<K> {
    /// Expands `key` where the kernel list chose this kernel, and
    /// `None` for any other choice.
    pub(crate) fn new(
        key: &[u8; K],
        chosen: Chosen<super::super::Kernel>,
    ) -> Option<Self> {
        // SAFETY: only the list makes a `Chosen`, and only for a row
        // whose features were in force; this is that row.
        (chosen.kernel() == super::super::Kernel::Armv8)
            .then(|| unsafe { Self::new_unchecked(key) })
    }

    /// Expands `key` without checking for the AES instructions.
    ///
    /// # Safety
    /// The caller must have confirmed that the AES instructions are
    /// available.
    pub(crate) unsafe fn new_unchecked(key: &[u8; K]) -> Self {
        unsafe {
            let size = KeySize::for_key(key);
            expand(key, size)
        }
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.size.rounds()
    }

    /// Encrypts every block in place, independently (ECB).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = blocks.as_flattened_mut();
        // SAFETY: the struct only exists if try_new confirmed support.
        // SAFETY: the struct only exists if try_new confirmed support;
        // the length is a whole number of blocks.
        unsafe { encrypt_blocks(&self.enc, self.rounds(), data) }
    }

    /// Decrypts every block in place, independently (ECB).
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = blocks.as_flattened_mut();
        // SAFETY: the struct only exists if try_new confirmed support.
        // SAFETY: the struct only exists if try_new confirmed support;
        // the length is a whole number of blocks.
        unsafe { decrypt_blocks(&self.dec, self.rounds(), data) }
    }
}

/// Reverses the bytes of a register, as `tbl` indices. The counter is
/// the last four bytes of a block, most significant first; reversed,
/// it is the low word, least significant first, where a word add can
impl<const K: usize> super::Keyed for Aes<K> {
    /// Always: this implementation exists only where they do.
    fn schedule(&self) -> Option<super::Schedule<'_>> {
        Some(super::Schedule::new(&self.enc, self.rounds()))
    }

    fn decryption(&self) -> Option<super::Schedule<'_>> {
        Some(super::Schedule::new(&self.dec, self.rounds()))
    }
}

// The key schedule, in registers. There is no key-assist instruction
// here; `aese` against a zero key is `SubBytes` then `ShiftRows`, and
// on a vector whose four words are the same, `ShiftRows` moves equal
// bytes onto each other and changes nothing, so it is `SubWord` of
// that word in every lane. `RotWord` is a byte rotate of each lane,
// and the running XOR down a round key is three shift-and-XOR steps.
// Nothing leaves the vector registers until a round key is whole.

/// `SubWord` of the word in every lane of `v`.
#[inline(always)]
unsafe fn sub_lanes(v: uint32x4_t) -> uint32x4_t {
    unsafe {
        vreinterpretq_u32_u8(vaeseq_u8(vreinterpretq_u8_u32(v), vdupq_n_u8(0)))
    }
}

/// `RotWord` of every lane: each word rotated right by a byte, which
/// on the little-endian view is the standard's rotate left.
#[inline(always)]
unsafe fn rot_lanes(v: uint32x4_t) -> uint32x4_t {
    unsafe { vsriq_n_u32::<8>(vshlq_n_u32::<24>(v), v) }
}

/// XORs each word of `k` into every word above it: the running sum
/// that FIPS 197 section 5.2 forms one word at a time.
#[inline(always)]
unsafe fn fold(mut k: uint32x4_t) -> uint32x4_t {
    unsafe {
        let zero = vdupq_n_u32(0);
        for _ in 0..3 {
            let up = vreinterpretq_u32_u8(vextq_u8::<12>(
                vreinterpretq_u8_u32(zero),
                vreinterpretq_u8_u32(k),
            ));
            k = veorq_u32(k, up);
        }
        k
    }
}

/// The word `SubWord(RotWord(w)) ^ rcon` that starts a round key,
/// with `w` the lane `LANE` of `v`, broadcast.
#[inline(always)]
unsafe fn assist<const LANE: i32>(v: uint32x4_t, rcon: u32) -> uint32x4_t {
    unsafe {
        let w = vdupq_laneq_u32::<LANE>(v);
        veorq_u32(sub_lanes(rot_lanes(w)), vdupq_n_u32(rcon))
    }
}

/// The round constants, `x^i` in GF(2^8), for as many steps as the
/// widest schedule takes.
const RCON: [u32; 10] =
    [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES-128: ten round keys after the key itself.
#[target_feature(enable = "aes")]
unsafe fn expand128(key: &[u8], out: &mut [u32; MAX_WORDS]) {
    unsafe {
        let mut k = vld1q_u32(key.as_ptr() as *const u32);
        vst1q_u32(out.as_mut_ptr(), k);
        for (i, &rcon) in RCON.iter().enumerate() {
            k = veorq_u32(fold(k), assist::<3>(k, rcon));
            vst1q_u32(out.as_mut_ptr().add(4 * (i + 1)), k);
        }
    }
}

/// AES-192: six words a step, four in `k0` and two in the low half
/// of `k1`. The assist is on the last of the six, lane 1 of `k1`;
/// after the four are folded, their last word runs on into the two.
#[target_feature(enable = "aes")]
unsafe fn expand192(key: &[u8], out: &mut [u32; MAX_WORDS]) {
    unsafe {
        let zero = vdupq_n_u32(0);
        let mut k0 = vld1q_u32(key.as_ptr() as *const u32);
        let mut k1 = vcombine_u32(
            vld1_u32(key.as_ptr().add(16) as *const u32),
            vdup_n_u32(0),
        );
        vst1q_u32(out.as_mut_ptr(), k0);
        vst1_u32(out.as_mut_ptr().add(4), vget_low_u32(k1));
        // Eight steps make forty-eight words after the six; the last
        // step's two are beyond the schedule and are not stored.
        for (i, &rcon) in RCON[..8].iter().enumerate() {
            k0 = veorq_u32(fold(k0), assist::<1>(k1, rcon));
            let at = 6 * (i + 1);
            vst1q_u32(out.as_mut_ptr().add(at), k0);
            if at + 6 > 4 * (KeySize::Aes192.rounds() + 1) {
                break;
            }
            let up = vreinterpretq_u32_u8(vextq_u8::<12>(
                vreinterpretq_u8_u32(zero),
                vreinterpretq_u8_u32(k1),
            ));
            k1 = veorq_u32(veorq_u32(k1, up), vdupq_laneq_u32::<3>(k0));
            vst1_u32(out.as_mut_ptr().add(at + 4), vget_low_u32(k1));
        }
    }
}

/// AES-256: two round keys a step. The first takes the rotated assist
/// with the round constant, as AES-128 does; the second takes the
/// plain `SubWord` of the first's last word, with no constant.
#[target_feature(enable = "aes")]
unsafe fn expand256(key: &[u8], out: &mut [u32; MAX_WORDS]) {
    unsafe {
        let mut k0 = vld1q_u32(key.as_ptr() as *const u32);
        let mut k1 = vld1q_u32(key.as_ptr().add(16) as *const u32);
        vst1q_u32(out.as_mut_ptr(), k0);
        vst1q_u32(out.as_mut_ptr().add(4), k1);
        for (i, &rcon) in RCON[..7].iter().enumerate() {
            k0 = veorq_u32(fold(k0), assist::<3>(k1, rcon));
            vst1q_u32(out.as_mut_ptr().add(8 * (i + 1)), k0);
            if i == 6 {
                break;
            }
            let plain = sub_lanes(vdupq_laneq_u32::<3>(k0));
            k1 = veorq_u32(fold(k1), plain);
            vst1q_u32(out.as_mut_ptr().add(8 * (i + 1) + 4), k1);
        }
    }
}

/// The expanded key both ways round, built in place.
///
/// # Safety
/// Requires the AES instructions.
#[target_feature(enable = "aes")]
unsafe fn expand<const K: usize>(key: &[u8; K], size: KeySize) -> Aes<K> {
    unsafe {
        let rounds = size.rounds();
        let mut aes = Aes {
            enc: [0; MAX_WORDS],
            dec: [0; MAX_WORDS],
            size,
        };
        match size {
            KeySize::Aes128 => expand128(key, &mut aes.enc),
            KeySize::Aes192 => expand192(key, &mut aes.enc),
            KeySize::Aes256 => expand256(key, &mut aes.enc),
        }

        // Decryption runs the round keys backwards, with the inner ones
        // passed through InvMixColumns so `aesd`/`aesimc` can use them
        // directly.
        let enc = &aes.enc;
        let dec = &mut aes.dec;
        dec[..4].copy_from_slice(&enc[4 * rounds..4 * rounds + 4]);
        for r in 1..rounds {
            let src = 4 * (rounds - r);
            // SAFETY: both slices are four words; vld1q/vst1q have no
            // alignment demand.
            let k = vld1q_u8(enc[src..].as_ptr() as *const u8);
            vst1q_u8(dec[4 * r..].as_mut_ptr() as *mut u8, vaesimcq_u8(k));
        }
        dec[4 * rounds..4 * rounds + 4].copy_from_slice(&enc[..4]);
        aes
    }
}

/// Encrypts a whole number of blocks.
///
/// # Safety
/// Requires the AES instructions; `data.len()` must be a multiple of
/// 16.
unsafe fn encrypt_blocks(
    rk: &[u32; MAX_WORDS],
    rounds: usize,
    data: &mut [u8],
) {
    unsafe {
        run(
            rk.as_ptr(),
            rounds,
            data,
            encrypt8,
            [
                encrypt1, encrypt2, encrypt3, encrypt4, encrypt5, encrypt6,
                encrypt7,
            ],
        )
    }
}

/// Decrypts a whole number of blocks.
///
/// # Safety
/// Requires the AES instructions; `data.len()` must be a multiple of
/// 16.
unsafe fn decrypt_blocks(
    rk: &[u32; MAX_WORDS],
    rounds: usize,
    data: &mut [u8],
) {
    unsafe {
        run(
            rk.as_ptr(),
            rounds,
            data,
            decrypt8,
            [
                decrypt1, decrypt2, decrypt3, decrypt4, decrypt5, decrypt6,
                decrypt7,
            ],
        )
    }
}

/// A body that processes `n` blocks at `data`.
type Body = unsafe fn(*const u32, usize, *mut u8);

/// Whole groups of eight through `groups`, then the 1 to 7 leftover
/// blocks through the body of exactly that width, so the tail is one
/// interleaved pass rather than a sequence of single blocks.
///
/// # Safety
/// Requires the AES instructions; `data.len()` must be a multiple of
/// 16.
unsafe fn run(
    rk: *const u32,
    rounds: usize,
    data: &mut [u8],
    groups: unsafe fn(*const u32, usize, *mut u8, usize),
    tails: [Body; 7],
) {
    unsafe {
        let blocks = data.len() / BLOCK_SIZE;
        let full = blocks / 8;
        let mut p = data.as_mut_ptr();
        if full > 0 {
            groups(rk, rounds, p, full);
            p = p.add(full * 8 * BLOCK_SIZE);
        }
        if let Some(tail) = (blocks % 8).checked_sub(1) {
            tails[tail](rk, rounds, p);
        }
    }
}

// The bodies below are hand-written so the instruction order can be
// tuned. Blocks live in v0..v7; round keys stream through v8 (and v9
// for the last one) from memory. `aese` xors the key in before
// SubBytes, so the middle-round loop covers keys 0 to `rounds - 2`
// with `aesmc`, then the last `aese` and a plain `eor` of the final
// key. The pairing of `aese` with the `aesmc` on the same register
// matters: cores fuse the two. The `target_feature` attribute only
// tells the assembler the instructions are allowed.

/// Defines a body that runs the listed registers through the cipher
/// once; blocks are loaded and stored in order from `data`.
macro_rules! body {
    ($name:ident, $mid:literal, $mix:literal, [$($r:literal),+]) => {
        /// # Safety
        /// Requires the AES instructions; `rk` must point at
        /// `rounds + 1` round keys and `data` at the blocks this body
        /// handles.
        #[target_feature(enable = "aes")]
        unsafe fn $name(rk: *const u32, rounds: usize, data: *mut u8) {
            unsafe {
                core::arch::asm!(
                    "mov {p}, {data}",
                    $(concat!("ld1 {{", $r, ".16b}}, [{p}], #16"),)+
                    "mov {k}, {rk}",
                    "mov {n}, {nr}",
                    "2:",
                    "ld1 {{v8.16b}}, [{k}], #16",
                    $(concat!($mid, " ", $r, ".16b, v8.16b"),
                      concat!($mix, " ", $r, ".16b, ", $r, ".16b"),)+
                    "subs {n}, {n}, #1",
                    "b.ne 2b",
                    "ld1 {{v8.16b, v9.16b}}, [{k}]",
                    $(concat!($mid, " ", $r, ".16b, v8.16b"),
                      concat!("eor ", $r, ".16b, ", $r, ".16b, v9.16b"),)+
                    "mov {p}, {data}",
                    $(concat!("st1 {{", $r, ".16b}}, [{p}], #16"),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = in(reg) data,
                    p = out(reg) _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Defines the loop over whole groups of eight blocks.
macro_rules! groups {
    ($name:ident, $mid:literal, $mix:literal) => {
        /// # Safety
        /// Requires the AES instructions; `rk` must point at
        /// `rounds + 1` round keys and `data` at `groups * 128`
        /// writable bytes, `groups >= 1`.
        #[target_feature(enable = "aes")]
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            data: *mut u8,
            groups: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    "3:",
                    "add {p}, {data}, #64",
                    "ld1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{data}]",
                    "ld1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{p}]",
                    "mov {k}, {rk}",
                    "mov {n}, {nr}",
                    "2:",
                    "ld1 {{v8.16b}}, [{k}], #16",
                    concat!($mid, " v0.16b, v8.16b"),
                    concat!($mix, " v0.16b, v0.16b"),
                    concat!($mid, " v1.16b, v8.16b"),
                    concat!($mix, " v1.16b, v1.16b"),
                    concat!($mid, " v2.16b, v8.16b"),
                    concat!($mix, " v2.16b, v2.16b"),
                    concat!($mid, " v3.16b, v8.16b"),
                    concat!($mix, " v3.16b, v3.16b"),
                    concat!($mid, " v4.16b, v8.16b"),
                    concat!($mix, " v4.16b, v4.16b"),
                    concat!($mid, " v5.16b, v8.16b"),
                    concat!($mix, " v5.16b, v5.16b"),
                    concat!($mid, " v6.16b, v8.16b"),
                    concat!($mix, " v6.16b, v6.16b"),
                    concat!($mid, " v7.16b, v8.16b"),
                    concat!($mix, " v7.16b, v7.16b"),
                    "subs {n}, {n}, #1",
                    "b.ne 2b",
                    "ld1 {{v8.16b, v9.16b}}, [{k}]",
                    concat!($mid, " v0.16b, v8.16b"),
                    "eor v0.16b, v0.16b, v9.16b",
                    concat!($mid, " v1.16b, v8.16b"),
                    "eor v1.16b, v1.16b, v9.16b",
                    concat!($mid, " v2.16b, v8.16b"),
                    "eor v2.16b, v2.16b, v9.16b",
                    concat!($mid, " v3.16b, v8.16b"),
                    "eor v3.16b, v3.16b, v9.16b",
                    concat!($mid, " v4.16b, v8.16b"),
                    "eor v4.16b, v4.16b, v9.16b",
                    concat!($mid, " v5.16b, v8.16b"),
                    "eor v5.16b, v5.16b, v9.16b",
                    concat!($mid, " v6.16b, v8.16b"),
                    "eor v6.16b, v6.16b, v9.16b",
                    concat!($mid, " v7.16b, v8.16b"),
                    "eor v7.16b, v7.16b, v9.16b",
                    "st1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{data}], #64",
                    "st1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{data}], #64",
                    "subs {groups}, {groups}, #1",
                    "b.ne 3b",
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    p = out(reg) _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _,
                    options(nostack),
                );
            }
        }
    };
}

groups!(encrypt8, "aese", "aesmc");
groups!(decrypt8, "aesd", "aesimc");

body!(encrypt1, "aese", "aesmc", ["v0"]);
body!(encrypt2, "aese", "aesmc", ["v0", "v1"]);
body!(encrypt3, "aese", "aesmc", ["v0", "v1", "v2"]);
body!(encrypt4, "aese", "aesmc", ["v0", "v1", "v2", "v3"]);
body!(encrypt5, "aese", "aesmc", ["v0", "v1", "v2", "v3", "v4"]);
body!(
    encrypt6,
    "aese",
    "aesmc",
    ["v0", "v1", "v2", "v3", "v4", "v5"]
);
body!(
    encrypt7,
    "aese",
    "aesmc",
    ["v0", "v1", "v2", "v3", "v4", "v5", "v6"]
);

body!(decrypt1, "aesd", "aesimc", ["v0"]);
body!(decrypt2, "aesd", "aesimc", ["v0", "v1"]);
body!(decrypt3, "aesd", "aesimc", ["v0", "v1", "v2"]);
body!(decrypt4, "aesd", "aesimc", ["v0", "v1", "v2", "v3"]);
body!(decrypt5, "aesd", "aesimc", ["v0", "v1", "v2", "v3", "v4"]);
body!(
    decrypt6,
    "aesd",
    "aesimc",
    ["v0", "v1", "v2", "v3", "v4", "v5"]
);
body!(
    decrypt7,
    "aesd",
    "aesimc",
    ["v0", "v1", "v2", "v3", "v4", "v5", "v6"]
);
