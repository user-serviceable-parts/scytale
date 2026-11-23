//! AES using the AES-NI instructions on 128-bit registers, with the
//! block loops in hand-written assembly.
//!
//! The loops run eight blocks through each round together: the
//! instruction is pipelined, so eight independent blocks keep it busy
//! where one block would wait on its own result. This is the
//! interleave Intel recommends for ECB-style processing. A tail of
//! fewer blocks goes through one pass of exactly its width.
//!
//! The S-box lives in hardware, so unlike the table-driven portable
//! implementation this one does not leak key material through cache
//! timing.
//!
//! # Availability
//!
//! [`Aes::supported`] says whether this processor has AES-NI.
//! [`Aes::new`] panics without it, so the dispatching cipher asks
//! first; nothing outside this crate can name the type.
//!

use core::fmt;

use super::RoundKeys;
use crate::cipher::aes::BLOCK_SIZE;
use crate::features::Chosen;
use zeroize::ZeroizeOnDrop;

/// An AES cipher with an expanded key, using AES-NI.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::new`]; the key is wiped on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes<const K: usize> {
    keys: RoundKeys,
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
        (chosen.kernel() == super::super::Kernel::AesNi)
            .then(|| unsafe { Self::new_unchecked(key) })
    }

    /// Expands `key` without checking for AES-NI.
    ///
    /// # Safety
    /// The caller must have confirmed that AES-NI is available.
    pub(crate) unsafe fn new_unchecked(key: &[u8; K]) -> Self {
        unsafe {
            let size = super::KeySize::for_key(key);
            Aes {
                keys: RoundKeys::new(key, size),
            }
        }
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.keys.size.rounds()
    }

    /// Encrypts every block in place, independently (ECB).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        // SAFETY: the struct only exists if try_new confirmed AES-NI.
        unsafe { encrypt_blocks(&self.keys, blocks.as_flattened_mut()) }
    }

    /// Decrypts every block in place, independently (ECB).
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        // SAFETY: the struct only exists if try_new confirmed AES-NI.
        unsafe { decrypt_blocks(&self.keys, blocks.as_flattened_mut()) }
    }
}

impl<const K: usize> super::Keyed for Aes<K> {
    /// Always: this implementation exists only where they do.
    fn schedule(&self) -> Option<super::Schedule<'_>> {
        Some(super::Schedule::new(&self.keys))
    }

    fn decryption(&self) -> Option<super::Schedule<'_>> {
        Some(super::Schedule::inverse(&self.keys))
    }
}

impl<const K: usize> Aes<K> {}

/// Encrypts a whole number of blocks.
///
/// # Safety
/// Requires AES-NI; `data.len()` must be a multiple of 16.
pub(super) unsafe fn encrypt_blocks(keys: &RoundKeys, data: &mut [u8]) {
    unsafe {
        run(
            keys.enc.as_ptr(),
            keys.size.rounds(),
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
/// Requires AES-NI; `data.len()` must be a multiple of 16.
pub(super) unsafe fn decrypt_blocks(keys: &RoundKeys, data: &mut [u8]) {
    unsafe {
        run(
            keys.dec.as_ptr(),
            keys.size.rounds(),
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
/// Requires AES-NI; `data.len()` must be a multiple of 16.
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
// tuned. Blocks live in xmm0..xmm7; round keys stream through xmm8
// from memory (always via `movdqu`: the key array is not 16-byte
// aligned, which legacy SSE memory operands require). The middle
// rounds loop over the key pointer, so one body serves all key sizes.

/// Defines a body that runs the listed registers, loaded from the
/// listed byte offsets, through the cipher once.
macro_rules! body {
    ($name:ident, $mid:literal, $last:literal,
     [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires AES-NI; `rk` must point at `rounds + 1` round keys
        /// and `data` at the blocks this body handles.
        unsafe fn $name(rk: *const u32, rounds: usize, data: *mut u8) {
            unsafe {
                core::arch::asm!(
                    "movdqu xmm8, [{rk}]",
                    $(concat!("movdqu ", $r, ", [{data} + ", $off, "]"),)+
                    $(concat!("pxor ", $r, ", xmm8"),)+
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "movdqu xmm8, [{k}]",
                    $(concat!($mid, " ", $r, ", xmm8"),)+
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "movdqu xmm8, [{k}]",
                    $(concat!($last, " ", $r, ", xmm8"),)+
                    $(concat!("movdqu [{data} + ", $off, "], ", $r),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = in(reg) data,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Defines the loop over whole groups of eight blocks.
macro_rules! groups {
    ($name:ident, $mid:literal, $last:literal) => {
        /// # Safety
        /// Requires AES-NI; `rk` must point at `rounds + 1` round keys
        /// and `data` at `groups * 128` writable bytes, `groups >= 1`.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            data: *mut u8,
            groups: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    "3:",
                    "movdqu xmm8, [{rk}]",
                    "movdqu xmm0, [{data}]",
                    "movdqu xmm1, [{data} + 16]",
                    "movdqu xmm2, [{data} + 32]",
                    "movdqu xmm3, [{data} + 48]",
                    "movdqu xmm4, [{data} + 64]",
                    "movdqu xmm5, [{data} + 80]",
                    "movdqu xmm6, [{data} + 96]",
                    "movdqu xmm7, [{data} + 112]",
                    "pxor xmm0, xmm8",
                    "pxor xmm1, xmm8",
                    "pxor xmm2, xmm8",
                    "pxor xmm3, xmm8",
                    "pxor xmm4, xmm8",
                    "pxor xmm5, xmm8",
                    "pxor xmm6, xmm8",
                    "pxor xmm7, xmm8",
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "movdqu xmm8, [{k}]",
                    concat!($mid, " xmm0, xmm8"),
                    concat!($mid, " xmm1, xmm8"),
                    concat!($mid, " xmm2, xmm8"),
                    concat!($mid, " xmm3, xmm8"),
                    concat!($mid, " xmm4, xmm8"),
                    concat!($mid, " xmm5, xmm8"),
                    concat!($mid, " xmm6, xmm8"),
                    concat!($mid, " xmm7, xmm8"),
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "movdqu xmm8, [{k}]",
                    concat!($last, " xmm0, xmm8"),
                    concat!($last, " xmm1, xmm8"),
                    concat!($last, " xmm2, xmm8"),
                    concat!($last, " xmm3, xmm8"),
                    concat!($last, " xmm4, xmm8"),
                    concat!($last, " xmm5, xmm8"),
                    concat!($last, " xmm6, xmm8"),
                    concat!($last, " xmm7, xmm8"),
                    "movdqu [{data}], xmm0",
                    "movdqu [{data} + 16], xmm1",
                    "movdqu [{data} + 32], xmm2",
                    "movdqu [{data} + 48], xmm3",
                    "movdqu [{data} + 64], xmm4",
                    "movdqu [{data} + 80], xmm5",
                    "movdqu [{data} + 96], xmm6",
                    "movdqu [{data} + 112], xmm7",
                    "add {data}, 128",
                    "dec {groups}",
                    "jnz 3b",
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _,
                    options(nostack),
                );
            }
        }
    };
}

groups!(encrypt8, "aesenc", "aesenclast");
groups!(decrypt8, "aesdec", "aesdeclast");

body!(encrypt1, "aesenc", "aesenclast", [("xmm0", "0")]);
body!(
    encrypt2,
    "aesenc",
    "aesenclast",
    [("xmm0", "0"), ("xmm1", "16")]
);
body!(
    encrypt3,
    "aesenc",
    "aesenclast",
    [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]
);
body!(
    encrypt4,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
body!(
    encrypt5,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
body!(
    encrypt6,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
body!(
    encrypt7,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80"),
        ("xmm6", "96")
    ]
);

body!(decrypt1, "aesdec", "aesdeclast", [("xmm0", "0")]);
body!(
    decrypt2,
    "aesdec",
    "aesdeclast",
    [("xmm0", "0"), ("xmm1", "16")]
);
body!(
    decrypt3,
    "aesdec",
    "aesdeclast",
    [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]
);
body!(
    decrypt4,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
body!(
    decrypt5,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
body!(
    decrypt6,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
body!(
    decrypt7,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80"),
        ("xmm6", "96")
    ]
);
