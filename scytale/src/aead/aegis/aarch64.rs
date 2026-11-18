//! AEGIS on the ARMv8 AES instructions, with the loops in
//! hand-written assembly.
//!
//! The round AEGIS is built from is `aese` against a register of
//! zeros, which is SubBytes and ShiftRows with no key going in,
//! `aesmc` for MixColumns, and an `eor` for what the draft calls the
//! round key. The `aesmc` follows its `aese` directly and on the
//! same register, every time: the processor fuses the pair, and does
//! not if anything stands between them.
//!
//! An update of the state is one of those for each block, none
//! waiting on another, so the processor runs them side by side.
//!
//! # The state moves through the registers
//!
//! `aese` writes over the block it is given, as `aesenc` does on
//! x86-64, so the loop has the shape it has there and for the same
//! reason: it is written out once for each place the state can lie,
//! eight for AEGIS-128L and six for AEGIS-256, the state is back
//! where it started at the bottom, and a message that ends part of
//! the way down leaves through the store for the place it had
//! reached. See [`x86_64`](super) for the argument.
//!
//! The registers are `v0` on for the state and `v16` on for the
//! rest, which leaves alone the eight a function must preserve.
//!
//! # Availability
//!
//! The callers name this kernel only where its row of their list is
//! in force, which is where the processor has the AES instructions.
//!
//! The input pointer moves on by a step the caller gives, so that the
//! one loop takes a run of blocks and also one block many times over,
//! which is what `Init` and `Finalize` do.

#![allow(unsafe_code)]

use super::State;

/// Calls `$body` with a label and the numbers of the registers
/// holding S0 to S7, in order, for each of the eight places the
/// AEGIS-128L state can lie.
macro_rules! rotations128l {
    ($body:ident) => {
        concat!(
            $body!("30", "0", "1", "2", "3", "4", "5", "6", "7"),
            $body!("31", "7", "0", "1", "2", "3", "4", "5", "6"),
            $body!("32", "6", "7", "0", "1", "2", "3", "4", "5"),
            $body!("33", "5", "6", "7", "0", "1", "2", "3", "4"),
            $body!("34", "4", "5", "6", "7", "0", "1", "2", "3"),
            $body!("35", "3", "4", "5", "6", "7", "0", "1", "2"),
            $body!("36", "2", "3", "4", "5", "6", "7", "0", "1"),
            $body!("37", "1", "2", "3", "4", "5", "6", "7", "0"),
        )
    };
}

/// One round: register `$in` through SubBytes, ShiftRows and
/// MixColumns, then `$key` xored in. `v16` is zero.
macro_rules! round {
    ($in:literal, $key:literal) => {
        concat!(
            "aese v",
            $in,
            ".16b, v16.16b\n",
            "aesmc v",
            $in,
            ".16b, v",
            $in,
            ".16b\n",
            "eor v",
            $in,
            ".16b, v",
            $in,
            ".16b, v",
            $key,
            ".16b\n",
        )
    };
}

/// The AEGIS-128L update, for M0 in `v17` and M1 in `v18`, then on to
/// the next block of input, leaving through the store at `$label` if
/// that was the last. The new S0 is left where S7 was, and every
/// other block where the one before it was.
macro_rules! update128l {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal, $s6:literal, $s7:literal) => {
        concat!(
            "eor v17.16b, v17.16b, v",
            $s0,
            ".16b\n",
            "eor v18.16b, v18.16b, v",
            $s4,
            ".16b\n",
            round!($s0, $s1),
            round!($s1, $s2),
            round!($s2, $s3),
            round!($s3, "18"),
            round!($s4, $s5),
            round!($s5, $s6),
            round!($s6, $s7),
            round!($s7, "17"),
            "subs {n}, {n}, #1\n",
            "b.eq ",
            $label,
            "f\n",
        )
    };
}

/// The AEGIS-128L keystream: z0 into `v19` and z1 into `v20`.
macro_rules! keystream128l {
    ($s1:literal, $s2:literal, $s3:literal, $s5:literal, $s6:literal,
     $s7:literal) => {
        concat!(
            "and v19.16b, v",
            $s2,
            ".16b, v",
            $s3,
            ".16b\n",
            "and v20.16b, v",
            $s6,
            ".16b, v",
            $s7,
            ".16b\n",
            "eor v19.16b, v19.16b, v",
            $s1,
            ".16b\n",
            "eor v20.16b, v20.16b, v",
            $s2,
            ".16b\n",
            "eor v19.16b, v19.16b, v",
            $s6,
            ".16b\n",
            "eor v20.16b, v20.16b, v",
            $s5,
            ".16b\n",
        )
    };
}

macro_rules! absorb128l {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal, $s6:literal, $s7:literal) => {
        concat!(
            "ld1 {{v17.16b, v18.16b}}, [{data}], {step}\n",
            update128l!($label, $s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7),
        )
    };
}

macro_rules! encrypt128l {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal, $s6:literal, $s7:literal) => {
        concat!(
            "ld1 {{v17.16b, v18.16b}}, [{data}]\n",
            keystream128l!($s1, $s2, $s3, $s5, $s6, $s7),
            "eor v19.16b, v19.16b, v17.16b\n",
            "eor v20.16b, v20.16b, v18.16b\n",
            "st1 {{v19.16b, v20.16b}}, [{data}], {step}\n",
            update128l!($label, $s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7),
        )
    };
}

/// As encryption, but the state is updated with what comes out
/// rather than with what went in.
macro_rules! decrypt128l {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal, $s6:literal, $s7:literal) => {
        concat!(
            "ld1 {{v17.16b, v18.16b}}, [{data}]\n",
            keystream128l!($s1, $s2, $s3, $s5, $s6, $s7),
            "eor v17.16b, v17.16b, v19.16b\n",
            "eor v18.16b, v18.16b, v20.16b\n",
            "st1 {{v17.16b, v18.16b}}, [{data}], {step}\n",
            update128l!($label, $s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7),
        )
    };
}

/// Where a message that ended after the update of the same label
/// leaves: the state as that update left it, back to memory in
/// order.
macro_rules! store128l {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal, $s6:literal, $s7:literal) => {
        concat!(
            $label,
            ":\n",
            "stp q",
            $s7,
            ", q",
            $s0,
            ", [{state}]\n",
            "stp q",
            $s1,
            ", q",
            $s2,
            ", [{state}, #32]\n",
            "stp q",
            $s3,
            ", q",
            $s4,
            ", [{state}, #64]\n",
            "stp q",
            $s5,
            ", q",
            $s6,
            ", [{state}, #96]\n",
            "b 4f\n",
        )
    };
}

macro_rules! load128l {
    () => {
        "ldp q0, q1, [{state}]\n\
         ldp q2, q3, [{state}, #32]\n\
         ldp q4, q5, [{state}, #64]\n\
         ldp q6, q7, [{state}, #96]\n"
    };
}

/// As [`rotations128l`], for the six places the AEGIS-256 state can
/// lie, S0 to S5.
macro_rules! rotations256 {
    ($body:ident) => {
        concat!(
            $body!("30", "0", "1", "2", "3", "4", "5"),
            $body!("31", "5", "0", "1", "2", "3", "4"),
            $body!("32", "4", "5", "0", "1", "2", "3"),
            $body!("33", "3", "4", "5", "0", "1", "2"),
            $body!("34", "2", "3", "4", "5", "0", "1"),
            $body!("35", "1", "2", "3", "4", "5", "0"),
        )
    };
}

/// The AEGIS-256 update, for M in `v17`; see [`update128l`].
macro_rules! update256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            "eor v17.16b, v17.16b, v",
            $s0,
            ".16b\n",
            round!($s0, $s1),
            round!($s1, $s2),
            round!($s2, $s3),
            round!($s3, $s4),
            round!($s4, $s5),
            round!($s5, "17"),
            "subs {n}, {n}, #1\n",
            "b.eq ",
            $label,
            "f\n",
        )
    };
}

/// The AEGIS-256 keystream, into `v19`.
macro_rules! keystream256 {
    ($s1:literal, $s2:literal, $s3:literal, $s4:literal, $s5:literal) => {
        concat!(
            "and v19.16b, v",
            $s2,
            ".16b, v",
            $s3,
            ".16b\n",
            "eor v20.16b, v",
            $s4,
            ".16b, v",
            $s5,
            ".16b\n",
            "eor v19.16b, v19.16b, v",
            $s1,
            ".16b\n",
            "eor v19.16b, v19.16b, v20.16b\n",
        )
    };
}

macro_rules! absorb256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            "ld1 {{v17.16b}}, [{data}], {step}\n",
            update256!($label, $s0, $s1, $s2, $s3, $s4, $s5),
        )
    };
}

macro_rules! encrypt256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            "ld1 {{v17.16b}}, [{data}]\n",
            keystream256!($s1, $s2, $s3, $s4, $s5),
            "eor v19.16b, v19.16b, v17.16b\n",
            "st1 {{v19.16b}}, [{data}], {step}\n",
            update256!($label, $s0, $s1, $s2, $s3, $s4, $s5),
        )
    };
}

macro_rules! decrypt256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            "ld1 {{v17.16b}}, [{data}]\n",
            keystream256!($s1, $s2, $s3, $s4, $s5),
            "eor v17.16b, v17.16b, v19.16b\n",
            "st1 {{v17.16b}}, [{data}], {step}\n",
            update256!($label, $s0, $s1, $s2, $s3, $s4, $s5),
        )
    };
}

macro_rules! store256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            $label,
            ":\n",
            "stp q",
            $s5,
            ", q",
            $s0,
            ", [{state}]\n",
            "stp q",
            $s1,
            ", q",
            $s2,
            ", [{state}, #32]\n",
            "stp q",
            $s3,
            ", q",
            $s4,
            ", [{state}, #64]\n",
            "b 4f\n",
        )
    };
}

macro_rules! load256 {
    () => {
        "ldp q0, q1, [{state}]\n\
         ldp q2, q3, [{state}, #32]\n\
         ldp q4, q5, [{state}, #64]\n"
    };
}

/// Defines a kernel: the state into the registers, `$body` for each
/// block of input round the places the state can lie, and the state
/// back from wherever the input ended.
macro_rules! kernel {
    ($(#[$doc:meta])* $name:ident, $data:ty, $load:ident,
     $rotations:ident, $body:ident, $store:ident) => {
        $(#[$doc])*
        ///
        /// # Safety
        /// Requires the AES instructions; `data` must point at
        /// `blocks` blocks of input, each `step` bytes on from the
        /// last, and `blocks >= 1`.
        #[target_feature(enable = "aes")]
        unsafe fn $name(
            state: &mut State,
            data: $data,
            step: usize,
            blocks: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    "movi v16.16b, #0",
                    $load!(),
                    "2:",
                    $rotations!($body),
                    "b 2b",
                    $rotations!($store),
                    "4:",
                    state = in(reg) state.as_mut_ptr(),
                    data = inout(reg) data => _,
                    step = in(reg) step,
                    n = inout(reg) blocks => _,
                    out("v0") _, out("v1") _, out("v2") _,
                    out("v3") _, out("v4") _, out("v5") _,
                    out("v6") _, out("v7") _, out("v16") _,
                    out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _,
                    options(nostack),
                );
            }
        }
    };
}

kernel!(
    /// The AEGIS-128L `Absorb`.
    run_absorb128l,
    *const u8,
    load128l,
    rotations128l,
    absorb128l,
    store128l
);
kernel!(
    /// The AEGIS-128L `Enc`, in place.
    run_encrypt128l,
    *mut u8,
    load128l,
    rotations128l,
    encrypt128l,
    store128l
);
kernel!(
    /// The AEGIS-128L `Dec`, in place.
    run_decrypt128l,
    *mut u8,
    load128l,
    rotations128l,
    decrypt128l,
    store128l
);
kernel!(
    /// The AEGIS-256 `Absorb`.
    run_absorb256,
    *const u8,
    load256,
    rotations256,
    absorb256,
    store256
);
kernel!(
    /// The AEGIS-256 `Enc`, in place.
    run_encrypt256,
    *mut u8,
    load256,
    rotations256,
    encrypt256,
    store256
);
kernel!(
    /// The AEGIS-256 `Dec`, in place.
    run_decrypt256,
    *mut u8,
    load256,
    rotations256,
    decrypt256,
    store256
);

entries!(
    32,
    run_absorb128l,
    run_encrypt128l,
    run_decrypt128l,
    absorb128l,
    stir128l,
    encrypt128l,
    decrypt128l
);
entries!(
    16,
    run_absorb256,
    run_encrypt256,
    run_decrypt256,
    absorb256,
    stir256,
    encrypt256,
    decrypt256
);
