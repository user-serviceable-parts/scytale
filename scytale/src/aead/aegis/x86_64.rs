//! AEGIS on the AES-NI instructions, with the loops in hand-written
//! assembly.
//!
//! `aesenc` is the whole of the round AEGIS is built from: it puts
//! its first operand through SubBytes, ShiftRows and MixColumns and
//! xors the second in. An update of the state is one of those for
//! each block, none waiting on another, so the processor runs them
//! side by side and an update costs about one round's latency.
//!
//! # The state moves through the registers
//!
//! `aesenc` writes over its first operand. In an update every block
//! is the first operand once, to make its successor, and the second
//! once, as its own next value is made; so the new block `i` can only
//! go where the old block `i - 1` was, and the state has moved round
//! one register by the end. Copying it back would cost as many moves
//! as there are rounds. Instead the loop is written out once for each
//! place the state can lie, eight for AEGIS-128L and six for
//! AEGIS-256, and the state is back where it started at the bottom.
//! A message that ends part of the way down leaves through the store
//! for the place it had reached.
//!
//! One block is still copied in each update: the one whose register
//! is written first and whose old value is wanted last. A register
//! move costs nothing to wait for.
//!
//! # Where the message goes in
//!
//! The draft gives a block that takes message the round of its
//! neighbour with `block ^ message` as the key. Here the round takes
//! the message alone as its key and the block is xored in after it,
//! which is the same value. The difference is in what the next
//! update waits for: a block's old value reaches its new one through
//! one xor, and not through an xor and then a round. Measured on a
//! Raptor Lake core, where an xor between two rounds costs as much
//! as a round, that took the AEGIS-256 update from 6.4 cycles to 4.7.
//! Decryption goes a step further for the same reason; see
//! `decrypt128l` below.
//!
//! # Availability
//!
//! These are in the legacy SSE encoding, so they need the AES
//! instructions and nothing newer. The callers name this kernel only
//! where its row of their list is in force.
//!
//! The input pointer moves on by a step the caller gives, so that the
//! one loop takes a run of blocks and also one block many times over,
//! which is what `Init` and `Finalize` do.

#![allow(unsafe_code)]

use super::State;

/// Calls `$body` with a label and the registers holding S0 to S7, in
/// order, for each of the eight places the AEGIS-128L state can lie.
macro_rules! rotations128l {
    ($body:ident) => {
        concat!(
            $body!(
                "30", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6",
                "xmm7"
            ),
            $body!(
                "31", "xmm7", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
                "xmm6"
            ),
            $body!(
                "32", "xmm6", "xmm7", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
                "xmm5"
            ),
            $body!(
                "33", "xmm5", "xmm6", "xmm7", "xmm0", "xmm1", "xmm2", "xmm3",
                "xmm4"
            ),
            $body!(
                "34", "xmm4", "xmm5", "xmm6", "xmm7", "xmm0", "xmm1", "xmm2",
                "xmm3"
            ),
            $body!(
                "35", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm0", "xmm1",
                "xmm2"
            ),
            $body!(
                "36", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm0",
                "xmm1"
            ),
            $body!(
                "37", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
                "xmm0"
            ),
        )
    };
}

/// On to the next block of input, leaving through the store at
/// `$label` if that was the last.
macro_rules! next {
    ($label:literal) => {
        concat!("add {data}, {step}\n", "dec {n}\n", "jz ", $label, "f\n")
    };
}

/// The AEGIS-128L update, for M0 in `xmm8` and M1 in `xmm9`. The new
/// S0 is left where S7 was, and every other block where the one
/// before it was.
///
/// The two blocks that take a block of message take it as the
/// round's key and have their own old value xored in afterwards,
/// rather than the two xored first and given to the round together.
/// The answer is the same and the wait is not: a block's old value
/// then reaches its new one through an xor alone, where the other
/// way round it goes through the xor and then the round, every
/// update. S0 is kept in `xmm12` for that, since its register is
/// the first written and it is wanted last.
macro_rules! update128l {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal, $s6:literal, $s7:literal) => {
        concat!(
            "movdqa xmm12, ",
            $s0,
            "\n",
            "aesenc ",
            $s0,
            ", ",
            $s1,
            "\n",
            "aesenc ",
            $s1,
            ", ",
            $s2,
            "\n",
            "aesenc ",
            $s2,
            ", ",
            $s3,
            "\n",
            "aesenc ",
            $s3,
            ", xmm9\n",
            "pxor ",
            $s3,
            ", ",
            $s4,
            "\n",
            "aesenc ",
            $s4,
            ", ",
            $s5,
            "\n",
            "aesenc ",
            $s5,
            ", ",
            $s6,
            "\n",
            "aesenc ",
            $s6,
            ", ",
            $s7,
            "\n",
            "aesenc ",
            $s7,
            ", xmm8\n",
            "pxor ",
            $s7,
            ", xmm12\n",
            next!($label),
        )
    };
}

/// The AEGIS-128L keystream: z0 into `xmm10` and z1 into `xmm11`.
macro_rules! keystream128l {
    ($s1:literal, $s2:literal, $s3:literal, $s5:literal, $s6:literal,
     $s7:literal) => {
        concat!(
            "movdqa xmm10, ",
            $s2,
            "\n",
            "movdqa xmm11, ",
            $s6,
            "\n",
            "pand xmm10, ",
            $s3,
            "\n",
            "pand xmm11, ",
            $s7,
            "\n",
            "pxor xmm10, ",
            $s1,
            "\n",
            "pxor xmm11, ",
            $s2,
            "\n",
            "pxor xmm10, ",
            $s6,
            "\n",
            "pxor xmm11, ",
            $s5,
            "\n",
        )
    };
}

/// The two blocks of input, into `xmm8` and `xmm9`.
macro_rules! input128l {
    () => {
        "movdqu xmm8, [{data}]\nmovdqu xmm9, [{data} + {second}]\n"
    };
}

macro_rules! absorb128l {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal, $s6:literal, $s7:literal) => {
        concat!(
            input128l!(),
            update128l!($label, $s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7),
        )
    };
}

macro_rules! encrypt128l {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal, $s6:literal, $s7:literal) => {
        concat!(
            input128l!(),
            keystream128l!($s1, $s2, $s3, $s5, $s6, $s7),
            "pxor xmm10, xmm8\n",
            "pxor xmm11, xmm9\n",
            "movdqu [{data}], xmm10\n",
            "movdqu [{data} + {second}], xmm11\n",
            update128l!($label, $s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7),
        )
    };
}

/// Decryption, which updates the state with what comes out rather
/// than with what went in, and what comes out is made from the
/// state. Of the blocks the keystream is made from, S1 and S5 were
/// the two written by the update before, from the blocks that took
/// its message, so they are the last to arrive; each is given to the
/// round as its key and everything else is xored in afterwards,
/// which keeps them off the path the next update waits on.
macro_rules! decrypt128l {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal, $s6:literal, $s7:literal) => {
        concat!(
            input128l!(),
            // All of each block but its late one: the ciphertext
            // with the rest of the keystream.
            "movdqa xmm10, ",
            $s2,
            "\n",
            "movdqa xmm11, ",
            $s6,
            "\n",
            "pand xmm10, ",
            $s3,
            "\n",
            "pand xmm11, ",
            $s7,
            "\n",
            "pxor xmm10, ",
            $s6,
            "\n",
            "pxor xmm11, ",
            $s2,
            "\n",
            "pxor xmm10, xmm8\n",
            "pxor xmm11, xmm9\n",
            "movdqa xmm12, ",
            $s1,
            "\n",
            // The message, for the output alone.
            "movdqa xmm8, xmm10\n",
            "movdqa xmm9, xmm11\n",
            "pxor xmm8, ",
            $s1,
            "\n",
            "pxor xmm9, ",
            $s5,
            "\n",
            "movdqu [{data}], xmm8\n",
            "movdqu [{data} + {second}], xmm9\n",
            "pxor xmm10, ",
            $s0,
            "\n",
            "pxor xmm11, ",
            $s4,
            "\n",
            "aesenc ",
            $s0,
            ", ",
            $s1,
            "\n",
            "aesenc ",
            $s1,
            ", ",
            $s2,
            "\n",
            "aesenc ",
            $s2,
            ", ",
            $s3,
            "\n",
            "aesenc ",
            $s3,
            ", ",
            $s5,
            "\n",
            "pxor ",
            $s3,
            ", xmm11\n",
            "aesenc ",
            $s4,
            ", ",
            $s5,
            "\n",
            "aesenc ",
            $s5,
            ", ",
            $s6,
            "\n",
            "aesenc ",
            $s6,
            ", ",
            $s7,
            "\n",
            "aesenc ",
            $s7,
            ", xmm12\n",
            "pxor ",
            $s7,
            ", xmm10\n",
            next!($label),
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
            "movdqu [{state}], ",
            $s7,
            "\n",
            "movdqu [{state} + 16], ",
            $s0,
            "\n",
            "movdqu [{state} + 32], ",
            $s1,
            "\n",
            "movdqu [{state} + 48], ",
            $s2,
            "\n",
            "movdqu [{state} + 64], ",
            $s3,
            "\n",
            "movdqu [{state} + 80], ",
            $s4,
            "\n",
            "movdqu [{state} + 96], ",
            $s5,
            "\n",
            "movdqu [{state} + 112], ",
            $s6,
            "\n",
            "jmp 4f\n",
        )
    };
}

macro_rules! load128l {
    () => {
        "movdqu xmm0, [{state}]\n\
         movdqu xmm1, [{state} + 16]\n\
         movdqu xmm2, [{state} + 32]\n\
         movdqu xmm3, [{state} + 48]\n\
         movdqu xmm4, [{state} + 64]\n\
         movdqu xmm5, [{state} + 80]\n\
         movdqu xmm6, [{state} + 96]\n\
         movdqu xmm7, [{state} + 112]\n"
    };
}

/// As [`rotations128l`], for the six places the AEGIS-256 state can
/// lie, S0 to S5.
macro_rules! rotations256 {
    ($body:ident) => {
        concat!(
            $body!("30", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"),
            $body!("31", "xmm5", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4"),
            $body!("32", "xmm4", "xmm5", "xmm0", "xmm1", "xmm2", "xmm3"),
            $body!("33", "xmm3", "xmm4", "xmm5", "xmm0", "xmm1", "xmm2"),
            $body!("34", "xmm2", "xmm3", "xmm4", "xmm5", "xmm0", "xmm1"),
            $body!("35", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm0"),
        )
    };
}

/// The AEGIS-256 update, for M in `xmm8`; see [`update128l`]. S0 is
/// kept in `xmm9`.
macro_rules! update256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            "movdqa xmm9, ",
            $s0,
            "\n",
            "aesenc ",
            $s0,
            ", ",
            $s1,
            "\n",
            "aesenc ",
            $s1,
            ", ",
            $s2,
            "\n",
            "aesenc ",
            $s2,
            ", ",
            $s3,
            "\n",
            "aesenc ",
            $s3,
            ", ",
            $s4,
            "\n",
            "aesenc ",
            $s4,
            ", ",
            $s5,
            "\n",
            "aesenc ",
            $s5,
            ", xmm8\n",
            "pxor ",
            $s5,
            ", xmm9\n",
            next!($label),
        )
    };
}

/// The AEGIS-256 keystream, into `xmm10`.
macro_rules! keystream256 {
    ($s1:literal, $s2:literal, $s3:literal, $s4:literal, $s5:literal) => {
        concat!(
            "movdqa xmm10, ",
            $s2,
            "\n",
            "pand xmm10, ",
            $s3,
            "\n",
            "pxor xmm10, ",
            $s1,
            "\n",
            "pxor xmm10, ",
            $s4,
            "\n",
            "pxor xmm10, ",
            $s5,
            "\n",
        )
    };
}

macro_rules! absorb256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            "movdqu xmm8, [{data}]\n",
            update256!($label, $s0, $s1, $s2, $s3, $s4, $s5),
        )
    };
}

macro_rules! encrypt256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            "movdqu xmm8, [{data}]\n",
            keystream256!($s1, $s2, $s3, $s4, $s5),
            "pxor xmm10, xmm8\n",
            "movdqu [{data}], xmm10\n",
            update256!($label, $s0, $s1, $s2, $s3, $s4, $s5),
        )
    };
}

/// Decryption; see [`decrypt128l`]. S1 is the block that arrives
/// last, and is kept in `xmm9` to be the round's key.
macro_rules! decrypt256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            "movdqu xmm8, [{data}]\n",
            "movdqa xmm10, ",
            $s2,
            "\n",
            "movdqa xmm9, ",
            $s1,
            "\n",
            "pand xmm10, ",
            $s3,
            "\n",
            "pxor xmm8, ",
            $s4,
            "\n",
            "pxor xmm10, ",
            $s5,
            "\n",
            "pxor xmm10, xmm8\n",
            "movdqa xmm11, xmm10\n",
            "pxor xmm11, ",
            $s1,
            "\n",
            "movdqu [{data}], xmm11\n",
            "pxor xmm10, ",
            $s0,
            "\n",
            "aesenc ",
            $s0,
            ", ",
            $s1,
            "\n",
            "aesenc ",
            $s1,
            ", ",
            $s2,
            "\n",
            "aesenc ",
            $s2,
            ", ",
            $s3,
            "\n",
            "aesenc ",
            $s3,
            ", ",
            $s4,
            "\n",
            "aesenc ",
            $s4,
            ", ",
            $s5,
            "\n",
            "aesenc ",
            $s5,
            ", xmm9\n",
            "pxor ",
            $s5,
            ", xmm10\n",
            next!($label),
        )
    };
}

macro_rules! store256 {
    ($label:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal,
     $s4:literal, $s5:literal) => {
        concat!(
            $label,
            ":\n",
            "movdqu [{state}], ",
            $s5,
            "\n",
            "movdqu [{state} + 16], ",
            $s0,
            "\n",
            "movdqu [{state} + 32], ",
            $s1,
            "\n",
            "movdqu [{state} + 48], ",
            $s2,
            "\n",
            "movdqu [{state} + 64], ",
            $s3,
            "\n",
            "movdqu [{state} + 80], ",
            $s4,
            "\n",
            "jmp 4f\n",
        )
    };
}

macro_rules! load256 {
    () => {
        "movdqu xmm0, [{state}]\n\
         movdqu xmm1, [{state} + 16]\n\
         movdqu xmm2, [{state} + 32]\n\
         movdqu xmm3, [{state} + 48]\n\
         movdqu xmm4, [{state} + 64]\n\
         movdqu xmm5, [{state} + 80]\n"
    };
}

/// Defines a kernel: the state into the registers, `$body` for each
/// block of input round the places the state can lie, and the state
/// back from wherever the input ended. A `halves` kernel takes its
/// block in two pieces `second` bytes apart, and a `whole` one in
/// one.
macro_rules! kernel {
    (halves, $(#[$doc:meta])* $name:ident, $data:ty, $load:ident,
     $rotations:ident, $body:ident, $store:ident) => {
        $(#[$doc])*
        ///
        /// # Safety
        /// Requires the AES instructions; `data` must point at
        /// `blocks` blocks of input, each `step` bytes on from the
        /// last and each with a second piece `second` bytes on from
        /// its first, and `blocks >= 1`.
        unsafe fn $name(
            state: &mut State,
            data: $data,
            second: usize,
            step: usize,
            blocks: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    $load!(),
                    "2:",
                    $rotations!($body),
                    "jmp 2b",
                    $rotations!($store),
                    "4:",
                    state = in(reg) state.as_mut_ptr(),
                    data = inout(reg) data => _,
                    second = in(reg) second,
                    step = in(reg) step,
                    n = inout(reg) blocks => _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm7") _, out("xmm8") _,
                    out("xmm9") _, out("xmm10") _, out("xmm11") _,
                    out("xmm12") _,
                    options(nostack),
                );
            }
        }
    };
    (whole, $(#[$doc:meta])* $name:ident, $data:ty, $load:ident,
     $rotations:ident, $body:ident, $store:ident) => {
        $(#[$doc])*
        ///
        /// # Safety
        /// Requires the AES instructions; `data` must point at
        /// `blocks` blocks of input, each `step` bytes on from the
        /// last, and `blocks >= 1`.
        unsafe fn $name(
            state: &mut State,
            data: $data,
            step: usize,
            blocks: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    $load!(),
                    "2:",
                    $rotations!($body),
                    "jmp 2b",
                    $rotations!($store),
                    "4:",
                    state = in(reg) state.as_mut_ptr(),
                    data = inout(reg) data => _,
                    step = in(reg) step,
                    n = inout(reg) blocks => _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm7") _, out("xmm8") _,
                    out("xmm9") _, out("xmm10") _, out("xmm11") _,
                    options(nostack),
                );
            }
        }
    };
}

kernel!(
    halves,
    /// The AEGIS-128L `Absorb`.
    run_absorb128l,
    *const u8,
    load128l,
    rotations128l,
    absorb128l,
    store128l
);
kernel!(
    halves,
    /// The AEGIS-128L `Enc`, in place.
    run_encrypt128l,
    *mut u8,
    load128l,
    rotations128l,
    encrypt128l,
    store128l
);
kernel!(
    halves,
    /// The AEGIS-128L `Dec`, in place.
    run_decrypt128l,
    *mut u8,
    load128l,
    rotations128l,
    decrypt128l,
    store128l
);
kernel!(
    whole,
    /// The AEGIS-256 `Absorb`.
    run_absorb256,
    *const u8,
    load256,
    rotations256,
    absorb256,
    store256
);
kernel!(
    whole,
    /// The AEGIS-256 `Enc`, in place.
    run_encrypt256,
    *mut u8,
    load256,
    rotations256,
    encrypt256,
    store256
);
kernel!(
    whole,
    /// The AEGIS-256 `Dec`, in place.
    run_decrypt256,
    *mut u8,
    load256,
    rotations256,
    decrypt256,
    store256
);

entries!(
    halves,
    32,
    run_absorb128l,
    run_encrypt128l,
    run_decrypt128l,
    absorb128l,
    stir128l,
    encrypt128l,
    decrypt128l,
    absorb128l_lane,
    encrypt128l_lane,
    decrypt128l_lane
);
entries!(
    whole,
    16,
    run_absorb256,
    run_encrypt256,
    run_decrypt256,
    absorb256,
    stir256,
    encrypt256,
    decrypt256,
    absorb256_lane,
    encrypt256_lane,
    decrypt256_lane
);

/// The parallel variants on VAES, two lanes to a 256-bit register.
///
/// Each lane is a state of its own, kept apart in memory as the
/// narrow kernels want it, and a pair of them is brought into the
/// halves of eight registers, or six, for the length of a call. The
/// input needs no such gathering: the two lanes' pieces of a block
/// lie side by side in it, which is the reason the draft deals a
/// block out the way it does.
///
/// These are in the VEX encoding, whose three-operand `vaesenc` does
/// not write over its input, so the state stays where it is and the
/// loop is written once. The update is arranged as the narrow one is:
/// the message is the round's key and the block's old value is xored
/// in after, and decryption gives the round the keystream block that
/// arrives last.
///
/// The callers name this kernel only where its row of their list is
/// in force, which is VAES on 256-bit registers with the operating
/// system saving them.
pub(super) mod vaes {
    use super::State;
    use crate::aead::aegis::Lane;

    /// A pair of states into `ymm0` on, `$n` blocks of them.
    macro_rules! load {
        ($($r:literal, $at:literal),+) => {
            concat!($(
                "vmovdqu xmm", $r, ", [{state} + ", $at, "]\n",
                "vinserti128 ymm", $r, ", ymm", $r,
                ", [{state} + 128 + ", $at, "], 1\n",
            )+)
        };
    }

    /// The pair back to memory.
    macro_rules! store {
        ($($r:literal, $at:literal),+) => {
            concat!($(
                "vmovdqu [{state} + ", $at, "], xmm", $r, "\n",
                "vextracti128 [{state} + 128 + ", $at, "], ymm", $r,
                ", 1\n",
            )+)
        };
    }

    /// The AEGIS-128 update, for M0 in `ymm8` and M1 in `ymm9`.
    macro_rules! update128 {
        () => {
            "vaesenc ymm10, ymm7, ymm8\n\
             vaesenc ymm11, ymm3, ymm9\n\
             vaesenc ymm7, ymm6, ymm7\n\
             vaesenc ymm6, ymm5, ymm6\n\
             vaesenc ymm5, ymm4, ymm5\n\
             vpxor ymm4, ymm4, ymm11\n\
             vaesenc ymm3, ymm2, ymm3\n\
             vaesenc ymm2, ymm1, ymm2\n\
             vaesenc ymm1, ymm0, ymm1\n\
             vpxor ymm0, ymm0, ymm10\n"
        };
    }

    macro_rules! absorb128 {
        () => {
            concat!(
                "vmovdqu ymm8, [{data}]\n",
                "vmovdqu ymm9, [{data} + {second}]\n",
                update128!(),
            )
        };
    }

    macro_rules! encrypt128 {
        () => {
            concat!(
                "vmovdqu ymm8, [{data}]\n",
                "vmovdqu ymm9, [{data} + {second}]\n",
                "vpand ymm12, ymm2, ymm3\n",
                "vpand ymm13, ymm6, ymm7\n",
                "vpxor ymm12, ymm12, ymm1\n",
                "vpxor ymm13, ymm13, ymm2\n",
                "vpxor ymm12, ymm12, ymm6\n",
                "vpxor ymm13, ymm13, ymm5\n",
                "vpxor ymm12, ymm12, ymm8\n",
                "vpxor ymm13, ymm13, ymm9\n",
                "vmovdqu [{data}], ymm12\n",
                "vmovdqu [{data} + {second}], ymm13\n",
                update128!(),
            )
        };
    }

    /// Decryption: all of each block of message but the keystream
    /// block that arrives last, S1 for the first and S5 for the
    /// second, is gathered beside the rounds, and that last block is
    /// the round's key.
    macro_rules! decrypt128 {
        () => {
            "vmovdqu ymm8, [{data}]\n\
             vmovdqu ymm9, [{data} + {second}]\n\
             vpand ymm12, ymm2, ymm3\n\
             vpand ymm13, ymm6, ymm7\n\
             vpxor ymm12, ymm12, ymm6\n\
             vpxor ymm13, ymm13, ymm2\n\
             vpxor ymm12, ymm12, ymm8\n\
             vpxor ymm13, ymm13, ymm9\n\
             vpxor ymm8, ymm12, ymm1\n\
             vpxor ymm9, ymm13, ymm5\n\
             vmovdqu [{data}], ymm8\n\
             vmovdqu [{data} + {second}], ymm9\n\
             vpxor ymm12, ymm12, ymm0\n\
             vpxor ymm13, ymm13, ymm4\n\
             vaesenc ymm10, ymm7, ymm1\n\
             vaesenc ymm11, ymm3, ymm5\n\
             vaesenc ymm7, ymm6, ymm7\n\
             vaesenc ymm6, ymm5, ymm6\n\
             vaesenc ymm5, ymm4, ymm5\n\
             vpxor ymm4, ymm11, ymm13\n\
             vaesenc ymm3, ymm2, ymm3\n\
             vaesenc ymm2, ymm1, ymm2\n\
             vaesenc ymm1, ymm0, ymm1\n\
             vpxor ymm0, ymm10, ymm12\n"
        };
    }

    /// The AEGIS-256 update, for M in the register `$m`.
    macro_rules! update256 {
        ($m:literal) => {
            concat!(
                "vaesenc ymm10, ymm5, ",
                $m,
                "\n",
                "vaesenc ymm5, ymm4, ymm5\n",
                "vaesenc ymm4, ymm3, ymm4\n",
                "vaesenc ymm3, ymm2, ymm3\n",
                "vaesenc ymm2, ymm1, ymm2\n",
                "vaesenc ymm1, ymm0, ymm1\n",
                "vpxor ymm0, ymm0, ymm10\n",
            )
        };
    }

    macro_rules! absorb256 {
        () => {
            concat!("vmovdqu ymm8, [{data}]\n", update256!("ymm8"))
        };
    }

    macro_rules! encrypt256 {
        () => {
            concat!(
                "vmovdqu ymm8, [{data}]\n",
                "vpand ymm12, ymm2, ymm3\n",
                "vpxor ymm13, ymm4, ymm5\n",
                "vpxor ymm12, ymm12, ymm1\n",
                "vpxor ymm13, ymm13, ymm8\n",
                "vpxor ymm12, ymm12, ymm13\n",
                "vmovdqu [{data}], ymm12\n",
                update256!("ymm8"),
            )
        };
    }

    /// Decryption; see [`decrypt128`]. S1 is the block that arrives
    /// last.
    macro_rules! decrypt256 {
        () => {
            "vmovdqu ymm8, [{data}]\n\
             vpand ymm12, ymm2, ymm3\n\
             vpxor ymm13, ymm4, ymm5\n\
             vpxor ymm12, ymm12, ymm8\n\
             vpxor ymm12, ymm12, ymm13\n\
             vpxor ymm8, ymm12, ymm1\n\
             vmovdqu [{data}], ymm8\n\
             vpxor ymm12, ymm12, ymm0\n\
             vaesenc ymm10, ymm5, ymm1\n\
             vaesenc ymm5, ymm4, ymm5\n\
             vaesenc ymm4, ymm3, ymm4\n\
             vaesenc ymm3, ymm2, ymm3\n\
             vaesenc ymm2, ymm1, ymm2\n\
             vaesenc ymm1, ymm0, ymm1\n\
             vpxor ymm0, ymm10, ymm12\n"
        };
    }

    macro_rules! load128 {
        () => {
            load!(
                "0", "0", "1", "16", "2", "32", "3", "48", "4", "64", "5",
                "80", "6", "96", "7", "112"
            )
        };
    }

    macro_rules! store128 {
        () => {
            store!(
                "0", "0", "1", "16", "2", "32", "3", "48", "4", "64", "5",
                "80", "6", "96", "7", "112"
            )
        };
    }

    macro_rules! load256 {
        () => {
            load!(
                "0", "0", "1", "16", "2", "32", "3", "48", "4", "64", "5", "80"
            )
        };
    }

    macro_rules! store256 {
        () => {
            store!(
                "0", "0", "1", "16", "2", "32", "3", "48", "4", "64", "5", "80"
            )
        };
    }

    /// Defines a kernel over a pair of lanes: the two states into the
    /// registers, `$body` for each block of input, and the states
    /// back. A `halves` kernel takes its block in two pieces, and a
    /// `whole` one in one.
    macro_rules! kernel {
        (halves, $(#[$doc:meta])* $name:ident, $data:ty, $pointer:ident,
         $load:ident, $body:ident, $store:ident) => {
            $(#[$doc])*
            ///
            /// `lane` is the first of the two, which are side by side
            /// in the input. The processor must have VAES on 256-bit
            /// registers.
            pub(in crate::aead::aegis) fn $name(
                states: &mut [State; 2],
                data: $data,
                lane: Lane,
            ) {
                // What is checked for the further lane holds for the
                // nearer.
                let further = Lane {
                    offset: lane.offset + 16,
                    width: lane.width,
                };
                let (blocks, second) = further.halves(data.len());
                if blocks == 0 {
                    return;
                }
                // SAFETY: both lanes' pieces lie inside every one of
                // those blocks, and the two states are side by side;
                // the instructions are the caller's word.
                unsafe {
                    core::arch::asm!(
                        $load!(),
                        "2:",
                        $body!(),
                        "add {data}, {step}",
                        "dec {n}",
                        "jnz 2b",
                        $store!(),
                        "vzeroupper",
                        state = in(reg) states.as_mut_ptr(),
                        data = inout(reg)
                            data.$pointer().add(lane.offset) => _,
                        second = in(reg) second,
                        step = in(reg) lane.width,
                        n = inout(reg) blocks => _,
                        out("ymm0") _, out("ymm1") _, out("ymm2") _,
                        out("ymm3") _, out("ymm4") _, out("ymm5") _,
                        out("ymm6") _, out("ymm7") _, out("ymm8") _,
                        out("ymm9") _, out("ymm10") _, out("ymm11") _,
                        out("ymm12") _, out("ymm13") _,
                        options(nostack),
                    );
                }
            }
        };
        (whole, $(#[$doc:meta])* $name:ident, $data:ty, $pointer:ident,
         $load:ident, $body:ident, $store:ident) => {
            $(#[$doc])*
            ///
            /// `lane` is the first of the two, which are side by side
            /// in the input. The processor must have VAES on 256-bit
            /// registers.
            pub(in crate::aead::aegis) fn $name(
                states: &mut [State; 2],
                data: $data,
                lane: Lane,
            ) {
                // What is checked for the further lane holds for the
                // nearer.
                let further = Lane {
                    offset: lane.offset + 16,
                    width: lane.width,
                };
                let blocks = further.piece(data.len());
                if blocks == 0 {
                    return;
                }
                // SAFETY: both lanes' pieces lie inside every one of
                // those blocks, and the two states are side by side;
                // the instructions are the caller's word.
                unsafe {
                    core::arch::asm!(
                        $load!(),
                        "2:",
                        $body!(),
                        "add {data}, {step}",
                        "dec {n}",
                        "jnz 2b",
                        $store!(),
                        "vzeroupper",
                        state = in(reg) states.as_mut_ptr(),
                        data = inout(reg)
                            data.$pointer().add(lane.offset) => _,
                        step = in(reg) lane.width,
                        n = inout(reg) blocks => _,
                        out("ymm0") _, out("ymm1") _, out("ymm2") _,
                        out("ymm3") _, out("ymm4") _, out("ymm5") _,
                        out("ymm6") _, out("ymm7") _, out("ymm8") _,
                        out("ymm9") _, out("ymm10") _, out("ymm11") _,
                        out("ymm12") _, out("ymm13") _,
                        options(nostack),
                    );
                }
            }
        };
    }

    kernel!(
        halves,
        /// The AEGIS-128 `Absorb`, over two lanes of each whole block.
        absorb128,
        &[u8],
        as_ptr,
        load128,
        absorb128,
        store128
    );
    kernel!(
        halves,
        /// The AEGIS-128 `Enc`, over two lanes of each whole block.
        encrypt128,
        &mut [u8],
        as_mut_ptr,
        load128,
        encrypt128,
        store128
    );
    kernel!(
        halves,
        /// The AEGIS-128 `Dec`, over two lanes of each whole block.
        decrypt128,
        &mut [u8],
        as_mut_ptr,
        load128,
        decrypt128,
        store128
    );
    kernel!(
        whole,
        /// The AEGIS-256 `Absorb`, over two lanes of each whole block.
        absorb256,
        &[u8],
        as_ptr,
        load256,
        absorb256,
        store256
    );
    kernel!(
        whole,
        /// The AEGIS-256 `Enc`, over two lanes of each whole block.
        encrypt256,
        &mut [u8],
        as_mut_ptr,
        load256,
        encrypt256,
        store256
    );
    kernel!(
        whole,
        /// The AEGIS-256 `Dec`, over two lanes of each whole block.
        decrypt256,
        &mut [u8],
        as_mut_ptr,
        load256,
        decrypt256,
        store256
    );

    /// What every one of the loops below writes.
    macro_rules! seeded {
        ($($body:tt)*) => {
            core::arch::asm!(
                $($body)*
                out("ymm0") _, out("ymm1") _, out("ymm2") _,
                out("ymm3") _, out("ymm4") _, out("ymm5") _,
                out("ymm6") _, out("ymm7") _, out("ymm8") _,
                out("ymm9") _, out("ymm10") _, out("ymm11") _,
                out("ymm12") _, out("ymm13") _, out("ymm14") _,
                options(nostack),
            )
        };
    }

    /// The updates of the AEGIS-128 `Init`, for a pair of lanes that
    /// hold the state it starts from: ten with the nonce and the
    /// key, which are `block`, each lane's mark going into its
    /// fourth and eighth blocks before every one. Both lanes take
    /// the same message, so it is read once and stays in registers.
    ///
    /// The processor must have VAES on 256-bit registers.
    pub(in crate::aead::aegis) fn init128(
        states: &mut [State; 2],
        block: &[u8; 32],
        marks: &[[u8; 16]; 2],
    ) {
        // SAFETY: every pointer is to as many bytes as are read or
        // written through it; the instructions are the caller's word.
        unsafe {
            seeded!(
                load128!(),
                "vbroadcasti128 ymm8, [{block}]",
                "vbroadcasti128 ymm9, [{block} + 16]",
                "vmovdqu ymm14, [{marks}]",
                "2:",
                "vpxor ymm3, ymm3, ymm14",
                "vpxor ymm7, ymm7, ymm14",
                update128!(),
                "dec {n}",
                "jnz 2b",
                store128!(),
                "vzeroupper",
                state = in(reg) states.as_mut_ptr(),
                block = in(reg) block.as_ptr(),
                marks = in(reg) marks.as_ptr(),
                n = inout(reg) 10usize => _,
            );
        }
    }

    /// The updates of the AEGIS-128 `Finalize`, for a pair of lanes:
    /// seven with each lane's third block xored with `lengths`, in
    /// both halves of the input.
    ///
    /// The processor must have VAES on 256-bit registers.
    pub(in crate::aead::aegis) fn finish128(
        states: &mut [State; 2],
        lengths: &[u8; 16],
    ) {
        // SAFETY: as for `init128`.
        unsafe {
            seeded!(
                load128!(),
                "vbroadcasti128 ymm8, [{lengths}]",
                "vpxor ymm8, ymm8, ymm2",
                "vmovdqa ymm9, ymm8",
                "2:",
                update128!(),
                "dec {n}",
                "jnz 2b",
                store128!(),
                "vzeroupper",
                state = in(reg) states.as_mut_ptr(),
                lengths = in(reg) lengths.as_ptr(),
                n = inout(reg) 7usize => _,
            );
        }
    }

    /// The updates of the AEGIS-256 `Init`, for a pair of lanes that
    /// hold the state it starts from: the four blocks of `inputs` in
    /// turn, four times over, each lane's mark going into its fourth
    /// and sixth blocks before every one.
    ///
    /// The processor must have VAES on 256-bit registers.
    pub(in crate::aead::aegis) fn init256(
        states: &mut [State; 2],
        inputs: &[[u8; 16]; 4],
        marks: &[[u8; 16]; 2],
    ) {
        // SAFETY: as for `init128`.
        unsafe {
            seeded!(
                load256!(),
                "vbroadcasti128 ymm8, [{inputs}]",
                "vbroadcasti128 ymm9, [{inputs} + 16]",
                "vbroadcasti128 ymm12, [{inputs} + 32]",
                "vbroadcasti128 ymm13, [{inputs} + 48]",
                "vmovdqu ymm14, [{marks}]",
                "2:",
                "vpxor ymm3, ymm3, ymm14",
                "vpxor ymm5, ymm5, ymm14",
                update256!("ymm8"),
                "vpxor ymm3, ymm3, ymm14",
                "vpxor ymm5, ymm5, ymm14",
                update256!("ymm9"),
                "vpxor ymm3, ymm3, ymm14",
                "vpxor ymm5, ymm5, ymm14",
                update256!("ymm12"),
                "vpxor ymm3, ymm3, ymm14",
                "vpxor ymm5, ymm5, ymm14",
                update256!("ymm13"),
                "dec {n}",
                "jnz 2b",
                store256!(),
                "vzeroupper",
                state = in(reg) states.as_mut_ptr(),
                inputs = in(reg) inputs.as_ptr(),
                marks = in(reg) marks.as_ptr(),
                n = inout(reg) 4usize => _,
            );
        }
    }

    /// The updates of the AEGIS-256 `Finalize`, for a pair of lanes:
    /// seven with each lane's fourth block xored with `lengths`.
    ///
    /// The processor must have VAES on 256-bit registers.
    pub(in crate::aead::aegis) fn finish256(
        states: &mut [State; 2],
        lengths: &[u8; 16],
    ) {
        // SAFETY: as for `init128`.
        unsafe {
            seeded!(
                load256!(),
                "vbroadcasti128 ymm8, [{lengths}]",
                "vpxor ymm8, ymm8, ymm3",
                "2:",
                update256!("ymm8"),
                "dec {n}",
                "jnz 2b",
                store256!(),
                "vzeroupper",
                state = in(reg) states.as_mut_ptr(),
                lengths = in(reg) lengths.as_ptr(),
                n = inout(reg) 7usize => _,
            );
        }
    }
}
