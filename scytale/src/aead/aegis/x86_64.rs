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
        "movdqu xmm8, [{data}]\nmovdqu xmm9, [{data} + 16]\n"
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
            "movdqu [{data} + 16], xmm11\n",
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
            "movdqu [{data} + 16], xmm9\n",
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
                    out("xmm12") _,
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
