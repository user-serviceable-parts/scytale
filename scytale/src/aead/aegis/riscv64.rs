//! AEGIS on the RISC-V AES instructions, vector and scalar, with the
//! loops in hand-written assembly.
//!
//! [`zvkned`] holds each block of the state in a vector register and
//! is the shape of the x86-64 and AArch64 kernels. [`zkn`] holds each
//! in a pair of integer registers, for a processor with the scalar
//! instructions and no vector unit.
//!
//! # Availability
//!
//! The callers name these kernels only where their rows of the lists
//! are in force. The `.option arch` directives only tell the
//! assembler the instructions are allowed.

#![allow(unsafe_code)]

/// AEGIS on Zvkned, a block to a vector register.
///
/// `vaesem.vv` is the whole of the round AEGIS is built from: it puts
/// its destination through SubBytes, ShiftRows and MixColumns and
/// xors the other operand in. It writes over the block it is given,
/// as `aesenc` does, so the loop is written out once for each place
/// the state can lie and a message that ends part of the way down
/// leaves through the store for the place it had reached; see
/// [`x86_64`](super::super) for the argument.
///
/// The vector length is set to four 32-bit elements throughout, one
/// block, whatever length the registers have.
pub(super) mod zvkned {
    use super::super::State;

    /// Calls `$body` with a label and the registers holding S0 to
    /// S7, in order, for each of the eight places the AEGIS-128L
    /// state can lie.
    macro_rules! rotations128l {
        ($body:ident) => {
            concat!(
                $body!("30", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"),
                $body!("31", "v7", "v0", "v1", "v2", "v3", "v4", "v5", "v6"),
                $body!("32", "v6", "v7", "v0", "v1", "v2", "v3", "v4", "v5"),
                $body!("33", "v5", "v6", "v7", "v0", "v1", "v2", "v3", "v4"),
                $body!("34", "v4", "v5", "v6", "v7", "v0", "v1", "v2", "v3"),
                $body!("35", "v3", "v4", "v5", "v6", "v7", "v0", "v1", "v2"),
                $body!("36", "v2", "v3", "v4", "v5", "v6", "v7", "v0", "v1"),
                $body!("37", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v0"),
            )
        };
    }

    /// The AEGIS-128L update, for M0 in `v8` and M1 in `v9`, then on
    /// to the next block of input, leaving through the store at
    /// `$label` if that was the last. The new S0 is left where S7
    /// was, and every other block where the one before it was.
    macro_rules! update128l {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal, $s6:literal,
         $s7:literal) => {
            concat!(
                "vxor.vv v8, v8, ",
                $s0,
                "\n",
                "vxor.vv v9, v9, ",
                $s4,
                "\n",
                "vaesem.vv ",
                $s0,
                ", ",
                $s1,
                "\n",
                "vaesem.vv ",
                $s1,
                ", ",
                $s2,
                "\n",
                "vaesem.vv ",
                $s2,
                ", ",
                $s3,
                "\n",
                "vaesem.vv ",
                $s3,
                ", v9\n",
                "vaesem.vv ",
                $s4,
                ", ",
                $s5,
                "\n",
                "vaesem.vv ",
                $s5,
                ", ",
                $s6,
                "\n",
                "vaesem.vv ",
                $s6,
                ", ",
                $s7,
                "\n",
                "vaesem.vv ",
                $s7,
                ", v8\n",
                "addi {data}, {data}, 32\n",
                "addi {n}, {n}, -1\n",
                "beqz {n}, ",
                $label,
                "f\n",
            )
        };
    }

    /// The AEGIS-128L keystream: z0 into `v10` and z1 into `v11`.
    macro_rules! keystream128l {
        ($s1:literal, $s2:literal, $s3:literal, $s5:literal,
         $s6:literal, $s7:literal) => {
            concat!(
                "vand.vv v10, ",
                $s2,
                ", ",
                $s3,
                "\n",
                "vand.vv v11, ",
                $s6,
                ", ",
                $s7,
                "\n",
                "vxor.vv v10, v10, ",
                $s1,
                "\n",
                "vxor.vv v11, v11, ",
                $s2,
                "\n",
                "vxor.vv v10, v10, ",
                $s6,
                "\n",
                "vxor.vv v11, v11, ",
                $s5,
                "\n",
            )
        };
    }

    /// The two blocks of input, into `v8` and `v9`; `{t}` is left at
    /// the second.
    macro_rules! input128l {
        () => {
            "vle32.v v8, ({data})\n\
             addi {t}, {data}, 16\n\
             vle32.v v9, ({t})\n"
        };
    }

    macro_rules! absorb128l {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal, $s6:literal,
         $s7:literal) => {
            concat!(
                input128l!(),
                update128l!($label, $s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7),
            )
        };
    }

    macro_rules! encrypt128l {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal, $s6:literal,
         $s7:literal) => {
            concat!(
                input128l!(),
                keystream128l!($s1, $s2, $s3, $s5, $s6, $s7),
                "vxor.vv v10, v10, v8\n",
                "vxor.vv v11, v11, v9\n",
                "vse32.v v10, ({data})\n",
                "vse32.v v11, ({t})\n",
                update128l!($label, $s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7),
            )
        };
    }

    /// As encryption, but the state is updated with what comes out
    /// rather than with what went in.
    macro_rules! decrypt128l {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal, $s6:literal,
         $s7:literal) => {
            concat!(
                input128l!(),
                keystream128l!($s1, $s2, $s3, $s5, $s6, $s7),
                "vxor.vv v8, v8, v10\n",
                "vxor.vv v9, v9, v11\n",
                "vse32.v v8, ({data})\n",
                "vse32.v v9, ({t})\n",
                update128l!($label, $s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7),
            )
        };
    }

    /// One block of the state to memory at `{t}`, and `{t}` on to
    /// the next.
    macro_rules! put {
        ($s:literal) => {
            concat!("vse32.v ", $s, ", ({t})\naddi {t}, {t}, 16\n")
        };
    }

    /// One block of the state from memory at `{t}`, and `{t}` on to
    /// the next.
    macro_rules! get {
        ($s:literal) => {
            concat!("vle32.v ", $s, ", ({t})\naddi {t}, {t}, 16\n")
        };
    }

    /// Where a message that ended after the update of the same label
    /// leaves: the state as that update left it, back to memory in
    /// order.
    macro_rules! store128l {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal, $s6:literal,
         $s7:literal) => {
            concat!(
                $label,
                ":\n",
                "mv {t}, {state}\n",
                put!($s7),
                put!($s0),
                put!($s1),
                put!($s2),
                put!($s3),
                put!($s4),
                put!($s5),
                put!($s6),
                "j 4f\n",
            )
        };
    }

    macro_rules! load128l {
        () => {
            concat!(
                "mv {t}, {state}\n",
                get!("v0"),
                get!("v1"),
                get!("v2"),
                get!("v3"),
                get!("v4"),
                get!("v5"),
                get!("v6"),
                get!("v7"),
            )
        };
    }

    /// As [`rotations128l`], for the six places the AEGIS-256 state
    /// can lie, S0 to S5.
    macro_rules! rotations256 {
        ($body:ident) => {
            concat!(
                $body!("30", "v0", "v1", "v2", "v3", "v4", "v5"),
                $body!("31", "v5", "v0", "v1", "v2", "v3", "v4"),
                $body!("32", "v4", "v5", "v0", "v1", "v2", "v3"),
                $body!("33", "v3", "v4", "v5", "v0", "v1", "v2"),
                $body!("34", "v2", "v3", "v4", "v5", "v0", "v1"),
                $body!("35", "v1", "v2", "v3", "v4", "v5", "v0"),
            )
        };
    }

    /// The AEGIS-256 update, for M in `v8`; see [`update128l`].
    macro_rules! update256 {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal) => {
            concat!(
                "vxor.vv v8, v8, ",
                $s0,
                "\n",
                "vaesem.vv ",
                $s0,
                ", ",
                $s1,
                "\n",
                "vaesem.vv ",
                $s1,
                ", ",
                $s2,
                "\n",
                "vaesem.vv ",
                $s2,
                ", ",
                $s3,
                "\n",
                "vaesem.vv ",
                $s3,
                ", ",
                $s4,
                "\n",
                "vaesem.vv ",
                $s4,
                ", ",
                $s5,
                "\n",
                "vaesem.vv ",
                $s5,
                ", v8\n",
                "addi {data}, {data}, 16\n",
                "addi {n}, {n}, -1\n",
                "beqz {n}, ",
                $label,
                "f\n",
            )
        };
    }

    /// The AEGIS-256 keystream, into `v10`.
    macro_rules! keystream256 {
        ($s1:literal, $s2:literal, $s3:literal, $s4:literal,
         $s5:literal) => {
            concat!(
                "vand.vv v10, ",
                $s2,
                ", ",
                $s3,
                "\n",
                "vxor.vv v11, ",
                $s4,
                ", ",
                $s5,
                "\n",
                "vxor.vv v10, v10, ",
                $s1,
                "\n",
                "vxor.vv v10, v10, v11\n",
            )
        };
    }

    macro_rules! absorb256 {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal) => {
            concat!(
                "vle32.v v8, ({data})\n",
                update256!($label, $s0, $s1, $s2, $s3, $s4, $s5),
            )
        };
    }

    macro_rules! encrypt256 {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal) => {
            concat!(
                "vle32.v v8, ({data})\n",
                keystream256!($s1, $s2, $s3, $s4, $s5),
                "vxor.vv v10, v10, v8\n",
                "vse32.v v10, ({data})\n",
                update256!($label, $s0, $s1, $s2, $s3, $s4, $s5),
            )
        };
    }

    macro_rules! decrypt256 {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal) => {
            concat!(
                "vle32.v v8, ({data})\n",
                keystream256!($s1, $s2, $s3, $s4, $s5),
                "vxor.vv v8, v8, v10\n",
                "vse32.v v8, ({data})\n",
                update256!($label, $s0, $s1, $s2, $s3, $s4, $s5),
            )
        };
    }

    macro_rules! store256 {
        ($label:literal, $s0:literal, $s1:literal, $s2:literal,
         $s3:literal, $s4:literal, $s5:literal) => {
            concat!(
                $label,
                ":\n",
                "mv {t}, {state}\n",
                put!($s5),
                put!($s0),
                put!($s1),
                put!($s2),
                put!($s3),
                put!($s4),
                "j 4f\n",
            )
        };
    }

    macro_rules! load256 {
        () => {
            concat!(
                "mv {t}, {state}\n",
                get!("v0"),
                get!("v1"),
                get!("v2"),
                get!("v3"),
                get!("v4"),
                get!("v5"),
            )
        };
    }

    /// Defines a kernel: the state into the registers, `$body` for
    /// each block of `$rate` bytes round the places the state can
    /// lie, and the state back from wherever the input ended.
    macro_rules! kernel {
        ($(#[$doc:meta])* $name:ident, $data:ty, $pointer:ident,
         $rate:literal, $load:ident, $rotations:ident, $body:ident,
         $store:ident) => {
            $(#[$doc])*
            ///
            /// The processor must have the vector extension and
            /// Zvkned.
            pub(in super::super) fn $name(state: &mut State, data: $data) {
                let blocks = data.len() / $rate;
                if blocks == 0 {
                    return;
                }
                // SAFETY: the loop reads and writes `blocks` whole
                // blocks at `data`, which is that long, and the
                // state, which is eight blocks; the instructions are
                // the caller's word.
                unsafe {
                    core::arch::asm!(
                        ".option push",
                        ".option arch, +v, +zvkned",
                        "vsetivli zero, 4, e32, m1, ta, ma",
                        $load!(),
                        "2:",
                        $rotations!($body),
                        "j 2b",
                        $rotations!($store),
                        "4:",
                        ".option pop",
                        state = in(reg) state.as_mut_ptr(),
                        data = inout(reg) data.$pointer() => _,
                        n = inout(reg) blocks => _,
                        t = out(reg) _,
                        out("v0") _, out("v1") _, out("v2") _,
                        out("v3") _, out("v4") _, out("v5") _,
                        out("v6") _, out("v7") _, out("v8") _,
                        out("v9") _, out("v10") _, out("v11") _,
                        options(nostack),
                    );
                }
            }
        };
    }

    kernel!(
        /// The AEGIS-128L `Absorb`, over each block of `data`.
        absorb128l,
        &[u8],
        as_ptr,
        32,
        load128l,
        rotations128l,
        absorb128l,
        store128l
    );
    kernel!(
        /// The AEGIS-128L `Enc`, over each block of `data` in place.
        encrypt128l,
        &mut [u8],
        as_mut_ptr,
        32,
        load128l,
        rotations128l,
        encrypt128l,
        store128l
    );
    kernel!(
        /// The AEGIS-128L `Dec`, over each block of `data` in place.
        decrypt128l,
        &mut [u8],
        as_mut_ptr,
        32,
        load128l,
        rotations128l,
        decrypt128l,
        store128l
    );
    kernel!(
        /// The AEGIS-256 `Absorb`, over each block of `data`.
        absorb256,
        &[u8],
        as_ptr,
        16,
        load256,
        rotations256,
        absorb256,
        store256
    );
    kernel!(
        /// The AEGIS-256 `Enc`, over each block of `data` in place.
        encrypt256,
        &mut [u8],
        as_mut_ptr,
        16,
        load256,
        rotations256,
        encrypt256,
        store256
    );
    kernel!(
        /// The AEGIS-256 `Dec`, over each block of `data` in place.
        decrypt256,
        &mut [u8],
        as_mut_ptr,
        16,
        load256,
        rotations256,
        decrypt256,
        store256
    );
}

/// AEGIS on Zkne, a block to a pair of integer registers.
///
/// `aes64esm` makes one half of a block's round from both halves and
/// writes it wherever it is told, so nothing is written over before
/// it has been read and the state stays where it is: each block,
/// from the last down, takes the round of the one before it, and the
/// round of the last block, which the first needs and which is
/// overwritten first, is made before the rest.
///
/// AEGIS-128L holds its sixteen halves in registers, which leaves
/// ten of the twenty-six there are to use for everything else.
pub(super) mod zkn {
    use super::super::State;

    /// Block `$to` takes the round of block `$from`.
    macro_rules! round {
        ($from:literal, $to:literal) => {
            concat!(
                "aes64esm {a}, {s",
                $from,
                "l}, {s",
                $from,
                "h}\n",
                "aes64esm {b}, {s",
                $from,
                "h}, {s",
                $from,
                "l}\n",
                "xor {s",
                $to,
                "l}, {s",
                $to,
                "l}, {a}\n",
                "xor {s",
                $to,
                "h}, {s",
                $to,
                "h}, {b}\n",
            )
        };
    }

    /// Block `$s` of the state from memory.
    macro_rules! get {
        ($s:literal, $low:literal, $high:literal) => {
            concat!(
                "ld {s",
                $s,
                "l}, ",
                $low,
                "({state})\n",
                "ld {s",
                $s,
                "h}, ",
                $high,
                "({state})\n",
            )
        };
    }

    /// Block `$s` of the state to memory.
    macro_rules! put {
        ($s:literal, $low:literal, $high:literal) => {
            concat!(
                "sd {s",
                $s,
                "l}, ",
                $low,
                "({state})\n",
                "sd {s",
                $s,
                "h}, ",
                $high,
                "({state})\n",
            )
        };
    }

    /// The pair `$l`, `$h` takes the bytes at `$low` and `$high` of
    /// the input.
    macro_rules! input {
        ($l:literal, $h:literal, $low:literal, $high:literal) => {
            concat!(
                "ld {",
                $l,
                "}, ",
                $low,
                "({data})\n",
                "ld {",
                $h,
                "}, ",
                $high,
                "({data})\n",
            )
        };
    }

    /// The pair `$l`, `$h` goes to the bytes at `$low` and `$high`
    /// of the output.
    macro_rules! output {
        ($l:literal, $h:literal, $low:literal, $high:literal) => {
            concat!(
                "sd {",
                $l,
                "}, ",
                $low,
                "({data})\n",
                "sd {",
                $h,
                "}, ",
                $high,
                "({data})\n",
            )
        };
    }

    /// The AEGIS-128L update, for M0 in the pair `r` and M1 in the
    /// pair `m`, then round again for the next block of input.
    macro_rules! update128l {
        () => {
            concat!(
                "aes64esm {a}, {s7l}, {s7h}\n",
                "aes64esm {b}, {s7h}, {s7l}\n",
                "xor {rl}, {rl}, {a}\n",
                "xor {rh}, {rh}, {b}\n",
                round!("6", "7"),
                round!("5", "6"),
                round!("4", "5"),
                round!("3", "4"),
                "xor {s4l}, {s4l}, {ml}\n",
                "xor {s4h}, {s4h}, {mh}\n",
                round!("2", "3"),
                round!("1", "2"),
                round!("0", "1"),
                "xor {s0l}, {s0l}, {rl}\n",
                "xor {s0h}, {s0h}, {rh}\n",
                "addi {data}, {data}, 32\n",
                "addi {n}, {n}, -1\n",
                "bnez {n}, 2b\n",
            )
        };
    }

    /// One half of the AEGIS-128L keystream into `$out`: `$x ^ $y ^
    /// ($p & $q)`.
    macro_rules! keystream {
        ($out:literal, $x:literal, $y:literal, $p:literal, $q:literal) => {
            concat!(
                "and {", $out, "}, {", $p, "}, {", $q, "}\n", "xor {", $out,
                "}, {", $out, "}, {", $x, "}\n", "xor {", $out, "}, {", $out,
                "}, {", $y, "}\n",
            )
        };
    }

    macro_rules! absorb128l {
        () => {
            concat!(
                input!("rl", "rh", "0", "8"),
                input!("ml", "mh", "16", "24"),
                update128l!(),
            )
        };
    }

    macro_rules! encrypt128l {
        () => {
            concat!(
                input!("rl", "rh", "0", "8"),
                keystream!("a", "s1l", "s6l", "s2l", "s3l"),
                keystream!("b", "s1h", "s6h", "s2h", "s3h"),
                "xor {a}, {a}, {rl}\n",
                "xor {b}, {b}, {rh}\n",
                output!("a", "b", "0", "8"),
                input!("ml", "mh", "16", "24"),
                keystream!("a", "s2l", "s5l", "s6l", "s7l"),
                keystream!("b", "s2h", "s5h", "s6h", "s7h"),
                "xor {a}, {a}, {ml}\n",
                "xor {b}, {b}, {mh}\n",
                output!("a", "b", "16", "24"),
                update128l!(),
            )
        };
    }

    /// As encryption, but the state is updated with what comes out
    /// rather than with what went in.
    macro_rules! decrypt128l {
        () => {
            concat!(
                input!("rl", "rh", "0", "8"),
                keystream!("a", "s1l", "s6l", "s2l", "s3l"),
                keystream!("b", "s1h", "s6h", "s2h", "s3h"),
                "xor {rl}, {rl}, {a}\n",
                "xor {rh}, {rh}, {b}\n",
                output!("rl", "rh", "0", "8"),
                input!("ml", "mh", "16", "24"),
                keystream!("a", "s2l", "s5l", "s6l", "s7l"),
                keystream!("b", "s2h", "s5h", "s6h", "s7h"),
                "xor {ml}, {ml}, {a}\n",
                "xor {mh}, {mh}, {b}\n",
                output!("ml", "mh", "16", "24"),
                update128l!(),
            )
        };
    }

    /// Defines an AEGIS-128L kernel over `$body`.
    macro_rules! kernel128l {
        ($(#[$doc:meta])* $name:ident, $data:ty, $pointer:ident,
         $body:ident) => {
            $(#[$doc])*
            ///
            /// The processor must have Zkne.
            pub(in super::super) fn $name(state: &mut State, data: $data) {
                let blocks = data.len() / 32;
                if blocks == 0 {
                    return;
                }
                // SAFETY: the loop reads and writes `blocks` whole
                // blocks at `data`, which is that long, and the
                // state, which is eight blocks; the instructions are
                // the caller's word.
                unsafe {
                    core::arch::asm!(
                        ".option push",
                        ".option arch, +zkne",
                        get!("0", "0", "8"),
                        get!("1", "16", "24"),
                        get!("2", "32", "40"),
                        get!("3", "48", "56"),
                        get!("4", "64", "72"),
                        get!("5", "80", "88"),
                        get!("6", "96", "104"),
                        get!("7", "112", "120"),
                        "2:",
                        $body!(),
                        put!("0", "0", "8"),
                        put!("1", "16", "24"),
                        put!("2", "32", "40"),
                        put!("3", "48", "56"),
                        put!("4", "64", "72"),
                        put!("5", "80", "88"),
                        put!("6", "96", "104"),
                        put!("7", "112", "120"),
                        ".option pop",
                        state = in(reg) state.as_mut_ptr(),
                        data = inout(reg) data.$pointer() => _,
                        n = inout(reg) blocks => _,
                        s0l = out(reg) _, s0h = out(reg) _,
                        s1l = out(reg) _, s1h = out(reg) _,
                        s2l = out(reg) _, s2h = out(reg) _,
                        s3l = out(reg) _, s3h = out(reg) _,
                        s4l = out(reg) _, s4h = out(reg) _,
                        s5l = out(reg) _, s5h = out(reg) _,
                        s6l = out(reg) _, s6h = out(reg) _,
                        s7l = out(reg) _, s7h = out(reg) _,
                        rl = out(reg) _, rh = out(reg) _,
                        ml = out(reg) _, mh = out(reg) _,
                        a = out(reg) _, b = out(reg) _,
                        options(nostack),
                    );
                }
            }
        };
    }

    kernel128l!(
        /// The AEGIS-128L `Absorb`, over each block of `data`.
        absorb128l,
        &[u8],
        as_ptr,
        absorb128l
    );
    kernel128l!(
        /// The AEGIS-128L `Enc`, over each block of `data` in place.
        encrypt128l,
        &mut [u8],
        as_mut_ptr,
        encrypt128l
    );
    kernel128l!(
        /// The AEGIS-128L `Dec`, over each block of `data` in place.
        decrypt128l,
        &mut [u8],
        as_mut_ptr,
        decrypt128l
    );

    /// The AEGIS-256 update, for M in the pair `r`, then round again
    /// for the next block of input.
    macro_rules! update256 {
        () => {
            concat!(
                "aes64esm {a}, {s5l}, {s5h}\n",
                "aes64esm {b}, {s5h}, {s5l}\n",
                "xor {rl}, {rl}, {a}\n",
                "xor {rh}, {rh}, {b}\n",
                round!("4", "5"),
                round!("3", "4"),
                round!("2", "3"),
                round!("1", "2"),
                round!("0", "1"),
                "xor {s0l}, {s0l}, {rl}\n",
                "xor {s0h}, {s0h}, {rh}\n",
                "addi {data}, {data}, 16\n",
                "addi {n}, {n}, -1\n",
                "bnez {n}, 2b\n",
            )
        };
    }

    /// One half of the AEGIS-256 keystream into `$out`, for the half
    /// `$half` of each block.
    macro_rules! keystream256 {
        ($out:literal, $half:literal) => {
            concat!(
                "and {", $out, "}, {s2", $half, "}, {s3", $half, "}\n",
                "xor {", $out, "}, {", $out, "}, {s1", $half, "}\n", "xor {",
                $out, "}, {", $out, "}, {s4", $half, "}\n", "xor {", $out,
                "}, {", $out, "}, {s5", $half, "}\n",
            )
        };
    }

    macro_rules! absorb256 {
        () => {
            concat!(input!("rl", "rh", "0", "8"), update256!())
        };
    }

    macro_rules! encrypt256 {
        () => {
            concat!(
                input!("rl", "rh", "0", "8"),
                keystream256!("a", "l"),
                keystream256!("b", "h"),
                "xor {a}, {a}, {rl}\n",
                "xor {b}, {b}, {rh}\n",
                output!("a", "b", "0", "8"),
                update256!(),
            )
        };
    }

    macro_rules! decrypt256 {
        () => {
            concat!(
                input!("rl", "rh", "0", "8"),
                keystream256!("a", "l"),
                keystream256!("b", "h"),
                "xor {rl}, {rl}, {a}\n",
                "xor {rh}, {rh}, {b}\n",
                output!("rl", "rh", "0", "8"),
                update256!(),
            )
        };
    }

    /// Defines an AEGIS-256 kernel over `$body`.
    macro_rules! kernel256 {
        ($(#[$doc:meta])* $name:ident, $data:ty, $pointer:ident,
         $body:ident) => {
            $(#[$doc])*
            ///
            /// The processor must have Zkne.
            pub(in super::super) fn $name(state: &mut State, data: $data) {
                let blocks = data.len() / 16;
                if blocks == 0 {
                    return;
                }
                // SAFETY: the loop reads and writes `blocks` whole
                // blocks at `data`, which is that long, and the
                // first six blocks of the state, which is eight; the
                // instructions are the caller's word.
                unsafe {
                    core::arch::asm!(
                        ".option push",
                        ".option arch, +zkne",
                        get!("0", "0", "8"),
                        get!("1", "16", "24"),
                        get!("2", "32", "40"),
                        get!("3", "48", "56"),
                        get!("4", "64", "72"),
                        get!("5", "80", "88"),
                        "2:",
                        $body!(),
                        put!("0", "0", "8"),
                        put!("1", "16", "24"),
                        put!("2", "32", "40"),
                        put!("3", "48", "56"),
                        put!("4", "64", "72"),
                        put!("5", "80", "88"),
                        ".option pop",
                        state = in(reg) state.as_mut_ptr(),
                        data = inout(reg) data.$pointer() => _,
                        n = inout(reg) blocks => _,
                        s0l = out(reg) _, s0h = out(reg) _,
                        s1l = out(reg) _, s1h = out(reg) _,
                        s2l = out(reg) _, s2h = out(reg) _,
                        s3l = out(reg) _, s3h = out(reg) _,
                        s4l = out(reg) _, s4h = out(reg) _,
                        s5l = out(reg) _, s5h = out(reg) _,
                        rl = out(reg) _, rh = out(reg) _,
                        a = out(reg) _, b = out(reg) _,
                        options(nostack),
                    );
                }
            }
        };
    }

    kernel256!(
        /// The AEGIS-256 `Absorb`, over each block of `data`.
        absorb256,
        &[u8],
        as_ptr,
        absorb256
    );
    kernel256!(
        /// The AEGIS-256 `Enc`, over each block of `data` in place.
        encrypt256,
        &mut [u8],
        as_mut_ptr,
        encrypt256
    );
    kernel256!(
        /// The AEGIS-256 `Dec`, over each block of `data` in place.
        decrypt256,
        &mut [u8],
        as_mut_ptr,
        decrypt256
    );
}
