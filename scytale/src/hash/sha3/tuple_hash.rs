//! TupleHash (NIST SP 800-185): a hash of a sequence of strings.
//!
//! Hashing strings one after another loses where each ends: `"ab",
//! "c"` and `"a", "bc"` are the same bytes. TupleHash absorbs each
//! string with its length ahead of it, so two sequences hash alike
//! only if they hold the same strings in the same order. It is
//! cSHAKE under the function name `"TupleHash"`, with the output
//! length absorbed last.
//!
//! ```
//! use scytale::hash::sha3::TupleHash128;
//!
//! let mut hash = TupleHash128::new(b"My Tuple App");
//! hash.push(&[0, 1, 2]);
//! hash.push(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
//! let mut out = [0u8; 32];
//! hash.finalize_to(&mut out);
//! assert_eq!(out[..4], [0x75, 0xcd, 0xb2, 0x0f]);
//! ```
//!
//! As with KMAC, the output length is absorbed before the output is
//! squeezed, so a 16-byte hash is not the first half of a 32-byte
//! one. TupleHashXOF, [`finalize_xof`](TupleHash128::finalize_xof),
//! fixes no length and gives a stream instead.

use core::fmt;

use super::cshake::{Core, bits_of, left_encode, right_encode};
use super::{Auto, AutoReader, variant};
use crate::hash::XofReader;

/// The function name TupleHash gives cSHAKE.
const NAME: &[u8] = b"TupleHash";

/// Defines TupleHash at one width, with its XOF reader.
macro_rules! tuple_hash {
    ($(#[$doc:meta])* $name:ident, $reader:ident, $variant:ident) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name {
            /// cSHAKE after the name and customization.
            core: Core<Auto<variant::$variant>>,
        }

        #[doc = concat!("The output stream of [`", stringify!($name),
            "::finalize_xof`], TupleHashXOF.")]
        #[derive(Clone, Debug)]
        pub struct $reader(AutoReader<variant::$variant>);

        impl XofReader for $reader {
            fn squeeze(&mut self, out: &mut [u8]) {
                self.0.squeeze(out)
            }
        }

        impl $name {
            /// Starts a hash under `customization`, which may be
            /// empty.
            pub fn new(customization: &[u8]) -> Self {
                $name {
                    core: Core::with(Auto::new(), NAME, customization),
                }
            }

            /// Appends `element` to the sequence as one string.
            ///
            /// Unlike a message's `update`, each call is a string of
            /// its own: pushing `"ab"` then `"c"` is not pushing
            /// `"abc"`.
            pub fn push(&mut self, element: &[u8]) {
                let (length, n) = left_encode(bits_of(element));
                self.core.update(&length[..n]);
                self.core.update(element);
            }

            /// Ends the sequence and fills `out` with its hash, the
            /// output length being `out`'s. The hash is then back at
            /// the start of a sequence.
            pub fn finalize_to(&mut self, out: &mut [u8]) {
                let (length, n) = right_encode(bits_of(out));
                self.core.update(&length[..n]);
                self.core.finalize_xof().squeeze(out);
            }

            /// Ends the sequence and returns TupleHashXOF's output
            /// stream, which commits to no length. The hash is then
            /// back at the start of a sequence.
            pub fn finalize_xof(&mut self) -> $reader {
                let (length, n) = right_encode(0);
                self.core.update(&length[..n]);
                $reader(self.core.finalize_xof())
            }

            /// Returns to the start of a sequence, under the same
            /// customization.
            pub fn reset(&mut self) {
                self.core.reset()
            }
        }

        impl fmt::Debug for $name {
            /// Deliberately omits the state, which is a function of
            /// the strings.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

tuple_hash!(
    /// TupleHash128, over cSHAKE128.
    TupleHash128,
    TupleHash128Reader,
    CShake128
);
tuple_hash!(
    /// TupleHash256, over cSHAKE256.
    TupleHash256,
    TupleHash256Reader,
    CShake256
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::vec;
    use std::vec::Vec;

    fn unhex(text: &str) -> Vec<u8> {
        let text: Vec<u8> =
            text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        text.chunks(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).expect("ascii");
                u8::from_str_radix(pair, 16).expect("hex")
            })
            .collect()
    }

    const APP: &[u8] = b"My Tuple App";

    /// The three strings of the NIST samples, of which each sample
    /// takes the first two or all three.
    fn strings(n: usize) -> Vec<Vec<u8>> {
        let all = [
            vec![0x00, 0x01, 0x02],
            (0x10..=0x15).collect(),
            (0x20..=0x28).collect(),
        ];
        all[..n].to_vec()
    }

    fn hash128(n: usize, s: &[u8], xof: bool) -> Vec<u8> {
        let mut h = TupleHash128::new(s);
        strings(n).iter().for_each(|e| h.push(e));
        let mut out = vec![0u8; 32];
        if xof {
            h.finalize_xof().squeeze(&mut out);
        } else {
            h.finalize_to(&mut out);
        }
        out
    }

    fn hash256(n: usize, s: &[u8], xof: bool) -> Vec<u8> {
        let mut h = TupleHash256::new(s);
        strings(n).iter().for_each(|e| h.push(e));
        let mut out = vec![0u8; 64];
        if xof {
            h.finalize_xof().squeeze(&mut out);
        } else {
            h.finalize_to(&mut out);
        }
        out
    }

    /// The NIST TupleHash samples, 1 to 6.
    #[test]
    fn nist_tuplehash_samples() {
        assert_eq!(
            hash128(2, b"", false),
            unhex(
                "C5D8786C1AFB9B82111AB34B65B2C004
                 8FA64E6D48E263264CE1707D3FFC8ED1"
            )
        );
        assert_eq!(
            hash128(2, APP, false),
            unhex(
                "75CDB20FF4DB1154E841D758E24160C5
                 4BAE86EB8C13E7F5F40EB35588E96DFB"
            )
        );
        assert_eq!(
            hash128(3, APP, false),
            unhex(
                "E60F202C89A2631EDA8D4C588CA5FD07
                 F39E5151998DECCF973ADB3804BB6E84"
            )
        );
        assert_eq!(
            hash256(2, b"", false),
            unhex(
                "CFB7058CACA5E668F81A12A20A2195CE
                 97A925F1DBA3E7449A56F82201EC6073
                 11AC2696B1AB5EA2352DF1423BDE7BD4
                 BB78C9AED1A853C78672F9EB23BBE194"
            )
        );
        assert_eq!(
            hash256(2, APP, false),
            unhex(
                "147C2191D5ED7EFD98DBD96D7AB5A116
                 92576F5FE2A5065F3E33DE6BBA9F3AA1
                 C4E9A068A289C61C95AAB30AEE1E410B
                 0B607DE3620E24A4E3BF9852A1D4367E"
            )
        );
        assert_eq!(
            hash256(3, APP, false),
            unhex(
                "45000BE63F9B6BFD89F54717670F69A9
                 BC763591A4F05C50D68891A744BCC6E7
                 D6D5B5E82C018DA999ED35B0BB49C967
                 8E526ABD8E85C13ED254021DB9E790CE"
            )
        );
    }

    /// The NIST TupleHashXOF samples, 1 to 6.
    #[test]
    fn nist_tuplehashxof_samples() {
        assert_eq!(
            hash128(2, b"", true),
            unhex(
                "2F103CD7C32320353495C68DE1A81292
                 45C6325F6F2A3D608D92179C96E68488"
            )
        );
        assert_eq!(
            hash128(2, APP, true),
            unhex(
                "3FC8AD69453128292859A18B6C67D7AD
                 85F01B32815E22CE839C49EC374E9B9A"
            )
        );
        assert_eq!(
            hash128(3, APP, true),
            unhex(
                "900FE16CAD098D28E74D632ED852F99D
                 AAB7F7DF4D99E775657885B4BF76D6F8"
            )
        );
        assert_eq!(
            hash256(2, b"", true),
            unhex(
                "03DED4610ED6450A1E3F8BC44951D14F
                 BC384AB0EFE57B000DF6B6DF5AAE7CD5
                 68E77377DAF13F37EC75CF5FC598B684
                 1D51DD207C991CD45D210BA60AC52EB9"
            )
        );
        assert_eq!(
            hash256(2, APP, true),
            unhex(
                "6483CB3C9952EB20E830AF4785851FC5
                 97EE3BF93BB7602C0EF6A65D741AECA7
                 E63C3B128981AA05C6D27438C79D2754
                 BB1B7191F125D6620FCA12CE658B2442"
            )
        );
        assert_eq!(
            hash256(3, APP, true),
            unhex(
                "0C59B11464F2336C34663ED51B2B950B
                 EC743610856F36C28D1D088D8A244628
                 4DD09830A6A178DC752376199FAE935D
                 86CFDEE5913D4922DFD369B66A53C897"
            )
        );
    }

    /// Where the strings divide matters, which is the point.
    #[test]
    fn boundaries_count() {
        let hash = |parts: &[&[u8]]| {
            let mut h = TupleHash128::new(b"");
            parts.iter().for_each(|p| h.push(p));
            let mut out = [0u8; 32];
            h.finalize_to(&mut out);
            out
        };
        assert_ne!(hash(&[b"ab", b"c"]), hash(&[b"a", b"bc"]));
        assert_ne!(hash(&[b"abc"]), hash(&[b"abc", b""]));
        assert_ne!(hash(&[]), hash(&[b""]));
    }

    /// The output length is part of the hash, and finalizing or
    /// resetting starts the next sequence afresh.
    #[test]
    fn length_finalize_and_reset() {
        let mut h = TupleHash256::new(APP);
        let mut short = [0u8; 16];
        let mut long = [0u8; 32];
        h.push(b"x");
        h.finalize_to(&mut short);
        h.push(b"x");
        h.finalize_to(&mut long);
        assert_ne!(short[..], long[..16]);

        h.push(b"garbage");
        h.reset();
        h.push(b"x");
        let mut again = [0u8; 32];
        h.finalize_to(&mut again);
        assert_eq!(again, long);
    }

    /// The state stays out of the debug output.
    #[test]
    fn debug_omits_the_state() {
        let h = TupleHash128::new(b"secret label");
        assert_eq!(format!("{h:?}"), "TupleHash128 { .. }");
    }
}
