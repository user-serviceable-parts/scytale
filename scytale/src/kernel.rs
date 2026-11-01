//! The names the mode kernels go by.
//!
//! A mode is written more than once: for the instructions a processor
//! offers, and for a processor that offers none. Which one ran is not
//! an internal detail -- it is the first thing a benchmark or a
//! vector suite has to say, and it decides whether a processor can
//! run the code at all. So the kernels are named for their
//! instructions, and the names are kept here rather than invented
//! separately by each mode.
//!
//! Each mode lists its kernels as rows of `(Kernel, Features)`, best
//! first, and a new value takes the first row whose needs the set in
//! force meets, through [`features::select`](crate::features::select).
//! The list is the one place a kernel is named: the tests, the vector
//! suites and the benchmark walk it rather than keep lists of their
//! own, and what a caller outside the crate sees is the needs alone,
//! through [`Dispatcher`](crate::features::Dispatcher).
//!
//! Only the names a mode or an AEAD can be written against are here.
//! A primitive whose kernels turn on some other instruction -- GHASH
//! on RISC-V, which has three ways to multiply -- names those itself,
//! since they are its own and no other suite shares them.

/// Which kernel of a mode is meant.
///
/// The hardware names exist only on the architecture that has them,
/// so naming one that cannot be built is a compile error rather than
/// a run-time nothing. Every architecture has [`Portable`].
///
/// [`Portable`]: Kernel::Portable
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    /// AES-NI, with PCLMULQDQ where a hash runs beside the cipher.
    #[cfg(target_arch = "x86_64")]
    Aesni,
    /// VAES, two blocks to a register, with VPCLMULQDQ likewise.
    #[cfg(target_arch = "x86_64")]
    Vaes,
    /// The ARMv8 cryptographic extension.
    #[cfg(target_arch = "aarch64")]
    Armv8,
    /// RISC-V vector AES, Zvkned, with whatever vector hash the mode
    /// needs beside it.
    #[cfg(target_arch = "riscv64")]
    Zvkned,
    /// The construction over the cipher's own calls, which every
    /// processor can run whatever cipher it was given.
    Portable,
}

/// The rows of a mode's list that a cipher can run with: all of them
/// where the instructions can read its key schedule, and the last
/// alone, the portable construction over the cipher's own calls,
/// where they cannot.
///
/// Generic over the row so that a kernel list and its profiles are
/// cut the same way.
pub(crate) fn rows_for<T>(rows: &'static [T], readable: bool) -> &'static [T] {
    if readable {
        rows
    } else {
        &rows[rows.len() - 1..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;
    use crate::aead::{Ccm, Gcm, GcmSiv, ccm, gcm, gcm_siv};
    use crate::cipher::aes::Aes128;
    use crate::cipher::mode::{Cbc, Ctr, Xts, cbc, ctr, xts};
    use crate::features::{self, Features};

    /// Every mode dispatches as the primitives do: the list ends in
    /// the portable kernel, each row can be chosen, the profiles are
    /// the rows' needs, and a new value takes the first row the set
    /// in force meets. Over AES, whose schedule the instructions can
    /// read, so every row is in play.
    #[test]
    fn every_mode_picks_the_first_kernel_whose_needs_are_met() {
        let key = Key::from([0u8; 16]);
        let tweak = Key::from([1u8; 16]);
        let cbc = Cbc::<Aes128>::new(&key);
        features::dispatches(
            cbc::KERNELS,
            Cbc::<Aes128>::profiles(),
            cbc.kernel(),
        );
        let ctr = Ctr::<Aes128>::new(&key);
        features::dispatches(
            ctr::KERNELS,
            Ctr::<Aes128>::profiles(),
            ctr.kernel(),
        );
        let xts = Xts::<Aes128>::try_new(&key, &tweak).expect("distinct");
        features::dispatches(
            xts::KERNELS,
            Xts::<Aes128>::profiles(),
            xts.kernel(),
        );
        let gcm = Gcm::<Aes128>::new(&key);
        features::dispatches(
            gcm::KERNELS,
            Gcm::<Aes128>::profiles(),
            gcm.kernel(),
        );
        let siv = GcmSiv::<Aes128>::new(&key);
        features::dispatches(
            gcm_siv::KERNELS,
            GcmSiv::<Aes128>::profiles(),
            siv.kernel(),
        );
        let ccm = Ccm::<Aes128>::new(&key);
        features::dispatches(
            ccm::KERNELS,
            Ccm::<Aes128>::profiles(),
            ccm.kernel(),
        );
    }

    /// Each list names a kernel once: one that named it twice would
    /// measure and validate it twice over.
    #[test]
    fn every_list_names_each_kernel_once() {
        for list in [
            cbc::KERNELS,
            ctr::KERNELS,
            xts::KERNELS,
            gcm::KERNELS,
            gcm_siv::KERNELS,
            ccm::KERNELS,
        ] {
            assert_eq!(list.last(), Some(&(Kernel::Portable, Features::new())));
            for (i, (one, _)) in list.iter().enumerate() {
                assert!(
                    !list[i + 1..].iter().any(|(other, _)| other == one),
                    "{one:?} twice"
                );
            }
        }
    }

    #[test]
    fn a_cipher_the_instructions_cannot_read_gets_the_portable_row() {
        const PORTABLE: &[(Kernel, Features)] =
            &[(Kernel::Portable, Features::new())];
        assert_eq!(rows_for(PORTABLE, true), PORTABLE);
        assert_eq!(rows_for(PORTABLE, false), PORTABLE);
        let ctr = crate::cipher::mode::ctr::KERNELS;
        assert_eq!(rows_for(ctr, true), ctr);
        assert_eq!(rows_for(ctr, false), PORTABLE);
    }
}
