//! Asking the processor what it can do.
//!
//! Each architecture has its own way of reporting which optional
//! instructions are present, and more than one primitive wants the
//! answer, so the asking lives here rather than beside any one of
//! them.

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;
#[cfg(target_arch = "riscv64")]
pub(crate) mod riscv64;
#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

use crate::features::Features;

/// Everything this processor has, of the features the crate names;
/// the empty set on an architecture nothing here is written for.
pub(crate) fn detected() -> Features {
    #[cfg(target_arch = "aarch64")]
    return aarch64::detected();
    #[cfg(target_arch = "riscv64")]
    return riscv64::detected();
    #[cfg(target_arch = "x86_64")]
    return x86_64::detected();
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )))]
    Features::new()
}
