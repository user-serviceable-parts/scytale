//! Which AArch64 instruction sets this processor has.
//!
//! The fields of `ID_AA64ISAR0_EL1` say. Linux traps and emulates
//! reads of the ID registers from user space (since 4.11); without an
//! operating system that does, there is no safe way to ask, and only
//! a feature named at build time counts. One read answers for every
//! feature the crate looks for; [`crate::features::detected`] keeps
//! the answer, so this runs once.

#![allow(unsafe_code)]

use crate::features::{Features, aarch64::Feature};

/// Everything this processor has, of the features the crate names.
pub(crate) fn detected() -> Features {
    let isar0 = isar0();
    let field = |low: u32| (isar0 >> low) & 0xf;
    // The AES field, bits 7:4: 1 means the AES instructions, 2 adds
    // the 64-bit polynomial multiply. The SHA2 field, bits 15:12: 1
    // means SHA-256, 2 adds SHA-512. SHA1 is bits 11:8, SHA3 bits
    // 35:32. The build-time names group them as the targets do: `aes`
    // brings PMULL, `sha2` brings SHA-1, `sha3` brings SHA-512.
    let aes = cfg!(target_feature = "aes");
    let sha2 = cfg!(target_feature = "sha2");
    let sha3 = cfg!(target_feature = "sha3");

    let mut found = Features::new();
    let mut add = |has: bool, feature: Feature| {
        if has {
            found.insert(feature.into());
        }
    };
    add(aes || field(4) >= 1, Feature::Aes);
    add(aes || field(4) >= 2, Feature::Pmull);
    add(sha2 || field(8) >= 1, Feature::Sha1);
    add(sha2 || field(12) >= 1, Feature::Sha2);
    add(sha3 || field(12) >= 2, Feature::Sha512);
    add(sha3 || field(32) != 0, Feature::Sha3);
    found
}

/// `ID_AA64ISAR0_EL1`, as the kernel shows it to user space.
#[cfg(target_os = "linux")]
fn isar0() -> u64 {
    let isar0: u64;
    // SAFETY: reads a register the kernel exposes to user space; no
    // memory is touched.
    unsafe {
        core::arch::asm!(
            "mrs {}, ID_AA64ISAR0_EL1",
            out(reg) isar0,
            options(nomem, nostack, preserves_flags),
        );
    }
    isar0
}

/// Without an operating system that exposes the ID registers there is
/// no safe way to ask, so every field reads as absent.
#[cfg(not(target_os = "linux"))]
fn isar0() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The standard library asks the same questions by another route,
    /// and must get the same answers for what both can name. It
    /// reports SHA-512 and SHA-3 together, as one feature.
    #[test]
    fn agrees_with_the_standard_library() {
        use std::arch::is_aarch64_feature_detected as has;
        let found = detected();
        let pairs = [
            (Feature::Aes, has!("aes")),
            (Feature::Pmull, has!("pmull")),
            (Feature::Sha2, has!("sha2")),
            (Feature::Sha512, has!("sha3")),
            (Feature::Sha3, has!("sha3")),
        ];
        for (feature, expected) in pairs {
            assert_eq!(found.contains(feature.into()), expected, "{feature}");
        }
    }
}
