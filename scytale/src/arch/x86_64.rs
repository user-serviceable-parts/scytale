//! Which x86-64 instruction sets this processor has.
//!
//! One `cpuid` pass answers for every feature the crate looks for;
//! [`crate::features::detected`] keeps the answer, so this runs once.

#![allow(unsafe_code)]

use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

use crate::features::{Features, x86_64::Feature};

/// Everything this processor and operating system have, of the
/// features the crate names.
pub(crate) fn detected() -> Features {
    let leaf1 = __cpuid(1);
    // A processor whose highest leaf is below seven answers leaf seven
    // with the data of its highest, not with zeros, so the bits would
    // be whatever that leaf happens to hold.
    let (ebx7, ecx7) = if __cpuid(0).eax >= 7 {
        let leaf7 = __cpuid_count(7, 0);
        (leaf7.ebx, leaf7.ecx)
    } else {
        (0, 0)
    };

    // AVX, and every instruction encoded with it, faults unless the
    // operating system has turned the wider register state on: OSXSAVE
    // (ECX bit 27) says XGETBV may be asked, and XCR0 bits 1 and 2 say
    // the SSE and AVX state are saved.
    let osxsave = leaf1.ecx & (1 << 27) != 0;
    let avx = osxsave && leaf1.ecx & (1 << 28) != 0 && {
        // SAFETY: OSXSAVE was just confirmed, so XGETBV is available.
        let xcr0 = unsafe { _xgetbv(0) };
        xcr0 & 0b110 == 0b110
    };

    let mut found = Features::new();
    let mut add = |has: bool, feature: Feature| {
        if has {
            found.insert(feature.into());
        }
    };
    add(leaf1.ecx & (1 << 25) != 0, Feature::Aes);
    add(leaf1.ecx & (1 << 9) != 0, Feature::Ssse3);
    add(leaf1.ecx & (1 << 19) != 0, Feature::Sse41);
    add(leaf1.ecx & (1 << 1) != 0, Feature::Pclmulqdq);
    add(avx, Feature::Avx);
    add(avx && ebx7 & (1 << 5) != 0, Feature::Avx2);
    add(avx && ecx7 & (1 << 9) != 0, Feature::Vaes);
    add(avx && ecx7 & (1 << 10) != 0, Feature::Vpclmulqdq);
    add(ebx7 & (1 << 29) != 0, Feature::Sha);
    add(ebx7 & (1 << 19) != 0, Feature::Adx);
    add(ebx7 & (1 << 3) != 0, Feature::Bmi1);
    add(ebx7 & (1 << 8) != 0, Feature::Bmi2);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The standard library asks the same questions by another route,
    /// and must get the same answers for what both can name.
    #[test]
    fn agrees_with_the_standard_library() {
        use std::arch::is_x86_feature_detected as has;
        let found = detected();
        let pairs = [
            (Feature::Aes, has!("aes")),
            (Feature::Ssse3, has!("ssse3")),
            (Feature::Sse41, has!("sse4.1")),
            (Feature::Avx, has!("avx")),
            (Feature::Avx2, has!("avx2")),
            (Feature::Vaes, has!("vaes") && has!("avx")),
            (Feature::Pclmulqdq, has!("pclmulqdq")),
            (Feature::Vpclmulqdq, has!("vpclmulqdq") && has!("avx")),
            (Feature::Sha, has!("sha")),
            (Feature::Adx, has!("adx")),
            (Feature::Bmi1, has!("bmi1")),
            (Feature::Bmi2, has!("bmi2")),
        ];
        for (feature, expected) in pairs {
            assert_eq!(found.contains(feature.into()), expected, "{feature}");
        }
    }
}
