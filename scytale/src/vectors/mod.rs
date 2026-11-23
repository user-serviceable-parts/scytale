//! The Wycheproof, CFRG and BLAKE2 vector suites.
//!
//! Inside the crate rather than in `tests/`, because an integration
//! test is a separate crate and would see only the public types,
//! while each kernel is validated in its own right. The NIST ACVP
//! suites are not here: they run through the public API from the
//! `scytale-acvp` crate, offline against the vendored files and
//! online against NIST's servers, and every kernel is reached there
//! by the feature profile that selects it.
//!
//! The suites here run under the kernel this processor dispatches to;
//! each kernel answers its own vectors in its kernel test, which runs
//! the drivers here through a builder built under its row.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

pub(crate) mod support;

/// ChaCha20-Poly1305 (RFC 8439), through Project Wycheproof's cases:
/// there is no ACVP suite for it. The whole AEAD runs under the
/// kernel the processor picks, and each kernel runs the keystream
/// those same cases imply.
mod chacha20_poly1305 {
    use super::*;

    #[test]
    fn wycheproof() {
        support::wycheproof::chacha20_poly1305::run();
    }
}

/// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha), through Project
/// Wycheproof's cases: there is no ACVP suite for it either. The
/// keystream kernels are ChaCha20's and are covered above; what this
/// adds is the HChaCha20 block, which is one portable function.
mod xchacha20_poly1305 {
    use super::*;

    #[test]
    fn wycheproof() {
        support::wycheproof::xchacha20_poly1305::run();
    }
}

/// Key agreement: X25519, X448 and ECDH, through Project Wycheproof's
/// edge cases. ACVP's XECDH suites run from `scytale-acvp`.
mod kex {
    use super::*;

    #[test]
    fn wycheproof_ecdh() {
        support::wycheproof::ecdh::run();
    }

    #[test]
    fn wycheproof_x25519() {
        support::wycheproof::x25519::run();
    }

    #[test]
    fn wycheproof_x448() {
        support::wycheproof::x448::run();
    }
}

/// Key encapsulation: ML-KEM, through Project Wycheproof's malformed
/// keys and ciphertexts.
mod kem {
    use super::*;

    #[test]
    fn wycheproof_ml_kem() {
        support::wycheproof::ml_kem::run();
    }
}

/// Public-key encryption: HPKE, through the CFRG test vectors.
mod pke {
    use super::*;

    #[test]
    fn cfrg_hpke() {
        support::cfrg::run();
    }
}

/// BLAKE2b (RFC 7693), through the reference implementation's
/// known answers: there is no ACVP or Wycheproof suite for it. One
/// implementation, so nothing to repeat per kernel.
mod blake2 {
    use super::*;

    #[test]
    fn reference_known_answers() {
        support::blake2::run();
    }
}

/// Signatures: ECDSA, Ed25519, Ed448, ML-DSA and RSA, through Project
/// Wycheproof.
mod sig {
    use super::*;

    #[test]
    fn wycheproof_ecdsa() {
        support::wycheproof::ecdsa::run();
    }

    #[test]
    fn wycheproof_ed25519() {
        support::wycheproof::ed25519::run();
    }

    #[test]
    fn wycheproof_ed448() {
        support::wycheproof::ed448::run();
    }

    #[test]
    fn wycheproof_ml_dsa() {
        support::wycheproof::ml_dsa::run();
    }

    #[test]
    fn wycheproof_rsa() {
        support::wycheproof::rsa::run();
    }
}
