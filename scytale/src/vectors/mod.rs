//! The Wycheproof, CFRG and BLAKE2 vector suites, and the inventory
//! of the implementations this build holds.
//!
//! Inside the crate rather than in `tests/`, because an integration
//! test is a separate crate and would see only the public types,
//! while each kernel is validated in its own right. The NIST ACVP
//! suites are not here: they run through the public API from the
//! `scytale-acvp` crate, offline against the vendored files and
//! online against NIST's servers, and every kernel is reached there
//! by the feature profile that selects it.
//!
//! A kernel the processor cannot run is reported, never silently
//! skipped; [`inventory`] prints the ones that are built and says
//! which of them this processor can run.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

mod support;

/// Runs `suite` once per kernel in `kernels` that this processor can
/// build, and reports the ones it cannot: a silent skip would look
/// like a pass. A kernel named twice, under two sets that each
/// suffice, runs once.
fn every_kernel<K>(
    kernels: &[(K, crate::features::Features)],
    available: impl Fn(K) -> bool,
    suite: impl Fn(K),
) where
    K: Copy + PartialEq + core::fmt::Debug,
{
    for (i, &(kernel, _)) in kernels.iter().enumerate() {
        if kernels[..i].iter().any(|(k, _)| *k == kernel) {
            continue;
        }
        if available(kernel) {
            suite(kernel);
        } else {
            eprintln!("{kernel:?} not available; skipping");
        }
    }
}

/// ChaCha20-Poly1305 (RFC 8439), through Project Wycheproof's cases:
/// there is no ACVP suite for it. The whole AEAD runs under the
/// kernel the processor picks, and each kernel runs the keystream
/// those same cases imply.
mod chacha20_poly1305 {
    use super::*;
    use crate::Key;
    use crate::cipher::chacha20::ChaCha20;

    #[test]
    fn wycheproof() {
        support::wycheproof::chacha20_poly1305::run();
    }

    #[test]
    fn wycheproof_keystream() {
        every_kernel(
            ChaCha20::kernels(),
            |kernel| {
                ChaCha20::with_kernel(&Key::from([0u8; 32]), kernel).is_some()
            },
            |kernel| {
                support::wycheproof::chacha20_poly1305::run_cipher(&|key| {
                    ChaCha20::with_kernel(key, kernel).expect("available")
                })
            },
        );
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

/// The suites above run once, under the kernels the processor picks,
/// and the kernels below those answer the ACVP vectors that test
/// them, from `scytale-acvp`. Poly1305 has no ACVP suite, so its
/// other kernels answer Wycheproof's cases here, each once.
///
/// This changes the set in force for the whole process, so it is
/// ignored by default and run on its own, single-threaded, as
/// `features::tests::alone` is:
///
/// ```text
/// cargo test --lib vectors::alone -- --ignored --test-threads=1
/// ```
mod alone {
    use super::support;
    use crate::features;
    use crate::mac::poly1305::Poly1305;

    /// Puts the hardware back in force when dropped, so a failed
    /// assertion does not leave the next test a narrowed set.
    struct Restore;

    impl Drop for Restore {
        fn drop(&mut self) {
            features::reset();
        }
    }

    #[test]
    #[ignore]
    fn chacha20_poly1305_under_every_other_poly1305_kernel() {
        let _restore = Restore;
        let rows = Poly1305::profiles();
        let row = |set| {
            rows.iter()
                .position(|p| p.is_subset(set))
                .expect("every list ends empty")
        };
        // The row the plain test above ran under.
        let picked = row(features::get());
        for (i, &profile) in rows.iter().enumerate() {
            if i == picked || features::set(profile).is_err() {
                continue;
            }
            assert_eq!(row(profile), i, "{profile} selects its own row");
            support::wycheproof::chacha20_poly1305::run();
        }
    }
}

/// Every implementation this build holds, whether this processor
/// can run it, and whether that is the right answer.
///
/// A suite whose implementation is absent skips, and a skip reads as
/// a pass, so this is where a log says what was actually exercised:
///
/// ```text
/// cargo test --lib acvp::inventory -- --nocapture
/// ```
///
/// It is also where the probes are held to account. Each row says
/// which processor features its implementation needs, in the names
/// the standard library detects them by, and the row has to be
/// available exactly when the processor has them all. That fails in
/// both directions: a probe that asks for less than its loop uses is
/// caught on the first processor that has the one and not the other,
/// before the loop is run there; and a probe that has started saying
/// no everywhere, which would otherwise leave its implementation
/// untested behind a run of passing skips, is caught on any machine
/// that has the features. Emulated processors are what make the
/// first of those happen: see the jobs in `ci.yml`.
///
/// A job that emulates a processor says what it expects of it in
/// `SCYTALE_CPU_FEATURES`, a list separated by spaces. The list is
/// checked against what the processor reports, so that an emulator
/// too old to offer an extension fails the job rather than quietly
/// testing nothing; and on RISC-V, where the standard library cannot
/// yet be asked, the list is all the rows have to be checked against.
mod inventory {
    use std::cell::RefCell;
    use std::string::String;
    use std::string::ToString;
    use std::vec::Vec;
    #[allow(unused_imports)]
    use std::{format, println, vec};

    use crate::cipher::{aes, chacha20};
    use crate::features::{self, Feature, Features};
    use crate::hash::{sha2, sha3};

    /// Where an emulating job declares the processor's features.
    const DECLARED: &str = "SCYTALE_CPU_FEATURES";

    /// The table as it is printed, and what was wrong with it.
    struct Audit {
        /// What the job said the processor has, if it said.
        declared: Option<Features>,
        wrong: RefCell<Vec<String>>,
        /// Whether every row must be available: the `-cpu max` jobs
        /// set [`EXPECT_ALL`], so a kernel no machine in CI can build
        /// fails there instead of skipping forever.
        expect_all: bool,
    }

    /// Set, to anything, where every row is expected to run.
    const EXPECT_ALL: &str = "SCYTALE_EXPECT_ALL";

    impl Audit {
        fn new() -> Self {
            let declared = std::env::var(DECLARED).ok().map(|list| {
                list.parse::<Features>().unwrap_or_else(|_| {
                    panic!("{DECLARED} names a feature no row knows: {list}")
                })
            });
            let audit = Audit {
                declared,
                wrong: RefCell::new(Vec::new()),
                expect_all: std::env::var(EXPECT_ALL)
                    .is_ok_and(|v| !v.is_empty()),
            };
            let Some(declared) = audit.declared else {
                return audit;
            };
            // The emulator has to be offering what the job thinks it
            // is, or the job is not testing what it says.
            let found = features::detected();
            for feature in features::native_all().iter() {
                let (said, is) =
                    (declared.contains(feature), found.contains(feature));
                if said != is {
                    audit.wrong.borrow_mut().push(format!(
                        "{feature}: the processor reports {is}, \
                         {DECLARED} says {said}"
                    ));
                }
            }
            audit
        }

        /// What a kernel may need, by the job's word where it gave
        /// one and the set in force otherwise, and the virtual
        /// features with it: what [`features::available`] grants the
        /// test constructors, so the rows here say what the suites
        /// ran.
        fn has(&self) -> Features {
            self.declared.unwrap_or_else(features::get)
                | Features::of(&[Feature::Isolated])
        }

        /// Whether a kernel should be available: one that needs
        /// nothing always is, and one with `requires` listed is
        /// where any one of those sets is present.
        fn expects(&self, requires: &[Features]) -> bool {
            let has = self.has();
            requires.is_empty() || requires.iter().any(|r| r.is_subset(has))
        }

        /// One row, under the heading `suite`: the modes all call
        /// their kernels by the same names.
        fn row(
            &self,
            suite: &str,
            name: &str,
            available: bool,
            requires: &[Features],
        ) {
            let state = if available { "run" } else { "not available" };
            println!("  {name:<32} {state}");
            if self.expect_all && !available {
                self.wrong.borrow_mut().push(format!(
                    "{suite} {name}: not available, and {EXPECT_ALL} says \
                     every kernel must be"
                ));
            }
            let expected = self.expects(requires);
            if expected != available {
                let needs: Vec<String> =
                    requires.iter().map(|r| r.to_string()).collect();
                self.wrong.borrow_mut().push(format!(
                    "{suite} {name}: {state}, but it needs one of {needs:?} \
                     and the processor {}",
                    if expected { "has it" } else { "lacks them all" }
                ));
            }
        }

        fn finish(self) {
            let source = match self.declared {
                Some(_) => DECLARED,
                None => "the library's own detection",
            };
            println!("checked against {source}\n");
            let wrong = self.wrong.into_inner();
            assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
        }
    }

    /// Every kernel of one list, named, with what it needs from each
    /// row that names it, and whether `has` can build it.
    fn kernels<K>(
        audit: &Audit,
        suite: &str,
        all: &[(K, Features)],
        has: &dyn Fn(K) -> bool,
    ) where
        K: Copy + PartialEq + core::fmt::Debug,
    {
        println!("{suite}");
        for (i, &(k, _)) in all.iter().enumerate() {
            if all[..i].iter().any(|(other, _)| *other == k) {
                continue;
            }
            let needs: Vec<Features> = all
                .iter()
                .filter(|(other, _)| *other == k)
                .map(|(_, needs)| *needs)
                .collect();
            audit.row(suite, &format!("{k:?}"), has(k), &needs);
        }
    }

    /// Every kernel of every mode that has more than one, under the
    /// cipher `C`. What each needs comes from its row in the mode's
    /// list, the same row that chooses it.
    fn modes<C>(audit: &Audit)
    where
        C: crate::cipher::BlockCipher<
                Block = [u8; 16],
                Key = crate::Key<[u8; 16]>,
            >,
    {
        use crate::aead::{ccm, gcm, gcm_siv};
        use crate::cipher::mode::{cbc, ctr, xts};

        let key = crate::Key::from([0x42u8; 16]);
        let tweak = crate::Key::from([0x99u8; 16]);
        kernels(audit, "AES-CBC", cbc::KERNELS, &|k| {
            cbc::Cbc::<C>::with_kernel(&key, k).is_some()
        });
        kernels(audit, "AES-CTR", ctr::KERNELS, &|k| {
            ctr::Ctr::<C>::with_kernel(&key, k).is_some()
        });
        kernels(audit, "AES-XTS", xts::KERNELS, &|k| {
            xts::Xts::<C>::with_kernel(&key, &tweak, k).is_some()
        });
        kernels(audit, "AES-CCM", ccm::KERNELS, &|k| {
            ccm::Ccm::<C>::with_kernel(&key, k).is_some()
        });
        kernels(audit, "AES-GCM", gcm::KERNELS, &|k| {
            gcm::Gcm::<C>::with_kernel(&key, k).is_some()
        });
        kernels(audit, "AES-GCM-SIV", gcm_siv::KERNELS, &|k| {
            gcm_siv::GcmSiv::<C>::with_kernel(&key, k).is_some()
        });
    }

    /// Every kernel the crate has, from the lists that choose them,
    /// and whether this processor can build each. The dispatching
    /// types themselves need nothing and are not rows.
    #[test]
    fn implementations() {
        let audit = Audit::new();
        println!();
        kernels(&audit, "AES", aes::KERNELS, &|k| {
            aes::Aes::<16>::with_kernel(&[0; 16], k).is_some()
        });

        // The modes and AEADs written out for particular
        // instructions, which are kernels in their own right and
        // validated by name like the cipher's above.
        modes::<aes::Aes128>(&audit);

        // SHA-256 and SHA-512 are listed apart: they are different
        // instructions, and a processor can have one without the
        // other.
        kernels(&audit, "SHA-256", sha2::Sha256::kernels(), &|k| {
            sha2::Sha256::with_kernel(k).is_some()
        });
        kernels(&audit, "SHA-512", sha2::Sha512::kernels(), &|k| {
            sha2::Sha512::with_kernel(k).is_some()
        });
        kernels(&audit, "SHA-3", sha3::kernels(), &|k| {
            sha3::Sha3_256::with_kernel(k).is_some()
        });
        let key = crate::Key::from([0u8; 32]);
        kernels(&audit, "ChaCha20", chacha20::ChaCha20::kernels(), &|k| {
            chacha20::ChaCha20::with_kernel(&key, k).is_some()
        });

        // The kernels no dispatching type stands over: a hash with
        // no kernel in the value, the multiply inside GHASH, and the
        // arithmetic behind the curves, RSA and Poly1305. Each is a
        // list all the same, and what its code asks of the set in
        // force is what is reported here.
        use crate::aead::ghash;
        use crate::hash::sha1;
        kernels(&audit, "SHA-1", sha1::KERNELS, &|k| {
            features::allows(sha1::KERNELS, k)
        });
        kernels(&audit, "GHASH", ghash::KERNELS, &|k| {
            features::allows(ghash::KERNELS, k)
        });
        #[cfg(target_arch = "x86_64")]
        {
            use crate::mac::poly1305;
            use crate::math::{ec, limbs};
            kernels(&audit, "Limb arithmetic", limbs::x86_64::KERNELS, &|k| {
                features::allows(limbs::x86_64::KERNELS, k)
            });
            kernels(&audit, "P-256 point table", ec::x86_64::KERNELS, &|k| {
                features::allows(ec::x86_64::KERNELS, k)
            });
            kernels(&audit, "Poly1305", poly1305::x86_64::KERNELS, &|k| {
                features::allows(poly1305::x86_64::KERNELS, k)
            });
            // The POLYVAL loop GCM-SIV hashes with borrows GCM's
            // narrower row rather than having one of its own.
            println!("POLYVAL");
            audit.row(
                "POLYVAL",
                "gcm::x86_64::Polyval",
                crate::aead::gcm::x86_64::Polyval::new(&[0; 16]).is_some(),
                &[crate::aead::gcm::x86_64::NARROW],
            );
        }
        audit.finish();
    }
}
