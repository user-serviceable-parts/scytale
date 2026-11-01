//! The public face of `features`: what a program outside the crate
//! can see and do. The set in force is global to the process, so the
//! tests that edit it hold a lock, and this file has a binary to
//! itself so that no other test runs beside them.
//!
//! The kernels themselves are not visible from here, by design; the
//! library's own tests check which one a set selects. What can be
//! checked from outside is the shape of each type's profiles, that a
//! narrowed set is honoured, and that every profile answers the same.

use std::sync::{Mutex, MutexGuard};

use scytale::cipher::aes::Aes128;
use scytale::cipher::chacha20::ChaCha20;
use scytale::features::{
    self, Dispatcher, Feature, Features, aarch64, riscv64, x86_64,
};
use scytale::hash::Hash;
use scytale::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use scytale::hash::sha3::{Sha3_256, Shake128};
use scytale::{Error, Key};

static LOCK: Mutex<()> = Mutex::new(());

/// Holds the lock and, when dropped, puts the hardware back in force.
struct Edit(#[allow(dead_code)] MutexGuard<'static, ()>);

impl Edit {
    fn begin() -> Self {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        features::reset();
        Edit(guard)
    }
}

impl Drop for Edit {
    fn drop(&mut self) {
        features::reset();
    }
}

#[test]
fn the_hardware_is_in_force_until_set() {
    let _edit = Edit::begin();
    assert_eq!(features::get(), features::detected());
    assert!(!features::detected().contains(Feature::Isolated));
}

#[test]
fn set_replaces_and_reset_restores() {
    let _edit = Edit::begin();
    features::set(Features::new()).unwrap();
    assert_eq!(features::get(), Features::new());
    features::reset();
    assert_eq!(features::get(), features::detected());
}

#[test]
fn a_virtual_feature_may_be_added() {
    let _edit = Edit::begin();
    let mut f = features::detected();
    f.insert(Feature::Isolated);
    features::set(f).unwrap();
    assert_eq!(features::get(), f);
    assert!(features::get().contains(Feature::Isolated));
}

#[test]
fn a_feature_the_processor_lacks_is_refused() {
    let _edit = Edit::begin();
    let before = features::get();
    let detected = features::detected();
    // Every architecture's features that this processor does not
    // have; on another architecture they are all inert instead.
    let absent: Vec<Feature> = x86_64::Feature::ALL
        .iter()
        .map(|&f| Feature::from(f))
        .chain(aarch64::Feature::ALL.iter().map(|&f| Feature::from(f)))
        .chain(riscv64::Feature::ALL.iter().map(|&f| Feature::from(f)))
        .filter(|&f| !detected.contains(f))
        .collect();
    for f in absent {
        let native = match f {
            Feature::X86_64(_) => cfg!(target_arch = "x86_64"),
            Feature::Aarch64(_) => cfg!(target_arch = "aarch64"),
            Feature::Riscv64(_) => cfg!(target_arch = "riscv64"),
            _ => false,
        };
        let result = features::set(Features::of(&[f]));
        if native {
            assert_eq!(result, Err(Error::UnsupportedFeature(f)), "{f}");
            assert_eq!(features::get(), before, "{f} left a mark");
        } else {
            assert_eq!(result, Ok(()), "{f} should be inert");
            assert_eq!(features::get(), Features::of(&[f]));
            features::reset();
        }
    }
}

#[test]
fn the_empty_set_prints_as_none() {
    assert_eq!(Features::new().to_string(), "none");
    assert_eq!("none".parse::<Features>(), Ok(Features::new()));
}

/// Every dispatching type's profiles end with one that needs nothing,
/// so a value can always be built, and no profile includes one above
/// it, so setting exactly a profile selects the choice it stands for.
#[test]
fn profiles_end_in_nothing_and_are_each_reachable() {
    fn check<T: Dispatcher>() {
        let profiles = T::profiles();
        let last = profiles[profiles.len() - 1];
        assert!(last.is_empty(), "{profiles:?}");
        for (i, higher) in profiles.iter().enumerate() {
            for lower in &profiles[i + 1..] {
                assert!(!higher.is_subset(*lower), "{profiles:?}");
            }
        }
    }
    check::<Aes128>();
    check::<Sha224>();
    check::<Sha256>();
    check::<Sha384>();
    check::<Sha512>();
    check::<Sha3_256>();
    check::<Shake128>();
    check::<ChaCha20>();
    // The trait and the inherent method agree.
    assert_eq!(<Sha256 as Dispatcher>::profiles(), Sha256::profiles());
}

/// Under every profile this processor can satisfy, the type gives
/// the same answer. This is the agreement a vector run relies on.
#[test]
fn every_profile_answers_the_same() {
    let _edit = Edit::begin();
    let hardware = features::detected();
    let key = Key::from([0x42u8; 16]);
    let message = b"the quick brown fox jumps over the lazy dog";

    let reference_hash = Sha256::digest(message);
    let mut reference_block = [[0x5au8; 16]];
    Aes128::new(&key).encrypt(&mut reference_block);

    // Virtual features are granted rather than detected, so a profile
    // naming one is satisfiable whenever its hardware part is.
    let grantable = hardware | Features::of(&[Feature::Isolated]);
    let satisfiable = |p: &Features| p.is_subset(grantable);
    let mut tried = 0;
    for &profile in Sha256::profiles().iter().filter(|p| satisfiable(p)) {
        features::set(profile).unwrap();
        assert_eq!(Sha256::digest(message), reference_hash, "{profile}");
        tried += 1;
    }
    for &profile in Aes128::profiles().iter().filter(|p| satisfiable(p)) {
        features::set(profile).unwrap();
        let mut block = [[0x5au8; 16]];
        Aes128::new(&key).encrypt(&mut block);
        assert_eq!(block, reference_block, "{profile}");
        tried += 1;
    }
    // The empty profile is always satisfiable, so both loops ran.
    assert!(tried >= 2);
}
