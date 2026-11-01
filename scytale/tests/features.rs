//! The set of features in force is global to the process, so these
//! tests have a binary to themselves, and each holds the lock while
//! it edits the set so that none sees another's edit.

use std::sync::{Mutex, MutexGuard};

use scytale::cipher::aes::{self, Aes128};
use scytale::cipher::chacha20::{self, ChaCha20};
use scytale::features::{self, Feature, Features, aarch64, riscv64, x86_64};
use scytale::hash::sha2::{self, Sha256, Sha512};
use scytale::hash::sha3::{self, Sha3_256};
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

/// Removing the feature the chosen engine needs selects the next
/// engine down, for every family and every row of its ranking.
#[test]
fn removing_a_feature_selects_the_engine_below() {
    let _edit = Edit::begin();
    let key = Key::from([0u8; 16]);
    let chacha_key = Key::from([0u8; 32]);
    let detected = features::detected();

    fn walk<E: Copy + PartialEq + std::fmt::Debug>(
        ranking: &[(E, Features)],
        detected: Features,
        engine_now: &dyn Fn() -> E,
    ) {
        // Rows nobody can reach here: those needing a virtual feature
        // or something the processor lacks.
        let reachable: Vec<&(E, Features)> = ranking
            .iter()
            .filter(|(_, needs)| needs.is_subset(detected))
            .collect();
        let mut in_force = detected;
        for (i, (engine, needs)) in reachable.iter().enumerate() {
            features::set(in_force).unwrap();
            assert_eq!(engine_now(), *engine, "with {in_force}");
            // Take away what this row needs, then give back what the
            // rows below it need, so the next reachable row is chosen.
            in_force = in_force - *needs;
            for (_, lower) in &reachable[i + 1..] {
                in_force = in_force | *lower;
            }
        }
        features::set(Features::new()).unwrap();
        let (last, needs) = reachable[reachable.len() - 1];
        assert!(needs.is_empty());
        assert_eq!(engine_now(), *last);
    }

    walk(Aes128::ranking(), detected, &|| Aes128::new(&key).engine());
    walk(Sha256::ranking(), detected, &|| Sha256::new().engine());
    walk(Sha512::ranking(), detected, &|| Sha512::new().engine());
    walk(Sha3_256::ranking(), detected, &|| Sha3_256::new().engine());
    walk(ChaCha20::ranking(), detected, &|| {
        ChaCha20::new(&chacha_key).engine()
    });
}

#[test]
fn isolated_admits_the_tables_below_the_hardware() {
    let _edit = Edit::begin();
    let key = Key::from([0u8; 16]);

    // Alone, it unlocks the table-driven code over the bitsliced.
    features::set(Features::of(&[Feature::Isolated])).unwrap();
    assert_eq!(Aes128::new(&key).engine(), aes::Engine::Tables);

    // Beside the hardware, the hardware still wins.
    let mut f = features::detected();
    f.insert(Feature::Isolated);
    features::set(f).unwrap();
    let hardware = Aes128::ranking()
        .iter()
        .find(|(_, needs)| needs.is_subset(features::detected()))
        .map(|(e, _)| *e)
        .unwrap();
    assert_eq!(Aes128::new(&key).engine(), hardware);

    // And without it, the tables are never chosen.
    features::set(Features::new()).unwrap();
    assert_eq!(Aes128::new(&key).engine(), aes::Engine::Bitsliced);
}

#[test]
fn the_portable_engines_answer_the_same() {
    let _edit = Edit::begin();
    use scytale::hash::Hash;

    let key = Key::from([0x42u8; 16]);
    let message = b"the quick brown fox";
    let before = Aes128::new(&key);
    let hash_before = Sha256::digest(message);

    features::set(Features::new()).unwrap();
    let portable = Aes128::new(&key);
    assert_eq!(portable.engine(), aes::Engine::Bitsliced);
    assert_eq!(Sha256::new().engine(), sha2::Engine::Portable);
    assert_eq!(Sha3_256::new().engine(), sha3::Engine::Portable);
    // On AArch64 the ranking ends with NEON, which every processor
    // has, rather than with the portable code.
    let chacha = ChaCha20::new(&Key::from([0u8; 32]));
    let (last, _) = ChaCha20::ranking()[ChaCha20::ranking().len() - 1];
    assert_eq!(chacha.engine(), last);
    assert!(matches!(
        last,
        chacha20::Engine::Portable | chacha20::Engine::Neon
    ));
    assert_eq!(Sha256::digest(message), hash_before);

    let mut a = [[0x5au8; 16]];
    let mut b = a;
    before.encrypt(&mut a);
    portable.encrypt(&mut b);
    assert_eq!(a, b);
}

#[test]
fn a_value_keeps_the_engine_it_was_built_with() {
    let _edit = Edit::begin();
    let key = Key::from([0u8; 16]);
    let built = Aes128::new(&key);
    let engine = built.engine();
    features::set(Features::new()).unwrap();
    assert_eq!(built.engine(), engine);
    assert_eq!(Aes128::new(&key).engine(), aes::Engine::Bitsliced);
}

#[test]
fn the_rankings_end_in_portable_and_tell_their_rows_apart() {
    fn check<E: Copy + PartialEq + std::fmt::Debug>(ranking: &[(E, Features)]) {
        let (_, last) = ranking[ranking.len() - 1];
        assert!(last.is_empty(), "{ranking:?}");
        for (i, (_, a)) in ranking.iter().enumerate() {
            for (_, b) in &ranking[i + 1..] {
                assert_ne!(a, b, "{ranking:?}");
            }
        }
    }
    check(Aes128::ranking());
    check(Sha256::ranking());
    check(Sha512::ranking());
    check(Sha3_256::ranking());
    check(ChaCha20::ranking());
}
