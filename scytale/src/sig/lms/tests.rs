use std::vec::Vec;

use super::hss;
use super::rfc8554::{self, hex};
use super::*;
use crate::random::CtrDrbg;

fn rng() -> CtrDrbg {
    CtrDrbg::from_system().expect("system entropy")
}

/// The sets of each family with the given height suffix and width.
fn sets(family: Family, h: u32, w: u32) -> (Lms, Lmots) {
    let lms = Lms::ALL
        .into_iter()
        .find(|s| s.family() == family && s.h() == h)
        .expect("a set of that height");
    let ots = Lmots::ALL
        .into_iter()
        .find(|s| s.family() == family && s.w() == w)
        .expect("a set of that width");
    (lms, ots)
}

const FAMILIES: [Family; 4] = [
    Family::Sha256,
    Family::Sha256_192,
    Family::Shake256,
    Family::Shake256_192,
];

#[test]
fn typecodes_name_the_sets() {
    for (i, ots) in Lmots::ALL.into_iter().enumerate() {
        assert_eq!(ots.typecode() as usize, i + 1);
        assert_eq!(Lmots::from_typecode(ots.typecode()), Ok(ots));
    }
    for (i, lms) in Lms::ALL.into_iter().enumerate() {
        assert_eq!(lms.typecode() as usize, i + 5);
        assert_eq!(Lms::from_typecode(lms.typecode()), Ok(lms));
    }
    for code in [0, 17, 4, 25, u32::MAX] {
        assert!(Lmots::from_typecode(code).is_err() || code == 4);
        assert!(Lms::from_typecode(code).is_err() || code == 17);
    }
    for ots in Lmots::ALL {
        assert_eq!(Lmots::from_name(ots.name()), Ok(ots));
    }
    for lms in Lms::ALL {
        assert_eq!(Lms::from_name(lms.name()), Ok(lms));
    }
    assert_eq!(Lmots::ShakeN24W8.name(), "LMOTS_SHAKE_N24_W8");
    assert_eq!(Lms::Sha256M24H15.name(), "LMS_SHA256_M24_H15");
    assert_eq!(
        Lms::from_name("LMS_SHA256_M24_H30"),
        Err(Error::WrongAlgorithm)
    );
    assert_eq!(Lmots::ShakeN24W8.family(), Family::Shake256_192);
    assert_eq!(Lmots::ShakeN24W8.n(), 24);
    assert_eq!(Lmots::ShakeN24W8.w(), 8);
    assert_eq!(Lmots::Sha256N24W2.family(), Family::Sha256_192);
    assert_eq!(Lmots::Sha256N24W2.w(), 2);
    assert_eq!(Lms::ShakeM24H25.family(), Family::Shake256_192);
    assert_eq!(Lms::ShakeM24H25.h(), 25);
    assert_eq!(Lms::Sha256M32H10.h(), 10);
    assert_eq!(Lms::Sha256M24H15.m(), 24);
    assert_eq!(Lms::ShakeM32H20.family(), Family::Shake256);
    // Table 1's signature lengths, and the RFC's H10/W8 figure.
    assert_eq!(Lmots::Sha256N32W1.signature_len(), 8516);
    assert_eq!(Lmots::Sha256N32W2.signature_len(), 4292);
    assert_eq!(Lmots::Sha256N32W4.signature_len(), 2180);
    assert_eq!(Lmots::Sha256N32W8.signature_len(), 1124);
    assert_eq!(Lms::Sha256M32H10.signature_len(Lmots::Sha256N32W8), 1452);
    assert_eq!(SIGNATURE_MAX, 9324);
    assert_eq!(hss::signature_max(2), 4 + 2 * 9324 + 56);
}

#[test]
fn mismatched_hashes_are_refused() {
    let mut rng = rng();
    let bad =
        PrivateKey::generate(&mut rng, Lms::Sha256M32H5, Lmots::ShakeN32W8);
    assert_eq!(bad.err(), Some(Error::WrongAlgorithm));
    let bad =
        PrivateKey::generate(&mut rng, Lms::Sha256M24H5, Lmots::Sha256N32W8);
    assert_eq!(bad.err(), Some(Error::WrongAlgorithm));
    let sets = [
        (Lms::Sha256M32H5, Lmots::Sha256N32W8),
        (Lms::ShakeM32H5, Lmots::ShakeN32W8),
    ];
    let bad = hss::PrivateKey::<2>::generate(&mut rng, &sets);
    assert_eq!(bad.err(), Some(Error::WrongAlgorithm));
    let mut bytes = [0u8; 56];
    bytes[..4].copy_from_slice(&5u32.to_be_bytes());
    bytes[4..8].copy_from_slice(&9u32.to_be_bytes());
    assert_eq!(PublicKey::new(&bytes).err(), Some(Error::WrongAlgorithm));
    bytes[4..8].copy_from_slice(&4u32.to_be_bytes());
    assert!(PublicKey::new(&bytes).is_ok());
    assert_eq!(
        PublicKey::new(&bytes[..55]).err(),
        Some(Error::InvalidEncoding)
    );
    bytes[..4].copy_from_slice(&99u32.to_be_bytes());
    assert_eq!(PublicKey::new(&bytes).err(), Some(Error::WrongAlgorithm));
}

#[test]
fn rfc8554_test_case_1() {
    let public = hss::PublicKey::new(&hex(rfc8554::TC1_PUBLIC_KEY)).unwrap();
    assert_eq!(public.levels(), 2);
    assert_eq!(public.top().lms(), Lms::Sha256M32H5);
    assert_eq!(public.top().lmots(), Lmots::Sha256N32W8);
    let message = hex(rfc8554::TC1_MESSAGE);
    let signature = hex(rfc8554::TC1_SIGNATURE);
    public.verify(&message, &signature).unwrap();
    assert!(public.verify(&message[1..], &signature).is_err());
    assert_eq!(
        public.bytes()[..public.len()],
        hex(rfc8554::TC1_PUBLIC_KEY)[..]
    );
}

#[test]
fn rfc8554_test_case_2() {
    let public = hss::PublicKey::new(&hex(rfc8554::TC2_PUBLIC_KEY)).unwrap();
    assert_eq!(public.top().lms(), Lms::Sha256M32H10);
    assert_eq!(public.top().lmots(), Lmots::Sha256N32W4);
    let message = hex(rfc8554::TC2_MESSAGE);
    let signature = hex(rfc8554::TC2_SIGNATURE);
    public.verify(&message, &signature).unwrap();

    // The keys grow from the printed seeds (appendix A): the top
    // key's root is the public key, and the lower key's root is the
    // public key the signature carries.
    let private = hex(rfc8554::TC2_PRIVATE_KEY);
    let seed = &private[..32];
    let i: [u8; I_SIZE] = private[32..48].try_into().unwrap();
    let top =
        PrivateKey::from_seed(Lms::Sha256M32H10, Lmots::Sha256N32W4, &i, seed)
            .unwrap();
    assert_eq!(top.public_key(), public.top());
    let seed = &private[48..80];
    let i: [u8; I_SIZE] = private[80..96].try_into().unwrap();
    let lower =
        PrivateKey::from_seed(Lms::Sha256M32H5, Lmots::Sha256N32W8, &i, seed)
            .unwrap();
    let short = PrivateKey::from_seed(
        Lms::Sha256M32H5,
        Lmots::Sha256N32W8,
        &i,
        &seed[1..],
    );
    assert_eq!(short.err(), Some(Error::InvalidSeedLength(31)));
    let top_sig_len = public.top().signature_len();
    let lower_public = &signature[4 + top_sig_len..4 + top_sig_len + 56];
    assert_eq!(lower.public_key().bytes()[..56], *lower_public);
    assert_eq!(lower.public_key().len(), 56);

    // And the lower tree's own leaf 4 verifies the message under the
    // printed lower public key, so the tree is the same tree.
    let lower_sig = &signature[4 + top_sig_len + 56..];
    PublicKey::new(lower_public)
        .unwrap()
        .verify(&message, lower_sig)
        .unwrap();
}

/// Every leaf of a tree signs and verifies, in order, with the
/// traversal state always ready and never falling back to computing
/// a node outright.
fn walk_tree(lms: Lms, ots: Lmots) {
    let mut rng = rng();
    let mut key = PrivateKey::generate(&mut rng, lms, ots).unwrap();
    let public = key.public_key().clone();
    let leaves = lms.leaves();
    assert_eq!(key.remaining(), leaves);
    let mut sig = std::vec![0u8; key.signature_len()];
    for q in 0..leaves {
        let message = q.to_be_bytes();
        let n = key.sign(&mut rng, &message, &mut sig).unwrap();
        assert_eq!(n, sig.len());
        assert_eq!(u32_at(&sig, 0), q as u32);
        public.verify(&message, &sig).unwrap();
        assert_eq!(key.remaining(), leaves - q - 1);
        assert_eq!(key.state.slow, 0, "{lms:?} leaf {q} computed outright");
    }
    assert_eq!(
        key.sign(&mut rng, b"one more", &mut sig).err(),
        Some(Error::SequenceExhausted)
    );
    // Short output does not advance the key either.
    let mut short = std::vec![0u8; sig.len() - 1];
    let mut fresh = PrivateKey::generate(&mut rng, lms, ots).unwrap();
    assert_eq!(
        fresh.sign(&mut rng, b"m", &mut short).err(),
        Some(Error::OutputTooSmall(sig.len()))
    );
    assert_eq!(fresh.remaining(), leaves);
}

#[test]
fn every_h5_set_walks_its_tree() {
    for family in FAMILIES {
        for w in [1, 2, 4, 8] {
            let (lms, ots) = sets(family, 5, w);
            walk_tree(lms, ots);
        }
    }
}

#[test]
fn every_family_walks_an_h10_tree() {
    for family in FAMILIES {
        let (lms, ots) = sets(family, 10, 1);
        walk_tree(lms, ots);
    }
}

/// H15 under the cheapest width: minutes in a debug build, so run
/// by hand with `--release --ignored`.
#[test]
#[ignore]
fn h15_walks_its_tree() {
    walk_tree(Lms::Sha256M32H15, Lmots::Sha256N32W1);
}

/// The traversal state and `q` survive the encoding at every point
/// of a tree's life, and the decoded key goes on exactly as the
/// original would.
#[test]
fn tree_state_round_trips_through_hss_encoding() {
    let mut rng = rng();
    let sets = [(Lms::Sha256M32H5, Lmots::Sha256N32W2)];
    let mut key = hss::PrivateKey::<1>::generate(&mut rng, &sets).unwrap();
    let public = key.public_key();
    let mut sig = [0u8; hss::signature_max(1)];
    let mut der = [0u8; hss::der_max(1)];
    let mut pem = [0u8; hss::pem_max(1)];
    for q in 0..32 {
        let n = key.der_bytes(&mut der).unwrap();
        let mut copy = hss::PrivateKey::<1>::try_from_der(&der[..n]).unwrap();
        let m = key.pem_bytes(&mut pem).unwrap();
        let mut copy2 = hss::PrivateKey::<1>::try_from_pem(&pem[..m]).unwrap();
        assert_eq!(copy.remaining(), 32 - q);
        assert_eq!(hss::levels(&der[..n]), Ok(1));
        assert_eq!(hss::levels_from_pem(&pem[..m]), Ok(1));
        let len = key.sign(&mut rng, b"m", &mut sig).unwrap();
        public.verify(b"m", &sig[..len]).unwrap();
        let len = copy.sign(&mut rng, b"m", &mut sig).unwrap();
        public.verify(b"m", &sig[..len]).unwrap();
        let len = copy2.sign(&mut rng, b"m", &mut sig).unwrap();
        public.verify(b"m", &sig[..len]).unwrap();
        // Same leaf used, same state after: the encodings agree.
        let n = key.der_bytes(&mut der).unwrap();
        let mut again = [0u8; hss::der_max(1)];
        let n2 = copy.der_bytes(&mut again).unwrap();
        assert_eq!(der[..n], again[..n2]);
        let n2 = copy2.der_bytes(&mut again).unwrap();
        assert_eq!(der[..n], again[..n2]);
    }
    assert_eq!(key.remaining(), 0);
    let n = key.der_bytes(&mut der).unwrap();
    let mut spent = hss::PrivateKey::<1>::try_from_der(&der[..n]).unwrap();
    assert_eq!(
        spent.sign(&mut rng, b"m", &mut sig).err(),
        Some(Error::SequenceExhausted)
    );
}

#[test]
fn hss_replaces_a_spent_lower_tree() {
    let mut rng = rng();
    let sets = [
        (Lms::Sha256M24H5, Lmots::Sha256N24W1),
        (Lms::Sha256M24H5, Lmots::Sha256N24W2),
    ];
    let mut key = hss::PrivateKey::<2>::generate(&mut rng, &sets).unwrap();
    assert_eq!(key.sets(), sets);
    let public = key.public_key();
    assert_eq!(public.levels(), 2);
    assert_eq!(public.len(), 4 + 24 + 24);
    assert_eq!(key.remaining(), 32 * 32);
    let mut sig = [0u8; hss::signature_max(2)];
    let len = key.signature_len();
    assert_eq!(
        len,
        4 + Lms::Sha256M24H5.signature_len(Lmots::Sha256N24W1)
            + 48
            + Lms::Sha256M24H5.signature_len(Lmots::Sha256N24W2)
    );
    let mut lower_keys: Vec<Vec<u8>> = Vec::new();
    let mut der = [0u8; hss::der_max(2)];
    for i in 0..32 * 32 {
        let n = key.sign(&mut rng, b"m", &mut sig).unwrap();
        assert_eq!(n, len);
        public.verify(b"m", &sig[..n]).unwrap();
        assert_eq!(key.remaining(), 32 * 32 - i - 1);
        // The top signature's q counts lower trees; the lower public
        // key changes with it and is signed once per tree.
        let top_sig_len = Lms::Sha256M24H5.signature_len(Lmots::Sha256N24W1);
        assert_eq!(u32_at(&sig, 0), 1);
        assert_eq!(u32_at(&sig, 4), (i / 32) as u32);
        let lower = sig[4 + top_sig_len..4 + top_sig_len + 48].to_vec();
        let signed = sig[..4 + top_sig_len].to_vec();
        if i % 32 == 0 {
            assert!(!lower_keys.contains(&lower));
            lower_keys.push(lower.clone());
        }
        assert_eq!(*lower_keys.last().unwrap(), lower);
        assert_eq!(u32_at(&sig, 4 + top_sig_len + 48), (i % 32) as u32);
        // The encoding carries the cached signature, so a decoded key
        // signs with the same one while the lower tree lasts.
        let n = key.der_bytes(&mut der).unwrap();
        let mut copy = hss::PrivateKey::<2>::try_from_der(&der[..n]).unwrap();
        if (i + 1) % 32 != 0 {
            let n = copy.sign(&mut rng, b"m", &mut sig).unwrap();
            public.verify(b"m", &sig[..n]).unwrap();
            assert_eq!(sig[..4 + top_sig_len], signed[..]);
        }
    }
    assert_eq!(key.remaining(), 0);
    assert_eq!(
        key.sign(&mut rng, b"m", &mut sig).err(),
        Some(Error::SequenceExhausted)
    );
    let n = key.der_bytes(&mut der).unwrap();
    let wrong = hss::PrivateKey::<1>::try_from_der(&der[..n]);
    assert_eq!(wrong.err(), Some(Error::WrongAlgorithm));
}

#[test]
fn three_levels_sign_and_verify() {
    let mut rng = rng();
    let sets = [
        (Lms::ShakeM32H5, Lmots::ShakeN32W4),
        (Lms::ShakeM32H5, Lmots::ShakeN32W2),
        (Lms::ShakeM32H5, Lmots::ShakeN32W1),
    ];
    let mut key = hss::PrivateKey::<3>::generate(&mut rng, &sets).unwrap();
    assert_eq!(key.remaining(), 32 * 32 * 32);
    let public = key.public_key();
    let mut sig = std::vec![0u8; key.signature_len()];
    for _ in 0..40 {
        let n = key.sign(&mut rng, b"three", &mut sig).unwrap();
        public.verify(b"three", &sig[..n]).unwrap();
    }
    assert_eq!(key.remaining(), 32 * 32 * 32 - 40);
    // A signature of another level count is refused by length and
    // by its count alike.
    let two =
        hss::PrivateKey::<2>::generate(&mut rng, &[sets[0], sets[1]]).unwrap();
    assert!(
        public
            .verify(b"three", &sig[..two.signature_len()])
            .is_err()
    );
}

#[test]
fn every_set_pair_verifies() {
    let mut rng = rng();
    for family in FAMILIES {
        for w in [1, 2, 4, 8] {
            let (lms, ots) = sets(family, 5, w);
            let mut key = PrivateKey::generate(&mut rng, lms, ots).unwrap();
            let mut sig = std::vec![0u8; key.signature_len()];
            key.sign(&mut rng, b"pair", &mut sig).unwrap();
            key.public_key().verify(b"pair", &sig).unwrap();
            // A key of every height reads back from its public bytes.
            for h in [10, 15, 20, 25] {
                let (tall, _) = sets(family, h, w);
                let mut bytes = key.public_key().bytes();
                bytes[..4].copy_from_slice(&tall.typecode().to_be_bytes());
                let tall_key =
                    PublicKey::new(&bytes[..key.public_key().len()]).unwrap();
                assert_eq!(tall_key.lms(), tall);
                assert!(tall_key.verify(b"pair", &sig).is_err());
            }
        }
    }
}

#[test]
fn tampering_is_refused() {
    let mut rng = rng();
    let sets = [
        (Lms::Sha256M32H5, Lmots::Sha256N32W8),
        (Lms::Sha256M32H5, Lmots::Sha256N32W4),
    ];
    let mut key = hss::PrivateKey::<2>::generate(&mut rng, &sets).unwrap();
    let public = key.public_key();
    let mut sig = std::vec![0u8; key.signature_len()];
    key.sign(&mut rng, b"m", &mut sig).unwrap();
    public.verify(b"m", &sig).unwrap();
    let top_sig_len = Lms::Sha256M32H5.signature_len(Lmots::Sha256N32W8);
    // Every byte class: the level count, q, the OTS typecode, C,
    // the chains, the LMS typecode, the path, the lower public key,
    // and the lower signature's fields.
    let offsets = [
        0,
        4,
        8,
        12,
        12 + 32,
        4 + 4 + 1124 - 32,
        4 + 4 + 1124,
        4 + 4 + 1124 + 4,
        4 + top_sig_len - 1,
        4 + top_sig_len,
        4 + top_sig_len + 8,
        4 + top_sig_len + 24,
        4 + top_sig_len + 55,
        4 + top_sig_len + 56,
        4 + top_sig_len + 56 + 4,
        4 + top_sig_len + 56 + 12,
        sig.len() - 1,
    ];
    for offset in offsets {
        let mut bad = sig.clone();
        bad[offset] ^= 1;
        assert!(public.verify(b"m", &bad).is_err(), "offset {offset}");
    }
    assert!(public.verify(b"m", &sig[..sig.len() - 1]).is_err());
    let mut long = sig.clone();
    long.push(0);
    assert!(public.verify(b"m", &long).is_err());
    assert!(public.verify(b"m", &[]).is_err());
    assert!(public.verify(b"n", &sig).is_err());
    // q past the tree.
    let mut bad = sig.clone();
    bad[4..8].copy_from_slice(&32u32.to_be_bytes());
    assert!(public.verify(b"m", &bad).is_err());
    // Another key of the same sets.
    let other = hss::PrivateKey::<2>::generate(&mut rng, &sets).unwrap();
    assert!(other.public_key().verify(b"m", &sig).is_err());
}

#[test]
fn public_keys_round_trip_through_der_and_pem() {
    let mut rng = rng();
    let sets = [
        (Lms::ShakeM24H5, Lmots::ShakeN24W8),
        (Lms::ShakeM24H5, Lmots::ShakeN24W8),
    ];
    let key = hss::PrivateKey::<2>::generate(&mut rng, &sets).unwrap();
    let public = key.public_key();
    let mut der = [0u8; hss::PUBLIC_KEY_DER_MAX];
    let n = public.der_bytes(&mut der).unwrap();
    assert_eq!(hss::PublicKey::try_from_der(&der[..n]).unwrap(), public);
    // RFC 9708: the OID, no parameters, the bytes raw in the BIT
    // STRING.
    let oid = [
        0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03,
        0x11,
    ];
    assert!(der[..n].windows(oid.len()).any(|w| w == oid));
    assert_eq!(der[n - public.len()..n], public.bytes()[..public.len()]);
    let mut pem = [0u8; hss::PUBLIC_KEY_PEM_MAX];
    let m = public.pem_bytes(&mut pem).unwrap();
    assert!(pem[..m].starts_with(b"-----BEGIN PUBLIC KEY-----\n"));
    assert_eq!(hss::PublicKey::try_from_pem(&pem[..m]).unwrap(), public);
    assert_eq!(
        PublicKey::try_from_der(&der[..n]).err(),
        Some(Error::WrongAlgorithm)
    );
    assert_eq!(
        hss::PrivateKey::<2>::try_from_der(&der[..n]).err(),
        Some(Error::InvalidEncoding)
    );
    let ed = crate::sig::ed25519::PrivateKey::generate(&mut rng).unwrap();
    let ed_pem = ed.public_key().pem_bytes();
    assert_eq!(
        hss::PublicKey::try_from_pem(&ed_pem).err(),
        Some(Error::WrongAlgorithm)
    );

    // A single tree writes the one-level HSS form and reads it back.
    let tree = PrivateKey::generate(&mut rng, sets[0].0, sets[0].1).unwrap();
    let n = tree.public_key().der_bytes(&mut der).unwrap();
    let single = hss::PublicKey::try_from_der(&der[..n]).unwrap();
    assert_eq!(single.levels(), 1);
    assert_eq!(single.top(), tree.public_key());
    assert_eq!(
        &PublicKey::try_from_der(&der[..n]).unwrap(),
        tree.public_key()
    );
    let m = tree.public_key().pem_bytes(&mut pem).unwrap();
    assert_eq!(
        &PublicKey::try_from_pem(&pem[..m]).unwrap(),
        tree.public_key()
    );
    assert_eq!(tree.public_key().as_hss(), single);
}

#[test]
fn key_info_names_hss() {
    let mut rng = rng();
    let sets = [(Lms::Sha256M32H5, Lmots::Sha256N32W8)];
    let key = hss::PrivateKey::<1>::generate(&mut rng, &sets).unwrap();
    let mut der = [0u8; hss::der_max(1)];
    let n = key.der_bytes(&mut der).unwrap();
    let info = crate::KeyInfo::try_from_der(&der[..n]).unwrap();
    assert_eq!(info.algorithm, crate::Algorithm::Hss);
    assert!(info.private);
    let n = key.public_key().der_bytes(&mut der).unwrap();
    let info = crate::KeyInfo::try_from_der(&der[..n]).unwrap();
    assert_eq!(info.algorithm, crate::Algorithm::Hss);
    assert!(!info.private);
    assert_eq!(crate::Algorithm::Hss.name(), "HSS");
}

#[test]
fn debug_hides_secrets() {
    let mut rng = rng();
    let key =
        PrivateKey::generate(&mut rng, Lms::Sha256M32H5, Lmots::Sha256N32W8)
            .unwrap();
    let text = std::format!("{key:?}");
    assert!(text.contains("Sha256M32H5"));
    assert!(!text.contains("seed"));
    let text = std::format!("{:?}", key.public_key());
    assert!(text.contains("Sha256N32W8"));
}
