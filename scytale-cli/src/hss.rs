//! HSS keys and signatures (RFC 8554, SP 800-208): the one scheme
//! here whose private key changes with every signature.
//!
//! A key is named `hss-HASH-hH[-hH...]-wW`: the hash, one tree height
//! per level from the top down, and the Winternitz width every level
//! uses. Signing reads the key file, signs, writes the advanced key
//! beside it and renames it over the original, and only then writes
//! the signature: a signature never leaves without the leaf it spent
//! being recorded, which is the whole safety of the scheme.

use std::fs;
use std::io::Write;
use std::path::Path;

use scytale::random::CtrDrbg;
use scytale::sig::lms::{Family, Lmots, Lms, hss};
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::{io, names};

/// The hashes a name may ask for.
const HASHES: [(&str, Family); 4] = [
    ("sha256", Family::Sha256),
    ("sha256-192", Family::Sha256_192),
    ("shake256", Family::Shake256),
    ("shake256-192", Family::Shake256_192),
];

/// What a key name asks for.
#[derive(Debug)]
struct Spec {
    family: Family,
    heights: Vec<u32>,
    width: u32,
}

impl Spec {
    /// Reads `hss-HASH-hH[-hH...]-wW`.
    fn parse(name: &str) -> Result<Self> {
        let shape = || {
            usage!(
                "{name}: an HSS key is named hss-HASH-hH[-hH...]-wW, the \
                 hash sha256, sha256-192, shake256 or shake256-192, one \
                 tree height per level (5, 10, 15, 20 or 25, up to eight \
                 levels) and the width 1, 2, 4 or 8: hss-sha256-h10-w8, \
                 hss-shake256-h5-h10-w4"
            )
        };
        let lower = names::normalise(name);
        let rest = lower.strip_prefix("hss-").ok_or_else(shape)?;
        let tokens: Vec<&str> = rest.split('-').collect();
        let first_height = tokens
            .iter()
            .position(|t| t.starts_with('h') && t[1..].parse::<u32>().is_ok())
            .ok_or_else(shape)?;
        let hash = tokens[..first_height].join("-");
        let family = HASHES
            .iter()
            .find(|(n, _)| *n == hash)
            .map(|(_, f)| *f)
            .ok_or_else(shape)?;
        let (width, heights) =
            tokens[first_height..].split_last().ok_or_else(shape)?;
        let width: u32 = width
            .strip_prefix('w')
            .and_then(|w| w.parse().ok())
            .filter(|w| [1, 2, 4, 8].contains(w))
            .ok_or_else(shape)?;
        let heights: Vec<u32> = heights
            .iter()
            .map(|h| {
                h.strip_prefix('h')
                    .and_then(|h| h.parse().ok())
                    .filter(|h| [5, 10, 15, 20, 25].contains(h))
                    .ok_or_else(shape)
            })
            .collect::<Result<_>>()?;
        if heights.is_empty() || heights.len() > hss::LEVELS_MAX {
            return Err(shape());
        }
        Ok(Spec {
            family,
            heights,
            width,
        })
    }

    /// The sets, top level first.
    fn sets(&self) -> Result<Vec<(Lms, Lmots)>> {
        let ots = Lmots::ALL
            .into_iter()
            .find(|s| s.family() == self.family && s.w() == self.width);
        self.heights
            .iter()
            .map(|&h| {
                let lms = Lms::ALL
                    .into_iter()
                    .find(|s| s.family() == self.family && s.h() == h);
                match (lms, ots) {
                    (Some(lms), Some(ots)) => Ok((lms, ots)),
                    // Parse admits only what the tables hold, so this
                    // is a table that has lost a row.
                    _ => Err(usage!(
                        "no LMS set of height {h} with {}",
                        self.family_name()
                    )),
                }
            })
            .collect()
    }

    fn family_name(&self) -> &'static str {
        HASHES
            .iter()
            .find(|(_, f)| *f == self.family)
            .map_or("that hash", |(n, _)| n)
    }
}

/// Runs `$body` with `$L` the level count `$levels`, which the key
/// type takes as a type parameter.
macro_rules! with_levels {
    ($levels:expr, $L:ident => $body:expr) => {
        match $levels {
            1 => {
                const $L: usize = 1;
                $body
            }
            2 => {
                const $L: usize = 2;
                $body
            }
            3 => {
                const $L: usize = 3;
                $body
            }
            4 => {
                const $L: usize = 4;
                $body
            }
            5 => {
                const $L: usize = 5;
                $body
            }
            6 => {
                const $L: usize = 6;
                $body
            }
            7 => {
                const $L: usize = 7;
                $body
            }
            8 => {
                const $L: usize = 8;
                $body
            }
            n => return Err(usage!("{n} levels; an HSS key has 1 to 8")),
        }
    };
}

/// Whether `name` is an HSS key name, well formed or not.
pub fn is_key_name(name: &str) -> bool {
    names::normalise(name).starts_with("hss-")
}

/// A fresh key under `name`, as PEM.
pub fn generate(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let spec = Spec::parse(name)?;
    let sets = spec.sets()?;
    for (level, &h) in spec.heights.iter().enumerate() {
        if h > 10 {
            eprintln!(
                "note: level {} is a tree of 2^{h} leaves to hash before \
                 the key exists; H15 takes seconds, H20 minutes, H25 hours",
                level + 1
            );
        }
    }
    let mut rng = CtrDrbg::from_system()?;
    with_levels!(sets.len(), L => {
        let sets: [(Lms, Lmots); L] = std::array::from_fn(|i| sets[i]);
        let key = hss::PrivateKey::<L>::generate(&mut rng, &sets)?;
        let mut pem = Zeroizing::new(vec![0u8; hss::pem_max(L)]);
        let n = key.pem_bytes(&mut pem)?;
        pem.truncate(n);
        Ok(pem)
    })
}

/// The level count of the private key in `pem`.
fn levels(pem: &[u8]) -> Result<usize> {
    Ok(hss::levels_from_pem(pem)?)
}

/// The public half of the private key in `pem`, as PEM.
pub fn public(pem: &[u8]) -> Result<Vec<u8>> {
    with_levels!(levels(pem)?, L => {
        let key = hss::PrivateKey::<L>::try_from_pem(pem)?;
        let mut out = vec![0u8; hss::PUBLIC_KEY_PEM_MAX];
        let n = key.public_key().pem_bytes(&mut out)?;
        out.truncate(n);
        Ok(out)
    })
}

/// The sets as `key show` prints them: `LMS_SHA256_M32_H10 with
/// LMOTS_SHA256_N32_W8`.
fn describe(sets: &[(Lms, Lmots)]) -> String {
    let levels: Vec<String> = sets
        .iter()
        .map(|(lms, ots)| format!("{} with {}", lms.name(), ots.name()))
        .collect();
    levels.join(", then ")
}

/// What `key show` adds after the algorithm for the key in `pem`.
pub fn detail(pem: &[u8], private: bool) -> Result<String> {
    if private {
        with_levels!(levels(pem)?, L => {
            let key = hss::PrivateKey::<L>::try_from_pem(pem)?;
            let plural = if L == 1 { "" } else { "s" };
            Ok(format!(
                ", {L} level{plural}: {}; {} signatures left",
                describe(&key.sets()),
                key.remaining()
            ))
        })
    } else {
        let key = hss::PublicKey::try_from_pem(pem)?;
        let levels = key.levels();
        let plural = if levels == 1 { "" } else { "s" };
        let top = (key.top().lms(), key.top().lmots());
        Ok(format!(
            ", {levels} level{plural}: {} on top",
            describe(&[top])
        ))
    }
}

/// Signs `message` with the key in `path`, which is first rewritten
/// with the leaf spent: the new key goes to a file beside it, synced,
/// then renamed over it, so a crash leaves either the old key or the
/// new, never half of one. The signature is returned only once the
/// key is on disk.
pub fn sign(path: &Path, message: &[u8]) -> Result<Vec<u8>> {
    let pem = Zeroizing::new(io::read_all(Some(path))?);
    let mut rng = CtrDrbg::from_system()?;
    let exhausted = |e: scytale::Error| match e {
        scytale::Error::SequenceExhausted => usage!(
            "{}: the key has no signatures left; it has signed as many \
             messages as its trees hold, and a new key is the only way on",
            path.display()
        ),
        other => other.into(),
    };
    with_levels!(levels(&pem)?, L => {
        let mut key = hss::PrivateKey::<L>::try_from_pem(&pem)?;
        let mut signature = vec![0u8; key.signature_len()];
        let n = key.sign(&mut rng, message, &mut signature).map_err(exhausted)?;
        signature.truncate(n);
        let mut advanced = Zeroizing::new(vec![0u8; hss::pem_max(L)]);
        let n = key.pem_bytes(&mut advanced)?;
        drop(key);
        replace(path, &advanced[..n])?;
        Ok(signature)
    })
}

/// Writes `bytes` to a file beside `path` and renames it over `path`.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = Path::new(&tmp);
    let failed = |e: std::io::Error| {
        crate::fail::Fail::Other(format!(
            "{}: the key could not be rewritten with its next leaf, so no \
             signature was made: {e}",
            path.display()
        ))
    };
    let mut file = io::create(tmp, true)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(tmp, path))
        .map_err(|e| {
            let _ = fs::remove_file(tmp);
            failed(e)
        })
}

/// Checks `signature` over `message` under the public key in `pem`.
pub fn verify(
    pem: &[u8],
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), scytale::Error> {
    hss::PublicKey::try_from_pem(pem)?.verify(message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse() {
        let spec = Spec::parse("hss-sha256-h10-w8").unwrap();
        assert_eq!(spec.family, Family::Sha256);
        assert_eq!(spec.heights, [10]);
        assert_eq!(spec.width, 8);
        assert_eq!(
            spec.sets().unwrap(),
            [(Lms::Sha256M32H10, Lmots::Sha256N32W8)]
        );
        let spec = Spec::parse("HSS_SHAKE256_192-h5-h10-h25-w1").unwrap();
        assert_eq!(spec.family, Family::Shake256_192);
        assert_eq!(spec.heights, [5, 10, 25]);
        assert_eq!(
            spec.sets().unwrap(),
            [
                (Lms::ShakeM24H5, Lmots::ShakeN24W1),
                (Lms::ShakeM24H10, Lmots::ShakeN24W1),
                (Lms::ShakeM24H25, Lmots::ShakeN24W1),
            ]
        );
        for bad in [
            "hss",
            "hss-",
            "hss-sha256",
            "hss-sha256-w8",
            "hss-sha256-h10",
            "hss-sha256-h7-w8",
            "hss-sha256-h10-w3",
            "hss-sha256-h10-w8-h5",
            "hss-md5-h10-w8",
            "hss-sha256-h5-h5-h5-h5-h5-h5-h5-h5-h5-w8",
            "lms-sha256-h10-w8",
        ] {
            let e = Spec::parse(bad).unwrap_err().to_string();
            assert!(e.contains("hss-HASH-hH"), "{bad}: {e}");
        }
        assert!(is_key_name("HSS-x") && !is_key_name("ml-dsa-44"));
    }
}
