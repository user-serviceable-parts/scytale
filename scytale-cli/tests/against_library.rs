//! Every name `scytale list` prints, run through the binary and
//! checked against the library called directly on the same inputs.
//!
//! The library answers the standards' vectors on its own, so what is
//! left to check here is the tool's wiring: that each name reaches the
//! construction it says, under the hash, width, mode or curve it says,
//! with its options in the places they belong. A round trip through
//! the tool alone cannot show that, since a name wired to the wrong
//! hash still verifies what it signed. Each family walks its whole
//! list and fails on a name it has no library call for, so a name
//! added to the tool without a check here is caught.
//!
//! Where the output is drawn at random (signatures that are hedged,
//! encapsulations, HPKE), each side checks the other's: the library
//! opens or verifies what the tool made, and the tool what the
//! library made.
#![cfg(not(target_family = "wasm"))]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::*;
use scytale::aead::{
    Aead, Ccm, ChaCha20Poly1305, Gcm, GcmSiv, XChaCha20Poly1305, Xpn,
};
use scytale::cipher::BlockCipher;
use scytale::cipher::aes::{Aes128, Aes192, Aes256};
use scytale::cipher::chacha20::ChaCha20;
use scytale::cipher::mode::alphabet::DIGITS;
use scytale::cipher::mode::{
    Cbc, Cfb1, Cfb8, Cfb128, Ctr, Ff1, Ff3_1, Kw, Kwp, Ofb, Xts,
};
use scytale::cipher::padding::pkcs7;
use scytale::cipher::xchacha20::XChaCha20;
use scytale::hash::{Hash, Xof, XofReader};
use scytale::kdf::sp800_108::Counter;
use scytale::kdf::{argon2, hkdf, one_step, pbkdf2, sp800_108, tls12, x963};
use scytale::mac::Mac;
use scytale::mac::cmac::Cmac;
use scytale::mac::hmac::Hmac;
use scytale::mac::kmac::{Kmac128, Kmac256};
use scytale::mac::poly1305::Poly1305;
use scytale::random::CtrDrbg;
use scytale::{Key, KeyType};

/// A message of no particular length: not a whole number of blocks.
const MESSAGE: &[u8] = b"a message of no particular length, \
                         thirty-odd bytes and more";

/// Four whole AES blocks, for the modes run without padding.
const BLOCKS: [u8; 64] = {
    let mut b = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        b[i] = (i * 7 + 3) as u8;
        i += 1;
    }
    b
};

/// `n` bytes of a pattern that depends on `seed`, for keys and IVs.
fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31) ^ seed).collect()
}

/// A value as the tool takes it.
fn arg(bytes: &[u8]) -> String {
    format!("hex:{}", hex(bytes))
}

/// A key of `K`'s width from `bytes`.
fn key_of<K: KeyType>(bytes: &[u8]) -> K::Key {
    let mut key = K::zero_key();
    key.as_mut().copy_from_slice(bytes);
    key
}

/// The names `scytale list` prints for `family`.
fn names(family: &str) -> Vec<String> {
    text(ok(&["list", family], b""))
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The tool's hex output, decoded.
fn unhex(out: Vec<u8>) -> Vec<u8> {
    hex_bytes(&text(out))
}

/// Runs `$body` with `$H` the plain hash `$name` names, or evaluates
/// `$else` for a name that is not one. Written out here rather than
/// shared with the tool, so that the two map names independently.
macro_rules! hash_type {
    ($name:expr, $H:ident => $body:expr, _ => $else:expr) => {
        match $name {
            "sha1" => {
                type $H = scytale::hash::sha1::Sha1;
                $body
            }
            "sha224" => {
                type $H = scytale::hash::sha2::Sha224;
                $body
            }
            "sha256" => {
                type $H = scytale::hash::sha2::Sha256;
                $body
            }
            "sha384" => {
                type $H = scytale::hash::sha2::Sha384;
                $body
            }
            "sha512" => {
                type $H = scytale::hash::sha2::Sha512;
                $body
            }
            "sha512-224" => {
                type $H = scytale::hash::sha2::Sha512_224;
                $body
            }
            "sha512-256" => {
                type $H = scytale::hash::sha2::Sha512_256;
                $body
            }
            "sha3-224" => {
                type $H = scytale::hash::sha3::Sha3_224;
                $body
            }
            "sha3-256" => {
                type $H = scytale::hash::sha3::Sha3_256;
                $body
            }
            "sha3-384" => {
                type $H = scytale::hash::sha3::Sha3_384;
                $body
            }
            "sha3-512" => {
                type $H = scytale::hash::sha3::Sha3_512;
                $body
            }
            _ => $else,
        }
    };
}

/// Runs `$body` with `$C` the AES of `$bits` bits.
macro_rules! aes_type {
    ($bits:expr, $C:ident => $body:expr) => {
        match $bits {
            "128" => {
                type $C = Aes128;
                $body
            }
            "192" => {
                type $C = Aes192;
                $body
            }
            "256" => {
                type $C = Aes256;
                $body
            }
            other => panic!("no AES of {other} bits"),
        }
    };
}

fn digest<H: Hash + Default>(message: &[u8]) -> Vec<u8> {
    let mut h = H::default();
    h.update(message);
    h.finalize().as_ref().to_vec()
}

#[test]
fn hashes_match_the_library() {
    use scytale::hash::blake2::{Blake2b256, Blake2b512};
    use scytale::hash::sha3::{
        CShake128, CShake256, Shake128, Shake256, TupleHash128, TupleHash256,
    };
    // Forty bytes of `xof` over the message.
    fn squeeze<X: Xof>(mut xof: X) -> Vec<u8> {
        let mut out = [0u8; 40];
        xof.update(MESSAGE);
        xof.finalize_xof().squeeze(&mut out);
        out.to_vec()
    }
    for name in names("hash") {
        let name = name.as_str();
        let plain = |args: &[&str], input: &[u8]| {
            let line = text(ok(args, input));
            let (digest, file) = line.split_once("  ").unwrap();
            assert_eq!(file, "-", "{name}");
            hex_bytes(digest)
        };
        let (ours, theirs) = match name {
            "blake2b-256" => (
                plain(&["hash", name], MESSAGE),
                digest::<Blake2b256>(MESSAGE),
            ),
            "blake2b-512" => (
                plain(&["hash", name], MESSAGE),
                digest::<Blake2b512>(MESSAGE),
            ),
            "shake128" | "shake256" => {
                let ours = plain(&["hash", name, "-l", "40"], MESSAGE);
                let theirs = if name == "shake128" {
                    squeeze(Shake128::default())
                } else {
                    squeeze(Shake256::default())
                };
                (ours, theirs)
            }
            "cshake128" | "cshake256" => {
                let args = [
                    "hash",
                    name,
                    "-l",
                    "40",
                    "--function-name",
                    "str:F",
                    "--customization",
                    "str:C",
                ];
                let ours = plain(&args, MESSAGE);
                let theirs = if name == "cshake128" {
                    squeeze(CShake128::new(b"F", b"C"))
                } else {
                    squeeze(CShake256::new(b"F", b"C"))
                };
                (ours, theirs)
            }
            "tuplehash128" | "tuplehash256" => {
                let args = [
                    "hash",
                    name,
                    "-l",
                    "40",
                    "--customization",
                    "str:C",
                    "--element",
                    "str:one",
                    "--element",
                    "hex:0203",
                ];
                let ours = unhex(ok(&args, b""));
                let mut theirs = [0u8; 40];
                if name == "tuplehash128" {
                    let mut t = TupleHash128::new(b"C");
                    t.push(b"one");
                    t.push(&[2, 3]);
                    t.finalize_to(&mut theirs);
                } else {
                    let mut t = TupleHash256::new(b"C");
                    t.push(b"one");
                    t.push(&[2, 3]);
                    t.finalize_to(&mut theirs);
                }
                (ours, theirs.to_vec())
            }
            _ => hash_type!(name, H => (
                plain(&["hash", name], MESSAGE),
                digest::<H>(MESSAGE),
            ), _ => panic!("no library call for hash {name}")),
        };
        assert_eq!(ours, theirs, "{name}");
    }
}

#[test]
fn macs_match_the_library() {
    for name in names("mac") {
        let name = name.as_str();
        let (key, extra, theirs): (Vec<u8>, Vec<&str>, Vec<u8>) =
            if let Some(hash) = name.strip_prefix("hmac-") {
                // A key past every block size, which HMAC hashes first.
                let key = bytes(150, 1);
                let tag = hash_type!(hash, H => {
                    let mut mac = Hmac::<H>::new(&key);
                    mac.update(MESSAGE);
                    mac.finalize().as_ref().to_vec()
                }, _ => panic!("no hash {hash}"));
                (key, vec![], tag)
            } else if let Some(bits) = name.strip_prefix("cmac-aes-") {
                aes_type!(bits, C => {
                    let key = bytes(bits.parse::<usize>().unwrap() / 8, 2);
                    let mut mac = Cmac::<C>::new(&key_of::<C>(&key));
                    mac.update(MESSAGE);
                    (key, vec![], mac.finalize().to_vec())
                })
            } else if name == "kmac128" || name == "kmac256" {
                let key = bytes(32, 3);
                let mut tag = [0u8; 40];
                if name == "kmac128" {
                    let mut mac = Kmac128::new(&key, b"C");
                    mac.update(MESSAGE);
                    mac.finalize_to(&mut tag);
                } else {
                    let mut mac = Kmac256::new(&key, b"C");
                    mac.update(MESSAGE);
                    mac.finalize_to(&mut tag);
                }
                (
                    key,
                    vec!["-l", "40", "--customization", "str:C"],
                    tag.to_vec(),
                )
            } else if name == "poly1305" {
                let key = bytes(32, 4);
                let mut mac = Poly1305::new(&key_of::<Poly1305>(&key));
                mac.update(MESSAGE);
                (key, vec![], mac.finalize().to_vec())
            } else {
                panic!("no library call for mac {name}");
            };
        let key = arg(&key);
        let mut tag_args = vec!["mac", "tag", name, "-k", &key];
        tag_args.extend(&extra);
        assert_eq!(unhex(ok(&tag_args, MESSAGE)), theirs, "{name}");
        // And the library's tag verifies through the tool.
        let tag = arg(&theirs);
        let mut verify = vec!["mac", "verify", name, "-k", &key, "-t", &tag];
        verify.extend(&extra);
        ok(&verify, MESSAGE);
    }
}

/// The library's sealing of `message` under an AEAD, ciphertext then
/// tag, as the tool writes it.
fn library_aead(name: &str, key: &[u8], nonce: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut data = MESSAGE.to_vec();
    let mut tag = [0u8; 16];
    if name == "chacha20-poly1305" {
        let aead = ChaCha20Poly1305::new(&key_of::<ChaCha20Poly1305>(key));
        aead.encrypt(nonce.try_into().unwrap(), aad, &mut data, &mut tag)
            .unwrap();
    } else if name == "xchacha20-poly1305" {
        let aead = XChaCha20Poly1305::new(&key_of::<XChaCha20Poly1305>(key));
        aead.encrypt(nonce.try_into().unwrap(), aad, &mut data, &mut tag)
            .unwrap();
    } else {
        let rest = name.strip_prefix("aes-").unwrap();
        let (bits, mode) = rest.split_once('-').unwrap();
        match (bits, mode) {
            ("128", "gcm-siv") => {
                GcmSiv::<Aes128>::new(&key_of::<Aes128>(key))
                    .encrypt(
                        nonce.try_into().unwrap(),
                        aad,
                        &mut data,
                        &mut tag,
                    )
                    .unwrap();
            }
            ("256", "gcm-siv") => {
                GcmSiv::<Aes256>::new(&key_of::<Aes256>(key))
                    .encrypt(
                        nonce.try_into().unwrap(),
                        aad,
                        &mut data,
                        &mut tag,
                    )
                    .unwrap();
            }
            (_, "gcm") => aes_type!(bits, C => {
                let nonce = nonce.try_into().unwrap();
                Gcm::<C>::new(&key_of::<C>(key))
                    .encrypt(nonce, aad, &mut data, &mut tag)
                    .unwrap();
            }),
            (_, "ccm") => aes_type!(bits, C => {
                Ccm::<C>::new(&key_of::<C>(key))
                    .encrypt(nonce, aad, &mut data, &mut tag)
                    .unwrap();
            }),
            (_, "xpn") => aes_type!(bits, C => {
                let salt = nonce[..12].try_into().unwrap();
                let frame = nonce[12..].try_into().unwrap();
                Xpn::<C>::new(&key_of::<C>(key))
                    .encrypt(salt, frame, aad, &mut data, &mut tag)
                    .unwrap();
            }),
            _ => panic!("no library call for aead {name}"),
        }
    }
    data.extend_from_slice(&tag);
    data
}

#[test]
fn aeads_match_the_library() {
    for name in names("aead") {
        let name = name.as_str();
        let width = match name {
            "chacha20-poly1305" | "xchacha20-poly1305" => 32,
            _ => name[4..7].parse::<usize>().unwrap() / 8,
        };
        let nonce_len = if name.ends_with("-ccm") {
            13
        } else if name.ends_with("-xpn") || name.starts_with("xchacha") {
            24
        } else {
            12
        };
        let (key, nonce) = (bytes(width, 5), bytes(nonce_len, 6));
        let theirs = library_aead(name, &key, &nonce, b"header");
        let (key, nonce) = (arg(&key), arg(&nonce));
        let args = |verb| {
            [
                "aead",
                verb,
                name,
                "-k",
                &key,
                "-n",
                &nonce,
                "--aad",
                "str:header",
            ]
        };
        assert_eq!(ok(&args("encrypt"), MESSAGE), theirs, "{name}");
        assert_eq!(ok(&args("decrypt"), &theirs), MESSAGE, "{name}");
    }
}

/// `data` under one AES mode, as the library computes it, with PKCS#7
/// padding first when `padded`.
fn library_aes<C>(
    mode: &str,
    key: &C::Key,
    iv: &[u8; 16],
    data: &[u8],
) -> Vec<u8>
where
    C: BlockCipher<Block = [u8; 16]>,
{
    let mut data = data.to_vec();
    if matches!(mode, "ecb" | "cbc" | "cfb128") {
        let len = data.len();
        data.resize(pkcs7::padded_len(len, 16), 0);
        pkcs7::pad(&mut data, len, 16).unwrap();
    }
    match mode {
        "ecb" => {
            let (blocks, rest) = data.as_chunks_mut::<16>();
            assert!(rest.is_empty());
            C::new(key).encrypt(blocks);
        }
        "cbc" => Cbc::<C>::new(key).encryptor(iv).update(&mut data).unwrap(),
        "cfb128" => Cfb128::<C>::new(key)
            .encryptor(iv)
            .update(&mut data)
            .unwrap(),
        "cfb8" => Cfb8::<C>::new(key).encryptor(iv).update(&mut data),
        "cfb1" => {
            let bits = data.len() * 8;
            Cfb1::<C>::new(key).encrypt(iv, &mut data, bits).unwrap();
        }
        "ofb" => Ofb::<C>::new(key).stream(iv).update(&mut data),
        "ctr" => Ctr::<C>::new(key).stream(iv).update(&mut data),
        other => panic!("no library call for AES mode {other}"),
    }
    data
}

#[test]
fn ciphers_match_the_library() {
    let iv = bytes(16, 7);
    let iv_arg = arg(&iv);
    let iv: [u8; 16] = iv.try_into().unwrap();
    for name in names("cipher") {
        let name = name.as_str();
        if name == "chacha20" || name == "xchacha20" {
            let key = bytes(32, 8);
            let typed = Key::from(<[u8; 32]>::try_from(&key[..]).unwrap());
            let mut theirs = MESSAGE.to_vec();
            let nonce = if name == "xchacha20" {
                let nonce = bytes(24, 9);
                XChaCha20::new(&typed)
                    .stream(nonce[..].try_into().unwrap(), 7)
                    .update(&mut theirs)
                    .unwrap();
                nonce
            } else {
                let nonce = bytes(12, 9);
                ChaCha20::new(&typed)
                    .stream(nonce[..].try_into().unwrap(), 7)
                    .update(&mut theirs)
                    .unwrap();
                nonce
            };
            let (key, nonce) = (arg(&key), arg(&nonce));
            let args = |verb| {
                [
                    "cipher",
                    verb,
                    name,
                    "-k",
                    &key,
                    "-n",
                    &nonce,
                    "--counter",
                    "7",
                ]
            };
            assert_eq!(ok(&args("encrypt"), MESSAGE), theirs, "{name}");
            assert_eq!(ok(&args("decrypt"), &theirs), MESSAGE, "{name}");
            continue;
        }
        if name.starts_with("ff1-") || name.starts_with("ff3-1-") {
            fpe_matches(name);
            continue;
        }
        let rest = name
            .strip_prefix("aes-")
            .unwrap_or_else(|| panic!("no library call for cipher {name}"));
        let (bits, mode) = rest.split_once('-').unwrap();
        let width = bits.parse::<usize>().unwrap() / 8;
        let key = bytes(width, 10);
        aes_type!(bits, C => {
            let typed = key_of::<C>(&key);
            let key = arg(&key);
            match mode {
                "kw" | "kwp" => {
                    // A key of whole 8-byte blocks for kw, and one that
                    // is not for kwp.
                    let plain = bytes(if mode == "kw" { 32 } else { 27 }, 11);
                    let mut out = vec![0u8; plain.len() + 16];
                    let n = if mode == "kw" {
                        Kw::<C>::new(&typed).wrap(&plain, &mut out)
                    } else {
                        Kwp::<C>::new(&typed).wrap(&plain, &mut out)
                    }
                    .unwrap();
                    let theirs = &out[..n];
                    let wrap = |verb| ["cipher", verb, name, "-k", &key];
                    assert_eq!(ok(&wrap("wrap"), &plain), theirs, "{name}");
                    assert_eq!(ok(&wrap("unwrap"), theirs), plain, "{name}");
                }
                "xts" => {
                    let second = bytes(width, 12);
                    let mut theirs = MESSAGE.to_vec();
                    Xts::<C>::try_new(&typed, &key_of::<C>(&second))
                        .unwrap()
                        .encrypt(&iv, &mut theirs)
                        .unwrap();
                    let second = arg(&second);
                    let args = |verb| {
                        [
                            "cipher", verb, name, "-k", &key, "--tweak-key",
                            &second, "--iv", &iv_arg,
                        ]
                    };
                    let ours = ok(&args("encrypt"), MESSAGE);
                    assert_eq!(ours, theirs, "{name}");
                    let back = ok(&args("decrypt"), &theirs);
                    assert_eq!(back, MESSAGE, "{name}");
                }
                _ => {
                    let padded = matches!(mode, "ecb" | "cbc" | "cfb128");
                    let mut args = vec!["cipher", "encrypt", name, "-k", &key];
                    if mode != "ecb" {
                        args.extend(["--iv", &iv_arg]);
                    }
                    if padded {
                        args.extend(["--padding", "pkcs7"]);
                    }
                    let theirs = library_aes::<C>(mode, &typed, &iv, MESSAGE);
                    assert_eq!(ok(&args, MESSAGE), theirs, "{name}");
                    args[1] = "decrypt";
                    assert_eq!(ok(&args, &theirs), MESSAGE, "{name}");
                    if padded {
                        // Without padding, on whole blocks: the library's
                        // padded output's first blocks are the same
                        // computation, so compare those.
                        let n = args.len();
                        args[n - 1] = "none";
                        args[1] = "encrypt";
                        let ours = ok(&args, &BLOCKS);
                        let full = library_aes::<C>(mode, &typed, &iv, &BLOCKS);
                        assert_eq!(ours, full[..BLOCKS.len()], "{name} none");
                    }
                }
            }
        });
    }
}

/// FF1 or FF3-1 over decimal digits: a line through the tool, the same
/// numerals through the library.
fn fpe_matches(name: &str) {
    let ff3 = name.starts_with("ff3-1-");
    let bits = name.rsplit('-').next().unwrap();
    let line = "4000123456789010";
    let tweak: Vec<u8> = if ff3 { bytes(7, 13) } else { bytes(5, 14) };
    let mut symbols = vec![0u16; line.len()];
    DIGITS.encode(line, &mut symbols).unwrap();
    aes_type!(bits, C => {
        let key = bytes(bits.parse::<usize>().unwrap() / 8, 15);
        let typed = key_of::<C>(&key);
        if ff3 {
            Ff3_1::<C>::try_new(&typed, DIGITS.radix())
                .unwrap()
                .encrypt(tweak[..].try_into().unwrap(), &mut symbols)
                .unwrap();
        } else {
            Ff1::<C>::try_new(&typed, DIGITS.radix())
                .unwrap()
                .encrypt(&tweak, &mut symbols)
                .unwrap();
        }
        let mut theirs = vec![0u8; symbols.len() * 4];
        let n = DIGITS.decode(&symbols, &mut theirs).unwrap();
        theirs.truncate(n);
        theirs.push(b'\n');
        let (key, tweak) = (arg(&key), arg(&tweak));
        let args = |verb| ["cipher", verb, name, "-k", &key, "--tweak", &tweak];
        assert_eq!(ok(&args("encrypt"), line.as_bytes()), theirs, "{name}");
        let back = ok(&args("decrypt"), &theirs);
        assert_eq!(back, format!("{line}\n").as_bytes(), "{name}");
    });
}

#[test]
fn kdfs_match_the_library() {
    let secret = bytes(32, 16);
    let s = arg(&secret);
    let (a, b) = (bytes(5, 17), bytes(9, 18));
    let (a_arg, b_arg) = (arg(&a), arg(&b));
    let parts: [&[u8]; 2] = [&a, &b];
    let run = |args: &[&str]| unhex(ok(args, b""));
    for name in names("kdf") {
        let h = name.as_str();
        hash_type!(h, H => {
            let mut out = [0u8; 42];
            hkdf::derive::<H>(b"salt", &secret, &parts, &mut out).unwrap();
            let ours = run(&[
                "kdf", "hkdf", h, "--ikm", &s, "--salt", "str:salt",
                "--info", &a_arg, "--info", &b_arg, "-l", "42",
            ]);
            assert_eq!(ours, out, "hkdf {h}");

            let mut out = [0u8; 40];
            pbkdf2::pbkdf2::<H>(b"pw", b"salt", 3, &mut out).unwrap();
            let ours = run(&[
                "kdf", "pbkdf2", h, "--password", "str:pw", "--salt",
                "str:salt", "-i", "3", "-l", "40",
            ]);
            assert_eq!(ours, out, "pbkdf2 {h}");

            let mut out = [0u8; 40];
            tls12::prf::<H>(&secret, b"label", &parts, &mut out);
            let ours = run(&[
                "kdf", "tls12", h, "--secret", &s, "--label", "str:label",
                "--seed", &a_arg, "--seed", &b_arg, "-l", "40",
            ]);
            assert_eq!(ours, out, "tls12 {h}");

            let mut out = [0u8; 40];
            one_step::hash::<H>(&secret, &parts, &mut out).unwrap();
            let ours = run(&[
                "kdf", "one-step", h, "--secret", &s, "--info", &a_arg,
                "--info", &b_arg, "-l", "40",
            ]);
            assert_eq!(ours, out, "one-step {h}");

            let mut out = [0u8; 16];
            one_step::hash_no_counter::<H>(&secret, &parts, &mut out)
                .unwrap();
            let ours = run(&[
                "kdf", "one-step", h, "--secret", &s, "--info", &a_arg,
                "--info", &b_arg, "--no-counter", "-l", "16",
            ]);
            assert_eq!(ours, out, "one-step {h} without the counter");

            let mut out = [0u8; 40];
            x963::derive::<H>(&secret, &parts, &mut out).unwrap();
            let ours = run(&[
                "kdf", "x963", h, "--secret", &s, "--info", &a_arg,
                "--info", &b_arg, "-l", "40",
            ]);
            assert_eq!(ours, out, "x963 {h}");
        }, _ => panic!("no library call for kdf {h}"));
    }

    // The KDFs keyed by a MAC take the MAC family's names.
    for name in names("mac") {
        let m = name.as_str();
        let one_step_args = |extra: &[&str]| {
            let mut args = vec![
                "kdf", "one-step", m, "--secret", &s, "--salt", "str:salt",
                "--info", &a_arg, "--info", &b_arg, "-l", "40",
            ];
            args.extend(extra);
            run(&args)
        };
        let fixed = ["--fixed", &a_arg, "--fixed", &b_arg];
        let iv = arg(&bytes(16, 19));
        let iv_bytes = bytes(16, 19);
        // Counter mode as the tool defaults it, feedback with the
        // counter ahead of the chaining value, and the double pipeline
        // with a 16-bit counter eight bits into the fixed input.
        let modes: [(Vec<&str>, &str); 3] = [
            (vec![], "counter"),
            (
                vec![
                    "--mode",
                    "feedback",
                    "--iv",
                    &iv,
                    "--counter-at",
                    "before",
                ],
                "feedback",
            ),
            (
                vec![
                    "--mode",
                    "double-pipeline",
                    "--counter-bits",
                    "16",
                    "--counter-at",
                    "8",
                ],
                "double-pipeline",
            ),
        ];
        let sp = |key: &str, extra: &[&str]| {
            let mut args = vec!["kdf", "sp800-108", m, "-k", key];
            args.extend(fixed);
            args.extend(extra);
            args.extend(["-l", "40"]);
            run(&args)
        };
        // One PRF through the three modes as `modes` asks for them,
        // keyed afresh each time.
        fn three<M: Mac>(
            mut prf: impl FnMut() -> M,
            iv: &[u8],
            parts: &[&[u8]],
        ) -> [[u8; 40]; 3] {
            let mut out = [[0u8; 40]; 3];
            sp800_108::counter(&mut prf(), 32, 0, parts, &mut out[0]).unwrap();
            sp800_108::feedback(
                &mut prf(),
                iv,
                Counter::BeforeIterator(32),
                parts,
                &mut out[1],
            )
            .unwrap();
            sp800_108::double_pipeline(
                &mut prf(),
                Counter::InFixed { bits: 16, at: 8 },
                parts,
                &mut out[2],
            )
            .unwrap();
            out
        }
        let key = bytes(24, 20);
        if let Some(hash) = m.strip_prefix("hmac-") {
            hash_type!(hash, H => {
                let mut out = [0u8; 40];
                let mut mac = Hmac::<H>::new(b"salt");
                one_step::mac(&mut mac, &secret, &parts, &mut out).unwrap();
                assert_eq!(one_step_args(&[]), out, "one-step {m}");
                let theirs = three(|| Hmac::<H>::new(&key), &iv_bytes, &parts);
                for ((extra, mode), theirs) in modes.iter().zip(theirs) {
                    assert_eq!(sp(&arg(&key), extra), theirs, "{mode} {m}");
                }
            }, _ => panic!("no hash {hash}"));
        } else if let Some(bits) = m.strip_prefix("cmac-aes-") {
            aes_type!(bits, C => {
                let key = bytes(bits.parse::<usize>().unwrap() / 8, 21);
                let theirs = three(
                    || Cmac::<C>::new(&key_of::<C>(&key)),
                    &iv_bytes,
                    &parts,
                );
                for ((extra, mode), theirs) in modes.iter().zip(theirs) {
                    assert_eq!(sp(&arg(&key), extra), theirs, "{mode} {m}");
                }
            });
        } else if m == "kmac128" || m == "kmac256" {
            let mut out = [0u8; 40];
            let mut derived = [0u8; 40];
            if m == "kmac128" {
                one_step::kmac128(b"salt", &secret, &parts, &mut out);
                sp800_108::kmac128(&key, b"L", b"C", &mut derived);
            } else {
                one_step::kmac256(b"salt", &secret, &parts, &mut out);
                sp800_108::kmac256(&key, b"L", b"C", &mut derived);
            }
            assert_eq!(one_step_args(&[]), out, "one-step {m}");
            let k = arg(&key);
            let ours = run(&[
                "kdf",
                "sp800-108",
                m,
                "-k",
                &k,
                "--label",
                "str:L",
                "--context",
                "str:C",
                "-l",
                "40",
            ]);
            assert_eq!(ours, derived, "sp800-108 {m}");
        } else if m != "poly1305" {
            panic!("no library call for the KDFs over {m}");
        }
    }

    // Argon2id, which takes no hash name.
    let params = argon2::Params {
        passes: 2,
        memory_kib: 64,
        lanes: 2,
    };
    let mut work = vec![argon2::Block::ZERO; 64];
    let mut out = [0u8; 24];
    argon2::argon2id(b"pw", b"saltsalt", &a, &b, params, &mut work, &mut out)
        .unwrap();
    let ours = run(&[
        "kdf",
        "argon2id",
        "--password",
        "str:pw",
        "--salt",
        "str:saltsalt",
        "--secret",
        &a_arg,
        "--data",
        &b_arg,
        "--passes",
        "2",
        "--memory",
        "64",
        "--lanes",
        "2",
        "-l",
        "24",
    ]);
    assert_eq!(ours, out, "argon2id");
}

/// A key file for every name `scytale list key` prints, made by the
/// tool, with its public half beside it.
struct Keys {
    dir: PathBuf,
}

impl Keys {
    fn new(dir: &Path) -> Keys {
        for name in names("key") {
            let private = dir.join(format!("{name}.pem"));
            let public = dir.join(format!("{name}.pub"));
            let (private, public) =
                (private.to_str().unwrap(), public.to_str().unwrap());
            ok(&["key", "generate", &name, "-o", private], b"");
            ok(&["key", "public", private, "-o", public], b"");
        }
        Keys {
            dir: dir.to_owned(),
        }
    }

    fn private(&self, name: &str) -> String {
        self.path(name, "pem")
    }

    fn public(&self, name: &str) -> String {
        self.path(name, "pub")
    }

    fn path(&self, name: &str, ext: &str) -> String {
        let path = self.dir.join(format!("{name}.{ext}"));
        path.to_str().unwrap().to_owned()
    }

    fn read(&self, path: &str) -> Vec<u8> {
        fs::read(path).unwrap()
    }
}

/// Runs `$body` with `$m` the post-quantum module `$name` names, of
/// either kind.
macro_rules! pq_module {
    ($name:expr, $m:ident => $body:expr, _ => $else:expr) => {
        kem_module!($name, $m => $body, _ => {
            pq_sig_module!($name, $m => $body, _ => $else)
        })
    };
}

/// Runs `$body` with `$m` the ML-KEM module `$name` names.
macro_rules! kem_module {
    ($name:expr, $m:ident => $body:expr, _ => $else:expr) => {
        match $name {
            "ml-kem-512" => {
                use scytale::kem::ml_kem::ml_kem_512 as $m;
                $body
            }
            "ml-kem-768" => {
                use scytale::kem::ml_kem::ml_kem_768 as $m;
                $body
            }
            "ml-kem-1024" => {
                use scytale::kem::ml_kem::ml_kem_1024 as $m;
                $body
            }
            _ => $else,
        }
    };
}

/// The signature half of [`pq_module`].
macro_rules! pq_sig_module {
    ($name:expr, $m:ident => $body:expr, _ => $else:expr) => {
        match $name {
            "ml-dsa-44" => {
                use scytale::sig::ml_dsa::ml_dsa_44 as $m;
                $body
            }
            "ml-dsa-65" => {
                use scytale::sig::ml_dsa::ml_dsa_65 as $m;
                $body
            }
            "ml-dsa-87" => {
                use scytale::sig::ml_dsa::ml_dsa_87 as $m;
                $body
            }
            "slh-dsa-sha2-128s" => {
                use scytale::sig::slh_dsa::sha2_128s as $m;
                $body
            }
            "slh-dsa-sha2-128f" => {
                use scytale::sig::slh_dsa::sha2_128f as $m;
                $body
            }
            "slh-dsa-sha2-192s" => {
                use scytale::sig::slh_dsa::sha2_192s as $m;
                $body
            }
            "slh-dsa-sha2-192f" => {
                use scytale::sig::slh_dsa::sha2_192f as $m;
                $body
            }
            "slh-dsa-sha2-256s" => {
                use scytale::sig::slh_dsa::sha2_256s as $m;
                $body
            }
            "slh-dsa-sha2-256f" => {
                use scytale::sig::slh_dsa::sha2_256f as $m;
                $body
            }
            "slh-dsa-shake-128s" => {
                use scytale::sig::slh_dsa::shake_128s as $m;
                $body
            }
            "slh-dsa-shake-128f" => {
                use scytale::sig::slh_dsa::shake_128f as $m;
                $body
            }
            "slh-dsa-shake-192s" => {
                use scytale::sig::slh_dsa::shake_192s as $m;
                $body
            }
            "slh-dsa-shake-192f" => {
                use scytale::sig::slh_dsa::shake_192f as $m;
                $body
            }
            "slh-dsa-shake-256s" => {
                use scytale::sig::slh_dsa::shake_256s as $m;
                $body
            }
            "slh-dsa-shake-256f" => {
                use scytale::sig::slh_dsa::shake_256f as $m;
                $body
            }
            _ => $else,
        }
    };
}

/// The public half the library derives from the private key in
/// `pem`, as PEM, for the key algorithm `name` names.
fn library_public(name: &str, pem: &[u8]) -> Vec<u8> {
    use scytale::kex::{x448, x25519};
    use scytale::sig::{ecdsa, ed448, ed25519, rsa};
    let mut out = vec![0u8; 16 * 1024];
    let n = match name {
        "ed25519" => {
            let key = ed25519::PrivateKey::try_from_pem(pem).unwrap();
            return key.public_key().pem_bytes().to_vec();
        }
        "ed448" => {
            let key = ed448::PrivateKey::try_from_pem(pem).unwrap();
            return key.public_key().pem_bytes().to_vec();
        }
        "x25519" => {
            let key = x25519::PrivateKey::try_from_pem(pem).unwrap();
            return key.public_key().pem_bytes().to_vec();
        }
        "x448" => {
            let key = x448::PrivateKey::try_from_pem(pem).unwrap();
            return key.public_key().pem_bytes().to_vec();
        }
        "ecdsa-p256" | "ecdh-p256" => {
            ecdsa::p256::PrivateKey::try_from_pem(pem)
                .unwrap()
                .public_key()
                .pem_bytes(&mut out)
        }
        "ecdsa-p384" | "ecdh-p384" => {
            ecdsa::p384::PrivateKey::try_from_pem(pem)
                .unwrap()
                .public_key()
                .pem_bytes(&mut out)
        }
        "ecdsa-p521" | "ecdh-p521" => {
            ecdsa::p521::PrivateKey::try_from_pem(pem)
                .unwrap()
                .public_key()
                .pem_bytes(&mut out)
        }
        _ if name.starts_with("rsa-") => rsa::PrivateKey::try_from_pem(pem)
            .unwrap()
            .public_key()
            .pem_bytes(&mut out),
        // The listed name is a one-level key.
        _ if name.starts_with("hss-") => {
            use scytale::sig::lms::hss::PrivateKey;
            PrivateKey::<1>::try_from_pem(pem)
                .unwrap()
                .public_key()
                .pem_bytes(&mut out)
        }
        _ => pq_module!(name, m => {
            m::PrivateKey::try_from_pem(pem)
                .unwrap()
                .public_key()
                .pem_bytes(&mut out)
        }, _ => panic!("no library call for key {name}")),
    }
    .unwrap();
    out.truncate(n);
    out
}

/// One test over every key, signature, agreement, encapsulation and
/// public-key encryption name, since they share the key files and
/// making the RSA ones is slow.
#[test]
fn public_key_commands_match_the_library() {
    let keys = Keys::new(&dir("against-library"));
    for name in names("key") {
        let private = keys.read(&keys.private(&name));
        let public = keys.read(&keys.public(&name));
        assert_eq!(public, library_public(&name, &private), "key {name}");
        // The RSA width is the one the name says.
        if let Some(bits) = name.strip_prefix("rsa-") {
            let key =
                scytale::sig::rsa::PrivateKey::try_from_pem(&private).unwrap();
            assert_eq!(key.modulus_len() * 8, bits.parse().unwrap(), "{name}");
        }
    }
    signatures(&keys);
    agreements(&keys);
    encapsulations(&keys);
    encryptions(&keys);
}

/// Every signature scheme: the tool's signature verifies under the
/// library, and the library's under the tool, on every key the scheme
/// takes; and RSA PKCS#1 v1.5, which draws nothing, signs to the same
/// bytes.
fn signatures(keys: &Keys) {
    use scytale::sig::{ecdsa, ed448, ed25519, rsa};
    let mut rng = CtrDrbg::from_system().unwrap();
    let sign = |scheme: &str, key: &str, extra: &[&str]| {
        let mut args = vec!["sig", "sign", scheme, "-k", key];
        args.extend(extra);
        ok(&args, MESSAGE)
    };
    let verify = |scheme: &str, key: &str, sig: &[u8], extra: &[&str]| {
        let sig = arg(sig);
        let mut args = vec!["sig", "verify", scheme, "-p", key, "-s", &sig];
        args.extend(extra);
        ok(&args, MESSAGE);
    };
    let ctx = ["--context", "str:ctx"];
    for name in names("sig") {
        let scheme = name.as_str();
        if scheme == "ed25519" {
            let (sk, pk) = (keys.private("ed25519"), keys.public("ed25519"));
            let key =
                ed25519::PrivateKey::try_from_pem(&keys.read(&sk)).unwrap();
            let public = key.public_key();
            let sig: [u8; 64] = sign(scheme, &sk, &[]).try_into().unwrap();
            public.verify(MESSAGE, &sig).unwrap();
            let sig: [u8; 64] = sign(scheme, &sk, &ctx).try_into().unwrap();
            public.verify_ctx(b"ctx", MESSAGE, &sig).unwrap();
            verify(scheme, &pk, &key.sign_deterministic(MESSAGE), &[]);
            let sig = key.sign_ctx_deterministic(b"ctx", MESSAGE).unwrap();
            verify(scheme, &pk, &sig, &ctx);
        } else if scheme == "ed448" {
            // Ed448 always hashes a context: the empty one without
            // --context, which the library's empty context must match.
            let (sk, pk) = (keys.private("ed448"), keys.public("ed448"));
            let key = ed448::PrivateKey::try_from_pem(&keys.read(&sk)).unwrap();
            let public = key.public_key();
            let sig: [u8; 114] = sign(scheme, &sk, &[]).try_into().unwrap();
            public.verify(b"", MESSAGE, &sig).unwrap();
            let sig: [u8; 114] = sign(scheme, &sk, &ctx).try_into().unwrap();
            public.verify(b"ctx", MESSAGE, &sig).unwrap();
            let sig = key.sign_deterministic(b"", MESSAGE).unwrap();
            verify(scheme, &pk, &sig, &[]);
            let sig = key.sign_deterministic(b"ctx", MESSAGE).unwrap();
            verify(scheme, &pk, &sig, &ctx);
        } else if let Some(h) = scheme.strip_prefix("ecdsa-") {
            hash_type!(h, H => {
                macro_rules! curve {
                    ($c:ident, $key:literal) => {{
                        let (sk, pk) = (keys.private($key), keys.public($key));
                        let key = ecdsa::$c::PrivateKey::try_from_pem(
                            &keys.read(&sk),
                        )
                        .unwrap();
                        let der = sign(scheme, &sk, &[]);
                        let sig = ecdsa::$c::signature_from_der(&der).unwrap();
                        key.public_key().verify::<H>(MESSAGE, &sig).unwrap();
                        let raw = sign(scheme, &sk, &["--raw-ecdsa"]);
                        let raw = raw.as_slice().try_into().unwrap();
                        key.public_key().verify::<H>(MESSAGE, raw).unwrap();
                        let sig = key.sign_deterministic::<H>(MESSAGE).unwrap();
                        verify(scheme, &pk, &sig, &["--raw-ecdsa"]);
                        let mut der = [0u8; 160];
                        let n = ecdsa::$c::signature_der(&sig, &mut der)
                            .unwrap();
                        verify(scheme, &pk, &der[..n], &[]);
                    }};
                }
                curve!(p256, "ecdsa-p256");
                curve!(p384, "ecdsa-p384");
                curve!(p521, "ecdsa-p521");
            }, _ => panic!("no hash {h}"));
        } else if let Some(h) = scheme.strip_prefix("rsa-pss-") {
            let (sk, pk) = (keys.private("rsa-2048"), keys.public("rsa-2048"));
            let key = rsa::PrivateKey::try_from_pem(&keys.read(&sk)).unwrap();
            hash_type!(h, H => {
                let sig = sign(scheme, &sk, &[]);
                key.public_key().verify_pss::<H>(MESSAGE, &sig).unwrap();
                let sig = key.sign_pss::<H, _>(&mut rng, MESSAGE).unwrap();
                verify(scheme, &pk, sig.as_ref(), &[]);
            }, _ => panic!("no hash {h}"));
        } else if let Some(h) = scheme.strip_prefix("rsa-pkcs1-") {
            let (sk, pk) = (keys.private("rsa-2048"), keys.public("rsa-2048"));
            let key = rsa::PrivateKey::try_from_pem(&keys.read(&sk)).unwrap();
            hash_type!(h, H => {
                let theirs = key.sign_pkcs1::<H>(MESSAGE).unwrap();
                assert_eq!(sign(scheme, &sk, &[]), theirs.as_ref(), "{scheme}");
                verify(scheme, &pk, theirs.as_ref(), &[]);
            }, _ => panic!("no hash {h}"));
        } else if scheme == "hss" {
            use scytale::sig::lms::hss::{PrivateKey, PublicKey};
            let name = "hss-sha256-h5-w8";
            let (sk, pk) = (keys.private(name), keys.public(name));
            let public = PublicKey::try_from_pem(&keys.read(&pk)).unwrap();
            // The tool's signature verifies under the library, and the
            // file it leaves behind is the key one leaf on, which the
            // library signs with next; that verifies under the tool.
            let sig = sign(scheme, &sk, &[]);
            public.verify(MESSAGE, &sig).unwrap();
            assert_eq!(u32::from_be_bytes(sig[4..8].try_into().unwrap()), 0);
            let mut key =
                PrivateKey::<1>::try_from_pem(&keys.read(&sk)).unwrap();
            assert_eq!(key.remaining(), 31);
            let mut sig = vec![0u8; key.signature_len()];
            let n = key.sign(&mut rng, MESSAGE, &mut sig).unwrap();
            assert_eq!(u32::from_be_bytes(sig[4..8].try_into().unwrap()), 1);
            verify(scheme, &pk, &sig[..n], &[]);
        } else {
            pq_sig_module!(scheme, m => {
                let (sk, pk) = (keys.private(scheme), keys.public(scheme));
                let key = m::PrivateKey::try_from_pem(&keys.read(&sk))
                    .unwrap();
                let sig: [u8; m::SIGNATURE_SIZE] =
                    sign(scheme, &sk, &ctx).try_into().unwrap();
                key.public_key().verify(b"ctx", MESSAGE, &sig).unwrap();
                let sig = key.sign_deterministic(b"ctx", MESSAGE).unwrap();
                verify(scheme, &pk, &sig, &ctx);
            }, _ => panic!("no library call for sig {scheme}"));
        }
    }
}

/// Every key agreement: the tool's secret between two keys it made is
/// the one the library computes from the same two files.
fn agreements(keys: &Keys) {
    use scytale::kex::{ecdh, x448, x25519};
    let dir = &keys.dir;
    for name in names("kex") {
        let name = name.as_str();
        let peer = dir.join(format!("{name}-peer.pem"));
        let peer = peer.to_str().unwrap();
        let peer_pub = format!("{peer}.pub");
        // ECDH's keys are the ECDSA names'; the agreement names the
        // curve.
        ok(&["key", "generate", name, "-o", peer], b"");
        ok(&["key", "public", peer, "-o", &peer_pub], b"");
        let sk = keys.private(name);
        let ours =
            unhex(ok(&["kex", "agree", name, "-k", &sk, "-p", &peer_pub], b""));
        let (sk, pk) = (keys.read(&sk), fs::read(&peer_pub).unwrap());
        let theirs = match name {
            "x25519" => x25519::PrivateKey::try_from_pem(&sk)
                .unwrap()
                .shared_secret(&x25519::PublicKey::try_from_pem(&pk).unwrap())
                .unwrap()
                .to_vec(),
            "x448" => x448::PrivateKey::try_from_pem(&sk)
                .unwrap()
                .shared_secret(&x448::PublicKey::try_from_pem(&pk).unwrap())
                .unwrap()
                .to_vec(),
            "ecdh-p256" => ecdh::p256::PrivateKey::try_from_pem(&sk)
                .unwrap()
                .shared_secret(
                    &ecdh::p256::PublicKey::try_from_pem(&pk).unwrap(),
                )
                .to_vec(),
            "ecdh-p384" => ecdh::p384::PrivateKey::try_from_pem(&sk)
                .unwrap()
                .shared_secret(
                    &ecdh::p384::PublicKey::try_from_pem(&pk).unwrap(),
                )
                .to_vec(),
            "ecdh-p521" => ecdh::p521::PrivateKey::try_from_pem(&sk)
                .unwrap()
                .shared_secret(
                    &ecdh::p521::PublicKey::try_from_pem(&pk).unwrap(),
                )
                .to_vec(),
            _ => panic!("no library call for kex {name}"),
        };
        assert_eq!(ours, theirs, "{name}");
    }
}

/// Every KEM: what the tool encapsulates the library decapsulates to
/// the secret the tool wrote aside, and the tool decapsulates what
/// the library encapsulated.
fn encapsulations(keys: &Keys) {
    let mut rng = CtrDrbg::from_system().unwrap();
    for name in names("kem") {
        let name = name.as_str();
        let (sk, pk) = (keys.private(name), keys.public(name));
        let secret_out = keys.path(name, "ss");
        let ciphertext = ok(
            &[
                "kem",
                "encapsulate",
                name,
                "-p",
                &pk,
                "--secret-out",
                &secret_out,
            ],
            b"",
        );
        let written = fs::read(&secret_out).unwrap();
        kem_module!(name, m => {
            let key = m::PrivateKey::try_from_pem(&keys.read(&sk)).unwrap();
            let c: [u8; m::CIPHERTEXT_SIZE] = ciphertext.try_into().unwrap();
            assert_eq!(key.decapsulate(&c)[..], written[..], "{name}");
            let (c, secret) = key.public_key().encapsulate(&mut rng).unwrap();
            let ours = unhex(ok(&["kem", "decapsulate", name, "-k", &sk], &c));
            assert_eq!(ours, secret, "{name}");
        }, _ => panic!("no library call for kem {name}"));
    }
}

/// Runs `$body` with `$H` and `$A` the KDF and AEAD an HPKE suite's
/// name ends in.
macro_rules! hpke_types {
    ($kdf:expr, $aead:expr, $H:ident, $A:ident => $body:expr) => {
        match $kdf {
            "sha256" => {
                type $H = scytale::hash::sha2::Sha256;
                hpke_types!(@aead $aead, $A => $body)
            }
            "sha384" => {
                type $H = scytale::hash::sha2::Sha384;
                hpke_types!(@aead $aead, $A => $body)
            }
            "sha512" => {
                type $H = scytale::hash::sha2::Sha512;
                hpke_types!(@aead $aead, $A => $body)
            }
            other => panic!("no HPKE KDF {other}"),
        }
    };
    (@aead $aead:expr, $A:ident => $body:expr) => {
        match $aead {
            "aes-128-gcm" => {
                type $A = Gcm<Aes128>;
                $body
            }
            "aes-256-gcm" => {
                type $A = Gcm<Aes256>;
                $body
            }
            "chacha20-poly1305" => {
                type $A = ChaCha20Poly1305;
                $body
            }
            other => panic!("no HPKE AEAD {other}"),
        }
    };
}

/// Every public-key encryption scheme, both ways: the library opens
/// what the tool sealed, and the tool what the library sealed.
fn encryptions(keys: &Keys) {
    use scytale::kex::{ecdh, x448, x25519};
    use scytale::pke::{hpke, rsa};
    let mut rng = CtrDrbg::from_system().unwrap();
    for name in names("pke") {
        let scheme = name.as_str();
        if let Some(h) = scheme.strip_prefix("rsa-oaep-") {
            let (sk, pk) = (keys.private("rsa-2048"), keys.public("rsa-2048"));
            let key = rsa::PrivateKey::try_from_pem(&keys.read(&sk)).unwrap();
            let public = key.public_key();
            let seal =
                ["pke", "encrypt", scheme, "-p", &pk, "--label", "str:L"];
            let open =
                ["pke", "decrypt", scheme, "-k", &sk, "--label", "str:L"];
            hash_type!(h, H => {
                let c = ok(&seal, MESSAGE);
                let mut out = vec![0u8; key.modulus_len()];
                let n = key.decrypt_oaep::<H>(b"L", &c, &mut out).unwrap();
                assert_eq!(&out[..n], MESSAGE, "{scheme}");
                let c = public.encrypt_oaep::<H, _>(&mut rng, b"L", MESSAGE)
                    .unwrap();
                let back = ok(&open, c.as_ref());
                assert_eq!(back, MESSAGE, "{scheme}");
            }, _ => panic!("no hash {h}"));
            continue;
        }
        let suite = scheme
            .strip_prefix("hpke-")
            .unwrap_or_else(|| panic!("no library call for pke {scheme}"));
        let kem = ["x25519", "x448", "ecdh-p256", "ecdh-p384", "ecdh-p521"]
            .into_iter()
            .find(|k| suite.starts_with(&format!("{k}-")))
            .unwrap_or_else(|| panic!("no HPKE KEM in {scheme}"));
        let (kdf, aead) = suite[kem.len() + 1..].split_once('-').unwrap();
        // The KEM is named as the key type is.
        let (sk, pk) = (keys.private(kem), keys.public(kem));
        let (sk_pem, pk_pem) = (keys.read(&sk), keys.read(&pk));
        let seal = [
            "pke", "encrypt", scheme, "-p", &pk, "--info", "str:I", "--aad",
            "str:A",
        ];
        let open = [
            "pke", "decrypt", scheme, "-k", &sk, "--info", "str:I", "--aad",
            "str:A",
        ];
        let sealed = ok(&seal, MESSAGE);
        hpke_types!(kdf, aead, H, A => {
            macro_rules! check {
                ($private:expr, $public:expr) => {{
                    let (private, public) = ($private, $public);
                    // The library opens the tool's message.
                    let n = sealed.len() - hpke::TAG_SIZE;
                    let enc_len = n - MESSAGE.len();
                    let enc = sealed[..enc_len].try_into().unwrap();
                    let mut data = sealed[enc_len..n].to_vec();
                    let tag = sealed[n..].try_into().unwrap();
                    private
                        .recipient::<H, A>(enc, b"I")
                        .unwrap()
                        .decrypt(b"A", &mut data, tag)
                        .unwrap();
                    assert_eq!(data, MESSAGE, "{scheme}");
                    // The tool opens the library's.
                    let (enc, mut context) =
                        public.sender::<H, A, _>(&mut rng, b"I").unwrap();
                    let mut data = MESSAGE.to_vec();
                    let mut tag = [0u8; hpke::TAG_SIZE];
                    context.encrypt(b"A", &mut data, &mut tag).unwrap();
                    let mut message = enc.to_vec();
                    message.extend_from_slice(&data);
                    message.extend_from_slice(&tag);
                    assert_eq!(ok(&open, &message), MESSAGE, "{scheme}");
                }};
            }
            // The key files as the agreement module reads them, then
            // as the HPKE module takes them.
            macro_rules! xdh {
                ($m:ident) => {{
                    let sk = $m::PrivateKey::try_from_pem(&sk_pem).unwrap();
                    let pk = $m::PublicKey::try_from_pem(&pk_pem).unwrap();
                    let secret = Key::from(sk.secret_bytes());
                    check!(
                        hpke::$m::PrivateKey::new(&secret),
                        hpke::$m::PublicKey::new(&pk.bytes())
                    )
                }};
            }
            macro_rules! nist {
                ($m:ident) => {{
                    let sk =
                        ecdh::$m::PrivateKey::try_from_pem(&sk_pem).unwrap();
                    let pk =
                        ecdh::$m::PublicKey::try_from_pem(&pk_pem).unwrap();
                    let secret = sk.secret_bytes();
                    let point = pk.sec1_bytes();
                    check!(
                        hpke::$m::PrivateKey::try_new(&secret).unwrap(),
                        hpke::$m::PublicKey::try_new(&point).unwrap()
                    )
                }};
            }
            match kem {
                "x25519" => xdh!(x25519),
                "x448" => xdh!(x448),
                "ecdh-p256" => nist!(p256),
                "ecdh-p384" => nist!(p384),
                _ => nist!(p521),
            }
        });
    }
}
