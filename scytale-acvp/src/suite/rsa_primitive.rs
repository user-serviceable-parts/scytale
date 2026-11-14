//! The two RSA component suites, which drive the primitives on
//! their own rather than through a scheme.
//!
//! `RSA-SignaturePrimitive` is the one place where NIST supplies
//! private keys with expected answers, so it is the only external
//! check that a value this crate *produces* under a private exponent
//! is the right one. It runs at all three widths in both the plain
//! and the Chinese remainder key forms. A message at or above the
//! modulus is the case that must fail, and the primitive is what
//! refuses it.
//!
//! The server's CRT cases name the primes and the reduced exponents
//! but no private exponent, which the key still asks for; it is
//! derived here from the primes, as the library derives it when it
//! makes a key. The vendored file names it.
//!
//! `RSA-decryptionPrimitive` hands over ciphertexts and asks for each
//! one's key and plaintext, or a refusal when the ciphertext is at or
//! above the modulus. The server's prompt names no key, and says how
//! many of the group's ciphertexts must be refused: the client picks
//! the keys, so the client decides. The largest ciphertexts are the
//! ones to refuse, and a key is generated for an entry until its
//! modulus falls on the right side of the ciphertext; a key is kept
//! for the next entry while it serves. The library's primes carry
//! their top two bits, so a modulus is at least nine sixteenths of
//! its width's range, and a ciphertext below that cannot be refused
//! honestly: such a group is an error, not a false refusal. The
//! vendored file names each entry's public key and plaintext but no
//! private exponent: there the plaintext is checked by the public
//! direction instead, which must give back the ciphertext.

use super::{answer_groups, answer_tests};
use crate::support::{
    Error, Rng, hex, hex_value, int, list, opt_hex, opt_int, text,
    unknown_test_type,
};
use scytale::Random;
use scytale::pke::rsa::{
    PrivateKey as PkePrivateKey, PublicKey as PkePublicKey,
};
use scytale::sig::rsa::PrivateKey;
use serde_json::{Value, json};

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    let signature = match text(doc, "mode")? {
        "signaturePrimitive" => true,
        "decryptionPrimitive" => false,
        other => return Err(Error::new(format!("mode {other}"))),
    };
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        if signature {
            answer_tests(group, |t| signature_case(group, t))
        } else {
            decryption_group(group, rng)
        }
    })
}

/// One signature-primitive case.
fn signature_case(group: &Value, t: &Value) -> Result<Value, Error> {
    let n = hex(t, "n")?;
    let e = hex(t, "e")?;
    let key = match text(group, "keyMode")? {
        "standard" => PrivateKey::try_new(&n, &e, &hex(t, "d")?)?,
        "crt" => PrivateKey::try_new_crt(
            &n,
            &e,
            &match opt_hex(t, "d")? {
                Some(d) => d,
                None => private_exponent(&hex(t, "p")?, &hex(t, "q")?, &e)?,
            },
            &hex(t, "p")?,
            &hex(t, "q")?,
            &hex(t, "dmp1")?,
            &hex(t, "dmq1")?,
            &hex(t, "iqmp")?,
        )?,
        other => return Err(Error::new(format!("keyMode {other}"))),
    };
    let modulo = int(group, "modulo")?;
    if key.bits() as u64 != modulo {
        return Err(Error::new(format!(
            "a {}-bit modulus in a {modulo}-bit group",
            key.bits()
        )));
    }

    let message = hex(t, "message")?;
    let len = key.modulus_len();
    let mut signature = vec![0u8; len];
    match key.sign_primitive(&message, &mut signature) {
        Ok(()) => {}
        // A representative at or above the modulus is what the
        // failing cases are made of.
        Err(scytale::Error::MessageTooLong) => {
            return Ok(json!({ "testPassed": false }));
        }
        Err(e) => return Err(e.into()),
    }
    // The public direction must undo it, which also proves the answer
    // is a representative and not a stray value.
    let mut back = vec![0u8; len];
    key.public_key().verify_primitive(&signature, &mut back)?;
    if back != message {
        return Err(Error::new("the signature does not round trip"));
    }
    Ok(json!({ "testPassed": true, "signature": hex_value(&signature) }))
}

/// How many keys are tried for one entry before giving up on a
/// modulus on the right side of its ciphertext.
const KEY_TRIES: usize = 64;

/// Answers a decryption-primitive group, whose cases each hold many
/// independent entries.
fn decryption_group(
    group: &Value,
    rng: &mut dyn Random,
) -> Result<Option<Value>, Error> {
    let bits = int(group, "modulo")? as usize;
    let len = bits.div_ceil(8);
    let failing = opt_int(group, "totalFailingCases");
    // Made only when an entry names no key of its own, which is every
    // entry the server sends, and kept while it serves.
    let mut generated: Option<PkePrivateKey> = None;
    answer_tests(group, |t| {
        let entries = list(t, "resultsArray")?;
        let refuse = to_refuse(entries, failing, len)?;
        let mut results = Vec::new();
        for (i, r) in entries.iter().enumerate() {
            let entry = match (opt_hex(r, "n")?, opt_hex(r, "e")?) {
                (Some(n), Some(e)) => given_key_entry(r, &n, &e),
                _ => {
                    let ct = hex(r, "cipherText")?;
                    let key = key_for(
                        &mut generated,
                        &ct,
                        refuse.as_ref().map(|set| set[i]),
                        bits,
                        rng,
                    )?;
                    generated_key_entry(r, key)
                }
            }
            .map_err(|e| Error::new(format!("entry {i}: {e}")))?;
            results.push(entry);
        }
        Ok(json!({ "resultsArray": results }))
    })
}

/// Which entries are to be refused, when the group says how many: the
/// largest ciphertexts, as many as it says. `None` when it does not.
fn to_refuse(
    entries: &[Value],
    failing: Option<u64>,
    len: usize,
) -> Result<Option<Vec<bool>>, Error> {
    let Some(failing) = failing else {
        return Ok(None);
    };
    let failing = usize::try_from(failing)
        .map_err(|_| Error::new("totalFailingCases is too large"))?;
    if failing > entries.len() {
        return Err(Error::new(format!(
            "{failing} failing cases among {} entries",
            entries.len()
        )));
    }
    let mut order: Vec<(Vec<u8>, usize)> = Vec::new();
    for (i, r) in entries.iter().enumerate() {
        let ct = hex(r, "cipherText")?;
        // A ciphertext wider than the key is refused whatever the key.
        let ct = aligned(&ct, len).unwrap_or_else(|| vec![0xff; len + 1]);
        order.push((ct, i));
    }
    order.sort();
    let mut refuse = vec![false; entries.len()];
    for (_, i) in order.iter().rev().take(failing) {
        refuse[*i] = true;
    }
    Ok(Some(refuse))
}

/// The key the entry is answered under: the one in hand when its
/// modulus falls on the side of the ciphertext the entry needs, else
/// fresh ones until one does. With no requirement, any key.
fn key_for<'k>(
    generated: &'k mut Option<PkePrivateKey>,
    ct: &[u8],
    refuse: Option<bool>,
    bits: usize,
    rng: &mut dyn Random,
) -> Result<&'k PkePrivateKey, Error> {
    for _ in 0..KEY_TRIES {
        let key = match generated {
            Some(key) => key,
            None => generated
                .insert(PkePrivateKey::generate(&mut Rng(&mut *rng), bits)?),
        };
        match refuse {
            None => break,
            Some(refuse) if refuses(key, ct)? == refuse => break,
            Some(_) => *generated = None,
        }
    }
    match generated {
        Some(key) => Ok(key),
        None => Err(Error::new(format!(
            "no key of {bits} bits found in {KEY_TRIES} tries whose \
             modulus is {} the ciphertext",
            if refuse == Some(true) {
                "at most"
            } else {
                "above"
            }
        ))),
    }
}

/// Whether the key refuses the ciphertext, which is when the
/// ciphertext is not below the modulus.
fn refuses(key: &PkePrivateKey, ct: &[u8]) -> Result<bool, Error> {
    let public = key.public_key();
    let len = public.modulus_len();
    let mut n = vec![0u8; len];
    public.modulus_bytes(&mut n)?;
    Ok(match aligned(ct, len) {
        Some(ct) => ct >= n,
        None => true,
    })
}

/// `bytes` right-aligned into `len` bytes, since a representative may
/// be written with leading zeros; `None` if it is wider than that.
fn aligned(bytes: &[u8], len: usize) -> Option<Vec<u8>> {
    let start = bytes.len().saturating_sub(len);
    if bytes[..start].iter().any(|b| *b != 0) {
        return None;
    }
    let tail = &bytes[start..];
    let mut out = vec![0u8; len];
    out[len - tail.len()..].copy_from_slice(tail);
    Some(out)
}

/// An entry decrypted under the group's generated key.
fn generated_key_entry(r: &Value, key: &PkePrivateKey) -> Result<Value, Error> {
    let public = key.public_key();
    let len = public.modulus_len();
    let mut n = vec![0u8; len];
    let n_len = public.modulus_bytes(&mut n)?;
    let e = public.exponent_bytes();
    let start = e.iter().position(|b| *b != 0).unwrap_or(e.len() - 1);
    let mut out = json!({
        "e": hex_value(&e[start..]),
        "n": hex_value(&n[..n_len]),
    });
    let mut pt = vec![0u8; len];
    let decrypted = match aligned(&hex(r, "cipherText")?, len) {
        Some(ct) => match key.decrypt_primitive(&ct, &mut pt) {
            Ok(()) => true,
            // A ciphertext at or above the modulus is the refusal.
            Err(scytale::Error::DecryptionFailed) => false,
            Err(e) => return Err(e.into()),
        },
        None => false,
    };
    out["testPassed"] = json!(decrypted);
    if decrypted {
        out["plainText"] = hex_value(&pt);
    }
    Ok(out)
}

/// An entry under the key the vendored file names, which comes with
/// its plaintext but no private exponent.
fn given_key_entry(r: &Value, n: &[u8], e: &[u8]) -> Result<Value, Error> {
    let mut out = json!({ "e": hex_value(e), "n": hex_value(n) });
    // A failing entry can be bad in either of two ways, and the crate
    // refuses them at different points: an even modulus never becomes
    // a key at all, while a ciphertext at or above the modulus is
    // caught by the primitive.
    let Ok(key) = PkePublicKey::try_new(n, e) else {
        out["testPassed"] = json!(false);
        return Ok(out);
    };
    let len = key.modulus_len();
    let ct = hex(r, "cipherText")?;
    let Some(pt) = opt_hex(r, "plainText")? else {
        // With no private exponent, the refusal is checked against
        // the same modulus comparison the private primitive makes.
        let mut back = vec![0u8; len];
        match key.encrypt_primitive(&ct, &mut back) {
            Err(scytale::Error::MessageTooLong) => {
                out["testPassed"] = json!(false);
                return Ok(out);
            }
            Err(e) => return Err(e.into()),
            Ok(()) => {
                return Err(Error::new(
                    "no plaintext and no private key to decrypt with",
                ));
            }
        }
    };
    let full = aligned(&pt, len)
        .ok_or_else(|| Error::new("plainText is wider than the key"))?;
    let mut back = vec![0u8; len];
    key.encrypt_primitive(&full, &mut back)?;
    if back != ct {
        return Err(Error::new("plainText does not encrypt to cipherText"));
    }
    out["testPassed"] = json!(true);
    out["plainText"] = hex_value(&pt);
    Ok(out)
}

/// The private exponent of the key with primes `p` and `q` under the
/// public exponent `e`: the inverse of `e` modulo phi = (p-1)(q-1),
/// found as the library finds it, d = (1 + k * phi) / e for the k
/// that makes the division exact, k = -phi^-1 mod e. NIST reduces
/// modulo the lcm of p-1 and q-1 instead, so its `d` is smaller;
/// both sign alike. The exponent must fit a word, as the library's
/// must.
fn private_exponent(p: &[u8], q: &[u8], e: &[u8]) -> Result<Vec<u8>, Error> {
    let e = limbs::word(e)?;
    let mut p = limbs::of(p);
    let mut q = limbs::of(q);
    limbs::sub_one(&mut p)?;
    limbs::sub_one(&mut q)?;
    let phi = limbs::mul(&p, &q);
    let inverse = limbs::inv_mod_word(limbs::rem_word(&phi, e), e)
        .ok_or_else(|| Error::new("e has no inverse modulo phi"))?;
    let mut d = limbs::mul_word(&phi, e - inverse);
    limbs::add_one(&mut d);
    if limbs::div_word(&mut d, e) != 0 {
        return Err(Error::new("the private exponent did not divide out"));
    }
    Ok(limbs::bytes(&d))
}

/// Just enough multiple-precision arithmetic to derive a private
/// exponent: big numbers as little-endian 32-bit limbs, and the
/// public exponent as a word.
mod limbs {
    use crate::support::Error;

    pub fn of(bytes: &[u8]) -> Vec<u32> {
        bytes
            .rchunks(4)
            .map(|c| c.iter().fold(0u32, |v, b| v << 8 | u32::from(*b)))
            .collect()
    }

    /// Big-endian, without leading zero bytes.
    pub fn bytes(a: &[u32]) -> Vec<u8> {
        let out: Vec<u8> =
            a.iter().rev().flat_map(|l| l.to_be_bytes()).collect();
        let start = out.iter().position(|b| *b != 0).unwrap_or(out.len() - 1);
        out[start..].to_vec()
    }

    pub fn word(bytes: &[u8]) -> Result<u64, Error> {
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        if bytes.len() - start > 8 {
            return Err(Error::new("the public exponent is wider than a word"));
        }
        let e = bytes[start..]
            .iter()
            .fold(0u64, |v, b| v << 8 | u64::from(*b));
        if e < 3 {
            return Err(Error::new("the public exponent is below 3"));
        }
        Ok(e)
    }

    pub fn sub_one(a: &mut [u32]) -> Result<(), Error> {
        for limb in a.iter_mut() {
            let (v, borrow) = limb.overflowing_sub(1);
            *limb = v;
            if !borrow {
                return Ok(());
            }
        }
        Err(Error::new("a prime of zero"))
    }

    pub fn add_one(a: &mut Vec<u32>) {
        for limb in a.iter_mut() {
            let (v, carry) = limb.overflowing_add(1);
            *limb = v;
            if !carry {
                return;
            }
        }
        a.push(1);
    }

    pub fn mul(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut out = vec![0u32; a.len() + b.len()];
        for (i, x) in a.iter().enumerate() {
            let mut carry = 0u64;
            for (j, y) in b.iter().enumerate() {
                let v = u64::from(*x) * u64::from(*y)
                    + u64::from(out[i + j])
                    + carry;
                out[i + j] = v as u32;
                carry = v >> 32;
            }
            out[i + b.len()] = carry as u32;
        }
        out
    }

    pub fn mul_word(a: &[u32], k: u64) -> Vec<u32> {
        let mut out = Vec::with_capacity(a.len() + 2);
        let mut carry = 0u128;
        for x in a {
            let v = u128::from(*x) * u128::from(k) + carry;
            out.push(v as u32);
            carry = v >> 32;
        }
        out.push(carry as u32);
        out.push((carry >> 32) as u32);
        out
    }

    pub fn rem_word(a: &[u32], m: u64) -> u64 {
        let mut r = 0u128;
        for x in a.iter().rev() {
            r = (r << 32 | u128::from(*x)) % u128::from(m);
        }
        r as u64
    }

    /// Divides in place and gives the remainder.
    pub fn div_word(a: &mut [u32], m: u64) -> u64 {
        let mut r = 0u128;
        for x in a.iter_mut().rev() {
            let v = r << 32 | u128::from(*x);
            *x = (v / u128::from(m)) as u32;
            r = v % u128::from(m);
        }
        r as u64
    }

    /// The inverse of `a` modulo `m`, or `None` when they share a
    /// factor; extended Euclid.
    pub fn inv_mod_word(a: u64, m: u64) -> Option<u64> {
        let (mut r0, mut r1) = (i128::from(m), i128::from(a % m));
        let (mut t0, mut t1) = (0i128, 1i128);
        while r1 != 0 {
            let q = r0 / r1;
            (r0, r1) = (r1, r0 - q * r1);
            (t0, t1) = (t1, t0 - q * t1);
        }
        if r0 != 1 {
            return None;
        }
        Some(t0.rem_euclid(i128::from(m)) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{find, fixed_rng};
    use super::*;
    use crate::support::to_hex;

    /// The server's CRT cases name no `d`. The file's `d` is NIST's,
    /// reduced modulo the lcm of p-1 and q-1 where the derived one is
    /// reduced modulo their product, so the two need not agree; the
    /// derived one is checked by signing with it alone, which must
    /// give the file's signature.
    #[test]
    fn private_exponent_is_derived_from_the_primes() {
        let Some(doc) =
            super::super::vendored(find("RSA-SignaturePrimitive-2.0")[0])
        else {
            return;
        };
        let mut seen = 0;
        for group in list(&doc, "testGroups").unwrap() {
            if group["keyMode"] != "crt" {
                continue;
            }
            for t in list(group, "tests").unwrap() {
                let Some(expected) = opt_hex(t, "signature").unwrap() else {
                    continue;
                };
                let (n, e) = (hex(t, "n").unwrap(), hex(t, "e").unwrap());
                let d = private_exponent(
                    &hex(t, "p").unwrap(),
                    &hex(t, "q").unwrap(),
                    &e,
                )
                .unwrap();
                let key = PrivateKey::try_new(&n, &e, &d).unwrap();
                let mut signature = vec![0u8; key.modulus_len()];
                key.sign_primitive(&hex(t, "message").unwrap(), &mut signature)
                    .unwrap();
                assert_eq!(to_hex(&signature), to_hex(&expected));
                seen += 1;
            }
        }
        assert!(seen > 0);
    }

    #[test]
    fn crt_cases_sign_without_a_private_exponent() {
        let Some(mut doc) =
            super::super::vendored(find("RSA-SignaturePrimitive-2.0")[0])
        else {
            return;
        };
        let with = answer(&doc, &mut fixed_rng()).unwrap();
        for group in doc["testGroups"].as_array_mut().unwrap() {
            if group["keyMode"] != "crt" {
                continue;
            }
            for t in group["tests"].as_array_mut().unwrap() {
                t.as_object_mut().unwrap().remove("d");
            }
        }
        let without = answer(&doc, &mut fixed_rng()).unwrap();
        assert_eq!(with, without);
    }

    #[test]
    fn small_word_arithmetic() {
        assert_eq!(limbs::inv_mod_word(3, 65537), Some(21846));
        assert_eq!(limbs::inv_mod_word(6, 9), None);
        let a = limbs::of(&[0x01, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(limbs::rem_word(&a, 65537), (1u64 << 32) % 65537);
        let mut b = limbs::mul_word(&a, 65537);
        assert_eq!(limbs::div_word(&mut b, 65537), 0);
        assert_eq!(limbs::bytes(&b), vec![0x01, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn decryption_without_a_key_generates_one() {
        let low = format!("{:0>512}", "01");
        let high = "FF".repeat(256);
        let doc = json!({
            "mode": "decryptionPrimitive",
            "testGroups": [{
                "tgId": 1, "testType": "AFT", "modulo": 2048,
                "tests": [{"tcId": 1, "resultsArray": [
                    {"cipherText": low}, {"cipherText": high},
                ]}],
            }],
        });
        let answered = answer(&doc, &mut fixed_rng()).unwrap();
        let entries = &answered["testGroups"][0]["tests"][0]["resultsArray"];
        let (pass, fail) = (&entries[0], &entries[1]);
        // One key serves the whole group when it can.
        assert_eq!(pass["n"], fail["n"]);
        assert_eq!(pass["testPassed"], true);
        assert_eq!(fail["testPassed"], false);
        assert!(fail.get("plainText").is_none());
        let key = PkePublicKey::try_new(
            &hex(pass, "n").unwrap(),
            &hex(pass, "e").unwrap(),
        )
        .unwrap();
        let mut back = vec![0u8; 256];
        key.encrypt_primitive(&hex(pass, "plainText").unwrap(), &mut back)
            .unwrap();
        assert_eq!(to_hex(&back), low);
    }

    /// The group says how many entries to refuse: the largest
    /// ciphertexts, under keys whose moduli fall on the right side.
    #[test]
    fn refusals_are_counted_out() {
        // Two entries the library's keys can refuse, which lie above
        // every modulus it can make, and two they cannot.
        let doc = json!({
            "mode": "decryptionPrimitive",
            "testGroups": [{
                "tgId": 1, "testType": "AFT", "modulo": 2048,
                "totalTestCases": 4, "totalFailingCases": 2,
                "tests": [{"tcId": 1, "resultsArray": [
                    {"cipherText": "FE".repeat(256)},
                    {"cipherText": format!("{:0>512}", "01")},
                    {"cipherText": "FF".repeat(256)},
                    {"cipherText": format!("{:0>512}", "02")},
                ]}],
            }],
        });
        let answered = answer(&doc, &mut fixed_rng()).unwrap();
        let entries = &answered["testGroups"][0]["tests"][0]["resultsArray"];
        let passed: Vec<bool> = entries
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["testPassed"] == true)
            .collect();
        assert_eq!(passed, [false, true, false, true]);

        // A ciphertext below any modulus the library makes cannot be
        // refused, and the driver says so rather than pretending.
        let mut doc = doc;
        doc["testGroups"][0]["tests"][0]["resultsArray"][2]["cipherText"] =
            json!(format!("80{}", "00".repeat(255)));
        let err = answer(&doc, &mut fixed_rng()).unwrap_err();
        assert!(err.message.contains("no key"), "{}", err.message);
    }
}
