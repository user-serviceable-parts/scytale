//! XECDH shared-secret computation and key generation (RFC 7748),
//! over Curve25519 and Curve448.
//!
//! The IUT's private key is the file's (`privateKey` for keyGen,
//! `privateIut` for SSC) where it gives one; the server's prompt does
//! not, so one is drawn from the generator instead.
//!
//! The keyVer suite is deliberately not run. RFC 7748 masks the top
//! bit and accepts any 32-byte string as a public key, so ACVP's only
//! Curve25519 failures there are keys of 31 and 33 bytes, which
//! `[u8; 32]` refuses at the type level. Its one remaining reason,
//! a set most significant bit, is a passing case whose public key is
//! not derived from the private key it is given, so it cannot serve
//! as extra keyGen coverage either.

use super::{answer_groups, answer_tests};
use crate::support::{Error, hex, hex_value, opt_hex, text, unknown_test_type};
use scytale::Random;
use scytale::kex::{x448, x25519};
use serde_json::{Value, json};

/// One curve's two functions, at its key width.
struct Curve<const N: usize> {
    public_key: fn(&[u8; N]) -> [u8; N],
    function: fn(&[u8; N], &[u8; N]) -> [u8; N],
}

const X25519: Curve<{ x25519::KEY_SIZE }> = Curve {
    public_key: x25519::public_key,
    function: x25519::x25519,
};

const X448: Curve<{ x448::KEY_SIZE }> = Curve {
    public_key: x448::public_key,
    function: x448::x448,
};

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    let mode = text(doc, "mode")?;
    answer_groups(doc, |group| match text(group, "curve")? {
        "Curve25519" => answer_group(&X25519, mode, group, rng),
        "Curve448" => answer_group(&X448, mode, group, rng),
        curve => Err(Error::new(format!("no curve named {curve}"))),
    })
}

fn answer_group<const N: usize>(
    curve: &Curve<N>,
    mode: &str,
    group: &Value,
    rng: &mut dyn Random,
) -> Result<Option<Value>, Error> {
    match (mode, text(group, "testType")?) {
        ("keyGen", "AFT") => answer_tests(group, |t| {
            let private: [u8; N] = private_key(t, "privateKey", rng)?;
            let public = (curve.public_key)(&private);
            Ok(json!({
                "privateKey": hex_value(&private),
                "publicKey": hex_value(&public),
            }))
        }),
        ("SSC", "AFT") => answer_tests(group, |t| {
            let private: [u8; N] = private_key(t, "privateIut", rng)?;
            let server = key(&hex(t, "publicServer")?, "publicServer")?;
            Ok(json!({
                "publicIut": hex_value(&(curve.public_key)(&private)),
                "z": hex_value(&(curve.function)(&private, &server)),
            }))
        }),
        _ => Err(unknown_test_type(group)),
    }
}

/// `bytes` as a key, or an error naming the field.
fn key<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::new(format!("field {name} is not {N} bytes")))
}

/// The private key the file gives as `name` in `t`, or a fresh one.
fn private_key<const N: usize>(
    t: &Value,
    name: &str,
    rng: &mut dyn Random,
) -> Result<[u8; N], Error> {
    match opt_hex(t, name)? {
        Some(k) => key(&k, name),
        None => {
            let mut k = [0u8; N];
            rng.fill(&mut k)?;
            Ok(k)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixed_rng;
    use super::*;
    use crate::support::list;

    /// The server's prompt gives no private key, so the driver draws
    /// one; the secret it answers must be the one the server reaches.
    #[test]
    fn fresh_keys_are_consistent() {
        let server = [7u8; 32];
        let doc = json!({
            "algorithm": "XECDH", "mode": "SSC", "testGroups": [{
                "tgId": 1, "testType": "AFT", "curve": "Curve25519",
                "tests": [{
                    "tcId": 1,
                    "publicServer": hex_value(&x25519::public_key(&server)),
                }],
            }],
        });
        let answered = answer(&doc, &mut fixed_rng()).unwrap();
        let t = &answered["testGroups"][0]["tests"][0];
        let iut: [u8; 32] =
            key(&hex(t, "publicIut").unwrap(), "publicIut").unwrap();
        let z = x25519::x25519(&server, &iut);
        assert_eq!(hex(t, "z").unwrap(), z);
    }

    /// The answer computes the IUT's side only; the server's side of
    /// each vendored case must reach the same secret, on both curves.
    #[test]
    fn server_side_agrees() {
        let suite = super::super::find("XECDH-SSC-RFC7748")[0];
        let Some(doc) = super::super::vendored(suite) else {
            return;
        };
        fn check<const N: usize>(curve: &Curve<N>, t: &Value) {
            let key = |name| key::<N>(&hex(t, name).unwrap(), name).unwrap();
            let z = (curve.function)(&key("privateServer"), &key("publicIut"));
            assert_eq!(z, key("z"), "tcId {}", t["tcId"]);
        }
        let mut curves = 0;
        for group in list(&doc, "testGroups").unwrap() {
            for t in list(group, "tests").unwrap() {
                match group["curve"].as_str() {
                    Some("Curve25519") => check(&X25519, t),
                    Some("Curve448") => check(&X448, t),
                    other => panic!("no curve {other:?}"),
                }
            }
            curves += 1;
        }
        assert_eq!(curves, 2);
    }
}
