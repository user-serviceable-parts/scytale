//! RSA from draft-celi-acvp-rsa: signing and verifying under FIPS
//! 186-5, verifying under FIPS 186-4 for its 1024-bit keys, and the
//! two primitives; and RSA-OAEP key transport, KTS-IFC from
//! draft-hammett-acvp-kas-ifc at Sp800-56Br2.
//!
//! PSS is offered with MGF1 over a fixed-output hash and a salt as
//! long as the digest; the SHAKE hashes and masks are not. Key
//! transport is the basic scheme, with no key confirmation, in both
//! roles; the server generates the implementation's key for the
//! responder role, so no key generation method with a fixed
//! exponent is claimed.

use serde_json::{Value, json};

use super::Options;

/// The hashes FIPS 186-5 signs with here, with their digest length
/// in bytes, which is the PSS salt length offered.
const HASHES_186_5: &[(&str, u64)] = &[
    ("SHA2-224", 28),
    ("SHA2-256", 32),
    ("SHA2-384", 48),
    ("SHA2-512", 64),
    ("SHA2-512/224", 28),
    ("SHA2-512/256", 32),
    ("SHA3-224", 28),
    ("SHA3-256", 32),
    ("SHA3-384", 48),
    ("SHA3-512", 64),
];

/// The hashes FIPS 186-4 verifies with.
const HASHES_186_4: &[(&str, u64)] = &[
    ("SHA-1", 20),
    ("SHA2-224", 28),
    ("SHA2-256", 32),
    ("SHA2-384", 48),
    ("SHA2-512", 64),
    ("SHA2-512/224", 28),
    ("SHA2-512/256", 32),
];

const MODULI: &[u64] = &[2048, 3072, 4096];

/// The hashes OAEP may run over.
const OAEP_HASHES: &[&str] =
    &["SHA-1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512"];

/// `SCYTALE`, as the hex identifier the key transport asks for.
const IUT_ID: &str = "53435954414C45";

/// The two signature schemes over `moduli` and `hashes`: PKCS#1
/// v1.5 with each hash, PSS with each hash and a digest-length salt
/// under MGF1 (named only where `with_mask`, since FIPS 186-4 has
/// no other mask and no field for it). A 1024-bit key cannot carry
/// a 64-byte salt with SHA-512; FIPS 186-4 caps that one at 62.
fn capabilities_of(
    moduli: &[u64],
    hashes: &[(&str, u64)],
    with_mask: bool,
) -> Value {
    let pkcs1: Vec<Value> = moduli
        .iter()
        .map(|modulo| {
            let pairs: Vec<Value> = hashes
                .iter()
                .map(|(hash, _)| json!({"hashAlg": hash}))
                .collect();
            json!({"modulo": modulo, "hashPair": pairs})
        })
        .collect();
    let pss: Vec<Value> = moduli
        .iter()
        .map(|&modulo| {
            let pairs: Vec<Value> = hashes
                .iter()
                .map(|&(hash, salt)| {
                    let salt = if modulo == 1024 { salt.min(62) } else { salt };
                    json!({"hashAlg": hash, "saltLen": salt})
                })
                .collect();
            let mut property = json!({"modulo": modulo, "hashPair": pairs});
            if with_mask {
                property["maskFunction"] = json!(["mgf1"]);
            }
            property
        })
        .collect();
    json!([
        {"sigType": "pkcs1v1.5", "properties": pkcs1},
        {"sigType": "pss", "properties": pss},
    ])
}

pub fn capabilities(_: Options) -> Vec<Value> {
    vec![
        json!({
            "algorithm": "RSA",
            "mode": "sigGen",
            "revision": "FIPS186-5",
            "capabilities": capabilities_of(MODULI, HASHES_186_5, true),
        }),
        json!({
            "algorithm": "RSA",
            "mode": "sigVer",
            "revision": "FIPS186-5",
            "pubExpMode": "random",
            "capabilities": capabilities_of(MODULI, HASHES_186_5, true),
        }),
        json!({
            "algorithm": "RSA",
            "mode": "sigVer",
            "revision": "FIPS186-4",
            "pubExpMode": "random",
            "capabilities": capabilities_of(
                &[1024, 2048, 3072, 4096],
                HASHES_186_4,
                false,
            ),
        }),
        json!({
            "algorithm": "RSA",
            "mode": "signaturePrimitive",
            "revision": "2.0",
            "keyFormat": ["standard", "crt"],
            "pubExpMode": "random",
            "modulo": MODULI,
        }),
        json!({
            "algorithm": "RSA",
            "mode": "decryptionPrimitive",
            "revision": "1.0",
            "modulo": [2048],
        }),
        json!({
            "algorithm": "KTS-IFC",
            "revision": "Sp800-56Br2",
            "function": ["keyPairGen"],
            "iutId": IUT_ID,
            "keyGenerationMethods": ["rsakpg2-basic"],
            "modulo": [2048],
            "scheme": {
                "KTS-OAEP-basic": {
                    "kasRole": ["initiator", "responder"],
                    "ktsMethod": {
                        "hashAlgs": OAEP_HASHES,
                        "supportsNullAssociatedData": true,
                        "associatedDataPattern":
                            "l||uPartyInfo||vPartyInfo||label",
                        "encoding": ["concatenation"],
                    },
                    "l": 1024,
                },
            },
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_registrations() {
        let all = capabilities(Options::default());
        assert_eq!(all.len(), 6);
        assert!(all[..5].iter().all(|c| c["algorithm"] == "RSA"));
        assert_eq!(all[5]["algorithm"], "KTS-IFC");
    }

    #[test]
    fn pss_salts_are_the_digest_except_at_1024_bits() {
        let caps = capabilities_of(&[1024, 2048], HASHES_186_4, false);
        let pss = &caps[1]["properties"];
        let sha512 = |i: usize| &pss[i]["hashPair"][4];
        assert_eq!(sha512(0)["hashAlg"], "SHA2-512");
        assert_eq!(sha512(0)["saltLen"], 62);
        assert_eq!(sha512(1)["saltLen"], 64);
        assert!(pss[0]["maskFunction"].is_null());
        let with_mask = capabilities_of(MODULI, HASHES_186_5, true);
        assert_eq!(
            with_mask[1]["properties"][0]["maskFunction"],
            json!(["mgf1"])
        );
        assert!(with_mask[0]["properties"][0]["maskFunction"].is_null());
    }

    #[test]
    fn the_iut_id_spells_the_name() {
        let bytes: Vec<u8> = (0..IUT_ID.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&IUT_ID[i..i + 2], 16).expect("hex"))
            .collect();
        assert_eq!(bytes, b"SCYTALE");
    }
}
