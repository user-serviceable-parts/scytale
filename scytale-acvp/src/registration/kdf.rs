//! The generator and the key derivation functions: ctrDRBG from
//! draft-vassilev-acvp-drbg, PBKDF from draft-celi-acvp-pbkdf, KDA
//! HKDF from draft-hammett-acvp-kas-kdf-hkdf at Sp800-56Cr2, and the
//! TLS 1.2 KDF with the extended master secret from
//! draft-celi-acvp-kdf-tls at RFC7627.
//!
//! The generator is AES-256 and nothing else, so one mode is
//! registered, in both constructions: through the derivation
//! function, whose seed material must come to at least a seed, and
//! without it, where the entropy is exactly a seed and there is no
//! nonce. HKDF is registered with the hybrid shared secret and the
//! one fixed-info pattern the answering code builds.

use serde_json::{Value, json};

use super::Options;

/// A CTR_DRBG seed over AES-256, in bits: key and block.
const SEED: u64 = 384;

/// The hashes HMAC may run over in PBKDF.
const PBKDF_HASHES: &[&str] = &[
    "SHA-1",
    "SHA2-224",
    "SHA2-256",
    "SHA2-384",
    "SHA2-512",
    "SHA2-512/224",
    "SHA2-512/256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
];

/// The hashes HMAC may run over in the key agreement derivation;
/// the answering code dispatches these ten.
const HKDF_HASHES: &[&str] = &[
    "SHA2-224",
    "SHA2-256",
    "SHA2-384",
    "SHA2-512",
    "SHA2-512/224",
    "SHA2-512/256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
];

pub fn capabilities(_: Options) -> Vec<Value> {
    let bytes = |min: u64, max: u64| {
        json!([{
            "min": min, "max": max, "increment": 8,
        }])
    };
    vec![
        json!({
            "algorithm": "ctrDRBG",
            "revision": "1.0",
            "predResistanceEnabled": [true, false],
            "reseedImplemented": true,
            "capabilities": [
                {
                    "mode": "AES-256",
                    "derFuncEnabled": true,
                    "entropyInputLen": bytes(SEED, 1024),
                    "nonceLen": bytes(128, SEED),
                    "persoStringLen": bytes(256, SEED),
                    "additionalInputLen": bytes(256, SEED),
                    "returnedBitsLen": bytes(128, 4096),
                },
                {
                    "mode": "AES-256",
                    "derFuncEnabled": false,
                    "entropyInputLen": [SEED],
                    "nonceLen": [0],
                    "persoStringLen": bytes(256, SEED),
                    "additionalInputLen": bytes(256, SEED),
                    "returnedBitsLen": bytes(128, 4096),
                },
            ],
        }),
        json!({
            "algorithm": "PBKDF",
            "revision": "1.0",
            "capabilities": [{
                "hmacAlg": PBKDF_HASHES,
                "iterationCount": [{"min": 1, "max": 2000, "increment": 1}],
                "keyLen": bytes(112, 4096),
                "passwordLen": [{"min": 8, "max": 128, "increment": 1}],
                "saltLen": bytes(128, 4096),
            }],
        }),
        json!({
            "algorithm": "KDA",
            "mode": "HKDF",
            "revision": "Sp800-56Cr2",
            "fixedInfoPattern": "uPartyInfo||vPartyInfo||l",
            "encoding": ["concatenation"],
            "hmacAlg": HKDF_HASHES,
            "macSaltMethods": ["default", "random"],
            "l": 1024,
            "z": bytes(224, 65536),
            "usesHybridSharedSecret": true,
            "auxSharedSecretLen": bytes(112, 65536),
            "performMultiExpansionTests": true,
        }),
        json!({
            "algorithm": "TLS-v1.2",
            "mode": "KDF",
            "revision": "RFC7627",
            "hashAlg": ["SHA2-256", "SHA2-384", "SHA2-512"],
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generator_is_aes_256_both_ways() {
        let drbg = &capabilities(Options::default())[0];
        let modes = drbg["capabilities"].as_array().expect("array");
        assert_eq!(modes.len(), 2);
        assert!(modes.iter().all(|m| m["mode"] == "AES-256"));
        let without = &modes[1];
        assert_eq!(without["derFuncEnabled"], false);
        assert_eq!(without["entropyInputLen"], json!([384]));
        assert_eq!(without["nonceLen"], json!([0]));
    }

    #[test]
    fn hkdf_is_the_hybrid_form_with_one_pattern() {
        let all = capabilities(Options::default());
        let hkdf = &all[2];
        assert_eq!(hkdf["mode"], "HKDF");
        assert_eq!(hkdf["usesHybridSharedSecret"], true);
        assert_eq!(hkdf["fixedInfoPattern"], "uPartyInfo||vPartyInfo||l");
        assert_eq!(all[1]["capabilities"][0]["hmacAlg"][0], "SHA-1");
    }
}
