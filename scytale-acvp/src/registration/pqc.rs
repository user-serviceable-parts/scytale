//! The post-quantum schemes: ML-KEM from draft-celi-acvp-ml-kem,
//! ML-DSA from draft-celi-acvp-ml-dsa and SLH-DSA from
//! draft-livelsberger-acvp-slh-dsa, every parameter set of each.
//!
//! The signatures are offered through the pure external interface
//! only: no pre-hashing, no externally computed `mu`, and not the
//! internal functions, which is what the library exposes. Signing is
//! offered both hedged and deterministic, and ML-DSA keys in both
//! the seed and the expanded form, as the server has them.

use serde_json::{Value, json};

use super::Options;

const ML_KEM: &[&str] = &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];

const ML_DSA: &[&str] = &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

const SLH_DSA: &[&str] = &[
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s",
    "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s",
    "SLH-DSA-SHAKE-256f",
];

/// What a signing or verifying registration says of its messages
/// and contexts, over `sets`.
fn signing(sets: &[&str]) -> Value {
    json!([{
        "parameterSets": sets,
        "messageLength": [{"min": 8, "max": 65536, "increment": 8}],
        "contextLength": [{"min": 0, "max": 2040, "increment": 8}],
    }])
}

pub fn capabilities(_: Options) -> Vec<Value> {
    vec![
        json!({
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "FIPS203",
            "parameterSets": ML_KEM,
        }),
        json!({
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203-tr1",
            "parameterSets": ML_KEM,
            "functions": [
                "encapsulation",
                "decapsulation",
                "encapsulationKeyCheck",
                "decapsulationKeyCheck",
            ],
            "keyFormats": ["expanded", "seed"],
        }),
        json!({
            "algorithm": "ML-DSA",
            "mode": "keyGen",
            "revision": "FIPS204",
            "parameterSets": ML_DSA,
        }),
        json!({
            "algorithm": "ML-DSA",
            "mode": "sigGen",
            "revision": "FIPS204-tr1",
            "deterministic": [true, false],
            "signatureInterfaces": ["external"],
            "preHash": ["pure"],
            "externalMu": [false],
            "keyFormats": ["expanded", "seed"],
            "capabilities": signing(ML_DSA),
        }),
        json!({
            "algorithm": "ML-DSA",
            "mode": "sigVer",
            "revision": "FIPS204",
            "signatureInterfaces": ["external"],
            "preHash": ["pure"],
            "externalMu": [false],
            "capabilities": signing(ML_DSA),
        }),
        json!({
            "algorithm": "SLH-DSA",
            "mode": "keyGen",
            "revision": "FIPS205",
            "parameterSets": SLH_DSA,
        }),
        json!({
            "algorithm": "SLH-DSA",
            "mode": "sigGen",
            "revision": "FIPS205",
            "deterministic": [true, false],
            "signatureInterfaces": ["external"],
            "preHash": ["pure"],
            "capabilities": signing(SLH_DSA),
        }),
        json!({
            "algorithm": "SLH-DSA",
            "mode": "sigVer",
            "revision": "FIPS205",
            "signatureInterfaces": ["external"],
            "preHash": ["pure"],
            "capabilities": signing(SLH_DSA),
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eight_registrations_every_set_pure_external() {
        let all = capabilities(Options::default());
        assert_eq!(all.len(), 8);
        for c in &all {
            if let Some(interfaces) = c["signatureInterfaces"].as_array() {
                assert_eq!(interfaces, &[json!("external")]);
                assert_eq!(c["preHash"], json!(["pure"]));
            }
        }
        assert_eq!(all[6]["capabilities"][0]["parameterSets"], json!(SLH_DSA));
        assert_eq!(SLH_DSA.len(), 12);
    }
}
