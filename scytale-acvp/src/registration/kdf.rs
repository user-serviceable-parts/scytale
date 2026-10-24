//! The generators and the key derivation functions: ctrDRBG,
//! hashDRBG and hmacDRBG from draft-vassilev-acvp-drbg, PBKDF from
//! draft-celi-acvp-pbkdf, the SP 800-108 KDF and KDF-KMAC from
//! draft-celi-acvp-kbkdf, KDA HKDF, OneStep and OneStepNoCounter
//! from the draft-hammett-acvp-kas-kdf drafts at Sp800-56Cr2, ANSI
//! X9.63 from draft-celi-acvp-kdf-ansi-x963, and the TLS 1.2 KDF
//! with the extended master secret from draft-celi-acvp-kdf-tls at
//! RFC7627.
//!
//! The counter-mode generator is AES-256 and nothing else, so one
//! mode is registered, in both constructions: through the derivation
//! function, whose seed material must come to at least a seed, and
//! without it, where the entropy is exactly a seed and there is no
//! nonce. The hash generators have no derivation function to leave
//! out, so each hash is one capability, in both revisions of the
//! suite, which ask for different amounts of output. The key
//! agreement KDFs are registered with the hybrid shared secret `t`
//! and the one fixed-info pattern the answering code builds.

use serde_json::{Value, json};

use super::Options;

/// A CTR_DRBG seed over AES-256, in bits: key and block.
const SEED: u64 = 384;

/// The hashes a hash or HMAC generator may run over, each with its
/// security strength in bits, which floors the entropy and the
/// personalization and additional inputs, and its digest, which
/// floors the output.
const DRBG_HASHES: &[(&str, u64, u64)] = &[
    ("SHA-1", 128, 160),
    ("SHA2-224", 192, 224),
    ("SHA2-256", 256, 256),
    ("SHA2-384", 256, 384),
    ("SHA2-512", 256, 512),
    ("SHA2-512/224", 192, 224),
    ("SHA2-512/256", 256, 256),
    ("SHA3-224", 192, 224),
    ("SHA3-256", 256, 256),
    ("SHA3-384", 256, 384),
    ("SHA3-512", 256, 512),
];

/// The MACs the SP 800-108 modes may run over; the answering code
/// dispatches these fourteen, and has no Triple DES.
const KBKDF_MACS: &[&str] = &[
    "CMAC-AES128",
    "CMAC-AES192",
    "CMAC-AES256",
    "HMAC-SHA-1",
    "HMAC-SHA2-224",
    "HMAC-SHA2-256",
    "HMAC-SHA2-384",
    "HMAC-SHA2-512",
    "HMAC-SHA2-512/224",
    "HMAC-SHA2-512/256",
    "HMAC-SHA3-224",
    "HMAC-SHA3-256",
    "HMAC-SHA3-384",
    "HMAC-SHA3-512",
];

/// The hashes the one-step KDF may run over, bare or under HMAC,
/// each with its digest in bits, which bounds the output of the
/// form without a counter.
const ONE_STEP_HASHES: &[(&str, u64)] = &[
    ("SHA-1", 160),
    ("SHA2-224", 224),
    ("SHA2-256", 256),
    ("SHA2-384", 384),
    ("SHA2-512", 512),
    ("SHA2-512/224", 224),
    ("SHA2-512/256", 256),
    ("SHA3-224", 224),
    ("SHA3-256", 256),
    ("SHA3-384", 384),
    ("SHA3-512", 512),
];

/// The fixed-info pattern both one-step forms are answered with:
/// the hybrid secret, both parties, the length.
const ONE_STEP_PATTERN: &str = "t||uPartyInfo||vPartyInfo||l";

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
    let mut all = vec![
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
            "algorithm": "KDA",
            "mode": "OneStep",
            "revision": "Sp800-56Cr2",
            "auxFunctions": one_step_functions(None),
            "fixedInfoPattern": ONE_STEP_PATTERN,
            "encoding": ["concatenation"],
            "z": bytes(224, 65536),
            "l": 1024,
        }),
        json!({
            "algorithm": "KDA",
            "mode": "OneStepNoCounter",
            "revision": "Sp800-56Cr2",
            "auxFunctions": one_step_functions(Some(2048)),
            "fixedInfoPattern": ONE_STEP_PATTERN,
            "encoding": ["concatenation"],
            "z": bytes(224, 65536),
        }),
        json!({
            "algorithm": "kdf-components",
            "mode": "ansix9.63",
            "revision": "1.0",
            "hashAlg": HKDF_HASHES,
            "sharedInfoLength": [0, 1024],
            "fieldSize": [224, 521],
            "keyDataLength": [128, 4096],
        }),
        json!({
            "algorithm": "KDF",
            "revision": "1.0",
            "capabilities": [
                kbkdf_mode(
                    "counter",
                    &["before fixed data", "after fixed data",
                      "middle fixed data"],
                    &[8, 16, 24, 32],
                    false,
                ),
                kbkdf_mode(
                    "feedback",
                    &["none", "before fixed data", "after fixed data",
                      "before iterator"],
                    &[0, 8, 16, 24, 32],
                    true,
                ),
                kbkdf_mode(
                    "double pipeline iteration",
                    &["none", "before fixed data", "after fixed data",
                      "before iterator"],
                    &[0, 8, 16, 24, 32],
                    false,
                ),
            ],
        }),
        json!({
            "algorithm": "KDF",
            "mode": "KMAC",
            "revision": "Sp800-108r1",
            "macMode": ["KMAC-128", "KMAC-256"],
            "keyDerivationKeyLength": bytes(112, 4096),
            "contextLength": bytes(8, 4096),
            "labelLength": bytes(8, 4096),
            "derivedKeyLength": bytes(112, 4096),
        }),
        json!({
            "algorithm": "TLS-v1.2",
            "mode": "KDF",
            "revision": "RFC7627",
            "hashAlg": ["SHA2-256", "SHA2-384", "SHA2-512"],
        }),
    ];
    for algorithm in ["hashDRBG", "hmacDRBG"] {
        for revision in ["1.0", "SP800-90Ar1"] {
            all.push(hash_drbg(algorithm, revision));
        }
    }
    all
}

/// One SP 800-108 mode over every MAC: outputs of any bit length
/// to the longest the server tests, the counter at every width and
/// place the mode allows, and an empty IV where feedback takes one.
fn kbkdf_mode(
    mode: &str,
    places: &[&str],
    widths: &[u64],
    empty_iv: bool,
) -> Value {
    json!({
        "kdfMode": mode,
        "macMode": KBKDF_MACS,
        "supportedLengths": [{"min": 8, "max": 4096, "increment": 1}],
        "fixedDataOrder": places,
        "counterLength": widths,
        "supportsEmptyIv": empty_iv,
        "requiresEmptyIv": false,
    })
}

/// The one-step auxiliary functions: every hash bare and under
/// HMAC, and both KMACs, the keyed ones with the default salt and a
/// random one. Without a counter each names its own output length,
/// a digest or, for KMAC, `kmac_bits`.
fn one_step_functions(kmac_bits: Option<u64>) -> Vec<Value> {
    let mut functions = Vec::new();
    let with_length = |mut f: Value, bits: u64| {
        if kmac_bits.is_some() {
            f["l"] = json!(bits);
        }
        f
    };
    for &(hash, digest) in ONE_STEP_HASHES {
        functions.push(with_length(json!({"auxFunctionName": hash}), digest));
        functions.push(with_length(
            json!({
                "auxFunctionName": format!("HMAC-{hash}"),
                "macSaltMethods": ["default", "random"],
            }),
            digest,
        ));
    }
    for kmac in ["KMAC-128", "KMAC-256"] {
        functions.push(with_length(
            json!({
                "auxFunctionName": kmac,
                "macSaltMethods": ["default", "random"],
            }),
            kmac_bits.unwrap_or(0),
        ));
    }
    functions
}

/// A hash or HMAC generator in one revision of its suite: every
/// hash, with the lengths the standard floors at its security
/// strength, reseeding, and prediction resistance both ways. The
/// 1.0 suite names one output length and the r1 suite a range.
fn hash_drbg(algorithm: &str, revision: &str) -> Value {
    let modes: Vec<Value> = DRBG_HASHES
        .iter()
        .map(|&(mode, strength, digest)| {
            let lengths =
                |min: u64| json!([{"min": min, "max": 4096, "increment": 8}]);
            json!({
                "mode": mode,
                "derFuncEnabled": false,
                "entropyInputLen": lengths(strength),
                "nonceLen": lengths(strength / 2),
                "persoStringLen": lengths(0),
                "additionalInputLen": lengths(0),
                "returnedBitsLen": if revision == "1.0" {
                    json!(4096)
                } else {
                    lengths(digest)
                },
            })
        })
        .collect();
    json!({
        "algorithm": algorithm,
        "revision": revision,
        "predResistanceEnabled": [true, false],
        "reseedImplemented": true,
        "capabilities": modes,
    })
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

    /// The form without a counter names each function's length, and
    /// the form with one does not.
    #[test]
    fn one_step_lengths_belong_to_the_counterless_form() {
        let all = capabilities(Options::default());
        let one_step = &all[3];
        assert_eq!(one_step["mode"], "OneStep");
        assert_eq!(one_step["l"], 1024);
        let functions = one_step["auxFunctions"].as_array().expect("aux");
        assert_eq!(functions.len(), 2 * ONE_STEP_HASHES.len() + 2);
        assert!(functions.iter().all(|f| f["l"].is_null()));
        assert!(functions[0]["macSaltMethods"].is_null());
        assert_eq!(functions[1]["auxFunctionName"], "HMAC-SHA-1");
        assert_eq!(functions[1]["macSaltMethods"][0], "default");
        let no_counter = &all[4];
        assert_eq!(no_counter["mode"], "OneStepNoCounter");
        assert!(no_counter["l"].is_null());
        let functions = no_counter["auxFunctions"].as_array().expect("aux");
        assert_eq!(functions[0]["l"], 160);
        assert_eq!(functions[9]["l"], 512);
        assert_eq!(functions[22]["auxFunctionName"], "KMAC-128");
        assert_eq!(functions[22]["l"], 2048);
    }

    /// Counter mode never goes without its counter, and only the
    /// feedback mode takes an IV, which may be empty.
    #[test]
    fn kbkdf_modes_place_their_counters() {
        let all = capabilities(Options::default());
        let kdf = &all[6];
        assert_eq!(kdf["algorithm"], "KDF");
        let modes = kdf["capabilities"].as_array().expect("modes");
        assert_eq!(modes.len(), 3);
        assert_eq!(modes[0]["kdfMode"], "counter");
        assert!(
            !modes[0]["counterLength"]
                .as_array()
                .unwrap()
                .contains(&json!(0))
        );
        assert!(
            !modes[0]["fixedDataOrder"]
                .as_array()
                .unwrap()
                .contains(&json!("none"))
        );
        assert_eq!(modes[1]["kdfMode"], "feedback");
        assert_eq!(modes[1]["supportsEmptyIv"], true);
        assert_eq!(modes[2]["supportsEmptyIv"], false);
        assert!(modes.iter().all(|m| {
            !m["macMode"]
                .as_array()
                .unwrap()
                .contains(&json!("CMAC-TDES"))
        }));
        assert_eq!(all[7]["mode"], "KMAC");
    }

    /// Both hash generators, in both revisions, over every hash,
    /// with the entropy floored at the strength and the output as
    /// the revision wants it.
    #[test]
    fn hash_generators_come_in_both_revisions() {
        let all = capabilities(Options::default());
        let generators: Vec<&Value> = all
            .iter()
            .filter(|c| {
                c["algorithm"] == "hashDRBG" || c["algorithm"] == "hmacDRBG"
            })
            .collect();
        assert_eq!(generators.len(), 4);
        let one = &generators[0];
        assert_eq!(one["revision"], "1.0");
        let modes = one["capabilities"].as_array().expect("modes");
        assert_eq!(modes.len(), DRBG_HASHES.len());
        assert_eq!(modes[0]["mode"], "SHA-1");
        assert_eq!(modes[0]["entropyInputLen"][0]["min"], 128);
        assert_eq!(modes[0]["nonceLen"][0]["min"], 64);
        assert_eq!(modes[0]["returnedBitsLen"], 4096);
        let r1 = &generators[1];
        assert_eq!(r1["revision"], "SP800-90Ar1");
        let modes = r1["capabilities"].as_array().expect("modes");
        assert_eq!(modes[4]["mode"], "SHA2-512");
        assert_eq!(modes[4]["returnedBitsLen"][0]["min"], 512);
        assert!(modes.iter().all(|m| m["derFuncEnabled"] == false));
    }
}
