//! The MACs and the SP 800-185 functions: HMAC and CMAC from
//! draft-fussell-acvp-mac, cSHAKE and KMAC from draft-celi-acvp-xof,
//! all at revision 1.0.
//!
//! HMAC and CMAC tags are cut to whole bytes, so their lengths step
//! by eight bits; KMAC and cSHAKE take keys, messages and outputs of
//! any bit length, so theirs step by one.

use serde_json::{Value, json};

use super::Options;

/// Each HMAC, with its hash's digest length in bits, which bounds
/// the tag.
const HMACS: &[(&str, u64)] = &[
    ("HMAC-SHA-1", 160),
    ("HMAC-SHA2-224", 224),
    ("HMAC-SHA2-256", 256),
    ("HMAC-SHA2-384", 384),
    ("HMAC-SHA2-512", 512),
    ("HMAC-SHA2-512/224", 224),
    ("HMAC-SHA2-512/256", 256),
    ("HMAC-SHA3-224", 224),
    ("HMAC-SHA3-256", 256),
    ("HMAC-SHA3-384", 384),
    ("HMAC-SHA3-512", 512),
];

pub fn capabilities(_: Options) -> Vec<Value> {
    let bits = |min: u64, max: u64| {
        json!([{
            "min": min, "max": max, "increment": 1,
        }])
    };
    let bytes = |min: u64, max: u64| {
        json!([{
            "min": min, "max": max, "increment": 8,
        }])
    };
    let mut all: Vec<Value> = HMACS
        .iter()
        .map(|&(algorithm, digest)| {
            json!({
                "algorithm": algorithm,
                "revision": "1.0",
                "keyLen": bytes(8, 4096),
                "macLen": bytes(32, digest),
            })
        })
        .collect();
    let cmac_widths: Vec<Value> = [128, 192, 256]
        .iter()
        .map(|width| {
            json!({
                "direction": ["gen", "ver"],
                "keyLen": [width],
                "msgLen": bytes(0, 65536),
                "macLen": bytes(8, 128),
            })
        })
        .collect();
    all.push(json!({
        "algorithm": "CMAC-AES",
        "revision": "1.0",
        "capabilities": cmac_widths,
    }));
    for algorithm in ["cSHAKE-128", "cSHAKE-256"] {
        all.push(json!({
            "algorithm": algorithm,
            "revision": "1.0",
            "hexCustomization": true,
            "outputLen": bits(16, 65536),
            "msgLen": bits(0, 65536),
        }));
    }
    for algorithm in ["KMAC-128", "KMAC-256"] {
        all.push(json!({
            "algorithm": algorithm,
            "revision": "1.0",
            "xof": [true, false],
            "hexCustomization": true,
            "msgLen": bits(0, 65536),
            "keyLen": bits(128, 4096),
            "macLen": bits(32, 4096),
        }));
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_tags_stop_at_the_digest() {
        let all = capabilities(Options::default());
        assert_eq!(all.len(), HMACS.len() + 5);
        let sha1 = &all[0];
        assert_eq!(sha1["algorithm"], "HMAC-SHA-1");
        assert_eq!(sha1["macLen"][0]["max"], 160);
        let sha512 = &all[4];
        assert_eq!(sha512["macLen"][0]["max"], 512);
    }

    #[test]
    fn cmac_has_one_capability_per_width() {
        let all = capabilities(Options::default());
        let cmac = &all[HMACS.len()];
        assert_eq!(cmac["algorithm"], "CMAC-AES");
        assert_eq!(cmac["capabilities"].as_array().expect("array").len(), 3);
    }

    #[test]
    fn kmac_offers_both_shapes() {
        let all = capabilities(Options::default());
        let kmac = all.last().expect("kmac");
        assert_eq!(kmac["algorithm"], "KMAC-256");
        assert_eq!(kmac["xof"], json!([true, false]));
    }
}
