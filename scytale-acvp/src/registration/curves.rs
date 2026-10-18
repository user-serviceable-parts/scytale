//! The curve schemes: ECDSA and the deterministic ECDSA from
//! draft-fussell-acvp-ecdsa at FIPS186-5, EdDSA from
//! draft-celi-acvp-eddsa at 1.0, and XECDH from
//! draft-vandersmissen-acvp-xecdh at RFC7748.
//!
//! ECDSA is offered over P-256, P-384 and P-521 with the SHA-2 and
//! SHA-3 hashes, not the SHAKEs; its keys are drawn by rejection
//! sampling, which FIPS 186-5 calls testing candidates. EdDSA is
//! Ed25519 in its plain and pre-hashed forms, with a context of any
//! length. XECDH is Curve25519. The other curves are not
//! implemented.

use serde_json::{Value, json};

use super::Options;

const CURVES: &[&str] = &["P-256", "P-384", "P-521"];

const HASHES: &[&str] = &[
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
    let signing: Vec<Value> = CURVES
        .iter()
        .map(|curve| json!({"curve": curve, "hashAlg": HASHES}))
        .collect();
    let ecdsa = |mode: &str| {
        json!({
            "algorithm": "ECDSA",
            "mode": mode,
            "revision": "FIPS186-5",
        })
    };
    let eddsa = |mode: &str| {
        json!({
            "algorithm": "EDDSA",
            "mode": mode,
            "revision": "1.0",
            "curve": ["ED-25519"],
        })
    };
    let xecdh = |mode: &str| {
        json!({
            "algorithm": "XECDH",
            "mode": mode,
            "revision": "RFC7748",
            "curve": ["Curve25519"],
        })
    };
    let mut all = Vec::new();

    let mut key_gen = ecdsa("keyGen");
    key_gen["curve"] = json!(CURVES);
    key_gen["secretGenerationMode"] = json!(["testing candidates"]);
    all.push(key_gen);
    let mut key_ver = ecdsa("keyVer");
    key_ver["curve"] = json!(CURVES);
    all.push(key_ver);
    let mut sig_gen = ecdsa("sigGen");
    sig_gen["capabilities"] = json!(signing);
    sig_gen["componentTest"] = json!(false);
    all.push(sig_gen);
    let mut det_sig_gen = ecdsa("sigGen");
    det_sig_gen["algorithm"] = json!("DetECDSA");
    det_sig_gen["capabilities"] = json!(signing);
    det_sig_gen["componentTest"] = json!(false);
    all.push(det_sig_gen);
    let mut sig_ver = ecdsa("sigVer");
    sig_ver["capabilities"] = json!(signing);
    all.push(sig_ver);

    all.push(eddsa("keyGen"));
    all.push(eddsa("keyVer"));
    let mut sig_gen = eddsa("sigGen");
    sig_gen["pure"] = json!(true);
    sig_gen["preHash"] = json!(true);
    sig_gen["contextLength"] = json!([{"min": 0, "max": 255, "increment": 1}]);
    all.push(sig_gen);
    let mut sig_ver = eddsa("sigVer");
    sig_ver["pure"] = json!(true);
    sig_ver["preHash"] = json!(true);
    all.push(sig_ver);

    all.push(xecdh("keyGen"));
    all.push(xecdh("keyVer"));
    all.push(xecdh("SSC"));
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twelve_registrations_over_the_implemented_curves() {
        let all = capabilities(Options::default());
        assert_eq!(all.len(), 12);
        let ecdsa: Vec<&Value> = all
            .iter()
            .filter(|c| {
                c["algorithm"] == "ECDSA" || c["algorithm"] == "DetECDSA"
            })
            .collect();
        assert_eq!(ecdsa.len(), 5);
        for c in &ecdsa {
            if let Some(caps) = c["capabilities"].as_array() {
                assert_eq!(caps.len(), CURVES.len());
                assert!(caps.iter().all(|k| k["hashAlg"] == json!(HASHES)));
            }
        }
        assert!(all.iter().all(|c| c["mode"].is_string()));
    }

    #[test]
    fn eddsa_signs_pure_and_prehashed_ed25519_only() {
        let all = capabilities(Options::default());
        let sig_gen = all
            .iter()
            .find(|c| c["algorithm"] == "EDDSA" && c["mode"] == "sigGen")
            .expect("sigGen");
        assert_eq!(sig_gen["curve"], json!(["ED-25519"]));
        assert_eq!(sig_gen["pure"], true);
        assert_eq!(sig_gen["preHash"], true);
    }
}
