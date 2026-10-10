//! The authenticated modes and the key wraps,
//! draft-celi-acvp-symmetric revision 1.0: GCM, GMAC, GCM-SIV, XPN,
//! CCM, KW and KWP.
//!
//! Nonces and salts are taken from the caller, so the GCM and XPN
//! registrations say so; the server then supplies them. Lengths are
//! bytes here, so every domain steps by eight bits.

use serde_json::{Value, json};

use super::Options;

/// The tag lengths GCM and XPN offer, in bits.
const GCM_TAGS: &[u64] = &[32, 64, 96, 104, 112, 120, 128];

/// The tag lengths CCM offers: every even byte count from 4 to 16.
const CCM_TAGS: &[u64] = &[32, 48, 64, 80, 96, 112, 128];

pub fn capabilities(_: Options) -> Vec<Value> {
    let directions = json!(["encrypt", "decrypt"]);
    let widths = json!([128, 192, 256]);
    let bytes = |min: u64, max: u64| {
        json!([{
            "min": min, "max": max, "increment": 8,
        }])
    };
    vec![
        json!({
            "algorithm": "ACVP-AES-GCM",
            "revision": "1.0",
            "direction": directions,
            "keyLen": widths,
            "payloadLen": bytes(0, 65536),
            "ivLen": bytes(8, 1024),
            "ivGen": "external",
            "ivGenMode": "8.2.2",
            "aadLen": bytes(0, 65536),
            "tagLen": GCM_TAGS,
        }),
        json!({
            "algorithm": "ACVP-AES-GMAC",
            "revision": "1.0",
            "direction": directions,
            "keyLen": widths,
            "ivLen": bytes(8, 1024),
            "ivGen": "external",
            "ivGenMode": "8.2.2",
            "aadLen": bytes(0, 65536),
            "tagLen": GCM_TAGS,
        }),
        json!({
            "algorithm": "ACVP-AES-GCM-SIV",
            "revision": "1.0",
            "direction": directions,
            "keyLen": [128, 256],
            "payloadLen": bytes(0, 65536),
            "aadLen": bytes(0, 65536),
        }),
        json!({
            "algorithm": "ACVP-AES-XPN",
            "revision": "1.0",
            "direction": directions,
            "keyLen": widths,
            "payloadLen": bytes(0, 65536),
            "ivGen": "external",
            "ivGenMode": "8.2.2",
            "saltGen": "external",
            "aadLen": bytes(8, 65536),
            "tagLen": GCM_TAGS,
        }),
        json!({
            "algorithm": "ACVP-AES-CCM",
            "revision": "1.0",
            "direction": directions,
            "keyLen": widths,
            "payloadLen": bytes(0, 256),
            "ivLen": bytes(56, 104),
            "aadLen": bytes(0, 65536),
            "tagLen": CCM_TAGS,
        }),
        json!({
            "algorithm": "ACVP-AES-KW",
            "revision": "1.0",
            "direction": directions,
            "keyLen": widths,
            "kwCipher": ["cipher", "inverse"],
            "payloadLen": [{"min": 128, "max": 4096, "increment": 64}],
        }),
        json!({
            "algorithm": "ACVP-AES-KWP",
            "revision": "1.0",
            "direction": directions,
            "keyLen": widths,
            "kwCipher": ["cipher", "inverse"],
            "payloadLen": bytes(8, 4096),
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_modes_with_the_server_supplying_nonces() {
        let all = capabilities(Options::default());
        assert_eq!(all.len(), 7);
        for c in &all {
            if !c["ivGen"].is_null() {
                assert_eq!(c["ivGen"], "external", "{c}");
            }
        }
        let siv = &all[2];
        assert_eq!(siv["keyLen"], json!([128, 256]));
        assert!(siv["ivGen"].is_null());
    }

    #[test]
    fn gmac_has_no_payload() {
        let gmac = &capabilities(Options::default())[1];
        assert_eq!(gmac["algorithm"], "ACVP-AES-GMAC");
        assert!(gmac["payloadLen"].is_null());
    }
}
