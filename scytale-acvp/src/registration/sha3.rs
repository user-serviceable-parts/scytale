//! SHA-3 and SHAKE, draft-celi-acvp-sha3: the digests at revision
//! 2.0, SHAKE at 1.0.
//!
//! Messages of any bit length, as for SHA-2, and SHAKE output of any
//! bit length from the smallest the specification allows to the
//! largest.

use serde_json::{Value, json};

use super::Options;

const DIGESTS: &[&str] = &["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"];

const XOFS: &[&str] = &["SHAKE-128", "SHAKE-256"];

/// Sizes in GiB the specification lets the large data test ask for.
const LARGE_DATA: &[u64] = &[1, 2, 4, 8];

pub fn capabilities(options: Options) -> Vec<Value> {
    let digests = DIGESTS.iter().map(|algorithm| {
        let mut c = json!({
            "algorithm": algorithm,
            "revision": "2.0",
            "messageLength": [
                {"min": 0, "max": 65536, "increment": 1},
            ],
        });
        if options.large_data {
            c["performLargeDataTest"] = json!(LARGE_DATA);
        }
        c
    });
    let xofs = XOFS.iter().map(|algorithm| {
        json!({
            "algorithm": algorithm,
            "revision": "1.0",
            "inBit": true,
            "inEmpty": true,
            "outBit": true,
            "outputLen": [
                {"min": 16, "max": 65536, "increment": 1},
            ],
        })
    });
    digests.chain(xofs).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_then_xofs() {
        let all = capabilities(Options::default());
        assert_eq!(all.len(), DIGESTS.len() + XOFS.len());
        assert!(all[..4].iter().all(|c| c["revision"] == "2.0"));
        assert!(all[4..].iter().all(|c| c["outBit"] == true));
        assert!(all.iter().all(|c| c["performLargeDataTest"].is_null()));
    }

    #[test]
    fn large_data_is_for_the_digests_only() {
        let options = Options { large_data: true };
        for c in capabilities(options) {
            let digest = c["revision"] == "2.0";
            assert_eq!(c["performLargeDataTest"].is_array(), digest, "{c}");
        }
    }
}
