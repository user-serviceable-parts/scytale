//! SHA-1 and SHA-2, draft-celi-acvp-sha revision 1.0.
//!
//! The library takes messages of any bit length, so the message
//! length domain runs over every bit count the specification
//! allows. The large data test is optional there and here: each
//! size is gigabytes of hashing per algorithm.

use serde_json::{Value, json};

use super::Options;

const ALGORITHMS: &[&str] = &[
    "SHA-1",
    "SHA2-224",
    "SHA2-256",
    "SHA2-384",
    "SHA2-512",
    "SHA2-512/224",
    "SHA2-512/256",
];

/// Sizes in GiB the specification lets the large data test ask for.
const LARGE_DATA: &[u64] = &[1, 2, 4, 8];

pub fn capabilities(options: Options) -> Vec<Value> {
    ALGORITHMS
        .iter()
        .map(|algorithm| {
            let mut c = json!({
                "algorithm": algorithm,
                "revision": "1.0",
                "messageLength": [
                    {"min": 0, "max": 65536, "increment": 1},
                ],
            });
            if options.large_data {
                c["performLargeDataTest"] = json!(LARGE_DATA);
            }
            c
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_per_algorithm() {
        let all = capabilities(Options::default());
        assert_eq!(all.len(), ALGORITHMS.len());
        assert!(all.iter().all(|c| c["performLargeDataTest"].is_null()));
    }

    #[test]
    fn large_data_is_opted_into() {
        let options = Options { large_data: true };
        for c in capabilities(options) {
            assert_eq!(c["performLargeDataTest"], json!([1, 2, 4, 8]));
        }
    }
}
