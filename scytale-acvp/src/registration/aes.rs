//! The AES modes, draft-celi-acvp-symmetric: the block cipher modes
//! at revision 1.0, XTS at 2.0 since 1.0 is no longer served, and
//! the two format-preserving modes.
//!
//! Counter mode is registered without the counter tests: those have
//! the server infer the counters an implementation generated, and
//! this library takes the counter from the caller. XTS is registered
//! with each data unit the whole payload, which is how the mode is
//! offered.

use serde_json::{Value, json};

use super::Options;

/// The modes whose registration is the direction and key width.
const PLAIN: &[&str] = &[
    "ACVP-AES-ECB",
    "ACVP-AES-CBC",
    "ACVP-AES-CFB1",
    "ACVP-AES-CFB8",
    "ACVP-AES-CFB128",
    "ACVP-AES-OFB",
];

/// The format-preserving alphabets, as (alphabet, radix). The
/// shortest message is the one SP 800-38G allows, the first length
/// with a million messages in it; the longest is what the mode
/// takes.
const FF1_ALPHABETS: &[(&str, u32)] = &[
    ("ab", 2),
    ("0123", 4),
    ("0123456789", 10),
    ("0123456789abcdef", 16),
    ("abcdefghijklmnopqrstuvwxyz", 26),
    ("012345abcdefghijklmnopqrstuvwxyz", 32),
    (
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
        64,
    ),
];

const FF3_1_ALPHABETS: &[(&str, u32)] = &[
    ("0123456789", 10),
    ("abcdefghijklmnopqrstuvwxyz", 26),
    (
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
        64,
    ),
];

/// The smallest number of messages a format allows, SP 800-38G.
const MIN_DOMAIN: u64 = 1_000_000;

/// The longest FF1 message the library takes, in symbols.
const FF1_MAX_SYMBOLS: u64 = 512;

/// Bits one half of an FF3-1 message must fit in.
const FF3_1_HALF_BITS: f64 = 96.0;

pub fn capabilities(_: Options) -> Vec<Value> {
    let directions = json!(["encrypt", "decrypt"]);
    let widths = json!([128, 192, 256]);
    let mut all: Vec<Value> = PLAIN
        .iter()
        .map(|algorithm| {
            json!({
                "algorithm": algorithm,
                "revision": "1.0",
                "direction": directions,
                "keyLen": widths,
            })
        })
        .collect();
    all.push(json!({
        "algorithm": "ACVP-AES-CTR",
        "revision": "1.0",
        "direction": directions,
        "keyLen": widths,
        "payloadLen": [{"min": 1, "max": 128, "increment": 1}],
        "incrementalCounter": true,
        "overflowCounter": true,
        "performCounterTests": false,
    }));
    all.push(json!({
        "algorithm": "ACVP-AES-XTS",
        "revision": "2.0",
        "direction": directions,
        "keyLen": [128, 256],
        "tweakMode": ["hex", "number"],
        "dataUnitLenMatchesPayload": true,
        "payloadLen": [{"min": 128, "max": 65536, "increment": 8}],
    }));
    all.push(json!({
        "algorithm": "ACVP-AES-FF1",
        "revision": "1.0",
        "direction": directions,
        "keyLen": widths,
        "tweakLen": [{"min": 0, "max": 128, "increment": 8}],
        "capabilities": formats(FF1_ALPHABETS, |_| FF1_MAX_SYMBOLS),
    }));
    all.push(json!({
        "algorithm": "ACVP-AES-FF3-1",
        "revision": "1.0",
        "direction": directions,
        "keyLen": widths,
        "tweakLen": [56],
        "capabilities": formats(FF3_1_ALPHABETS, ff3_1_max),
    }));
    all
}

/// One capability per alphabet, the longest message from `max`.
fn formats(alphabets: &[(&str, u32)], max: fn(u32) -> u64) -> Value {
    let entries: Vec<Value> = alphabets
        .iter()
        .map(|&(alphabet, radix)| {
            json!({
                "alphabet": alphabet,
                "radix": radix,
                "minLen": min_len(radix),
                "maxLen": max(radix),
            })
        })
        .collect();
    Value::Array(entries)
}

/// The shortest message with a million possibilities at `radix`.
fn min_len(radix: u32) -> u64 {
    let mut len = 0;
    let mut domain: u64 = 1;
    while domain < MIN_DOMAIN {
        domain *= u64::from(radix);
        len += 1;
    }
    len
}

/// The longest FF3-1 message at `radix`: two halves of 96 bits.
fn ff3_1_max(radix: u32) -> u64 {
    2 * (FF3_1_HALF_BITS / f64::from(radix).log2()).floor() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_lengths_follow_sp_800_38g() {
        assert_eq!(min_len(2), 20);
        assert_eq!(min_len(10), 6);
        assert_eq!(min_len(26), 5);
        assert_eq!(min_len(64), 4);
    }

    #[test]
    fn ff3_1_maximum_lengths() {
        assert_eq!(ff3_1_max(10), 56);
        assert_eq!(ff3_1_max(26), 40);
        assert_eq!(ff3_1_max(64), 32);
    }

    #[test]
    fn every_mode_once() {
        let all = capabilities(Options::default());
        assert_eq!(all.len(), PLAIN.len() + 4);
        let xts = all.iter().find(|c| c["algorithm"] == "ACVP-AES-XTS");
        assert_eq!(xts.expect("xts")["revision"], "2.0");
        let ctr = all.iter().find(|c| c["algorithm"] == "ACVP-AES-CTR");
        assert_eq!(ctr.expect("ctr")["performCounterTests"], false);
    }

    #[test]
    fn alphabets_match_their_radix() {
        for &(alphabet, radix) in FF1_ALPHABETS.iter().chain(FF3_1_ALPHABETS) {
            assert_eq!(alphabet.len() as u32, radix, "{alphabet}");
        }
    }
}
