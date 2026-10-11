//! What scytale tells the server it can do: one capability object
//! per algorithm, each written from that algorithm's specification
//! at <https://pages.nist.gov/ACVP/>. Only what the library's
//! answering step can answer is advertised, so that a gap is a
//! missing registration and never a failed vector set.

use serde_json::Value;

use crate::Result;

mod aead;
mod aes;
mod mac;
mod sha;
mod sha3;

/// Choices that change what is registered.
#[derive(Clone, Copy, Default)]
pub struct Options {
    /// Ask for the large data tests, which hash gigabytes.
    pub large_data: bool,
}

/// Every capability object, in a stable order.
pub fn capabilities(options: Options) -> Vec<Value> {
    let mut all = sha::capabilities(options);
    all.extend(sha3::capabilities(options));
    all.extend(aes::capabilities(options));
    all.extend(aead::capabilities(options));
    all.extend(mac::capabilities(options));
    all
}

/// The name of a capability object as `--algorithm` takes it: the
/// algorithm, and `/mode` when it has one.
pub fn name(capability: &Value) -> String {
    let algorithm = capability["algorithm"].as_str().unwrap_or("?");
    match capability["mode"].as_str() {
        Some(mode) => format!("{algorithm}/{mode}"),
        None => algorithm.to_owned(),
    }
}

/// The capability objects named in `names`, or all of them when
/// `names` is empty. A name that matches nothing is an error, since
/// a typo would otherwise register less than was asked for.
pub fn select(names: &[String], options: Options) -> Result<Vec<Value>> {
    let all = capabilities(options);
    if names.is_empty() {
        return Ok(all);
    }
    let mut selected = Vec::new();
    for wanted in names {
        let before = selected.len();
        selected.extend(all.iter().filter(|c| matches(c, wanted)).cloned());
        if selected.len() == before {
            return Err(format!("no algorithm named {wanted}").into());
        }
    }
    Ok(selected)
}

/// Whether `wanted` names `capability`: its full name, or its
/// algorithm alone, which takes every mode.
fn matches(capability: &Value, wanted: &str) -> bool {
    let full = name(capability);
    full == wanted || capability["algorithm"] == wanted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_names_an_algorithm_and_revision() {
        for c in capabilities(Options::default()) {
            assert!(c["algorithm"].is_string(), "{c}");
            assert!(c["revision"].is_string(), "{c}");
        }
    }

    #[test]
    fn names_are_unique() {
        let mut names: Vec<String> =
            capabilities(Options::default()).iter().map(name).collect();
        let count = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn empty_selection_is_everything() {
        let options = Options::default();
        let all = capabilities(options);
        assert_eq!(select(&[], options).expect("select"), all);
    }

    #[test]
    fn selects_by_name() {
        let names = ["SHA2-256".to_owned()];
        let selected = select(&names, Options::default()).expect("select");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0]["algorithm"], "SHA2-256");
    }

    #[test]
    fn unknown_name_is_an_error() {
        let names = ["SHA2-255".to_owned()];
        let err = select(&names, Options::default()).expect_err("err");
        assert!(err.to_string().contains("SHA2-255"), "{err}");
    }

    #[test]
    fn mode_is_part_of_the_name() {
        let c = serde_json::json!({"algorithm": "ECDSA", "mode": "sigGen"});
        assert_eq!(name(&c), "ECDSA/sigGen");
        assert!(matches(&c, "ECDSA"));
        assert!(matches(&c, "ECDSA/sigGen"));
        assert!(!matches(&c, "ECDSA/sigVer"));
    }
}
