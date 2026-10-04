//! Answers a test session from the NIST ACVP server.
//!
//! `scytale-acvp register` downloads a session's vector sets into a
//! directory; this answers them, through the same functions the
//! vendored suites run, and `scytale-acvp submit` sends the answers
//! back. It is a test because the answering code is test code: it
//! lives in this crate so that it can reach every implementation,
//! and the crate's test build is the one with a file system and a
//! JSON parser. It is ignored because it does nothing without a
//! session:
//!
//! ```sh
//! SCYTALE_ACVP_SESSION=target/acvp/12345 \
//!     cargo test --lib acvp::live -- --ignored --nocapture
//! ```
//!
//! Every `<vsId>.prompt.json` in the directory is answered into
//! `<vsId>.response.json`. Where the server also sent its expected
//! answers (`<vsId>.expected.json`, sample sessions), the answers
//! are held to them here and the first disagreement is named, which
//! says more than the server's verdict will.
//!
//! A vector set this crate cannot answer fails the run: the
//! registration advertised it, so one of the two is wrong, and a
//! skip would hide which.

#[allow(unused_imports)]
use std::{
    borrow::ToOwned, eprintln, format, println, string::String, vec, vec::Vec,
};

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::support::acvp::{check, sha, shake};
use crate::hash::{sha1, sha2, sha3};
use sha::Family;

/// Names the session directory.
const SESSION: &str = "SCYTALE_ACVP_SESSION";

/// The response to `prompt`, by its algorithm, mode and revision,
/// on the implementation this processor picks.
fn answer(prompt: &Value) -> Value {
    let text = |name: &str| prompt[name].as_str().unwrap_or("");
    let (algorithm, mode, revision) =
        (text("algorithm"), text("mode"), text("revision"));
    match (algorithm, mode, revision) {
        ("SHA-1", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha1::Sha1::new)
        }
        ("SHA2-224", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha224::new)
        }
        ("SHA2-256", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha256::new)
        }
        ("SHA2-384", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha384::new)
        }
        ("SHA2-512", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha512::new)
        }
        ("SHA2-512/224", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha512_224::new)
        }
        ("SHA2-512/256", "", "1.0") => {
            sha::answer(prompt, Family::Sha2, sha2::Sha512_256::new)
        }
        ("SHA3-224", "", "2.0") => {
            sha::answer(prompt, Family::Sha3, sha3::Sha3_224::new)
        }
        ("SHA3-256", "", "2.0") => {
            sha::answer(prompt, Family::Sha3, sha3::Sha3_256::new)
        }
        ("SHA3-384", "", "2.0") => {
            sha::answer(prompt, Family::Sha3, sha3::Sha3_384::new)
        }
        ("SHA3-512", "", "2.0") => {
            sha::answer(prompt, Family::Sha3, sha3::Sha3_512::new)
        }
        ("SHAKE-128", "", "1.0") => shake::answer(prompt, sha3::Shake128::new),
        ("SHAKE-256", "", "1.0") => shake::answer(prompt, sha3::Shake256::new),
        _ => panic!(
            "{algorithm}/{mode} {revision}: nothing here answers it, \
             yet scytale-acvp registered it"
        ),
    }
}

/// `<vsId>.prompt.json` files under `dir`, in order.
fn prompts(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".prompt.json"))
        })
        .collect();
    found.sort();
    found
}

fn read(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Answers every vector set of the session named by the
/// environment, and holds the answers to the server's where it sent
/// them.
#[test]
#[ignore]
fn answer_session() {
    let dir = std::env::var(SESSION)
        .unwrap_or_else(|_| panic!("{SESSION} names the session directory"));
    // Cargo runs a test in its crate's directory; a relative path
    // is meant from the checkout, where scytale-acvp keeps sessions.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let dir = &root.join(dir);
    let prompts = prompts(dir);
    assert!(!prompts.is_empty(), "no prompts in {}", dir.display());
    let mut differ = Vec::new();
    for path in prompts {
        let name = path.file_name().and_then(|n| n.to_str()).expect("name");
        let id = name.trim_end_matches(".prompt.json");
        let prompt = read(&path);
        eprintln!(
            "{id}: {} {}",
            prompt["algorithm"].as_str().unwrap_or("?"),
            prompt["revision"].as_str().unwrap_or("?")
        );
        let response = answer(&prompt);
        let text = serde_json::to_string_pretty(&response).expect("JSON");
        let out = dir.join(format!("{id}.response.json"));
        fs::write(&out, text)
            .unwrap_or_else(|e| panic!("{}: {e}", out.display()));
        let expected = dir.join(format!("{id}.expected.json"));
        if expected.is_file() {
            let expected = read(&expected);
            match check(&expected["testGroups"], &response["testGroups"]) {
                Ok(()) => eprintln!("{id}: as the server expects"),
                Err(why) => {
                    eprintln!("{id}: differs from the server: {why}");
                    differ.push(id.to_owned());
                }
            }
        }
    }
    assert!(
        differ.is_empty(),
        "answers differ from the server's for vector sets {differ:?}"
    );
}
