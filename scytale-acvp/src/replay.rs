//! A saved session answered again, offline: the prompts a run wrote
//! with `--save`, compared with the expected answers saved beside
//! them.

use crate::envelope;
use crate::profile::{Seed, answer_under};
use crate::suite::{self, Suite, compare};
use crate::support::Error;
use scytale::features::Features;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// The driver for `doc` among `chosen`; an empty `chosen` means every
/// suite. One not among a nonempty `chosen` is `None`, so a run
/// restricted to some suites leaves the others alone.
pub fn suite_for<'a>(chosen: &[&'a Suite], doc: &Value) -> Option<&'a Suite> {
    let algorithm = doc["algorithm"].as_str()?;
    let mode = doc["mode"].as_str().filter(|m| !m.is_empty());
    let revision = doc["revision"].as_str();
    let fits = |s: &&Suite| {
        s.algorithm == algorithm
            && s.mode == mode
            && revision.is_none_or(|r| r == s.revision)
    };
    if chosen.is_empty() {
        suite::SUITES.iter().find(fits)
    } else {
        chosen.iter().copied().find(fits)
    }
}

/// Answers every saved prompt in `dir` again and compares with the
/// saved expected answers where there are any.
pub fn replay(
    dir: &Path,
    seed: &Seed,
    profiles: &[Features],
) -> Result<Vec<String>, Error> {
    let mut problems = Vec::new();
    let mut names: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.to_string_lossy().ends_with(".prompt.json"))
        .collect();
    names.sort();
    for prompt in names {
        let text = fs::read_to_string(&prompt)?;
        let doc: Value = serde_json::from_str(&text)?;
        let doc = envelope::unwrap(&doc).unwrap_or(doc);
        let name = prompt.file_name().unwrap_or_default().to_string_lossy();
        let Some(suite) = suite_for(&[], &doc) else {
            problems.push(format!("{name}: no driver"));
            continue;
        };
        let answered = answer_under(suite, &doc, seed, profiles)?;
        let expected = prompt
            .to_string_lossy()
            .replace(".prompt.json", ".expected.json");
        if let Ok(text) = fs::read_to_string(&expected) {
            let expected: Value = serde_json::from_str(&text)?;
            let expected = envelope::unwrap(&expected).unwrap_or(expected);
            match compare(suite, &expected, &answered) {
                Ok(n) => eprintln!("{name}: {n} cases match"),
                Err(e) => problems.push(format!("{name}: {e}")),
            }
        } else {
            eprintln!("{name}: answered, nothing to compare with");
        }
    }
    Ok(problems)
}

/// Writes `doc` to `dir/name`, pretty-printed.
pub fn save(dir: &Path, name: &str, doc: &Value) -> Result<(), Error> {
    let text = serde_json::to_string_pretty(doc)?;
    fs::write(dir.join(name), text)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chosen_suites_exclude_the_rest() {
        let sha = suite::find("ACVP-SHA2-256-1.0");
        let cbc = json!({ "algorithm": "ACVP-AES-CBC", "revision": "1.0" });
        assert!(suite_for(&sha, &cbc).is_none());
        assert!(suite_for(&[], &cbc).is_some());
        let doc = json!({ "algorithm": "SHA2-256", "revision": "1.0" });
        assert!(suite_for(&sha, &doc).is_some());
    }
}
