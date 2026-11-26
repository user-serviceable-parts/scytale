//! The ACVP protocol against a server: log in, open a test session,
//! fetch each vector set, answer it, post the answer and read the
//! verdict.
//!
//! Every message is `[{"acvVersion": "1.0"}, {...}]`; [`Http`] wraps
//! and unwraps that. The server's URLs are relative to its root,
//! which the base URL names up to and including `/acvp/v1`.
//!
//! A run saves what it sends and receives, `session.json` first, and
//! [`Run::resume`] picks a saved session up again: the server still
//! holds its vector sets and the verdicts on them, so only the sets
//! that have not passed are answered.

use crate::http::Http;
use crate::profile::{Seed, answer_under};
use crate::replay::{save, suite_for};
use crate::suite::{Suite, compare, with_prompt};
use crate::support::{Error, list, opt_int, text};
use crate::totp;
use scytale::features::Features;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

/// NIST's demo server.
pub const DEMO: &str = "https://demo.acvts.nist.gov/acvp/v1";

/// How often a failed connection is tried again, and the pause.
const RETRIES: u32 = 3;
const RETRY_WAIT: u64 = 10;

/// What a run does with each vector set.
pub struct Run<'a> {
    pub http: Http,
    pub base: String,
    pub totp_seed: String,
    pub seed: Seed,
    /// The profiles to answer under; one means no comparison.
    pub profiles: Vec<Features>,
    /// Where to write each vector set and its answer; a run without
    /// one names a directory after the session.
    pub save: Option<PathBuf>,
    pub sample: bool,
    pub suites: Vec<&'a Suite>,
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub session: String,
    pub passed: usize,
    /// The vector sets that did not pass: algorithm, mode, and what
    /// the server said.
    pub failed: Vec<String>,
}

impl Run<'_> {
    /// Logs in with a fresh code.
    pub fn login(&mut self) -> Result<(), Error> {
        self.login_with(None)
    }

    /// Renews the token in use, which the server lets lapse after
    /// half an hour: the same login, with the old token alongside the
    /// fresh code, and the server returns a new one for the session.
    fn renew(&mut self) -> Result<(), Error> {
        let old = self.http.token().map(str::to_string);
        self.login_with(old)
    }

    /// `POST /login` with the current code and, for a renewal, the
    /// token to renew. The server takes each code once, so a second
    /// login inside one thirty-second window is refused; that waits
    /// for the next window and tries again.
    fn login_with(&mut self, old: Option<String>) -> Result<(), Error> {
        let url = format!("{}/login", self.base);
        let mut body = json!({ "password": totp::code(&self.totp_seed)? });
        if let Some(old) = &old {
            body["accessToken"] = json!(old);
        }
        // The token to renew goes in the body alone.
        self.http.clear_token();
        let reply = match self.http.post(&url, &body) {
            Err(e) if e.http_status == Some(403) => {
                let wait = totp::seconds_left()?;
                eprintln!("login: code already used, retrying in {wait}s");
                sleep(Duration::from_secs(wait));
                body["password"] = json!(totp::code(&self.totp_seed)?);
                self.http.post(&url, &body)?
            }
            other => other?,
        };
        let token = text(&reply, "accessToken")?.to_string();
        self.http.set_token(token);
        Ok(())
    }

    /// `GET url`, once more after a renewal if the token had lapsed,
    /// and again after a pause when the connection itself failed,
    /// which the server does now and then on a long reply.
    fn get(&mut self, url: &str) -> Result<Value, Error> {
        let mut tries = 0;
        loop {
            match self.http.get(url) {
                Err(e) if e.http_status == Some(401) => {
                    self.renew()?;
                }
                Err(e) if e.http_status.is_none() && tries < RETRIES => {
                    tries += 1;
                    eprintln!("{url}: {e}; retrying in {RETRY_WAIT}s");
                    sleep(Duration::from_secs(RETRY_WAIT));
                }
                other => return other,
            }
        }
    }

    /// `POST url`, once more after a renewal if the token had lapsed:
    /// a refused post was not acted on, so sending it again is safe.
    fn post(&mut self, url: &str, body: &Value) -> Result<Value, Error> {
        match self.http.post(url, body) {
            Err(e) if e.http_status == Some(401) => {
                self.renew()?;
                self.http.post(url, body)
            }
            other => other,
        }
    }

    /// The whole session: registration, every vector set, verdict.
    pub fn session(
        &mut self,
        registrations: &[Value],
    ) -> Result<Verdict, Error> {
        self.login()?;
        let url = format!("{}/testSessions", self.base);
        let body = json!({
            "isSample": self.sample,
            "algorithms": registrations,
        });
        let mut reply = self.post(&url, &body)?;
        let session = text(&reply, "url")?.to_string();
        // A session carries a token of its own, scoped to it.
        if let Some(token) = reply.get("accessToken").and_then(Value::as_str) {
            self.http.set_token(token.to_string());
        }
        let sets = vector_set_urls(&reply)?;
        eprintln!("session {session}: {} vector sets", sets.len());
        let dir = self.save.clone().unwrap_or_else(|| {
            PathBuf::from(format!("acvp-{}", id_of(&session)))
        });
        fs::create_dir_all(&dir)?;
        // The reply does not say whether the session is a sample, and
        // a resume needs to know.
        if let Some(obj) = reply.as_object_mut() {
            obj.insert("isSample".into(), json!(self.sample));
        }
        save(&dir, "session.json", &reply)?;
        eprintln!(
            "saving to {}; resume with: scytale-acvp resume {0}",
            dir.display()
        );
        self.save = Some(dir);
        let mut verdict = Verdict {
            session,
            passed: 0,
            failed: Vec::new(),
        };
        for set in &sets {
            self.judge(set, &mut verdict, |run, url| run.vector_set(url))?;
        }
        self.summary(&verdict.session)?;
        Ok(verdict)
    }

    /// A saved session taken up again: the sets the server has
    /// already passed are left alone, as are the sets of suites not
    /// chosen, and the rest are answered as in [`session`](Self::session).
    pub fn resume(&mut self, dir: &Path) -> Result<Verdict, Error> {
        let text = fs::read_to_string(dir.join("session.json"))?;
        let saved: Value = serde_json::from_str(&text)?;
        let session = text_of(&saved, "url")?;
        self.sample = saved["isSample"].as_bool().unwrap_or(false);
        self.save = Some(dir.to_path_buf());
        if let Some(token) = saved.get("accessToken").and_then(Value::as_str) {
            self.http.set_token(token.to_string());
        }
        // The saved token has lapsed by now; the renewal takes it
        // alongside a fresh code.
        self.renew()?;
        let sets = vector_set_urls(&saved)?;
        eprintln!("session {session}: {} vector sets", sets.len());
        // One summary says which sets have passed.
        let summary =
            self.get(&self.absolute(&format!("{session}/results")))?;
        let passed = passed_sets(&summary);
        let mut verdict = Verdict {
            session,
            passed: 0,
            failed: Vec::new(),
        };
        for set in &sets {
            if passed.iter().any(|p| p == set) {
                eprintln!("{set}: already passed");
                verdict.passed += 1;
                continue;
            }
            // The prompt the first run saved says what the set is
            // without fetching it again; a set never reached is
            // fetched to find out.
            let doc = match saved_prompt(dir, id_of(set)) {
                Some(doc) => doc,
                None => match self.fetch(&self.absolute(set)) {
                    Ok(doc) => doc,
                    Err(e) => {
                        eprintln!("{set}: {e}");
                        verdict.failed.push(format!("{set}: {e}"));
                        continue;
                    }
                },
            };
            if suite_for(&self.suites, &doc).is_none() {
                // Neither passed nor failed: not this run's business.
                eprintln!("{set}: not chosen, left alone");
                continue;
            }
            self.judge(set, &mut verdict, |run, url| {
                run.answer_set(url, &doc)
            })?;
        }
        self.summary(&verdict.session)?;
        Ok(verdict)
    }

    /// Runs `f` on one set and books the outcome: a pass, a failure
    /// the server named, or an error of ours, which fails the set and
    /// lets the rest run. A disagreement between implementations is
    /// the one error that stops everything.
    fn judge(
        &mut self,
        set: &str,
        verdict: &mut Verdict,
        f: impl FnOnce(&mut Self, &str) -> Result<Option<String>, Error>,
    ) -> Result<(), Error> {
        let url = self.absolute(set);
        match f(self, &url) {
            Ok(None) => verdict.passed += 1,
            Ok(Some(why)) => verdict.failed.push(why),
            Err(e) if e.status == 2 => return Err(e),
            Err(e) => {
                eprintln!("{set}: {e}");
                verdict.failed.push(format!("{set}: {e}"));
            }
        }
        Ok(())
    }

    /// The server's summary of the session, saved; a summary that
    /// cannot be read is reported, the verdicts being in by then.
    fn summary(&mut self, session: &str) -> Result<(), Error> {
        let url = self.absolute(&format!("{session}/results"));
        match self.get(&url) {
            Ok(summary) => {
                if let Some(dir) = &self.save {
                    save(dir, "results.json", &summary)?;
                }
            }
            Err(e) => eprintln!("{session}: no summary: {e}"),
        }
        Ok(())
    }

    /// Fetches, answers, posts and judges one vector set. `None` if
    /// it passed, otherwise what went wrong.
    fn vector_set(&mut self, url: &str) -> Result<Option<String>, Error> {
        let doc = self.fetch(url)?;
        self.answer_set(url, &doc)
    }

    /// Answers, posts and judges a vector set already fetched.
    fn answer_set(
        &mut self,
        url: &str,
        doc: &Value,
    ) -> Result<Option<String>, Error> {
        let id = opt_int(doc, "vsId").unwrap_or(0);
        let name = format!(
            "{} {}",
            doc["algorithm"].as_str().unwrap_or("?"),
            doc["mode"].as_str().unwrap_or("")
        );
        let stem = format!("{id}-{}", name.trim().replace(['/', ' '], "-"));
        if let Some(dir) = &self.save {
            save(dir, &format!("{stem}.prompt.json"), doc)?;
        }
        let Some(suite) = suite_for(&self.suites, doc) else {
            return Ok(Some(format!("{name}: no driver")));
        };
        eprintln!("{name} (vsId {id}): answering");
        let answered = answer_under(suite, doc, &self.seed, &self.profiles)?;
        if let Some(dir) = &self.save {
            save(dir, &format!("{stem}.answer.json"), &answered)?;
        }
        if self.sample {
            let expected = self.fetch(&format!("{url}/expected"))?;
            if let Some(dir) = &self.save {
                save(dir, &format!("{stem}.expected.json"), &expected)?;
            }
            let checked = with_prompt(doc, &expected)
                .and_then(|expected| compare(suite, &expected, &answered));
            match checked {
                Ok(n) => {
                    eprintln!("{name}: {n} cases match the expected answers")
                }
                Err(e) => eprintln!("{name}: differs from expected: {e}"),
            }
        }
        self.post(&format!("{url}/results"), &answered)?;
        let verdict = self.verdict(&format!("{url}/results"))?;
        if let Some(dir) = &self.save {
            save(dir, &format!("{stem}.verdict.json"), &verdict)?;
        }
        let disposition = verdict["disposition"].as_str().unwrap_or("?");
        if disposition == "passed" {
            eprintln!("{name}: passed");
            return Ok(None);
        }
        let mut why = format!("{name}: {disposition}");
        for t in verdict["tests"].as_array().into_iter().flatten() {
            if t["result"].as_str() != Some("passed") {
                why.push_str(&format!(
                    "\n  tcId {}: {} {}",
                    t["tcId"],
                    t["result"].as_str().unwrap_or("?"),
                    t["reason"].as_str().unwrap_or("")
                ));
            }
        }
        eprintln!("{why}");
        Ok(Some(why))
    }

    /// A document the server may still be preparing: a reply that
    /// carries `retry` says how many seconds to wait.
    fn fetch(&mut self, url: &str) -> Result<Value, Error> {
        loop {
            let doc = self.get(url)?;
            match opt_int(&doc, "retry") {
                Some(seconds) if doc.get("testGroups").is_none() => {
                    eprintln!("{url}: not ready, retrying in {seconds}s");
                    sleep(Duration::from_secs(seconds.clamp(1, 60)));
                }
                _ => return Ok(doc),
            }
        }
    }

    /// Reads the verdict once the server has one.
    fn verdict(&mut self, url: &str) -> Result<Value, Error> {
        loop {
            let doc = self.get(url)?;
            match doc["disposition"].as_str() {
                Some("unreceived") | Some("incomplete") | None => {
                    let seconds = opt_int(&doc, "retry").unwrap_or(5);
                    sleep(Duration::from_secs(seconds.clamp(1, 60)));
                }
                _ => return Ok(doc),
            }
        }
    }

    /// The server gives URLs from its root, `/acvp/v1/...`.
    fn absolute(&self, path: &str) -> String {
        if path.starts_with("http") {
            return path.to_string();
        }
        let root = self.base.trim_end_matches("/acvp/v1");
        format!("{root}{path}")
    }
}

/// The vector set URLs a session reply lists.
fn vector_set_urls(reply: &Value) -> Result<Vec<String>, Error> {
    Ok(list(reply, "vectorSetUrls")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect())
}

/// A string field, owned.
fn text_of(doc: &Value, name: &str) -> Result<String, Error> {
    Ok(text(doc, name)?.to_string())
}

/// The last segment of a session URL, which names its directory.
fn id_of(session: &str) -> &str {
    session
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("session")
}

/// The vector sets a session summary says have passed.
fn passed_sets(summary: &Value) -> Vec<String> {
    summary["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["status"].as_str() == Some("passed"))
        .filter_map(|r| r["vectorSetUrl"].as_str().map(str::to_string))
        .collect()
}

/// The prompt a run saved for vector set `id`, if it got that far.
fn saved_prompt(dir: &Path, id: &str) -> Option<Value> {
    let prefix = format!("{id}-");
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".prompt.json") {
            let text = fs::read_to_string(entry.path()).ok()?;
            return serde_json::from_str(&text).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_directory_is_named_after_the_id() {
        assert_eq!(id_of("/acvp/v1/testSessions/784731"), "784731");
        assert_eq!(id_of("/acvp/v1/testSessions/784731/"), "784731");
        assert_eq!(id_of(""), "");
    }

    #[test]
    fn only_passed_sets_are_skipped() {
        let summary = json!({ "passed": false, "results": [
            { "status": "passed", "vectorSetUrl": "/s/1" },
            { "status": "incomplete", "vectorSetUrl": "/s/2" },
            { "status": "failed", "vectorSetUrl": "/s/3" },
        ]});
        assert_eq!(passed_sets(&summary), vec!["/s/1".to_string()]);
        assert!(passed_sets(&json!({ "retry": 30 })).is_empty());
    }

    #[test]
    fn saved_prompt_is_found_by_its_set_id() {
        let dir = std::env::temp_dir()
            .join(format!("scytale-acvp-resume-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        save(&dir, "41-SHA2-256.prompt.json", &json!({ "vsId": 41 })).unwrap();
        assert_eq!(saved_prompt(&dir, "41").unwrap()["vsId"], 41);
        assert!(saved_prompt(&dir, "4").is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn saved_session_lists_its_sets() {
        let reply = json!({
            "url": "/acvp/v1/testSessions/7",
            "vectorSetUrls": ["/acvp/v1/testSessions/7/vectorSets/1"],
            "accessToken": "t",
        });
        assert_eq!(
            vector_set_urls(&reply).unwrap(),
            vec!["/acvp/v1/testSessions/7/vectorSets/1".to_string()]
        );
        assert!(vector_set_urls(&json!({})).is_err());
    }
}
