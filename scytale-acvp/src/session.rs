//! A test session on disk: one directory per session under the
//! sessions root, holding what the server sent and what was sent
//! back, so that the answering step can run separately, on another
//! machine if need be, and a failed set can be looked at afterwards.
//!
//! ```text
//! <root>/<session id>/
//!     session.json          url, token, vector set urls, isSample
//!     <vsId>.prompt.json    the vector set as downloaded
//!     <vsId>.expected.json  the server's answers, sample sessions
//!     <vsId>.response.json  the answers, written by the library
//!     <vsId>.result.json    the server's verdict
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::Result;

pub struct Session {
    pub dir: PathBuf,
    /// The server's path to the session, `/acvp/v1/testSessions/N`.
    pub url: String,
    /// The JWT the server issued for this session.
    pub token: String,
    pub sample: bool,
    /// The server's paths to the vector sets.
    pub vector_sets: Vec<String>,
}

/// The last segment of a server path: the session or vector set id.
pub fn id_of(url: &str) -> &str {
    url.trim_end_matches('/').rsplit('/').next().unwrap_or(url)
}

impl Session {
    /// A session from the server's answer to a registration, its
    /// directory created and `session.json` written.
    pub fn create(root: &Path, created: &Value) -> Result<Session> {
        let text = |name: &str| -> Result<String> {
            created[name]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("no {name} in the session").into())
        };
        let url = text("url")?;
        let vector_sets = created["vectorSetUrls"]
            .as_array()
            .ok_or("no vectorSetUrls in the session")?
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or("a vectorSetUrl is not a string")?;
        let session = Session {
            dir: root.join(id_of(&url)),
            url,
            token: text("accessToken")?,
            sample: created["isSample"].as_bool().unwrap_or(false),
            vector_sets,
        };
        fs::create_dir_all(&session.dir)?;
        session.save()?;
        Ok(session)
    }

    /// The session `id` under `root`.
    pub fn open(root: &Path, id: &str) -> Result<Session> {
        let dir = root.join(id);
        let saved = read_json(&dir.join("session.json"))?;
        let text = |name: &str| -> Result<String> {
            saved[name]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("no {name} in session.json").into())
        };
        Ok(Session {
            url: text("url")?,
            token: text("accessToken")?,
            sample: saved["isSample"].as_bool().unwrap_or(false),
            vector_sets: saved["vectorSetUrls"]
                .as_array()
                .ok_or("no vectorSetUrls in session.json")?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            dir,
        })
    }

    /// Writes `session.json`. It holds the token, so it is readable
    /// by its owner only.
    pub fn save(&self) -> Result<()> {
        let value = json!({
            "url": self.url,
            "accessToken": self.token,
            "isSample": self.sample,
            "vectorSetUrls": self.vector_sets,
        });
        write_private(&self.dir.join("session.json"), &value)
    }

    pub fn id(&self) -> &str {
        id_of(&self.url)
    }

    /// The file for `kind` of the vector set at `url`: `prompt`,
    /// `expected`, `response` or `result`.
    pub fn file(&self, url: &str, kind: &str) -> PathBuf {
        self.dir.join(format!("{}.{kind}.json", id_of(url)))
    }
}

pub fn read_json(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("{}: {e}", path.display()).into())
}

pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(value)?;
    fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(())
}

/// [`write_json`] with the file readable by its owner only.
fn write_private(path: &Path, value: &Value) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::to_writer_pretty(file, value)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        let unique = format!(
            "scytale-acvp-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        );
        let dir = std::env::temp_dir().join(unique);
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn created() -> Value {
        json!({
            "url": "/acvp/v1/testSessions/42",
            "accessToken": "jwt",
            "isSample": true,
            "vectorSetUrls": [
                "/acvp/v1/testSessions/42/vectorSets/7",
                "/acvp/v1/testSessions/42/vectorSets/8",
            ],
        })
    }

    #[test]
    fn ids_are_the_last_segment() {
        assert_eq!(id_of("/acvp/v1/testSessions/42"), "42");
        assert_eq!(id_of("/acvp/v1/testSessions/42/vectorSets/7/"), "7");
    }

    #[test]
    fn round_trips_through_the_directory() {
        let root = root();
        let session = Session::create(&root, &created()).expect("create");
        assert_eq!(session.id(), "42");
        assert_eq!(session.dir, root.join("42"));
        let again = Session::open(&root, "42").expect("open");
        assert_eq!(again.url, session.url);
        assert_eq!(again.token, "jwt");
        assert!(again.sample);
        assert_eq!(again.vector_sets, session.vector_sets);
        assert_eq!(
            again.file(&again.vector_sets[1], "response"),
            root.join("42").join("8.response.json")
        );
        fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn missing_fields_are_errors() {
        let root = root();
        let mut created = created();
        created["accessToken"] = Value::Null;
        let err = match Session::create(&root, &created) {
            Ok(_) => panic!("created without a token"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("accessToken"), "{err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn session_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = root();
        let session = Session::create(&root, &created()).expect("create");
        let mode = fs::metadata(session.dir.join("session.json"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_dir_all(&root).expect("clean up");
    }
}
