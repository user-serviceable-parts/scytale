//! `scytale-acvp`: the library against NIST's ACVP demo server.
//!
//! A validation has three steps, and this tool does the two that
//! talk to the server. `register` says what the library can do,
//! opens a test session and downloads its vector sets into a
//! directory; the library's own test build answers them, since the
//! answering code is the test code (`cargo test --lib acvp::live`
//! in the scytale crate, see [`session`] for the files); and
//! `submit` sends the answers back and reports the verdict.
//! `scripts/acvp-live` runs all three.
//!
//! Credentials come from the environment: `ACVP_CLIENT_CERT` and
//! `ACVP_CLIENT_KEY` name the PEM files NIST issued, `ACVP_TOTP_SEED`
//! is the seed they sent, and `ACVP_SERVER` picks another server
//! than the demo one. None of them is ever printed, and neither is a
//! token.
//!
//! Exit status is 0 when every vector set passed, 1 when any did
//! not, and 2 when the run itself failed.

use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json::{Value, json};

mod client;
mod registration;
mod session;
mod totp;

use client::{Client, Credentials};
use session::Session;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

const DEMO: &str = "https://demo.acvts.nist.gov";

/// How often a session's results are asked for while the server is
/// still grading.
const POLL: Duration = Duration::from_secs(15);

#[derive(Parser)]
#[command(name = "scytale-acvp", about = "scytale against an ACVP server")]
struct Args {
    /// Where sessions are kept, one directory each.
    #[arg(long, global = true, default_value = "target/acvp")]
    sessions: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Lists the algorithms that can be registered.
    List,
    /// Registers, opens a session and downloads its vector sets;
    /// prints the session id.
    Register {
        /// Ask for a sample session, whose expected answers the
        /// server will hand over too.
        #[arg(long)]
        sample: bool,
        /// Ask for the large data tests, which hash gigabytes.
        #[arg(long)]
        large_data: bool,
        /// Register these algorithms only, by the names `list`
        /// prints; an algorithm name alone takes all its modes.
        #[arg(long = "algorithm", value_name = "NAME")]
        algorithms: Vec<String>,
    },
    /// Uploads a session's answers and waits for the verdict.
    Submit { session: String },
    /// Reports a session's verdict without uploading anything.
    Status { session: String },
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("scytale-acvp: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Args) -> Result<ExitCode> {
    match args.command {
        Command::List => {
            let options = registration::Options { large_data: false };
            for c in registration::capabilities(options) {
                println!("{}", registration::name(&c));
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Register {
            sample,
            large_data,
            algorithms,
        } => {
            let options = registration::Options { large_data };
            let capabilities = registration::select(&algorithms, options)?;
            let client = connect()?;
            register(&client, &args.sessions, sample, capabilities)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Submit { session } => {
            let session = Session::open(&args.sessions, &session)?;
            let client = connect()?;
            client.use_token(&session.token);
            submit(&client, &session)?;
            report(&client, &session, true)
        }
        Command::Status { session } => {
            let session = Session::open(&args.sessions, &session)?;
            let client = connect()?;
            client.use_token(&session.token);
            report(&client, &session, false)
        }
    }
}

fn connect() -> Result<Client> {
    let server = std::env::var("ACVP_SERVER").unwrap_or(DEMO.to_owned());
    Client::connect(&server, Credentials::from_env()?)
}

/// Opens the session and downloads every vector set, and the
/// expected answers of a sample session. The id goes to stdout, on
/// its own, for a script to take.
fn register(
    client: &Client,
    root: &std::path::Path,
    sample: bool,
    capabilities: Vec<Value>,
) -> Result<()> {
    let count = capabilities.len();
    let registration = json!({
        "isSample": sample,
        "algorithms": capabilities,
    });
    let created = client.post(&client.url("/testSessions"), &registration)?;
    let session = Session::create(root, &created)?;
    client.use_token(&session.token);
    eprintln!(
        "session {}: {count} algorithms, {} vector sets, in {}",
        session.id(),
        session.vector_sets.len(),
        session.dir.display()
    );
    for url in &session.vector_sets {
        let prompt = client.vector_set(url)?;
        session::write_json(&session.file(url, "prompt"), &prompt)?;
        if sample {
            let expected = client.get(&format!("{url}/expected"))?;
            session::write_json(&session.file(url, "expected"), &expected)?;
        }
        eprintln!("  {} {}", session::id_of(url), describe(&prompt));
    }
    // The token may have been renewed while downloading.
    if let Some(token) = client.token() {
        let mut session = session;
        session.token = token;
        session.save()?;
        println!("{}", session.id());
    }
    Ok(())
}

/// `algorithm/mode revision` of a vector set.
fn describe(set: &Value) -> String {
    let text = |name: &str| set[name].as_str().unwrap_or("");
    let mut out = text("algorithm").to_owned();
    if !text("mode").is_empty() {
        out = format!("{out}/{}", text("mode"));
    }
    if !text("revision").is_empty() {
        out = format!("{out} {}", text("revision"));
    }
    out
}

/// Uploads every vector set's answers. A missing answer file is an
/// error before anything is sent, so a half-answered session is not
/// half-graded.
fn submit(client: &Client, session: &Session) -> Result<()> {
    let mut answers = Vec::new();
    for url in &session.vector_sets {
        let path = session.file(url, "response");
        let value = session::read_json(&path).map_err(|e| {
            format!("{e}; has the answering step run for this session?")
        })?;
        answers.push((url, value));
    }
    for (url, value) in &answers {
        client.submit(url, value)?;
        eprintln!("  {} submitted", session::id_of(url));
    }
    Ok(())
}

/// Reads every vector set's verdict, waiting for the server to
/// finish grading when `wait`, writes each to its result file and
/// prints the failures. Exit status 1 if any vector set did not
/// pass.
fn report(client: &Client, session: &Session, wait: bool) -> Result<ExitCode> {
    let mut passed = true;
    let mut pending: Vec<&String> = session.vector_sets.iter().collect();
    loop {
        let mut still = Vec::new();
        for url in pending {
            let reply = client.get(&format!("{url}/results"))?;
            // The specification nests the object under "results";
            // take either.
            let results = match reply.get("results") {
                Some(inner) if inner.is_object() => inner.clone(),
                _ => reply,
            };
            let disposition = results["disposition"].as_str().unwrap_or("?");
            if wait && matches!(disposition, "unreceived" | "incomplete") {
                still.push(url);
                continue;
            }
            session::write_json(&session.file(url, "result"), &results)?;
            println!("{} {disposition}", session::id_of(url));
            if disposition != "passed" {
                passed = false;
                print_failures(&results);
            }
        }
        if still.is_empty() {
            break;
        }
        eprintln!("{} vector sets still grading", still.len());
        thread::sleep(POLL);
        pending = still;
    }
    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn print_failures(results: &Value) {
    let Some(tests) = results["tests"].as_array() else {
        return;
    };
    for t in tests {
        if t["result"] == "passed" {
            continue;
        }
        let reason = t["reason"].as_str().unwrap_or("");
        println!("    tcId {} {}: {reason}", t["tcId"], t["result"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_a_vector_set() {
        let set = json!({
            "algorithm": "ECDSA", "mode": "sigGen", "revision": "FIPS186-5"
        });
        assert_eq!(describe(&set), "ECDSA/sigGen FIPS186-5");
        let set = json!({"algorithm": "SHA2-256", "revision": "1.0"});
        assert_eq!(describe(&set), "SHA2-256 1.0");
    }
}
