//! The protocol, draft-fussell-acvp-spec: login with the one-time
//! password for a JWT, renew it when the server says 401, wrap every
//! body in the version object, wait when a vector set is not ready,
//! and go through the large-submission endpoint when an answer is
//! bigger than the server takes directly.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use ureq::Agent;
use ureq::tls::{ClientCert, PemItem, TlsConfig};

use crate::Result;
use crate::totp::Totp;

/// The protocol version in every request and response.
const VERSION: &str = "1.0";

/// Where the protocol lives on the server.
const PREFIX: &str = "/acvp/v1";

/// The longest a single `retry` is honoured for. The server names
/// 30 seconds; a wild value is a server fault, not a reason to hang.
const MAX_RETRY: Duration = Duration::from_secs(120);

/// The NIST client certificate and key, PEM, and the TOTP seed.
pub struct Credentials {
    pub certificate: Vec<u8>,
    pub key: Vec<u8>,
    pub totp: Totp,
}

impl Credentials {
    /// From the environment: `ACVP_CLIENT_CERT` and `ACVP_CLIENT_KEY`
    /// name the PEM files, `ACVP_TOTP_SEED` is the seed itself.
    pub fn from_env() -> Result<Self> {
        let file = |name: &str| -> Result<Vec<u8>> {
            let path = env(name)?;
            fs::read(Path::new(&path))
                .map_err(|e| format!("{name}={path}: {e}").into())
        };
        Ok(Credentials {
            certificate: file("ACVP_CLIENT_CERT")?,
            key: file("ACVP_CLIENT_KEY")?,
            totp: Totp::from_base64(&env("ACVP_TOTP_SEED")?)?,
        })
    }

    /// The certificate chain and key as the TLS layer takes them.
    fn client_cert(&self) -> Result<ClientCert> {
        let mut chain = Vec::new();
        let mut key = None;
        let items = ureq::tls::parse_pem(&self.certificate)
            .chain(ureq::tls::parse_pem(&self.key));
        for item in items {
            match item.map_err(|e| format!("client credentials: {e}"))? {
                PemItem::Certificate(c) => chain.push(c),
                PemItem::PrivateKey(k) => key = Some(k),
                _ => {}
            }
        }
        if chain.is_empty() {
            return Err("ACVP_CLIENT_CERT holds no certificate".into());
        }
        let key = key.ok_or("ACVP_CLIENT_KEY holds no private key")?;
        Ok(ClientCert::new_with_certs(&chain, key))
    }
}

fn env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| format!("{name} is not set").into())
}

pub struct Client {
    agent: Agent,
    /// Scheme and host, `https://demo.acvts.nist.gov`.
    origin: String,
    totp: Totp,
    /// The JWT in use: the login's, then the session's.
    token: RefCell<Option<String>>,
    /// The size above which a submission goes through `/large`,
    /// when the server wants that.
    large_above: Cell<Option<usize>>,
}

impl Client {
    /// Connects to `origin` with `credentials` and logs in.
    pub fn connect(origin: &str, credentials: Credentials) -> Result<Self> {
        let tls = TlsConfig::builder()
            .client_cert(Some(credentials.client_cert()?))
            .build();
        let config = Agent::config_builder()
            .tls_config(tls)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(300)))
            .build();
        let agent = Agent::new_with_config(config);
        let client = Self::with_agent(agent, origin, credentials.totp);
        client.login()?;
        Ok(client)
    }

    fn with_agent(agent: Agent, origin: &str, totp: Totp) -> Self {
        Client {
            agent,
            origin: origin.trim_end_matches('/').to_owned(),
            totp,
            token: RefCell::new(None),
            large_above: Cell::new(None),
        }
    }

    /// Switches to `token`, a session's JWT. An expired one is
    /// renewed at the first 401, as the login's would be.
    pub fn use_token(&self, token: &str) {
        *self.token.borrow_mut() = Some(token.to_owned());
    }

    /// The JWT in use, for saving with a session.
    pub fn token(&self) -> Option<String> {
        self.token.borrow().clone()
    }

    /// Logs in, or renews the token in use, with a fresh password.
    fn login(&self) -> Result<()> {
        let mut body = json!({"password": self.totp.password()?});
        if let Some(token) = self.token.borrow().as_deref() {
            body["accessToken"] = json!(token);
        }
        let url = self.url("/login");
        let reply = self.exchange("POST", &url, Some(&body), None)?;
        let token = reply["accessToken"]
            .as_str()
            .ok_or("login returned no accessToken")?;
        self.use_token(token);
        let required = reply["largeEndpointRequired"].as_bool();
        let constraint = reply["sizeConstraint"].as_u64();
        self.large_above.set(match (required, constraint) {
            (Some(true), Some(n)) if n > 0 => Some(n as usize),
            _ => None,
        });
        Ok(())
    }

    /// `GET path`, renewing the token if it has expired.
    pub fn get(&self, path: &str) -> Result<Value> {
        self.call("GET", path, None)
    }

    /// `POST path` with `body`, renewing the token if it has expired.
    pub fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.call("POST", path, Some(body))
    }

    /// The vector set at `path`, waiting as long as the server says
    /// it is still being generated.
    pub fn vector_set(&self, path: &str) -> Result<Value> {
        loop {
            let reply = self.get(path)?;
            let Some(retry) = reply["retry"].as_u64() else {
                return Ok(reply);
            };
            let wait = Duration::from_secs(retry).min(MAX_RETRY);
            eprintln!("{path}: not ready, waiting {}s", wait.as_secs());
            thread::sleep(wait);
        }
    }

    /// Posts `answers` as the results of the vector set at `path`,
    /// through the large-submission endpoint when they are bigger
    /// than the server takes directly.
    pub fn submit(&self, path: &str, answers: &Value) -> Result<Value> {
        let size = serde_json::to_vec(&wrap(answers))?.len();
        match self.large_above.get() {
            Some(limit) if size > limit => {
                let request = json!({
                    "submissionSize": size,
                    "vectorSetUrl": path,
                });
                let ticket = self.post(&self.url("/large"), &request)?;
                let url = ticket["url"]
                    .as_str()
                    .ok_or("the large endpoint returned no url")?;
                let token = ticket["accessToken"].as_str();
                eprintln!("{path}: {size} bytes, via the large endpoint");
                Ok(self.exchange("POST", url, Some(answers), token)?)
            }
            _ => self.post(&format!("{path}/results"), answers),
        }
    }

    /// A path under the protocol prefix as a full URL.
    pub fn url(&self, path: &str) -> String {
        format!("{}{PREFIX}{path}", self.origin)
    }

    /// One request, renewed and repeated once on a 401.
    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = self.absolute(path);
        match self.exchange(method, &url, body, None) {
            Err(Error::Status(401, _)) => {
                eprintln!("token expired, logging in again");
                self.login()?;
                Ok(self.exchange(method, &url, body, None)?)
            }
            other => Ok(other?),
        }
    }

    /// `path` as the server gives it, `/acvp/v1/...`, made a URL;
    /// one that already is a URL is left alone.
    fn absolute(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_owned()
        } else {
            format!("{}{path}", self.origin)
        }
    }

    /// Sends one request with `body` wrapped in the version object,
    /// under `token` or else the token in use, and unwraps the
    /// reply.
    fn exchange(
        &self,
        method: &str,
        url: &str,
        body: Option<&Value>,
        token: Option<&str>,
    ) -> std::result::Result<Value, Error> {
        let held = self.token.borrow();
        let bearer = token.or(held.as_deref()).map(|t| format!("Bearer {t}"));
        let transport = |e: ureq::Error| Error::Transport(format!("{e}"));
        let sent = match (method, body) {
            ("GET", _) => {
                let mut request = self.agent.get(url);
                if let Some(bearer) = &bearer {
                    request = request.header("Authorization", bearer);
                }
                request.call()
            }
            (_, Some(body)) => {
                let mut request = self.agent.post(url);
                if let Some(bearer) = &bearer {
                    request = request.header("Authorization", bearer);
                }
                request.send_json(wrap(body))
            }
            _ => return Err(Error::Transport("a POST needs a body".into())),
        };
        drop(held);
        let mut response = sent.map_err(transport)?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            // Vector sets with signatures in them run to megabytes.
            .limit(1 << 30)
            .read_to_string()
            .map_err(transport)?;
        if !(200..300).contains(&status) {
            return Err(Error::Status(status, text));
        }
        let reply = serde_json::from_str(&text)
            .map_err(|e| Error::Transport(format!("not JSON: {e}")))?;
        unwrap(reply)
    }
}

/// `[{"acvVersion": "1.0"}, body]`, as every request is sent.
fn wrap(body: &Value) -> Value {
    json!([{"acvVersion": VERSION}, body])
}

/// The object after the version object, as every reply is received;
/// a reply that is a bare object is taken as it is.
fn unwrap(reply: Value) -> std::result::Result<Value, Error> {
    let malformed = |what: String| Error::Transport(what);
    match reply {
        Value::Array(mut parts) => {
            let version = parts.first().and_then(|v| v["acvVersion"].as_str());
            if version != Some(VERSION) {
                let what = format!("reply is not {VERSION}: {version:?}");
                return Err(malformed(what));
            }
            if parts.len() != 2 {
                let what = format!("reply has {} parts", parts.len());
                return Err(malformed(what));
            }
            Ok(parts.swap_remove(1))
        }
        object @ Value::Object(_) => Ok(object),
        other => Err(malformed(format!("reply is not an object: {other}"))),
    }
}

/// What a request can come back with.
#[derive(Debug)]
pub enum Error {
    /// An HTTP status outside 2xx, with the body.
    Status(u16, String),
    /// Could not reach the server, or read what it said.
    Transport(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Status(code, body) => write!(f, "HTTP {code}: {body}"),
            Error::Transport(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// What the stub saw of one request.
    struct Seen {
        method: String,
        path: String,
        bearer: Option<String>,
        body: Value,
    }

    /// A one-thread HTTP server that answers from a script, one
    /// (status, body) per request in order, and reports what it was
    /// sent. The body is sent as it is, so a script wraps it in the
    /// version object itself where the real server would.
    fn stub(script: Vec<(u16, Value)>) -> (String, mpsc::Receiver<Seen>) {
        stub_at(|_| script)
    }

    /// [`stub`] whose script may name the stub's own origin.
    fn stub_at(
        script: impl FnOnce(&str) -> Vec<(u16, Value)>,
    ) -> (String, mpsc::Receiver<Seen>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let origin = format!("http://{address}");
        let script = script(&origin);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for (status, reply) in script {
                let (stream, _) = listener.accept().expect("accept");
                let mut reader = BufReader::new(stream);
                let seen = read_request(&mut reader);
                tx.send(seen).expect("report");
                let reply = reply.to_string();
                let mut stream = reader.into_inner();
                write!(
                    stream,
                    "HTTP/1.1 {status} X\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{reply}",
                    reply.len(),
                )
                .expect("write");
                stream.flush().expect("flush");
            }
        });
        (origin, rx)
    }

    fn read_request(reader: &mut impl BufRead) -> Seen {
        let mut line = String::new();
        reader.read_line(&mut line).expect("request line");
        let mut words = line.split_whitespace();
        let method = words.next().expect("method").to_owned();
        let path = words.next().expect("path").to_owned();
        let mut length = 0;
        let mut bearer = None;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).expect("header");
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':').expect("header");
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = value.parse().expect("length"),
                "authorization" => {
                    bearer = value.strip_prefix("Bearer ").map(str::to_owned)
                }
                _ => {}
            }
        }
        let mut raw = vec![0u8; length];
        reader.read_exact(&mut raw).expect("body");
        let body = if raw.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&raw).expect("JSON body")
        };
        Seen {
            method,
            path,
            bearer,
            body,
        }
    }

    fn totp() -> Totp {
        Totp::from_base64("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
            .expect("seed")
    }

    fn client(origin: &str) -> Client {
        let config =
            Agent::config_builder().http_status_as_error(false).build();
        Client::with_agent(Agent::new_with_config(config), origin, totp())
    }

    fn login_reply(token: &str) -> Value {
        wrap(&json!({
            "accessToken": token,
            "largeEndpointRequired": false,
            "sizeConstraint": -1,
        }))
    }

    #[test]
    fn login_sends_a_password_and_keeps_the_token() {
        let (origin, seen) = stub(vec![(200, login_reply("first"))]);
        let client = client(&origin);
        client.login().expect("login");
        let request = seen.recv().expect("seen");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/acvp/v1/login");
        assert_eq!(request.bearer, None);
        assert_eq!(request.body[0], json!({"acvVersion": "1.0"}));
        let password = request.body[1]["password"].as_str().expect("pw");
        assert_eq!(password.len(), 8);
        assert!(request.body[1]["accessToken"].is_null());
        assert_eq!(client.token().as_deref(), Some("first"));
    }

    #[test]
    fn a_401_renews_the_token_and_repeats() {
        let (origin, seen) = stub(vec![
            (401, json!({"error": "expired"})),
            (200, login_reply("second")),
            (200, wrap(&json!({"vsId": 7}))),
        ]);
        let client = client(&origin);
        client.use_token("first");
        let reply = client.get("/acvp/v1/x").expect("get");
        assert_eq!(reply, json!({"vsId": 7}));
        let first = seen.recv().expect("seen");
        assert_eq!(first.bearer.as_deref(), Some("first"));
        let login = seen.recv().expect("seen");
        assert_eq!(login.path, "/acvp/v1/login");
        assert_eq!(login.body[1]["accessToken"], "first");
        let again = seen.recv().expect("seen");
        assert_eq!(again.path, "/acvp/v1/x");
        assert_eq!(again.bearer.as_deref(), Some("second"));
    }

    #[test]
    fn other_statuses_are_errors_with_the_body() {
        let (origin, _seen) = stub(vec![(400, json!({"error": "bad"}))]);
        let client = client(&origin);
        let err = client.get("/acvp/v1/x").expect_err("error");
        let text = err.to_string();
        assert!(text.contains("400") && text.contains("bad"), "{text}");
    }

    #[test]
    fn a_vector_set_is_fetched_again_after_retry() {
        let (origin, seen) = stub(vec![
            (200, wrap(&json!({"vsId": 7, "retry": 0}))),
            (200, wrap(&json!({"vsId": 7, "testGroups": []}))),
        ]);
        let client = client(&origin);
        let set = client.vector_set("/acvp/v1/ts/1/vectorSets/7").expect("vs");
        assert_eq!(set["testGroups"], json!([]));
        assert_eq!(seen.recv().expect("seen").method, "GET");
        assert_eq!(seen.recv().expect("seen").method, "GET");
    }

    #[test]
    fn a_small_submission_goes_to_results() {
        let (origin, seen) = stub(vec![
            (200, login_reply("t")),
            (200, wrap(&json!({"ok": true}))),
        ]);
        let client = client(&origin);
        client.login().expect("login");
        let answers = json!({"vsId": 7, "testGroups": []});
        client
            .submit("/acvp/v1/ts/1/vectorSets/7", &answers)
            .expect("ok");
        seen.recv().expect("login");
        let posted = seen.recv().expect("seen");
        assert_eq!(posted.path, "/acvp/v1/ts/1/vectorSets/7/results");
        assert_eq!(posted.body[1], answers);
        assert_eq!(posted.bearer.as_deref(), Some("t"));
    }

    #[test]
    fn a_large_submission_goes_through_the_large_endpoint() {
        let (origin, seen) = stub_at(|origin| {
            vec![
                (
                    200,
                    wrap(&json!({
                        "accessToken": "t",
                        "largeEndpointRequired": true,
                        "sizeConstraint": 10,
                    })),
                ),
                (
                    200,
                    wrap(&json!({
                        "url": format!("{origin}/large/QWERTY"),
                        "accessToken": "big",
                    })),
                ),
                (200, wrap(&json!({"ok": true}))),
            ]
        });
        let client = client(&origin);
        client.login().expect("login");
        let answers = json!({"vsId": 7, "testGroups": [{"tgId": 1}]});
        let path = "/acvp/v1/ts/1/vectorSets/7";
        client.submit(path, &answers).expect("ok");
        seen.recv().expect("login");
        let ticket = seen.recv().expect("seen");
        assert_eq!(ticket.path, "/acvp/v1/large");
        assert_eq!(ticket.body[1]["vectorSetUrl"], path);
        let size = ticket.body[1]["submissionSize"].as_u64().expect("size");
        assert!(size > 10);
        let posted = seen.recv().expect("seen");
        assert_eq!(posted.path, "/large/QWERTY");
        assert_eq!(posted.bearer.as_deref(), Some("big"));
        assert_eq!(posted.body[1], answers);
    }

    #[test]
    fn replies_must_carry_the_version() {
        assert!(unwrap(json!([{"acvVersion": "0.5"}, {}])).is_err());
        assert!(unwrap(json!([{"acvVersion": "1.0"}])).is_err());
        assert!(unwrap(json!("text")).is_err());
        assert_eq!(unwrap(json!({"a": 1})).expect("bare"), json!({"a": 1}));
        let reply = json!([{"acvVersion": "1.0"}, {"a": 1}]);
        assert_eq!(unwrap(reply).expect("wrapped"), json!({"a": 1}));
    }
}
