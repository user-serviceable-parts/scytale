//! The transport: one HTTPS agent with the client certificate the
//! server requires, the bearer token once logged in, and the JSON
//! envelope every ACVP message wears.

use crate::envelope;
use crate::support::Error;
use serde_json::Value;
use std::fs;
use std::time::Duration;
use ureq::tls::{ClientCert, PemItem, TlsConfig, TlsProvider, parse_pem};

/// The most a reply may hold: the largest vector sets are a few
/// megabytes, and the limit is against a runaway, not a budget.
const BODY_LIMIT: u64 = 1 << 30;

pub struct Http {
    agent: ureq::Agent,
    token: Option<String>,
}

impl Http {
    /// An agent presenting the certificate and key in the PEM files
    /// named, with the roots the webpki crate bundles.
    pub fn try_new(cert_file: &str, key_file: &str) -> Result<Self, Error> {
        let certs = fs::read(cert_file)
            .map_err(|e| Error::new(format!("{cert_file}: {e}")))?;
        let key = fs::read(key_file)
            .map_err(|e| Error::new(format!("{key_file}: {e}")))?;
        let mut chain = Vec::new();
        for item in parse_pem(&certs) {
            if let PemItem::Certificate(c) =
                item.map_err(|e| Error::new(format!("{cert_file}: {e}")))?
            {
                chain.push(c);
            }
        }
        if chain.is_empty() {
            return Err(Error::new(format!("{cert_file}: no certificate")));
        }
        let key = parse_pem(&key)
            .find_map(|item| match item {
                Ok(PemItem::PrivateKey(k)) => Some(Ok(k)),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .ok_or_else(|| Error::new(format!("{key_file}: no private key")))?
            .map_err(|e| Error::new(format!("{key_file}: {e}")))?;
        let tls = TlsConfig::builder()
            .client_cert(Some(ClientCert::new_with_certs(&chain, key)))
            .provider(TlsProvider::NativeTls)
            .build();
        let config = ureq::Agent::config_builder()
            .tls_config(tls)
            // Statuses are read here, so an error body can be shown.
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(300)))
            .user_agent("scytale-acvp")
            .build();
        Ok(Http {
            agent: config.new_agent(),
            token: None,
        })
    }

    /// Sends the bearer token from now on.
    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    /// The bearer token in use.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Stops sending a token, for the logins: a lapsed token sent in
    /// the header of a renewal is refused before the body is read.
    pub fn clear_token(&mut self) {
        self.token = None;
    }

    /// `GET url`, the reply unwrapped from its envelope.
    pub fn get(&self, url: &str) -> Result<Value, Error> {
        let mut request = self.agent.get(url);
        if let Some(token) = &self.token {
            request =
                request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request
            .call()
            .map_err(|e| Error::new(format!("GET {url}: {e}")))?;
        Self::unwrap(url, response)
    }

    /// `POST url` with `body` in the envelope, the reply unwrapped.
    pub fn post(&self, url: &str, body: &Value) -> Result<Value, Error> {
        let mut request = self.agent.post(url);
        if let Some(token) = &self.token {
            request =
                request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request
            .header("Content-Type", "application/json")
            .send(envelope::wrap(body).to_string().as_bytes())
            .map_err(|e| Error::new(format!("POST {url}: {e}")))?;
        Self::unwrap(url, response)
    }

    /// The payload of a reply: the second element of the envelope,
    /// or an error naming the status and quoting the body.
    fn unwrap(
        url: &str,
        mut response: ureq::http::Response<ureq::Body>,
    ) -> Result<Value, Error> {
        let status = response.status().as_u16();
        // A vector set can run past ureq's ten-megabyte default.
        let text = response
            .body_mut()
            .with_config()
            .limit(BODY_LIMIT)
            .read_to_string()
            .map_err(|e| Error::new(format!("{url}: reading reply: {e}")))?;
        if !(200..300).contains(&status) {
            let shown: String = text.chars().take(4000).collect();
            return Err(Error::http(
                status,
                format!("{url}: status {status}: {shown}"),
            ));
        }
        let doc: Value = serde_json::from_str(&text).map_err(|e| {
            Error::new(format!("{url}: reply is not JSON: {e}"))
        })?;
        envelope::unwrap(&doc)
            .ok_or_else(|| Error::new(format!("{url}: reply without envelope")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_files_are_named() {
        let e = Http::try_new("/nonexistent/c.pem", "/nonexistent/k.pem")
            .err()
            .unwrap();
        assert!(e.message.starts_with("/nonexistent/c.pem"));
    }
}
