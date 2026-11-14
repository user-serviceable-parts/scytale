//! Helpers shared by the drivers: field access, hex, the vendored
//! files, and the error type.

use scytale::Random;
use serde_json::{Map, Value};
use std::fmt;
use std::fs;
use std::path::PathBuf;

/// Why a driver, a check or a session could not go on. The message
/// names the suite, group and case where it can; the status is what
/// the binary exits with for it: 2 when two implementations of this
/// processor disagree, 3 for anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub message: String,
    pub status: i32,
    /// The HTTP status the server answered with, where one did.
    pub http_status: Option<u16>,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error {
            message: message.into(),
            status: 3,
            http_status: None,
        }
    }

    /// Two implementations answered one case differently.
    pub fn disagreement(message: impl Into<String>) -> Self {
        Error {
            message: message.into(),
            status: 2,
            http_status: None,
        }
    }

    /// A reply the server refused with `status`.
    pub fn http(status: u16, message: impl Into<String>) -> Self {
        Error {
            message: message.into(),
            status: 3,
            http_status: Some(status),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<scytale::Error> for Error {
    fn from(e: scytale::Error) -> Self {
        Error::new(format!("{e:?}"))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::new(format!("JSON: {e}"))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::new(format!("I/O: {e}"))
    }
}

/// A `Random` over a trait object, so a driver can hand the session's
/// generator to the library's generic calls.
pub struct Rng<'a>(pub &'a mut dyn Random);

impl Random for Rng<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), scytale::Error> {
        self.0.fill(out)
    }
}

/// The field `name` of `obj`, or an error naming it.
pub fn field<'a>(obj: &'a Value, name: &str) -> Result<&'a Value, Error> {
    match obj.get(name) {
        Some(v) if !v.is_null() => Ok(v),
        _ => Err(Error::new(format!("missing field {name}"))),
    }
}

/// The hex field `name` of `obj` decoded.
pub fn hex(obj: &Value, name: &str) -> Result<Vec<u8>, Error> {
    decode_hex(text(obj, name)?)
        .ok_or_else(|| Error::new(format!("field {name} is not hex")))
}

/// The hex field `name` of `obj` decoded, or `None` if absent.
pub fn opt_hex(obj: &Value, name: &str) -> Result<Option<Vec<u8>>, Error> {
    match obj.get(name) {
        Some(Value::String(s)) => decode_hex(s)
            .map(Some)
            .ok_or_else(|| Error::new(format!("field {name} is not hex"))),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(Error::new(format!("field {name} is not a string"))),
    }
}

/// The string field `name` of `obj`.
pub fn text<'a>(obj: &'a Value, name: &str) -> Result<&'a str, Error> {
    field(obj, name)?
        .as_str()
        .ok_or_else(|| Error::new(format!("field {name} is not a string")))
}

/// The string field `name` of `obj`, or `None` if absent.
pub fn opt_text<'a>(obj: &'a Value, name: &str) -> Option<&'a str> {
    obj.get(name).and_then(Value::as_str)
}

/// The integer field `name` of `obj`.
pub fn int(obj: &Value, name: &str) -> Result<u64, Error> {
    field(obj, name)?
        .as_u64()
        .ok_or_else(|| Error::new(format!("field {name} is not an integer")))
}

/// The integer field `name` of `obj`, or `None` if absent.
pub fn opt_int(obj: &Value, name: &str) -> Option<u64> {
    obj.get(name).and_then(Value::as_u64)
}

/// The boolean field `name` of `obj`.
pub fn flag(obj: &Value, name: &str) -> Result<bool, Error> {
    field(obj, name)?
        .as_bool()
        .ok_or_else(|| Error::new(format!("field {name} is not a boolean")))
}

/// The array field `name` of `obj`.
pub fn list<'a>(obj: &'a Value, name: &str) -> Result<&'a [Value], Error> {
    field(obj, name)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| Error::new(format!("field {name} is not an array")))
}

/// The object `v` as a map, or an error.
pub fn object(v: &Value) -> Result<&Map<String, Value>, Error> {
    v.as_object().ok_or_else(|| Error::new("not an object"))
}

/// Decodes a hex string; `None` on an odd length or a bad digit.
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Encodes bytes as the server does: upper-case hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// `bytes` as a JSON hex string.
pub fn hex_value(bytes: &[u8]) -> Value {
    Value::String(to_hex(bytes))
}

/// An error naming the test type a driver does not handle.
pub fn unknown_test_type(group: &Value) -> Error {
    Error::new(format!(
        "tgId {}: unknown testType {:?}",
        group["tgId"], group["testType"]
    ))
}

/// Set to `required` by a run that knows it has the vectors. A suite
/// that skips passes, so a checkout whose vectors cannot be found
/// looks exactly like one that was tested against them.
const REQUIRED: &str = "SCYTALE_VECTORS";

/// The vendored file `vectors/<name>` parsed, or `None` if the
/// vectors are not in this copy.
///
/// # Panics
///
/// If the file is missing and `SCYTALE_VECTORS` is `required`.
pub fn load(name: &str) -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join(name);
    match fs::read_to_string(&path) {
        Ok(text) => Some(serde_json::from_str(&text).expect("valid JSON")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            assert!(
                std::env::var(REQUIRED).as_deref() != Ok("required"),
                "{}: not found, and {REQUIRED} requires it",
                path.display()
            );
            eprintln!("{name}: not vendored in this copy; skipping");
            None
        }
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        assert_eq!(decode_hex("00ff1A"), Some(vec![0, 255, 26]));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(to_hex(&[0, 255, 26]), "00FF1A");
    }

    #[test]
    fn fields_are_named_in_errors() {
        let v = serde_json::json!({"a": "0A", "n": 3, "b": true});
        assert_eq!(hex(&v, "a").unwrap(), vec![10]);
        assert_eq!(int(&v, "n").unwrap(), 3);
        assert!(flag(&v, "b").unwrap());
        assert_eq!(hex(&v, "x").unwrap_err().message, "missing field x");
        assert_eq!(
            int(&v, "a").unwrap_err().message,
            "field a is not an integer"
        );
        assert_eq!(opt_hex(&v, "x").unwrap(), None);
    }
}

/// An entropy source that always gives the same bytes, so a
/// generator over it is reproducible: the drivers' randomness must
/// not vary between the implementations a run compares.
#[derive(Default)]
pub struct FixedEntropy(u8);

impl scytale::random::Entropy for FixedEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), scytale::Error> {
        for b in out {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// The key of `C` from `bytes`, or an error if it is another width.
pub fn key_of<C: scytale::KeyType>(bytes: &[u8]) -> Result<C::Key, Error> {
    let mut key = C::zero_key();
    if key.as_ref().len() != bytes.len() {
        return Err(Error::new(format!("key of {} bytes", bytes.len())));
    }
    key.as_mut().copy_from_slice(bytes);
    Ok(key)
}

/// An entropy source with nothing to give, for a generator whose
/// every seeding the vectors supply: it refuses with
/// [`ReseedRequired`](scytale::Error::ReseedRequired), so a reseed
/// the driver did not make explicitly cannot slip in.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoEntropy;

impl scytale::random::Entropy for NoEntropy {
    fn fill(&mut self, _out: &mut [u8]) -> Result<(), scytale::Error> {
        Err(scytale::Error::ReseedRequired)
    }
}
