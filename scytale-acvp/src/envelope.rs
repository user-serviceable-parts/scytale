//! The JSON envelope every ACVP message wears:
//! `[{"acvVersion": "1.0"}, {...}]`.

use serde_json::{Value, json};

/// The protocol version every message carries.
pub const ACV_VERSION: &str = "1.0";

/// `body` in the envelope.
pub fn wrap(body: &Value) -> Value {
    json!([{ "acvVersion": ACV_VERSION }, body])
}

/// The payload of an enveloped document.
pub fn unwrap(doc: &Value) -> Option<Value> {
    match doc {
        Value::Array(items) if items.len() == 2 => Some(items[1].clone()),
        // A vector set is handed out bare by some servers.
        Value::Object(_) => Some(doc.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_the_second_element() {
        let doc = json!([{ "acvVersion": "1.0" }, { "vsId": 7 }]);
        assert_eq!(unwrap(&doc), Some(json!({ "vsId": 7 })));
        assert_eq!(unwrap(&json!([1])), None);
        assert_eq!(unwrap(&wrap(&json!({ "a": 1 }))), Some(json!({ "a": 1 })));
    }
}
