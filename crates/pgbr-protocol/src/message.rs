//! Typed request / response shapes for the pgBackRest local/remote protocol.
//!
//! See the crate-level documentation for the wire format. The types here
//! preserve `param` and `out` payloads as raw [`serde_json::Value`] so each
//! command implementation can decode its own argument and result shapes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One protocol message. Either a request from the caller or a response
/// from the callee.
///
/// `Message` is a tagged enum on the Rust side but maps to two distinct
/// JSON shapes on the wire — distinguished by which of `cmd` or `out` /
/// `err` is present in the object.
// Both variants carry strings; size difference between Request and Response
// is small relative to the heap-owned data, so we do not box.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A request from caller to callee.
    Request(Request),
    /// A response from callee back to caller.
    Response(Response),
}

/// `{"cmd": "<command>", "param": [...]}`. The `param` array is preserved
/// verbatim as `Vec<Value>` so each command can decode its own arg shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Name of the command being invoked (`noOp`, `archiveGet`, ...).
    pub cmd: String,
    /// Positional command arguments. Empty when the command takes none.
    #[serde(default)]
    pub param: Vec<Value>,
}

/// Either a success or an error response from a callee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    /// A successful response carrying an optional `out` payload.
    Err(ErrResponse),
    /// An error response with code, message, and optional stack trace.
    Ok(OkResponse),
}

/// Success response: `{"out": <value>}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkResponse {
    /// Result value of the call. Absent when the command produced no
    /// payload, in which case the wire form is simply `{}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out: Option<Value>,
}

/// Error response: `{"err": <code>, "out": "<message>", "errStack": "<stack>"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrResponse {
    /// Numeric error code (matches `pgbr_error::ErrorType` codes).
    pub err: u32,
    /// Human-readable error message. The wire field is `out` for
    /// backward compatibility with the C protocol.
    #[serde(default, rename = "out")]
    pub message: String,
    /// Optional stack trace (debug builds).
    #[serde(default, rename = "errStack", skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
}

impl Message {
    /// Serialize to the JSON wire form expected by the C side.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails (e.g. a `Value`
    /// containing a non-finite float).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Request(r) => serde_json::to_string(r),
            Self::Response(r) => serde_json::to_string(r),
        }
    }

    /// Try to parse a JSON line as a [`Request`] first, then as a
    /// [`Response`]. Returns the matching variant.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if `json` matches neither shape or
    /// is not valid JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        // Try Request first (has the "cmd" key); fall back to Response.
        if let Ok(req) = serde_json::from_str::<Request>(json) {
            return Ok(Self::Request(req));
        }
        let resp: Response = serde_json::from_str(json)?;
        Ok(Self::Response(resp))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_serializes_with_cmd_and_param() {
        let req = Request {
            cmd: "archiveGet".to_owned(),
            param: vec![json!("000000010000000000000001")],
        };
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, r#"{"cmd":"archiveGet","param":["000000010000000000000001"]}"#);
    }

    #[test]
    fn ok_response_with_no_out_serializes_to_empty_object() {
        let r = Response::Ok(OkResponse { out: None });
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, "{}");
    }

    #[test]
    fn err_response_serializes_all_fields() {
        let r = Response::Err(ErrResponse {
            err: 25,
            message: "boom".to_owned(),
            stack: Some("trace".to_owned()),
        });
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"err":25,"out":"boom","errStack":"trace"}"#);
    }

    #[test]
    fn message_from_json_picks_request_when_cmd_present() {
        let m = Message::from_json(r#"{"cmd":"noOp"}"#).unwrap();
        assert_eq!(
            m,
            Message::Request(Request {
                cmd: "noOp".to_owned(),
                param: Vec::new()
            })
        );
    }

    #[test]
    fn message_from_json_picks_response_when_no_cmd() {
        let m = Message::from_json(r#"{"out":42}"#).unwrap();
        assert_eq!(m, Message::Response(Response::Ok(OkResponse { out: Some(json!(42)) })));
    }
}
