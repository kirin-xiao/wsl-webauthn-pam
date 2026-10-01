//! stdin/stdout framing glue (plan §3 process contract).
//!
//! Kept free of any platform calls so it is testable on Linux. `main` uses
//! these helpers for the one-request/one-response invariant; the exit-code
//! policy is applied by `main`.

use wsl_webauthn_protocol::{BridgeError, MAX_RESPONSE_BYTES, Response};
use wsl_webauthn_protocol::{Request, read_frame};

/// Why an input frame could not be turned into a [`Request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    /// Not a well-formed frame / not valid JSON / not a valid request object.
    /// → exit code 3.
    BadFrame,
    /// Valid JSON object with an `op` that is not `probe`/`enroll`/`assert`.
    /// → exit code 4.
    UnknownOp,
}

/// Read exactly one framed request from `r`, capped at
/// [`wsl_webauthn_protocol::MAX_REQUEST_BYTES`].
///
/// A framing error (`Eof`, `TooLarge`, `Io`) is [`InputError::BadFrame`]; a
/// malformed/unknown operation is classified via [`decode_request`].
pub fn read_request<R: std::io::Read>(r: &mut R) -> Result<Request, InputError> {
    let payload = read_frame(r, wsl_webauthn_protocol::MAX_REQUEST_BYTES)
        .map_err(|_| InputError::BadFrame)?;
    decode_request(&payload)
}

/// Classify and deserialize a request payload.
///
/// Distinguishes an *unknown operation* (exit 4) from a *malformed frame*
/// (exit 3), per the plan's exit-code contract.
pub fn decode_request(payload: &[u8]) -> Result<Request, InputError> {
    // First parse as JSON to inspect `op` without losing the malformed case.
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| InputError::BadFrame)?;
    match value.get("op") {
        Some(serde_json::Value::String(op)) => {
            if !matches!(op.as_str(), "probe" | "enroll" | "assert") {
                return Err(InputError::UnknownOp);
            }
        }
        _ => return Err(InputError::BadFrame),
    }
    serde_json::from_slice::<Request>(payload).map_err(|_| InputError::BadFrame)
}

/// Serialize a response to a framed payload, enforcing [`MAX_RESPONSE_BYTES`].
///
/// If a (future) response ever overflowed the cap, an `internal` error is
/// emitted instead so the peer always sees a well-formed, in-cap frame.
pub fn encode_response(resp: &Response) -> Vec<u8> {
    match serde_json::to_vec(resp) {
        Ok(payload) if payload.len() <= MAX_RESPONSE_BYTES => {
            wsl_webauthn_protocol::encode_frame(&payload)
        }
        _ => {
            let fallback = serde_json::to_vec(&Response::error(BridgeError::Internal))
                .unwrap_or_else(|_| b"{}".to_vec());
            wsl_webauthn_protocol::encode_frame(&fallback)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use wsl_webauthn_protocol::{MAX_REQUEST_BYTES, read_frame};

    fn framed(req: &Request) -> Vec<u8> {
        req.to_frame().unwrap()
    }

    #[test]
    fn read_request_round_trips_every_op() {
        for req in [
            Request::Probe { timeout_ms: 3000 },
            Request::Enroll {
                client_data_json: "AAAA".into(),
                user_id: "YWxpY2U".into(),
                user_name: "alice".into(),
                user_display_name: "alice (Linux sudo)".into(),
                algs: vec![-7, -257],
                timeout_ms: 55_000,
            },
            Request::Assert {
                client_data_json: "AAAA".into(),
                allow_credentials: vec!["YWJj".into()],
                timeout_ms: 55_000,
            },
        ] {
            let bytes = framed(&req);
            let mut cur = Cursor::new(bytes);
            assert_eq!(read_request(&mut cur).unwrap(), req);
        }
    }

    #[test]
    fn read_request_rejects_empty_and_truncated_frames() {
        let mut cur = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_request(&mut cur), Err(InputError::BadFrame));

        let mut cur = Cursor::new(vec![10, 0, 0, 0, b'{']);
        assert_eq!(read_request(&mut cur), Err(InputError::BadFrame));
    }

    #[test]
    fn read_request_rejects_oversized_frame() {
        // Declared length one past the cap; the payload is never read.
        let mut bytes = ((MAX_REQUEST_BYTES + 1) as u32).to_le_bytes().to_vec();
        bytes.extend(std::iter::repeat_n(0u8, 8));
        let mut cur = Cursor::new(bytes);
        assert_eq!(read_request(&mut cur), Err(InputError::BadFrame));
    }

    #[test]
    fn decode_request_classifies_unknown_op_vs_bad_frame() {
        assert_eq!(
            decode_request(br#"{"op":"frobnicate"}"#),
            Err(InputError::UnknownOp)
        );
        assert_eq!(decode_request(br#"{"op":123}"#), Err(InputError::BadFrame));
        assert_eq!(
            decode_request(br#"{"not_op":1}"#),
            Err(InputError::BadFrame)
        );
        assert_eq!(decode_request(b"not json"), Err(InputError::BadFrame));
        // Correct op but malformed body (missing field).
        assert_eq!(
            decode_request(br#"{"op":"probe"}"#),
            Err(InputError::BadFrame)
        );
        // Unknown extra field is rejected by `deny_unknown_fields`.
        assert_eq!(
            decode_request(br#"{"op":"probe","timeout_ms":1,"x":2}"#),
            Err(InputError::BadFrame)
        );
    }

    #[test]
    fn encode_response_is_framed_and_decodable() {
        let resp = Response::probe(true, 9);
        let framed = encode_response(&resp);
        let mut cur = Cursor::new(framed);
        let payload = read_frame(&mut cur, MAX_RESPONSE_BYTES).unwrap();
        assert_eq!(serde_json::from_slice::<Response>(&payload).unwrap(), resp);
    }

    // ---- golden JSON per op --------------------------------------------

    #[test]
    fn golden_request_wire_shapes() {
        let cases = [
            (
                Request::Probe { timeout_ms: 3000 },
                r#"{"op":"probe","timeout_ms":3000}"#,
            ),
            (
                Request::Enroll {
                    client_data_json: "AAAA".into(),
                    user_id: "YWxpY2U".into(),
                    user_name: "alice".into(),
                    user_display_name: "alice (Linux sudo)".into(),
                    algs: vec![-7, -257],
                    timeout_ms: 55_000,
                },
                r#"{"op":"enroll","client_data_json":"AAAA","user_id":"YWxpY2U","user_name":"alice","user_display_name":"alice (Linux sudo)","algs":[-7,-257],"timeout_ms":55000}"#,
            ),
            (
                Request::Assert {
                    client_data_json: "AAAA".into(),
                    allow_credentials: vec!["YWJjMTIz".into()],
                    timeout_ms: 55_000,
                },
                r#"{"op":"assert","client_data_json":"AAAA","allow_credentials":["YWJjMTIz"],"timeout_ms":55000}"#,
            ),
        ];
        for (req, wire) in cases {
            // Serialize to the exact wire bytes, then decode back.
            assert_eq!(serde_json::to_string(&req).unwrap(), wire);
            let framed = req.to_frame().unwrap();
            // Framed payload = 4-byte LE length + exactly the wire bytes.
            assert_eq!(&framed[4..], wire.as_bytes());
            assert_eq!(decode_request(wire.as_bytes()).unwrap(), req);
        }
    }

    #[test]
    fn golden_response_json_shapes() {
        let cases: [(Response, &str); 4] = [
            (
                Response::probe(true, 7),
                r#"{"op":"probe","ok":true,"uv_platform_available":true,"api_version":7}"#,
            ),
            (
                Response::enroll("packed", "AAAA", "YWJj"),
                r#"{"op":"enroll","ok":true,"format":"packed","attestation_object":"AAAA","credential_id":"YWJj"}"#,
            ),
            (
                Response::assertion("AAAA", "BBBB", "YWJj", Some("AAAA".into())),
                r#"{"op":"assert","ok":true,"authenticator_data":"AAAA","signature":"BBBB","credential_id":"YWJj","client_data_json_echo":"AAAA"}"#,
            ),
            (
                Response::error(BridgeError::UserCancelled),
                r#"{"op":"*","ok":false,"error":"user_cancelled"}"#,
            ),
        ];
        for (resp, wire) in cases {
            let framed = encode_response(&resp);
            let mut cur = Cursor::new(framed);
            let payload = read_frame(&mut cur, MAX_RESPONSE_BYTES).unwrap();
            assert_eq!(std::str::from_utf8(&payload).unwrap(), wire);
            assert_eq!(serde_json::from_slice::<Response>(&payload).unwrap(), resp);
        }
    }

    #[test]
    fn encode_response_over_cap_falls_back_to_internal_error() {
        // A 70 KiB base64 blob exceeds MAX_RESPONSE_BYTES (64 KiB).
        let huge = wsl_webauthn_protocol::b64u_encode(&vec![0u8; 70 * 1024]);
        let resp = Response::enroll("packed", huge, "AAAA");
        let framed = encode_response(&resp);
        let mut cur = Cursor::new(framed);
        let payload = read_frame(&mut cur, MAX_RESPONSE_BYTES).unwrap();
        assert_eq!(
            serde_json::from_slice::<Response>(&payload).unwrap(),
            Response::error(BridgeError::Internal)
        );
    }
}
