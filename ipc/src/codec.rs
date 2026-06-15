//! Encoding for the control-plane protocol, in two layers (see the
//! `ipc-service-split-design-m7` decision):
//!
//! 1. **Message codec** ([`encode_message`]/[`decode_message`]) — `serde` + `postcard`,
//!    turning one message into bytes. This is the portable primitive used by
//!    **message-oriented** transports that already have boundaries (Apple NE
//!    `sendProviderMessage`, Android in-process).
//! 2. **Length-delimited framing** ([`encode_frame`]/[`decode_frame`]) — a `[u32 LE
//!    body-len][postcard body]` wrapper layered on top, used by **stream** transports
//!    (unix socket, named pipe) where messages have no boundaries. Framing is kept separate
//!    so the message-oriented platforms never need it.
//!
//! [`decode_frame`] reports a truncated prefix as [`IpcError::Incomplete`] (read more and
//! retry) — the same convention as the data-path codecs in `spark-core`.

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Maximum accepted frame body length. Control messages are tiny; the cap bounds the
/// allocation a hostile or buggy peer can induce by forging a huge length prefix. The IPC
/// peer is a privilege boundary, so this guard is load-bearing.
pub const MAX_FRAME_LEN: usize = 1 << 20; // 1 MiB

/// Errors encoding or decoding a control-plane message or frame.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// `postcard` failed to serialize or deserialize a message body.
    #[error("postcard codec error")]
    Codec(#[from] postcard::Error),
    /// A frame buffer holds only a truncated prefix; read more bytes and retry.
    #[error("incomplete frame")]
    Incomplete,
    /// A frame's declared body length exceeds [`MAX_FRAME_LEN`].
    #[error("frame body length {len} exceeds maximum {max}")]
    FrameTooLarge {
        /// The declared body length.
        len: usize,
        /// The accepted maximum ([`MAX_FRAME_LEN`]).
        max: usize,
    },
}

/// Serialize a message body to postcard bytes (no framing).
pub fn encode_message<M: Serialize>(msg: &M) -> Result<Vec<u8>, IpcError> {
    Ok(postcard::to_stdvec(msg)?)
}

/// Deserialize a message body from postcard bytes (the whole slice must be one message).
pub fn decode_message<M: DeserializeOwned>(bytes: &[u8]) -> Result<M, IpcError> {
    Ok(postcard::from_bytes(bytes)?)
}

/// Serialize a message as a length-delimited frame: `[u32 LE body-len][postcard body]`.
pub fn encode_frame<M: Serialize>(msg: &M) -> Result<Vec<u8>, IpcError> {
    let body = encode_message(msg)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(IpcError::FrameTooLarge {
            len: body.len(),
            max: MAX_FRAME_LEN,
        });
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Parse one length-delimited frame from the front of `buf`, returning the message and the
/// number of bytes consumed (so a caller draining a stream buffer knows where the next frame
/// begins). Returns [`IpcError::Incomplete`] when `buf` is a truncated prefix.
pub fn decode_frame<M: DeserializeOwned>(buf: &[u8]) -> Result<(M, usize), IpcError> {
    let len_bytes: [u8; 4] = buf
        .get(..4)
        .ok_or(IpcError::Incomplete)?
        .try_into()
        .map_err(|_| IpcError::Incomplete)?;
    let body_len = u32::from_le_bytes(len_bytes) as usize;
    if body_len > MAX_FRAME_LEN {
        return Err(IpcError::FrameTooLarge {
            len: body_len,
            max: MAX_FRAME_LEN,
        });
    }
    let end = 4 + body_len;
    let body = buf.get(4..end).ok_or(IpcError::Incomplete)?;
    let msg = decode_message(body)?;
    Ok((msg, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::*;

    fn sample_request() -> Request {
        Request {
            req_id: 42,
            payload: RequestPayload::Subscribe {
                events: true,
                logs: false,
            },
        }
    }

    fn sample_response() -> Response {
        Response {
            req_id: 42,
            payload: ResponsePayload::Status(TunnelStatus {
                state: TunnelState::Connected,
                direct_fallback: false,
            }),
        }
    }

    #[test]
    fn message_round_trips() {
        let req = sample_request();
        let bytes = encode_message(&req).unwrap();
        assert_eq!(decode_message::<Request>(&bytes).unwrap(), req);

        let resp = sample_response();
        let bytes = encode_message(&resp).unwrap();
        assert_eq!(decode_message::<Response>(&bytes).unwrap(), resp);

        let push = Push::Event(TunnelEvent::FellOpenToDirect);
        let bytes = encode_message(&push).unwrap();
        assert_eq!(decode_message::<Push>(&bytes).unwrap(), push);
    }

    #[test]
    fn frame_round_trips_and_reports_consumed_length() {
        let req = sample_request();
        let mut frame = encode_frame(&req).unwrap();
        let frame_len = frame.len();
        // A second frame's bytes after the first prove `decode_frame` stops at the boundary.
        frame.extend_from_slice(b"TRAILER");

        let (decoded, consumed) = decode_frame::<Request>(&frame).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(consumed, frame_len);
        assert_eq!(&frame[consumed..], b"TRAILER");
    }

    #[test]
    fn postcard_is_compact() {
        // Sanity: the binary encoding is far smaller than the JSON would be.
        assert!(encode_message(&sample_request()).unwrap().len() < 8);
    }

    #[test]
    fn truncated_frame_is_incomplete() {
        let frame = encode_frame(&sample_request()).unwrap();
        for n in 0..frame.len() {
            assert!(
                matches!(
                    decode_frame::<Request>(&frame[..n]),
                    Err(IpcError::Incomplete)
                ),
                "prefix of length {n} should be Incomplete"
            );
        }
        // The full frame decodes.
        assert!(decode_frame::<Request>(&frame).is_ok());
    }

    #[test]
    fn oversized_length_prefix_is_rejected_without_allocating() {
        // A forged header claiming a body far larger than MAX_FRAME_LEN must be refused
        // before any attempt to read/allocate the body.
        let mut buf = ((MAX_FRAME_LEN + 1) as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(b"only a few bytes follow");
        assert!(matches!(
            decode_frame::<Request>(&buf),
            Err(IpcError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn complete_frame_with_garbage_body_is_a_codec_error_not_incomplete() {
        // Length says 3 bytes and 3 bytes are present, but they aren't a valid Request.
        let buf = [3u8, 0, 0, 0, 0xFF, 0xFF, 0xFF];
        assert!(matches!(
            decode_frame::<Request>(&buf),
            Err(IpcError::Codec(_))
        ));
    }
}
