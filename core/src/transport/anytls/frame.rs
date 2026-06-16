//! AnyTLS session-frame codec — the wire format *inside* the (TLS) session, after auth.
//!
//! An AnyTLS session is a stream of frames; multiplexed logical streams are distinguished by
//! `stream_id`:
//!
//! ```text
//! command(1) | streamId(4, big-endian) | data length(2, big-endian) | data
//! ```
//!
//! The 7-byte header is fixed; `data` is `data length` bytes (0..=65535). This mirrors the
//! address codec in [`super::super::tcp_tunnel::header`]: [`Frame::parse`] separates "need more
//! bytes" ([`FrameError::Incomplete`]) from "malformed", so a streaming reader can buffer-and-retry
//! on the former and fail fast on the latter.
//!
//! Reference: the AnyTLS protocol spec (`anytls/anytls-go`, `docs/protocol.md`). See
//! `docs/adr/0001-chrome-mimicry-tls-backend.md` and the `m11-transport-candidates-anytls-samizdat`
//! memory for why AnyTLS is the first M11 transport.

use bytes::{BufMut, Bytes, BytesMut};

/// The fixed frame-header length: `command(1) + streamId(4) + dataLength(2)`.
pub const HEADER_LEN: usize = 1 + 4 + 2;

/// The largest payload a single frame can carry — the 2-byte big-endian `data length`.
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

/// AnyTLS session commands. Values 0–6 are v1; 7–10 were added in v2. A v2 peer that has
/// negotiated down to v1 must not emit the v2 commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Padding bytes — the receiver reads `data length` bytes and discards them.
    Waste = 0,
    /// Open a logical stream (`stream_id`).
    Syn = 1,
    /// Stream data.
    Psh = 2,
    /// Close a stream (EOF).
    Fin = 3,
    /// Client → server settings (sent immediately on a new session): `key=value` lines.
    Settings = 4,
    /// Server → client text warning, after which both sides close.
    Alert = 5,
    /// Server → client: replace the client's padding scheme (the anti-blocklist lever).
    UpdatePaddingScheme = 6,
    /// (v2) Server → client: the outbound TCP is established, or carries an error string.
    SynAck = 7,
    /// (v2) Keepalive request.
    HeartRequest = 8,
    /// (v2) Keepalive response.
    HeartResponse = 9,
    /// (v2) Server → client settings.
    ServerSettings = 10,
}

impl Command {
    /// Map a wire byte to a [`Command`], or [`FrameError::UnknownCommand`] if unrecognized.
    pub fn from_u8(b: u8) -> Result<Self, FrameError> {
        Ok(match b {
            0 => Command::Waste,
            1 => Command::Syn,
            2 => Command::Psh,
            3 => Command::Fin,
            4 => Command::Settings,
            5 => Command::Alert,
            6 => Command::UpdatePaddingScheme,
            7 => Command::SynAck,
            8 => Command::HeartRequest,
            9 => Command::HeartResponse,
            10 => Command::ServerSettings,
            other => return Err(FrameError::UnknownCommand(other)),
        })
    }
}

/// One decoded AnyTLS session frame.
///
/// `payload` is a [`Bytes`] (cheap to slice/clone, ref-counted — never a `Vec` on the data path).
/// The simple [`Frame::parse`] used by tests copies the payload once; the streaming session reader
/// (a later chunk) will parse from a `BytesMut` with `split_to(..).freeze()` for zero-copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The command.
    pub command: Command,
    /// The logical stream this frame belongs to (0 for session-level commands like `Settings`).
    pub stream_id: u32,
    /// The frame body — at most [`MAX_PAYLOAD`] bytes.
    pub payload: Bytes,
}

impl Frame {
    /// Build a frame, rejecting a payload that does not fit the 2-byte length
    /// ([`FrameError::PayloadTooLarge`]). With the length checked here, [`encode`](Self::encode)
    /// is infallible.
    pub fn new(
        command: Command,
        stream_id: u32,
        payload: impl Into<Bytes>,
    ) -> Result<Self, FrameError> {
        let payload = payload.into();
        if payload.len() > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(payload.len()));
        }
        Ok(Frame {
            command,
            stream_id,
            payload,
        })
    }

    /// A payload-less control frame (e.g. `Syn`, `Fin`, `HeartRequest`).
    pub fn control(command: Command, stream_id: u32) -> Self {
        Frame {
            command,
            stream_id,
            payload: Bytes::new(),
        }
    }

    /// The number of bytes [`encode`](Self::encode) will append.
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }

    /// Append this frame's wire encoding to `dst`. Infallible: the payload-length bound is
    /// enforced by [`Frame::new`].
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(self.encoded_len());
        dst.put_u8(self.command as u8);
        dst.put_u32(self.stream_id);
        dst.put_u16(self.payload.len() as u16); // ≤ MAX_PAYLOAD guaranteed by `new`
        dst.put_slice(&self.payload);
    }

    /// Parse one frame from the front of `src`, returning it and the number of bytes consumed.
    ///
    /// Returns [`FrameError::Incomplete`] when `src` holds only a truncated prefix (header or
    /// body) — read more and retry. Other errors are permanent.
    pub fn parse(src: &[u8]) -> Result<(Frame, usize), FrameError> {
        if src.len() < HEADER_LEN {
            return Err(FrameError::Incomplete);
        }
        let command = Command::from_u8(src[0])?;
        let stream_id = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
        let data_len = u16::from_be_bytes([src[5], src[6]]) as usize;
        let total = HEADER_LEN + data_len;
        if src.len() < total {
            return Err(FrameError::Incomplete);
        }
        let payload = Bytes::copy_from_slice(&src[HEADER_LEN..total]);
        Ok((
            Frame {
                command,
                stream_id,
                payload,
            },
            total,
        ))
    }
}

/// Errors from encoding or parsing an AnyTLS session frame.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    /// `src` holds only a truncated prefix of a frame; read more and retry.
    #[error("incomplete frame")]
    Incomplete,
    /// The command byte is not one of the known commands.
    #[error("unknown command byte {0}")]
    UnknownCommand(u8),
    /// A payload larger than the 2-byte length field can express (got {0} bytes).
    #[error("payload too large: {0} bytes (max 65535)")]
    PayloadTooLarge(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode then parse yields the original frame and consumes exactly the encoded length,
    /// leaving any trailing bytes untouched.
    fn round_trip(frame: Frame) {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert_eq!(
            buf.len(),
            frame.encoded_len(),
            "encoded_len disagrees with encode"
        );

        // Append trailing bytes to prove parse reports the right consumed length and stops at the
        // frame boundary (a session stream packs frames back-to-back).
        let trailer = b"NEXTFRAME";
        buf.extend_from_slice(trailer);

        let (parsed, consumed) = Frame::parse(&buf).expect("parse");
        assert_eq!(parsed, frame);
        assert_eq!(consumed, frame.encoded_len());
        assert_eq!(&buf[consumed..], trailer, "frame boundary");
    }

    #[test]
    fn round_trips_control_frame() {
        round_trip(Frame::control(Command::Syn, 1));
    }

    #[test]
    fn round_trips_data_frame() {
        round_trip(Frame::new(Command::Psh, 7, Bytes::from_static(b"hello world")).unwrap());
    }

    #[test]
    fn round_trips_settings_with_high_stream_id() {
        round_trip(
            Frame::new(
                Command::Settings,
                u32::MAX,
                Bytes::from_static(b"v=2\nclient=spark"),
            )
            .unwrap(),
        );
    }

    #[test]
    fn stream_id_and_len_are_big_endian() {
        let mut buf = BytesMut::new();
        Frame::new(
            Command::Psh,
            0x01020304,
            Bytes::from_static(&[0xAA; 0x0102]),
        )
        .unwrap()
        .encode(&mut buf);
        assert_eq!(
            &buf[1..5],
            &[0x01, 0x02, 0x03, 0x04],
            "stream_id big-endian"
        );
        assert_eq!(&buf[5..7], &[0x01, 0x02], "data length big-endian");
    }

    #[test]
    fn all_command_bytes_round_trip() {
        for b in 0u8..=10 {
            let cmd = Command::from_u8(b).expect("known command");
            assert_eq!(cmd as u8, b, "command byte round-trip");
        }
        assert_eq!(Command::from_u8(11), Err(FrameError::UnknownCommand(11)));
        assert_eq!(Command::from_u8(255), Err(FrameError::UnknownCommand(255)));
    }

    #[test]
    fn truncated_inputs_report_incomplete() {
        let mut buf = BytesMut::new();
        Frame::new(Command::Psh, 42, Bytes::from_static(b"some payload"))
            .unwrap()
            .encode(&mut buf);
        // Every strict prefix — header bytes and body bytes alike — is Incomplete, not malformed.
        for n in 0..buf.len() {
            assert_eq!(
                Frame::parse(&buf[..n]).err(),
                Some(FrameError::Incomplete),
                "prefix of len {n} should be Incomplete"
            );
        }
        // The full buffer parses.
        assert!(Frame::parse(&buf).is_ok());
    }

    #[test]
    fn rejects_unknown_command() {
        // command=11 (unknown), stream_id=0, len=0.
        let bytes = [11u8, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            Frame::parse(&bytes).err(),
            Some(FrameError::UnknownCommand(11))
        );
    }

    #[test]
    fn rejects_oversized_payload_at_construction() {
        let too_big = vec![0u8; MAX_PAYLOAD + 1];
        assert_eq!(
            Frame::new(Command::Psh, 1, too_big).err(),
            Some(FrameError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
        // Exactly MAX_PAYLOAD is allowed.
        assert!(Frame::new(Command::Psh, 1, vec![0u8; MAX_PAYLOAD]).is_ok());
    }

    #[test]
    fn empty_payload_frame_is_header_only() {
        let mut buf = BytesMut::new();
        Frame::control(Command::Fin, 3).encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN);
    }
}
