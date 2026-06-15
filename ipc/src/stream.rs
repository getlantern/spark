//! Async length-delimited framing over a byte stream (feature `stream`).
//!
//! Thin async wrappers over the pure [`encode_frame`](crate::encode_frame)/
//! [`decode_frame`](crate::decode_frame) codec for byte-stream transports (unix socket,
//! named pipe). Kept behind the `stream` feature so message-oriented consumers never pull
//! `tokio`. Reads use `read_exact` and are **not** cancel-safe — drive them from a dedicated
//! read loop, not inside a `select!` branch.

use std::io;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::{decode_message, encode_frame, MAX_FRAME_LEN};
use crate::message::{
    ProtocolVersion, Request, RequestPayload, ResponsePayload, ServerMessage, PROTOCOL_VERSION,
};

/// Write `msg` as one length-delimited frame to `writer`.
pub async fn write_frame<W, M>(writer: &mut W, msg: &M) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
    M: Serialize,
{
    let frame = encode_frame(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    writer.write_all(&frame).await
}

/// Read one length-delimited frame from `reader`, returning the decoded message, or `None`
/// on a clean EOF at a frame boundary (the peer closed the connection). A truncated frame or
/// a body that exceeds [`MAX_FRAME_LEN`] is an error.
pub async fn read_frame<R, M>(reader: &mut R) -> io::Result<Option<M>>
where
    R: AsyncRead + Unpin + ?Sized,
    M: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        // EOF before any length byte = the peer closed cleanly between frames.
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame body {len} exceeds maximum {MAX_FRAME_LEN}"),
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    decode_message(&body)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// A control-plane client over a byte stream: does the [`PROTOCOL_VERSION`] handshake and
/// issues request/response calls, transparently skipping any interleaved [`Push`](crate::Push)
/// stream items. The caller supplies the connected stream (a `UnixStream` on desktop), so
/// this stays transport-generic and testable over a duplex.
pub struct Client<S> {
    stream: S,
    next_id: u64,
}

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap a connected stream. Call [`handshake`](Self::handshake) before any command.
    pub fn new(stream: S) -> Self {
        Self { stream, next_id: 0 }
    }

    /// Perform the `Hello` handshake, returning the negotiated protocol version. Errors if
    /// the service rejects the version.
    pub async fn handshake(&mut self) -> io::Result<ProtocolVersion> {
        match self
            .request(RequestPayload::Hello {
                client_version: PROTOCOL_VERSION,
            })
            .await?
        {
            ResponsePayload::Hello { negotiated, .. } => Ok(negotiated),
            ResponsePayload::Error { message, .. } => {
                Err(io::Error::new(io::ErrorKind::InvalidData, message))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected handshake reply: {other:?}"),
            )),
        }
    }

    /// Send one request and return its response payload, skipping any `Push` items that
    /// arrive in between.
    pub async fn request(&mut self, payload: RequestPayload) -> io::Result<ResponsePayload> {
        self.next_id += 1;
        let req_id = self.next_id;
        write_frame(&mut self.stream, &Request { req_id, payload }).await?;
        loop {
            match read_frame::<_, ServerMessage>(&mut self.stream).await? {
                Some(ServerMessage::Response(resp)) if resp.req_id == req_id => {
                    return Ok(resp.payload)
                }
                // Ignore stray responses (shouldn't happen) and unsolicited pushes.
                Some(_) => continue,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "service closed the connection",
                    ))
                }
            }
        }
    }

    /// Read the next server-initiated [`Push`](crate::Push), or `None` on a clean close.
    /// Useful after `Subscribe`. (Responses, if any, are skipped.)
    pub async fn next_push(&mut self) -> io::Result<Option<crate::Push>> {
        loop {
            match read_frame::<_, ServerMessage>(&mut self.stream).await? {
                Some(ServerMessage::Push(push)) => return Ok(Some(push)),
                Some(ServerMessage::Response(_)) => continue,
                None => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Request, RequestPayload};

    fn req(req_id: u64) -> Request {
        Request {
            req_id,
            payload: RequestPayload::GetStatus,
        }
    }

    #[tokio::test]
    async fn frames_round_trip_over_a_duplex() {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_frame(&mut a, &req(1)).await.unwrap();
        write_frame(&mut a, &req(2)).await.unwrap();
        assert_eq!(
            read_frame::<_, Request>(&mut b).await.unwrap(),
            Some(req(1))
        );
        assert_eq!(
            read_frame::<_, Request>(&mut b).await.unwrap(),
            Some(req(2))
        );
    }

    #[tokio::test]
    async fn clean_eof_returns_none() {
        let (a, mut b) = tokio::io::duplex(256);
        drop(a); // close the writer end
        assert_eq!(read_frame::<_, Request>(&mut b).await.unwrap(), None);
    }
}
