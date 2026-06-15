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
