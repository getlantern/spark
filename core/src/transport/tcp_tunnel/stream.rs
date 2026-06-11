//! The relay stream and the server-side header reader.
//!
//! [`TunnelStream`] is the value [`super::client::TunnelClient::dial`] returns: once the
//! address header has been sent, the connection is a transparent byte relay, so the
//! stream just delegates `AsyncRead`/`AsyncWrite` to the underlying connection.
//!
//! [`read_header`] is the read-side counterpart to [`Address::encode`] — the partial-read
//! buffering a relay/server uses to recover the target address from the head of a stream
//! before relaying the rest. It is exercised by the M3b integration test's in-test relay.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::header::{Address, HeaderError};

/// The largest a valid encoded address can be: ATYP + 1-byte length + 255-byte domain +
/// 2-byte port. Used only as a buffer capacity hint.
const MAX_HEADER_LEN: usize = 1 + 1 + u8::MAX as usize + 2;

/// A tunnel relay stream over an underlying connection `S`.
///
/// The address header is sent by [`TunnelClient::dial`](super::client::TunnelClient::dial)
/// before this wrapper is handed back, so reads and writes here are a transparent relay.
/// Keeping it a distinct type (rather than returning the raw connection) localizes any
/// future framing or TLS changes and gives the transport a named stream type for M4.
pub struct TunnelStream<S> {
    inner: S,
}

impl<S> TunnelStream<S> {
    /// Wrap an underlying connection whose address header has already been sent.
    pub(crate) fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TunnelStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TunnelStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Read and decode the address header from the front of `reader`, returning the target
/// [`Address`] and any bytes already read past the header (the start of the relayed
/// payload, which the caller must forward to the target first).
///
/// Buffers across reads: a truncated header ([`HeaderError::Incomplete`]) triggers another
/// read rather than an error. A malformed header is reported as
/// [`io::ErrorKind::InvalidData`]; EOF mid-header as [`io::ErrorKind::UnexpectedEof`].
pub async fn read_header<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<(Address, BytesMut)> {
    let mut buf = BytesMut::with_capacity(MAX_HEADER_LEN);
    let mut chunk = [0u8; 512];
    loop {
        match Address::parse(&buf) {
            Ok((addr, consumed)) => {
                let payload = buf.split_off(consumed);
                return Ok((addr, payload));
            }
            Err(HeaderError::Incomplete) => {
                let n = reader.read(&mut chunk).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed before the tunnel address header was complete",
                    ));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `AsyncRead` that yields at most one byte per poll, forcing `read_header` through
    /// its `Incomplete` retry path on every intermediate byte — a deterministic stand-in
    /// for a header dribbled across many TCP segments.
    struct OneBytePerRead {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for OneBytePerRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.pos < this.data.len() && buf.remaining() > 0 {
                buf.put_slice(&this.data[this.pos..this.pos + 1]);
                this.pos += 1;
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn reads_header_dribbled_one_byte_at_a_time() {
        let addr = Address::domain("example.com", 443).unwrap();
        let mut wire = BytesMut::new();
        addr.encode(&mut wire);
        wire.extend_from_slice(b"PAYLOAD"); // trailing payload past the header

        let mut reader = OneBytePerRead {
            data: wire.to_vec(),
            pos: 0,
        };
        // `read_header` stops the instant the header parses, so with one-byte reads it has
        // not yet touched the payload: leftover is empty and the payload stays in the reader.
        let (parsed, leftover) = read_header(&mut reader).await.unwrap();
        assert_eq!(parsed, addr);
        assert!(leftover.is_empty());
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(&rest, b"PAYLOAD");
    }

    #[tokio::test]
    async fn captures_payload_read_alongside_the_header() {
        let addr = Address::Ip("198.51.100.7:8080".parse().unwrap());
        let mut wire = BytesMut::new();
        addr.encode(&mut wire);
        wire.extend_from_slice(b"PAYLOAD");

        // `&[u8]` hands the whole buffer back in one read, so the bytes past the header are
        // returned as leftover for the caller to forward.
        let bytes = wire.to_vec();
        let mut reader: &[u8] = &bytes;
        let (parsed, leftover) = read_header(&mut reader).await.unwrap();
        assert_eq!(parsed, addr);
        assert_eq!(&leftover[..], b"PAYLOAD");
    }

    #[tokio::test]
    async fn eof_mid_header_is_unexpected_eof() {
        let addr = Address::Ip("192.0.2.1:80".parse().unwrap());
        let mut wire = BytesMut::new();
        addr.encode(&mut wire);
        wire.truncate(wire.len() - 1); // drop the last port byte

        let mut reader = OneBytePerRead {
            data: wire.to_vec(),
            pos: 0,
        };
        let err = read_header(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
