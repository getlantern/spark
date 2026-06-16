//! Async framed I/O over the (TLS) byte stream: read/write whole AnyTLS [`Frame`]s.
//!
//! [`FrameReader`] buffers socket reads and drains frames with the zero-copy
//! [`Frame::decode`]; [`FrameWriter`] encodes and writes one frame. These adapt chunk-1's pure
//! codec to a `tokio` `AsyncRead`/`AsyncWrite`, and are the only things the session
//! ([`super::session`]) needs from the underlying transport — so the session is generic over any
//! byte stream and is tested over an in-memory `duplex` before TLS is wired in.

use std::io;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::frame::Frame;

/// The read buffer's initial capacity — one comfortable TLS record's worth.
const READ_BUF_CAP: usize = 16 * 1024;

/// Reads whole [`Frame`]s from an [`AsyncRead`], buffering partial reads.
pub struct FrameReader<R> {
    inner: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Wrap a reader.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(READ_BUF_CAP),
        }
    }

    /// Read the next frame.
    ///
    /// - `Ok(Some(frame))` — a full frame.
    /// - `Ok(None)` — clean EOF (the peer closed on a frame boundary, nothing buffered).
    /// - `Err(_)` — I/O error, a malformed frame, or EOF mid-frame (`UnexpectedEof`).
    ///
    /// Cancel-safe: it only `.await`s `read_buf` (itself cancel-safe) and any already-buffered
    /// bytes survive across calls, so it is safe to use as a `tokio::select!` branch.
    pub async fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        loop {
            if let Some(frame) = Frame::decode(&mut self.buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            {
                return Ok(Some(frame));
            }
            // Not enough buffered for a whole frame — read more.
            let n = self.inner.read_buf(&mut self.buf).await?;
            if n == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "eof in the middle of an AnyTLS frame",
                    ))
                };
            }
        }
    }
}

/// Encodes and writes whole [`Frame`]s to an [`AsyncWrite`].
pub struct FrameWriter<W> {
    inner: W,
    buf: BytesMut,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    /// Wrap a writer.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(READ_BUF_CAP),
        }
    }

    /// Encode and write one frame (not flushed). Reuses an internal buffer across calls.
    pub async fn write_frame(&mut self, frame: &Frame) -> io::Result<()> {
        self.buf.clear();
        frame.encode(&mut self.buf);
        self.inner.write_all(&self.buf).await
    }

    /// Flush the underlying writer.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().await
    }

    /// Flush and shut down the write side.
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::anytls::frame::Command;
    use bytes::Bytes;

    #[tokio::test]
    async fn round_trips_frames_over_a_duplex() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut writer = FrameWriter::new(a);
        let mut reader = FrameReader::new(b);

        let frames = vec![
            Frame::control(Command::Syn, 1),
            Frame::new(Command::Psh, 1, Bytes::from_static(b"hello")).unwrap(),
            Frame::new(Command::Settings, 0, Bytes::from_static(b"v=2")).unwrap(),
            Frame::control(Command::Fin, 1),
        ];
        let expected = frames.clone();
        let writer_task = tokio::spawn(async move {
            for f in &frames {
                writer.write_frame(f).await.unwrap();
            }
            writer.flush().await.unwrap();
            drop(writer); // closes the write half → reader sees clean EOF
        });

        for want in expected {
            assert_eq!(reader.next_frame().await.unwrap(), Some(want));
        }
        assert_eq!(reader.next_frame().await.unwrap(), None, "clean EOF");
        writer_task.await.unwrap();
    }

    #[tokio::test]
    async fn eof_mid_frame_is_an_error() {
        use crate::transport::anytls::frame::HEADER_LEN;
        let (mut a, b) = tokio::io::duplex(64 * 1024);
        let mut reader = FrameReader::new(b);
        // Send a header that promises a body, then only part of it, then drop (EOF mid-frame).
        tokio::spawn(async move {
            let mut partial = BytesMut::new();
            Frame::new(Command::Psh, 1, Bytes::from_static(b"twelve bytes"))
                .unwrap()
                .encode(&mut partial);
            a.write_all(&partial[..HEADER_LEN + 3]).await.unwrap();
            a.flush().await.unwrap();
            // `a` drops here → EOF
        });
        let err = reader.next_frame().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
