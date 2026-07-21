//! [`TransformStream`] — an `AsyncRead`+`AsyncWrite` adapter that pumps a byte stream through a
//! dynamic-transport module (a [`Transform`]).
//!
//! The module is treated as a **stateful stream codec**: on the write side, application bytes are
//! handed to [`Transform::transform_out`] and the obfuscated result is written to the underlying
//! stream; on the read side, raw bytes are pulled from the underlying stream and handed to
//! [`Transform::transform_in`], yielding recovered application bytes. The module may carry state
//! across calls and emit any output length (including zero, to buffer a partial frame), so this
//! adapter never assumes length preservation or a 1:1 relationship between calls and bytes.
//!
//! All framing, if any, lives *inside* the module — the host adds nothing to the wire, because a
//! host-added length prefix would itself be a fingerprint.
//!
//! The transform calls are synchronous (`wasmi` is an interpreter), and run on the control path, so
//! invoking them inside `poll_*` is fine. Buffering state lives in struct fields, so the methods are
//! poll-driven state machines — usable inside `tokio::select!` without losing partial progress.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Transform;

/// Size of the scratch buffer for a single read from the underlying stream (before deobfuscation).
const READ_SCRATCH: usize = 16 * 1024;

/// Wraps an underlying byte stream `S`, obfuscating writes and deobfuscating reads through a
/// dynamic-transport [`Transform`]. One [`Transform`] (hence one `TransformStream`) per connection.
pub struct TransformStream<S> {
    inner: S,
    transform: Transform,
    /// Obfuscated bytes produced by `transform_out`, awaiting write to `inner` (a FIFO drained
    /// front-first via [`Buf::advance`]).
    write_buf: BytesMut,
    /// Recovered application bytes produced by `transform_in`, awaiting delivery to the reader.
    read_buf: Bytes,
    /// Reused scratch for raw reads from `inner`; allocated once so reads don't allocate per call.
    scratch: Box<[u8]>,
    /// One-shot flag for the first read: a handshake-driving module can over-read the peer's first
    /// steady-state bytes off the wire (when they coalesce with the handshake tail) and buffer them
    /// internally. Those bytes are no longer on the wire, so the first `poll_read` must drain them
    /// with an empty-input `transform_in` before blocking on a wire read that would never return.
    handshake_drain_pending: bool,
}

impl<S> TransformStream<S> {
    /// Wrap `inner`, running every write through `transform`'s outbound transform and every read
    /// through its inbound transform.
    pub fn new(inner: S, transform: Transform) -> Self {
        let handshake_drain_pending = transform.drives_handshake();
        Self {
            inner,
            transform,
            write_buf: BytesMut::new(),
            read_buf: Bytes::new(),
            scratch: vec![0u8; READ_SCRATCH].into_boxed_slice(),
            handshake_drain_pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> TransformStream<S> {
    /// Write as much of `write_buf` to `inner` as it will accept. `Pending` means the underlying
    /// stream is not currently writable (the waker is registered); `Ready(Ok(()))` means drained.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "wasm transform stream: underlying write accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => self.write_buf.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TransformStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Backpressure: don't accept new application bytes until the previous transform output has
        // drained, so in-flight buffering stays bounded to ~one transform output.
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.transform.transform_out(buf) {
            Ok(out) => this.write_buf.extend_from_slice(&out),
            Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
        }
        // Eagerly push the freshly-produced output so data actually flows without requiring the
        // caller to flush after every write — otherwise `write_all` followed by a read deadlocks
        // with the bytes stuck in `write_buf`. A would-block leaves the remainder buffered for the
        // next poll_write/poll_flush; we've taken all of `buf`, so report it fully consumed. A hard
        // write error surfaces now (the stream is then broken, so the buffered bytes won't be sent).
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TransformStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Serve already-recovered bytes first.
            if !this.read_buf.is_empty() {
                let n = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            // Once, before the first wire read: drain any complete frame the handshake driver
            // over-read into the module (see `handshake_drain_pending`). A no-op unless the module
            // buffered bytes — but it must precede the wire read, which would otherwise block forever
            // on bytes that are already inside the module rather than on the wire.
            if this.handshake_drain_pending {
                this.handshake_drain_pending = false;
                match this.transform.transform_in(&[]) {
                    Ok(recovered) if !recovered.is_empty() => {
                        this.read_buf = Bytes::from(recovered);
                        continue;
                    }
                    Ok(_) => {}
                    Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
                }
            }
            // Otherwise pull more wire bytes and deobfuscate.
            let mut scratch = ReadBuf::new(&mut this.scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut scratch) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    if scratch.filled().is_empty() {
                        return Poll::Ready(Ok(())); // EOF on the underlying stream
                    }
                    match this.transform.transform_in(scratch.filled()) {
                        // Empty output means the module buffered a partial frame internally; pull
                        // more wire bytes rather than reporting a spurious read of 0 (which a reader
                        // would interpret as EOF).
                        Ok(recovered) if recovered.is_empty() => continue,
                        Ok(recovered) => this.read_buf = Bytes::from(recovered),
                        Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::wasm::testutil::xor_module;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn round_trips_application_bytes_both_directions() {
        let module = xor_module();
        let (a, b) = tokio::io::duplex(4096);
        let mut client = TransformStream::new(a, module.instantiate().expect("instantiate"));
        let mut server = TransformStream::new(b, module.instantiate().expect("instantiate"));

        // No explicit flush between write and read: poll_write must push eagerly, or this deadlocks.
        let request = b"hello over the wasm transform stream";
        client.write_all(request).await.expect("client write");
        let mut got = vec![0u8; request.len()];
        server.read_exact(&mut got).await.expect("server read");
        assert_eq!(got.as_slice(), &request[..]);

        let reply = b"and back the other way";
        server.write_all(reply).await.expect("server write");
        let mut got = vec![0u8; reply.len()];
        client.read_exact(&mut got).await.expect("client read");
        assert_eq!(got.as_slice(), &reply[..]);
    }

    #[tokio::test]
    async fn wire_bytes_are_obfuscated() {
        // The bytes that actually traverse the underlying stream must differ from the plaintext.
        let module = xor_module();
        let (mut wire_reader, app_side) = tokio::io::duplex(4096);
        let mut client = TransformStream::new(app_side, module.instantiate().expect("instantiate"));

        let plaintext = b"plaintext payload that must not appear on the wire";
        client.write_all(plaintext).await.expect("write");
        client.flush().await.expect("flush");
        drop(client); // close the write half so read_to_end terminates

        let mut wire = Vec::new();
        wire_reader.read_to_end(&mut wire).await.expect("read wire");
        assert_eq!(
            wire.len(),
            plaintext.len(),
            "the XOR fixture is length-preserving"
        );
        assert_ne!(
            wire.as_slice(),
            &plaintext[..],
            "wire bytes must be obfuscated"
        );
    }

    /// An `AsyncRead` that yields at most `chunk` bytes per poll, exercising the read-side reassembly
    /// loop. It returns `Pending` (waking itself) every other poll — mimicking a real socket, which
    /// punctuates a transfer with `Pending` whenever its buffer drains. That matters: an always-ready
    /// reader would run the whole transfer inside one executor poll, building a large single-poll
    /// stack in debug builds — an artifact that real, sometimes-`Pending` I/O never produces.
    struct ChunkedReader {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
        pending_next: bool,
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.pending_next {
                this.pending_next = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.pending_next = true;
            let remaining = &this.data[this.pos..];
            if remaining.is_empty() {
                return Poll::Ready(Ok(())); // EOF
            }
            let n = remaining.len().min(this.chunk).min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn chunked_wire_reads_reassemble() {
        // Obfuscate a multi-chunk payload, then read it back through a transform whose underlying
        // reader hands over only 64 bytes per poll — exercising the read-side reassembly loop.
        let module = xor_module();
        let payload: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
        // The fixture XORs with 0x5A; compute the wire bytes directly rather than via one large
        // `transform_out` call. (A large single call only troubles debug's non-TCO interpreter — see
        // the release-only large-transform test; here we want to exercise the small chunked reads.)
        let wire: Vec<u8> = payload.iter().map(|b| b ^ 0x5a).collect();

        let reader = ChunkedReader {
            data: wire,
            pos: 0,
            chunk: 64,
            pending_next: false,
        };
        let mut server = TransformStream::new(reader, module.instantiate().expect("instantiate"));
        let mut got = vec![0u8; payload.len()];
        server.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload);
    }
}
