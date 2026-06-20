//! HTTP/2 CONNECT multiplexing for the Samizdat transport (ADR 0007 §4).
//!
//! One outer TLS connection carries many proxied flows, each an HTTP/2 `CONNECT` stream whose
//! `:authority` is the destination (matching `getlantern/samizdat`'s `h2transport.go`, which sets
//! `req.Host = destination`). [`H2Conn`] owns the connection + driver task; [`H2Conn::connect`]
//! opens a tunnel and returns an [`H2Stream`] — an `AsyncRead + AsyncWrite` over the stream's DATA
//! frames, with HTTP/2 flow control handled internally.
//!
//! The `h2` crate is a scoped, documented exception to the no-hyper rule (ADR 0007 §4): the H2 layer
//! lives inside TLS, so its wire fingerprint is encrypted and is not an evasion surface.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::{Method, Request, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

fn to_io<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::other(e)
}

/// An established HTTP/2 connection to a Samizdat server, multiplexing CONNECT tunnels.
pub struct H2Conn {
    send_request: SendRequest<Bytes>,
    _driver: DriverGuard,
}

/// Aborts the connection-driver task when the [`H2Conn`] is dropped (a bare `JoinHandle` would
/// detach and leak the task).
struct DriverGuard(JoinHandle<()>);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl H2Conn {
    /// Perform the HTTP/2 client handshake over `io` (an established, ALPN-`h2` TLS stream) and
    /// spawn the connection driver (aborted when the returned [`H2Conn`] is dropped).
    pub async fn handshake<S>(io: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (send_request, connection) = h2::client::handshake(io).await.map_err(to_io)?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self {
            send_request,
            _driver: DriverGuard(driver),
        })
    }

    /// Open a CONNECT tunnel to `target` (`"host:port"`), returning a bidirectional byte stream.
    /// Multiple concurrent tunnels share this one connection.
    pub async fn connect(&self, target: &str) -> io::Result<H2Stream> {
        // Build a CONNECT request whose `:authority` is the target. For CONNECT (no extended-connect
        // protocol), h2 emits only `:method` + `:authority` (no `:scheme`/`:path`). `"host:port"`
        // parses ambiguously as a URI, so build the authority explicitly.
        let authority: http::uri::Authority = target.parse().map_err(to_io)?;
        let mut parts = http::uri::Parts::default();
        parts.authority = Some(authority);
        let uri = Uri::from_parts(parts).map_err(to_io)?;
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .body(())
            .map_err(to_io)?;

        let mut send_request = self.send_request.clone().ready().await.map_err(to_io)?;
        let (response, send) = send_request.send_request(request, false).map_err(to_io)?;
        let response = response.await.map_err(to_io)?;
        if response.status() != StatusCode::OK {
            // A non-200 is a stream-level rejection — the connection itself is healthy. Tag it
            // distinctly (`ConnectionRefused`) so the transport doesn't tear down the shared
            // connection (which serves other tunnels) over one refused target.
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "samizdat: CONNECT rejected with status {}",
                    response.status()
                ),
            ));
        }
        Ok(H2Stream::new(send, response.into_body()))
    }
}

/// A single CONNECT tunnel: `AsyncRead + AsyncWrite` over one HTTP/2 stream's DATA frames.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    /// Bytes from a received DATA frame not yet copied to the reader.
    read_buf: Bytes,
    /// Whether the write half has been END_STREAM-closed (`poll_shutdown`).
    write_closed: bool,
}

impl H2Stream {
    fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: Bytes::new(),
            write_closed: false,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Serve buffered leftovers from a prior DATA frame first, releasing flow-control capacity
        // only for the bytes actually drained — so the receive window tracks real consumption.
        if !this.read_buf.is_empty() {
            let n = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf.split_to(n));
            let _ = this.recv.flow_control().release_capacity(n);
            return Poll::Ready(Ok(()));
        }
        match this.recv.poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())), // END_STREAM → EOF
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(to_io(e))),
            Poll::Ready(Some(Ok(mut data))) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data.split_to(n));
                // Release only what we hand to the caller now; the remainder's capacity is released
                // above as it's drained from `read_buf`. Releasing the whole frame here would
                // re-open the window for bytes the application hasn't consumed yet (weak backpressure
                // → unbounded buffering under a slow reader).
                let _ = this.recv.flow_control().release_capacity(n);
                this.read_buf = data; // remainder kept for the next poll
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "samizdat: write after shutdown",
            )));
        }
        // Request capacity for this write, then send as much as HTTP/2 flow control currently allows
        // (the caller loops for the rest).
        this.send.reserve_capacity(buf.len());
        loop {
            let cap = this.send.capacity();
            if cap > 0 {
                let n = cap.min(buf.len());
                return match this
                    .send
                    .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(e) => Poll::Ready(Err(to_io(e))),
                };
            }
            match this.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "samizdat: h2 send stream closed",
                    )));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(to_io(e))),
                Poll::Ready(Some(Ok(_))) => {} // capacity granted; loop to use it
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The connection driver task does the actual socket writes; nothing to flush here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            // Empty DATA with END_STREAM = the HTTP/2 half-close (matches the Go client's CloseWrite).
            if let Err(e) = this.send.send_data(Bytes::new(), true) {
                return Poll::Ready(Err(to_io(e)));
            }
            this.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A minimal h2 server (plain TCP, h2 prior-knowledge) that accepts one CONNECT and echoes the
    /// tunnel's bytes back — reusing [`H2Stream`] on the server side too (split + copy).
    async fn connect_echo_server(listener: TcpListener) {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut conn = h2::server::handshake(tcp).await.unwrap();
        while let Some(accepted) = conn.accept().await {
            let (request, mut respond) = accepted.unwrap();
            assert_eq!(request.method(), Method::CONNECT);
            let recv = request.into_body();
            let send = respond
                .send_response(Response::builder().status(200).body(()).unwrap(), false)
                .unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(H2Stream::new(send, recv));
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    }

    #[tokio::test]
    async fn connect_tunnel_round_trips_through_h2() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(connect_echo_server(listener));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let conn = H2Conn::handshake(tcp).await.unwrap();
        let mut stream = conn.connect("example.com:1234").await.unwrap();

        let payload = b"ping-through-connect";
        stream.write_all(payload).await.unwrap();
        stream.shutdown().await.unwrap(); // half-close: server then echoes and closes

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(
            &got, payload,
            "the CONNECT tunnel must echo the payload back"
        );
    }

    #[tokio::test]
    async fn large_payload_round_trips_across_the_flow_control_window() {
        // A payload larger than the initial HTTP/2 receive window, read in small chunks while
        // writing concurrently. This exercises the buffered-remainder path and, crucially, the
        // incremental capacity release: if `poll_read` over- or under-released the window, the
        // transfer would stall and this test would hang.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(connect_echo_server(listener));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let conn = H2Conn::handshake(tcp).await.unwrap();
        let stream = conn.connect("example.com:1234").await.unwrap();

        // > 64 KiB (the default initial window), so it must span several window refills.
        let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();

        // Read and write concurrently (full-duplex) so the echo can drain while the upload streams.
        let (mut rd, mut wr) = tokio::io::split(stream);
        let upload = payload.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&upload).await.unwrap();
            wr.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        let mut buf = [0u8; 512]; // small reads force the frame remainder through `read_buf`
        loop {
            let n = rd.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        writer.await.unwrap();
        assert_eq!(got, payload, "the large payload must reassemble exactly");
    }

    #[tokio::test]
    async fn connect_rejection_maps_to_connection_refused() {
        // A non-200 CONNECT response is a stream-level rejection (the connection stays healthy),
        // surfaced as `ErrorKind::ConnectionRefused` so the transport keeps the shared connection.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(tcp).await.unwrap();
            while let Some(accepted) = conn.accept().await {
                let (request, mut respond) = accepted.unwrap();
                assert_eq!(request.method(), Method::CONNECT);
                let _ =
                    respond.send_response(Response::builder().status(502).body(()).unwrap(), true);
            }
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let conn = H2Conn::handshake(tcp).await.unwrap();
        match conn.connect("example.com:1234").await {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused),
            Ok(_) => panic!("a non-200 CONNECT must be rejected"),
        }
    }
}
