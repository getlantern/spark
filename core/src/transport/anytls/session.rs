//! AnyTLS session multiplexer — many logical [`Stream`]s over one (TLS) byte transport.
//!
//! Design follows the project's concurrency rules (channels over locks, actor-style ownership):
//! the transport is split into read/write halves, each owned by its own task, and there is **no
//! shared `Mutex`** over the stream table. (`anytls-rs` dropped multiplexing citing deadlock
//! fragility — this layout is the deadlock-avoidance answer.)
//!
//! ```text
//!   Stream ─PSH/FIN─▶ outbound mpsc ─▶ [writer task] owns WriteHalf ─▶ transport
//!   Stream ◀──bytes── inbound mpsc ◀── [reader task] owns ReadHalf  ◀── transport
//!                                         │ owns HashMap<stream_id, inbound sender>
//!                                         └─ Register (oneshot-acked) from open_stream
//! ```
//!
//! Each [`Stream`] is an `AsyncRead + AsyncWrite` byte channel keyed by `stream_id`. The reader
//! task demuxes inbound `cmdPSH`/`cmdFIN` to the right stream; the writer task serializes all
//! outbound frames onto the single write half (no lock).
//!
//! **Client-side only** (spark opens streams; it does not accept). The idle-session **pool**
//! (acquire/reuse/sweep) and session-level handling of `cmdSettings`/`cmdUpdatePaddingScheme`/auth
//! land in later chunks. A [`Session`] must **outlive** the [`Stream`]s it opens (the pool will own
//! sessions); when it drops, both tasks abort.
//!
//! ## Backpressure (current state)
//! - **Inbound** (peer → stream) is a *bounded* channel; the reader `.await`s on a full one, which
//!   backpressures the peer but head-of-line-blocks other streams until per-stream flow control is
//!   added.
//! - **Outbound** (stream → writer) is *unbounded* for now, so [`Stream`] writes never block. When
//!   this is wired to the real TLS transport (chunk 4) it becomes a bounded channel with poll-based
//!   reservation so `poll_write` applies real backpressure.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::frame::{Command, Frame, MAX_PAYLOAD};
use super::io::{FrameReader, FrameWriter};

/// Capacity of the reader's control channel (stream registrations).
const CONTROL_CAP: usize = 16;
/// Per-stream inbound queue depth (frames buffered for a stream before the reader backpressures).
const STREAM_INBOUND_CAP: usize = 32;

/// A message to the reader task — currently only "register this new stream so inbound frames for
/// `stream_id` are routable." Acked over `ack` so `open_stream` registers *before* sending the SYN
/// (no race where a reply arrives before the stream is known).
enum Control {
    Register {
        stream_id: u32,
        inbound: mpsc::Sender<Bytes>,
        ack: oneshot::Sender<()>,
    },
}

/// A multiplexed AnyTLS session over one byte transport. Cheap to hold; spawns two background
/// tasks (reader/writer) that are aborted when the `Session` is dropped.
pub struct Session {
    outbound: mpsc::UnboundedSender<Frame>,
    control: mpsc::Sender<Control>,
    next_id: AtomicU32,
    tasks: Vec<JoinHandle<()>>,
}

impl Session {
    /// Start a session over `transport` (already TLS-wrapped in production; an in-memory duplex in
    /// tests). Spawns the reader and writer tasks.
    pub fn new<S>(transport: S) -> Session
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (rd, wr) = tokio::io::split(transport);
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (control_tx, control_rx) = mpsc::channel(CONTROL_CAP);
        let writer = tokio::spawn(writer_task(FrameWriter::new(wr), outbound_rx));
        let reader = tokio::spawn(reader_task(FrameReader::new(rd), control_rx));
        Session {
            outbound: outbound_tx,
            control: control_tx,
            next_id: AtomicU32::new(1),
            tasks: vec![writer, reader],
        }
    }

    /// Open a new logical stream: allocate the next `stream_id`, register it with the reader (and
    /// wait for the ack so replies are routable), then send `cmdSYN`. The returned [`Stream`]
    /// relays bytes via `cmdPSH` and closes with `cmdFIN`.
    ///
    /// The AnyTLS target address (the SOCKS5 `SocksAddr` the client sends as the first `cmdPSH`) is
    /// the caller's concern — this opens an address-agnostic byte stream.
    pub async fn open_stream(&self) -> io::Result<Stream> {
        let stream_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (inbound_tx, inbound_rx) = mpsc::channel(STREAM_INBOUND_CAP);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.control
            .send(Control::Register {
                stream_id,
                inbound: inbound_tx,
                ack: ack_tx,
            })
            .await
            .map_err(|_| session_gone("reader"))?;
        ack_rx.await.map_err(|_| session_gone("reader"))?;
        self.outbound
            .send(Frame::control(Command::Syn, stream_id))
            .map_err(|_| session_gone("writer"))?;
        Ok(Stream {
            stream_id,
            outbound: self.outbound.clone(),
            inbound: inbound_rx,
            read_rem: Bytes::new(),
            write_closed: false,
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn session_gone(which: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        format!("anytls session {which} task gone"),
    )
}

/// Owns the write half; serializes every outbound frame onto it. Coalesces a burst of
/// already-queued frames before flushing.
async fn writer_task<W: AsyncWrite + Unpin>(
    mut writer: FrameWriter<W>,
    mut outbound: mpsc::UnboundedReceiver<Frame>,
) {
    'outer: while let Some(frame) = outbound.recv().await {
        if writer.write_frame(&frame).await.is_err() {
            break;
        }
        // Drain frames already queued so a burst becomes one flush.
        while let Ok(f) = outbound.try_recv() {
            if writer.write_frame(&f).await.is_err() {
                break 'outer;
            }
        }
        if writer.flush().await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

/// Owns the read half and the stream table; demuxes inbound frames to per-stream channels and
/// services stream registrations.
async fn reader_task<R: AsyncRead + Unpin>(
    mut reader: FrameReader<R>,
    mut control: mpsc::Receiver<Control>,
) {
    let mut streams: HashMap<u32, mpsc::Sender<Bytes>> = HashMap::new();
    let mut control_open = true;
    loop {
        tokio::select! {
            // Bias toward registrations so a stream is always known before its frames are routed.
            biased;
            ctrl = control.recv(), if control_open => match ctrl {
                Some(Control::Register { stream_id, inbound, ack }) => {
                    streams.insert(stream_id, inbound);
                    let _ = ack.send(());
                }
                // The Session handle was dropped; keep routing to live streams until EOF.
                None => control_open = false,
            },
            frame = reader.next_frame() => match frame {
                Ok(Some(f)) => route(f, &mut streams).await,
                Ok(None) => break,  // clean EOF
                Err(_) => break,    // I/O error or malformed frame → tear down
            },
        }
    }
}

/// Route one inbound frame to its stream (or handle it at the session level).
async fn route(frame: Frame, streams: &mut HashMap<u32, mpsc::Sender<Bytes>>) {
    match frame.command {
        Command::Psh => {
            if let Some(tx) = streams.get(&frame.stream_id) {
                // Bounded send → backpressure (HOL across streams until per-stream flow control).
                // If the stream's reader was dropped, forget the stream.
                if tx.send(frame.payload).await.is_err() {
                    streams.remove(&frame.stream_id);
                }
            }
        }
        // Dropping the inbound sender makes the Stream's reader observe EOF.
        Command::Fin => {
            streams.remove(&frame.stream_id);
        }
        // Established-ack, server-role, and session-level frames are handled in later chunks.
        Command::SynAck
        | Command::Syn
        | Command::Settings
        | Command::ServerSettings
        | Command::UpdatePaddingScheme
        | Command::Alert
        | Command::HeartRequest
        | Command::HeartResponse => {}
        // Padding — discard.
        Command::Waste => {}
    }
}

/// One multiplexed logical stream: an `AsyncRead + AsyncWrite` byte channel over a `stream_id`.
pub struct Stream {
    stream_id: u32,
    outbound: mpsc::UnboundedSender<Frame>,
    inbound: mpsc::Receiver<Bytes>,
    /// Leftover from an inbound frame that didn't fit the caller's read buffer.
    read_rem: Bytes,
    write_closed: bool,
}

impl Stream {
    /// This stream's id within its session.
    pub fn id(&self) -> u32 {
        self.stream_id
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_rem.is_empty() {
                let n = std::cmp::min(buf.remaining(), this.read_rem.len());
                buf.put_slice(&this.read_rem[..n]);
                this.read_rem.advance(n);
                return Poll::Ready(Ok(()));
            }
            match this.inbound.poll_recv(cx) {
                // Skip a (rare) empty inbound frame rather than mis-signal EOF.
                Poll::Ready(Some(b)) => this.read_rem = b,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // FIN / session gone → EOF
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let n = std::cmp::min(data.len(), MAX_PAYLOAD);
        // Fields are bounded by construction (n <= MAX_PAYLOAD), so build the frame directly —
        // no fallible `Frame::new`, no `expect` on the data path.
        let frame = Frame {
            command: Command::Psh,
            stream_id: this.stream_id,
            payload: Bytes::copy_from_slice(&data[..n]),
        };
        match this.outbound.send(frame) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(_) => Poll::Ready(Err(session_gone("writer"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The writer task flushes the transport after draining queued frames; the unbounded
        // outbound channel exposes no buffer to flush here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            this.write_closed = true;
            let _ = this
                .outbound
                .send(Frame::control(Command::Fin, this.stream_id));
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// A minimal peer: echo every `cmdPSH` back on the same `stream_id`; ignore everything else.
    async fn echo_peer(io: DuplexStream) {
        let (rd, wr) = tokio::io::split(io);
        let mut reader = FrameReader::new(rd);
        let mut writer = FrameWriter::new(wr);
        while let Ok(Some(frame)) = reader.next_frame().await {
            if frame.command == Command::Psh {
                let echo = Frame {
                    command: Command::Psh,
                    stream_id: frame.stream_id,
                    payload: frame.payload,
                };
                if writer.write_frame(&echo).await.is_err() {
                    break;
                }
                let _ = writer.flush().await;
            }
        }
    }

    #[tokio::test]
    async fn opens_relays_and_closes_a_stream() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(echo_peer(server_io));
        let session = Session::new(client_io);

        let mut stream = session.open_stream().await.unwrap();
        assert_eq!(stream.id(), 1);
        stream.write_all(b"hello anytls").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 12];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello anytls");

        stream.shutdown().await.unwrap(); // sends FIN
        drop(stream);
        drop(session); // aborts tasks → peer's read half EOFs → echo_peer returns
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn multiplexes_two_streams_independently() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(echo_peer(server_io));
        let session = Session::new(client_io);

        let mut a = session.open_stream().await.unwrap();
        let mut b = session.open_stream().await.unwrap();
        assert_eq!((a.id(), b.id()), (1, 2));

        // Interleave writes; each stream must read back exactly its own bytes (routed by id).
        a.write_all(b"aaaaaaaa").await.unwrap();
        b.write_all(b"bbbb").await.unwrap();
        a.flush().await.unwrap();
        b.flush().await.unwrap();

        let mut abuf = [0u8; 8];
        let mut bbuf = [0u8; 4];
        b.read_exact(&mut bbuf).await.unwrap();
        a.read_exact(&mut abuf).await.unwrap();
        assert_eq!(&abuf, b"aaaaaaaa");
        assert_eq!(&bbuf, b"bbbb");

        drop((a, b, session));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn peer_fin_signals_eof() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        // Peer: on the first PSH, reply with a FIN for that stream (no data), then idle.
        let peer = tokio::spawn(async move {
            let (rd, wr) = tokio::io::split(server_io);
            let mut reader = FrameReader::new(rd);
            let mut writer = FrameWriter::new(wr);
            while let Ok(Some(frame)) = reader.next_frame().await {
                if frame.command == Command::Psh {
                    writer
                        .write_frame(&Frame::control(Command::Fin, frame.stream_id))
                        .await
                        .unwrap();
                    writer.flush().await.unwrap();
                    break;
                }
            }
        });
        let session = Session::new(client_io);
        let mut stream = session.open_stream().await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        // The peer's FIN closes our inbound → read returns 0 (EOF).
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "peer FIN should surface as EOF");
        peer.await.unwrap();
    }
}
