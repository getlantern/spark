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
//! task demuxes inbound `cmdPSH`/`cmdFIN` to the right stream; the writer serializes all outbound
//! frames onto the single write half (no lock).
//!
//! Two constructors:
//! - [`Session::new`] — the **raw** mux (frames written as-is, no handshake/padding). Low-level
//!   building block, used in tests.
//! - [`Session::client`] — a **client session**: writes the auth record, sends a buffered
//!   `cmdSettings`, and shapes outgoing packets with the [`super::padding`] engine, faithfully to
//!   anytls-go. Open a stream and write the SOCKS5 target address as its first bytes; that flushes
//!   the buffered `cmdSettings`+`cmdSYN`+address as padded packet 1.
//!
//! **Client-side only** (spark opens streams; it does not accept). The client adopts a server
//! `cmdUpdatePaddingScheme` (swapping the shared scheme the writer shapes with) and closes a stream
//! on a non-empty `cmdSYNACK` (the server's upstream-dial error). A [`Session`] must **outlive** the
//! [`Stream`]s it opens; when it drops, both tasks abort.
//!
//! ## Backpressure (current state)
//! - **Inbound** (peer → stream) is a *bounded* channel; the reader `.await`s on a full one, which
//!   backpressures the peer but head-of-line-blocks other streams until per-stream flow control.
//! - **Outbound** (stream → writer) is *unbounded* for now, so [`Stream`] writes never block. It
//!   becomes a bounded poll-reserve channel when wired to the real TLS transport.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::auth::encode_auth;
use super::frame::{Command, Frame, MAX_PAYLOAD};
use super::io::FrameReader;
use super::padding::{shape_records, PaddingScheme, Seg, SizeSampler, SystemSampler};
use super::settings::Settings;
use super::PROTOCOL_VERSION;

/// Capacity of the reader's control channel (stream registrations).
const CONTROL_CAP: usize = 16;
/// Per-stream inbound queue depth (frames buffered for a stream before the reader backpressures).
const STREAM_INBOUND_CAP: usize = 32;
/// The `client=` identifier sent in `cmdSettings`.
const CLIENT_ID: &str = concat!("spark/", env!("CARGO_PKG_VERSION"));

/// An item for the writer task: a frame to send, or the marker that ends the client's initial
/// buffering phase (so `cmdSettings`+`cmdSYN`+address batch into padded packet 1).
enum Out {
    Frame(Frame),
    EndBuffering,
}

/// A message to the reader task — register a new stream so inbound frames for `stream_id` are
/// routable. Acked over `ack` so `open_stream` registers *before* sending the SYN (no race where a
/// reply arrives before the stream is known).
enum Control {
    Register {
        stream_id: u32,
        inbound: mpsc::Sender<Bytes>,
        ack: oneshot::Sender<()>,
    },
}

/// Client-mode writer state: the auth record to send first and the padding scheme to shape with.
/// The scheme is shared so the reader can swap it on a server `cmdUpdatePaddingScheme`.
struct Handshake {
    auth: Bytes,
    scheme: Arc<Mutex<PaddingScheme>>,
}

/// A multiplexed AnyTLS session over one byte transport. Cheap to hold; spawns two background
/// tasks (reader/writer) that are aborted when the `Session` is dropped.
pub struct Session {
    outbound: mpsc::UnboundedSender<Out>,
    control: mpsc::Sender<Control>,
    next_id: AtomicU32,
    /// Count of currently-open [`Stream`]s (incremented in `open_stream`, decremented on
    /// `Stream` drop) — lets the transport pool reuse and sweep sessions.
    streams: Arc<AtomicUsize>,
    tasks: Vec<JoinHandle<()>>,
}

impl Session {
    /// The **raw** mux over `transport`: frames written as-is, no handshake or padding. Building
    /// block / test harness; production clients use [`Session::client`].
    pub fn new<S>(transport: S) -> Session
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::spawn(transport, None)
    }

    /// A **client session** over `transport` (already TLS-wrapped in production). Writes the auth
    /// record `sha256(password) | u16(padLen) | zeros` (padLen = the packet-0 scheme size), then a
    /// buffered `cmdSettings`; subsequent packets are shaped by `scheme`. Open a stream and write
    /// the SOCKS5 target address as its first bytes (anytls choreography).
    pub fn client<S>(transport: S, password: &str, scheme: PaddingScheme) -> Session
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Auth padding length = the first packet-0 record size (anytls GenerateRecordPayloadSizes(0)[0]).
        let mut sampler = SystemSampler::new();
        let pad_len = match scheme.plan(0).first() {
            Some(Seg::Size { lo, hi }) => {
                (sampler.sample(*lo, *hi) as usize).min(u16::MAX as usize)
            }
            _ => 0,
        };
        let mut auth = BytesMut::new();
        if encode_auth(password, &vec![0u8; pad_len], &mut auth).is_err() {
            // Unreachable (pad_len is clamped to the 2-byte field); fall back to no padding.
            auth.clear();
            let _ = encode_auth(password, &[], &mut auth);
        }
        let settings = Settings::for_scheme(PROTOCOL_VERSION, CLIENT_ID, &scheme).encode();

        let session = Self::spawn(
            transport,
            Some(Handshake {
                auth: auth.freeze(),
                scheme: Arc::new(Mutex::new(scheme)),
            }),
        );
        // First buffered frame: cmdSettings (session-level, stream 0).
        let _ = session.outbound.send(Out::Frame(Frame {
            command: Command::Settings,
            stream_id: 0,
            payload: settings,
        }));
        session
    }

    fn spawn<S>(transport: S, handshake: Option<Handshake>) -> Session
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (rd, wr) = tokio::io::split(transport);
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (control_tx, control_rx) = mpsc::channel(CONTROL_CAP);
        // The reader needs the shared scheme to apply a server `cmdUpdatePaddingScheme`.
        let scheme = handshake.as_ref().map(|h| Arc::clone(&h.scheme));
        let writer = tokio::spawn(writer_task(wr, outbound_rx, handshake));
        let reader = tokio::spawn(reader_task(FrameReader::new(rd), control_rx, scheme));
        Session {
            outbound: outbound_tx,
            control: control_tx,
            next_id: AtomicU32::new(1),
            streams: Arc::new(AtomicUsize::new(0)),
            tasks: vec![writer, reader],
        }
    }

    /// Number of streams currently open on this session (0 = idle).
    pub fn active_streams(&self) -> usize {
        self.streams.load(Ordering::Relaxed)
    }

    /// Whether both background tasks are still running — i.e. the underlying connection is up. A
    /// dropped or errored connection makes the reader task finish, so this turns `false`.
    pub fn is_alive(&self) -> bool {
        self.tasks.iter().all(|t| !t.is_finished())
    }

    /// Open a new logical stream: allocate the next `stream_id`, register it with the reader (and
    /// wait for the ack so replies are routable), then send `cmdSYN` and end the initial buffering
    /// phase. The returned [`Stream`] relays bytes via `cmdPSH` and closes with `cmdFIN`.
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
            .send(Out::Frame(Frame::control(Command::Syn, stream_id)))
            .map_err(|_| session_gone("writer"))?;
        // End the client's initial buffering phase (a no-op for a raw session, and idempotent for
        // later streams since buffering is already off).
        let _ = self.outbound.send(Out::EndBuffering);
        self.streams.fetch_add(1, Ordering::Relaxed);
        Ok(Stream {
            stream_id,
            outbound: self.outbound.clone(),
            inbound: inbound_rx,
            read_rem: Bytes::new(),
            write_closed: false,
            streams: Arc::clone(&self.streams),
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

/// The writer task: client mode (auth + buffering + padding) or raw mode (frames as-is).
async fn writer_task<W: AsyncWrite + Unpin>(
    wr: W,
    outbound: mpsc::UnboundedReceiver<Out>,
    handshake: Option<Handshake>,
) {
    match handshake {
        Some(h) => client_writer(wr, outbound, h).await,
        None => raw_writer(wr, outbound).await,
    }
}

/// Raw mode: encode and write each frame, coalescing a burst before flushing. `EndBuffering` is a
/// no-op here.
async fn raw_writer<W: AsyncWrite + Unpin>(mut wr: W, mut outbound: mpsc::UnboundedReceiver<Out>) {
    let _ = raw_writer_inner(&mut wr, &mut outbound).await;
    let _ = wr.shutdown().await;
}

async fn raw_writer_inner<W: AsyncWrite + Unpin>(
    wr: &mut W,
    outbound: &mut mpsc::UnboundedReceiver<Out>,
) -> io::Result<()> {
    let mut buf = BytesMut::new();
    while let Some(item) = outbound.recv().await {
        let Out::Frame(f) = item else { continue };
        buf.clear();
        f.encode(&mut buf);
        wr.write_all(&buf).await?;
        while let Ok(Out::Frame(f)) = outbound.try_recv() {
            buf.clear();
            f.encode(&mut buf);
            wr.write_all(&buf).await?;
        }
        wr.flush().await?;
    }
    Ok(())
}

/// Client mode: write the auth record (packet 0), buffer frames until `EndBuffering`, then shape
/// each write into padded records via [`shape_records`]. Each non-buffered frame is one packet.
async fn client_writer<W: AsyncWrite + Unpin>(
    mut wr: W,
    mut outbound: mpsc::UnboundedReceiver<Out>,
    h: Handshake,
) {
    let _ = client_writer_inner(&mut wr, &mut outbound, h).await;
    let _ = wr.shutdown().await;
}

async fn client_writer_inner<W: AsyncWrite + Unpin>(
    wr: &mut W,
    outbound: &mut mpsc::UnboundedReceiver<Out>,
    h: Handshake,
) -> io::Result<()> {
    let mut sampler = SystemSampler::new();
    // Packet 0: the auth record, its own write (as anytls' dialer does).
    wr.write_all(&h.auth).await?;
    wr.flush().await?;

    let mut buffering = true;
    let mut buffer = BytesMut::new(); // accumulated cmdSettings+cmdSYN during buffering
    let mut pkt: usize = 0;
    while let Some(item) = outbound.recv().await {
        match item {
            Out::EndBuffering => buffering = false,
            Out::Frame(f) if buffering => f.encode(&mut buffer),
            Out::Frame(f) => {
                // One packet = the buffered prefix (if any) ++ this frame.
                let mut data = std::mem::take(&mut buffer);
                f.encode(&mut data);
                pkt += 1;
                // Lock only to read the (possibly server-updated) scheme; shape_records is sync.
                let records = {
                    let scheme = h.scheme.lock().unwrap_or_else(|e| e.into_inner());
                    shape_records(&scheme, pkt, data.freeze(), &mut sampler)
                };
                for rec in records {
                    wr.write_all(&rec).await?;
                }
                wr.flush().await?;
            }
        }
    }
    Ok(())
}

/// Owns the read half and the stream table; demuxes inbound frames to per-stream channels and
/// services stream registrations.
async fn reader_task<R: AsyncRead + Unpin>(
    mut reader: FrameReader<R>,
    mut control: mpsc::Receiver<Control>,
    scheme: Option<Arc<Mutex<PaddingScheme>>>,
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
                Ok(Some(f)) => route(f, &mut streams, scheme.as_deref()).await,
                Ok(None) => break,  // clean EOF
                Err(_) => break,    // I/O error or malformed frame → tear down
            },
        }
    }
}

/// Route one inbound frame to its stream (or handle it at the session level). `scheme` is the
/// client's shared padding scheme, swappable on a server `cmdUpdatePaddingScheme`.
async fn route(
    frame: Frame,
    streams: &mut HashMap<u32, mpsc::Sender<Bytes>>,
    scheme: Option<&Mutex<PaddingScheme>>,
) {
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
        // A non-empty SYNACK carries the server's error (the upstream dial failed); close the
        // stream so its reader unblocks (an empty SYNACK is a success ack — nothing to do).
        Command::SynAck => {
            if !frame.payload.is_empty() {
                streams.remove(&frame.stream_id);
            }
        }
        // The server pushes a new padding scheme (its anti-blocklist lever); adopt it for future
        // packets. A malformed scheme is ignored (keep the current one).
        Command::UpdatePaddingScheme => {
            if let Some(scheme) = scheme {
                if let Ok(text) = std::str::from_utf8(&frame.payload) {
                    if let Ok(updated) = PaddingScheme::parse(text) {
                        *scheme.lock().unwrap_or_else(|e| e.into_inner()) = updated;
                    }
                }
            }
        }
        // Server-role / session-level frames not yet acted on; Waste = padding (discard).
        Command::Syn
        | Command::Settings
        | Command::ServerSettings
        | Command::Alert
        | Command::HeartRequest
        | Command::HeartResponse
        | Command::Waste => {}
    }
}

/// One multiplexed logical stream: an `AsyncRead + AsyncWrite` byte channel over a `stream_id`.
pub struct Stream {
    stream_id: u32,
    outbound: mpsc::UnboundedSender<Out>,
    inbound: mpsc::Receiver<Bytes>,
    /// Leftover from an inbound frame that didn't fit the caller's read buffer.
    read_rem: Bytes,
    write_closed: bool,
    /// The session's open-stream counter; decremented when this stream drops.
    streams: Arc<AtomicUsize>,
}

impl Stream {
    /// This stream's id within its session.
    pub fn id(&self) -> u32 {
        self.stream_id
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // FIN the stream if it wasn't already shut down (e.g. a dropped UDP association, whose
        // split halves never call `poll_shutdown`) so the server releases it promptly instead of on
        // idle timeout. A closed writer just drops the send.
        if !self.write_closed {
            let _ = self
                .outbound
                .send(Out::Frame(Frame::control(Command::Fin, self.stream_id)));
        }
        self.streams.fetch_sub(1, Ordering::Relaxed);
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
        match this.outbound.send(Out::Frame(frame)) {
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
                .send(Out::Frame(Frame::control(Command::Fin, this.stream_id)));
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::anytls::io::FrameWriter;
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

    /// What an AnyTLS server peer observed during the client handshake.
    struct HandshakeSeen {
        hash_ok: bool,
        settings: Option<Bytes>,
        saw_syn: bool,
        psh: Vec<u8>,
    }

    /// A minimal AnyTLS *server* peer: read + verify the auth record, then parse the frame stream
    /// (discarding `cmdWaste` padding), collect the handshake frames, echo the first `cmdPSH`.
    async fn anytls_server(io: DuplexStream, password: String) -> HandshakeSeen {
        let (mut rd, wr) = tokio::io::split(io);
        // Auth record: sha256(32) | u16(padLen) | padding.
        let mut hash = [0u8; 32];
        rd.read_exact(&mut hash).await.unwrap();
        let mut len_be = [0u8; 2];
        rd.read_exact(&mut len_be).await.unwrap();
        let mut pad = vec![0u8; u16::from_be_bytes(len_be) as usize];
        rd.read_exact(&mut pad).await.unwrap();
        let expect = ring::digest::digest(&ring::digest::SHA256, password.as_bytes());
        let hash_ok = hash == expect.as_ref();

        // The rest is the (padded) frame stream.
        let mut reader = FrameReader::new(rd);
        let mut writer = FrameWriter::new(wr);
        let mut seen = HandshakeSeen {
            hash_ok,
            settings: None,
            saw_syn: false,
            psh: Vec::new(),
        };
        while let Ok(Some(f)) = reader.next_frame().await {
            match f.command {
                Command::Settings => seen.settings = Some(f.payload),
                Command::Syn => seen.saw_syn = true,
                Command::Psh => {
                    seen.psh.extend_from_slice(&f.payload);
                    writer
                        .write_frame(&Frame {
                            command: Command::Psh,
                            stream_id: f.stream_id,
                            payload: f.payload,
                        })
                        .await
                        .unwrap();
                    writer.flush().await.unwrap();
                }
                Command::Fin => break,
                _ => {} // discard cmdWaste padding and anything else
            }
        }
        seen
    }

    #[tokio::test]
    async fn client_handshake_writes_auth_settings_syn_then_relays() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let password = "hunter2";
        let peer = tokio::spawn(anytls_server(server_io, password.to_string()));

        let session = Session::client(client_io, password, PaddingScheme::default());
        let mut stream = session.open_stream().await.unwrap();
        // The stream's first bytes stand in for the SOCKS5 target address + initial data.
        stream.write_all(b"target-addr-and-data").await.unwrap();
        stream.flush().await.unwrap();

        let mut echo = [0u8; 20];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"target-addr-and-data", "relayed bytes round-trip");

        stream.shutdown().await.unwrap();
        drop(stream);
        drop(session);

        let seen = peer.await.unwrap();
        assert!(seen.hash_ok, "auth record sha256(password) matches");
        let settings = Settings::parse(&seen.settings.expect("cmdSettings sent")).unwrap();
        assert_eq!(settings.version, PROTOCOL_VERSION);
        assert!(settings.padding_md5.is_some(), "padding-md5 present");
        assert!(seen.saw_syn, "cmdSYN sent");
        assert_eq!(seen.psh, b"target-addr-and-data", "address/data delivered");
    }

    #[tokio::test]
    async fn tracks_active_streams_and_liveness() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(echo_peer(server_io));
        let session = Session::new(client_io);
        assert!(session.is_alive(), "a fresh session is alive");
        assert_eq!(session.active_streams(), 0);

        let s1 = session.open_stream().await.unwrap();
        let s2 = session.open_stream().await.unwrap();
        assert_eq!(session.active_streams(), 2, "two open streams");
        drop(s1);
        assert_eq!(
            session.active_streams(),
            1,
            "drop decrements (the pool's idle signal)"
        );
        drop(s2);
        assert_eq!(session.active_streams(), 0, "idle again");
        assert!(session.is_alive());

        drop(session);
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn update_padding_scheme_swaps_the_shared_scheme() {
        let scheme = Mutex::new(PaddingScheme::default()); // stop=8
        let mut streams = HashMap::new();
        let frame = Frame::new(
            Command::UpdatePaddingScheme,
            0,
            Bytes::from_static(b"stop=1\n0=5-5"),
        )
        .unwrap();
        route(frame, &mut streams, Some(&scheme)).await;
        assert_eq!(scheme.lock().unwrap().stop(), 1, "server scheme adopted");

        // A malformed scheme is ignored (keep the current one).
        let bad = Frame::new(
            Command::UpdatePaddingScheme,
            0,
            Bytes::from_static(b"garbage"),
        )
        .unwrap();
        route(bad, &mut streams, Some(&scheme)).await;
        assert_eq!(scheme.lock().unwrap().stop(), 1, "malformed update ignored");
    }

    #[tokio::test]
    async fn synack_error_closes_stream_but_success_ack_does_not() {
        let mut streams = HashMap::new();
        let (err_tx, _err_rx) = mpsc::channel(4);
        let (ok_tx, _ok_rx) = mpsc::channel(4);
        streams.insert(7u32, err_tx);
        streams.insert(8u32, ok_tx);

        // Non-empty SYNACK = the server's error → close the stream.
        let err = Frame::new(
            Command::SynAck,
            7,
            Bytes::from_static(b"connection refused"),
        )
        .unwrap();
        route(err, &mut streams, None).await;
        assert!(!streams.contains_key(&7), "error SYNACK closes the stream");

        // Empty SYNACK = success ack → keep the stream.
        route(Frame::control(Command::SynAck, 8), &mut streams, None).await;
        assert!(streams.contains_key(&8), "success SYNACK keeps the stream");
    }
}
