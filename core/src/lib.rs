//! `spark-core` — the process- and IPC-agnostic proxy core.
//!
//! M0 pinned the vendored netstack. M1 added the TUN data-path foundation: an async
//! [`tun`] device abstraction and a minimal zero-copy IP [`packet`] inspector. M2 added
//! the [`netstack`] bridge (TUN ↔ userspace TCP/IP stack) and a plain [`proxy`] TCP
//! forwarder. M3 built the [`transport`] tunnel client in isolation; M4 wires it in behind
//! the [`transport::Transport`] trait so the forwarder dials either directly or through a
//! tunnel. See `docs/PLAN.md`.

use tokio::io::{AsyncRead, AsyncWrite};

pub mod netstack;
pub mod packet;
pub mod proxy;
pub mod transport;
pub mod tun;

/// Marker for a bidirectional async byte stream. Blanket-implemented for every
/// `AsyncRead + AsyncWrite`, so a surfaced netstack flow and a dialed transport stream can
/// share one boxed type ([`BoxedStream`]).
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// An owned, boxed bidirectional stream — the currency between netstack flows
/// ([`netstack::TcpFlow`]) and transports ([`transport::Transport::dial`]).
pub type BoxedStream = Box<dyn AsyncReadWrite + Unpin + Send>;
