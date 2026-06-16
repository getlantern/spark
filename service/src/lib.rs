//! `spark-service` — the privileged tunnel process: owns the TUN/WinTun + routes, runs
//! `spark-core` in-process, and serves the unprivileged client over `spark-ipc`. The data
//! plane never crosses the control channel.
//!
//! The pieces: the peer-authorization policy ([`auth`]), the channels-over-locks event loop
//! ([`service`]), the transport-generic framed serve loop ([`conn`]), and the real
//! [`engine::TunnelEngine`] ([`engine::CoreEngine`]) that brings up the device, manages routes
//! (the kill-switch), and runs the core. The control transport is platform-specific: a
//! unix-domain socket with `SO_PEERCRED` auth + a `spark`-group socket DACL (the `listener`
//! module) on unix, an admin-only named pipe (the `pipe` module) on Windows — both feeding the
//! same serve loop.
//! See `docs/process-architecture-and-ipc.md` and the `ipc-service-split-design-m7` decision.

pub mod auth;
pub mod conn;
pub mod engine;
pub mod service;

// The control transport is platform-specific: a unix-domain socket (peer-cred auth + socket
// perms) on unix, a named pipe (admin-only DACL) on Windows. Both plug into the shared,
// transport-generic [`conn::serve_connection`]. `serve` resolves to the platform impl.
#[cfg(unix)]
pub mod groups;
#[cfg(unix)]
pub mod listener;
#[cfg(windows)]
pub mod pipe;

pub use auth::{AuthPolicy, PeerCreds};
pub use conn::serve_connection;
pub use engine::{CoreEngine, EngineError, Teardown, TunnelEngine};
pub use service::{channel, run_service, Envelope};

#[cfg(unix)]
pub use listener::serve;
#[cfg(windows)]
pub use pipe::serve;
