//! `spark-service` — the privileged tunnel process: owns the TUN/WinTun + routes, runs
//! `spark-core` in-process, and serves the unprivileged client over `spark-ipc`. The data
//! plane never crosses the control channel.
//!
//! **Session 2 (this commit) is the no-root core:** the peer-authorization policy ([`auth`]),
//! the channels-over-locks event loop ([`service`]), and the transport-generic framed serve
//! loop ([`conn`]) — all exercised hermetically over an in-memory duplex. The privileged/live
//! wiring is deferred (it needs root): the `UnixListener` accept loop + `SO_PEERCRED`
//! extraction, the real [`engine::TunnelEngine`] that brings up the device and runs the core,
//! privilege drop, supervision, and fail-open route-restore. See
//! `docs/process-architecture-and-ipc.md` and the `ipc-service-split-design-m7` decision.

pub mod auth;
pub mod conn;
pub mod engine;
pub mod listener;
pub mod service;

pub use auth::{AuthPolicy, PeerCreds};
pub use conn::serve_connection;
pub use engine::{CoreEngine, EngineError, TunnelEngine};
pub use listener::serve;
pub use service::{channel, run_service, Envelope};
