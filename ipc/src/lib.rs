//! `spark-ipc` — the control-plane IPC protocol crate (commands/status/logs between
//! the unprivileged client and the privileged tunnel service).
//!
//! Empty at M0 by design. The versioned `postcard` message protocol, length-prefixed
//! framing, and `Hello` handshake are built at M7 (see `docs/PLAN.md` and
//! `docs/process-architecture-and-ipc.md`). The data plane never crosses this channel.
