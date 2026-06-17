//! The **system (kernel-TCP) netstack** — a second [`Netstack`](super::Netstack) implementation in
//! which the host kernel owns the TCP state machine, as an alternative to the userspace
//! [`SmoltcpNetstack`](super::SmoltcpNetstack). It is what sing-box calls `stack = system`.
//!
//! Instead of terminating TCP in userspace (smoltcp), it runs a **NAT redirect gateway**: a local
//! kernel TCP listener on the tun's address, plus an in-place rewrite of every TUN packet's TCP
//! 4-tuple so the kernel routes each application connection to that listener and its replies back.
//! `accept()` then yields a real kernel `TcpStream` per flow — naturally parallel, with kernel
//! congestion control and offloads, and none of the single-poll-loop multi-flow collapse the
//! userspace path exhibits (see `bench/`, `docs/system-stack-design.md` §9).
//!
//! ## Status (built incrementally)
//! - [`nat`] — the source⇄natPort [`TcpNat`] table. **Built.**
//! - [`rewrite`] — in-place TCP/IP header rewrite + checksum recompute. **Built.**
//! - The pump (TUN read → classify → rewrite → write), the accept loop (listener → [`TcpFlow`]),
//!   the idle reaper, and the [`Netstack`] impl — *next chunks*.
//!
//! Feature-gated behind `system-stack` (off by default; desktop-only — Linux/macOS). The proxy core
//! and transports are untouched: a system-stack flow is a kernel `TcpStream` surfaced as the same
//! [`TcpFlow`](super::TcpFlow).
//!
//! [`TcpFlow`]: super::TcpFlow
//! [`TcpNat`]: nat::TcpNat

pub mod nat;
pub mod rewrite;
