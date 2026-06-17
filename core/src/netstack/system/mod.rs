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
//! - [`pump`] — the [`Gateway`](pump::Gateway): classify + rewrite each packet (app→listener,
//!   listener→app) and resolve accepted connections back to their original endpoints. **Built.**
//! - [`stack`] — [`SystemNetstack`]: the live wiring (TUN pump loop +
//!   kernel listener accept loop + reaper) implementing [`Netstack`](super::Netstack). **Built +
//!   live-gated; eliminates the concurrent-download collapse (see `docs/system-stack-design.md`).**
//! - `[tun] stack = "system"` config knob + selection in [`build`](super::build). **Built.**
//! - NAT lifecycle (FIN/RST removal) + the **mixed stack** (UDP via the proxy's datagram path, so
//!   DNS works). **Built.** Remaining: pump parallelism / GSO for single-stream peak; IPv6.
//!
//! Feature-gated behind `system-stack` (off by default). Works wherever there's a Linux/macOS-style
//! tun fd — Linux, macOS, and Android via `VpnService` (sing-box runs `stack: system` on Android the
//! same way); not iOS (`NEPacketTunnelFlow`, no kernel tun). The proxy core
//! and transports are untouched: a system-stack flow is a kernel `TcpStream` surfaced as the same
//! [`TcpFlow`](super::TcpFlow).
//!
//! [`TcpFlow`]: super::TcpFlow
//! [`TcpNat`]: nat::TcpNat

pub mod nat;
pub mod pump;
pub mod rewrite;
pub mod stack;

pub use stack::SystemNetstack;
