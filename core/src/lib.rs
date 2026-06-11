//! `spark-core` — the process- and IPC-agnostic proxy core.
//!
//! M0 pinned the vendored netstack. M1 added the TUN data-path foundation: an async
//! [`tun`] device abstraction and a minimal zero-copy IP [`packet`] inspector. M2 adds
//! the [`netstack`] bridge (TUN ↔ userspace TCP/IP stack) and a plain [`proxy`] TCP
//! forwarder that dials the original destination directly. The tunnel transport lands
//! in later milestones (see `docs/PLAN.md`).

pub mod netstack;
pub mod packet;
pub mod proxy;
pub mod transport;
pub mod tun;
