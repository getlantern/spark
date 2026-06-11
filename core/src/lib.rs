//! `spark-core` — the process- and IPC-agnostic proxy core.
//!
//! M0 pinned the vendored netstack. M1 adds the TUN data-path foundation: an async
//! [`tun`] device abstraction and a minimal zero-copy IP [`packet`] inspector (enough
//! to log flows and answer ICMP echo). The netstack, transport, and proxy modules land
//! in later milestones (see `docs/PLAN.md`).

pub mod packet;
pub mod tun;
