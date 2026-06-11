//! `spark-core` — the process- and IPC-agnostic proxy core.
//!
//! At M0 this crate only pins the vendored netstack as a `path` dependency and
//! carries the [`examples/netstack_smoke`](../examples/netstack_smoke.rs) gate that
//! proves the netstack composes on the real toolchain. The TUN, packet-parser,
//! netstack, transport, and proxy modules land in later milestones (see
//! `docs/PLAN.md`); the public surface is intentionally empty until M1.
