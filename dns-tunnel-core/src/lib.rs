//! `dns-tunnel-core` — the shared, no-I/O core of spark's DNS-tunnel transport (ADR 0011).
//!
//! A clean-slate DNS-tunnelling protocol inspired by MasterDnsVPN's architecture but not
//! wire-compatible with it, dnstt, or Slipstream. This crate holds every correctness-critical,
//! network-agnostic piece so it can be reused verbatim by both the spark client transport
//! (`core/src/transport/dns_tunnel/`, behind the `dns-tunnel` feature) and the `dns-tunnel-server`
//! binary, and so it can be exhaustively unit- and fuzz-tested with no async runtime in the way.
//!
//! **This crate never does I/O**: no `tokio`, no sockets. It transforms bytes and drives state
//! machines; the caller owns the DNS UDP sockets, the resolver pool, and the timers.
//!
//! Planned modules (added milestone-by-milestone per `docs/dns-tunnel-plan.md`):
//! - `crypto`   — PSK decode, HKDF-SHA256 key schedule, `ring` AEAD wrappers, secure random.
//! - `frame`    — the compact binary frame header (version/flags/ConnectionID/StreamID/seq/…) + seal/open.
//! - `dns`      — DNS TXT query/answer build + parse, QNAME base32 label packing, EDNS0 OPT.
//! - `compress` — optional LZ4 payload compression (compress-if-smaller, threshold, bomb cap).
//! - `mtu`      — payload ↔ QNAME-capacity math (base32 expansion + crypto overhead).
//! - `arq`      — the reliable per-stream state machine (seq/ack/nack/RTO/window/lifecycle).
//!
//! See `docs/dns-tunnel-design.md` for the full wire specification.

#![forbid(unsafe_code)]
