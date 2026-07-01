//! Fake-IP DNS subsystem (design:
//! `docs/superpowers/specs/2026-07-01-spark-smart-routing-ad-block-design.md`).
//!
//! The app's DNS already lands in-tunnel (Android `VpnService` / Apple NE point DNS at spark). Spark
//! answers each A/AAAA query with a **fake IP** from a reserved range (`198.18.0.0/15` + an IPv6
//! ULA), records `fakeip→domain`, and recovers the domain when the app then connects to that fake IP
//! — so the [`crate::rules`] router sees the domain even though the netstack only surfaces an IP.
//!
//! Pipeline: [`wire`] parses the query / builds the answer → `fakeip` allocates + maps (M4.2) →
//! `server` ties them together with a per-action resolver (M4.3+).

pub mod fakeip;
pub mod wire;
