# CLAUDE.md — Standing Instructions (Censorship Circumvention Tool)

> This file is loaded automatically every session. It is the *how to write code here*
> reference. **Read order each session:** `docs/GOAL.md` (north star) → `docs/PLAN.md` §2
> (session protocol) → `docs/STATE.md` (current position) → the current milestone in
> `docs/PLAN.md` §4 → this file for code standards → `docs/tun-to-shadowsocks-design.md` and
> `docs/process-architecture-and-ipc.md` for architecture as needed. `PLAN.md` governs *what
> to build and how to pace it*. Work one bounded chunk per session and leave the tree green
> (see `docs/PLAN.md` §2).

You are building a from-scratch VPN/proxy tool that supports multiple censorship circumvention protocols. Performance and binary size are critical (target: <3 MB stripped). The deployment audience is end users in restrictive network environments, so reliability, fingerprint resistance, and minimal runtime overhead matter more than feature breadth.

Follow every constraint in this document. When a choice isn't covered here, ask before introducing new dependencies or architectural patterns.

## Tech Stack (locked)

- **Language**: Rust, edition 2021, MSRV 1.85 (current `netstack-smoltcp` → `smoltcp 0.12` needs ≥1.80, and `tun-rs` 2.8.x needs edition 2024 → ≥1.85; verified by spike)
- **Async runtime**: `tokio` (multi-thread scheduler, full features)
- **TLS**: `rustls` with the `ring` backend — NOT `native-tls`, NOT `openssl`
- **Crypto primitives**: `ring` (fallback: `aws-lc-rs` if a primitive is missing)
- **TUN interface**: `tun-rs` (cross-platform: Linux, macOS, Windows desktop/CLI)
- **Netstack (L3→L4)**: `netstack-smoltcp` — turns TUN IP packets into TCP streams +
  UDP datagrams. Do NOT hand-roll a smoltcp `Device` bridge; this crate does it.
  **VENDORED, not a crates.io dependency.** It is a ~1K-SLoC single-maintainer crate
  with a governance split across two GitHub repos, so we fork it into the workspace
  under `vendor/netstack-smoltcp/` and depend on it by `path`. This lets us bump
  `smoltcp` ourselves if upstream is slow, and it is part of our attack surface
  (it parses hostile packets) so it must be audited regardless. Pin `smoltcp`
  explicitly in the vendored `Cargo.toml`. Note the builder API differs across minor
  versions (`.mtu()` exists in 0.2.x, not 0.1.x); we target the 0.2.x API.
  Access the netstack ONLY through our own `Netstack`/`Flow` trait (see below) so the
  implementation can be swapped without touching the proxy core.
- **Buffers**: `bytes::Bytes` / `bytes::BytesMut` on every data path
- **Framing**: `tokio-util::codec`
- **Errors**: `thiserror` at module boundaries, `anyhow` only at the binary entry point
- **CLI**: `clap` with derive macros
- **Logging**: `tracing` + `tracing-subscriber` (env filter)
- **Config**: `serde` + `toml`
- **Control-plane IPC**: `serde` + `postcard` (compact binary) with length-prefixed framing,
  in a dedicated `ipc/` crate. This is for the **control channel only** (commands/status/
  logs) between the unprivileged client and the privileged tunnel process — see the
  process-architecture doc. JSON encoding allowed behind a `--debug-ipc` feature.

Do not add other dependencies without asking. In particular, never pull in `reqwest`, `hyper` (use raw rustls + tokio), or anything that transitively depends on `openssl-sys`.

## Cargo.toml Release Profile

```toml
[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
strip = true
panic = "abort"
overflow-checks = false
```

After each milestone, build with `cargo build --release` and report the binary size.

## Architecture Patterns (use these)

0. **Process model — data plane stays in-process.** Shipping desktop runs a privileged
   tunnel process (owns the TUN/WinTun + routes + the core) and an unprivileged client,
   connected by a **control-plane** channel only (commands/status/logs). **Packets never
   cross a process boundary** — the core runs in whichever process owns the OS tunnel
   primitive. For privilege separation, pass the tunnel **fd** once (Linux `SCM_RIGHTS`),
   never per-packet data. `core/` must stay process/IPC-agnostic; process/IPC concerns live
   in `service/`, `ipc/`, and `platforms/`. See process-architecture-and-ipc.md.

1. **Connection halves**: Use `TcpStream::into_split()` for owned independent read/write halves. Do NOT use `tokio::io::split()` — the owned variant is simpler to move into separate tasks and avoids the internal lock.

2. **Protocol state machines**: For protocol cores (handshakes, framing, obfuscation layers), prefer explicit `enum`-based state machines over deeply nested `async fn` flows. This avoids `Pin`/self-referential struct issues and makes state inspection trivial for debugging.

3. **Pluggable transports**: Define a trait like:
   ```rust
   #[async_trait::async_trait]
   pub trait Transport: Send + Sync {
       async fn dial(&self, target: Address) -> Result<BoxedStream>;
   }
   ```
   Use the `async-trait` crate for trait objects. If you want AFIT instead, fully understand the `Send`-bound implications first and document them.

4. **Buffer hygiene**: Allocate `BytesMut` with explicit capacity (e.g. `BytesMut::with_capacity(16 * 1024)`). Use `.freeze()` to hand off immutable `Bytes` to other tasks. Never `clone()` a `Vec<u8>` on the data path.

5. **Cancellation safety**: Inside `tokio::select!`, only call cancel-safe futures. `read_buf` is safe; `read_exact` is not. When you must call a non-cancel-safe future, wrap it in a `tokio::spawn`'d task with a oneshot for cancellation, or use `tokio::pin!` plus manual polling.

6. **Channels over locks**: For shared state between tasks, prefer `tokio::sync::mpsc` or actor-style ownership over `Arc<Mutex<T>>`. Locks are acceptable for short-lived, never-held-across-`.await` critical sections.

## Anti-Patterns (do not do these)

- Do NOT hold a `std::sync::MutexGuard` or `tokio::sync::MutexGuard` across an `.await` point.
- Do NOT use `unwrap()` or `expect()` outside of tests, build scripts, or one-shot startup code where panic is acceptable.
- Do NOT use `Vec<u8>` for buffers on hot paths.
- Do NOT use `tokio::spawn` without storing the `JoinHandle` somewhere that can cancel/await it, unless the task is genuinely fire-and-forget.
- Do NOT silently ignore errors. Every `Result` is either propagated with `?`, matched explicitly, or logged with rationale.
- Do NOT use `async-std`, `smol`, or any non-tokio runtime.
- Do NOT ship packets across a process boundary / over IPC. The data path is in-process;
  pass the tunnel fd or handle, not packet bytes.
- Do NOT run the UI/client with tunnel privileges, and do NOT trust an IPC peer just because
  it connected — authenticate it (peer creds / pipe DACL / XPC code-signing). See the
  process-architecture doc.
- Do NOT echo proxy secrets (PSKs/keys) back to clients over IPC; they live in the
  privileged store only.
- Do NOT use `String` where `&str` or `Cow<'_, str>` would do on hot paths.

## Code Style

- All public APIs have rustdoc comments with examples for non-trivial functions.
- One `Error` enum per module, derived with `thiserror`.
- Module layout: `tun`, `transport`, `proxy`, `crypto`, `config`, `cli`.
- Tests: unit tests inline (`#[cfg(test)] mod tests`), integration tests in `tests/`.
- `cargo clippy -- -D warnings` must pass clean.
- `cargo fmt` before every commit.

## Verification Discipline

You do not have reliable memory of crate APIs. Before writing code that uses a non-trivial API from `tokio`, `rustls`, `tun-rs`, `bytes`, or `ring`, you must either:
- State that you have verified the signature against current docs.rs, or
- Ask the user to confirm the API surface.

If you're guessing at a method name or signature, say so.

## Spike reference (for Milestone 0)

The M0 gate and steps are defined in PLAN.md §4. One code-standard note specific to the
provided artifact: a reference spike (`netstack-spike/`) already exercises the netstack
type assumptions, but it was verified against the **0.1.x API on rustc 1.75**. You must
re-verify against the **vendored 0.2.x source on ≥1.85**, and in particular confirm the
`.mtu()` builder call and the exact `build()` return tuple on that version. If anything
fails to compile, STOP and report the exact error and the version that caused it before
proceeding.

## Netstack Abstraction (write this in `core/`)

Wrap the vendored crate so the proxy core never imports `netstack_smoltcp` directly:

```rust
/// A surfaced L4 flow, independent of the netstack implementation.
pub struct TcpFlow {
    pub original_dst: SocketAddr,
    pub src: SocketAddr,
    pub stream: Box<dyn AsyncReadWrite + Unpin + Send>, // blanket-impl'd over AsyncRead+AsyncWrite
}

/// The netstack surface our proxy depends on. netstack-smoltcp is one impl.
#[async_trait::async_trait]
pub trait Netstack: Send {
    /// Yields accepted TCP flows. Backed by netstack-smoltcp's TcpListener stream.
    async fn accept_tcp(&mut self) -> Option<TcpFlow>;
    // UDP surface added when the UDP path is built.
}
```

This keeps a future swap to `ipstack`, a hand-rolled smoltcp bridge, or a newer netstack
to a single module.

## Milestones

The full milestone ladder (M0 toolchain gate → M1 TUN scaffold → M2 plain forwarder →
M3 SS client → M4 integrate → M5 UDP → M6 config/log-hygiene → M7 packaging → M8 Android →
M9 Apple → M10 more transports), with exact binary pass/fail gates and per-session scoping,
lives in **PLAN.md §4**. Do not duplicate or reorder it here. Find your current milestone in
STATE.md and execute one bounded chunk per the session protocol (PLAN.md §2).

Non-negotiable build order: prove the netstack pipeline with **no crypto** (M2) before
building the SS client in isolation (M3) before wiring them together (M4). Crypto bugs and
netstack bugs look identical from the outside; keep them separated until each is proven.

Ask before starting if anything in the locked stack or these standards conflicts with what
`tun-rs`/`netstack-smoltcp` actually support on the pinned toolchain.
