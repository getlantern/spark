# Multi-Server Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a spark config carry a **pool of servers**; spark probes each (handshake latency + a callback-URL health check *through* the transport), routes new flows through the lowest-latency healthy one, fails over on error, and periodically re-probes (in bounded batches) to track the best.

**Architecture:** A new `SelectingTransport` in `spark-core` *is* the `Arc<dyn Transport>`/`Arc<dyn UdpTransport>` the forwarder already holds; it owns the built pool + an atomically-read current-best (short `std::sync::Mutex`, never held across `.await`) + a background prober task (aborted on drop). `from_config` returns it when `[[transport.servers]]` is set, else the unchanged single-transport path. flint-dial gains `probe_windowed` (bounded-concurrency collect-all-and-rank, sibling of `race_windowed`).

**Tech Stack:** Rust 2021 (MSRV 1.85), tokio, `async-trait`, `serde`/`toml`, `flint-dial`; HTTPS health check reuses the `boring` backend already linked by `anytls` (no `rustls` added to base — protects the <3 MB budget). Spec: `docs/multi-server-selection-design.md`.

**Worktree:** spark work is in a dedicated worktree on branch `multi-server-selection` (`<spark>` below = that root). The flint change is in a separate worktree/branch of `getlantern/flint` (`<flint>`). `cargo` is at `~/.cargo/bin/cargo` if not on PATH. The spark *main checkout* is a different working tree — never edit it.

---

## File Structure

- Modify: `<flint>/crates/flint-dial/src/race.rs` — add `probe_windowed`; `<flint>/crates/flint-dial/src/lib.rs` — re-export it.
- Modify: `<spark>/core/Cargo.toml` — bump flint rev (after flint lands); add a `multi-server` feature that pulls `flint-dial` (and gates the pool path so the base build is unaffected); `cli`/`service` Cargo.toml forward it.
- Modify: `<spark>/core/src/config/mod.rs` — `ServerSpec`/`ServerEntry`, `transport.servers`, `transport.callback_url`, `transport.probe_interval_secs`, `transport.probe_window`; `TunnelConfig` for the plain kind.
- Create: `<spark>/core/src/transport/probe.rs` — `CallbackUrl` parse + `HealthClient` (HTTP/1.1 over the transport stream; boring TLS for https behind `anytls`) + `probe()`.
- Create: `<spark>/core/src/transport/select.rs` — `SelectingTransport` + the prober.
- Modify: `<spark>/core/src/transport/mod.rs` — extract `build_one`; `from_config` returns `SelectingTransport` for a pool; declare the new modules.
- Modify: `<spark>/core/src/bootstrap/mod.rs` — extend `resolve_endpoints` to iterate pool entries' `(server, sni)`.

---

## Phase A — flint: `probe_windowed`

### Task A1: add `probe_windowed` to flint-dial

**Files:**
- Modify: `<flint>/crates/flint-dial/src/race.rs`
- Modify: `<flint>/crates/flint-dial/src/lib.rs`

- [ ] **Step 1: Write the failing tests.** Add inside the existing `mod tests` block in `crates/flint-dial/src/race.rs`:

```rust
    #[tokio::test]
    async fn probe_windowed_returns_all_results_with_indices() {
        // 6 probes, window 2; each returns its index doubled. All 6 results come back, indexed.
        let mut got = probe_windowed(6, 2, |i| async move { i * 10 }).await;
        got.sort_by_key(|(i, _)| *i);
        assert_eq!(got, vec![(0, 0), (1, 10), (2, 20), (3, 30), (4, 40), (5, 50)]);
    }

    #[tokio::test]
    async fn probe_windowed_never_exceeds_the_window() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let inflight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let got = probe_windowed(10, 3, |_| {
            let inflight = Arc::clone(&inflight);
            let max_seen = Arc::clone(&max_seen);
            async move {
                let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(5)).await;
                inflight.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;
        assert_eq!(got.len(), 10);
        assert!(max_seen.load(Ordering::SeqCst) <= 3, "max in flight {} > window", max_seen.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn probe_windowed_empty_is_empty() {
        let got: Vec<(usize, i32)> = probe_windowed(0, 4, |_| async move { 0 }).await;
        assert!(got.is_empty());
    }

    #[test]
    fn probe_windowed_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        assert_send(probe_windowed(1, 1, |_| async { 0i32 }));
    }
```

- [ ] **Step 2: Run to verify they fail.** Run: `cd <flint> && cargo test -p flint-dial probe_windowed`. Expected: FAIL — `cannot find function probe_windowed`.

- [ ] **Step 3: Implement `probe_windowed`.** Add to `crates/flint-dial/src/race.rs` (after `race_windowed`). Note: this collects **all** results (it does not short-circuit on `Ok`), and the probe closure returns a plain value `T` (not a `Result`) — health/latency are encoded *in* `T`. Single push site keeps the future `Send` with no boxing (same lesson as `race_windowed`):

```rust
/// Run all `count` probes with at most `window` in flight, refilling as each finishes, and return
/// **every** result paired with its index (unlike [`race_windowed`], which returns only the first
/// `Ok`). Order of the returned vec is completion order; sort by index if you need positional order.
/// `window` is clamped to at least 1; `count == 0` yields an empty vec. Used to probe a server pool
/// in bounded batches and rank the results.
pub async fn probe_windowed<F, Fut, T>(count: usize, window: usize, mut probe_one: F) -> Vec<(usize, T)>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = T>,
{
    let window = window.max(1);
    let mut set = FuturesUnordered::new();
    let mut next = 0;
    let mut out = Vec::with_capacity(count);
    loop {
        while next < count && set.len() < window {
            let i = next;
            next += 1;
            let fut = probe_one(i);
            set.push(async move { (i, fut.await) });
        }
        match set.next().await {
            Some(result) => out.push(result),
            None => return out,
        }
    }
}
```

- [ ] **Step 4: Re-export from the crate root.** In `crates/flint-dial/src/lib.rs`, find the line re-exporting `race_windowed` (e.g. `pub use race::{race, race_with, race_windowed};`) and add `probe_windowed` to it: `pub use race::{probe_windowed, race, race_with, race_windowed};`.

- [ ] **Step 5: Run + lint + commit.**

```bash
cd <flint>
cargo test -p flint-dial
cargo clippy -p flint-dial -- -D warnings
cargo fmt
git add crates/flint-dial/src/race.rs crates/flint-dial/src/lib.rs
git commit -m "feat(flint-dial): probe_windowed — bounded-concurrency collect-all-and-rank"
```
Expected: all flint-dial tests pass (existing + 4 new `probe_windowed_*`); clippy/fmt clean.

### Task A2: publish flint + bump spark's pin

**Files:** `<spark>/core/Cargo.toml`

- [ ] **Step 1: Push flint and capture the rev.**
```bash
cd <flint>
git push -u origin multi-server-flint   # push the branch you did A1 on (create it if needed)
git rev-parse HEAD                        # record as <FLINTREV>
```
(If A1 was committed directly on a branch you already pushed, just `git push` and `git rev-parse HEAD`.) Open a flint PR for the change.

- [ ] **Step 2: Bump all five flint pins in spark.** In `<spark>/core/Cargo.toml`, replace every occurrence of the current flint rev `40733ff63045b9952fa2b64f91aab56bfe1c5691` with `<FLINTREV>` (the `flint-shaping`, `flint-tls`, `flint-verify`, `flint-dial`, `flint-dns` lines — **all five must stay on one rev**).

- [ ] **Step 3: Verify one rev + build.**
```bash
cd <spark>
cargo build -p spark-core
cargo build -p spark-core --features bootstrap-dns
cargo tree -p spark-core --features bootstrap-dns -i flint-shaping   # single node
```
Expected: builds succeed; one `flint-shaping` node.

- [ ] **Step 4: Commit.**
```bash
git add core/Cargo.toml Cargo.lock
git commit -m "build(core): bump flint to <FLINTREV> (probe_windowed)"
```

---

## Phase B — config: the server pool

### Task B1: `ServerSpec` + `TunnelConfig`

**Files:** `<spark>/core/src/config/mod.rs`

- [ ] **Step 1: Write the failing test.** Add to the `#[cfg(test)] mod tests` block in `core/src/config/mod.rs`:

```rust
    #[test]
    fn server_spec_parses_each_kind() {
        // internally-tagged by `kind`, flat fields.
        let anytls: ServerSpec = toml::from_str("kind = \"anytls\"\nserver = \"1.2.3.4:443\"\npassword = \"pw\"\n").unwrap();
        assert!(matches!(anytls, ServerSpec::Anytls(_)));
        let tunnel: ServerSpec = toml::from_str("kind = \"tunnel\"\nserver = \"5.6.7.8:443\"\n").unwrap();
        assert!(matches!(tunnel, ServerSpec::Tunnel(_)));
        // unknown kind is rejected.
        assert!(toml::from_str::<ServerSpec>("kind = \"bogus\"\n").is_err());
    }
```

- [ ] **Step 2: Run to verify it fails.** Run: `cd <spark> && cargo test -p spark-core server_spec_parses`. Expected: FAIL — `cannot find type ServerSpec`.

- [ ] **Step 3: Define `TunnelConfig` + `ServerSpec`.** In `core/src/config/mod.rs`, add near the other transport config structs:

```rust
/// The plain `tcp_tunnel` client kind for a pool entry — a tunnel server addressed by `server`,
/// with no extra mimicry (mirrors the legacy top-level `transport.server`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    /// The tunnel server address — `IP:port` or `host:port` (resolved at startup).
    pub server: Endpoint,
    /// TLS SNI is not applicable to the plain tunnel; present for symmetry, currently unused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

/// One transport kind in a server pool, internally tagged by `kind` with the kind's fields flat
/// alongside it (e.g. `kind = "anytls"`, `server = ...`, `password = ...`). Wraps the existing
/// per-kind config structs so a pool entry is configured exactly like a single transport.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ServerSpec {
    /// AnyTLS-over-boring (ADR 0001).
    Anytls(AnytlsConfig),
    /// Samizdat (ADR 0007).
    Samizdat(SamizdatConfig),
    /// Dynamic wasm transport (ADR 0003).
    Wasm(WasmConfig),
    /// Plain `tcp_tunnel` client.
    Tunnel(TunnelConfig),
}
```

> **Verify (serde/toml):** `#[serde(tag = "kind")]` internally-tagged enums with flat variant fields are supported by the `toml` crate in use here; the Step-1 test confirms it. `deny_unknown_fields` is intentionally **not** on `ServerSpec` (serde forbids it with internal tagging). If the Step-1 test surprisingly fails to deserialize, STOP and report — the fallback is an explicit `kind: ServerKind` field + per-kind `Option<...>` rather than redesigning silently.

- [ ] **Step 4: Run to verify it passes.** Run: `cd <spark> && cargo test -p spark-core server_spec_parses`. Expected: PASS. (Don't run `clippy -D warnings` yet — `ServerSpec`/`TunnelConfig` are unused until Task B2; warnings are expected and don't fail `cargo test`.)

- [ ] **Step 5: Commit.**
```bash
git add core/src/config/mod.rs
git commit -m "feat(config): ServerSpec tagged enum + TunnelConfig for the server pool"
```

### Task B2: `ServerEntry` + pool fields on `TransportConfig`

**Files:** `<spark>/core/src/config/mod.rs`

- [ ] **Step 1: Write the failing test.** Add to the `mod tests` block:

```rust
    #[test]
    fn parses_a_server_pool_with_callbacks_and_knobs() {
        let c = Config::from_toml_str(
            r#"
            [transport]
            callback_url = "https://canary.example/generate_204"
            probe_interval_secs = 120
            probe_window = 4

            [[transport.servers]]
            kind = "anytls"
            server = "proxy-a.example.com:443"
            password = "pw"

            [[transport.servers]]
            kind = "samizdat"
            server = "203.0.113.7:443"
            server_pubkey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            short_id = "1011121314151617"
            callback_url = "https://other.example/ok"
            "#,
        )
        .unwrap();
        assert_eq!(c.transport.callback_url.as_deref(), Some("https://canary.example/generate_204"));
        assert_eq!(c.transport.probe_interval_secs, 120);
        assert_eq!(c.transport.probe_window, 4);
        let servers = &c.transport.servers;
        assert_eq!(servers.len(), 2);
        assert!(matches!(servers[0].spec, ServerSpec::Anytls(_)));
        assert_eq!(servers[0].callback_url, None); // falls back to the global default
        assert_eq!(servers[1].callback_url.as_deref(), Some("https://other.example/ok"));
    }

    #[test]
    fn pool_defaults_when_absent() {
        let c = Config::default();
        assert!(c.transport.servers.is_empty());
        assert_eq!(c.transport.probe_interval_secs, 300);
        assert_eq!(c.transport.probe_window, 8);
        assert_eq!(c.transport.callback_url, None);
    }
```

- [ ] **Step 2: Run to verify it fails.** Run: `cd <spark> && cargo test -p spark-core server_pool`. Expected: FAIL — no field `servers`/`callback_url`/`probe_interval_secs` on `TransportConfig`.

- [ ] **Step 3: Add `ServerEntry` + the fields.** In `core/src/config/mod.rs`, add the `ServerEntry` struct (after `ServerSpec`):

```rust
/// One server in the pool: a transport spec plus an optional per-entry callback override (falls back
/// to `transport.callback_url`). `#[serde(flatten)]` puts the spec's `kind` + fields and the
/// `callback_url` at the same TOML level. (`deny_unknown_fields` is incompatible with `flatten`.)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ServerEntry {
    /// The transport kind + its config.
    #[serde(flatten)]
    pub spec: ServerSpec,
    /// Per-entry health-check URL; overrides `transport.callback_url` when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}
```

Then add these fields to `TransportConfig` (alongside `shaping`):

```rust
    /// A pool of servers to probe and select among by latency (see
    /// `docs/multi-server-selection-design.md`). When non-empty, supersedes the single-transport
    /// fields above; spark builds a latency-selecting transport over the pool. Empty = the legacy
    /// single-transport path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<ServerEntry>,
    /// Default health-check URL fetched *through* each server to confirm it works end-to-end
    /// (per-entry `callback_url` overrides). Required when `servers` is non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    /// Seconds between full pool re-probes.
    pub probe_interval_secs: u64,
    /// Max probes in flight at once (bounded concurrency for large pools).
    pub probe_window: usize,
```

`TransportConfig` has a `#[serde(default)]` derive at the struct level, so add a `Default` impl (or, since the struct already derives `Default`, give the new non-`Option` fields their defaults via a manual `Default`). **Replace** `TransportConfig`'s `#[derive(... Default ...)]` with a manual impl if needed:

```rust
impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            server: None,
            protect_interface: None,
            anytls: None,
            wasm: None,
            samizdat: None,
            shaping: ShapingConfig::default(),
            servers: Vec::new(),
            callback_url: None,
            probe_interval_secs: 300,
            probe_window: 8,
        }
    }
}
```

(Remove `Default` from the `#[derive(...)]` on `TransportConfig` when adding this manual impl. Keep `#[serde(default, deny_unknown_fields)]` on the struct.)

- [ ] **Step 4: Run to verify it passes.** Run: `cd <spark> && cargo test -p spark-core server_pool && cargo test -p spark-core pool_defaults`. Expected: PASS. Confirm the existing config tests still pass: `cargo test -p spark-core config::`.

- [ ] **Step 5: Commit.**
```bash
git add core/src/config/mod.rs
git commit -m "feat(config): transport.servers pool + callback_url + probe knobs"
```

---

## Phase C — `build_one` extraction (refactor, behavior-preserving)

### Task C1: extract `build_one` and route `from_config` through it

**Files:** `<spark>/core/src/transport/mod.rs`

- [ ] **Step 1: Confirm the safety net.** Run: `cd <spark> && cargo test -p spark-core --features anytls,samizdat,wasm-transport`. Expected: PASS (record the count). This refactor must keep these green — no new test; the existing `from_config`/transport tests are the spec.

- [ ] **Step 2: Add `build_one` and call it from the single-transport path.** In `core/src/transport/mod.rs`, add a `build_one` that maps a `ServerSpec` (+ cloned protector + wire) to a built pair, reusing the existing per-kind fns. Place it just above `from_config`:

```rust
/// Build one server entry's transport pair from its [`ServerSpec`]. The single seam for transport
/// kinds — adding a kind is a new `ServerSpec` variant + a match arm here. `protector` is cloned per
/// entry (it is `Clone`); `wire` is the shared opening-shaping plan.
pub(crate) fn build_one(
    spec: &crate::config::ServerSpec,
    protector: Option<&SocketProtector>,
    wire: &WirePlan,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    use crate::config::ServerSpec;
    match spec {
        ServerSpec::Anytls(cfg) => anytls_transport(cfg, protector.cloned(), wire.clone()),
        ServerSpec::Samizdat(cfg) => samizdat_transport(cfg, protector.cloned(), wire.clone()),
        ServerSpec::Wasm(cfg) => wasm_transport(cfg, protector.cloned()),
        ServerSpec::Tunnel(cfg) => {
            let server = cfg.server.socket_addr()?;
            let mut client = tcp_tunnel::client::TunnelClient::new(server);
            if let Some(p) = protector.cloned() {
                client = client.with_socket_protection(p);
            }
            let client = Arc::new(client);
            Ok((
                client.clone() as Arc<dyn Transport>,
                client as Arc<dyn UdpTransport>,
            ))
        }
    }
}
```

> This requires `WirePlan: Clone`. **Verify** `WirePlan` derives `Clone` (it is a small data-only shaping plan); if not, add `#[derive(Clone)]` to it in `transport/shaping` (it holds only `Vec`/numbers). The per-kind `*_transport` fns already take `Option<SocketProtector>`/`WirePlan` by value, matching `protector.cloned()`/`wire.clone()`.

- [ ] **Step 3: Build with each feature set to confirm `build_one` compiles for every arm.** Run:
```bash
cd <spark>
cargo build -p spark-core
cargo build -p spark-core --features anytls,samizdat,wasm-transport
```
Expected: PASS. (`build_one` is `pub(crate)` and currently unused outside tests → an unused-function warning under base is fine here; it's used in Phase E. Don't gate on `clippy -D warnings` yet.)

- [ ] **Step 4: Commit.**
```bash
git add core/src/transport/mod.rs
git commit -m "refactor(transport): extract build_one (per-kind build seam) for the pool"
```

---

## Phase D — the health probe

### Task D1: `CallbackUrl` parsing

**Files:** Create `<spark>/core/src/transport/probe.rs`; modify `core/src/transport/mod.rs` (declare module).

- [ ] **Step 1: Declare the module.** In `core/src/transport/mod.rs`, add near the other `pub mod` lines: `pub mod probe;`

- [ ] **Step 2: Write the failing test.** Create `core/src/transport/probe.rs` with the parser and its test:

```rust
//! Health probe for multi-server selection (design: `docs/multi-server-selection-design.md`):
//! time a transport's establish + verify it works end-to-end by fetching a callback URL *through*
//! it (2xx = healthy). The HTTP client is hand-rolled (no `hyper`/`reqwest`); HTTPS reuses the
//! `boring` backend linked by `anytls` (the callback TLS rides inside the tunnel, so no mimicry).

use std::io;

/// A minimally-parsed callback URL: `{scheme}://{host}[:{port}]{path}`. Hand-parsed (no `url` crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackUrl {
    /// `true` for `https://` (TLS), `false` for `http://`.
    pub tls: bool,
    /// Host to dial through the transport.
    pub host: String,
    /// Port (defaults: 443 for https, 80 for http).
    pub port: u16,
    /// Request path (includes leading `/`; `/` if none).
    pub path: String,
}

impl CallbackUrl {
    /// Parse `http(s)://host[:port]/path`. Errors on any other scheme or a malformed authority.
    pub fn parse(s: &str) -> io::Result<Self> {
        let (scheme, rest) = s.split_once("://").ok_or_else(|| io::Error::other(format!("callback url missing scheme: {s}")))?;
        let (tls, default_port) = match scheme {
            "https" => (true, 443),
            "http" => (false, 80),
            other => return Err(io::Error::other(format!("unsupported callback scheme `{other}`"))),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(io::Error::other(format!("callback url missing host: {s}")));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse::<u16>().map_err(|_| io::Error::other(format!("bad callback port: {authority}")))?),
            None => (authority.to_owned(), default_port),
        };
        if host.is_empty() {
            return Err(io::Error::other(format!("callback url missing host: {s}")));
        }
        Ok(CallbackUrl { tls, host, port, path: path.to_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_callback_urls() {
        let u = CallbackUrl::parse("https://canary.example/generate_204").unwrap();
        assert_eq!(u, CallbackUrl { tls: true, host: "canary.example".into(), port: 443, path: "/generate_204".into() });
        let u = CallbackUrl::parse("http://1.2.3.4:8080/ok").unwrap();
        assert_eq!(u, CallbackUrl { tls: false, host: "1.2.3.4".into(), port: 8080, path: "/ok".into() });
        let u = CallbackUrl::parse("https://h.example").unwrap();
        assert_eq!(u.path, "/");
        assert!(CallbackUrl::parse("ftp://h/x").is_err());
        assert!(CallbackUrl::parse("notaurl").is_err());
        assert!(CallbackUrl::parse("https://:443/x").is_err());
    }
}
```

- [ ] **Step 3: Run to verify it passes** (the parser + test land together). Run: `cd <spark> && cargo test -p spark-core probe::tests::parses_callback_urls`. Expected: PASS.

- [ ] **Step 4: Commit.**
```bash
git add core/src/transport/mod.rs core/src/transport/probe.rs
git commit -m "feat(transport): CallbackUrl parser for the health probe"
```

### Task D2: HTTP/1.1 status reader over a stream

**Files:** `<spark>/core/src/transport/probe.rs`

- [ ] **Step 1: Write the failing test** (against an in-memory duplex stream — no network). Add to `probe.rs`'s `mod tests`:

```rust
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn http_get_reads_2xx_and_sends_request() {
        // A fake server on one end of a duplex pipe: read the request, assert it's a well-formed GET,
        // reply 204. http_get_ok should return true.
        let (client, mut server) = tokio::io::duplex(4096);
        let url = CallbackUrl { tls: false, host: "h.example".into(), port: 80, path: "/ok".into() };
        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            server.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            req
        });
        let ok = http_get_ok(client, &url).await.unwrap();
        assert!(ok);
        let req = server_task.await.unwrap();
        assert!(req.starts_with("GET /ok HTTP/1.1\r\n"), "req was: {req}");
        assert!(req.contains("Host: h.example\r\n"));
    }

    #[tokio::test]
    async fn http_get_rejects_non_2xx() {
        let (client, mut server) = tokio::io::duplex(4096);
        let url = CallbackUrl { tls: false, host: "h.example".into(), port: 80, path: "/".into() };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        assert!(!http_get_ok(client, &url).await.unwrap());
    }
```

- [ ] **Step 2: Run to verify it fails.** Run: `cd <spark> && cargo test -p spark-core probe::tests::http_get`. Expected: FAIL — `cannot find function http_get_ok`.

- [ ] **Step 3: Implement `http_get_ok`.** Add to `probe.rs`. It writes a minimal GET and reads just the status line, returning `healthy = 2xx`. Generic over any `AsyncRead + AsyncWrite` (so it works over a plain transport stream *or* a TLS-wrapped one):

```rust
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Send `GET {path}` over `stream`, read the status line, and return `true` iff the status is 2xx.
/// `Connection: close` so the server ends the body; we only parse the status line.
pub(crate) async fn http_get_ok<S>(mut stream: S, url: &CallbackUrl) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: spark-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path, url.host
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    // Read up to the end of the status line (first CRLF). Bounded read so a hostile server can't
    // make us read forever; the caller also wraps the whole probe in a deadline.
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while buf.len() < 256 {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            break;
        }
    }
    // Status line: "HTTP/1.1 204 ...". Parse the 3-digit code.
    let line = String::from_utf8_lossy(&buf);
    let code = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("malformed HTTP status line: {line:?}")))?;
    Ok((200..300).contains(&code))
}
```

- [ ] **Step 4: Run to verify it passes.** Run: `cd <spark> && cargo test -p spark-core probe::tests::http_get`. Expected: PASS (both tests).

- [ ] **Step 5: Commit.**
```bash
git add core/src/transport/probe.rs
git commit -m "feat(transport): minimal HTTP/1.1 status reader for the health probe"
```

### Task D3: `probe()` — dial through the transport, time + health-check

**Files:** `<spark>/core/src/transport/probe.rs`; `core/Cargo.toml` (tokio-boring2 already optional under `anytls`).

- [ ] **Step 1: Write the failing test** (fake `Transport` returning a scripted stream; no network). Add to `probe.rs`'s `mod tests`:

```rust
    use crate::transport::{Transport, BoxedStream};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use async_trait::async_trait;

    // A fake transport whose dial yields one end of a duplex pipe; a paired task plays the HTTP server.
    struct FakeTransport { status: &'static [u8] }
    #[async_trait]
    impl Transport for FakeTransport {
        async fn dial(&self, _t: SocketAddr) -> io::Result<BoxedStream> {
            let (client, mut server) = tokio::io::duplex(4096);
            let status = self.status;
            tokio::spawn(async move {
                let mut b = vec![0u8; 1024];
                let _ = server.read(&mut b).await;
                let _ = server.write_all(status).await;
            });
            Ok(Box::new(client))
        }
    }

    #[tokio::test]
    async fn probe_healthy_on_2xx_with_latency() {
        let t: Arc<dyn Transport> = Arc::new(FakeTransport { status: b"HTTP/1.1 204 No Content\r\n\r\n" });
        let url = CallbackUrl { tls: false, host: "h".into(), port: 80, path: "/".into() };
        let out = probe(&t, &url, Duration::from_secs(5)).await;
        assert!(out.healthy);
    }

    #[tokio::test]
    async fn probe_unhealthy_on_non_2xx() {
        let t: Arc<dyn Transport> = Arc::new(FakeTransport { status: b"HTTP/1.1 500 Err\r\n\r\n" });
        let url = CallbackUrl { tls: false, host: "h".into(), port: 80, path: "/".into() };
        assert!(!probe(&t, &url, Duration::from_secs(5)).await.healthy);
    }
```

- [ ] **Step 2: Run to verify it fails.** Run: `cd <spark> && cargo test -p spark-core probe::tests::probe_`. Expected: FAIL — `cannot find function probe` / `ProbeOutcome`.

- [ ] **Step 3: Implement `ProbeOutcome` + `probe` + the TLS split.** Add to `probe.rs`:

```rust
use std::sync::Arc;
use std::time::{Duration, Instant};
use crate::transport::Transport;

/// Result of probing one server.
#[derive(Debug, Clone, Copy)]
pub struct ProbeOutcome {
    /// Time to establish + complete the callback (only meaningful when `healthy`).
    pub latency: Duration,
    /// `true` iff the callback returned 2xx within the deadline.
    pub healthy: bool,
}

impl ProbeOutcome {
    fn unhealthy() -> Self {
        ProbeOutcome { latency: Duration::MAX, healthy: false }
    }
}

/// Probe one transport: dial the callback host through it (timing establish), run the HTTP GET, and
/// report health + latency. The whole attempt is bounded by `deadline`. Never panics; any error ⇒
/// unhealthy (disqualified from ranking).
pub async fn probe(transport: &Arc<dyn Transport>, url: &CallbackUrl, deadline: Duration) -> ProbeOutcome {
    let started = Instant::now();
    let result = tokio::time::timeout(deadline, probe_inner(transport, url)).await;
    match result {
        Ok(Ok(true)) => ProbeOutcome { latency: started.elapsed(), healthy: true },
        _ => ProbeOutcome::unhealthy(),
    }
}

async fn probe_inner(transport: &Arc<dyn Transport>, url: &CallbackUrl) -> io::Result<bool> {
    let target = resolve_callback_addr(&url.host, url.port).await?;
    let stream = transport.dial(target).await?;
    if url.tls {
        let tls = tls_wrap(stream, &url.host).await?;
        http_get_ok(tls, url).await
    } else {
        http_get_ok(stream, url).await
    }
}

/// Resolve a callback host to a dial address: an IP literal is used directly; a hostname is resolved
/// via the local resolver. The original `url.host` is kept for the TLS SNI + `Host:` header.
async fn resolve_callback_addr(host: &str, port: u16) -> io::Result<std::net::SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("callback host `{host}` resolved to no addresses")))
}
```

> **Callback host resolution:** `Transport::dial` takes a `SocketAddr`, so a hostname callback (the common case, e.g. `https://canary.example/...`) is resolved via the local resolver before dialing, keeping `url.host` for the TLS SNI + `Host:` header. (An earlier draft required an IP-literal host; that was wrong — the config/docs/tests all use hostnames, so it would have made every probe fail. Local resolution of a public canary is fine for a health check; a poisoned/missing record just marks the server unhealthy that round.)

- [ ] **Step 4: Implement `tls_wrap` (boring, behind `anytls`; clear error otherwise).** Add to `probe.rs`:

```rust
/// Wrap `stream` in client TLS for the callback host. Reuses the boring backend linked by `anytls`
/// (the callback TLS rides inside the tunnel, so a plain connector — no Chrome mimicry — is fine).
#[cfg(feature = "anytls")]
async fn tls_wrap<S>(stream: S, host: &str) -> io::Result<impl AsyncRead + AsyncWrite + Unpin>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // VERIFY against tokio-boring2: build a default client SslConnector and connect over `stream`.
    use boring2::ssl::{SslConnector, SslMethod};
    let connector = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| io::Error::other(format!("probe tls: {e}")))?
        .build();
    let config = connector
        .configure()
        .map_err(|e| io::Error::other(format!("probe tls: {e}")))?;
    tokio_boring2::connect(config, host, stream)
        .await
        .map_err(|e| io::Error::other(format!("probe tls handshake: {e}")))
}

#[cfg(not(feature = "anytls"))]
async fn tls_wrap<S>(_stream: S, _host: &str) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Err(io::Error::other(
        "https callback URL requires a TLS backend; build with the `anytls` feature (or use an http:// callback)",
    ))
}
```

> **Verify (tokio-boring2 API):** the exact constructor (`SslConnector::builder(SslMethod::tls_client())`, `.configure()`, `tokio_boring2::connect(config, domain, stream)`) against the `tokio-boring2`/`boring2` version in `Cargo.lock` — mirror how `flint-tls`'s connector / `samizdat/session_id.rs` build their boring client. Adjust names if they differ; the *shape* (build connector → configure → connect over the existing stream) is what matters. The `#[cfg(not(feature="anytls"))]` arm returns the stream type `S` so the non-TLS build still type-checks (it's only reached for `https://`, which errors).

- [ ] **Step 5: Run to verify it passes.** Run (base build covers the http path): `cd <spark> && cargo test -p spark-core probe::tests::probe_`. Expected: PASS. Then confirm the TLS arm compiles: `cargo build -p spark-core --features anytls`.

- [ ] **Step 6: Commit.**
```bash
git add core/src/transport/probe.rs
git commit -m "feat(transport): probe() — handshake timing + callback health check (http base, https via boring/anytls)"
```

### Task D4: live-gated end-to-end probe

**Files:** `<spark>/core/src/transport/probe.rs`

Mirrors the bootstrap resolver's `#[ignore]` live test. It probes a real callback **through `DirectTransport`** (no proxy needed to validate the probe + HTTP/TLS client end-to-end against a live server). Operator-parameterized via `SPARK_LIVE_CALLBACK` (any `http(s)://` URL — `probe` now resolves hostnames); the test no-ops when it's unset so CI without the env stays green.

- [ ] **Step 1: Add the live test.** Add to `probe.rs`'s `mod tests`:

```rust
    /// Live e2e: probe a real callback through a direct (no-proxy) transport. Set
    /// `SPARK_LIVE_CALLBACK` to any reachable `http(s)://` URL (hostname or IP), e.g.
    /// `SPARK_LIVE_CALLBACK=https://www.gstatic.com/generate_204`. https needs `anytls`.
    /// Run: `SPARK_LIVE_CALLBACK=... cargo test -p spark-core --features multi-server,anytls -- --ignored live_probe`
    #[tokio::test]
    #[ignore = "live: needs network + SPARK_LIVE_CALLBACK"]
    async fn live_probe() {
        let Ok(raw) = std::env::var("SPARK_LIVE_CALLBACK") else { return };
        let url = CallbackUrl::parse(&raw).expect("valid SPARK_LIVE_CALLBACK");
        let direct: std::sync::Arc<dyn crate::transport::Transport> =
            std::sync::Arc::new(crate::transport::DirectTransport::new(None));
        let out = probe(&direct, &url, std::time::Duration::from_secs(8)).await;
        assert!(out.healthy, "live callback {raw} should be healthy");
    }
```

- [ ] **Step 2: Verify it compiles + is skipped.** Run: `cd <spark> && cargo test -p spark-core --features anytls live_probe -- --list`. Expected: `live_probe` is listed (compiles) and not run. (`anytls` so the https TLS path compiles; the `multi-server` feature isn't needed here — `probe`/`DirectTransport` are base, only `select.rs` is gated.)

- [ ] **Step 3: Commit.**
```bash
git add core/src/transport/probe.rs
git commit -m "test(transport): live-gated e2e probe through DirectTransport"
```

---

## Phase E — `SelectingTransport` + prober

### Task E1: pool member + selection state + `Transport`/`UdpTransport` with failover

**Files:** Create `<spark>/core/src/transport/select.rs`; modify `core/src/transport/mod.rs` (declare module).

- [ ] **Step 1: Add the `multi-server` feature and declare the gated module.** This must happen now (not later): `select.rs` uses `flint_dial` (Task E3), which is only pulled by a feature — gate from the start so the base build never breaks. In `core/Cargo.toml` `[features]` add:

```toml
# Latency-selecting multi-server pool (design: docs/multi-server-selection-design.md). Pulls
# flint-dial for windowed probing. https callbacks additionally need `anytls` (boring TLS).
multi-server = ["dep:flint-dial"]
```

(`flint-dial` is already an optional dep; without its `boring` feature it still provides `probe_windowed`/`race_*`, which are pure async helpers — no boring/cmake in the base.) Then in `core/src/transport/mod.rs` add:

```rust
#[cfg(feature = "multi-server")]
pub mod select;
```

Run `cargo build -p spark-core --features multi-server` (compiles `flint-dial` in) to confirm the feature resolves before writing code.

- [ ] **Step 2: Write the failing tests** (fake transports with scripted dial success/failure; no network). Create `core/src/transport/select.rs`:

```rust
//! Latency-selecting transport over a server pool (design: `docs/multi-server-selection-design.md`).
//! Implements `Transport`/`UdpTransport`; new flows use the current-best member; a background prober
//! re-ranks and swaps with failover + hysteresis. The current selection is read under a short
//! `std::sync::Mutex` (never held across `.await`).

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::transport::probe::{probe, CallbackUrl, ProbeOutcome};
use crate::transport::{BoxedPacketSink, BoxedPacketSource, Transport, UdpTransport};
use crate::BoxedStream;

/// A built pool member: its transport pair + the callback URL used to probe it.
struct Member {
    transport: Arc<dyn Transport>,
    udp: Arc<dyn UdpTransport>,
    callback: CallbackUrl,
}

/// Ranked selection: indices into the pool, best-first; empty = nothing healthy.
#[derive(Default)]
struct Selection {
    ranked: Vec<usize>,
}

/// A latency-selecting transport over a pool of [`Member`]s.
pub struct SelectingTransport {
    members: Arc<Vec<Member>>,
    selection: Arc<Mutex<Selection>>,
    prober: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SelectingTransport {
    /// Current best-first order (snapshot; lock not held across `.await`).
    fn order(&self) -> Vec<usize> {
        self.selection.lock().expect("selection mutex").ranked.clone()
    }
}

#[async_trait]
impl Transport for SelectingTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let order = self.order();
        if order.is_empty() {
            return Err(io::Error::other("no healthy server in the pool"));
        }
        let mut last_err = None;
        for i in order {
            match self.members[i].transport.dial(target).await {
                Ok(s) => return Ok(s),
                Err(e) => last_err = Some(e), // failover to next-best
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no healthy server in the pool")))
    }
}

#[async_trait]
impl UdpTransport for SelectingTransport {
    async fn dial_udp(&self, target: SocketAddr) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        let order = self.order();
        if order.is_empty() {
            return Err(io::Error::other("no healthy server in the pool"));
        }
        let mut last_err = None;
        for i in order {
            match self.members[i].udp.dial_udp(target).await {
                Ok(p) => return Ok(p),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no healthy server in the pool")))
    }
}

impl Drop for SelectingTransport {
    fn drop(&mut self) {
        if let Some(h) = self.prober.lock().expect("prober mutex").take() {
            h.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::BoxedStream;

    // A fake transport: dial always errors, or always yields a dummy stream.
    struct FakeT { ok: bool }
    #[async_trait]
    impl Transport for FakeT {
        async fn dial(&self, _t: SocketAddr) -> io::Result<BoxedStream> {
            if self.ok { Ok(Box::new(tokio::io::duplex(16).0)) } else { Err(io::Error::other("down")) }
        }
    }
    struct NoUdp;
    #[async_trait]
    impl UdpTransport for NoUdp {
        async fn dial_udp(&self, _t: SocketAddr) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
            Err(io::Error::other("no udp"))
        }
    }
    fn member(ok: bool) -> Member {
        Member {
            transport: Arc::new(FakeT { ok }),
            udp: Arc::new(NoUdp),
            callback: CallbackUrl { tls: false, host: "h".into(), port: 80, path: "/".into() },
        }
    }
    fn selecting(members: Vec<Member>, ranked: Vec<usize>) -> SelectingTransport {
        SelectingTransport {
            members: Arc::new(members),
            selection: Arc::new(Mutex::new(Selection { ranked })),
            prober: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn dial_uses_best_then_fails_over() {
        // best (index 0) is down, index 1 is up → failover succeeds.
        let t = selecting(vec![member(false), member(true)], vec![0, 1]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn dial_errors_when_no_healthy() {
        let t = selecting(vec![member(true)], vec![]); // empty ranking = none healthy
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_err());
    }

    #[tokio::test]
    async fn dial_errors_when_all_down() {
        let t = selecting(vec![member(false), member(false)], vec![0, 1]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_err());
    }
}
```

- [ ] **Step 3: Run to verify they pass** (code + tests land together; it's a new type). Run: `cd <spark> && cargo test -p spark-core --features multi-server select::tests`. Expected: PASS — `dial_uses_best_then_fails_over`, `dial_errors_when_no_healthy`, `dial_errors_when_all_down`. (`probe`/`ProbeOutcome` imports are unused until E2/E3 — expected warnings; don't run `clippy -D warnings` yet. Also confirm the base build is untouched: `cargo build -p spark-core`.)

- [ ] **Step 4: Commit.**
```bash
git add core/src/transport/mod.rs core/src/transport/select.rs
git commit -m "feat(transport): SelectingTransport dial/dial_udp with failover + drop-abort"
```

### Task E2: ranking + hysteresis (pure function)

**Files:** `<spark>/core/src/transport/select.rs`

- [ ] **Step 1: Write the failing test.** Add to `select.rs`'s `mod tests`:

```rust
    #[test]
    fn rank_orders_healthy_by_latency_and_drops_unhealthy() {
        let outs = vec![
            (0, ProbeOutcome { latency: Duration::from_millis(80), healthy: true }),
            (1, ProbeOutcome { latency: Duration::MAX, healthy: false }),
            (2, ProbeOutcome { latency: Duration::from_millis(20), healthy: true }),
        ];
        assert_eq!(rank(&outs), vec![2, 0]); // 20ms before 80ms; index 1 dropped
    }

    #[test]
    fn next_order_keeps_current_unless_challenger_is_20pct_better() {
        let current = vec![0];
        // index 0 = 100ms (current), index 2 = 90ms challenger: only 10% better → keep 0 first.
        let fresh = vec![
            (0, ProbeOutcome { latency: Duration::from_millis(100), healthy: true }),
            (2, ProbeOutcome { latency: Duration::from_millis(90), healthy: true }),
        ];
        assert_eq!(next_order(&current, &fresh)[0], 0);
        // index 2 = 70ms: 30% better → it leads.
        let fresh = vec![
            (0, ProbeOutcome { latency: Duration::from_millis(100), healthy: true }),
            (2, ProbeOutcome { latency: Duration::from_millis(70), healthy: true }),
        ];
        assert_eq!(next_order(&current, &fresh)[0], 2);
        // current became unhealthy → challenger leads regardless of margin.
        let fresh = vec![
            (0, ProbeOutcome { latency: Duration::MAX, healthy: false }),
            (2, ProbeOutcome { latency: Duration::from_millis(99), healthy: true }),
        ];
        assert_eq!(next_order(&current, &fresh)[0], 2);
    }
```

- [ ] **Step 2: Run to verify it fails.** Run: `cd <spark> && cargo test -p spark-core --features multi-server select::tests::rank select::tests::next_order`. Expected: FAIL — `cannot find function rank`/`next_order`.

- [ ] **Step 3: Implement `rank` + `next_order`.** Add to `select.rs` (module-level, above the tests):

```rust
/// How much lower a challenger's latency must be to displace the incumbent best (hysteresis).
const SWITCH_MARGIN: f64 = 0.20;

/// Healthy members, best (lowest latency) first; unhealthy dropped.
fn rank(outcomes: &[(usize, ProbeOutcome)]) -> Vec<usize> {
    let mut healthy: Vec<&(usize, ProbeOutcome)> = outcomes.iter().filter(|(_, o)| o.healthy).collect();
    healthy.sort_by_key(|(_, o)| o.latency);
    healthy.iter().map(|(i, _)| *i).collect()
}

/// New best-first order given the `current` order and a fresh probe round. The fresh ranking wins,
/// EXCEPT the incumbent best is kept in front unless a challenger is ≥ `SWITCH_MARGIN` lower latency
/// or the incumbent is no longer healthy — hysteresis against flapping between near-equal servers.
fn next_order(current: &[usize], fresh: &[(usize, ProbeOutcome)]) -> Vec<usize> {
    let ranked = rank(fresh);
    let incumbent = match current.first() {
        Some(i) => *i,
        None => return ranked, // nothing to keep
    };
    let incumbent_latency = fresh.iter().find(|(i, _)| *i == incumbent).filter(|(_, o)| o.healthy).map(|(_, o)| o.latency);
    let challenger = ranked.first().copied();
    match (incumbent_latency, challenger) {
        // incumbent still healthy and either no challenger or challenger not 20% better → keep it first.
        (Some(inc), Some(ch)) if ch != incumbent => {
            let ch_latency = fresh.iter().find(|(i, _)| *i == ch).map(|(_, o)| o.latency).unwrap_or(Duration::MAX);
            if (ch_latency.as_secs_f64()) <= inc.as_secs_f64() * (1.0 - SWITCH_MARGIN) {
                ranked // challenger is meaningfully better → adopt fresh order
            } else {
                // keep incumbent first, then the rest of the fresh order (minus the incumbent).
                let mut order = vec![incumbent];
                order.extend(ranked.into_iter().filter(|i| *i != incumbent));
                order
            }
        }
        (Some(_), _) => ranked, // incumbent is also the challenger (still best) → fresh order is fine
        (None, _) => ranked,    // incumbent unhealthy → adopt fresh order
    }
}
```

- [ ] **Step 4: Run to verify it passes.** Run: `cd <spark> && cargo test -p spark-core --features multi-server select::tests::rank select::tests::next_order`. Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
git add core/src/transport/select.rs
git commit -m "feat(transport): rank + next_order (latency ranking with switch hysteresis)"
```

### Task E3: the prober loop + `SelectingTransport::new`

**Files:** `<spark>/core/src/transport/select.rs`

- [ ] **Step 1: Write the failing test** (fake transports + immediate-200 callbacks via a fake; assert the prober populates a healthy ranking). Add to `select.rs`'s `mod tests`:

```rust
    #[tokio::test(start_paused = true)]
    async fn new_probes_and_populates_selection() {
        // Two members; both healthy (the FakeT dial yields a duplex whose far end answers 204 — reuse
        // the probe test's fake by giving each member a transport that serves 204). Here we instead
        // drive the prober directly by constructing with a tiny interval and asserting a best appears.
        let members = vec![member_serving_204(), member_serving_204()];
        let st = SelectingTransport::new(members, Duration::from_secs(300), 8);
        // Yield so the spawned prober runs its initial round.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        assert!(!st.order().is_empty(), "prober should have selected a healthy server");
    }
```

Add this test helper to `mod tests` (a member whose transport serves `204` to the probe GET):

```rust
    struct Serve204;
    #[async_trait]
    impl Transport for Serve204 {
        async fn dial(&self, _t: SocketAddr) -> io::Result<BoxedStream> {
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut b = vec![0u8; 1024];
                let _ = server.read(&mut b).await;
                let _ = server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            });
            Ok(Box::new(client))
        }
    }
    fn member_serving_204() -> Member {
        Member {
            transport: Arc::new(Serve204),
            udp: Arc::new(NoUdp),
            // 127.0.0.1 is never dialed for real (the fake transport ignores the target); using an IP
            // literal just keeps the test offline (no DNS lookup in `resolve_callback_addr`).
            callback: CallbackUrl { tls: false, host: "127.0.0.1".into(), port: 80, path: "/".into() },
        }
    }
```

- [ ] **Step 2: Run to verify it fails.** Run: `cd <spark> && cargo test -p spark-core select::tests::new_probes`. Expected: FAIL — `no function new`.

- [ ] **Step 3: Implement `new` + the prober loop.** Add to `select.rs`:

```rust
impl SelectingTransport {
    /// Build a selecting transport over `members`, spawning a background prober. Must be called inside
    /// a tokio runtime (as `from_config`'s callers are). The prober runs an initial round immediately,
    /// then re-probes every `interval`; `window` bounds probe concurrency.
    pub fn new(members: Vec<Member>, interval: Duration, window: usize) -> Self {
        let members = Arc::new(members);
        let selection = Arc::new(Mutex::new(Selection::default()));
        let task = tokio::spawn(prober_loop(Arc::clone(&members), Arc::clone(&selection), interval, window.max(1)));
        SelectingTransport { members, selection, prober: Mutex::new(Some(task)) }
    }
}

/// Background prober: probe the pool (windowed), update the ranked selection (with hysteresis), then
/// wait `interval` and repeat. Per-probe deadline = `interval` capped at 10s so a slow server can't
/// stall a whole round on a short interval.
async fn prober_loop(members: Arc<Vec<Member>>, selection: Arc<Mutex<Selection>>, interval: Duration, window: usize) {
    let per_probe = interval.min(Duration::from_secs(10));
    loop {
        let outcomes = flint_dial::probe_windowed(members.len(), window, |i| {
            // Clone the (cheap) Arc + CallbackUrl into the future so it borrows nothing from `members`.
            let transport = Arc::clone(&members[i].transport);
            let callback = members[i].callback.clone();
            async move { probe(&transport, &callback, per_probe).await }
        })
        .await;
        {
            let mut sel = selection.lock().expect("selection mutex");
            sel.ranked = next_order(&sel.ranked, &outcomes);
        }
        tracing::debug!(healthy = outcomes.iter().filter(|(_, o)| o.healthy).count(), pool = members.len(), "pool re-probed");
        tokio::time::sleep(interval).await;
    }
}
```

> **Note (initial fast-pick):** the spec's "select from the first batch that yields a healthy candidate, then keep ranking" is an optimization; this v1 prober probes the whole pool (windowed, so bounded) before the first selection. For very large pools you can later make the first round emit a provisional best as soon as one healthy result lands. Don't build that now (YAGNI); the windowing already bounds concurrency. `flint_dial` is available via the `multi-server` feature (added in E1), which gates this module.

- [ ] **Step 4: Run to verify it passes.** Run: `cd <spark> && cargo test -p spark-core --features multi-server select::tests::new_probes`. Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
git add core/src/transport/select.rs
git commit -m "feat(transport): prober loop + SelectingTransport::new (windowed probe + re-rank)"
```

### Task E4: verify builds + fmt the module

**Files:** none (verification + `cargo fmt`; the `multi-server` feature + gating were added in Task E1).

> **Note:** do NOT run `clippy -D warnings` here. The module's entry points (`SelectingTransport::new`, `build_one`, and transitively `rank`/`next_order`/`prober_loop`/`SWITCH_MARGIN`/`Member.callback`) are only *used* once `from_config` calls `build_selecting` — that's **Task F1**. Until then they're legitimately dead code, so `-D warnings` would fail on expected dead-code. The clippy gate runs in **Task F3** (after wiring). Here we just confirm builds + tests + formatting.

- [ ] **Step 1: Format + verify builds and tests.** Run:
```bash
cd <spark>
cargo fmt
cargo fmt --check
cargo build -p spark-core                                   # base: select not compiled
cargo build -p spark-core --features multi-server           # pool path compiles
cargo build -p spark-core --features multi-server,anytls    # + https probe TLS
cargo test -p spark-core --features multi-server select:: probe::
```
Expected: fmt clean after `cargo fmt`; all three builds succeed; select + probe tests pass.

- [ ] **Step 2: Commit the formatting.**
```bash
git add -A
git commit -m "style(transport): rustfmt the multi-server + probe modules"
```

---

## Phase F — wiring

### Task F1: `from_config` builds `SelectingTransport` for a pool

**Files:** `<spark>/core/src/transport/mod.rs`

- [ ] **Step 1: Write the failing test.** Add to the `#[cfg(all(test, feature = "multi-server"))]` test area in `transport/mod.rs` (create the module if absent):

```rust
#[cfg(all(test, feature = "multi-server"))]
mod pool_config_tests {
    use super::*;
    use crate::config::{Config, ServerEntry, ServerSpec, TransportConfig, TunnelConfig};

    #[tokio::test]
    async fn from_config_builds_a_selecting_transport_for_a_pool() {
        let cfg = Config {
            transport: TransportConfig {
                servers: vec![ServerEntry {
                    spec: ServerSpec::Tunnel(TunnelConfig { server: "1.2.3.4:443".parse().unwrap(), sni: None }),
                    callback_url: None,
                }],
                callback_url: Some("http://127.0.0.1:80/ok".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        // Builds within a runtime (spawns the prober). Just assert it constructs.
        from_config(&cfg).expect("from_config should build the selecting transport");
    }

    #[tokio::test]
    async fn pool_without_callback_url_is_an_error() {
        let cfg = Config {
            transport: TransportConfig {
                servers: vec![ServerEntry {
                    spec: ServerSpec::Tunnel(TunnelConfig { server: "1.2.3.4:443".parse().unwrap(), sni: None }),
                    callback_url: None,
                }],
                callback_url: None, // neither global nor per-entry → error
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(from_config(&cfg).is_err());
    }
}
```

- [ ] **Step 2: Run to verify it fails.** Run: `cd <spark> && cargo test -p spark-core --features multi-server pool_config_tests`. Expected: FAIL — `from_config` ignores `servers`.

- [ ] **Step 3: Branch `from_config` on a non-empty pool.** In `core/src/transport/mod.rs`, at the **top** of `from_config` (after building `protector`), add the pool branch:

```rust
    // A configured server pool supersedes the single-transport fields: build a latency-selecting
    // transport over it.
    if !config.transport.servers.is_empty() {
        return build_selecting(config, protector);
    }
```

Then add the builder (feature-split):

```rust
/// Build a `SelectingTransport` over `config.transport.servers`. Each entry's callback URL is its
/// per-entry override or the global `transport.callback_url`; the pool needs at least one callback.
#[cfg(feature = "multi-server")]
fn build_selecting(
    config: &Config,
    protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    use crate::transport::probe::CallbackUrl;
    use crate::transport::select::{Member, SelectingTransport};
    let wire = wire_plan_from_config(&config.transport.shaping);
    let mut members = Vec::with_capacity(config.transport.servers.len());
    for entry in &config.transport.servers {
        let raw = entry
            .callback_url
            .as_deref()
            .or(config.transport.callback_url.as_deref())
            .ok_or_else(|| io::Error::other("transport.servers requires a callback_url (global or per-entry)"))?;
        let callback = CallbackUrl::parse(raw)?;
        let (transport, udp) = build_one(&entry.spec, protector.as_ref(), &wire)?;
        members.push(Member::new(transport, udp, callback));
    }
    let st = Arc::new(SelectingTransport::new(
        members,
        std::time::Duration::from_secs(config.transport.probe_interval_secs),
        config.transport.probe_window,
    ));
    Ok((st.clone() as Arc<dyn Transport>, st as Arc<dyn UdpTransport>))
}

#[cfg(not(feature = "multi-server"))]
fn build_selecting(
    _config: &Config,
    _protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.servers is configured but spark was built without the `multi-server` feature",
    ))
}
```

This needs `Member` to be constructible from `select.rs`. Add a public constructor there:

```rust
impl Member {
    pub(crate) fn new(transport: Arc<dyn Transport>, udp: Arc<dyn UdpTransport>, callback: CallbackUrl) -> Self {
        Member { transport, udp, callback }
    }
}
```

and make `Member` / `SelectingTransport::new` reachable: `Member` is `pub(crate)` (struct already in `select.rs`; mark it `pub(crate) struct Member`), `SelectingTransport` and `new` are `pub`.

- [ ] **Step 4: Run to verify it passes.** Run: `cd <spark> && cargo test -p spark-core --features multi-server pool_config_tests`. Expected: PASS (both). Confirm base still builds: `cargo build -p spark-core`.

- [ ] **Step 5: Commit.**
```bash
git add core/src/transport/mod.rs core/src/transport/select.rs
git commit -m "feat(transport): from_config builds SelectingTransport when a server pool is set"
```

### Task F2: resolve pool endpoints at startup (bootstrap)

**Files:** `<spark>/core/src/bootstrap/mod.rs`

- [ ] **Step 1: Write the failing test.** Add to `bootstrap/mod.rs`'s `mod tests`:

```rust
    #[tokio::test]
    async fn resolve_endpoints_rewrites_pool_entries() {
        use crate::config::{ServerEntry, ServerSpec, TunnelConfig};
        let mut cfg = Config {
            transport: crate::config::TransportConfig {
                servers: vec![ServerEntry {
                    spec: ServerSpec::Tunnel(TunnelConfig { server: "proxy.example.com:443".parse().unwrap(), sni: None }),
                    callback_url: None,
                }],
                callback_url: Some("http://127.0.0.1/ok".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolver = RacingResolver::new(vec![ok("9.9.9.9:443")]);
        resolve_endpoints(&mut cfg, &resolver).await.unwrap();
        match &cfg.transport.servers[0].spec {
            ServerSpec::Tunnel(t) => assert_eq!(t.server, crate::config::Endpoint::Ip("9.9.9.9:443".parse().unwrap())),
            _ => panic!("expected tunnel"),
        }
    }
```

- [ ] **Step 2: Run to verify it fails.** Run: `cd <spark> && cargo test -p spark-core --features bootstrap-dns resolve_endpoints_rewrites_pool`. Expected: FAIL — pool entries not resolved.

- [ ] **Step 3: Extend `resolve_endpoints` to cover pool entries.** In `core/src/bootstrap/mod.rs`, after the existing `anytls`/`samizdat` pushes and **before** the resolve loop, also collect each pool entry's `(server, sni)`:

```rust
    for entry in config.transport.servers.iter_mut() {
        match &mut entry.spec {
            crate::config::ServerSpec::Anytls(c) => entries.push((&mut c.server, &mut c.sni)),
            crate::config::ServerSpec::Samizdat(c) => entries.push((&mut c.server, &mut c.sni)),
            crate::config::ServerSpec::Tunnel(c) => entries.push((&mut c.server, &mut c.sni)),
            crate::config::ServerSpec::Wasm(_) => {} // wasm.server is a SocketAddr, never a hostname
        }
    }
```

(The loop body that resolves `(ep, sni)` is unchanged.)

- [ ] **Step 4: Run to verify it passes.** Run: `cd <spark> && cargo test -p spark-core --features bootstrap-dns resolve_endpoints`. Expected: PASS (the new pool test + existing ones).

- [ ] **Step 5: Commit.**
```bash
git add core/src/bootstrap/mod.rs
git commit -m "feat(bootstrap): resolve hostnames for server-pool entries too"
```

### Task F3: green sweep + PR

**Files:** none (verification)

- [ ] **Step 1: Full sweep across feature sets.**
```bash
cd <spark>
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p spark-core --features multi-server,anytls,samizdat,wasm-transport,bootstrap-dns --all-targets -- -D warnings
cargo test --workspace
cargo test -p spark-core --features multi-server,anytls,samizdat,wasm-transport,bootstrap-dns
```
Expected: all clean / pass.

- [ ] **Step 2: Binary-size check (the <3 MB base budget).**
```bash
cargo build --release -p spark-cli && ls -lh target/release/spark              # base — must stay <3 MB
cargo build --release -p spark-cli --features multi-server,anytls && ls -lh target/release/spark
```
Record both sizes; confirm base is under budget. Add a `bootstrap-dns`-style passthrough so the CLI/service can enable `multi-server` (in `cli/Cargo.toml` and `service/Cargo.toml`: `multi-server = ["spark-core/multi-server"]`) and commit that with this task.

- [ ] **Step 3: Push + open the PR.**
```bash
git push -u origin multi-server-selection
```
PR body: summarize the pool config, `SelectingTransport` (current-best hot-swap, failover + 20% hysteresis), the probe (handshake + callback, http base / https via boring), `flint-dial::probe_windowed`, and the L4/UDP-readiness notes. Include a mermaid `sequenceDiagram` of selection (startup probe → rank → set best; per-flow dial → failover; periodic re-probe → hysteresis swap), since the flow spans config → prober → transport. Request Copilot review (POST `requested_reviewers` with `{"reviewers":["copilot-pull-request-reviewer[bot]"]}` via `--input`).

---

## Notes for the implementer

- **One flint rev everywhere** (Task A2): all five flint deps pinned to `<FLINTREV>`; `cargo tree -i flint-shaping` shows one node.
- **Three verification points** (CLAUDE.md Verification Discipline) flagged inline: (1) the `toml` internally-tagged-enum round-trip (B1 test confirms it), (2) the `tokio-boring2` client-connect API in `tls_wrap` (D3 — mirror `flint-tls`/samizdat), (3) `WirePlan: Clone` (C1). Resolve each by checking the actual API, not guessing.
- **No `MutexGuard` across `.await`** — `SelectingTransport::order()` clones the ranked vec inside the lock and drops the guard before any dial. Keep it that way.
- **Probe-by-IP (option a)** is assumed for callback hosts (`probe_inner` parses the host as an IP). If a hostname callback is needed, resolve it once at startup (bootstrap) and thread the `SocketAddr` through — noted in D3.
- **YAGNI**: no per-flow racing, no live-connection migration, no adaptive cadence, no expected-body match, no capability-aware UDP/TCP split — all roadmapped in the design, none built here.
- **Crate/bin names:** core = `spark-core`/`spark_core`; CLI = `spark-cli`/bin `spark`; service = `spark-service`.
