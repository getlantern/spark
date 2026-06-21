# Bootstrap Resolver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give spark an un-poisoned, Chrome-mimicry control-plane name resolver so a proxy `server` can be configured by **hostname** (resolved at startup, before any tunnel exists), instead of only by raw IP.

**Architecture:** A new `spark_core::bootstrap` module (behind a `bootstrap-dns` feature) exposes a `NameResolver` trait and a `RacingResolver` that happy-eyeballs-races resolution *strategies* — `DohResolver` (flint-dns un-poisoned DoH, the always-available path) and `ProxyResolver` (tunnel a DNS query through an IP-addressed proxy). A new `config::Endpoint` enum lets `[transport.anytls]`/`[transport.samizdat]` `server` be `IP:port` **or** `host:port`. A bootstrap phase resolves every `Endpoint::Host` to an `Endpoint::Ip` in each entry point right before `transport::from_config`, which stays synchronous. flint gains one enhancement: bounded-concurrency (`race_windowed`) racing, used by `flint_dns::resolve` so the pool race runs in batches.

**Tech Stack:** Rust 2021 (MSRV 1.85), tokio, `async-trait`, `serde`/`toml`, the public `getlantern/flint` crates (`flint-dial`, `flint-dns`) over boring2 Chrome-mimicry TLS. Spec: `docs/bootstrap-resolver-design.md`.

**Worktree:** do the spark work in a dedicated git worktree on a feature branch (e.g. `git worktree add ../spark-bootstrap-resolver -b bootstrap-resolver`), and the flint changes in a separate worktree/branch of `getlantern/flint`. Paths below are written relative to each repo root; substitute your own worktree locations. (This plan was first executed against worktrees under `~/go/src/github.com/getlantern/…`; those absolute paths are illustrative, not required.)

---

## File Structure

**flint repo** (`/Users/afisk/go/src/github.com/getlantern/flint`):
- Modify: `crates/flint-dial/src/race.rs` — add `race_windowed`; refactor `race_with` to delegate.
- Modify: `crates/flint-dns/src/lib.rs` — make `resolve` (and `resolve_cached`'s slow path) use `race_windowed`.

**spark worktree** (`/Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver`):
- Modify: `core/Cargo.toml` — bump 3 flint pins to the new rev; add `flint-dial` + `flint-dns` optional deps; add the `bootstrap-dns` feature.
- Modify: `core/src/config/mod.rs` — add `Endpoint` enum + `EndpointParseError`; change `AnytlsConfig.server` and `SamizdatConfig.server` from `SocketAddr` to `Endpoint`; add `Config::first_unresolved_host`.
- Modify: `core/src/transport/mod.rs` — read the resolved `SocketAddr` via `cfg.server.socket_addr()?` in `anytls_transport`/`samizdat_transport`; fix the in-file config-test constructors.
- Create: `core/src/bootstrap/mod.rs` — `NameResolver`, `RacingResolver`, `DohResolver`, `ProxyResolver`, `resolve_endpoints`, `default_resolver` (all behind `bootstrap-dns`).
- Modify: `core/src/lib.rs` — declare `bootstrap` (gated); add the always-compiled `resolve_bootstrap` shim (two cfg bodies).
- Modify: `core/src/fd_tunnel.rs`, `cli/src/main.rs`, `service/src/engine.rs` — call `resolve_bootstrap` before building the transport.
- Modify: `cli/Cargo.toml`, `service/Cargo.toml` — forward a `bootstrap-dns` feature to `spark-core/bootstrap-dns`.

---

## Phase A — flint: windowed racing

The inner DoH pool race must run in bounded batches so it scales to large resolver lists (design §3.1). Add `flint_dial::race_windowed` and route `flint_dns::resolve` through it. Then publish a new flint rev and point spark at it.

### Task A1: `race_windowed` in flint-dial

**Files:**
- Modify: `/Users/afisk/go/src/github.com/getlantern/flint/crates/flint-dial/src/race.rs`

- [ ] **Step 1: Write the failing tests**

Add these tests inside the existing `mod tests` block in `crates/flint-dial/src/race.rs` (after `empty_set_yields_no_errors`):

```rust
    #[tokio::test]
    async fn windowed_never_exceeds_the_window_and_runs_all() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let inflight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        // 10 dials, window 3, all fail → every dial runs (10 errors) but never >3 concurrently.
        let res = race_windowed(10, 3, |_| {
            let inflight = Arc::clone(&inflight);
            let max_seen = Arc::clone(&max_seen);
            async move {
                let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(5)).await;
                inflight.fetch_sub(1, Ordering::SeqCst);
                Err::<i32, _>(io::Error::other("decline"))
            }
        })
        .await;
        assert_eq!(res.unwrap_err().len(), 10, "all dials should run");
        assert!(
            max_seen.load(Ordering::SeqCst) <= 3,
            "max in flight {} exceeded the window",
            max_seen.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn windowed_first_ok_wins_with_refill() {
        // Window 2; index 5 is the only Ok. It can only start after earlier failures refill the
        // window, so this also exercises refill. It must still win.
        let res = race_windowed(8, 2, |i| async move {
            if i == 5 {
                Ok::<_, io::Error>(55)
            } else {
                tokio::time::sleep(Duration::from_millis(1)).await;
                Err(io::Error::other("decline"))
            }
        })
        .await;
        assert_eq!(res.unwrap().1, 55);
    }

    #[tokio::test]
    async fn windowed_with_window_larger_than_count_is_unbounded() {
        let res = race_windowed(3, 99, |i| async move {
            if i == 2 { Ok::<_, io::Error>(2) } else { Err(io::Error::other("x")) }
        })
        .await;
        assert_eq!(res.unwrap(), (2, 2));
    }

    #[tokio::test]
    async fn windowed_empty_yields_no_errors() {
        let res = race_windowed(0, 4, |_| async move { Ok::<i32, io::Error>(0) }).await;
        assert!(res.unwrap_err().is_empty());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /Users/afisk/go/src/github.com/getlantern/flint && cargo test -p flint-dial windowed`
Expected: FAIL — `cannot find function race_windowed in this scope`.

- [ ] **Step 3: Implement `race_windowed` and refactor `race_with` to delegate**

In `crates/flint-dial/src/race.rs`, replace the body of `race_with` so it delegates, and add `race_windowed` above it. The new `race_with` (keep its doc comment + signature exactly as-is):

```rust
pub async fn race_with<F, Fut, T>(
    count: usize,
    dial_one: F,
) -> Result<(usize, T), Vec<io::Error>>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    // Unbounded == a window as wide as the field.
    race_windowed(count, count, dial_one).await
}

/// Like [`race_with`] but with **bounded concurrency**: at most `window` dials are in flight at once,
/// refilling as each finishes, so a large `count` doesn't open every connection simultaneously
/// (design §3.1). Returns `(winning_index, value)` for the first `Ok`; the losers are dropped. If all
/// fail, returns every error in completion order. `window` is clamped to at least 1; `count == 0`
/// yields `Err(vec![])`. With `window >= count` this is exactly [`race_with`] (unbounded).
pub async fn race_windowed<F, Fut, T>(
    count: usize,
    window: usize,
    mut dial_one: F,
) -> Result<(usize, T), Vec<io::Error>>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let window = window.max(1);
    let mut set = FuturesUnordered::new();
    let mut next = 0;
    let mut errors = Vec::new();
    loop {
        // Refill the window up to capacity. There is exactly ONE `async move` push site in this
        // function on purpose: two syntactically-distinct `async move` blocks are two anonymous
        // types, which `FuturesUnordered<Fut>` (one element type) rejects (E0308). Keeping a single
        // push site also keeps the wrapper future `Send` when `Fut`/`T` are — no boxing — which the
        // downstream `#[async_trait]` resolvers require. Do NOT box with `LocalBoxFuture` (not `Send`).
        while next < count && set.len() < window {
            let i = next;
            next += 1;
            let fut = dial_one(i);
            set.push(async move { (i, fut.await) });
        }
        match set.next().await {
            Some((i, Ok(v))) => return Ok((i, v)),
            Some((_, Err(e))) => errors.push(e),
            None => return Err(errors), // window empty and nothing left to start → all failed
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /Users/afisk/go/src/github.com/getlantern/flint && cargo test -p flint-dial`
Expected: PASS — all existing `race_with` tests plus the four new `windowed_*` tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/afisk/go/src/github.com/getlantern/flint
git add crates/flint-dial/src/race.rs
git commit -m "feat(flint-dial): bounded-concurrency race_windowed; race_with delegates to it"
```

### Task A2: route `flint_dns::resolve` through `race_windowed` with a per-attempt timeout

**Files:**
- Modify: `/Users/afisk/go/src/github.com/getlantern/flint/crates/flint-dns/src/lib.rs`
- Modify: `/Users/afisk/go/src/github.com/getlantern/flint/crates/flint-dns/Cargo.toml`

**Why the timeout (spec §5):** `flint_dial::dial` does `TcpStream::connect(...).await?` with **no timeout**. Under censorship a filtered resolver IP blackholes the connect (no RST), which would hang for the OS default (~minutes). With windowing this is worse than unbounded: a hung connect *occupies its window slot* and starves refills, so a good resolver further down a large pool never gets dialed and the all-fail case never returns. A per-attempt timeout frees the slot so the window refills with potentially-good resolvers. This belongs in flint (it bounds the inner per-resolver attempt and also benefits the future data-plane resolver).

- [ ] **Step 1: Write the failing test**

Add this test inside the existing `mod tests` block in `crates/flint-dns/src/lib.rs`:

```rust
    #[tokio::test]
    async fn resolve_on_an_empty_pool_fails() {
        // No network: an empty pool races nothing → AllFailed{0}. Proves resolve still funnels an
        // all-fail race into ResolveError (now via the windowed, timeout-bounded path).
        let err = resolve("example.com", TYPE_A, &[]).await.unwrap_err();
        assert!(matches!(err, ResolveError::AllFailed { tried: 0 }));
    }
```

- [ ] **Step 2: Run the test (it already passes — it's a guard for the refactor)**

Run: `cd /Users/afisk/go/src/github.com/getlantern/flint && cargo test -p flint-dns resolve_on_an_empty_pool`
Expected: PASS even now (the current `resolve` already returns `AllFailed{0}` for an empty pool). This behavior must survive the internals swap to `race_windowed` + timeout — note it and proceed.

- [ ] **Step 3: Enable the tokio `time` (and `rt`) features in flint-dns**

In `crates/flint-dns/Cargo.toml`, in `[dependencies]`, change:

```toml
tokio = { version = "1", default-features = false, features = ["io-util"] }
```

to:

```toml
tokio = { version = "1", default-features = false, features = ["io-util", "rt", "time"] }
```

(`time` is for the new `ATTEMPT_TIMEOUT`. `rt` is also added: `doh.rs` uses `tokio::spawn` + `JoinHandle` in non-test code, which need `rt` — the original manifest omitted it and only compiled because spark unifies tokio's `rt` downstream. Declaring it honestly lets flint-dns build standalone.)

- [ ] **Step 4: Switch `resolve` and `resolve_cached` to windowed + timeout-bounded racing**

In `crates/flint-dns/src/lib.rs`, add `use std::time::Duration;` to the imports (next to `use std::io;`). Add these constants above `resolve` (after the `ResolveError` enum is fine):

```rust
/// How many DoH dials race at once inside [`resolve`]. The pool may grow to hundreds of raw resolver
/// IPs (design §3.1); the window caps in-flight attempts regardless of list length. Today's pool fits
/// in one window, so it's effectively all-at-once.
const DEFAULT_WINDOW: usize = 16;

/// Per-resolver attempt deadline. `flint_dial::dial` doesn't bound its TCP connect, so a filtered
/// resolver IP would blackhole the connect and (worse, under windowing) hold its window slot. Bounding
/// each attempt frees the slot so the window refills, and makes the all-fail case return promptly
/// (spec §5) instead of hanging on the slowest resolver.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
```

Then replace the race call in `resolve`:

```rust
    match flint_dial::race_with(pool.len(), |i| resolve_one(&pool[i], name, qtype)).await {
```

with:

```rust
    match flint_dial::race_windowed(pool.len(), DEFAULT_WINDOW, |i| async move {
        match tokio::time::timeout(ATTEMPT_TIMEOUT, resolve_one(&pool[i], name, qtype)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "resolver attempt timed out")),
        }
    })
    .await
    {
```

And make the **identical** replacement for the slow-path race call in `resolve_cached` (the one after the cache miss/fallthrough comment).

- [ ] **Step 5: Run flint-dns tests**

Run: `cd /Users/afisk/go/src/github.com/getlantern/flint && cargo test -p flint-dns`
Expected: PASS — including `resolve_on_an_empty_pool_fails` and `resolve_cached_on_an_empty_pool_fails_without_network`. (The timeout path is exercised live in spark's `doh_resolves_live` e2e and logically by flint-dial's `windowed_first_ok_wins_with_refill` — a timed-out attempt is just an `Err`, which the windowed refill already covers; no no-network unit test can force a real TCP hang.)

- [ ] **Step 6: Lint + commit**

```bash
cd /Users/afisk/go/src/github.com/getlantern/flint
cargo clippy -p flint-dial -p flint-dns -- -D warnings
cargo fmt
git add crates/flint-dns/src/lib.rs crates/flint-dns/Cargo.toml
git commit -m "feat(flint-dns): bounded-window DoH race with per-attempt timeout"
```

### Task A3: publish the new flint rev and point spark at it

**Files:**
- Modify: `core/Cargo.toml` (spark worktree)

- [ ] **Step 1: Push flint and capture the new rev**

```bash
cd /Users/afisk/go/src/github.com/getlantern/flint
git push origin main
git rev-parse HEAD
```

Record the full 40-char SHA printed by `git rev-parse HEAD` — call it `<NEWREV>` below.

- [ ] **Step 2: Bump the three existing pins and add the two new deps**

In `/Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver/core/Cargo.toml`, replace every occurrence of the old rev `56d4d567ff2e16ab7552fd7e39cdf2ae02ff56b7` with `<NEWREV>` (the `flint-shaping`, `flint-tls`, and `flint-verify` lines — **all three must stay on one rev** or two copies of `flint_shaping`/`flint_tls` will be linked). Then add these two new optional deps immediately after the `flint-verify` line (line 55):

```toml
# Bootstrap control-plane name resolution (design: docs/bootstrap-resolver-design.md). flint-dial
# supplies happy-eyeballs racing (race_with / race_windowed); flint-dns supplies the un-poisoned DoH
# resolver + the A/AAAA codec + answer validation. Both optional — only the `bootstrap-dns` feature
# pulls them (and the boring Chrome connector they dial over). Same rev as the other flint crates.
flint-dial = { git = "https://github.com/getlantern/flint", rev = "<NEWREV>", optional = true }
flint-dns = { git = "https://github.com/getlantern/flint", rev = "<NEWREV>", optional = true }
```

- [ ] **Step 3: Add the `bootstrap-dns` feature**

In the same file's `[features]` block, add after the `wasm-transport` line (line 71):

```toml
# Un-poisoned control-plane DNS for startup (design: docs/bootstrap-resolver-design.md). Pulls
# flint-dns/flint-dial with their boring Chrome-mimicry connector, so a proxy `server` can be a
# hostname resolved before the tunnel exists. Off by default — the base build stays boring/cmake-free.
bootstrap-dns = ["dep:flint-dial", "dep:flint-dns", "flint-dial/boring", "flint-dns/boring"]
```

- [ ] **Step 4: Verify the dep graph resolves to one rev and builds both ways**

```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver
cargo build -p spark-core                              # base build, no new deps compiled
cargo build -p spark-core --features bootstrap-dns     # pulls flint-dial/flint-dns + boring (cmake)
cargo tree -p spark-core --features bootstrap-dns -i flint-shaping
```

Expected: both builds succeed; `cargo tree -i flint-shaping` shows a **single** `flint-shaping` node (proves no multi-rev split). The boring cmake build runs once and caches.

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.toml Cargo.lock
git commit -m "build(core): bump flint to <NEWREV>; add bootstrap-dns feature (flint-dial/flint-dns)"
```

---

## Phase B — `config::Endpoint`

Let a proxy `server` be `IP:port` (unchanged path) or `host:port` (resolved at startup). Applies only to the boring transports (`anytls`, `samizdat`); `transport.server` and `wasm.server` stay `SocketAddr`.

### Task B1: the `Endpoint` type

**Files:**
- Modify: `core/src/config/mod.rs`
- Test: same file's `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `core/src/config/mod.rs`:

```rust
    #[test]
    fn endpoint_parses_ip_and_host() {
        assert_eq!(
            "1.2.3.4:443".parse::<Endpoint>().unwrap(),
            Endpoint::Ip("1.2.3.4:443".parse().unwrap())
        );
        assert_eq!(
            "[2001:db8::1]:443".parse::<Endpoint>().unwrap(),
            Endpoint::Ip("[2001:db8::1]:443".parse().unwrap())
        );
        assert_eq!(
            "proxy.example.com:443".parse::<Endpoint>().unwrap(),
            Endpoint::Host { host: "proxy.example.com".into(), port: 443 }
        );
        // junk: no port, empty host, or non-numeric port.
        assert!("notanaddress".parse::<Endpoint>().is_err());
        assert!(":443".parse::<Endpoint>().is_err());
        assert!("host:notaport".parse::<Endpoint>().is_err());
    }

    #[test]
    fn endpoint_socket_addr_and_unresolved() {
        let ip: Endpoint = "1.2.3.4:443".parse().unwrap();
        assert_eq!(ip.socket_addr().unwrap(), "1.2.3.4:443".parse().unwrap());
        assert_eq!(ip.unresolved(), None);

        let host: Endpoint = "h.example:80".parse().unwrap();
        assert!(host.socket_addr().is_err());
        assert_eq!(host.unresolved(), Some(("h.example", 80)));
    }

    #[test]
    fn endpoint_serde_round_trips() {
        // Endpoint serializes/deserializes as a single string, for both variants. Tested directly
        // (not via anytls.server, which is still a SocketAddr until Task B2).
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            e: Endpoint,
        }
        for s in ["1.2.3.4:443", "proxy.example.com:8443"] {
            let w = W { e: s.parse().unwrap() };
            let toml = toml::to_string(&w).unwrap();
            let back: W = toml::from_str(&toml).unwrap();
            assert_eq!(w, back, "round-trip changed:\n{toml}");
        }
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo test -p spark-core endpoint`
Expected: FAIL — `cannot find type Endpoint in this scope`.

- [ ] **Step 3: Define `Endpoint` + `EndpointParseError`**

In `core/src/config/mod.rs`, add (place it right after the imports, before `pub struct Config`):

```rust
/// A proxy server address: a literal `IP:port` ([`Endpoint::Ip`], the unchanged path with no startup
/// DNS) or a `host:port` to resolve before dialing ([`Endpoint::Host`], requires the `bootstrap-dns`
/// feature). Deserializes from a single TOML string. See `docs/bootstrap-resolver-design.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// An already-resolved socket address — dialed directly.
    Ip(SocketAddr),
    /// A hostname + port resolved at startup by the bootstrap resolver.
    Host {
        /// The hostname to resolve.
        host: String,
        /// The port to pair with the resolved address.
        port: u16,
    },
}

impl Endpoint {
    /// The resolved [`SocketAddr`], or an error if this is still an unresolved [`Endpoint::Host`].
    /// The bootstrap phase resolves every `Host` to an `Ip` before the transport is built, so a `Host`
    /// reaching here means resolution didn't run (e.g. built without the `bootstrap-dns` feature).
    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Endpoint::Ip(addr) => Ok(*addr),
            Endpoint::Host { host, port } => Err(io::Error::other(format!(
                "endpoint {host}:{port} was not resolved (build with the `bootstrap-dns` feature to resolve hostnames)"
            ))),
        }
    }

    /// `(host, port)` when this needs resolution; `None` when it is already an [`Endpoint::Ip`].
    pub fn unresolved(&self) -> Option<(&str, u16)> {
        match self {
            Endpoint::Host { host, port } => Some((host.as_str(), *port)),
            Endpoint::Ip(_) => None,
        }
    }
}

impl std::str::FromStr for Endpoint {
    type Err = EndpointParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(Endpoint::Ip(addr));
        }
        let (host, port) = s.rsplit_once(':').ok_or(EndpointParseError)?;
        let port: u16 = port.parse().map_err(|_| EndpointParseError)?;
        if host.is_empty() {
            return Err(EndpointParseError);
        }
        Ok(Endpoint::Host { host: host.to_owned(), port })
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Ip(addr) => write!(f, "{addr}"),
            Endpoint::Host { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// A `[transport.*].server` string was neither `IP:port` nor `host:port`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("endpoint must be `IP:port` or `host:port`")]
pub struct EndpointParseError;

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Serialize for Endpoint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo test -p spark-core endpoint`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/config/mod.rs
git commit -m "feat(config): Endpoint enum (IP:port or host:port) with serde + FromStr"
```

### Task B2: switch `anytls`/`samizdat` `server` to `Endpoint`

**Files:**
- Modify: `core/src/config/mod.rs` (`AnytlsConfig.server`, `SamizdatConfig.server`)
- Modify: `core/src/transport/mod.rs` (read `socket_addr()`; in-file test constructors)

- [ ] **Step 1: Change the two struct fields**

In `core/src/config/mod.rs`, in `AnytlsConfig` change:

```rust
    /// The AnyTLS server address.
    pub server: SocketAddr,
```

to:

```rust
    /// The AnyTLS server address — `IP:port` or `host:port` (resolved at startup, see
    /// `docs/bootstrap-resolver-design.md`).
    pub server: Endpoint,
```

In `SamizdatConfig` change:

```rust
    /// The Samizdat server address.
    pub server: SocketAddr,
```

to:

```rust
    /// The Samizdat server address — `IP:port` or `host:port` (resolved at startup).
    pub server: Endpoint,
```

- [ ] **Step 2: Run to see what breaks (compile failure is the "failing test" here)**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo build -p spark-core --features anytls,samizdat`
Expected: FAIL — `anytls_transport`/`samizdat_transport` call `cfg.server.ip()` / pass `cfg.server` where a `SocketAddr` is needed.

- [ ] **Step 3: Read the resolved `SocketAddr` in the transport builders**

In `core/src/transport/mod.rs`, in `anytls_transport` (the `#[cfg(feature = "anytls")]` one), add a line at the top of the body (before the `sni` binding) and rewrite the three `cfg.server` uses to use it. Replace:

```rust
    let sni = cfg
        .sni
        .clone()
        .unwrap_or_else(|| cfg.server.ip().to_string());
```

with:

```rust
    let server = cfg.server.socket_addr()?;
    let sni = cfg.sni.clone().unwrap_or_else(|| server.ip().to_string());
```

Then in the same function change the dynamic-gambit constructor call's first arg `cfg.server,` → `server,` and the plain constructor call's first arg `cfg.server,` → `server,`.

In `samizdat_transport` (the `#[cfg(feature = "samizdat")]` one), replace:

```rust
    let sni = cfg
        .sni
        .clone()
        .unwrap_or_else(|| cfg.server.ip().to_string());
    let t = Arc::new(samizdat::SamizdatTransport::new(
        cfg.server,
```

with:

```rust
    let server = cfg.server.socket_addr()?;
    let sni = cfg.sni.clone().unwrap_or_else(|| server.ip().to_string());
    let t = Arc::new(samizdat::SamizdatTransport::new(
        server,
```

- [ ] **Step 4: Fix the in-file config-test constructors and add the through-config round-trip**

The `.parse().unwrap()` constructors already produce `Endpoint::Ip` via `FromStr`, so most need no change. Verify the assertion-style comparisons still type-check. In `core/src/config/mod.rs` tests, the `parses_samizdat_config` test asserts:

```rust
        assert_eq!(s.server, "192.0.2.1:443".parse().unwrap());
```

This still works (both sides infer `Endpoint`). The `parses_inline_anytls_gambit_knobs` / `parses_anytls_dynamic_gambit_module` tests don't read `.server`, so they're unaffected. No edits expected here — but run the build to confirm, and only if a constructor fails to infer, annotate it (e.g. `server: "192.0.2.1:443".parse::<Endpoint>().unwrap()`).

Now that `anytls.server` is an `Endpoint`, add a test confirming a **hostname** server round-trips through the real config (this is the case Task B1 couldn't test yet). Add to the `mod tests` block in `core/src/config/mod.rs`:

```rust
    #[test]
    fn anytls_host_server_round_trips_through_toml() {
        for s in ["1.2.3.4:443", "proxy.example.com:8443"] {
            let toml = format!("[transport.anytls]\nserver = \"{s}\"\npassword = \"pw\"\n");
            let c = Config::from_toml_str(&toml).unwrap();
            let rendered = c.to_toml_string().unwrap();
            let back = Config::from_toml_str(&rendered).unwrap();
            assert_eq!(c, back, "round-trip changed:\n{rendered}");
        }
        // And the hostname actually lands as Endpoint::Host.
        let c = Config::from_toml_str(
            "[transport.anytls]\nserver = \"proxy.example.com:8443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        assert_eq!(
            c.transport.anytls.unwrap().server,
            Endpoint::Host { host: "proxy.example.com".into(), port: 8443 }
        );
    }
```

- [ ] **Step 5: Run the full feature build + tests**

Run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver
cargo build -p spark-core --features anytls,samizdat
cargo test -p spark-core --features anytls,samizdat
```
Expected: PASS — including `samizdat_config_tests`, `anytls_gambit_config_tests`, and the `config` round-trip tests.

- [ ] **Step 6: Commit**

```bash
git add core/src/config/mod.rs core/src/transport/mod.rs
git commit -m "feat(transport): anytls/samizdat server is an Endpoint; resolve to SocketAddr at build"
```

---

## Phase C — `spark_core::bootstrap` module

The resolver itself. All of it is behind `bootstrap-dns`; the only always-compiled piece is the `resolve_bootstrap` shim (Task C5) and `Config::first_unresolved_host` (Task C4).

### Task C1: module skeleton + `NameResolver` + `RacingResolver`

**Files:**
- Create: `core/src/bootstrap/mod.rs`
- Modify: `core/src/lib.rs` (declare the module)

- [ ] **Step 1: Declare the module (gated)**

In `core/src/lib.rs`, add after the `pub mod transport;` line:

```rust
/// Control-plane name resolution for startup (design: docs/bootstrap-resolver-design.md). Resolves a
/// proxy `server` hostname to validated IPs via an un-poisoned Chrome-mimicry DoH race, before any
/// tunnel exists. Behind `bootstrap-dns` (pulls flint-dns/flint-dial + boring).
#[cfg(feature = "bootstrap-dns")]
pub mod bootstrap;
```

- [ ] **Step 2: Write the failing test**

Create `core/src/bootstrap/mod.rs` with the trait, `RacingResolver`, and its test (no network — fake strategies):

```rust
//! Un-poisoned control-plane name resolution for spark startup (design:
//! `docs/bootstrap-resolver-design.md`).
//!
//! Resolution races at two levels: an *outer* race across strategies ([`RacingResolver`] over
//! [`DohResolver`] / [`ProxyResolver`]) and an *inner* race within DoH across the resolver pool
//! (`flint_dns::resolve`). Neither a blocked strategy nor a blocked individual resolver holds up the
//! first **validated** answer.

// Import the full set the module uses by the end of Phase C. `Arc`/`Duration`/`Config`/`Endpoint`/
// `UdpTransport` are used by Tasks C2–C4; they produce harmless unused-import warnings until then
// (this task's gate is `cargo test`, where warnings don't fail; the `-D warnings` clippy gate runs at
// the end of Phase C, by which point all are used).
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::{Config, Endpoint};
use crate::transport::UdpTransport;

/// Resolves a control-plane hostname to its first **validated** address. One impl per resolution
/// strategy; [`RacingResolver`] composes several. A trait so the wiring is unit-testable with a fake.
#[async_trait]
pub trait NameResolver: Send + Sync {
    /// Resolve `host` to a `SocketAddr` on `port`, returning the first validated address.
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr>;
}

/// The outer happy-eyeballs race: holds an ordered set of strategy resolvers and returns the first
/// that yields a validated answer; errors only if every strategy fails.
pub struct RacingResolver {
    strategies: Vec<Box<dyn NameResolver>>,
}

impl RacingResolver {
    /// Race the given strategies (order is informational; all start together — the field is small).
    pub fn new(strategies: Vec<Box<dyn NameResolver>>) -> Self {
        Self { strategies }
    }
}

#[async_trait]
impl NameResolver for RacingResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        match flint_dial::race_with(self.strategies.len(), |i| self.strategies[i].resolve(host, port))
            .await
        {
            Ok((_winner, addr)) => Ok(addr),
            Err(errors) => Err(io::Error::other(format!(
                "all {} resolver strategies failed for {host}: {errors:?}",
                self.strategies.len()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(io::Result<SocketAddr>);
    #[async_trait]
    impl NameResolver for Fixed {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<SocketAddr> {
            match &self.0 {
                Ok(a) => Ok(*a),
                Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
            }
        }
    }

    fn ok(s: &str) -> Box<dyn NameResolver> {
        Box::new(Fixed(Ok(s.parse().unwrap())))
    }
    fn fail() -> Box<dyn NameResolver> {
        Box::new(Fixed(Err(io::Error::other("decline"))))
    }

    #[tokio::test]
    async fn first_validated_wins() {
        let r = RacingResolver::new(vec![fail(), ok("1.2.3.4:443")]);
        assert_eq!(r.resolve("h", 443).await.unwrap(), "1.2.3.4:443".parse().unwrap());
    }

    #[tokio::test]
    async fn all_fail_is_an_error() {
        let r = RacingResolver::new(vec![fail(), fail()]);
        assert!(r.resolve("h", 443).await.is_err());
    }
}
```

- [ ] **Step 3: Run to verify the tests pass**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo test -p spark-core --features bootstrap-dns bootstrap::tests`
Expected: PASS (`first_validated_wins`, `all_fail_is_an_error`). This task introduces both the code and its tests together. Unused-import warnings for `Arc`/`Duration`/`Config`/`Endpoint`/`UdpTransport` are expected here and resolved by C2–C4; `cargo test` doesn't fail on warnings.

- [ ] **Step 4: Commit**

```bash
git add core/src/lib.rs core/src/bootstrap/mod.rs
git commit -m "feat(bootstrap): NameResolver trait + RacingResolver (outer happy-eyeballs race)"
```

### Task C2: `DohResolver`

**Files:**
- Modify: `core/src/bootstrap/mod.rs`

- [ ] **Step 1: Add the implementation**

Add to `core/src/bootstrap/mod.rs` (after `RacingResolver`'s `impl NameResolver`):

```rust
/// The always-available strategy: resolve over `flint_dns`'s un-poisoned DoH pool (the inner race).
/// Takes the first validated A record. The per-network winner cache is intentionally **not** used
/// here (design §3.1) — bootstrap is infrequent and a stale cached winner could eat a timeout.
pub struct DohResolver {
    pool: Vec<flint_dns::Resolver>,
}

impl Default for DohResolver {
    fn default() -> Self {
        Self { pool: flint_dns::default_pool() }
    }
}

#[async_trait]
impl NameResolver for DohResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        let ips = flint_dns::resolve(host, flint_dns::TYPE_A, &self.pool)
            .await
            .map_err(io::Error::other)?;
        let ip = ips
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other("DoH returned no A records"))?;
        Ok(SocketAddr::new(ip, port))
    }
}
```

- [ ] **Step 2: Build (no unit test — exercised by the live e2e in Task C6)**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo build -p spark-core --features bootstrap-dns`
Expected: PASS. (`DohResolver` calls real DoH; its happy path is covered by the `#[ignore]` live test in C6, mirroring `flint-dns`'s own live test. No fake is meaningful here because `flint_dns::resolve` owns the network.)

- [ ] **Step 3: Commit**

```bash
git add core/src/bootstrap/mod.rs
git commit -m "feat(bootstrap): DohResolver over the flint-dns un-poisoned DoH pool"
```

### Task C3: `ProxyResolver` (tunnel a DNS query through an IP proxy)

**Files:**
- Modify: `core/src/bootstrap/mod.rs`

- [ ] **Step 1: Write the failing tests (fake `UdpTransport`, no network)**

Add to the `mod tests` block in `core/src/bootstrap/mod.rs`:

```rust
    use crate::transport::{BoxedPacketSink, BoxedPacketSource, PacketSink, PacketSource};

    /// A canned A-record response for `name` → `ip`, matching `flint_dns::codec::parse_response`
    /// (header, one question, one answer with a 0xC00C name pointer).
    fn dns_response_a(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&[0x00, 0x00]); // ID
        m.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, rcode=0
        m.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        m.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
        m.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS/AR
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        m.extend_from_slice(&[0xc0, 0x0c]); // answer NAME → pointer to the question
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL 300
        m.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        m.extend_from_slice(&ip);
        m
    }

    struct FakeUdp {
        response: Vec<u8>,
    }
    #[async_trait]
    impl UdpTransport for FakeUdp {
        async fn dial_udp(
            &self,
            _target: SocketAddr,
        ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
            Ok((
                Box::new(FakeSink),
                Box::new(FakeSource { response: self.response.clone() }),
            ))
        }
    }
    struct FakeSink;
    #[async_trait]
    impl PacketSink for FakeSink {
        async fn send(&mut self, _payload: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }
    struct FakeSource {
        response: Vec<u8>,
    }
    #[async_trait]
    impl PacketSource for FakeSource {
        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.response.len().min(buf.len());
            buf[..n].copy_from_slice(&self.response[..n]);
            Ok(n)
        }
    }

    #[tokio::test]
    async fn proxy_resolver_parses_and_validates() {
        let udp: Arc<dyn UdpTransport> = Arc::new(FakeUdp {
            response: dns_response_a("example.com", [93, 184, 216, 34]),
        });
        let r = ProxyResolver::new(udp, vec!["8.8.8.8:53".parse().unwrap()]);
        assert_eq!(
            r.resolve("example.com", 443).await.unwrap(),
            "93.184.216.34:443".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn proxy_resolver_rejects_a_bogon() {
        let udp: Arc<dyn UdpTransport> = Arc::new(FakeUdp {
            response: dns_response_a("example.com", [0, 0, 0, 0]), // 0.0.0.0 is a bogon
        });
        let r = ProxyResolver::new(udp, vec!["8.8.8.8:53".parse().unwrap()]);
        assert!(r.resolve("example.com", 443).await.is_err());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo test -p spark-core --features bootstrap-dns proxy_resolver`
Expected: FAIL — `cannot find type ProxyResolver`.

- [ ] **Step 3: Implement `ProxyResolver`**

Add to `core/src/bootstrap/mod.rs` (after `DohResolver`). Add the imports `use std::sync::Arc;`, `use std::time::Duration;`, and `use crate::transport::UdpTransport;` to the top of the file if not already present (from C1's correction they belong here):

```rust
/// Resolve a name by tunnelling a plain DNS/UDP query **through a proxy** addressed by IP: the exit
/// resolves upstream un-poisoned. Reuses `flint_dns`'s codec + answer validation. Independent of the
/// data-plane tunnel — it only needs the transport's UDP client. Chicken-and-egg (design §3.1): a
/// proxy named by *hostname* can't resolve itself through a proxy, so this only adds racers for
/// already-IP-addressed proxies.
pub struct ProxyResolver {
    udp: Arc<dyn UdpTransport>,
    upstreams: Vec<SocketAddr>,
    deadline: Duration,
}

impl ProxyResolver {
    /// A `ProxyResolver` that races `upstreams` (public recursive resolvers, e.g. `8.8.8.8:53`) over
    /// `udp`. Each attempt is bounded by a 5s deadline so an all-fail returns promptly.
    pub fn new(udp: Arc<dyn UdpTransport>, upstreams: Vec<SocketAddr>) -> Self {
        Self { udp, upstreams, deadline: Duration::from_secs(5) }
    }

    async fn query_one(&self, upstream: SocketAddr, host: &str, port: u16) -> io::Result<SocketAddr> {
        let (mut sink, mut source) = self.udp.dial_udp(upstream).await?;
        let query = flint_dns::codec::build_query(host, flint_dns::TYPE_A).map_err(io::Error::other)?;
        sink.send(&query).await?;
        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(self.deadline, source.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS-through-proxy timed out"))??;
        let answers = flint_dns::codec::parse_response(&buf[..n]).map_err(io::Error::other)?;
        let validated = flint_dns::validate::validate_answers(answers).map_err(io::Error::other)?;
        let ip = validated
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other("no validated A records"))?;
        Ok(SocketAddr::new(ip, port))
    }
}

#[async_trait]
impl NameResolver for ProxyResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        match flint_dial::race_with(self.upstreams.len(), |i| {
            self.query_one(self.upstreams[i], host, port)
        })
        .await
        {
            Ok((_winner, addr)) => Ok(addr),
            Err(errors) => Err(io::Error::other(format!(
                "all {} proxy upstreams failed for {host}: {errors:?}",
                self.upstreams.len()
            ))),
        }
    }
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo test -p spark-core --features bootstrap-dns proxy_resolver`
Expected: PASS — both `proxy_resolver_parses_and_validates` and `proxy_resolver_rejects_a_bogon`.

- [ ] **Step 5: Commit**

```bash
git add core/src/bootstrap/mod.rs
git commit -m "feat(bootstrap): ProxyResolver — tunnel a DNS query through an IP proxy"
```

### Task C4: `resolve_endpoints` + `default_resolver`

**Files:**
- Modify: `core/src/bootstrap/mod.rs`

- [ ] **Step 1: Write the failing test (fake `NameResolver`, no network)**

Add to the `mod tests` block in `core/src/bootstrap/mod.rs`:

```rust
    use crate::config::{AnytlsConfig, Endpoint, TransportConfig};

    fn anytls_cfg(server: &str) -> Config {
        Config {
            transport: TransportConfig {
                anytls: Some(AnytlsConfig {
                    server: server.parse().unwrap(),
                    password: "pw".into(),
                    sni: None,
                    clienthello: Default::default(),
                    records: Default::default(),
                    gambit: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn resolve_endpoints_rewrites_host_to_ip() {
        let mut cfg = anytls_cfg("proxy.example.com:443");
        let resolver = RacingResolver::new(vec![ok("5.6.7.8:443")]);
        resolve_endpoints(&mut cfg, &resolver).await.unwrap();
        assert_eq!(
            cfg.transport.anytls.unwrap().server,
            Endpoint::Ip("5.6.7.8:443".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn resolve_endpoints_leaves_ip_untouched() {
        let mut cfg = anytls_cfg("1.2.3.4:443");
        // A resolver that would panic if called — proves an Ip endpoint never hits it.
        let resolver = RacingResolver::new(vec![fail()]);
        resolve_endpoints(&mut cfg, &resolver).await.unwrap();
        assert_eq!(
            cfg.transport.anytls.unwrap().server,
            Endpoint::Ip("1.2.3.4:443".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn resolve_endpoints_all_fail_is_an_error() {
        let mut cfg = anytls_cfg("proxy.example.com:443");
        let resolver = RacingResolver::new(vec![fail()]);
        assert!(resolve_endpoints(&mut cfg, &resolver).await.is_err());
    }
```

(Note: `AnytlsConfig` has `gambit` only with the `wasm-transport` feature off it still has the field — it's always present in the struct. If a compile error says `gambit` is unexpected, the field exists unconditionally per `config/mod.rs`, so this is correct.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo test -p spark-core --features bootstrap-dns resolve_endpoints`
Expected: FAIL — `cannot find function resolve_endpoints`.

- [ ] **Step 3: Implement `resolve_endpoints` + `default_resolver`**

Add to `core/src/bootstrap/mod.rs` (after `ProxyResolver`). Ensure `use crate::config::Config;` and `use crate::config::Endpoint;` are imported at the top:

```rust
/// Resolve every `Endpoint::Host` proxy `server` in `config` to an `Endpoint::Ip` via `resolver`
/// (design §3.3). An already-resolved `Ip` is left untouched. Errors with a clear message if any host
/// fails to resolve — **no silent fallthrough** to a poisoned/system lookup.
pub async fn resolve_endpoints(config: &mut Config, resolver: &dyn NameResolver) -> io::Result<()> {
    let mut servers: Vec<&mut Endpoint> = Vec::new();
    if let Some(anytls) = config.transport.anytls.as_mut() {
        servers.push(&mut anytls.server);
    }
    if let Some(samizdat) = config.transport.samizdat.as_mut() {
        servers.push(&mut samizdat.server);
    }
    for ep in servers {
        if let Some((host, port)) = ep.unresolved() {
            let host = host.to_owned();
            let addr = resolver.resolve(&host, port).await.map_err(|e| {
                io::Error::other(format!("couldn't resolve {host}:{port}: {e}"))
            })?;
            *ep = Endpoint::Ip(addr);
        }
    }
    Ok(())
}

/// Build the default startup resolver. v1: DoH only — it is the always-available, un-poisoned path.
/// `ProxyResolver` needs an IP-addressed proxy to tunnel a query through, but with spark's current
/// single-proxy config a proxy named by *hostname* is exactly the case being resolved, so there is no
/// IP proxy to add here (chicken-and-egg, design §3.1). `ProxyResolver` is built + tested for the
/// future multi-proxy / API config-fetch consumer, which will construct it directly.
pub fn default_resolver(_config: &Config) -> RacingResolver {
    RacingResolver::new(vec![Box::new(DohResolver::default())])
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo test -p spark-core --features bootstrap-dns resolve_endpoints`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/bootstrap/mod.rs
git commit -m "feat(bootstrap): resolve_endpoints + default_resolver (DoH-only v1)"
```

### Task C5: the always-compiled `resolve_bootstrap` shim + `first_unresolved_host`

**Files:**
- Modify: `core/src/config/mod.rs` (`Config::first_unresolved_host`)
- Modify: `core/src/lib.rs` (`resolve_bootstrap`, two cfg bodies)

- [ ] **Step 1: Write the failing test for the feature-off path**

Add to the `mod tests` block in `core/src/config/mod.rs`:

```rust
    #[test]
    fn first_unresolved_host_finds_a_hostname() {
        let c = Config::from_toml_str(
            "[transport.anytls]\nserver = \"proxy.example.com:443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        assert_eq!(c.first_unresolved_host().as_deref(), Some("proxy.example.com:443"));

        let c2 = Config::from_toml_str(
            "[transport.anytls]\nserver = \"1.2.3.4:443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        assert_eq!(c2.first_unresolved_host(), None);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo test -p spark-core first_unresolved_host`
Expected: FAIL — `no method named first_unresolved_host`.

- [ ] **Step 3: Implement `first_unresolved_host`**

In `core/src/config/mod.rs`, in the existing `impl Config` block (where `from_toml_str` etc. live), add:

```rust
    /// The first proxy `server` configured as a hostname needing resolution (`"host:port"`), or
    /// `None` if every configured server is an IP literal. Used to fail fast when a hostname is
    /// configured but the resolver wasn't built in (no `bootstrap-dns` feature).
    pub fn first_unresolved_host(&self) -> Option<String> {
        let servers = [
            self.transport.anytls.as_ref().map(|c| &c.server),
            self.transport.samizdat.as_ref().map(|c| &c.server),
        ];
        servers
            .into_iter()
            .flatten()
            .find_map(|ep| ep.unresolved().map(|(h, p)| format!("{h}:{p}")))
    }
```

- [ ] **Step 4: Implement the `resolve_bootstrap` shim**

In `core/src/lib.rs`, add at the end of the file (after the `BoxedStream` type alias):

```rust
/// Bootstrap phase: resolve every `Endpoint::Host` proxy `server` in `config` to an `Endpoint::Ip`
/// before the transport is built (design §3.3). With `bootstrap-dns` this uses the un-poisoned
/// Chrome-mimicry resolver; without it, a configured hostname is a hard error — never a silent
/// system-DNS fallback. An all-IP config is a no-op (and works with the feature off).
#[cfg(feature = "bootstrap-dns")]
pub async fn resolve_bootstrap(config: &mut config::Config) -> std::io::Result<()> {
    let resolver = bootstrap::default_resolver(config);
    bootstrap::resolve_endpoints(config, &resolver).await
}

/// See the `bootstrap-dns` variant. Without the feature, a configured hostname is rejected explicitly.
#[cfg(not(feature = "bootstrap-dns"))]
pub async fn resolve_bootstrap(config: &mut config::Config) -> std::io::Result<()> {
    if let Some(host) = config.first_unresolved_host() {
        return Err(std::io::Error::other(format!(
            "proxy server `{host}` is a hostname, which requires the bootstrap-dns feature"
        )));
    }
    Ok(())
}
```

(Note: `bootstrap-dns` is intentionally *not* backtick-wrapped in the message so it matches the test's `contains("bootstrap-dns feature")` assertion below.)

- [ ] **Step 5: Add a feature-off behavior test for the shim**

Add a gated test module at the end of `core/src/lib.rs` (covers spec §5: a `Host` with the feature off is an explicit error; an all-IP config is a no-op):

```rust
#[cfg(all(test, not(feature = "bootstrap-dns")))]
mod resolve_bootstrap_tests {
    use crate::config::Config;

    #[tokio::test]
    async fn host_without_the_feature_is_an_explicit_error() {
        let mut cfg = Config::from_toml_str(
            "[transport.anytls]\nserver = \"proxy.example.com:443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        let err = super::resolve_bootstrap(&mut cfg).await.unwrap_err();
        assert!(err.to_string().contains("bootstrap-dns feature"));
    }

    #[tokio::test]
    async fn all_ip_config_is_a_noop() {
        let mut cfg = Config::from_toml_str(
            "[transport.anytls]\nserver = \"1.2.3.4:443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        super::resolve_bootstrap(&mut cfg).await.expect("all-IP config resolves trivially");
    }
}
```

- [ ] **Step 6: Run both feature configurations**

Run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver
cargo test -p spark-core first_unresolved_host                    # feature off
cargo build -p spark-core                                          # resolve_bootstrap (feature-off body)
cargo build -p spark-core --features bootstrap-dns                 # resolve_bootstrap (feature-on body)
```
Expected: PASS (including the two `resolve_bootstrap_tests`) / both builds succeed.

- [ ] **Step 7: Commit**

```bash
git add core/src/config/mod.rs core/src/lib.rs
git commit -m "feat(bootstrap): resolve_bootstrap shim (feature-gated) + Config::first_unresolved_host"
```

### Task C6: live-gated e2e for `DohResolver`

**Files:**
- Modify: `core/src/bootstrap/mod.rs`

- [ ] **Step 1: Add the `#[ignore]` live test**

Add to the `mod tests` block in `core/src/bootstrap/mod.rs`:

```rust
    /// Live end-to-end: `DohResolver` resolves a real hostname to a public (non-bogon) address.
    /// Requires network egress + boring; `#[ignore]`d in CI, mirroring flint-dns's own live test.
    /// Run with: `cargo test -p spark-core --features bootstrap-dns -- --ignored doh_resolves_live`
    #[tokio::test]
    #[ignore = "live: requires network egress to public DoH resolvers"]
    async fn doh_resolves_live() {
        let r = DohResolver::default();
        let addr = r.resolve("one.one.one.one", 443).await.expect("resolve via DoH");
        assert_eq!(addr.port(), 443);
        assert!(!flint_dns::validate::is_bogon(addr.ip()));
    }
```

- [ ] **Step 2: Verify it compiles (ignored, not run)**

Run: `cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver && cargo test -p spark-core --features bootstrap-dns doh_resolves_live -- --list`
Expected: the test is listed (compiles) and not executed.

- [ ] **Step 3 (optional, manual): run it live**

Run: `cargo test -p spark-core --features bootstrap-dns -- --ignored doh_resolves_live`
Expected (with network): PASS — resolves `one.one.one.one` to a public IP on port 443.

- [ ] **Step 4: Lint + commit**

```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver
cargo clippy -p spark-core --features bootstrap-dns -- -D warnings
cargo fmt
git add core/src/bootstrap/mod.rs
git commit -m "test(bootstrap): live-gated e2e DohResolver resolution"
```

---

## Phase D — wire the bootstrap phase into the entry points

Call `resolve_bootstrap` right before each `transport::from_config`. All three sites are already in an async/tokio context.

### Task D1: CLI (`run_tunnel`)

**Files:**
- Modify: `cli/src/main.rs`
- Modify: `cli/Cargo.toml`

- [ ] **Step 1: Make `config` mutable and resolve before building the transport**

In `cli/src/main.rs`, in `run_tunnel`, change `let config = match &args.config {` to `let mut config = match &args.config {`. Then add the resolve call right after `init_tracing(config.log.debug);`:

```rust
    spark_core::resolve_bootstrap(&mut config)
        .await
        .context("resolving bootstrap endpoints")?;
```

(Place it before the TUN open. The existing `info!` logging of `anytls.server` works because `Endpoint` implements `Display` — and after this call the logged value is the resolved IP.)

- [ ] **Step 2: Add the feature passthrough**

In `cli/Cargo.toml`, in `[features]`, add a `bootstrap-dns` feature that forwards to core. (If the CLI has a `default`/`anytls`/`samizdat` feature, mirror its forwarding style.) Add:

```toml
bootstrap-dns = ["spark-core/bootstrap-dns"]
```

- [ ] **Step 3: Build both ways**

Run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver
cargo build -p spark-cli                                      # feature-off resolve_bootstrap shim
cargo build -p spark-cli --features anytls,bootstrap-dns      # feature-on path
```
Expected: both succeed. (`cli/Cargo.toml`: package `spark-cli`, binary `spark`.)

- [ ] **Step 4: Commit**

```bash
git add cli/src/main.rs cli/Cargo.toml
git commit -m "feat(cli): resolve bootstrap endpoints before building the transport"
```

### Task D2: embedded fd path (`fd_tunnel::run_with_handle`)

**Files:**
- Modify: `core/src/fd_tunnel.rs`

- [ ] **Step 1: Resolve inside the runtime block, before `from_config`**

In `core/src/fd_tunnel.rs`, in `run_with_handle`, inside the `runtime.block_on(async move { ... })` body, the `config` is moved in. Add a mutable rebind as the first line of the async block and the resolve call before `transport::from_config`. Change:

```rust
    let result = runtime.block_on(async move {
        // SAFETY: `fd` is the TUN fd from the OS ...
        let tun = Arc::new(
            unsafe { Tun::from_fd(fd, mtu) }.map_err(|e| std::io::Error::other(e.to_string()))?,
        );

        let (tcp_transport, udp_transport) = transport::from_config(&config)?;
```

to:

```rust
    let result = runtime.block_on(async move {
        let mut config = config;
        crate::resolve_bootstrap(&mut config).await?;
        // SAFETY: `fd` is the TUN fd from the OS ...
        let tun = Arc::new(
            unsafe { Tun::from_fd(fd, mtu) }.map_err(|e| std::io::Error::other(e.to_string()))?,
        );

        let (tcp_transport, udp_transport) = transport::from_config(&config)?;
```

(`resolve_bootstrap` returns `io::Result<()>`; the block already returns `io::Result`, so `?` flows. The `mut config` rebind silences the "unused mut" / borrow concerns since `config` is owned by the future.)

- [ ] **Step 2: Build for a mobile-ish target gate**

`fd_tunnel` is `#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]`. On macOS this compiles in the default build:

Run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver
cargo build -p spark-core                                   # fd_tunnel compiled on macOS (feature off)
cargo build -p spark-core --features bootstrap-dns
```
Expected: both succeed.

- [ ] **Step 3: Commit**

```bash
git add core/src/fd_tunnel.rs
git commit -m "feat(fd_tunnel): resolve bootstrap endpoints before building the transport"
```

### Task D3: service engine (`CoreEngine::start`)

**Files:**
- Modify: `service/src/engine.rs`
- Modify: `service/Cargo.toml`

- [ ] **Step 1: Resolve before `from_config` in `start`**

In `service/src/engine.rs`, change the `start` signature's `config: Config` to `mut config: Config`:

```rust
    async fn start(&mut self, mut config: Config, exit: mpsc::Sender<()>) -> Result<(), EngineError> {
```

Then add the resolve call right before `let (tcp_transport, udp_transport) = transport::from_config(&config)`:

```rust
        spark_core::resolve_bootstrap(&mut config)
            .await
            .map_err(|e| EngineError(format!("resolving bootstrap endpoints: {e}")))?;
```

(If `engine.rs` imports `transport` via `use spark_core::transport;`, then `spark_core::resolve_bootstrap` is reachable by the same crate path. If it uses a `use spark_core::{...}` group, add `resolve_bootstrap` to it or use the full `spark_core::resolve_bootstrap` path as written.)

- [ ] **Step 2: Add the feature passthrough**

In `service/Cargo.toml`, in `[features]`, add:

```toml
bootstrap-dns = ["spark-core/bootstrap-dns"]
```

- [ ] **Step 3: Build both ways**

Run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver
cargo build -p spark-service
cargo build -p spark-service --features bootstrap-dns
```
Expected: both succeed. (`service/Cargo.toml`: package `spark-service`.)

- [ ] **Step 4: Commit**

```bash
git add service/src/engine.rs service/Cargo.toml
git commit -m "feat(service): resolve bootstrap endpoints before building the transport"
```

### Task D4: workspace green sweep

**Files:** none (verification)

- [ ] **Step 1: Full clippy + test across the relevant feature sets**

Run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-bootstrap-resolver
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features bootstrap-dns,anytls,samizdat -- -D warnings
cargo test --workspace
cargo test --workspace --features bootstrap-dns,anytls,samizdat
```
Expected: all clean / all pass. (Feature flags are forwarded per-crate; if a workspace-level `--features` errors because not every crate defines them, run the feature builds per package: `-p spark-core`, `-p spark-cli`, `-p spark-service`.)

- [ ] **Step 2: Report the release binary size (CLAUDE.md discipline)**

Run: `cargo build --release -p spark-cli --features anytls,bootstrap-dns && ls -lh target/release/spark`
Expected: record the stripped size (the `spark-cli` package's binary is named `spark`); note it in the PR (the <3 MB target applies to the base build; the boring-bearing feature build is larger and expected).

- [ ] **Step 3: Push the branch and open the PR**

```bash
git push -u origin bootstrap-resolver
```

PR body should summarize: the two-world DNS framing (in-tunnel vs control-plane), the `Endpoint` type, the two-level race (outer strategies / inner windowed DoH pool), the flint `race_windowed` enhancement, and that the base build is unaffected (boring/cmake-free; hostname + feature-off = explicit error). Include a mermaid `sequenceDiagram` of the startup flow (`load Config → resolve_bootstrap → from_config → dial`) since the change spans config → bootstrap → transport across the entry points.

---

## Notes for the implementer

- **One flint rev everywhere.** After Task A3, all five flint deps (`flint-shaping`, `flint-tls`, `flint-verify`, `flint-dial`, `flint-dns`) must be pinned to the *same* `<NEWREV>`. A mismatch silently links two copies of `flint_shaping`/`flint_tls` and produces baffling type-mismatch errors. `cargo tree -i flint-shaping` is the check.
- **Boring build cost.** Any `--features bootstrap-dns` (or `anytls`/`samizdat`) command triggers a one-time cmake BoringSSL build. It caches; don't be alarmed by the first slow compile.
- **No scope creep.** This plan adds *only* control-plane name resolution for startup dials. The per-flow router (#2), fake-IP DNS interception + per-category resolver policy (#3), app-split (#4), and the API config-fetch are separate sub-projects (design §7). `ProxyResolver` is built and tested but wired into `default_resolver` only when a future multi-proxy config supplies an IP proxy.
- **Crate/binary names (confirmed).** CLI: package `spark-cli`, binary `spark`. Service: package `spark-service`. Core: package `spark-core`, lib `spark_core`. The `<NEWREV>` flint SHA is the only value still resolved at execution time (it doesn't exist until A1–A2 are pushed).
