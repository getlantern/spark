# Config-new fetch (v1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended)
> or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Spark's NE extension fetches its server pool from the Lantern `config-new` API (direct TLS,
free-tier), caches it on disk, refreshes on a server-driven offline-resilient loop, and feeds the
response into the merged `config_raw.json` adapter.

**Architecture:** A new `core::config::fetch` module (feature `config-fetch`, which implies `anytls`
for the boring TLS already used by `probe`). It reuses `DirectTransport` + `probe::tls_wrap` to do a
hand-rolled HTTPS `POST` (no `reqwest`/`hyper`), maps the JSON response through
`Config::from_config_str`, persists last-good to a caller-supplied data dir, and runs a poll loop
(server `poll_interval_seconds`, ≥10s/10min; quadratic backoff on failure, never gives up). The Apple
NE `build_config` selects it via a reserved `lantern-api` config sentinel.

**Tech Stack:** Rust (edition 2021), tokio, `serde`/`serde_json`, `boring2`/`tokio-boring2` (TLS, via
`anytls`), `ring` (device-id RNG), the existing `core::transport::{DirectTransport, probe}`.

**Spec:** `docs/config-new-fetch-design.md`. **Branch:** `fisk/config-new-fetch`.

---

## File structure

- Create `core/src/config/fetch/mod.rs` — orchestration: `FetchEnv`/`FetchOptions`, `FetchOutcome`,
  `device_id`, `fetch_once`, `load_or_fetch`, `run_loop`, `poll_after`.
- Create `core/src/config/fetch/request.rs` — `ConfigRequest` + `build_request_bytes` (request line +
  `X-Lantern-*`/conditional headers + JSON body).
- Create `core/src/config/fetch/http.rs` — `post_collect` (write request, parse status + `ETag` + body
  over any `AsyncRead+AsyncWrite`).
- Create `core/src/config/fetch/cache.rs` — `CacheMeta`, `load`, `store` (atomic), in a data dir.
- Modify `core/Cargo.toml` — add the `config-fetch` feature.
- Modify `core/src/config/mod.rs` — `#[cfg(feature = "config-fetch")] pub mod fetch;`.
- Modify `core/src/transport/probe.rs` — make `tls_wrap` and `http`-status parsing reusable
  (`pub(crate)`).
- Modify `platforms/apple/src/lib.rs` — `build_config`: the `lantern-api` sentinel → run the fetch.

---

## Task 1: Feature + module skeleton

**Files:**
- Modify: `core/Cargo.toml` (`[features]`)
- Modify: `core/src/config/mod.rs`
- Create: `core/src/config/fetch/mod.rs`

- [ ] **Step 1: Add the feature**

In `core/Cargo.toml` under `[features]`, after the `multi-server` line:

```toml
# Fetch config from the Lantern config-new API (design: docs/config-new-fetch-design.md). Pulls
# `anytls` for the boring TLS the hand-rolled HTTP client uses, AND `multi-server` — the adapter always
# maps the response into a `transport.servers` pool, which `from_config_with_control` can't build
# without it (errors at connect). `serde_json` (already a dep) parses the JSON. Hostname pool members
# additionally need `bootstrap-dns`, a build-level add (see Task 10 Step 3). Off by default.
config-fetch = ["anytls", "multi-server"]
```

> **Note (final-review fix):** an earlier draft had `config-fetch = ["anytls"]`. That builds a binary
> whose `lantern-api` mode always fails at connect, because the adapter unconditionally produces a
> `transport.servers` pool and `build_selecting` is a `multi-server`-gated stub otherwise. `multi-server`
> is therefore an unconditional dependency of `config-fetch`.

- [ ] **Step 2: Declare the module (gated)**

In `core/src/config/mod.rs`, right after the `pub mod lantern;` declaration:

```rust
/// Fetch config from the Lantern `config-new` API and feed it into [`lantern`] (Phase 3 fetch half).
#[cfg(feature = "config-fetch")]
pub mod fetch;
```

- [ ] **Step 3: Create the module with a smoke test**

`core/src/config/fetch/mod.rs`:

```rust
//! Fetch Spark's server pool from the Lantern `config-new` API (design:
//! `docs/config-new-fetch-design.md`). Direct TLS (no fronting yet), free-tier, disk-cached, fed into
//! [`crate::config::Config::from_config_str`]. Trust is TLS — no signature, matching radiance.

mod cache;
mod http;
mod request;

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        // Placeholder smoke test; real behavior is covered in later tasks.
        assert_eq!(2 + 2, 4);
    }
}
```

(`cache`/`http`/`request` are created in Tasks 2–4; declare them now so the module tree is fixed. If
the build can't find them yet, create empty files `core/src/config/fetch/{cache,http,request}.rs` with
a single `//! placeholder` line and fill them in those tasks.)

- [ ] **Step 4: Verify it builds**

Run: `cd core && cargo build --features config-fetch`
Expected: builds clean (warnings about unused empty modules are fine until Task 2+).

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.toml core/src/config/mod.rs core/src/config/fetch/
git commit -m "feat(config-fetch): module skeleton + feature flag"
```

---

## Task 2: `ConfigRequest` + request bytes

**Files:**
- Create/replace: `core/src/config/fetch/request.rs`

- [ ] **Step 1: Write the failing tests**

`core/src/config/fetch/request.rs`:

```rust
//! The `config-new` request: the JSON body (`ConfigRequest`) + the HTTP request bytes (request line,
//! `X-Lantern-*` + conditional headers, body). Mirrors radiance `common.ConfigRequest` + headers.go.

use serde::Serialize;

/// Free-tier `config-new` request body. `user_id`/`pro_token`/`wg_public_key` are intentionally
/// absent in v1. `backend = "sing-box"` so the API returns the `config_raw.json` shape the adapter
/// reads; `protocols` lists only the kinds the adapter maps, so we don't get unusable outbounds.
///
/// `time_zone` rides the `X-Lantern-Time-Zone` **header**, not the JSON body, so it is `#[serde(skip)]`.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigRequest {
    pub device_id: String,
    pub platform: String,
    pub app_name: String,
    pub backend: String,
    pub singbox_version: String,
    pub version: String,
    pub locale: String,
    pub protocols: Vec<String>,
    #[serde(skip)]
    pub time_zone: String,
}

impl ConfigRequest {
    /// The free-tier default request for this build.
    pub fn new(device_id: String) -> Self {
        ConfigRequest {
            device_id,
            platform: std::env::consts::OS.to_string(), // "macos"/"linux"/...
            app_name: "spark".to_string(),
            backend: "sing-box".to_string(),
            singbox_version: "1.11.0".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            locale: "en-US".to_string(),
            protocols: vec![
                "samizdat".to_string(),
                "hysteria2".to_string(),
                "shadowsocks".to_string(),
            ],
            time_zone: local_timezone(),
        }
    }
}

/// Best-effort IANA time zone (e.g. `"America/New_York"`) for the `X-Lantern-Time-Zone` header. Reads
/// the `/etc/localtime` symlink target on Unix (covers macOS + Linux — where Spark runs) and slices
/// after `zoneinfo/`; falls back to `"UTC"`. Std-only, no tz/chrono dependency (locked stack).
pub fn local_timezone() -> String {
    #[cfg(unix)]
    {
        if let Ok(target) = std::fs::read_link("/etc/localtime") {
            let s = target.to_string_lossy();
            if let Some(idx) = s.find("zoneinfo/") {
                let tz = &s[idx + "zoneinfo/".len()..];
                if !tz.is_empty() {
                    return tz.to_string();
                }
            }
        }
    }
    "UTC".to_string()
}

/// Conditional-fetch state from the cache: the prior `ETag` and `Last-Modified` (RFC1123).
#[derive(Debug, Clone, Default)]
pub struct Conditional {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// Build the full HTTP/1.1 request bytes for `POST {path}` to `host` with `body_json`.
///
/// Headers mirror radiance `common/headers.go`. `X-Lantern-Time-Zone` carries `req.time_zone` (the
/// real IANA zone via [`local_timezone`], `UTC` fallback). `X-Lantern-Rand` (0–300 random padding
/// chars) is **intentionally deferred**: its only purpose is request-size padding for traffic-analysis
/// resistance, which matters on the fronted/censored path (design §9, a later milestone), not on a
/// plain direct TLS fetch. Adding it now would also make these bytes non-deterministic to test.
pub fn build_request_bytes(
    host: &str,
    path: &str,
    req: &ConfigRequest,
    cond: &Conditional,
) -> Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(req)?;
    let mut head = String::new();
    head.push_str(&format!("POST {path} HTTP/1.1\r\n"));
    head.push_str(&format!("Host: {host}\r\n"));
    head.push_str("X-Lantern-App: spark\r\n");
    head.push_str(&format!("X-Lantern-App-Version: {}\r\n", req.version));
    head.push_str(&format!("X-Lantern-Version: {}\r\n", req.version));
    head.push_str(&format!("X-Lantern-Platform: {}\r\n", req.platform));
    head.push_str(&format!("X-Lantern-Device-Id: {}\r\n", req.device_id));
    head.push_str(&format!("X-Lantern-Time-Zone: {}\r\n", req.time_zone));
    head.push_str("Content-Type: application/json\r\n");
    head.push_str("Cache-Control: no-cache\r\n");
    if let Some(etag) = &cond.etag {
        head.push_str(&format!("If-None-Match: {etag}\r\n"));
    }
    if let Some(lm) = &cond.last_modified {
        head.push_str(&format!("If-Modified-Since: {lm}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_has_free_tier_fields_and_no_pro() {
        let req = ConfigRequest::new("dev-123".into());
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"device_id\":\"dev-123\""));
        assert!(json.contains("\"backend\":\"sing-box\""));
        assert!(json.contains("samizdat") && json.contains("hysteria2"));
        assert!(!json.contains("pro_token") && !json.contains("user_id"));
        assert!(!json.contains("time_zone"), "time_zone is a header, not a body field");
    }

    #[test]
    fn local_timezone_returns_nonempty() {
        // Real value is environment-dependent; just assert it produces something usable.
        assert!(!local_timezone().is_empty());
    }

    #[test]
    fn request_bytes_have_method_headers_conditional_and_body() {
        let mut req = ConfigRequest::new("dev-123".into());
        req.time_zone = "America/New_York".into(); // pin for a deterministic header assertion
        let cond = Conditional {
            etag: Some("\"abc\"".into()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".into()),
        };
        let bytes = build_request_bytes("df.iantem.io", "/api/v1/config-new", &req, &cond).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("POST /api/v1/config-new HTTP/1.1\r\n"));
        assert!(s.contains("Host: df.iantem.io\r\n"));
        assert!(s.contains("X-Lantern-Device-Id: dev-123\r\n"));
        assert!(s.contains("X-Lantern-Time-Zone: America/New_York\r\n"));
        assert!(!s.contains("X-Lantern-Rand"), "Rand is deferred to the fronting milestone");
        assert!(s.contains("Content-Type: application/json\r\n"));
        assert!(s.contains("If-None-Match: \"abc\"\r\n"));
        assert!(s.contains("If-Modified-Since: Mon, 01 Jan 2024 00:00:00 GMT\r\n"));
        // Content-Length matches the JSON body that follows the blank line.
        let (head, body) = s.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert!(body.contains("\"device_id\":\"dev-123\""));
    }

    #[test]
    fn omits_conditional_headers_when_absent() {
        let req = ConfigRequest::new("d".into());
        let s = String::from_utf8(
            build_request_bytes("h", "/p", &req, &Conditional::default()).unwrap(),
        )
        .unwrap();
        assert!(!s.contains("If-None-Match") && !s.contains("If-Modified-Since"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd core && cargo test --features config-fetch config::fetch::request`
Expected: FAIL to compile until `request.rs` replaces the placeholder (then the 3 tests run).

- [ ] **Step 3 (already written above): the implementation is in the same file** — request types + `build_request_bytes`.

- [ ] **Step 4: Run to verify pass**

Run: `cd core && cargo test --features config-fetch config::fetch::request`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add core/src/config/fetch/request.rs
git commit -m "feat(config-fetch): ConfigRequest + HTTP request builder"
```

> **Applied during code review (kept here so the plan stays accurate):**
> - **Platform string:** `std::env::consts::OS` is `"macos"`, but the Lantern API (Go `runtime.GOOS`)
>   expects `"darwin"` and keys outbound selection on it. Map via a pure `lantern_platform(os) -> &str`
>   (`"macos" => "darwin"`, else passthrough) and test it host-OS-independently.
> - **Header-injection guard:** `cond.etag`/`cond.last_modified` are server-origin and cached to disk,
>   so strip `['\r','\n']` from each before interpolating into `If-None-Match`/`If-Modified-Since`.
> - Use `rfind("zoneinfo/")` (last occurrence) in `local_timezone`.

---

## Task 3: HTTP response parse (`post_collect`)

**Files:**
- Modify: `core/src/transport/probe.rs` (extract the status-code parse as `pub(crate) fn parse_status_code`)
- Create/replace: `core/src/config/fetch/http.rs`

- [ ] **Step 1: Extract the status parser in `probe.rs`**

In `core/src/transport/probe.rs`, replace the inline status parse inside `http_get_ok` (the
`let code = line.split_whitespace()...` block at `probe.rs:142-148`) with a call to a new shared fn,
and add the fn:

```rust
/// Parse the HTTP status code from a status line like `HTTP/1.1 204 No Content`.
pub(crate) fn parse_status_code(status_line: &str) -> io::Result<u16> {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("malformed HTTP status line: {status_line:?}")))
}
```

(Replace the body that computed `code` with `let code = parse_status_code(&line)?;`. Re-run
`cargo test -p spark-core --features anytls config::../transport::probe` — existing probe tests must
still pass.)

- [ ] **Step 2: Write the failing tests for `post_collect`**

`core/src/config/fetch/http.rs`:

```rust
//! Hand-rolled HTTP/1.1 response collection for the config fetch: write the request bytes, then read
//! the full response and return (status, ETag, body). No `reqwest`/`hyper` (locked stack); works over
//! any `AsyncRead + AsyncWrite` (a TLS stream in production, a duplex pipe in tests).

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A collected HTTP response: status code, the `ETag` header value (if any), and the body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub etag: Option<String>,
    pub body: Vec<u8>,
}

/// Write `request` to `stream`, then read the whole response (headers + body to EOF; the request sets
/// `Connection: close`, so EOF terminates the body). `max_body` caps the body so a hostile server
/// can't exhaust memory.
pub async fn post_collect<S>(mut stream: S, request: &[u8], max_body: usize) -> io::Result<HttpResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    stream.flush().await?;
    let mut raw = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > max_body + 64 * 1024 {
            return Err(io::Error::other("config-new response too large"));
        }
    }
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("config-new response: no header terminator"))?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = crate::transport::probe::parse_status_code(status_line)?;
    let mut etag = None;
    for line in lines {
        if let Some(v) = line.strip_prefix("ETag:").or_else(|| line.strip_prefix("etag:")) {
            etag = Some(v.trim().to_string());
        }
    }
    let body = raw[sep + 4..].to_vec();
    if body.len() > max_body {
        return Err(io::Error::other("config-new body exceeds max_body"));
    }
    Ok(HttpResponse { status, etag, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(server_bytes: &'static [u8]) -> (HttpResponse, String) {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let t = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            server.write_all(server_bytes).await.unwrap();
            drop(server); // EOF
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let resp = post_collect(client, b"POST /p HTTP/1.1\r\nHost: h\r\n\r\n", 1 << 20)
            .await
            .unwrap();
        (resp, t.await.unwrap())
    }

    #[tokio::test]
    async fn parses_200_with_etag_and_body() {
        let (resp, sent) = run(b"HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}").await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.etag.as_deref(), Some("\"v1\""));
        assert_eq!(resp.body, b"{\"ok\":true}");
        assert!(sent.starts_with("POST /p HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn parses_304_no_body() {
        let (resp, _) = run(b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n").await;
        assert_eq!(resp.status, 304);
        assert!(resp.body.is_empty());
    }
}
```

- [ ] **Step 3: Run to verify pass**

Run: `cd core && cargo test --features config-fetch config::fetch::http`
Expected: 2 passed (and probe tests still pass).

- [ ] **Step 4: Commit**

```bash
git add core/src/transport/probe.rs core/src/config/fetch/http.rs
git commit -m "feat(config-fetch): hand-rolled HTTP response collector + shared status parse"
```

---

## Task 4: Disk cache

**Files:**
- Create/replace: `core/src/config/fetch/cache.rs`

- [ ] **Step 1: Write the failing tests + implementation**

`core/src/config/fetch/cache.rs`:

```rust
//! On-disk last-good config cache: the raw `config_raw.json` body + a small meta sidecar
//! (`config_meta.json`: etag, last-modified, fetched-at, poll-interval). Atomic writes (temp + rename).

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Sidecar metadata persisted next to the cached raw config.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheMeta {
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub poll_interval_seconds: u64,
}

fn raw_path(dir: &Path) -> PathBuf {
    dir.join("config_raw.json")
}
fn meta_path(dir: &Path) -> PathBuf {
    dir.join("config_meta.json")
}

/// Load the cached raw config body + meta, or `None` if no cache exists yet.
pub fn load(dir: &Path) -> Option<(String, CacheMeta)> {
    let raw = std::fs::read_to_string(raw_path(dir)).ok()?;
    let meta = std::fs::read_to_string(meta_path(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Some((raw, meta))
}

/// Atomically persist the raw config body + meta into `dir` (creating it if needed).
pub fn store(dir: &Path, raw: &str, meta: &CacheMeta) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_atomic(&raw_path(dir), raw.as_bytes())?;
    let meta_json = serde_json::to_vec(meta).map_err(io::Error::other)?;
    write_atomic(&meta_path(dir), &meta_json)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_raw_and_meta() {
        let dir = std::env::temp_dir().join(format!("spark-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load(&dir).is_none());
        let meta = CacheMeta {
            etag: Some("\"e\"".into()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".into()),
            poll_interval_seconds: 30,
        };
        store(&dir, "{\"servers\":[]}", &meta).unwrap();
        let (raw, got) = load(&dir).unwrap();
        assert_eq!(raw, "{\"servers\":[]}");
        assert_eq!(got, meta);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

- [ ] **Step 2: Run to verify pass**

Run: `cd core && cargo test --features config-fetch config::fetch::cache`
Expected: 1 passed.

- [ ] **Step 3: Commit**

```bash
git add core/src/config/fetch/cache.rs
git commit -m "feat(config-fetch): atomic on-disk config cache + meta"
```

---

## Task 5: `device_id` (ring RNG) + cadence helper

**Files:**
- Modify: `core/src/config/fetch/mod.rs`

- [ ] **Step 1: Write the failing tests + implementation**

In `core/src/config/fetch/mod.rs`, above the test module:

```rust
use std::path::Path;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};

/// Read the persisted device id from `{dir}/device_id`, or generate + persist a fresh one (16 random
/// bytes, lowercase hex). Stable across runs once written.
pub fn device_id(dir: &Path) -> std::io::Result<String> {
    let path = dir.join("device_id");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| std::io::Error::other("device_id rng failed"))?;
    let id = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, &id)?;
    Ok(id)
}

/// Choose the sleep before the next poll on a *successful* fetch: the server's `poll_interval_seconds`
/// clamped to a ≥10s floor, or the 10-minute default when the server gives 0/none.
pub fn poll_after(server_seconds: u64) -> Duration {
    const MIN: u64 = 10;
    const DEFAULT: u64 = 600;
    if server_seconds == 0 {
        Duration::from_secs(DEFAULT)
    } else {
        Duration::from_secs(server_seconds.max(MIN))
    }
}
```

Replace the placeholder `module_compiles` test with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_stable_and_persisted() {
        let dir = std::env::temp_dir().join(format!("spark-did-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = device_id(&dir).unwrap();
        let b = device_id(&dir).unwrap();
        assert_eq!(a, b, "device id stable across calls");
        assert_eq!(a.len(), 32, "16 bytes hex");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn poll_after_clamps_and_defaults() {
        assert_eq!(poll_after(0), Duration::from_secs(600)); // default
        assert_eq!(poll_after(5), Duration::from_secs(10)); // floor
        assert_eq!(poll_after(45), Duration::from_secs(45)); // server value
    }
}
```

- [ ] **Step 2: Run to verify pass**

Run: `cd core && cargo test --features config-fetch config::fetch`
Expected: device-id + poll_after tests pass.

- [ ] **Step 3: Commit**

```bash
git add core/src/config/fetch/mod.rs
git commit -m "feat(config-fetch): persisted device_id + server-driven poll cadence helper"
```

---

## Task 6: `fetch_once` (dial + TLS + POST → outcome)

**Files:**
- Modify: `core/src/transport/probe.rs` (make `tls_wrap` `pub(crate)`)
- Modify: `core/src/config/fetch/mod.rs`

- [ ] **Step 1: Expose `tls_wrap`**

In `core/src/transport/probe.rs`, change both `tls_wrap` definitions (the `#[cfg(feature="anytls")]`
and the `#[cfg(not)]` stub) from `async fn tls_wrap` to `pub(crate) async fn tls_wrap`. Re-run probe
tests to confirm no breakage.

- [ ] **Step 2: Add `FetchOutcome`, `FetchEnv`, and `fetch_once`**

In `core/src/config/fetch/mod.rs`:

```rust
use std::sync::Arc;

use crate::config::fetch::http::post_collect;
use crate::config::fetch::request::{build_request_bytes, Conditional, ConfigRequest};
use crate::transport::{probe::tls_wrap, DirectTransport, Transport};

/// Where to fetch from. Prod fronts via `df.iantem.io`; staging hits the API host directly.
#[derive(Debug, Clone)]
pub struct FetchEnv {
    pub host: String,
    pub path: String,
    pub port: u16,
}

impl FetchEnv {
    pub fn prod() -> Self {
        FetchEnv { host: "df.iantem.io".into(), path: "/api/v1/config-new".into(), port: 443 }
    }
    pub fn staging() -> Self {
        FetchEnv { host: "api.staging.iantem.io".into(), path: "/v1/config-new".into(), port: 443 }
    }
    /// Select via `SPARK_CONFIG_ENV=staging`, else prod.
    pub fn from_env() -> Self {
        Self::select(std::env::var("SPARK_CONFIG_ENV").ok().as_deref())
    }

    /// Pure selector behind [`from_env`](Self::from_env): `Some("staging")` → staging, else prod.
    /// Split out so the choice is testable without mutating process-global env (parallel-test-safe).
    fn select(env_value: Option<&str>) -> Self {
        match env_value {
            Some("staging") => Self::staging(),
            _ => Self::prod(),
        }
    }
}

/// Result of one fetch attempt.
#[derive(Debug)]
pub enum FetchOutcome {
    /// New config body + the response `ETag` (for the next conditional request).
    New { raw: String, etag: Option<String> },
    /// Server says nothing changed (304/204) — keep the cache.
    NotModified,
}

/// Do one direct fetch: dial the API host directly, TLS-wrap, POST the request, collect the response.
/// Errors on any network/TLS/HTTP failure (the loop turns errors into backoff-retries). The whole
/// network sequence is bounded by `ATTEMPT_TIMEOUT` — `post_collect` reads to EOF with no internal
/// timeout, so a hung/keep-alive server would otherwise stall the refresh loop forever instead of
/// backing off. Timeout ⇒ error ⇒ backoff-retry, which is the offline-resilience contract.
pub async fn fetch_once(
    env: &FetchEnv,
    device_id: &str,
    cond: &Conditional,
) -> std::io::Result<FetchOutcome> {
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

    let req = ConfigRequest::new(device_id.to_string());
    let bytes =
        build_request_bytes(&env.host, &env.path, &req, cond).map_err(std::io::Error::other)?;
    let resp = tokio::time::timeout(ATTEMPT_TIMEOUT, async {
        let addr = resolve(&env.host, env.port).await?;
        let direct: Arc<dyn Transport> = Arc::new(DirectTransport::new(None));
        let stream = direct.dial(addr).await?;
        let tls = tls_wrap(stream, &env.host).await?;
        post_collect(tls, &bytes, 4 * 1024 * 1024).await
    })
    .await
    .map_err(|_| std::io::Error::other("config-new fetch timed out"))??;
    match resp.status {
        200 | 206 => {
            let raw = String::from_utf8(resp.body)
                .map_err(|_| std::io::Error::other("config-new body not UTF-8"))?;
            Ok(FetchOutcome::New { raw, etag: resp.etag })
        }
        304 | 204 => Ok(FetchOutcome::NotModified),
        other => Err(std::io::Error::other(format!("config-new HTTP {other}"))),
    }
}

/// Resolve a host:port to a socket address (IP literal fast-path, else system resolver).
async fn resolve(host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| std::io::Error::other(format!("config host `{host}` resolved to no addresses")))
}
```

- [ ] **Step 3: Add a unit test for the outcome mapping** (the network path is covered by the live test in Task 9). Add to the test module:

```rust
    #[test]
    fn fetch_env_selects_staging_only_for_staging_value() {
        // Pure selector — no process-env mutation, so it's parallel-test-safe.
        assert_eq!(FetchEnv::select(None).host, "df.iantem.io");
        assert_eq!(FetchEnv::select(Some("prod")).host, "df.iantem.io");
        assert_eq!(FetchEnv::select(Some("staging")).host, "api.staging.iantem.io");
    }
```

- [ ] **Step 4: Build + test**

Run: `cd core && cargo build --features config-fetch && cargo test --features config-fetch config::fetch`
Expected: builds; the env-selection test passes. (`fetch_once`'s network path isn't unit-tested here.)

- [ ] **Step 5: Commit**

```bash
git add core/src/transport/probe.rs core/src/config/fetch/mod.rs
git commit -m "feat(config-fetch): fetch_once (direct dial + TLS + POST) + env selection"
```

---

## Task 7: `load_or_fetch` + adapter integration

**Files:**
- Modify: `core/src/config/fetch/mod.rs`

- [ ] **Step 1: Implement cache-first load + adapt**

In `core/src/config/fetch/mod.rs`:

```rust
// `cache` is already in scope via `mod cache;` — import only the type (a `{self, CacheMeta}` form
// would re-bind `cache` and fail to compile, E0255). Reference `cache::load`/`cache::store` directly.
use crate::config::fetch::cache::CacheMeta;
use crate::config::Config;

/// Bootstrap a [`Config`] for connect: prefer the on-disk cache (fast start), else do a blocking
/// fetch. Returns the adapted Config + the meta to seed the refresh loop. Errors only when there is
/// no cache AND the fetch fails (cold-start offline) — the caller surfaces "waiting for config".
pub async fn load_or_fetch(dir: &Path, env: &FetchEnv) -> std::io::Result<(Config, CacheMeta)> {
    let did = device_id(dir)?;
    if let Some((raw, meta)) = cache::load(dir) {
        if let Ok(cfg) = Config::from_config_str(&raw) {
            return Ok((cfg, meta));
        }
        // Corrupt/empty cache: fall through to a fetch.
    }
    let cond = Conditional::default();
    match fetch_once(env, &did, &cond).await? {
        FetchOutcome::New { raw, etag } => {
            let cfg = Config::from_config_str(&raw).map_err(std::io::Error::other)?;
            // Persist the server's requested cadence too, so a cold start that immediately 304s in
            // run_loop still sleeps the server interval (not the 600s default). See `server_poll_seconds`.
            let meta = CacheMeta {
                etag,
                last_modified: None,
                poll_interval_seconds: server_poll_seconds(&raw),
            };
            cache::store(dir, &raw, &meta)?;
            Ok((cfg, meta))
        }
        FetchOutcome::NotModified => {
            Err(std::io::Error::other("config-new returned 304 with no cached config"))
        }
    }
}

/// Extract the server-recommended `poll_interval_seconds` (a top-level `config_raw.json` body field)
/// without modelling the whole response. `0` when absent/unparseable (→ `poll_after`'s 10-min default).
/// Shared by `load_or_fetch` (to seed the cache meta) and `run_loop` (each refresh).
fn server_poll_seconds(raw: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("poll_interval_seconds").and_then(|n| n.as_u64()))
        .unwrap_or(0)
}
```

- [ ] **Step 2: Test the cache-first path (no network)**

Add to the test module — seed a cache with a minimal `config_raw.json` and assert `load_or_fetch`
returns a pool without hitting the network:

```rust
    #[tokio::test]
    async fn load_or_fetch_uses_cache_without_network() {
        let dir = std::env::temp_dir().join(format!("spark-lof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let raw = r#"{ "options": { "outbounds": [
            { "type": "samizdat", "tag": "s1", "server": "198.51.100.10", "server_port": 443,
              "public_key": "ab", "short_id": "cd", "server_name": "x" }
        ]}}"#;
        cache::store(&dir, raw, &CacheMeta::default()).unwrap();
        // A bogus env proves we never dial: cache hit short-circuits.
        let env = FetchEnv { host: "127.0.0.1".into(), path: "/".into(), port: 1 };
        let (cfg, _meta) = load_or_fetch(&dir, &env).await.unwrap();
        assert_eq!(cfg.transport.servers.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_poll_seconds_reads_body_field() {
        assert_eq!(server_poll_seconds(r#"{"poll_interval_seconds":45}"#), 45);
        assert_eq!(server_poll_seconds(r#"{"x":1}"#), 0);
        assert_eq!(server_poll_seconds("not json"), 0);
    }
```

- [ ] **Step 3: Run + commit**

Run: `cd core && cargo test --features config-fetch config::fetch`
Expected: cache-first test passes.

```bash
git add core/src/config/fetch/mod.rs
git commit -m "feat(config-fetch): load_or_fetch (cache-first) + adapter integration"
```

---

## Task 8: `run_loop` — server cadence + offline backoff

**Files:**
- Modify: `core/src/config/fetch/mod.rs`

- [ ] **Step 1: Implement the loop**

The loop mirrors `radiance/config/config.go:302-336`: on success sleep `poll_after(server_seconds)`,
on failure quadratic backoff capped at 2 min, retried until cancelled. `on_config` is called with each
newly-adapted `Config`. `should_stop` lets the caller cancel (tunnel teardown).

```rust
/// Run the refresh loop until `should_stop()` returns true. On each successful `New` fetch it adapts +
/// caches + calls `on_config`, then sleeps the server-recommended interval; failures (offline, etc.)
/// back off (quadratic, ≤2min) and retry forever. `304`/NotModified just re-sleeps on the prior
/// interval. Never returns an error — config refresh must not crash the tunnel.
pub async fn run_loop<F, Stop>(dir: &Path, env: &FetchEnv, mut on_config: F, should_stop: Stop)
where
    F: FnMut(Config),
    Stop: Fn() -> bool,
{
    let did = match device_id(dir) {
        Ok(d) => d,
        Err(_) => return,
    };
    // Seed both the conditional state AND the initial sleep from the cached meta, so a warm start
    // (or a cold start whose first request 304s) uses the server's last-known cadence, not the default.
    let (mut cond, mut last_interval) = match cache::load(dir) {
        Some((_, m)) => (
            Conditional {
                etag: m.etag,
                last_modified: m.last_modified,
            },
            poll_after(m.poll_interval_seconds),
        ),
        None => (Conditional::default(), poll_after(0)),
    };
    let mut fail = 0u32;
    while !should_stop() {
        match fetch_once(env, &did, &cond).await {
            Ok(FetchOutcome::New { raw, etag }) => match Config::from_config_str(&raw) {
                Ok(cfg) => {
                    fail = 0;
                    let secs = server_poll_seconds(&raw);
                    let meta = CacheMeta {
                        etag: etag.clone(),
                        last_modified: None,
                        poll_interval_seconds: secs,
                    };
                    let _ = cache::store(dir, &raw, &meta);
                    cond.etag = etag;
                    last_interval = poll_after(secs);
                    on_config(cfg);
                    sleep_or_stop(last_interval, &should_stop).await;
                }
                Err(_) => {
                    // A 200 with an unusable body (parse error / NoSupportedOutbounds) is treated as a
                    // failed fetch (design §7): don't cache, keep last-good, and back off — so a server
                    // serving a broken config isn't re-polled at the fast steady-state cadence.
                    fail = fail.saturating_add(1);
                    sleep_or_stop(backoff(fail), &should_stop).await;
                }
            },
            Ok(FetchOutcome::NotModified) => {
                fail = 0;
                sleep_or_stop(last_interval, &should_stop).await;
            }
            Err(_) => {
                fail = fail.saturating_add(1);
                sleep_or_stop(backoff(fail), &should_stop).await;
            }
        }
    }
}

/// Quadratic backoff (10ms·n²) capped at 2 minutes — matches radiance's `common.NewBackoff`.
fn backoff(n: u32) -> Duration {
    let ms = (10u64).saturating_mul((n as u64).saturating_mul(n as u64));
    Duration::from_millis(ms.min(120_000))
}

// `server_poll_seconds` is defined in Task 7 (shared by `load_or_fetch` and this loop) — do not redefine.

/// Sleep `d`, but wake early (return) if `should_stop` flips. Poll the stop flag each second.
async fn sleep_or_stop<Stop: Fn() -> bool>(d: Duration, should_stop: &Stop) {
    let mut left = d;
    let step = Duration::from_secs(1);
    while left > Duration::ZERO && !should_stop() {
        let s = left.min(step);
        tokio::time::sleep(s).await;
        left = left.saturating_sub(s);
    }
}
```

> **Error visibility (CLAUDE.md compliance):** add fully-qualified `tracing` calls to `run_loop` — a
> `tracing::warn!` on `device_id` failure (before the early `return`), and `tracing::debug!` on a
> cache-write failure (`if let Err(e) = cache::store(...)`), on each backoff arm (network + unusable
> body — bind `Err(e)`, not `Err(_)`), and once when the loop stops. No `use tracing` import (the
> macros are fully qualified). `tracing` is already a core dependency. Don't silently drop these errors.

- [ ] **Step 2: Test the pure helpers**

```rust
    #[test]
    fn backoff_is_quadratic_and_capped() {
        assert_eq!(backoff(1), Duration::from_millis(10));
        assert_eq!(backoff(2), Duration::from_millis(40));
        assert_eq!(backoff(10_000), Duration::from_millis(120_000)); // capped 2min
    }
    // (`server_poll_seconds` is tested in Task 7, where the helper is defined.)
```

- [ ] **Step 3: Run + commit**

Run: `cd core && cargo test --features config-fetch config::fetch`
Expected: backoff + server_poll_seconds tests pass; whole module builds.

```bash
git add core/src/config/fetch/mod.rs
git commit -m "feat(config-fetch): offline-resilient refresh loop (server cadence + backoff)"
```

---

## Task 9: Live staging test (ignored) + clippy/fmt gate

**Files:**
- Modify: `core/src/config/fetch/mod.rs`

- [ ] **Step 1: Add an ignored live test**

```rust
    /// Live: hits real staging. Run:
    /// `SPARK_CONFIG_ENV=staging cargo test -p spark-core --features config-fetch -- --ignored live_fetch`
    #[tokio::test]
    #[ignore = "live: needs network"]
    async fn live_fetch() {
        let dir = std::env::temp_dir().join("spark-live-fetch");
        let _ = std::fs::remove_dir_all(&dir);
        let env = FetchEnv::staging();
        let (cfg, _m) = load_or_fetch(&dir, &env).await.expect("staging fetch + adapt");
        assert!(!cfg.transport.servers.is_empty(), "staging should return a pool");
    }
```

- [ ] **Step 2: fmt + clippy (match CI)**

Run:
```bash
cargo fmt --all --check
cargo clippy -p spark-core --all-targets --features config-fetch -- -D warnings
cargo test -p spark-core --features config-fetch config::fetch
```
Expected: all clean; unit tests pass. (Optionally run the live test against staging by hand.)

> **CI note (verified):** the entire `config::fetch` module is behind `#[cfg(feature = "config-fetch")]`,
> so a plain `cargo test`/`cargo clippy` skips it. CI is already fine: `.github/workflows/ci.yml`
> runs `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo test
> --workspace --all-features`, and `--all-features` enables `config-fetch` — so the module's tests +
> lints are covered with no workflow change. The ignored `live_fetch` test is skipped in CI (ignored
> tests don't run without `--ignored`). No CI patch needed.

- [ ] **Step 3: Commit**

```bash
git add core/src/config/fetch/mod.rs
git commit -m "test(config-fetch): ignored live staging fetch"
```

---

## Task 10: Apple NE integration — `lantern-api` sentinel

**Files:**
- Modify: `core/src/fd_tunnel.rs` — extract the tunnel data path; add `run_fd_lantern_api`.
- Modify: `platforms/apple/Cargo.toml` — add a `config-fetch = ["spark-core/config-fetch"]` feature.
- Modify: `platforms/apple/build-xcframework.sh` — add `config-fetch` to the darwin slice's features.
- Modify: `platforms/apple/src/lib.rs` — `spark_tunnel_run` gains a `data_dir` arg; `lantern-api` → `run_fd_lantern_api`.
- Modify: `platforms/apple/include/spark.h` (+ the `SparkCore.xcframework/*/Headers/spark.h` copies) — new prototype.
- Modify: `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift` — pass the app-group container path.
- Modify: the app connect path (`SparkApp.swift` `Vpn.connect()`) — set `providerConfiguration["config"]="lantern-api"` to activate.

> **Investigation result (Explore, recorded):** there is **no live pool-rebuild handle** — `PoolControl`
> (`transport/mod.rs`) is snapshot+pin only, and `from_config_with_control` freezes the pool for the
> tunnel's lifetime. So `on_config` is a **no-op in v1**: the loop already writes the cache, and a fetched
> config takes effect on the next reconnect (matches design §4). And `build_config` runs **before**
> `run_fd` builds its tokio runtime, so the async `load_or_fetch` can't run there — hence a new core entry
> that fetches + spawns the loop *inside* the runtime. `stop()` signals a per-tunnel `tokio::sync::Notify`
> registered in `fd_tunnel`. The Swift NE provider (`PacketTunnelProvider.swift`) currently calls
> `spark_tunnel_run(fd, mtu, config)` and resolves no app-group path.

- [ ] **Step 1: Core — extract the tunnel data path (no behavior change)**

In `core/src/fd_tunnel.rs`, extract the body of `run_with_handle`'s `runtime.block_on(async move { … })`
into a reusable async fn (so the lantern-api entry can run the same data path):

```rust
/// The tunnel data path shared by `run_with_handle` and the lantern-api entry: adopt `fd`, build the
/// transport/netstack from `config`, register the pool control, and run until `waiter` is signalled or
/// the accept loop exits.
async fn run_tunnel_data_path(
    fd: i32,
    mtu: u16,
    mut config: Config,
    waiter: &Notify,
) -> std::io::Result<()> {
    crate::resolve_bootstrap(&mut config).await?;
    // SAFETY: `fd` is the OS TUN fd handed to native for the tunnel's lifetime.
    let tun = Arc::new(
        unsafe { Tun::from_fd(fd, mtu) }.map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let (tcp_transport, udp_transport, control) = transport::from_config_with_control(&config)?;
    set_pool(control);
    let (stack, udp_surface) = netstack::build(Arc::clone(&tun), &config)?;
    let idle = Duration::from_secs(config.udp.idle_timeout_secs);
    if let Some((udp_inbound, udp_reply)) = udp_surface {
        tokio::spawn(proxy::udp::run_udp(udp_inbound, udp_reply, udp_transport, idle));
    }
    info!(mtu, "spark tunnel up (fd mode)");
    let metrics = Arc::new(crate::metrics::Metrics::default());
    tokio::select! {
        _ = proxy::tcp::run(stack, tcp_transport, metrics) => warn!("netstack accept loop exited"),
        _ = waiter.notified() => info!("stop requested; tearing the tunnel down"),
    }
    drop(tun);
    Ok(())
}
```

Replace `run_with_handle`'s `block_on` body with `run_tunnel_data_path(fd, mtu, config, &waiter).await`.
Verify no behavior change: `cargo test -p spark-core tcp_tunnel udp_tunnel` + the `fd_tunnel` unit tests pass.

- [ ] **Step 2: Core — add `run_fd_lantern_api` (gated on `config-fetch`)**

Add, after `run_with_handle`:

```rust
/// Apple NE entry for `lantern-api` mode: fetch the boot config from the Lantern API (cache-first,
/// retrying on cold-start offline until a config is obtained or stop is signalled), spawn the
/// background refresh loop (warms the on-disk cache; no live pool swap in v1), then run the tunnel.
/// Blocks until stop; `0` clean, `-1` on error. `data_dir` is the app-group container path.
#[cfg(feature = "config-fetch")]
pub fn run_fd_lantern_api(fd: i32, mtu: u16, data_dir: std::path::PathBuf) -> i32 {
    use crate::config::fetch::{self, FetchEnv};

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "lantern-api: runtime build failed");
            return -1;
        }
    };
    let stop = Arc::new(Notify::new());
    register(&stop);
    let waiter = Arc::clone(&stop);
    let result: std::io::Result<()> = runtime.block_on(async move {
        let env = FetchEnv::from_env();
        // Cold-start resilience (design §6): keep retrying until a config is obtained (cache or fetch)
        // or stop fires while we wait. `load_or_fetch` returns instantly on a warm cache.
        let mut attempt = 0u32;
        let (config, _meta) = loop {
            match fetch::load_or_fetch(&data_dir, &env).await {
                Ok(c) => break c,
                Err(e) => {
                    warn!(error = %e, "lantern-api: waiting for config (offline?)");
                    attempt = attempt.saturating_add(1);
                    let wait = Duration::from_secs(((attempt as u64) * 5).clamp(5, 30));
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = waiter.notified() => return Ok(()), // stopped before first config
                    }
                }
            }
        };
        // Background refresh: warms the cache for the next connect; ends when stop fires.
        let loop_dir = data_dir.clone();
        let loop_stop = Arc::clone(&waiter);
        tokio::spawn(async move {
            let env = FetchEnv::from_env();
            tokio::select! {
                _ = fetch::run_loop(&loop_dir, &env, |_cfg| {}, || false) => {}
                _ = loop_stop.notified() => {}
            }
        });
        run_tunnel_data_path(fd, mtu, config, &waiter).await
    });
    deregister(&stop);
    set_pool(None);
    match result {
        Ok(()) => 0,
        Err(e) => {
            warn!(error = %e, "lantern-api tunnel exited with error");
            -1
        }
    }
}
```

`cargo build -p spark-core --features config-fetch` + `cargo clippy -p spark-core --all-targets --features config-fetch -- -D warnings`.

- [ ] **Step 3: Apple build — add the `config-fetch` feature (darwin slice)**

`spark-apple` forwards features to `spark-core` (the existing `anytls`/`multi-server` features at
`platforms/apple/Cargo.toml:21,25`). Mirror that pattern:
- In `platforms/apple/Cargo.toml` `[features]`, add `config-fetch = ["spark-core/config-fetch"]` AND
  `bootstrap-dns = ["spark-core/bootstrap-dns"]` (the latter resolves hostname pool members — config_raw
  *file* or `lantern-api` fetch — which otherwise hard-error at connect; darwin-only, it pulls the boring
  DNS connector).
- In `platforms/apple/build-xcframework.sh:20`, add both to the **darwin-only** feature list:
  `[[ "$t" == *darwin* ]] && feat=(--features anytls,multi-server,bootstrap-dns,config-fetch)`.
Verify: `cargo build -p spark-apple --features anytls,multi-server,bootstrap-dns,config-fetch` (full darwin
set) and `cargo build -p spark-apple` (iOS-equivalent, no feature — the `lantern-api` branch compiles to `-1`).

- [ ] **Step 4: C ABI — `data_dir` arg + `lantern-api` dispatch**

In `platforms/apple/src/lib.rs`, add a `data_dir: *const c_char` param to `spark_tunnel_run`, and before
`build_config` branch on the sentinel. The branch is `#[cfg]`-gated on the spark-apple `config-fetch`
feature (Step 3) — `config-fetch` pulls `anytls` (the BoringSSL C build), so like `anytls` it's the
**darwin slice only**; the iOS slice has no `config-fetch` and returns -1 for `lantern-api`:

```rust
    pub unsafe extern "C" fn spark_tunnel_run(
        fd: c_int,
        mtu: c_int,
        config: *const c_char,
        data_dir: *const c_char,
    ) -> c_int {
        // `lantern-api` mode: self-fetch config from the Lantern API into `data_dir` (the app-group
        // container path). Gated on `config-fetch` (darwin slice only — it pulls the BoringSSL build).
        if !config.is_null() {
            // SAFETY: caller contract — `config` is a valid NUL-terminated C string when non-null.
            if let Ok("lantern-api") = unsafe { CStr::from_ptr(config) }.to_str().map(str::trim) {
                #[cfg(feature = "config-fetch")]
                {
                    // SAFETY: caller contract — `data_dir` is null or a valid NUL-terminated C string.
                    let dir = if data_dir.is_null() {
                        None
                    } else {
                        unsafe { CStr::from_ptr(data_dir) }
                            .to_str()
                            .ok()
                            .map(std::path::PathBuf::from)
                    };
                    return match dir {
                        Some(d) => spark_core::fd_tunnel::run_fd_lantern_api(fd, mtu as u16, d),
                        None => -1, // api mode needs a data dir to cache device_id + config
                    };
                }
                #[cfg(not(feature = "config-fetch"))]
                {
                    let _ = data_dir; // unused without config-fetch (iOS slice)
                    return -1; // `lantern-api` unsupported in this slice
                }
            }
        }
        // SAFETY: caller contract — `config` is null or a valid NUL-terminated C string.
        let config = match unsafe { build_config(config) } {
            Some(c) => c,
            None => return -1,
        };
        spark_core::fd_tunnel::run_fd(fd, mtu as u16, config)
    }
```

Update the doc comment + `# Safety` to cover `data_dir`. Mirror the prototype in
`platforms/apple/include/spark.h` **and** the three `SparkCore.xcframework/*/Headers/spark.h` copies:
```c
int32_t spark_tunnel_run(int32_t fd, int32_t mtu, const char *config, const char *data_dir);
```

- [ ] **Step 5: Swift — pass the app-group container path + activate**

In `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift`, resolve the shared container and pass
its path as the 4th arg (nil when unavailable), keeping the existing nil-config behavior:
```swift
let dataDir = FileManager.default
    .containerURL(forSecurityApplicationGroupIdentifier: "group.org.getlantern.spark")?
    .appendingPathComponent("config", isDirectory: true).path
// inside the worker thread, replacing the two spark_tunnel_run calls:
func runNative(_ cfg: UnsafePointer<CChar>?) -> Int32 {
    if let dataDir {
        return dataDir.withCString { spark_tunnel_run(fd, Int32(mtu), cfg, $0) }
    }
    return spark_tunnel_run(fd, Int32(mtu), cfg, nil)
}
if let config, !config.isEmpty {
    rc = config.withCString { runNative($0) }
} else {
    rc = runNative(nil)
}
```
To **activate** API mode set `providerConfiguration["config"] = "lantern-api"` in `SparkApp.swift`
`Vpn.connect()` (behind a toggle; default-off is fine — the plumbing is inert unless the sentinel is set).

- [ ] **Step 6: Build + on-device validation (owner)**

`cargo build -p spark-apple --features config-fetch`, then `packaging/macos/build-tauri-dmg.sh` with
`REUSE_SYSEXT` unset (fresh extension + xcframework rebuild so the new ABI lands). On device, app set to
`lantern-api` (staging via `SPARK_CONFIG_ENV=staging`): connect → confirm a pool builds on cold start and
a second launch boots instantly from cache; pull the network mid-session → tunnel keeps running on
last-good config; confirm a fetched config change applies after a reconnect.

- [ ] **Step 7: Commit**

```bash
git add core/src/fd_tunnel.rs platforms/apple/src/lib.rs platforms/apple/Cargo.toml \
        platforms/apple/include/spark.h platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift
git commit -m "feat(apple): self-fetch config via the lantern-api sentinel"
```

---

## Self-review notes (coverage)

- Wire contract (endpoint/request/headers/conditional/response/status) → Tasks 2, 3, 6.
- `config_raw.json` adapter reuse → Tasks 7, 8 (`Config::from_config_str`).
- Disk cache + conditional state → Tasks 4, 7, 8.
- Server-driven cadence + offline backoff (never gives up) → Tasks 5, 8.
- Free-tier `device_id` → Task 5.
- Extension self-fetch + `lantern-api` sentinel → Task 10.
- Deferred (fronting/Pro/smart-routing) → not in this plan, per the design.

**Header decision (vs spec §2):** `X-Lantern-Time-Zone` carries the real IANA zone resolved std-only
from `/etc/localtime` on Unix (`local_timezone`, `UTC` fallback) — no tz/chrono dep. It rides the
header via a `#[serde(skip)]` field so it stays out of the JSON body. `X-Lantern-Rand` is intentionally
**not** sent in v1 — it's request-size padding for traffic-analysis resistance that only matters on the
fronted path (design §9, deferred), and it would make the request bytes non-deterministic to unit-test.
Recorded as a decision, not an omission.

**Feature-gating verified:** `Config::from_config_str` (`core/src/config/mod.rs:630`) and the
`transport.servers` field (`:257`) are both unconditional, so `config-fetch = ["anytls"]` is enough for
the core unit tests (Tasks 7, 9). Runtime latency *selection* among the pool needs `multi-server`,
which the Apple/Darwin build already enables (Task 10 Step 2).

**Known integration risk (Task 10):** threading the app-group data-dir path into the core fetch + the
`on_config` → pool-rebuild wiring is the least mechanical part — hence Task 10 Step 1 is an explicit
signature-confirmation step rather than pre-baked code. Budget review time there.
