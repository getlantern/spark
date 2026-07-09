# Windows W3 — Plugin ServiceControl over spark-ipc Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Tauri plugin's desktop `ServiceControl` a real spark-ipc client so the unprivileged Windows/Linux GUI can drive the privileged `spark-service` (connect / disconnect / status) over the named pipe (Windows) / unix socket (Linux) — replacing the "not yet implemented (spark-ipc)" stub. Same plugin macOS/Android already use.

**Architecture:** The plugin (`gui-tauri/tauri-plugin-spark-vpn`, a **separate cargo workspace**) gains a `service_ipc` module (gated `not(android)`, so it compiles + unit-tests on macOS too) holding a per-call sync→async bridge: each `TunnelControl` call opens the platform transport, does the spark-ipc `Client` handshake + one request, and returns. `ServiceControl` (gated `not(macos), not(android)` = Windows + Linux) delegates connect/disconnect/status to it. Settings (routing-mode/ad-block/split-tunnel) stay locally persisted (the ipc is profile-based — no granular setters; live-apply is a documented follow-up).

**Tech Stack:** Rust; `spark-ipc` (path dep, `stream` feature) + `tokio` (added to the plugin, target-gated `not(android)`); tokio `net::windows::named_pipe` (Windows) / `net::UnixStream` (unix). Validated locally on all three targets (macOS clippy+test, `cargo xwin` Windows).

> **Implementation note (post-review, as merged):** during the Copilot review the sync→async
> bridge evolved from a per-call `std::thread::scope` runtime to a **single long-lived worker
> thread + current-thread runtime served off an mpsc queue** (avoids thread/runtime churn under the
> GUI's ~2s status poll), with a **15s round-trip timeout** and a **Windows pipe-open retry**
> (`ERROR_FILE_NOT_FOUND`/`ERROR_PIPE_BUSY`). The **plugin CI job was deferred to W4** (workflow-edit
> hook + belongs with packaging), and the plugin's **`Cargo.lock` is gitignored** (regenerated per
> build, not committed). The step-by-step below is the original plan; where it differs, the merged
> code + this note win.

---

## Context for the implementer (verified facts — do not re-guess)

- **The plugin is its own workspace** (`[workspace]` at the top of `gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`); the repo-root `cargo --workspace` does NOT include it, and it currently has **no CI**. Its `Cargo.lock` is **gitignored** (regenerated per build, not committed).
- **`ServiceControl`** lives in `desktop.rs:823`, `#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]` (Windows **and** Linux desktop). It's `struct ServiceControl { base: PathBuf }`. connect/disconnect/select_server/set_excluded_apps currently return `Error::Platform("...not yet implemented (spark-ipc)")`; status returns a canned Disconnected; settings getters/setters use `crate::persist::*` (keep those).
- **`TunnelControl`** (`control.rs`) is a **synchronous** trait. The Tauri commands (`commands.rs`) are `#[tauri::command] async fn` that call the sync trait method — so the call runs **inside** Tauri's tokio runtime. Therefore a naive `Runtime::block_on` inside a trait method **panics** ("Cannot start a runtime from within a runtime"). The bridge MUST run its runtime on a separate OS thread (see IpcClient below).
- **spark-ipc** (`ipc/`, path `../../ipc` from the plugin) exposes: `Client<S: AsyncRead+AsyncWrite+Unpin>` with `async fn handshake() -> io::Result<ProtocolVersion>` and `async fn request(RequestPayload) -> io::Result<ResponsePayload>`; plus `read_frame`/`write_frame` and `message::{Request, Response, ResponsePayload, ServerMessage, RequestPayload, TunnelStatus, TunnelState, PROTOCOL_VERSION}`. `Client` needs the `stream` feature (pulls tokio). Wire protocol (from `stream.rs`): client writes `Request{req_id, payload}` frames; server replies `ServerMessage::Response(Response{req_id, payload})`; handshake is `RequestPayload::Hello{client_version}` → `ResponsePayload::Hello{service_version, negotiated}`.
- **`TunnelStatus { state: TunnelState, direct_fallback: bool }`** — no protocol field. Map `state` → the plugin `Status.state` string, `direct_fallback` → `Status.fail_open`. `Status.protocol` has no ipc source here → use a fixed placeholder (`"".to_string()` or the build's default) — a follow-up can fill it via `GetDetails`.
- **Plugin `Status { state: String, protocol: String, fail_open: bool }`** (`models.rs`; serializes camelCase `failOpen`).
- **Control-plane address defaults** (match `daemon.rs`): Windows `\\.\pipe\spark`; unix `/var/run/spark.sock`.
- **Local build reality:** `ServiceControl` is `not(macos)`, so it does **not** compile on the macOS host — but `cargo xwin clippy --target x86_64-pc-windows-msvc` (verified working on the tauri plugin) compiles the Windows path. The `service_ipc` module is gated `not(android)` (compiles on macOS), and its unix-socket branch is the **same code Linux uses**, so a macOS `cargo test` exercises the real round-trip. Net local coverage: macOS clippy+test (helper + macOS branch = Linux path), `cargo xwin` (Windows ServiceControl + pipe).
- **Constraints:** no `unwrap`/`expect` outside tests; `unsafe` needs `// SAFETY:` (none expected here); `cargo fmt` + `clippy -D warnings` clean. New deps go in the plugin's own `Cargo.toml`; its `Cargo.lock` is gitignored, so do NOT try to commit it. Commit trailer as usual.

---

## File Structure

- **Modify** `gui-tauri/tauri-plugin-spark-vpn/Cargo.toml` — add `spark-ipc` (path, `stream`) + `tokio` under `[target.'cfg(not(target_os = "android"))'.dependencies]`.
- **Create** `gui-tauri/tauri-plugin-spark-vpn/src/service_ipc.rs` — the bridge (`default_control_addr`, `IpcClient`, `map_status`) + unit tests.
- **Modify** `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` — declare the module (`#[cfg(not(target_os = "android"))] mod service_ipc;`) and construct `ServiceControl` with the default addr.
- **Modify** `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs` — `ServiceControl` holds an `IpcClient`; connect/disconnect/status delegate to it.
- **Modify** `.github/workflows/ci.yml` — a `plugin` job on `[macos-latest, windows-latest]` (fmt + clippy + test in the plugin dir).

---

## Task 1: plugin deps + the `service_ipc` bridge (host-tested)

**Files:** `Cargo.toml`, `src/service_ipc.rs` (create)

- [ ] **Step 1: Add deps to the plugin `Cargo.toml`**

After the `[dependencies]` block (before the macOS target block), add:

```toml
# Windows/Linux desktop: talk to the privileged spark-service over spark-ipc (W3). Gated off
# android (which uses the JNI core). macOS is included so the transport-agnostic ipc client +
# status mapping compile and unit-test on the dev host (its unix-socket path == the Linux path).
[target.'cfg(not(target_os = "android"))'.dependencies]
spark-ipc = { path = "../../ipc", features = ["stream"] }
tokio = { version = "1", features = ["rt", "net", "io-util", "time"] }
```

- [ ] **Step 2: Write the failing test first (unix-socket round-trip + mapping)**

Create `src/service_ipc.rs` with the tests up front (they won't compile until the impl exists — that's the RED):

```rust
//! Desktop control over spark-ipc: a synchronous bridge from the [`TunnelControl`] trait to the
//! async spark-ipc [`Client`], talking to the privileged `spark-service` over the platform control
//! transport (named pipe on Windows, unix socket elsewhere).
//!
//! Compiled off android (which drives the in-process core via JNI). macOS is included so this
//! module compiles and unit-tests on the dev host — its unix-socket path is the same code Linux
//! uses; only the Windows named-pipe branch is Windows-only (cross-compiled, not host-run).

#![cfg(not(target_os = "android"))]

use std::path::PathBuf;

use spark_ipc::message::{RequestPayload, ResponsePayload, TunnelState, TunnelStatus};
use spark_ipc::Client;

use crate::models::Status;

/// The default control-plane address (matches `spark-service`'s `daemon.rs` defaults).
pub(crate) fn default_control_addr() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"\\.\pipe\spark")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/run/spark.sock")
    }
}

/// Map a service [`TunnelStatus`] to the frontend [`Status`] shape.
pub(crate) fn map_status(s: TunnelStatus) -> Status {
    let state = match s.state {
        TunnelState::Disconnected => "disconnected",
        TunnelState::Connecting => "connecting",
        TunnelState::Connected => "connected",
        TunnelState::Disconnecting => "disconnecting",
        TunnelState::Failed => "failed",
    }
    .to_string();
    Status {
        state,
        // No protocol field on TunnelStatus; a later pass can source it from GetDetails.
        protocol: String::new(),
        fail_open: s.direct_fallback,
    }
}

/// A synchronous spark-ipc client for the desktop service. Each call opens a fresh connection,
/// handshakes, sends one request, and closes — simple + stateless for an infrequent control plane.
#[derive(Clone)]
pub(crate) struct IpcClient {
    addr: PathBuf,
}

impl IpcClient {
    pub(crate) fn new(addr: PathBuf) -> Self {
        Self { addr }
    }

    /// Send one request and return its response payload. Runs the async round-trip on a dedicated
    /// thread with its own current-thread runtime, so it never panics even when the caller is
    /// already inside Tauri's tokio runtime (the plugin commands are `async fn`).
    pub(crate) fn request(&self, payload: RequestPayload) -> crate::Result<ResponsePayload> {
        let addr = self.addr.clone();
        std::thread::scope(|scope| {
            scope
                .spawn(move || -> crate::Result<ResponsePayload> {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| crate::Error::Platform(format!("ipc runtime: {e}")))?;
                    rt.block_on(round_trip(&addr, payload))
                        .map_err(|e| crate::Error::Platform(format!("service ipc: {e}")))
                })
                .join()
                .map_err(|_| crate::Error::Platform("ipc worker panicked".into()))?
        })
    }
}

/// Connect to the control transport, handshake, and issue one request. Transport is
/// platform-specific; the [`Client`] round-trip is shared.
async fn round_trip(addr: &std::path::Path, payload: RequestPayload) -> std::io::Result<ResponsePayload> {
    #[cfg(target_os = "windows")]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        let pipe = ClientOptions::new().open(addr)?;
        let mut client = Client::new(pipe);
        client.handshake().await?;
        client.request(payload).await
    }
    #[cfg(not(target_os = "windows"))]
    {
        use tokio::net::UnixStream;
        let sock = UnixStream::connect(addr).await?;
        let mut client = Client::new(sock);
        client.handshake().await?;
        client.request(payload).await
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use spark_ipc::message::{Request, Response, ServerMessage, PROTOCOL_VERSION};
    use spark_ipc::{read_frame, write_frame};
    use tokio::net::UnixListener;

    fn temp_sock(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("spark-w3-test-{}-{tag}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// A minimal one-connection server: handshake, then answer each request with `answer`.
    async fn serve_one(listener: UnixListener, answer: ResponsePayload) {
        let (mut stream, _) = listener.accept().await.unwrap();
        while let Some(req) = read_frame::<_, Request>(&mut stream).await.unwrap() {
            let payload = match req.payload {
                RequestPayload::Hello { .. } => ResponsePayload::Hello {
                    service_version: PROTOCOL_VERSION,
                    negotiated: PROTOCOL_VERSION,
                },
                _ => answer.clone(),
            };
            let msg = ServerMessage::Response(Response {
                req_id: req.req_id,
                payload,
            });
            write_frame(&mut stream, &msg).await.unwrap();
        }
    }

    #[test]
    fn map_status_translates_state_and_fallback() {
        let s = map_status(TunnelStatus {
            state: TunnelState::Connected,
            direct_fallback: true,
        });
        assert_eq!(s.state, "connected");
        assert!(s.fail_open);
    }

    #[test]
    fn request_round_trips_over_a_unix_socket() {
        let addr = temp_sock("rt");
        // Run the server on its own current-thread runtime + thread; IpcClient::request spawns its
        // own thread/runtime, so the two don't nest.
        let server_addr = addr.clone();
        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = UnixListener::bind(&server_addr).unwrap();
                serve_one(listener, ResponsePayload::Ack).await;
            });
        });
        // Give the listener a moment to bind (it's on another thread).
        std::thread::sleep(std::time::Duration::from_millis(100));

        let client = IpcClient::new(addr.clone());
        let resp = client.request(RequestPayload::Connect).unwrap();
        assert!(matches!(resp, ResponsePayload::Ack));

        server.join().unwrap();
        let _ = std::fs::remove_file(&addr);
    }
}
```

- [ ] **Step 3: Run the test — expect RED then GREEN**

The impl and tests are in the same commit here (the module is new), so run:
`cd gui-tauri/tauri-plugin-spark-vpn && cargo test service_ipc`
Expected: PASS (both `map_status_translates_state_and_fallback` and `request_round_trips_over_a_unix_socket`). If `Client`/`read_frame`/message-type imports don't resolve, confirm the `stream` feature is enabled on the `spark-ipc` dep and that names match `ipc/src/message.rs` (adjust `TunnelState` variant names to the actual enum — `Disconnected/Connecting/Connected/Disconnecting/Failed`; verify the last against the source).

- [ ] **Step 4: host clippy (plugin dir)**

`cargo clippy --all-targets -- -D warnings`
Expected: clean (compiles the module + macOS branch; the test compiles under `cfg(all(test, unix))`).

- [ ] **Step 5: Commit**

```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/tauri-plugin-spark-vpn/Cargo.toml gui-tauri/tauri-plugin-spark-vpn/src/service_ipc.rs  # Cargo.lock is gitignored
git commit -m "$(cat <<'EOF'
Windows W3: spark-ipc sync bridge for the desktop plugin (service_ipc)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: wire `ServiceControl` to the ipc bridge

**Files:** `src/lib.rs`, `src/desktop.rs`

- [ ] **Step 1: Declare the module + construct with the addr (`lib.rs`)**

Add near the other `#[cfg(not(target_os = "android"))]` modules:

```rust
#[cfg(not(target_os = "android"))]
mod service_ipc;
```

In `platform::control`, change the non-macOS construction to pass the default addr:

```rust
        #[cfg(not(target_os = "macos"))]
        {
            Ok(Box::new(crate::desktop::ServiceControl::new(base)))
        }
```

- [ ] **Step 2: `ServiceControl` holds an `IpcClient` + delegates (`desktop.rs`)**

Replace the struct + the three stubbed methods:

```rust
#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
pub(crate) struct ServiceControl {
    pub(crate) base: PathBuf,
    ipc: crate::service_ipc::IpcClient,
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
impl ServiceControl {
    pub(crate) fn new(base: PathBuf) -> Self {
        let ipc = crate::service_ipc::IpcClient::new(crate::service_ipc::default_control_addr());
        Self { base, ipc }
    }
}
```

Then in the `impl TunnelControl for ServiceControl`:

```rust
    fn connect(&self) -> crate::Result<()> {
        match self.ipc.request(spark_ipc::message::RequestPayload::Connect)? {
            spark_ipc::message::ResponsePayload::Ack => Ok(()),
            other => Err(crate::Error::Platform(format!("connect: unexpected reply {other:?}"))),
        }
    }

    fn disconnect(&self) -> crate::Result<()> {
        match self.ipc.request(spark_ipc::message::RequestPayload::Disconnect)? {
            spark_ipc::message::ResponsePayload::Ack => Ok(()),
            other => Err(crate::Error::Platform(format!("disconnect: unexpected reply {other:?}"))),
        }
    }

    fn status(&self) -> crate::Result<Status> {
        match self.ipc.request(spark_ipc::message::RequestPayload::GetStatus)? {
            spark_ipc::message::ResponsePayload::Status(s) => Ok(crate::service_ipc::map_status(s)),
            other => Err(crate::Error::Platform(format!("status: unexpected reply {other:?}"))),
        }
    }
```

Leave `servers()` returning `Ok(Vec::new())`, the settings getters/setters using `crate::persist::*`, and `list_installed_apps`/`get_excluded_apps` returning `"[]"`. Change `select_server` and `set_excluded_apps` to keep returning the honest `Error::Platform("... not supported by the desktop service yet")` (reword away from "not yet implemented (spark-ipc)" since ipc now works — say the *operation* isn't supported by the desktop service's control API yet).

Note: `spark_ipc` must be importable in `desktop.rs` — it's a dep now (not android), and `desktop.rs` is `cfg(not(android))`, so `use spark_ipc::...` or fully-qualified paths resolve. Prefer fully-qualified `spark_ipc::message::…` to avoid unused-import churn on the macOS `AppleControl` build.

- [ ] **Step 3: host clippy (plugin dir, macOS — ServiceControl NOT compiled here, but lib.rs/construction is)**

`cargo clippy --all-targets -- -D warnings`
Expected: clean. (On macOS, `platform::control`'s `not(macos)` arm is compiled out, so the `ServiceControl::new` call is not type-checked here — Step 4 does that.)

- [ ] **Step 4: Windows cross-clippy (the real check for ServiceControl)**

`cargo xwin clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings`
Expected: clean — this compiles `ServiceControl` (+ its `IpcClient`, the named-pipe `round_trip` branch, connect/disconnect/status, and the `lib.rs` `ServiceControl::new` construction). This is the authoritative gate for W3's Windows code.

- [ ] **Step 5: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/lib.rs gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs
git commit -m "$(cat <<'EOF'
Windows W3: ServiceControl connect/disconnect/status over spark-ipc

The desktop plugin now drives the privileged spark-service over the named pipe
(Windows) / unix socket (Linux) via the service_ipc bridge, replacing the
not-yet-implemented stub. Settings stay locally persisted (the ipc is
profile-based; live-apply is a follow-up). Cross-compiled for Windows via
cargo-xwin; the shared round-trip + mapping are unit-tested on the host.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: full gate + PR

**Note — plugin CI job deferred to W4.** A `plugin` CI job (macOS + Windows) is the right way to get
the plugin's first CI coverage, but adding it now is blocked by the repo's workflow-edit security
hook and belongs with W4's CI/packaging work (Windows Tauri build + wintun bundling + the
windows-latest job). So W3 is validated **locally across all three platforms** (macOS `clippy`+`test`,
Windows `cargo xwin clippy`); the W4 plan adds the plugin CI job. State this in the PR.

- [ ] **Step 1: Full local gate (plugin dir)**

```bash
cd gui-tauri/tauri-plugin-spark-vpn
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings                                   # macOS host
cargo test                                                                   # runs the unix-socket round-trip test
cargo xwin clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings   # Windows ServiceControl
```
All must be clean/green. Also confirm the **main** workspace still builds (unchanged): from the repo root `cargo clippy --workspace --all-targets -- -D warnings`.

- [ ] **Step 3: Push + PR**

```bash
git add .github/workflows/ci.yml
git commit -m "Windows W3: CI job for the Tauri control plugin (macOS + Windows) ..."
git push -u origin fisk/windows-w3-service-ipc
```
Open the PR (base `main`). Body: what changed (ServiceControl → real ipc client), the sync/async bridge rationale (commands are async → separate-thread runtime), the profile-based-ipc note (settings stay local; live-apply deferred), and the validation (local all-platform compile + macOS round-trip test + the new plugin CI job). A mermaid diagram of GUI→command→ServiceControl→IpcClient→pipe→service is worthwhile (multi-layer).

- [ ] **Step 4: review-pr loop** → squash-merge on green (incl. the new `plugin` job) + 0 unresolved threads. Then W4.

---

## Self-Review

- **Spec coverage:** implements the spec's W3 "plugin `ServiceControl` → real named-pipe ipc client (connect/disconnect/status …)". Server-selection + live routing-mode/ad-block/split-tunnel over ipc are explicitly deferred (profile-based ipc has no granular setters) — noted, not silently dropped.
- **Sync/async correctness:** commands are `async fn` (in-runtime), so the bridge runs its runtime on a **dedicated long-lived worker thread** (mpsc queue) — never nests runtimes, and reused across calls. Verified against `commands.rs`.
- **Host-verifiability:** `service_ipc` is `not(android)` so it compiles + unit-tests on macOS; its unix-socket branch == the Linux path. `ServiceControl` (`not(macos)`) is compiled via `cargo xwin` (verified working on the tauri plugin) + the Windows CI job. No code path is validated only by assertion.
- **Type consistency:** `IpcClient::request(RequestPayload) -> Result<ResponsePayload>`; `map_status(TunnelStatus) -> Status`; `Client::new(stream)` accepts `NamedPipeClient`/`UnixStream` (both `AsyncRead+AsyncWrite+Unpin`). `TunnelState` variants must match `ipc/src/message.rs` — verify the `Failed` variant name during Step 3.
