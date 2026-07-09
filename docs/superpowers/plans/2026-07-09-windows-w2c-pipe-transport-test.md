# Windows W2c — Named-Pipe Control-Transport Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or executing-plans. Steps use `- [ ]`.

**Goal:** Exercise the Windows named-pipe control transport (`pipe::serve` → `serve_connection` → `spark-ipc`) end-to-end in the `windows-latest` CI job — moving it from "type-checked, never run" to "run in CI" — without needing real Windows hardware.

**Architecture:** The Windows service transport (pipe SDDL + SCM + daemon wiring) is **already implemented and wired** (built in the P4.1 forward-compat seam; W2a/W2b filled the genuine routing + loop-prevention gaps). Its `serve_connection` core is already unit-tested over an in-memory duplex (`conn.rs`, 6 tests), and the unix transport has a socket round-trip test (`listener.rs`). The one Windows-specific gap is that `pipe.rs`'s accept loop + admin-only DACL creation have **zero test coverage**. W2c adds a same-process named-pipe round-trip test mirroring `listener.rs`'s unix test.

**Tech Stack:** Rust, tokio 1.52 `net::windows::named_pipe` (`ClientOptions`), `spark-ipc` `Client`, `windows-sys` (`ERROR_PIPE_BUSY`, already a `service/` dep).

---

## Context for the implementer

- **`pipe::serve(name: &OsStr, commands: mpsc::Sender<Envelope>)`** (`service/src/pipe.rs`) creates the admin-only-DACL pipe (`AdminOnlySecurity::new()` → `ConvertStringSecurityDescriptorToSecurityDescriptorW`), pre-creates the first instance, then loops: `connect().await`, hand off to `serve_connection`, create the next instance. Exercising `serve` exercises the SDDL FFI + the accept loop + `serve_connection`.
- **The unix analog to mirror** is `listener.rs`'s `authorized_client_drives_the_service` test: `channel()` → spawn `run_service(FakeEngine, cmd_rx, false, BackendInfo::default(), None)` → spawn `serve(...)` → `Client::new(stream)` → `handshake()` == `PROTOCOL_VERSION` → `request(Connect)` == `Ack` → assert `running` → `request(GetStatus)` == `Status{ state: Connected }`.
- **tokio named-pipe client**: `tokio::net::windows::named_pipe::ClientOptions::new().open(name)` returns `io::Result<NamedPipeClient>`. It can race the server's first-instance creation (→ `ERROR_FILE_NOT_FOUND`) or hit `ERROR_PIPE_BUSY`; retry a few times with a short sleep (the documented idiom). `NamedPipeClient` impls `AsyncRead + AsyncWrite + Unpin`, so `spark_ipc::Client::new` accepts it (same as `UnixStream`/`DuplexStream`).
- **DACL access on CI**: the pipe grants `SY`+`BA`. GitHub `windows-latest` runners run elevated with `BA`, so a **same-process** client→server open should succeed. To avoid a red build if a token is UAC-filtered, the test **skips** (returns) if `open` fails with `PermissionDenied` after retries — mirroring `listener.rs`'s "skip when running as root" pattern. The normal case still exercises the real admin-DACL path.
- **Pre-CI safety net**: `cargo xwin clippy --all-targets --target x86_64-pc-windows-msvc` compiles this `#[cfg(all(test, windows))]` test on the macOS host (catches API/type errors). Only its *runtime* behavior is validated in `windows-latest` CI; the host `cargo test` does not run it (cfg'd out).
- **Constraints**: no production-code refactor for testability (test the real `serve` as-is). `unsafe` needs `// SAFETY:`. `cargo fmt`/`clippy -D warnings` clean. Test-only deps: `windows-sys` `ERROR_PIPE_BUSY` is in `Win32_Foundation` (already enabled in `service/Cargo.toml`).

---

## File Structure

- **Modify** `service/src/pipe.rs` — add `#[cfg(all(test, windows))] mod tests` with the round-trip test.

No other files. No production-code change.

---

## Task 1: named-pipe round-trip test

**Files:** Modify `service/src/pipe.rs`

- [ ] **Step 1: Add the test module at the end of `pipe.rs`**

```rust
#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::engine::test_support::FakeEngine;
    use crate::service::{channel, run_service, BackendInfo};
    use spark_ipc::{Client, RequestPayload, ResponsePayload, TunnelState, PROTOCOL_VERSION};
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};

    /// A unique pipe name per test process so parallel/rerun tests don't collide.
    fn temp_pipe(tag: &str) -> std::ffi::OsString {
        std::ffi::OsString::from(format!(r"\\.\pipe\spark-test-{}-{tag}", std::process::id()))
    }

    /// Connect a client to `name`, retrying the startup race (pipe not yet created) and
    /// ERROR_PIPE_BUSY. Returns `None` if the pipe can't be opened for access reasons (a
    /// UAC-filtered token on some CI hosts) so the caller can skip rather than fail.
    async fn connect(name: &std::ffi::OsStr) -> Option<tokio::net::windows::named_pipe::NamedPipeClient> {
        for _ in 0..50 {
            match ClientOptions::new().open(name) {
                Ok(client) => return Some(client),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {}
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {}
                Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => return None,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
                Err(e) => panic!("unexpected pipe open error: {e}"),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("pipe never became connectable");
    }

    /// A client drives connect/status over the real admin-DACL named pipe + `serve_connection`.
    /// Exercises `AdminOnlySecurity` (SDDL FFI), the accept loop, and the ipc round-trip in the
    /// windows-latest CI job. Skips if the CI token can't open the admin pipe.
    #[tokio::test]
    async fn client_drives_the_service_over_the_pipe() {
        let name = temp_pipe("ok");

        let (cmd_tx, cmd_rx) = channel();
        let engine = FakeEngine::default();
        let running = engine.running.clone();
        tokio::spawn(run_service(
            engine,
            cmd_rx,
            false,
            BackendInfo::default(),
            None,
        ));
        tokio::spawn({
            let name = name.clone();
            async move {
                let _ = serve(name.as_os_str(), cmd_tx).await;
            }
        });

        let Some(pipe) = connect(name.as_os_str()).await else {
            eprintln!("skipping: cannot open the admin-DACL pipe in this environment");
            return;
        };
        let mut client = Client::new(pipe);
        assert_eq!(client.handshake().await.unwrap(), PROTOCOL_VERSION);
        assert!(matches!(
            client.request(RequestPayload::Connect).await.unwrap(),
            ResponsePayload::Ack
        ));
        assert!(running.load(Ordering::SeqCst), "engine should be started");
        match client.request(RequestPayload::GetStatus).await.unwrap() {
            ResponsePayload::Status(s) => assert_eq!(s.state, TunnelState::Connected),
            other => panic!("unexpected status reply: {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Confirm the referenced items match the crate** (verify, don't guess)

Check the same imports `listener.rs`'s test uses actually resolve here: `crate::service::{channel, run_service, BackendInfo}`, `crate::engine::test_support::FakeEngine`, and the `spark_ipc` names (`Client`, `RequestPayload::{Connect, GetStatus}`, `ResponsePayload::{Ack, Status}`, `TunnelState::Connected`, `PROTOCOL_VERSION`). They're used verbatim in `listener.rs:71-121`, so they resolve. Confirm `ERROR_ACCESS_DENIED`/`ERROR_FILE_NOT_FOUND`/`ERROR_PIPE_BUSY` are in `windows_sys::Win32::Foundation` (they are; `Win32_Foundation` is enabled in `service/Cargo.toml`). If any name differs, fix to match.

- [ ] **Step 3: Host gate (test compiled out on macOS, but the crate must build)**

Run: `cargo clippy -p spark-service --all-targets -- -D warnings`
Expected: clean (the `cfg(all(test, windows))` module is not compiled on the host).

- [ ] **Step 4: Windows cross-compile the test (the real pre-CI check)**

Run: `cargo xwin clippy -p spark-service --all-targets --target x86_64-pc-windows-msvc -- -D warnings`
Expected: clean. This compiles the `#[cfg(all(test, windows))]` test, so it catches every API/type error before CI — the only thing left for CI is runtime behavior.

- [ ] **Step 5: fmt + commit**

```bash
cargo fmt --all
git add service/src/pipe.rs
git commit -m "$(cat <<'EOF'
Windows W2c: named-pipe control-transport round-trip test (windows CI)

Exercises pipe::serve (admin-DACL SDDL FFI + accept loop) + serve_connection +
spark-ipc end-to-end over a real named pipe, mirroring the unix listener test.
Runs in the windows-latest CI job; skips gracefully if the CI token can't open
the admin-DACL pipe. Moves the Windows transport from type-checked to
exercised-in-CI. Live SCM/on-Windows tunneling still deferred to hardware.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: gate + PR

- [ ] fmt --check; `cargo clippy --workspace --all-targets -D warnings`; `cargo xwin clippy --workspace --all-targets --target x86_64-pc-windows-msvc -D warnings`; `cargo test --workspace` (host — the new test is cfg'd out, existing suite stays green).
- [ ] Push `fisk/windows-w2c-pipe-test`; open PR (base `main`). Body: what it exercises, that it's validated by the `windows-latest` CI run of this very test, and that live SCM + on-Windows tunneling remain deferred.
- [ ] review-pr loop → squash-merge on green (esp. the `windows-latest` test job actually running the new test) + 0 unresolved threads. Then W3.

---

## Self-Review

- **Scope:** one test file, no production change — proportional to the fact that W2c's transport code already exists.
- **Not a test anti-pattern:** it drives the *real* `serve` over a *real* pipe (not a mock), asserting real behavior (handshake/connect/status), exactly like the trusted unix `listener.rs` test.
- **CI-only-runtime risk** acknowledged + mitigated (xwin compiles it pre-CI; retry handles the startup race; skip handles token filtering).
- **Type consistency:** mirrors `listener.rs:71-121` verbatim for the shared items; `NamedPipeClient: AsyncRead+AsyncWrite+Unpin` satisfies `Client::new`.
