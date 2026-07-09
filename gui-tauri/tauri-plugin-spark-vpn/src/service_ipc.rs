//! Desktop control over spark-ipc: a synchronous bridge from the [`TunnelControl`](crate::TunnelControl)
//! trait to the async spark-ipc [`Client`], talking to the privileged `spark-service` over the
//! platform control transport (named pipe on Windows, unix socket elsewhere).
//!
//! Compiled off android (which drives the in-process core via JNI). macOS is included so this
//! module compiles and unit-tests on the dev host — its unix-socket path is the same code Linux
//! uses; only the Windows named-pipe branch is Windows-only (cross-compiled, not host-run).

#![cfg(not(target_os = "android"))]
// On macOS the plugin uses AppleControl, not ServiceControl, so nothing in this module is used by
// the (non-test) macOS lib build — it's compiled here only so its transport-agnostic logic
// unit-tests on the dev host. Windows/Linux (where ServiceControl uses it) still enforce dead_code.
#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::path::{Path, PathBuf};

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
        // TunnelStatus carries no protocol; a later pass can source it from GetDetails.
        protocol: String::new(),
        fail_open: s.direct_fallback,
    }
}

/// A synchronous spark-ipc client for the desktop service. Each call opens a fresh connection,
/// handshakes, sends one request, and closes — simple + stateless for an infrequent control plane.
/// A queued request: the payload plus the channel to return its result on.
type Job = (
    RequestPayload,
    std::sync::mpsc::Sender<crate::Result<ResponsePayload>>,
);

/// A synchronous spark-ipc client for the desktop service. A single long-lived worker thread owns
/// one current-thread runtime and serves every request off an mpsc queue — so repeated polls (the
/// GUI polls `status` every ~2s) reuse the runtime instead of spawning a thread + runtime per call.
/// Each request still opens a fresh connection (handshake + one request) — simple + stateless for
/// an infrequent control plane. `block_on` runs on this dedicated thread, never inside Tauri's
/// runtime, so it can't nest runtimes (the plugin commands are `async fn`).
#[derive(Clone)]
pub(crate) struct IpcClient {
    tx: std::sync::mpsc::Sender<Job>,
}

impl IpcClient {
    pub(crate) fn new(addr: PathBuf) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    // Can't build the runtime: fail every queued/future request instead of hanging.
                    for (_payload, resp) in rx {
                        let _ = resp.send(Err(crate::Error::Platform(format!("ipc runtime: {e}"))));
                    }
                    return;
                }
            };
            // Serve requests until all senders drop (IpcClient/ServiceControl gone), then exit.
            // Bound the whole round-trip so a service that accepts the connection but stops
            // responding (or a stuck uncancel-safe read) can't hang the worker + the caller
            // forever. The window covers the Windows open-retry (~3s) + handshake + request.
            // Status polls (the GUI hits `status` ~every 2s) get a shorter deadline than the
            // mutating commands: a hung-but-connected service must not make every poll cost the full
            // window and back the queue up behind this single worker — status should be near-instant,
            // so time it out fast and let the next poll through; connect/disconnect keep the longer
            // window (they can legitimately take a few seconds, incl. the ~3s pipe open-retry).
            for (payload, resp) in rx {
                let deadline = match payload {
                    RequestPayload::GetStatus => std::time::Duration::from_secs(5),
                    _ => std::time::Duration::from_secs(15),
                };
                // Isolate a panic in the round-trip (a codec/decoder bug, an allocation on a forged
                // frame length, a dependency `unwrap`) so it fails just this request instead of
                // unwinding the worker loop — which would drop the receiver and wedge the control
                // plane for the rest of the session (every later command erroring "worker is gone").
                // No-op under `panic = "abort"`; a strict improvement under unwind.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rt.block_on(async {
                        match tokio::time::timeout(deadline, round_trip(&addr, payload)).await {
                            Ok(Ok(payload)) => Ok(payload),
                            Ok(Err(e)) => Err(crate::Error::Platform(format!("service ipc: {e}"))),
                            Err(_elapsed) => {
                                Err(crate::Error::Platform("service ipc timed out".into()))
                            }
                        }
                    })
                }))
                .unwrap_or_else(|_| {
                    Err(crate::Error::Platform("service ipc worker panicked".into()))
                });
                let _ = resp.send(result);
            }
        });
        Self { tx }
    }

    /// Send one request and block until the worker returns its response payload.
    pub(crate) fn request(&self, payload: RequestPayload) -> crate::Result<ResponsePayload> {
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();
        self.tx
            .send((payload, resp_tx))
            .map_err(|_| crate::Error::Platform("ipc worker is gone".into()))?;
        resp_rx
            .recv()
            .map_err(|_| crate::Error::Platform("ipc worker dropped the response".into()))?
    }
}

/// Connect to the control transport, handshake, and issue one request. The transport is
/// platform-specific; the [`Client`] round-trip is shared.
async fn round_trip(addr: &Path, payload: RequestPayload) -> std::io::Result<ResponsePayload> {
    #[cfg(target_os = "windows")]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        use tokio::time::{sleep, Duration, Instant};
        use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};
        // The service pipe may not exist yet (startup) or all instances may be momentarily busy;
        // both are transient. Retry those for up to ~3s so the GUI doesn't surface spurious errors.
        let deadline = Instant::now() + Duration::from_secs(3);
        let pipe = loop {
            match ClientOptions::new().open(addr.as_os_str()) {
                Ok(pipe) => break pipe,
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(code)
                            if code == ERROR_FILE_NOT_FOUND as i32
                                || code == ERROR_PIPE_BUSY as i32
                    ) && Instant::now() < deadline =>
                {
                    sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        };
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

    /// A minimal one-connection server: reply to `Hello` with a version, and to every other request
    /// with `answer`.
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
        // Run the server on its own thread + current-thread runtime; IpcClient::request spawns its
        // own thread/runtime, so the two never nest. A readiness channel (not a sleep) makes the
        // client wait until the listener is actually bound.
        let server_addr = addr.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = UnixListener::bind(&server_addr).unwrap();
                ready_tx.send(()).unwrap();
                serve_one(listener, ResponsePayload::Ack).await;
            });
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("server listener should bind within 5s");

        let client = IpcClient::new(addr.clone());
        let resp = client.request(RequestPayload::Connect).unwrap();
        assert!(matches!(resp, ResponsePayload::Ack));

        server.join().unwrap();
        let _ = std::fs::remove_file(&addr);
    }
}
