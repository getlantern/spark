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

/// Connect to the control transport, handshake, and issue one request. The transport is
/// platform-specific; the [`Client`] round-trip is shared.
async fn round_trip(addr: &Path, payload: RequestPayload) -> std::io::Result<ResponsePayload> {
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
        // own thread/runtime, so the two never nest.
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
        // Let the listener bind (it's on another thread).
        std::thread::sleep(std::time::Duration::from_millis(100));

        let client = IpcClient::new(addr.clone());
        let resp = client.request(RequestPayload::Connect).unwrap();
        assert!(matches!(resp, ResponsePayload::Ack));

        server.join().unwrap();
        let _ = std::fs::remove_file(&addr);
    }
}
