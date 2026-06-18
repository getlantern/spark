//! `spark-ffi` — the control-plane backend binding.
//!
//! Exposes a typed [`Backend`] over the `spark-ipc` control [`Client`](spark_ipc::Client) as
//! UniFFI-generated Swift/Kotlin, so any UI drives a running `spark-service` through one API. This
//! supersedes the CLI's hand-written control client (`cli/src/main.rs::control`). It is the
//! **control** surface only; the data path stays in the platform shims (`platforms/android`,
//! `platforms/apple`), which run the core in-process on an OS-provided fd.
//!
//! `Backend` owns a tokio runtime. The control methods are `async` — they generate Swift `async` /
//! Kotlin `suspend` bindings, so foreign callers `await` them directly without managing threads.
//! Each runs one request/response round-trip on the owned runtime: the work is `spawn`ed there and
//! the method awaits its `JoinHandle`, so the tokio IO has a reactor no matter which foreign thread
//! UniFFI polls the future from (we drive the future ourselves rather than via `async_runtime =
//! "tokio"` / `async-compat`'s global runtime, keeping one runtime for both calls and the
//! subscription). [`Backend::subscribe`] spawns a long-lived task on that same runtime that streams
//! server pushes to a foreign [`EventListener`].

use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

use spark_ipc::{Client, Push, RequestPayload, ResponsePayload};
use tokio::task::AbortHandle;

uniffi::setup_scaffolding!();

/// Mirror of [`spark_ipc::TunnelState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

impl From<spark_ipc::TunnelState> for TunnelState {
    fn from(s: spark_ipc::TunnelState) -> Self {
        use spark_ipc::TunnelState as S;
        match s {
            S::Disconnected => Self::Disconnected,
            S::Connecting => Self::Connecting,
            S::Connected => Self::Connected,
            S::Disconnecting => Self::Disconnecting,
            S::Failed => Self::Failed,
        }
    }
}

/// Mirror of [`spark_ipc::TunnelStatus`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TunnelStatus {
    pub state: TunnelState,
    /// The kill-switch failed open and traffic is currently routing directly — surface this loudly.
    pub direct_fallback: bool,
}

impl From<spark_ipc::TunnelStatus> for TunnelStatus {
    fn from(s: spark_ipc::TunnelStatus) -> Self {
        Self {
            state: s.state.into(),
            direct_fallback: s.direct_fallback,
        }
    }
}

/// Mirror of [`spark_ipc::TunnelEvent`] — the item type of the event stream.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TunnelEvent {
    StateChanged { state: TunnelState },
    FellOpenToDirect,
}

impl From<spark_ipc::TunnelEvent> for TunnelEvent {
    fn from(e: spark_ipc::TunnelEvent) -> Self {
        use spark_ipc::TunnelEvent as E;
        match e {
            E::StateChanged(s) => Self::StateChanged { state: s.into() },
            E::FellOpenToDirect => Self::FellOpenToDirect,
        }
    }
}

/// Errors surfaced to foreign callers: the service's typed [`ErrorCode`](spark_ipc::ErrorCode)
/// categories plus a transport bucket for connect/IO/handshake failures.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BackendError {
    #[error("not authorized to control the service")]
    Unauthorized,
    #[error("no common control-protocol version")]
    UnsupportedVersion,
    #[error("invalid request for the current state")]
    InvalidRequest,
    #[error("the operation requires an active tunnel")]
    NotConnected,
    #[error("service error: {message}")]
    Internal { message: String },
    /// Could not reach or talk to the service (connect failed, closed mid-call, unexpected reply).
    #[error("control transport error: {message}")]
    Transport { message: String },
}

impl From<spark_ipc::ErrorCode> for BackendError {
    fn from(c: spark_ipc::ErrorCode) -> Self {
        use spark_ipc::ErrorCode as E;
        match c {
            E::Unauthorized => Self::Unauthorized,
            E::UnsupportedVersion => Self::UnsupportedVersion,
            E::InvalidRequest => Self::InvalidRequest,
            E::NotConnected => Self::NotConnected,
            E::Internal => Self::Internal {
                message: "internal service error".to_owned(),
            },
        }
    }
}

/// Wrap an IO/transport failure.
fn transport(e: impl std::fmt::Display) -> BackendError {
    BackendError::Transport {
        message: e.to_string(),
    }
}

/// The foreign-implemented event sink: the `Subscribe` → `Push(Event)` stream of `spark-ipc`.
#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: TunnelEvent);
}

/// A handle to a running `spark-service`'s control plane. Drives the `spark-ipc` protocol on an
/// owned tokio runtime.
#[derive(uniffi::Object)]
pub struct Backend {
    socket_path: String,
    runtime: tokio::runtime::Runtime,
    /// The live event-subscription task, if any.
    subscription: Mutex<Option<AbortHandle>>,
}

#[uniffi::export]
impl Backend {
    /// Create a backend bound to a service control endpoint (a unix-socket path on unix, a named
    /// pipe on Windows). Does not connect until a method is called.
    #[uniffi::constructor]
    pub fn new(socket_path: String) -> Result<Arc<Self>, BackendError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(transport)?;
        Ok(Arc::new(Self {
            socket_path,
            runtime,
            subscription: Mutex::new(None),
        }))
    }

    /// Bring the tunnel up.
    pub async fn connect(&self) -> Result<(), BackendError> {
        match self.call(RequestPayload::Connect).await? {
            ResponsePayload::Ack => Ok(()),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("connect", &other)),
        }
    }

    /// Tear the tunnel down.
    pub async fn disconnect(&self) -> Result<(), BackendError> {
        match self.call(RequestPayload::Disconnect).await? {
            ResponsePayload::Ack => Ok(()),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("disconnect", &other)),
        }
    }

    /// Fetch the current tunnel status.
    pub async fn status(&self) -> Result<TunnelStatus, BackendError> {
        match self.call(RequestPayload::GetStatus).await? {
            ResponsePayload::Status(s) => Ok(s.into()),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("status", &other)),
        }
    }

    /// Stream tunnel events to `listener` on a background task. Replaces any prior subscription.
    pub fn subscribe(&self, listener: Box<dyn EventListener>) {
        self.unsubscribe();
        let path = self.socket_path.clone();
        let task = self.runtime.spawn(async move {
            let stream = match connect_control(Path::new(&path)).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut client = Client::new(stream);
            if client.handshake().await.is_err() {
                return;
            }
            if client
                .request(RequestPayload::Subscribe {
                    events: true,
                    logs: false,
                })
                .await
                .is_err()
            {
                return;
            }
            loop {
                match client.next_push().await {
                    Ok(Some(Push::Event(event))) => listener.on_event(event.into()),
                    // The service only pushes events here (logs disabled); ignore anything else.
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        });
        *self.subscription.lock().unwrap() = Some(task.abort_handle());
    }

    /// Stop streaming events (no-op if not subscribed).
    pub fn unsubscribe(&self) {
        if let Some(handle) = self.subscription.lock().unwrap().take() {
            handle.abort();
        }
    }
}

impl Backend {
    /// Run one request → response on the owned runtime. The round-trip is `spawn`ed onto the
    /// runtime — so its tokio IO has a reactor regardless of which foreign thread polls this
    /// future — and we await the resulting `JoinHandle`. A `JoinError` (the task panicked or was
    /// cancelled) surfaces as a `Transport` error.
    async fn call(&self, payload: RequestPayload) -> Result<ResponsePayload, BackendError> {
        let path = self.socket_path.clone();
        self.runtime
            .spawn(async move { round_trip(&path, payload).await })
            .await
            .map_err(transport)?
    }
}

/// Open a fresh control connection, handshake, and run one request → response. Per-call
/// connections match the CLI and keep the client stateless (control ops are infrequent).
async fn round_trip(
    socket_path: &str,
    payload: RequestPayload,
) -> Result<ResponsePayload, BackendError> {
    let stream = connect_control(Path::new(socket_path))
        .await
        .map_err(transport)?;
    let mut client = Client::new(stream);
    client.handshake().await.map_err(transport)?;
    client.request(payload).await.map_err(transport)
}

impl Drop for Backend {
    fn drop(&mut self) {
        // Stop the event task before the runtime tears down.
        if let Some(handle) = self.subscription.lock().unwrap().take() {
            handle.abort();
        }
    }
}

/// Build a `Transport` error for a response that doesn't fit the request.
fn unexpected(op: &str, reply: &ResponsePayload) -> BackendError {
    BackendError::Transport {
        message: format!("unexpected reply to {op}: {reply:?}"),
    }
}

/// Connect to the service's control endpoint: a unix-domain socket on unix, a named pipe on
/// Windows (mirrors `cli/src/main.rs::connect_control`).
#[cfg(unix)]
async fn connect_control(
    endpoint: &Path,
) -> std::io::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> {
    tokio::net::UnixStream::connect(endpoint).await
}

#[cfg(windows)]
async fn connect_control(
    endpoint: &Path,
) -> std::io::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint.as_os_str())
}
