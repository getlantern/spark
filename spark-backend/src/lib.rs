//! `spark-backend` — the GUI-agnostic control-plane backend.
//!
//! A typed async [`Backend`] over `spark-ipc`'s [`Client`](spark_ipc::Client): the request/response
//! control surface (`connect`/`disconnect`/`status`/`details`/`metrics`/profiles) plus a
//! reconnecting subscription. It returns plain `spark-ipc` types, carries **no** binding annotations
//! (UniFFI/frb/…) and owns **no** runtime — so the dependency arrows point *into* it, never out.
//! Every frontend is a thin layer on top: `spark-ffi` (UniFFI → Swift/Kotlin, mobile), a
//! `flutter_rust_bridge` bridge (Flutter desktop), Tauri/Dioxus/CLI directly.
//!
//! Per-call connections (open → `Hello` → request) match the CLI and keep the client stateless;
//! control ops are infrequent. The caller drives these `async fn`s on whatever executor it has.

use std::path::Path;
use std::time::Duration;

use spark_ipc::{
    Capabilities, Client, Details, ErrorCode, LogLine, Metrics, ProfileDoc, ProfileSummary, Push,
    RequestPayload, ResponsePayload, TunnelEvent, TunnelStatus, Validation,
};

/// Control-plane errors: the service's typed [`ErrorCode`] categories plus a transport bucket for
/// connect/IO/handshake failures and unexpected replies. No secrets.
#[derive(Debug, thiserror::Error)]
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

impl From<ErrorCode> for BackendError {
    fn from(c: ErrorCode) -> Self {
        match c {
            ErrorCode::Unauthorized => Self::Unauthorized,
            ErrorCode::UnsupportedVersion => Self::UnsupportedVersion,
            ErrorCode::InvalidRequest => Self::InvalidRequest,
            ErrorCode::NotConnected => Self::NotConnected,
            ErrorCode::Internal => Self::Internal {
                message: "internal service error".to_owned(),
            },
        }
    }
}

fn transport(e: impl std::fmt::Display) -> BackendError {
    BackendError::Transport {
        message: e.to_string(),
    }
}

fn unexpected(op: &str, reply: &ResponsePayload) -> BackendError {
    BackendError::Transport {
        message: format!("unexpected reply to {op}: {reply:?}"),
    }
}

/// An item from the subscription stream — agnostic of any binding's event type. Bindings map this
/// to their own callback/stream (`spark-ffi` → `EventListener`, frb → a Dart `Stream`, …).
#[derive(Debug, Clone)]
pub enum BackendEvent {
    /// A tunnel lifecycle event from the service.
    Event(TunnelEvent),
    /// A redacted log line from the service.
    Log(LogLine),
    /// The stream dropped and re-established (not the first connect) — events during the gap were
    /// missed, so the holder's state may be stale; re-query `status()`.
    Reconnected,
}

/// A typed control client for a running `spark-service`. Cheap to clone (just the endpoint path) and
/// holds no runtime, so a binding can clone it into a spawned task and drive it on its own executor.
#[derive(Debug, Clone)]
pub struct Backend {
    socket_path: String,
}

impl Backend {
    /// Bind to a service control endpoint (a unix-socket path on unix, a named pipe on Windows).
    /// Does not connect until a method is called.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Open a fresh control connection, handshake, and run one request → response.
    async fn call(&self, payload: RequestPayload) -> Result<ResponsePayload, BackendError> {
        let stream = connect_control(Path::new(&self.socket_path))
            .await
            .map_err(transport)?;
        let mut client = Client::new(stream);
        client.handshake().await.map_err(transport)?;
        client.request(payload).await.map_err(transport)
    }

    /// Bring the tunnel up.
    pub async fn connect(&self) -> Result<(), BackendError> {
        self.ack(RequestPayload::Connect, "connect").await
    }

    /// Tear the tunnel down.
    pub async fn disconnect(&self) -> Result<(), BackendError> {
        self.ack(RequestPayload::Disconnect, "disconnect").await
    }

    /// Fetch the current tunnel status.
    pub async fn status(&self) -> Result<TunnelStatus, BackendError> {
        match self.call(RequestPayload::GetStatus).await? {
            ResponsePayload::Status(s) => Ok(s),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("status", &other)),
        }
    }

    /// Fetch what this service build supports (transports, stacks, versions).
    pub async fn capabilities(&self) -> Result<Capabilities, BackendError> {
        match self.call(RequestPayload::GetCapabilities).await? {
            ResponsePayload::Capabilities(c) => Ok(c),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("capabilities", &other)),
        }
    }

    /// Fetch a richer status snapshot than [`Backend::status`].
    pub async fn details(&self) -> Result<Details, BackendError> {
        match self.call(RequestPayload::GetDetails).await? {
            ResponsePayload::Details(d) => Ok(d),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("details", &other)),
        }
    }

    /// Fetch the data-path counters.
    pub async fn metrics(&self) -> Result<Metrics, BackendError> {
        match self.call(RequestPayload::GetMetrics).await? {
            ResponsePayload::Metrics(m) => Ok(m),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("metrics", &other)),
        }
    }

    /// List the stored connection profiles (redacted — no secrets).
    pub async fn list_profiles(&self) -> Result<Vec<ProfileSummary>, BackendError> {
        match self.call(RequestPayload::ListProfiles).await? {
            ResponsePayload::Profiles(ps) => Ok(ps),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("list_profiles", &other)),
        }
    }

    /// Fetch one profile as a redacted TOML config document (secrets blanked).
    pub async fn get_profile(&self, name: String) -> Result<ProfileDoc, BackendError> {
        match self.call(RequestPayload::GetProfile { name }).await? {
            ResponsePayload::Profile(d) => Ok(d),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("get_profile", &other)),
        }
    }

    /// Create or replace a profile from a TOML config document (blanked secrets keep the stored
    /// value).
    pub async fn set_profile(&self, name: String, toml: String) -> Result<(), BackendError> {
        self.ack(RequestPayload::SetProfile { name, toml }, "set_profile")
            .await
    }

    /// Delete a stored profile.
    pub async fn delete_profile(&self, name: String) -> Result<(), BackendError> {
        self.ack(RequestPayload::DeleteProfile { name }, "delete_profile")
            .await
    }

    /// Select the active profile (the one a future `connect` will use).
    pub async fn set_active_profile(&self, name: String) -> Result<(), BackendError> {
        self.ack(
            RequestPayload::SetActiveProfile { name },
            "set_active_profile",
        )
        .await
    }

    /// Validate a TOML config document without storing it.
    pub async fn validate_profile(&self, toml: String) -> Result<Validation, BackendError> {
        match self.call(RequestPayload::ValidateProfile { toml }).await? {
            ResponsePayload::Validated(v) => Ok(v),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("validate_profile", &other)),
        }
    }

    /// A request whose only success reply is `Ack`.
    async fn ack(&self, payload: RequestPayload, op: &str) -> Result<(), BackendError> {
        match self.call(payload).await? {
            ResponsePayload::Ack => Ok(()),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected(op, &other)),
        }
    }

    /// Run the reconnecting subscription loop, delivering each [`BackendEvent`] to `on_event`, until
    /// the future is dropped (the binding cancels its task). Capped exponential backoff (floor
    /// 250 ms, cap 30 s) that resets once a session is established; a `Reconnected` is emitted on
    /// every *re*-establishment (not the first connect). `sleep`/`next_push` are the only await
    /// points, so dropping the task tears it down cleanly.
    pub async fn run_subscription(&self, mut on_event: impl FnMut(BackendEvent) + Send) {
        const MIN_BACKOFF: Duration = Duration::from_millis(250);
        const MAX_BACKOFF: Duration = Duration::from_secs(30);
        let mut backoff = MIN_BACKOFF;
        let mut established_before = false;
        loop {
            let established = self.run_session(&mut on_event, established_before).await;
            established_before |= established;
            backoff = if established {
                MIN_BACKOFF
            } else {
                (backoff * 2).min(MAX_BACKOFF)
            };
            tokio::time::sleep(backoff).await;
        }
    }

    /// One subscription session: connect, handshake, `Subscribe`, pump pushes to `on_event` until
    /// the stream ends. Returns whether it was *established* (so the loop can reset its backoff).
    async fn run_session(
        &self,
        on_event: &mut (impl FnMut(BackendEvent) + Send),
        emit_reconnect: bool,
    ) -> bool {
        let stream = match connect_control(Path::new(&self.socket_path)).await {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut client = Client::new(stream);
        if client.handshake().await.is_err() {
            return false;
        }
        if client
            .request(RequestPayload::Subscribe {
                events: true,
                logs: true,
            })
            .await
            .is_err()
        {
            return false;
        }
        if emit_reconnect {
            on_event(BackendEvent::Reconnected);
        }
        loop {
            match client.next_push().await {
                Ok(Some(Push::Event(e))) => on_event(BackendEvent::Event(e)),
                Ok(Some(Push::Log(l))) => on_event(BackendEvent::Log(l)),
                // `Push::Dropped` (backpressure marker) carries no payload the caller acts on.
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        true
    }
}

/// Connect to the service's control endpoint: a unix-domain socket on unix, a named pipe on Windows.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_map_to_typed_errors() {
        assert!(matches!(
            BackendError::from(ErrorCode::NotConnected),
            BackendError::NotConnected
        ));
        assert!(matches!(
            BackendError::from(ErrorCode::Unauthorized),
            BackendError::Unauthorized
        ));
        assert!(matches!(
            BackendError::from(ErrorCode::Internal),
            BackendError::Internal { .. }
        ));
    }

    #[test]
    fn backend_is_cheap_to_clone() {
        let b = Backend::new("/var/run/spark.sock");
        let _c = b.clone(); // just the endpoint path — no runtime, no connection
    }
}
