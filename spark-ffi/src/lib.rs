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
//! subscription). [`Backend::subscribe`] spawns a long-lived, auto-reconnecting task on that same
//! runtime that streams server pushes to a foreign [`EventListener`].

use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

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

/// The item type of the event stream: the service's [`spark_ipc::TunnelEvent`]s plus one
/// binding-only variant the reconnect loop synthesizes ([`TunnelEvent::StreamReconnected`]).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TunnelEvent {
    StateChanged {
        state: TunnelState,
    },
    FellOpenToDirect,
    /// The event stream dropped and the subscription re-established (a service restart or a control
    /// connection blip). Events during the gap were missed, so the state you hold may be stale —
    /// re-query [`Backend::status`] on this. Synthesized by `spark-ffi`, never sent by the service.
    StreamReconnected,
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

/// Mirror of [`spark_ipc::TransportKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TransportKind {
    Direct,
    Plain,
    Anytls,
    Wasm,
}

impl From<spark_ipc::TransportKind> for TransportKind {
    fn from(t: spark_ipc::TransportKind) -> Self {
        use spark_ipc::TransportKind as T;
        match t {
            T::Direct => Self::Direct,
            T::Plain => Self::Plain,
            T::Anytls => Self::Anytls,
            T::Wasm => Self::Wasm,
        }
    }
}

/// Mirror of [`spark_ipc::NetStack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NetStack {
    Userspace,
    System,
}

impl From<spark_ipc::NetStack> for NetStack {
    fn from(s: spark_ipc::NetStack) -> Self {
        match s {
            spark_ipc::NetStack::Userspace => Self::Userspace,
            spark_ipc::NetStack::System => Self::System,
        }
    }
}

/// Mirror of [`spark_ipc::KillSwitchMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KillSwitchMode {
    FailOpen,
    FailClosed,
}

impl From<spark_ipc::KillSwitchMode> for KillSwitchMode {
    fn from(m: spark_ipc::KillSwitchMode) -> Self {
        match m {
            spark_ipc::KillSwitchMode::FailOpen => Self::FailOpen,
            spark_ipc::KillSwitchMode::FailClosed => Self::FailClosed,
        }
    }
}

/// Mirror of [`spark_ipc::ModuleInfo`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ModuleInfo {
    pub name: String,
    pub version: u32,
}

impl From<spark_ipc::ModuleInfo> for ModuleInfo {
    fn from(m: spark_ipc::ModuleInfo) -> Self {
        Self {
            name: m.name,
            version: m.version,
        }
    }
}

/// Mirror of [`spark_ipc::Capabilities`] — what the service build supports.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Capabilities {
    pub protocol_version: u32,
    pub build_version: String,
    pub transports: Vec<TransportKind>,
    pub stacks: Vec<NetStack>,
    pub platform: String,
}

impl From<spark_ipc::Capabilities> for Capabilities {
    fn from(c: spark_ipc::Capabilities) -> Self {
        Self {
            protocol_version: c.protocol_version,
            build_version: c.build_version,
            transports: c.transports.into_iter().map(Into::into).collect(),
            stacks: c.stacks.into_iter().map(Into::into).collect(),
            platform: c.platform,
        }
    }
}

/// Mirror of [`spark_ipc::Details`] — a richer status snapshot than [`TunnelStatus`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Details {
    pub state: TunnelState,
    pub direct_fallback: bool,
    pub selected_transport: TransportKind,
    pub selected_stack: NetStack,
    pub module: Option<ModuleInfo>,
    pub kill_switch: KillSwitchMode,
    pub last_error: Option<String>,
}

impl From<spark_ipc::Details> for Details {
    fn from(d: spark_ipc::Details) -> Self {
        Self {
            state: d.state.into(),
            direct_fallback: d.direct_fallback,
            selected_transport: d.selected_transport.into(),
            selected_stack: d.selected_stack.into(),
            module: d.module.map(Into::into),
            kill_switch: d.kill_switch.into(),
            last_error: d.last_error,
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

    /// Fetch what this service build supports (transports, stacks, versions) — render valid UI
    /// choices. Static for the service's lifetime.
    pub async fn capabilities(&self) -> Result<Capabilities, BackendError> {
        match self.call(RequestPayload::GetCapabilities).await? {
            ResponsePayload::Capabilities(c) => Ok(c.into()),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("capabilities", &other)),
        }
    }

    /// Fetch a richer status snapshot than [`Backend::status`]: selected transport/stack, the loaded
    /// module, kill-switch mode, and the last error.
    pub async fn details(&self) -> Result<Details, BackendError> {
        match self.call(RequestPayload::GetDetails).await? {
            ResponsePayload::Details(d) => Ok(d.into()),
            ResponsePayload::Error { code, .. } => Err(code.into()),
            other => Err(unexpected("details", &other)),
        }
    }

    /// Stream tunnel events to `listener` on a background task. Replaces any prior subscription.
    ///
    /// The task auto-reconnects with capped exponential backoff, so it survives a service restart
    /// or a dropped control connection. Events that occur while disconnected are missed (this is a
    /// state-event stream, not a log); on each reconnect the listener gets a
    /// [`TunnelEvent::StreamReconnected`], on which it should re-query [`Backend::status`] for the
    /// authoritative state.
    pub fn subscribe(&self, listener: Box<dyn EventListener>) {
        self.unsubscribe();
        let path = self.socket_path.clone();
        let task = self.runtime.spawn(subscription_loop(path, listener));
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

/// The reconnecting event-subscription loop backing [`Backend::subscribe`]. Runs until the task is
/// aborted (`unsubscribe`/`Drop`): each iteration runs one subscription session, then waits before
/// reconnecting. Backoff resets to the floor once a session is established and grows (capped) while
/// the service is unreachable. `sleep` and `next_push` are the only await points, so an abort tears
/// the task down cleanly. No jitter — this is a single client, not a thundering herd.
///
/// Every *re*-establishment (not the first connect) emits [`TunnelEvent::StreamReconnected`] before
/// pumping, so the listener knows there was a gap and can re-query `status()`.
async fn subscription_loop(path: String, listener: Box<dyn EventListener>) {
    const MIN_BACKOFF: Duration = Duration::from_millis(250);
    const MAX_BACKOFF: Duration = Duration::from_secs(30);
    let mut backoff = MIN_BACKOFF;
    let mut established_before = false;
    loop {
        // Emit the resync signal only on a *re*-establishment — the first successful connect (even
        // after connect retries) isn't a gap the listener needs to recover from.
        let established =
            run_subscription_session(&path, listener.as_ref(), established_before).await;
        established_before |= established;
        backoff = if established {
            MIN_BACKOFF
        } else {
            (backoff * 2).min(MAX_BACKOFF)
        };
        tokio::time::sleep(backoff).await;
    }
}

/// Open one control connection, handshake, `Subscribe`, and pump `Push(Event)`s to `listener` until
/// the stream ends or errors. Returns whether the subscription was *established* (handshake +
/// `Subscribe` both succeeded) so [`subscription_loop`] can decide whether to reset its backoff.
/// When `emit_reconnect` is set, fires [`TunnelEvent::StreamReconnected`] the moment the
/// subscription is (re)established, before any pushes.
async fn run_subscription_session(
    path: &str,
    listener: &dyn EventListener,
    emit_reconnect: bool,
) -> bool {
    let stream = match connect_control(Path::new(path)).await {
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
            logs: false,
        })
        .await
        .is_err()
    {
        return false;
    }
    if emit_reconnect {
        listener.on_event(TunnelEvent::StreamReconnected);
    }
    loop {
        match client.next_push().await {
            Ok(Some(Push::Event(event))) => listener.on_event(event.into()),
            // The service only pushes events here (logs disabled); ignore anything else.
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    true
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
