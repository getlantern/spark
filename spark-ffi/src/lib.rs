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

use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;

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

/// Mirror of [`spark_ipc::Metrics`] — the data-path counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct Metrics {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub sessions_active: u64,
    pub sessions_total: u64,
}

impl From<spark_ipc::Metrics> for Metrics {
    fn from(m: spark_ipc::Metrics) -> Self {
        Self {
            bytes_up: m.bytes_up,
            bytes_down: m.bytes_down,
            sessions_active: m.sessions_active,
            sessions_total: m.sessions_total,
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

/// Mirror of [`spark_ipc::ProfileSummary`] — a stored profile's redacted summary.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProfileSummary {
    pub name: String,
    pub transport: TransportKind,
    pub stack: NetStack,
    pub has_password: bool,
    pub active: bool,
}

impl From<spark_ipc::ProfileSummary> for ProfileSummary {
    fn from(p: spark_ipc::ProfileSummary) -> Self {
        Self {
            name: p.name,
            transport: p.transport.into(),
            stack: p.stack.into(),
            has_password: p.has_password,
            active: p.active,
        }
    }
}

/// Mirror of [`spark_ipc::ProfileDoc`] — a profile as a redacted TOML config document.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProfileDoc {
    pub name: String,
    pub toml: String,
}

impl From<spark_ipc::ProfileDoc> for ProfileDoc {
    fn from(d: spark_ipc::ProfileDoc) -> Self {
        Self {
            name: d.name,
            toml: d.toml,
        }
    }
}

/// Mirror of [`spark_ipc::Validation`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Validation {
    pub valid: bool,
    pub error: Option<String>,
}

impl From<spark_ipc::Validation> for Validation {
    fn from(v: spark_ipc::Validation) -> Self {
        Self {
            valid: v.valid,
            error: v.error,
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

impl From<spark_backend::BackendError> for BackendError {
    fn from(e: spark_backend::BackendError) -> Self {
        use spark_backend::BackendError as E;
        match e {
            E::Unauthorized => Self::Unauthorized,
            E::UnsupportedVersion => Self::UnsupportedVersion,
            E::InvalidRequest => Self::InvalidRequest,
            E::NotConnected => Self::NotConnected,
            E::Internal { message } => Self::Internal { message },
            E::Transport { message } => Self::Transport { message },
        }
    }
}

/// Wrap an IO/transport failure.
fn transport(e: impl std::fmt::Display) -> BackendError {
    BackendError::Transport {
        message: e.to_string(),
    }
}

/// Log severity, mirror of [`spark_ipc::LogLevel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<spark_ipc::LogLevel> for LogLevel {
    fn from(l: spark_ipc::LogLevel) -> Self {
        use spark_ipc::LogLevel as L;
        match l {
            L::Error => Self::Error,
            L::Warn => Self::Warn,
            L::Info => Self::Info,
            L::Debug => Self::Debug,
            L::Trace => Self::Trace,
        }
    }
}

/// A redacted log line streamed to a subscriber, mirror of [`spark_ipc::LogLine`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LogLine {
    pub level: LogLevel,
    pub message: String,
}

impl From<spark_ipc::LogLine> for LogLine {
    fn from(l: spark_ipc::LogLine) -> Self {
        Self {
            level: l.level.into(),
            message: l.message,
        }
    }
}

/// The foreign-implemented sink for the subscription stream: tunnel events and (already-redacted)
/// log lines. `subscribe` opts into both; a listener that doesn't care about logs leaves `on_log`
/// empty.
#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    /// A tunnel lifecycle event (state change, fail-open, reconnect).
    fn on_event(&self, event: TunnelEvent);
    /// A redacted log line from the service.
    fn on_log(&self, line: LogLine);
}

/// A handle to a running `spark-service`'s control plane. A thin UniFFI wrapper over the
/// GUI-agnostic [`spark_backend::Backend`]: it owns the tokio runtime UniFFI's foreign calls are
/// driven on, mirrors the `spark-ipc` types into UniFFI records/enums, and adapts the subscription
/// to a foreign [`EventListener`]. All control *logic* lives in `spark-backend`.
#[derive(uniffi::Object)]
pub struct Backend {
    inner: spark_backend::Backend,
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
        // This is the control-plane client runtime (it talks to the privileged service over a
        // socket/pipe), not the data path — 2 workers is plenty and avoids one-worker-per-core.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(transport)?;
        Ok(Arc::new(Self {
            inner: spark_backend::Backend::new(socket_path),
            runtime,
            subscription: Mutex::new(None),
        }))
    }

    /// Bring the tunnel up.
    pub async fn connect(&self) -> Result<(), BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.connect().await }).await
    }

    /// Tear the tunnel down.
    pub async fn disconnect(&self) -> Result<(), BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.disconnect().await }).await
    }

    /// Fetch the current tunnel status.
    pub async fn status(&self) -> Result<TunnelStatus, BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.status().await })
            .await
            .map(Into::into)
    }

    /// Fetch what this service build supports (transports, stacks, versions) — render valid UI
    /// choices. Static for the service's lifetime.
    pub async fn capabilities(&self) -> Result<Capabilities, BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.capabilities().await })
            .await
            .map(Into::into)
    }

    /// Fetch a richer status snapshot than [`Backend::status`]: selected transport/stack, the loaded
    /// module, kill-switch mode, and the last error.
    pub async fn details(&self) -> Result<Details, BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.details().await })
            .await
            .map(Into::into)
    }

    /// Fetch the data-path counters (bytes up/down, active/total sessions). Poll for live values.
    pub async fn metrics(&self) -> Result<Metrics, BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.metrics().await })
            .await
            .map(Into::into)
    }

    /// List the stored connection profiles (redacted — no secrets).
    pub async fn list_profiles(&self) -> Result<Vec<ProfileSummary>, BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.list_profiles().await })
            .await
            .map(|v| v.into_iter().map(Into::into).collect())
    }

    /// Fetch one profile as a redacted TOML config document (secrets blanked).
    pub async fn get_profile(&self, name: String) -> Result<ProfileDoc, BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.get_profile(name).await })
            .await
            .map(Into::into)
    }

    /// Create or replace a profile from a TOML config document. Blanked secret fields keep the
    /// stored value, so a `get_profile` → edit → `set_profile` round-trip preserves secrets.
    pub async fn set_profile(&self, name: String, toml: String) -> Result<(), BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.set_profile(name, toml).await })
            .await
    }

    /// Delete a stored profile.
    pub async fn delete_profile(&self, name: String) -> Result<(), BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.delete_profile(name).await })
            .await
    }

    /// Select the active profile (the one a future `connect` will use).
    pub async fn set_active_profile(&self, name: String) -> Result<(), BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.set_active_profile(name).await })
            .await
    }

    /// Validate a TOML config document without storing it.
    pub async fn validate_profile(&self, toml: String) -> Result<Validation, BackendError> {
        let inner = self.inner.clone();
        self.spawn(async move { inner.validate_profile(toml).await })
            .await
            .map(Into::into)
    }

    /// Stream tunnel events + logs to `listener` on a background task. Replaces any prior
    /// subscription; auto-reconnects (see [`spark_backend::Backend::run_subscription`]). On each
    /// re-establishment the listener gets [`TunnelEvent::StreamReconnected`].
    pub fn subscribe(&self, listener: Box<dyn EventListener>) {
        self.unsubscribe();
        let inner = self.inner.clone();
        let task = self.runtime.spawn(async move {
            inner
                .run_subscription(move |ev| match ev {
                    spark_backend::BackendEvent::Event(e) => listener.on_event(e.into()),
                    spark_backend::BackendEvent::Log(l) => listener.on_log(l.into()),
                    spark_backend::BackendEvent::Reconnected => {
                        listener.on_event(TunnelEvent::StreamReconnected)
                    }
                })
                .await
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
    /// Drive a backend call on the owned runtime: `spawn` it (so its tokio IO has a reactor no
    /// matter which foreign thread polls this future) and await the `JoinHandle`. A `JoinError`
    /// surfaces as `Transport`; the backend's own error maps via [`From`].
    async fn spawn<T, F>(&self, fut: F) -> Result<T, BackendError>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, spark_backend::BackendError>> + Send + 'static,
    {
        self.runtime
            .spawn(fut)
            .await
            .map_err(transport)?
            .map_err(Into::into)
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        // Stop the event task before the runtime tears down.
        if let Some(handle) = self.subscription.lock().unwrap().take() {
            handle.abort();
        }
    }
}
