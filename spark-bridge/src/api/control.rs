//! The `flutter_rust_bridge`-exposed control surface. Mirror types (so the generated Dart is small
//! and stable instead of frb traversing `spark-ipc`'s whole graph) plus an opaque [`SparkBridge`]
//! handle whose methods delegate to [`spark_backend::Backend`]. All control *logic* lives in
//! `spark-backend`; this file is marshalling only.
//!
//! Runtime model (mirrors `spark-ffi`): the handle owns a multi-thread tokio runtime and each method
//! `block_on`s the delegated async call. frb runs these (non-`sync`) methods on its worker-thread
//! pool, so the blocking call never touches frb's own executor and the Dart side still gets a
//! `Future`. The single `#[frb(sync)]` is the constructor, so Dart can build the handle without an
//! `await`.

use flutter_rust_bridge::frb;

/// Tunnel lifecycle state — mirrors [`spark_ipc::TunnelState`] and the Dart `TunnelState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

impl From<spark_ipc::TunnelState> for BridgeState {
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

/// A status snapshot — mirrors [`spark_ipc::TunnelStatus`].
pub struct BridgeStatus {
    pub state: BridgeState,
    /// The kill-switch failed open and traffic is routing directly — the UI must surface this.
    pub direct_fallback: bool,
}

impl From<spark_ipc::TunnelStatus> for BridgeStatus {
    fn from(s: spark_ipc::TunnelStatus) -> Self {
        Self {
            state: s.state.into(),
            direct_fallback: s.direct_fallback,
        }
    }
}

/// Control-plane error — mirrors [`spark_backend::BackendError`] 1:1 (the FFI surface for Dart). The
/// generated Dart throws this on a failed call.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
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

impl From<spark_backend::BackendError> for BridgeError {
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

/// An opaque handle to a running `spark-service`'s control plane, for the desktop Flutter GUI. Holds
/// the tokio runtime frb's worker threads drive the control calls on; all logic delegates to
/// [`spark_backend::Backend`].
#[frb(opaque)]
pub struct SparkBridge {
    inner: spark_backend::Backend,
    runtime: tokio::runtime::Runtime,
}

impl SparkBridge {
    /// Bind to a service control endpoint (a unix-socket path on unix, a named pipe on Windows).
    /// Does not connect until a method is called. Synchronous so Dart builds it without `await`.
    #[frb(sync)]
    pub fn new(socket_path: String) -> Result<SparkBridge, BridgeError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| BridgeError::Transport {
                message: e.to_string(),
            })?;
        Ok(SparkBridge {
            inner: spark_backend::Backend::new(socket_path),
            runtime,
        })
    }

    /// Bring the tunnel up.
    pub fn connect(&self) -> Result<(), BridgeError> {
        self.runtime
            .block_on(self.inner.connect())
            .map_err(Into::into)
    }

    /// Tear the tunnel down.
    pub fn disconnect(&self) -> Result<(), BridgeError> {
        self.runtime
            .block_on(self.inner.disconnect())
            .map_err(Into::into)
    }

    /// Fetch the current tunnel status.
    pub fn status(&self) -> Result<BridgeStatus, BridgeError> {
        self.runtime
            .block_on(self.inner.status())
            .map(Into::into)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_mirror_one_to_one() {
        use spark_ipc::TunnelState as S;
        assert!(matches!(
            BridgeState::from(S::Connected),
            BridgeState::Connected
        ));
        assert!(matches!(
            BridgeState::from(S::Disconnecting),
            BridgeState::Disconnecting
        ));
        assert!(matches!(BridgeState::from(S::Failed), BridgeState::Failed));
    }

    #[test]
    fn status_maps_state_and_fallback() {
        let s = BridgeStatus::from(spark_ipc::TunnelStatus {
            state: spark_ipc::TunnelState::Connected,
            direct_fallback: true,
        });
        assert!(matches!(s.state, BridgeState::Connected));
        assert!(s.direct_fallback);
    }

    #[test]
    fn errors_mirror_one_to_one() {
        use spark_backend::BackendError as E;
        assert!(matches!(
            BridgeError::from(E::NotConnected),
            BridgeError::NotConnected
        ));
        assert!(matches!(
            BridgeError::from(E::UnsupportedVersion),
            BridgeError::UnsupportedVersion
        ));
        assert!(matches!(
            BridgeError::from(E::Internal { message: "boom".to_owned() }),
            BridgeError::Internal { message } if message == "boom"
        ));
        assert!(matches!(
            BridgeError::from(E::Transport { message: "eof".to_owned() }),
            BridgeError::Transport { message } if message == "eof"
        ));
    }
}
