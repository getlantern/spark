//! The tunnel engine the service event loop drives.
//!
//! [`TunnelEngine`] is the seam between the control-plane event loop ([`crate::service`]) and
//! the actual data path. `Connect`/`Disconnect` from the client become `start`/`stop` calls
//! here. The real engine — which brings up the TUN, installs routes, and runs `spark-core` —
//! is privileged and wired in the live path (it needs root); the loop is written against this
//! trait so it can be unit-tested with a fake.

use async_trait::async_trait;

/// An error from bringing the tunnel up or down.
#[derive(Debug, thiserror::Error)]
#[error("tunnel engine error: {0}")]
pub struct EngineError(pub String);

/// Drives the actual tunnel data path on behalf of the control-plane event loop.
#[async_trait]
pub trait TunnelEngine: Send {
    /// Bring the tunnel up (open the device, install routes, start the core).
    async fn start(&mut self) -> Result<(), EngineError>;
    /// Tear the tunnel down and restore direct routing.
    async fn stop(&mut self) -> Result<(), EngineError>;
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// A fake engine that records whether the tunnel is "running" without touching the
    /// network. Lets the event loop be tested with no TUN and no root.
    #[derive(Clone, Default)]
    pub struct FakeEngine {
        pub running: Arc<AtomicBool>,
    }

    #[async_trait]
    impl TunnelEngine for FakeEngine {
        async fn start(&mut self) -> Result<(), EngineError> {
            self.running.store(true, Ordering::SeqCst);
            Ok(())
        }
        async fn stop(&mut self) -> Result<(), EngineError> {
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }
    }
}
