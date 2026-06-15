//! The tunnel engine the service event loop drives.
//!
//! [`TunnelEngine`] is the seam between the control-plane event loop ([`crate::service`]) and
//! the actual data path. `Connect`/`Disconnect` from the client become `start`/`stop` calls
//! here. The real engine — which brings up the TUN, installs routes, and runs `spark-core` —
//! is privileged and wired in the live path (it needs root); the loop is written against this
//! trait so it can be unit-tested with a fake.
//!
//! `start` is handed an `exit` sender it fires if the data path dies on its own (a netstack or
//! forwarder loop returned) — distinct from a deliberate `stop`. The event loop watches the
//! other end to fail open and alert (the kill-switch); see [`crate::service`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;

use spark_core::config::Config;
use spark_core::netstack::SmoltcpNetstack;
use spark_core::proxy;
use spark_core::transport;
use spark_core::tun::{Tun, TunConfig};

/// An error from bringing the tunnel up or down.
#[derive(Debug, thiserror::Error)]
#[error("tunnel engine error: {0}")]
pub struct EngineError(pub String);

/// Drives the actual tunnel data path on behalf of the control-plane event loop.
#[async_trait]
pub trait TunnelEngine: Send {
    /// Bring the tunnel up (open the device, install routes, start the core). `exit` is fired
    /// (one `()`) if the data path later dies on its own — NOT on a deliberate [`stop`](Self::stop),
    /// which aborts before the signal is sent.
    async fn start(&mut self, exit: mpsc::Sender<()>) -> Result<(), EngineError>;
    /// Tear the tunnel down and restore direct routing.
    async fn stop(&mut self) -> Result<(), EngineError>;
}

/// The production engine: opens the TUN, starts `spark-core`'s netstack + forwarders, and
/// tears them down on stop. This is the same data path the `spark run` CLI driver builds —
/// here it is owned by the privileged service and toggled by control-plane commands.
///
/// Opening the device requires elevated privilege, so `start` only succeeds when the service
/// runs privileged; the live gate exercises it under root. Route installation/restoration
/// (the active half of the fail-open kill-switch) is the remaining piece layered on top.
pub struct CoreEngine {
    config: Config,
    tun: Option<Arc<Tun>>,
    supervisor: Option<JoinHandle<()>>,
}

impl CoreEngine {
    /// Create an engine that brings tunnels up per `config`.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            tun: None,
            supervisor: None,
        }
    }
}

#[async_trait]
impl TunnelEngine for CoreEngine {
    async fn start(&mut self, exit: mpsc::Sender<()>) -> Result<(), EngineError> {
        if self.tun.is_some() {
            return Ok(()); // already running
        }
        let tun = Arc::new(
            Tun::open(TunConfig {
                name: self.config.tun.name.clone(),
                ipv4: (self.config.tun.addr, self.config.tun.prefix),
                mtu: self.config.tun.mtu,
            })
            .map_err(|e| EngineError(format!("opening TUN device: {e}")))?,
        );
        let device = tun.name().unwrap_or_else(|_| "?".to_string());
        let tunneled = self.config.transport.server.is_some();
        info!(device = %device, addr = %self.config.tun.addr, tunneled, "tunnel up");

        let (tcp_transport, udp_transport) = transport::from_config(&self.config)
            .map_err(|e| EngineError(format!("building transport: {e}")))?;

        let mut netstack = SmoltcpNetstack::new(Arc::clone(&tun))
            .map_err(|e| EngineError(format!("starting the netstack: {e}")))?;
        let udp_surface = netstack.take_udp();
        let idle = Duration::from_secs(self.config.udp.idle_timeout_secs);

        // One supervisor task runs the data-path loops. It signals `exit` only if a loop
        // returns on its own; `stop` aborts the task before that line is reached.
        let supervisor = tokio::spawn(async move {
            match udp_surface {
                Some((udp_inbound, udp_reply)) => {
                    tokio::select! {
                        _ = proxy::tcp::run(netstack, tcp_transport) => {}
                        _ = proxy::udp::run_udp(udp_inbound, udp_reply, udp_transport, idle) => {}
                    }
                }
                None => proxy::tcp::run(netstack, tcp_transport).await,
            }
            let _ = exit.send(()).await; // unexpected exit (not reached on abort)
        });

        self.supervisor = Some(supervisor);
        self.tun = Some(tun);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), EngineError> {
        if let Some(task) = self.supervisor.take() {
            task.abort();
        }
        // Dropping the last `Tun` reference tears the OS device down (and restores routing).
        if self.tun.take().is_some() {
            info!("tunnel down");
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A fake engine that records whether the tunnel is "running" without touching the
    /// network, and lets a test simulate an unexpected exit by firing [`Self::kill`].
    #[derive(Clone, Default)]
    pub struct FakeEngine {
        pub running: Arc<AtomicBool>,
        exit: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    }

    impl FakeEngine {
        /// Simulate the data path dying unexpectedly (fires the `exit` sender from `start`).
        pub async fn kill(&self) {
            let sender = self.exit.lock().unwrap().clone();
            if let Some(tx) = sender {
                let _ = tx.send(()).await;
            }
        }
    }

    #[async_trait]
    impl TunnelEngine for FakeEngine {
        async fn start(&mut self, exit: mpsc::Sender<()>) -> Result<(), EngineError> {
            self.running.store(true, Ordering::SeqCst);
            *self.exit.lock().unwrap() = Some(exit);
            Ok(())
        }
        async fn stop(&mut self) -> Result<(), EngineError> {
            self.running.store(false, Ordering::SeqCst);
            *self.exit.lock().unwrap() = None;
            Ok(())
        }
    }
}
