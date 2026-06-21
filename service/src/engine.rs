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
use spark_core::metrics::{Metrics, MetricsSnapshot};
use spark_core::netstack;
use spark_core::proxy;
use spark_core::routing::RouteManager;
use spark_core::transport;
use spark_core::tun::{Tun, TunConfig};

/// An error from bringing the tunnel up or down.
#[derive(Debug, thiserror::Error)]
#[error("tunnel engine error: {0}")]
pub struct EngineError(pub String);

/// How to leave routing when tearing the tunnel down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Teardown {
    /// Restore direct routing — a normal disconnect, or the fail-open kill-switch.
    RestoreDirect,
    /// Blackhole traffic instead of restoring direct routing — the fail-closed kill-switch.
    Block,
}

/// Drives the actual tunnel data path on behalf of the control-plane event loop.
#[async_trait]
pub trait TunnelEngine: Send {
    /// Bring the tunnel up (open the device, install routes, start the core). `exit` is fired
    /// (one `()`) if the data path later dies on its own — NOT on a deliberate [`stop`](Self::stop),
    /// which aborts before the signal is sent.
    async fn start(&mut self, config: Config, exit: mpsc::Sender<()>) -> Result<(), EngineError>;
    /// Tear the tunnel down, leaving the routing end-state requested by `teardown`.
    async fn stop(&mut self, teardown: Teardown) -> Result<(), EngineError>;
    /// A snapshot of the data-path counters (ADR 0004 slice 2). Cheap atomic reads; cumulative over
    /// the engine's lifetime, with `sessions_active` reflecting currently-open flows.
    fn metrics(&self) -> MetricsSnapshot;
}

/// The production engine: opens the TUN, starts `spark-core`'s netstack + forwarders, and
/// tears them down on stop. This is the same data path the `spark run` CLI driver builds —
/// here it is owned by the privileged service and toggled by control-plane commands.
///
/// Opening the device requires elevated privilege, so `start` only succeeds when the service
/// runs privileged; the live gate exercises it under root. Full-tunnel route management (the
/// active half of the kill-switch) is opt-in via `[routing] manage`; the live route commands
/// themselves are unit-tested but not yet exercised under root.
/// The config is supplied per [`start`](TunnelEngine::start) (the resolved active profile, or the
/// launch config), not stored — so a reconnect can use a different profile without rebuilding the
/// engine.
#[derive(Default)]
pub struct CoreEngine {
    tun: Option<Arc<Tun>>,
    supervisor: Option<JoinHandle<()>>,
    /// Present only while connected with `[routing] manage` on — owns the installed routes.
    routes: Option<RouteManager>,
    /// Data-path counters, shared into the forwarder; persists across connect/disconnect so totals
    /// are cumulative for the engine's lifetime.
    metrics: Arc<Metrics>,
}

impl CoreEngine {
    /// Create an idle engine; the per-connect config is passed to [`start`](TunnelEngine::start).
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TunnelEngine for CoreEngine {
    async fn start(
        &mut self,
        mut config: Config,
        exit: mpsc::Sender<()>,
    ) -> Result<(), EngineError> {
        if self.tun.is_some() {
            return Ok(()); // already running
        }
        spark_core::resolve_bootstrap(&mut config)
            .await
            .map_err(|e| EngineError(format!("resolving bootstrap endpoints: {e}")))?;
        let tun = Arc::new(
            Tun::open(TunConfig {
                name: config.tun.name.clone(),
                ipv4: (config.tun.addr, config.tun.prefix),
                mtu: config.tun.mtu,
            })
            .map_err(|e| EngineError(format!("opening TUN device: {e}")))?,
        );
        let device = tun.name().unwrap_or_else(|_| "?".to_string());
        let tunneled = config.transport.server.is_some();
        info!(device = %device, addr = %config.tun.addr, tunneled, "tunnel up");

        let (tcp_transport, udp_transport) = transport::from_config(&config)
            .map_err(|e| EngineError(format!("building transport: {e}")))?;

        let (stack, udp_surface) = netstack::build(Arc::clone(&tun), &config)
            .map_err(|e| EngineError(format!("starting the netstack: {e}")))?;
        let idle = Duration::from_secs(config.udp.idle_timeout_secs);

        // One supervisor task runs the data-path loops. It signals `exit` only if a loop
        // returns on its own; `stop` aborts the task before that line is reached.
        let metrics = Arc::clone(&self.metrics); // shared with the TCP forwarder for counters
        let supervisor = tokio::spawn(async move {
            match udp_surface {
                Some((udp_inbound, udp_reply)) => {
                    tokio::select! {
                        _ = proxy::tcp::run(stack, tcp_transport, metrics) => {}
                        _ = proxy::udp::run_udp(udp_inbound, udp_reply, udp_transport, idle) => {}
                    }
                }
                None => proxy::tcp::run(stack, tcp_transport, metrics).await,
            }
            let _ = exit.send(()).await; // unexpected exit (not reached on abort)
        });

        self.supervisor = Some(supervisor);
        self.tun = Some(tun);

        // Take over the routing table only when asked (full-tunnel); otherwise the operator
        // routes traffic in. Keep the manager even if install fails so `stop` can clear any
        // partial state.
        if config.routing.manage {
            let mut routes = RouteManager::new(&device);
            let outcome = routes.install().await;
            self.routes = Some(routes);
            if let Err(e) = outcome {
                let _ = self.stop(Teardown::RestoreDirect).await;
                return Err(EngineError(format!("installing routes: {e}")));
            }
        }
        Ok(())
    }

    async fn stop(&mut self, teardown: Teardown) -> Result<(), EngineError> {
        if let Some(task) = self.supervisor.take() {
            task.abort();
        }
        // Drop the TUN first: the OS removes the device (and the routes through it), so the
        // split-default covers fall away even before we touch the table.
        if self.tun.take().is_some() {
            info!("tunnel down");
        }
        // Then settle the routing end-state. The ops clear stale covers first, so they're
        // correct regardless of whether the device teardown already removed them.
        if let Some(mut routes) = self.routes.take() {
            let result = match teardown {
                Teardown::RestoreDirect => routes.restore().await,
                Teardown::Block => routes.block().await,
            };
            result.map_err(|e| EngineError(format!("tearing down routes: {e}")))?;
        }
        Ok(())
    }

    fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A fake engine that records whether the tunnel is "running" (and how it was last torn
    /// down) without touching the network, and lets a test simulate an unexpected exit by
    /// firing [`Self::kill`].
    #[derive(Clone, Default)]
    pub struct FakeEngine {
        pub running: Arc<AtomicBool>,
        last_teardown: Arc<Mutex<Option<Teardown>>>,
        last_config: Arc<Mutex<Option<Config>>>,
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

        /// The teardown mode of the most recent `stop` (the kill-switch routing decision).
        pub fn last_teardown(&self) -> Option<Teardown> {
            *self.last_teardown.lock().unwrap()
        }

        /// The config the most recent `start` was given (to assert connect-by-active-profile).
        pub fn last_config(&self) -> Option<Config> {
            self.last_config.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TunnelEngine for FakeEngine {
        async fn start(
            &mut self,
            config: Config,
            exit: mpsc::Sender<()>,
        ) -> Result<(), EngineError> {
            self.running.store(true, Ordering::SeqCst);
            *self.last_config.lock().unwrap() = Some(config);
            *self.exit.lock().unwrap() = Some(exit);
            Ok(())
        }
        async fn stop(&mut self, teardown: Teardown) -> Result<(), EngineError> {
            self.running.store(false, Ordering::SeqCst);
            *self.last_teardown.lock().unwrap() = Some(teardown);
            *self.exit.lock().unwrap() = None;
            Ok(())
        }
        fn metrics(&self) -> MetricsSnapshot {
            MetricsSnapshot::default()
        }
    }
}
