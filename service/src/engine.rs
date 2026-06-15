//! The tunnel engine the service event loop drives.
//!
//! [`TunnelEngine`] is the seam between the control-plane event loop ([`crate::service`]) and
//! the actual data path. `Connect`/`Disconnect` from the client become `start`/`stop` calls
//! here. The real engine — which brings up the TUN, installs routes, and runs `spark-core` —
//! is privileged and wired in the live path (it needs root); the loop is written against this
//! trait so it can be unit-tested with a fake.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::task::JoinHandle;

use spark_core::config::Config;
use spark_core::netstack::SmoltcpNetstack;
use spark_core::proxy;
use spark_core::transport::tcp_tunnel::client::TunnelClient;
use spark_core::transport::{DirectTransport, Transport, UdpTransport};
use spark_core::tun::{Tun, TunConfig};

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

/// The production engine: opens the TUN, starts `spark-core`'s netstack + forwarders, and
/// tears them down on stop. This is the same data path the `spark run` CLI driver builds —
/// here it is owned by the privileged service and toggled by control-plane commands.
///
/// Opening the device requires elevated privilege, so `start` only succeeds when the service
/// runs privileged; the live gate exercises it under root. Route installation/restoration
/// (the fail-open kill-switch) is the remaining piece layered on top.
pub struct CoreEngine {
    config: Config,
    tun: Option<Arc<Tun>>,
    tasks: Vec<JoinHandle<()>>,
}

impl CoreEngine {
    /// Create an engine that brings tunnels up per `config`.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            tun: None,
            tasks: Vec::new(),
        }
    }
}

#[async_trait]
impl TunnelEngine for CoreEngine {
    async fn start(&mut self) -> Result<(), EngineError> {
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

        let (tcp_transport, udp_transport): (Arc<dyn Transport>, Arc<dyn UdpTransport>) =
            match self.config.transport.server {
                Some(server) => {
                    let client = Arc::new(TunnelClient::new(server));
                    let tcp: Arc<dyn Transport> = client.clone();
                    let udp: Arc<dyn UdpTransport> = client;
                    (tcp, udp)
                }
                None => {
                    let direct = Arc::new(DirectTransport);
                    let tcp: Arc<dyn Transport> = direct.clone();
                    let udp: Arc<dyn UdpTransport> = direct;
                    (tcp, udp)
                }
            };

        let mut netstack = SmoltcpNetstack::new(Arc::clone(&tun))
            .map_err(|e| EngineError(format!("starting the netstack: {e}")))?;

        let idle = Duration::from_secs(self.config.udp.idle_timeout_secs);
        if let Some((udp_inbound, udp_reply)) = netstack.take_udp() {
            self.tasks.push(tokio::spawn(proxy::udp::run_udp(
                udp_inbound,
                udp_reply,
                udp_transport,
                idle,
            )));
        }
        self.tasks
            .push(tokio::spawn(proxy::tcp::run(netstack, tcp_transport)));
        self.tun = Some(tun);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), EngineError> {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        // Dropping the last `Tun` reference tears the OS device down (and restores routing).
        self.tun = None;
        Ok(())
    }
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
