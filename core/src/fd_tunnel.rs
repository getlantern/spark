//! Run the tunnel data path on a TUN fd handed to us by the OS — the shared mobile/NE entry.
//!
//! Some platforms own the privilege to create the tunnel interface and hand the app a ready fd
//! instead of letting us open a device: **Android** via `VpnService.establish()`/`detachFd()`,
//! and **Apple** NetworkExtension (iOS + macOS) via the `utun` fd the Packet Tunnel Provider
//! resolves (KVC `socket.fileDescriptor`, with a public-symbol fd-scan fallback — the
//! WireGuard/sing-box/Mullvad/Proton/lantern technique).
//!
//! Either way the core adopts the fd with [`crate::tun::Tun::from_fd`] and runs the same
//! netstack and forwarder as `spark run`. The thin FFI shims live in `platforms/android` (JNI) and
//! `platforms/apple` (C ABI); both call [`run_tunnel`] / [`stop`]. Loop avoidance is the host's
//! job (Android `addDisallowedApplication`; on Apple the NE process's own dials egress the real
//! interface), so there's no per-socket protection here. Default config = direct forwarding.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{info, warn};

use crate::config::Config;
use crate::netstack::SmoltcpNetstack;
use crate::proxy;
use crate::transport;
use crate::tun::Tun;

/// Process-global stop signal: [`run_tunnel`] waits on it, [`stop`] fires it. The host lifecycle
/// is start → stop, and the waiter is registered before stop can fire (the tunnel is up), so
/// `notify_waiters` is sufficient.
fn shutdown() -> &'static Notify {
    static SHUTDOWN: OnceLock<Notify> = OnceLock::new();
    SHUTDOWN.get_or_init(Notify::new)
}

/// Run the tunnel on `fd` (owned) with `mtu`, blocking the calling thread on a private tokio
/// runtime until [`stop`] is called or the data path exits. Returns once torn down.
pub fn run_tunnel(fd: i32, mtu: u16) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        // SAFETY: `fd` is the TUN fd from the OS (Android `establish()`/`detachFd`, or the Apple
        // NE utun fd); the host side transfers ownership to native for the tunnel's lifetime.
        let tun = Arc::new(
            unsafe { Tun::from_fd(fd, mtu) }.map_err(|e| std::io::Error::other(e.to_string()))?,
        );

        let config = Config::default();
        let (tcp_transport, udp_transport) = transport::from_config(&config)?;
        let mut netstack = SmoltcpNetstack::new(Arc::clone(&tun))?;
        let idle = Duration::from_secs(config.udp.idle_timeout_secs);
        if let Some((udp_inbound, udp_reply)) = netstack.take_udp() {
            tokio::spawn(proxy::udp::run_udp(
                udp_inbound,
                udp_reply,
                udp_transport,
                idle,
            ));
        }

        info!(mtu, "spark tunnel up (fd mode)");
        tokio::select! {
            _ = proxy::tcp::run(netstack, tcp_transport) => warn!("netstack accept loop exited"),
            _ = shutdown().notified() => info!("stop requested; tearing the tunnel down"),
        }
        drop(tun);
        Ok(())
    })
}

/// Signal a running [`run_tunnel`] to stop (called from the host's teardown via FFI).
pub fn stop() {
    shutdown().notify_waiters();
}
