//! Android entry: run the tunnel data path on a TUN fd handed to us by `VpnService`.
//!
//! On Android the OS owns interface creation: `VpnService.establish()` returns a fd (via
//! `detachFd`) and the app passes it here. We adopt it with [`crate::tun::Tun::from_fd`] and run
//! the same netstack + forwarder as `spark run`. There is no privileged-daemon split (the
//! `VpnService` runs in-process, same uid), so no `service`/`ipc` here — just the data path.
//!
//! Loop avoidance is the `VpnService`'s job: it calls `addDisallowedApplication(<self>)` so the
//! app's own sockets (this proxy's upstream dials) bypass the tunnel — the Android analog of the
//! desktop [`crate::net::SocketProtector`]. So we run on the default config (direct forwarding)
//! with no per-socket protection here.
//!
//! The thin `#[no_mangle]` JNI symbols live in the `platforms/android` cdylib, which calls
//! [`run_tunnel`] / [`stop`]. Built for Android only (`#[cfg(target_os = "android")]`).

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

/// Process-global stop signal: [`run_tunnel`] waits on it, [`stop`] fires it. The `VpnService`
/// lifecycle is start → stop, and the waiter is registered before stop can fire (the tunnel is
/// up), so `notify_waiters` is sufficient.
fn shutdown() -> &'static Notify {
    static SHUTDOWN: OnceLock<Notify> = OnceLock::new();
    SHUTDOWN.get_or_init(Notify::new)
}

/// Run the tunnel on `fd` (owned) with `mtu`, blocking the calling (JNI) thread on a private
/// tokio runtime until [`stop`] is called or the data path exits. Returns once torn down.
pub fn run_tunnel(fd: i32, mtu: u16) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        // SAFETY: `fd` is the TUN fd from `VpnService.establish()`; the JVM side transfers
        // ownership to native for the tunnel's lifetime (Kotlin uses `detachFd`).
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

        info!(mtu, "spark android tunnel up");
        tokio::select! {
            _ = proxy::tcp::run(netstack, tcp_transport) => warn!("netstack accept loop exited"),
            _ = shutdown().notified() => info!("stop requested; tearing the tunnel down"),
        }
        drop(tun);
        Ok(())
    })
}

/// Signal a running [`run_tunnel`] to stop (called from `VpnService.onDestroy` via JNI).
pub fn stop() {
    shutdown().notify_waiters();
}
