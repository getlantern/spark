//! Run the tunnel data path on a TUN fd handed to us by the OS — the shared mobile/NE entry.
//!
//! Some platforms own the privilege to create the tunnel interface and hand the app a ready fd
//! instead of letting us open a device: **Android** via `VpnService.establish()`/`detachFd()`,
//! and **Apple** NetworkExtension (iOS + macOS) via the `utun` fd the Packet Tunnel Provider
//! resolves (KVC `socket.fileDescriptor`, with a public-symbol fd-scan fallback — the
//! WireGuard/sing-box/Mullvad/Proton/lantern technique).
//!
//! Either way the core adopts the fd with [`crate::tun::Tun::from_fd`] and runs the same netstack
//! and forwarder as `spark run`. The thin FFI shims live in `platforms/android` (JNI) and
//! `platforms/apple` (C ABI); both marshal their platform's args into [`fd_config`] + [`run_fd`]
//! and call [`stop`] on teardown — so the `Result` → status-code convention and the config building
//! live here, once, not duplicated in each shim. Loop avoidance is the host's job (Android
//! `addDisallowedApplication`; on Apple the NE process's own dials egress the real interface), so
//! there's no per-socket protection here. Default config = direct forwarding.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{info, warn};

use crate::config::{Config, StackKind};
use crate::netstack;
use crate::proxy;
use crate::transport;
use crate::tun::Tun;

/// Process-global stop signal: [`run_tunnel_with_config`] waits on it, [`stop`] fires it. The host
/// lifecycle is start → stop, and the waiter is registered before stop can fire (the tunnel is up),
/// so `notify_waiters` is sufficient.
fn shutdown() -> &'static Notify {
    static SHUTDOWN: OnceLock<Notify> = OnceLock::new();
    SHUTDOWN.get_or_init(Notify::new)
}

/// Build the fd-path [`Config`] from the host primitives the platform shims share: direct
/// forwarding with the given tun `addr`/`prefix` and netstack selection. `system_stack` picks the
/// kernel-TCP stack (Android only — it requires the `system-stack` build feature and errors at
/// startup otherwise); `false` selects the cross-platform userspace stack. Loop avoidance stays the
/// host's job (see the module docs).
pub fn fd_config(addr: Ipv4Addr, prefix: u8, system_stack: bool) -> Config {
    let mut config = Config::default();
    config.tun.addr = addr;
    config.tun.prefix = prefix;
    config.tun.stack = if system_stack {
        StackKind::System
    } else {
        StackKind::Userspace
    };
    config
}

/// Shared FFI entry for the platform shims: run the tunnel on `fd` (owned) with `mtu` and `config`,
/// blocking until [`stop`], and return the C-style status both the JNI and C-ABI shims expose —
/// `0` on a clean stop, `-1` on error. This is the single home of the `Result` → status-code
/// convention; the shims differ only in how they marshal their platform's args into this call.
pub fn run_fd(fd: i32, mtu: u16, config: Config) -> i32 {
    match run_tunnel_with_config(fd, mtu, config) {
        Ok(()) => 0,
        Err(e) => {
            warn!(error = %e, "tunnel exited with error");
            -1
        }
    }
}

/// Run the tunnel on `fd` (owned) with `mtu` and an explicit [`Config`], blocking the calling
/// thread on a private tokio runtime until [`stop`] is called or the data path exits. The `Config`
/// selects the netstack (`config.tun.stack`) and supplies the tun address the **system** stack
/// binds its listener to (the userspace stack ignores it); `mtu` is applied to the adopted fd
/// (`config.tun.mtu` is unused on the fd path). Returns once torn down. The FFI shims go through
/// [`run_fd`] (which adds the shared status-code convention); call this directly from Rust.
pub fn run_tunnel_with_config(fd: i32, mtu: u16, config: Config) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        // SAFETY: `fd` is the TUN fd from the OS (Android `establish()`/`detachFd`, or the Apple
        // NE utun fd); the host side transfers ownership to native for the tunnel's lifetime.
        let tun = Arc::new(
            unsafe { Tun::from_fd(fd, mtu) }.map_err(|e| std::io::Error::other(e.to_string()))?,
        );

        let (tcp_transport, udp_transport) = transport::from_config(&config)?;
        let (stack, udp_surface) = netstack::build(Arc::clone(&tun), &config)?;
        let idle = Duration::from_secs(config.udp.idle_timeout_secs);
        if let Some((udp_inbound, udp_reply)) = udp_surface {
            tokio::spawn(proxy::udp::run_udp(
                udp_inbound,
                udp_reply,
                udp_transport,
                idle,
            ));
        }

        info!(mtu, "spark tunnel up (fd mode)");
        tokio::select! {
            _ = proxy::tcp::run(stack, tcp_transport) => warn!("netstack accept loop exited"),
            _ = shutdown().notified() => info!("stop requested; tearing the tunnel down"),
        }
        drop(tun);
        Ok(())
    })
}

/// Signal a running tunnel ([`run_fd`] / [`run_tunnel_with_config`]) to stop, called from the
/// host's teardown via FFI.
pub fn stop() {
    shutdown().notify_waiters();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_config_maps_primitives() {
        let c = fd_config(Ipv4Addr::new(10, 1, 2, 3), 30, false);
        assert_eq!(c.tun.addr, Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(c.tun.prefix, 30);
        assert_eq!(c.tun.stack, StackKind::Userspace);
        // system_stack = true selects the kernel-TCP stack (whether the build can serve it is a
        // feature concern checked at startup, not here).
        assert_eq!(
            fd_config(Ipv4Addr::UNSPECIFIED, 24, true).tun.stack,
            StackKind::System
        );
    }
}
