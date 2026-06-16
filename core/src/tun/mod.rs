//! Async TUN device abstraction over `tun-rs`.
//!
//! Wraps `tun_rs::AsyncDevice` behind a small surface (`recv`/`send` of raw IP
//! packets, plus `mtu`/`name`) so the rest of the core never imports `tun-rs`
//! directly. `tun-rs` normalizes platform quirks for us: on macOS `utun` the 4-byte
//! address-family prefix is stripped, so every platform hands us a raw L3 packet whose
//! first nibble is the IP version. The framed `Stream`/`Sink` bridge into the netstack
//! is added at M2; M1 uses the direct `recv`/`send` path.

use std::io;
use std::net::Ipv4Addr;

use tun_rs::AsyncDevice;
// On Android (`VpnService`) and Apple iOS (NetworkExtension) the OS creates the interface and
// hands us a fd; `tun-rs` exposes no `DeviceBuilder`/`name` on those targets, only the fd path
// (`from_fd`). So device *creation* is desktop-only (incl. macOS, where `spark run` opens one).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tun_rs::DeviceBuilder;

/// Errors from bringing up or naming the TUN device.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// The device could not be created or configured (commonly: not running as root,
    /// or the requested name/address is unavailable).
    #[error("failed to create TUN device (are you running with sufficient privileges?)")]
    Create(#[source] io::Error),
    /// Querying a device property (name, MTU) failed after creation.
    #[error("failed to query TUN device property")]
    Query(#[source] io::Error),
}

/// How to bring up the TUN device.
pub struct TunConfig {
    /// Optional device name request (e.g. `utun9` on macOS, `tun0` on Linux). The OS
    /// may assign a different name; consult [`Tun::name`] after opening.
    pub name: Option<String>,
    /// IPv4 address and prefix length to assign to the interface.
    pub ipv4: (Ipv4Addr, u8),
    /// Optional MTU override. When `None`, the device's default MTU is used.
    pub mtu: Option<u16>,
}

/// An open TUN device that reads and writes raw IP packets.
pub struct Tun {
    dev: AsyncDevice,
    mtu: usize,
}

impl Tun {
    /// Bring up a TUN device per `cfg`. Requires elevated privileges on every desktop
    /// platform. Not available on Android or iOS, where the OS creates the interface and the
    /// core adopts its fd via [`from_fd`](Self::from_fd) instead.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn open(cfg: TunConfig) -> Result<Self, TunError> {
        let mut builder = DeviceBuilder::new().ipv4(cfg.ipv4.0, cfg.ipv4.1, None);
        if let Some(name) = cfg.name {
            builder = builder.name(name);
        }
        if let Some(mtu) = cfg.mtu {
            builder = builder.mtu(mtu);
        }
        let dev = builder.build_async().map_err(TunError::Create)?;
        let mtu = dev.mtu().map_err(TunError::Query)? as usize;
        Ok(Self { dev, mtu })
    }

    /// Adopt an existing TUN file descriptor instead of creating a device. This is the mobile
    /// path: the OS owns the privilege to create the interface, so Android's
    /// `VpnService.establish()` (via `detachFd`) and Apple's `NEPacketTunnelFlow` hand the app a
    /// ready-configured fd, and the core only moves packets. Takes ownership of `fd` (closing it
    /// on drop). `mtu` is supplied by the caller — the same value it set on the platform side
    /// (e.g. `VpnService.Builder.setMtu`) — since the fd isn't a queryable named interface here.
    ///
    /// # Safety
    /// `fd` must be a valid, open TUN file descriptor owned by no one else; this takes ownership
    /// and will close it on drop. Passing an invalid or aliased fd is undefined behavior.
    #[cfg(unix)]
    pub unsafe fn from_fd(fd: std::os::fd::RawFd, mtu: u16) -> Result<Self, TunError> {
        // SAFETY: forwarded to the caller's contract above (valid, solely-owned TUN fd).
        let dev = unsafe { AsyncDevice::from_fd(fd) }.map_err(TunError::Create)?;
        Ok(Self {
            dev,
            mtu: mtu as usize,
        })
    }

    /// The device MTU in bytes — the maximum packet size to size receive buffers to.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// The OS-assigned interface name. Not available on Android/iOS (a from-fd device has no
    /// queryable name; the OS owns the interface).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn name(&self) -> Result<String, TunError> {
        self.dev.name().map_err(TunError::Query)
    }

    /// Read a single IP packet into `buf`, returning the number of bytes read.
    /// `&self` so the device can be shared across tasks once we split read/write later.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.recv(buf).await
    }

    /// Write a single IP packet, returning the number of bytes written.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.dev.send(buf).await
    }
}
