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

use tun_rs::{AsyncDevice, DeviceBuilder};

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
    /// platform.
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

    /// The device MTU in bytes — the maximum packet size to size receive buffers to.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// The OS-assigned interface name.
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
