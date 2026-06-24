//! Socket protection — bind upstream sockets to a physical egress interface so their traffic
//! bypasses the tunnel's own route.
//!
//! A transparent TUN proxy forwards a flow by dialing its destination. If the OS route for
//! that destination points back into the TUN (which it must, to capture the app's traffic in
//! the first place), the proxy's own dial would re-enter the TUN and loop forever. On Linux
//! you can sidestep this per-socket with `SO_BINDTODEVICE`/the routing table; on macOS there
//! is no such per-socket route exemption, so the standard fix — used by every VPN — is to
//! pin the proxy's outbound sockets to the physical interface with `IP_BOUND_IF`
//! (`IP_UNICAST_IF` on Linux). [`SocketProtector`] applies that binding.
//!
//! (The Apple NetworkExtension path gets this from the OS automatically; the daemon path,
//! and `spark run`, need to do it explicitly — hence this module.)

use std::io;
use std::num::NonZeroU32;

/// Pins sockets to a chosen physical interface (by index) so their traffic bypasses the
/// tunnel route. Cheap to clone; share one per transport.
#[derive(Debug, Clone)]
pub struct SocketProtector {
    /// The interface name, kept for diagnostics (and read by the derived `Debug`).
    interface: String,
    /// The resolved interface index used by `bind_device_by_index_*`.
    index: NonZeroU32,
}

impl SocketProtector {
    /// Resolve an interface name (e.g. `"en0"`) to a protector. Errors if the interface is
    /// unknown or the platform cannot resolve it.
    pub fn for_interface(interface: &str) -> io::Result<Self> {
        Ok(Self {
            interface: interface.to_string(),
            index: interface_index(interface)?,
        })
    }

    /// The interface this protector binds to.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Bind `sock` to the protected interface. `ipv4` selects the address family (the option
    /// differs for v4 vs v6). A no-op on platforms without per-socket egress binding.
    pub fn protect(&self, sock: socket2::SockRef<'_>, ipv4: bool) -> io::Result<()> {
        bind_to_index(sock, self.index, ipv4)
    }
}

/// Best-effort discovery of the host's physical egress interface (e.g. `en0`), for pinning the
/// proxy's own sockets so they bypass our tunnel.
///
/// On macOS the NetworkExtension auto-bypasses the provider's **TCP** but **not** its **UDP/QUIC**
/// (confirmed on device: hysteria2's QUIC handshake hung while samizdat's TCP worked because the QUIC
/// socket wasn't pinned). So the lantern-api path must pin sockets to the physical interface
/// explicitly. Picks the first running, non-loopback, non-tunnel interface with an IPv4 address,
/// preferring `en*` (Wi-Fi/Ethernet). `None` → caller leaves sockets unpinned (prior behavior).
#[cfg(target_os = "macos")]
pub fn default_physical_interface() -> Option<String> {
    use std::ffi::CStr;
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` allocates the list; we read fields only while it's alive, copy the chosen
    // name out (owned `String`), and `freeifaddrs` before returning on every path.
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 || ifap.is_null() {
            return None;
        }
        let up_running = libc::IFF_UP as u32 | libc::IFF_RUNNING as u32;
        let mut fallback: Option<String> = None;
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
                continue;
            }
            // One entry per address family; key off the IPv4 one (pinning by name covers v6 too).
            if i32::from((*ifa.ifa_addr).sa_family) != libc::AF_INET {
                continue;
            }
            let flags = ifa.ifa_flags;
            if flags & up_running != up_running || flags & libc::IFF_LOOPBACK as u32 != 0 {
                continue;
            }
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            // Skip our own tunnel + other virtual interfaces.
            if ["utun", "tun", "tap", "ppp", "ipsec", "lo"]
                .iter()
                .any(|p| name.starts_with(p))
            {
                continue;
            }
            // Prefer a real Wi-Fi/Ethernet interface; take the first one found.
            if name.starts_with("en") {
                libc::freeifaddrs(ifap);
                return Some(name);
            }
            fallback.get_or_insert(name);
        }
        libc::freeifaddrs(ifap);
        fallback
    }
}

/// Non-macOS: no discovery (the daemon/`spark run` paths configure `protect_interface` explicitly,
/// and Android's `VpnService.protect` handles bypass).
#[cfg(not(target_os = "macos"))]
pub fn default_physical_interface() -> Option<String> {
    None
}

/// Resolve an interface name to its index via `if_nametoindex`.
#[cfg(unix)]
fn interface_index(interface: &str) -> io::Result<NonZeroU32> {
    let cname = std::ffi::CString::new(interface).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "interface name contains a NUL")
    })?;
    // SAFETY: `cname` is a valid NUL-terminated C string that outlives the call.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    NonZeroU32::new(index).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("unknown interface {interface:?}"),
        )
    })
}

#[cfg(not(unix))]
fn interface_index(_interface: &str) -> io::Result<NonZeroU32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket protection is not supported on this platform",
    ))
}

// `bind_device_by_index_*` (IP_BOUND_IF / IP_UNICAST_IF) is available on this OS set in
// socket2; elsewhere protection is a no-op.
#[cfg(any(
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "linux",
    target_os = "android",
))]
fn bind_to_index(sock: socket2::SockRef<'_>, index: NonZeroU32, ipv4: bool) -> io::Result<()> {
    if ipv4 {
        sock.bind_device_by_index_v4(Some(index))
    } else {
        sock.bind_device_by_index_v6(Some(index))
    }
}

#[cfg(not(any(
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "linux",
    target_os = "android",
)))]
fn bind_to_index(_sock: socket2::SockRef<'_>, _index: NonZeroU32, _ipv4: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_interface_errors() {
        let err = SocketProtector::for_interface("definitely-not-an-iface-xyz").unwrap_err();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::Unsupported
        ));
    }

    #[cfg(unix)]
    fn loopback_protector() -> SocketProtector {
        // `lo0` (macOS/BSD) or `lo` (Linux) — at least one exists on every unix host.
        SocketProtector::for_interface("lo0")
            .or_else(|_| SocketProtector::for_interface("lo"))
            .expect("a loopback interface should resolve")
    }

    #[cfg(unix)]
    #[test]
    fn loopback_interface_resolves() {
        assert!(!loopback_protector().interface().is_empty());
    }

    // Best-effort discovery never returns a loopback/tunnel interface, and what it returns must
    // resolve to a real index. (May be `None` on a headless CI host with no `en*` up — that's fine.)
    #[cfg(target_os = "macos")]
    #[test]
    fn physical_interface_is_real_and_not_virtual() {
        if let Some(name) = super::default_physical_interface() {
            assert!(!name.is_empty());
            for p in ["lo", "utun", "tun", "ppp", "ipsec"] {
                assert!(!name.starts_with(p), "picked a virtual interface: {name}");
            }
            SocketProtector::for_interface(&name).expect("discovered interface should resolve");
        }
    }

    // Confirms the IP_BOUND_IF / IP_UNICAST_IF setsockopt actually applies on this host
    // (no root required for the socket option). Only meaningful where socket2 supports it.
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn protect_binds_a_socket_without_error() {
        let protector = loopback_protector();
        let v4 = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        protector
            .protect(socket2::SockRef::from(&v4), true)
            .expect("binding a v4 socket to the interface should succeed");
        let v6 = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None).unwrap();
        protector
            .protect(socket2::SockRef::from(&v6), false)
            .expect("binding a v6 socket to the interface should succeed");
    }
}
