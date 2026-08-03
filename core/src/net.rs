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

/// A cheap identifier for "the network this host is currently attached to", for caches whose entries
/// are only valid on one network — the proxyless transport's chosen strategy above all. (Not an
/// intra-doc link: that module is behind the `proxyless` feature while this one is always compiled.)
///
/// It is the **source address the kernel would pick for off-link traffic**, one per family. Obtained
/// by `connect`ing an unbound UDP socket to a reserved destination and reading back the local address:
/// UDP `connect` transmits nothing, it only runs route lookup and source selection, so this costs a
/// few syscalls and touches no network. The destinations are documentation prefixes (RFC 5737 /
/// RFC 3849) precisely so that nothing is reachable there even in principle.
///
/// `None` means "cannot tell" — no route, or no usable socket. Callers should treat that as *no
/// information* rather than as a changed network, or an offline moment would invalidate a perfectly
/// good cache entry.
///
/// # What it does and does not distinguish
///
/// Switching Wi-Fi networks, moving between Wi-Fi and cellular, or gaining/losing IPv6 all change this
/// string. Two different networks that both hand out the same DHCP address (`192.168.1.x` is not rare)
/// collide, and the caller keeps a stale entry — no worse than having no fingerprint at all, which is
/// the alternative. A DHCP renewal onto a different address on the *same* network looks like a change
/// and costs one unnecessary re-selection. Both failure modes are bounded and one-sided.
///
/// Pass the `protector` a caller uses for its real dials. Under a full tunnel the default route points
/// into the TUN, so an unprotected probe reports the TUN's address — constant across networks, which
/// silently disables change detection rather than breaking it.
pub fn egress_fingerprint(protector: Option<&SocketProtector>) -> Option<String> {
    // Reserved-for-documentation destinations: route lookup succeeds via the default route, and the
    // address is guaranteed not to belong to anyone. Port is arbitrary (discard).
    const PROBE_V4: &str = "192.0.2.1:9";
    const PROBE_V6: &str = "[2001:db8::1]:9";

    let v4 = egress_source_addr(PROBE_V4, true, protector);
    let v6 = egress_source_addr(PROBE_V6, false, protector);
    if v4.is_none() && v6.is_none() {
        return None;
    }
    // Both families in one key: a network offering IPv6 is not the same network as one that does not,
    // even when the v4 address happens to match.
    Some(format!(
        "v4={} v6={}",
        v4.as_deref().unwrap_or("-"),
        v6.as_deref().unwrap_or("-")
    ))
}

/// The local address the kernel selects for `dst`, or `None` if it cannot route there.
fn egress_source_addr(
    dst: &str,
    ipv4: bool,
    protector: Option<&SocketProtector>,
) -> Option<String> {
    use socket2::{Domain, Protocol, SockRef, Socket, Type};

    let dst: std::net::SocketAddr = dst.parse().ok()?;
    let domain = if ipv4 { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    // Bind to the physical interface first, so under a full tunnel the route lookup below resolves
    // against the real egress rather than our own TUN.
    if let Some(p) = protector {
        p.protect(SockRef::from(&sock), ipv4).ok()?;
    }
    sock.connect(&dst.into()).ok()?;
    Some(sock.local_addr().ok()?.as_socket()?.ip().to_string())
}

/// The interface that holds `addr`, by name. Used to bind the system stack's redirect listener to
/// the TUN itself.
///
/// Linux/Android only, because that is where it is needed and where `SO_BINDTODEVICE` exists. On
/// Android the TUN comes from `VpnService` as a bare fd with no queryable name, so the only way to
/// identify it is to find whichever interface carries the address we were told to use.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn interface_name_for_addr(addr: std::net::IpAddr) -> Option<String> {
    use getifaddrs::Address;
    getifaddrs::getifaddrs()
        .ok()?
        .find(|i| match (&i.address, addr) {
            (Address::V4(a), std::net::IpAddr::V4(want)) => a.address == want,
            (Address::V6(a), std::net::IpAddr::V6(want)) => a.address == want,
            _ => false,
        })
        .map(|i| i.name)
}

/// Bind `sock` to `interface` for **both** directions (`SO_BINDTODEVICE`).
///
/// Deliberately not [`SocketProtector::protect`], which uses `IP_UNICAST_IF` and only steers
/// *outbound* packets. A listener needs the socket associated with the device so that packets
/// *arriving* on it match — the distinction that matters for the system stack's redirect, where the
/// whole point is receiving traffic the pump injected into the TUN.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind_socket_to_device(sock: socket2::SockRef<'_>, interface: &str) -> io::Result<()> {
    sock.bind_device(Some(interface.as_bytes()))
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

/// Windows: pick the physical egress interface to pin the proxy's own sockets to (loop-prevention).
/// First up+running, non-loopback interface with an IPv4 address and a usable index, skipping our
/// own tun and other virtual adapters by name. `None` → caller leaves sockets unpinned.
#[cfg(target_os = "windows")]
pub fn default_physical_interface() -> Option<String> {
    for iface in getifaddrs::getifaddrs().ok()? {
        // One entry per address family; key off IPv4 (pinning by index covers v6 too).
        if !iface.address.is_ipv4() {
            continue;
        }
        let flags = iface.flags;
        if !flags.contains(getifaddrs::InterfaceFlags::UP)
            || !flags.contains(getifaddrs::InterfaceFlags::RUNNING)
            || flags.contains(getifaddrs::InterfaceFlags::LOOPBACK)
        {
            continue;
        }
        if iface.index.and_then(NonZeroU32::new).is_none() {
            continue; // unusable for IP_UNICAST_IF
        }
        let lname = iface.name.to_ascii_lowercase();
        // Skip our own tunnel + common virtual adapters (WinTun/TAP/loopback/transition tech).
        if [
            "wintun", "tun", "tap", "loopback", "isatap", "teredo", "pseudo",
        ]
        .iter()
        .any(|p| lname.contains(p))
        {
            continue;
        }
        return Some(iface.name);
    }
    None
}

/// Other non-macOS platforms: no discovery (the daemon/`spark run` paths configure
/// `protect_interface` explicitly, and Android's `VpnService.protect` handles bypass).
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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

/// Resolve an interface name to its index by matching the `getifaddrs` enumeration. Uses the same
/// source as [`default_physical_interface`], so a name that discovery returned always resolves here
/// (no `if_nametoindex` round-trip to worry about).
#[cfg(target_os = "windows")]
fn interface_index(interface: &str) -> io::Result<NonZeroU32> {
    for iface in getifaddrs::getifaddrs()? {
        if iface.name == interface {
            if let Some(idx) = iface.index.and_then(NonZeroU32::new) {
                return Ok(idx);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("unknown or index-less interface {interface:?}"),
    ))
}

#[cfg(not(any(unix, target_os = "windows")))]
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

// Windows: socket2 0.6 has no `bind_device_by_index` here, so pin via a raw setsockopt.
// IP_UNICAST_IF (v4) wants the index in network byte order; IPV6_UNICAST_IF (v6) in host order.
#[cfg(target_os = "windows")]
fn bind_to_index(sock: socket2::SockRef<'_>, index: NonZeroU32, ipv4: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF,
        SOCKET,
    };

    let s = sock.as_raw_socket() as SOCKET;
    let (level, optname, arg) = if ipv4 {
        (
            IPPROTO_IP,
            IP_UNICAST_IF,
            ipv4_unicast_if_index(index.get()),
        )
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index.get())
    };
    // SAFETY: `s` is a live socket for the lifetime of `sock` (a borrowed SockRef); `&arg` is a
    // 4-byte DWORD matching the documented optlen for these options; setsockopt copies it and does
    // not retain the pointer.
    let rc = unsafe {
        setsockopt(
            s,
            level,
            optname,
            &arg as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        // WinSock sets the error via WSASetLastError, so read it with WSAGetLastError (not
        // GetLastError, which io::Error::last_os_error() would use) for an accurate code.
        // SAFETY: a plain FFI getter with no arguments and no pointers.
        let code = unsafe { WSAGetLastError() };
        return Err(io::Error::from_raw_os_error(code));
    }
    Ok(())
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
    target_os = "windows",
)))]
fn bind_to_index(_sock: socket2::SockRef<'_>, _index: NonZeroU32, _ipv4: bool) -> io::Result<()> {
    Ok(())
}

/// The value to pass as the `IP_UNICAST_IF` option for `index`. IPv4's `IP_UNICAST_IF` expects the
/// interface index as a `DWORD` in **network byte order** (big-endian) — unlike `IPV6_UNICAST_IF`,
/// which uses host order. Isolated as a pure fn so the byte-order contract is unit-tested on the
/// host even though the `setsockopt` call only compiles for Windows.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn ipv4_unicast_if_index(index: u32) -> u32 {
    index.to_be()
}

#[cfg(test)]
mod tests {
    use super::*;

    // IP_UNICAST_IF (IPv4) takes the interface index as a DWORD in NETWORK byte order, unlike
    // IPV6_UNICAST_IF (host order). The 4 bytes handed to setsockopt must be big-endian regardless
    // of host endianness: index 5 -> [0, 0, 0, 5].
    #[test]
    fn ipv4_unicast_if_index_is_network_order() {
        assert_eq!(ipv4_unicast_if_index(5).to_ne_bytes(), [0, 0, 0, 5]);
        assert_eq!(ipv4_unicast_if_index(1).to_ne_bytes(), [0, 0, 0, 1]);
        assert_eq!(
            ipv4_unicast_if_index(0x0102_0304).to_ne_bytes(),
            [1, 2, 3, 4]
        );
    }

    #[test]
    fn unknown_interface_errors() {
        let err = SocketProtector::for_interface("definitely-not-an-iface-xyz").unwrap_err();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::Unsupported
        ));
    }

    #[test]
    fn the_egress_fingerprint_is_stable_across_calls() {
        // The property the strategy cache depends on: two calls with the network unchanged must agree,
        // or every dial would look like a network change and re-run a verified search. Deliberately not
        // asserting a value — that would hardcode whatever this host is attached to, and would fail in
        // a network-less CI container for a reason unrelated to the code.
        assert_eq!(egress_fingerprint(None), egress_fingerprint(None));
    }

    #[test]
    fn the_fingerprint_names_both_families_when_it_reports_anything() {
        // `None` (no route at all) is legitimate — a sandboxed runner has no egress — but a `Some` must
        // be well-formed, because it is used as a cache key and a mangled one would silently partition
        // the cache.
        if let Some(fp) = egress_fingerprint(None) {
            assert!(fp.starts_with("v4="), "{fp}");
            assert!(fp.contains(" v6="), "{fp}");
            assert!(
                fp != "v4=- v6=-",
                "an all-absent fingerprint should have been None, not a key: {fp}"
            );
        }
    }

    #[test]
    fn the_probe_sends_nothing_and_needs_no_reachable_peer() {
        // The destinations are RFC 5737 / RFC 3849 documentation prefixes that route nowhere. If this
        // ever blocked or errored on unreachability, the fingerprint would be unusable on exactly the
        // restricted networks that matter most — so pin that a probe to one returns promptly either
        // way. (UDP connect only does route lookup; it transmits nothing.)
        let started = std::time::Instant::now();
        let _ = egress_source_addr("192.0.2.1:9", true, None);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "route lookup must not wait on the network"
        );
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
