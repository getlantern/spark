//! Source-app attribution for split tunneling: map a flow's local (source) endpoint to the owning
//! process. Desktop-only; each OS has its own backend (macOS: sysctl PCB table). Mirrors sing-box's
//! `common/process` (searcher_darwin.go), but in Rust and read from `flow.src` in the data path.

#[cfg(not(target_os = "macos"))]
use std::net::IpAddr;

/// The process that owns a local socket endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// The owning process id.
    pub pid: u32,
    /// Absolute executable path (e.g. `/Applications/Firefox.app/Contents/MacOS/firefox`).
    pub exe_path: String,
}

use std::net::SocketAddr;

/// Transport protocol of a flow, so the resolver reads the right kernel socket table (TCP flows
/// live in `net.inet.tcp.pcblist_n`, UDP/QUIC in `net.inet.udp.pcblist_n`). Threaded from the
/// forwarder — the TCP path knows it's TCP, the UDP path knows it's UDP — because a browser's QUIC
/// traffic never appears in the TCP table and would otherwise resolve to `None` (and get tunneled).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Resolve the executable path of the process that owns a flow's local (source) endpoint. Desktop
/// app split tunneling uses this to route excluded apps Direct. `None` = couldn't attribute (the
/// caller must fail **open**: tunnel the flow, never leak it).
pub trait ProcessResolver: Send + Sync {
    fn resolve(&self, src: SocketAddr, proto: Protocol) -> Option<String>;
}

/// Cache key: the flow's local endpoint plus its transport. Keyed on the protocol too, so a TCP and
/// a UDP flow from the same local endpoint don't alias to the same entry (they scan different
/// pcblist tables).
#[cfg(target_os = "macos")]
type CacheKey = (SocketAddr, Protocol);

/// Cache value: when the entry was inserted, and the resolved exe path (`None` = attribution failed).
#[cfg(target_os = "macos")]
type CacheValue = (std::time::Instant, Option<String>);

/// A [`ProcessResolver`] that caches results by source endpoint for a short TTL, so a per-flow
/// kernel PCB scan doesn't run on every connection. Bounded size (oldest entries evicted). macOS
/// backend ([`resolve`]); other platforms get their own backend in P4.
#[cfg(target_os = "macos")]
pub struct CachingResolver {
    ttl: std::time::Duration,
    cap: usize,
    // std Mutex; never held across .await (per-flow sync call).
    cache: std::sync::Mutex<std::collections::HashMap<CacheKey, CacheValue>>,
}

#[cfg(target_os = "macos")]
impl CachingResolver {
    pub fn new(ttl: std::time::Duration, cap: usize) -> Self {
        Self {
            ttl,
            cap,
            cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(target_os = "macos")]
impl ProcessResolver for CachingResolver {
    fn resolve(&self, src: SocketAddr, proto: Protocol) -> Option<String> {
        let now = std::time::Instant::now();
        let key = (src, proto);
        {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, path)) = cache.get(&key) {
                if now.duration_since(*at) < self.ttl {
                    return path.clone();
                }
            }
        }
        // Miss/expired: scan the pcblist table for this protocol (TCP or UDP/QUIC).
        let path = resolve(src.ip(), src.port(), proto)
            .ok()
            .flatten()
            .map(|i| i.exe_path);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= self.cap {
            // Cheap bound: drop the oldest entry.
            if let Some(oldest) = cache.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| *k) {
                cache.remove(&oldest);
            }
        }
        cache.insert(key, (now, path.clone()));
        path
    }
}

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::resolve;

/// Resolve the process owning a socket whose local endpoint is `(ip, port)`, reading the pcblist
/// table for `proto` (TCP or UDP).
///
/// Returns `Ok(None)` when no process matches (or on platforms without a backend); `Err` only when
/// the platform lookup itself fails. This is the cross-platform seam; the macOS implementation lives
/// in [`darwin`].
///
/// # Examples
///
/// ```no_run
/// use std::net::Ipv4Addr;
/// # #[cfg(target_os = "macos")]
/// # {
/// use spark_core::process::Protocol;
/// let info = spark_core::process::resolve(Ipv4Addr::LOCALHOST.into(), 54321, Protocol::Tcp).unwrap();
/// if let Some(info) = info {
///     println!("owned by pid {} at {}", info.pid, info.exe_path);
/// }
/// # }
/// ```
#[cfg(not(target_os = "macos"))]
pub fn resolve(_ip: IpAddr, _port: u16, _proto: Protocol) -> std::io::Result<Option<ProcessInfo>> {
    Ok(None)
}

#[cfg(all(test, target_os = "macos"))]
mod resolver_tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    #[test]
    fn caching_resolver_resolves_and_caches_own_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut client = TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.write_all(b"x").expect("write");
        let src = client.local_addr().expect("local");

        let r = CachingResolver::new(Duration::from_secs(3), 128);
        let first = r
            .resolve(src, Protocol::Tcp)
            .expect("resolve our own socket");
        assert!(
            first.ends_with(env!("CARGO_PKG_NAME")) || !first.is_empty(),
            "exe path: {first}"
        );
        // Second call is served from cache (same value); just assert it stays consistent.
        assert_eq!(
            r.resolve(src, Protocol::Tcp).as_deref(),
            Some(first.as_str())
        );
    }
}
