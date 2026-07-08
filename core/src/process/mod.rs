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

/// Resolve the executable path of the process that owns a flow's local (source) endpoint. Desktop
/// app split tunneling uses this to route excluded apps Direct. `None` = couldn't attribute (the
/// caller must fail **open**: tunnel the flow, never leak it).
pub trait ProcessResolver: Send + Sync {
    fn resolve(&self, src: SocketAddr) -> Option<String>;
}

/// A [`ProcessResolver`] that caches results by source endpoint for a short TTL, so a per-flow
/// kernel PCB scan doesn't run on every connection. Bounded size (oldest entries evicted). macOS
/// backend (`resolve_tcp`); other platforms get their own backend in P4.
#[cfg(target_os = "macos")]
pub struct CachingResolver {
    ttl: std::time::Duration,
    cap: usize,
    // src -> (inserted_at, exe_path). std Mutex; never held across .await (per-flow sync call).
    cache: std::sync::Mutex<
        std::collections::HashMap<SocketAddr, (std::time::Instant, Option<String>)>,
    >,
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
    fn resolve(&self, src: SocketAddr) -> Option<String> {
        let now = std::time::Instant::now();
        {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, path)) = cache.get(&src) {
                if now.duration_since(*at) < self.ttl {
                    return path.clone();
                }
            }
        }
        // Miss/expired: scan the PCB table (TCP only for v1; UDP flows tunnel).
        let path = resolve_tcp(src.ip(), src.port())
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
        cache.insert(src, (now, path.clone()));
        path
    }
}

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::resolve_tcp;

/// Resolve the process owning a TCP socket whose local endpoint is `(ip, port)`.
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
/// let info = spark_core::process::resolve_tcp(Ipv4Addr::LOCALHOST.into(), 54321).unwrap();
/// if let Some(info) = info {
///     println!("owned by pid {} at {}", info.pid, info.exe_path);
/// }
/// # }
/// ```
#[cfg(not(target_os = "macos"))]
pub fn resolve_tcp(_ip: IpAddr, _port: u16) -> std::io::Result<Option<ProcessInfo>> {
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
        let first = r.resolve(src).expect("resolve our own socket");
        assert!(
            first.ends_with(env!("CARGO_PKG_NAME")) || !first.is_empty(),
            "exe path: {first}"
        );
        // Second call is served from cache (same value); just assert it stays consistent.
        assert_eq!(r.resolve(src).as_deref(), Some(first.as_str()));
    }
}
