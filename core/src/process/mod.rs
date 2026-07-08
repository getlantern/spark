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
