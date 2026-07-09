//! macOS backend: `sysctl(net.inet.{tcp,udp}.pcblist_n)` → match local endpoint → `so_last_pid` →
//! `proc_pidpath`. Ported from sing-box `common/process/searcher_darwin.go`. The kernel returns a
//! packed list of per-socket blobs; each blob is a sequence of TLV-tagged sub-structs
//! (`xinpcb_n`, `xsocket_n`, `xsockbuf_n` ×2, `xsockstat_n`, and for TCP a `xtcpcb_n`). Rather than
//! hard-code the total blob stride (which is version-sensitive), we walk the sub-structs by their
//! self-described length (`xNN_len`, the first `u32` of each), keyed by the `xNN_kind` tag. This is
//! how the XNU userspace tooling (`netstat`) reads the same table and is robust across releases.
//!
//! The TCP and UDP tables share the same `xinpcb_n`/`xsocket_n` TLV layout — only the sysctl name
//! differs — so the parser below is protocol-agnostic; [`resolve`] just picks the table by
//! [`Protocol`]. This matters for split tunneling because browsers carry most traffic over QUIC
//! (UDP), which never appears in the TCP table.

use super::{ProcessInfo, Protocol};
use std::net::IpAddr;

// libc gives us sysctlbyname + proc_pidpath. `c_char` is `u8` on aarch64-apple-darwin.
use libc::{c_char, c_void, proc_pidpath};

/// TLV kind tags from `bsd/netinet/in_pcblist.c` (`get_pcblist_n`) / `bsd/kern/uipc_socket2.c`.
/// Each sub-struct in a socket blob begins with `{ u32 len; u32 kind; ... }`.
const XSO_SOCKET: u32 = 0x001;
const XSO_INPCB: u32 = 0x010;

/// `proc_pidpath` needs a buffer of `PROC_PIDPATHINFO_MAXSIZE`; libc exposes it as `c_int`.
const PROC_PIDPATHINFO_MAXSIZE: usize = libc::PROC_PIDPATHINFO_MAXSIZE as usize;

/// Read a native-endian `u32` from `buf` at `off`, or `None` if out of range.
fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let slice = buf.get(off..end)?;
    Some(u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// One parsed socket, reduced to what the matcher needs.
struct Pcb {
    lport_be: u16,
    vflag: u8,
    /// Local IPv4 (valid when `vflag & 0x1`).
    laddr4: [u8; 4],
    /// Local IPv6 (valid when `vflag & 0x2`).
    laddr6: [u8; 16],
    last_pid: u32,
}

/// Read the whole `net.inet.{tcp,udp}.pcblist_n` blob via the two-call size-then-read
/// `sysctlbyname`. The table is chosen by `proto`; both share the same TLV blob layout.
fn read_pcblist(proto: Protocol) -> std::io::Result<Vec<u8>> {
    let name: &[u8] = match proto {
        Protocol::Tcp => b"net.inet.tcp.pcblist_n\0",
        Protocol::Udp => b"net.inet.udp.pcblist_n\0",
    };

    // First call with a null buffer just fills in the required size.
    let mut needed: libc::size_t = 0;
    // SAFETY: `name` is NUL-terminated; passing null `oldp` with a valid `oldlenp` is the documented
    // size-query form of sysctlbyname; all other pointers are null/valid.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const c_char,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buf = vec![0u8; needed];
    // SAFETY: `buf` has `needed` bytes; `needed` is updated in place to the bytes actually written.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const c_char,
            buf.as_mut_ptr() as *mut c_void,
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(needed);
    Ok(buf)
}

/// Walk the packed pcblist blob, yielding one [`Pcb`] per socket. The blob begins with a 24-byte
/// `xinpgen` header; then socket blobs follow, each a run of TLV sub-structs terminated by the next
/// socket's `xinpcb_n` (kind `XSO_INPCB`). We assemble a `Pcb` from the `xinpcb_n` (ports/addrs/
/// vflag) and the `xsocket_n` (`so_last_pid`) of each socket.
fn parse_pcbs(buf: &[u8]) -> Vec<Pcb> {
    let mut out = Vec::new();
    let mut i = 24usize; // skip the leading xinpgen block

    let mut cur: Option<Pcb> = None;
    while i + 8 <= buf.len() {
        let len = match read_u32(buf, i) {
            Some(0) | None => break, // zero-length sub-struct → malformed; stop
            Some(l) => l as usize,
        };
        let kind = match read_u32(buf, i + 4) {
            Some(k) => k,
            None => break,
        };
        if len < 8 || i + len > buf.len() {
            break;
        }
        let item = &buf[i..i + len];

        match kind {
            XSO_INPCB => {
                // A new socket starts here; flush the previous one.
                if let Some(pcb) = cur.take() {
                    out.push(pcb);
                }
                // xinpcb_n layout (bsd/netinet/in_pcb.h, struct xinpcb_n), offsets empirically
                // verified on Darwin 25 (macOS 26) by dumping our own socket's bytes:
                //   0  u32 xi_len          (== 104 here)
                //   4  u32 xi_kind         (== XSO_INPCB)
                //   8  u64 xi_inpp         (kernel pointer)
                //   16 u16 inp_fport       (network byte order)
                //   18 u16 inp_lport       (network byte order)          <- OFF_LPORT
                //   20 u32 inp_flow
                //   ...
                //   44 u8  inp_vflag       (0x1 = IPv4, 0x2 = IPv6)       <- OFF_VFLAG
                //   ...
                //   48 inp_dependfaddr union (16 bytes; foreign IPv4 in last 4 @ 60)
                //   64 inp_dependladdr union (16 bytes; local IPv4 in last 4 @ 76)  <- OFF_LADDR6/4
                // These are validated by `resolves_our_own_tcp_socket`; adjust there if a future
                // macOS reshuffles the struct.
                let lport_be = item
                    .get(OFF_LPORT..OFF_LPORT + 2)
                    .map(|s| u16::from_ne_bytes([s[0], s[1]]))
                    .unwrap_or(0);
                let vflag = item.get(OFF_VFLAG).copied().unwrap_or(0);
                let mut laddr4 = [0u8; 4];
                let mut laddr6 = [0u8; 16];
                // inp_dependladdr is a 16-byte union: IPv6 fills all 16; IPv4 is its last 4 bytes.
                if let Some(s) = item.get(OFF_LADDR6..OFF_LADDR6 + 16) {
                    laddr6.copy_from_slice(s);
                    laddr4.copy_from_slice(&s[12..16]);
                }
                cur = Some(Pcb {
                    lport_be,
                    vflag,
                    laddr4,
                    laddr6,
                    last_pid: 0,
                });
            }
            XSO_SOCKET => {
                if let Some(pcb) = cur.as_mut() {
                    // xsocket_n: so_last_pid is a pid_t (i32) inside the struct; offset validated by
                    // the test.
                    pcb.last_pid = read_u32(item, OFF_SO_LAST_PID).unwrap_or(0);
                }
            }
            _ => {}
        }

        i += rup8(len);
    }
    if let Some(pcb) = cur.take() {
        out.push(pcb);
    }
    out
}

/// Round up to an 8-byte boundary (the kernel pads each sub-struct).
fn rup8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// Offset of `inp_lport` (u16, network byte order) within `xinpcb_n`.
const OFF_LPORT: usize = 18;

/// Offset of `inp_vflag` (u8; bit 0x1 = IPv4, 0x2 = IPv6) within `xinpcb_n`.
const OFF_VFLAG: usize = 44;

/// Offset of `inp_dependladdr` (local address union, 16 bytes) within `xinpcb_n`. For IPv6 all 16
/// bytes are the address; for IPv4 the address is the last 4 bytes (offset 76 overall).
const OFF_LADDR6: usize = 64;

/// Offset of `so_last_pid` (pid_t) within `xsocket_n`. Validated by the test.
const OFF_SO_LAST_PID: usize = 68;

/// Resolve the process owning the socket whose local endpoint is `(ip, port)`, reading the pcblist
/// table for `proto` (TCP or UDP/QUIC).
///
/// Returns `Ok(None)` if no PCB matches; `Err` only on a `sysctl` failure. The `ip` may be a
/// wildcard/loopback source as reported by [`std::net::TcpStream::local_addr`].
///
/// # Examples
///
/// ```no_run
/// use std::net::Ipv4Addr;
/// use spark_core::process::Protocol;
/// let owner = spark_core::process::resolve(Ipv4Addr::LOCALHOST.into(), 12345, Protocol::Tcp)?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn resolve(ip: IpAddr, port: u16, proto: Protocol) -> std::io::Result<Option<ProcessInfo>> {
    let buf = read_pcblist(proto)?;
    let target_lport_be = port.to_be();
    let is_ipv4 = ip.is_ipv4();

    // A UDP socket is frequently bound to the wildcard address (0.0.0.0 / ::) even while sending —
    // Chrome's QUIC sockets are — so `udp.pcblist_n` reports `inp_laddr` as unspecified while the
    // netstack surfaces the flow's *concrete* source IP. An exact-laddr match then misses the owner,
    // so QUIC never attributes to the app and app split tunneling silently skips it. Prefer an exact
    // laddr match, but fall back to a wildcard-bound socket on the same lport. UDP only: a wildcard
    // TCP laddr is a *listener*, not the outbound flow's owner, so matching it would misattribute.
    let mut wildcard_pid: Option<u32> = None;
    for pcb in parse_pcbs(&buf) {
        if pcb.lport_be != target_lport_be {
            continue;
        }
        let laddr = if is_ipv4 && pcb.vflag & 0x1 != 0 {
            IpAddr::from(pcb.laddr4)
        } else if !is_ipv4 && pcb.vflag & 0x2 != 0 {
            IpAddr::from(pcb.laddr6)
        } else {
            continue; // address family doesn't match the flow
        };
        if laddr == ip {
            let pid = pcb.last_pid;
            return Ok(exe_path(pid).map(|exe_path| ProcessInfo { pid, exe_path }));
        }
        if proto == Protocol::Udp && laddr.is_unspecified() {
            wildcard_pid.get_or_insert(pcb.last_pid); // first wildcard-bound socket on this lport
        }
    }
    if let Some(pid) = wildcard_pid {
        return Ok(exe_path(pid).map(|exe_path| ProcessInfo { pid, exe_path }));
    }
    Ok(None)
}

/// `proc_pidpath(pid)` → absolute executable path, or `None` on failure.
fn exe_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: `buf` is `PROC_PIDPATHINFO_MAXSIZE` bytes and we pass that exact capacity as the size.
    let n = unsafe {
        proc_pidpath(
            pid as i32,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    // `proc_pidpath` writes a NUL-terminated path and returns its length. Defensively cut at the
    // first NUL within the returned range (in case the count ever includes the terminator), then
    // decode lossily — macOS paths are effectively always UTF-8, but don't drop a valid path (which
    // `String::from_utf8` would) on the off chance one isn't, since it feeds later path matching.
    let len = n as usize;
    let end = buf[..len].iter().position(|&b| b == 0).unwrap_or(len);
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    // Open a real loopback TCP connection, take the CLIENT socket's local endpoint, and assert the
    // resolver maps it back to THIS test process (pid + an exe path ending in the test binary).
    #[test]
    fn resolves_our_own_tcp_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut client = TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");
        // Keep both ends alive + established while we scan the PCB table.
        client.write_all(b"x").expect("write");
        let local = client.local_addr().expect("local");

        let info = resolve(local.ip(), local.port(), Protocol::Tcp)
            .expect("sysctl/parse ok")
            .expect("our socket is in the PCB table");
        assert_eq!(info.pid, std::process::id(), "must resolve to this process");
        assert!(
            !info.exe_path.is_empty(),
            "exe path must be non-empty, got {:?}",
            info.exe_path
        );
        let _ = server.write(b"y");
        drop(server);
    }

    // Bind a UDP socket and `connect` it to a peer so it has a concrete local endpoint, then assert
    // the UDP-table resolver (`net.inet.udp.pcblist_n`) maps that endpoint back to THIS process —
    // the QUIC/UDP path that the TCP-only resolver missed. The same TLV parser reads both tables.
    #[test]
    fn resolves_our_own_udp_socket() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        // A peer to connect to, so the kernel pins a local endpoint we can look up.
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer addr");
        sock.connect(peer_addr).expect("connect");
        // Send one datagram: on some stacks a UDP PCB isn't reliably present in `udp.pcblist_n`
        // until the socket has actually transmitted, so this avoids a flaky lookup. Assert the send
        // succeeds — a silent failure here would surface later as a confusing "not in PCB table".
        sock.send(b"x")
            .expect("send datagram to force a UDP PCB entry");
        let local = sock.local_addr().expect("local");

        let info = resolve(local.ip(), local.port(), Protocol::Udp)
            .expect("sysctl/parse ok")
            .expect("our udp socket is in the UDP PCB table");
        assert_eq!(info.pid, std::process::id(), "must resolve to this process");
        assert!(
            !info.exe_path.is_empty(),
            "exe path must be non-empty, got {:?}",
            info.exe_path
        );
    }

    // A UDP socket bound to the wildcard address (0.0.0.0) — as Chrome's QUIC sockets are — keeps
    // `inp_laddr = 0.0.0.0` in `udp.pcblist_n` even while sending. The netstack surfaces the flow's
    // *concrete* source IP, so an exact-laddr match misses it; the resolver must fall back to the
    // wildcard-bound socket on the same lport. Without that fallback, Chrome's QUIC never attributes
    // to the app and app split tunneling silently misses it (regression this guards).
    #[test]
    fn resolves_wildcard_bound_udp_socket_by_concrete_ip() {
        // Bind to the wildcard so `inp_laddr` stays 0.0.0.0 (unconnected → the kernel doesn't pin a
        // local address the way `connect` does).
        let sock = UdpSocket::bind("0.0.0.0:0").expect("bind wildcard");
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer addr");
        // Transmit (unconnected) to force a PCB entry, without pinning a concrete local address.
        sock.send_to(b"x", peer_addr)
            .expect("send_to to force a UDP PCB entry");
        let port = sock.local_addr().expect("local").port();

        // Query by a CONCRETE source IP (what the netstack surfaces for a real flow) + the socket's
        // port. Exact-laddr matching would fail (0.0.0.0 != 127.0.0.1); the wildcard fallback wins.
        let info = resolve("127.0.0.1".parse().unwrap(), port, Protocol::Udp)
            .expect("sysctl/parse ok")
            .expect("a wildcard-bound udp socket must resolve by concrete src IP");
        assert_eq!(info.pid, std::process::id(), "must resolve to this process");
    }
}
