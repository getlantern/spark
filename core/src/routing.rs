//! Full-tunnel route management — point the default route at the TUN, and tear it back down.
//!
//! **Opt-in** (`[routing] manage`); when off, routing is left to the operator (the current
//! dev-gate workflow). When on, [`RouteManager`] uses the *split-default* trick: instead of
//! editing the existing `0.0.0.0/0` default, it installs two more-specific covering routes,
//! `0.0.0.0/1` and `128.0.0.0/1`, via the TUN. Each is a longer prefix than the default, so
//! they win for all traffic while the real default sits untouched underneath. That makes
//! teardown trivial and crash-safe: deleting the two covers (or letting the TUN interface
//! vanish, which the kernel cleans up) reverts to direct routing — we never mutated state we'd
//! have to reconstruct. Upstream dials bypass these covers via [`crate::net::SocketProtector`],
//! so there is no routing loop.
//!
//! Kill-switch teardown has two modes (process-architecture-and-ipc.md §5): **fail open**
//! ([`RouteManager::restore`]) removes the covers so traffic flows directly, and **fail closed**
//! ([`RouteManager::block`]) replaces them with a blackhole so traffic is dropped, not leaked.
//!
//! IPv4 only for now — the TUN is configured v4-only ([`crate::config::TunConfig`]), so there
//! is no v6 path to capture yet; a v6 split-default (`::/1` + `8000::/1`) is a follow-up.
//!
//! NB: the live route commands have been unit-tested for construction but not yet exercised
//! under root on a real box — that is gated with the rest of the privileged live gates.

use std::io;

use tracing::{debug, warn};

/// The two halves of the IPv4 space that, together, cover everything more specifically than the
/// default route — so installing both via the TUN captures all traffic without touching the
/// real default.
const HALVES: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];

/// A single route-table (or DNS) mutation: the program to run, its args, and whether a non-zero
/// exit is tolerable (true for the pre-clear deletes, which legitimately fail when absent).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteOp {
    program: &'static str,
    args: Vec<String>,
    ignore_failure: bool,
}

impl RouteOp {
    fn required(args: Vec<&str>) -> Self {
        Self::required_with(ROUTE_PROGRAM, args)
    }
    fn ignorable(args: Vec<&str>) -> Self {
        Self::ignorable_with(ROUTE_PROGRAM, args)
    }
    fn required_with(program: &'static str, args: Vec<&str>) -> Self {
        Self {
            program,
            args: args.into_iter().map(String::from).collect(),
            ignore_failure: false,
        }
    }
    fn ignorable_with(program: &'static str, args: Vec<&str>) -> Self {
        Self {
            program,
            args: args.into_iter().map(String::from).collect(),
            ignore_failure: true,
        }
    }
}

/// Manages the lifetime of spark's full-tunnel routes for one TUN device. Liveness is tracked
/// by the owner (the engine holds `Option<RouteManager>`), so this type is stateless beyond the
/// device name.
#[derive(Debug)]
pub struct RouteManager {
    tun: String,
}

impl RouteManager {
    /// Create a manager for the named TUN device. No routes change until [`install`](Self::install).
    pub fn new(tun: impl Into<String>) -> Self {
        Self { tun: tun.into() }
    }

    /// Install the split-default covers via the TUN, capturing all IPv4 traffic. Clears any
    /// pre-existing covers first, so a re-connect after a fail-closed block heals cleanly.
    pub async fn install(&mut self) -> io::Result<()> {
        debug!(tun = %self.tun, "installing full-tunnel routes");
        run(install_ops(&self.tun)).await
    }

    /// Fail open: remove the covers so the real default route resurfaces (direct routing).
    /// Idempotent — deleting absent covers is tolerated.
    pub async fn restore(&mut self) -> io::Result<()> {
        debug!(tun = %self.tun, "restoring direct routing (removing full-tunnel routes)");
        run(restore_ops()).await
    }

    /// Fail closed: replace the covers with a blackhole so traffic is dropped, not leaked.
    pub async fn block(&mut self) -> io::Result<()> {
        warn!(tun = %self.tun, "failing closed — blackholing traffic");
        run(block_ops()).await
    }
}

/// Execute a sequence of route ops in order, stopping at the first required op that fails.
async fn run(ops: Vec<RouteOp>) -> io::Result<()> {
    for op in ops {
        run_one(&op).await?;
    }
    Ok(())
}

/// Run one route command. A non-zero exit is an error unless the op tolerates it.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
async fn run_one(op: &RouteOp) -> io::Result<()> {
    let output = tokio::process::Command::new(op.program)
        .args(&op.args)
        .stdin(std::process::Stdio::null())
        .output()
        .await?;
    if output.status.success() || op.ignore_failure {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(io::Error::other(format!(
        "`{} {}` failed ({}): {}",
        op.program,
        op.args.join(" "),
        output.status,
        stderr.trim()
    )))
}

/// On unsupported platforms route management is a no-op (logged once at call sites). The TUN
/// teardown itself still reverts routing on those platforms via OS interface cleanup.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
async fn run_one(_op: &RouteOp) -> io::Result<()> {
    Ok(())
}

// --- Per-platform command construction (pure; unit-tested) -------------------------------

#[cfg(target_os = "macos")]
const ROUTE_PROGRAM: &str = "route";
#[cfg(target_os = "linux")]
const ROUTE_PROGRAM: &str = "ip";
#[cfg(target_os = "windows")]
const ROUTE_PROGRAM: &str = "route";

/// Delete the cover for `half` (used to clear stale covers before re-installing; ignorable).
#[cfg(target_os = "macos")]
fn clear_op(half: &str) -> RouteOp {
    RouteOp::ignorable(vec!["-n", "delete", "-net", half])
}
#[cfg(target_os = "linux")]
fn clear_op(half: &str) -> RouteOp {
    RouteOp::ignorable(vec!["route", "del", half])
}

/// Add the cover for `half` pointing at `tun`.
#[cfg(target_os = "macos")]
fn via_tun_op(half: &str, tun: &str) -> RouteOp {
    RouteOp::required(vec!["-n", "add", "-net", half, "-interface", tun])
}
#[cfg(target_os = "linux")]
fn via_tun_op(half: &str, tun: &str) -> RouteOp {
    RouteOp::required(vec!["route", "add", half, "dev", tun])
}

/// Add a blackhole cover for `half` (fail-closed). Independent of the TUN, so it survives the
/// device teardown. macOS has no blackhole route type, so route the half at `lo0` (loopback),
/// which discards it.
#[cfg(target_os = "macos")]
fn blackhole_op(half: &str) -> RouteOp {
    RouteOp::required(vec!["-n", "add", "-net", half, "-interface", "lo0"])
}
#[cfg(target_os = "linux")]
fn blackhole_op(half: &str) -> RouteOp {
    RouteOp::required(vec!["route", "add", "blackhole", half])
}

// --- Windows (`route.exe`) --------------------------------------------------------------
// Windows `route.exe` takes an explicit dest+mask (no CIDR) and routes on-link via an
// interface index (not a name), so the halves are translated with `half_to_dest_mask` and the
// `tun` argument carries the resolved interface **index** string (RouteManager formats the
// index into the `tun` field on Windows — see `RouteManager` below). VALIDATION-DEFERRED: the
// exact `route add … 0.0.0.0 … IF <idx>` gateway/interface form is per Microsoft docs and is
// flagged for on-Windows validation (macOS host cannot exercise it).

/// Delete the cover for `half` (used to clear stale covers before re-installing; ignorable).
/// Windows `route delete <dest>` removes by destination.
#[cfg(target_os = "windows")]
fn clear_op(half: &str) -> RouteOp {
    let (dest, _mask) = half_to_dest_mask(half);
    RouteOp::ignorable(vec!["delete", dest])
}

/// Add the cover for `half` via the tun interface. `tun` is the resolved interface **index**
/// (see `RouteManager` on Windows). `0.0.0.0` gateway + `IF <idx>` routes on-link via that
/// iface; `metric 1` beats the physical default.
#[cfg(target_os = "windows")]
fn via_tun_op(half: &str, tun: &str) -> RouteOp {
    let (dest, mask) = half_to_dest_mask(half);
    RouteOp::required(vec![
        "add", dest, "mask", mask, "0.0.0.0", "metric", "1", "IF", tun,
    ])
}

/// Blackhole the cover (fail-closed) independent of the tun: route via loopback (ifindex 1),
/// which discards. Survives tun teardown.
#[cfg(target_os = "windows")]
fn blackhole_op(half: &str) -> RouteOp {
    let (dest, mask) = half_to_dest_mask(half);
    RouteOp::required(vec![
        "add", dest, "mask", mask, "0.0.0.0", "metric", "1", "IF", "1",
    ])
}

// A fallback so the crate compiles on other targets; these are never run (`run_one` is a no-op).
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn clear_op(half: &str) -> RouteOp {
    RouteOp::ignorable(vec!["delete", half])
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn via_tun_op(half: &str, tun: &str) -> RouteOp {
    RouteOp::required(vec!["add", half, tun])
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn blackhole_op(half: &str) -> RouteOp {
    RouteOp::required(vec!["blackhole", half])
}

/// Clear stale covers, then point both halves at the TUN.
fn install_ops(tun: &str) -> Vec<RouteOp> {
    let mut ops: Vec<RouteOp> = HALVES.iter().map(|h| clear_op(h)).collect();
    ops.extend(HALVES.iter().map(|h| via_tun_op(h, tun)));
    ops
}

/// Remove the covers (direct routing resurfaces).
fn restore_ops() -> Vec<RouteOp> {
    HALVES.iter().map(|h| clear_op(h)).collect()
}

/// Clear stale covers, then blackhole both halves.
fn block_ops() -> Vec<RouteOp> {
    let mut ops: Vec<RouteOp> = HALVES.iter().map(|h| clear_op(h)).collect();
    ops.extend(HALVES.iter().map(|h| blackhole_op(h)));
    ops
}

/// Translate one of the split-default `HALVES` (`"0.0.0.0/1"` / `"128.0.0.0/1"`) to the
/// `(dest, mask)` pair Windows `route.exe` wants. Only ever called with the two `HALVES`
/// constants, so the `/1` mask is fixed at `128.0.0.0`; returns static strs.
// Only wired into runtime callers on Windows (the `route.exe` builders, added in a later
// task); on macOS/Linux it is exercised solely by the unit tests, so the non-test lib build
// would otherwise flag it as dead code.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn half_to_dest_mask(half: &str) -> (&'static str, &'static str) {
    match half {
        "0.0.0.0/1" => ("0.0.0.0", "128.0.0.0"),
        "128.0.0.0/1" => ("128.0.0.0", "128.0.0.0"),
        other => unreachable!("half_to_dest_mask called with non-HALVES value: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(op: &RouteOp) -> String {
        op.args.join(" ")
    }

    #[test]
    fn half_to_dest_mask_translates_the_two_covers() {
        assert_eq!(half_to_dest_mask("0.0.0.0/1"), ("0.0.0.0", "128.0.0.0"));
        assert_eq!(half_to_dest_mask("128.0.0.0/1"), ("128.0.0.0", "128.0.0.0"));
    }

    #[test]
    fn ops_default_to_the_platform_route_program() {
        // The generic constructors carry the platform's default route program.
        assert_eq!(RouteOp::required(vec!["x"]).program, ROUTE_PROGRAM);
        assert_eq!(RouteOp::ignorable(vec!["x"]).program, ROUTE_PROGRAM);
        // An explicit-program op carries what it was given.
        assert_eq!(RouteOp::required_with("netsh", vec!["x"]).program, "netsh");
    }

    #[test]
    fn install_clears_then_covers_both_halves_via_the_tun() {
        let ops = install_ops("utun7");
        assert_eq!(ops.len(), 4, "two clears + two adds");
        // The clears come first and tolerate failure; the adds are required.
        assert!(ops[0].ignore_failure && ops[1].ignore_failure);
        assert!(!ops[2].ignore_failure && !ops[3].ignore_failure);
        // Every op names a half; the adds name the TUN.
        for op in &ops {
            assert!(HALVES.iter().any(|h| argv(op).contains(h)));
        }
        assert!(argv(&ops[2]).contains("utun7") && argv(&ops[3]).contains("utun7"));
    }

    #[test]
    fn restore_only_clears_the_covers() {
        let ops = restore_ops();
        assert_eq!(ops.len(), 2);
        assert!(ops.iter().all(|o| o.ignore_failure));
        // Restore must not reference the TUN — it only removes the covering routes.
        assert!(ops.iter().all(|o| !argv(o).contains("utun")));
    }

    #[test]
    fn block_clears_then_blackholes_both_halves_independent_of_the_tun() {
        let ops = block_ops();
        assert_eq!(ops.len(), 4);
        // The blackhole adds are required and must not depend on the (torn-down) TUN.
        assert!(!ops[2].ignore_failure && !ops[3].ignore_failure);
        assert!(ops[2..].iter().all(|o| !argv(o).contains("utun")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_route_with_interface() {
        assert_eq!(ROUTE_PROGRAM, "route");
        assert_eq!(
            argv(&via_tun_op("0.0.0.0/1", "utun4")),
            "-n add -net 0.0.0.0/1 -interface utun4"
        );
        assert_eq!(
            argv(&blackhole_op("0.0.0.0/1")),
            "-n add -net 0.0.0.0/1 -interface lo0"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_uses_ip_route() {
        assert_eq!(ROUTE_PROGRAM, "ip");
        assert_eq!(
            argv(&via_tun_op("0.0.0.0/1", "tun0")),
            "route add 0.0.0.0/1 dev tun0"
        );
        assert_eq!(
            argv(&blackhole_op("0.0.0.0/1")),
            "route add blackhole 0.0.0.0/1"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_uses_route_exe_dest_mask_via_ifindex() {
        assert_eq!(ROUTE_PROGRAM, "route");
        // `tun` carries the resolved interface index on Windows.
        assert_eq!(
            argv(&via_tun_op("0.0.0.0/1", "12")),
            "add 0.0.0.0 mask 128.0.0.0 0.0.0.0 metric 1 IF 12"
        );
        assert_eq!(
            argv(&blackhole_op("0.0.0.0/1")),
            "add 0.0.0.0 mask 128.0.0.0 0.0.0.0 metric 1 IF 1" // loopback ifindex 1 = discard
        );
        assert_eq!(argv(&clear_op("128.0.0.0/1")), "delete 128.0.0.0");
    }
}
