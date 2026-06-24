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

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{info, warn};

use crate::config::{Config, StackKind};
use crate::netstack;
use crate::proxy;
use crate::transport;
use crate::tun::Tun;

/// The stop signal of every running tunnel. Each tunnel registers its own [`Notify`] here for its
/// lifetime: the no-arg [`stop`] (the shim entry) signals them all, while a [`TunnelHandle`] signals
/// only its own — so independent tunnels tear down independently (replacing the former single
/// process-global signal). Each waiter is registered before its stop can fire (the tunnel is up),
/// so `notify_waiters` is sufficient.
fn registry() -> &'static Mutex<Vec<Arc<Notify>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Arc<Notify>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn register(stop: &Arc<Notify>) {
    registry().lock().unwrap().push(Arc::clone(stop));
}

fn deregister(stop: &Arc<Notify>) {
    registry().lock().unwrap().retain(|n| !Arc::ptr_eq(n, stop));
}

/// The active server pool's control handle, if the running tunnel built a multi-server pool. The NE
/// runs one tunnel per process, so a single slot suffices: set while a pool tunnel is up, cleared on
/// teardown. The platform FFI ([`servers_json`]/[`select_server`]) reads it from its own thread, so
/// it is behind a mutex; the pool's own methods are independently thread-safe.
fn pool() -> &'static Mutex<Option<Arc<dyn transport::PoolControl>>> {
    static POOL: OnceLock<Mutex<Option<Arc<dyn transport::PoolControl>>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(None))
}

fn set_pool(control: Option<Arc<dyn transport::PoolControl>>) {
    *pool().lock().unwrap() = control;
}

fn current_pool() -> Option<Arc<dyn transport::PoolControl>> {
    pool().lock().unwrap().clone()
}

/// Readiness of the current tunnel's data path, for the platform shim to gate "connected" on. The NE
/// runs one tunnel per process, so a single global suffices. The shim calls [`mark_connecting`]
/// **synchronously** before starting the worker thread (a race-free baseline so [`wait_ready`] on
/// another thread can't observe a stale `Up`/`Down` from a previous run); the data path flips it to
/// `Up` once it's actually servicing the fd; teardown / early-failure flips it to `Down`. This lets the
/// shim avoid reporting the tunnel up while (e.g.) lantern-api cold-start is still fetching config and
/// nothing is servicing the utun fd — which would blackhole traffic.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Readiness {
    Pending,
    Up,
    Down,
}

fn readiness() -> &'static (Mutex<Readiness>, Condvar) {
    static READINESS: OnceLock<(Mutex<Readiness>, Condvar)> = OnceLock::new();
    READINESS.get_or_init(|| (Mutex::new(Readiness::Down), Condvar::new()))
}

fn set_ready(state: Readiness) {
    let (lock, cvar) = readiness();
    *lock.lock().unwrap() = state;
    cvar.notify_all();
}

/// Mark the data path **connecting** (not yet up). The platform shim calls this **synchronously**
/// before it starts the tunnel worker thread, so a [`wait_ready`] on another thread can't observe a
/// stale `Up`/`Down` from a previous connect. Called across the platform FFI.
pub fn mark_connecting() {
    set_ready(Readiness::Pending);
}

/// Mark the data path **down**. Idempotent; the `run_fd*` paths already set this on teardown, so the
/// shim only needs it on early-failure paths that never entered a `run_fd*` (e.g. a config parse
/// error) to unblock a waiting [`wait_ready`] promptly. Called across the platform FFI.
pub fn mark_stopped() {
    set_ready(Readiness::Down);
}

/// Abandon a tun `fd` on an early-failure / pre-adoption bail-out: close it (the platform transferred
/// ownership to native, but no `Tun::from_fd` adopted it here, so its drop won't) and [`mark_stopped`]
/// so a `wait_ready` waiter fails the connect instead of timing out. Use this on every path that
/// returns without running the tunnel — otherwise each failed start leaks the utun fd. Called across
/// the platform FFI.
pub fn abandon_fd(fd: i32) {
    // SAFETY: only called on paths where `fd` was never adopted by `Tun::from_fd`; nothing else owns it.
    unsafe { libc::close(fd) };
    mark_stopped();
}

/// Block until the current tunnel's data path is **up** (returns `0`), or `-1` if it doesn't come up
/// within `timeout_ms` (e.g. lantern-api cold-start still offline) or it went down first. Lets the
/// platform shim gate "connected" on a serviceable fd instead of blackholing traffic into an fd
/// nothing is reading yet. Runs on the shim's sync, runtime-less thread, so it blocks on a condvar —
/// not the async stop [`Notify`]. Called across the platform FFI.
pub fn wait_ready(timeout_ms: u32) -> i32 {
    let (lock, cvar) = readiness();
    let guard = lock.lock().unwrap();
    let (guard, res) = cvar
        .wait_timeout_while(guard, Duration::from_millis(timeout_ms as u64), |s| {
            *s == Readiness::Pending
        })
        .unwrap();
    if res.timed_out() || *guard != Readiness::Up {
        -1
    } else {
        0
    }
}

/// The current pool's member snapshot as the server-selection UI's JSON array (`"[]"` when no pool
/// is active — direct/single-tunnel/AnyTLS configs have no pool to choose among). Called across the
/// platform FFI.
pub fn servers_json() -> String {
    match current_pool() {
        Some(c) => transport::snapshot_to_json(&c.snapshot()),
        None => "[]".to_string(),
    }
}

/// Pin which pool member new flows dial first: `Some(index)` pins (overrides latency ranking),
/// `None` returns to auto. Returns `true` only when the pin was actually applied; `false` when no
/// server pool is active (nothing to pin) *or* the index was out of range — so the FFI/UI can tell
/// a real selection from a no-op. Takes effect for new flows only. Called across the platform FFI.
pub fn select_server(index: Option<usize>) -> bool {
    match current_pool() {
        Some(c) => c.set_pin(index),
        None => false,
    }
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

/// The single home of the **config-acquisition policy** the fd-shims share — the Apple C-ABI and
/// Android JNI shims call this today (the desktop service is a documented follow-up; it owns its own
/// TUN and shares the lower-level `config::fetch`, not this entry). The decision tree lives here once,
/// not duplicated per shim.
/// `config` is the controlling app's explicit data-path string (`None`/`""` = no app config);
/// `data_dir` is the per-platform cache dir (app-group container on Apple, app files dir on Android)
/// the self-fetch path needs; `tun_base` carries the platform's tun primitives (built via
/// [`fd_config`]) — the platform owns the interface/stack reality (Apple = userspace, Android =
/// `VpnService` addr/prefix + system stack), the config string only ever supplies the transport.
/// `fd` ownership is transferred; returns the C-style status (`0` clean / `-1` error).
///
/// The policy (identical to the former inline Apple dispatch):
/// - `None`/empty or the `"lantern-api"` sentinel → on the `config-fetch` slice, **self-fetch** the
///   pool from the Lantern config-new API ([`run_fd_lantern_api`]); needs a `data_dir` (else fail
///   closed). Without `config-fetch`, empty falls through to **direct**, and the explicit
///   `"lantern-api"` sentinel can't be served (`-1`).
/// - a bare `host:port` literal → tunnel every flow through that **plain relay** (explicit override).
/// - any other string → a full [`Config`] (native TOML or a Lantern `config_raw.json`, auto-detected
///   by [`Config::from_config_str`]); an unparseable string fails closed.
pub fn run_fd_dispatch(
    fd: i32,
    mtu: u16,
    config: Option<&str>,
    data_dir: Option<&std::path::Path>,
    tun_base: Config,
) -> i32 {
    // A null/absent config string is "no explicit config"; trim so " " / "\n" count as empty too.
    let cfg_str = config.map(str::trim).unwrap_or("");

    // Daemon-owned self-fetch: the *absence* of an explicit config — or the explicit `lantern-api`
    // sentinel — means "fetch the pool from the Lantern config-new API myself, run from it, and
    // refresh in the background". Only on the `config-fetch` slice (which pulls the BoringSSL build
    // the fetch's TLS uses); the fetch must bypass the tunnel, which only the daemon can guarantee.
    #[cfg(feature = "config-fetch")]
    if cfg_str.is_empty() || cfg_str == "lantern-api" {
        return match data_dir {
            Some(d) => run_fd_lantern_api(fd, mtu, d.to_path_buf(), tun_base),
            None => {
                // fetch mode needs a data dir to cache device_id + config; close the (transferred)
                // fd, unblock any `wait_ready` waiter, and fail the connect.
                abandon_fd(fd);
                -1
            }
        };
    }

    // Without `config-fetch`, self-fetch is unsupported: an empty config falls through to direct
    // below, but the explicit `"lantern-api"` sentinel can't be served here.
    #[cfg(not(feature = "config-fetch"))]
    if cfg_str == "lantern-api" {
        let _ = data_dir; // unused without config-fetch
        abandon_fd(fd); // close fd + unblock waiter; can't serve it here
        return -1;
    }

    // An explicit config (or, without `config-fetch`, empty = direct). The platform's `tun_base`
    // always supplies the tun/stack; the string supplies the transport.
    match explicit_config(cfg_str, &tun_base) {
        Some(config) => run_fd(fd, mtu, config),
        None => {
            // Unparseable config: close the (transferred) fd, unblock any waiter, and fail.
            abandon_fd(fd);
            -1
        }
    }
}

/// Resolve an explicit config `s` onto the platform's `tun_base`: empty → direct forwarding;
/// a bare `host:port` → the plain relay; otherwise a full [`Config`] (TOML or `config_raw.json`,
/// auto-detected). In every case the platform's `tun_base` owns `tun`/stack (the fd + interface are
/// a platform reality); the string only sets the transport. `None` signals a parse error.
fn explicit_config(s: &str, tun_base: &Config) -> Option<Config> {
    if s.is_empty() {
        return Some(tun_base.clone()); // direct forwarding on the platform tun
    }
    // Back-compat: a bare host:port is the plain-relay server (the `SPARK_PROXY` path).
    if let Ok(addr) = s.parse::<SocketAddr>() {
        let mut c = tun_base.clone();
        c.transport.server = Some(addr);
        return Some(c);
    }
    // Otherwise a full config — native TOML or a Lantern `config_raw.json`, auto-detected. The
    // platform tun_base wins for tun/stack (the fd is already established by the OS / VpnService).
    let mut c = Config::from_config_str(s).ok()?;
    c.tun = tun_base.tun.clone();
    Some(c)
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
    // A private stop signal registered for the no-arg `stop` (the shim entry); behavior is identical
    // to the former single global signal for the one-tunnel-per-process shim case.
    run_with_handle(fd, mtu, config, Arc::new(Notify::new()))
}

/// The shared implementation: run the tunnel until `stop` is signalled (by [`stop`] or a
/// [`TunnelHandle`]) or the data path exits, registering `stop` for its lifetime so the no-arg
/// [`stop`] can find it.
fn run_with_handle(fd: i32, mtu: u16, config: Config, stop: Arc<Notify>) -> std::io::Result<()> {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            // Never adopted `fd` and never flipped readiness `Up`; close it (ownership was transferred
            // to native) and mark down so a `wait_ready` waiter fails the connect instead of timing out.
            abandon_fd(fd);
            return Err(e);
        }
    };
    register(&stop);
    let waiter = Arc::clone(&stop);
    let result = runtime.block_on(run_tunnel_data_path(fd, mtu, config, &waiter));
    deregister(&stop);
    // Drop the pool control handle for this (now torn-down) tunnel so the FFI reports no active pool.
    set_pool(None);
    set_ready(Readiness::Down);
    result
}

/// The tunnel data path shared by `run_with_handle` and the lantern-api entry: adopt `fd`, build the
/// transport/netstack from `config`, register the pool control, and run until `waiter` is signalled or
/// the accept loop exits.
async fn run_tunnel_data_path(
    fd: i32,
    mtu: u16,
    mut config: Config,
    waiter: &Notify,
) -> std::io::Result<()> {
    crate::resolve_bootstrap(&mut config).await?;
    // SAFETY: `fd` is the OS TUN fd handed to native for the tunnel's lifetime.
    let tun = Arc::new(
        unsafe { Tun::from_fd(fd, mtu) }.map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let (tcp_transport, udp_transport, control) = transport::from_config_with_control(&config)?;
    set_pool(control);
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
    // The fd is adopted and the netstack is about to accept — the data path is live. The platform
    // shim's `wait_ready` gates "connected" on this (see [`Readiness`]).
    set_ready(Readiness::Up);
    let metrics = Arc::new(crate::metrics::Metrics::default());
    tokio::select! {
        _ = proxy::tcp::run(stack, tcp_transport, metrics) => warn!("netstack accept loop exited"),
        _ = waiter.notified() => info!("stop requested; tearing the tunnel down"),
    }
    drop(tun);
    Ok(())
}

/// `lantern-api` self-fetch entry (shared by every platform's [`run_fd_dispatch`]): fetch the boot
/// config from the Lantern API (cache-first, retrying on cold-start offline until a config is obtained
/// or stop is signalled), spawn the background refresh loop (warms the on-disk cache; no live pool
/// swap in v1), then run the tunnel. Blocks until stop; `0` clean, `-1` on error. `data_dir` is the
/// per-platform cache dir (Apple app-group container, Android app files dir). `tun_base` supplies the
/// platform's `tun`/stack — the fetched `config_raw.json` is a server pool with no meaningful tun
/// section, so the platform owns the interface reality (Apple = userspace, Android = system stack).
#[cfg(feature = "config-fetch")]
pub fn run_fd_lantern_api(
    fd: i32,
    mtu: u16,
    data_dir: std::path::PathBuf,
    tun_base: Config,
) -> i32 {
    use crate::config::fetch::{self, FetchEnv};

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "lantern-api: runtime build failed");
            // `fd` was never adopted; close it (NE ownership transfer) and unblock a `wait_ready` waiter.
            abandon_fd(fd);
            return -1;
        }
    };
    let stop = Arc::new(Notify::new());
    register(&stop);
    let waiter = Arc::clone(&stop);
    info!(dir = %data_dir.display(), "lantern-api: starting (daemon self-fetch of boot config)");
    let result: std::io::Result<()> = runtime.block_on(async move {
        let env = FetchEnv::from_env();
        // Cold-start resilience (design §6): keep retrying until a config is obtained (cache or fetch)
        // or stop fires while we wait. `load_or_fetch` returns instantly on a warm cache.
        let mut attempt = 0u32;
        let (mut config, _meta) = loop {
            // Race the (possibly slow) fetch against stop so a teardown during an in-flight attempt
            // cancels it promptly — rather than waiting out `fetch_once`'s timeout — and unblocks the
            // readiness waiter. `fd` isn't adopted yet on any of these paths.
            tokio::select! {
                res = fetch::load_or_fetch(&data_dir, &env) => match res {
                    Ok(c) => break c,
                    Err(e) => {
                        warn!(error = %e, "lantern-api: waiting for config (offline?)");
                        attempt = attempt.saturating_add(1);
                        let wait = Duration::from_secs(((attempt as u64) * 5).clamp(5, 30));
                        tokio::select! {
                            _ = tokio::time::sleep(wait) => {}
                            _ = waiter.notified() => {
                                abandon_fd(fd);
                                return Ok(());
                            }
                        }
                    }
                },
                _ = waiter.notified() => {
                    // Stopped during an in-flight fetch — close the (still-unadopted) fd and bail.
                    abandon_fd(fd);
                    return Ok(());
                }
            }
        };
        // The fetched `config_raw.json` is a server pool; its `tun` section is defaults. The platform
        // owns the interface reality (the fd is already established by the OS / VpnService), so take
        // `tun`/stack from `tun_base` — userspace on Apple, the system stack + VpnService addr/prefix
        // on Android. (No-op on Apple, where `tun_base` is the userspace default.)
        config.tun = tun_base.tun.clone();
        // Pin the proxy's own sockets to the physical interface so they bypass our tunnel. The NE
        // does this automatically for TCP but NOT for UDP/QUIC, so without it hysteria2's QUIC
        // handshake loops back into the tunnel and hangs (samizdat/TCP is unaffected). A fetched
        // config carries no `protect_interface`, so discover it here; respect an explicit one.
        if config.transport.protect_interface.is_none() {
            match crate::net::default_physical_interface() {
                Some(iface) => {
                    info!(interface = %iface, "lantern-api: pinning proxy sockets to physical interface (UDP/QUIC tunnel bypass)");
                    config.transport.protect_interface = Some(iface);
                }
                None => warn!(
                    "lantern-api: no physical interface found to pin to; UDP/QUIC transports may not egress"
                ),
            }
        }
        info!(
            servers = config.transport.servers.len(),
            "lantern-api: boot config ready, bringing tunnel up"
        );
        // Background refresh: warms the cache for the next connect; ends when stop fires.
        let loop_dir = data_dir.clone();
        let loop_stop = Arc::clone(&waiter);
        tokio::spawn(async move {
            let env = FetchEnv::from_env();
            tokio::select! {
                _ = fetch::run_loop(&loop_dir, &env, |_cfg| {}, || false) => {}
                _ = loop_stop.notified() => {}
            }
        });
        run_tunnel_data_path(fd, mtu, config, &waiter).await
    });
    deregister(&stop);
    set_pool(None);
    set_ready(Readiness::Down);
    match result {
        Ok(()) => 0,
        Err(e) => {
            warn!(error = %e, "lantern-api tunnel exited with error");
            -1
        }
    }
}

/// Signal **every** running tunnel ([`run_fd`] / [`run_tunnel_with_config`]) to stop — the no-arg
/// teardown the JNI/C-ABI shims call (they own one tunnel per process). For a single tunnel this
/// addresses the [`TunnelHandle::stop`] target.
pub fn stop() {
    for stop in registry().lock().unwrap().iter() {
        stop.notify_waiters();
    }
}

/// A handle to a tunnel started by [`spawn_tunnel`]: stop it via [`TunnelHandle::stop`] (or by
/// dropping the handle). The per-tunnel alternative to the process-global [`stop`], for an
/// in-process embedder that owns the lifecycle (the desktop service uses the IPC control plane
/// instead; the mobile shims use the blocking [`run_fd`] + no-arg [`stop`]).
pub struct TunnelHandle {
    stop: Arc<Notify>,
}

impl TunnelHandle {
    /// Signal this tunnel to tear down (idempotent; a no-op once it has stopped).
    pub fn stop(&self) {
        self.stop.notify_waiters();
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        // Dropping the handle tears the tunnel down — the embedder's RAII lifecycle.
        self.stop.notify_waiters();
    }
}

/// Start a tunnel on `fd` on a background thread and return a [`TunnelHandle`] that stops it.
/// Unlike [`run_fd`] this does **not** block; a start failure is logged (the non-blocking handle
/// can't report it). The thread runs on its own private runtime until the handle stops it (or the
/// data path exits).
pub fn spawn_tunnel(fd: i32, mtu: u16, config: Config) -> TunnelHandle {
    let stop = Arc::new(Notify::new());
    let stop_thread = Arc::clone(&stop);
    std::thread::spawn(move || {
        if let Err(e) = run_with_handle(fd, mtu, config, stop_thread) {
            warn!(error = %e, "spawned tunnel exited with error");
        }
    });
    TunnelHandle { stop }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_ready_reflects_data_path_state() {
        // No other test exercises the readiness global (the tunnel data path needs a real fd), so this
        // single test can drive it through its sub-cases serially without inter-test races.

        // Up after a short delay → ready (0).
        mark_connecting();
        let h = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(50));
            set_ready(Readiness::Up);
        });
        assert_eq!(wait_ready(5_000), 0);
        h.join().unwrap();

        // Down before/while waiting → not ready (-1).
        mark_connecting();
        mark_stopped();
        assert_eq!(wait_ready(5_000), -1);

        // Stays pending past the timeout (e.g. cold-start still offline) → not ready (-1).
        mark_connecting();
        assert_eq!(wait_ready(50), -1);
        mark_stopped(); // leave the global in a clean terminal state
    }

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

    #[test]
    fn explicit_config_maps_each_kind_onto_the_platform_tun() {
        // Android-shaped base: system stack + a VpnService addr/prefix that must survive every path.
        let base = fd_config(Ipv4Addr::new(10, 1, 2, 3), 30, true);

        // empty → direct forwarding (no server), platform tun preserved.
        let direct = explicit_config("", &base).expect("empty is direct");
        assert_eq!(direct.transport.server, None);
        assert_eq!(direct.tun.addr, Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(direct.tun.stack, StackKind::System);

        // bare host:port → plain relay, platform tun preserved.
        let relay = explicit_config("192.0.2.7:9000", &base).expect("host:port is a relay");
        assert_eq!(
            relay.transport.server,
            Some("192.0.2.7:9000".parse().unwrap())
        );
        assert_eq!(relay.tun.stack, StackKind::System);
        assert_eq!(relay.tun.prefix, 30);

        // a full TOML config keeps its transport but the platform tun_base wins for tun/stack — even
        // when the TOML names its own [tun] (the fd is already established by the OS / VpnService).
        let full = explicit_config(
            "[tun]\nstack = \"userspace\"\naddr = \"172.16.0.9\"\n\n[transport]\nserver = \"203.0.113.4:443\"\n",
            &base,
        )
        .expect("a full TOML config");
        assert_eq!(
            full.transport.server,
            Some("203.0.113.4:443".parse().unwrap())
        );
        assert_eq!(
            full.tun.stack,
            StackKind::System,
            "platform tun_base wins over the config's [tun]"
        );
        assert_eq!(full.tun.addr, Ipv4Addr::new(10, 1, 2, 3));

        // junk that is neither host:port nor a valid config → None (the shim fails closed).
        assert!(explicit_config("not-a-config !!", &base).is_none());
    }

    #[tokio::test]
    async fn registered_stop_wakes_only_its_own_waiter() {
        // Two independent tunnel stop signals; signalling one must not wake the other.
        let a = Arc::new(Notify::new());
        let b = Arc::new(Notify::new());
        register(&a);
        register(&b);

        let a2 = Arc::clone(&a);
        let wa = tokio::spawn(async move { a2.notified().await });
        let b2 = Arc::clone(&b);
        let mut wb = tokio::spawn(async move { b2.notified().await });
        // Let both waiters register their interest before signalling.
        tokio::time::sleep(Duration::from_millis(50)).await;

        TunnelHandle {
            stop: Arc::clone(&a),
        }
        .stop(); // stop only tunnel a (handle drop also signals a)

        tokio::time::timeout(Duration::from_secs(1), wa)
            .await
            .expect("a's waiter must be woken")
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut wb)
                .await
                .is_err(),
            "b's waiter must NOT be woken by a's stop"
        );

        // The global stop() then wakes b too.
        super::stop();
        tokio::time::timeout(Duration::from_secs(1), &mut wb)
            .await
            .expect("global stop must wake b")
            .unwrap();

        deregister(&a);
        deregister(&b);
    }
}
