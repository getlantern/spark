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
#[cfg(feature = "smart-routing")]
use crate::dns;
use crate::netstack;
use crate::proxy;
use crate::transport;
use crate::tun::Tun;

/// Worker threads for the tunnel data-path runtime. The data path is I/O-bound (the netstack pump
/// plus per-flow proxy copies), not CPU-bound — on-device profiling showed ~3% CPU under real
/// streaming — so tokio's default of one worker per core (e.g. 8 on an 8-core phone) just wastes
/// thread stacks and wakeups, which matters on low-end devices. Two workers keep the netstack pump
/// and a proxy task running in parallel without over-subscribing.
const TUNNEL_WORKER_THREADS: usize = 2;

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

/// The running tunnel's router, registered at connect so the live split-tunnel update
/// ([`set_split_tunnel`]) can reach it, and cleared on teardown. One tunnel per process (like the
/// pool handle), so a single global suffices.
#[cfg(feature = "smart-routing")]
fn active_router() -> &'static Mutex<Option<Arc<crate::rules::router::Router>>> {
    static R: OnceLock<Mutex<Option<Arc<crate::rules::router::Router>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(None))
}

#[cfg(feature = "smart-routing")]
fn set_active_router(r: Option<Arc<crate::rules::router::Router>>) {
    // Poison-tolerant: this is reached from FFI teardown, so recover the guard from a poisoned
    // mutex (`into_inner`) rather than panicking and crashing the NE/JNI host. The inner Option is
    // trivially consistent, so recovering it is safe.
    *active_router().lock().unwrap_or_else(|e| e.into_inner()) = r;
}

/// Update the running tunnel's split-tunnel bypass list live (no reconnect). `json` is the
/// `{enabled,domains,ips}` payload. Returns `true` if applied, `false` if the JSON was invalid or no
/// router is active (not connected, or connected with no smart-routing path). Called across the
/// platform FFI (Apple C-ABI / Android JNI).
#[cfg(feature = "smart-routing")]
pub fn set_split_tunnel(json: &str) -> bool {
    let Ok(st) = crate::split_tunnel::parse(json) else {
        return false;
    };
    // Clone the Arc out under the lock, then release the mutex before touching the router — so this
    // mutex is never held across the router's own RwLock. `unwrap_or_else(into_inner)` recovers from
    // a poisoned mutex instead of panicking: this is FFI-reachable and must not crash the host.
    let router = active_router()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match router {
        Some(r) => {
            r.set_user_bypass(Some(&st));
            true
        }
        None => false,
    }
}

/// Without `smart-routing`, live split-tunnel updates are unsupported.
#[cfg(not(feature = "smart-routing"))]
pub fn set_split_tunnel(_json: &str) -> bool {
    false
}

/// Live-push the app-bypass list (JSON array of canonical `.app` bundle-root paths) to the running
/// router. Returns false if the JSON was invalid or no tunnel/router is active. Mirrors
/// [`set_split_tunnel`], but the payload is a bare `["/Applications/Foo.app", ...]` array (the
/// catalog stores bundle-root paths, matched by prefix against the resolved process path so
/// in-bundle helpers match too — NOT executable paths). Called across the platform FFI (Apple
/// C-ABI).
#[cfg(feature = "smart-routing")]
pub fn set_app_bypass(json: &str) -> bool {
    let paths: Vec<String> = match serde_json::from_str(json) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("set_app_bypass: invalid JSON: {e}");
            return false;
        }
    };
    // Clone the Arc out under the lock, then release the mutex before touching the router — so this
    // mutex is never held across the router's own RwLock. `unwrap_or_else(into_inner)` recovers from
    // a poisoned mutex instead of panicking: this is FFI-reachable and must not crash the host.
    let router = active_router()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match router {
        Some(r) => {
            r.set_app_bypass(&paths);
            true
        }
        None => false,
    }
}

/// Without `smart-routing`, live app-bypass updates are unsupported.
#[cfg(not(feature = "smart-routing"))]
pub fn set_app_bypass(_json: &str) -> bool {
    false
}

/// Update the running tunnel's routing mode live (no reconnect). `mode` is `"smart"`/`"full"`.
/// Returns true if applied, false if no router is active. Called across the platform FFI.
#[cfg(feature = "smart-routing")]
pub fn set_routing_mode(mode: &str) -> bool {
    let m = crate::routing_mode::parse(mode);
    let router = active_router()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match router {
        Some(r) => {
            r.set_mode(m);
            true
        }
        None => false,
    }
}

/// Without `smart-routing`, live routing-mode updates are unsupported.
#[cfg(not(feature = "smart-routing"))]
pub fn set_routing_mode(_mode: &str) -> bool {
    false
}

/// The router the running tunnel is actually using, or `None` when no tunnel is up.
///
/// This is the SAME `Arc` the flow hooks and the DNS ad-block closure hold, which is what makes an
/// in-place update (`Router::reload_rules`, `set_ad_block_enabled`) reach live traffic — replacing
/// the router wholesale would not.
#[cfg(feature = "smart-routing")]
pub fn live_router() -> Option<Arc<crate::rules::router::Router>> {
    active_router()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Enable/disable ad-block on the running tunnel live (no reconnect). Returns true if applied,
/// false if no router is active. Called across the platform FFI.
#[cfg(feature = "smart-routing")]
pub fn set_ad_block_enabled(enabled: bool) -> bool {
    let router = live_router();
    match router {
        Some(r) => {
            r.set_ad_block_enabled(enabled);
            true
        }
        None => false,
    }
}

/// Without `smart-routing`, live ad-block updates are unsupported.
#[cfg(not(feature = "smart-routing"))]
pub fn set_ad_block_enabled(_enabled: bool) -> bool {
    false
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
/// - a bare `IP:port` literal (an IP address, not a hostname — it is `SocketAddr`-parsed) → tunnel
///   every flow through that **plain relay** (explicit override).
/// - any other string → a full [`Config`] (native TOML or a Lantern `config_raw.json`, auto-detected
///   by [`Config::from_config_str`]); an unparseable string fails closed.
#[allow(clippy::too_many_arguments)]
// one plumbing hop from the platform FFI; each arg is distinct
// `identity` is only consumed on the config-fetch slice (it exists to name the account a fetch runs
// as); a build without that feature never fetches, so the parameter is legitimately unused there.
#[cfg_attr(not(feature = "config-fetch"), allow(unused_variables))]
pub fn run_fd_dispatch(
    fd: i32,
    mtu: u16,
    config: Option<&str>,
    data_dir: Option<&std::path::Path>,
    tun_base: Config,
    split_tunnel: Option<&str>,
    routing_mode: Option<&str>,
    identity: Option<&str>,
) -> i32 {
    // A null/absent config string is "no explicit config"; trim so " " / "\n" count as empty too.
    let cfg_str = config.map(str::trim).unwrap_or("");
    // A malformed or partial blob parses to `None` and falls back to dir-backed identity — hosts that
    // require the supplied one (the Apple NE) reject it before calling us, so this stays a fallback
    // for Android/CLI rather than a silent downgrade on the path that matters.
    #[cfg(feature = "config-fetch")]
    let identity = identity.and_then(crate::config::fetch::Identity::parse);

    // On mobile, boring's default cert store finds no CA roots (Android/iOS keep them outside
    // OpenSSL's paths), so flint's fronted TLS — the rule-set (`.srs`) fetch and the fronted leg of
    // config-fetch — can't verify the CDN cert. Install the bundled roots via `SSL_CERT_FILE` before
    // any fetch runs. No-op off-mobile; needs a writable data dir.
    #[cfg(feature = "config-fetch")]
    if let Some(dir) = data_dir {
        crate::ca_roots::install_bundled_roots(dir);
    }

    // Daemon-owned self-fetch: the *absence* of an explicit config — or the explicit `lantern-api`
    // sentinel — means "fetch the pool from the Lantern config-new API myself, run from it, and
    // refresh in the background". Only on the `config-fetch` slice (which pulls the BoringSSL build
    // the fetch's TLS uses); the fetch must bypass the tunnel, which only the daemon can guarantee.
    #[cfg(feature = "config-fetch")]
    if cfg_str.is_empty() || cfg_str == "lantern-api" {
        return match data_dir {
            Some(d) => run_fd_lantern_api(
                fd,
                mtu,
                d.to_path_buf(),
                tun_base,
                split_tunnel,
                routing_mode,
                identity,
            ),
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
        Some(config) => run_fd_with_split_tunnel(fd, mtu, config, split_tunnel, routing_mode),
        None => {
            // Unparseable config: close the (transferred) fd, unblock any waiter, and fail.
            abandon_fd(fd);
            -1
        }
    }
}

/// Resolve an explicit config `s` onto the platform's `tun_base`: empty → direct forwarding;
/// a bare `IP:port` (IP literal only, not a hostname) → the plain relay; otherwise a full [`Config`]
/// (TOML or `config_raw.json`,
/// auto-detected). In every case the platform's `tun_base` owns `tun`/stack (the fd + interface are
/// a platform reality); the string only sets the transport. `None` signals a parse error.
fn explicit_config(s: &str, tun_base: &Config) -> Option<Config> {
    if s.is_empty() {
        return Some(tun_base.clone()); // direct forwarding on the platform tun
    }
    // Back-compat: a bare IP:port is the plain-relay server (the `SPARK_PROXY` path). `SocketAddr`
    // parsing accepts only IP literals (or bracketed IPv6), not hostnames — a hostname falls through
    // to the full-config branch below and fails closed.
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
    run_fd_with_split_tunnel(fd, mtu, config, None, None)
}

/// Like [`run_fd`] but also applies an initial split-tunnel bypass list (`split_tunnel` is the raw
/// JSON `{enabled,domains,ips}` payload). The list seeds the router immediately at connect, before
/// any flow is accepted. `None` or an invalid JSON string are both treated as no bypass list.
fn run_fd_with_split_tunnel(
    fd: i32,
    mtu: u16,
    config: Config,
    split_tunnel: Option<&str>,
    routing_mode: Option<&str>,
) -> i32 {
    match run_tunnel_with_config(fd, mtu, config, split_tunnel, routing_mode) {
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
///
/// `split_tunnel` is the raw JSON `{enabled,domains,ips}` payload to apply as the initial user
/// bypass list; `None` means no bypass list. This seeds the router at connect; live updates use
/// [`set_split_tunnel`] after the tunnel is up.
pub fn run_tunnel_with_config(
    fd: i32,
    mtu: u16,
    config: Config,
    split_tunnel: Option<&str>,
    routing_mode: Option<&str>,
) -> std::io::Result<()> {
    // A private stop signal registered for the no-arg `stop` (the shim entry); behavior is identical
    // to the former single global signal for the one-tunnel-per-process shim case.
    run_with_handle(
        fd,
        mtu,
        config,
        split_tunnel,
        routing_mode,
        Arc::new(Notify::new()),
    )
}

/// The shared implementation: run the tunnel until `stop` is signalled (by [`stop`] or a
/// [`TunnelHandle`]) or the data path exits, registering `stop` for its lifetime so the no-arg
/// [`stop`] can find it.
fn run_with_handle(
    fd: i32,
    mtu: u16,
    config: Config,
    split_tunnel: Option<&str>,
    routing_mode: Option<&str>,
    stop: Arc<Notify>,
) -> std::io::Result<()> {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(TUNNEL_WORKER_THREADS)
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
    let result = runtime.block_on(run_tunnel_data_path(
        fd,
        mtu,
        config,
        None,
        split_tunnel,
        routing_mode,
        &waiter,
    ));
    deregister(&stop);
    // Drop the pool control handle for this (now torn-down) tunnel so the FFI reports no active pool.
    set_pool(None);
    #[cfg(feature = "smart-routing")]
    set_active_router(None);
    set_ready(Readiness::Down);
    result
}

/// The tunnel data path shared by `run_with_handle` and the lantern-api entry: adopt `fd`, build the
/// transport/netstack from `config`, register the pool control, and run until `waiter` is signalled or
/// the accept loop exits. `data_dir` is the per-platform cache dir (Apple app-group container, Android
/// app files dir) the smart-routing loader reads rule-set `.srs` from (`<data_dir>/rulesets/`); `None`
/// (e.g. the desktop `spawn_tunnel` path) means no on-disk rule-sets — inline IP rules still apply.
/// `split_tunnel` is the raw JSON `{enabled,domains,ips}` payload to apply as the initial user bypass
/// list; `None` means no bypass list.
async fn run_tunnel_data_path(
    fd: i32,
    mtu: u16,
    mut config: Config,
    data_dir: Option<&std::path::Path>,
    split_tunnel: Option<&str>,
    routing_mode: Option<&str>,
    waiter: &Notify,
) -> std::io::Result<()> {
    crate::resolve_bootstrap(&mut config).await?;
    // SAFETY: `fd` is the OS TUN fd handed to native for the tunnel's lifetime.
    let tun = Arc::new(
        unsafe { Tun::from_fd(fd, mtu) }.map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let (tcp_transport, udp_transport, control) = transport::from_config_with_control(&config)?;
    set_pool(control);
    // A direct transport for the router's `Direct` action, pinned to the physical interface
    // (`transport.protect_interface`) so those flows bypass our own tunnel. On Android the app's own
    // sockets already bypass via `addDisallowedApplication` (interface usually unset); the lantern-api
    // path sets it to the physical interface, so direct flows dial off-tunnel there. Built
    // unconditionally (cheap); only dialed when a router returns `Direct`.
    let protector = match config.transport.protect_interface.as_deref() {
        Some(name) => Some(crate::net::SocketProtector::for_interface(name)?),
        None => None,
    };
    // One concrete DirectTransport (one protector), viewed as both a TCP `Transport` (router `Direct`)
    // and a `UdpTransport` (dialed only for `Direct`-routed UDP flows when smart-routing is on).
    let direct = Arc::new(transport::DirectTransport::new(protector));
    let direct_transport: Arc<dyn transport::Transport> = direct.clone();
    let direct_udp: Arc<dyn transport::UdpTransport> = direct;
    let (stack, udp_surface) = netstack::build(Arc::clone(&tun), &config)?;
    let idle = Duration::from_secs(config.udp.idle_timeout_secs);
    // Build the smart-routing hooks and wire the UDP path together (they share one fake-IP pool):
    // intercept DNS (`:53`) to the fake-IP server when smart-routing is active, otherwise run the
    // plain UDP proxy. Returns the per-flow route hooks for the TCP forwarder (`None` = proxy
    // everything, today's behavior).
    let hooks = setup_routing_and_udp(
        &config,
        data_dir,
        split_tunnel,
        routing_mode,
        udp_surface,
        udp_transport,
        direct_udp,
        idle,
    );
    info!(mtu, "spark tunnel up (fd mode)");
    // The fd is adopted and the netstack is about to accept — the data path is live. The platform
    // shim's `wait_ready` gates "connected" on this (see [`Readiness`]).
    set_ready(Readiness::Up);
    let metrics = Arc::new(crate::metrics::Metrics::default());
    tokio::select! {
        _ = proxy::tcp::run(stack, tcp_transport, direct_transport, hooks, metrics)
            => warn!("netstack accept loop exited"),
        _ = waiter.notified() => info!("stop requested; tearing the tunnel down"),
    }
    drop(tun);
    Ok(())
}

/// Fake-IP DNS tuning: how long a `fakeip↔domain` mapping lives in the pool, the live-mapping LRU
/// cap, the TTL stamped into DNS answers, and the DNS-interceptor forward channel depth.
#[cfg(feature = "smart-routing")]
const FAKEIP_TTL: Duration = Duration::from_secs(600);
#[cfg(feature = "smart-routing")]
const FAKEIP_CAP: usize = 8192;
#[cfg(feature = "smart-routing")]
const DNS_ANSWER_TTL_SECS: u32 = 30;
#[cfg(feature = "smart-routing")]
const DNS_FORWARD_DEPTH: usize = 256;
/// How long a cached `.srs` is considered fresh before the background loop re-fetches it. Rule-sets
/// change slowly, so this is long — the refresh is a cache-warm, not a hot path. Only the config-fetch
/// (`lantern-api`) path spawns the refresh loop, so it's gated on both features.
#[cfg(all(feature = "smart-routing", feature = "config-fetch"))]
const RULESET_REFRESH_INTERVAL: Duration = Duration::from_secs(12 * 3600);

/// Set up smart routing and the UDP data path in one place, since both share a single fake-IP pool.
///
/// With `smart-routing` on and rules configured: build the per-flow router, a shared fake-IP pool, a
/// [`dns::server::DnsServer`] over it, and the [`proxy::RouteHooks`] (recoverer + DoH resolvers); then
/// wire UDP so DNS (`:53`) is answered locally with fake IPs and everything else is proxied. With no
/// rules (or the feature off) it just spawns the plain UDP proxy. Returns the hooks for the TCP
/// forwarder (`None` = proxy everything). Rule-set `.srs` bytes load from `<data_dir>/rulesets/`; a
/// missing list is skipped (the tunnel still runs). Inline IP rules need no `.srs` and apply even with
/// `data_dir == None`.
#[cfg(feature = "smart-routing")]
#[allow(clippy::too_many_arguments)]
fn setup_routing_and_udp(
    config: &Config,
    data_dir: Option<&std::path::Path>,
    split_tunnel: Option<&str>,
    routing_mode: Option<&str>,
    udp_surface: Option<netstack::UdpSurface>,
    udp_transport: Arc<dyn transport::UdpTransport>,
    direct_udp: Arc<dyn transport::UdpTransport>,
    idle: Duration,
) -> Option<Arc<proxy::RouteHooks>> {
    let sr = &config.smart_routing;
    // The user's split-tunnel bypass list (a per-device pref injected at connect), if any.
    let user_bypass = split_tunnel
        .and_then(|j| crate::split_tunnel::parse(j).ok())
        .filter(|s| s.enabled && !s.is_empty());
    let has_rules = !sr.rule_sets.is_empty() || !sr.inline_ip_rules.is_empty();
    let (hooks, dns_server) = if !has_rules && user_bypass.is_none() {
        (None, None) // no fetched rules and no bypass — proxy everything (today's path)
    } else {
        let router = crate::rules::router::Router::build(sr, |r| {
            // Go through the shared, tag-sanitizing cache_path so a fetched tag can't traverse out of
            // the rulesets dir (path-traversal hardening — matches the fetcher's write path).
            let dir = data_dir?;
            std::fs::read(crate::rules::ruleset::cache_path(dir, &r.tag)).ok()
        });
        router.set_user_bypass(user_bypass.as_ref());
        router.set_mode(crate::routing_mode::parse(routing_mode.unwrap_or("smart")));
        // App split tunneling (macOS): install the process resolver so a flow can be attributed to
        // its owning executable and routed Direct if that exe is on the app-bypass list. Set on the
        // same `router` instance later stashed into `active_router()`, before the `Arc` wrap. The
        // resolver only runs when the app-bypass list is non-empty (`set_app_bypass`), so it's inert
        // until the NE pushes a list. Non-macOS builds skip this (no backend until P4).
        #[cfg(target_os = "macos")]
        router.set_process_resolver(Some(std::sync::Arc::new(
            crate::process::CachingResolver::new(std::time::Duration::from_secs(3), 1024),
        )));
        let router = Arc::new(router);
        set_active_router(Some(router.clone()));
        // Clone for the DNS ad-block check before `router` is moved into the flow hooks below.
        // Blocking ad domains at DNS (NODATA, no fake IP) means the browser never opens a flow
        // for them at all — cheaper than a flow-level Reject and it doesn't churn the netstack's
        // socket set (which was stalling legit flows on ad-heavy pages).
        let ad_block_router = router.clone();
        // One pool: the DNS server allocates on query, the recoverer recovers on connect.
        let pool = dns::server::shared_pool(FAKEIP_TTL, FAKEIP_CAP);
        // Per-action resolvers from the config's `options.dns`: `dns_local` (direct, best-local) for
        // the Direct action, `dns_remote` + the resilient pool for the Proxy client-side fallback.
        // The proxyless transport for `Action::Proxyless` flows (ADR 0014), built only when
        // `[transport.proxyless]` is configured. `None` makes such flows reject rather than silently
        // downgrade — see `proxy::Decision::Proxyless`.
        let (proxyless_transport, proxyless_udp) = transport::proxyless_pair(config);
        let hooks = Arc::new(proxy::RouteHooks {
            router: router as Arc<dyn proxy::FlowRouter>,
            recoverer: Some(Arc::new(dns::server::FakeIpRecoverer::new(pool.clone()))),
            direct_resolver: dns::resolver::direct_resolver(&config.dns),
            proxy_resolver: dns::resolver::proxy_resolver(&config.dns),
            proxyless_transport,
            proxyless_udp,
        });
        let dns_server = Arc::new(
            dns::server::DnsServer::new(pool, DNS_ANSWER_TTL_SECS)
                .with_ad_block(Arc::new(move |d: &str| ad_block_router.is_ad_blocked(d))),
        );
        info!(
            rule_sets = sr.rule_sets.len(),
            inline_ip_rules = sr.inline_ip_rules.len(),
            user_bypass = user_bypass
                .as_ref()
                .map_or(0, |s| s.domains.len() + s.ips.len()),
            "smart-routing: fake-IP DNS + per-flow route hooks active"
        );
        (Some(hooks), Some(dns_server))
    };

    if let Some((udp_inbound, udp_reply)) = udp_surface {
        match dns_server {
            // Interpose the DNS interceptor between the netstack and the UDP proxy: `:53` → fake-IP
            // server (replies on `udp_reply`), everything else → `run_udp` via a fresh channel.
            Some(server) => {
                let (forward_tx, forward_rx) = tokio::sync::mpsc::channel(DNS_FORWARD_DEPTH);
                tokio::spawn(dns_intercept(
                    udp_inbound,
                    forward_tx,
                    udp_reply.clone(),
                    server,
                ));
                tokio::spawn(proxy::udp::run_udp(
                    forward_rx,
                    udp_reply,
                    udp_transport,
                    direct_udp,
                    hooks.clone(),
                    idle,
                ));
            }
            None => {
                tokio::spawn(proxy::udp::run_udp(
                    udp_inbound,
                    udp_reply,
                    udp_transport,
                    direct_udp,
                    hooks.clone(),
                    idle,
                ));
            }
        }
    }
    hooks
}

/// Without `smart-routing`: no route hooks, and the plain UDP proxy (today's behavior).
#[cfg(not(feature = "smart-routing"))]
#[allow(clippy::too_many_arguments)]
fn setup_routing_and_udp(
    _config: &Config,
    _data_dir: Option<&std::path::Path>,
    _split_tunnel: Option<&str>,
    _routing_mode: Option<&str>,
    udp_surface: Option<netstack::UdpSurface>,
    udp_transport: Arc<dyn transport::UdpTransport>,
    direct_udp: Arc<dyn transport::UdpTransport>,
    idle: Duration,
) -> Option<Arc<proxy::RouteHooks>> {
    if let Some((udp_inbound, udp_reply)) = udp_surface {
        tokio::spawn(proxy::udp::run_udp(
            udp_inbound,
            udp_reply,
            udp_transport,
            direct_udp,
            None,
            idle,
        ));
    }
    None
}

/// Peel DNS (any `:53` UDP) off the netstack's inbound stream and answer it locally with fake IPs
/// (replying on `reply`); forward every other datagram to the UDP proxy via `forward`. An unparseable
/// query is dropped (no reply). Ends when either channel closes (teardown).
#[cfg(feature = "smart-routing")]
async fn dns_intercept(
    mut inbound: tokio::sync::mpsc::Receiver<netstack::UdpDatagram>,
    forward: tokio::sync::mpsc::Sender<netstack::UdpDatagram>,
    reply: tokio::sync::mpsc::Sender<netstack::UdpDatagram>,
    server: Arc<dns::server::DnsServer>,
) {
    while let Some(dgram) = inbound.recv().await {
        if dgram.original_dst.port() == 53 {
            if let Some(payload) = server.handle(&dgram.payload) {
                // The netstack writes the reply as src=original_dst, dst=client_src, so the app sees
                // the answer coming from the DNS server it queried — keep both fields as received.
                let reply_dgram = netstack::UdpDatagram {
                    client_src: dgram.client_src,
                    original_dst: dgram.original_dst,
                    payload,
                };
                if reply.send(reply_dgram).await.is_err() {
                    break; // netstack reply channel closed (teardown)
                }
            }
        } else if forward.send(dgram).await.is_err() {
            break; // UDP proxy gone (teardown)
        }
    }
}

/// `lantern-api` self-fetch entry (shared by every platform's [`run_fd_dispatch`]): fetch the boot
/// config from the Lantern API (cache-first, retrying on cold-start offline until a config is obtained
/// or stop is signalled), spawn the background refresh loop (warms the on-disk cache; no live pool
/// swap in v1), then run the tunnel. Blocks until stop; `0` clean, `-1` on error. `data_dir` is the
/// per-platform cache dir (Apple app-group container, Android app files dir). `tun_base` supplies the
/// platform's `tun`/stack — the fetched `config_raw.json` is a server pool with no meaningful tun
/// section, so the platform owns the interface reality (Apple = userspace, Android = system stack).
/// `split_tunnel` is the raw JSON `{enabled,domains,ips}` payload to apply as the initial user bypass
/// list; `None` means no bypass list.
#[cfg(feature = "config-fetch")]
pub fn run_fd_lantern_api(
    fd: i32,
    mtu: u16,
    data_dir: std::path::PathBuf,
    tun_base: Config,
    split_tunnel: Option<&str>,
    routing_mode: Option<&str>,
    identity: Option<crate::config::fetch::Identity>,
) -> i32 {
    use crate::config::fetch::{self, FetchEnv};

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(TUNNEL_WORKER_THREADS)
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
        // Tunnel-process diagnostics (design §5 Phase B-lite): full loop — sink +
        // panic hook + unclean-exit sentinel + uploader fed by this process's own
        // config cache. `data_dir` here IS the tunnel's cache dir: it came down from
        // `spark_tunnel_run(data_dir)` → `run_fd_dispatch` and is the same dir
        // `load_or_fetch`/`run_loop` below cache `device_id` + `config_raw.json`
        // into, so diag identity matches this process's config identity. Placed
        // inside `block_on` because init spawns (sink writer, re-parse task,
        // uploader) and needs the ambient runtime.
        //
        // macOS NE **and** the Android `:vpn` process — both are the tunnel process on
        // their platform, and both self-fetch here, so both have the config cache the
        // uploader reads its endpoint from. Windows/Linux run the desktop service
        // instead, which does its own wiring.
        //
        // Android was previously deferred over "battery/consent posture". Consent was
        // never an Android-specific question — it is one shared gate for every host
        // (#168). Battery is real but small, and bounded by where this runs: the
        // `:vpn` process only exists while the tunnel is up, so the uploader cannot
        // outlive a connected session, and its 60 s tick does no network work at all
        // when the spool is empty. Against that, the whole point of this telemetry is
        // a field-optimization loop, and a loop blind to the platform with the least
        // visibility into its own failures is the wrong trade.
        #[cfg(all(
            feature = "config-fetch",
            any(target_os = "macos", target_os = "android")
        ))]
        crate::diag::tunnel_host::init(
            &data_dir,
            env!("CARGO_PKG_VERSION"),
            identity.as_ref().map(|i| i.device_id.as_str()),
        );

        // Every fetch in this process — the connect fetch below and the refresh loop further down —
        // runs as the supplied identity when the app handed one over, so the tunnel never registers a
        // second account. Without one, the historical dir-backed behaviour stands (Android, CLI).
        let env = match &identity {
            Some(id) => FetchEnv::from_env().with_identity(id.clone()),
            None => FetchEnv::from_env(),
        };
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
                // Android needs no pinning: the VpnService excludes this app's own UID from the
                // tunnel (`addDisallowedApplication(<self>)`), which covers UDP/QUIC as well as
                // TCP, so the proxy's upstream dials already bypass it. `default_physical_interface`
                // is a hardcoded `None` off macOS/Windows, so warning here fired on EVERY Android
                // and Linux run and claimed something false — it read as evidence that hysteria2 was
                // broken on Android when it is not. Verified on an emulator: QUIC connects, `/auth`
                // returns `udp=true`, and the health probe answers 200 in ~600 ms.
                #[cfg(target_os = "android")]
                None => tracing::debug!(
                    "lantern-api: no interface pinning on Android; app-UID exclusion already bypasses the tunnel"
                ),
                #[cfg(not(target_os = "android"))]
                None => warn!(
                    "lantern-api: no physical interface found to pin to; UDP/QUIC transports may not egress"
                ),
            }
        }
        info!(
            servers = config.transport.servers.len(),
            "lantern-api: boot config ready, bringing tunnel up"
        );
        // Background refresh: on each new config, live-reload the running server pool (new servers
        // get probed + surfaced without a reconnect; the best prior working proxy is retained) and
        // warm the cache for the next connect. Ends when stop fires.
        let loop_dir = data_dir.clone();
        let loop_stop = Arc::clone(&waiter);
        // A fetched config carries no `protect_interface`; reuse the one discovered at bringup so a
        // rebuilt pool pins its sockets identically (UDP/QUIC tunnel bypass, above).
        let reload_iface = config.transport.protect_interface.clone();
        // Same identity as the connect fetch — a refresh that re-derived it would reintroduce exactly
        // the second account this is removing.
        let loop_identity = identity.clone();
        tokio::spawn(async move {
            let env = match loop_identity {
                Some(id) => FetchEnv::from_env().with_identity(id),
                None => FetchEnv::from_env(),
            };
            let on_config = move |mut cfg: Config| {
                cfg.transport.protect_interface = reload_iface.clone();
                // No live pool (direct/tunnel/single-transport) → the refresh still warmed the
                // on-disk cache for the next connect, as before.
                if let Some(pool) = current_pool() {
                    match pool.reload_from_config(&cfg) {
                        Ok(()) => info!(
                            servers = cfg.transport.servers.len(),
                            "config-fetch: live-reloaded the server pool"
                        ),
                        Err(e) => warn!(
                            error = %e,
                            "config-fetch: pool reload failed; keeping the current pool"
                        ),
                    }
                }
            };
            tokio::select! {
                _ = fetch::run_loop(&loop_dir, &env, on_config, || false) => {}
                _ = loop_stop.notified() => {}
            }
        });
        // Smart-routing: keep the `.srs` rule-set cache warm in the background, fetched through the
        // embedded domain-fronting config (censorship-resilient), next to the config refresh. Only
        // stale lists are re-fetched. Rules apply on the next connect (this warms the on-disk cache;
        // no live router swap in v1, mirroring the config pool).
        #[cfg(feature = "smart-routing")]
        if !config.smart_routing.rule_sets.is_empty() {
            match crate::rules::ruleset::FrontedRuleSetFetcher::new() {
                Some(fetcher) => {
                    let fetcher: Arc<dyn crate::rules::ruleset::RuleSetFetcher> = Arc::new(fetcher);
                    info!(
                        rule_sets = config.smart_routing.rule_sets.len(),
                        "lantern-api: starting rule-set refresh (fronted)"
                    );
                    tokio::spawn(crate::rules::ruleset::run_refresh_loop(
                        fetcher,
                        data_dir.clone(),
                        config.smart_routing.clone(),
                        RULESET_REFRESH_INTERVAL,
                        Arc::clone(&waiter),
                    ));
                }
                None => warn!("rule-set refresh skipped: embedded fronted config failed to parse"),
            }
        }
        run_tunnel_data_path(fd, mtu, config, Some(data_dir.as_path()), split_tunnel, routing_mode, &waiter).await
    });
    deregister(&stop);
    set_pool(None);
    #[cfg(feature = "smart-routing")]
    set_active_router(None);
    set_ready(Readiness::Down);
    // Controlled exit of the tunnel loop (Ok or Err — either way the teardown path
    // ran and any error was already logged/captured above): disarm the unclean-exit
    // sentinel so this return isn't flagged as a crash on the next launch. Belt and
    // suspenders with the disarm in `spark_tunnel_stop` — the NE host usually stops
    // us via stop(), but this covers a data path that ends on its own.
    //
    // On Android this is the ONLY disarm: `nativeStop` signals the run loop rather
    // than tearing down itself, so the loop's own exit is where an orderly stop is
    // observed. It must stay paired with the init above — a gate widened on one and
    // not the other turns every clean Android stop into a false `error.unclean_exit`
    // on the next launch.
    #[cfg(all(
        feature = "config-fetch",
        any(target_os = "macos", target_os = "android")
    ))]
    crate::diag::tunnel_host::disarm_sentinel();
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
    // Clear the live router handle so set_split_tunnel no-ops immediately after stop() is called,
    // even before the tunnel thread's own teardown runs set_active_router(None).
    #[cfg(feature = "smart-routing")]
    set_active_router(None);
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
        // `None` split-tunnel / routing-mode: the in-process/desktop-service embedder path
        // doesn't plumb these yet (only the mobile/C-ABI `run_fd_dispatch` path does). Add
        // slots to `TunnelHandle` if this path ever needs them.
        if let Err(e) = run_with_handle(fd, mtu, config, None, None, stop_thread) {
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

        // run_fd_dispatch fail-closed routing: on the config-fetch slice, lantern-api self-fetch needs
        // a data dir; with none it must close the (transferred) fd and return -1 rather than run. This
        // lives here (not a separate test) because abandon_fd touches the readiness global — keeping it
        // in the readiness-owning test avoids an inter-test race. (The self-fetch-success / relay /
        // full-config branches need a live TUN + runtime; the parse decision is covered by
        // `explicit_config_maps_each_kind_onto_the_platform_tun`.) Unix-gated: it uses `/dev/null` +
        // `libc::open`/fd semantics, and the fd-shim platforms that reach this path (iOS/macOS/Android)
        // are all Unix — there's no point running it on the Windows `--all-features` test job.
        #[cfg(all(feature = "config-fetch", unix))]
        {
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            assert!(fd >= 0, "open /dev/null for the dispatch fail-closed check");
            assert_eq!(
                run_fd_dispatch(fd, 1500, None, None, Config::default(), None, None, None),
                -1,
                "self-fetch with no data_dir must fail closed"
            );
        }

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

        // bare IP:port → plain relay, platform tun preserved.
        let relay = explicit_config("192.0.2.7:9000", &base).expect("IP:port is a relay");
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

        // junk that is neither IP:port nor a valid config → None (the shim fails closed).
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

    /// The DNS interceptor answers `:53` locally with a fake IP (allocating a pool mapping) and
    /// forwards non-DNS datagrams to the UDP proxy untouched.
    #[cfg(feature = "smart-routing")]
    #[tokio::test]
    async fn dns_intercept_answers_53_and_forwards_the_rest() {
        use crate::netstack::UdpDatagram;

        // A minimal A-query for `name` (one question, no compression).
        fn a_query(name: &str) -> Vec<u8> {
            let mut b = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            for label in name.split('.') {
                b.push(label.len() as u8);
                b.extend_from_slice(label.as_bytes());
            }
            b.push(0);
            b.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
            b.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
            b
        }

        let (in_tx, in_rx) = tokio::sync::mpsc::channel(8);
        let (fwd_tx, mut fwd_rx) = tokio::sync::mpsc::channel(8);
        let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel(8);
        let pool = dns::server::shared_pool(Duration::from_secs(300), 100);
        let server = Arc::new(dns::server::DnsServer::new(Arc::clone(&pool), 30));
        tokio::spawn(dns_intercept(in_rx, fwd_tx, reply_tx, server));

        // A DNS query to :53 → answered locally; a fake IP is allocated and a reply is returned to
        // the querying app (same client_src/original_dst so the netstack sources it from the server).
        in_tx
            .send(UdpDatagram {
                client_src: "10.0.0.2:5000".parse().unwrap(),
                original_dst: "8.8.8.8:53".parse().unwrap(),
                payload: a_query("example.com"),
            })
            .await
            .unwrap();
        let reply = reply_rx.recv().await.expect("a DNS reply");
        assert_eq!(reply.original_dst, "8.8.8.8:53".parse().unwrap());
        assert_eq!(reply.client_src, "10.0.0.2:5000".parse().unwrap());
        assert_eq!(
            u16::from_be_bytes([reply.payload[6], reply.payload[7]]),
            1,
            "one A answer"
        );
        assert_eq!(pool.lock().unwrap().len(), 1, "a fake IP was allocated");

        // A non-DNS datagram (:443) → forwarded to the UDP proxy untouched, no reply.
        in_tx
            .send(UdpDatagram {
                client_src: "10.0.0.2:5001".parse().unwrap(),
                original_dst: "1.2.3.4:443".parse().unwrap(),
                payload: vec![9, 9, 9],
            })
            .await
            .unwrap();
        let fwd = fwd_rx.recv().await.expect("a forwarded datagram");
        assert_eq!(fwd.original_dst, "1.2.3.4:443".parse().unwrap());
        assert_eq!(fwd.payload, vec![9, 9, 9]);
    }
}
