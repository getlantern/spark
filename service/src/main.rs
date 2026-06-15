//! `spark-service` — the privileged tunnel daemon.
//!
//! Owns the TUN device + the core, and serves an unprivileged client over a unix-socket
//! control channel authenticated by peer credentials. Run it privileged (the device + routes
//! need it); the client is `spark` in client mode.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use spark_core::config::Config;
use spark_service::auth::AuthPolicy;
use spark_service::engine::CoreEngine;
use spark_service::listener::serve;
use spark_service::service::{channel, run_service};
use tokio::net::UnixListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// The privileged spark tunnel daemon.
#[derive(Parser, Debug)]
#[command(name = "spark-service", version, about)]
struct Args {
    /// Path of the control socket to listen on.
    #[arg(long, default_value = "/var/run/spark.sock")]
    socket: PathBuf,

    /// TOML config for the tunnel (TUN settings + transport). Defaults are used if omitted.
    #[arg(long)]
    config: Option<PathBuf>,

    /// gid of the `spark` group permitted to control the daemon (besides root). When unset,
    /// only root may connect.
    #[arg(long)]
    spark_gid: Option<u32>,

    /// Physical interface to pin upstream sockets to (e.g. `en0`), so the daemon's own dials
    /// bypass the tunnel route. Overrides `[transport] protect_interface` from the config.
    /// Required on macOS to forward without a routing loop.
    #[arg(long)]
    protect_interface: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let mut config = match &args.config {
        Some(path) => Config::from_path(path)
            .with_context(|| format!("loading config from {}", path.display()))?,
        None => Config::default(),
    };
    // A `--protect-interface` flag overrides the config field for convenience.
    if args.protect_interface.is_some() {
        config.transport.protect_interface = args.protect_interface.clone();
    }

    // The event loop owns the engine + tunnel state; connections talk to it over `cmd_tx`.
    let fail_closed = config.kill_switch.fail_closed;
    let (cmd_tx, cmd_rx) = channel();
    tokio::spawn(run_service(CoreEngine::new(config), cmd_rx, fail_closed));

    let policy = AuthPolicy {
        spark_gid: args.spark_gid,
        allow_uids: Vec::new(),
    };

    // Clear any stale socket and make sure the parent directory exists.
    if let Some(parent) = args.socket.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&args.socket);
    let listener = UnixListener::bind(&args.socket)
        .with_context(|| format!("binding control socket {}", args.socket.display()))?;
    // The OS enforces connect permission on the socket file, so the daemon (running
    // privileged) must open it up to the authorized peers: group `spark_gid` + mode 0660.
    // peer-cred auth in `serve` remains the authoritative check (don't trust perms alone).
    secure_socket(&args.socket, args.spark_gid)
        .with_context(|| format!("securing control socket {}", args.socket.display()))?;
    info!(socket = %args.socket.display(), "spark-service listening for control connections");

    serve(listener, policy, cmd_tx)
        .await
        .context("control listener failed")?;
    Ok(())
}

/// Restrict the control socket to root + the `spark` group: chown its group to `group` (when
/// set) and set mode `0660`. The connecting peer is still authenticated by `SO_PEERCRED`
/// (see `serve`); this is the filesystem layer of defense.
#[cfg(unix)]
fn secure_socket(path: &std::path::Path, group: Option<u32>) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    if let Some(gid) = group {
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "socket path contains a NUL",
            )
        })?;
        // SAFETY: `cpath` is a valid NUL-terminated path for the call; owner `u32::MAX` (-1)
        // leaves the owner unchanged and only sets the group.
        let rc = unsafe { libc::chown(cpath.as_ptr(), u32::MAX, gid) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
}

#[cfg(not(unix))]
fn secure_socket(_path: &std::path::Path, _group: Option<u32>) -> std::io::Result<()> {
    Ok(())
}
