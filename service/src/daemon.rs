//! The spark-service daemon entry: argument parsing, config loading, and the shared run loop
//! used by both the foreground (console) entry and the Windows service entry ([`crate::winsvc`]).
//!
//! `main.rs` is a thin shim over [`run`]. On Windows, [`run`] first tries to attach to the
//! Service Control Manager; if the process wasn't launched by the SCM it falls back to running
//! the daemon in the foreground (the same path unix always takes).

use std::future::Future;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use spark_core::config::Config;
use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::engine::CoreEngine;
use crate::service::{backend_info, channel, run_service, Envelope};

/// The privileged spark tunnel daemon.
#[derive(Parser, Debug)]
#[command(name = "spark-service", version, about)]
pub struct Args {
    /// Path of the control socket to listen on.
    #[cfg(unix)]
    #[arg(long, default_value = "/var/run/spark.sock")]
    pub socket: PathBuf,

    /// Named pipe to listen on (e.g. `\\.\pipe\spark`).
    #[cfg(windows)]
    #[arg(long, default_value = r"\\.\pipe\spark")]
    pub socket: PathBuf,

    /// TOML config for the tunnel (TUN settings + transport). Defaults are used if omitted.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// gid of the `spark` group permitted to control the daemon (besides root). When unset,
    /// only root may connect. Unix only — on Windows access is controlled by the pipe DACL.
    #[cfg(unix)]
    #[arg(long)]
    pub spark_gid: Option<u32>,

    /// Physical interface to pin upstream sockets to (e.g. `en0`), so the daemon's own dials
    /// bypass the tunnel route. Overrides `[transport] protect_interface` from the config.
    #[arg(long)]
    pub protect_interface: Option<String>,
}

/// Entry point: initialize logging, then — on Windows — run as a service if the SCM launched us;
/// otherwise run the daemon in the foreground until the process is signalled.
pub fn run() -> anyhow::Result<()> {
    init_tracing();

    #[cfg(windows)]
    {
        // If launched by the SCM, this runs the service to completion and returns `true`.
        if crate::winsvc::run_as_service_if_launched_by_scm()? {
            return Ok(());
        }
    }

    let args = Args::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    // Foreground: no in-process shutdown signal — the service supervisor (systemd/launchd)
    // signals the process, which terminates it; routing then reverts via OS device cleanup.
    runtime.block_on(serve_daemon(args, std::future::pending::<()>()))
}

/// Load config, start the control-plane event loop + engine, and serve control connections until
/// `shutdown` resolves (the Windows-service stop signal) or forever (foreground). Shared by both
/// entry points so the daemon body lives in exactly one place.
pub async fn serve_daemon(args: Args, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
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
    let info = backend_info(&config); // capabilities + selected transport/stack for the v2 requests
    let (cmd_tx, cmd_rx) = channel();
    tokio::spawn(run_service(
        CoreEngine::new(config),
        cmd_rx,
        fail_closed,
        info,
    ));

    tokio::pin!(shutdown);
    tokio::select! {
        result = listen(&args, cmd_tx) => result,
        _ = &mut shutdown => {
            // Dropping the `listen` future (and its `cmd_tx`) ends the event loop, which tears
            // the tunnel down on its way out.
            info!("shutdown requested; stopping control listener");
            Ok(())
        }
    }
}

/// Bind the unix control socket (root + `spark` group, mode 0660) and serve it. Peer-cred auth
/// in `serve` is the authoritative check — the perms are the filesystem layer of defense.
#[cfg(unix)]
async fn listen(args: &Args, cmd_tx: mpsc::Sender<Envelope>) -> anyhow::Result<()> {
    use crate::auth::AuthPolicy;
    use crate::serve;
    use tokio::net::UnixListener;

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
    secure_socket(&args.socket, args.spark_gid)
        .with_context(|| format!("securing control socket {}", args.socket.display()))?;
    info!(socket = %args.socket.display(), "spark-service listening for control connections");

    serve(listener, policy, cmd_tx)
        .await
        .context("control listener failed")
}

/// Serve the Windows named pipe. The pipe's admin-only DACL is the authorization boundary
/// (see [`crate::pipe`]); there is no separate peer-credential check.
#[cfg(windows)]
async fn listen(args: &Args, cmd_tx: mpsc::Sender<Envelope>) -> anyhow::Result<()> {
    use crate::serve;

    info!(pipe = %args.socket.display(), "spark-service listening for control connections (named pipe)");
    serve(args.socket.as_os_str(), cmd_tx)
        .await
        .context("control listener failed")
}

/// Restrict the control socket to root + the `spark` group: chown its group to `group` (when
/// set) and set mode `0660`.
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

/// Initialize tracing from `RUST_LOG` (default `info`).
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
