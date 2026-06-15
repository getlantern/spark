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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = match &args.config {
        Some(path) => Config::from_path(path)
            .with_context(|| format!("loading config from {}", path.display()))?,
        None => Config::default(),
    };

    // The event loop owns the engine + tunnel state; connections talk to it over `cmd_tx`.
    let (cmd_tx, cmd_rx) = channel();
    tokio::spawn(run_service(CoreEngine::new(config), cmd_rx));

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
    info!(socket = %args.socket.display(), "spark-service listening for control connections");

    serve(listener, policy, cmd_tx)
        .await
        .context("control listener failed")?;
    Ok(())
}
