//! `spark-wasm-server` — the exit side of spark's dynamic WASM transports (ADR 0013 §7).
//!
//! Argument parsing only; everything it does lives in the library beside this file so the wiring is
//! reachable from tests rather than only from a running process.

use anyhow::Result;
use clap::Parser;
use wasm_server::{install, serve, serve_bitcoin, Cli, Cmd};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            match cli.cmd {
                Cmd::Install(a) => install(a),
                Cmd::Serve(a) => serve(a).await,
                Cmd::ServeBitcoin(a) => serve_bitcoin(a).await,
            }
        })
}
