//! `spark-wasm-server` — the exit side of spark's dynamic WASM transports (ADR 0013 §7).
//!
//! Argument parsing only; everything it does lives in the library beside this file so the wiring is
//! reachable from tests rather than only from a running process.

use clap::Parser;
use wasm_server::{install, serve, serve_bitcoin, Cli, Cmd, ServerError};

fn main() -> Result<(), ServerError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    // Returning the library's own error rather than wrapping it in `anyhow`: there is exactly one
    // caller, and `ServerError`'s `Display` already says what failed and why.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| ServerError::Io {
            context: "starting the tokio runtime".to_owned(),
            source: e,
        })?
        .block_on(async {
            match cli.cmd {
                Cmd::Install(a) => install(a),
                Cmd::Serve(a) => serve(a).await,
                Cmd::ServeBitcoin(a) => serve_bitcoin(a).await,
            }
        })
}
