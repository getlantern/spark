//! `dns-tunnel-server` — the authoritative-side server binary for spark's DNS-tunnel transport
//! (ADR 0011). `keygen` mints a static Ed25519 identity; `serve` binds a UDP endpoint and relays
//! tunnelled TCP through real egress connections, authenticating each session's forward-secret
//! handshake with the identity's private key. The **public** key is what clients are given.

use clap::{Parser, Subcommand};
use dns_tunnel_core::crypto;
use dns_tunnel_core::session::Config;
use dns_tunnel_server::{export, metrics::Metrics, serve, ServerConfig};
use tokio::net::UdpSocket;

#[derive(Parser)]
#[command(about = "spark DNS-tunnel server (ADR 0011)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a server identity keypair. Prints two lines to stdout: `privkey <base64>` (store this
    /// on the server, keep it secret) and `pubkey <base64>` (distribute to clients).
    Keygen,
    /// Print the public key for an existing private key, so a lost `pubkey` can be recovered from the
    /// server that still holds its `privkey` — without the private half ever leaving the host.
    ///
    /// Every client needs this key to authenticate the server, and before this subcommand existed the
    /// only copy was `keygen`'s output: lose it and the recovery path was to re-run `keygen`, which
    /// mints a *new* identity and orphans every client configured for the old one. Deriving it is
    /// arithmetic (it is the public half of the same Ed25519 pair) — there simply was no command that
    /// did so.
    Pubkey(PubkeyArgs),
    /// Run the tunnel server.
    Serve(ServeArgs),
}

#[derive(Parser)]
struct PubkeyArgs {
    /// Path to the base64 private key (PKCS#8) — the same file `serve --privkey-file` reads.
    #[arg(long)]
    privkey_file: String,
}

#[derive(Parser)]
struct ServeArgs {
    /// Delegated tunnel zone (the NS-delegated subdomain), e.g. `t.example.com`.
    #[arg(long)]
    zone: String,
    /// Path to a file holding the base64 server private key (PKCS#8) from `keygen`.
    #[arg(long)]
    privkey_file: String,
    /// UDP address to bind (front with `iptables` from :53 in production).
    #[arg(long, default_value = "0.0.0.0:5300")]
    bind: String,
    /// Idle session timeout, in seconds.
    #[arg(long, default_value_t = 300)]
    idle_secs: u64,
    /// OTLP collector host, e.g. `ingest.us.signoz.cloud`. **Telemetry is off unless this is set** —
    /// without it the server opens no outbound connections at all.
    #[arg(long)]
    otel_host: Option<String>,
    /// OTLP collector port.
    #[arg(long, default_value_t = 443)]
    otel_port: u16,
    /// Ingestion key, sent as `signoz-ingestion-key`.
    ///
    /// Read from the environment in production so it never appears in a process listing or a shell
    /// history — the systemd unit sources it from a root-only `EnvironmentFile`.
    #[arg(long)]
    otel_key: Option<String>,
    /// Opaque label distinguishing this server on a dashboard.
    ///
    /// Operator-chosen and deliberately not defaulted to the hostname or zone: the label lands in
    /// every exported series, and a zone-derived one would publish the tunnel's location to everyone
    /// with dashboard access.
    #[arg(long, default_value = "dns-tunnel")]
    otel_instance: String,
    /// Seconds between metric exports.
    #[arg(long, default_value_t = 60)]
    otel_interval_secs: u64,
}

/// An environment variable, treating unset and empty as equally absent.
///
/// Empty matters: a systemd `Environment=` line for an unconfigured key yields `""`, and an empty
/// string here would otherwise enable export against a hostless endpoint or send a blank auth header.
fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// A numeric environment variable, falling back to `flag` when unset, empty, or unparseable.
///
/// Unparseable falls back rather than failing: a typo in a systemd `Environment=` line should cost
/// the default export interval, not prevent the tunnel from starting. The tunnel is the product;
/// telemetry misconfiguration must never be able to take it down.
fn env_num<T: std::str::FromStr>(key: &str, flag: T) -> T {
    match env_opt(key).map(|v| v.trim().parse::<T>()) {
        Some(Ok(v)) => v,
        Some(Err(_)) => {
            tracing::warn!(
                key,
                "ignoring unparseable numeric env var, using the default"
            );
            flag
        }
        None => flag,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match Cli::parse().cmd {
        Cmd::Keygen => {
            let pkcs8 = crypto::ServerStatic::generate()?;
            let pubkey = crypto::server_public_from_pkcs8(&pkcs8)?;
            // stdout, parseable. The privkey is secret — never log it.
            println!("privkey {}", crypto::base64_encode(&pkcs8));
            println!("pubkey {}", crypto::base64_encode(&pubkey));
        }
        Cmd::Pubkey(a) => {
            let privb64 = std::fs::read_to_string(&a.privkey_file)?;
            let pkcs8 = crypto::base64_decode(privb64.trim())
                .ok_or_else(|| anyhow::anyhow!("privkey file is not valid base64"))?;
            let pubkey = crypto::server_public_from_pkcs8(&pkcs8)?;
            // Only the public half is printed; the private key is read and dropped.
            println!("pubkey {}", crypto::base64_encode(&pubkey));
        }
        Cmd::Serve(a) => {
            let privb64 = std::fs::read_to_string(&a.privkey_file)?;
            let privkey = crypto::base64_decode(privb64.trim())
                .ok_or_else(|| anyhow::anyhow!("privkey file is not valid base64"))?;
            let udp = UdpSocket::bind(&a.bind).await?;
            // Log hygiene: report readiness without the zone or bind address.
            tracing::info!("dns-tunnel-server listening");

            // Env fallback is resolved here rather than via clap's `env` feature: that feature
            // would have to be enabled on the *workspace* clap, and cargo's feature unification
            // would then pull it into the client binaries the <3 MB size budget guards.
            let otel_host = a.otel_host.or_else(|| env_opt("SPARK_OTEL_HOST"));
            // The key comes from the environment in production so it never lands in a process
            // listing or a shell history; the systemd unit sources it from a root-only file.
            let otel_key = a.otel_key.or_else(|| env_opt("SPARK_OTEL_INGEST_KEY"));
            let otel_instance = env_opt("SPARK_OTEL_INSTANCE").unwrap_or(a.otel_instance);
            let otel_port = env_num("SPARK_OTEL_PORT", a.otel_port);
            let otel_interval_secs = env_num("SPARK_OTEL_INTERVAL_SECS", a.otel_interval_secs);

            let metrics = std::sync::Arc::new(Metrics::new());
            // Held so the exporter is cancelled with the process rather than detached (CLAUDE.md:
            // no `tokio::spawn` whose handle is dropped unless the task is genuinely fire-and-forget).
            let _exporter = otel_host.map(|host| {
                tracing::info!(interval_secs = otel_interval_secs, "metrics export enabled");
                export::spawn(
                    std::sync::Arc::clone(&metrics),
                    export::ExportConfig {
                        host,
                        port: otel_port,
                        key: otel_key,
                        instance: otel_instance,
                        interval: std::time::Duration::from_secs(otel_interval_secs.max(1)),
                    },
                )
            });

            serve(
                udp,
                ServerConfig {
                    zone: a.zone,
                    privkey,
                    session: Config::default(),
                    idle_timeout_ms: a.idle_secs.saturating_mul(1000),
                },
                metrics,
            )
            .await?;
        }
    }
    Ok(())
}
