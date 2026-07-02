//! `dns-tunnel-server` — the authoritative-side server binary for spark's DNS-tunnel transport
//! (ADR 0011). Binds a UDP endpoint and relays tunnelled TCP through real egress connections.

use clap::Parser;
use dns_tunnel_core::crypto;
use dns_tunnel_core::session::Config;
use dns_tunnel_server::{serve, ServerConfig};
use tokio::net::UdpSocket;

#[derive(Parser)]
#[command(about = "spark DNS-tunnel server (ADR 0011)")]
struct Args {
    /// Delegated tunnel zone (the NS-delegated subdomain), e.g. `t.example.com`.
    #[arg(long)]
    zone: String,
    /// Pre-shared key, base64 (decoded length >= 32 bytes).
    #[arg(long)]
    psk: String,
    /// UDP address to bind (the tunnel endpoint; front with `iptables` from :53 in production).
    #[arg(long, default_value = "0.0.0.0:5300")]
    bind: String,
    /// Idle session timeout, in seconds.
    #[arg(long, default_value_t = 300)]
    idle_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let psk = crypto::decode_psk(&args.psk)?;
    let udp = UdpSocket::bind(&args.bind).await?;
    // Log hygiene: report readiness without the zone or bind address.
    tracing::info!("dns-tunnel-server listening");

    let cfg = ServerConfig {
        zone: args.zone,
        psk,
        session: Config::default(),
        idle_timeout_ms: args.idle_secs.saturating_mul(1000),
    };
    serve(udp, cfg).await?;
    Ok(())
}
