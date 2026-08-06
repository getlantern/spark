//! `dns-tunnel-server` — the authoritative-side server binary for spark's DNS-tunnel transport
//! (ADR 0011). `keygen` mints a static Ed25519 identity; `serve` binds a UDP endpoint and relays
//! tunnelled TCP through real egress connections, authenticating each session's forward-secret
//! handshake with the identity's private key. The **public** key is what clients are given.

use clap::{Parser, Subcommand};
use dns_tunnel_core::crypto;
use dns_tunnel_core::session::Config;
use dns_tunnel_server::{serve, ServerConfig};
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
    /// The public key is not derivable by any other means once the `keygen` output is gone, and every
    /// client needs it to authenticate this server. Re-running `keygen` would mint a *new* identity
    /// and orphan every client already configured for the old one.
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
            serve(
                udp,
                ServerConfig {
                    zone: a.zone,
                    privkey,
                    session: Config::default(),
                    idle_timeout_ms: a.idle_secs.saturating_mul(1000),
                },
            )
            .await?;
        }
    }
    Ok(())
}
