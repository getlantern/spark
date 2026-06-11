//! `spark` CLI driver.
//!
//! M1: bring up a TUN device, read IP packets, log each one, and answer ICMP echo
//! requests — the liveness proof that the TUN data path works end to end. Routing real
//! traffic through the netstack arrives at M2.
//!
//! Log hygiene (a product privacy property, see `docs/GOAL.md`): at the default level we
//! log only the protocol and length. Source/destination addresses are logged at `debug`
//! only. Run with `RUST_LOG=debug` (or `--debug`) to see them during the ping test.

use std::net::Ipv4Addr;

use anyhow::Context;
use clap::Parser;
use spark_core::packet::{icmp_echo_reply, protocol_name, IpPacket};
use spark_core::tun::{Tun, TunConfig};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

/// A from-scratch multi-protocol VPN/proxy tunnel (M1: TUN scaffold).
#[derive(Parser, Debug)]
#[command(name = "spark", version, about)]
struct Cli {
    /// Requested TUN device name (the OS may assign a different one).
    #[arg(long)]
    name: Option<String>,

    /// IPv4 address to assign to the TUN interface.
    #[arg(long, default_value = "10.0.0.1")]
    addr: Ipv4Addr,

    /// IPv4 prefix length for the interface address.
    #[arg(long, default_value_t = 24)]
    prefix: u8,

    /// MTU for the TUN interface (defaults to the device's own MTU when unset).
    #[arg(long)]
    mtu: Option<u16>,

    /// Log destination addresses too (equivalent to `RUST_LOG=debug`). Off by default
    /// for log hygiene.
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.debug);

    let tun = Tun::open(TunConfig {
        name: cli.name.clone(),
        ipv4: (cli.addr, cli.prefix),
        mtu: cli.mtu,
    })
    .context("bringing up the TUN device")?;

    let name = tun.name().context("reading TUN device name")?;
    let mtu = tun.mtu();
    info!(device = %name, mtu, addr = %cli.addr, "TUN up — replying to ICMP echo; Ctrl-C to stop");

    // One reusable read buffer sized to the MTU; no per-packet allocation on the hot path.
    let mut buf = vec![0u8; mtu];
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
            result = tun.recv(&mut buf) => {
                match result {
                    Ok(n) => handle_packet(&buf[..n], &tun).await,
                    Err(e) => warn!(error = %e, "TUN recv failed"),
                }
            }
        }
    }
    Ok(())
}

/// Log a received packet (hygienically) and answer it if it's an ICMP echo request.
async fn handle_packet(pkt: &[u8], tun: &Tun) {
    let Some(ip) = IpPacket::parse(pkt) else {
        debug!(len = pkt.len(), "rx: unparseable / non-IP packet");
        return;
    };

    info!(proto = protocol_name(ip.protocol()), len = ip.len(), "rx");
    debug!(src = %ip.src(), dst = %ip.dst(), "rx addresses");

    if let Some(reply) = icmp_echo_reply(pkt) {
        match tun.send(&reply).await {
            Ok(_) => debug!("tx: ICMP echo reply"),
            Err(e) => warn!(error = %e, "failed to send ICMP echo reply"),
        }
    }
}

/// Initialize tracing. `RUST_LOG` wins if set; otherwise `--debug` selects the `debug`
/// level and the default is `info`.
fn init_tracing(debug: bool) {
    let default = if debug { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
