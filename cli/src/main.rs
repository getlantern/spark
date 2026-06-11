//! `spark` CLI driver.
//!
//! Bring up a TUN device, bridge it into the userspace netstack, and forward every
//! accepted TCP flow to its original destination. With `--server <addr>` the flows are
//! routed through a tunnel server (M4); without it, they are dialed directly (the M2
//! behavior). With a route installed pointing traffic at the device,
//! `curl --interface <tun> https://1.1.1.1` flows end to end.
//!
//! Log hygiene (a product privacy property, see `docs/GOAL.md`): the default level logs
//! only non-identifying facts (device, MTU, byte counts). Source/destination addresses
//! are logged at `debug` only. Run with `RUST_LOG=debug` (or `--debug`) to see them.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use spark_core::netstack::SmoltcpNetstack;
use spark_core::proxy;
use spark_core::transport::tcp_tunnel::client::TunnelClient;
use spark_core::transport::{DirectTransport, Transport, UdpTransport};
use spark_core::tun::{Tun, TunConfig};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// A from-scratch multi-protocol VPN/proxy tunnel.
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

    /// Tunnel server address (`host:port`). When set, flows are tunneled through it;
    /// when omitted, flows are dialed directly to their original destination.
    #[arg(long)]
    server: Option<SocketAddr>,

    /// Log source/destination addresses too (equivalent to `RUST_LOG=debug`). Off by
    /// default for log hygiene.
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.debug);

    let tun = Arc::new(
        Tun::open(TunConfig {
            name: cli.name.clone(),
            ipv4: (cli.addr, cli.prefix),
            mtu: cli.mtu,
        })
        .context("bringing up the TUN device")?,
    );

    let name = tun.name().context("reading TUN device name")?;
    let mtu = tun.mtu();

    // One underlying transport serves both the TCP and UDP forwarders.
    let (tcp_transport, udp_transport): (Arc<dyn Transport>, Arc<dyn UdpTransport>) = match cli
        .server
    {
        Some(server) => {
            info!(device = %name, mtu, addr = %cli.addr, %server, "TUN up — tunneling TCP+UDP through server; Ctrl-C to stop");
            let client = Arc::new(TunnelClient::new(server));
            let tcp: Arc<dyn Transport> = client.clone();
            let udp: Arc<dyn UdpTransport> = client;
            (tcp, udp)
        }
        None => {
            info!(device = %name, mtu, addr = %cli.addr, "TUN up — forwarding TCP+UDP directly (no tunnel); Ctrl-C to stop");
            let direct = Arc::new(DirectTransport);
            let tcp: Arc<dyn Transport> = direct.clone();
            let udp: Arc<dyn UdpTransport> = direct;
            (tcp, udp)
        }
    };

    let mut netstack = SmoltcpNetstack::new(Arc::clone(&tun)).context("starting the netstack")?;

    // Drive the UDP path on the netstack's UDP surface (taken before the netstack moves into
    // the TCP accept loop).
    if let Some((udp_inbound, udp_reply)) = netstack.take_udp() {
        tokio::spawn(proxy::udp::run_udp(
            udp_inbound,
            udp_reply,
            udp_transport,
            proxy::udp::DEFAULT_IDLE_TIMEOUT,
        ));
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
        }
        _ = proxy::tcp::run(netstack, tcp_transport) => {
            warn!("netstack accept loop exited unexpectedly");
        }
    }
    Ok(())
}

/// Initialize tracing. `RUST_LOG` wins if set; otherwise `--debug` selects the `debug`
/// level and the default is `info`.
fn init_tracing(debug: bool) {
    let default = if debug { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
