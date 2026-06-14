//! `spark` CLI driver.
//!
//! Bring up a TUN device, bridge it into the userspace netstack, and forward TCP and UDP
//! flows to their original destinations — directly, or through a tunnel server when one is
//! configured. Configuration comes from `--config <file.toml>` (the full schema, see
//! `spark_core::config`) or, when that is absent, from the individual flags below.
//!
//! Log hygiene (a product privacy property, see `docs/GOAL.md`): source/destination
//! addresses are emitted only at `debug`, and at the default level the log writer also
//! redacts any IP literal as a backstop. Run with `--debug` (or `RUST_LOG=debug`) to see
//! addresses and disable redaction.

use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use spark_core::config::{self, Config};
use spark_core::netstack::SmoltcpNetstack;
use spark_core::proxy;
use spark_core::redact::redact_addrs;
use spark_core::transport::tcp_tunnel::client::TunnelClient;
use spark_core::transport::{DirectTransport, Transport, UdpTransport};
use spark_core::tun::Tun;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// A from-scratch multi-protocol VPN/proxy tunnel.
#[derive(Parser, Debug)]
#[command(name = "spark", version, about)]
struct Cli {
    /// Load the full configuration from a TOML file. When set, the individual flags below
    /// are ignored.
    #[arg(long)]
    config: Option<PathBuf>,

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

    /// Log source/destination addresses too and disable redaction (equivalent to
    /// `RUST_LOG=debug`). Off by default for log hygiene.
    #[arg(long)]
    debug: bool,
}

impl Cli {
    /// Build a [`Config`] from the individual flags (used when `--config` is not given).
    fn to_config(&self) -> Config {
        Config {
            tun: config::TunConfig {
                name: self.name.clone(),
                addr: self.addr,
                prefix: self.prefix,
                mtu: self.mtu,
            },
            transport: config::TransportConfig {
                server: self.server,
            },
            udp: config::UdpConfig::default(),
            log: config::LogConfig { debug: self.debug },
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = match &cli.config {
        Some(path) => Config::from_path(path)
            .with_context(|| format!("loading config from {}", path.display()))?,
        None => cli.to_config(),
    };

    init_tracing(config.log.debug);

    let tun = Arc::new(
        Tun::open(spark_core::tun::TunConfig {
            name: config.tun.name.clone(),
            ipv4: (config.tun.addr, config.tun.prefix),
            mtu: config.tun.mtu,
        })
        .context("bringing up the TUN device")?,
    );

    let name = tun.name().context("reading TUN device name")?;
    let mtu = tun.mtu();

    // One underlying transport serves both the TCP and UDP forwarders.
    let (tcp_transport, udp_transport): (Arc<dyn Transport>, Arc<dyn UdpTransport>) = match config
        .transport
        .server
    {
        Some(server) => {
            info!(device = %name, mtu, addr = %config.tun.addr, %server, "TUN up — tunneling TCP+UDP through server; Ctrl-C to stop");
            let client = Arc::new(TunnelClient::new(server));
            let tcp: Arc<dyn Transport> = client.clone();
            let udp: Arc<dyn UdpTransport> = client;
            (tcp, udp)
        }
        None => {
            info!(device = %name, mtu, addr = %config.tun.addr, "TUN up — forwarding TCP+UDP directly (no tunnel); Ctrl-C to stop");
            let direct = Arc::new(DirectTransport);
            let tcp: Arc<dyn Transport> = direct.clone();
            let udp: Arc<dyn UdpTransport> = direct;
            (tcp, udp)
        }
    };

    let mut netstack = SmoltcpNetstack::new(Arc::clone(&tun)).context("starting the netstack")?;

    // Drive the UDP path on the netstack's UDP surface (taken before the netstack moves into
    // the TCP accept loop).
    let idle_timeout = Duration::from_secs(config.udp.idle_timeout_secs);
    if let Some((udp_inbound, udp_reply)) = netstack.take_udp() {
        tokio::spawn(proxy::udp::run_udp(
            udp_inbound,
            udp_reply,
            udp_transport,
            idle_timeout,
        ));
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("signal received — shutting down");
        }
        _ = proxy::tcp::run(netstack, tcp_transport) => {
            warn!("netstack accept loop exited unexpectedly");
        }
    }

    // Dropping `netstack` (in either branch's future) aborts the runner + bridge + UDP drain
    // tasks; dropping the last `Tun` reference tears the OS device down. Make that explicit
    // and ordered so teardown is deterministic.
    drop(tun);
    info!("shut down cleanly");
    Ok(())
}

/// Initialize tracing. `RUST_LOG` wins if set; otherwise `debug` selects the `debug` level
/// and the default is `info`. Unless in debug mode, the writer redacts IP literals as a
/// privacy backstop on top of the level convention.
fn init_tracing(debug: bool) {
    let default = if debug { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let redact = !debug;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(move || RedactingWriter {
            inner: io::stdout(),
            redact,
        })
        .init();
}

/// A log writer that scrubs IP literals from each formatted line unless redaction is off.
struct RedactingWriter<W> {
    inner: W,
    redact: bool,
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.redact {
            if let Ok(line) = std::str::from_utf8(buf) {
                self.inner.write_all(redact_addrs(line).as_bytes())?;
                return Ok(buf.len());
            }
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
