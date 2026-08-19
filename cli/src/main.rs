//! `spark` CLI.
//!
//! Two modes, by subcommand:
//! - `spark run …` — bring the tunnel up **in-process** (the dev driver): open the TUN,
//!   bridge it into the netstack, and forward TCP/UDP directly or through a tunnel server.
//! - `spark connect|disconnect|status …` — act as the unprivileged **control client** for a
//!   running `spark-service` daemon, over its unix-socket control channel.
//!
//! Log hygiene (a product privacy property, see `docs/GOAL.md`): source/destination
//! addresses are emitted only at `debug`, and at the default level the log writer redacts IP
//! literals as a backstop. Run with `--debug` (or `RUST_LOG=debug`) to see addresses.

use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use spark_core::config::{self, Config};
use spark_core::netstack;
use spark_core::proxy;
use spark_core::redact::redact_addrs;
use spark_core::transport;
use spark_core::tun::Tun;
use spark_ipc::{Client, RequestPayload, ResponsePayload};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// A from-scratch multi-protocol VPN/proxy tunnel.
#[derive(Parser, Debug)]
#[command(name = "spark", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the tunnel in-process (dev driver). Requires privilege to open the TUN.
    Run(RunArgs),
    /// Tell a running spark-service to bring the tunnel up.
    Connect(CtlArgs),
    /// Tell a running spark-service to tear the tunnel down.
    Disconnect(CtlArgs),
    /// Print the tunnel status from a running spark-service.
    Status(CtlArgs),
    /// Print what the service build supports (transports, stacks, versions).
    Capabilities(CtlArgs),
    /// Print a detailed status snapshot (selected transport/stack, kill-switch, last error).
    Details(CtlArgs),
    /// Print the data-path counters (bytes up/down, active/total sessions).
    Metrics(CtlArgs),
    /// List the stored connection profiles (`*` marks the active one).
    Profiles(CtlArgs),
}

/// Flags for the in-process `run` driver.
#[derive(Args, Debug)]
struct RunArgs {
    /// Load the full configuration from a TOML file. When set, the other flags are ignored.
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
    /// Tunnel server address (`host:port`); omit to dial destinations directly.
    #[arg(long)]
    server: Option<SocketAddr>,
    /// Physical interface to pin upstream sockets to (e.g. `en0`), so the proxy's own dials
    /// bypass the tunnel route. Required on macOS to forward without a routing loop.
    #[arg(long)]
    protect_interface: Option<String>,
    /// Log source/destination addresses too and disable redaction.
    #[arg(long)]
    debug: bool,
}

impl RunArgs {
    fn to_config(&self) -> Config {
        Config {
            tun: config::TunConfig {
                name: self.name.clone(),
                addr: self.addr,
                prefix: self.prefix,
                mtu: self.mtu,
                // The bare `run` flags default to the userspace stack; select `system` via --config.
                stack: config::StackKind::default(),
            },
            transport: config::TransportConfig {
                server: self.server,
                protect_interface: self.protect_interface.clone(),
                // AnyTLS, the wasm transport, and handshake shaping are configured via a TOML file
                // (`run --config`), not the bare flags.
                anytls: None,
                samizdat: None,
                wasm: None,
                shaping: config::ShapingConfig::default(),
                // The multi-server pool + probe knobs are TOML-only (`run --config`); the bare flags
                // use their defaults (empty pool → single-transport path).
                ..Default::default()
            },
            udp: config::UdpConfig::default(),
            routing: config::RoutingConfig::default(),
            // Smart-routing/ad-block rules come from a Lantern `config_raw.json` (`run --config`), not
            // the bare `run` flags; the flag path uses the empty default (proxy-everything).
            smart_routing: config::SmartRoutingConfig::default(),
            // Per-action DNS resolver endpoints likewise come from `config_raw.json`'s `options.dns`.
            dns: config::DnsConfig::default(),
            kill_switch: config::KillSwitchConfig::default(),
            log: config::LogConfig { debug: self.debug },
        }
    }
}

/// Flags for the control-client subcommands.
#[derive(Args, Debug)]
struct CtlArgs {
    /// Control socket of the running spark-service.
    #[cfg(unix)]
    #[arg(long, default_value = "/var/run/spark.sock")]
    socket: PathBuf,
    /// Named pipe of the running spark-service.
    #[cfg(windows)]
    #[arg(long, default_value = r"\\.\pipe\spark")]
    socket: PathBuf,
}

/// Connect to the running service's control endpoint: a unix-domain socket on unix, a named
/// pipe on Windows. Returns a connected byte stream for [`Client`].
#[cfg(unix)]
async fn connect_control(
    endpoint: &std::path::Path,
) -> io::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> {
    tokio::net::UnixStream::connect(endpoint).await
}
#[cfg(windows)]
async fn connect_control(
    endpoint: &std::path::Path,
) -> io::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint.as_os_str())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Run(args) => run_tunnel(args).await,
        Command::Connect(ctl) => control(ctl.socket, RequestPayload::Connect).await,
        Command::Disconnect(ctl) => control(ctl.socket, RequestPayload::Disconnect).await,
        Command::Status(ctl) => control(ctl.socket, RequestPayload::GetStatus).await,
        Command::Capabilities(ctl) => control(ctl.socket, RequestPayload::GetCapabilities).await,
        Command::Details(ctl) => control(ctl.socket, RequestPayload::GetDetails).await,
        Command::Metrics(ctl) => control(ctl.socket, RequestPayload::GetMetrics).await,
        Command::Profiles(ctl) => control(ctl.socket, RequestPayload::ListProfiles).await,
    }
}

/// The in-process driver (the former all-in-one behavior).
async fn run_tunnel(args: RunArgs) -> anyhow::Result<()> {
    let mut config = match &args.config {
        Some(path) => Config::from_path(path)
            .with_context(|| format!("loading config from {}", path.display()))?,
        None => args.to_config(),
    };

    init_tracing(config.log.debug);
    spark_core::resolve_bootstrap(&mut config)
        .await
        .context("resolving bootstrap endpoints")?;

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

    if let Some(anytls) = &config.transport.anytls {
        info!(device = %name, mtu, addr = %config.tun.addr, server = %anytls.server, "TUN up — tunneling TCP through AnyTLS; Ctrl-C to stop")
    } else {
        match &config.transport.server {
            Some(server) => {
                info!(device = %name, mtu, addr = %config.tun.addr, %server, "TUN up — tunneling TCP+UDP through server; Ctrl-C to stop")
            }
            None => {
                info!(device = %name, mtu, addr = %config.tun.addr, "TUN up — forwarding TCP+UDP directly (no tunnel); Ctrl-C to stop")
            }
        }
    }
    // Ahead of the transport build, for the same reason the service does it there: core skips an
    // `unbounded` pool member when no builder is installed, and does not revisit it.
    #[cfg(feature = "unbounded")]
    spark_sharing::install();

    let (tcp_transport, udp_transport) =
        transport::from_config(&config).context("building the transport")?;

    let (stack, udp_surface) =
        netstack::build(Arc::clone(&tun), &config).context("starting the netstack")?;

    let idle_timeout = Duration::from_secs(config.udp.idle_timeout_secs);
    if let Some((udp_inbound, udp_reply)) = udp_surface {
        // The CLI has no smart-routing hooks (proxy everything), so the UDP forwarder never makes a
        // `Direct` decision and this transport goes unused; it's passed only to satisfy `run_udp`'s
        // signature (which needs a direct UDP transport for the hooks-enabled `Direct` path).
        let direct_udp: Arc<dyn transport::UdpTransport> =
            Arc::new(transport::DirectTransport::default());
        tokio::spawn(proxy::udp::run_udp(
            udp_inbound,
            udp_reply,
            udp_transport,
            direct_udp,
            None,
            idle_timeout,
        ));
    }

    // The in-process driver doesn't surface metrics; a local counter satisfies the forwarder.
    let metrics = Arc::new(spark_core::metrics::Metrics::default());
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("signal received — shutting down");
        }
        // `spark run` has no smart-routing hooks (that's the fetched-config path); pass `None` so
        // every flow is proxied, and a direct transport for the (here unused) Direct action.
        _ = proxy::tcp::run(
            stack,
            tcp_transport,
            Arc::new(transport::DirectTransport::default()),
            None,
            metrics,
        ) => {
            warn!("netstack accept loop exited unexpectedly");
        }
    }

    drop(tun);
    info!("shut down cleanly");
    Ok(())
}

/// Connect to a running spark-service, handshake, issue one command, and print the result.
async fn control(socket: PathBuf, payload: RequestPayload) -> anyhow::Result<()> {
    let stream = connect_control(&socket)
        .await
        .with_context(|| format!("connecting to spark-service at {}", socket.display()))?;
    let mut client = Client::new(stream);
    client
        .handshake()
        .await
        .context("control handshake with the service")?;

    match client.request(payload).await.context("control request")? {
        ResponsePayload::Ack => println!("ok"),
        ResponsePayload::Status(s) => {
            println!("state: {:?}", s.state);
            if s.direct_fallback {
                println!("WARNING: failed open — traffic is routing directly, not tunneled");
            }
        }
        ResponsePayload::Capabilities(c) => {
            println!(
                "protocol: {}  build: {}",
                c.protocol_version, c.build_version
            );
            println!("platform: {}", c.platform);
            println!("transports: {:?}", c.transports);
            println!("stacks: {:?}", c.stacks);
        }
        ResponsePayload::Details(d) => {
            println!("state: {:?}", d.state);
            println!(
                "transport: {:?}  stack: {:?}  kill-switch: {:?}",
                d.selected_transport, d.selected_stack, d.kill_switch
            );
            if d.direct_fallback {
                println!("WARNING: failed open — traffic is routing directly, not tunneled");
            }
            if let Some(m) = d.module {
                println!("module: {} v{}", m.name, m.version);
            }
            if let Some(e) = d.last_error {
                println!("last error: {e}");
            }
        }
        ResponsePayload::Metrics(m) => {
            println!("bytes up: {}  down: {}", m.bytes_up, m.bytes_down);
            println!(
                "sessions active: {}  total: {}",
                m.sessions_active, m.sessions_total
            );
        }
        ResponsePayload::Profiles(ps) => {
            if ps.is_empty() {
                println!("(no profiles)");
            }
            for p in ps {
                let active = if p.active { " *" } else { "" };
                println!(
                    "{}{active}  transport={:?} stack={:?} password={}",
                    p.name, p.transport, p.stack, p.has_password
                );
            }
        }
        ResponsePayload::Profile(d) => {
            println!("# profile: {}", d.name);
            print!("{}", d.toml);
        }
        ResponsePayload::Validated(v) => match v.error {
            None => println!("valid"),
            Some(e) => anyhow::bail!("invalid: {e}"),
        },
        ResponsePayload::Error { code, message } => {
            anyhow::bail!("service error [{code:?}]: {message}");
        }
        ResponsePayload::Hello { .. } => {}
    }
    Ok(())
}

/// Initialize tracing. `RUST_LOG` wins if set; otherwise `debug` selects `debug` and the
/// default is `info`. Unless in debug mode, the writer redacts IP literals as a backstop.
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
