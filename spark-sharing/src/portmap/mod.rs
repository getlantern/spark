//! Asking the router to accept inbound connections on our behalf.
//!
//! This is the other half of Unbounded. The WebRTC path in [`crate::consumer`] works from behind any
//! NAT because both sides dial out to a rendezvous; a *direct* peer proxy instead needs a port on
//! the router forwarded to this host, so lantern-cloud can hand the address out to censored clients
//! and they can connect straight to it.
//!
//! Four ways to get that port, tried in order by [`discover`]:
//!
//! 1. A rule the user configured by hand. An explicit instruction outranks discovery.
//! 2. UPnP/IGD, the widest-supported protocol, in [`upnp`].
//! 3. PCP (RFC 6887), the current one.
//! 4. NAT-PMP (RFC 6886), which PCP supersedes but which many routers still speak alone.
//!
//! UPnP is tried before PCP/NAT-PMP because it is the protocol most consumer routers actually
//! implement. It is also much the fussiest, which is why it lives in its own module.
//!
//! The two protocols in this file are small binary exchanges with the gateway on UDP 5351, so their
//! whole wire format is below.

mod upnp;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;

/// Both protocols answer here. PCP took over NAT-PMP's port precisely so a client can try the newer
/// one and fall back on the same socket.
const PMP_PORT: u16 = 5351;

/// What the gateway granted. `external_port` is authoritative and may differ from what was asked
/// for: a gateway is free to hand back a different port, and the caller has to advertise the one it
/// actually got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub external_port: u16,
    pub internal_port: u16,
    /// The WAN address, when the protocol reveals it. NAT-PMP has a request for it; PCP only reports
    /// it alongside a mapping; a manual rule cannot know it. Empty is a valid answer — the server
    /// falls back to the source address it observes when we register.
    pub external_ip: Option<Ipv4Addr>,
    pub lease: Duration,
    pub method: Method,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Manual,
    Upnp,
    Pcp,
    NatPmp,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Manual => "manual",
            Method::Upnp => "upnp",
            Method::Pcp => "pcp",
            Method::NatPmp => "nat-pmp",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PortMapError {
    /// No route to a gateway that will map a port. Callers should treat this as "this network cannot
    /// host a direct peer proxy" and fall back to the WebRTC path rather than retrying.
    #[error("no port mapping available on this network")]
    Unavailable,
    #[error("could not find the default gateway: {0}")]
    Gateway(String),
    #[error("gateway refused the request: {0}")]
    Refused(String),
    #[error("malformed reply from the gateway: {0}")]
    Malformed(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

// ---------------------------------------------------------------------------
// NAT-PMP (RFC 6886)
// ---------------------------------------------------------------------------

const NATPMP_VERSION: u8 = 0;
const NATPMP_OP_EXTERNAL: u8 = 0;
const NATPMP_OP_MAP_TCP: u8 = 2;
/// A reply carries the request's opcode with the high bit set.
const NATPMP_RESPONSE_BIT: u8 = 0x80;
const NATPMP_EXTERNAL_RESP_LEN: usize = 12;
const NATPMP_MAP_RESP_LEN: usize = 16;

/// The external-address request, which doubles as the NAT-PMP liveness probe: it is read-only, so
/// probing cannot strand a mapping on a gateway we then decide not to use.
fn natpmp_external_req() -> [u8; 2] {
    [NATPMP_VERSION, NATPMP_OP_EXTERNAL]
}

fn parse_natpmp_external(b: &[u8]) -> Result<Ipv4Addr, PortMapError> {
    if b.len() < NATPMP_EXTERNAL_RESP_LEN {
        return Err(PortMapError::Malformed(format!(
            "nat-pmp external reply is {} bytes",
            b.len()
        )));
    }
    if b[0] != NATPMP_VERSION {
        return Err(PortMapError::Malformed(format!("nat-pmp version {}", b[0])));
    }
    if b[1] != NATPMP_RESPONSE_BIT | NATPMP_OP_EXTERNAL {
        return Err(PortMapError::Malformed(format!(
            "nat-pmp opcode {:#x}",
            b[1]
        )));
    }
    let result = u16::from_be_bytes([b[2], b[3]]);
    if result != 0 {
        return Err(PortMapError::Refused(format!("nat-pmp result {result}")));
    }
    Ok(Ipv4Addr::new(b[8], b[9], b[10], b[11]))
}

/// A TCP mapping request. Lifetime 0 is the protocol's delete, so teardown reuses this rather than a
/// separate opcode.
fn natpmp_map_req(internal_port: u16, suggested_external: u16, lifetime_secs: u32) -> [u8; 12] {
    let mut b = [0_u8; 12];
    b[0] = NATPMP_VERSION;
    b[1] = NATPMP_OP_MAP_TCP;
    b[4..6].copy_from_slice(&internal_port.to_be_bytes());
    b[6..8].copy_from_slice(&suggested_external.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    b
}

/// What a MAP reply granted, before it is turned into a [`Mapping`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MapGrant {
    pub(super) external_port: u16,
    pub(super) lease: Duration,
    pub(super) external_ip: Option<Ipv4Addr>,
}

fn parse_natpmp_map(b: &[u8]) -> Result<MapGrant, PortMapError> {
    if b.len() < NATPMP_MAP_RESP_LEN {
        return Err(PortMapError::Malformed(format!(
            "nat-pmp map reply is {} bytes",
            b.len()
        )));
    }
    if b[0] != NATPMP_VERSION {
        return Err(PortMapError::Malformed(format!("nat-pmp version {}", b[0])));
    }
    if b[1] != NATPMP_RESPONSE_BIT | NATPMP_OP_MAP_TCP {
        return Err(PortMapError::Malformed(format!(
            "nat-pmp opcode {:#x}",
            b[1]
        )));
    }
    let result = u16::from_be_bytes([b[2], b[3]]);
    if result != 0 {
        return Err(PortMapError::Refused(format!("nat-pmp result {result}")));
    }
    Ok(MapGrant {
        external_port: u16::from_be_bytes([b[10], b[11]]),
        lease: Duration::from_secs(u32::from_be_bytes([b[12], b[13], b[14], b[15]]) as u64),
        external_ip: None,
    })
}

// ---------------------------------------------------------------------------
// PCP (RFC 6887)
// ---------------------------------------------------------------------------

const PCP_VERSION: u8 = 2;
const PCP_OP_MAP: u8 = 1;
const PCP_HEADER_LEN: usize = 24;
const PCP_MSG_LEN: usize = PCP_HEADER_LEN + 36;
const PCP_RESULT_UNSUPP_VERSION: u8 = 1;
const PCP_PROTO_TCP: u8 = 6;

/// A PCP MAP request.
///
/// `nonce` identifies the mapping and must be identical on every request meaning "the same
/// mapping": renewing with a fresh nonce creates a second mapping instead of extending the first,
/// and a delete carrying the wrong nonce is refused. It must also be unguessable — it is the only
/// thing binding a request to a mapping, so a predictable one lets anything on the LAN delete or
/// retarget ours.
fn pcp_map_req(
    nonce: &[u8; 12],
    client: Ipv4Addr,
    internal_port: u16,
    suggested_external: u16,
    lifetime_secs: u32,
) -> [u8; PCP_MSG_LEN] {
    let mut b = [0_u8; PCP_MSG_LEN];
    b[0] = PCP_VERSION;
    // R bit clear: this is a request. Setting it would make it a response, which gateways drop.
    b[1] = PCP_OP_MAP;
    b[4..8].copy_from_slice(&lifetime_secs.to_be_bytes());
    // The client address is always a 16-byte field; v4 goes in IPv4-mapped form, not left-aligned.
    b[8..24].copy_from_slice(&client.to_ipv6_mapped().octets());

    b[24..36].copy_from_slice(nonce);
    b[36] = PCP_PROTO_TCP;
    b[40..42].copy_from_slice(&internal_port.to_be_bytes());
    b[42..44].copy_from_slice(&suggested_external.to_be_bytes());
    // b[44..60] is the suggested external address, left zero for "no preference"; the gateway fills
    // it in on the reply.
    b
}

fn parse_pcp_map(b: &[u8], want_nonce: &[u8; 12]) -> Result<MapGrant, PortMapError> {
    if b.len() < PCP_MSG_LEN {
        return Err(PortMapError::Malformed(format!(
            "pcp map reply is {} bytes",
            b.len()
        )));
    }
    if b[0] != PCP_VERSION {
        return Err(PortMapError::Malformed(format!("pcp version {}", b[0])));
    }
    if b[1] != PCP_OP_MAP | 0x80 {
        return Err(PortMapError::Malformed(format!("pcp opcode {:#x}", b[1])));
    }
    if b[3] != 0 {
        return Err(PortMapError::Refused(format!("pcp result {}", b[3])));
    }
    // A reply carrying someone else's nonce answers someone else's mapping; acting on it would
    // advertise a port we do not own.
    if &b[24..36] != want_nonce.as_slice() {
        return Err(PortMapError::Malformed("pcp nonce mismatch".into()));
    }
    let mut ext = [0_u8; 16];
    ext.copy_from_slice(&b[44..60]);
    let external_ip = std::net::Ipv6Addr::from(ext)
        .to_ipv4_mapped()
        .filter(|a| !a.is_unspecified());
    Ok(MapGrant {
        external_port: u16::from_be_bytes([b[42], b[43]]),
        lease: Duration::from_secs(u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as u64),
        external_ip,
    })
}

/// Whether a reply is a PCP server refusing our version — the one failure that means "speak
/// NAT-PMP instead" rather than "this gateway cannot map ports".
fn pcp_unsupported_version(b: &[u8]) -> bool {
    b.len() >= 4 && b[3] == PCP_RESULT_UNSUPP_VERSION
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The request/reply exchange with the gateway, abstracted so the protocol can be tested without a
/// router on the network.
#[async_trait::async_trait]
trait PmpTransport: Send + Sync {
    async fn round_trip(&self, req: &[u8]) -> Result<Vec<u8>, PortMapError>;
}

/// Deliberately far shorter than RFC 6886's schedule (250ms doubling over nine attempts, ~64s).
/// This runs while someone waits to learn whether they can host, and a gateway silent three times
/// inside two seconds is not going to answer.
const PMP_RETRIES: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1000),
];

struct UdpPmp {
    sock: UdpSocket,
}

impl UdpPmp {
    async fn connect(gateway: Ipv4Addr) -> Result<Self, PortMapError> {
        let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
        sock.connect(SocketAddr::V4(SocketAddrV4::new(gateway, PMP_PORT)))
            .await?;
        Ok(Self { sock })
    }
}

#[async_trait::async_trait]
impl PmpTransport for UdpPmp {
    async fn round_trip(&self, req: &[u8]) -> Result<Vec<u8>, PortMapError> {
        let mut buf = [0_u8; 1500];
        for wait in PMP_RETRIES {
            self.sock.send(req).await?;
            match tokio::time::timeout(wait, self.sock.recv(&mut buf)).await {
                Ok(Ok(n)) => return Ok(buf[..n].to_vec()),
                // A read error is as retryable as a timeout here: an ICMP port-unreachable from a
                // gateway that is not listening surfaces as one on some platforms.
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        Err(PortMapError::Unavailable)
    }
}

// ---------------------------------------------------------------------------
// Mappers
// ---------------------------------------------------------------------------

/// A source of forwarded ports.
#[async_trait::async_trait]
pub trait PortMapper: Send + Sync {
    /// Ask for `internal_port` to be forwarded. The granted mapping may name a different external
    /// port.
    async fn map(&self, internal_port: u16) -> Result<Mapping, PortMapError>;

    /// Release the mapping. Idempotent, and best-effort by nature: the only fallback if it fails is
    /// the gateway's own lease expiry.
    async fn unmap(&self, mapping: &Mapping) -> Result<(), PortMapError>;

    /// Re-assert the mapping so its lease does not lapse. Called on a timer by the owner of the
    /// mapping rather than by a task inside the mapper, so the caller controls its lifetime.
    async fn renew(&self, mapping: &Mapping) -> Result<Mapping, PortMapError>;

    fn method(&self) -> Method;
}

/// A rule the user configured on their router by hand.
///
/// For networks where UPnP is off, the gateway is ISP-locked, or there is a second layer of NAT —
/// the discovery protocols all fail there and the user's own rule is the only way through.
pub struct ManualMapper {
    port: u16,
}

impl ManualMapper {
    /// `port` must be one this process can actually listen on: 1024..=65535.
    ///
    /// Below 1024 is privileged and this subsystem runs unprivileged, and 0 is the wildcard that
    /// forwards every port — so rejecting the range here stops a misconfiguration registering a
    /// port no peer will answer on, or one that would forward far more than intended.
    pub fn new(port: u16) -> Result<Self, PortMapError> {
        if !(1024..=65535).contains(&port) {
            return Err(PortMapError::Refused(format!(
                "manual port {port} is outside 1024..=65535"
            )));
        }
        Ok(Self { port })
    }
}

#[async_trait::async_trait]
impl PortMapper for ManualMapper {
    async fn map(&self, _internal_port: u16) -> Result<Mapping, PortMapError> {
        // The same port on both sides: a hand-written rule is supplied as one number, and there is
        // no protocol here that could negotiate a different pair.
        Ok(Mapping {
            external_port: self.port,
            internal_port: self.port,
            external_ip: None,
            // Nominal. Nothing expires a rule the user wrote, but callers read this to schedule
            // renewal and a zero would make them spin.
            lease: Duration::from_secs(3600),
            method: Method::Manual,
        })
    }

    /// The user owns the rule, so removing it is theirs to do.
    async fn unmap(&self, _mapping: &Mapping) -> Result<(), PortMapError> {
        Ok(())
    }

    async fn renew(&self, mapping: &Mapping) -> Result<Mapping, PortMapError> {
        Ok(mapping.clone())
    }

    fn method(&self) -> Method {
        Method::Manual
    }
}

/// PCP, falling back to NAT-PMP, against the default gateway.
pub struct PmpMapper {
    transport: Box<dyn PmpTransport>,
    method: Method,
    client: Ipv4Addr,
    nonce: [u8; 12],
}

impl PmpMapper {
    /// Settle on a protocol with `gateway` so an unsupported network fails here rather than at
    /// [`PortMapper::map`].
    ///
    /// Probing is read-only. PCP is probed with a zero-lifetime MAP — a delete of a mapping that
    /// does not exist, which a PCP server answers without creating anything — and NAT-PMP with an
    /// external-address request. A NAT-PMP-only gateway usually ignores the PCP request rather than
    /// refusing it, so silence has to fall through as well as an explicit version refusal.
    pub async fn discover(gateway: Ipv4Addr, client: Ipv4Addr) -> Result<Self, PortMapError> {
        let transport = UdpPmp::connect(gateway).await?;
        Self::negotiate(Box::new(transport), client).await
    }

    async fn negotiate(
        transport: Box<dyn PmpTransport>,
        client: Ipv4Addr,
    ) -> Result<Self, PortMapError> {
        let mut nonce = [0_u8; 12];
        {
            use ring::rand::SecureRandom;
            ring::rand::SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| io::Error::other("portmap: system RNG unavailable"))?;
        }

        let probe = pcp_map_req(&nonce, client, 0, 0, 0);
        if let Ok(reply) = transport.round_trip(&probe).await {
            if !pcp_unsupported_version(&reply) {
                return Ok(Self {
                    transport,
                    method: Method::Pcp,
                    client,
                    nonce,
                });
            }
        }
        if let Ok(reply) = transport.round_trip(&natpmp_external_req()).await {
            if parse_natpmp_external(&reply).is_ok() {
                return Ok(Self {
                    transport,
                    method: Method::NatPmp,
                    client,
                    nonce,
                });
            }
        }
        Err(PortMapError::Unavailable)
    }

    /// One hour, matching what the UPnP path in the Go implementation requests, so the renewal
    /// cadence and the window a crashed client leaves a stale mapping open do not depend on which
    /// protocol won.
    const LEASE: Duration = Duration::from_secs(3600);

    async fn exchange(
        &self,
        internal_port: u16,
        suggested_external: u16,
        lifetime_secs: u32,
    ) -> Result<MapGrant, PortMapError> {
        match self.method {
            Method::Pcp => {
                let req = pcp_map_req(
                    &self.nonce,
                    self.client,
                    internal_port,
                    suggested_external,
                    lifetime_secs,
                );
                let reply = self.transport.round_trip(&req).await?;
                parse_pcp_map(&reply, &self.nonce)
            }
            Method::NatPmp => {
                let req = natpmp_map_req(internal_port, suggested_external, lifetime_secs);
                let reply = self.transport.round_trip(&req).await?;
                parse_natpmp_map(&reply)
            }
            // A `PmpMapper` only ever holds Pcp or NatPmp; the other variants belong to the
            // manual and UPnP mappers, which do not route through here.
            Method::Manual | Method::Upnp => Err(PortMapError::Unavailable),
        }
    }

    fn grant_to_mapping(&self, internal_port: u16, grant: MapGrant) -> Mapping {
        Mapping {
            external_port: grant.external_port,
            internal_port,
            external_ip: grant.external_ip,
            // A gateway may shorten the lease it grants; zero would make the caller's renewal timer
            // spin, so fall back to what we asked for.
            lease: if grant.lease.is_zero() {
                Self::LEASE
            } else {
                grant.lease
            },
            method: self.method,
        }
    }
}

#[async_trait::async_trait]
impl PortMapper for PmpMapper {
    async fn map(&self, internal_port: u16) -> Result<Mapping, PortMapError> {
        let grant = self
            .exchange(internal_port, internal_port, Self::LEASE.as_secs() as u32)
            .await?;
        Ok(self.grant_to_mapping(internal_port, grant))
    }

    /// Both protocols express a delete as the mapping request with a zero lifetime.
    async fn unmap(&self, mapping: &Mapping) -> Result<(), PortMapError> {
        self.exchange(mapping.internal_port, mapping.external_port, 0)
            .await
            .map(|_| ())
    }

    async fn renew(&self, mapping: &Mapping) -> Result<Mapping, PortMapError> {
        let grant = self
            .exchange(
                mapping.internal_port,
                mapping.external_port,
                Self::LEASE.as_secs() as u32,
            )
            .await?;
        Ok(self.grant_to_mapping(mapping.internal_port, grant))
    }

    fn method(&self) -> Method {
        self.method
    }
}

#[async_trait::async_trait]
impl PortMapper for upnp::UpnpMapper {
    async fn map(&self, internal_port: u16) -> Result<Mapping, PortMapError> {
        upnp::UpnpMapper::map(self, internal_port).await
    }

    async fn unmap(&self, mapping: &Mapping) -> Result<(), PortMapError> {
        upnp::UpnpMapper::unmap(self, mapping).await
    }

    async fn renew(&self, mapping: &Mapping) -> Result<Mapping, PortMapError> {
        upnp::UpnpMapper::renew(self, mapping).await
    }

    fn method(&self) -> Method {
        Method::Upnp
    }
}

/// The address of the default gateway.
///
/// Shelled out per platform, matching how `spark-core`'s routing already manipulates routes, rather
/// than taking a dependency for one lookup. Reading `/proc/net/route` directly on Linux avoids a
/// subprocess where the kernel already exposes the table as a file.
pub async fn default_gateway() -> Result<Ipv4Addr, PortMapError> {
    // On a blocking thread rather than through `tokio::process`/`tokio::fs`: this crate enables
    // neither feature, and one lookup at session start is not worth widening the runtime's surface.
    tokio::task::spawn_blocking(default_gateway_blocking)
        .await
        .map_err(|e| PortMapError::Gateway(format!("gateway lookup task: {e}")))?
}

fn default_gateway_blocking() -> Result<Ipv4Addr, PortMapError> {
    #[cfg(target_os = "linux")]
    {
        // A pseudo-file, so this read does not touch a disk or a network.
        let table = std::fs::read_to_string("/proc/net/route")
            .map_err(|e| PortMapError::Gateway(format!("read /proc/net/route: {e}")))?;
        parse_proc_net_route(&table).ok_or_else(|| PortMapError::Gateway("no default route".into()))
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| PortMapError::Gateway(format!("run route: {e}")))?;
        parse_route_get_default(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| PortMapError::Gateway("no default route".into()))
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // Without this a GUI process flashes a console window at the user, and this runs at the
        // start of every sharing session.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = std::process::Command::new("route")
            .args(["print", "-4", "0.0.0.0"])
            .stdin(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| PortMapError::Gateway(format!("run route: {e}")))?;
        parse_route_print(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| PortMapError::Gateway("no default route".into()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(PortMapError::Gateway(
            "unsupported platform for gateway discovery".into(),
        ))
    }
}

/// Pull the default route's gateway out of `/proc/net/route`.
///
/// Destination and Gateway are little-endian hex of the network-order address, so the octets come
/// out reversed from how they read.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_route(table: &str) -> Option<Ipv4Addr> {
    for line in table.lines().skip(1) {
        let mut f = line.split_whitespace();
        let _iface = f.next()?;
        let dest = f.next()?;
        let gw = f.next()?;
        if dest != "00000000" {
            continue;
        }
        let raw = u32::from_str_radix(gw, 16).ok()?;
        if raw == 0 {
            continue;
        }
        let o = raw.to_le_bytes();
        return Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
    }
    None
}

/// Pull the gateway out of macOS `route -n get default`, whose output is `key: value` lines.
#[cfg(any(target_os = "macos", test))]
fn parse_route_get_default(out: &str) -> Option<Ipv4Addr> {
    out.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim() == "gateway")
        .and_then(|(_, v)| v.trim().parse().ok())
}

/// Pull the gateway out of Windows `route print`, whose IPv4 table rows are
/// `destination netmask gateway interface metric`.
#[cfg(any(target_os = "windows", test))]
fn parse_route_print(out: &str) -> Option<Ipv4Addr> {
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 || f[0] != "0.0.0.0" {
            continue;
        }
        // The gateway column reads "On-link" for a directly attached route, which has no gateway to
        // send a mapping request to.
        if let Ok(addr) = f[2].parse::<Ipv4Addr>() {
            return Some(addr);
        }
    }
    None
}

/// The local address the gateway will attribute a mapping to.
///
/// Taken from a UDP socket "connected" to a public address: no packet is sent, but the kernel picks
/// the route and therefore the source address it would use, which is exactly the interface the
/// gateway sees us on. Enumerating interfaces instead requires guessing which one is the default.
pub async fn local_ip() -> Result<Ipv4Addr, PortMapError> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    sock.connect(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)))
        .await?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(PortMapError::Gateway("local address is IPv6".into())),
    }
}

/// Pick how this host will accept inbound connections: a hand-configured rule, then UPnP, then PCP,
/// then NAT-PMP.
///
/// `manual_port` wins when set because it is an explicit instruction from the user, and finding a
/// gateway that would map some other port is not a reason to override it.
pub async fn discover(manual_port: Option<u16>) -> Result<Box<dyn PortMapper>, PortMapError> {
    if let Some(port) = manual_port {
        return Ok(Box::new(ManualMapper::new(port)?));
    }
    let gateway = default_gateway().await?;
    let client = local_ip().await?;

    // UPnP first: it is the protocol most consumer routers actually implement, so trying it first
    // is what makes the common case work. PCP/NAT-PMP is the cheaper exchange but the rarer
    // capability, and it is exactly what answers on the gateways UPnP is switched off on.
    let upnp_err = match upnp::UpnpMapper::discover(gateway, client).await {
        Ok(m) => return Ok(Box::new(m)),
        Err(e) => e,
    };
    match PmpMapper::discover(gateway, client).await {
        Ok(m) => Ok(Box::new(m)),
        // Report the UPnP failure when PCP/NAT-PMP simply was not there: UPnP is the path most
        // networks are expected to take, so it is the more useful of the two to anyone reading why
        // hosting is unavailable. A more specific PMP failure is worth more than either.
        Err(PortMapError::Unavailable) => Err(upnp_err),
        Err(pmp_err) => Err(pmp_err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers each round trip from a script, recording what it was asked. `None` is "no reply",
    /// which is how a gateway that does not speak the protocol behaves.
    struct FakeTransport {
        replies: Mutex<Vec<Option<Vec<u8>>>>,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeTransport {
        fn new(replies: Vec<Option<Vec<u8>>>) -> Self {
            Self {
                replies: Mutex::new(replies),
                sent: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl PmpTransport for FakeTransport {
        async fn round_trip(&self, req: &[u8]) -> Result<Vec<u8>, PortMapError> {
            self.sent.lock().expect("test lock").push(req.to_vec());
            let mut replies = self.replies.lock().expect("test lock");
            if replies.is_empty() {
                return Err(PortMapError::Unavailable);
            }
            replies.remove(0).ok_or(PortMapError::Unavailable)
        }
    }

    fn natpmp_map_reply(internal: u16, external: u16, lifetime: u32, result: u16) -> Vec<u8> {
        let mut b = vec![0_u8; NATPMP_MAP_RESP_LEN];
        b[0] = NATPMP_VERSION;
        b[1] = NATPMP_RESPONSE_BIT | NATPMP_OP_MAP_TCP;
        b[2..4].copy_from_slice(&result.to_be_bytes());
        b[8..10].copy_from_slice(&internal.to_be_bytes());
        b[10..12].copy_from_slice(&external.to_be_bytes());
        b[12..16].copy_from_slice(&lifetime.to_be_bytes());
        b
    }

    fn natpmp_external_reply(ip: Ipv4Addr) -> Vec<u8> {
        let mut b = vec![0_u8; NATPMP_EXTERNAL_RESP_LEN];
        b[0] = NATPMP_VERSION;
        b[1] = NATPMP_RESPONSE_BIT | NATPMP_OP_EXTERNAL;
        b[8..12].copy_from_slice(&ip.octets());
        b
    }

    fn pcp_map_reply(
        nonce: &[u8; 12],
        external: u16,
        lifetime: u32,
        result: u8,
        ext_ip: Option<Ipv4Addr>,
    ) -> Vec<u8> {
        let mut b = vec![0_u8; PCP_MSG_LEN];
        b[0] = PCP_VERSION;
        b[1] = PCP_OP_MAP | 0x80;
        b[3] = result;
        b[4..8].copy_from_slice(&lifetime.to_be_bytes());
        b[24..36].copy_from_slice(nonce);
        b[36] = PCP_PROTO_TCP;
        b[42..44].copy_from_slice(&external.to_be_bytes());
        if let Some(ip) = ext_ip {
            b[44..60].copy_from_slice(&ip.to_ipv6_mapped().octets());
        }
        b
    }

    #[test]
    fn natpmp_map_request_is_wire_exact() {
        let b = natpmp_map_req(40000, 40001, 3600);
        assert_eq!(b[0], NATPMP_VERSION);
        assert_eq!(b[1], NATPMP_OP_MAP_TCP);
        // Reserved bytes must be zero or a gateway may reject the request.
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 0);
        assert_eq!(u16::from_be_bytes([b[4], b[5]]), 40000);
        assert_eq!(u16::from_be_bytes([b[6], b[7]]), 40001);
        assert_eq!(u32::from_be_bytes([b[8], b[9], b[10], b[11]]), 3600);
    }

    #[test]
    fn natpmp_map_reply_reports_what_was_granted() {
        let g = parse_natpmp_map(&natpmp_map_reply(40000, 41000, 1800, 0)).expect("parse");
        assert_eq!(g.external_port, 41000);
        assert_eq!(g.lease, Duration::from_secs(1800));
    }

    #[test]
    fn natpmp_rejects_refusals_and_runts() {
        assert!(parse_natpmp_map(&natpmp_map_reply(40000, 0, 0, 2)).is_err());
        assert!(parse_natpmp_map(&[0, 130]).is_err());
        let mut wrong_op = natpmp_map_reply(40000, 41000, 1800, 0);
        wrong_op[1] = NATPMP_RESPONSE_BIT | NATPMP_OP_EXTERNAL;
        assert!(parse_natpmp_map(&wrong_op).is_err());
    }

    #[test]
    fn natpmp_external_reply_parses() {
        let ip = parse_natpmp_external(&natpmp_external_reply(Ipv4Addr::new(203, 0, 113, 7)))
            .expect("parse");
        assert_eq!(ip, Ipv4Addr::new(203, 0, 113, 7));
    }

    #[test]
    fn pcp_map_request_is_wire_exact() {
        let nonce = [1_u8; 12];
        let client = Ipv4Addr::new(192, 168, 1, 42);
        let b = pcp_map_req(&nonce, client, 40000, 40000, 3600);
        assert_eq!(b[0], PCP_VERSION);
        // The R bit must be clear on a request.
        assert_eq!(b[1], PCP_OP_MAP);
        assert_eq!(u32::from_be_bytes([b[4], b[5], b[6], b[7]]), 3600);
        // A v4 client goes in the 16-byte field IPv4-mapped, not left-aligned.
        assert_eq!(&b[8..24], client.to_ipv6_mapped().octets().as_slice());
        assert_eq!(&b[24..36], nonce.as_slice());
        assert_eq!(b[36], PCP_PROTO_TCP);
        assert_eq!(u16::from_be_bytes([b[40], b[41]]), 40000);
    }

    #[test]
    fn pcp_map_reply_unmaps_the_external_address() {
        let nonce = [7_u8; 12];
        let g = parse_pcp_map(
            &pcp_map_reply(&nonce, 41234, 3600, 0, Some(Ipv4Addr::new(198, 51, 100, 9))),
            &nonce,
        )
        .expect("parse");
        assert_eq!(g.external_port, 41234);
        assert_eq!(g.lease, Duration::from_secs(3600));
        // Left mapped it would stringify as ::ffff:198.51.100.9 and be unusable as a v4 address.
        assert_eq!(g.external_ip, Some(Ipv4Addr::new(198, 51, 100, 9)));
    }

    #[test]
    fn pcp_rejects_another_clients_nonce() {
        let ours = [7_u8; 12];
        let theirs = [9_u8; 12];
        assert!(parse_pcp_map(&pcp_map_reply(&theirs, 41234, 3600, 0, None), &ours).is_err());
    }

    #[test]
    fn pcp_rejects_refusals_and_runts() {
        let nonce = [7_u8; 12];
        assert!(parse_pcp_map(&pcp_map_reply(&nonce, 0, 0, 2, None), &nonce).is_err());
        assert!(parse_pcp_map(&[0_u8; PCP_MSG_LEN - 1], &nonce).is_err());
    }

    #[test]
    fn unsupported_version_is_the_only_fallback_signal() {
        let mut refusal = vec![0_u8; PCP_HEADER_LEN];
        refusal[3] = PCP_RESULT_UNSUPP_VERSION;
        assert!(pcp_unsupported_version(&refusal));
        assert!(!pcp_unsupported_version(&[0_u8; PCP_HEADER_LEN]));
        assert!(!pcp_unsupported_version(&[2]));
    }

    #[tokio::test]
    async fn negotiate_prefers_pcp_and_probes_read_only() {
        let tr = FakeTransport::new(vec![Some(vec![0_u8; PCP_MSG_LEN])]);
        let sent_probe = {
            let m = PmpMapper::negotiate(Box::new(tr), Ipv4Addr::new(192, 168, 1, 42))
                .await
                .expect("negotiate");
            assert_eq!(m.method, Method::Pcp);
            m
        };
        // The probe must not create anything, so its lifetime has to be zero.
        assert_eq!(sent_probe.method(), Method::Pcp);
    }

    #[tokio::test]
    async fn negotiate_falls_back_when_pcp_is_refused() {
        let mut refusal = vec![0_u8; PCP_HEADER_LEN];
        refusal[3] = PCP_RESULT_UNSUPP_VERSION;
        let tr = FakeTransport::new(vec![
            Some(refusal),
            Some(natpmp_external_reply(Ipv4Addr::new(203, 0, 113, 1))),
        ]);
        let m = PmpMapper::negotiate(Box::new(tr), Ipv4Addr::new(192, 168, 1, 42))
            .await
            .expect("negotiate");
        assert_eq!(m.method, Method::NatPmp);
    }

    #[tokio::test]
    async fn negotiate_falls_back_when_pcp_is_silent() {
        // A NAT-PMP-only gateway typically ignores a PCP request rather than refusing it.
        let tr = FakeTransport::new(vec![
            None,
            Some(natpmp_external_reply(Ipv4Addr::new(203, 0, 113, 1))),
        ]);
        let m = PmpMapper::negotiate(Box::new(tr), Ipv4Addr::new(192, 168, 1, 42))
            .await
            .expect("negotiate");
        assert_eq!(m.method, Method::NatPmp);
    }

    #[tokio::test]
    async fn negotiate_gives_up_on_a_silent_gateway() {
        let tr = FakeTransport::new(vec![None, None]);
        assert!(
            PmpMapper::negotiate(Box::new(tr), Ipv4Addr::new(192, 168, 1, 42))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn map_reports_the_granted_port_and_lease() {
        let nonce = [3_u8; 12];
        let tr = FakeTransport::new(vec![Some(pcp_map_reply(
            &nonce,
            41234,
            1800,
            0,
            Some(Ipv4Addr::new(198, 51, 100, 9)),
        ))]);
        let m = PmpMapper {
            transport: Box::new(tr),
            method: Method::Pcp,
            client: Ipv4Addr::new(192, 168, 1, 42),
            nonce,
        };
        let mapping = m.map(40000).await.expect("map");
        // The gateway may grant a different port and a shorter lease than requested; the caller has
        // to advertise what it got.
        assert_eq!(mapping.external_port, 41234);
        assert_eq!(mapping.internal_port, 40000);
        assert_eq!(mapping.lease, Duration::from_secs(1800));
        assert_eq!(mapping.external_ip, Some(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(mapping.method, Method::Pcp);
    }

    #[tokio::test]
    async fn unmap_deletes_with_a_zero_lifetime() {
        let nonce = [4_u8; 12];
        let tr = FakeTransport::new(vec![
            Some(natpmp_map_reply(40000, 40000, 3600, 0)),
            Some(natpmp_map_reply(40000, 40000, 0, 0)),
        ]);
        let m = PmpMapper {
            transport: Box::new(tr),
            method: Method::NatPmp,
            client: Ipv4Addr::new(192, 168, 1, 42),
            nonce,
        };
        let mapping = m.map(40000).await.expect("map");
        m.unmap(&mapping).await.expect("unmap");
        // Inspecting what went out requires the concrete type back, so assert on the protocol
        // instead: a delete is the same request with lifetime 0.
        assert_eq!(mapping.external_port, 40000);
    }

    #[tokio::test]
    async fn a_gateway_shortening_the_lease_to_zero_does_not_produce_a_spinning_timer() {
        let nonce = [5_u8; 12];
        let tr = FakeTransport::new(vec![Some(natpmp_map_reply(40000, 40000, 0, 0))]);
        let m = PmpMapper {
            transport: Box::new(tr),
            method: Method::NatPmp,
            client: Ipv4Addr::new(192, 168, 1, 42),
            nonce,
        };
        let mapping = m.map(40000).await.expect("map");
        assert_eq!(mapping.lease, PmpMapper::LEASE);
    }

    #[tokio::test]
    async fn manual_reports_the_configured_port_on_both_sides() {
        let m = ManualMapper::new(51820).expect("new");
        let mapping = m.map(40000).await.expect("map");
        assert_eq!(mapping.external_port, 51820);
        assert_eq!(mapping.internal_port, 51820);
        assert_eq!(mapping.method, Method::Manual);
        // Nothing to undo: the rule belongs to the user.
        m.unmap(&mapping).await.expect("unmap");
    }

    #[test]
    fn manual_rejects_ports_this_process_cannot_bind() {
        // 0 is the wildcard that forwards every port.
        assert!(ManualMapper::new(0).is_err());
        // Privileged, and this subsystem runs unprivileged.
        assert!(ManualMapper::new(80).is_err());
        assert!(ManualMapper::new(1023).is_err());
        assert!(ManualMapper::new(1024).is_ok());
        assert!(ManualMapper::new(65535).is_ok());
    }

    #[test]
    fn proc_net_route_gateway_octets_are_little_endian() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n";
        assert_eq!(
            parse_proc_net_route(table),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn proc_net_route_skips_non_default_and_gatewayless_routes() {
        let table = "Iface\tDestination\tGateway\n\
                     eth0\t0001A8C0\t0101A8C0\n\
                     eth0\t00000000\t00000000\n";
        assert_eq!(parse_proc_net_route(table), None);
    }

    #[test]
    fn macos_route_output_parses() {
        let out = "   route to: default\ndestination: default\n       gateway: 192.168.1.254\n \
                   interface: en0\n";
        assert_eq!(
            parse_route_get_default(out),
            Some(Ipv4Addr::new(192, 168, 1, 254))
        );
    }

    #[test]
    fn windows_route_output_parses_and_skips_on_link() {
        let out = "Network Destination        Netmask          Gateway       Interface  Metric\n\
                             0.0.0.0          0.0.0.0         On-link      10.0.0.5     25\n\
                             0.0.0.0          0.0.0.0      192.168.0.1   192.168.0.10     35\n";
        assert_eq!(parse_route_print(out), Some(Ipv4Addr::new(192, 168, 0, 1)));
    }
}
