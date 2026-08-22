//! UPnP/IGD port mapping, hand-rolled.
//!
//! UPnP is the widest-supported of the three protocols and by far the least well behaved. It is
//! SSDP over UDP multicast to find the gateway, then HTTP to fetch an XML device description, then
//! SOAP to act on it — and consumer routers deviate at every step. Everything unusual below is
//! there because a real device needs it, and the source of each is named so it can be checked
//! rather than taken on faith. The two implementations mined for this are `tailscale.com/net/
//! portmapper` (which runs against a very large fleet of home routers) and `huin/goupnp`.
//!
//! Hand-rolled rather than taken from a crate because the crates bring an HTTP client, an XML
//! parser and the `url`/`idna`/ICU chain — 47 crates for `igd-next` with default features off —
//! against a binary with a size budget, to talk to one LAN device whose URLs never need IDN
//! normalisation. What is actually needed is three SOAP calls with fixed argument lists.
//!
//! Deliberately NOT implemented: SSDP NOTIFY subscriptions, eventing, and IPv6 firewall control.
//! None of them contribute to getting one TCP port forwarded.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::{MapGrant, Mapping, Method, PortMapError};

const SSDP_MULTICAST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);

/// Service types we can map with, best first.
///
/// `WANIPConnection:2` comes first because only it has `AddAnyPortMapping`, which lets the gateway
/// resolve a port conflict itself instead of us guessing again.
///
/// The `dslforum-org` pair are the pre-standard URNs, deprecated in 2015 and still answered by
/// older DSL gateways; `tailscale.com/net/portmapper` still tries them, so we do too.
const SERVICE_TYPES: [&str; 5] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:dslforum-org:service:WANIPConnection:1",
    "urn:dslforum-org:service:WANPPPConnection:1",
];

/// `ConflictInMappingEntry`: the external port is taken by someone else, so retry with another.
const ERR_CONFLICT: u16 = 718;
/// `OnlyPermanentLeasesSupported`. Some gateways reject any non-zero lease.
const ERR_ONLY_PERMANENT: u16 = 725;
/// `InvalidArgs`. Seen in the wild from gateways that mean `OnlyPermanentLeasesSupported`, so it
/// gets the same permanent-lease retry (tailscale#15223).
const ERR_INVALID_ARGS: u16 = 402;

/// One hour, the value the UPnP specification recommends and what the Go implementation requests.
const LEASE_SECS: u32 = 3600;

/// A discovered service we can issue actions against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Service {
    /// Absolute URL to POST SOAP actions to.
    control_url: String,
    /// The service type, which is also the SOAP action namespace.
    service_type: String,
}

// ---------------------------------------------------------------------------
// SSDP
// ---------------------------------------------------------------------------

/// An M-SEARCH for a given search target.
fn msearch(st: &str) -> String {
    // MAN must be quoted, and MX must be present: some devices ignore a search without them.
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: {st}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n"
    )
}

/// Pull the `LOCATION` header out of an SSDP reply.
///
/// Header names are case-insensitive and devices are inconsistent about them, so the match is too.
fn ssdp_location(reply: &str) -> Option<String> {
    reply
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.trim().to_string())
}

/// Find candidate device-description URLs.
///
/// Three things here are not obvious and all three are load-bearing:
///
/// The search is sent to the gateway's UNICAST address before the multicast group. Some LANs and
/// hosts have broken multicast, so the unicast probe is the one that gets through there; and SSDP
/// replies come from the device's unicast address to ours, which stateful host firewalls often drop
/// because they never saw a matching outbound flow — sending the unicast query first teaches the
/// firewall to expect exactly that (tailscale#3197). The multicast query still has to be sent,
/// because strictly-conformant devices answer only that one.
///
/// Two search targets are sent, not one: some devices answer `ssdp:all` with only their first
/// descriptor, which may be something irrelevant like a Wi-Fi Alliance device rather than the
/// gateway, so `InternetGatewayDevice:1` is asked for by name as well (tailscale#3557).
///
/// Every distinct reply is collected rather than the first, because a LAN can hold more than one
/// UPnP gateway and the first to answer is not necessarily the one with the internet connection.
async fn discover_locations(
    gateway: Ipv4Addr,
    window: Duration,
) -> Result<Vec<String>, PortMapError> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    let all = msearch("ssdp:all");
    let igd = msearch("urn:schemas-upnp-org:device:InternetGatewayDevice:1");

    let unicast = SocketAddr::V4(SocketAddrV4::new(gateway, 1900));
    let multicast = SocketAddr::V4(SSDP_MULTICAST);
    // Send failures are not fatal on their own: a host with multicast disabled fails only the
    // multicast send, and the unicast probe may still find the gateway.
    let _ = sock.send_to(all.as_bytes(), unicast).await;
    let _ = sock.send_to(all.as_bytes(), multicast).await;
    let _ = sock.send_to(igd.as_bytes(), multicast).await;

    let mut locations = Vec::new();
    let mut buf = [0_u8; 4096];
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(Ok((n, _))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
        let reply = String::from_utf8_lossy(&buf[..n]);
        if let Some(loc) = ssdp_location(&reply) {
            if !locations.contains(&loc) {
                locations.push(loc);
            }
        }
    }
    if locations.is_empty() {
        return Err(PortMapError::Unavailable);
    }
    Ok(locations)
}

// ---------------------------------------------------------------------------
// Minimal HTTP
// ---------------------------------------------------------------------------

/// Split a `host:port` authority out of an absolute http URL, with the path.
fn split_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("http://")?;
    match rest.find('/') {
        Some(i) => Some((rest[..i].to_string(), rest[i..].to_string())),
        // A URL with no path still addresses the root.
        None => Some((rest.to_string(), "/".to_string())),
    }
}

/// Rewrite a description URL so it points at the gateway.
///
/// A gateway may advertise a `LOCATION` whose host is not its own address — a floating or secondary
/// address that is not necessarily reachable from here (tailscale#5502). The port and path are
/// kept; only the host is repointed.
fn repoint_at_gateway(url: &str, gateway: Ipv4Addr) -> String {
    let Some((authority, path)) = split_url(url) else {
        return url.to_string();
    };
    let port = authority.rsplit_once(':').map(|(_, p)| p).unwrap_or("80");
    let host_matches = authority
        .rsplit_once(':')
        .map(|(h, _)| h == gateway.to_string())
        .unwrap_or(false);
    if host_matches {
        return url.to_string();
    }
    format!("http://{gateway}:{port}{path}")
}

/// Bounded, single-shot HTTP/1.1 over plain TCP.
///
/// Written here rather than pulled in because everything a general client provides — TLS, redirects,
/// connection reuse, cookies, IDN — is irrelevant to one request to a LAN device, and the reply is a
/// small XML document.
async fn http_request(
    url: &str,
    method: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
    limit: usize,
) -> Result<(u16, String), PortMapError> {
    let (authority, path) =
        split_url(url).ok_or_else(|| PortMapError::Malformed(format!("not an http url: {url}")))?;
    let addr: SocketAddr = tokio::net::lookup_host(&authority)
        .await
        .map_err(|e| PortMapError::Malformed(format!("resolve {authority}: {e}")))?
        .next()
        .ok_or_else(|| PortMapError::Malformed(format!("no address for {authority}")))?;

    let mut stream = TcpStream::connect(addr).await?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHOST: {authority}\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    // Close after the reply: this is one request, and it means the body can be read to EOF when a
    // device omits Content-Length.
    req.push_str("CONNECTION: close\r\n");
    match body {
        Some(b) => {
            req.push_str(&format!("CONTENT-LENGTH: {}\r\n\r\n", b.len()));
            req.push_str(b);
        }
        None => req.push_str("\r\n"),
    }
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Bounded read: a device that streams without end must not be able to exhaust memory here.
    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() >= limit {
            break;
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status =
        parse_status(&text).ok_or_else(|| PortMapError::Malformed("no HTTP status line".into()))?;
    let body = split_body(&text);
    Ok((status, body))
}

fn parse_status(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Everything after the header block.
///
/// Chunk-size lines are not stripped: the XML extraction below scans for tags and is unbothered by
/// them, and a chunked-decoding path would be code with no other purpose. Both `\r\n\r\n` and the
/// bare-`\n` form some devices emit are accepted as the separator.
fn split_body(response: &str) -> String {
    if let Some(i) = response.find("\r\n\r\n") {
        return response[i + 4..].to_string();
    }
    if let Some(i) = response.find("\n\n") {
        return response[i + 2..].to_string();
    }
    String::new()
}

// ---------------------------------------------------------------------------
// XML, by tag extraction
// ---------------------------------------------------------------------------

/// The text of the first `<tag>…</tag>`, ignoring namespace prefixes and attributes.
///
/// Tag extraction rather than parsing: the documents involved are a device description and SOAP
/// replies, from which a handful of leaf values are needed. A parser would add a dependency to read
/// values a scan finds just as reliably, and it would still need the same tolerance for namespace
/// prefixes that devices apply inconsistently.
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let mut from = 0;
    while let Some(open_rel) = xml[from..].find('<') {
        let open = from + open_rel;
        let close = open + xml[open..].find('>')?;
        let inner = &xml[open + 1..close];
        // Skip closing tags, declarations and comments.
        if inner.starts_with('/') || inner.starts_with('?') || inner.starts_with('!') {
            from = close + 1;
            continue;
        }
        // Strip attributes, then any namespace prefix.
        let name = inner.split_whitespace().next().unwrap_or(inner);
        let local = name.rsplit(':').next().unwrap_or(name);
        if local.eq_ignore_ascii_case(tag) && !inner.ends_with('/') {
            let after = close + 1;
            let end_rel = xml[after..].find("</")?;
            return Some(xml[after..after + end_rel].trim().to_string());
        }
        from = close + 1;
    }
    None
}

/// Every `<service>` block's (serviceType, controlURL) pair.
///
/// Services can sit at any depth in a device description's nested `deviceList`, so the blocks are
/// found directly instead of walking the device tree.
fn service_blocks(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = xml[from..].find("<service>") {
        let start = from + rel;
        let Some(end_rel) = xml[start..].find("</service>") else {
            break;
        };
        let block = &xml[start..start + end_rel];
        if let (Some(t), Some(u)) = (
            tag_text(block, "serviceType"),
            tag_text(block, "controlURL"),
        ) {
            out.push((t, u));
        }
        from = start + end_rel;
    }
    out
}

/// Make a possibly-relative `controlURL` absolute.
///
/// Devices supply all three forms: absolute, root-relative, and — against the specification —
/// path-relative. `URLBase`, when the description carries one, wins over the location it was
/// fetched from.
fn absolute_control_url(control: &str, location: &str, url_base: Option<&str>) -> Option<String> {
    if control.starts_with("http://") {
        return Some(control.to_string());
    }
    let base = url_base
        .filter(|b| b.starts_with("http://"))
        .unwrap_or(location);
    let (authority, base_path) = split_url(base)?;
    if let Some(rest) = control.strip_prefix('/') {
        return Some(format!("http://{authority}/{rest}"));
    }
    let dir = match base_path.rfind('/') {
        Some(i) => &base_path[..=i],
        None => "/",
    };
    Some(format!("http://{authority}{dir}{control}"))
}

/// The `errorCode` from a SOAP fault, which arrives as an HTTP 500 with the code buried in
/// `detail/UPnPError`. Distinguishing codes is what makes the lease and conflict retries possible,
/// so a fault without one is not usable as a fault.
fn soap_error_code(body: &str) -> Option<u16> {
    tag_text(body, "errorCode")?.trim().parse().ok()
}

// ---------------------------------------------------------------------------
// SOAP
// ---------------------------------------------------------------------------

/// Build a SOAP request body.
///
/// The envelope is hand-written in this exact prefixed shape on purpose: goupnp records a router
/// that answers 500 when the outer default namespace is the SOAP one and is then reassigned inside,
/// which is what a generic serialiser tends to emit.
fn soap_body(service_type: &str, action: &str, args: &[(&str, String)]) -> String {
    let mut s = String::with_capacity(512);
    s.push_str(r#"<?xml version="1.0" encoding="utf-8"?>"#);
    s.push_str(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>"#,
    );
    s.push_str(&format!(r#"<u:{action} xmlns:u="{service_type}">"#));
    for (k, v) in args {
        s.push_str(&format!("<{k}>{}</{k}>", xml_escape(v)));
    }
    s.push_str(&format!("</u:{action}>"));
    s.push_str("</s:Body></s:Envelope>");
    s
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A SOAP fault carrying the UPnP error code, when the device supplied one.
#[derive(Debug)]
struct SoapFault {
    code: Option<u16>,
}

impl Service {
    async fn action(
        &self,
        action: &str,
        args: &[(&str, String)],
    ) -> Result<Result<String, SoapFault>, PortMapError> {
        let body = soap_body(&self.service_type, action, args);
        let soap_action = format!("\"{}#{}\"", self.service_type, action);
        let (status, reply) = http_request(
            &self.control_url,
            "POST",
            &[
                ("CONTENT-TYPE", "text/xml; charset=\"utf-8\""),
                ("SOAPACTION", &soap_action),
            ],
            Some(&body),
            64 * 1024,
        )
        .await?;
        if status == 200 {
            return Ok(Ok(reply));
        }
        Ok(Err(SoapFault {
            code: soap_error_code(&reply),
        }))
    }

    async fn external_ip(&self) -> Result<Ipv4Addr, PortMapError> {
        match self.action("GetExternalIPAddress", &[]).await? {
            Ok(reply) => tag_text(&reply, "NewExternalIPAddress")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| PortMapError::Malformed("no external address in reply".into())),
            Err(f) => Err(PortMapError::Refused(format!(
                "GetExternalIPAddress: upnp error {:?}",
                f.code
            ))),
        }
    }

    /// Whether the gateway considers its WAN link up. Used only to choose between several
    /// candidates, so a device that does not implement it is treated as usable.
    async fn is_connected(&self) -> bool {
        match self.action("GetStatusInfo", &[]).await {
            Ok(Ok(reply)) => tag_text(&reply, "NewConnectionStatus")
                .map(|s| s == "Connected")
                .unwrap_or(true),
            _ => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

/// Arguments shared by `AddPortMapping` and `AddAnyPortMapping`.
///
/// `NewProtocol` is upper-case because some routers reject a lower-case protocol outright
/// (tailscale#7377), and `miniupnpc` sends upper-case for the same reason. `NewRemoteHost` is empty
/// to accept connections from anywhere, which is the point of a peer proxy.
fn add_mapping_args(
    external_port: u16,
    internal_port: u16,
    client: Ipv4Addr,
    lease_secs: u32,
    description: &str,
) -> Vec<(&'static str, String)> {
    vec![
        ("NewRemoteHost", String::new()),
        ("NewExternalPort", external_port.to_string()),
        ("NewProtocol", "TCP".to_string()),
        ("NewInternalPort", internal_port.to_string()),
        ("NewInternalClient", client.to_string()),
        ("NewEnabled", "1".to_string()),
        ("NewPortMappingDescription", description.to_string()),
        ("NewLeaseDuration", lease_secs.to_string()),
    ]
}

/// UPnP against one gateway.
pub(super) struct UpnpMapper {
    service: Service,
    client: Ipv4Addr,
    /// Set once a gateway has told us it only accepts permanent leases, so renewals stop asking for
    /// a duration it already rejected.
    permanent_only: std::sync::atomic::AtomicBool,
}

impl UpnpMapper {
    /// Find a usable gateway service, or fail.
    ///
    /// Several may answer. A device on a second internal network will happily map a port and report
    /// a private external address, which is useless for hosting, so candidates are preferred in
    /// this order: WAN link up, and an external address that is actually public.
    pub(super) async fn discover(
        gateway: Ipv4Addr,
        client: Ipv4Addr,
    ) -> Result<Self, PortMapError> {
        let locations = discover_locations(gateway, Duration::from_millis(1200)).await?;
        let mut fallback: Option<Service> = None;

        for loc in locations {
            let loc = repoint_at_gateway(&loc, gateway);
            let Ok((200, xml)) = http_request(&loc, "GET", &[], None, 256 * 1024).await else {
                continue;
            };
            let url_base = tag_text(&xml, "URLBase");
            let found = service_blocks(&xml);
            let by_type: HashMap<&str, &str> = found
                .iter()
                .map(|(t, u)| (t.as_str(), u.as_str()))
                .collect();

            for wanted in SERVICE_TYPES {
                let Some(control) = by_type.get(wanted) else {
                    continue;
                };
                let Some(control_url) = absolute_control_url(control, &loc, url_base.as_deref())
                else {
                    continue;
                };
                let service = Service {
                    control_url,
                    service_type: wanted.to_string(),
                };
                if !service.is_connected().await {
                    fallback = fallback.or(Some(service));
                    continue;
                }
                match service.external_ip().await {
                    // A public address means this is the gateway that actually faces the internet.
                    Ok(ip) if is_public_v4(ip) => {
                        return Ok(Self::new(service, client));
                    }
                    _ => fallback = fallback.or(Some(service)),
                }
            }
        }
        fallback
            .map(|s| Self::new(s, client))
            .ok_or(PortMapError::Unavailable)
    }

    fn new(service: Service, client: Ipv4Addr) -> Self {
        Self {
            service,
            client,
            permanent_only: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Ask for a mapping, working around the two failures that are worth retrying.
    ///
    /// A gateway that answers `OnlyPermanentLeasesSupported` — or `InvalidArgs`, which some mean by
    /// it (tailscale#9343, #15223) — gets asked again with no lease at all. A gateway that answers
    /// `ConflictInMappingEntry` has that external port taken by something else, so another is
    /// tried. `AddAnyPortMapping` avoids the conflict case entirely by letting the gateway choose,
    /// but only `WANIPConnection:2` has it.
    async fn request(&self, internal_port: u16) -> Result<MapGrant, PortMapError> {
        use std::sync::atomic::Ordering;
        let v2 = self.service.service_type.ends_with("WANIPConnection:2");
        let mut external = sanitize_external_port(internal_port);

        for attempt in 0..4 {
            let lease = if self.permanent_only.load(Ordering::Relaxed) {
                0
            } else {
                LEASE_SECS
            };
            let args = add_mapping_args(
                external,
                internal_port,
                self.client,
                lease,
                "spark-unbounded",
            );
            let action = if v2 {
                "AddAnyPortMapping"
            } else {
                "AddPortMapping"
            };
            match self.service.action(action, &args).await? {
                Ok(reply) => {
                    // AddAnyPortMapping reports the port it actually reserved, which may not be the
                    // one asked for; AddPortMapping reserves exactly what was asked.
                    let granted = tag_text(&reply, "NewReservedPort")
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(external);
                    return Ok(MapGrant {
                        external_port: granted,
                        lease: Duration::from_secs(if lease == 0 {
                            LEASE_SECS as u64
                        } else {
                            lease as u64
                        }),
                        external_ip: None,
                    });
                }
                Err(fault) => match fault.code {
                    Some(ERR_ONLY_PERMANENT) | Some(ERR_INVALID_ARGS)
                        if !self.permanent_only.load(Ordering::Relaxed) =>
                    {
                        self.permanent_only.store(true, Ordering::Relaxed);
                    }
                    Some(ERR_CONFLICT) => {
                        external = next_external_port(external, attempt);
                    }
                    other => {
                        return Err(PortMapError::Refused(format!(
                            "{action}: upnp error {other:?}"
                        )));
                    }
                },
            }
        }
        Err(PortMapError::Refused(
            "gateway refused every external port tried".into(),
        ))
    }

    pub(super) async fn map(&self, internal_port: u16) -> Result<Mapping, PortMapError> {
        let grant = self.request(internal_port).await?;
        // Best effort: a mapping without a known external address is still usable, because the
        // server falls back to the source address it sees when we register.
        let external_ip = self
            .service
            .external_ip()
            .await
            .ok()
            .filter(|ip| is_public_v4(*ip));
        Ok(Mapping {
            external_port: grant.external_port,
            internal_port,
            external_ip,
            lease: grant.lease,
            method: Method::Upnp,
        })
    }

    pub(super) async fn unmap(&self, mapping: &Mapping) -> Result<(), PortMapError> {
        let args = vec![
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", mapping.external_port.to_string()),
            ("NewProtocol", "TCP".to_string()),
        ];
        match self.service.action("DeletePortMapping", &args).await? {
            Ok(_) => Ok(()),
            Err(f) => Err(PortMapError::Refused(format!(
                "DeletePortMapping: upnp error {:?}",
                f.code
            ))),
        }
    }

    pub(super) async fn renew(&self, mapping: &Mapping) -> Result<Mapping, PortMapError> {
        // Re-issuing the add is how a lease is extended; most gateways treat it as an extension and
        // the rest replace the entry, which is equally fine.
        let grant = self.request(mapping.internal_port).await?;
        Ok(Mapping {
            external_port: grant.external_port,
            internal_port: mapping.internal_port,
            external_ip: mapping.external_ip,
            lease: grant.lease,
            method: Method::Upnp,
        })
    }
}

/// Keep the requested external port out of two ranges that cause trouble.
///
/// Zero is a WILDCARD in the specification — it forwards every unmapped external port to this host —
/// so it must never be sent by accident. Ports below 1024 are privileged and many gateways refuse to
/// map them at all.
fn sanitize_external_port(internal_port: u16) -> u16 {
    if internal_port >= 1024 {
        internal_port
    } else {
        // Deterministic rather than random: a caller retrying after a restart should ask for the
        // same port, so a mapping left behind by a previous run is reused instead of accumulating.
        1024 + internal_port
    }
}

/// Step to another external port after a conflict, staying inside the unprivileged range.
fn next_external_port(current: u16, attempt: u32) -> u16 {
    let step = 1 + attempt as u16;
    match current.checked_add(step) {
        Some(p) if p >= 1024 => p,
        _ => 1024,
    }
}

/// Whether an address is usable as a peer's public address. A gateway behind a second layer of NAT
/// reports a private one, and hosting through it cannot work.
fn is_public_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        // 100.64.0.0/10, carrier-grade NAT.
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msearch_carries_the_headers_devices_require() {
        let m = msearch("ssdp:all");
        assert!(m.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(m.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(m.contains("ST: ssdp:all\r\n"));
        // MAN must be quoted or devices ignore the search.
        assert!(m.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(m.contains("MX: 2\r\n"));
        assert!(m.ends_with("\r\n\r\n"));
    }

    #[test]
    fn ssdp_location_is_case_insensitive() {
        let reply = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n\
                     Location: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n";
        assert_eq!(
            ssdp_location(reply).as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
        let upper = "HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1/desc.xml\r\n\r\n";
        assert_eq!(
            ssdp_location(upper).as_deref(),
            Some("http://10.0.0.1/desc.xml")
        );
        assert_eq!(ssdp_location("HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn a_location_pointing_elsewhere_is_repointed_at_the_gateway() {
        // The advertised host may be an address that is not reachable from here.
        assert_eq!(
            repoint_at_gateway(
                "http://10.9.9.9:5000/desc.xml",
                Ipv4Addr::new(192, 168, 1, 1)
            ),
            "http://192.168.1.1:5000/desc.xml"
        );
        // A location that already names the gateway is left exactly as it is.
        assert_eq!(
            repoint_at_gateway(
                "http://192.168.1.1:5000/desc.xml",
                Ipv4Addr::new(192, 168, 1, 1)
            ),
            "http://192.168.1.1:5000/desc.xml"
        );
    }

    #[test]
    fn tag_text_ignores_prefixes_and_attributes() {
        assert_eq!(tag_text("<a><b>x</b></a>", "b").as_deref(), Some("x"));
        // Devices apply namespace prefixes inconsistently.
        assert_eq!(
            tag_text(
                "<s:Body><u:NewExternalIPAddress>1.2.3.4</u:NewExternalIPAddress></s:Body>",
                "NewExternalIPAddress"
            )
            .as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            tag_text(r#"<controlURL xmlns:x="y">/ctl</controlURL>"#, "controlurl").as_deref(),
            Some("/ctl")
        );
        assert_eq!(tag_text("<a/>", "a"), None);
        assert_eq!(
            tag_text(r#"<?xml version="1.0"?><a>1</a>"#, "a").as_deref(),
            Some("1")
        );
    }

    #[test]
    fn service_blocks_are_found_at_any_depth() {
        let xml = "<root><device><deviceList><device><serviceList>\
                   <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
                   <controlURL>/ctl/IPConn</controlURL></service>\
                   </serviceList></device></deviceList></device></root>";
        assert_eq!(
            service_blocks(xml),
            vec![(
                "urn:schemas-upnp-org:service:WANIPConnection:1".to_string(),
                "/ctl/IPConn".to_string()
            )]
        );
    }

    #[test]
    fn control_urls_resolve_in_all_three_forms_devices_send() {
        let loc = "http://192.168.1.1:5000/sub/rootDesc.xml";
        assert_eq!(
            absolute_control_url("http://192.168.1.1:5000/ctl", loc, None).as_deref(),
            Some("http://192.168.1.1:5000/ctl")
        );
        assert_eq!(
            absolute_control_url("/ctl/IPConn", loc, None).as_deref(),
            Some("http://192.168.1.1:5000/ctl/IPConn")
        );
        // Path-relative is against the spec but devices send it.
        assert_eq!(
            absolute_control_url("ctl/IPConn", loc, None).as_deref(),
            Some("http://192.168.1.1:5000/sub/ctl/IPConn")
        );
        // URLBase, when present, wins over the location.
        assert_eq!(
            absolute_control_url("/ctl", loc, Some("http://192.168.1.1:80/")).as_deref(),
            Some("http://192.168.1.1:80/ctl")
        );
    }

    #[test]
    fn soap_envelope_uses_the_prefixed_form() {
        let body = soap_body(
            "urn:svc:1",
            "AddPortMapping",
            &[("NewExternalPort", "40000".into())],
        );
        // A default-namespace envelope reassigned inside makes at least one router answer 500, so
        // the prefixed shape is deliberate.
        assert!(body.contains(r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/""#));
        assert!(body.contains(r#"<u:AddPortMapping xmlns:u="urn:svc:1">"#));
        assert!(body.contains("<NewExternalPort>40000</NewExternalPort>"));
        assert!(body.ends_with("</s:Body></s:Envelope>"));
    }

    #[test]
    fn soap_arguments_are_escaped() {
        let body = soap_body("urn:svc:1", "A", &[("D", "a&b<c".into())]);
        assert!(body.contains("<D>a&amp;b&lt;c</D>"));
    }

    #[test]
    fn fault_error_code_is_extracted_from_the_detail() {
        let fault = r#"<?xml version="1.0"?><s:Envelope><s:Body><s:Fault>
            <faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>
            <detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
            <errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription>
            </UPnPError></detail></s:Fault></s:Body></s:Envelope>"#;
        assert_eq!(soap_error_code(fault), Some(725));
        assert_eq!(soap_error_code("<a>no code</a>"), None);
    }

    #[test]
    fn add_mapping_args_avoid_the_two_known_rejections() {
        let args = add_mapping_args(40000, 40000, Ipv4Addr::new(192, 168, 1, 5), 3600, "d");
        let map: std::collections::HashMap<_, _> = args.iter().cloned().collect();
        // Lower-case is rejected outright by some routers.
        assert_eq!(map.get("NewProtocol").map(String::as_str), Some("TCP"));
        // Empty RemoteHost means "from anywhere", which is the point of a peer proxy.
        assert_eq!(map.get("NewRemoteHost").map(String::as_str), Some(""));
        assert_eq!(map.get("NewEnabled").map(String::as_str), Some("1"));
        assert_eq!(
            map.get("NewLeaseDuration").map(String::as_str),
            Some("3600")
        );
    }

    #[test]
    fn external_port_zero_is_never_requested() {
        // Zero is a wildcard that forwards every unmapped port to this host.
        assert_ne!(sanitize_external_port(0), 0);
        assert!(sanitize_external_port(0) >= 1024);
        // Privileged ports are widely refused.
        assert!(sanitize_external_port(80) >= 1024);
        // An already-safe port is left alone so a restart reuses its own mapping.
        assert_eq!(sanitize_external_port(40000), 40000);
    }

    #[test]
    fn conflict_retries_stay_unprivileged() {
        assert_eq!(next_external_port(40000, 0), 40001);
        assert_eq!(next_external_port(40000, 1), 40002);
        // Wrapping past the top of the range must not land on a privileged port.
        assert_eq!(next_external_port(65535, 0), 1024);
    }

    #[test]
    fn a_double_natted_gateway_is_not_treated_as_public() {
        assert!(is_public_v4(Ipv4Addr::new(93, 184, 216, 34)));
        // 203.0.113.0/24 is TEST-NET-3 and reserved for documentation, so it is not a public
        // address a peer could be reached on either.
        assert!(!is_public_v4(Ipv4Addr::new(203, 0, 113, 5)));
        assert!(!is_public_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_public_v4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_public_v4(Ipv4Addr::new(172, 16, 0, 1)));
        // Carrier-grade NAT: a real address, but not one anything can connect to.
        assert!(!is_public_v4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_public_v4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn http_status_and_body_split_tolerates_a_bare_lf_separator() {
        assert_eq!(
            parse_status("HTTP/1.1 500 Internal Server Error\r\n\r\n"),
            Some(500)
        );
        assert_eq!(split_body("HTTP/1.1 200 OK\r\nX: 1\r\n\r\nbody"), "body");
        // Some devices emit LF-only line endings.
        assert_eq!(split_body("HTTP/1.1 200 OK\nX: 1\n\nbody"), "body");
        assert_eq!(split_body("HTTP/1.1 200 OK"), "");
    }

    #[test]
    fn service_types_are_tried_best_first() {
        // Only WANIPConnection:2 has AddAnyPortMapping, which lets the gateway resolve a conflict
        // itself, so it has to be first.
        assert_eq!(
            SERVICE_TYPES[0],
            "urn:schemas-upnp-org:service:WANIPConnection:2"
        );
        // The pre-standard URNs are still answered by older DSL gateways.
        assert!(SERVICE_TYPES.contains(&"urn:dslforum-org:service:WANPPPConnection:1"));
    }
}
