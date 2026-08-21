//! ICE STUN servers for the volunteer (donor) side.
//!
//! Without STUN, ICE gathers host candidates only and cannot traverse most NATs — so a donor
//! advertises, a censored client answers, and the DataChannel never opens. Spark shipped with an
//! empty list and consequently carried no traffic; Lantern carries traffic quickly.
//!
//! **This deliberately mirrors what Lantern does**, rather than inventing something better. Lantern's
//! donor (`radiance/unbounded/unbounded.go`) takes `clientcore.NewDefaultWebRTCOptions()` and
//! overrides only the discovery and egress URLs — verified: `STUNBatch` is never overridden anywhere
//! in radiance. So the batch comes from broflake's `DefaultSTUNBatchFunc`, which fetches
//! `pradt2/always-online-stun`'s `valid_ipv4s.txt` and picks 5 at random, prefixing each with
//! `stun:`.
//!
//! Two properties of that design are worth naming rather than discovering later:
//!
//! - It is a **runtime dependency on `raw.githubusercontent.com`** and on a third-party list nobody
//!   here curates. That is a real trust and availability surface for a censorship tool: the fetch is
//!   plausibly blocked in exactly the regions that matter, and the list's contents are not ours.
//!   Accepted for now on the grounds of matching the implementation that demonstrably works; the
//!   principled fix is for the config to carry the donor's STUN servers the way the *consumer's*
//!   outbound already does (`stun_servers`), at which point this whole module becomes a fallback.
//! - Failure is **non-fatal**. An unreachable list yields an empty batch and the donor behaves as it
//!   did before — no worse, and it still gathers host candidates, which suffice on an open network.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Host serving the STUN list. Same source broflake uses, so a donor here joins the mesh on the same
/// terms as a Lantern donor or a browser-widget donor.
const LIST_HOST: &str = "raw.githubusercontent.com";
const LIST_PORT: u16 = 443;
const LIST_PATH: &str = "/pradt2/always-online-stun/master/valid_ipv4s.txt";

/// How many to select. Matches broflake's `STUNBatchSize`.
pub const DEFAULT_BATCH_SIZE: usize = 5;

/// Embedded fallback, used when the remote list is unreachable — which for a censorship tool is not a
/// remote possibility: `raw.githubusercontent.com` is exactly the sort of host that gets blocked, and
/// a third-party repo can be renamed or emptied without notice. Broflake has no fallback and simply
/// gets no STUN in that case; this is the one place spark deliberately does more than mirror it.
///
/// Chosen for **operator diversity** rather than length: one company's outage must not take the whole
/// list with it. Five operators, and `stun.nextcloud.com` is on **443** so at least one entry survives
/// egress filtering that permits only web ports.
///
/// Every entry was verified with a real RFC 5389 binding request on 2026-08-20 (a Binding Success
/// carrying XOR-MAPPED-ADDRESS, not merely a reachable port). `stun.stunprotocol.org`, which older
/// guides still recommend, was dropped from this set because it no longer resolves — which is the
/// argument for re-probing these rather than trusting them indefinitely.
const EMBEDDED: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "global.stun.twilio.com:3478",
    "stun.nextcloud.com:443",
    "stun.sipgate.net:3478",
];

/// Cap on the response body. The list is a few tens of KiB of `ip:port` lines; this bounds a
/// misbehaving or hostile server without being anywhere near the real size.
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// How long the whole fetch may take before the donor gives up and starts with host candidates only.
/// Sharing is a background activity — it must not stall startup waiting on a third-party host.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Fetch the public STUN list and return up to `size` entries as `stun:host:port`, in random order.
///
/// Returns the reason on failure rather than swallowing it. The **caller** decides to degrade — a
/// donor with no STUN is degraded, not broken, so refusing to share would be worse — but it decides
/// that visibly, and it is the side with a `tracing` subscriber attached. This crate deliberately
/// carries no logging dependency of its own.
async fn batch(size: usize) -> Result<Vec<String>, String> {
    match tokio::time::timeout(FETCH_TIMEOUT, fetch_list()).await {
        Ok(Ok(body)) => {
            let picked = select(&body, size);
            // A 200 carrying nothing usable is a failure, not a success with an empty batch: the
            // caller would otherwise start a donor with no STUN and no reason recorded.
            if picked.is_empty() {
                return Err("remote list contained no usable entries".into());
            }
            Ok(picked)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(format!("timed out after {FETCH_TIMEOUT:?}")),
    }
}

/// The embedded fallback, sampled the same way as the remote list.
///
/// Sampled rather than returned whole so donors do not all present ICE the same servers in the same
/// order — and so the set can grow past `size` without this becoming a different code path.
///
/// Makes no network call, so it is also the way to get a usable list offline.
///
/// # Examples
///
/// ```
/// # use spark_sharing::{stun_embedded_batch, STUN_BATCH_SIZE};
/// let servers = stun_embedded_batch(STUN_BATCH_SIZE);
/// assert_eq!(servers.len(), STUN_BATCH_SIZE);
/// // Each is an ICE-ready URL, e.g. "stun:stun.cloudflare.com:3478".
/// assert!(servers.iter().all(|s| s.starts_with("stun:")));
/// // Asking for fewer than the set holds returns exactly that many.
/// assert_eq!(stun_embedded_batch(2).len(), 2);
/// ```
pub fn embedded_batch(size: usize) -> Vec<String> {
    select_from(EMBEDDED.to_vec(), size)
}

/// The batch to actually use: the remote list when it works, the embedded set otherwise.
///
/// Returns `(servers, from_remote, why_not)` — the servers to hand ICE, whether they came from the
/// remote list, and if not, the reason. The reason is returned rather than logged because this crate
/// carries no logging dependency; the caller has the subscriber and decides how loudly to report a
/// fallback.
///
/// Never fails: a donor with no STUN is degraded, not broken, so the embedded set is always available
/// as the floor. `servers` is therefore non-empty whenever `size > 0`.
///
/// # Examples
///
/// ```no_run
/// # use spark_sharing::{stun_batch_or_embedded, STUN_BATCH_SIZE};
/// # async fn run() {
/// let (servers, from_remote, why_not) = stun_batch_or_embedded(STUN_BATCH_SIZE).await;
/// if let Some(reason) = why_not {
///     // The remote list was unreachable — expected in a censored region, and survivable.
///     eprintln!("using {} embedded STUN servers: {reason}", servers.len());
/// }
/// assert!(!servers.is_empty());
/// assert!(servers.iter().all(|s| s.starts_with("stun:")));
/// let _ = from_remote;
/// # }
/// ```
pub async fn batch_or_embedded(size: usize) -> (Vec<String>, bool, Option<String>) {
    match batch(size).await {
        Ok(servers) => (servers, true, None),
        Err(e) => (embedded_batch(size), false, Some(e)),
    }
}

/// Pick up to `size` entries at random, `stun:`-prefixed.
///
/// Selection is by swap-remove from a shrinking candidate pool (broflake's approach), which samples
/// *without replacement* — handing ICE the same server five times would waste four of the five slots.
fn select(body: &str, size: usize) -> Vec<String> {
    // Normalized, validated, de-duplicated — in that order — before sampling. A `BTreeSet` because
    // the remote list is untrusted input: `swap_remove` sampling removes a *position*, not a value, so
    // a list containing the same endpoint twice could otherwise be picked twice and waste an ICE slot.
    let unique: std::collections::BTreeSet<String> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(public_v4_endpoint)
        .collect();
    let candidates: Vec<&str> = unique.iter().map(String::as_str).collect();
    select_from(candidates, size)
}

/// Normalize one untrusted list entry to `ip:port`, or reject it.
///
/// The remote list is `valid_ipv4s.txt` — literal IPv4 socket addresses — so this parses strictly
/// rather than accepting anything containing a colon. That matters beyond tidiness: entries are
/// attacker-influenceable (a third-party repo), and ICE will dutifully send STUN probes wherever it is
/// pointed. An entry naming `127.0.0.1`, `10.x`, or `169.254.x` would aim that traffic at the
/// volunteer's own host or LAN. Only globally-routable addresses with a non-zero port survive.
///
/// The **embedded** fallback deliberately does not go through here: those are hostnames, curated in
/// this file, and resolving them to check would mean a DNS lookup per entry to validate a list we
/// already trust.
fn public_v4_endpoint(line: &str) -> Option<String> {
    let addr: std::net::SocketAddrV4 = line.parse().ok()?;
    if addr.port() == 0 || !is_public_v4(addr.ip()) {
        return None;
    }
    Some(addr.to_string())
}

/// Whether `ip` is a globally-routable IPv4 address.
///
/// Hand-rolled because `Ipv4Addr::is_global` is still unstable. The listed ranges are the ones that
/// would point ICE somewhere harmful or useless — loopback and private/link-local aim at the
/// volunteer's own machine or LAN, and the rest cannot answer a STUN request at all.
fn is_public_v4(ip: &std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        // 0.0.0.0/8 "this network", and 100.64.0.0/10 carrier-grade NAT — a CGNAT address is a
        // provider's internal space, not somewhere a public STUN server lives.
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24 IETF protocol assignments, 198.18.0.0/15 benchmarking, 240.0.0.0/4 reserved.
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

/// Sample up to `size` of `candidates` without replacement, `stun:`-prefixed. Shared by the remote
/// list and the embedded fallback so they cannot drift in format or selection behaviour.
fn select_from(mut candidates: Vec<&str>, size: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(size.min(candidates.len()));
    while out.len() < size && !candidates.is_empty() {
        let idx = random_below(candidates.len());
        out.push(format!("stun:{}", candidates[idx]));
        candidates.swap_remove(idx);
    }
    out
}

/// A uniform index below `n`, from the system CSPRNG.
///
/// Rejection sampling rather than `% n`, which biases toward low indices when `n` does not divide the
/// range. Overkill for choosing STUN servers, but it is three lines and removes the need to reason
/// about whether the bias matters.
fn random_below(n: usize) -> usize {
    use ring::rand::SecureRandom;
    if n <= 1 {
        return 0;
    }
    let rng = ring::rand::SystemRandom::new();
    let limit = (u32::MAX / n as u32) * n as u32;
    loop {
        let mut raw = [0_u8; 4];
        if rng.fill(&mut raw).is_err() {
            // The CSPRNG is unavailable; any index is better than refusing to share.
            return 0;
        }
        let v = u32::from_be_bytes(raw);
        if v < limit {
            return (v % n as u32) as usize;
        }
    }
}

/// GET the list over HTTPS, mirroring the raw rustls + tokio path in [`crate::geo`] rather than
/// pulling in an HTTP client.
async fn fetch_list() -> Result<String, String> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(LIST_HOST).map_err(|e| e.to_string())?;

    let stream = TcpStream::connect((LIST_HOST, LIST_PORT))
        .await
        .map_err(|e| e.to_string())?;
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| e.to_string())?;

    let request = format!(
        "GET {LIST_PATH} HTTP/1.1\r\nHost: {LIST_HOST}\r\nAccept: text/plain\r\n\
         User-Agent: spark\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let mut received = Vec::with_capacity(64 * 1024);
    loop {
        let mut chunk = [0_u8; 8192];
        let read = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..read]);
        // Checked right after appending, so one read cannot push far past the cap.
        if received.len() > MAX_RESPONSE_BYTES {
            return Err("STUN list exceeds size limit".into());
        }
    }
    body_of_2xx(&received)
}

/// Body of a raw HTTP/1.1 response, requiring 2xx.
///
/// The endpoint answers a `Content-Length`-framed body read to EOF via `Connection: close`, so no
/// chunked decoding — a framing surprise fails here or yields nothing usable at [`select`], and both
/// degrade to an empty batch.
fn body_of_2xx(received: &[u8]) -> Result<String, String> {
    let text = String::from_utf8_lossy(received);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "no header terminator".to_string())?;
    let status = head.lines().next().unwrap_or_default();
    // `HTTP/1.1 200 OK` — the code is the second token.
    let ok = status
        .split_whitespace()
        .nth(1)
        .is_some_and(|c| c.starts_with('2'));
    if !ok {
        return Err(format!("non-2xx status: {status}"));
    }
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_up_to_size_prefixed_and_without_repeats() {
        let body = "1.1.1.1:3478\n2.2.2.2:3478\n3.3.3.3:3478\n4.4.4.4:3478\n";
        let picked = select(body, 3);
        assert_eq!(picked.len(), 3);
        assert!(picked.iter().all(|s| s.starts_with("stun:")));
        // Sampling WITHOUT replacement: a repeat would silently waste an ICE slot.
        let mut deduped = picked.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            picked.len(),
            "picked a server twice: {picked:?}"
        );
    }

    #[test]
    fn asking_for_more_than_the_list_holds_yields_the_whole_list() {
        let picked = select("1.1.1.1:3478\n2.2.2.2:3478\n", 10);
        assert_eq!(picked.len(), 2);
    }

    #[test]
    fn skips_blank_comment_and_malformed_lines() {
        // Not a hypothetical: the list is third-party, so its format is free to grow a header or a
        // comment, and a malformed entry must be dropped rather than handed to ICE as a URL.
        let body = "\n# comment\n1.1.1.1:3478\nnot-an-endpoint\n   \n2.2.2.2:19302\n";
        let picked = select(body, 10);
        assert_eq!(picked.len(), 2);
        assert!(picked.contains(&"stun:1.1.1.1:3478".to_string()));
        assert!(picked.contains(&"stun:2.2.2.2:19302".to_string()));
    }

    /// The remote list is attacker-influenceable (a third-party repo), and ICE sends STUN probes
    /// wherever it is pointed — so an entry naming the volunteer's own host or LAN must never reach it.
    #[test]
    fn rejects_non_public_and_malformed_endpoints_from_the_remote_list() {
        let body = "\n             127.0.0.1:3478\n             10.0.0.5:3478\n             192.168.1.1:3478\n             172.16.0.1:3478\n             169.254.1.1:3478\n             100.64.0.1:3478\n             0.0.0.0:3478\n             224.0.0.1:3478\n             255.255.255.255:3478\n             203.0.113.5:3478\n             198.18.0.1:3478\n             240.0.0.1:3478\n             192.0.0.1:3478\n             1.1.1.1:0\n             1.1.1.1:notaport\n             1.1.1.1\n             [2001:db8::1]:3478\n             9.9.9.9:3478\n";
        let picked = select(&body.replace("             ", ""), 50);
        // Only the one globally-routable entry with a usable port survives.
        assert_eq!(
            picked,
            vec!["stun:9.9.9.9:3478".to_string()],
            "a non-public or malformed endpoint reached ICE"
        );
    }

    /// Sampling removes a vector *position*, so a list repeating an endpoint could otherwise hand ICE
    /// the same server twice and waste a slot. Deduplication happens before sampling, not during.
    #[test]
    fn duplicate_remote_entries_are_collapsed_before_sampling() {
        let body = "1.1.1.1:3478\n1.1.1.1:3478\n1.1.1.1:3478\n2.2.2.2:3478\n";
        let picked = select(body, 5);
        assert_eq!(picked.len(), 2, "duplicates were not collapsed: {picked:?}");
    }

    #[test]
    fn is_public_v4_classifies_the_edges() {
        use std::net::Ipv4Addr;
        for bad in [
            "127.0.0.1",
            "10.1.1.1",
            "172.31.255.255",
            "192.168.0.1",
            "169.254.0.1",
            "100.127.255.255",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "203.0.113.1",
            "198.19.0.1",
            "240.0.0.1",
            "255.0.0.1",
            "192.0.0.8",
        ] {
            assert!(
                !is_public_v4(&bad.parse::<Ipv4Addr>().unwrap()),
                "{bad} must be rejected"
            );
        }
        for good in [
            "1.1.1.1",
            "8.8.8.8",
            "9.9.9.9",
            "100.63.255.255",
            "100.128.0.1",
            "192.0.1.1",
        ] {
            assert!(
                is_public_v4(&good.parse::<Ipv4Addr>().unwrap()),
                "{good} must be accepted"
            );
        }
    }

    #[test]
    fn an_empty_list_yields_no_servers_rather_than_panicking() {
        assert!(select("", 5).is_empty());
        assert!(select("\n\n#only comments\n", 5).is_empty());
    }

    /// The fallback is the whole point of embedding it: it must be usable with no network at all.
    #[test]
    fn the_embedded_fallback_yields_servers_offline() {
        let picked = embedded_batch(DEFAULT_BATCH_SIZE);
        assert_eq!(picked.len(), DEFAULT_BATCH_SIZE);
        assert!(picked.iter().all(|s| s.starts_with("stun:")));
        let mut deduped = picked.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), picked.len(), "duplicate in the fallback");
    }

    /// Operator diversity is the property that makes the fallback worth having — five entries from one
    /// provider would all fail together, which is the failure it exists to survive.
    #[test]
    fn the_embedded_fallback_spans_several_operators_and_includes_a_443_entry() {
        // Registrable-ish suffix: last two labels. Crude, but enough to catch "all Google".
        let operators: std::collections::BTreeSet<String> = EMBEDDED
            .iter()
            .filter_map(|e| e.rsplit_once(':').map(|(host, _)| host))
            .map(|h| h.split('.').rev().take(2).collect::<Vec<_>>().join("."))
            .collect();
        assert!(
            operators.len() >= 4,
            "too few distinct operators, one outage would take them all: {operators:?}"
        );
        assert!(
            EMBEDDED.iter().any(|e| e.ends_with(":443")),
            "no 443 entry, so egress filtering that permits only web ports leaves nothing"
        );
    }

    #[test]
    fn rejects_a_non_2xx_response() {
        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert!(body_of_2xx(resp).is_err());
    }

    #[test]
    fn extracts_a_2xx_body() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n1.1.1.1:3478\n";
        assert_eq!(body_of_2xx(resp).unwrap(), "1.1.1.1:3478\n");
    }

    #[test]
    fn random_below_stays_in_range() {
        for n in [1_usize, 2, 5, 17] {
            for _ in 0..64 {
                assert!(random_below(n) < n, "out of range for n={n}");
            }
        }
    }
}
