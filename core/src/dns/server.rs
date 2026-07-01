//! The fake-IP DNS server: answer the app's A/AAAA queries with fake IPs, recover the domain at
//! connect time.
//!
//! The server owns the query→answer half; the proxy forwarders own the recover half (a flow's fake
//! destination → its domain). Both touch the same pool, so it's shared behind a `Mutex` via
//! [`SharedFakeIp`]. v1 answers only IN-class A/AAAA with fakes; every other query type gets an empty
//! NOERROR (NODATA) so clients fall back to A/AAAA — no HTTPS/SVCB IP-hint or ECH can bypass fake-IP.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tracing::debug;

use super::fakeip::FakeIpPool;
use super::wire;

/// A fake-IP pool shared between the DNS server (allocates on query) and connect-time recovery in the
/// proxy forwarders (recovers on dial). Behind a `Mutex` since those run on different tasks.
pub type SharedFakeIp = Arc<Mutex<FakeIpPool>>;

/// Build a shared fake-IP pool with the given entry `ttl` and live-mapping `cap`.
pub fn shared_pool(ttl: Duration, cap: usize) -> SharedFakeIp {
    Arc::new(Mutex::new(FakeIpPool::new(ttl, cap)))
}

/// Recover the domain a fake IP stands for — the connect-time seam the proxy forwarders call. `None`
/// for a real IP or an unknown/expired fake IP (the caller then routes on the IP itself). Recovers
/// even a poisoned lock (the map stays structurally valid), so a panic elsewhere can't wedge routing.
pub fn recover_domain(pool: &SharedFakeIp, ip: IpAddr) -> Option<String> {
    pool.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .recover(ip, Instant::now())
}

/// Adapts the shared fake-IP pool to the forwarder's [`crate::proxy::DomainRecoverer`] seam, so the
/// TCP/UDP forwarders can recover a flow's domain from its fake destination IP at connect time
/// without depending on the `dns` module directly.
pub struct FakeIpRecoverer {
    pool: SharedFakeIp,
}

impl FakeIpRecoverer {
    /// A recoverer over `pool` (the same pool the [`DnsServer`] allocates into).
    pub fn new(pool: SharedFakeIp) -> Self {
        Self { pool }
    }
}

impl crate::proxy::DomainRecoverer for FakeIpRecoverer {
    fn recover(&self, ip: IpAddr) -> Option<String> {
        recover_domain(&self.pool, ip)
    }
}

/// Answers the app's DNS queries with fake IPs from the shared pool.
pub struct DnsServer {
    pool: SharedFakeIp,
    /// TTL (seconds) stamped into A/AAAA answers. Kept short so the client re-queries and the pool's
    /// entries stay warm; it needn't equal the pool's own entry TTL.
    answer_ttl_secs: u32,
}

impl DnsServer {
    /// A server over `pool`, stamping `answer_ttl_secs` into its A/AAAA answers.
    pub fn new(pool: SharedFakeIp, answer_ttl_secs: u32) -> Self {
        Self {
            pool,
            answer_ttl_secs,
        }
    }

    /// Handle one raw DNS query datagram, returning the raw response to send back, or `None` to drop
    /// (unparseable input). IN-class A/AAAA get a fake IP and a stored `fakeip→domain` mapping; every
    /// other type gets an empty NOERROR (NODATA). Forwarding non-A/AAAA upstream is deferred (design).
    pub fn handle(&self, query_bytes: &[u8]) -> Option<Vec<u8>> {
        let query = match wire::parse_query(query_bytes) {
            Ok(q) => q,
            Err(e) => {
                debug!(error = %e, "dns: dropping unparseable query");
                return None;
            }
        };
        let want_v6 = match query.qtype {
            wire::TYPE_A if query.qclass == wire::CLASS_IN => false,
            wire::TYPE_AAAA if query.qclass == wire::CLASS_IN => true,
            // Non-A/AAAA (HTTPS/SVCB, TXT, PTR, …): NODATA so the client falls back to A/AAAA.
            _ => return Some(wire::build_response(&query, &[], self.answer_ttl_secs)),
        };
        // An empty QNAME (the DNS root) has no address and can't be recovered into a dialable domain
        // (`Address::domain("")` is rejected), so answer NODATA rather than store an unusable mapping.
        if query.name.is_empty() {
            return Some(wire::build_response(&query, &[], self.answer_ttl_secs));
        }
        let ip = self
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .allocate(&query.name, want_v6, Instant::now());
        Some(wire::build_response(
            &query,
            std::slice::from_ref(&ip),
            self.answer_ttl_secs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-encode a standard one-question query (no compression) for the server tests.
    fn make_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&[0x01, 0x00]); // RD set
        b.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR counts
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        b
    }

    /// Decode the first A/AAAA answer IP from a response built by [`wire::build_response`] (whose
    /// answer name is always a 2-byte compression pointer).
    fn first_answer(resp: &[u8]) -> Option<IpAddr> {
        if u16::from_be_bytes([resp[6], resp[7]]) == 0 {
            return None; // ANCOUNT == 0
        }
        let mut i = 12; // skip header
        while resp[i] != 0 {
            i += 1 + resp[i] as usize; // walk the (uncompressed) question name
        }
        i += 1 + 4; // root label + qtype + qclass
        i += 2; // answer NAME (compression pointer)
        let rtype = u16::from_be_bytes([resp[i], resp[i + 1]]);
        i += 2 + 2 + 4; // type + class + ttl
        let rdlen = u16::from_be_bytes([resp[i], resp[i + 1]]) as usize;
        i += 2;
        let rdata = &resp[i..i + rdlen];
        match rtype {
            wire::TYPE_A => Some(IpAddr::from(<[u8; 4]>::try_from(rdata).ok()?)),
            wire::TYPE_AAAA => Some(IpAddr::from(<[u8; 16]>::try_from(rdata).ok()?)),
            _ => None,
        }
    }

    #[test]
    fn a_query_gets_a_fake_ip_and_records_the_mapping() {
        let pool = shared_pool(Duration::from_secs(300), 100);
        let srv = DnsServer::new(Arc::clone(&pool), 30);
        let resp = srv
            .handle(&make_query(0x1234, "ads.example.com", wire::TYPE_A))
            .unwrap();
        let ip = first_answer(&resp).expect("an A answer");
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                assert_eq!(o[0], 198);
                assert!(o[1] == 18 || o[1] == 19, "in 198.18.0.0/15");
            }
            IpAddr::V6(_) => panic!("A query must yield a v4 fake IP"),
        }
        // The fake IP recovers the queried domain at connect time.
        assert_eq!(
            recover_domain(&pool, ip),
            Some("ads.example.com".to_string())
        );
    }

    #[test]
    fn aaaa_query_gets_a_ula_fake_ip() {
        let pool = shared_pool(Duration::from_secs(300), 100);
        let srv = DnsServer::new(Arc::clone(&pool), 30);
        let resp = srv
            .handle(&make_query(1, "example.com", wire::TYPE_AAAA))
            .unwrap();
        let ip = first_answer(&resp).expect("a AAAA answer");
        match ip {
            IpAddr::V6(v6) => assert_eq!((v6.segments()[0], v6.segments()[1]), (0xfd00, 0x2018)),
            IpAddr::V4(_) => panic!("AAAA query must yield a v6 fake IP"),
        }
        assert_eq!(recover_domain(&pool, ip), Some("example.com".to_string()));
    }

    #[test]
    fn https_query_is_nodata_and_allocates_nothing() {
        let pool = shared_pool(Duration::from_secs(300), 100);
        let srv = DnsServer::new(Arc::clone(&pool), 30);
        let resp = srv
            .handle(&make_query(2, "example.com", wire::TYPE_HTTPS))
            .unwrap();
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]),
            0,
            "NODATA: no answers"
        );
        assert_eq!(resp[3] & 0x0F, 0, "RCODE NOERROR");
        assert!(first_answer(&resp).is_none());
        assert_eq!(
            pool.lock().unwrap().len(),
            0,
            "no mapping allocated for non-A/AAAA"
        );
    }

    #[test]
    fn unparseable_query_is_dropped() {
        let pool = shared_pool(Duration::from_secs(300), 100);
        let srv = DnsServer::new(pool, 30);
        assert!(srv.handle(&[0, 1, 2]).is_none());
    }

    #[test]
    fn root_name_query_is_nodata_and_allocates_nothing() {
        let pool = shared_pool(Duration::from_secs(300), 100);
        let srv = DnsServer::new(Arc::clone(&pool), 30);
        // An A query for the root: header + a single 0x00 (root label) + qtype A + qclass IN.
        let mut q = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x00];
        q.extend_from_slice(&wire::TYPE_A.to_be_bytes());
        q.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        let resp = srv.handle(&q).unwrap();
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]),
            0,
            "NODATA for the root name"
        );
        assert_eq!(
            pool.lock().unwrap().len(),
            0,
            "no mapping stored for the root name"
        );
    }

    #[test]
    fn recoverer_adapter_recovers_a_served_domain() {
        use crate::proxy::DomainRecoverer;
        let pool = shared_pool(Duration::from_secs(300), 100);
        let srv = DnsServer::new(Arc::clone(&pool), 30);
        // Serve a query so the pool holds a mapping, then recover it via the forwarder's seam.
        let resp = srv
            .handle(&make_query(9, "cdn.example.com", wire::TYPE_A))
            .unwrap();
        let ip = first_answer(&resp).expect("an A answer");
        let recoverer = FakeIpRecoverer::new(Arc::clone(&pool));
        assert_eq!(recoverer.recover(ip), Some("cdn.example.com".to_string()));
        assert_eq!(recoverer.recover("8.8.8.8".parse().unwrap()), None);
    }
}
