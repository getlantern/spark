//! The Samizdat SessionID-injection seam (ADR 0007 §5): make the boring TLS ClientHello carry a
//! chosen 32-byte `legacy_session_id` (the REALITY auth from [`super::auth`]), with **no BoringSSL
//! fork**.
//!
//! Mechanism (spike-validated; `docs/samizdat-transport-design.md` §5): set a fabricated TLS-1.2,
//! session-ID-based (`kID`), ticketless session whose `session_id` is the auth bytes, *before* the
//! handshake. BoringSSL's `handshake_client.cc` emits a `kID` session's id as `legacy_session_id`
//! even for a TLS-1.3 hello (the `kID` branch is checked before compatibility-mode, and
//! `ssl_session_get_type` keys off id-present + ticketless — no cipher/master-key needed). Because
//! boring builds the hello itself, the bytes are correctly bound into the TLS transcript. The
//! session is never actually resumed — the server negotiates a fresh 1.3 handshake.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use boring2::ssl::ConnectConfiguration;
use foreign_types_shared::ForeignTypeRef; // provides `as_ptr` on boring2's SslRef

use super::auth::SESSION_ID_LEN;

/// TLS 1.2 wire version, for `SSL_SESSION_set_protocol_version` (forces the `kID` path).
const TLS1_2_VERSION: u16 = 0x0303;
/// A long lifetime so the fabricated session is always "time-valid" when offered.
const SESSION_TIMEOUT_SECS: u32 = 7 * 24 * 3600;

/// Install `session_id` as the ClientHello `legacy_session_id` on `config`. Call after
/// `SslConnector::configure()` and before the handshake. See the module docs for the mechanism.
pub fn inject_session_id(
    config: &mut ConnectConfiguration,
    session_id: &[u8; SESSION_ID_LEN],
) -> io::Result<()> {
    let ssl = config.as_ptr();
    // SAFETY: `ssl` is the valid `SSL*` owned by `config` for the duration of this call. We own the
    // `SSL_SESSION` returned by `SSL_SESSION_new` until `SSL_set_session` takes its own reference
    // (it up-refs), after which we free ours. All pointers/lengths passed in are valid.
    unsafe {
        let ctx = boring_sys2::SSL_get_SSL_CTX(ssl);
        let sess = boring_sys2::SSL_SESSION_new(ctx);
        if sess.is_null() {
            return Err(io::Error::other("samizdat: SSL_SESSION_new failed"));
        }
        // TLS 1.2 + an id + no ticket ⇒ a `kID` session, whose id boring emits as the
        // ClientHello's `legacy_session_id` (even in a 1.3 hello). See the module docs.
        let configured = boring_sys2::SSL_SESSION_set_protocol_version(sess, TLS1_2_VERSION) == 1
            && boring_sys2::SSL_SESSION_set1_id(sess, session_id.as_ptr(), session_id.len()) == 1;
        if !configured {
            boring_sys2::SSL_SESSION_free(sess);
            return Err(io::Error::other(
                "samizdat: configuring the kID session failed",
            ));
        }
        // Keep the session "time-valid" so it is offered rather than dropped as expired.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        boring_sys2::SSL_SESSION_set_time(sess, now);
        boring_sys2::SSL_SESSION_set_timeout(sess, SESSION_TIMEOUT_SECS);

        let rc = boring_sys2::SSL_set_session(ssl, sess);
        boring_sys2::SSL_SESSION_free(sess); // SSL_set_session up-ref'd it; drop our reference
        if rc != 1 {
            return Err(io::Error::other("samizdat: SSL_set_session failed"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring2::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    /// A recognizable, non-random 32-byte pattern (0xC0..=0xDF).
    fn test_id() -> [u8; SESSION_ID_LEN] {
        let mut id = [0u8; SESSION_ID_LEN];
        for (i, b) in id.iter_mut().enumerate() {
            *b = 0xC0 + i as u8;
        }
        id
    }

    fn test_connector() -> SslConnector {
        let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
        b.set_verify(SslVerifyMode::NONE);
        b.build()
    }

    /// Drive a handshake against a capture-only listener; return the bytes the client wrote (the
    /// ClientHello — the listener never replies, so the handshake just stalls and we abort it).
    async fn capture_client_hello(config: ConnectConfiguration) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cap = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Read exactly the first TLS record (the ClientHello): a 5-byte header
            // (type, version, u16 length) then `length` payload bytes. Length-driven rather than
            // idle-timeout-driven, so a slow/contended CI delivering it in pieces can't truncate it.
            let read_record = async {
                let mut data = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = sock.read(&mut buf).await.ok()?;
                    if n == 0 {
                        return None; // EOF before a full record
                    }
                    data.extend_from_slice(&buf[..n]);
                    if data.len() >= 5 {
                        let record_len = ((data[3] as usize) << 8) | data[4] as usize;
                        if data.len() >= 5 + record_len {
                            return Some(data);
                        }
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(5), read_record)
                .await
                .ok()
                .flatten()
                .unwrap_or_default()
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        // The handshake never completes (the listener never replies), so drive it on a task we abort
        // once the ClientHello record is captured.
        let handshake = tokio::spawn(async move {
            let _ = tokio_boring2::connect(config, "example.org", tcp).await;
        });
        let data = cap.await.unwrap();
        handshake.abort();
        data
    }

    struct ParsedCh {
        session_id: Vec<u8>,
        supported_versions: Vec<u16>,
    }

    /// Strip TLS record headers (content-type 22) and concatenate handshake payload(s).
    fn handshake_bytes(wire: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 5 <= wire.len() {
            if wire[i] != 22 {
                break;
            }
            let len = ((wire[i + 3] as usize) << 8) | wire[i + 4] as usize;
            let start = i + 5;
            let end = (start + len).min(wire.len());
            out.extend_from_slice(&wire[start..end]);
            i = end;
        }
        out
    }

    fn be16(b: &[u8], p: usize) -> Option<u16> {
        Some(((*b.get(p)? as u16) << 8) | *b.get(p + 1)? as u16)
    }

    fn parse_client_hello(hs: &[u8]) -> Option<ParsedCh> {
        if *hs.first()? != 1 {
            return None; // not a ClientHello
        }
        let mut p = 4 + 2 + 32; // handshake header + legacy_version + random
        let sid_len = *hs.get(p)? as usize;
        p += 1;
        let session_id = hs.get(p..p + sid_len)?.to_vec();
        p += sid_len;
        let cs_len = be16(hs, p)? as usize;
        p += 2 + cs_len; // skip cipher suites
        let comp_len = *hs.get(p)? as usize;
        p += 1 + comp_len; // skip compression methods
        let ext_total = be16(hs, p)? as usize;
        p += 2;
        let ext_end = p + ext_total;
        let mut supported_versions = Vec::new();
        while p + 4 <= ext_end {
            let etype = be16(hs, p)?;
            let elen = be16(hs, p + 2)? as usize;
            p += 4;
            let edata = hs.get(p..p + elen)?;
            if etype == 43 {
                if let Some(&list_len) = edata.first() {
                    let mut q = 1;
                    while q + 2 <= 1 + list_len as usize && q + 2 <= edata.len() {
                        supported_versions.push(((edata[q] as u16) << 8) | edata[q + 1] as u16);
                        q += 2;
                    }
                }
            }
            p += elen;
        }
        Some(ParsedCh {
            session_id,
            supported_versions,
        })
    }

    #[tokio::test]
    async fn injects_chosen_session_id_into_a_tls13_hello() {
        let id = test_id();
        let mut config = test_connector().configure().unwrap();
        config.set_use_server_name_indication(true);
        config.set_verify_hostname(false);
        inject_session_id(&mut config, &id).expect("inject");

        let wire = capture_client_hello(config).await;
        let ch = parse_client_hello(&handshake_bytes(&wire)).expect("parse ClientHello");

        assert_eq!(
            &ch.session_id[..],
            &id[..],
            "legacy_session_id must equal the injected bytes"
        );
        assert!(
            ch.supported_versions.contains(&0x0304),
            "ClientHello must still offer TLS 1.3 (no version cap from the 1.2 session)"
        );
    }
}
