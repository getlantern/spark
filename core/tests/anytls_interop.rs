//! Live interop gate for the AnyTLS transport **with a P4a gambit applied** — the authoritative
//! check that a gambit-shaped opening (an injected `legacy_session_id` + a TLS-record split) still
//! completes a real handshake and proxies, i.e. the P4a knobs are well-formed and a real server
//! accepts them.
//!
//! Unlike the unit tests (which prove spark *emits* the right ClientHello bytes — flint-tls's
//! CH-parse + JA4 tests), this drives [`from_config`] → [`Transport::dial`] against a real AnyTLS
//! server (sing-box / anytls-go), with the gambit knobs set in `[transport.anytls.clienthello]` /
//! `[transport.anytls.records]`. It is **env-gated**: with no `SPARK_ANYTLS_SERVER` /
//! `SPARK_ANYTLS_PASSWORD` it prints a skip line and returns (a no-op in CI without a server).
//!
//! To run live (sing-box anytls inbound with a self-signed cert; spark's connector does not verify
//! the server cert):
//! ```text
//! SPARK_ANYTLS_SERVER=127.0.0.1:8443 SPARK_ANYTLS_PASSWORD=<pw> SPARK_ANYTLS_SNI=example.com \
//!   cargo test -p spark-core --features anytls --test anytls_interop -- --nocapture
//! ```
//! The TCP test reaches `example.com:80`, so a live run needs outbound internet from the server host.
#![cfg(feature = "anytls")]

use std::time::Duration;

use spark_core::config::Config;
use spark_core::transport::from_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(10);

/// Build a `[transport.anytls]` config with a **P4a gambit** applied, or `None` to skip.
///
/// Requires `SPARK_ANYTLS_SERVER` (`IP:port`) and `SPARK_ANYTLS_PASSWORD`; `SPARK_ANYTLS_SNI` is
/// optional (defaults to `example.com`). The gambit deliberately exercises the P4a knobs that change
/// what's on the wire — an injected 32-byte `legacy_session_id` (the kID recipe) and a TLS-record
/// split (`records.split_offsets`) — so a passing handshake proves a real server accepts them.
fn config_from_env() -> Option<Config> {
    let server = std::env::var("SPARK_ANYTLS_SERVER")
        .ok()
        .filter(|s| !s.is_empty())?;
    let password = std::env::var("SPARK_ANYTLS_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty());
    let Some(password) = password else {
        println!(
            "SKIP: set SPARK_ANYTLS_SERVER and SPARK_ANYTLS_PASSWORD (optionally SPARK_ANYTLS_SNI) \
             to run the live AnyTLS P4a-gambit interop gate"
        );
        return None;
    };
    let sni = std::env::var("SPARK_ANYTLS_SNI").unwrap_or_else(|_| "example.com".to_owned());

    // A P4a gambit: inject a fixed 32-byte legacy_session_id, and split the ClientHello across TLS
    // records at two offsets. (Explicit extension/cipher order is covered by flint-tls's CH-parse +
    // JA4 unit tests; here we exercise the two knobs that most change the on-wire opening a server
    // must accept.)
    let toml = format!(
        "[transport.anytls]\nserver = \"{server}\"\npassword = \"{password}\"\nsni = \"{sni}\"\n\n\
         [transport.anytls.clienthello]\n\
         session_id = {{ mode = \"inject\", hex = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\" }}\n\n\
         [transport.anytls.records]\nsplit_offsets = [6, 12]\n"
    );
    println!(
        "--- anytls P4a interop: server={server} sni={sni} (session-id inject + record split) ---"
    );
    match Config::from_toml_str(&toml) {
        Ok(cfg) => Some(cfg),
        Err(e) => panic!("SPARK_ANYTLS_* env produced an invalid config: {e}"),
    }
}

/// TCP: dial `example.com:80` **through** the live AnyTLS server using a P4a-shaped opening, and
/// confirm an HTTP response head. A failure here (handshake refused, reset, EOF before any bytes) is
/// a real interop bug in the P4a opening (the server rejected the injected session-id or the split
/// hello); a failure to resolve/route to example.com is an environment limitation.
#[tokio::test]
async fn p4a_gambit_tcp_get_through_live_server() {
    let Some(cfg) = config_from_env() else { return };
    let (tcp, _udp) = from_config(&cfg).expect("from_config should build the anytls transport");

    let target = timeout(TIMEOUT, tokio::net::lookup_host("example.com:80"))
        .await
        .expect("DNS lookup timed out")
        .expect("resolve example.com:80")
        .next()
        .expect("example.com:80 resolved to no addresses");
    println!("dialing example.com:80 ({target}) through the anytls server (P4a gambit)");

    let mut stream = timeout(TIMEOUT, tcp.dial(target))
        .await
        .expect("dial timed out")
        .expect("dial example.com:80 through the anytls server (P4a-shaped handshake)");

    let request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    timeout(TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .expect("write timed out")
        .expect("write GET through the anytls tunnel");

    let mut buf = [0u8; 1024];
    let n = timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read response through the anytls tunnel");
    assert!(n > 0, "server closed without sending any response bytes");

    let head = String::from_utf8_lossy(&buf[..n]);
    println!("--- response head through anytls (P4a) ---\n{head}\n---");
    assert!(
        head.starts_with("HTTP/1.1 "),
        "expected an HTTP/1.1 status line, got: {head:?}"
    );
}
