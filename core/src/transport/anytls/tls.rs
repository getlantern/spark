//! BoringSSL TLS connector for the AnyTLS transport (feature `anytls`, ADR 0001).
//!
//! Produces a raw TLS byte stream the [`super::session`] layer runs over, configured to emit a
//! **Chrome ClientHello** — cipher/curve/sigalg order, GREASE, extension permutation, brotli
//! certificate compression, ALPS (new codepoint), and ECH grease — so the handshake fingerprints
//! as Chrome (the ADR's anti-fingerprinting goal), not as boring's default. The profile values are
//! the current Chrome (137) tables from `wreq-util` (`emulation/device/chrome.rs`); the boring2
//! application mirrors `wreq`'s `tls/conn/boring.rs` + `tls/ext.rs`.
//!
//! Certificate verification is **skipped**: AnyTLS authenticates with the password (`sha256`), and
//! TLS is the camouflage carrier — the reference client does the same. (Fingerprint freshness is
//! covered by a JA4-drift check; see the `m11-transport-candidates-anytls-samizdat` memory.)

use std::io;

use boring2::ssl::{CertCompressionAlgorithm, SslConnector, SslCurve, SslMethod, SslVerifyMode};
use tokio_boring2::SslStream;

/// Chrome's TLS 1.3 + ECDHE/RSA cipher order (`wreq-util` `CIPHER_LIST`).
const CHROME_CIPHERS: &str = "TLS_AES_128_GCM_SHA256:\
    TLS_AES_256_GCM_SHA384:\
    TLS_CHACHA20_POLY1305_SHA256:\
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:\
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:\
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:\
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:\
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
    TLS_RSA_WITH_AES_128_GCM_SHA256:\
    TLS_RSA_WITH_AES_256_GCM_SHA384:\
    TLS_RSA_WITH_AES_128_CBC_SHA:\
    TLS_RSA_WITH_AES_256_CBC_SHA";

/// Chrome's signature algorithms (`wreq-util` `SIGALGS_LIST`).
const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:\
    rsa_pss_rsae_sha256:\
    rsa_pkcs1_sha256:\
    ecdsa_secp384r1_sha384:\
    rsa_pss_rsae_sha384:\
    rsa_pkcs1_sha384:\
    rsa_pss_rsae_sha512:\
    rsa_pkcs1_sha512";

/// Chrome's supported groups, post-quantum first (`wreq-util` `CURVES_3`).
const CHROME_CURVES: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
];

/// The same groups without the post-quantum X25519MLKEM768 — used when a gambit turns `pq_kem` off
/// (the only Layer-A supported-groups delta boring can express).
const CHROME_CURVES_NO_PQ: &[SslCurve] =
    &[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1];

/// ALPN as Chrome sends it: `h2`, then `http/1.1` (wire form: length-prefixed).
const ALPN_H2_HTTP11: &[u8] = b"\x02h2\x08http/1.1";

fn ssl(e: boring2::error::ErrorStack, what: &str) -> io::Error {
    io::Error::other(format!("anytls boring {what}: {e}"))
}

/// TLS-connect over an established byte stream with a Chrome ClientHello, using `sni` for SNI.
///
/// `profile` carries the gambit-resolved on/off knobs (ADR 0006 P2): GREASE, extension permutation,
/// the PQ supported-group, `record_size_limit`, ECH grease, and ALPS. The cipher/sigalg lists, cert
/// compression, ALPN, OCSP, and SCT are the fixed Chrome-137 anchor — boring exposes no knob for
/// them, and [`Profile`](super::profile::Profile)'s defaults reproduce the genuine Chrome handshake
/// (so [`Profile::default`](super::profile::Profile::default) ⇒ byte-identical to the prior hardcode).
///
/// Generic over the carrier so a [`crate::transport::shaping::SegmentShapingStream`] can sit between
/// boring and the socket (ADR 0006 Phase 1) to fragment the ClientHello.
pub async fn connect<S>(
    stream: S,
    sni: &str,
    profile: &super::profile::Profile,
) -> io::Result<SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| ssl(e, "builder"))?;
    // The cert is neither trusted nor pinned — AnyTLS's auth is the password (see module docs).
    b.set_verify(SslVerifyMode::NONE);
    // Chrome ClientHello shaping (gambit-resolved on/off knobs over the fixed anchor).
    b.set_grease_enabled(profile.grease);
    b.set_permute_extensions(profile.permute_extensions);
    let curves = if profile.pq_kem {
        CHROME_CURVES
    } else {
        CHROME_CURVES_NO_PQ
    };
    b.set_curves(curves).map_err(|e| ssl(e, "curves"))?;
    b.set_sigalgs_list(CHROME_SIGALGS)
        .map_err(|e| ssl(e, "sigalgs"))?;
    b.set_cipher_list(CHROME_CIPHERS)
        .map_err(|e| ssl(e, "ciphers"))?;
    b.add_cert_compression_alg(CertCompressionAlgorithm::Brotli)
        .map_err(|e| ssl(e, "cert-compression"))?;
    b.set_alpn_protos(ALPN_H2_HTTP11)
        .map_err(|e| ssl(e, "alpn"))?;
    if let Some(limit) = profile.record_size_limit {
        b.set_record_size_limit(limit);
    }
    // Chrome also sends status_request (OCSP) and signed_certificate_timestamp (SCT).
    b.enable_ocsp_stapling();
    b.enable_signed_cert_timestamps();

    let mut config = b.build().configure().map_err(|e| ssl(e, "configure"))?;
    // Per-connection extensions Chrome sends.
    config.set_use_server_name_indication(true);
    config.set_verify_hostname(false); // paired with set_verify(NONE)
    config.set_enable_ech_grease(profile.ech_grease);
    if profile.alps {
        config
            .add_application_settings(b"h2")
            .map_err(|e| ssl(e, "alps"))?; // ALPS
        config.set_alps_use_new_codepoint(true);
    }

    tokio_boring2::connect(config, sni, stream)
        .await
        .map_err(|e| io::Error::other(format!("anytls tls handshake: {e}")))
}
