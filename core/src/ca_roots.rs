//! Make boring's default cert store usable on mobile for flint's fronted TLS.
//!
//! flint verifies the CDN/front certificate against boring's default cert store. With no explicit
//! roots that store falls back to `X509_STORE_set_default_paths()` — OpenSSL's compile-time paths
//! (`/etc/ssl/…`, or the `SSL_CERT_FILE`/`SSL_CERT_DIR` env overrides). Android and iOS keep their
//! trust roots elsewhere (`/system/etc/security/cacerts` + Conscrypt; the Secure Transport
//! keychain), so that store is **empty** there and every fronted handshake fails with
//! `unable to get local issuer certificate`. That silently breaks the rule-set (`.srs`) fetch and
//! the fronted leg of config-fetch (config-fetch survives only because it also races a direct dial;
//! the rule-set fetch is fronting-only, so it fails outright).
//!
//! We write the bundled Mozilla root set (`webpki-root-certs`, already pulled in via `anytls`) to the
//! app data dir once and point `SSL_CERT_FILE` at it, so `set_default_paths()` finds a real anchor
//! set. Desktop platforms keep their working system store untouched (this is a no-op there).

/// Install the bundled CA roots for boring's default cert store on mobile, via `SSL_CERT_FILE`.
/// Called once during tunnel setup, before any fronted fetch runs. Best-effort: a failure is logged
/// and leaves fronted verification to fail as before, rather than aborting the connect.
#[cfg(any(target_os = "android", target_os = "ios"))]
pub(crate) fn install_bundled_roots(data_dir: &std::path::Path) {
    // Respect an explicit operator/test override.
    if std::env::var_os("SSL_CERT_FILE").is_some() {
        return;
    }
    let path = data_dir.join("ca-roots.pem");
    match write_bundle(&path) {
        Ok(()) => {
            // Safe: called once during setup, before the fetch/TLS worker tasks spawn.
            std::env::set_var("SSL_CERT_FILE", &path);
            tracing::info!(
                count = webpki_root_certs::TLS_SERVER_ROOT_CERTS.len(),
                "installed bundled CA roots for fronted TLS (SSL_CERT_FILE)"
            );
        }
        Err(e) => tracing::warn!(
            error = %e,
            "could not install bundled CA roots; fronted rule-set/config fetch may fail cert verification"
        ),
    }
}

/// Write the bundled Mozilla roots to `path` as a concatenated PEM bundle (atomic replace via a
/// temp file + rename), refreshing it each run so a `webpki-root-certs` bump takes effect.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn write_bundle(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("pem.tmp");
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            // boring2 is present whenever config-fetch is (config-fetch → anytls); reuse it to
            // DER→PEM so we need no base64/PEM dependency of our own.
            let cert = boring2::x509::X509::from_der(der.as_ref())
                .map_err(|e| std::io::Error::other(format!("root der→x509: {e}")))?;
            let pem = cert
                .to_pem()
                .map_err(|e| std::io::Error::other(format!("root x509→pem: {e}")))?;
            f.write_all(&pem)?;
        }
        f.flush()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Off-mobile the system trust store works, so there is nothing to install.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn install_bundled_roots(_data_dir: &std::path::Path) {}
