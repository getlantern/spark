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
    // Respect an explicit operator/test override — but only one that names something.
    if usable_override(std::env::var_os("SSL_CERT_FILE")) {
        return;
    }
    let path = data_dir.join("ca-roots.pem");
    match write_bundle(&path) {
        Ok(()) => {
            // Set as early as possible in tunnel setup, before the fetch/TLS tasks that read it spawn.
            // NOTE: process-env mutation isn't guaranteed thread-safe on every platform if another
            // thread reads the environment concurrently; the cleaner long-term fix is to install this
            // bundle directly on the SSL context (flint/boring) rather than via SSL_CERT_FILE.
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
    report_trust_anchors();
}

/// Whether `SSL_CERT_FILE` holds an override worth deferring to.
///
/// Presence alone is not enough. BoringSSL branches on `getenv() != NULL`, so a present-but-empty
/// value *is* the override: it takes that branch, fails to load, and does **not** fall back to the
/// compiled-in default (`by_file.c:88`). On mobile that default is empty anyway, so honoring an empty
/// override would leave the process with zero anchors — precisely the failure this module exists to
/// prevent, and one that surfaces as `unable to get local issuer certificate` on every fronted dial,
/// indistinguishable from a censored network.
///
/// A non-empty override that points somewhere useless is still honored: that is a real operator
/// intent, and [`report_trust_anchors`] is what tells them it is broken.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn usable_override(value: Option<std::ffi::OsString>) -> bool {
    value.is_some_and(|v| !v.is_empty())
}

/// Log whether boring can actually find trust anchors now that install has run.
///
/// A post-condition, not a gate: by this point either the bundle is installed or an override is in
/// force, and if neither yields anchors then *every* certificate-verified dial will fail. Saying so
/// here — with the paths named — is the difference between a one-line diagnosis and chasing a
/// phantom censorship event, because the proxyless strategy search reads those failures as evidence
/// about strategies and will exhaust the whole search space before giving up.
///
/// Deliberately non-fatal, matching the rest of this module: a failure leaves verification to fail as
/// it would have anyway rather than aborting the connect.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn report_trust_anchors() {
    match flint_tls::check_default_trust_anchors() {
        Ok(sources) => tracing::debug!(
            file = %sources.file.path.display(),
            file_usable = sources.file.usable,
            dir = %sources.dir.path.display(),
            dir_usable = sources.dir.usable,
            "boring trust anchors present"
        ),
        Err(e) => tracing::error!(
            error = %e,
            "no usable TLS trust anchors: every certificate-verified dial will fail, and will look \
             like a blocked network rather than a local misconfiguration"
        ),
    }
}

/// Write the bundled Mozilla roots to `path` as a concatenated PEM bundle (atomic replace via a
/// temp file + rename), refreshing it each run so a `webpki-root-certs` bump takes effect.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn write_bundle(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    // The data dir may not exist yet on a first run — create it so File::create can't fail on that.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Per-run-unique temp name (pid + a process-local counter) so two installs racing on the same
    // data dir can't clobber each other's partial write before the atomic rename.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "pem.tmp.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this replaced: `is_some()` honored `SSL_CERT_FILE=""` as an override and skipped the
    /// install, leaving boring to take the env branch, fail to load, and never fall back — zero
    /// anchors on exactly the platforms with no system store to fall back to.
    #[test]
    fn an_empty_ssl_cert_file_is_not_an_override_worth_honoring() {
        use std::ffi::OsString;

        assert!(
            !usable_override(Some(OsString::from(""))),
            "an empty value names nothing, so the bundle must still be installed"
        );
        assert!(!usable_override(None), "unset is not an override");
        assert!(
            usable_override(Some(OsString::from("/etc/ssl/cert.pem"))),
            "a real path is the operator's call, broken or not"
        );
    }
}
