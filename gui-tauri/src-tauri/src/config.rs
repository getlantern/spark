//! Data-path config resolution, mirroring the Flutter NEBackend precedence
//! (newest wins): a runtime `config.toml` in the app-support dir → the baked
//! `SPARK_CONFIG` (base64 TOML) → `SPARK_PROXY` (host:port) → None (direct).
//!
//! The resolved string is handed to the system extension via
//! `providerConfiguration["config"]`; the extension's C ABI (`spark_tunnel_run`)
//! decodes it (TOML, base64-TOML, or a bare host:port) exactly as it does for
//! the Flutter app, so this layer stays a passthrough.

use std::path::PathBuf;

/// macOS app-support config path: `~/Library/Application Support/org.getlantern.spark/config.toml`.
pub fn config_file_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join("Library/Application Support/org.getlantern.spark/config.toml"),
    )
}

/// Resolve the data-path config string, or None for a direct (untunneled) run.
pub fn resolve() -> Option<String> {
    resolve_with(
        config_file_path().and_then(|p| std::fs::read_to_string(p).ok()),
        std::env::var("SPARK_CONFIG").ok(),
        std::env::var("SPARK_PROXY").ok(),
    )
}

/// Pure precedence logic, split out so it's unit-testable without touching the
/// filesystem or environment. First non-empty wins, in NEBackend order.
fn resolve_with(
    file: Option<String>,
    baked: Option<String>,
    proxy: Option<String>,
) -> Option<String> {
    [file, baked, proxy]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::resolve_with;

    #[test]
    fn file_wins_over_everything() {
        let r = resolve_with(
            Some("  toml-from-file  ".into()),
            Some("baked".into()),
            Some("1.2.3.4:443".into()),
        );
        assert_eq!(r.as_deref(), Some("toml-from-file"));
    }

    #[test]
    fn baked_wins_when_no_file() {
        let r = resolve_with(None, Some("baked".into()), Some("1.2.3.4:443".into()));
        assert_eq!(r.as_deref(), Some("baked"));
    }

    #[test]
    fn proxy_is_last_resort() {
        let r = resolve_with(None, None, Some("1.2.3.4:443".into()));
        assert_eq!(r.as_deref(), Some("1.2.3.4:443"));
    }

    #[test]
    fn empty_and_whitespace_are_skipped() {
        // an empty/whitespace file falls through to the baked config
        let r = resolve_with(Some("   ".into()), Some("baked".into()), None);
        assert_eq!(r.as_deref(), Some("baked"));
    }

    #[test]
    fn none_means_direct() {
        assert_eq!(resolve_with(None, None, None), None);
        assert_eq!(resolve_with(Some(String::new()), None, None), None);
    }
}
