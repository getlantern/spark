//! AnyTLS `cmdSettings` payload — sent by the client immediately on a new session (and the
//! server's `cmdServerSettings` in v2). It is newline-separated `key=value` text:
//!
//! ```text
//! v=2
//! client=spark/0.1.0
//! padding-md5=<md5 of the client's current padding scheme>
//! ```
//!
//! `v` (protocol version) and `client` (an identifier) are always present; `padding-md5` lets the
//! server detect a scheme mismatch and push a `cmdUpdatePaddingScheme`. **The md5 is computed
//! elsewhere and passed in** — `ring` (our locked crypto primitive) omits MD5, and a tunnel
//! identifier hash is non-security, so the hash source is decided when the session handshake is
//! wired up (it is not in this module). Unknown keys are preserved on parse for forward-compat.

use std::collections::BTreeMap;

use bytes::Bytes;

use super::padding::PaddingScheme;

/// Parsed/!built AnyTLS session settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Protocol version (`v`).
    pub version: u8,
    /// Client identifier (`client`), e.g. `spark/0.1.0`.
    pub client: String,
    /// MD5 of the sender's current padding scheme (`padding-md5`), if present.
    pub padding_md5: Option<String>,
}

impl Settings {
    /// New settings with the required `v` and `client` fields.
    pub fn new(version: u8, client: impl Into<String>) -> Self {
        Settings {
            version,
            client: client.into(),
            padding_md5: None,
        }
    }

    /// Set the `padding-md5` field (the md5 hex string is computed by the caller).
    pub fn with_padding_md5(mut self, md5: impl Into<String>) -> Self {
        self.padding_md5 = Some(md5.into());
        self
    }

    /// Settings for `version`/`client` with `padding-md5` set from `scheme`'s md5 — the form the
    /// client sends at session start.
    pub fn for_scheme(version: u8, client: impl Into<String>, scheme: &PaddingScheme) -> Self {
        Settings::new(version, client).with_padding_md5(scheme.md5())
    }

    /// Encode as the `cmdSettings` payload (`key=value` lines, `\n`-separated, no trailing newline).
    /// Field order is `v`, `client`, then `padding-md5` (matching the reference).
    pub fn encode(&self) -> Bytes {
        let mut s = format!("v={}\nclient={}", self.version, self.client);
        if let Some(md5) = &self.padding_md5 {
            s.push_str("\npadding-md5=");
            s.push_str(md5);
        }
        Bytes::from(s)
    }

    /// Parse a `cmdSettings`/`cmdServerSettings` payload. Requires a valid `v`; `client` defaults to
    /// empty if absent; unknown keys are ignored. Errors only on missing/invalid `v` or non-UTF-8.
    pub fn parse(payload: &[u8]) -> Result<Settings, SettingsError> {
        let text = std::str::from_utf8(payload).map_err(|_| SettingsError::NotUtf8)?;
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                fields.insert(k.trim(), v.trim());
            }
            // Lines without '=' are ignored (forward-compat).
        }
        let version = fields
            .get("v")
            .ok_or(SettingsError::MissingVersion)?
            .parse()
            .map_err(|_| SettingsError::InvalidVersion)?;
        Ok(Settings {
            version,
            client: fields
                .get("client")
                .map(|s| s.to_string())
                .unwrap_or_default(),
            padding_md5: fields.get("padding-md5").map(|s| s.to_string()),
        })
    }
}

/// Errors from parsing a settings payload.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SettingsError {
    /// The payload is not valid UTF-8.
    #[error("settings payload is not valid UTF-8")]
    NotUtf8,
    /// No `v` (version) line.
    #[error("settings missing `v` (version)")]
    MissingVersion,
    /// The `v` value is not a `u8`.
    #[error("settings has an invalid `v` (version)")]
    InvalidVersion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_without_md5() {
        let s = Settings::new(2, "spark/0.1.0");
        assert_eq!(&s.encode()[..], b"v=2\nclient=spark/0.1.0");
    }

    #[test]
    fn encodes_with_md5_in_order() {
        let s =
            Settings::new(2, "spark/0.1.0").with_padding_md5("0123456789abcdef0123456789abcdef");
        assert_eq!(
            &s.encode()[..],
            b"v=2\nclient=spark/0.1.0\npadding-md5=0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn round_trips_through_parse() {
        let s =
            Settings::new(2, "spark/0.1.0").with_padding_md5("deadbeefdeadbeefdeadbeefdeadbeef");
        assert_eq!(Settings::parse(&s.encode()).unwrap(), s);
    }

    #[test]
    fn parse_ignores_unknown_keys_and_blank_lines() {
        let s = Settings::parse(b"v=2\n\nclient=anytls/0.0.1\nfuture-key=whatever\n").unwrap();
        assert_eq!(s.version, 2);
        assert_eq!(s.client, "anytls/0.0.1");
        assert_eq!(s.padding_md5, None);
    }

    #[test]
    fn for_scheme_sets_padding_md5_from_the_scheme() {
        let scheme = PaddingScheme::default();
        let s = Settings::for_scheme(2, "spark/0.1.0", &scheme);
        assert_eq!(s.padding_md5.as_deref(), Some(scheme.md5().as_str()));
        // The encoded payload carries it.
        assert!(Settings::parse(&s.encode()).unwrap().padding_md5.is_some());
    }

    #[test]
    fn parse_requires_valid_version() {
        assert_eq!(
            Settings::parse(b"client=x").err(),
            Some(SettingsError::MissingVersion)
        );
        assert_eq!(
            Settings::parse(b"v=notnum").err(),
            Some(SettingsError::InvalidVersion)
        );
    }
}
