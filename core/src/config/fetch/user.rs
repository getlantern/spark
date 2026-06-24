//! The Lantern account pre-step. config-new requires a `pro_token` (+ a real `user_id`); the server
//! mints both via `POST /user-create` on the pro/account host — even for free, unauthenticated
//! clients ("pro_token" is universal; paid features layer on top). Mirrors radiance
//! `account.Client.NewUser` + `config.fetcher.ensureUser`: create once, persist in the data dir, reuse.
//! No body; the server keys off the device-id + app/version/platform headers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::fetch::http::post_collect;
use crate::config::fetch::request::{platform, APP_NAME, LANTERN_VERSION};
use crate::transport::{probe::tls_wrap, DirectTransport, Transport};

/// Anonymous (free) account credentials from `/user-create`, persisted and reused across fetches.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Creds {
    /// Lantern account id as a decimal string (e.g. `"388687521"`).
    pub user_id: String,
    /// The universal token config-new requires.
    pub pro_token: String,
}

impl Creds {
    /// Usable for a fetch: a real (non-placeholder) id and a non-empty token.
    fn is_usable(&self) -> bool {
        !self.user_id.is_empty() && self.user_id != "0" && !self.pro_token.is_empty()
    }
}

/// The `/user-create` JSON response (radiance `UserDataResponse` subset). `userId` is a JSON number.
#[derive(Deserialize)]
struct UserCreateResponse {
    #[serde(rename = "userId")]
    user_id: i64,
    token: String,
}

fn creds_path(dir: &Path) -> PathBuf {
    dir.join("user.json")
}

/// Load persisted creds, or `None` if absent/corrupt/unusable (→ create fresh).
fn load_creds(dir: &Path) -> Option<Creds> {
    let s = std::fs::read_to_string(creds_path(dir)).ok()?;
    let creds: Creds = serde_json::from_str(&s).ok()?;
    creds.is_usable().then_some(creds)
}

fn store_creds(dir: &Path, creds: &Creds) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_vec(creds).map_err(std::io::Error::other)?;
    std::fs::write(creds_path(dir), json)
}

/// Build the `POST {path}` user-create request bytes for the pro `host`. No body; sends only the app /
/// version / platform / device-id headers (no user-id/pro-token yet — that's what we're minting).
fn build_user_create_request(host: &str, path: &str, device_id: &str) -> Vec<u8> {
    let mut head = String::new();
    head.push_str(&format!("POST {path} HTTP/1.1\r\n"));
    head.push_str(&format!("Host: {host}\r\n"));
    head.push_str(&format!("X-Lantern-App: {APP_NAME}\r\n"));
    head.push_str(&format!("X-Lantern-Version: {LANTERN_VERSION}\r\n"));
    head.push_str(&format!("X-Lantern-Platform: {}\r\n", platform()));
    // device_id is generated lowercase-hex (no CRLF); the server requires it to bind the new user.
    head.push_str(&format!("X-Lantern-Device-Id: {device_id}\r\n"));
    head.push_str("Content-Length: 0\r\n");
    head.push_str("Connection: close\r\n\r\n");
    head.into_bytes()
}

fn parse_user_create(body: &[u8]) -> std::io::Result<Creds> {
    let resp: UserCreateResponse = serde_json::from_slice(body)
        .map_err(|e| std::io::Error::other(format!("user-create response parse: {e}")))?;
    let creds = Creds {
        user_id: resp.user_id.to_string(),
        pro_token: resp.token,
    };
    if !creds.is_usable() {
        return Err(std::io::Error::other(
            "user-create returned empty user_id/token",
        ));
    }
    Ok(creds)
}

/// Return account creds for config-new, creating an anonymous user via `POST {pro_host}{pro_path}` on
/// first use and persisting them. Cache-first: a warm `user.json` short-circuits the network call.
/// Bounded by a 30s timeout (a hung pro server must not stall the connect — the caller turns the error
/// into a backoff/retry, same as the config fetch).
pub async fn ensure_user(dir: &Path, pro_host: &str, pro_path: &str) -> std::io::Result<Creds> {
    if let Some(creds) = load_creds(dir) {
        return Ok(creds);
    }
    let did = super::device_id(dir)?;
    let bytes = build_user_create_request(pro_host, pro_path, &did);
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
    let resp = tokio::time::timeout(ATTEMPT_TIMEOUT, async {
        let addr = super::resolve(pro_host, 443).await?;
        let stream = DirectTransport::new(None).dial(addr).await?;
        let tls = tls_wrap(stream, pro_host).await?;
        post_collect(tls, &bytes, 1 << 20).await
    })
    .await
    .map_err(|_| std::io::Error::other("user-create timed out"))??;
    if !(200..300).contains(&resp.status) {
        return Err(std::io::Error::other(format!(
            "user-create HTTP {}",
            resp.status
        )));
    }
    let creds = parse_user_create(&resp.body)?;
    store_creds(dir, &creds)?;
    Ok(creds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_create_request_has_headers_and_no_body() {
        let s = String::from_utf8(build_user_create_request(
            "api.getiantem.org",
            "/user-create",
            "devhex",
        ))
        .unwrap();
        assert!(s.starts_with("POST /user-create HTTP/1.1\r\n"));
        assert!(s.contains("Host: api.getiantem.org\r\n"));
        assert!(s.contains("X-Lantern-App: lantern\r\n"));
        assert!(s.contains("X-Lantern-Device-Id: devhex\r\n"));
        assert!(s.contains("Content-Length: 0\r\n"));
        // No JSON body (no user/token to send yet).
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parses_user_create_response_numeric_id() {
        let creds =
            parse_user_create(br#"{"userId":388687521,"token":"kT1e","locale":"en_US"}"#).unwrap();
        assert_eq!(creds.user_id, "388687521");
        assert_eq!(creds.pro_token, "kT1e");
        assert!(creds.is_usable());
    }

    #[test]
    fn rejects_empty_creds() {
        assert!(parse_user_create(br#"{"userId":0,"token":""}"#).is_err());
    }

    #[test]
    fn creds_round_trip_and_unusable_is_ignored() {
        let dir = std::env::temp_dir().join(format!("spark-creds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load_creds(&dir).is_none());
        let creds = Creds {
            user_id: "42".into(),
            pro_token: "tok".into(),
        };
        store_creds(&dir, &creds).unwrap();
        assert_eq!(load_creds(&dir), Some(creds));
        // A persisted-but-unusable creds file (placeholder id, empty token) is treated as absent.
        store_creds(
            &dir,
            &Creds {
                user_id: "0".into(),
                pro_token: String::new(),
            },
        )
        .unwrap();
        assert!(load_creds(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
