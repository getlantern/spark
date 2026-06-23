//! Hand-rolled HTTP/1.1 response collection for the config fetch: write the request bytes, then read
//! the full response and return (status, ETag, body). No `reqwest`/`hyper` (locked stack); works over
//! any `AsyncRead + AsyncWrite` (a TLS stream in production, a duplex pipe in tests).
// Consumed by fetch_once in a later plan task.
#![allow(dead_code)]

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A collected HTTP response: status code, the `ETag` header value (if any), and the body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub etag: Option<String>,
    pub body: Vec<u8>,
}

/// Write `request` to `stream`, then read the whole response (headers + body to EOF; the request sets
/// `Connection: close`, so EOF terminates the body). `max_body` caps the body so a hostile server
/// can't exhaust memory.
pub async fn post_collect<S>(
    mut stream: S,
    request: &[u8],
    max_body: usize,
) -> io::Result<HttpResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    stream.flush().await?;
    let mut raw = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > max_body + 64 * 1024 {
            return Err(io::Error::other("config-new response too large"));
        }
    }
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("config-new response: no header terminator"))?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = crate::transport::probe::parse_status_code(status_line)?;
    let mut etag = None;
    for line in lines {
        // HTTP header names are case-insensitive (RFC 9110); match `ETag` in any casing.
        if line
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case("etag:"))
        {
            etag = Some(line[5..].trim().to_string());
        }
    }
    // Body is read verbatim — identity transfer encoding only (no chunked decoding). The config API
    // sends a fixed-size JSON body and we request `Connection: close`, so EOF delimits the body.
    let body = raw[sep + 4..].to_vec();
    if body.len() > max_body {
        return Err(io::Error::other("config-new body exceeds max_body"));
    }
    Ok(HttpResponse { status, etag, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(server_bytes: &'static [u8]) -> (HttpResponse, String) {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let t = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            server.write_all(server_bytes).await.unwrap();
            drop(server); // EOF
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let resp = post_collect(client, b"POST /p HTTP/1.1\r\nHost: h\r\n\r\n", 1 << 20)
            .await
            .unwrap();
        (resp, t.await.unwrap())
    }

    #[tokio::test]
    async fn parses_200_with_etag_and_body() {
        let (resp, sent) = run(b"HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}").await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.etag.as_deref(), Some("\"v1\""));
        assert_eq!(resp.body, b"{\"ok\":true}");
        assert!(sent.starts_with("POST /p HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn parses_304_no_body() {
        let (resp, _) = run(b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n").await;
        assert_eq!(resp.status, 304);
        assert!(resp.body.is_empty());
    }

    #[tokio::test]
    async fn etag_match_is_case_insensitive() {
        let (resp, _) = run(b"HTTP/1.1 200 OK\r\nEtag: \"mixed\"\r\n\r\nx").await;
        assert_eq!(resp.etag.as_deref(), Some("\"mixed\""));
    }
}
