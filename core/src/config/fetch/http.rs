//! Hand-rolled HTTP/1.1 response collection for the config fetch: write the request bytes, then read
//! the full response and return (status, ETag, body). No `reqwest`/`hyper` (locked stack); works over
//! any `AsyncRead + AsyncWrite` (a TLS stream in production, a duplex pipe in tests).

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Inflate a gzip body, refusing to produce more than `max` bytes.
///
/// The cap is enforced **during** decompression, not after: a gzip bomb is small on the wire and
/// unbounded once expanded, so a decode-then-measure approach allocates the bomb before noticing.
/// `take(max + 1)` lets one byte past the limit through, which is what distinguishes "exactly at the
/// cap" from "over it" without reading the rest.
fn inflate_within(body: &[u8], max: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::with_capacity(body.len().saturating_mul(4).min(max));
    flate2::read::GzDecoder::new(body)
        .take(max as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| io::Error::other(format!("config-new gzip decode failed: {e}")))?;
    Ok(out)
}

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
    let mut gzipped = false;
    for line in lines {
        // HTTP header names are case-insensitive (RFC 9110); match `ETag` in any casing.
        if line
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case("etag:"))
        {
            etag = Some(line[5..].trim().to_string());
        } else if line
            .get(..17)
            .is_some_and(|p| p.eq_ignore_ascii_case("content-encoding:"))
        {
            // Only gzip is negotiated (see `Accept-Encoding` in `request::build_request_bytes`), so
            // only gzip is accepted here. An encoding we did not ask for is a server error, not
            // something to guess at — it falls through and fails the JSON parse rather than being
            // silently treated as identity.
            gzipped = line[17..].trim().eq_ignore_ascii_case("gzip");
        }
    }
    // Body is read verbatim — identity transfer encoding only (no chunked decoding). The config API
    // sends a fixed-size JSON body and we request `Connection: close`, so EOF delimits the body.
    let body = raw[sep + 4..].to_vec();
    let body = if gzipped {
        inflate_within(&body, max_body)?
    } else {
        body
    };
    // Checked on the DECODED body: a compressed one is bounded by the read loop above, but the size
    // that matters is what the parser receives. `inflate_within` also stops at the cap mid-stream, so
    // this is the second of two checks rather than the only one.
    if body.len() > max_body {
        return Err(io::Error::other("config-new body exceeds max_body"));
    }
    Ok(HttpResponse { status, etag, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As [`run`], for a response built at runtime (the gzip tests compress their own body).
    async fn run_owned(server_bytes: Vec<u8>, max_body: usize) -> io::Result<HttpResponse> {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _ = server.read(&mut buf).await;
            let _ = server.write_all(&server_bytes).await;
            drop(server); // EOF
        });
        post_collect(client, b"req", max_body).await
    }

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

    /// A gzip body is inflated, and the ETag still parses alongside it.
    #[tokio::test]
    async fn parses_a_gzipped_200() {
        use std::io::Write;
        let payload = br#"{"ok":true}"#;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(payload).unwrap();
        let gz = enc.finish().unwrap();

        let mut resp =
            b"HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        resp.extend_from_slice(&gz);

        let r = run_owned(resp, 1 << 20).await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.etag.as_deref(), Some("\"abc\""));
        assert_eq!(r.body, payload, "the parser must receive inflated JSON");
    }

    /// A gzip bomb is refused by the DECODED-size cap, not merely by the on-the-wire read limit.
    ///
    /// This is the reason the check moved: 10 MiB of zeroes compresses to a few KB, so it sails past
    /// the wire-size guard in the read loop. Enforcing during inflate means the bomb is never
    /// materialized — decode-then-measure would allocate it in full before noticing.
    #[tokio::test]
    async fn a_gzip_bomb_is_refused_on_the_decoded_size() {
        use std::io::Write;
        let bomb = vec![0u8; 10 * 1024 * 1024];
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&bomb).unwrap();
        let gz = enc.finish().unwrap();
        assert!(
            gz.len() < 64 * 1024,
            "the bomb must be small on the wire to be a bomb"
        );

        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        resp.extend_from_slice(&gz);

        let err = run_owned(resp, 64 * 1024)
            .await
            .expect_err("10 MiB decoded against a 64 KiB cap must fail");
        assert!(
            err.to_string().contains("exceeds max_body"),
            "expected the decoded-size refusal, got: {err}"
        );
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
