//! Health probe for multi-server selection (design: `docs/multi-server-selection-design.md`):
//! time a transport's establish + verify it works end-to-end by fetching a callback URL *through*
//! it (2xx = healthy). The HTTP client is hand-rolled (no `hyper`/`reqwest`); HTTPS reuses the
//! `boring` backend linked by `anytls` (the callback TLS rides inside the tunnel, so no mimicry).

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A minimally-parsed callback URL: `{scheme}://{host}[:{port}]{path}`. Hand-parsed (no `url` crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackUrl {
    /// `true` for `https://` (TLS), `false` for `http://`.
    pub tls: bool,
    /// Host to dial through the transport.
    pub host: String,
    /// Port (defaults: 443 for https, 80 for http).
    pub port: u16,
    /// Request path (includes leading `/`; `/` if none).
    pub path: String,
}

impl CallbackUrl {
    /// Parse `http(s)://host[:port]/path`. Errors on any other scheme or a malformed authority.
    pub fn parse(s: &str) -> io::Result<Self> {
        let (scheme, rest) = s
            .split_once("://")
            .ok_or_else(|| io::Error::other(format!("callback url missing scheme: {s}")))?;
        let (tls, default_port) = match scheme {
            "https" => (true, 443),
            "http" => (false, 80),
            other => return Err(io::Error::other(format!("unsupported callback scheme `{other}`"))),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(io::Error::other(format!("callback url missing host: {s}")));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_owned(),
                p.parse::<u16>()
                    .map_err(|_| io::Error::other(format!("bad callback port: {authority}")))?,
            ),
            None => (authority.to_owned(), default_port),
        };
        if host.is_empty() {
            return Err(io::Error::other(format!("callback url missing host: {s}")));
        }
        Ok(CallbackUrl { tls, host, port, path: path.to_owned() })
    }
}

/// Send `GET {path}` over `stream`, read the status line, and return `true` iff the status is 2xx.
/// `Connection: close` so the server ends the body; we only parse the status line.
pub(crate) async fn http_get_ok<S>(mut stream: S, url: &CallbackUrl) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: spark-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path, url.host
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    // Read up to the end of the status line (first CRLF). Bounded so a hostile server can't make us
    // read forever; the caller also wraps the whole probe in a deadline.
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while buf.len() < 256 {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            break;
        }
    }
    // Status line: "HTTP/1.1 204 ...". Parse the 3-digit code.
    let line = String::from_utf8_lossy(&buf);
    let code = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("malformed HTTP status line: {line:?}")))?;
    Ok((200..300).contains(&code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn http_get_reads_2xx_and_sends_request() {
        let (client, mut server) = tokio::io::duplex(4096);
        let url = CallbackUrl { tls: false, host: "h.example".into(), port: 80, path: "/ok".into() };
        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            server.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            req
        });
        let ok = http_get_ok(client, &url).await.unwrap();
        assert!(ok);
        let req = server_task.await.unwrap();
        assert!(req.starts_with("GET /ok HTTP/1.1\r\n"), "req was: {req}");
        assert!(req.contains("Host: h.example\r\n"));
    }

    #[tokio::test]
    async fn http_get_rejects_non_2xx() {
        let (client, mut server) = tokio::io::duplex(4096);
        let url = CallbackUrl { tls: false, host: "h.example".into(), port: 80, path: "/".into() };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        assert!(!http_get_ok(client, &url).await.unwrap());
    }

    #[test]
    fn parses_callback_urls() {
        let u = CallbackUrl::parse("https://canary.example/generate_204").unwrap();
        assert_eq!(u, CallbackUrl { tls: true, host: "canary.example".into(), port: 443, path: "/generate_204".into() });
        let u = CallbackUrl::parse("http://1.2.3.4:8080/ok").unwrap();
        assert_eq!(u, CallbackUrl { tls: false, host: "1.2.3.4".into(), port: 8080, path: "/ok".into() });
        let u = CallbackUrl::parse("https://h.example").unwrap();
        assert_eq!(u.path, "/");
        assert!(CallbackUrl::parse("ftp://h/x").is_err());
        assert!(CallbackUrl::parse("notaurl").is_err());
        assert!(CallbackUrl::parse("https://:443/x").is_err());
    }
}
