//! Health probe for multi-server selection (design: `docs/multi-server-selection-design.md`):
//! time a transport's establish + verify it works end-to-end by fetching a callback URL *through*
//! it (2xx = healthy). The HTTP client is hand-rolled (no `hyper`/`reqwest`); HTTPS reuses the
//! `boring` backend linked by `anytls` (the callback TLS rides inside the tunnel, so no mimicry).

use std::io;

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

#[cfg(test)]
mod tests {
    use super::*;

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
