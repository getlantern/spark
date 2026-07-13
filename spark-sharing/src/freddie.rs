use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use lantern_unbounded::protocol::{PROTOCOL_VERSION, VERSION_HEADER};
use lantern_unbounded::signaling::{Signaler, SignalingError};
use lantern_unbounded::{SignalMessage, SignalMessageType};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
/// Upper bound on the caller-supplied response limit. The chunked path computes
/// `max_wire_bytes = limit * 2 + MAX_HEADER_BYTES`; capping the limit here keeps that
/// well under `usize::MAX` so a pathological caller value can't saturate the multiply
/// into an effectively-unbounded read (OOM).
const MAX_RESPONSE_LIMIT: usize = 64 * 1024 * 1024;

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Configuration error returned before a Freddie signaling client starts.
#[derive(Debug, thiserror::Error)]
pub enum FreddieBuildError {
    /// The endpoint is not an absolute HTTP or HTTPS URL supported by this client.
    #[error("invalid Freddie endpoint: {0}")]
    InvalidEndpoint(String),
    /// The selected rustls ring provider cannot support its safe protocol defaults.
    #[error("unable to configure Freddie TLS: {0}")]
    Tls(#[from] rustls::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

#[derive(Debug, Clone)]
struct Endpoint {
    scheme: Scheme,
    host: String,
    port: u16,
    authority: String,
    target: String,
}

impl Endpoint {
    fn parse(value: &str) -> Result<Self, FreddieBuildError> {
        let (scheme, remainder, default_port) = if let Some(rest) = value.strip_prefix("http://") {
            (Scheme::Http, rest, 80)
        } else if let Some(rest) = value.strip_prefix("https://") {
            (Scheme::Https, rest, 443)
        } else {
            return Err(invalid_endpoint("expected http:// or https://"));
        };

        let boundary = remainder
            .char_indices()
            .find_map(|(index, character)| matches!(character, '/' | '?' | '#').then_some(index));
        let (authority, suffix) = match boundary {
            Some(index) => remainder.split_at(index),
            None => (remainder, ""),
        };
        let target = match suffix.chars().next() {
            Some('?') => format!("/{suffix}"),
            Some('/') | Some('#') => suffix.to_owned(),
            None => "/".to_owned(),
            Some(_) => unreachable!("request-target boundary is a known delimiter"),
        };
        if authority.is_empty()
            || authority.contains('@')
            || authority
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
            || target
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
            || target.contains('#')
        {
            return Err(invalid_endpoint("invalid authority or request target"));
        }

        let (host, port) = parse_authority(authority, default_port)?;
        if scheme == Scheme::Https {
            ServerName::try_from(host.clone())
                .map_err(|_| invalid_endpoint("invalid TLS server name"))?;
        }
        Ok(Self {
            scheme,
            host,
            port,
            authority: authority.to_owned(),
            target,
        })
    }
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), FreddieBuildError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or_else(|| invalid_endpoint("unterminated IPv6 address"))?;
        if host.is_empty() {
            return Err(invalid_endpoint("empty host"));
        }
        let port = if suffix.is_empty() {
            default_port
        } else {
            parse_port(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| invalid_endpoint("invalid IPv6 authority"))?,
            )?
        };
        return Ok((host.to_owned(), port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, parse_port(port)?),
        Some(_) => return Err(invalid_endpoint("IPv6 addresses must be bracketed")),
        None => (authority, default_port),
    };
    if host.is_empty() {
        return Err(invalid_endpoint("empty host"));
    }
    Ok((host.to_owned(), port))
}

fn parse_port(value: &str) -> Result<u16, FreddieBuildError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid_endpoint("invalid port"))
}

fn invalid_endpoint(reason: impl Into<String>) -> FreddieBuildError {
    FreddieBuildError::InvalidEndpoint(reason.into())
}

/// Raw Tokio + rustls implementation of the Go Freddie signaling exchange.
#[derive(Clone)]
pub struct FreddieSignaler {
    endpoint: Endpoint,
    tls: TlsConnector,
    max_response_bytes: usize,
}

impl fmt::Debug for FreddieSignaler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreddieSignaler")
            .field("endpoint", &"<redacted>")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl FreddieSignaler {
    /// Creates an HTTPS signaling client with a 1 MiB response-body limit.
    pub fn new(endpoint: impl AsRef<str>) -> Result<Self, FreddieBuildError> {
        Self::with_response_limit(endpoint, DEFAULT_MAX_RESPONSE_BYTES)
    }

    /// Creates an HTTPS signaling client with an explicit non-zero response-body limit.
    pub fn with_response_limit(
        endpoint: impl AsRef<str>,
        max_response_bytes: usize,
    ) -> Result<Self, FreddieBuildError> {
        let client = Self::with_any_scheme(endpoint.as_ref(), max_response_bytes)?;
        if client.endpoint.scheme != Scheme::Https {
            return Err(invalid_endpoint(
                "HTTPS is required; use new_insecure_http only for controlled local testing",
            ));
        }
        Ok(client)
    }

    /// Creates a plaintext HTTP client for controlled local tests only.
    pub fn new_insecure_http(endpoint: impl AsRef<str>) -> Result<Self, FreddieBuildError> {
        Self::with_insecure_http_response_limit(endpoint, DEFAULT_MAX_RESPONSE_BYTES)
    }

    /// Creates a plaintext HTTP test client with an explicit non-zero response-body limit.
    pub fn with_insecure_http_response_limit(
        endpoint: impl AsRef<str>,
        max_response_bytes: usize,
    ) -> Result<Self, FreddieBuildError> {
        let client = Self::with_any_scheme(endpoint.as_ref(), max_response_bytes)?;
        if client.endpoint.scheme != Scheme::Http {
            return Err(invalid_endpoint(
                "new_insecure_http requires an http:// endpoint",
            ));
        }
        Ok(client)
    }

    fn with_any_scheme(
        endpoint: &str,
        max_response_bytes: usize,
    ) -> Result<Self, FreddieBuildError> {
        if max_response_bytes == 0 {
            return Err(invalid_endpoint("response limit must be non-zero"));
        }
        if max_response_bytes > MAX_RESPONSE_LIMIT {
            return Err(invalid_endpoint(
                "response limit exceeds the 64 MiB maximum",
            ));
        }
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(endpoint, max_response_bytes, roots)
    }

    fn with_roots(
        endpoint: &str,
        max_response_bytes: usize,
        roots: RootCertStore,
    ) -> Result<Self, FreddieBuildError> {
        let tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(Self {
            endpoint: Endpoint::parse(endpoint)?,
            tls: TlsConnector::from(Arc::new(tls)),
            max_response_bytes,
        })
    }

    async fn connect(&self) -> Result<Box<dyn AsyncStream>, SignalingError> {
        let stream = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
            .await
            .map_err(transport_error)?;
        match self.endpoint.scheme {
            Scheme::Http => Ok(Box::new(stream)),
            Scheme::Https => {
                let server_name = ServerName::try_from(self.endpoint.host.clone())
                    .map_err(|error| transport_message(error.to_string()))?;
                let stream = self
                    .tls
                    .connect(server_name, stream)
                    .await
                    .map_err(transport_error)?;
                Ok(Box::new(stream))
            }
        }
    }

    async fn exchange_inner(
        &self,
        send_to: &str,
        kind: SignalMessageType,
        payload: &str,
    ) -> Result<Option<SignalMessage>, SignalingError> {
        let body = encode_form(&[
            ("data", payload),
            ("send-to", send_to),
            ("type", &(kind as u8).to_string()),
        ]);
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\n{}: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.endpoint.target,
            self.endpoint.authority,
            VERSION_HEADER,
            PROTOCOL_VERSION,
            body.len(),
            body
        );
        let mut stream = self.connect().await?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(transport_error)?;
        stream.flush().await.map_err(transport_error)?;
        let response = read_response(&mut stream, self.max_response_bytes)
            .await
            .map_err(transport_error)?;

        match response.status {
            200 if response.body.iter().all(u8::is_ascii_whitespace) => Ok(None),
            200 => Ok(Some(serde_json::from_slice(&response.body)?)),
            404 => Err(SignalingError::RecipientGone),
            418 => Err(SignalingError::ProtocolVersion(PROTOCOL_VERSION.into())),
            status => Err(SignalingError::Http(status)),
        }
    }
}

#[async_trait]
impl Signaler for FreddieSignaler {
    async fn exchange(
        &self,
        send_to: &str,
        kind: SignalMessageType,
        payload: &str,
    ) -> Result<Option<SignalMessage>, SignalingError> {
        self.exchange_inner(send_to, kind, payload).await
    }
}

fn encode_form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(name, value)| format!("{}={}", form_component(name), form_component(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(char::from(HEX[(byte >> 4) as usize]));
                encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
            }
        }
    }
    encoded
}

struct Response {
    status: u16,
    body: Vec<u8>,
}

async fn read_response(
    stream: &mut dyn AsyncStream,
    max_body_bytes: usize,
) -> io::Result<Response> {
    let mut received = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(position) = find_bytes(&received, b"\r\n\r\n") {
            break position + 4;
        }
        if received.len() >= MAX_HEADER_BYTES {
            return Err(invalid_data("Freddie response headers exceed limit"));
        }
        let mut chunk = [0_u8; 4096];
        let remaining = MAX_HEADER_BYTES - received.len();
        let read_capacity = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..read_capacity]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Freddie closed an incomplete response",
            ));
        }
        received.extend_from_slice(&chunk[..read]);
    };

    if header_end > MAX_HEADER_BYTES {
        return Err(invalid_data("Freddie response headers exceed limit"));
    }
    let (status, framing) = parse_headers(&received[..header_end])?;
    let mut body = received.split_off(header_end);
    match framing {
        BodyFraming::ContentLength(length) => {
            if length > max_body_bytes {
                return Err(invalid_data("Freddie response body exceeds limit"));
            }
            while body.len() < length {
                if read_more(stream, &mut body).await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Freddie closed before sending the declared Content-Length",
                    ));
                }
            }
            if body.len() != length {
                return Err(invalid_data("Freddie response exceeds Content-Length"));
            }
        }
        BodyFraming::Chunked => {
            let max_wire_bytes = max_body_bytes
                .saturating_mul(2)
                .saturating_add(MAX_HEADER_BYTES);
            read_to_close_bounded(stream, &mut body, max_wire_bytes).await?;
            body = decode_chunked(&body, max_body_bytes)?;
        }
        BodyFraming::CloseDelimited => {
            read_to_close_bounded(stream, &mut body, max_body_bytes).await?;
        }
    }
    Ok(Response { status, body })
}

async fn read_to_close_bounded(
    stream: &mut dyn AsyncStream,
    target: &mut Vec<u8>,
    limit: usize,
) -> io::Result<()> {
    loop {
        if target.len() > limit {
            return Err(invalid_data("Freddie response body exceeds limit"));
        }
        if target.len() == limit {
            let mut extra = [0_u8; 1];
            return match stream.read(&mut extra).await? {
                0 => Ok(()),
                _ => Err(invalid_data("Freddie response body exceeds limit")),
            };
        }
        let mut chunk = [0_u8; 4096];
        let remaining = limit - target.len();
        let read_capacity = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..read_capacity]).await?;
        if read == 0 {
            return Ok(());
        }
        target.extend_from_slice(&chunk[..read]);
    }
}

async fn read_more(stream: &mut dyn AsyncStream, target: &mut Vec<u8>) -> io::Result<usize> {
    let mut chunk = [0u8; 4096];
    let read = stream.read(&mut chunk).await?;
    target.extend_from_slice(&chunk[..read]);
    Ok(read)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

fn parse_headers(headers: &[u8]) -> io::Result<(u16, BodyFraming)> {
    let text = std::str::from_utf8(headers)
        .map_err(|_| invalid_data("Freddie response headers are not UTF-8"))?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing Freddie status line"))?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or_else(|| invalid_data("invalid Freddie status code"))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(invalid_data("unsupported Freddie HTTP version"));
    }

    let mut content_length = None;
    let mut transfer_encoding = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid_data("malformed Freddie response header"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| invalid_data("invalid Freddie Content-Length"))?;
            if content_length
                .replace(parsed)
                .is_some_and(|old| old != parsed)
            {
                return Err(invalid_data("conflicting Freddie Content-Length values"));
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            let parsed = if value.eq_ignore_ascii_case("chunked") {
                true
            } else if value.eq_ignore_ascii_case("identity") {
                false
            } else {
                return Err(invalid_data("unsupported Freddie Transfer-Encoding"));
            };
            if transfer_encoding
                .replace(parsed)
                .is_some_and(|old| old != parsed)
            {
                return Err(invalid_data("conflicting Freddie Transfer-Encoding values"));
            }
        }
    }
    let chunked = transfer_encoding == Some(true);
    let framing = match (content_length, chunked) {
        (Some(_), true) => {
            return Err(invalid_data(
                "Freddie response has conflicting body framing",
            ))
        }
        (Some(length), false) => BodyFraming::ContentLength(length),
        (None, true) => BodyFraming::Chunked,
        (None, false) => BodyFraming::CloseDelimited,
    };
    Ok((status, framing))
}

fn decode_chunked(encoded: &[u8], max_body_bytes: usize) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut cursor = 0;
    loop {
        let line_end = find_bytes(&encoded[cursor..], b"\r\n")
            .map(|position| cursor + position)
            .ok_or_else(|| invalid_data("incomplete Freddie chunk size"))?;
        if line_end - cursor > 128 {
            return Err(invalid_data("Freddie chunk size line exceeds limit"));
        }
        let size_text = std::str::from_utf8(&encoded[cursor..line_end])
            .map_err(|_| invalid_data("invalid Freddie chunk size"))?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or_default(), 16)
            .map_err(|_| invalid_data("invalid Freddie chunk size"))?;
        cursor = line_end + 2;
        if size == 0 {
            let trailers = encoded
                .get(cursor..)
                .ok_or_else(|| invalid_data("incomplete Freddie chunk trailer"))?;
            if trailers == b"\r\n" || trailers.ends_with(b"\r\n\r\n") {
                return Ok(decoded);
            }
            return Err(invalid_data("invalid Freddie chunk trailer"));
        }
        if decoded.len().saturating_add(size) > max_body_bytes {
            return Err(invalid_data("Freddie response body exceeds limit"));
        }
        let chunk_end = cursor
            .checked_add(size)
            .ok_or_else(|| invalid_data("invalid Freddie chunk size"))?;
        let chunk = encoded
            .get(cursor..chunk_end)
            .ok_or_else(|| invalid_data("incomplete Freddie chunk"))?;
        if encoded.get(chunk_end..chunk_end + 2) != Some(b"\r\n") {
            return Err(invalid_data("invalid Freddie chunk terminator"));
        }
        decoded.extend_from_slice(chunk);
        cursor = chunk_end + 2;
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn transport_error(error: impl fmt::Display) -> SignalingError {
    transport_message(error.to_string())
}

fn transport_message(message: String) -> SignalingError {
    SignalingError::Transport(message)
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    async fn stub(response: Vec<u8>) -> (String, oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            let _ = request_tx.send(request);
            stream.write_all(&response).await.unwrap();
        });
        (format!("http://{address}/v1/signal"), request_rx)
    }

    async fn read_request<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            request.extend_from_slice(&chunk[..read]);
            if let Some(end) = find_bytes(&request, b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end + 4]).unwrap();
                let content_length = headers
                    .split("\r\n")
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                if request.len() >= end + 4 + content_length {
                    return request;
                }
            }
        }
    }

    fn response(status: u16, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn sends_go_form_and_decodes_envelope() {
        let body = r#"{"ReplyTo":"offer-request","Type":1,"Payload":"{}"}"#;
        let (endpoint, request_rx) = stub(response(200, body)).await;
        let signaler = FreddieSignaler::new_insecure_http(endpoint).unwrap();
        let message = signaler
            .exchange("genesis/one", SignalMessageType::Genesis, "two words&?")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(message.reply_to, "offer-request");
        assert_eq!(message.kind, SignalMessageType::Offer);

        let request = String::from_utf8(request_rx.await.unwrap()).unwrap();
        assert!(request.starts_with("POST /v1/signal HTTP/1.1\r\n"));
        assert!(request.contains(&format!("\r\n{VERSION_HEADER}: {PROTOCOL_VERSION}\r\n")));
        assert!(request.ends_with("data=two+words%26%3F&send-to=genesis%2Fone&type=0"));
    }

    #[tokio::test]
    async fn maps_protocol_statuses() {
        for (status, expected) in [(404, "recipient"), (418, "version"), (503, "HTTP 503")] {
            let (endpoint, _) = stub(response(status, "error")).await;
            let error = FreddieSignaler::new_insecure_http(endpoint)
                .unwrap()
                .exchange("genesis", SignalMessageType::Genesis, "{}")
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected));
        }
    }

    #[tokio::test]
    async fn rejects_response_over_limit() {
        let (endpoint, _) = stub(response(200, "12345")).await;
        let error = FreddieSignaler::with_insecure_http_response_limit(endpoint, 4)
            .unwrap()
            .exchange("genesis", SignalMessageType::Genesis, "{}")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds limit"));
    }

    #[tokio::test]
    async fn rejects_headers_over_limit() {
        let mut encoded = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
        encoded.resize(MAX_HEADER_BYTES + 1, b'a');
        let (endpoint, _) = stub(encoded).await;
        let error = FreddieSignaler::new_insecure_http(endpoint)
            .unwrap()
            .exchange("genesis", SignalMessageType::Genesis, "{}")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("headers exceed limit"));
    }

    #[tokio::test]
    async fn bounded_close_reader_never_buffers_past_limit() {
        let (mut reader, mut writer) = tokio::io::duplex(16);
        tokio::spawn(async move {
            writer.write_all(b"12345").await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut body = Vec::new();
        let error = read_to_close_bounded(&mut reader, &mut body, 4)
            .await
            .unwrap_err();
        assert_eq!(body, b"1234");
        assert!(error.to_string().contains("exceeds limit"));
    }

    #[tokio::test]
    async fn rejects_eof_before_declared_content_length() {
        let encoded =
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nshort".to_vec();
        let (endpoint, _) = stub(encoded).await;
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            FreddieSignaler::new_insecure_http(endpoint)
                .unwrap()
                .exchange("genesis", SignalMessageType::Genesis, "{}"),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("Content-Length"));
    }

    #[tokio::test]
    async fn decodes_chunked_success_response() {
        let encoded = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nC\r\n{\"ReplyTo\":\"\r\n1F\r\noffer\",\"Type\":1,\"Payload\":\"{}\"}\r\n0\r\n\r\n".to_vec();
        let (endpoint, _) = stub(encoded).await;
        let message = FreddieSignaler::new_insecure_http(endpoint)
            .unwrap()
            .exchange("genesis", SignalMessageType::Genesis, "{}")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(message.reply_to, "offer");
    }

    #[tokio::test]
    async fn exchanges_over_rustls_with_verified_server_name() {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(identity.key_pair.serialize_der());
        let cert = CertificateDer::from(identity.cert);
        let server_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key.into())
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "https://localhost:{}/v1/signal",
            listener.local_addr().unwrap().port()
        );
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let _ = read_request(&mut stream).await;
            stream.write_all(&response(200, "")).await.unwrap();
        });
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let signaler =
            FreddieSignaler::with_roots(&endpoint, DEFAULT_MAX_RESPONSE_BYTES, roots).unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            signaler.exchange("genesis", SignalMessageType::Genesis, "{}"),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(result.is_none());
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn dropping_exchange_cancels_stalled_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/signal", listener.local_addr().unwrap());
        let (request_tx, request_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut stream).await;
            request_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let signaler = FreddieSignaler::new_insecure_http(endpoint).unwrap();
        let exchange = tokio::spawn(async move {
            signaler
                .exchange("genesis", SignalMessageType::Genesis, "{}")
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), request_rx)
            .await
            .unwrap()
            .unwrap();
        exchange.abort();
        assert!(exchange.await.unwrap_err().is_cancelled());
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn parses_supported_endpoint_forms() {
        let plain = Endpoint::parse("http://example.com/v1/signal").unwrap();
        assert_eq!((plain.host.as_str(), plain.port), ("example.com", 80));
        let ipv6 = Endpoint::parse("https://[::1]:8443/v1/signal?x=1").unwrap();
        assert_eq!((ipv6.host.as_str(), ipv6.port), ("::1", 8443));
        assert!(Endpoint::parse("ftp://example.com/signal").is_err());
        assert!(Endpoint::parse("http://user@example.com/signal").is_err());
        assert!(Endpoint::parse("http://example.com/raw path").is_err());
        assert!(Endpoint::parse("http://example.com/tab\there").is_err());
        assert!(Endpoint::parse("http://example.com/\u{7f}").is_err());
    }

    #[test]
    fn parses_query_without_path_and_rejects_fragments() {
        let query = Endpoint::parse("https://example.com?x=1").unwrap();
        assert_eq!(query.authority, "example.com");
        assert_eq!(query.target, "/?x=1");
        assert!(Endpoint::parse("https://example.com#fragment").is_err());
        assert!(Endpoint::parse("https://example.com/path#fragment").is_err());
    }

    #[test]
    fn requires_explicit_opt_in_for_plaintext_http() {
        assert!(FreddieSignaler::new("http://127.0.0.1/signal").is_err());
        assert!(FreddieSignaler::new_insecure_http("http://127.0.0.1/signal").is_ok());
        assert!(FreddieSignaler::new_insecure_http("https://example.com/signal").is_err());
    }

    #[test]
    fn accepts_a_response_without_headers() {
        assert_eq!(
            parse_headers(b"HTTP/1.1 200 OK\r\n\r\n").unwrap(),
            (200, BodyFraming::CloseDelimited)
        );
    }

    #[test]
    fn rejects_conflicting_transfer_encodings() {
        let headers =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_headers(headers)
            .unwrap_err()
            .to_string()
            .contains("conflicting"));
    }
}
