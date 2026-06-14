//! IP-literal redaction for log output — a privacy backstop (see `docs/GOAL.md`).
//!
//! The primary hygiene mechanism is the level convention: source/destination addresses are
//! only ever emitted in `debug!` calls, so at the default `info` level they are filtered
//! out. [`redact_addrs`] is defense in depth — wired into the logger's writer when not in
//! debug mode, it scrubs any IP literal that slips into a default-level line.
//!
//! It redacts IPv4 dotted-quads (`1.2.3.4`, with or without a trailing `:port`) and
//! bracketed IPv6 (`[2001:db8::1]`, how `SocketAddr` renders v6). It deliberately does *not*
//! pattern-match hostnames or bare (unbracketed) IPv6: those would risk mangling ordinary
//! text (module paths like `spark_core::proxy`, version strings like `0.2.2`), and they are
//! already kept out of default logs by the level convention.

use std::borrow::Cow;

/// Replacement token for a redacted address.
const REDACTED: &str = "[redacted-ip]";

/// Redact IPv4 dotted-quads and bracketed IPv6 literals from `input`.
///
/// Returns [`Cow::Borrowed`] unchanged when there is nothing to redact, so the common case
/// (a log line with no address) allocates nothing.
pub fn redact_addrs(input: &str) -> Cow<'_, str> {
    let bytes = input.as_bytes();
    let mut out: Option<String> = None;
    let mut last = 0;
    let mut i = 0;
    while i < bytes.len() {
        // Only start an IPv4 match at a boundary, so we never match the tail of a longer
        // number (e.g. `1234.5.6.7`).
        let prev_boundary = i == 0 || !(bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'.');
        let matched = (prev_boundary && bytes[i].is_ascii_digit())
            .then(|| match_ipv4(&bytes[i..]))
            .flatten()
            .or_else(|| match_bracketed_v6(&bytes[i..]));

        if let Some(len) = matched {
            let o = out.get_or_insert_with(String::new);
            o.push_str(&input[last..i]);
            o.push_str(REDACTED);
            i += len;
            last = i;
        } else {
            i += 1;
        }
    }
    match out {
        Some(mut o) => {
            o.push_str(&input[last..]);
            Cow::Owned(o)
        }
        None => Cow::Borrowed(input),
    }
}

/// Match a dotted-quad at the start of `b`, returning its byte length (excluding any
/// `:port`), or `None`. Rejects quads that are actually a prefix of a longer dotted number.
fn match_ipv4(b: &[u8]) -> Option<usize> {
    let mut pos = 0;
    for group in 0..4 {
        let mut digits = 0;
        while pos < b.len() && b[pos].is_ascii_digit() && digits < 3 {
            pos += 1;
            digits += 1;
        }
        if digits == 0 {
            return None;
        }
        if group < 3 {
            if b.get(pos) != Some(&b'.') {
                return None;
            }
            pos += 1; // consume the dot
        }
    }
    // Reject if the quad continues into a longer number: a 4th group cut at 3 digits
    // (`b[pos]` is a digit) or a 5th group (`.<digit>`).
    if pos < b.len() {
        if b[pos].is_ascii_digit() {
            return None;
        }
        if b[pos] == b'.' && b.get(pos + 1).is_some_and(u8::is_ascii_digit) {
            return None;
        }
    }
    Some(pos)
}

/// Match a bracketed IPv6 literal `[...]` at the start of `b`, returning its byte length
/// (including the brackets), or `None`. Requires the bracket content to look like an IPv6
/// address (a colon, and only hex / `:` / `.` / `%`-zone characters).
fn match_bracketed_v6(b: &[u8]) -> Option<usize> {
    if b.first() != Some(&b'[') {
        return None;
    }
    let close = b.iter().position(|&c| c == b']')?;
    let content = &b[1..close];
    // A `%zone` suffix (e.g. `%eth0`) is an arbitrary interface name; validate only the
    // address part before it.
    let addr_part = match content.iter().position(|&c| c == b'%') {
        Some(p) => &content[..p],
        None => content,
    };
    if !addr_part.contains(&b':') {
        return None;
    }
    if !addr_part
        .iter()
        .all(|&c| c.is_ascii_hexdigit() || matches!(c, b':' | b'.'))
    {
        return None;
    }
    Some(close + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_ipv4_with_and_without_port() {
        assert_eq!(
            redact_addrs("dial 1.2.3.4:443 now"),
            "dial [redacted-ip]:443 now"
        );
        assert_eq!(redact_addrs("from 192.0.2.10"), "from [redacted-ip]");
        assert_eq!(
            redact_addrs("a 10.0.0.1 b 8.8.8.8 c"),
            "a [redacted-ip] b [redacted-ip] c"
        );
    }

    #[test]
    fn redacts_bracketed_ipv6() {
        assert_eq!(
            redact_addrs("peer [2001:db8::1]:8443 up"),
            "peer [redacted-ip]:8443 up"
        );
        assert_eq!(redact_addrs("[fe80::1%eth0]"), "[redacted-ip]");
    }

    #[test]
    fn leaves_non_addresses_untouched() {
        // Version strings, MSRV, module paths, timestamps, level names.
        for s in [
            "MSRV 1.85 and dep 0.2.2",
            "v0.8.9 released",
            "spark_core::proxy::tcp: tcp flow completed",
            "2026-06-14T12:34:56Z  INFO ready",
            "to_upstream=42 to_app=99",
            "three groups 1.2.3 only",
        ] {
            assert!(
                matches!(redact_addrs(s), Cow::Borrowed(_)),
                "should not allocate or change: {s:?}"
            );
            assert_eq!(redact_addrs(s), s);
        }
    }

    #[test]
    fn does_not_mangle_longer_dotted_numbers() {
        // A 5-group or over-long run must not be partially redacted.
        assert_eq!(redact_addrs("1.2.3.4.5"), "1.2.3.4.5");
        assert_eq!(redact_addrs("1234.5.6.7"), "1234.5.6.7");
        assert_eq!(redact_addrs("1.2.3.4444"), "1.2.3.4444");
    }

    #[test]
    fn empty_and_borrowed_fast_path() {
        assert!(matches!(redact_addrs(""), Cow::Borrowed(_)));
        assert!(matches!(redact_addrs("no address here"), Cow::Borrowed(_)));
    }
}
