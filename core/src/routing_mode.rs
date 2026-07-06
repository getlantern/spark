//! The user's routing mode — Smart Routing (apply fetched rules) vs Full Tunnel (proxy everything
//! not user-bypassed). A per-device preference the UI sets; applied by `crate::rules::router`.

use serde::{Deserialize, Serialize};

/// Smart = apply the fetched smart-routing rules (default). Full = force all non-bypassed flows
/// through the proxy (ad-block Reject still honored; split-tunnel bypass still Direct).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    #[default]
    Smart,
    Full,
}

/// Parse the wire token (`"smart"`/`"full"`, case-insensitive); anything else → `Smart` (fail-safe).
pub fn parse(s: &str) -> RoutingMode {
    match s.trim().to_ascii_lowercase().as_str() {
        "full" => RoutingMode::Full,
        _ => RoutingMode::Smart,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tokens() {
        assert_eq!(parse("full"), RoutingMode::Full);
        assert_eq!(parse("Full"), RoutingMode::Full);
        assert_eq!(parse(" smart "), RoutingMode::Smart);
        assert_eq!(parse("nonsense"), RoutingMode::Smart); // fail-safe default
    }

    #[test]
    fn default_is_smart() {
        assert_eq!(RoutingMode::default(), RoutingMode::Smart);
    }
}
