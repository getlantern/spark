use serde::{Deserialize, Serialize};

/// The SparkBackend status shape the frontend renders.
/// Serializes to `{"state","protocol","failOpen"}` (camelCase `failOpen`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub state: String,
    pub protocol: String,
    #[serde(rename = "failOpen")]
    pub fail_open: bool,
}

/// One server for the selection UI, in the camelCase shape the frontend's `ServerInfo` expects
/// (`countryCode`/`latencyMs`/`isCurrent`/`isPinned`). Also the deserialize target for the tunnel's
/// live snapshot, so it must stay field-compatible with `spark_core::transport::snapshot_to_json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(
        rename = "countryCode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "latencyMs", default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub healthy: bool,
    #[serde(rename = "isCurrent", default)]
    pub is_current: bool,
    /// The member the user manually pinned, as the *tunnel* sees it. Distinct from `is_current` (which
    /// also moves on its own when the pool re-ranks) and from the plugin's cached pin index, which goes
    /// stale the moment a config refresh reorders the pool. `default` so a snapshot from an older
    /// tunnel build still deserializes.
    #[serde(rename = "isPinned", default)]
    pub is_pinned: bool,
}

#[cfg(test)]
mod tests {
    use super::Status;

    #[test]
    fn status_serializes_to_camel_case() {
        let s = Status {
            state: "disconnected".into(),
            protocol: "AnyTLS".into(),
            fail_open: false,
        };
        let json = serde_json::to_string(&s).expect("serialize Status");
        assert_eq!(
            json,
            r#"{"state":"disconnected","protocol":"AnyTLS","failOpen":false}"#
        );
    }
}
