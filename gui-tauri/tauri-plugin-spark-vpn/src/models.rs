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

/// One server for the selection UI. Mirrors `gui-tauri/src-tauri/src/config.rs::ServerInfo`
/// (same serde field/rename shape verbatim, incl. camelCase `countryCode`/`latencyMs`/`isCurrent`).
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
