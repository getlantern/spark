#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no active tunnel router to update (not connected, or running without smart-routing)")]
    NoTunnel,
    #[error("VPN consent was not granted")]
    Consent,
    #[error("{0}")]
    Platform(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
