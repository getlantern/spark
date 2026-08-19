use crate::models::{ServerInfo, Status};

/// Cross-platform tunnel control seam. Each platform implements this trait;
/// the plugin manages an instance as Tauri state and routes commands through it.
pub trait TunnelControl: Send + Sync {
    fn connect(&self) -> crate::Result<()>;
    fn disconnect(&self) -> crate::Result<()>;
    fn status(&self) -> crate::Result<Status>;
    fn servers(&self) -> crate::Result<Vec<ServerInfo>>;
    fn select_server(&self, index: i32) -> crate::Result<()>;
    /// Hand a freshly fetched config to the running tunnel, to apply live.
    ///
    /// The app is the only process that fetches — `/config-new` *assigns*, so a second fetcher
    /// produces a second, independent assignment for the same account and the two disagree about
    /// which servers exist. Forwarding what the app already has keeps the tunnel on that one
    /// assignment without a reconnect.
    ///
    /// Best-effort by contract: a tunnel that is down has nothing to apply to and the config is
    /// already cached for its next start, so implementations return `Ok(())` rather than an error
    /// in that case. A failure here must never fail the fetch that produced the config.
    fn push_config(&self, raw: &str) -> crate::Result<()>;
    fn get_split_tunnel(&self) -> crate::Result<String>;
    fn set_split_tunnel(&self, json: &str) -> crate::Result<()>;
    fn get_routing_mode(&self) -> crate::Result<String>;
    fn set_routing_mode(&self, mode: &str) -> crate::Result<()>;
    fn get_ad_block_enabled(&self) -> crate::Result<bool>;
    fn set_ad_block_enabled(&self, enabled: bool) -> crate::Result<()>;
    /// Installed apps for the exclude picker, as a JSON array string of `{id,name,icon}`.
    fn list_installed_apps(&self) -> crate::Result<String>;
    /// The persisted excluded-app match keys, as a JSON array string.
    fn get_excluded_apps(&self) -> crate::Result<String>;
    /// Persist + live-apply the excluded-app match keys (JSON array string).
    fn set_excluded_apps(&self, json: &str) -> crate::Result<()>;
}
