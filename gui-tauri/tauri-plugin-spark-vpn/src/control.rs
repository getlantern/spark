use crate::models::{ServerInfo, Status};

/// Cross-platform tunnel control seam. Each platform implements this trait;
/// the plugin manages an instance as Tauri state and routes commands through it.
pub trait TunnelControl: Send + Sync {
    fn connect(&self) -> crate::Result<()>;
    fn disconnect(&self) -> crate::Result<()>;
    fn status(&self) -> crate::Result<Status>;
    fn servers(&self) -> crate::Result<Vec<ServerInfo>>;
    fn select_server(&self, index: i32) -> crate::Result<()>;
    fn get_split_tunnel(&self) -> crate::Result<String>;
    fn set_split_tunnel(&self, json: &str) -> crate::Result<()>;
    fn get_routing_mode(&self) -> crate::Result<String>;
    fn set_routing_mode(&self, mode: &str) -> crate::Result<()>;
}
