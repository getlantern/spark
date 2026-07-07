use std::path::PathBuf;

use crate::control::TunnelControl;
use crate::models::{ServerInfo, Status};

// ── macOS: AppleControl (cross-process NE). ───────────────────────────────────
// STUB for connect/disconnect/status/servers/select_server — the ne_spike migration is a
// later task.  get/set_split_tunnel and get/set_routing_mode are REAL: they delegate to
// crate::persist using the platform-provided base dir.

#[cfg(target_os = "macos")]
pub(crate) struct AppleControl {
    pub(crate) base: PathBuf,
}

#[cfg(target_os = "macos")]
impl TunnelControl for AppleControl {
    fn connect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform("apple: not yet migrated".into()))
    }

    fn disconnect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform("apple: not yet migrated".into()))
    }

    fn status(&self) -> crate::Result<Status> {
        Ok(Status {
            state: "disconnected".into(),
            protocol: "AnyTLS".into(),
            fail_open: false,
        })
    }

    fn servers(&self) -> crate::Result<Vec<ServerInfo>> {
        Ok(Vec::new())
    }

    fn select_server(&self, _index: i32) -> crate::Result<()> {
        Err(crate::Error::NoTunnel)
    }

    fn get_split_tunnel(&self) -> crate::Result<String> {
        Ok(crate::persist::load_split_tunnel(&self.base))
    }

    fn set_split_tunnel(&self, json: &str) -> crate::Result<()> {
        crate::persist::save_split_tunnel(&self.base, json)
    }

    fn get_routing_mode(&self) -> crate::Result<String> {
        Ok(crate::persist::load_routing_mode(&self.base))
    }

    fn set_routing_mode(&self, mode: &str) -> crate::Result<()> {
        crate::persist::save_routing_mode(&self.base, mode)
    }
}

// ── Windows/Linux: ServiceControl over spark-ipc — future. ───────────────────

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
pub(crate) struct ServiceControl {
    pub(crate) base: PathBuf,
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
impl TunnelControl for ServiceControl {
    fn connect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "desktop service: not yet implemented (spark-ipc)".into(),
        ))
    }

    fn disconnect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "desktop service: not yet implemented (spark-ipc)".into(),
        ))
    }

    fn status(&self) -> crate::Result<Status> {
        Ok(Status {
            state: "disconnected".into(),
            protocol: "AnyTLS".into(),
            fail_open: false,
        })
    }

    fn servers(&self) -> crate::Result<Vec<ServerInfo>> {
        Ok(Vec::new())
    }

    fn select_server(&self, _index: i32) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "desktop service: not yet implemented (spark-ipc)".into(),
        ))
    }

    fn get_split_tunnel(&self) -> crate::Result<String> {
        Ok(crate::persist::load_split_tunnel(&self.base))
    }

    fn set_split_tunnel(&self, json: &str) -> crate::Result<()> {
        crate::persist::save_split_tunnel(&self.base, json)
    }

    fn get_routing_mode(&self) -> crate::Result<String> {
        Ok(crate::persist::load_routing_mode(&self.base))
    }

    fn set_routing_mode(&self, mode: &str) -> crate::Result<()> {
        crate::persist::save_routing_mode(&self.base, mode)
    }
}
