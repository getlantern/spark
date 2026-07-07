use crate::control::TunnelControl;
use crate::models::{ServerInfo, Status};

// ── macOS: AppleControl (cross-process NE). ───────────────────────────────────
// STUB for now — the ne_spike migration is a later task.

#[cfg(target_os = "macos")]
pub(crate) struct AppleControl;

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
        Ok("{\"enabled\":false,\"domains\":[],\"ips\":[]}".into())
    }

    fn set_split_tunnel(&self, _json: &str) -> crate::Result<()> {
        Err(crate::Error::NoTunnel)
    }

    fn get_routing_mode(&self) -> crate::Result<String> {
        Ok("smart".into())
    }

    fn set_routing_mode(&self, _mode: &str) -> crate::Result<()> {
        Err(crate::Error::NoTunnel)
    }
}

// ── Windows/Linux: ServiceControl over spark-ipc — future. ───────────────────

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
pub(crate) struct ServiceControl;

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
        Ok("{\"enabled\":false,\"domains\":[],\"ips\":[]}".into())
    }

    fn set_split_tunnel(&self, _json: &str) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "desktop service: not yet implemented (spark-ipc)".into(),
        ))
    }

    fn get_routing_mode(&self) -> crate::Result<String> {
        Ok("smart".into())
    }

    fn set_routing_mode(&self, _mode: &str) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "desktop service: not yet implemented (spark-ipc)".into(),
        ))
    }
}
