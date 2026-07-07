// Android tunnel control — real JNI/bridge wiring is a later task.
// AndroidControl STUB: returns disconnected state and unimplemented errors for mutating ops.

#[cfg(target_os = "android")]
use crate::control::TunnelControl;
#[cfg(target_os = "android")]
use crate::models::{ServerInfo, Status};

#[cfg(target_os = "android")]
pub(crate) struct AndroidControl;

#[cfg(target_os = "android")]
impl TunnelControl for AndroidControl {
    fn connect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "android: JNI bridge not yet wired".into(),
        ))
    }

    fn disconnect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "android: JNI bridge not yet wired".into(),
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
