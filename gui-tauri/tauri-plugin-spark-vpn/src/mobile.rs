// Android tunnel control — real JNI/bridge wiring is a later task (P3.2).
// AndroidControl STUB: holds the PluginHandle from register_android_plugin, returns disconnected
// state and unimplemented errors for mutating ops. The `run_mobile_plugin` calls that route each
// command to SparkVpnPlugin.kt are wired in P3.2.
//
// TYPE DECISION: `TunnelControl` is a non-generic object-safe trait boxed as
// `Box<dyn TunnelControl>`, but `PluginHandle` is generic over `R: Runtime`. Rather than pin the
// handle to `tauri::Wry`, `AndroidControl<R>` is generic over the same `R` as the plugin's
// `init<R>()`, and we box it as `Box<dyn TunnelControl>` at the call site (a concrete
// `AndroidControl<R>` erases cleanly to the non-generic trait object). `PluginHandle<R>` holds an
// `AppHandle<R>`, which is `Send + Sync`, so it satisfies `TunnelControl: Send + Sync`.

#[cfg(target_os = "android")]
use crate::control::TunnelControl;
#[cfg(target_os = "android")]
use crate::models::{ServerInfo, Status};
#[cfg(target_os = "android")]
use tauri::{plugin::PluginHandle, Runtime};

#[cfg(target_os = "android")]
pub(crate) struct AndroidControl<R: Runtime> {
    #[allow(dead_code)] // used for run_mobile_plugin in P3.2
    handle: PluginHandle<R>,
}

#[cfg(target_os = "android")]
impl<R: Runtime> AndroidControl<R> {
    pub(crate) fn new(handle: PluginHandle<R>) -> Self {
        Self { handle }
    }
}

#[cfg(target_os = "android")]
impl<R: Runtime> TunnelControl for AndroidControl<R> {
    fn connect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform("android: not yet wired".into()))
    }

    fn disconnect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform("android: not yet wired".into()))
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
        Err(crate::Error::Platform("android: not yet wired".into()))
    }

    fn get_split_tunnel(&self) -> crate::Result<String> {
        Ok("{\"enabled\":false,\"domains\":[],\"ips\":[]}".into())
    }

    fn set_split_tunnel(&self, _json: &str) -> crate::Result<()> {
        Err(crate::Error::Platform("android: not yet wired".into()))
    }

    fn get_routing_mode(&self) -> crate::Result<String> {
        Ok("smart".into())
    }

    fn set_routing_mode(&self, _mode: &str) -> crate::Result<()> {
        Err(crate::Error::Platform("android: not yet wired".into()))
    }
}
