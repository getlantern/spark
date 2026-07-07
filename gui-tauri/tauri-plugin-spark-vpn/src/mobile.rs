// Android tunnel control — forwards each TunnelControl method to the Kotlin SparkVpnPlugin over the
// Tauri mobile-plugin bridge (`PluginHandle::run_mobile_plugin`).
//
// TYPE DECISION: `TunnelControl` is a non-generic object-safe trait boxed as
// `Box<dyn TunnelControl>`, but `PluginHandle` is generic over `R: Runtime`. Rather than pin the
// handle to `tauri::Wry`, `AndroidControl<R>` is generic over the same `R` as the plugin's
// `init<R>()`, and we box it as `Box<dyn TunnelControl>` at the call site (a concrete
// `AndroidControl<R>` erases cleanly to the non-generic trait object). `PluginHandle<R>` holds an
// `AppHandle<R>`, which is `Send + Sync`, so it satisfies `TunnelControl: Send + Sync`.
//
// RETURN-SHAPE CONVENTION (must stay in sync with SparkVpnPlugin.kt):
//   - status         → Kotlin resolves `{state, protocol, failOpen}` → deserialize into `Status`.
//   - servers        → Kotlin resolves `{value: <jsonArrayString>}` → parse `value` into
//                      `Vec<ServerInfo>` ("[]" before connect).
//   - getSplitTunnel → Kotlin resolves `{value: <jsonString>}`   → return `value`.
//   - getRoutingMode → Kotlin resolves `{value: <modeString>}`   → return `value`.
//   - listInstalledApps/getExcludedApps → Kotlin resolves `{value: <jsonArrayString>}` → return
//                      `value`.
//   - selectServer   → Kotlin resolves `{ok: bool}`              → deserialize (ok ignored → ()).
//   - connect/disconnect/setSplitTunnel/setRoutingMode/setExcludedApps → Kotlin resolves unit
//     (`null`).

#[cfg(target_os = "android")]
use crate::control::TunnelControl;
#[cfg(target_os = "android")]
use crate::models::{ServerInfo, Status};
#[cfg(target_os = "android")]
use serde::{Deserialize, Serialize};
#[cfg(target_os = "android")]
use tauri::{plugin::PluginHandle, Runtime};

#[cfg(target_os = "android")]
pub(crate) struct AndroidControl<R: Runtime> {
    handle: PluginHandle<R>,
}

/// Command payload for `selectServer`.
#[cfg(target_os = "android")]
#[derive(Serialize)]
struct IndexArg {
    index: i32,
}

/// Command payload for `setSplitTunnel`.
#[cfg(target_os = "android")]
#[derive(Serialize)]
struct JsonArg<'a> {
    json: &'a str,
}

/// Command payload for `setRoutingMode`.
#[cfg(target_os = "android")]
#[derive(Serialize)]
struct ModeArg<'a> {
    mode: &'a str,
}

/// The `{value: String}` wrapper Kotlin resolves for `servers`/`getSplitTunnel`/`getRoutingMode`.
#[cfg(target_os = "android")]
#[derive(Deserialize)]
struct ValueString {
    value: String,
}

/// The `{ok: bool}` reply Kotlin resolves for `selectServer` (the flag is informational only).
#[cfg(target_os = "android")]
#[derive(Deserialize)]
struct OkReply {
    #[allow(dead_code)]
    ok: bool,
}

#[cfg(target_os = "android")]
impl<R: Runtime> AndroidControl<R> {
    pub(crate) fn new(handle: PluginHandle<R>) -> Self {
        Self { handle }
    }

    /// Route a command with a serializable payload to Kotlin, mapping the bridge error to `Platform`.
    fn call<T: serde::de::DeserializeOwned>(
        &self,
        cmd: &str,
        payload: impl serde::Serialize,
    ) -> crate::Result<T> {
        self.handle
            .run_mobile_plugin::<T>(cmd, payload)
            .map_err(|e| crate::Error::Platform(e.to_string()))
    }
}

#[cfg(target_os = "android")]
impl<R: Runtime> TunnelControl for AndroidControl<R> {
    fn connect(&self) -> crate::Result<()> {
        self.call::<()>("connect", ())
    }

    fn disconnect(&self) -> crate::Result<()> {
        self.call::<()>("disconnect", ())
    }

    fn status(&self) -> crate::Result<Status> {
        self.call::<Status>("status", ())
    }

    fn servers(&self) -> crate::Result<Vec<ServerInfo>> {
        // Kotlin resolves `{value: <jsonArrayString>}`; parse the inner array into ServerInfo.
        let wrapped: ValueString = self.call("servers", ())?;
        let servers = serde_json::from_str(&wrapped.value)?;
        Ok(servers)
    }

    fn select_server(&self, index: i32) -> crate::Result<()> {
        let _reply: OkReply = self.call("selectServer", IndexArg { index })?;
        Ok(())
    }

    fn get_split_tunnel(&self) -> crate::Result<String> {
        let wrapped: ValueString = self.call("getSplitTunnel", ())?;
        Ok(wrapped.value)
    }

    fn set_split_tunnel(&self, json: &str) -> crate::Result<()> {
        self.call::<()>("setSplitTunnel", JsonArg { json })
    }

    fn get_routing_mode(&self) -> crate::Result<String> {
        let wrapped: ValueString = self.call("getRoutingMode", ())?;
        Ok(wrapped.value)
    }

    fn set_routing_mode(&self, mode: &str) -> crate::Result<()> {
        self.call::<()>("setRoutingMode", ModeArg { mode })
    }

    fn list_installed_apps(&self) -> crate::Result<String> {
        // Kotlin resolves `{value: <jsonArrayString>}`; return the inner array string.
        let wrapped: ValueString = self.call("listInstalledApps", ())?;
        Ok(wrapped.value)
    }

    fn get_excluded_apps(&self) -> crate::Result<String> {
        let wrapped: ValueString = self.call("getExcludedApps", ())?;
        Ok(wrapped.value)
    }

    fn set_excluded_apps(&self, json: &str) -> crate::Result<()> {
        self.call::<()>("setExcludedApps", JsonArg { json })
    }
}
