# Tauri v2 mobile-plugin API notes (P0.1 spike — scratch; deleted at final gate 4.3)

Pinned from https://v2.tauri.app/develop/plugins/ + /develop/plugins/develop-mobile/ (2026-07-07).
**Tauri version in use:** `tauri = "2"` (v2) — `gui-tauri/src-tauri/Cargo.toml`.

## Scaffold
- `npx @tauri-apps/cli plugin new spark-vpn --android --ios` → `tauri-plugin-spark-vpn/` with
  `src/{commands,desktop,error,lib,mobile,models}.rs`, `permissions/`, `android/`, `ios/`, `guest-js/`.
- Existing plugin → add mobile: `npx @tauri-apps/cli plugin android add` (and `ios add`).
- We want it in-repo under `gui-tauri/tauri-plugin-spark-vpn/`; wire as a workspace member + a
  path dep in `gui-tauri/src-tauri/Cargo.toml`. (No NPM package needed — we call `invoke()` directly
  from `tauri_backend.ts`; `--no-api` is acceptable, or ignore the generated `guest-js`.)

## Rust plugin shape (`lib.rs`)
```rust
use tauri::{plugin::{Builder, TauriPlugin}, Runtime, Manager};
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("spark-vpn")
        .invoke_handler(tauri::generate_handler![
            commands::connect, commands::disconnect, commands::status, commands::servers,
            commands::select_server, commands::get_split_tunnel, commands::set_split_tunnel,
            commands::get_routing_mode, commands::set_routing_mode,
        ])
        .setup(|app, _api| {
            // construct the platform TunnelControl and manage it as state
            let ctl: Box<dyn crate::control::TunnelControl> = crate::platform_control(app)?;
            app.manage(ctl);
            Ok(())
        })
        .build()
}
```
- Command names invoked from JS as `plugin:spark-vpn|connect`, etc.

## Commands (`commands.rs`)
```rust
#[tauri::command]
pub(crate) async fn set_routing_mode<R: Runtime>(app: AppHandle<R>, mode: String) -> crate::Result<()> {
    app.state::<Box<dyn crate::control::TunnelControl>>().set_routing_mode(&mode)
}
```
- Commands can inject `AppHandle<R>`, `Window<R>`, state, `Channel`, and take serde args.

## Rust → Kotlin bridge (mobile.rs)
- `PluginHandle::run_mobile_plugin::<Ret>("commandName", payload) -> tauri::Result<Ret>`
  (docs.rs/tauri/2/tauri/plugin/struct.PluginHandle.html). `payload: impl Serialize`, `Ret: DeserializeOwned`.
- On mobile, `setup`'s `api.register_android_plugin("org.getlantern.spark", "SparkVpnPlugin")?` returns
  the `PluginHandle`; wrap it: `struct AndroidControl(PluginHandle<R>)` and call `self.0.run_mobile_plugin(...)`.
  (Confirm exact `register_android_plugin` signature from the generated template at scaffold time.)

## Kotlin plugin (android/)
```kotlin
@TauriPlugin(
  permissions = [ Permission(strings = [Manifest.permission.POST_NOTIFICATIONS], alias = "postNotification") ]
)
class SparkVpnPlugin(private val activity: Activity): Plugin(activity) {
  @Command fun connect(invoke: Invoke) { /* consent → foreground service → resolve */ }
  @Command fun setRoutingMode(invoke: Invoke) { val a = invoke.parseArgs(ModeArg::class.java); ...; invoke.resolve() }
}
@InvokeArg internal class ModeArg { lateinit var mode: String }
```
- `invoke.resolve(JSObject)` / `invoke.reject(message)`. `suspend` → wrap in a `CoroutineScope`.
- Lifecycle: `override fun load(webView: WebView)`, `override fun onNewIntent(intent: Intent)`.

## Permissions
- Declared in the `@TauriPlugin(permissions=[...])` annotation; Tauri auto-adds `checkPermissions` +
  `requestPermissions` commands. Rust: `run_mobile_plugin::<PermResp>("requestPermissions", Req{...})`.
- Command ACL: `build.rs` `tauri_plugin::Builder::new(COMMANDS).build()` with `COMMANDS: &[&str]` =
  snake_case command names → autogenerates `allow-<cmd>`/`deny-<cmd>` under `permissions/`.
  Add a `permissions/default.toml` set enabling all our commands, and reference it in the app's
  capability file (`gui-tauri/src-tauri/capabilities/*.json` → `"spark-vpn:default"`).

## JNI (in-process tunnel — Android)
- `[target.'cfg(target_os="android")'.dependencies] jni = "0.21"` (matches existing `platforms/android`).
- Kotlin `init { System.loadLibrary("spark_android") }`; `external fun native*` — the existing
  `SparkBridge` (package `org.getlantern.spark`) already declares these; the JNI symbols
  `Java_org_getlantern_spark_SparkBridge_*` live in `platforms/android/src/lib.rs` (unchanged).
- So on Android the plugin's Kotlin loads `libspark_android.so` (built by cargo-ndk into jniLibs) and
  JNIs it IN-PROCESS. **Decision (P0.3): keep `libspark_android.so` as the tunnel artifact.**
  **P0.3 confirmed (2026-07-07):** `cargo ndk -t arm64-v8a build -p spark-android` → valid ELF aarch64
  `libspark_android.so` with all JNI symbols exported (`Java_org_getlantern_spark_SparkBridge_native{Run,
  Servers,SetRoutingMode,SetSplitTunnel}`, `llvm-nm -D`). In-process native execution in the Tauri
  process is already proven (P0.2 ran `libgui_tauri_lib.so` live); the demo proved this exact JNI on
  Android. Full in-process load+call is wired for real at P3.2.
- NDK 28+ → 16KB-page bundles auto-generated (we have NDK 28.2) — no extra rustflags needed.

## TO VERIFY at P3.2 (not covered by these guides — the consent gate)
- **Activity-result** for `VpnService.prepare()`: Tauri's `Plugin` base class provides
  `startActivityForResult(invoke: Invoke, intent: Intent, callbackName: String)` + a method annotated
  `@ActivityCallback fun callbackName(invoke: Invoke, result: ActivityResult)`. Confirm the exact
  signatures against a shipping plugin that launches an activity (tauri-plugin-dialog file picker, or
  barcode-scanner) in the tauri-apps/plugins-workspace repo BEFORE writing P3.2's connect().
- Confirm `register_android_plugin` return + the generated `mobile.rs` template shape at scaffold time.
