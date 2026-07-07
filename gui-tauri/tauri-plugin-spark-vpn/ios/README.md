# tauri-plugin-spark-vpn — iOS (deferred seam)

iOS is a **reserved seam**, not built in this milestone. When implemented, iOS reuses the
cross-process `AppleControl` (`src/desktop.rs`) — Apple's NetworkExtension API is shared between
macOS and iOS, and the `SparkCore.xcframework` already builds the `ios-arm64` + `ios-arm64-simulator`
slices. The remaining iOS work is *packaging* the existing NE as an iOS Packet Tunnel Provider
app-extension inside a Tauri iOS target (ADR 0008 flags this as unproven), plus a Swift `Plugin`
shim here — NOT rewriting control logic.

To wire it later: `npx @tauri-apps/cli plugin ios init` (generates the SPM project + Swift Plugin),
add `.ios_path("ios")` to `build.rs`, and gate `AppleControl` on `any(target_os="macos", target_os="ios")`.
