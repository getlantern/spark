//! U1a spike — terminal-runnable proof that Rust (objc2) reaches macOS
//! NetworkExtension. Run: `cargo run --example ne_probe` on macOS. Prints the
//! NEVPNStatus of a fresh NETunnelProviderManager's connection. A real status
//! (e.g. "invalid (0)" on an unsigned dev build) proves the Tauri-desktop →
//! NETunnelProviderManager bridge — no Swift toolchain involved.

#[cfg(target_os = "macos")]
fn main() {
    let raw = gui_tauri_lib::ne_spike::probe_status_raw();
    println!(
        "NE bridge OK — NEVPNStatus = {} ({})",
        gui_tauri_lib::ne_spike::status_name(raw),
        raw
    );
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("ne_probe is macOS-only");
}
