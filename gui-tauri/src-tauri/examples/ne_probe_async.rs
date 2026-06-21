//! U1b machinery proof — runs the async `loadAllFromPreferences` read on the main
//! thread, driving the run loop so the main-queue completion fires. Run on macOS:
//! `cargo run --example ne_probe_async`. Prints the saved-manager count + the first
//! manager's NEVPNStatus. On an unsigned dev build this is `0 managers` (no NE
//! entitlement to save any), which still proves the block2 + run-loop completion
//! path that connect/disconnect will reuse in U1c.

#[cfg(target_os = "macos")]
fn main() {
    let (count, status) = gui_tauri_lib::ne_spike::load_first_status_blocking();
    let name = if status < 0 {
        "n/a"
    } else {
        gui_tauri_lib::ne_spike::status_name(status)
    };
    println!("NE async read OK — {count} saved manager(s); first status = {name} ({status})");
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("ne_probe_async is macOS-only");
}
