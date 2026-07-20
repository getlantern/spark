const COMMANDS: &[&str] = &[
    "connect",
    "disconnect",
    "status",
    "servers",
    "select_server",
    "get_split_tunnel",
    "set_split_tunnel",
    "get_routing_mode",
    "set_routing_mode",
    "get_ad_block_enabled",
    "set_ad_block_enabled",
    "list_installed_apps",
    "get_excluded_apps",
    "set_excluded_apps",
    "unbounded_start",
    "unbounded_stop",
    "unbounded_status",
    "unbounded_available",
    "unbounded_get_settings",
    "unbounded_set_settings",
    "diag_report_webview_error",
    "diag_set_enabled",
    "diag_get_enabled",
];

fn main() {
    // Embed the short git sha for the diagnostics resource attrs (`spark.git_sha`,
    // diag_host.rs). Best-effort: a non-git build (source tarball) reports "unknown".
    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SPARK_GIT_SHA={sha}");
    // Re-run on branch switch so the embedded sha tracks HEAD (the repo root is two
    // levels up from this plugin crate). Same-branch commits don't touch .git/HEAD,
    // so a stale sha is possible within a branch — acceptable for a diagnostics attr.
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}
