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
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}
