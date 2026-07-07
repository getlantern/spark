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
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}
