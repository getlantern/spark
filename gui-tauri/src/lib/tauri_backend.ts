// The real backend: drives the tauri-plugin-spark-vpn command surface
// (plugin:spark-vpn|status / |connect / |disconnect …) over Tauri's invoke().
// status() reflects the live tunnel connection state; connect()/disconnect() drive
// the real write path (on macOS, the plugin's NETunnelProviderManager
// save/load/start/stop). Same SparkBackend shape as MockBackend, so the UI is
// unchanged.

import { invoke } from "@tauri-apps/api/core";

import type { InstalledApp, ServerInfo, SparkBackend, SparkStatus, SplitTunnel, UnboundedSettings, UnboundedStatus } from "./spark_backend";

export class TauriBackend implements SparkBackend {
  async status(): Promise<SparkStatus> {
    return await invoke<SparkStatus>("plugin:spark-vpn|status");
  }
  async connect(): Promise<void> {
    await invoke("plugin:spark-vpn|connect");
  }
  async disconnect(): Promise<void> {
    await invoke("plugin:spark-vpn|disconnect");
  }
  async servers(): Promise<ServerInfo[]> {
    return await invoke<ServerInfo[]>("plugin:spark-vpn|servers");
  }
  async selectServer(index: number | null): Promise<void> {
    // The plugin command takes a plain i32; -1 means auto (the pool has no negative indices).
    await invoke("plugin:spark-vpn|select_server", { index: index ?? -1 });
  }
  async getSelectedServer(): Promise<number | null> {
    // -1 (Smart/auto) maps back to null; any non-negative index is a pin.
    const i = await invoke<number>("plugin:spark-vpn|get_selected_server");
    return i < 0 ? null : i;
  }
  async getSplitTunnel(): Promise<SplitTunnel> {
    return JSON.parse(await invoke<string>("plugin:spark-vpn|get_split_tunnel"));
  }
  async setSplitTunnel(st: SplitTunnel): Promise<void> {
    await invoke("plugin:spark-vpn|set_split_tunnel", { json: JSON.stringify(st) });
  }
  async getRoutingMode(): Promise<"smart" | "full"> {
    // Coerce rather than cast: an unexpected value (corrupt file, older backend) falls back to the
    // known-safe default, matching the Rust get_routing_mode() which also defaults to "smart".
    const mode = await invoke<string>("plugin:spark-vpn|get_routing_mode");
    return mode === "full" ? "full" : "smart";
  }
  async setRoutingMode(mode: "smart" | "full"): Promise<void> {
    await invoke("plugin:spark-vpn|set_routing_mode", { mode });
  }
  async getAdBlockEnabled(): Promise<boolean> {
    return await invoke<boolean>("plugin:spark-vpn|get_ad_block_enabled");
  }
  async setAdBlockEnabled(enabled: boolean): Promise<void> {
    await invoke("plugin:spark-vpn|set_ad_block_enabled", { enabled });
  }
  async listInstalledApps(): Promise<InstalledApp[]> {
    return JSON.parse(await invoke<string>("plugin:spark-vpn|list_installed_apps")) as InstalledApp[];
  }
  async getExcludedApps(): Promise<string[]> {
    return JSON.parse(await invoke<string>("plugin:spark-vpn|get_excluded_apps")) as string[];
  }
  async setExcludedApps(ids: string[]): Promise<void> {
    await invoke("plugin:spark-vpn|set_excluded_apps", { json: JSON.stringify(ids) });
  }
  async unboundedStart(): Promise<void> {
    await invoke("plugin:spark-vpn|unbounded_start");
  }
  async unboundedStop(): Promise<void> {
    await invoke("plugin:spark-vpn|unbounded_stop");
  }
  async unboundedStatus(): Promise<UnboundedStatus> {
    return await invoke<UnboundedStatus>("plugin:spark-vpn|unbounded_status");
  }
  async unboundedGetSettings(): Promise<UnboundedSettings> {
    return await invoke<UnboundedSettings>("plugin:spark-vpn|unbounded_get_settings");
  }
  async unboundedSetSettings(settings: Partial<UnboundedSettings>): Promise<void> {
    // camelCase keys — Tauri maps them to the Rust command's snake_case params
    // (auto_enable / hidden / welcome_seen); omitted keys stay unchanged.
    await invoke("plugin:spark-vpn|unbounded_set_settings", settings);
  }
  async unboundedAvailable(): Promise<boolean> {
    return await invoke<boolean>("plugin:spark-vpn|unbounded_available");
  }
}

// True when running inside the Tauri webview (vs a plain browser at `npm run dev`).
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
